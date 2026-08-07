//! Who is making a management request, and what they may do with it.
//!
//! This replaces a boolean. The old question was "is this the management
//! token?", asked identically by every route, and its answer carried no
//! information beyond yes — not who, not from where, not how recently they
//! proved it. Four kinds of credential now reach `/v1/manage`, and they are
//! not equivalent:
//!
//! | credential | who is behind it | can step up |
//! |---|---|---|
//! | browser session | a person, right now | yes, by re-running the ceremony |
//! | device access token | a person, on a device they authorized | inherits the ceremony's time |
//! | automation token | nobody | never |
//! | legacy management token | unknowable | exempt, and that is why it is going away |
//!
//! Authorization happens in one place — [`require_principal`], layered over
//! the whole manage router — rather than in ninety handlers. A handler cannot
//! forget to check, because a handler never checks: by the time one runs, the
//! layer has already matched the request against [`crate::auth::policy`] and
//! refused any that did not qualify.

// Refusals here are whole `Response`s, which clippy flags as a large `Err`.
// That is deliberate: an authorization failure has a status, a reason, and a
// body, and every caller wants to return it unchanged. Boxing would move the
// allocation, not remove it.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use axum::extract::{FromRequestParts, MatchedPath};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{bearer_token, request_peer, AppState};
use crate::auth::policy::{AuthMethod, ClientSurface, Scope, ScopeSet, StepUp, RECENT_AUTH_WINDOW};
use crate::auth::routes::{CSRF_HEADER, SESSION_COOKIE};
use crate::auth::store::{ACCESS_PREFIX, AUTOMATION_PREFIX, SESSION_PREFIX};
use crate::identity::MANAGE_TOKEN_PREFIX;

/// An authenticated management caller.
#[derive(Clone)]
pub struct ManagePrincipal {
    /// The account, when a human is behind the credential. `None` only for
    /// the legacy management token, which proves possession and nothing else.
    pub account: Option<Uuid>,
    /// What to revoke to end this: a session, a device grant, or an
    /// automation token.
    pub credential: Option<Uuid>,
    pub method: AuthMethod,
    pub surface: ClientSurface,
    pub scopes: ScopeSet,
    /// When a human last completed a passkey ceremony for this credential.
    pub authenticated_at: Option<DateTime<Utc>>,
    /// Short human label for the activity log: a device name, or the surface.
    pub label: String,
    /// The legacy management token's plaintext, kept only so the two routes
    /// that rotate and revoke it can still prove current authority under one
    /// lock. Zeroized on drop; absent for every other credential.
    legacy_token: Option<Zeroizing<String>>,
    /// How to re-check later that this credential still authenticates. An SSE
    /// stream can outlive its authorization by hours.
    revalidate: Revalidator,
}

impl std::fmt::Debug for ManagePrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagePrincipal")
            .field("account", &self.account)
            .field("credential", &self.credential)
            .field("method", &self.method.as_str())
            .field("surface", &self.surface.as_str())
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl ManagePrincipal {
    /// The legacy management token's plaintext, for the two routes that
    /// rotate or revoke it. `None` for every other credential — those prove
    /// their authority through the principal instead.
    pub fn legacy_token(&self) -> Option<&str> {
        self.legacy_token.as_deref().map(|token| token.as_str())
    }

    pub fn revalidator(&self) -> Revalidator {
        self.revalidate.clone()
    }

    /// Whether the human behind this credential proved themselves recently
    /// enough for a step-up route.
    fn recently_authenticated(&self) -> bool {
        let window = chrono::Duration::from_std(RECENT_AUTH_WINDOW)
            .unwrap_or_else(|_| chrono::Duration::minutes(5));
        self.authenticated_at
            .is_some_and(|at| Utc::now().signed_duration_since(at) < window)
    }

    /// Demand an authority the route table cannot express.
    ///
    /// The table is keyed by route, and a handful of routes carry more than
    /// one kind of operation — a settings patch that happens to include the
    /// field retiring the management token is an identity change wearing a
    /// settings change's clothes. Those handlers ask here directly.
    pub fn require(&self, scope: Scope, step_up: StepUp) -> Result<(), Response> {
        self.satisfies(scope, step_up)
    }

    fn satisfies(&self, scope: Scope, step_up: StepUp) -> Result<(), Response> {
        if !self.scopes.contains(scope) {
            return Err(refuse(
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                format!(
                    "this credential does not carry {scope}; it holds {}",
                    self.scope_list()
                ),
            ));
        }
        let fresh = match step_up {
            StepUp::No => true,
            // A tab left open on a shared machine is the threat. A device
            // grant is not that: it is per-machine, named, and revocable.
            StepUp::BrowserSession => {
                self.surface != ClientSurface::Web || self.recently_authenticated()
            }
            StepUp::Always => match self.method {
                // The legacy token has no ceremony behind it to be recent,
                // and it is the credential that rotates itself — refusing it
                // here would leave no way to retire it. Exempt, and this
                // exemption is the clearest argument for its retirement.
                AuthMethod::LegacyManageToken => true,
                _ => self.recently_authenticated(),
            },
        };
        if !fresh {
            return Err(refuse(
                StatusCode::UNAUTHORIZED,
                "step_up_required",
                match self.authenticated_at {
                    Some(_) => "confirm with your passkey to continue".into(),
                    // Automation lands here, and should: nothing unattended
                    // can consent to an irreversible change.
                    None => "this action needs a person to confirm it with a passkey, \
                             so a noninteractive credential cannot take it"
                        .into(),
                },
            ));
        }
        Ok(())
    }

    fn scope_list(&self) -> String {
        let held: Vec<&str> = self.scopes.iter().map(|scope| scope.as_str()).collect();
        if held.is_empty() {
            "no scopes".into()
        } else {
            held.join(", ")
        }
    }

    /// Attribution for the activity log. Records the authenticated actor —
    /// not, as before, whichever proxy happened to be the socket peer.
    pub fn decision_context(&self, peer: Option<std::net::SocketAddr>) -> crate::types::DecisionContext {
        crate::types::DecisionContext {
            approver: Some(self.label.clone()),
            surface: crate::types::DecisionSurface::Remote { peer },
        }
    }

    /// How a change this principal authorized was confirmed.
    pub fn confirmation(&self) -> crate::types::ConfirmationMethod {
        match self.method {
            AuthMethod::LegacyManageToken => crate::types::ConfirmationMethod::ManagementToken,
            AuthMethod::PasskeySession | AuthMethod::DeviceToken => {
                crate::types::ConfirmationMethod::Passkey
            }
            AuthMethod::AutomationToken => crate::types::ConfirmationMethod::AutomationToken,
        }
    }
}

/// Re-checks a credential that was verified once and is being relied on
/// still — an SSE stream lives until the client disconnects, and a
/// revocation has to reach it.
#[derive(Clone)]
pub enum Revalidator {
    Legacy {
        identity: Arc<dyn crate::repository::IdentityRepository>,
        workspace: crate::repository::WorkspaceContext,
        token: Zeroizing<String>,
    },
    Session {
        auth: Arc<crate::auth::AuthStore>,
        cookie: Zeroizing<String>,
    },
    Access {
        auth: Arc<crate::auth::AuthStore>,
        token: Zeroizing<String>,
    },
    Automation {
        auth: Arc<crate::auth::AuthStore>,
        token: Zeroizing<String>,
    },
}

impl Revalidator {
    /// Whether this credential still authenticates *right now*.
    ///
    /// This binds an approval-surface lease to its principal: the stream
    /// holding the lease ends the moment this goes false, and the lease's
    /// `Drop` releases the capability with it.
    pub fn still_valid(&self) -> bool {
        match self {
            Self::Legacy {
                identity,
                workspace,
                token,
            } => identity.verify_manage(workspace, token).is_ok(),
            Self::Session { auth, cookie } => auth.verify_session(cookie, None).is_ok(),
            Self::Access { auth, token } => auth.verify_access(token).is_ok(),
            Self::Automation { auth, token } => auth.verify_automation(token).is_ok(),
        }
    }
}

fn refuse(status: StatusCode, reason: &str, detail: String) -> Response {
    (status, Json(json!({ "reason": reason, "detail": detail }))).into_response()
}

/// Read the session cookie out of a request.
fn session_cookie(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .find(|(key, _)| *key == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

/// Resolve the credential a request is presenting, or say why not.
///
/// We refuse two kinds at once rather than picking a winner by precedence. A
/// caller holding both a cookie and a bearer token has not told us which
/// authority they mean to exercise, and choosing one for them is how a
/// low-privilege credential gets silently upgraded by an attacker-supplied
/// cookie riding along on someone else's request.
fn resolve(state: &AppState, parts: &Parts) -> Result<ManagePrincipal, Response> {
    let bearer = bearer_token(&parts.headers).ok().map(str::to_string);
    let cookie = session_cookie(parts);
    let auth = state.broker.auth.clone();

    match (bearer, cookie) {
        (Some(_), Some(_)) => Err(refuse(
            StatusCode::BAD_REQUEST,
            "conflicting_credentials",
            "this request carries both a session cookie and a bearer token; \
             send exactly one"
                .into(),
        )),

        (Some(bearer), None) => {
            if bearer.starts_with(ACCESS_PREFIX) {
                let verified = auth
                    .verify_access(&bearer)
                    .map_err(|error| unauthorized(state, parts, "device_token", &error))?;
                let label = auth
                    .devices()
                    .into_iter()
                    .find(|device| Some(device.id) == Some(verified.credential))
                    .map(|device| device.name)
                    .unwrap_or_else(|| "a signed-in device".into());
                Ok(ManagePrincipal {
                    account: Some(verified.account),
                    credential: Some(verified.credential),
                    method: AuthMethod::DeviceToken,
                    surface: verified.surface,
                    scopes: verified.scopes,
                    authenticated_at: verified.authenticated_at,
                    label,
                    legacy_token: None,
                    revalidate: Revalidator::Access {
                        auth,
                        token: Zeroizing::new(bearer),
                    },
                })
            } else if bearer.starts_with(AUTOMATION_PREFIX) {
                let verified = auth
                    .verify_automation(&bearer)
                    .map_err(|error| unauthorized(state, parts, "automation_token", &error))?;
                let label = auth
                    .automation_tokens()
                    .into_iter()
                    .find(|token| token.id == verified.credential)
                    .map(|token| token.name)
                    .unwrap_or_else(|| "an automation token".into());
                Ok(ManagePrincipal {
                    account: Some(verified.account),
                    credential: Some(verified.credential),
                    method: AuthMethod::AutomationToken,
                    surface: ClientSurface::Automation,
                    scopes: verified.scopes,
                    authenticated_at: None,
                    label,
                    legacy_token: None,
                    revalidate: Revalidator::Automation {
                        auth,
                        token: Zeroizing::new(bearer),
                    },
                })
            } else if bearer.starts_with(MANAGE_TOKEN_PREFIX) {
                legacy(state, parts, bearer)
            } else {
                Err(unknown_credential(state, parts))
            }
        }

        (None, Some(cookie)) => {
            // Cookies are a browser thing. On the Unix socket there is no
            // browser and no origin, so a cookie there is either confusion
            // or an attempt to reach a browser credential from somewhere it
            // was never meant to work.
            let Some(rp) = state.passkeys.as_ref() else {
                return Err(refuse(
                    StatusCode::UNAUTHORIZED,
                    "no_browser_origin",
                    "session cookies authenticate only on this broker's public origin".into(),
                ));
            };
            if !cookie.starts_with(SESSION_PREFIX) {
                return Err(unknown_credential(state, parts));
            }
            // An unsafe method needs the Origin to be ours and the CSRF
            // secret to be present. A safe one needs neither: the browser
            // sends the cookie either way, and a cross-origin *read* cannot
            // see the response.
            let mutating = !matches!(
                parts.method,
                axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
            );
            let csrf = if mutating {
                let sent = parts
                    .headers
                    .get(axum::http::header::ORIGIN)
                    .and_then(|value| value.to_str().ok());
                match sent {
                    Some(sent) if rp.origin().matches(sent) => {}
                    _ => {
                        return Err(refuse(
                            StatusCode::FORBIDDEN,
                            "cross_origin",
                            format!("this request must come from {}", rp.origin()),
                        ))
                    }
                }
                Some(
                    parts
                        .headers
                        .get(CSRF_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default(),
                )
            } else {
                None
            };
            let verified = auth
                .verify_session(&cookie, csrf)
                .map_err(|error| unauthorized(state, parts, "session", &error))?;
            Ok(ManagePrincipal {
                account: Some(verified.account),
                credential: Some(verified.credential),
                method: AuthMethod::PasskeySession,
                surface: ClientSurface::Web,
                scopes: verified.scopes,
                authenticated_at: verified.authenticated_at,
                label: "the web app".into(),
                legacy_token: None,
                revalidate: Revalidator::Session {
                    auth,
                    cookie: Zeroizing::new(cookie),
                },
            })
        }

        (None, None) => Err(super::err_missing_token(
            bearer_token(&parts.headers).unwrap_err(),
        )),
    }
}

/// The management token — on its way out, but still the only credential a
/// local shell has until the desktop migrates.
fn legacy(state: &AppState, parts: &Parts, token: String) -> Result<ManagePrincipal, Response> {
    // The operator retires this once passkeys are established. Check the
    // setting before verification so a still-valid token stops working the
    // moment they turn it off, rather than at its next rotation.
    if !state
        .broker
        .store
        .settings(&state.broker.workspace)
        .legacy_manage_token
    {
        record_failure(state, parts, "legacy_token_retired");
        return Err(refuse(
            StatusCode::UNAUTHORIZED,
            "manage_token_retired",
            "this broker no longer accepts the management token; sign in with a passkey"
                .into(),
        ));
    }
    match state
        .broker
        .identity
        .verify_manage(&state.broker.workspace, &token)
    {
        Ok(()) => Ok(ManagePrincipal {
            account: None,
            credential: None,
            method: AuthMethod::LegacyManageToken,
            surface: ClientSurface::LegacyManageToken,
            // Everything, which is the whole problem with it.
            scopes: ScopeSet::all(),
            authenticated_at: None,
            label: "the management token".into(),
            legacy_token: Some(Zeroizing::new(token.clone())),
            revalidate: Revalidator::Legacy {
                identity: state.broker.identity.clone(),
                workspace: state.broker.workspace.clone(),
                token: Zeroizing::new(token),
            },
        }),
        Err(error) => {
            record_failure(state, parts, error.reason().as_str());
            if let Some(limited) = rate_limited(state, parts) {
                return Err(limited);
            }
            let detail = if error == crate::identity::TokenError::Expired {
                "the management token has expired; issue a fresh one on the \
                 broker host with `multitool manage token`"
            } else {
                "manage routes require this broker's management token \
                 (issue one on the broker host with `multitool manage token`)"
            };
            Err(refuse(
                StatusCode::UNAUTHORIZED,
                "invalid_manage_token",
                detail.into(),
            ))
        }
    }
}

fn unknown_credential(state: &AppState, parts: &Parts) -> Response {
    record_failure(state, parts, "unknown_credential");
    if let Some(limited) = rate_limited(state, parts) {
        return limited;
    }
    refuse(
        StatusCode::UNAUTHORIZED,
        "invalid_manage_token",
        "that is not a credential this broker issues; sign in with a passkey, \
         or use the management token"
            .into(),
    )
}

fn unauthorized(
    state: &AppState,
    parts: &Parts,
    kind: &str,
    error: &crate::auth::AuthError,
) -> Response {
    record_failure(state, parts, kind);
    if let Some(limited) = rate_limited(state, parts) {
        return limited;
    }
    refuse(
        StatusCode::UNAUTHORIZED,
        "invalid_credential",
        error.detail(),
    )
}

fn record_failure(state: &AppState, parts: &Parts, reason: &str) {
    let peer = request_peer(parts).map(|peer| peer.ip().to_string());
    state.broker.audit_auth_failure(
        "manage",
        reason,
        state.transport.audit_label(),
        peer.as_deref(),
    );
}

fn rate_limited(state: &AppState, parts: &Parts) -> Option<Response> {
    let source = request_peer(parts)
        .map(|peer| peer.ip().to_string())
        .unwrap_or_else(|| state.transport.audit_label().to_string());
    state
        .broker
        .manage_auth_limiter
        .check(&source)
        .err()
        .map(|wait| super::err_rate_limited(crate::wire::ErrorReason::RateLimited, wait))
}

/// Authenticate and authorize every manage request, once, before any handler
/// runs.
///
/// The requirement comes from the *matched route template* rather than the
/// request path, so a path crafted to resemble another route cannot pick up
/// its policy, and a route with no table entry still demands a scope
/// (see [`crate::auth::policy`]).
pub async fn require_principal(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let principal = match resolve(&state, &parts) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let matched = parts
        .extensions
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        // No matched path means no such route; it will 404, but it does so
        // as an authenticated caller who also had to hold the method's
        // default scope.
        .unwrap_or_else(|| parts.uri.path().to_string());
    let requirement = crate::auth::policy::requirement(&parts.method, &matched);
    if let Err(response) = principal.satisfies(requirement.scope, requirement.step_up) {
        return response;
    }

    let peer = request_peer(&parts);
    let context = principal.decision_context(peer);
    parts.extensions.insert(principal);
    request = axum::extract::Request::from_parts(parts, body);
    crate::audit::with_request_decision_context(context, next.run(request)).await
}

/// Handlers that need to know who is calling take this. It cannot fail:
/// [`require_principal`] already ran, or the request never reached a handler.
impl FromRequestParts<AppState> for ManagePrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<ManagePrincipal>().cloned().ok_or_else(|| {
            // Only reachable if a route were mounted outside the layer.
            tracing::error!("a manage handler ran with no principal; the auth layer is missing");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "this route is misconfigured".into(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::policy::Scope;

    fn principal(
        method: AuthMethod,
        surface: ClientSurface,
        scopes: ScopeSet,
        authenticated_at: Option<DateTime<Utc>>,
    ) -> ManagePrincipal {
        ManagePrincipal {
            account: Some(Uuid::new_v4()),
            credential: Some(Uuid::new_v4()),
            method,
            surface,
            scopes,
            authenticated_at,
            label: "test".into(),
            legacy_token: None,
            // These tests exercise the authorization decision, which does
            // not consult the revalidator; any live one will do.
            revalidate: Revalidator::Session {
                auth: Arc::new(crate::auth::AuthStore::ephemeral(Arc::new(
                    futures::executor::block_on(crate::integrity::StateIntegrity::open(
                        &crate::vault::MemoryVault::new(),
                    ))
                    .unwrap(),
                ))),
                cookie: Zeroizing::new(String::new()),
            },
        }
    }

    fn web(authenticated_at: Option<DateTime<Utc>>) -> ManagePrincipal {
        principal(
            AuthMethod::PasskeySession,
            ClientSurface::Web,
            ScopeSet::all(),
            authenticated_at,
        )
    }

    fn desktop(authenticated_at: Option<DateTime<Utc>>) -> ManagePrincipal {
        principal(
            AuthMethod::DeviceToken,
            ClientSurface::Desktop,
            ScopeSet::desktop(),
            authenticated_at,
        )
    }

    #[test]
    fn a_scope_it_does_not_hold_is_refused() {
        let pusher = principal(
            AuthMethod::AutomationToken,
            ClientSurface::Automation,
            ScopeSet::cloud_pusher(),
            None,
        );
        assert!(pusher.satisfies(Scope::CloudPush, StepUp::No).is_ok());
        assert!(pusher.satisfies(Scope::ManageRead, StepUp::No).is_err());
        assert!(pusher.satisfies(Scope::SecretsReveal, StepUp::No).is_err());
    }

    #[test]
    fn a_browser_must_be_fresh_to_reveal_but_a_desktop_need_not_be() {
        let stale = Some(Utc::now() - chrono::Duration::hours(3));
        let fresh = Some(Utc::now() - chrono::Duration::seconds(30));

        assert!(web(stale).satisfies(Scope::SecretsReveal, StepUp::BrowserSession).is_err());
        assert!(web(fresh).satisfies(Scope::SecretsReveal, StepUp::BrowserSession).is_ok());
        // The desktop's live 2FA countdown polls; a timer that prompts is
        // not a security control, it is an outage.
        assert!(desktop(stale)
            .satisfies(Scope::SecretsReveal, StepUp::BrowserSession)
            .is_ok());
    }

    #[test]
    fn an_always_route_needs_a_recent_ceremony_from_every_human_surface() {
        let stale = Some(Utc::now() - chrono::Duration::hours(3));
        let fresh = Some(Utc::now() - chrono::Duration::seconds(30));
        for build in [web as fn(Option<DateTime<Utc>>) -> ManagePrincipal, desktop] {
            assert!(build(stale)
                .satisfies(Scope::IdentityManage, StepUp::Always)
                .is_err());
            assert!(build(fresh)
                .satisfies(Scope::IdentityManage, StepUp::Always)
                .is_ok());
        }
    }

    #[test]
    fn nothing_unattended_can_take_an_irreversible_action() {
        let automation = principal(
            AuthMethod::AutomationToken,
            ClientSurface::Automation,
            ScopeSet::all(),
            None,
        );
        let refusal = automation
            .satisfies(Scope::IdentityManage, StepUp::Always)
            .expect_err("automation must not step up");
        assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        // Holding every scope does not help: there is no person to confirm.
        assert!(automation.satisfies(Scope::IdentityManage, StepUp::No).is_ok());
    }

    #[test]
    fn the_legacy_token_is_exempt_from_step_up() {
        // Not because it is trustworthy — because it has no ceremony behind
        // it that could be recent, and it is the credential that rotates
        // itself. Refusing it here would leave no way to retire it.
        let legacy = principal(
            AuthMethod::LegacyManageToken,
            ClientSurface::LegacyManageToken,
            ScopeSet::all(),
            None,
        );
        assert!(legacy.satisfies(Scope::IdentityManage, StepUp::Always).is_ok());
        assert!(legacy
            .satisfies(Scope::SecretsReveal, StepUp::BrowserSession)
            .is_ok());
    }

    #[test]
    fn a_ceremony_exactly_at_the_window_edge_is_stale() {
        let edge = Some(Utc::now() - chrono::Duration::from_std(RECENT_AUTH_WINDOW).unwrap());
        assert!(!web(edge).recently_authenticated());
        let inside = Some(
            Utc::now() - chrono::Duration::from_std(RECENT_AUTH_WINDOW).unwrap()
                + chrono::Duration::seconds(5),
        );
        assert!(web(inside).recently_authenticated());
    }

    #[test]
    fn a_refusal_names_what_the_credential_actually_holds() {
        let pusher = principal(
            AuthMethod::AutomationToken,
            ClientSurface::Automation,
            ScopeSet::cloud_pusher(),
            None,
        );
        assert_eq!(pusher.scope_list(), "cloud:push");
        let empty = principal(
            AuthMethod::AutomationToken,
            ClientSurface::Automation,
            ScopeSet::empty(),
            None,
        );
        assert_eq!(empty.scope_list(), "no scopes");
        assert!(empty.satisfies(Scope::ManageRead, StepUp::No).is_err());
    }

    #[test]
    fn the_audit_actor_is_the_human_not_the_proxy() {
        let mut desktop = desktop(Some(Utc::now()));
        desktop.label = "Raymond's Mac".into();
        let peer: std::net::SocketAddr = "10.0.0.7:44321".parse().unwrap();
        let context = desktop.decision_context(Some(peer));
        assert_eq!(context.approver.as_deref(), Some("Raymond's Mac"));
        assert_eq!(
            context.surface,
            crate::types::DecisionSurface::Remote { peer: Some(peer) }
        );
        assert_eq!(
            desktop.confirmation(),
            crate::types::ConfirmationMethod::Passkey
        );
    }

    #[test]
    fn debug_never_prints_a_credential() {
        let mut legacy = principal(
            AuthMethod::LegacyManageToken,
            ClientSurface::LegacyManageToken,
            ScopeSet::all(),
            None,
        );
        legacy.legacy_token = Some(Zeroizing::new("akamgr_supersecret".into()));
        let text = format!("{legacy:?}");
        assert!(!text.contains("supersecret"), "{text}");
    }
}
