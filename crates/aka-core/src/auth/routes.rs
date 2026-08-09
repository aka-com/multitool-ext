//! The public sign-in surface.
//!
//! Served only on the TCP listener, and only when an operator has configured
//! `--public-url`. The local Unix socket does not carry these routes: reaching
//! it already requires being the broker's own user, so a passkey ceremony
//! there would prove nothing useful.
//!
//! Two audiences share it. A **browser** posts the two ceremonies and gets a
//! session cookie. The **desktop** never touches a ceremony: it opens
//! `/authorize` in the system browser, which is how the same synced passkey
//! that works on the web works there too, and receives an authorization code
//! on a loopback callback that it exchanges here for tokens.
//!
//! The code exchange is PKCE-protected and the redirect target is restricted
//! to a literal loopback address. `localhost` is deliberately not accepted:
//! it resolves through DNS, and a resolver an attacker controls turns "the
//! desktop's callback" into theirs.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use super::store::AuthError;
use super::{ClientSurface, PublicOrigin, RelyingParty, ScopeSet};
use crate::daemon::AppState;

/// The cookie a signed-in browser carries.
pub const SESSION_COOKIE: &str = "aka_session";

/// Where the web UI puts the CSRF secret it read from `GET /v1/auth/session`.
/// A cross-origin page can cause the browser to send the cookie but cannot
/// read the secret to put here — the whole of the double-submit defence.
pub const CSRF_HEADER: &str = "x-multitool-csrf";

/// Clients allowed to run the authorization-code flow, and what each is
/// granted. We refuse an unrecognized `client_id` rather than defaulting it.
const CLIENTS: &[(&str, ClientSurface)] = &[
    ("multitool-desktop", ClientSurface::Desktop),
    ("multitool-cli", ClientSurface::Cli),
];

/* ------------------------------- errors ---------------------------------- */

fn error(status: StatusCode, reason: &str, detail: String) -> Response {
    (status, Json(json!({ "reason": reason, "detail": detail }))).into_response()
}

fn auth_error(error_value: AuthError) -> Response {
    let (status, reason) = match &error_value {
        AuthError::NotEnrolled => (StatusCode::CONFLICT, "not_enrolled"),
        AuthError::EnrollmentRefused => (StatusCode::FORBIDDEN, "enrollment_refused"),
        AuthError::InviteRefused => (StatusCode::FORBIDDEN, "invite_refused"),
        AuthError::Ceremony(_) => (StatusCode::UNAUTHORIZED, "ceremony_failed"),
        AuthError::Invalid(_) => (StatusCode::UNAUTHORIZED, "invalid_credential"),
        AuthError::RefreshReuse => (StatusCode::UNAUTHORIZED, "refresh_token_reused"),
        AuthError::Persist(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    error(status, reason, error_value.detail())
}

/// The relying party, or the reason there isn't one.
// The error is a whole `Response`, which clippy notes is a large Err. That is
// the shape every handler here wants — the refusal is ready to return — and
// boxing it would only move the allocation.
#[allow(clippy::result_large_err)]
fn relying_party(state: &AppState) -> Result<&Arc<RelyingParty>, Response> {
    state.passkeys.as_ref().ok_or_else(|| {
        let detail = state
            .broker
            .public_origin()
            .err()
            .map(|error| error.detail())
            .unwrap_or_else(|| "passkey sign-in is not available here".into());
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "passkeys_unavailable",
            detail,
        )
    })
}

/// The directly-connected peer, when the listener records one.
///
/// Operational provenance only: behind a reverse proxy this is the proxy.
/// It is used to spread the rate limiter's budget, never to authorize.
fn socket_peer(extensions: &axum::http::Extensions) -> Option<std::net::SocketAddr> {
    extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0)
}

/* ------------------------------- cookies --------------------------------- */

/// Read one cookie out of the request.
///
/// Hand-rolled rather than pulling in a cookie crate: this reads exactly one
/// name, and the parsing rule that matters is that a repeated name must not
/// let a second value shadow the first — so the *first* match wins, which is
/// what a browser sends for the most specific path.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

/// Build the session cookie.
///
/// `Secure` is set only for an https origin: a browser discards a `Secure`
/// cookie sent over plain http, so setting it unconditionally would silently
/// break the loopback development origin — the one place plain http is
/// allowed at all.
fn set_cookie(origin: &PublicOrigin, value: &str, max_age: i64) -> String {
    let secure = if origin.as_str().starts_with("https://") {
        " Secure;"
    } else {
        ""
    };
    format!(
        "{SESSION_COOKIE}={value}; Path=/; HttpOnly;{secure} SameSite=Strict; Max-Age={max_age}"
    )
}

fn clear_cookie(origin: &PublicOrigin) -> String {
    set_cookie(origin, "", 0)
}

/// Refuse a state-changing request whose `Origin` is not ours.
///
/// Belt to the CSRF token's braces, and the check that also covers a browser
/// too old for `SameSite`. We refuse a missing `Origin` too: every browser
/// sends it on a cross-origin request, so its absence on a POST means the
/// caller is not the browser this surface is for.
fn same_origin(headers: &HeaderMap, origin: &PublicOrigin) -> Option<Response> {
    let sent = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    match sent {
        Some(sent) if origin.matches(sent) => None,
        _ => Some(error(
            StatusCode::FORBIDDEN,
            "cross_origin",
            format!("this request must come from {origin}"),
        )),
    }
}

/* -------------------------------- router --------------------------------- */

/// The enrollment opener, served on the local socket and nowhere else.
///
/// This is the answer to "who becomes the owner?", and it must not be
/// answerable over the network — otherwise the first stranger to find the URL
/// before the real owner does is the owner. Reaching the Unix socket requires
/// being the broker's own user on the broker's own host, which is the same
/// bar the management bootstrap token already sets, and it is a bar an
/// attacker on the internet cannot clear.
///
/// The mirror image of [`router`]: neither surface is reachable from where
/// the other lives.
pub fn local_router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/auth/enrollment",
            post(open_enrollment).delete(close_enrollment),
        )
        .route(
            "/v1/auth/invites",
            get(list_invites).post(open_invite).delete(cancel_invites),
        )
}

#[derive(serde::Deserialize, Default)]
struct InviteQuery {
    #[serde(default)]
    label: Option<String>,
}

/// Mint a one-use agent-plane invite.
///
/// Socket-only for the same reason enrollment is: minting a credential that
/// hands out the shared key decides who gets to use this broker's
/// connections, so it takes local access to the host rather than a
/// credential someone could carry. Redemption (`POST /v1/join`) is the half
/// that must work over the network.
async fn open_invite(
    State(state): State<AppState>,
    Query(query): Query<InviteQuery>,
) -> Response {
    let label = query
        .label
        .map(|label| label.trim().to_string())
        .filter(|label| !label.is_empty());
    match state.broker.auth.open_invite(label.clone()) {
        Ok(code) => {
            state.broker.audit_sign_in(
                crate::audit::AuditKind::Passkey,
                &match &label {
                    Some(label) => format!("Agent invite created: {label}"),
                    None => "Agent invite created".to_string(),
                },
                "on the broker host",
            );
            let url = state
                .broker
                .public_origin()
                .ok()
                .map(|origin| origin.url(""));
            Json(json!({
                "invite": code.as_str(),
                "public_url": url,
                "expires_in_seconds": 15 * 60,
            }))
            .into_response()
        }
        Err(error_value) => auth_error(error_value),
    }
}

async fn list_invites(State(state): State<AppState>) -> Response {
    let invites: Vec<_> = state
        .broker
        .auth
        .invites()
        .into_iter()
        .map(|(label, created_at, expires_at)| {
            json!({ "label": label, "created_at": created_at, "expires_at": expires_at })
        })
        .collect();
    Json(json!({ "invites": invites })).into_response()
}

async fn cancel_invites(State(state): State<AppState>) -> Response {
    match state.broker.auth.cancel_invites() {
        Ok(cancelled) => Json(json!({ "cancelled": cancelled })).into_response(),
        Err(error_value) => auth_error(error_value),
    }
}

async fn open_enrollment(State(state): State<AppState>) -> Response {
    match state.broker.auth.open_enrollment() {
        Ok(secret) => {
            state.broker.audit_sign_in(
                crate::audit::AuditKind::Passkey,
                "Passkey enrollment opened",
                "on the broker host",
            );
            let url = state
                .broker
                .public_origin()
                .ok()
                .map(|origin| origin.url("/authorize"));
            Json(json!({
                "secret": secret.as_str(),
                "sign_in_url": url,
                "already_enrolled": state.broker.auth.is_enrolled(),
            }))
            .into_response()
        }
        Err(error_value) => auth_error(error_value),
    }
}

async fn close_enrollment(State(state): State<AppState>) -> Response {
    match state.broker.auth.close_enrollment() {
        Ok(()) => Json(json!({ "closed": true })).into_response(),
        Err(error_value) => auth_error(error_value),
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/config", get(config))
        .route("/v1/auth/session", get(session_info))
        .route("/v1/auth/register/options", post(register_options))
        .route("/v1/auth/register", post(register_finish))
        .route("/v1/auth/signin/options", post(signin_options))
        .route("/v1/auth/signin", post(signin_finish))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/authorize", post(authorize_submit))
        .route("/v1/auth/token", post(token))
        .route("/authorize", get(authorize_page))
}

/* ------------------------------ discovery -------------------------------- */

/// What the sign-in page needs to render before anybody has authenticated.
/// Deliberately says nothing about *who* the owner is — only whether this
/// broker has one.
async fn config(State(state): State<AppState>) -> Response {
    let enrolled = state.broker.auth.is_enrolled();
    let origin = state.passkeys.as_ref().map(|rp| rp.origin().as_str());
    Json(json!({
        "enrolled": enrolled,
        "enrollment_open": state.broker.auth.enrollment_open(),
        "origin": origin,
        "passkeys_available": origin.is_some(),
    }))
    .into_response()
}

async fn session_info(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(value) = cookie(&headers, SESSION_COOKIE) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "no_session",
            "not signed in".into(),
        );
    };
    match state.broker.auth.verify_session(&value, None) {
        Ok(verified) => {
            let csrf = state.broker.auth.csrf_for(&verified.credential);
            Json(json!({
                "account": verified.account,
                "session": verified.credential,
                "scopes": verified.scopes,
                "authenticated_at": verified.authenticated_at,
                "csrf": csrf,
            }))
            .into_response()
        }
        Err(error_value) => auth_error(error_value),
    }
}

/* ----------------------------- registration ------------------------------ */

#[derive(Deserialize)]
struct RegisterOptionsBody {
    /// The one-use secret printed on the broker host. Required unless a
    /// signed-in owner is adding another passkey.
    #[serde(default)]
    enrollment_secret: Option<String>,
    /// What to call this authenticator in the list of enrolled passkeys.
    #[serde(default)]
    label: Option<String>,
}

async fn register_options(
    State(state): State<AppState>,
    extensions: axum::http::Extensions,
    headers: HeaderMap,
    Json(body): Json<RegisterOptionsBody>,
) -> Response {
    let peer = socket_peer(&extensions);
    let rp = match relying_party(&state) {
        Ok(rp) => rp,
        Err(response) => return response,
    };
    if let Some(refusal) = same_origin(&headers, rp.origin()) {
        return refusal;
    }
    if let Some(refusal) = limit(&state, peer, "register") {
        return refusal;
    }

    // A signed-in owner may add a passkey without a fresh enrollment secret.
    let signed_in = cookie(&headers, SESSION_COOKIE)
        .and_then(|value| state.broker.auth.verify_session(&value, None).ok());
    let secret = body.enrollment_secret.as_deref();
    if signed_in.is_none() && secret.is_none() {
        return auth_error(AuthError::EnrollmentRefused);
    }

    let account = state.broker.auth.owner();
    let handle = account
        .as_ref()
        .map(|a| a.handle)
        .unwrap_or_else(Uuid::new_v4);
    let display = account
        .as_ref()
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| "Owner".into());
    let exclude = state.broker.auth.passkeys();
    let (challenge, ceremony) = match rp.start_registration(handle, &display, &display, exclude) {
        Ok(pair) => pair,
        Err(error_value) => return auth_error(error_value),
    };
    let label = clean_label(body.label.as_deref(), "Passkey");
    // A signed-in owner passes no secret; the session is the authorization.
    let secret = signed_in.is_none().then_some(secret).flatten();
    match state
        .broker
        .auth
        .begin_registration(ceremony, &label, &display, secret)
    {
        Ok(id) => Json(json!({ "challenge_id": id, "options": challenge })).into_response(),
        Err(error_value) => auth_error(error_value),
    }
}

#[derive(Deserialize)]
struct RegisterFinishBody {
    challenge_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinishBody>,
) -> Response {
    let rp = match relying_party(&state) {
        Ok(rp) => rp,
        Err(response) => return response,
    };
    if let Some(refusal) = same_origin(&headers, rp.origin()) {
        return refusal;
    }
    let (account, label, ceremony) = match state.broker.auth.take_registration(&body.challenge_id) {
        Ok(taken) => taken,
        Err(error_value) => return auth_error(error_value),
    };
    let passkey = match rp.finish_registration(&body.credential, &ceremony) {
        Ok(passkey) => passkey,
        Err(error_value) => return auth_error(error_value),
    };
    let credential = match state
        .broker
        .auth
        .finish_registration(account, label, passkey)
    {
        Ok(credential) => credential,
        Err(error_value) => return auth_error(error_value),
    };
    state.broker.audit_sign_in(
        crate::audit::AuditKind::Passkey,
        "Passkey enrolled",
        &credential.label,
    );

    // Enrolling signs you in: the ceremony just proved the same thing a
    // sign-in would, and making the user immediately do it again proves
    // nothing further.
    open_session(&state, rp.origin(), account, credential.id, "enrolled")
}

/* ---------------------------------- sign-in ------------------------------ */

async fn signin_options(
    State(state): State<AppState>,
    extensions: axum::http::Extensions,
    headers: HeaderMap,
) -> Response {
    let peer = socket_peer(&extensions);
    let rp = match relying_party(&state) {
        Ok(rp) => rp,
        Err(response) => return response,
    };
    if let Some(refusal) = same_origin(&headers, rp.origin()) {
        return refusal;
    }
    if let Some(refusal) = limit(&state, peer, "signin") {
        return refusal;
    }
    let credentials = state.broker.auth.passkeys();
    let (challenge, ceremony) = match rp.start_authentication(&credentials) {
        Ok(pair) => pair,
        Err(error_value) => return auth_error(error_value),
    };
    match state.broker.auth.begin_authentication(ceremony) {
        Ok(id) => Json(json!({ "challenge_id": id, "options": challenge })).into_response(),
        Err(error_value) => auth_error(error_value),
    }
}

#[derive(Deserialize)]
struct SigninFinishBody {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
}

async fn signin_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SigninFinishBody>,
) -> Response {
    let rp = match relying_party(&state) {
        Ok(rp) => rp,
        Err(response) => return response,
    };
    if let Some(refusal) = same_origin(&headers, rp.origin()) {
        return refusal;
    }
    let ceremony = match state.broker.auth.take_authentication(&body.challenge_id) {
        Ok(ceremony) => ceremony,
        Err(error_value) => return auth_error(error_value),
    };
    let assertion = match rp.finish_authentication(&body.credential, &ceremony) {
        Ok(assertion) => assertion,
        Err(error_value) => {
            state.broker.audit_sign_in(
                crate::audit::AuditKind::AuthenticationFailed,
                "Passkey sign-in refused",
                "an assertion did not verify",
            );
            return auth_error(error_value);
        }
    };
    let credential = match state.broker.auth.record_assertion(&assertion) {
        Ok(credential) => credential,
        Err(error_value) => return auth_error(error_value),
    };

    // Signing in again on a live session re-stamps it rather than opening a
    // second: this is also the step-up path, and a step-up must refresh the
    // session the user is already holding.
    if let Some(existing) = cookie(&headers, SESSION_COOKIE)
        .and_then(|value| state.broker.auth.verify_session(&value, None).ok())
    {
        if existing.account == credential.account {
            if let Err(error_value) = state.broker.auth.restamp_session(&existing.credential) {
                return auth_error(error_value);
            }
            state.broker.audit_sign_in(
                crate::audit::AuditKind::Passkey,
                "Passkey confirmed",
                &credential.label,
            );
            return Json(json!({
                "account": credential.account,
                "session": existing.credential,
                "csrf": state.broker.auth.csrf_for(&existing.credential),
                "stepped_up": true,
            }))
            .into_response();
        }
    }
    state.broker.audit_sign_in(
        crate::audit::AuditKind::Passkey,
        "Signed in with a passkey",
        &credential.label,
    );
    open_session(
        &state,
        rp.origin(),
        credential.account,
        credential.id,
        "signed in",
    )
}

fn open_session(
    state: &AppState,
    origin: &PublicOrigin,
    account: Uuid,
    credential: Uuid,
    _how: &str,
) -> Response {
    let issued = match state
        .broker
        .auth
        .create_session(account, credential, ScopeSet::all())
    {
        Ok(issued) => issued,
        Err(error_value) => return auth_error(error_value),
    };
    let max_age = (issued.session.expires_at - issued.session.created_at).num_seconds();
    let mut response = Json(json!({
        "account": account,
        "session": issued.session.id,
        "csrf": issued.csrf.as_str(),
        "expires_at": issued.session.expires_at,
    }))
    .into_response();
    if let Ok(value) =
        axum::http::HeaderValue::from_str(&set_cookie(origin, issued.cookie.as_str(), max_age))
    {
        response
            .headers_mut()
            .insert(axum::http::header::SET_COOKIE, value);
    }
    response
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rp = match relying_party(&state) {
        Ok(rp) => rp,
        Err(response) => return response,
    };
    if let Some(refusal) = same_origin(&headers, rp.origin()) {
        return refusal;
    }
    // Deliberately does not require the CSRF token. A forged sign-out is a
    // nuisance, not a compromise, and refusing one would leave a user whose
    // token is stale unable to sign out at all.
    if let Some(value) = cookie(&headers, SESSION_COOKIE) {
        if let Ok(verified) = state.broker.auth.verify_session(&value, None) {
            let _ = state.broker.auth.revoke_session(&verified.credential);
        }
    }
    let mut response = Json(json!({ "signed_out": true })).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&clear_cookie(rp.origin())) {
        response
            .headers_mut()
            .insert(axum::http::header::SET_COOKIE, value);
    }
    response
}

/* ------------------------- the desktop handshake ------------------------- */

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: String,
    /// What to call this device in the list of authorized ones.
    #[serde(default)]
    device_name: Option<String>,
}

/// Validate the authorization request before any of it is shown to a user.
///
/// Everything here is a refusal. The redirect target especially: a code is a
/// bearer credential for the token exchange, and the only thing standing
/// between it and an attacker is where the browser is willing to send it.
fn check_authorize(params: &AuthorizeParams) -> Result<ClientSurface, String> {
    let Some((_, surface)) = CLIENTS.iter().find(|(id, _)| *id == params.client_id) else {
        return Err(format!("unknown client {:?}", params.client_id));
    };
    if params.code_challenge_method != "S256" {
        return Err("PKCE must use S256; plain is not accepted".into());
    }
    // base64url of a SHA-256 digest, unpadded.
    let well_formed = params.code_challenge.len() == 43
        && params
            .code_challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !well_formed {
        return Err("the PKCE challenge is not a base64url SHA-256 digest".into());
    }
    if params.state.is_empty() || params.state.len() > 256 {
        return Err("the state parameter is missing or too long".into());
    }
    check_redirect(&params.redirect_uri)?;
    Ok(*surface)
}

/// Only a literal loopback address, only http, and no query or fragment.
///
/// We refuse `localhost` on purpose. It is a name, names resolve, and a
/// resolver an attacker influences — a hosts file, a captive portal, DNS on a
/// shared network — turns the desktop's private callback into a public one.
/// Literal loopback addresses cannot be redirected that way.
fn check_redirect(redirect: &str) -> Result<(), String> {
    let url: url::Url = redirect
        .parse()
        .map_err(|_| "the redirect URI is not a URL".to_string())?;
    if url.scheme() != "http" {
        return Err("the redirect URI must be http on loopback".into());
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        // Including "localhost": see above.
        _ => false,
    };
    if !loopback {
        return Err(
            "the redirect URI must be a loopback address (127.0.0.1 or [::1]), \
                    not a hostname"
                .into(),
        );
    }
    if url.port().is_none() {
        return Err("the redirect URI must name the callback's port".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("the redirect URI must not carry a query or fragment".into());
    }
    Ok(())
}

/// The page the desktop opens in the system browser.
///
/// Served as one self-contained document with no external references, so the
/// content-security policy can forbid every remote origin outright. It signs
/// the user in if they are not already, then asks them to confirm the device.
async fn authorize_page(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let rp = match relying_party(&state) {
        Ok(rp) => rp,
        Err(response) => return response,
    };
    if let Err(detail) = check_authorize(&params) {
        let nonce = nonce();
        return html(
            StatusCode::BAD_REQUEST,
            page(
                &format!(
                    "<h1>This sign-in link is not valid</h1><p class=detail>{}</p>",
                    escape(&detail)
                ),
                &nonce,
            ),
            &nonce,
        );
    }
    if !state.broker.auth.is_enrolled() {
        let nonce = nonce();
        return html(
            StatusCode::CONFLICT,
            page(
                "<h1>No passkey is enrolled</h1><p class=detail>Run \
                 <code>aka admin enroll</code> on the broker host, then \
                 open the link it prints.</p>",
                &nonce,
            ),
            &nonce,
        );
    }
    let device = clean_label(params.device_name.as_deref(), "This device");
    let nonce = nonce();
    let body = include_str!("authorize.html")
        .replace("__ORIGIN__", &escape(rp.origin().as_str()))
        .replace("__DEVICE__", &escape(&device))
        .replace("__PARAMS__", &json_script(&params))
        .replace("__NONCE__", &nonce);
    html(StatusCode::OK, page(&body, &nonce), &nonce)
}

#[derive(Deserialize)]
struct AuthorizeSubmit {
    #[serde(flatten)]
    params: AuthorizeParams,
}

/// Mint the code, once the browser session exists and the user has confirmed.
async fn authorize_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AuthorizeSubmit>,
) -> Response {
    let rp = match relying_party(&state) {
        Ok(rp) => rp,
        Err(response) => return response,
    };
    if let Some(refusal) = same_origin(&headers, rp.origin()) {
        return refusal;
    }
    let surface = match check_authorize(&body.params) {
        Ok(surface) => surface,
        Err(detail) => return error(StatusCode::BAD_REQUEST, "invalid_request", detail),
    };
    let Some(value) = cookie(&headers, SESSION_COOKIE) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "no_session",
            "sign in before authorizing a device".into(),
        );
    };
    let csrf = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    let verified = match state
        .broker
        .auth
        .verify_session(&value, Some(csrf.unwrap_or_default()))
    {
        Ok(verified) => verified,
        Err(error_value) => return auth_error(error_value),
    };
    // Authorizing a device is an `identity:manage` act with `Always` step-up:
    // the session must be freshly authenticated, not merely live.
    let fresh = verified.authenticated_at.is_some_and(|at| {
        chrono::Utc::now() - at
            < chrono::Duration::from_std(super::RECENT_AUTH_WINDOW).unwrap_or_default()
    });
    if !fresh {
        return error(
            StatusCode::UNAUTHORIZED,
            "step_up_required",
            "confirm with your passkey before authorizing a device".into(),
        );
    }

    let device = clean_label(body.params.device_name.as_deref(), "This device");
    let code = match state.broker.auth.mint_code(
        verified.account,
        verified.credential,
        &device,
        surface,
        ScopeSet::desktop(),
        &body.params.code_challenge,
        &body.params.redirect_uri,
        verified.authenticated_at.unwrap_or_else(chrono::Utc::now),
    ) {
        Ok(code) => code,
        Err(error_value) => return auth_error(error_value),
    };
    state.broker.audit_sign_in(
        crate::audit::AuditKind::DeviceGrant,
        "Device authorized",
        &device,
    );

    // The state is echoed exactly as sent; the desktop compares it to what it
    // generated, which is what ties this response to its own request.
    let redirect = format!(
        "{}?code={}&state={}",
        body.params.redirect_uri,
        urlencode(code.as_str()),
        urlencode(&body.params.state)
    );
    Json(json!({ "redirect": redirect })).into_response()
}

/* -------------------------------- tokens --------------------------------- */

#[derive(Deserialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
enum TokenRequest {
    AuthorizationCode {
        code: String,
        code_verifier: String,
        redirect_uri: String,
        client_id: String,
    },
    RefreshToken {
        refresh_token: String,
    },
}

/// The one endpoint the desktop talks to without a browser.
///
/// No `Origin` check and no cookie: this is not a browser surface. What
/// authorizes it is possession of a code plus the verifier that produced its
/// challenge, or of the current refresh token.
async fn token(
    State(state): State<AppState>,
    extensions: axum::http::Extensions,
    body: String,
) -> Response {
    let peer = socket_peer(&extensions);
    if let Some(refusal) = limit(&state, peer, "token") {
        return refusal;
    }
    let request: TokenRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(error_value) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                error_value.to_string(),
            )
        }
    };
    let issued = match request {
        TokenRequest::AuthorizationCode {
            code,
            code_verifier,
            redirect_uri,
            client_id,
        } => {
            if !CLIENTS.iter().any(|(id, _)| *id == client_id) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client",
                    format!("unknown client {client_id:?}"),
                );
            }
            match state
                .broker
                .auth
                .redeem_code(&code, &code_verifier, &redirect_uri)
                .and_then(|device| state.broker.auth.issue_for_device(device))
            {
                Ok(issued) => issued,
                Err(error_value) => return auth_error(error_value),
            }
        }
        TokenRequest::RefreshToken { refresh_token } => {
            match state.broker.auth.refresh_device(&refresh_token) {
                Ok(issued) => issued,
                Err(error_value) => return auth_error(error_value),
            }
        }
    };
    let expires_in = (issued.access_expires_at - chrono::Utc::now())
        .num_seconds()
        .max(0);
    Json(json!({
        "access_token": issued.access.as_str(),
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": issued.refresh.as_str(),
        "scope": issued.scopes,
        "device_id": issued.device,
        "device_name": issued.device_name,
    }))
    .into_response()
}

/* -------------------------------- helpers -------------------------------- */

/// Rate-limit by peer, reusing the broker's existing manage-auth limiter
/// budget. Ceremonies are cheap for a browser and expensive for a guesser.
fn limit(state: &AppState, peer: Option<std::net::SocketAddr>, bucket: &str) -> Option<Response> {
    // Keyed by peer, not by bucket alone. A single shared counter would let
    // one caller — deliberately or by looping on a failure — spend the
    // budget for everybody, turning a rate limit into an outage. Behind a
    // reverse proxy every request shares the proxy's address, which is a
    // known limitation of counting at this layer rather than a reason to
    // count globally instead.
    let source = peer
        .map(|peer| peer.ip().to_string())
        .unwrap_or_else(|| state.transport.audit_label().to_string());
    match state
        .broker
        .manage_auth_limiter
        .check(&format!("auth:{bucket}:{source}"))
    {
        Ok(()) => None,
        Err(wait) => Some(crate::daemon::err_rate_limited(
            crate::wire::ErrorReason::RateLimited,
            wait,
        )),
    }
}

/// A user-supplied label, made safe to store and to render.
fn clean_label(label: Option<&str>, fallback: &str) -> String {
    let cleaned = label
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(|label| crate::untrusted_text::cap(label, 64))
        .unwrap_or_default();
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Serialize for embedding inside `<script type="application/json">`.
///
/// HTML escaping would be *wrong* here and not merely unnecessary: the
/// contents of a script element are raw text, so entities are never decoded
/// and `&quot;` would reach `JSON.parse` verbatim. What the context actually
/// requires is that no `<` appears, since `</script` ends the element
/// wherever it occurs — including inside a JSON string. `<` is valid
/// JSON for the same character and cannot close anything.
fn json_script<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "{}".into())
        .replace('<', "\\u003c")
}

fn urlencode(text: &str) -> String {
    percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// A one-use nonce for this response's inline script and style.
///
/// The alternative is `'unsafe-inline'`, which would also permit any script
/// an injection managed to get onto the page — on the two pages where a
/// passkey ceremony runs. A nonce permits exactly the markup this handler
/// emitted.
fn nonce() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("os rng");
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(buf)
}

/// Wrap page content in the shared shell, binding both to one nonce.
fn page(body: &str, nonce: &str) -> String {
    include_str!("page.html")
        .replace("<!--BODY-->", body)
        .replace("__NONCE__", nonce)
}

/// An HTML response whose CSP names the nonce its own markup carries.
///
/// Set here rather than in the daemon's blanket layer because the value is
/// per-response; the layer fills in the default for everything else.
fn html(status: StatusCode, body: String, nonce: &str) -> Response {
    let mut response = (status, Html(body)).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
         img-src 'self' data:; connect-src 'self'; form-action 'none'; \
         base-uri 'none'; frame-ancestors 'none'"
    )) {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static("content-security-policy"),
            value,
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> AuthorizeParams {
        AuthorizeParams {
            client_id: "multitool-desktop".into(),
            redirect_uri: "http://127.0.0.1:51234/callback".into(),
            // 43 base64url characters.
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            code_challenge_method: "S256".into(),
            state: "opaque-state".into(),
            device_name: Some("Raymond's Mac".into()),
        }
    }

    #[test]
    fn a_well_formed_desktop_request_is_accepted() {
        assert_eq!(check_authorize(&params()).unwrap(), ClientSurface::Desktop);
    }

    #[test]
    fn an_unknown_client_is_refused() {
        let mut params = params();
        params.client_id = "someone-elses-app".into();
        assert!(check_authorize(&params).is_err());
    }

    #[test]
    fn plain_pkce_is_refused() {
        let mut params = params();
        params.code_challenge_method = "plain".into();
        assert!(check_authorize(&params).is_err());
        // A challenge that is the verifier, which is what "plain" means.
        params.code_challenge_method = "S256".into();
        params.code_challenge = "short".into();
        assert!(check_authorize(&params).is_err());
    }

    #[test]
    fn a_missing_state_is_refused() {
        let mut params = params();
        params.state = String::new();
        assert!(check_authorize(&params).is_err());
    }

    #[test]
    fn only_literal_loopback_addresses_may_receive_a_code() {
        assert!(check_redirect("http://127.0.0.1:51234/callback").is_ok());
        assert!(check_redirect("http://[::1]:51234/callback").is_ok());

        // A name resolves, and a resolver can be influenced.
        assert!(check_redirect("http://localhost:51234/callback").is_err());
        // Anything off the machine.
        assert!(check_redirect("http://broker.example/callback").is_err());
        assert!(check_redirect("https://evil.test/callback").is_err());
        assert!(check_redirect("http://10.0.0.5:51234/callback").is_err());
        // A scheme that could hand the code to another app.
        assert!(check_redirect("multitool://callback").is_err());
        assert!(check_redirect("javascript:alert(1)").is_err());
        // No port means no way to know which listener gets it.
        assert!(check_redirect("http://127.0.0.1/callback").is_err());
        // A query would let the caller smuggle a second `code` parameter.
        assert!(check_redirect("http://127.0.0.1:51234/cb?code=x").is_err());
        assert!(check_redirect("http://127.0.0.1:51234/cb#x").is_err());
    }

    #[test]
    fn a_decimal_or_octal_loopback_literal_is_still_loopback() {
        // 2130706433 == 127.0.0.1. `url` normalizes these, and they are
        // genuinely the same address, so accepting them is correct.
        assert!(check_redirect("http://2130706433:51234/cb").is_ok());
    }

    #[test]
    fn the_session_cookie_is_read_by_exact_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "other=1; aka_session=akases_abc; aka_session_x=nope"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            cookie(&headers, SESSION_COOKIE).as_deref(),
            Some("akases_abc")
        );
        assert_eq!(cookie(&headers, "missing"), None);
    }

    #[test]
    fn a_shadowing_second_cookie_does_not_win() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "aka_session=real; aka_session=forged".parse().unwrap(),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("real"));
    }

    #[test]
    fn the_cookie_is_http_only_and_strict_and_secure_on_https() {
        let https =
            PublicOrigin::from_configured_public_url(Some("https://broker.example")).unwrap();
        let value = set_cookie(&https, "akases_abc", 3600);
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("Secure"));
        assert!(value.contains("SameSite=Strict"));
        assert!(value.contains("Path=/"));
    }

    #[test]
    fn the_loopback_origin_does_not_set_secure() {
        // A browser discards a Secure cookie sent over plain http, so setting
        // it here would break the one origin where plain http is allowed.
        let http = PublicOrigin::from_configured_public_url(Some("http://localhost:4780")).unwrap();
        let value = set_cookie(&http, "akases_abc", 3600);
        assert!(!value.contains("Secure"));
        assert!(value.contains("HttpOnly"));
    }

    #[test]
    fn only_our_own_origin_may_post() {
        let origin =
            PublicOrigin::from_configured_public_url(Some("https://broker.example")).unwrap();
        let with = |value: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(value) = value {
                headers.insert(axum::http::header::ORIGIN, value.parse().unwrap());
            }
            same_origin(&headers, &origin).is_none()
        };
        assert!(with(Some("https://broker.example")));
        assert!(!with(Some("https://evil.test")));
        assert!(!with(Some("https://broker.example.evil.test")));
        assert!(!with(Some("null")));
        // Absent is refused: a browser always sends it cross-origin, so its
        // absence on a POST means this is not the browser surface.
        assert!(!with(None));
    }

    #[test]
    fn labels_are_sanitized_and_defaulted() {
        assert_eq!(clean_label(None, "This device"), "This device");
        assert_eq!(clean_label(Some("   "), "This device"), "This device");
        assert_eq!(clean_label(Some("  Work Mac "), "x"), "Work Mac");
        // Nothing a label carries may break out of where it is rendered.
        let nasty = clean_label(Some("<script>alert(1)</script>"), "x");
        assert!(!escape(&nasty).contains("<script"));
    }

    #[test]
    fn escaping_covers_every_html_context_a_label_reaches() {
        assert_eq!(
            escape(r#"<a href="x" onclick='y'>&</a>"#),
            "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
        );
    }
}
