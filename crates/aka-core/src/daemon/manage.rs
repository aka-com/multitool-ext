//! The manage plane: the desktop shell's HTTP surface onto a broker.
//!
//! Routes mirror the [`ManagementBackend`] trait one-to-one; the handlers
//! drive a [`LocalBackend`] so a remote shell exercises exactly the code
//! path an in-process shell does. Authorization is the management token
//! (`akamgr_…`) — a credential distinct from the agent key, closed until
//! `aka manage token` issues one. Agent keys never authenticate here and
//! the manage token never authenticates the agent plane.
//!
//! Failures cross the wire as the `aka-api` [`ManageError`] serialization,
//! so a remote shell reconstructs the same structured error an in-process
//! shell receives; the HTTP status is a coarse hint for humans and curl.

use std::convert::Infallible;

use aka_api::{ManageError, ManageEvent};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::principal::ManagePrincipal;
use super::{ApiJson, AppState};
use crate::manage::{
    AccessBody, AllowedToolsBody, ApprovalResponseBody, AuditStatementsBody, ConfirmBody,
    ConnectionAddBody, ConnectionConfigPatchBody, ConnectionRenameBody, ConnectionUpdateBody,
    ConnectionsReorderBody, DraftTestBody, ElicitationResponseBody, EndpointExpiryBody,
    EndpointRequireAuthBody, ManagementBackend, McpAuthDeliverBody, McpAuthStartBody,
    OAuthCompleteBody, OAuthReconnectBody, OAuthStartBody, OnePasswordIntegrationAddBody,
    OnePasswordSecretAddBody, OnePasswordTokenBody, ResponseCredentialsBody, SecretAddBody,
    SecretEditBody, SettingsPatchBody,
};

fn manage_error_response(error: ManageError) -> Response {
    let status = match &error {
        ManageError::SecretNotFound
        | ManageError::ConnectionNotFound
        | ManageError::EndpointNotFound => StatusCode::NOT_FOUND,
        ManageError::EndpointExpired => StatusCode::GONE,
        ManageError::SecretNameTaken { .. }
        | ManageError::ConnectionNameTaken { .. }
        | ManageError::ConnectionTargetTaken { .. }
        | ManageError::ConnectionChanged
        | ManageError::ApprovalConnectionChanged
        | ManageError::SecretInUse { .. }
        | ManageError::KindChange
        | ManageError::EndpointLimit { .. }
        | ManageError::EndpointRequiresWiring => StatusCode::CONFLICT,
        ManageError::InvalidSecretName { .. }
        | ManageError::InvalidSite { .. }
        | ManageError::InvalidTotpSeed { .. }
        | ManageError::TotpNotConfigured
        | ManageError::NotAPassword
        | ManageError::InvalidConnectionName { .. }
        | ManageError::Template { .. }
        | ManageError::UnknownTemplateRef { .. }
        | ManageError::WrongSecretCount { .. }
        | ManageError::InvalidConnectionConfig { .. }
        | ManageError::InvalidSetting { .. }
        | ManageError::InvalidConnectionField { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        ManageError::RemoteUnsupported { .. } => StatusCode::NOT_IMPLEMENTED,
        ManageError::InvalidManageToken { .. } => StatusCode::UNAUTHORIZED,
        ManageError::Unreachable { .. } => StatusCode::BAD_GATEWAY,
        ManageError::OnePassword { provider_code, .. }
            if matches!(
                provider_code.as_str(),
                "integration_not_found" | "not_found"
            ) =>
        {
            StatusCode::NOT_FOUND
        }
        ManageError::OnePassword { provider_code, .. } if provider_code == "integration_in_use" => {
            StatusCode::CONFLICT
        }
        ManageError::OnePassword { provider_code, .. }
            if matches!(
                provider_code.as_str(),
                "invalid_configuration" | "invalid_request" | "linked_secret_read_only"
            ) =>
        {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        ManageError::OnePassword { provider_code, .. } if provider_code == "rate_limited" => {
            StatusCode::TOO_MANY_REQUESTS
        }
        ManageError::OnePassword { .. } => StatusCode::BAD_GATEWAY,
        ManageError::OAuth { .. } | ManageError::Vault { .. } | ManageError::Internal { .. } => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (status, Json(error)).into_response()
}

fn ok<T: serde::Serialize>(value: T) -> Response {
    Json(value).into_response()
}

fn respond<T: serde::Serialize>(result: Result<T, ManageError>) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => manage_error_response(error),
    }
}

/// The manage router, nested at `/v1/manage` by the daemon.
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/whoami", get(whoami))
        .route(
            "/management-token",
            post(rotate_management_token).delete(revoke_management_token),
        )
        .route("/events", get(events))
        .route("/approval-surfaces", post(create_approval_surface))
        .route(
            "/approval-surfaces/{id}",
            put(heartbeat_approval_surface).delete(release_approval_surface),
        )
        .route("/secrets", get(list_secrets).post(add_secret))
        .route("/secrets/{id}", patch(edit_secret).delete(delete_secret))
        .route("/secrets/{id}/reveal", post(reveal_secret))
        // POST: issuing a code is audited, so the route is not a safe GET.
        .route("/secrets/{id}/totp", post(secret_totp_code))
        .route("/secrets/{id}/copy-value", post(secret_value_for_copy))
        .route(
            "/integrations",
            get(list_onepassword_integrations).post(add_onepassword_integration),
        )
        .route(
            "/integrations/onepassword/secrets",
            post(add_onepassword_secret),
        )
        .route("/integrations/{id}", delete(delete_onepassword_integration))
        .route("/integrations/{id}/token", put(replace_onepassword_token))
        .route("/integrations/{id}/health", get(onepassword_health))
        .route("/integrations/{id}/vaults", get(onepassword_vaults))
        .route(
            "/integrations/{id}/vaults/{vault_id}/items",
            get(onepassword_items),
        )
        .route(
            "/integrations/{id}/vaults/{vault_id}/items/{item_id}/fields",
            get(onepassword_fields),
        )
        .route("/connections", get(list_connections).post(add_connection))
        .route("/connections/test-draft", post(test_connection_draft))
        .route("/connections/reorder", post(reorder_connections))
        .route(
            "/connections/{id}",
            put(update_connection)
                .patch(rename_connection)
                .delete(delete_connection),
        )
        .route("/connections/{id}/config", patch(patch_connection))
        .route("/connections/{id}/test", post(test_connection))
        .route("/connections/{id}/access", post(set_tool_access))
        .route("/connections/{id}/confirm", post(set_confirm_mode))
        .route(
            "/connections/{id}/response-credentials",
            post(set_expose_response_credentials),
        )
        .route("/connections/{id}/allowed-tools", post(set_allowed_tools))
        .route(
            "/connections/{id}/audit-statements",
            post(set_audit_statements),
        )
        .route("/connections/{id}/mcp-tools", get(list_mcp_tools))
        .route("/connections/{id}/mcp-status", post(mcp_status))
        .route(
            "/connections/{id}/endpoint",
            post(issue_endpoint).get(get_endpoint),
        )
        .route("/connections/{id}/endpoint/copy", post(copy_endpoint))
        .route("/connections/{id}/endpoint/renew", post(renew_endpoint))
        .route(
            "/connections/{id}/endpoint/expiry",
            post(set_endpoint_expiry),
        )
        .route(
            "/connections/{id}/endpoint/require-auth",
            post(set_endpoint_require_auth),
        )
        .route("/endpoints/{id}", delete(revoke_endpoint))
        .route("/mcp-auth", post(mcp_auth_start))
        .route(
            "/mcp-auth/{id}",
            get(mcp_auth_state).delete(mcp_auth_cancel),
        )
        .route("/mcp-auth/{id}/deliver", post(mcp_auth_deliver))
        .route("/oauth/start", post(oauth_start))
        .route("/oauth/reconnect/{id}", post(oauth_reconnect_start))
        .route("/oauth/complete/{id}", post(oauth_complete))
        .route("/identity", get(identity))
        .route("/identity/agent-key", get(agent_key))
        .route("/identity/rotate", post(rotate_key))
        .route("/approvals", get(approvals))
        .route("/approvals/snapshot", get(approval_snapshot))
        .route("/approvals/{id}", post(respond_approval))
        .route("/elicitations", get(elicitations))
        .route("/elicitations/{id}", post(respond_elicitation))
        .route("/requests", get(requests))
        .route("/sessions", get(sessions))
        .route("/sessions/{id}", delete(close_session))
        .route("/activity", get(activity).delete(clear_activity))
        .route("/cloud/session", post(push_cloud_session))
        .route("/cloud/pushable", post(pushable_connections))
        .route("/activity/page", get(activity_page))
        .route("/settings", get(settings).patch(patch_settings))
        .route("/agent-setup", get(agent_setup))
        // Who can sign in, and on what. Kept on the manage plane rather than
        // beside the ceremonies: these are management operations, they need
        // `identity:manage`, and putting them here means one authorization
        // path to the data instead of two.
        .route("/auth/whoami", get(auth_whoami))
        .route("/auth/passkeys", get(list_passkeys))
        .route("/auth/passkeys/{id}", delete(remove_passkey))
        .route("/auth/sessions", get(list_browser_sessions))
        .route("/auth/sessions/{id}", delete(revoke_browser_session))
        .route("/auth/devices", get(list_devices))
        .route(
            "/auth/devices/{id}",
            patch(rename_device).delete(revoke_device),
        )
        .route("/auth/tokens", get(list_automation).post(mint_automation))
        .route("/auth/tokens/{id}", delete(revoke_automation))
        // One layer authenticates and authorizes every route above, and
        // scopes the deciding actor across the handler so the activity log
        // records who acted rather than which proxy forwarded them. No
        // handler repeats the check; none can forget it.
        .layer(axum::middleware::from_fn_with_state(
            state,
            super::principal::require_principal,
        ))
}

async fn whoami(State(state): State<AppState>) -> Response {
    ok(json!({
        "ok": true,
        "version": state.broker.config.version,
        "client_id": state.broker.identity.client_id(&state.broker.workspace),
        "capabilities": [
            aka_api::APPROVAL_SURFACE_CAPABILITY,
            aka_api::ONEPASSWORD_PROVIDER_CAPABILITY,
            aka_api::TYPED_CREDENTIALS_CAPABILITY,
            aka_api::PASSKEY_AUTH_CAPABILITY,
        ],
        "approval_surface_attached": state.broker.events.has_approval_surface(),
    }))
}

#[derive(serde::Deserialize)]
struct RotateManagementTokenBody {
    ttl_days: u64,
}

fn token_mutation_error(error: crate::identity::ManageTokenMutationError) -> Response {
    match error {
        crate::identity::ManageTokenMutationError::Unauthorized(error) => {
            let detail = if error == crate::identity::TokenError::Expired {
                "the management token expired before it could authorize rotation"
            } else {
                "the management token was rotated or revoked before this request completed"
            };
            manage_error_response(ManageError::InvalidManageToken {
                detail: Some(detail.into()),
            })
        }
        crate::identity::ManageTokenMutationError::Persist(error) => {
            manage_error_response(ManageError::from(error))
        }
    }
}

/// Rotate only under authority of the still-current management token. The
/// identity store performs the second verification and mutation under one
/// lock, closing the extractor-to-handler race between concurrent rotations.
async fn rotate_management_token(
    State(state): State<AppState>,
    principal: ManagePrincipal,
    ApiJson(body): ApiJson<RotateManagementTokenBody>,
) -> Response {
    if !(1..=3650).contains(&body.ttl_days) {
        return manage_error_response(ManageError::InvalidSetting {
            message: "management-token TTL must be between 1 and 3650 days".into(),
        });
    }
    let ttl = std::time::Duration::from_secs(body.ttl_days * 86_400);
    // Rotating *with* the current token is the race-free path: the identity
    // store re-verifies and mutates under one lock, so two concurrent
    // rotations cannot both win. A passkey principal has no such token to
    // present — its authority came from a ceremony the layer already
    // checked, and it reached this route only by holding `identity:manage`
    // with a fresh step-up.
    let rotated = match principal.legacy_token() {
        Some(current) => {
            state
                .broker
                .identity
                .rotate_manage_token_with_ttl(&state.broker.workspace, current, Some(ttl))
                .await
        }
        None => state
            .broker
            .identity
            .issue_manage_token_with_ttl(&state.broker.workspace, Some(ttl))
            .await
            .map_err(crate::identity::ManageTokenMutationError::Persist),
    };
    match rotated {
        Ok(token) => {
            if let Err(error) = state.broker.paths.remove_manage_bootstrap_token() {
                tracing::warn!("could not remove consumed management bootstrap token: {error}");
            }
            let expires_at = state
                .broker
                .identity
                .manage_token_expires_at(&state.broker.workspace)
                .expect("online rotations always carry a TTL");
            let mut entry = crate::audit::AuditEntry::new(
                crate::audit::AuditKind::ManagementTokenIssued,
                "Management token rotated online",
            )
            .outcome("rotated")
            .field("expires_at", expires_at.to_rfc3339())
            .confirmation(principal.confirmation());
            if let Some(context) = crate::audit::current_decision_context() {
                entry = entry.context(&context);
            }
            state.broker.audit.append(entry);
            ok(json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            }))
        }
        Err(error) => token_mutation_error(error),
    }
}

async fn revoke_management_token(
    State(state): State<AppState>,
    principal: ManagePrincipal,
) -> Response {
    let revoked = match principal.legacy_token() {
        Some(current) => {
            state
                .broker
                .identity
                .revoke_manage_token_with_token(&state.broker.workspace, current)
                .await
        }
        // A passkey holder closing the manage API they are not using.
        None => state
            .broker
            .identity
            .revoke_manage_token(&state.broker.workspace)
            .await
            .map(|_| ())
            .map_err(crate::identity::ManageTokenMutationError::Persist),
    };
    match revoked {
        Ok(()) => {
            if let Err(error) = state.broker.paths.remove_manage_bootstrap_token() {
                tracing::warn!("could not remove consumed management bootstrap token: {error}");
            }
            let mut entry = crate::audit::AuditEntry::new(
                crate::audit::AuditKind::ManagementTokenRevoked,
                "Management token revoked online",
            )
            .outcome("revoked")
            .confirmation(principal.confirmation());
            if let Some(context) = crate::audit::current_decision_context() {
                entry = entry.context(&context);
            }
            state.broker.audit.append(entry);
            ok(json!({ "revoked": true }))
        }
        Err(error) => token_mutation_error(error),
    }
}

async fn create_approval_surface(State(state): State<AppState>) -> Response {
    let id = state.broker.manage_bus().mint_polling_approval_surface();
    ok(serde_json::to_value(aka_api::ApprovalSurfaceDto {
        id: id.to_string(),
        expires_in_ms: aka_api::APPROVAL_SURFACE_TTL_MS,
    })
    .expect("approval surface DTO serializes"))
}

/// Renew a capability minted for an attached event-stream or polling inbox.
/// Heartbeats cannot create capabilities: a released or unknown id fails
/// closed.
async fn heartbeat_approval_surface(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    if state.broker.manage_bus().renew_approval_surface(&id) {
        ok(json!({
            "expires_in_ms": aka_api::APPROVAL_SURFACE_TTL_MS,
        }))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "reason": "approval_surface_not_attached" })),
        )
            .into_response()
    }
}

async fn release_approval_surface(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    ok(json!({
        "released": state.broker.manage_bus().release_approval_surface(&id),
    }))
}

/// The SSE change feed with reconnect resume. Each frame carries an
/// `id: <epoch>:<seq>`; a client reconnecting with `Last-Event-ID` is sent
/// only the events it missed (or a single `resync` when its position is
/// unknown, foreign to this broker process, or has aged out of the buffer).
/// Live delivery still emits `resync` on broadcast lag.
async fn events(
    State(state): State<AppState>,
    principal: ManagePrincipal,
    headers: axum::http::HeaderMap,
) -> Response {
    use crate::manage::{parse_event_id, ManageReplay, SeqEvent};

    let bus = state.broker.manage_bus().clone();
    let approval_surface = headers
        .get(aka_api::APPROVAL_SURFACE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| *value == aka_api::APPROVAL_SURFACE_V1)
        .map(|_| bus.lease_approval_surface());
    let mut response_headers = axum::http::HeaderMap::new();
    // Nginx otherwise commonly buffers tiny SSE frames, which would leave a
    // desktop heartbeating a stream whose approval events it cannot see.
    response_headers.insert(
        axum::http::HeaderName::from_static("x-accel-buffering"),
        axum::http::HeaderValue::from_static("no"),
    );
    response_headers.insert(
        aka_api::APPROVAL_SURFACE_STATUS_HEADER,
        axum::http::HeaderValue::from_static(if approval_surface.is_some() {
            aka_api::APPROVAL_SURFACE_STATUS_ACTIVE
        } else {
            aka_api::APPROVAL_SURFACE_STATUS_OBSERVER
        }),
    );
    if let Some(surface) = &approval_surface {
        response_headers.insert(
            aka_api::APPROVAL_SURFACE_ID_HEADER,
            axum::http::HeaderValue::from_str(&surface.id().to_string())
                .expect("UUID is a header-safe value"),
        );
    }
    // Subscribe *before* asking for replay so nothing slips through the gap
    // between the ring snapshot and going live; live events at or below the
    // replayed head are then deduped by seq.
    let rx = bus.subscribe();
    let last = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let parsed = last.as_deref().and_then(parse_event_id);

    let epoch = bus.epoch().to_string();
    let mut backlog: std::collections::VecDeque<SeqEvent> = std::collections::VecDeque::new();
    let mut delivered_head = parsed.map(|(_, seq)| seq).unwrap_or(0);
    let mut resync_first = false;
    match bus.replay_since(parsed) {
        ManageReplay::Replay(events) => {
            delivered_head = events.last().map(|e| e.seq).unwrap_or(delivered_head);
            backlog.extend(events);
        }
        ManageReplay::UpToDate => {}
        ManageReplay::Resync => {
            resync_first = true;
            // The client's position is meaningless here (fresh, foreign
            // epoch, or aged out), so it must not become the live-dedupe
            // baseline: a foreign id whose seq is *above* this process's
            // head would otherwise swallow every live event after the
            // resync — and the resync frame would teach the client that
            // same poisoned position back. Baseline on this process's own
            // head instead; anything at or below it is covered by the
            // refetch the resync triggers.
            delivered_head = bus.head_seq();
        }
    }

    struct StreamState {
        rx: tokio::sync::broadcast::Receiver<SeqEvent>,
        backlog: std::collections::VecDeque<SeqEvent>,
        epoch: String,
        // Whatever credential opened this stream, re-checked on a timer and
        // before every frame. This is what binds the approval-surface lease
        // below to its principal: revoking the session, the device, or the
        // management token ends the stream, and the lease's Drop releases
        // the capability with it.
        revalidate_credential: super::principal::Revalidator,
        // Present only when the authenticated client explicitly promised a
        // user-facing request inbox. Its Drop releases capability as soon as
        // the response stream goes away.
        _approval_surface: Option<crate::manage::ApprovalSurfaceLease>,
        revalidate: tokio::time::Interval,
        // Highest seq already sent, so a live event the backlog covered is
        // not sent twice.
        delivered_head: u64,
        // An immediate comment proves the response body is not being
        // buffered before the desktop activates its capability lease.
        ready_first: bool,
        resync_first: bool,
    }
    let init = StreamState {
        rx,
        backlog,
        epoch,
        revalidate_credential: principal.revalidator(),
        _approval_surface: approval_surface,
        revalidate: tokio::time::interval(std::time::Duration::from_secs(1)),
        delivered_head,
        ready_first: true,
        resync_first,
    };

    let stream = futures::stream::unfold(init, |mut st| async move {
        // Authentication on the initial HTTP request is not enough for a
        // stream that can live indefinitely. Rotation, revocation, and TTL
        // expiry must stop both event disclosure and the stream counting as
        // an approval surface.
        if !st.revalidate_credential.still_valid() {
            return None;
        }
        if std::mem::take(&mut st.ready_first) {
            return Some((Ok::<_, Infallible>(Event::default().comment("ready")), st));
        }
        // A resync marker leads, carrying the current head id so the client
        // has a baseline to resume from next time.
        if std::mem::take(&mut st.resync_first) {
            let id = format!("{}:{}", st.epoch, st.delivered_head);
            let sse = Event::default()
                .id(id)
                .json_data(&ManageEvent::Resync)
                .ok()?;
            return Some((Ok::<_, Infallible>(sse), st));
        }
        // Drain any replay backlog before live events.
        if let Some(item) = st.backlog.pop_front() {
            st.delivered_head = item.seq;
            let sse = Event::default()
                .id(format!("{}:{}", st.epoch, item.seq))
                .json_data(&item.event)
                .ok()?;
            return Some((Ok(sse), st));
        }
        loop {
            let item = tokio::select! {
                biased;
                _ = st.revalidate.tick() => {
                    if !st.revalidate_credential.still_valid() {
                        return None;
                    }
                    continue;
                }
                result = st.rx.recv() => match result {
                    Ok(item) => item,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Dropped live notifications: force a full refetch,
                        // but never disclose it after the stream's credential
                        // has ceased to be valid.
                        if !st.revalidate_credential.still_valid() {
                            return None;
                        }
                        let id = format!("{}:{}", st.epoch, st.delivered_head);
                        let sse = Event::default()
                            .id(id)
                            .json_data(&ManageEvent::Resync)
                            .ok()?;
                        return Some((Ok(sse), st));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                },
            };
            // Skip anything the replay backlog already covered.
            if item.seq <= st.delivered_head {
                continue;
            }
            if !st.revalidate_credential.still_valid() {
                return None;
            }
            st.delivered_head = item.seq;
            let sse = Event::default()
                .id(format!("{}:{}", st.epoch, item.seq))
                .json_data(&item.event)
                .ok()?;
            return Some((Ok(sse), st));
        }
    });
    (
        response_headers,
        Sse::new(stream).keep_alive(KeepAlive::default()),
    )
        .into_response()
}

/* ------------------------------- secrets ---------------------------------- */

async fn list_secrets(State(state): State<AppState>) -> Response {
    respond(state.manage.list_secrets().await)
}

async fn add_secret(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<SecretAddBody>,
) -> Response {
    respond(state.manage.add_credential(body).await)
}

async fn edit_secret(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<SecretEditBody>,
) -> Response {
    respond(state.manage.edit_secret(id, body).await)
}

async fn secret_totp_code(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.secret_totp_code(id).await)
}

async fn delete_secret(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.delete_secret(id).await)
}

/// Release a value for the client to show on screen, after the user has
/// asked for that secret by name and confirmed it. The core audits the
/// reveal as it releases the value.
async fn reveal_secret(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(
        state
            .manage
            .reveal_secret(id)
            .await
            .map(|value| json!({ "value": value.to_string() })),
    )
}

/// The other route that returns a stored secret's full value: the remote
/// shell's clipboard copy (the value goes shell-side to the clipboard and
/// never enters the webview, mirroring the local flow). Gated by the same
/// core read-confirmation path as a local copy — and audited *here*, at
/// release: once the value leaves the broker the copy has happened for
/// audit purposes, whatever the client does next. (The local flow audits
/// through `note_secret_copied` after its own clipboard write; there is no
/// honor-system note route for remote clients.)
async fn secret_value_for_copy(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.manage.secret_value_for_copy(id).await;
    if result.is_ok() {
        if let Ok(meta) = state
            .broker
            .store
            .secret_by_id(&state.broker.workspace, &id)
        {
            state.broker.audit.append(crate::audit::AuditEntry::new(
                crate::audit::AuditKind::SecretCopied,
                format!("Secret value copied (manage API): {}", meta.name),
            ));
        }
    }
    respond(result.map(|value| json!({ "value": value.to_string() })))
}

/* -------------------------- 1Password provider -------------------------- */

async fn list_onepassword_integrations(State(state): State<AppState>) -> Response {
    respond(state.manage.list_onepassword_integrations().await)
}

async fn add_onepassword_integration(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<OnePasswordIntegrationAddBody>,
) -> Response {
    let (auth, token) = body.authentication.into_parts();
    respond(
        state
            .manage
            .add_onepassword_integration(body.label, auth, token)
            .await,
    )
}

async fn replace_onepassword_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<OnePasswordTokenBody>,
) -> Response {
    respond(
        state
            .manage
            .replace_onepassword_token(id, Zeroizing::new(body.token))
            .await,
    )
}

async fn delete_onepassword_integration(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    respond(state.manage.delete_onepassword_integration(id).await)
}

async fn onepassword_health(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.onepassword_health(id).await)
}

async fn onepassword_vaults(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.onepassword_vaults(id).await)
}

async fn onepassword_items(
    State(state): State<AppState>,
    Path((id, vault_id)): Path<(Uuid, String)>,
) -> Response {
    respond(state.manage.onepassword_items(id, vault_id).await)
}

async fn onepassword_fields(
    State(state): State<AppState>,
    Path((id, vault_id, item_id)): Path<(Uuid, String, String)>,
) -> Response {
    respond(state.manage.onepassword_fields(id, vault_id, item_id).await)
}

async fn add_onepassword_secret(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<OnePasswordSecretAddBody>,
) -> Response {
    let (name, reference) = body.into_reference();
    respond(state.manage.add_onepassword_secret(name, reference).await)
}

/* ----------------------------- connections -------------------------------- */

async fn list_connections(State(state): State<AppState>) -> Response {
    respond(state.manage.list_connections().await)
}

async fn add_connection(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<ConnectionAddBody>,
) -> Response {
    let mut new_secrets = body.new_secrets;
    if let Some(new_secret) = body.new_secret {
        new_secrets.push(new_secret);
    }
    match new_secrets.len() {
        0 => respond(state.manage.add_connection(body.spec).await),
        1 => {
            let new_secret = new_secrets.remove(0);
            respond(
                state
                    .manage
                    .add_connection_with_secret(
                        // Connection-first setup stores a plain named secret;
                        // typed fields have no meaning on this path.
                        new_secret.name.unwrap_or_default(),
                        Zeroizing::new(new_secret.value),
                        body.spec,
                    )
                    .await,
            )
        }
        _ => respond(
            state
                .manage
                .add_connection_with_secrets(
                    new_secrets
                        .into_iter()
                        .map(|secret| {
                            (
                                secret.name.unwrap_or_default(),
                                Zeroizing::new(secret.value),
                            )
                        })
                        .collect(),
                    body.spec,
                )
                .await,
        ),
    }
}

async fn update_connection(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConnectionUpdateBody>,
) -> Response {
    respond(
        state
            .manage
            .update_connection(id, body.expected_updated_at, body.spec)
            .await,
    )
}

async fn rename_connection(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConnectionRenameBody>,
) -> Response {
    respond(
        state
            .manage
            .rename_connection(id, body.expected_updated_at, body.name)
            .await,
    )
}

async fn patch_connection(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConnectionConfigPatchBody>,
) -> Response {
    respond(
        state
            .manage
            .patch_connection(id, body.expected_updated_at, body.patch)
            .await,
    )
}

async fn delete_connection(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.delete_connection(id).await)
}

async fn reorder_connections(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<ConnectionsReorderBody>,
) -> Response {
    respond(state.manage.reorder_connections(body.ordered_ids).await)
}

async fn test_connection(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.test_connection(id).await)
}

async fn test_connection_draft(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<DraftTestBody>,
) -> Response {
    let typed = body
        .typed_secret
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new);
    respond(state.manage.test_connection_draft(body.spec, typed).await)
}

async fn set_tool_access(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<AccessBody>,
) -> Response {
    respond(
        state
            .manage
            .set_tool_access(id, body.enabled)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn set_confirm_mode(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ConfirmBody>,
) -> Response {
    respond(
        state
            .manage
            .set_confirm_mode(id, body.on)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn set_expose_response_credentials(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ResponseCredentialsBody>,
) -> Response {
    respond(
        state
            .manage
            .set_expose_response_credentials(id, body.expose)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn approvals(State(state): State<AppState>) -> Response {
    respond(state.manage.approvals().await)
}

async fn approval_snapshot(State(state): State<AppState>) -> Response {
    // Capture the bus head first. A mutation racing the following queue read
    // can make the data newer than its version (safe and self-correcting),
    // but can never label stale data with a newer version.
    let version = format!(
        "{}:{}",
        state.broker.manage_bus().epoch(),
        state.broker.manage_bus().head_seq()
    );
    let result = match state.manage.approvals().await {
        Ok(approvals) => {
            state
                .manage
                .elicitations()
                .await
                .map(|elicitations| aka_api::ApprovalSnapshotDto {
                    version,
                    approvals,
                    elicitations,
                })
        }
        Err(error) => Err(error),
    };
    respond(result)
}

async fn elicitations(State(state): State<AppState>) -> Response {
    respond(state.manage.elicitations().await)
}

async fn respond_elicitation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ElicitationResponseBody>,
) -> Response {
    respond(
        state
            .manage
            .respond_elicitation(id, body.approved, body.values)
            .await
            .map(|answered| json!({ "answered": answered })),
    )
}

async fn requests(State(state): State<AppState>) -> Response {
    respond(state.manage.requests().await)
}

async fn respond_approval(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<ApprovalResponseBody>,
) -> Response {
    respond(
        state
            .manage
            .respond_approval(id, body.decision)
            .await
            .map(|answered| json!({ "answered": answered })),
    )
}

async fn set_allowed_tools(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<AllowedToolsBody>,
) -> Response {
    respond(
        state
            .manage
            .set_allowed_tools(id, body.tools)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn set_audit_statements(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<AuditStatementsBody>,
) -> Response {
    respond(
        state
            .manage
            .set_audit_statements(id, body.audit_statements)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn set_endpoint_require_auth(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<EndpointRequireAuthBody>,
) -> Response {
    respond(
        state
            .manage
            .set_endpoint_require_auth(id, body.require_auth)
            .await
            .map(|changed| json!({ "changed": changed })),
    )
}

async fn list_mcp_tools(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.list_mcp_tools(id).await)
}

/// The check options ride as a required JSON body; `{}` means defaults.
async fn mcp_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(options): ApiJson<crate::mcp::McpCheckOptions>,
) -> Response {
    respond(state.manage.mcp_status(id, options).await)
}

async fn issue_endpoint(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.issue_endpoint(id).await)
}

async fn renew_endpoint(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.renew_endpoint(id).await)
}

async fn set_endpoint_expiry(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<EndpointExpiryBody>,
) -> Response {
    respond(state.manage.set_endpoint_expiry(id, body.expire).await)
}

async fn get_endpoint(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.get_endpoint(id).await)
}

async fn copy_endpoint(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(state.manage.copy_endpoint(id).await)
}

async fn revoke_endpoint(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    respond(
        state
            .manage
            .revoke_endpoint(id)
            .await
            .map(|revoked| json!({ "revoked": revoked })),
    )
}

/* -------------------------- relayed MCP sign-in --------------------------- */

/// Begin a relayed MCP sign-in. Progress rides the SSE feed as
/// `mcp_auth_changed`; the shell opens the authorize URL itself and
/// delivers the code its catcher receives.
async fn mcp_auth_start(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<McpAuthStartBody>,
) -> Response {
    let result = state
        .broker
        .ui_start_mcp_auth_external(body.draft, &body.redirect_uri);
    respond(result.map_err(ManageError::from))
}

async fn mcp_auth_state(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    ok(state.broker.ui_mcp_auth_state(&id))
}

async fn mcp_auth_cancel(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    ok(json!({ "cancelled": state.broker.ui_cancel_mcp_auth(&id) }))
}

async fn mcp_auth_deliver(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<McpAuthDeliverBody>,
) -> Response {
    ok(json!({
        "delivered": state
            .broker
            .ui_mcp_auth_deliver_code(&id, body.code, body.state, body.iss)
    }))
}

/* ------------------------- relayed OAuth (BYO app) ------------------------ */

/// Begin a relayed OAuth connect. The shell's loopback catcher receives the
/// browser redirect on the *user's* machine; the broker keeps the verifier
/// and completes on `/oauth/complete/{flow_id}`.
async fn oauth_start(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<OAuthStartBody>,
) -> Response {
    let result = state.broker.manage_oauth_start(
        &body.secret_name,
        body.client_secret.map(Zeroizing::new),
        body.spec,
        &body.redirect_uri,
    );
    respond(result.map_err(ManageError::from))
}

async fn oauth_reconnect_start(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<OAuthReconnectBody>,
) -> Response {
    let result = state
        .broker
        .manage_oauth_reconnect_start(&id, &body.redirect_uri)
        .await;
    respond(result.map_err(ManageError::from))
}

async fn oauth_complete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<OAuthCompleteBody>,
) -> Response {
    let result = state
        .broker
        .manage_oauth_complete(&id, &body.code, &body.state)
        .await;
    respond(result.map_err(ManageError::from))
}

/* ---------------------- identity, sessions, activity ---------------------- */

async fn identity(State(state): State<AppState>) -> Response {
    respond(state.manage.identity().await)
}

/// The agent key's plaintext, for the shell-side "copy key" affordance.
/// Holders of the manage token could read the token file on the host
/// anyway; this keeps the Connect page's copy button working remotely.
/// (`LocalBackend::agent_key` audits the release, so remote copies land
/// in the activity log exactly once.)
async fn agent_key(State(state): State<AppState>) -> Response {
    respond(
        state
            .manage
            .agent_key()
            .await
            .map(|token| json!({ "token": token })),
    )
}

async fn rotate_key(State(state): State<AppState>) -> Response {
    respond(state.manage.rotate_key().await)
}

async fn sessions(State(state): State<AppState>) -> Response {
    respond(state.manage.sessions().await)
}

async fn close_session(State(state): State<AppState>, Path(id): Path<u64>) -> Response {
    respond(
        state
            .manage
            .close_session(id)
            .await
            .map(|closed| json!({ "closed": closed })),
    )
}

#[derive(serde::Deserialize)]
struct ActivityQuery {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(serde::Deserialize)]
struct ActivityPageQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    before: Option<u64>,
}

/// Default activity tail when the caller does not choose a limit. Matches the
/// desktop view's ceiling so a default read and the app's own read agree.
const ACTIVITY_VIEW_LIMIT: usize = 500;

async fn activity(State(state): State<AppState>, Query(query): Query<ActivityQuery>) -> Response {
    let limit = query.limit.unwrap_or(ACTIVITY_VIEW_LIMIT);
    respond(state.manage.activity(limit).await)
}

async fn activity_page(
    State(state): State<AppState>,
    Query(query): Query<ActivityPageQuery>,
) -> Response {
    let limit = query
        .limit
        .unwrap_or(ACTIVITY_VIEW_LIMIT)
        .min(ACTIVITY_VIEW_LIMIT);
    respond(state.manage.activity_page(limit, query.before).await)
}

/// Accept a cloud session minted on the machine that owns the credentials.
///
/// Authenticated as any other manage write. Note what a caller can and
/// cannot do with it: the pushed material is short-lived and scoped to one
/// connection that already exists and already declares itself
/// machine-bound, so this widens nothing that adding a connection did not
/// already allow.
async fn push_cloud_session(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<aka_api::CloudSessionPushDto>,
) -> Response {
    respond(state.manage.push_cloud_session(body).await)
}

#[derive(serde::Deserialize)]
struct PushableBody {
    install_id: String,
}

/// The refresher's read. POST rather than GET because the install id goes in
/// the body: it identifies which install's `~/.aws` is being asked about, and
/// query strings end up in proxy access logs.
async fn pushable_connections(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<PushableBody>,
) -> Response {
    respond(state.manage.pushable_connections(&body.install_id).await)
}

async fn clear_activity(State(state): State<AppState>) -> Response {
    // `LocalBackend::clear_activity` publishes the ActivityCleared manage
    // event itself, so route-driven and in-process clears both reach SSE
    // subscribers.
    respond(state.manage.clear_activity().await)
}

/* --------------------------------- sign-in -------------------------------- */

/// Who this request is, as the principal resolved it. The web app's and the
/// desktop's "signed in as" both read this.
async fn auth_whoami(State(state): State<AppState>, principal: ManagePrincipal) -> Response {
    ok(json!({
        "account": principal.account,
        "credential": principal.credential,
        "method": principal.method,
        "surface": principal.surface,
        "scopes": principal.scopes,
        "authenticated_at": principal.authenticated_at,
        "label": principal.label,
        "passkeys_enrolled": state.broker.auth.is_enrolled(),
    }))
}

fn auth_error(error: crate::auth::AuthError) -> Response {
    manage_error_response(ManageError::InvalidSetting {
        message: error.detail(),
    })
}

async fn list_passkeys(State(state): State<AppState>) -> Response {
    ok(state
        .broker
        .auth
        .credentials()
        .into_iter()
        .map(|credential| {
            json!({
                "id": credential.id,
                "label": credential.label,
                "created_at": credential.created_at,
                "last_used_at": credential.last_used_at,
            })
        })
        .collect::<Vec<_>>())
}

async fn remove_passkey(
    State(state): State<AppState>,
    principal: ManagePrincipal,
    Path(id): Path<Uuid>,
) -> Response {
    match state.broker.auth.remove_credential(&id) {
        Ok(removed) => {
            if removed {
                state.broker.audit_sign_in(
                    crate::audit::AuditKind::Passkey,
                    "Passkey removed",
                    &principal.label,
                );
            }
            ok(json!({ "removed": removed }))
        }
        Err(error) => auth_error(error),
    }
}

async fn list_browser_sessions(State(state): State<AppState>) -> Response {
    ok(state
        .broker
        .auth
        .sessions()
        .into_iter()
        .map(|session| {
            json!({
                "id": session.id,
                "created_at": session.created_at,
                "last_seen_at": session.last_seen_at,
                "expires_at": session.expires_at,
                "authenticated_at": session.authenticated_at,
            })
        })
        .collect::<Vec<_>>())
}

async fn revoke_browser_session(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    match state.broker.auth.revoke_session(&id) {
        Ok(revoked) => ok(json!({ "revoked": revoked })),
        Err(error) => auth_error(error),
    }
}

async fn list_devices(State(state): State<AppState>, principal: ManagePrincipal) -> Response {
    ok(state
        .broker
        .auth
        .devices()
        .into_iter()
        .map(|device| {
            json!({
                "id": device.id,
                "name": device.name,
                "surface": device.surface,
                "created_at": device.created_at,
                "last_seen_at": device.last_seen_at,
                // So the list can mark "this one" and warn before a user
                // revokes the device they are reading the list on.
                "current": principal.credential == Some(device.id),
            })
        })
        .collect::<Vec<_>>())
}

#[derive(serde::Deserialize)]
struct RenameDeviceBody {
    name: String,
}

async fn rename_device(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<RenameDeviceBody>,
) -> Response {
    let name = crate::untrusted_text::cap(body.name.trim(), 64);
    if name.is_empty() {
        return manage_error_response(ManageError::InvalidSetting {
            message: "a device needs a name".into(),
        });
    }
    match state.broker.auth.rename_device(&id, &name) {
        Ok(renamed) => ok(json!({ "renamed": renamed })),
        Err(error) => auth_error(error),
    }
}

async fn revoke_device(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    match state.broker.auth.revoke_device(&id) {
        Ok(revoked) => {
            if revoked {
                state.broker.audit_sign_in(
                    crate::audit::AuditKind::DeviceGrant,
                    "Device revoked",
                    &id.to_string(),
                );
            }
            ok(json!({ "revoked": revoked }))
        }
        Err(error) => auth_error(error),
    }
}

async fn list_automation(State(state): State<AppState>) -> Response {
    ok(state
        .broker
        .auth
        .automation_tokens()
        .into_iter()
        .map(|token| {
            json!({
                "id": token.id,
                "name": token.name,
                "scopes": token.scopes,
                "created_at": token.created_at,
                "expires_at": token.expires_at,
                "last_used_at": token.last_used_at,
            })
        })
        .collect::<Vec<_>>())
}

#[derive(serde::Deserialize)]
struct MintAutomationBody {
    name: String,
    scopes: crate::auth::ScopeSet,
    /// Days until it stops working. Absent means never, which the UI should
    /// make the harder choice to pick.
    #[serde(default)]
    ttl_days: Option<u64>,
}

async fn mint_automation(
    State(state): State<AppState>,
    principal: ManagePrincipal,
    ApiJson(body): ApiJson<MintAutomationBody>,
) -> Response {
    let name = crate::untrusted_text::cap(body.name.trim(), 64);
    if name.is_empty() {
        return manage_error_response(ManageError::InvalidSetting {
            message: "an automation token needs a name".into(),
        });
    }
    if body.scopes.is_empty() {
        return manage_error_response(ManageError::InvalidSetting {
            message: "an automation token with no scopes could do nothing".into(),
        });
    }
    // A grant may narrow what its issuer holds, never widen it. Otherwise
    // the narrowest credential on the broker could mint the broadest one.
    if !body.scopes.is_subset_of(principal.scopes) {
        return manage_error_response(ManageError::InvalidSetting {
            message: "a token cannot be granted more than the credential minting it holds".into(),
        });
    }
    let Some(account) = principal.account else {
        return manage_error_response(ManageError::InvalidSetting {
            message: "sign in with a passkey to mint an automation token".into(),
        });
    };
    let ttl = body
        .ttl_days
        .map(|days| chrono::Duration::days(days.clamp(1, 3650) as i64));
    match state
        .broker
        .auth
        .mint_automation(account, &name, body.scopes, ttl)
    {
        Ok((record, token)) => {
            state.broker.audit_sign_in(
                crate::audit::AuditKind::DeviceGrant,
                "Automation token issued",
                &name,
            );
            ok(json!({
                "id": record.id,
                "name": record.name,
                "scopes": record.scopes,
                "expires_at": record.expires_at,
                // Shown once. Only the hash is kept.
                "token": token.as_str(),
            }))
        }
        Err(error) => auth_error(error),
    }
}

async fn revoke_automation(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    match state.broker.auth.revoke_automation(&id) {
        Ok(revoked) => ok(json!({ "revoked": revoked })),
        Err(error) => auth_error(error),
    }
}

/* ------------------------------- settings ---------------------------------- */

async fn settings(State(state): State<AppState>) -> Response {
    respond(state.manage.settings().await)
}

/// Apply a settings patch, field by field.
///
/// Every field the body carries is applied. Until now only
/// `menu_bar_hides_dock` was — `confirm_ssh_host_keys` crossed the wire from
/// the remote client and was silently dropped, so a hosted broker's host-key
/// setting could be toggled in the UI and never changed. The others were
/// added alongside it and would have inherited the same hole.
async fn patch_settings(
    State(state): State<AppState>,
    principal: ManagePrincipal,
    ApiJson(body): ApiJson<SettingsPatchBody>,
) -> Response {
    if let Some(on) = body.menu_bar_hides_dock {
        if let Err(error) = state.manage.set_menu_bar_hides_dock(on).await {
            return manage_error_response(error);
        }
    }
    if let Some(on) = body.confirm_ssh_host_keys {
        if let Err(error) = state.manage.set_confirm_ssh_host_keys(on).await {
            return manage_error_response(error);
        }
    }
    if let Some(on) = body.legacy_manage_token {
        // Deciding what may sign in is `identity:manage`, whichever route it
        // arrives on, and it needs a person who proved themselves just now.
        if let Err(refusal) = principal.require(
            crate::auth::Scope::IdentityManage,
            crate::auth::StepUp::Always,
        ) {
            return refusal;
        }
        if let Err(error) = state.manage.set_legacy_manage_token(on).await {
            return manage_error_response(error);
        }
    }
    respond(state.manage.settings().await)
}

async fn agent_setup(State(state): State<AppState>) -> Response {
    respond(
        state
            .manage
            .agent_setup()
            .await
            .map(|instructions| json!({ "instructions": instructions })),
    )
}
