//! What this client presents to prove it may manage a broker.
//!
//! Two kinds, and the whole point of the abstraction is that the code above
//! it cannot tell them apart:
//!
//! - a **management token**, fixed and long-lived, which is what every
//!   client used before passkeys and what the Advanced path still offers;
//! - a **device grant**, obtained by signing in through the browser: a
//!   ten-minute access token held in memory behind a rotating refresh token
//!   held in the OS keychain.
//!
//! The second is the reason this module exists rather than a `String`. A
//! background loop — the cloud-session refresher runs every minute — must be
//! able to authenticate without a human present, so the credential has to
//! renew itself silently. And because the refresh token *rotates*, renewing
//! it is not idempotent: presenting a superseded one tells the broker that
//! two holders exist and revokes the device. So a refresh must happen once,
//! under a lock, with every waiting caller taking the result — never
//! concurrently.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Renew this long before the access token actually expires, so a request
/// that takes a moment to send does not arrive with a dead credential.
const RENEW_MARGIN: chrono::Duration = chrono::Duration::seconds(60);

/// Invoked with each newly issued refresh token.
///
/// Rotation makes the stored token stale the instant a refresh succeeds;
/// if the process dies before persisting the replacement, the next start
/// presents a superseded token and the broker revokes the device. So this
/// runs *before* any caller receives the new access token.
pub type OnRotate = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Debug)]
pub enum GrantError {
    /// The broker refused the refresh token. The device has to sign in again.
    SignInRequired(String),
    /// The broker could not be reached.
    Unreachable(String),
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignInRequired(detail) => write!(f, "sign in again: {detail}"),
            Self::Unreachable(detail) => write!(f, "could not reach the broker: {detail}"),
        }
    }
}

struct GrantState {
    access: Zeroizing<String>,
    access_expires_at: DateTime<Utc>,
    refresh: Zeroizing<String>,
}

/// A device grant that renews itself.
pub struct DeviceGrant {
    base: String,
    http: reqwest::Client,
    state: tokio::sync::Mutex<GrantState>,
    on_rotate: Option<OnRotate>,
    /// Set once the broker refuses the refresh token, so a wedged
    /// background loop stops hammering an endpoint that will keep saying no.
    exhausted: std::sync::atomic::AtomicBool,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
    refresh_token: String,
}

impl DeviceGrant {
    /// Resume a stored grant. Access tokens never persist, so we do not have
    /// one yet and the first request refreshes.
    pub fn resume(base: &str, refresh: &str, on_rotate: Option<OnRotate>) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            state: tokio::sync::Mutex::new(GrantState {
                access: Zeroizing::new(String::new()),
                // In the past, so the first `bearer()` refreshes.
                access_expires_at: DateTime::<Utc>::MIN_UTC,
                refresh: Zeroizing::new(refresh.to_string()),
            }),
            on_rotate,
            exhausted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// A grant that already has its first token pair, straight from the
    /// authorization-code exchange.
    pub fn fresh(
        base: &str,
        access: &str,
        expires_in: i64,
        refresh: &str,
        on_rotate: Option<OnRotate>,
    ) -> Self {
        let grant = Self::resume(base, refresh, on_rotate);
        {
            let mut state = grant.state.blocking_lock_or_replace();
            state.access = Zeroizing::new(access.to_string());
            state.access_expires_at = Utc::now() + chrono::Duration::seconds(expires_in.max(0));
        }
        grant
    }

    /// The bearer to send, refreshing first if the current one is about to
    /// expire.
    pub async fn bearer(&self) -> Result<Zeroizing<String>, GrantError> {
        // One lock for the whole check-and-refresh. Two callers noticing an
        // expired token at once must not both refresh: the second would
        // present a token the first had already rotated away, and the broker
        // reads that as a stolen credential and revokes the device.
        let mut state = self.state.lock().await;
        if !state.access.is_empty() && Utc::now() + RENEW_MARGIN < state.access_expires_at {
            return Ok(state.access.clone());
        }
        if self.exhausted.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(GrantError::SignInRequired(
                "this device's grant was refused; sign in again".into(),
            ));
        }
        let response = self
            .http
            .post(format!("{}/v1/auth/token", self.base))
            .json(&serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": state.refresh.as_str(),
            }))
            .send()
            .await
            .map_err(|error| GrantError::Unreachable(error.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| GrantError::Unreachable(error.to_string()))?;
        if !status.is_success() {
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("detail")
                        .and_then(|detail| detail.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| status.to_string());
            // A 429 (rate limited) or 408 (request timeout) is the broker
            // pushing back on *timing*, not refusing this credential — the
            // refresh token is still good and the next attempt should use it.
            // Retiring the grant here would turn one co-located client tripping
            // the per-IP limiter into a forced re-sign-in for a valid device.
            let transient = status.as_u16() == 429 || status.as_u16() == 408;
            // 5xx is the broker having a bad day, likewise not a verdict on
            // this credential; only a genuine refusal retires it.
            if status.is_client_error() && !transient {
                self.exhausted
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return Err(GrantError::SignInRequired(detail));
            }
            return Err(GrantError::Unreachable(detail));
        }
        let tokens: TokenResponse = match serde_json::from_str(&body) {
            Ok(tokens) => tokens,
            Err(error) => {
                // A success status means the broker already committed the
                // rotation, so the refresh token still in memory is superseded.
                // Retrying it would trip reuse detection and revoke the device;
                // retire the grant cleanly instead of retrying that dead token.
                self.exhausted
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return Err(GrantError::SignInRequired(format!(
                    "the broker rotated this device's grant but its response could \
                     not be read ({error}); sign in again"
                )));
            }
        };

        // Persist the rotated refresh token *before* anything can use the new
        // access token. A crash in the other order leaves the keychain holding
        // a token the broker has already superseded; presenting that on next
        // start revokes the device.
        if let Some(on_rotate) = &self.on_rotate {
            on_rotate(&tokens.refresh_token);
        }
        state.refresh = Zeroizing::new(tokens.refresh_token);
        state.access = Zeroizing::new(tokens.access_token);
        state.access_expires_at = Utc::now() + chrono::Duration::seconds(tokens.expires_in.max(0));
        Ok(state.access.clone())
    }

    /// The current refresh token, for storing at sign-in time.
    pub async fn refresh_token(&self) -> Zeroizing<String> {
        self.state.lock().await.refresh.clone()
    }
}

/// Small helper so [`DeviceGrant::fresh`] can seed state without being async.
trait BlockingLock<T> {
    fn blocking_lock_or_replace(&self) -> tokio::sync::MutexGuard<'_, T>;
}

impl<T> BlockingLock<T> for tokio::sync::Mutex<T> {
    fn blocking_lock_or_replace(&self) -> tokio::sync::MutexGuard<'_, T> {
        // Uncontended by construction: the mutex was created two lines ago
        // and no other handle to it exists yet.
        self.try_lock().expect("a just-created grant is uncontended")
    }
}

/// What a client presents to a broker's manage plane.
pub enum ManageCredential {
    /// The global management token. The same credential wherever anyone pastes
    /// it, which is why we are retiring it.
    ManageToken(Zeroizing<String>),
    /// A per-device grant from a passkey sign-in.
    Device(DeviceGrant),
}

impl ManageCredential {
    pub fn manage_token(token: &str) -> Self {
        Self::ManageToken(Zeroizing::new(token.to_string()))
    }

    /// The `Authorization: Bearer` value for the next request.
    pub async fn bearer(&self) -> Result<Zeroizing<String>, GrantError> {
        match self {
            Self::ManageToken(token) => Ok(token.clone()),
            Self::Device(grant) => grant.bearer().await,
        }
    }

    /// Whether this is the legacy credential, for the UI's migration nudge.
    pub fn is_manage_token(&self) -> bool {
        matches!(self, Self::ManageToken(_))
    }
}

impl std::fmt::Debug for ManageCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManageToken(_) => f.write_str("ManageToken(<redacted>)"),
            Self::Device(_) => f.write_str("Device(<redacted>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_management_token_is_handed_back_unchanged() {
        let credential = ManageCredential::manage_token("akamgr_abc");
        assert_eq!(credential.bearer().await.unwrap().as_str(), "akamgr_abc");
        assert!(credential.is_manage_token());
    }

    #[tokio::test]
    async fn a_fresh_grant_serves_its_access_token_without_calling_out() {
        // The base URL points nowhere; reaching for the network would fail.
        let grant = DeviceGrant::fresh(
            "http://127.0.0.1:1",
            "akaacc_abc",
            600,
            "akaref_abc",
            None,
        );
        assert_eq!(grant.bearer().await.unwrap().as_str(), "akaacc_abc");
    }

    #[tokio::test]
    async fn an_almost_expired_token_is_renewed_rather_than_used() {
        let grant = DeviceGrant::fresh(
            "http://127.0.0.1:1",
            "akaacc_abc",
            // Inside RENEW_MARGIN, so it must not be served.
            30,
            "akaref_abc",
            None,
        );
        let error = grant.bearer().await.expect_err("must try to refresh");
        assert!(matches!(error, GrantError::Unreachable(_)), "{error}");
    }

    #[tokio::test]
    async fn a_resumed_grant_has_no_access_token_until_it_refreshes() {
        let grant = DeviceGrant::resume("http://127.0.0.1:1", "akaref_abc", None);
        assert_eq!(grant.refresh_token().await.as_str(), "akaref_abc");
        assert!(grant.bearer().await.is_err());
    }

    #[tokio::test]
    async fn debug_never_prints_a_credential() {
        let credential = ManageCredential::manage_token("akamgr_supersecret");
        assert!(!format!("{credential:?}").contains("supersecret"));
    }

    /// A one-shot HTTP responder: bind loopback, answer the first request with
    /// `response`, and hand back the base URL to point a grant at.
    async fn serve_once(response: &'static str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut scratch = [0u8; 2048];
                let _ = stream.read(&mut scratch).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    fn exhausted(grant: &DeviceGrant) -> bool {
        grant.exhausted.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[tokio::test]
    async fn a_rate_limit_does_not_retire_the_grant() {
        // The broker's per-IP limiter answers 429; that is timing, not a
        // refusal, so the grant must stay usable rather than force a re-login.
        let base = serve_once(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await;
        let grant = DeviceGrant::resume(&base, "akaref_abc", None);
        let error = grant.bearer().await.expect_err("a 429 is not a token");
        assert!(matches!(error, GrantError::Unreachable(_)), "{error}");
        assert!(!exhausted(&grant), "a rate limit must not retire the grant");
    }

    #[tokio::test]
    async fn a_genuine_refusal_still_retires_the_grant() {
        let base = serve_once(
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await;
        let grant = DeviceGrant::resume(&base, "akaref_abc", None);
        let error = grant.bearer().await.expect_err("a refusal is terminal");
        assert!(matches!(error, GrantError::SignInRequired(_)), "{error}");
        assert!(exhausted(&grant), "a 401 must retire the grant");
    }

    #[tokio::test]
    async fn a_success_with_an_unreadable_body_retires_rather_than_replaying() {
        // 200 means the broker rotated the token, so the one in memory is dead.
        // A body we cannot parse must not send us back to retry that dead token
        // (which would trip reuse detection and revoke the device).
        let base = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: 3\r\nConnection: close\r\n\r\nnot",
        )
        .await;
        let grant = DeviceGrant::resume(&base, "akaref_abc", None);
        let error = grant.bearer().await.expect_err("an unreadable rotation is fatal");
        assert!(matches!(error, GrantError::SignInRequired(_)), "{error}");
        assert!(exhausted(&grant));
        // The stale token was not advanced to something bogus.
        assert_eq!(grant.refresh_token().await.as_str(), "akaref_abc");
    }
}
