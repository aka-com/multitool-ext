//! Signing this Mac in to a hosted broker with a passkey.
//!
//! The ceremony runs in the *system browser*, not in the app's webview, and
//! that is the whole design rather than an implementation detail. WebAuthn
//! binds a credential to an origin, so a ceremony run anywhere but on
//! `https://broker.example` produces a credential for something else. Using
//! the real browser at the real origin means the passkey the user already
//! has for the web app — synced across their devices by the platform — is
//! the same one that authorizes this app. There is nothing separate to
//! enroll and nothing to keep in step.
//!
//! What comes back is an authorization code on a loopback callback, which
//! this exchanges for a device grant. Three things protect that code:
//!
//! - **PKCE**: the verifier never leaves this process, so intercepting the
//!   redirect yields a code nobody else can spend.
//! - **A one-request listener on a random loopback port**, bound *before*
//!   the browser opens, so the port cannot be squatted in the gap.
//! - **`state`**, compared on return, so we reject a code from some other
//!   flow — or from a page an attacker sent the user to.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

/// How long to wait for the user to finish in the browser. Generous: they
/// may have to find a phone, and a passkey prompt can sit for a while.
const BROWSER_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a single accepted connection may take to send its request line
/// before we abandon it and go back to accepting. Without this a peer that
/// connects and sends nothing — a browser preconnect socket, or any local
/// process — wedges the accept loop until `BROWSER_TIMEOUT`, blocking the
/// real callback for five minutes.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on the callback request line, so a listener facing loopback cannot be
/// made to buffer without bound before the code is even parsed.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

pub struct SignedIn {
    pub access: Zeroizing<String>,
    pub expires_in: i64,
    pub refresh: Zeroizing<String>,
    pub device_name: String,
}

/// Hand-written rather than derived: this value is two bearer tokens, and a
/// derived `Debug` would print both into whatever log or panic message
/// happened to format it.
impl std::fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn")
            .field("device_name", &self.device_name)
            .field("expires_in", &self.expires_in)
            .field("access", &"<redacted>")
            .field("refresh", &"<redacted>")
            .finish()
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("os rng");
    b64(&buf)
}

/// This Mac's name, as the user will see it in the authorized-devices list.
pub fn default_device_name() -> String {
    // The host name is what people recognize ("Raymond's MacBook Pro"), and
    // it is already visible to every network this machine joins, so using it
    // discloses nothing new.
    let host = std::process::Command::new("scutil")
        .args(["--get", "ComputerName"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    host.unwrap_or_else(|| "This Mac".to_string())
}

/// Run the whole handshake: open the browser, catch the code, exchange it.
///
/// `open` is the browser opener, injected so this is testable without one.
pub async fn sign_in(
    base_url: &str,
    device_name: &str,
    open: impl FnOnce(&str) -> bool,
) -> Result<SignedIn, String> {
    let verifier = random(64);
    let challenge = b64(&Sha256::digest(verifier.as_bytes()));
    let state = random(32);

    // Bound to loopback and bound *first*. Asking the OS for a port after
    // sending the browser somewhere would leave a window in which another
    // process could take it and receive the code.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("could not open a callback port: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let authorize = format!(
        "{}/authorize?{}",
        base_url.trim_end_matches('/'),
        serde_urlencoded::to_string([
            ("client_id", "multitool-desktop"),
            ("redirect_uri", redirect.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", state.as_str()),
            ("device_name", device_name),
        ])
        .map_err(|error| error.to_string())?
    );
    if !open(&authorize) {
        return Err("could not open your browser to sign in".into());
    }

    let code = tokio::time::timeout(BROWSER_TIMEOUT, catch_code(listener, &state))
        .await
        .map_err(|_| "the browser sign-in timed out".to_string())??;

    exchange(base_url, &code, &verifier, &redirect, device_name).await
}

/// Accept exactly one callback and return the code it carries.
///
/// Loops rather than taking the first connection: a browser may probe the
/// port, and a preflight or favicon request must not consume the one chance
/// to receive the real callback.
async fn catch_code(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<Zeroizing<String>, String> {
    loop {
        let (mut stream, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("callback failed: {error}"))?;
        // Belt and braces: the socket is bound to loopback, so this cannot
        // be anything else, but the check costs nothing and the code is a
        // bearer credential.
        if !peer.ip().is_loopback() {
            continue;
        }
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let target = loop {
            // Bound each read: a connection that stalls mid-request must not
            // hold the one accept slot until the outer browser timeout.
            let read = match tokio::time::timeout(CALLBACK_READ_TIMEOUT, stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break None,
                Ok(Ok(read)) => read,
            };
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(head) = buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|end| buffer[..end].to_vec())
            {
                break String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .map(str::to_string);
            }
            if buffer.len() > MAX_REQUEST_BYTES {
                break None;
            }
        };
        let Some(target) = target else {
            let _ = stream.shutdown().await;
            continue;
        };
        let Some(query) = target.split_once('?').map(|(_, query)| query) else {
            let _ = reply(&mut stream, "Waiting for the sign-in to finish…").await;
            continue;
        };
        let params: std::collections::HashMap<String, String> =
            serde_urlencoded::from_str(query).unwrap_or_default();

        // Compare state before touching the code. A response whose state is
        // not the one we generated did not come from the request we made,
        // and its code is not ours to spend.
        let matches = params
            .get("state")
            .is_some_and(|state| constant_time_eq(state, expected_state));
        if !matches {
            let _ = reply(
                &mut stream,
                "That sign-in did not match this app's request. Close this tab and try again.",
            )
            .await;
            continue;
        }
        let Some(code) = params.get("code").filter(|code| !code.is_empty()) else {
            let _ = reply(&mut stream, "The broker did not return a sign-in code.").await;
            continue;
        };
        let _ = reply(&mut stream, "Signed in. You can close this tab.").await;
        return Ok(Zeroizing::new(code.clone()));
    }
}

/// Compare without leaking where two strings diverge.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

async fn reply(stream: &mut tokio::net::TcpStream, message: &str) -> std::io::Result<()> {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Multitool</title>\
         <body style=\"font:15px system-ui;display:grid;place-items:center;height:90vh\">\
         <p>{}</p>",
        message
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

async fn exchange(
    base_url: &str,
    code: &str,
    verifier: &str,
    redirect: &str,
    device_name: &str,
) -> Result<SignedIn, String> {
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?;
    let response = http
        .post(format!("{}/v1/auth/token", base_url.trim_end_matches('/')))
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect,
            "client_id": "multitool-desktop",
        }))
        .send()
        .await
        .map_err(|error| format!("could not reach the broker: {error}"))?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        return Err(parsed
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or("the broker refused the sign-in")
            .to_string());
    }
    let field = |name: &str| {
        parsed
            .get(name)
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };
    Ok(SignedIn {
        access: Zeroizing::new(
            field("access_token").ok_or("the broker returned no access token")?,
        ),
        expires_in: parsed
            .get("expires_in")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        refresh: Zeroizing::new(
            field("refresh_token").ok_or("the broker returned no refresh token")?,
        ),
        device_name: field("device_name").unwrap_or_else(|| device_name.to_string()),
    })
}

/// Build the grant this app will hold, persisting every rotation.
pub fn grant_for(
    url: &str,
    signed_in: &SignedIn,
    tokens: Arc<aka_client::credentials::TokenStore>,
) -> Arc<aka_client::grant::ManageCredential> {
    let key = url.to_string();
    let store = tokens.clone();
    Arc::new(aka_client::grant::ManageCredential::Device(
        aka_client::grant::DeviceGrant::fresh(
            url,
            &signed_in.access,
            signed_in.expires_in,
            &signed_in.refresh,
            Some(Arc::new(move |refresh: &str| {
                if let Err(error) = store.save_grant(&key, refresh) {
                    // Losing the rotation means the *next* start presents a
                    // superseded token and the broker revokes the device.
                    // Loud, because the user will otherwise be mystified.
                    tracing::error!(%error, "could not store the rotated device grant");
                }
            })),
        ),
    ))
}

/// Resume a stored grant on startup.
pub fn resume_grant(
    url: &str,
    refresh: &str,
    tokens: Arc<aka_client::credentials::TokenStore>,
) -> Arc<aka_client::grant::ManageCredential> {
    let key = url.to_string();
    let store = tokens.clone();
    Arc::new(aka_client::grant::ManageCredential::Device(
        aka_client::grant::DeviceGrant::resume(
            url,
            refresh,
            Some(Arc::new(move |refresh: &str| {
                if let Err(error) = store.save_grant(&key, refresh) {
                    tracing::error!(%error, "could not store the rotated device grant");
                }
            })),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pkce_challenge_is_the_verifier_digest() {
        let verifier = "a-verifier";
        let challenge = b64(&Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge.len(), 43);
        assert!(challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn generated_values_are_unpredictable_and_url_safe() {
        let a = random(32);
        let b = random(32);
        assert_ne!(a, b);
        assert!(a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn state_comparison_is_length_safe() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[tokio::test]
    async fn a_callback_with_the_wrong_state_is_not_accepted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let caught = tokio::spawn(async move { catch_code(listener, "the-real-state").await });

        // A code delivered under somebody else's state — the shape of a
        // forced-login attack — must not be taken as ours.
        let client = reqwest::Client::new();
        let _ = client
            .get(format!(
                "http://127.0.0.1:{port}/callback?code=akacode_x&state=not-ours"
            ))
            .send()
            .await;
        // Then the genuine one arrives and is accepted.
        let _ = client
            .get(format!(
                "http://127.0.0.1:{port}/callback?code=akacode_real&state=the-real-state"
            ))
            .send()
            .await;
        let code = caught.await.unwrap().unwrap();
        assert_eq!(code.as_str(), "akacode_real");
    }

    #[tokio::test]
    async fn a_callback_with_no_code_does_not_end_the_wait() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let caught = tokio::spawn(async move { catch_code(listener, "s").await });
        let client = reqwest::Client::new();
        // A browser probe, then an error redirect, then the real thing.
        let _ = client.get(format!("http://127.0.0.1:{port}/favicon.ico")).send().await;
        let _ = client
            .get(format!("http://127.0.0.1:{port}/callback?state=s"))
            .send()
            .await;
        let _ = client
            .get(format!("http://127.0.0.1:{port}/callback?code=akacode_ok&state=s"))
            .send()
            .await;
        assert_eq!(caught.await.unwrap().unwrap().as_str(), "akacode_ok");
    }

    #[tokio::test]
    async fn a_browser_that_cannot_be_opened_fails_before_waiting() {
        let started = std::time::Instant::now();
        let error = sign_in("https://broker.example", "Test Mac", |_| false)
            .await
            .expect_err("must not wait on a browser that never opened");
        assert!(error.contains("could not open"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
