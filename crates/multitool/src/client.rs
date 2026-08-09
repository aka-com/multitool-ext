//! Shared client for talking to a running broker: minimal HTTP over its Unix
//! control socket, the same calls over TCP to a remote broker, shared-key
//! loading, and authenticated capability opens. `aka mcp` builds its
//! discovery loop on the low-level pieces; `aka run` and `aka env` drive
//! [`Agent::open_session`] directly.

use std::path::Path;

use aka_core::paths::Paths;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Where the agent plane is, and the key to speak to it with.
///
/// The two arms differ in more than transport. Locally the shared key is a
/// file this user can read (or pair for), so it is fetched lazily and
/// re-read after a rotation. Remotely there is no such file: the key was
/// handed over once by redeeming an invite and stored by `aka login`, so it
/// is resolved before the call and a rotation means logging in again.
#[derive(Clone, Debug)]
pub enum Agent {
    Local(Paths),
    Remote { base: String, key: String },
}

impl Agent {
    /// A remote target, with the trailing slash normalized off so joined
    /// paths cannot produce a double slash.
    pub fn remote(base: &str, key: &str) -> Self {
        Self::Remote {
            base: base.trim_end_matches('/').to_string(),
            key: key.to_string(),
        }
    }

    /// How to name this broker in a message to the user.
    pub fn describe(&self) -> String {
        match self {
            Self::Local(paths) => paths.socket_file().display().to_string(),
            Self::Remote { base, .. } => base.clone(),
        }
    }

    /// One authenticated request, with the key resolved per arm.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        label: Option<&str>,
    ) -> Result<(u16, String), OpenSessionError> {
        match self {
            Self::Local(paths) => {
                let key = local_key(paths, label).await?;
                unix_http(
                    &paths.socket_file(),
                    method,
                    path,
                    body,
                    Some(&key),
                    label,
                )
                .await
                .map_err(|error| transport_error(&paths.socket_file(), error))
            }
            Self::Remote { base, key } => {
                let client = reqwest::Client::new();
                let url = format!("{base}{path}");
                let mut request = match method {
                    "GET" => client.get(&url),
                    "POST" => client.post(&url),
                    other => {
                        return Err(OpenSessionError::Malformed(format!(
                            "unsupported method {other}"
                        )))
                    }
                }
                .bearer_auth(key);
                if let Some(label) = label {
                    request = request.header("X-Multitool-Client", label);
                }
                if let Some(body) = body {
                    request = request
                        .header("content-type", "application/json")
                        .body(body.to_string());
                }
                let response = request.send().await.map_err(|error| {
                    OpenSessionError::RemoteUnreachable {
                        base: base.clone(),
                        detail: error.to_string(),
                    }
                })?;
                let status = response.status().as_u16();
                let payload = response.text().await.map_err(|error| {
                    OpenSessionError::RemoteUnreachable {
                        base: base.clone(),
                        detail: error.to_string(),
                    }
                })?;
                Ok((status, payload))
            }
        }
    }
}

#[derive(Debug)]
pub enum OpenSessionError {
    NoBroker {
        socket: std::path::PathBuf,
    },
    Refused {
        status: u16,
        reason: Option<String>,
        detail: String,
    },
    Transport {
        socket: std::path::PathBuf,
        detail: String,
    },
    RemoteUnreachable {
        base: String,
        detail: String,
    },
    Malformed(String),
}

impl std::fmt::Display for OpenSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBroker { socket } => write!(
                f,
                "no broker is running at {} — start Multitool for the local store \
                 (~/.aka), or `aka serve` (default ~/.akaserver) / \
                 `aka serve --root …` for a headless root",
                socket.display()
            ),
            Self::Refused { status, detail, .. } => {
                write!(f, "the broker refused the open (HTTP {status}): {detail}")
            }
            Self::Transport { socket, detail } => {
                write!(
                    f,
                    "could not reach the broker at {}: {detail}",
                    socket.display()
                )
            }
            Self::RemoteUnreachable { base, detail } => {
                write!(f, "could not reach the broker at {base}: {detail}")
            }
            Self::Malformed(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for OpenSessionError {}

/// One minimal HTTP/1.1 request over the broker's Unix socket. The broker
/// answers small JSON bodies with a Content-Length, so read-to-EOF with
/// `Connection: close` is sufficient — no HTTP client dependency can reach
/// a Unix socket portably anyway.
pub async fn unix_http(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
    bearer: Option<&str>,
    client_label: Option<&str>,
) -> std::io::Result<(u16, String)> {
    for (name, value) in [
        ("bearer token", bearer.unwrap_or_default()),
        ("client label", client_label.unwrap_or_default()),
    ] {
        if value.contains(['\r', '\n']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} must not contain CR or LF"),
            ));
        }
    }
    let mut stream = tokio::net::UnixStream::connect(socket).await?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if let Some(bearer) = bearer {
        request.push_str(&format!("Authorization: Bearer {bearer}\r\n"));
    }
    if let Some(label) = client_label {
        request.push_str(&format!("X-Multitool-Client: {label}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
    } else {
        request.push_str("\r\n");
    }
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let Some((head, payload)) = raw.split_once("\r\n\r\n") else {
        return Err(std::io::Error::other("malformed HTTP response"));
    };
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::other("malformed HTTP status line"))?;
    // Bodies here are Content-Length JSON; a chunked body would carry size
    // markers, so refuse it loudly rather than pass garbage along.
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return Err(std::io::Error::other("unexpected chunked response"));
    }
    Ok((status, payload.to_string()))
}

/// This computer's shared key: read the token file, or fetch the same key
/// through the compat pair endpoint when the file is unreadable.
pub async fn shared_key(paths: &Paths, label: Option<&str>) -> Result<String, String> {
    if let Ok(token) = std::fs::read_to_string(paths.token_file()) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }
    let body = pairing_body(label);
    let (status, payload) = unix_http(
        &paths.socket_file(),
        "POST",
        "/v1/pair",
        Some(&body),
        None,
        None,
    )
    .await
    .map_err(|e| format!("could not reach the broker to fetch the shared key: {e}"))?;
    if status != 200 {
        return Err(format!("the broker refused to hand out the key: {payload}"));
    }
    serde_json::from_str::<serde_json::Value>(&payload)
        .ok()
        .and_then(|v| v["token"].as_str().map(str::to_string))
        .ok_or_else(|| "the pair response carried no token".to_string())
}

fn pairing_body(label: Option<&str>) -> String {
    serde_json::json!({
        "agent_name": label.unwrap_or("mcp-bridge"),
    })
    .to_string()
}

/// The shared key for an authenticated agent-plane call: the token file when
/// it is readable, otherwise one pair round-trip (which hands the same shared
/// key back).
async fn local_key(
    paths: &Paths,
    client_label: Option<&str>,
) -> Result<String, OpenSessionError> {
    let socket = paths.socket_file();
    let key = std::fs::read_to_string(paths.token_file())
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    match key {
        Some(key) => Ok(key),
        None => {
            let body = pairing_body(client_label);
            let (status, payload) = unix_http(&socket, "POST", "/v1/pair", Some(&body), None, None)
                .await
                .map_err(|error| transport_error(&socket, error))?;
            let value: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
            if status != 200 {
                return Err(OpenSessionError::Refused {
                    status,
                    reason: value["reason"].as_str().map(str::to_string),
                    detail: value["detail"]
                        .as_str()
                        .or_else(|| value["reason"].as_str())
                        .unwrap_or(payload.trim())
                        .to_string(),
                });
            }
            value["token"].as_str().map(str::to_string).ok_or_else(|| {
                OpenSessionError::Malformed("the pair response carried no token".to_string())
            })
        }
    }
}

/// Turn a non-200 agent-plane answer into the terminal-ready refusal.
fn refusal(status: u16, payload: &str) -> OpenSessionError {
    let value: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
    let detail = value["detail"]
        .as_str()
        .or_else(|| value["reason"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| payload.trim().to_string());
    OpenSessionError::Refused {
        status,
        reason: value["reason"].as_str().map(str::to_string),
        detail,
    }
}

impl Agent {
    /// GET an authenticated agent-plane path and return the parsed 200 body.
    pub async fn agent_get(
        &self,
        path: &str,
        client_label: Option<&str>,
    ) -> Result<serde_json::Value, OpenSessionError> {
        let (status, payload) = self.request("GET", path, None, client_label).await?;
        if status != 200 {
            return Err(refusal(status, &payload));
        }
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
        if value.is_null() {
            return Err(OpenSessionError::Malformed(
                "the broker returned a malformed response".into(),
            ));
        }
        Ok(value)
    }

    /// POST an authenticated capability open (`{"connection": name}`) to a
    /// `/v1/*/open`-shaped endpoint and return the parsed 200 body. Every
    /// other outcome — no broker, a refusal, a malformed response — becomes
    /// a one-line error ready for the terminal.
    pub async fn open_session(
        &self,
        endpoint: &str,
        connection: &str,
        client_label: Option<&str>,
    ) -> Result<serde_json::Value, OpenSessionError> {
        let body = serde_json::json!({ "connection": connection }).to_string();
        let (status, payload) = self
            .request("POST", endpoint, Some(&body), client_label)
            .await?;
        if status != 200 {
            return Err(refusal(status, &payload));
        }
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
        if !value.is_object() {
            return Err(OpenSessionError::Malformed(
                "the broker returned a malformed response".into(),
            ));
        }
        Ok(value)
    }
}

fn transport_error(socket: &Path, error: std::io::Error) -> OpenSessionError {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            OpenSessionError::NoBroker {
                socket: socket.to_path_buf(),
            }
        }
        _ => OpenSessionError::Transport {
            socket: socket.to_path_buf(),
            detail: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_body_is_json_encoded_not_interpolated() {
        let label = "quoted\"\\\nlabel";
        let body = pairing_body(Some(label));
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["agent_name"], label);
    }

    #[tokio::test]
    async fn unix_http_rejects_header_newlines_before_connecting() {
        let error = unix_http(
            Path::new("/does/not/exist"),
            "GET",
            "/",
            None,
            None,
            Some("honest\r\nX-Forged: yes"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// A stub broker on a real Unix socket: asserts the shared key rides
    /// the request, answers /v1/pg/open, refuses /v1/ssh/open.
    async fn stub_broker(paths: &Paths) {
        use axum::http::HeaderMap;
        use axum::routing::post;

        paths.ensure().unwrap();
        std::fs::write(paths.token_file(), "aka_testkey\n").unwrap();

        async fn pg_open(
            headers: HeaderMap,
            body: String,
        ) -> ([(&'static str, &'static str); 1], String) {
            assert_eq!(headers.get("authorization").unwrap(), "Bearer aka_testkey");
            assert_eq!(headers.get("x-multitool-client").unwrap(), "test-cli");
            let request: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(request["connection"], "analytics");
            (
                [("content-type", "application/json")],
                r#"{"dsn":"postgres://ticket@127.0.0.1:5599/app?sslmode=disable","ticket":"tkt_ab12","expires_in_seconds":60}"#.to_string(),
            )
        }
        async fn denied() -> (axum::http::StatusCode, String) {
            (
                axum::http::StatusCode::FORBIDDEN,
                r#"{"reason":"denied_by_policy","detail":"agent access is off for prod"}"#
                    .to_string(),
            )
        }
        let app = axum::Router::new()
            .route("/v1/pg/open", post(pg_open))
            .route("/v1/ssh/open", post(denied));
        let listener = tokio::net::UnixListener::bind(paths.socket_file()).unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    }

    #[tokio::test]
    async fn open_session_authenticates_and_parses() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        stub_broker(&paths).await;

        let body = Agent::Local(paths.clone())
            .open_session("/v1/pg/open", "analytics", Some("test-cli"))
            .await
            .unwrap();
        assert_eq!(body["ticket"], "tkt_ab12");
        assert_eq!(body["expires_in_seconds"], 60);
    }

    #[tokio::test]
    async fn open_session_surfaces_refusals_and_absence() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());

        // No broker: name the socket and the fix, not an io::Error.
        std::fs::create_dir_all(paths.token_file().parent().unwrap()).unwrap();
        std::fs::write(paths.token_file(), "aka_testkey").unwrap();
        let error = Agent::Local(paths.clone())
            .open_session("/v1/pg/open", "analytics", None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, OpenSessionError::NoBroker { .. }),
            "{error}"
        );

        // A refusal carries the broker's detail through.
        stub_broker(&paths).await;
        let error = Agent::Local(paths.clone())
            .open_session("/v1/ssh/open", "analytics", Some("test-cli"))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            OpenSessionError::Refused {
                status: 403,
                ref reason,
                ..
            } if reason.as_deref() == Some("denied_by_policy")
        ));
        assert!(error.to_string().contains("agent access is off for prod"));
    }
}
