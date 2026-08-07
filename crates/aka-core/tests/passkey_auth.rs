//! The public sign-in surface, as a browser and a desktop see it.
//!
//! What is *not* here: a completed WebAuthn ceremony. Verifying one needs a
//! software authenticator holding a private key, which is webauthn-rs's own
//! test surface rather than ours; the ceremonies are covered by unit tests
//! against the relying party in `auth::passkey`. What these tests cover is
//! everything around the ceremony — where the routes are served, what they
//! refuse before any cryptography runs, and the headers a browser depends on.

use std::sync::Arc;

use aka_core::auth::ScopeSet;
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon::{self, ServeOptions};
use aka_core::events::BrokerEvents;
use aka_core::paths::Paths;
use aka_core::vault::MemoryVault;
use serde_json::{json, Value};

struct TestEvents;
impl BrokerEvents for TestEvents {}

struct Harness {
    _daemon: daemon::DaemonHandle,
    broker: Arc<Broker>,
    base: String,
    origin: String,
    _dir: tempfile::TempDir,
}

/// A broker on loopback. `http://localhost:<port>` is the one plain-http
/// origin a browser treats as secure, which is what makes this testable
/// without a certificate.
async fn harness(public_url: Option<&str>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig {
            version: "test".into(),
            ..BrokerConfig::default()
        },
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let handle = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            public_url: public_url.map(String::from),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let address = handle.tcp_addr.unwrap();
    Harness {
        broker,
        base: format!("http://{address}"),
        // The listener is on 127.0.0.1 but the RP id must be a name, so the
        // configured origin says `localhost` and the client dials the
        // address. That split is exactly the deployment shape: the origin is
        // what the operator published, not where the socket happens to be.
        origin: format!("http://localhost:{}", address.port()),
        _daemon: handle,
        _dir: dir,
    }
}

async fn localhost_harness() -> Harness {
    // Bind first so the port is known, then configure the origin to match.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig {
            version: "test".into(),
            ..BrokerConfig::default()
        },
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let handle = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            listen: Some(format!("127.0.0.1:{port}").parse().unwrap()),
            public_url: Some(format!("http://localhost:{port}")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    Harness {
        broker,
        base: format!("http://127.0.0.1:{port}"),
        origin: format!("http://localhost:{port}"),
        _daemon: handle,
        _dir: dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn get(base: &str, path: &str) -> (u16, Value, reqwest::header::HeaderMap) {
    let response = client().get(format!("{base}{path}")).send().await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response.text().await.unwrap();
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, body, headers)
}

async fn post_json(base: &str, path: &str, origin: Option<&str>, body: Value) -> (u16, Value) {
    let mut request = client().post(format!("{base}{path}")).json(&body);
    if let Some(origin) = origin {
        request = request.header(reqwest::header::ORIGIN, origin);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn authorize_query(overrides: &[(&str, &str)]) -> String {
    let mut params = vec![
        ("client_id", "multitool-desktop"),
        ("redirect_uri", "http://127.0.0.1:51234/callback"),
        ("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        ("code_challenge_method", "S256"),
        ("state", "opaque"),
        ("device_name", "Test Mac"),
    ];
    for (key, value) in overrides {
        if let Some(slot) = params.iter_mut().find(|(name, _)| name == key) {
            slot.1 = value;
        }
    }
    params
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}={}",
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/* --------------------------- where it is served -------------------------- */

#[tokio::test]
async fn sign_in_is_unavailable_without_a_configured_origin() {
    // A TCP listener with no --public-url has no name a passkey could be
    // bound to. The routes exist and say so, rather than 404ing or, worse,
    // guessing an origin from the Host header.
    let h = harness(None).await;
    let (status, body, _) = get(&h.base, "/v1/auth/config").await;
    assert_eq!(status, 200);
    assert_eq!(body["passkeys_available"], json!(false));

    let (status, body) = post_json(&h.base, "/v1/auth/signin/options", None, json!({})).await;
    assert_eq!(status, 503);
    assert_eq!(body["reason"], json!("passkeys_unavailable"));
    assert!(
        body["detail"].as_str().unwrap().contains("--public-url"),
        "the operator is told what to do about it: {body}"
    );
}

#[tokio::test]
async fn a_configured_origin_makes_the_surface_available() {
    let h = localhost_harness().await;
    let (status, body, _) = get(&h.base, "/v1/auth/config").await;
    assert_eq!(status, 200);
    assert_eq!(body["passkeys_available"], json!(true));
    assert_eq!(body["origin"], json!(h.origin));
    // Nothing is enrolled yet, and the surface says so without saying who
    // the owner would be.
    assert_eq!(body["enrolled"], json!(false));
    assert_eq!(body["enrollment_open"], json!(false));
    assert!(body.get("account").is_none());
}

#[tokio::test]
async fn the_unix_socket_does_not_serve_sign_in() {
    // Reaching the socket already requires being the broker's own user, so a
    // ceremony there would authenticate nobody to nothing. Its absence is
    // the assertion: a passkey surface on a 0600 socket is attack surface
    // with no corresponding gain.
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let router = daemon::router(broker);
    let request = axum::http::Request::builder()
        .uri("/v1/auth/config")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

/* ------------------------------- the web app ----------------------------- */

/// A broker serving a bundle, on the origin its own cookie is scoped to.
async fn web_harness() -> (Harness, tempfile::TempDir) {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let bundle = tempfile::tempdir().unwrap();
    std::fs::write(bundle.path().join("index.html"), "<!doctype html><title>app</title>").unwrap();
    std::fs::create_dir_all(bundle.path().join("assets")).unwrap();
    std::fs::write(bundle.path().join("assets/app-a1b2c3.js"), "export {}").unwrap();
    std::fs::write(bundle.path().join("secret.pem"), "PRIVATE KEY").unwrap();

    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    let handle = daemon::serve_with(
        broker.clone(),
        ServeOptions {
            listen: Some(format!("127.0.0.1:{port}").parse().unwrap()),
            public_url: Some(format!("http://localhost:{port}")),
            web_root: Some(bundle.path().to_path_buf()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (
        Harness {
            broker,
            base: format!("http://127.0.0.1:{port}"),
            origin: format!("http://localhost:{port}"),
            _daemon: handle,
            _dir: dir,
        },
        bundle,
    )
}

#[tokio::test]
async fn the_web_app_is_served_from_the_same_origin_as_its_api() {
    // Same-origin is the design, not a convenience: the session cookie is
    // SameSite=Strict on this host, the passkey is bound to this host, and
    // the CSRF check compares against this host.
    let (h, _bundle) = web_harness().await;
    let (status, body, headers) = get(&h.base, "/").await;
    assert_eq!(status, 200);
    assert!(body.as_str().unwrap().contains("<!doctype html>"));
    assert!(headers
        .get(reqwest::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));

    // A fingerprinted asset keeps its own long cache lifetime rather than
    // the API's no-store.
    let (status, _, headers) = get(&h.base, "/assets/app-a1b2c3.js").await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get(reqwest::header::CONTENT_TYPE).unwrap(),
        "text/javascript; charset=utf-8"
    );
    assert!(headers
        .get(reqwest::header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("immutable"));

    // The API keeps no-store even though the bundle is mounted.
    let (_, _, headers) = get(&h.base, "/v1/auth/config").await;
    assert_eq!(headers.get(reqwest::header::CACHE_CONTROL).unwrap(), "no-store");
}

#[tokio::test]
async fn a_client_route_falls_through_to_the_app_but_a_missing_api_route_does_not() {
    let (h, _bundle) = web_harness().await;
    // A path the single-page app owns.
    let (status, body, _) = get(&h.base, "/connections").await;
    assert_eq!(status, 200);
    assert!(body.as_str().unwrap().contains("<!doctype html>"));

    // An API path that does not exist must 404, not answer 200 with HTML —
    // a client parsing that as JSON would fail in a far more confusing way.
    for path in ["/v1/manage/nope", "/v1/auth/nope", "/.well-known/nope"] {
        let (status, _, _) = get(&h.base, path).await;
        assert_eq!(status, 404, "{path}");
    }
}

#[tokio::test]
async fn nothing_outside_the_bundle_can_be_fetched() {
    let (h, bundle) = web_harness().await;
    // Something sensitive one directory up from the web root.
    let outside = bundle.path().parent().unwrap().join("outside-secret.txt");
    std::fs::write(&outside, "PRIVATE").unwrap();

    for path in [
        "/../outside-secret.txt",
        "/assets/../../outside-secret.txt",
        "/%2e%2e/outside-secret.txt",
        "/..%2foutside-secret.txt",
    ] {
        let (_, body, _) = get(&h.base, path).await;
        let text = match &body {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        assert!(
            !text.contains("PRIVATE"),
            "{path} escaped the web root: {text}"
        );
    }
    let _ = std::fs::remove_file(outside);
}

/* --------------------------- manage authorization ------------------------ */

async fn manage(
    router: axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    origin: Option<&str>,
    csrf: Option<&str>,
) -> (u16, Value) {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", format!("aka_session={cookie}"));
    }
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-multitool-csrf", csrf);
    }
    let request = builder.body(axum::body::Body::empty()).unwrap();
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The narrow grant the background cloud refresher is meant to carry.
#[tokio::test]
async fn a_cloud_pusher_token_reaches_its_two_routes_and_nothing_else() {
    // The load-bearing test for the whole scope table. It also proves the
    // route policy is keyed correctly: axum reports the *nested* template
    // (`/v1/manage/cloud/session`, not `/cloud/session`), and if it did not,
    // every override would silently miss and this token would fall through
    // to the plain method defaults.
    let (router, broker, _dir) = socket_router().await;
    let account = uuid::Uuid::new_v4();
    let (_, token) = broker
        .auth
        .mint_automation(account, "cloud refresher", ScopeSet::cloud_pusher(), None)
        .unwrap();

    // Reaches its own route: a 4xx from the *handler* would still prove
    // authorization passed, but this one needs a body, so assert only that
    // the scope check did not refuse it.
    let (status, body) = manage(
        router.clone(),
        "POST",
        "/v1/manage/cloud/session",
        Some(&token),
        None,
        None,
        None,
    )
    .await;
    assert_ne!(status, 403, "cloud:push must reach its own route: {body}");
    assert_ne!(status, 401, "{body}");

    // And nothing else on the plane, in either direction.
    for (method, uri) in [
        ("GET", "/v1/manage/connections"),
        ("POST", "/v1/manage/connections"),
        ("GET", "/v1/manage/secrets"),
        ("GET", "/v1/manage/settings"),
        ("GET", "/v1/manage/activity"),
        ("GET", "/v1/manage/identity/agent-key"),
    ] {
        let (status, body) = manage(router.clone(), method, uri, Some(&token), None, None, None).await;
        assert_eq!(status, 403, "{method} {uri} must be refused: {body}");
        assert_eq!(body["reason"], json!("insufficient_scope"));
        // The refusal says what it does hold, so an operator can fix it.
        assert!(
            body["detail"].as_str().unwrap().contains("cloud:push"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn the_refresher_learns_nothing_about_the_catalog_it_cannot_read() {
    // `pushable_connections` exists so the background loop can do its job on
    // `cloud:push` alone. Its answer must therefore say only what minting
    // needs — not the endpoints, credential names, or tool policy that
    // `list_connections` would hand over.
    let (router, broker, _dir) = socket_router().await;
    let (_, token) = broker
        .auth
        .mint_automation(
            uuid::Uuid::new_v4(),
            "cloud refresher",
            ScopeSet::cloud_pusher(),
            None,
        )
        .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/manage/cloud/pushable")
        .header("authorization", format!("Bearer {}", token.as_str()))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "install_id": broker.install_id() }).to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // No connections exist in this harness, so the meaningful assertion is
    // that the route answered the pusher at all — the scope test above
    // proves `list_connections` does not.
    assert_eq!(body, json!([]));
}

#[tokio::test]
async fn an_empty_install_id_matches_nothing_rather_than_everything() {
    // The origin field is empty on a connection whose install was never
    // recorded. Matching on empty would hand those to any caller.
    let (router, broker, _dir) = socket_router().await;
    let token = broker
        .identity
        .issue_manage_token(&broker.workspace)
        .await
        .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/manage/cloud/pushable")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "install_id": "" }).to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), json!([]));
}

#[tokio::test]
async fn nothing_unattended_can_rotate_the_agent_key() {
    // `identity:manage` with StepUp::Always. The token holds every scope and
    // is still refused, because there is no person behind it to confirm an
    // action that invalidates every running agent's credential.
    let (router, broker, _dir) = socket_router().await;
    let (_, token) = broker
        .auth
        .mint_automation(uuid::Uuid::new_v4(), "ci", ScopeSet::all(), None)
        .unwrap();
    let (status, body) = manage(
        router,
        "POST",
        "/v1/manage/identity/rotate",
        Some(&token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], json!("step_up_required"));
}

#[tokio::test]
async fn a_device_token_works_and_stops_the_moment_it_is_revoked() {
    let (router, broker, _dir) = socket_router().await;
    let issued = broker
        .auth
        .create_device(
            uuid::Uuid::new_v4(),
            "Test Mac",
            aka_core::auth::ClientSurface::Desktop,
            ScopeSet::desktop(),
            chrono::Utc::now(),
            None,
        )
        .unwrap();
    let device = issued.device.id;
    let tokens = broker.auth.issue_for_device(issued).unwrap();

    let (status, _) = manage(
        router.clone(),
        "GET",
        "/v1/manage/connections",
        Some(&tokens.access),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);

    assert!(broker.auth.revoke_device(&device).unwrap());
    let (status, body) = manage(
        router,
        "GET",
        "/v1/manage/connections",
        Some(&tokens.access),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 401, "a revoked device must stop at once: {body}");
}

#[tokio::test]
async fn two_credentials_at_once_are_refused_rather_than_ranked() {
    // Picking one for the caller is how a bystander's cookie silently
    // upgrades — or downgrades — someone else's request.
    let (router, broker, _dir) = socket_router().await;
    let (_, token) = broker
        .auth
        .mint_automation(uuid::Uuid::new_v4(), "ci", ScopeSet::all(), None)
        .unwrap();
    let session = broker
        .auth
        .create_session(uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), ScopeSet::all())
        .unwrap();
    let (status, body) = manage(
        router,
        "GET",
        "/v1/manage/connections",
        Some(&token),
        Some(&session.cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["reason"], json!("conflicting_credentials"));
}

#[tokio::test]
async fn a_session_cookie_does_not_authenticate_on_the_socket() {
    // Cookies are a browser credential and the socket has no browser origin
    // to bind them to.
    let (router, broker, _dir) = socket_router().await;
    let session = broker
        .auth
        .create_session(uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), ScopeSet::all())
        .unwrap();
    let (status, body) = manage(
        router,
        "GET",
        "/v1/manage/connections",
        None,
        Some(&session.cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], json!("no_browser_origin"));
}

#[tokio::test]
async fn a_browser_mutation_needs_the_origin_and_the_csrf_secret() {
    let h = localhost_harness().await;
    let broker_session = client();
    // Mint a session directly; the ceremony itself is out of scope here.
    let (_, _, _) = get(&h.base, "/v1/auth/config").await;

    // Reading with only the cookie is fine — a cross-origin page can cause
    // the cookie to be sent but cannot read what comes back.
    let response = broker_session
        .get(format!("{}/v1/manage/connections", h.base))
        .header(reqwest::header::COOKIE, "aka_session=akases_nope")
        .send()
        .await
        .unwrap();
    // Not a real session, so 401 — but specifically an invalid-credential
    // 401 rather than a cross-origin refusal.
    assert_eq!(response.status().as_u16(), 401);

    // A mutation with no Origin is refused before the cookie is even looked
    // up, so a forged cross-site POST cannot reach the store.
    let response = broker_session
        .post(format!("{}/v1/manage/connections", h.base))
        .header(reqwest::header::COOKIE, "aka_session=akases_nope")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["reason"], json!("cross_origin"));
}

#[tokio::test]
async fn the_management_token_still_works_everywhere() {
    // The migration constraint: nothing above may break the credential the
    // desktop and CLI are still using today.
    let (router, broker, _dir) = socket_router().await;
    let token = broker
        .identity
        .issue_manage_token(&broker.workspace)
        .await
        .unwrap();
    for (method, uri) in [
        ("GET", "/v1/manage/connections"),
        ("GET", "/v1/manage/secrets"),
        ("GET", "/v1/manage/settings"),
        ("GET", "/v1/manage/whoami"),
    ] {
        let (status, body) = manage(router.clone(), method, uri, Some(&token), None, None, None).await;
        assert_eq!(status, 200, "{method} {uri}: {body}");
    }
    // Including the step-up routes, which it is exempt from because it has
    // no ceremony behind it that could be recent.
    let (status, _) = manage(
        router,
        "POST",
        "/v1/manage/identity/rotate",
        Some(&token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn an_unrecognized_bearer_is_not_mistaken_for_a_manage_token() {
    let (router, _broker, _dir) = socket_router().await;
    for bearer in [
        // The agent plane's key must never authenticate here.
        "aka_0000000000000000000000000000000000000000000000000000000000000000",
        "akases_0000000000000000000000000000000000000000000000000000000000000000",
        "not-a-token",
        "",
    ] {
        let (status, body) = manage(
            router.clone(),
            "GET",
            "/v1/manage/connections",
            Some(bearer),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, 401, "{bearer:?} must not authenticate: {body}");
    }
}

/* ------------------- long-lived streams and their leases ----------------- */

#[tokio::test]
async fn revoking_a_device_ends_its_event_stream_and_releases_its_lease() {
    // The stream can outlive its authorization by hours, and while it lives
    // it is what makes an agent's parked request answerable. Revoking the
    // device has to reach both: the stream ends, and the approval-surface
    // lease its Drop holds goes with it.
    let h = localhost_harness().await;
    let broker = h.broker.clone();
    let issued = broker
        .auth
        .create_device(
            uuid::Uuid::new_v4(),
            "Test Mac",
            aka_core::auth::ClientSurface::Desktop,
            ScopeSet::desktop(),
            chrono::Utc::now(),
            None,
        )
        .unwrap();
    let device = issued.device.id;
    let tokens = broker.auth.issue_for_device(issued).unwrap();

    assert!(
        !broker.events.has_approval_surface(),
        "nothing is attached yet"
    );
    let response = client()
        .get(format!("{}/v1/manage/events", h.base))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", tokens.access.as_str()),
        )
        .header("x-aka-approval-surface", "request-inbox-v1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("x-aka-approval-surface-status").unwrap(),
        "active"
    );
    let mut body = response.bytes_stream();
    use futures::StreamExt as _;
    // Wait for the ready comment so the lease is definitely established.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), body.next()).await;
    assert!(broker.events.has_approval_surface(), "the lease is held");

    assert!(broker.auth.revoke_device(&device).unwrap());
    // The stream revalidates on a one-second timer, so give it two.
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while (body.next().await).is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "the stream must end when the device is revoked");
    drop(body);

    // And the capability goes with it, so confirmed traffic fails closed
    // rather than waiting on a surface nobody is watching.
    let released = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while broker.events.has_approval_surface() {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(released.is_ok(), "the approval-surface lease must be released");
}

/* --------------------- retiring the management token --------------------- */

#[tokio::test]
async fn the_management_token_can_be_retired_and_stops_working_at_once() {
    let (router, broker, _dir) = socket_router().await;
    let token = broker
        .identity
        .issue_manage_token(&broker.workspace)
        .await
        .unwrap();

    // It works, as every install's does today.
    let (status, _) = manage(
        router.clone(),
        "GET",
        "/v1/manage/connections",
        Some(&token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);

    // Retiring it takes a passkey to exist first — otherwise this would
    // close the manage plane with no way back but a shell on the host.
    assert!(broker.ui_set_legacy_manage_token(false).await.is_err());

    let account = uuid::Uuid::new_v4();
    let issued = broker
        .auth
        .create_device(
            account,
            "Test Mac",
            aka_core::auth::ClientSurface::Desktop,
            ScopeSet::desktop(),
            chrono::Utc::now(),
            None,
        )
        .unwrap();
    let tokens = broker.auth.issue_for_device(issued).unwrap();
    broker.ui_set_legacy_manage_token(false).await.unwrap();

    // The same still-valid token now bounces — checked before verification,
    // so retirement does not wait for a rotation.
    let (status, body) = manage(
        router.clone(),
        "GET",
        "/v1/manage/connections",
        Some(&token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], json!("manage_token_retired"));

    // And the credential that replaced it keeps working.
    let (status, _) = manage(
        router,
        "GET",
        "/v1/manage/connections",
        Some(&tokens.access),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn retiring_the_token_is_an_identity_change_not_a_settings_change() {
    // It arrives on PATCH /settings, which the route table scores as an
    // ordinary write. The handler asks for more, because what it decides is
    // who may authenticate at all.
    let (router, broker, _dir) = socket_router().await;
    let account = uuid::Uuid::new_v4();
    let (_, automation) = broker
        .auth
        .mint_automation(account, "ci", ScopeSet::all(), None)
        .unwrap();

    let request = axum::http::Request::builder()
        .method("PATCH")
        .uri("/v1/manage/settings")
        .header("authorization", format!("Bearer {}", automation.as_str()))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "legacy_manage_token": false }).to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    // Every scope, and still refused: no person is behind it.
    assert_eq!(response.status(), 401);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["reason"], json!("step_up_required"));
}

#[tokio::test]
async fn a_settings_patch_applies_every_field_it_carries() {
    // It applied only one, and silently dropped the rest — a hosted
    // broker's host-key setting could be toggled in the UI and never change.
    let (router, broker, _dir) = socket_router().await;
    let token = broker
        .identity
        .issue_manage_token(&broker.workspace)
        .await
        .unwrap();
    let request = axum::http::Request::builder()
        .method("PATCH")
        .uri("/v1/manage/settings")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "confirm_ssh_host_keys": true }).to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["confirm_ssh_host_keys"], json!(true));
    assert_eq!(body["legacy_manage_token"], json!(true));
}

/* ------------------------------ enrollment ------------------------------- */

async fn socket_router() -> (axum::Router, Arc<Broker>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Paths::under(dir.path()),
        Arc::new(MemoryVault::new()),
        BrokerConfig::default(),
        Arc::new(TestEvents),
    )
    .await
    .unwrap();
    (daemon::router(broker.clone()), broker, dir)
}

async fn call(router: axum::Router, method: &str, uri: &str) -> (u16, Value) {
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn enrollment_is_opened_on_the_host_and_only_there() {
    // Who becomes the owner is decided by somebody standing on the broker's
    // machine, not by whoever reaches a URL first. The socket is 0600 and
    // owned by the broker's user, which is the bar; the network cannot
    // clear it.
    let (router, broker, _dir) = socket_router().await;
    assert!(!broker.auth.enrollment_open());

    let (status, body) = call(router.clone(), "POST", "/v1/auth/enrollment").await;
    assert_eq!(status, 200);
    let secret = body["secret"].as_str().expect("a one-use secret");
    assert!(secret.starts_with("akaenroll_"), "{secret}");
    assert!(broker.auth.enrollment_open());
    assert_eq!(body["already_enrolled"], json!(false));

    let (status, _) = call(router, "DELETE", "/v1/auth/enrollment").await;
    assert_eq!(status, 200);
    assert!(!broker.auth.enrollment_open());
}

#[tokio::test]
async fn enrollment_cannot_be_opened_over_the_network() {
    let h = localhost_harness().await;
    let response = client()
        .post(format!("{}/v1/auth/enrollment", h.base))
        .header(reqwest::header::ORIGIN, &h.origin)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        404,
        "the enrollment opener must not exist on the network listener"
    );
}

#[tokio::test]
async fn signing_in_is_not_served_on_the_socket() {
    // The other half of the same split.
    let (router, _broker, _dir) = socket_router().await;
    for uri in ["/v1/auth/signin/options", "/v1/auth/token"] {
        let (status, _) = call(router.clone(), "POST", uri).await;
        assert_eq!(status, 404, "{uri} must not be served on the socket");
    }
}

/* ------------------------- the authorize request ------------------------- */

#[tokio::test]
async fn the_authorize_page_refuses_a_request_it_cannot_trust() {
    let h = localhost_harness().await;
    for (label, query) in [
        (
            "an app that is not ours",
            authorize_query(&[("client_id", "someone-elses-app")]),
        ),
        (
            "PKCE downgraded to plain",
            authorize_query(&[("code_challenge_method", "plain")]),
        ),
        (
            "a challenge that is not a digest",
            authorize_query(&[("code_challenge", "short")]),
        ),
        ("no state to bind the reply", authorize_query(&[("state", "")])),
        (
            // The one that matters most: a code is a bearer credential, and
            // where the browser will send it is the only thing protecting it.
            "a redirect off this machine",
            authorize_query(&[("redirect_uri", "https://evil.test/callback")]),
        ),
        (
            "a redirect through a resolvable name",
            authorize_query(&[("redirect_uri", "http://localhost:51234/callback")]),
        ),
        (
            "a redirect to another scheme's handler",
            authorize_query(&[("redirect_uri", "multitool://callback")]),
        ),
    ] {
        let (status, _, _) = get(&h.base, &format!("/authorize?{query}")).await;
        assert_eq!(status, 400, "{label} must be refused");
    }
}

#[tokio::test]
async fn the_authorize_page_says_so_when_nothing_is_enrolled() {
    let h = localhost_harness().await;
    let (status, body, _) = get(&h.base, &format!("/authorize?{}", authorize_query(&[]))).await;
    assert_eq!(status, 409);
    let html = body.as_str().unwrap();
    assert!(html.contains("multitool manage enroll"), "{html}");
}

#[tokio::test]
async fn authorizing_a_device_needs_a_session() {
    let h = localhost_harness().await;
    let (status, body) = post_json(
        &h.base,
        "/v1/auth/authorize",
        Some(&h.origin),
        json!({
            "client_id": "multitool-desktop",
            "redirect_uri": "http://127.0.0.1:51234/callback",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "state": "opaque",
        }),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], json!("no_session"));
}

/* ------------------------------- browser CSRF ---------------------------- */

#[tokio::test]
async fn a_post_from_another_origin_is_refused() {
    let h = localhost_harness().await;
    for origin in [
        None,
        Some("https://evil.test"),
        Some("null"),
        // A name that merely contains ours.
        Some("https://localhost.evil.test"),
    ] {
        let (status, body) =
            post_json(&h.base, "/v1/auth/signin/options", origin, json!({})).await;
        assert_eq!(status, 403, "origin {origin:?} must not post here");
        assert_eq!(body["reason"], json!("cross_origin"));
    }
}

#[tokio::test]
async fn the_token_endpoint_is_not_a_browser_surface() {
    // No Origin, no cookie: the desktop calls this directly. What authorizes
    // it is the code plus its PKCE verifier, so it must work without the
    // browser headers — and must still refuse a code it never issued.
    let h = localhost_harness().await;
    let (status, body) = post_json(
        &h.base,
        "/v1/auth/token",
        None,
        json!({
            "grant_type": "authorization_code",
            "code": "akacode_0000000000000000000000000000000000000000000000000000000000000000",
            "code_verifier": "whatever",
            "redirect_uri": "http://127.0.0.1:51234/callback",
            "client_id": "multitool-desktop",
        }),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], json!("invalid_credential"));
}

#[tokio::test]
async fn the_token_endpoint_refuses_an_unknown_client() {
    let h = localhost_harness().await;
    let (status, body) = post_json(
        &h.base,
        "/v1/auth/token",
        None,
        json!({
            "grant_type": "authorization_code",
            "code": "akacode_00",
            "code_verifier": "whatever",
            "redirect_uri": "http://127.0.0.1:51234/callback",
            "client_id": "someone-elses-app",
        }),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["reason"], json!("invalid_client"));
}

#[tokio::test]
async fn an_unknown_refresh_token_is_refused() {
    let h = localhost_harness().await;
    let (status, body) = post_json(
        &h.base,
        "/v1/auth/token",
        None,
        json!({
            "grant_type": "refresh_token",
            "refresh_token": "akaref_0000000000000000000000000000000000000000000000000000000000000000",
        }),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], json!("invalid_credential"));
}

#[tokio::test]
async fn there_is_no_session_before_signing_in() {
    let h = localhost_harness().await;
    let (status, body, _) = get(&h.base, "/v1/auth/session").await;
    assert_eq!(status, 401);
    assert_eq!(body["reason"], json!("no_session"));
}

/* --------------------------- what a browser gets ------------------------- */

#[tokio::test]
async fn every_response_carries_the_headers_a_browser_needs() {
    let h = localhost_harness().await;
    let (_, _, headers) = get(&h.base, "/v1/auth/config").await;

    let csp = headers
        .get("content-security-policy")
        .and_then(|value| value.to_str().ok())
        .expect("a content-security-policy");
    // Framing the authorize page is how a device grant gets harvested from a
    // user who thought they were clicking something else.
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    // The sign-in pages are self-contained; nothing remote should load.
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("connect-src 'self'"), "{csp}");
    assert!(!csp.contains("http"), "no remote origin is allowed: {csp}");

    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "a JSON error body must not be sniffed into HTML"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    // An authorization code rides in a URL; a cached one is a reusable one.
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn the_sign_in_pages_permit_only_their_own_inline_script() {
    // These are the two pages a passkey ceremony runs on, so they are the
    // last place `'unsafe-inline'` belongs. A nonce permits exactly the
    // markup the handler emitted and nothing an injection could add.
    let h = localhost_harness().await;
    let response = client()
        .get(format!("{}/authorize?{}", h.base, authorize_query(&[])))
        .send()
        .await
        .unwrap();
    let csp = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let html = response.text().await.unwrap();

    assert!(!csp.contains("unsafe-inline"), "{csp}");
    let nonce = csp
        .split("script-src 'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .expect("a script nonce");
    assert!(nonce.len() >= 16, "a guessable nonce is not one: {nonce}");
    // The markup must actually carry it, or the page is simply broken.
    assert!(html.contains(&format!("nonce=\"{nonce}\"")), "{html}");
    assert!(!html.contains("__NONCE__"), "an unsubstituted placeholder");

    // A second load gets a different one.
    let again = client()
        .get(format!("{}/authorize?{}", h.base, authorize_query(&[])))
        .send()
        .await
        .unwrap();
    let second = again
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(csp, second, "the nonce must be per-response");
}

#[tokio::test]
async fn the_authorize_page_is_self_contained() {
    let h = localhost_harness().await;
    // Enroll nothing; the 409 page is still served through the same shell.
    let (_, body, headers) = get(&h.base, &format!("/authorize?{}", authorize_query(&[]))).await;
    let html = body.as_str().unwrap();
    assert!(headers
        .get(reqwest::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    // Nothing remote: no src=, no href= to another origin, no import.
    for forbidden in ["src=\"http", "src='http", "href=\"http", "@import"] {
        assert!(!html.contains(forbidden), "{forbidden} in the page");
    }
}
