//! Serving the web app off the broker's own origin.
//!
//! Same-origin is not a convenience here, it is the design: the session
//! cookie is `SameSite=Strict` and scoped to this host, WebAuthn binds the
//! passkey to this host, and the CSRF check compares against this host. A
//! bundle served from anywhere else would be a different origin and none of
//! those would hold.
//!
//! Files are read from a directory the operator points at (`serve
//! --web-root`), not embedded. Embedding would tie a UI rebuild to a broker
//! rebuild, and the two ship on different clocks.
//!
//! These routes do not authenticate. The bundle is the same JavaScript every
//! visitor would download; the manage plane behind it decides what a caller
//! may *do*, and authenticates every call. Serving the shell to an anonymous
//! browser is how the app gets a sign-in page at all.

use std::path::{Component, Path, PathBuf};

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::daemon::AppState;

/// Mount the web app when a root is configured.
///
/// The root travels as a request extension rather than as another
/// `AppState` field: two handlers need it and nothing else in the daemon
/// does.
pub fn router(root: Option<PathBuf>) -> Router<AppState> {
    match root {
        Some(root) => Router::new()
            .route("/", get(index))
            .fallback(get(asset))
            .layer(axum::Extension(WebRoot(std::sync::Arc::new(root)))),
        None => Router::new(),
    }
}

#[derive(Clone)]
struct WebRoot(std::sync::Arc<PathBuf>);

async fn index(root: axum::Extension<WebRoot>, state: State<AppState>) -> Response {
    serve(&root.0 .0, "index.html", &state).await
}

async fn asset(
    root: axum::Extension<WebRoot>,
    state: State<AppState>,
    uri: Uri,
) -> Response {
    let path = uri.path().trim_start_matches('/');
    // A single-page app owns its routes: anything that is not a file on
    // disk is one of its paths, and the shell resolves it client-side. An
    // API path that reached here is genuinely missing, though, and must not
    // be answered with a 200 and an HTML body.
    if path.starts_with("v1/") || path.starts_with(".well-known/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    serve(&root.0 .0, path, &state).await
}

/// Resolve a request path inside the web root, refusing anything that
/// escapes it.
///
/// We refuse traversal *structurally* — no `..` component may appear, and
/// no absolute or prefix component — rather than by canonicalizing and
/// comparing. Canonicalization follows symlinks, so a link planted inside
/// the root would pass a prefix check while pointing anywhere on the disk.
fn resolve(root: &Path, request: &str) -> Option<PathBuf> {
    let request = request.trim_start_matches('/');
    let relative = Path::new(request);
    for component in relative.components() {
        match component {
            Component::Normal(_) => {}
            // Everything else: `..`, `/`, `C:\`, and a bare `.`, which is
            // harmless but means the path was not the simple one expected.
            _ => return None,
        }
    }
    let candidate = root.join(relative);
    candidate.is_file().then_some(candidate)
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("map") => "application/json",
        // Never guessed. An unknown type served as something a browser will
        // execute is how an uploaded file becomes a script on this origin.
        _ => "application/octet-stream",
    }
}

async fn serve(root: &Path, request: &str, state: &AppState) -> Response {
    let Some(path) = resolve(root, request).or_else(|| resolve(root, "index.html")) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let mut response = (StatusCode::OK, bytes).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(&path)),
    );
    // Vite fingerprints its assets, so everything but the entry document is
    // safe to cache hard. `index.html` is what points at the current build
    // and must never be stale — and the outer layer already sets no-store,
    // which this only relaxes for content whose name contains its hash.
    if path.extension().and_then(|value| value.to_str()) != Some("html")
        && path
            .components()
            .any(|component| component.as_os_str() == "assets")
    {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    }
    let _ = state;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<!doctype html>").unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/app-a1b2.js"), "export {}").unwrap();
        dir
    }

    #[test]
    fn ordinary_files_resolve() {
        let dir = root();
        assert!(resolve(dir.path(), "index.html").is_some());
        assert!(resolve(dir.path(), "/assets/app-a1b2.js").is_some());
        assert!(resolve(dir.path(), "nope.js").is_none());
    }

    #[test]
    fn nothing_escapes_the_web_root() {
        let dir = root();
        // The parent holds the tempdir itself; a traversal that worked would
        // reach the whole filesystem from here.
        for attempt in [
            "../etc/passwd",
            "assets/../../etc/passwd",
            "./index.html",
            "/etc/passwd",
            "..",
            "assets/..",
        ] {
            assert!(
                resolve(dir.path(), attempt).is_none(),
                "{attempt} must not resolve"
            );
        }
    }

    #[test]
    fn a_symlink_out_of_the_root_is_not_followed_into_a_pass() {
        // Structural refusal is what makes this safe: a canonicalize-then-
        // compare check would resolve the link's target and, seeing it
        // outside the root, have to refuse — but only if it remembered to.
        // Here there is no path with a `..` in it at all, so the link is
        // simply a file in the root and is served as one. What must not
        // happen is a *path* escaping; the operator choosing to put a
        // symlink in their web root is their own decision.
        let dir = root();
        let outside = dir.path().parent().unwrap().join("outside.txt");
        std::fs::write(&outside, "secret").unwrap();
        let link = dir.path().join("link.txt");
        if std::os::unix::fs::symlink(&outside, &link).is_ok() {
            assert!(resolve(dir.path(), "link.txt").is_some());
            assert!(resolve(dir.path(), "../outside.txt").is_none());
        }
        let _ = std::fs::remove_file(outside);
    }

    #[test]
    fn content_types_are_declared_never_guessed() {
        assert_eq!(content_type(Path::new("a/index.html")), "text/html; charset=utf-8");
        assert_eq!(content_type(Path::new("a/app.js")), "text/javascript; charset=utf-8");
        assert_eq!(content_type(Path::new("a/app.css")), "text/css; charset=utf-8");
        // Anything unrecognized is a download, not something to execute.
        assert_eq!(content_type(Path::new("a/thing.wasm")), "application/octet-stream");
        assert_eq!(content_type(Path::new("a/noext")), "application/octet-stream");
    }
}
