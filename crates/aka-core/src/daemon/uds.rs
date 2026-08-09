//! Who is on the other end of a Unix-socket connection.
//!
//! The TCP listener has always had `ConnectInfo<SocketAddr>`; the Unix socket
//! had nothing, because `axum::serve` only attaches connection info when it is
//! asked to. This is the equivalent for the socket, and it is the input to
//! [`crate::attest`].
//!
//! The capture happens at **accept**, not per request, and that timing is the
//! security property. A pid on its own is a racy handle — the process can exit
//! and the number be reused — so the peer's start time is read here, in the
//! moment the kernel hands us a connection from a process that is by
//! definition still alive. Every later resolution re-checks that start time, so
//! a recycled pid resolves to nothing rather than to the wrong program.

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::UnixListener;

use crate::attest::PeerProcess;

/// The process that opened a control-socket connection, when the OS would say.
///
/// `None` covers a platform without peer credentials and a peer that exited
/// between accept and the lookup. Both mean the same thing downstream: nothing
/// was proven, so nothing is claimed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UdsPeer(pub Option<PeerProcess>);

impl UdsPeer {
    /// Read the peer's credentials and pin its start time.
    pub fn capture(stream: &tokio::net::UnixStream) -> Self {
        let Ok(cred) = stream.peer_cred() else {
            return UdsPeer(None);
        };
        // `pid()` is `Option` because not every Unix exposes it; macOS and
        // Linux both do.
        let Some(pid) = cred.pid() else {
            return UdsPeer(None);
        };
        let Some(platform) = crate::attest::platform() else {
            return UdsPeer(None);
        };
        let Some(info) = platform.process(pid) else {
            return UdsPeer(None);
        };
        UdsPeer(Some(PeerProcess {
            pid,
            uid: cred.uid(),
            start_time: info.start_time,
        }))
    }
}

impl Connected<IncomingStream<'_, UnixListener>> for UdsPeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        UdsPeer::capture(stream.io())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_connected_peer_is_captured_with_its_start_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sock");
        let listener = UnixListener::bind(&path).unwrap();
        let client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let peer = UdsPeer::capture(&server);
        drop(client);

        // Both ends are this test process, so the capture is checkable against
        // what the process already knows about itself.
        #[cfg(target_os = "macos")]
        {
            let captured = peer.0.expect("macOS reports peer credentials");
            assert_eq!(captured.pid, std::process::id() as i32);
            // SAFETY: getuid cannot fail.
            assert_eq!(captured.uid, unsafe { libc::getuid() });
            assert!(captured.start_time > 0);
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Without a platform attestor there is no start time to pin, so
            // the capture is deliberately empty rather than half-populated.
            assert!(peer.0.is_none());
        }
    }
}
