//! Client-side storage for the management token.
//!
//! The token authorizes full management of a (possibly remote) broker, so
//! it gets the same treatment the broker gives its own secrets: the macOS
//! Keychain where available, and a 0600 file fallback elsewhere (dev/CI
//! parity with the core's `FileVault`, with the same warning). One token is
//! stored per broker URL, so switching brokers never silently reuses the
//! wrong credential.
//!
//! On macOS this goes through the same data-protection keychain the vault
//! uses (see `aka_core::keychain`), so a signed build reads its stored token
//! without an ACL dialog. Unlike a secret value a token is re-obtainable, so
//! a build that cannot reach that keychain quietly falls back to the login
//! keychain and, finding nothing, asks for `aka admin login` again.

use std::path::PathBuf;

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use aka_core::keychain::{darwin::SecurityFramework, Keychain, KeychainApi as _, KeychainError};

/// Keychain service for stored management tokens.
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.aka.desktop.manage";

pub struct TokenStore {
    /// Directory for the non-macOS fallback file(s); the macOS build stores
    /// in the Keychain and never reads it.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    dir: PathBuf,
}

/// A fixed-length, collision-resistant account/filename key for a broker
/// origin or local socket path. Replacing punctuation is not enough:
/// `/tmp/a-b` and `/tmp/a_b` would otherwise share a management token, and a
/// long custom root can exceed the filesystem's component-length limit.
fn key_for(broker: &str) -> String {
    let digest = Sha256::digest(broker.trim_end_matches('/').as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl TokenStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// A user-facing description of where `save` puts this broker's token.
    #[cfg(target_os = "macos")]
    pub fn storage_description(&self, _url: &str) -> String {
        "macOS Keychain".to_string()
    }

    /// Non-macOS has no platform keychain integration. Name the exact 0600
    /// fallback so a successful login never hides that the token is on disk.
    #[cfg(not(target_os = "macos"))]
    pub fn storage_description(&self, url: &str) -> String {
        format!(
            "plaintext 0600 file {}; prefer AKA_MANAGE_TOKEN for CI",
            self.path_for(url).display()
        )
    }

    /// Which keychain this process can use, probed once. The answer is a
    /// property of the running binary's code signature, so it cannot change
    /// underneath us.
    #[cfg(target_os = "macos")]
    fn keychain() -> Keychain {
        static KEYCHAIN: std::sync::OnceLock<Keychain> = std::sync::OnceLock::new();
        *KEYCHAIN.get_or_init(|| aka_core::keychain::best_effort(&SecurityFramework))
    }

    #[cfg(target_os = "macos")]
    pub fn save(&self, url: &str, token: &str) -> Result<(), String> {
        SecurityFramework
            .write(
                Self::keychain(),
                KEYCHAIN_SERVICE,
                &key_for(url),
                &format!("Multitool management token ({url})"),
                token.as_bytes(),
            )
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "macos")]
    pub fn load(&self, url: &str) -> Option<Zeroizing<String>> {
        let bytes = aka_core::keychain::read_migrating(
            &SecurityFramework,
            Self::keychain(),
            KEYCHAIN_SERVICE,
            &key_for(url),
        )
        .ok()?;
        std::str::from_utf8(&bytes)
            .ok()
            .map(|token| Zeroizing::new(token.trim().to_string()))
    }

    #[cfg(target_os = "macos")]
    pub fn delete(&self, url: &str) -> Result<(), String> {
        let account = key_for(url);
        let keychain = Self::keychain();
        let removed = SecurityFramework.remove(keychain, KEYCHAIN_SERVICE, &account);
        // A copy the migration never got to must go too, or a logged-out
        // broker would log itself back in on the next read.
        if keychain == Keychain::DataProtection {
            let _ = SecurityFramework.remove(Keychain::Login, KEYCHAIN_SERVICE, &account);
        }
        match removed {
            Ok(()) | Err(KeychainError::NotFound) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn path_for(&self, url: &str) -> PathBuf {
        self.dir.join(format!("manage-token-{}", key_for(url)))
    }

    #[cfg(not(target_os = "macos"))]
    pub fn save(&self, url: &str, token: &str) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        tracing::warn!(
            "storing the management token in a plain file (no keychain on \
             this platform); dev fallback only"
        );
        std::fs::create_dir_all(&self.dir).map_err(|error| error.to_string())?;
        let path = self.path_for(url);
        // Created 0600 from the first byte — never world-readable, not even
        // between a write and a chmod.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(token.as_bytes())
            .map_err(|error| error.to_string())?;
        // `mode` only applies at creation; tighten a pre-existing file too.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn load(&self, url: &str) -> Option<Zeroizing<String>> {
        let token = std::fs::read_to_string(self.path_for(url)).ok()?;
        let token = token.trim();
        (!token.is_empty()).then(|| Zeroizing::new(token.to_string()))
    }

    #[cfg(not(target_os = "macos"))]
    pub fn delete(&self, url: &str) -> Result<(), String> {
        match std::fs::remove_file(self.path_for(url)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Namespace a device grant's refresh token so it cannot collide with the
/// management token for the same broker.
///
/// The two are different credentials with different lifetimes and need
/// separate removal: signing out of a passkey grant should not delete a
/// management token the user still wants under Advanced, and vice versa.
fn grant_key(url: &str) -> String {
    format!("device-grant\u{1f}{}", url.trim_end_matches('/'))
}

/// Namespace a remote broker's shared agent key, for the same reason
/// [`grant_key`] exists: it is a different plane's credential from the
/// management token and must be separately storable and removable.
fn agent_key_key(url: &str) -> String {
    format!("agent-key\u{1f}{}", url.trim_end_matches('/'))
}

impl TokenStore {
    /// Store the rotating refresh token for a passkey device grant.
    ///
    /// Call on every rotation, not only at sign-in: the stored value goes
    /// stale the moment the broker issues a replacement, and presenting a
    /// stale one on next start revokes the device.
    pub fn save_grant(&self, url: &str, refresh: &str) -> Result<(), String> {
        self.save(&grant_key(url), refresh)
    }

    pub fn load_grant(&self, url: &str) -> Option<Zeroizing<String>> {
        self.load(&grant_key(url))
    }

    /// Store a remote broker's shared agent key, as handed back by
    /// redeeming an invite. This is the agent plane's bearer token: it
    /// authorizes using connections, not managing the broker.
    pub fn save_agent_key(&self, url: &str, key: &str) -> Result<(), String> {
        self.save(&agent_key_key(url), key)
    }

    pub fn load_agent_key(&self, url: &str) -> Option<Zeroizing<String>> {
        self.load(&agent_key_key(url))
    }

    pub fn delete_agent_key(&self, url: &str) -> Result<(), String> {
        self.delete(&agent_key_key(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_grant_and_a_management_token_do_not_share_a_slot() {
        // Two credentials for one broker, separately revocable.
        assert_ne!(key_for("https://a"), key_for(&grant_key("https://a")));
        assert_eq!(grant_key("https://a/"), grant_key("https://a"));
    }

    #[test]
    fn the_agent_key_has_its_own_slot_on_every_plane() {
        // Three planes, one broker: the agent key must not collide with the
        // management token or the device grant, so logging out of one does
        // not silently disarm another.
        for other in [key_for("https://a"), key_for(&grant_key("https://a"))] {
            assert_ne!(key_for(&agent_key_key("https://a")), other);
        }
        assert_eq!(agent_key_key("https://a/"), agent_key_key("https://a"));
    }

    #[test]
    fn keys_are_scoped_per_url_and_safe() {
        let key = key_for("https://broker.example.dev/");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(key, key_for("https://broker.example.dev"));
        assert_ne!(key_for("http://a:1"), key_for("http://a:2"));
        assert_ne!(key_for("/tmp/a-b"), key_for("/tmp/a_b"));
        assert_eq!(key_for(&"x".repeat(1_000)).len(), 64);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn file_fallback_round_trips_per_url() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().to_path_buf());
        assert!(store.load("http://a:1").is_none());
        store.save("http://a:1", "akamgr_one").unwrap();
        store.save("http://a:2", "akamgr_two").unwrap();
        assert_eq!(store.load("http://a:1").unwrap().as_str(), "akamgr_one");
        assert_eq!(store.load("http://a:2").unwrap().as_str(), "akamgr_two");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(
            dir.path()
                .join(format!("manage-token-{}", key_for("http://a:1"))),
        )
        .unwrap()
        .permissions()
        .mode();
        assert_eq!(mode & 0o777, 0o600);
        store.delete("http://a:1").unwrap();
        assert!(store.load("http://a:1").is_none());
        store.delete("http://a:1").unwrap();
    }
}
