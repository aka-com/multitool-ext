//! Local/remote broker switching.
//!
//! The shell manages exactly one broker at a time: the in-process local
//! stack, or a remote broker over its manage API. This module owns the
//! active backend, the persisted choice, the remote link (SSE → Tauri
//! events), and the transitions between the two — including tearing the
//! local runtime down off the async runtime (dropping a tokio runtime on
//! an async thread panics).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use aka_client::{credentials::TokenStore, RemoteBackend, RemoteConfig};
use aka_core::manage::ManagementBackend;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, Manager as _};

use crate::commands::LocalRuntime;

/// What the webview renders the header switcher and takeover panes from.
#[derive(Debug, Clone, Serialize)]
pub struct BrokerProfileInfo {
    /// "local" | "remote".
    pub mode: String,
    /// The remote broker's URL (remote mode only).
    pub url: Option<String>,
    /// Whether the managed broker is reachable right now. Local mode is
    /// always connected — the broker lives in this process.
    pub connected: bool,
    /// Why not, when it isn't.
    pub error: Option<String>,
    /// A saved management token exists for `url`, so the connect form can
    /// offer to reuse it.
    pub has_saved_token: bool,
    /// A saved passkey device grant exists for `url`. Preferred over the
    /// token when both are present: it is per-device and revocable.
    pub has_saved_grant: bool,
    /// How the current connection authenticated: "passkey" | "token" |
    /// null. The header shows the migration nudge from this.
    pub credential: Option<String>,
    /// What this Mac is called in the broker's authorized-device list, so
    /// the user can find the right row when revoking one.
    pub device_name: Option<String>,
    /// Optional management features advertised by the active broker.
    /// Legacy remote brokers omit the 1Password capability and the shell
    /// keeps that surface disabled instead of issuing unsupported calls.
    pub capabilities: Vec<String>,
}

impl BrokerProfileInfo {
    fn local() -> Self {
        Self {
            mode: "local".into(),
            url: None,
            connected: true,
            error: None,
            has_saved_token: false,
            has_saved_grant: false,
            credential: None,
            device_name: None,
            capabilities: vec![
                aka_api::ONEPASSWORD_PROVIDER_CAPABILITY.into(),
                aka_api::TYPED_CREDENTIALS_CAPABILITY.into(),
            ],
        }
    }

    /// No broker chosen yet: the webview renders the chooser takeover from
    /// this, and everything else stays disabled behind it.
    fn unset() -> Self {
        Self {
            mode: "unset".into(),
            url: None,
            connected: false,
            error: None,
            has_saved_token: false,
            has_saved_grant: false,
            credential: None,
            device_name: None,
            capabilities: Vec::new(),
        }
    }
}

fn advertised_capabilities(whoami: &serde_json::Value) -> Vec<String> {
    let mut capabilities: Vec<String> = whoami
        .get("capabilities")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect();
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

/// The persisted mode choice (`shell.json` in the app data dir). The token
/// itself lives in the token store, never here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct ShellConfig {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    remote_url: Option<String>,
    /// Native request notifications are a property of this desktop shell,
    /// not of whichever local or hosted broker it currently manages.
    #[serde(default)]
    notifications: NotificationSettings,
    /// Likewise the window lock: it gates this app's surfaces, not the
    /// broker behind them.
    #[serde(default)]
    lock: crate::applock::LockSettings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMode {
    Off,
    WhenHidden,
    #[default]
    Always,
}

/// This-machine notification preferences. Preview text is deliberately
/// limited to agent and connection names; request summaries and details can
/// contain paths, arguments, or other lock-screen-inappropriate context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSettings {
    /// Retained in the config schema for compatibility; normalized to Always.
    #[serde(default)]
    pub mode: NotificationMode,
    /// Retained in the config schema for compatibility; normalized to true.
    #[serde(default)]
    pub show_context: bool,
    /// Play the platform's default sound for request notifications.
    #[serde(default = "default_notification_sound")]
    pub play_sound: bool,
    /// Ask the platform to treat request notifications as time-sensitive.
    /// The operating system and user remain authoritative about Focus/DND.
    #[serde(default)]
    pub time_sensitive: bool,
    /// Bring the Request Inbox forward and re-alert this many seconds before
    /// a waiting request expires. Zero disables the second native banner;
    /// the near-deadline in-app fallback remains active.
    #[serde(default = "default_notification_escalation_secs")]
    pub escalation_secs: u64,
    /// Retained in the config schema for compatibility; normalized to true so
    /// newly parked traffic opens its decision sheet whenever it is safe.
    #[serde(default = "default_present_approvals_as_modal")]
    pub present_approvals_as_modal: bool,
    /// Show a short, non-activating app-owned popup for newly waiting work.
    /// It is deliberately opt-in because it is not filtered by Focus.
    #[serde(default)]
    pub show_approval_hud: bool,
}

const fn default_notification_sound() -> bool {
    true
}

const fn default_notification_escalation_secs() -> u64 {
    15
}

const fn default_present_approvals_as_modal() -> bool {
    true
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            mode: NotificationMode::default(),
            show_context: true,
            play_sound: default_notification_sound(),
            time_sensitive: false,
            escalation_secs: default_notification_escalation_secs(),
            present_approvals_as_modal: default_present_approvals_as_modal(),
            show_approval_hud: false,
        }
    }
}

impl NotificationSettings {
    /// These are product policy rather than user preferences: Multitool is
    /// normally in the background, notifications should identify the waiting
    /// parties, and an open app should present a new approval immediately.
    fn with_fixed_delivery_policy(mut self) -> Self {
        self.mode = NotificationMode::Always;
        self.show_context = true;
        self.present_approvals_as_modal = true;
        self
    }

    fn validate(self) -> Result<Self, String> {
        if matches!(self.escalation_secs, 0 | 15) {
            Ok(self.with_fixed_delivery_policy())
        } else {
            Err("notification escalation must be off or 15 seconds".into())
        }
    }

    /// Migrate the former 30/60-second choices to the sole reminder interval.
    /// Unknown hand-edited values stay conservative and disable re-alerting.
    fn with_safe_persisted_policy(mut self) -> Self {
        self.escalation_secs = match self.escalation_secs {
            0 | 15 => self.escalation_secs,
            30 | 60 => 15,
            _ => 0,
        };
        self.with_fixed_delivery_policy()
    }
}

/// The remote link: the backend plus its event-stream task.
struct RemoteRuntime {
    /// Kept so the link's backend lives as long as its stream task.
    _backend: Arc<RemoteBackend>,
    sse_task: tauri::async_runtime::JoinHandle<()>,
}

impl Drop for RemoteRuntime {
    fn drop(&mut self) {
        self.sse_task.abort();
    }
}

pub struct BrokerState {
    backend: RwLock<Arc<dyn ManagementBackend>>,
    local: Mutex<Option<LocalRuntime>>,
    remote: Mutex<Option<RemoteRuntime>>,
    profile: Mutex<BrokerProfileInfo>,
    data_dir: PathBuf,
    tokens: Arc<TokenStore>,
    /// Serializes `shell.json` read-modify-write cycles. Broker transitions
    /// and notification settings can be changed from different async tasks;
    /// neither is allowed to overwrite the other's fields.
    shell_write: Mutex<()>,
    /// Transition attempts, monotonically numbered. A transition captures
    /// the counter when it begins and refuses to commit if another attempt
    /// began while it awaited (probe/startup): the user's latest choice
    /// wins, and a slow earlier attempt can never override it. Commits run
    /// holding this lock, so they are also mutually exclusive.
    transition_epoch: Mutex<u64>,
}

/// The error a transition reports when it lost to a newer one. Compared by
/// [`BrokerState::start_saved_remote`] to keep a lost startup attempt from
/// stomping the link state the winning transition established.
const TRANSITION_SUPERSEDED: &str =
    "the broker choice changed while connecting; nothing was applied";

/// The event the webview listens to for switcher/link state.
pub const EVT_BROKER: &str = "aka://broker-changed";

fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("shell.json")
}

fn load_config(data_dir: &Path) -> ShellConfig {
    std::fs::read(config_path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_config(data_dir: &Path, config: &ShellConfig) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(config).map_err(|error| error.to_string())?;
    std::fs::write(config_path(data_dir), bytes).map_err(|error| error.to_string())
}

/// The persisted boot choice. `Unset` boots the shell into the chooser
/// takeover with nothing started: picking is what starts a broker.
pub enum SavedMode {
    Unset,
    Local,
    Remote(String),
}

/// The saved mode choice, read before anything starts.
///
/// A config from before the chooser existed carries no `mode`, but an
/// `index.json` beside it means this machine's broker has been in use — that
/// user already chose, by using it, so the choice is recorded rather than
/// asked again. A mode string this build does not know (a corrupt edit, or a
/// newer config) falls back to the chooser: showing it once is recoverable,
/// silently starting a broker the user may not have chosen is not.
pub fn saved_mode(data_dir: &Path) -> SavedMode {
    let config = load_config(data_dir);
    match (config.mode.as_deref(), config.remote_url.as_deref()) {
        (Some("remote"), Some(url)) => SavedMode::Remote(url.to_string()),
        // "remote" with no URL is a state the app never writes; there is
        // nothing to connect to, so ask rather than guess.
        (Some("remote"), None) => SavedMode::Unset,
        (Some("local"), _) => SavedMode::Local,
        (Some(_), _) => SavedMode::Unset,
        (None, _) => {
            if data_dir.join("index.json").exists() {
                let mut config = config;
                config.mode = Some("local".into());
                if let Err(error) = save_config(data_dir, &config) {
                    // Not recording it costs one more probe next launch,
                    // never the choice itself.
                    tracing::warn!(%error, "could not record the migrated local broker choice");
                }
                SavedMode::Local
            } else {
                SavedMode::Unset
            }
        }
    }
}

/// Notification settings are loaded before the broker starts so even an
/// early remote event observes the user's saved delivery preference.
pub fn saved_notification_settings(data_dir: &Path) -> NotificationSettings {
    load_config(data_dir)
        .notifications
        .with_safe_persisted_policy()
}

/// Lock settings are read at startup, before the windows exist, so the
/// watchdog is armed from the first tick.
pub fn saved_lock_settings(data_dir: &Path) -> crate::applock::LockSettings {
    load_config(data_dir).lock.with_safe_persisted_delay()
}

/// Persist a lock-settings change through the same serialized shell-config
/// path everything else uses, so it cannot stomp a concurrent broker or
/// notification write.
pub fn save_lock_settings(
    app: &AppHandle,
    settings: crate::applock::LockSettings,
) -> Result<(), String> {
    let state = app
        .try_state::<crate::commands::AppState>()
        .ok_or_else(|| "app state is not ready".to_string())?;
    state
        .brokers
        .update_shell_config(|config| config.lock = settings)
}

impl BrokerState {
    /// Construct for local mode with an already-started local runtime.
    pub fn new_local(data_dir: PathBuf, runtime: LocalRuntime) -> Self {
        let backend: Arc<dyn ManagementBackend> =
            Arc::new(aka_core::manage::LocalBackend::new(runtime.broker.clone()));
        Self {
            backend: RwLock::new(backend),
            local: Mutex::new(Some(runtime)),
            remote: Mutex::new(None),
            profile: Mutex::new(BrokerProfileInfo::local()),
            tokens: Arc::new(TokenStore::new(data_dir.clone())),
            data_dir,
            shell_write: Mutex::new(()),
            transition_epoch: Mutex::new(0),
        }
    }

    /// Construct for remote mode from the saved choice; the connection is
    /// attempted by [`Self::start_saved_remote`] after the app is up.
    pub fn new_remote_pending(data_dir: PathBuf, url: String) -> Self {
        let tokens = Arc::new(TokenStore::new(data_dir.clone()));
        let has_saved_token = tokens.load(&url).is_some();
        let saved_grant = tokens.load_grant(&url);
        // Until the probe finishes there is still a backend to answer
        // commands: the remote one (with a placeholder token when nothing is
        // saved — every call then fails with a clear auth error rather
        // than a crash, and the takeover pane is what the user sees).
        // A saved device grant is deliberately *not* resumed here. Building a
        // grant now would leave two live grants for one device — this one and
        // the one `connect_remote` builds when `start_saved_remote` runs — and
        // two holders of a rotating refresh token race on it and get the
        // device revoked (see `RemoteConfig`'s own note). Until that single
        // real grant connects, the placeholder answers commands with a clear
        // auth error, exactly as the unset and pre-probe states already do.
        //
        // A management token does not rotate, so serving it immediately is
        // safe and keeps token-mode startup working without waiting on a probe.
        let config = match tokens.load(&url) {
            Some(token) if saved_grant.is_none() => RemoteConfig::new(&url, &token).ok(),
            _ => None,
        }
        .unwrap_or_else(|| {
            RemoteConfig::new("http://127.0.0.1:1", "akamgr_unconfigured").expect("static config")
        });
        let backend: Arc<dyn ManagementBackend> = Arc::new(
            RemoteBackend::new(config).with_opener(Arc::new(crate::events::open_consent_url)),
        );
        Self {
            backend: RwLock::new(backend),
            local: Mutex::new(None),
            remote: Mutex::new(None),
            profile: Mutex::new(BrokerProfileInfo {
                mode: "remote".into(),
                url: Some(url),
                connected: false,
                error: None,
                has_saved_token,
                has_saved_grant: saved_grant.is_some(),
                credential: None,
                device_name: None,
                capabilities: Vec::new(),
            }),
            tokens,
            data_dir,
            shell_write: Mutex::new(()),
            transition_epoch: Mutex::new(0),
        }
    }

    /// Construct with no broker chosen: nothing starts until the user picks.
    ///
    /// The first pick runs the same transitions as switching later —
    /// [`Self::switch_local`] or [`Self::connect_remote`] — and those are
    /// what persist the choice.
    pub fn new_unset(data_dir: PathBuf) -> Self {
        // The backend slot is never empty: a stray command in this state
        // fails with a clear error instead of a crash, exactly like the
        // pre-probe placeholder in `new_remote_pending`. The chooser
        // takeover is what the user sees.
        let config =
            RemoteConfig::new("http://127.0.0.1:1", "akamgr_unconfigured").expect("static config");
        let backend: Arc<dyn ManagementBackend> = Arc::new(
            RemoteBackend::new(config).with_opener(Arc::new(crate::events::open_consent_url)),
        );
        Self {
            backend: RwLock::new(backend),
            local: Mutex::new(None),
            remote: Mutex::new(None),
            profile: Mutex::new(BrokerProfileInfo::unset()),
            tokens: Arc::new(TokenStore::new(data_dir.clone())),
            data_dir,
            shell_write: Mutex::new(()),
            transition_epoch: Mutex::new(0),
        }
    }

    /// Begin a transition attempt: bump the counter, invalidating any
    /// attempt still in flight.
    fn begin_transition(&self) -> u64 {
        let mut epoch = self.transition_epoch.lock().unwrap();
        *epoch += 1;
        *epoch
    }

    /// Take the commit lock — `None` when a newer attempt began, in which
    /// case the caller must apply nothing. No awaiting while held.
    fn transition_guard(&self, epoch: u64) -> Option<std::sync::MutexGuard<'_, u64>> {
        let guard = self.transition_epoch.lock().unwrap();
        (*guard == epoch).then_some(guard)
    }

    /// The active backend (cloned out so no lock is held across awaits).
    pub fn backend(&self) -> Arc<dyn ManagementBackend> {
        self.backend.read().unwrap().clone()
    }

    /// The local broker, when local mode is active (window chrome reads a
    /// setting synchronously).
    pub fn local_broker(&self) -> Option<Arc<aka_core::broker::Broker>> {
        self.local
            .lock()
            .unwrap()
            .as_ref()
            .map(|runtime| runtime.broker.clone())
    }

    pub fn profile(&self) -> BrokerProfileInfo {
        self.profile.lock().unwrap().clone()
    }

    pub fn notification_settings(&self) -> NotificationSettings {
        let _write = self.shell_write.lock().unwrap();
        load_config(&self.data_dir)
            .notifications
            .with_safe_persisted_policy()
    }

    pub fn set_notification_settings(
        &self,
        settings: NotificationSettings,
    ) -> Result<NotificationSettings, String> {
        let settings = settings.validate()?;
        self.update_shell_config(|config| config.notifications = settings)?;
        Ok(settings)
    }

    pub(crate) fn update_shell_config(
        &self,
        update: impl FnOnce(&mut ShellConfig),
    ) -> Result<(), String> {
        let _write = self.shell_write.lock().unwrap();
        let mut config = load_config(&self.data_dir);
        update(&mut config);
        save_config(&self.data_dir, &config)
    }

    fn set_profile(&self, app: &AppHandle, profile: BrokerProfileInfo) {
        *self.profile.lock().unwrap() = profile.clone();
        crate::attention::set_scope(app, &profile.mode, profile.url.as_deref());
        let _ = app.emit(EVT_BROKER, profile);
    }

    fn update_link(&self, app: &AppHandle, connected: bool, error: Option<String>) {
        let mut profile = self.profile.lock().unwrap();
        if profile.mode != "remote" {
            return;
        }
        let reconnected = connected && !profile.connected;
        profile.connected = connected;
        profile.error = error;
        let snapshot = profile.clone();
        drop(profile);
        // A link coming back may be a broker that restarted, and a restarted
        // broker holds none of the sessions pushed to it — while this app's
        // push clock still says they are fresh. Re-push now rather than
        // leaving agents without the connection until half the TTL passes.
        // (The initial switch-time push arrives already connected, so this
        // fires only on a real drop-and-recover.)
        if reconnected {
            crate::cloud_refresh::refresh_soon(app);
        }
        let _ = app.emit(EVT_BROKER, snapshot);
    }

    /// Sign this Mac in to a hosted broker with a passkey.
    ///
    /// The ceremony runs in the system browser against the broker's own
    /// origin, so the passkey the user already has for the web app is the
    /// one that authorizes this app — see [`crate::passkey_signin`].
    pub async fn sign_in_remote(
        self: &Arc<Self>,
        app: &AppHandle,
        url: String,
        device_name: Option<String>,
    ) -> Result<BrokerProfileInfo, String> {
        let url = RemoteConfig::normalize_url(&url)?;
        let device_name = device_name
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(crate::passkey_signin::default_device_name);
        let signed_in =
            crate::passkey_signin::sign_in(&url, &device_name, crate::events::open_consent_url)
                .await?;
        // Store the refresh token before anything can rotate it. A rotation
        // that outruns the first write would leave the keychain holding a
        // superseded token, and presenting one of those revokes the device.
        self.tokens
            .save_grant(&url, &signed_in.refresh)
            .map_err(|error| format!("could not store this device's sign-in: {error}"))?;
        let credential = crate::passkey_signin::grant_for(&url, &signed_in, self.tokens.clone());
        let device_name = signed_in.device_name.clone();
        self.commit_remote(app, url, credential, "passkey", None, Some(device_name))
            .await
    }

    /// Connect to (and switch to) a remote broker. `token: None` reuses the
    /// saved credential for that URL, preferring a passkey device grant over
    /// a management token. On success the choice persists and the local
    /// stack (if any) is torn down; on failure nothing changes and the
    /// message is for the connect form.
    pub async fn connect_remote(
        self: &Arc<Self>,
        app: &AppHandle,
        url: String,
        token: Option<String>,
    ) -> Result<BrokerProfileInfo, String> {
        // Normalize before the saved-credential lookup: credentials are
        // stored under the canonical URL (what base_url() returns), so a
        // re-typed variant of the same broker — different case, an explicit
        // default port, a trailing slash — must collapse to the same key or
        // the saved one is missed and the user is asked to paste it again.
        let url = RemoteConfig::normalize_url(&url)?;
        let explicit = token.as_deref().map(str::trim).filter(|t| !t.is_empty());
        // A passkey grant wins over a saved management token for the same
        // broker: it is per-device and revocable by name, and it is where
        // the migration is going. An explicitly pasted token still wins over
        // both, because the user just chose it.
        if explicit.is_none() {
            if let Some(refresh) = self.tokens.load_grant(&url) {
                let credential =
                    crate::passkey_signin::resume_grant(&url, &refresh, self.tokens.clone());
                return self
                    .commit_remote(app, url, credential, "passkey", None, None)
                    .await;
            }
        }
        let token = match explicit {
            Some(token) => token.to_string(),
            None => match self.tokens.load(&url) {
                Some(saved) => saved.to_string(),
                None => return Err("sign in with a passkey, or enter a management token".into()),
            },
        };
        let credential = Arc::new(aka_client::grant::ManageCredential::manage_token(&token));
        self.commit_remote(app, url, credential, "token", Some(token), None)
            .await
    }

    /// Probe the broker with a credential and, if it answers, make it the
    /// active one. Shared by every way of arriving at a hosted broker.
    async fn commit_remote(
        self: &Arc<Self>,
        app: &AppHandle,
        url: String,
        credential: Arc<aka_client::grant::ManageCredential>,
        kind: &str,
        save_token: Option<String>,
        device_name: Option<String>,
    ) -> Result<BrokerProfileInfo, String> {
        let config = RemoteConfig::with_credential(&url, credential)?;
        let url = config.base_url();
        let backend = Arc::new(
            RemoteBackend::new(config).with_opener(Arc::new(crate::events::open_consent_url)),
        );
        let epoch = self.begin_transition();
        let whoami = backend.whoami().await.map_err(|error| error.to_string())?;
        let capabilities = advertised_capabilities(&whoami);
        // The probe succeeded: persist, swap, and (re)arm the link — unless
        // another transition began while the probe was in flight (the user
        // switched to this Mac, retried, or connected elsewhere); the later
        // choice wins and this attempt applies nothing.
        let (profile, stale_local) = {
            let Some(_commit) = self.transition_guard(epoch) else {
                return Err(TRANSITION_SUPERSEDED.into());
            };
            if let Some(token) = &save_token {
                if let Err(error) = self.tokens.save(&url, token) {
                    tracing::warn!(%error, "could not store the management token");
                }
            }
            if let Err(error) = self.update_shell_config(|config| {
                config.mode = Some("remote".into());
                config.remote_url = Some(url.clone());
            }) {
                tracing::warn!(%error, "could not persist the broker-mode choice");
            }
            self.teardown_remote();
            let stale_local = self.local.lock().unwrap().take();
            *self.backend.write().unwrap() = backend.clone();
            // Establish the notification scope before the event stream can
            // reconcile its first snapshot. `set_profile` repeats this with
            // the same key, which is intentionally a no-op.
            crate::attention::set_scope(app, "remote", Some(&url));
            // This broker holds none of the cloud sessions the last one did,
            // and may not be able to mint them at all — push what it needs
            // now rather than after a tick of nothing.
            crate::cloud_refresh::refresh_soon(app);
            self.arm_sse(app, backend);
            let profile = BrokerProfileInfo {
                mode: "remote".into(),
                has_saved_token: self.tokens.load(&url).is_some(),
                has_saved_grant: self.tokens.load_grant(&url).is_some(),
                credential: Some(kind.to_string()),
                device_name,
                url: Some(url),
                connected: true,
                error: None,
                capabilities,
            };
            self.set_profile(app, profile.clone());
            (profile, stale_local)
        };
        // The displaced local stack (if any) is dropped after the commit,
        // off the async runtime: dropping a tokio runtime from async
        // context panics.
        if let Some(runtime) = stale_local {
            let _ = tauri::async_runtime::spawn_blocking(move || drop(runtime)).await;
        }
        Ok(profile)
    }

    /// Re-attempt the saved remote connection (the error pane's Retry).
    pub async fn retry_remote(
        self: &Arc<Self>,
        app: &AppHandle,
    ) -> Result<BrokerProfileInfo, String> {
        let profile = self.profile();
        let url = profile
            .url
            .ok_or_else(|| "no remote broker is configured".to_string())?;
        // Show the attempt: clear the previous failure so the pane flips to
        // "Connecting…" while the probe runs, instead of pinning stale
        // error text with no sign the click did anything.
        if !profile.connected {
            self.update_link(app, false, None);
        }
        match self.connect_remote(app, url, None).await {
            Ok(profile) => Ok(profile),
            Err(message) => {
                // A failed connect emits no profile change on its own;
                // surface what this attempt hit so the pane stays honest.
                // A superseded attempt lost to a newer transition that owns
                // the profile now — leave that state alone.
                if message != TRANSITION_SUPERSEDED {
                    self.update_link(app, false, Some(message.clone()));
                }
                Err(message)
            }
        }
    }

    /// Called once at startup when the saved mode is remote: try the saved
    /// connection in the background; the webview renders the takeover pane
    /// from the profile either way.
    pub fn start_saved_remote(self: Arc<Self>, app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            let Some(url) = self.profile().url else {
                return;
            };
            match self.connect_remote(&app, url, None).await {
                Ok(_) => {}
                // A superseded attempt lost to a user-initiated transition
                // that already set the profile; reporting it as a link
                // failure would stomp the winner's state.
                Err(message) if message == TRANSITION_SUPERSEDED => {}
                Err(message) => self.update_link(&app, false, Some(message)),
            }
        });
    }

    /// Switch to this Mac's local broker, starting the local stack.
    pub async fn switch_local(
        self: &Arc<Self>,
        app: &AppHandle,
    ) -> Result<BrokerProfileInfo, String> {
        if self.profile().mode == "local" && self.local.lock().unwrap().is_some() {
            // Already local — but re-picking "This Mac" is still the user's
            // latest choice: bump the epoch so a remote connect still in
            // flight (its probe not yet back) cannot commit afterwards and
            // flip the app remote against that choice.
            let _ = self.begin_transition();
            return Ok(self.profile());
        }
        let epoch = self.begin_transition();
        // Start the local stack first: if it cannot start (another broker
        // holds the instance lock, say), the remote link must stay armed so
        // the user still has a working mode to stand on.
        let handle = app.clone();
        let runtime =
            tauri::async_runtime::spawn_blocking(move || crate::start_local_runtime(&handle))
                .await
                .map_err(|error| format!("local broker start stopped: {error}"))?
                .map_err(|error| error.to_string())?;
        // Commit under the transition lock; `runtime` stays in the slot
        // when the commit is refused so it can be dropped off-thread below
        // (the guard must not be held across an await).
        let mut runtime = Some(runtime);
        let committed = {
            match self.transition_guard(epoch) {
                Some(_commit) => {
                    self.teardown_remote();
                    let started = runtime.take().expect("freshly started runtime");
                    let backend: Arc<dyn ManagementBackend> =
                        Arc::new(aka_core::manage::LocalBackend::new(started.broker.clone()));
                    // The stack has been running since before this commit, so
                    // adopt its queues rather than only flipping the scope: a
                    // prompt raised while it was starting was tracked under
                    // the outgoing broker and would be lost with it.
                    crate::attention::adopt_local(app, &started.broker);
                    *self.local.lock().unwrap() = Some(started);
                    *self.backend.write().unwrap() = backend;
                    let remote_url = self.profile().url;
                    if let Err(error) = self.update_shell_config(|config| {
                        config.mode = Some("local".into());
                        config.remote_url = remote_url;
                    }) {
                        tracing::warn!(%error, "could not persist the broker-mode choice");
                    }
                    let profile = BrokerProfileInfo::local();
                    self.set_profile(app, profile.clone());
                    // Drop what was pushed to the broker we just left: this
                    // one reads the files itself, and stale bookkeeping would
                    // suppress real pushes if we switch back.
                    crate::cloud_refresh::refresh_soon(app);
                    Some(profile)
                }
                None => None,
            }
        };
        match committed {
            Some(profile) => Ok(profile),
            None => {
                // A newer transition began while the stack was starting;
                // drop the fresh runtime off the async thread (dropping a
                // tokio runtime in async context panics) and apply nothing.
                if let Some(started) = runtime.take() {
                    let _ = tauri::async_runtime::spawn_blocking(move || drop(started)).await;
                }
                Err(TRANSITION_SUPERSEDED.into())
            }
        }
    }

    /// Stop the remote link (keeps the saved token and URL).
    fn teardown_remote(&self) {
        *self.remote.lock().unwrap() = None;
    }

    /// Start the remote event stream, re-emitting manage events as the
    /// same Tauri events local mode produces so the webview stays mode-
    /// blind, and reflecting link transitions into the profile.
    fn arm_sse(self: &Arc<Self>, app: &AppHandle, backend: Arc<RemoteBackend>) {
        let state = self.clone();
        let app = app.clone();
        let event_app = app.clone();
        let sse_backend = backend.clone();
        let event_backend = backend.clone();
        let refresh_sequence = Arc::new(AtomicU64::new(0));
        let task = tauri::async_runtime::spawn(async move {
            aka_client::events::subscribe_request_surface(
                sse_backend,
                move |event| {
                    // A reconnect may replay an old request event, while a
                    // lag resync may be the only signal for a live one. The
                    // notification coordinator reconciles the authoritative
                    // queue so replays do not duplicate native alerts.
                    let should_reconcile = matches!(
                        &event,
                        aka_api::ManageEvent::ApprovalsChanged
                            | aka_api::ManageEvent::ApprovalExpired { .. }
                            | aka_api::ManageEvent::ElicitationsChanged
                            | aka_api::ManageEvent::Resync
                    );
                    crate::events::emit_manage_event(&event_app, event);
                    if should_reconcile {
                        // Approval and elicitation events often arrive in a
                        // burst for one broker mutation. Reconcile once after
                        // the burst instead of issuing one full snapshot read
                        // per event.
                        let sequence = refresh_sequence.fetch_add(1, Ordering::Relaxed) + 1;
                        let refresh_sequence = refresh_sequence.clone();
                        let backend = event_backend.clone();
                        let app = event_app.clone();
                        tauri::async_runtime::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                            if refresh_sequence.load(Ordering::Relaxed) != sequence {
                                return;
                            }
                            let Some(refresh_generation) =
                                crate::attention::begin_remote_refresh(&app)
                            else {
                                crate::windows::surface_for_approval(&app);
                                return;
                            };
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                backend.approval_snapshot(),
                            )
                            .await
                            {
                                Ok(Ok(snapshot)) => {
                                    crate::attention::reconcile_remote(
                                        &app,
                                        refresh_generation,
                                        snapshot,
                                    );
                                }
                                Ok(Err(error)) => {
                                    // The event itself made it through. If
                                    // the authoritative follow-up fails,
                                    // prefer one unnecessary window over a
                                    // real prompt timing out unseen.
                                    tracing::warn!(%error, "could not check the remote request queues");
                                    if crate::attention::remote_refresh_is_current(
                                        &app,
                                        refresh_generation,
                                    ) {
                                        crate::windows::surface_for_approval(&app);
                                    }
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        "remote request queue check timed out; surfacing defensively"
                                    );
                                    if crate::attention::remote_refresh_is_current(
                                        &app,
                                        refresh_generation,
                                    ) {
                                        crate::windows::surface_for_approval(&app);
                                    }
                                }
                            }
                        });
                    }
                },
                move |link| match link {
                    aka_client::events::LinkState::Connected => {
                        state.update_link(&app, true, None);
                    }
                    aka_client::events::LinkState::Disconnected { message } => {
                        state.update_link(&app, false, Some(message));
                    }
                },
            )
            .await;
        });
        *self.remote.lock().unwrap() = Some(RemoteRuntime {
            _backend: backend,
            sse_task: task,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_capabilities_are_read_from_whoami_and_legacy_is_empty() {
        let advertised = advertised_capabilities(&serde_json::json!({
            "capabilities": [
                "zeta",
                aka_api::ONEPASSWORD_PROVIDER_CAPABILITY,
                aka_api::ONEPASSWORD_PROVIDER_CAPABILITY
            ]
        }));
        assert_eq!(
            advertised,
            vec![
                aka_api::ONEPASSWORD_PROVIDER_CAPABILITY.to_string(),
                "zeta".into()
            ]
        );
        assert!(advertised_capabilities(&serde_json::json!({ "version": "legacy" })).is_empty());
    }

    #[test]
    fn a_fresh_install_boots_into_the_chooser_and_a_saved_choice_skips_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(saved_mode(dir.path()), SavedMode::Unset));

        save_config(
            dir.path(),
            &ShellConfig {
                mode: Some("local".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(saved_mode(dir.path()), SavedMode::Local));

        save_config(
            dir.path(),
            &ShellConfig {
                mode: Some("remote".into()),
                remote_url: Some("https://broker.example".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            matches!(saved_mode(dir.path()), SavedMode::Remote(url) if url == "https://broker.example")
        );
    }

    #[test]
    fn an_existing_local_install_is_migrated_rather_than_asked() {
        // A config from before the chooser has no `mode`, but broker state
        // beside it means the user already chose by using it. The probe also
        // records the choice so it holds even if index.json later goes away.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(config_path(dir.path()), br#"{"notifications":{}}"#).unwrap();
        std::fs::write(dir.path().join("index.json"), b"{}").unwrap();
        assert!(matches!(saved_mode(dir.path()), SavedMode::Local));
        assert_eq!(load_config(dir.path()).mode.as_deref(), Some("local"));
        std::fs::remove_file(dir.path().join("index.json")).unwrap();
        assert!(matches!(saved_mode(dir.path()), SavedMode::Local));
    }

    #[test]
    fn a_mode_this_build_does_not_know_asks_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        // An unknown mode string, and "remote" with nothing to connect to:
        // both recover through the chooser rather than starting a broker the
        // user may not have chosen.
        std::fs::write(config_path(dir.path()), br#"{"mode":"quantum"}"#).unwrap();
        assert!(matches!(saved_mode(dir.path()), SavedMode::Unset));
        std::fs::write(config_path(dir.path()), br#"{"mode":"remote"}"#).unwrap();
        assert!(matches!(saved_mode(dir.path()), SavedMode::Unset));
    }

    #[test]
    fn older_shell_config_defaults_to_fixed_notification_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            config_path(dir.path()),
            br#"{"mode":"remote","remote_url":"https://broker.example"}"#,
        )
        .unwrap();

        let config = load_config(dir.path());
        assert_eq!(config.mode.as_deref(), Some("remote"));
        assert_eq!(
            config.notifications,
            NotificationSettings {
                mode: NotificationMode::Always,
                show_context: true,
                ..NotificationSettings::default()
            }
        );
    }

    #[test]
    fn saving_notification_settings_preserves_the_broker_choice() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = ShellConfig {
            mode: Some("remote".into()),
            remote_url: Some("https://broker.example".into()),
            ..Default::default()
        };
        save_config(dir.path(), &config).unwrap();

        config = load_config(dir.path());
        config.notifications = NotificationSettings {
            mode: NotificationMode::Always,
            show_context: true,
            play_sound: false,
            time_sensitive: true,
            escalation_secs: 15,
            present_approvals_as_modal: true,
            show_approval_hud: true,
        };
        save_config(dir.path(), &config).unwrap();

        let saved = load_config(dir.path());
        assert_eq!(saved.mode.as_deref(), Some("remote"));
        assert_eq!(saved.remote_url.as_deref(), Some("https://broker.example"));
        assert_eq!(saved.notifications, config.notifications);
    }

    #[test]
    fn invalid_notification_escalation_is_never_persisted() {
        let invalid = NotificationSettings {
            escalation_secs: 31,
            ..NotificationSettings::default()
        };
        assert_eq!(
            invalid.validate().unwrap_err(),
            "notification escalation must be off or 15 seconds"
        );
    }

    #[test]
    fn saved_settings_enforce_fixed_delivery_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            config_path(dir.path()),
            br#"{
                "notifications": {
                    "mode": "off",
                    "showContext": true,
                    "playSound": false,
                    "timeSensitive": true,
                    "escalationSecs": 120
                }
            }"#,
        )
        .unwrap();

        let settings = saved_notification_settings(dir.path());
        assert_eq!(settings.mode, NotificationMode::Always);
        assert!(settings.show_context);
        assert!(settings.present_approvals_as_modal);
        assert!(!settings.play_sound);
        assert!(settings.time_sensitive);
        assert_eq!(settings.escalation_secs, 0);
    }

    #[test]
    fn legacy_reminder_delays_migrate_to_fifteen_seconds() {
        for escalation_secs in [30, 60] {
            let settings = NotificationSettings {
                escalation_secs,
                ..NotificationSettings::default()
            }
            .with_safe_persisted_policy();
            assert_eq!(settings.escalation_secs, 15);
        }
    }

    #[test]
    fn saves_cannot_override_fixed_delivery_policy() {
        let settings = NotificationSettings {
            mode: NotificationMode::Off,
            show_context: false,
            escalation_secs: 15,
            present_approvals_as_modal: false,
            ..NotificationSettings::default()
        }
        .validate()
        .unwrap();
        assert_eq!(settings.mode, NotificationMode::Always);
        assert!(settings.show_context);
        assert!(settings.present_approvals_as_modal);
    }
}
