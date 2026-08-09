//! Who may sign in, and what they are holding while signed in.
//!
//! Six kinds of record, split by how long they live and therefore by whether
//! they touch disk at all.
//!
//! **Durable** (`auth.json`, sealed with the same integrity key as
//! `identity.json`): the account, its passkeys, browser sessions, device
//! grants, and automation tokens. These survive a restart because a user who
//! signed in yesterday should still be signed in, and because revoking a
//! session only for a restart to restore it would be worse than useless.
//!
//! **Ephemeral** (memory only): in-flight WebAuthn challenges, authorization
//! codes, and access tokens. Each lives between sixty seconds and ten
//! minutes, each is one-use or nearly so, and each is a bearer credential
//! while it exists. Writing them down would widen their blast radius for the
//! sole benefit of surviving a restart inside a window measured in seconds —
//! and the recovery from losing one is that the user clicks the button again.
//! A restart therefore invalidates in-flight sign-ins and forces the desktop
//! to refresh early, both of which are correct.
//!
//! Nothing here stores a secret in the clear. We store only SHA-256 hashes and
//! look credentials up by hash, so a copy of `auth.json` — or of the process's
//! memory maps — yields nothing a holder can present.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};
use zeroize::Zeroizing;

use crate::auth::policy::{ClientSurface, ScopeSet};
use crate::integrity::StateIntegrity;
use crate::Result;

/* ----------------------------- lifetimes -------------------------------- */

/// How long a browser session lasts before the user signs in again,
/// regardless of activity. A hosted broker holds the keys to every
/// connection; "stay signed in forever" is not on offer.
const SESSION_LIFETIME: ChronoDuration = ChronoDuration::hours(12);

/// How long a session survives with no requests on it. Shorter than the
/// absolute cap so an idle tab closes itself.
const SESSION_IDLE: ChronoDuration = ChronoDuration::hours(2);

/// An authorization code's whole life: the moment between the browser
/// redirecting and the desktop exchanging it. One use, and this is a ceiling
/// rather than a budget.
const CODE_LIFETIME: ChronoDuration = ChronoDuration::seconds(60);

/// How long a desktop access token is good for. Short, because the refresh
/// grant behind it is what actually persists and is revocable.
const ACCESS_LIFETIME: ChronoDuration = ChronoDuration::minutes(10);

/// How long a device may go unused before its refresh grant stops working.
const DEVICE_IDLE_LIFETIME: ChronoDuration = ChronoDuration::days(30);

/// How long the one-use enrollment secret printed on the broker host stays
/// good. Long enough to walk to another machine, short enough that a
/// forgotten one is not a standing invitation.
const ENROLLMENT_LIFETIME: ChronoDuration = ChronoDuration::minutes(15);

/// A WebAuthn challenge's life. The browser prompt itself may sit for a
/// while; this bounds how long the server remembers offering it.
const CHALLENGE_LIFETIME: ChronoDuration = ChronoDuration::minutes(5);

/// How long an agent-plane invite stays redeemable. Same reasoning as
/// enrollment: long enough to paste into a teammate's terminal, short
/// enough that a forgotten one is not a standing key dispenser.
const INVITE_LIFETIME: ChronoDuration = ChronoDuration::minutes(15);

/// Outstanding invites kept at once, so an operator scripting `admin
/// invite` in a loop cannot grow the sealed file without bound.
const MAX_INVITES: usize = 32;

/// Superseded refresh-token hashes kept per device for reuse detection. A
/// token more than this many rotations old counts as unknown rather than as
/// theft — the safe direction, since we already refuse unknown tokens.
const REFRESH_HISTORY: usize = 8;

/// Ceilings on the ephemeral maps, so a caller that can start ceremonies
/// cannot grow the process's memory without bound.
const MAX_PENDING_CHALLENGES: usize = 64;
const MAX_PENDING_CODES: usize = 64;
const MAX_ACCESS_TOKENS: usize = 512;

/// Coalesce `last_seen` writes: a busy session would otherwise rewrite the
/// sealed file on every request.
const TOUCH_INTERVAL: ChronoDuration = ChronoDuration::minutes(5);

/* ------------------------------- tokens --------------------------------- */

/// Distinguishing prefixes so we reject a credential pasted into the wrong
/// field by shape rather than by lookup, and so a token-shaped string in a
/// log cannot be mistaken for a different plane's.
///
/// The agent plane's `aka_` and the management token's `akamgr_` are the two
/// that already exist; none of these collide with either.
pub const SESSION_PREFIX: &str = "akases_";
pub const CSRF_PREFIX: &str = "akacsrf_";
pub const CODE_PREFIX: &str = "akacode_";
pub const REFRESH_PREFIX: &str = "akaref_";
pub const ACCESS_PREFIX: &str = "akaacc_";
pub const AUTOMATION_PREFIX: &str = "akaauto_";
pub const ENROLLMENT_PREFIX: &str = "akaenroll_";
pub const INVITE_PREFIX: &str = "akajoin_";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 256 bits of OS randomness behind a naming prefix.
fn mint(prefix: &str) -> Zeroizing<String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    Zeroizing::new(format!("{prefix}{}", hex(&buf)))
}

/// SHA-256 of the credential: we store and compare this, never the plaintext.
fn digest(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Reject by shape before hashing. A lookup miss and a wrong-plane paste are
/// different mistakes and deserve different answers.
fn shaped(token: &str, prefix: &str) -> Option<String> {
    token.starts_with(prefix).then(|| digest(token))
}

/// Base64url without padding, as WebAuthn and PKCE both use.
fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/* ------------------------------- errors --------------------------------- */

#[derive(Debug)]
pub enum AuthError {
    /// No passkey has ever been enrolled, so there is nobody to authenticate.
    NotEnrolled,
    /// Enrollment is closed, or the offered secret does not match the open one.
    /// One variant covers both: distinguishing them would tell a caller whether
    /// guessing is worth continuing.
    EnrollmentRefused,
    /// No such invite, or it expired, or it was already redeemed. One
    /// variant for the same reason as `EnrollmentRefused`.
    InviteRefused,
    /// A ceremony failed. The message is deliberately coarse — the detailed
    /// reason goes to the log, not to the caller.
    Ceremony(&'static str),
    /// The challenge, code, session, or grant is unknown, expired, or spent.
    Invalid(&'static str),
    /// The caller presented a refresh token the device had already rotated away.
    /// By the time this error returns, we have revoked the whole grant family.
    RefreshReuse,
    /// Writing the sealed file failed.
    Persist(crate::error::CoreError),
}

impl AuthError {
    pub fn detail(&self) -> String {
        match self {
            Self::NotEnrolled => {
                "no passkey is enrolled on this broker yet; run `aka admin enroll` \
                 on the broker host to open enrollment"
                    .into()
            }
            Self::EnrollmentRefused => {
                "enrollment is not open, or that is not the secret it issued".into()
            }
            Self::InviteRefused => {
                "that invite is unknown, has expired, or has already been \
                 redeemed; ask the operator for a fresh `aka admin invite`"
                    .into()
            }
            Self::Ceremony(what) => format!("the passkey ceremony could not be completed: {what}"),
            Self::Invalid(what) => format!("{what} is not valid, has expired, or has been used"),
            Self::RefreshReuse => {
                "this device's grant was already refreshed; the whole family has been \
                 revoked because a replayed refresh token means one of the two holders \
                 is not the device. Sign in again."
                    .into()
            }
            Self::Persist(error) => format!("could not record the change: {error}"),
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail())
    }
}

impl std::error::Error for AuthError {}

impl From<crate::error::CoreError> for AuthError {
    fn from(error: crate::error::CoreError) -> Self {
        Self::Persist(error)
    }
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;

/* ------------------------------- records -------------------------------- */

/// The human this broker belongs to.
///
/// One today. The shape is plural because the alternative — a singleton that
/// later has to grow an id — is the migration nobody schedules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    /// The WebAuthn user handle. Random and opaque: the authenticator stores it,
    /// the browser's account picker shows it, and the platform syncs it to the
    /// user's other devices, so it must not be an email address or anything else
    /// that identifies them off this broker.
    pub handle: Uuid,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

/// One enrolled passkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: Uuid,
    pub account: Uuid,
    /// What the user calls this authenticator, e.g. "iPhone".
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// The verifying key and its signature counter, as webauthn-rs keeps it.
    pub passkey: Passkey,
}

/// A signed-in browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub id: Uuid,
    pub account: Uuid,
    /// Which passkey established it, so revoking a credential can close the
    /// sessions it opened.
    pub credential: Uuid,
    token_hash: String,
    /// The double-submit CSRF secret. Distinct from the session credential:
    /// the browser sends the cookie automatically and never this value, which
    /// is the whole mechanism.
    ///
    /// Deliberately the only plaintext field here. It is an anti-forgery
    /// nonce and not a credential: holding it authenticates nobody, because
    /// every request that uses it must *also* carry the session cookie, and
    /// we only ever store the cookie hashed. Keeping it recoverable lets a
    /// reloaded tab ask for its token again instead of signing the user out.
    csrf: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// When the passkey ceremony happened. Step-up measures against this,
    /// not against `created_at`, so a re-authentication refreshes it.
    pub authenticated_at: DateTime<Utc>,
    pub scopes: ScopeSet,
}

/// An authorized desktop or CLI, and the rotating refresh grant behind it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGrant {
    pub id: Uuid,
    pub account: Uuid,
    /// What the user named this device when they authorized it.
    pub name: String,
    pub surface: ClientSurface,
    pub scopes: ScopeSet,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// The passkey ceremony that authorized this device.
    pub authenticated_at: DateTime<Utc>,
    /// Hash of the refresh token that is currently good. Exactly one is live.
    refresh_hash: String,
    /// Hashes of the ones it replaced, newest first. Presenting any of these
    /// signals that two holders exist.
    superseded: Vec<String>,
    pub generation: u64,
}

/// A named, scoped, noninteractive credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationToken {
    pub id: Uuid,
    pub account: Uuid,
    pub name: String,
    token_hash: String,
    pub scopes: ScopeSet,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// An open invitation to enroll the first (or an additional) passkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Enrollment {
    secret_hash: String,
    expires_at: DateTime<Utc>,
}

/// A one-use invitation to fetch this broker's shared agent key.
///
/// The agent plane has exactly one key and pairing hands it out
/// unauthenticated, which is only acceptable behind the 0600 socket. An
/// invite is what makes the same handout safe over the network: the
/// operator mints it deliberately, it dies in minutes, and it is spent by
/// the first redemption. It carries no identity — the key it hands back is
/// the same shared key every other agent holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Invite {
    code_hash: String,
    /// Recorded on the redemption's audit entry, so a key handout can be
    /// traced to the invite an operator meant to issue.
    label: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Everything that survives a restart.
#[derive(Debug, Default, Serialize, Deserialize)]
struct AuthState {
    #[serde(default)]
    accounts: Vec<Account>,
    #[serde(default)]
    credentials: Vec<StoredCredential>,
    #[serde(default)]
    sessions: Vec<BrowserSession>,
    #[serde(default)]
    devices: Vec<DeviceGrant>,
    #[serde(default)]
    automation: Vec<AutomationToken>,
    #[serde(default)]
    enrollment: Option<Enrollment>,
    #[serde(default)]
    invites: Vec<Invite>,
}

/* ------------------------------ ephemera -------------------------------- */

struct PendingRegistration {
    account: Uuid,
    label: String,
    state: PasskeyRegistration,
    expires_at: DateTime<Utc>,
}

struct PendingAuthentication {
    state: PasskeyAuthentication,
    expires_at: DateTime<Utc>,
}

/// An issued authorization code, waiting to be exchanged.
struct PendingCode {
    account: Uuid,
    session: Uuid,
    device_name: String,
    surface: ClientSurface,
    scopes: ScopeSet,
    /// The PKCE challenge, S256 only. Exchange needs the verifier whose
    /// digest is this, which stops an interceptor of the redirect from
    /// spending the code.
    code_challenge: String,
    /// Bound at issue and compared at exchange: a code issued for one
    /// callback must not redeem against another.
    redirect_uri: String,
    authenticated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// A live access token. Access tokens are opaque and we look them up here
/// rather than signing them, so revoking a device takes effect on the next
/// request instead of at the next expiry.
struct LiveAccess {
    account: Uuid,
    device: Uuid,
    scopes: ScopeSet,
    surface: ClientSurface,
    authenticated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct Ephemeral {
    registrations: HashMap<Uuid, PendingRegistration>,
    authentications: HashMap<Uuid, PendingAuthentication>,
    codes: HashMap<String, PendingCode>,
    access: HashMap<String, LiveAccess>,
}

impl Ephemeral {
    fn prune(&mut self, now: DateTime<Utc>) {
        self.registrations.retain(|_, v| v.expires_at > now);
        self.authentications.retain(|_, v| v.expires_at > now);
        self.codes.retain(|_, v| v.expires_at > now);
        self.access.retain(|_, v| v.expires_at > now);
    }
}

/* ------------------------------- results -------------------------------- */

/// What a verified credential says about its holder. The manage plane turns
/// this into its principal; nothing else should need the records themselves.
#[derive(Debug, Clone)]
pub struct Verified {
    pub account: Uuid,
    /// The session, device, or automation token id — revoke this to end the
    /// credential.
    pub credential: Uuid,
    pub scopes: ScopeSet,
    pub surface: ClientSurface,
    /// When a human last proved themselves for this credential. `None` for
    /// automation, which never had a human behind it and therefore can never
    /// satisfy a step-up.
    pub authenticated_at: Option<DateTime<Utc>>,
}

/// A freshly minted browser session. The store keeps only hashes; the
/// plaintext cookie and CSRF secret exist only in this return value.
pub struct IssuedSession {
    pub session: BrowserSession,
    pub cookie: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
}

/// A freshly authorized device.
pub struct IssuedDevice {
    pub device: DeviceGrant,
    pub refresh: Zeroizing<String>,
}

/// The access/refresh pair from a code exchange or a refresh.
pub struct IssuedTokens {
    pub access: Zeroizing<String>,
    pub access_expires_at: DateTime<Utc>,
    pub refresh: Zeroizing<String>,
    pub device: Uuid,
    pub device_name: String,
    pub scopes: ScopeSet,
}

/* -------------------------------- store --------------------------------- */

pub struct AuthStore {
    path: PathBuf,
    integrity: Arc<StateIntegrity>,
    state: Mutex<AuthState>,
    ephemeral: Mutex<Ephemeral>,
}

impl AuthStore {
    /// Open (or create) `auth.json`. Sealed so a rewrite cannot go
    /// unnoticed, for the same reason `identity.json` is sealed — the file
    /// says who may sign in.
    pub fn open(path: PathBuf, integrity: Arc<StateIntegrity>) -> Result<Self> {
        let state: AuthState = integrity
            .read_verified(&path)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            path,
            integrity,
            state: Mutex::new(state),
            ephemeral: Mutex::new(Ephemeral::default()),
        })
    }

    /// An in-memory store for tests and for brokers with no data directory.
    pub fn ephemeral(integrity: Arc<StateIntegrity>) -> Self {
        Self {
            path: PathBuf::new(),
            integrity,
            state: Mutex::new(AuthState::default()),
            ephemeral: Mutex::new(Ephemeral::default()),
        }
    }

    fn persist(&self, state: &AuthState) -> AuthResult<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let bytes = serde_json::to_vec_pretty(state).map_err(crate::error::CoreError::from)?;
        self.integrity.write(&self.path, &bytes)?;
        Ok(())
    }

    fn locked(&self) -> MutexGuard<'_, AuthState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn ephemera(&self) -> MutexGuard<'_, Ephemeral> {
        self.ephemeral
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /* ---------------------------- enrollment ---------------------------- */

    /// Whether anybody can sign in at all.
    pub fn is_enrolled(&self) -> bool {
        !self.locked().credentials.is_empty()
    }

    /// Open enrollment and return the one-use secret.
    ///
    /// This is the answer to "who becomes the owner?", and the answer is not
    /// "the first person to reach the URL". The secret is generated here and
    /// written to a 0600 file on the broker host, so holding it proves local
    /// access to the machine — the same bar the management bootstrap token
    /// already sets.
    ///
    /// Opening it again replaces any outstanding secret, so a lost one gets
    /// re-issued rather than accumulating.
    pub fn open_enrollment(&self) -> AuthResult<Zeroizing<String>> {
        let secret = mint(ENROLLMENT_PREFIX);
        let mut state = self.locked();
        state.enrollment = Some(Enrollment {
            secret_hash: digest(&secret),
            expires_at: Utc::now() + ENROLLMENT_LIFETIME,
        });
        self.persist(&state)?;
        Ok(secret)
    }

    /// Close enrollment without using it.
    pub fn close_enrollment(&self) -> AuthResult<()> {
        let mut state = self.locked();
        state.enrollment = None;
        self.persist(&state)
    }

    pub fn enrollment_open(&self) -> bool {
        let now = Utc::now();
        self.locked()
            .enrollment
            .as_ref()
            .is_some_and(|open| open.expires_at > now)
    }

    /// Check an offered enrollment secret without consuming it.
    ///
    /// Deliberately separate from consumption: the secret authorizes
    /// *starting* a registration ceremony, and the ceremony can fail for
    /// reasons that are not the user's fault (a cancelled prompt, an
    /// authenticator that will not do user verification). Burning it at the
    /// start would make every such failure need a trip back to the broker
    /// host.
    fn check_enrollment(&self, state: &AuthState, secret: &str) -> AuthResult<()> {
        let Some(open) = state.enrollment.as_ref() else {
            return Err(AuthError::EnrollmentRefused);
        };
        if open.expires_at <= Utc::now() {
            return Err(AuthError::EnrollmentRefused);
        }
        let Some(offered) = shaped(secret, ENROLLMENT_PREFIX) else {
            return Err(AuthError::EnrollmentRefused);
        };
        if offered != open.secret_hash {
            return Err(AuthError::EnrollmentRefused);
        }
        Ok(())
    }

    /* ------------------------------ invites ----------------------------- */

    /// Mint a one-use agent-plane invite and return the code.
    ///
    /// Gated by the management token at the route, which is what makes this
    /// an operator act rather than an open key dispenser. Expired invites
    /// are swept here so the sealed file does not accumulate them.
    pub fn open_invite(&self, label: Option<String>) -> AuthResult<Zeroizing<String>> {
        let code = mint(INVITE_PREFIX);
        let now = Utc::now();
        let mut state = self.locked();
        state.invites.retain(|invite| invite.expires_at > now);
        if state.invites.len() >= MAX_INVITES {
            return Err(AuthError::Invalid("too many outstanding invites"));
        }
        state.invites.push(Invite {
            code_hash: digest(&code),
            label,
            created_at: now,
            expires_at: now + INVITE_LIFETIME,
        });
        self.persist(&state)?;
        Ok(code)
    }

    /// Spend an invite, returning its label for the audit entry.
    ///
    /// One-use by construction: the entry is removed before the caller is
    /// handed anything, inside the same lock, so two simultaneous
    /// redemptions cannot both win.
    pub fn redeem_invite(&self, code: &str) -> AuthResult<Option<String>> {
        let now = Utc::now();
        let mut state = self.locked();
        state.invites.retain(|invite| invite.expires_at > now);
        let Some(offered) = shaped(code, INVITE_PREFIX) else {
            return Err(AuthError::InviteRefused);
        };
        let Some(position) = state
            .invites
            .iter()
            .position(|invite| invite.code_hash == offered)
        else {
            // Persist the sweep even on refusal: expired invites are dead
            // either way, and a probe should not keep them alive.
            self.persist(&state)?;
            return Err(AuthError::InviteRefused);
        };
        let invite = state.invites.remove(position);
        self.persist(&state)?;
        Ok(invite.label)
    }

    /// Outstanding (unexpired) invites, newest last, for `admin invite --list`.
    pub fn invites(&self) -> Vec<(Option<String>, DateTime<Utc>, DateTime<Utc>)> {
        let now = Utc::now();
        self.locked()
            .invites
            .iter()
            .filter(|invite| invite.expires_at > now)
            .map(|invite| (invite.label.clone(), invite.created_at, invite.expires_at))
            .collect()
    }

    /// Drop every outstanding invite (`admin invite --cancel`).
    pub fn cancel_invites(&self) -> AuthResult<usize> {
        let now = Utc::now();
        let mut state = self.locked();
        let before = state
            .invites
            .iter()
            .filter(|invite| invite.expires_at > now)
            .count();
        state.invites.clear();
        self.persist(&state)?;
        Ok(before)
    }

    /* ------------------------------ accounts ---------------------------- */

    /// The owner, if enrollment has ever completed.
    pub fn owner(&self) -> Option<Account> {
        self.locked().accounts.first().cloned()
    }

    /// The owner, created on the first enrollment.
    fn ensure_owner(state: &mut AuthState, display_name: &str) -> Account {
        if let Some(account) = state.accounts.first() {
            return account.clone();
        }
        let account = Account {
            id: Uuid::new_v4(),
            handle: Uuid::new_v4(),
            display_name: display_name.to_string(),
            created_at: Utc::now(),
        };
        state.accounts.push(account.clone());
        account
    }

    pub fn credentials(&self) -> Vec<StoredCredential> {
        self.locked().credentials.clone()
    }

    /// The passkeys an authentication ceremony may offer.
    pub fn passkeys(&self) -> Vec<Passkey> {
        self.locked()
            .credentials
            .iter()
            .map(|credential| credential.passkey.clone())
            .collect()
    }

    /* ------------------------- registration ----------------------------- */

    /// Park a started registration ceremony and return its handle.
    ///
    /// Require `enrollment_secret` for the first passkey and for any
    /// enrollment that is not already authenticated; a signed-in owner adding
    /// a second passkey passes `None` and their session authorizes them.
    pub fn begin_registration(
        &self,
        state: PasskeyRegistration,
        label: &str,
        display_name: &str,
        enrollment_secret: Option<&str>,
    ) -> AuthResult<Uuid> {
        let mut durable = self.locked();
        let account = match (durable.accounts.first().cloned(), enrollment_secret) {
            // Adding to an existing account under an open enrollment secret.
            (Some(account), Some(secret)) => {
                self.check_enrollment(&durable, secret)?;
                account
            }
            // A signed-in owner adding another passkey; the caller checked
            // the session before getting here.
            (Some(account), None) => account,
            // First ever. The secret is the only thing that can authorize it.
            (None, Some(secret)) => {
                self.check_enrollment(&durable, secret)?;
                Self::ensure_owner(&mut durable, display_name)
            }
            (None, None) => return Err(AuthError::EnrollmentRefused),
        };
        self.persist(&durable)?;
        drop(durable);

        let mut ephemeral = self.ephemera();
        let now = Utc::now();
        ephemeral.prune(now);
        if ephemeral.registrations.len() >= MAX_PENDING_CHALLENGES {
            return Err(AuthError::Invalid("too many registrations are in flight"));
        }
        let handle = Uuid::new_v4();
        ephemeral.registrations.insert(
            handle,
            PendingRegistration {
                account: account.id,
                label: label.to_string(),
                state,
                expires_at: now + CHALLENGE_LIFETIME,
            },
        );
        Ok(handle)
    }

    /// Take a parked registration ceremony. One use: once something answers
    /// the challenge it is gone whether the answer verified or not, so a
    /// captured response cannot be replayed against it.
    pub fn take_registration(
        &self,
        handle: &Uuid,
    ) -> AuthResult<(Uuid, String, PasskeyRegistration)> {
        let mut ephemeral = self.ephemera();
        ephemeral.prune(Utc::now());
        let pending = ephemeral
            .registrations
            .remove(handle)
            .ok_or(AuthError::Invalid("that registration challenge"))?;
        Ok((pending.account, pending.label, pending.state))
    }

    /// Record a verified passkey and close enrollment.
    pub fn finish_registration(
        &self,
        account: Uuid,
        label: String,
        passkey: Passkey,
    ) -> AuthResult<StoredCredential> {
        let mut state = self.locked();
        // A credential id must be unique across the broker. webauthn-rs will
        // not tell us this; the spec says the relying party must.
        let id_bytes = passkey.cred_id().clone();
        if state
            .credentials
            .iter()
            .any(|existing| *existing.passkey.cred_id() == id_bytes)
        {
            return Err(AuthError::Ceremony("that passkey is already enrolled"));
        }
        let credential = StoredCredential {
            id: Uuid::new_v4(),
            account,
            label,
            created_at: Utc::now(),
            last_used_at: None,
            passkey,
        };
        state.credentials.push(credential.clone());
        // The invitation is spent the moment it produces a passkey.
        state.enrollment = None;
        self.persist(&state)?;
        Ok(credential)
    }

    /// Remove a passkey, and with it every session it established.
    ///
    /// Refuses to remove the last one: a broker with an account and no
    /// credential cannot be signed into at all, and recovering from that
    /// needs physical access to the host. Enroll the replacement first.
    pub fn remove_credential(&self, id: &Uuid) -> AuthResult<bool> {
        let mut state = self.locked();
        if !state.credentials.iter().any(|c| c.id == *id) {
            return Ok(false);
        }
        if state.credentials.len() == 1 {
            return Err(AuthError::Invalid(
                "the only enrolled passkey (enroll another first)",
            ));
        }
        state.credentials.retain(|c| c.id != *id);
        state.sessions.retain(|s| s.credential != *id);
        self.persist(&state)?;
        Ok(true)
    }

    /* ------------------------ authentication ---------------------------- */

    pub fn begin_authentication(&self, state: PasskeyAuthentication) -> AuthResult<Uuid> {
        let mut ephemeral = self.ephemera();
        let now = Utc::now();
        ephemeral.prune(now);
        if ephemeral.authentications.len() >= MAX_PENDING_CHALLENGES {
            return Err(AuthError::Invalid("too many sign-ins are in flight"));
        }
        let handle = Uuid::new_v4();
        ephemeral.authentications.insert(
            handle,
            PendingAuthentication {
                state,
                expires_at: now + CHALLENGE_LIFETIME,
            },
        );
        Ok(handle)
    }

    /// Take a parked authentication ceremony. One use, for the same reason
    /// registrations are.
    pub fn take_authentication(&self, handle: &Uuid) -> AuthResult<PasskeyAuthentication> {
        let mut ephemeral = self.ephemera();
        ephemeral.prune(Utc::now());
        ephemeral
            .authentications
            .remove(handle)
            .map(|pending| pending.state)
            .ok_or(AuthError::Invalid("that sign-in challenge"))
    }

    /// Record a successful assertion against the credential that made it,
    /// advancing the stored signature counter and backup state.
    ///
    /// A counter that went backwards is the spec's clone signal; webauthn-rs
    /// raises it during verification, so reaching here means it did not.
    pub fn record_assertion(
        &self,
        assertion: &crate::auth::passkey::Assertion,
    ) -> AuthResult<StoredCredential> {
        let mut state = self.locked();
        let credential = state
            .credentials
            .iter_mut()
            .find(|c| c.passkey.cred_id().as_slice() == assertion.credential_id())
            .ok_or(AuthError::Invalid("that passkey"))?;
        credential.passkey.update_credential(assertion.result());
        credential.last_used_at = Some(Utc::now());
        let updated = credential.clone();
        self.persist(&state)?;
        Ok(updated)
    }

    /* ------------------------------ sessions ---------------------------- */

    /// Open a browser session for a verified passkey.
    pub fn create_session(
        &self,
        account: Uuid,
        credential: Uuid,
        scopes: ScopeSet,
    ) -> AuthResult<IssuedSession> {
        let cookie = mint(SESSION_PREFIX);
        let csrf = mint(CSRF_PREFIX);
        let now = Utc::now();
        let session = BrowserSession {
            id: Uuid::new_v4(),
            account,
            credential,
            token_hash: digest(&cookie),
            csrf: csrf.to_string(),
            created_at: now,
            expires_at: now + SESSION_LIFETIME,
            last_seen_at: now,
            authenticated_at: now,
            scopes,
        };
        let mut state = self.locked();
        state.sessions.push(session.clone());
        Self::prune_sessions(&mut state, now);
        self.persist(&state)?;
        Ok(IssuedSession {
            session,
            cookie,
            csrf,
        })
    }

    fn prune_sessions(state: &mut AuthState, now: DateTime<Utc>) {
        state.sessions.retain(|session| {
            session.expires_at > now && session.last_seen_at + SESSION_IDLE > now
        });
    }

    /// Verify a session cookie.
    ///
    /// Pass `csrf` as `Some` for an unsafe method so we can check it against
    /// the stored secret; a browser sends the cookie whether or not the page
    /// that triggered the request was ours, and the CSRF value is the half
    /// it cannot forge cross-origin.
    pub fn verify_session(&self, cookie: &str, csrf: Option<&str>) -> AuthResult<Verified> {
        let Some(offered) = shaped(cookie, SESSION_PREFIX) else {
            return Err(AuthError::Invalid("that session"));
        };
        let now = Utc::now();
        let mut state = self.locked();
        let session = state
            .sessions
            .iter_mut()
            .find(|session| session.token_hash == offered)
            .ok_or(AuthError::Invalid("that session"))?;
        if session.expires_at <= now || session.last_seen_at + SESSION_IDLE <= now {
            let id = session.id;
            state.sessions.retain(|session| session.id != id);
            self.persist(&state)?;
            return Err(AuthError::Invalid("that session"));
        }
        if let Some(offered_csrf) = csrf {
            // Compare digests so the check does not run in time proportional
            // to a shared prefix.
            let matches =
                shaped(offered_csrf, CSRF_PREFIX).is_some_and(|hash| hash == digest(&session.csrf));
            if !matches {
                return Err(AuthError::Invalid("that request's CSRF token"));
            }
        }
        let verified = Verified {
            account: session.account,
            credential: session.id,
            scopes: session.scopes,
            surface: ClientSurface::Web,
            authenticated_at: Some(session.authenticated_at),
        };
        // Coalesced: a busy tab must not rewrite the sealed file per request.
        if session.last_seen_at + TOUCH_INTERVAL < now {
            session.last_seen_at = now;
            self.persist(&state)?;
        }
        Ok(verified)
    }

    /// Refresh a session's authentication time after a step-up ceremony.
    pub fn restamp_session(&self, id: &Uuid) -> AuthResult<()> {
        let mut state = self.locked();
        let session = state
            .sessions
            .iter_mut()
            .find(|session| session.id == *id)
            .ok_or(AuthError::Invalid("that session"))?;
        session.authenticated_at = Utc::now();
        session.last_seen_at = session.authenticated_at;
        self.persist(&state)
    }

    /// The CSRF secret a live session should send with its mutations.
    ///
    /// Returned only to a caller who already proved they hold the cookie,
    /// so this is not a way to obtain one — it is how a reloaded tab
    /// recovers the token it had.
    pub fn csrf_for(&self, session: &Uuid) -> Option<String> {
        self.locked()
            .sessions
            .iter()
            .find(|candidate| candidate.id == *session)
            .map(|candidate| candidate.csrf.clone())
    }

    pub fn sessions(&self) -> Vec<BrowserSession> {
        let now = Utc::now();
        let mut state = self.locked();
        Self::prune_sessions(&mut state, now);
        state.sessions.clone()
    }

    pub fn revoke_session(&self, id: &Uuid) -> AuthResult<bool> {
        let mut state = self.locked();
        let before = state.sessions.len();
        state.sessions.retain(|session| session.id != *id);
        let removed = state.sessions.len() != before;
        if removed {
            self.persist(&state)?;
        }
        Ok(removed)
    }

    /* ------------------------ authorization codes ----------------------- */

    /// Issue a one-use code for the desktop's loopback callback.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_code(
        &self,
        account: Uuid,
        session: Uuid,
        device_name: &str,
        surface: ClientSurface,
        scopes: ScopeSet,
        code_challenge: &str,
        redirect_uri: &str,
        authenticated_at: DateTime<Utc>,
    ) -> AuthResult<Zeroizing<String>> {
        let code = mint(CODE_PREFIX);
        let now = Utc::now();
        let mut ephemeral = self.ephemera();
        ephemeral.prune(now);
        if ephemeral.codes.len() >= MAX_PENDING_CODES {
            return Err(AuthError::Invalid("too many sign-ins are in flight"));
        }
        ephemeral.codes.insert(
            digest(&code),
            PendingCode {
                account,
                session,
                device_name: device_name.to_string(),
                surface,
                scopes,
                code_challenge: code_challenge.to_string(),
                redirect_uri: redirect_uri.to_string(),
                authenticated_at,
                expires_at: now + CODE_LIFETIME,
            },
        );
        Ok(code)
    }

    /// Exchange a code for a device grant.
    ///
    /// We remove the code before validating anything else, so a wrong verifier
    /// burns it rather than allowing another guess.
    pub fn redeem_code(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> AuthResult<IssuedDevice> {
        let Some(offered) = shaped(code, CODE_PREFIX) else {
            return Err(AuthError::Invalid("that authorization code"));
        };
        let pending = {
            let mut ephemeral = self.ephemera();
            ephemeral.prune(Utc::now());
            ephemeral
                .codes
                .remove(&offered)
                .ok_or(AuthError::Invalid("that authorization code"))?
        };
        if pending.redirect_uri != redirect_uri {
            return Err(AuthError::Invalid("that redirect URI"));
        }
        if b64(&Sha256::digest(verifier.as_bytes())) != pending.code_challenge {
            return Err(AuthError::Invalid("that PKCE verifier"));
        }
        self.create_device(
            pending.account,
            &pending.device_name,
            pending.surface,
            pending.scopes,
            pending.authenticated_at,
            Some(pending.session),
        )
    }

    /* ------------------------------ devices ----------------------------- */

    pub fn create_device(
        &self,
        account: Uuid,
        name: &str,
        surface: ClientSurface,
        scopes: ScopeSet,
        authenticated_at: DateTime<Utc>,
        _session: Option<Uuid>,
    ) -> AuthResult<IssuedDevice> {
        let refresh = mint(REFRESH_PREFIX);
        let now = Utc::now();
        let device = DeviceGrant {
            id: Uuid::new_v4(),
            account,
            name: name.to_string(),
            surface,
            scopes,
            created_at: now,
            last_seen_at: now,
            authenticated_at,
            refresh_hash: digest(&refresh),
            superseded: Vec::new(),
            generation: 0,
        };
        let mut state = self.locked();
        state.devices.push(device.clone());
        self.persist(&state)?;
        Ok(IssuedDevice { device, refresh })
    }

    /// Rotate a device's refresh grant and mint a fresh access token.
    ///
    /// Presenting a superseded token revokes the family. Two holders of one
    /// rotating credential means one of them is not the device, and there is
    /// no way to tell which — so neither continues.
    pub fn refresh_device(&self, refresh: &str) -> AuthResult<IssuedTokens> {
        let Some(offered) = shaped(refresh, REFRESH_PREFIX) else {
            return Err(AuthError::Invalid("that refresh token"));
        };
        let now = Utc::now();
        let next = mint(REFRESH_PREFIX);
        let (account, device_id, name, scopes, authenticated_at) = {
            let mut state = self.locked();
            if let Some(position) = state
                .devices
                .iter()
                .position(|device| device.superseded.contains(&offered))
            {
                let stolen = state.devices.remove(position);
                self.persist(&state)?;
                tracing::warn!(
                    device = %stolen.name,
                    generation = stolen.generation,
                    "a superseded refresh token was replayed; the device grant is revoked"
                );
                return Err(AuthError::RefreshReuse);
            }
            let device = state
                .devices
                .iter_mut()
                .find(|device| device.refresh_hash == offered)
                .ok_or(AuthError::Invalid("that refresh token"))?;
            if device.last_seen_at + DEVICE_IDLE_LIFETIME <= now {
                let id = device.id;
                state.devices.retain(|device| device.id != id);
                self.persist(&state)?;
                return Err(AuthError::Invalid("that device grant"));
            }
            device.superseded.insert(0, device.refresh_hash.clone());
            device.superseded.truncate(REFRESH_HISTORY);
            device.refresh_hash = digest(&next);
            device.generation += 1;
            device.last_seen_at = now;
            let snapshot = (
                device.account,
                device.id,
                device.name.clone(),
                device.scopes,
                device.authenticated_at,
            );
            self.persist(&state)?;
            snapshot
        };
        let access = self.mint_access(
            account,
            device_id,
            scopes,
            ClientSurface::Desktop,
            authenticated_at,
        )?;
        Ok(IssuedTokens {
            access: access.0,
            access_expires_at: access.1,
            refresh: next,
            device: device_id,
            device_name: name,
            scopes,
        })
    }

    /// The first token pair for a newly authorized device.
    pub fn issue_for_device(&self, issued: IssuedDevice) -> AuthResult<IssuedTokens> {
        let IssuedDevice { device, refresh } = issued;
        let (access, expires_at) = self.mint_access(
            device.account,
            device.id,
            device.scopes,
            device.surface,
            device.authenticated_at,
        )?;
        Ok(IssuedTokens {
            access,
            access_expires_at: expires_at,
            refresh,
            device: device.id,
            device_name: device.name,
            scopes: device.scopes,
        })
    }

    fn mint_access(
        &self,
        account: Uuid,
        device: Uuid,
        scopes: ScopeSet,
        surface: ClientSurface,
        authenticated_at: DateTime<Utc>,
    ) -> AuthResult<(Zeroizing<String>, DateTime<Utc>)> {
        let token = mint(ACCESS_PREFIX);
        let now = Utc::now();
        let expires_at = now + ACCESS_LIFETIME;
        let mut ephemeral = self.ephemera();
        ephemeral.prune(now);
        if ephemeral.access.len() >= MAX_ACCESS_TOKENS {
            return Err(AuthError::Invalid("too many access tokens are live"));
        }
        ephemeral.access.insert(
            digest(&token),
            LiveAccess {
                account,
                device,
                scopes,
                surface,
                authenticated_at,
                expires_at,
            },
        );
        Ok((token, expires_at))
    }

    /// Verify a desktop access token.
    ///
    /// We check the device list as well as the token map so revoking a
    /// device takes effect immediately, not when its last access token
    /// happens to expire.
    pub fn verify_access(&self, token: &str) -> AuthResult<Verified> {
        let Some(offered) = shaped(token, ACCESS_PREFIX) else {
            return Err(AuthError::Invalid("that access token"));
        };
        let now = Utc::now();
        let mut ephemeral = self.ephemera();
        ephemeral.prune(now);
        let live = ephemeral
            .access
            .get(&offered)
            .ok_or(AuthError::Invalid("that access token"))?;
        let verified = Verified {
            account: live.account,
            credential: live.device,
            scopes: live.scopes,
            surface: live.surface,
            authenticated_at: Some(live.authenticated_at),
        };
        let device = live.device;
        drop(ephemeral);
        if !self.locked().devices.iter().any(|grant| grant.id == device) {
            self.forget_access_for(&device);
            return Err(AuthError::Invalid("that device grant"));
        }
        Ok(verified)
    }

    fn forget_access_for(&self, device: &Uuid) {
        self.ephemera()
            .access
            .retain(|_, live| live.device != *device);
    }

    pub fn devices(&self) -> Vec<DeviceGrant> {
        self.locked().devices.clone()
    }

    pub fn revoke_device(&self, id: &Uuid) -> AuthResult<bool> {
        let mut state = self.locked();
        let before = state.devices.len();
        state.devices.retain(|device| device.id != *id);
        let removed = state.devices.len() != before;
        drop(state);
        if removed {
            self.forget_access_for(id);
            self.persist(&self.locked())?;
        }
        Ok(removed)
    }

    /// Rename a device, so a list of them is readable a year later.
    pub fn rename_device(&self, id: &Uuid, name: &str) -> AuthResult<bool> {
        let mut state = self.locked();
        let Some(device) = state.devices.iter_mut().find(|device| device.id == *id) else {
            return Ok(false);
        };
        device.name = name.to_string();
        self.persist(&state)?;
        Ok(true)
    }

    /* ---------------------------- automation ---------------------------- */

    pub fn mint_automation(
        &self,
        account: Uuid,
        name: &str,
        scopes: ScopeSet,
        ttl: Option<ChronoDuration>,
    ) -> AuthResult<(AutomationToken, Zeroizing<String>)> {
        let token = mint(AUTOMATION_PREFIX);
        let now = Utc::now();
        let record = AutomationToken {
            id: Uuid::new_v4(),
            account,
            name: name.to_string(),
            token_hash: digest(&token),
            scopes,
            created_at: now,
            expires_at: ttl.map(|ttl| now + ttl),
            last_used_at: None,
        };
        let mut state = self.locked();
        state.automation.push(record.clone());
        self.persist(&state)?;
        Ok((record, token))
    }

    pub fn verify_automation(&self, token: &str) -> AuthResult<Verified> {
        let Some(offered) = shaped(token, AUTOMATION_PREFIX) else {
            return Err(AuthError::Invalid("that automation token"));
        };
        let now = Utc::now();
        let mut state = self.locked();
        let record = state
            .automation
            .iter_mut()
            .find(|record| record.token_hash == offered)
            .ok_or(AuthError::Invalid("that automation token"))?;
        if record.expires_at.is_some_and(|expiry| expiry <= now) {
            let id = record.id;
            state.automation.retain(|record| record.id != id);
            self.persist(&state)?;
            return Err(AuthError::Invalid("that automation token"));
        }
        let verified = Verified {
            account: record.account,
            credential: record.id,
            scopes: record.scopes,
            surface: ClientSurface::Automation,
            // No human, ever. A step-up route is therefore unreachable with
            // one of these, which is the intended shape rather than an
            // oversight: an unattended process cannot consent.
            authenticated_at: None,
        };
        let stale = record
            .last_used_at
            .is_none_or(|last| last + TOUCH_INTERVAL < now);
        if stale {
            record.last_used_at = Some(now);
            self.persist(&state)?;
        }
        Ok(verified)
    }

    pub fn automation_tokens(&self) -> Vec<AutomationToken> {
        self.locked().automation.clone()
    }

    pub fn revoke_automation(&self, id: &Uuid) -> AuthResult<bool> {
        let mut state = self.locked();
        let before = state.automation.len();
        state.automation.retain(|record| record.id != *id);
        let removed = state.automation.len() != before;
        if removed {
            self.persist(&state)?;
        }
        Ok(removed)
    }

    /// Close every session and device for an account — the "sign out
    /// everywhere" that a suspected compromise needs.
    pub fn revoke_all(&self) -> AuthResult<()> {
        let mut state = self.locked();
        state.sessions.clear();
        state.devices.clear();
        self.persist(&state)?;
        drop(state);
        let mut ephemeral = self.ephemera();
        ephemeral.access.clear();
        ephemeral.codes.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::policy::Scope;

    fn store() -> AuthStore {
        AuthStore::ephemeral(Arc::new(
            futures::executor::block_on(StateIntegrity::open(&crate::vault::MemoryVault::new()))
                .unwrap(),
        ))
    }

    fn enrolled(store: &AuthStore) -> Account {
        let mut state = store.locked();
        let account = AuthStore::ensure_owner(&mut state, "Owner");
        drop(state);
        account
    }

    #[test]
    fn enrollment_needs_the_secret_the_host_issued() {
        let store = store();
        assert!(!store.enrollment_open());
        let secret = store.open_enrollment().unwrap();
        assert!(store.enrollment_open());

        let state = store.locked();
        assert!(store.check_enrollment(&state, &secret).is_ok());
        // A different secret, and a well-formed one of the wrong plane.
        assert!(store
            .check_enrollment(&state, "akaenroll_deadbeef")
            .is_err());
        assert!(store.check_enrollment(&state, "akamgr_deadbeef").is_err());
    }

    #[test]
    fn enrollment_expires() {
        let store = store();
        let secret = store.open_enrollment().unwrap();
        {
            let mut state = store.locked();
            state.enrollment.as_mut().unwrap().expires_at = Utc::now() - ChronoDuration::seconds(1);
        }
        assert!(!store.enrollment_open());
        let state = store.locked();
        assert!(store.check_enrollment(&state, &secret).is_err());
    }

    #[test]
    fn reopening_enrollment_invalidates_the_previous_secret() {
        let store = store();
        let first = store.open_enrollment().unwrap();
        let second = store.open_enrollment().unwrap();
        let state = store.locked();
        assert!(store.check_enrollment(&state, &first).is_err());
        assert!(store.check_enrollment(&state, &second).is_ok());
    }

    #[test]
    fn a_session_verifies_once_and_carries_its_scopes() {
        let store = store();
        let account = enrolled(&store);
        let credential = Uuid::new_v4();
        let issued = store
            .create_session(account.id, credential, ScopeSet::all())
            .unwrap();

        let verified = store.verify_session(&issued.cookie, None).unwrap();
        assert_eq!(verified.account, account.id);
        assert_eq!(verified.credential, issued.session.id);
        assert_eq!(verified.surface, ClientSurface::Web);
        assert!(verified.scopes.contains(Scope::ManageWrite));
        assert!(verified.authenticated_at.is_some());
    }

    #[test]
    fn a_session_cookie_of_the_wrong_shape_is_refused_before_lookup() {
        let store = store();
        let account = enrolled(&store);
        let issued = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();
        // The right bytes behind the wrong prefix must not authenticate:
        // prefixes are what keep the planes from being interchangeable.
        let confused = issued.cookie.replace(SESSION_PREFIX, "akamgr_");
        assert!(store.verify_session(&confused, None).is_err());
    }

    #[test]
    fn an_unsafe_method_needs_the_csrf_secret_too() {
        let store = store();
        let account = enrolled(&store);
        let issued = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();

        assert!(store
            .verify_session(&issued.cookie, Some(&issued.csrf))
            .is_ok());
        // The cookie alone is what a cross-origin form gets to send.
        assert!(store.verify_session(&issued.cookie, Some("")).is_err());
        assert!(store
            .verify_session(&issued.cookie, Some("akacsrf_00"))
            .is_err());
        // And the session token is not its own CSRF token.
        assert!(store
            .verify_session(&issued.cookie, Some(&issued.cookie))
            .is_err());
    }

    #[test]
    fn an_expired_session_is_refused_and_forgotten() {
        let store = store();
        let account = enrolled(&store);
        let issued = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();
        {
            let mut state = store.locked();
            state.sessions[0].expires_at = Utc::now() - ChronoDuration::seconds(1);
        }
        assert!(store.verify_session(&issued.cookie, None).is_err());
        assert!(store.locked().sessions.is_empty());
    }

    #[test]
    fn an_idle_session_stops_working_before_its_absolute_expiry() {
        let store = store();
        let account = enrolled(&store);
        let issued = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();
        {
            let mut state = store.locked();
            // Well inside SESSION_LIFETIME, well past SESSION_IDLE.
            state.sessions[0].last_seen_at = Utc::now() - SESSION_IDLE - ChronoDuration::minutes(1);
        }
        assert!(store.verify_session(&issued.cookie, None).is_err());
    }

    #[test]
    fn revoking_a_session_takes_effect_at_once() {
        let store = store();
        let account = enrolled(&store);
        let issued = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();
        assert!(store.revoke_session(&issued.session.id).unwrap());
        assert!(store.verify_session(&issued.cookie, None).is_err());
        assert!(!store.revoke_session(&issued.session.id).unwrap());
    }

    /* ------------------------------ PKCE -------------------------------- */

    fn challenge_for(verifier: &str) -> String {
        b64(&Sha256::digest(verifier.as_bytes()))
    }

    fn code_for(
        store: &AuthStore,
        account: Uuid,
        verifier: &str,
        redirect: &str,
    ) -> Zeroizing<String> {
        store
            .mint_code(
                account,
                Uuid::new_v4(),
                "Test Mac",
                ClientSurface::Desktop,
                ScopeSet::desktop(),
                &challenge_for(verifier),
                redirect,
                Utc::now(),
            )
            .unwrap()
    }

    #[test]
    fn a_code_exchanges_once_with_the_right_verifier() {
        let store = store();
        let account = enrolled(&store);
        let verifier = "a-high-entropy-verifier-value-0123456789";
        let redirect = "http://127.0.0.1:51234/callback";
        let code = code_for(&store, account.id, verifier, redirect);

        let device = store.redeem_code(&code, verifier, redirect).unwrap();
        assert_eq!(device.device.account, account.id);
        assert_eq!(device.device.name, "Test Mac");
        // One use.
        assert!(store.redeem_code(&code, verifier, redirect).is_err());
    }

    #[test]
    fn intercepting_the_redirect_is_not_enough_without_the_verifier() {
        let store = store();
        let account = enrolled(&store);
        let redirect = "http://127.0.0.1:51234/callback";
        let code = code_for(&store, account.id, "the-real-verifier-0123456789", redirect);

        assert!(store
            .redeem_code(&code, "a-guessed-verifier-0123456789", redirect)
            .is_err());
        // And the attempt burned it, so the real client's exchange fails too
        // rather than the attacker getting unlimited guesses.
        assert!(store
            .redeem_code(&code, "the-real-verifier-0123456789", redirect)
            .is_err());
    }

    #[test]
    fn a_code_is_bound_to_the_callback_it_was_issued_for() {
        let store = store();
        let account = enrolled(&store);
        let verifier = "a-high-entropy-verifier-value-0123456789";
        let code = code_for(
            &store,
            account.id,
            verifier,
            "http://127.0.0.1:51234/callback",
        );
        assert!(store
            .redeem_code(&code, verifier, "http://127.0.0.1:9999/callback")
            .is_err());
    }

    #[test]
    fn an_expired_code_cannot_be_exchanged() {
        let store = store();
        let account = enrolled(&store);
        let verifier = "a-high-entropy-verifier-value-0123456789";
        let redirect = "http://127.0.0.1:51234/callback";
        let code = code_for(&store, account.id, verifier, redirect);
        {
            let mut ephemeral = store.ephemera();
            for pending in ephemeral.codes.values_mut() {
                pending.expires_at = Utc::now() - ChronoDuration::seconds(1);
            }
        }
        assert!(store.redeem_code(&code, verifier, redirect).is_err());
    }

    /* ---------------------------- devices ------------------------------- */

    fn device(store: &AuthStore, account: Uuid) -> IssuedTokens {
        let issued = store
            .create_device(
                account,
                "Test Mac",
                ClientSurface::Desktop,
                ScopeSet::desktop(),
                Utc::now(),
                None,
            )
            .unwrap();
        store.issue_for_device(issued).unwrap()
    }

    #[test]
    fn an_access_token_verifies_until_it_expires() {
        let store = store();
        let account = enrolled(&store);
        let tokens = device(&store, account.id);

        let verified = store.verify_access(&tokens.access).unwrap();
        assert_eq!(verified.account, account.id);
        assert_eq!(verified.credential, tokens.device);
        assert_eq!(verified.surface, ClientSurface::Desktop);

        {
            let mut ephemeral = store.ephemera();
            for live in ephemeral.access.values_mut() {
                live.expires_at = Utc::now() - ChronoDuration::seconds(1);
            }
        }
        assert!(store.verify_access(&tokens.access).is_err());
    }

    #[test]
    fn refreshing_rotates_the_grant_and_the_old_one_stops_working() {
        let store = store();
        let account = enrolled(&store);
        let first = device(&store, account.id);

        let second = store.refresh_device(&first.refresh).unwrap();
        assert_ne!(*second.refresh, *first.refresh);
        assert_eq!(second.device, first.device);
        assert!(store.verify_access(&second.access).is_ok());
    }

    #[test]
    fn replaying_a_superseded_refresh_token_revokes_the_device() {
        let store = store();
        let account = enrolled(&store);
        let first = device(&store, account.id);
        let second = store.refresh_device(&first.refresh).unwrap();

        // Two holders of one rotating credential; neither continues.
        assert!(matches!(
            store.refresh_device(&first.refresh),
            Err(AuthError::RefreshReuse)
        ));
        assert!(store.refresh_device(&second.refresh).is_err());
        assert!(store.devices().is_empty());
        // The live access token the thief might already hold dies with it.
        assert!(store.verify_access(&second.access).is_err());
    }

    #[test]
    fn revoking_a_device_invalidates_its_live_access_token_at_once() {
        let store = store();
        let account = enrolled(&store);
        let tokens = device(&store, account.id);
        assert!(store.verify_access(&tokens.access).is_ok());

        assert!(store.revoke_device(&tokens.device).unwrap());
        assert!(store.verify_access(&tokens.access).is_err());
        assert!(store.refresh_device(&tokens.refresh).is_err());
    }

    #[test]
    fn an_idle_device_grant_ages_out() {
        let store = store();
        let account = enrolled(&store);
        let tokens = device(&store, account.id);
        {
            let mut state = store.locked();
            state.devices[0].last_seen_at =
                Utc::now() - DEVICE_IDLE_LIFETIME - ChronoDuration::days(1);
        }
        assert!(store.refresh_device(&tokens.refresh).is_err());
        assert!(store.devices().is_empty());
    }

    #[test]
    fn the_refresh_history_is_bounded() {
        let store = store();
        let account = enrolled(&store);
        let mut tokens = device(&store, account.id);
        for _ in 0..(REFRESH_HISTORY + 4) {
            tokens = store.refresh_device(&tokens.refresh).unwrap();
        }
        assert_eq!(store.locked().devices[0].superseded.len(), REFRESH_HISTORY);
    }

    /* --------------------------- automation ----------------------------- */

    #[test]
    fn an_automation_token_can_never_satisfy_a_step_up() {
        let store = store();
        let account = enrolled(&store);
        let (_, token) = store
            .mint_automation(account.id, "ci", ScopeSet::cloud_pusher(), None)
            .unwrap();

        let verified = store.verify_automation(&token).unwrap();
        assert_eq!(verified.surface, ClientSurface::Automation);
        assert_eq!(verified.scopes, ScopeSet::cloud_pusher());
        assert!(
            verified.authenticated_at.is_none(),
            "no human stands behind an automation token"
        );
    }

    #[test]
    fn an_expired_automation_token_is_refused_and_dropped() {
        let store = store();
        let account = enrolled(&store);
        let (record, token) = store
            .mint_automation(
                account.id,
                "ci",
                ScopeSet::cloud_pusher(),
                Some(ChronoDuration::seconds(-1)),
            )
            .unwrap();
        assert!(store.verify_automation(&token).is_err());
        assert!(!store.automation_tokens().iter().any(|t| t.id == record.id));
    }

    #[test]
    fn revoking_automation_takes_effect_at_once() {
        let store = store();
        let account = enrolled(&store);
        let (record, token) = store
            .mint_automation(account.id, "ci", ScopeSet::cloud_pusher(), None)
            .unwrap();
        assert!(store.revoke_automation(&record.id).unwrap());
        assert!(store.verify_automation(&token).is_err());
    }

    #[test]
    fn credentials_of_one_kind_do_not_verify_as_another() {
        let store = store();
        let account = enrolled(&store);
        let session = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();
        let tokens = device(&store, account.id);
        let (_, automation) = store
            .mint_automation(account.id, "ci", ScopeSet::cloud_pusher(), None)
            .unwrap();

        assert!(store.verify_access(&session.cookie).is_err());
        assert!(store.verify_automation(&session.cookie).is_err());
        assert!(store.verify_session(&tokens.access, None).is_err());
        assert!(store.verify_automation(&tokens.access).is_err());
        assert!(store.verify_session(&automation, None).is_err());
        assert!(store.verify_access(&automation).is_err());
    }

    #[test]
    fn revoke_all_closes_every_door() {
        let store = store();
        let account = enrolled(&store);
        let session = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();
        let tokens = device(&store, account.id);

        store.revoke_all().unwrap();
        assert!(store.verify_session(&session.cookie, None).is_err());
        assert!(store.verify_access(&tokens.access).is_err());
        assert!(store.refresh_device(&tokens.refresh).is_err());
    }

    #[test]
    fn token_prefixes_are_distinct_from_each_other_and_the_older_planes() {
        let prefixes = [
            SESSION_PREFIX,
            CSRF_PREFIX,
            CODE_PREFIX,
            REFRESH_PREFIX,
            ACCESS_PREFIX,
            AUTOMATION_PREFIX,
            ENROLLMENT_PREFIX,
            "aka_",
            crate::identity::MANAGE_TOKEN_PREFIX,
        ];
        for (i, a) in prefixes.iter().enumerate() {
            for (j, b) in prefixes.iter().enumerate() {
                if i == j {
                    continue;
                }
                // Not merely different: neither may be a prefix of the other,
                // or a `starts_with` check would accept both.
                assert!(!a.starts_with(b), "{a} starts with {b}");
            }
        }
    }

    #[test]
    fn nothing_persisted_holds_a_credential_in_the_clear() {
        let store = store();
        let account = enrolled(&store);
        let session = store
            .create_session(account.id, Uuid::new_v4(), ScopeSet::all())
            .unwrap();
        let tokens = device(&store, account.id);
        let (_, automation) = store
            .mint_automation(account.id, "ci", ScopeSet::all(), None)
            .unwrap();
        let enrollment = store.open_enrollment().unwrap();

        let serialized = serde_json::to_string(&*store.locked()).unwrap();
        for secret in [
            session.cookie.as_str(),
            tokens.refresh.as_str(),
            automation.as_str(),
            enrollment.as_str(),
        ] {
            assert!(
                !serialized.contains(secret),
                "a credential reached the sealed file in the clear"
            );
        }
        // The CSRF nonce is the documented exception: it authenticates
        // nobody without the cookie, and it has to be recoverable.
        assert!(serialized.contains(session.csrf.as_str()));
    }
}
