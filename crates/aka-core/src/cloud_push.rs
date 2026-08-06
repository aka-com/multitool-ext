//! Keeping a broker supplied with sessions minted on another machine.
//!
//! A reuse connection names a profile in one particular machine's `~/.aws`.
//! When the broker runs there too it reads the files itself and none of this
//! applies. When it does not — a hosted broker — it cannot read them, since
//! its own `~/.aws` is a different account entirely, so the deal inverts:
//! the app on the owning machine mints and pushes only the result.
//!
//! What that buys and what it costs are the same fact. The broker never
//! holds anything that outlives the hour, so long-lived keys stay on the
//! machine that owns them; but a broker holding only expiring material has
//! nothing to serve once the pushes stop, so agents lose the connection
//! while that machine is asleep or the app is closed. The mint path names
//! that cause rather than failing obscurely (see [`crate::cloud`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::manage::ManagementBackend;
use crate::types::{MAX_CLOUD_SESSION_TTL_SECS, MIN_CLOUD_SESSION_TTL_SECS};

/// Renew once a session is this far through its life. Early enough that a
/// failed attempt has several more chances before agents notice.
const RENEW_AFTER: f64 = 0.5;

/// What was last pushed, so a tick that changes nothing costs no STS calls.
/// Broker-side state is authoritative but unreadable from here; this is the
/// local shadow of it, and a broker restart simply means the next push
/// re-establishes what was lost.
#[derive(Default)]
pub struct PushedClock {
    by_connection: Mutex<HashMap<String, PushRecord>>,
}

struct PushRecord {
    expires_at: DateTime<Utc>,
    /// Session lifetime, so "half spent" is measured against the real TTL
    /// rather than a guess.
    lifetime_secs: i64,
}

impl PushedClock {
    fn needs_push(&self, connection: &str) -> bool {
        let records = self
            .by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(record) = records.get(connection) else {
            return true;
        };
        let remaining = (record.expires_at - Utc::now()).num_seconds();
        remaining <= (record.lifetime_secs as f64 * RENEW_AFTER) as i64
    }

    fn record(&self, connection: &str, expires_at: DateTime<Utc>, lifetime_secs: i64) {
        self.by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(
                connection.to_string(),
                PushRecord {
                    expires_at,
                    lifetime_secs: lifetime_secs.max(1),
                },
            );
    }

    /// Forget everything: called when the active broker changes, since what
    /// the old one held says nothing about the new one.
    pub fn reset(&self) {
        self.by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }
}

/* ------------------------------ leash pins -------------------------------- */

/// The STS parameters one push-mint runs with, as this app knows them.
///
/// Everything here shapes what the minted session can do: which profile's
/// keys sign the call, which role is assumed, what session policy AWS
/// intersects the caller with, and for how long. All of it is stored on the
/// broker's connection record — the same broker the minted session is handed
/// to — so a broker that could rewrite these fields could quietly widen its
/// own leash. The pin is the app's independent record of what the user
/// actually configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeashParams {
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_policy_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_policy: Option<String>,
    pub session_ttl_secs: u64,
}

/// Per-connection mint-parameter pins, persisted across app runs.
///
/// A pin is written from the submitted form when this app creates the
/// connection, or trust-on-first-use at the first refresh sight of a
/// connection created before pinning existed. From then on a broker that
/// reports different parameters gets no session: the manage plane cannot
/// re-leash the app's mints. Cloud connections are rename-only on the
/// manage patch surface, so a legitimate parameter change is a delete and
/// re-add — which forgets the old pin and writes a fresh one.
pub struct LeashPins {
    /// Where pins persist; `None` keeps them in memory (tests).
    path: Option<PathBuf>,
    by_connection: Mutex<HashMap<String, LeashParams>>,
}

impl LeashPins {
    /// Pins backed by a JSON file. An unreadable or corrupt file starts
    /// empty: existing connections re-pin on first sight, which is the same
    /// trust the very first run extended.
    pub fn load(path: PathBuf) -> Self {
        let by_connection = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            path: Some(path),
            by_connection: Mutex::new(by_connection),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            path: None,
            by_connection: Mutex::new(HashMap::new()),
        }
    }

    fn persist(&self, pins: &HashMap<String, LeashParams>) {
        let Some(path) = &self.path else { return };
        let write = || -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, serde_json::to_vec_pretty(pins)?)
        };
        if let Err(error) = write() {
            // Degrades to per-run pinning; the next successful write heals.
            tracing::debug!("could not persist cloud leash pins: {error}");
        }
    }

    /// Record what the user just configured, replacing any earlier pin.
    /// Called with the submitted form values at creation time — the one
    /// moment the parameters are known without asking the broker.
    pub fn pin(&self, connection_id: &str, params: LeashParams) {
        let mut pins = self
            .by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        pins.insert(connection_id.to_string(), params);
        self.persist(&pins);
    }

    /// Drop a deleted connection's pin. Never called from broker-driven
    /// paths: letting the broker clear a pin (by omitting the connection
    /// from one listing, say) would let it re-pin wider on the next.
    pub fn forget(&self, connection_id: &str) {
        let mut pins = self
            .by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if pins.remove(connection_id).is_some() {
            self.persist(&pins);
        }
    }

    /// Whether the broker-reported parameters match the pin, pinning them
    /// on first sight. `false` means refuse to mint.
    fn check_and_pin(&self, connection_id: &str, params: &LeashParams) -> bool {
        let mut pins = self
            .by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match pins.get(connection_id) {
            Some(pinned) => pinned == params,
            None => {
                pins.insert(connection_id.to_string(), params.clone());
                self.persist(&pins);
                true
            }
        }
    }
}

/// Mint and push every connection this install owns that is due, once.
///
/// Errors are per-connection and non-fatal: one profile that has gone away
/// (renamed, signed out) must not stop the others from refreshing, and the
/// agent-facing error for that one connection is already precise.
pub async fn refresh_once(
    backend: Arc<dyn ManagementBackend>,
    install_id: &str,
    clock: &PushedClock,
    pins: &LeashPins,
) {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap_or_default();
    if install_id.is_empty() {
        return;
    }
    let connections = match backend.list_connections().await {
        Ok(connections) => connections,
        // A broker that is down needs no pushes; the next tick retries.
        Err(_) => return,
    };
    for connection in connections {
        let Some(cloud) = connection.cloud.as_ref() else {
            continue;
        };
        // Only connections that name *this* install's files, and only when
        // the broker is not the one reading them: a local broker mints at
        // request time from the same ~/.aws, holds nothing, and refuses
        // pushes — minting here anyway would spend a real STS call per tick
        // on credentials the push path then throws away.
        if cloud.source_origin.as_deref() != Some(install_id) || !cloud.minted_elsewhere {
            continue;
        }
        let Some(profile) = cloud.source_profile.as_deref() else {
            continue;
        };
        if !clock.needs_push(&connection.id) {
            continue;
        }
        // The DTO's TTL is broker-supplied; the ceiling is ours to enforce.
        let ttl = cloud
            .session_ttl_secs
            .clamp(MIN_CLOUD_SESSION_TTL_SECS, MAX_CLOUD_SESSION_TTL_SECS);
        // Everything below rides in from the broker's listing — the same
        // broker the minted session goes back to. Mint only what matches
        // the leash this app pinned when the connection was configured; a
        // broker that reports a stripped policy or a swapped profile gets
        // nothing rather than a wider session.
        let params = LeashParams {
            profile: profile.to_string(),
            region: cloud.region.clone(),
            role_arn: cloud.role_arn.clone(),
            external_id: cloud.external_id.clone(),
            session_policy_arn: cloud.session_policy_arn.clone(),
            session_policy: cloud.session_policy.clone(),
            session_ttl_secs: ttl,
        };
        if !pins.check_and_pin(&connection.id, &params) {
            tracing::warn!(
                connection = %connection.name,
                "the broker reports different mint parameters than this app \
                 pinned for the connection; refusing to mint. Delete and \
                 re-add the connection to accept the change."
            );
            continue;
        }
        let session = match crate::cloud::mint_aws_profile_session(
            &http,
            &connection.name,
            &params.profile,
            params.region.as_deref(),
            params.role_arn.as_deref(),
            params.external_id.as_deref(),
            params.session_policy_arn.as_deref(),
            params.session_policy.as_deref(),
            ttl,
            // The broker attributes the eventual agent call; this names who
            // minted it, which is this app on this machine.
            "multitool-app",
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                tracing::debug!(
                    connection = %connection.name,
                    "could not mint a session to push: {error}"
                );
                continue;
            }
        };
        let expires_at = DateTime::parse_from_rfc3339(&session.expires_at)
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let push = aka_api::CloudSessionPushDto {
            connection_id: connection.id.clone(),
            expires_at: session.expires_at.clone(),
            expires_in_seconds: session.expires_in_seconds,
            provider: session.provider.clone(),
            env: session.env.clone(),
            credentials: session.credentials.clone(),
        };
        match backend.push_cloud_session(push).await {
            // Renewal is measured against the lifetime STS actually granted,
            // not the one requested: recording the request would skew the
            // half-life whenever the two diverge.
            Ok(()) => clock.record(
                &connection.id,
                expires_at,
                session.expires_in_seconds as i64,
            ),
            Err(error) => tracing::debug!(
                connection = %connection.name,
                "could not push a session: {error}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(policy_arn: Option<&str>) -> LeashParams {
        LeashParams {
            profile: "acme-dev".into(),
            region: Some("us-west-2".into()),
            role_arn: None,
            external_id: None,
            session_policy_arn: policy_arn.map(str::to_string),
            session_policy: None,
            session_ttl_secs: 900,
        }
    }

    #[test]
    fn pins_are_first_sight_then_exact_match() {
        let pins = LeashPins::in_memory();
        let read_only = params(Some("arn:aws:iam::aws:policy/ReadOnlyAccess"));
        // First sight pins and mints.
        assert!(pins.check_and_pin("conn-1", &read_only));
        // Unchanged parameters keep minting.
        assert!(pins.check_and_pin("conn-1", &read_only));
        // A stripped leash — the widening a hostile broker would report —
        // is refused, and does not overwrite the pin.
        assert!(!pins.check_and_pin("conn-1", &params(None)));
        assert!(pins.check_and_pin("conn-1", &read_only));
        // Deleting the connection forgets the pin; a re-add pins afresh.
        pins.forget("conn-1");
        assert!(pins.check_and_pin("conn-1", &params(None)));
    }

    #[test]
    fn pins_persist_across_loads() {
        let dir = std::env::temp_dir().join(format!("aka-leash-pins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pins.json");
        let read_only = params(Some("arn:aws:iam::aws:policy/ReadOnlyAccess"));
        {
            let pins = LeashPins::load(path.clone());
            pins.pin("conn-1", read_only.clone());
        }
        {
            let pins = LeashPins::load(path.clone());
            assert!(!pins.check_and_pin("conn-1", &params(None)));
            assert!(pins.check_and_pin("conn-1", &read_only));
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
