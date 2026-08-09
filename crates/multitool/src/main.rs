//! `aka` CLI.
//!
//! - `aka setup skill` emits the `/instructions` content as a checked-in
//!   skill file, the same content the daemon serves, so the convention
//!   layer can't drift from the daemon.
//! - `aka serve` runs a headless broker under its own root (default
//!   `~/.akaserver`, overridable with `--root` or `AKA_SERVER_ROOT`) so it
//!   never shares the desktop app's production store. Its TCP control plane
//!   defaults to loopback; `--no-listen` leaves only the Unix socket.
//! - `aka secret add|list|rename|replace|rm` and
//!   `aka conn add|list|show|update|rename|rm|enable|disable|test` manage the
//!   store from the terminal — the dev/headless counterpart of the app's
//!   Secrets and Tools tabs — with the same validation, so a `serve --root`
//!   harness never hand-writes (sealed) store files. Mutations beyond
//!   seeding run through the broker's own `ui_*` layer, so audit entries
//!   and access/endpoint side effects cannot drift from the app.
//! - `aka sessions`, `aka approvals`, and `aka admin settings` expose the remaining
//!   day-to-day broker visibility and lifecycle controls without requiring
//!   the desktop UI. The request command can hold a leased headless inbox and
//!   answer approvals or elicitations.
//! - `aka run` / `aka env` open data-plane sessions on a running broker.
//!   A trailing `-- <command...>` scopes the resulting PG/cloud environment
//!   or SSH agent to a child process; the printable compatibility forms keep
//!   tickets out of argv and machine-capturable values on stdout.
//! - `aka admin` / `aka status` / `aka activity` are the operator's view:
//!   the shared agent key (and its rotation), whether a broker is up and
//!   what it serves, and the audit trail.
//! - Management commands work online too: against the running local
//!   broker over its socket, or a hosted broker via `--broker <url>` —
//!   both through the manage API, authorized by the management token
//!   (`aka admin login` stores it). With no broker running they fall
//!   back to the offline construction above.

use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aka_api::{ActivityDto, ConnectionDto, ManageError, SecretDto};
use aka_client::credentials::TokenStore;
use aka_client::{RemoteBackend, RemoteConfig};
use aka_core::broker::Broker;
use aka_core::config::BrokerConfig;
use aka_core::daemon;
use aka_core::daemon::wellknown;
use aka_core::error::CoreError;
use aka_core::events::BrokerEvents;
use aka_core::manage::{
    activity_dto, ConnectionConfigPatch, LocalBackend, ManageResult, ManagementBackend,
};
use aka_core::paths::{BrokerInstanceLock, BrokerLockAttempt, BrokerLockRole, Paths};
use aka_core::store::ConnectionSpec;
use aka_core::types::{ConnectionConfig, PgSslMode, SecretValue, SignerSpec};
use aka_core::vault::{
    platform_vault, platform_vault_for_root, recorded_platform_vault_backend,
    selected_platform_vault_backend, PlatformVaultBackend, SecretVault,
};
use clap::builder::styling::{AnsiColor, Styles};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use uuid::Uuid;
use zeroize::Zeroizing;

mod client;
mod mcp_bridge;
mod presentation;
mod ssh_agent;

fn parse_client_label(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(value.to_string())
    } else {
        Err("must be 1-64 ASCII letters, digits, dots, underscores, or hyphens".into())
    }
}

fn parse_manage_ttl_days(value: &str) -> Result<u64, String> {
    let days: u64 = value
        .parse()
        .map_err(|_| "must be a whole number of days".to_string())?;
    if (1..=3650).contains(&days) {
        Ok(days)
    } else {
        Err("must be between 1 and 3650 days".to_string())
    }
}

const DEFAULT_MANAGE_TOKEN_TTL_DAYS: u64 = 30;

/// Env override for `aka serve`'s default root when `--root` is omitted.
const SERVER_ROOT_ENV: &str = "AKA_SERVER_ROOT";

/// A remote broker's shared agent key, for CI and other places that hand
/// credentials in rather than persisting them.
const AGENT_KEY_ENV: &str = "AKA_AGENT_KEY";

/// Clap help/error colors, matched to the `aka serve` banner palette:
/// green headings, cyan syntax, yellow invalid, red errors.
const CLI_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().bold())
    .valid(AnsiColor::Green.on_default().bold())
    .invalid(AnsiColor::Yellow.on_default().bold());

fn parse_positive_seconds(value: &str) -> Result<u64, String> {
    let secs: u64 = value
        .parse()
        .map_err(|_| "must be a whole number of seconds".to_string())?;
    if secs == 0 {
        Err("must be at least 1 second".to_string())
    } else {
        Ok(secs)
    }
}

fn parse_public_url(value: &str) -> Result<String, String> {
    RemoteConfig::normalize_url(value)
}

fn parse_field_value(value: &str) -> Result<String, String> {
    let Some((name, _)) = value.split_once('=') else {
        return Err("must be NAME=VALUE".into());
    };
    if name.trim().is_empty() {
        return Err("field name must not be empty".into());
    }
    Ok(value.to_string())
}

#[derive(Parser)]
#[command(
    name = "aka",
    version,
    about = "Agent access for APIs, MCPs, databases, and servers",
    styles = CLI_STYLES
)]
struct Cli {
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct SkillArgs {
    /// Write the file to `path` (default .claude/skills/multitool/SKILL.md)
    /// instead of printing to stdout.
    #[arg(long)]
    write: bool,
    /// Override the output path used with --write.
    #[arg(long, conflicts_with = "user", requires = "write")]
    path: Option<PathBuf>,
    /// With --write, target the user-level skills directory
    /// (~/.claude/skills/multitool/SKILL.md) instead of the repo-local
    /// default, so every project's agents see it.
    #[arg(long, requires = "write")]
    user: bool,
    /// Overwrite a non-Multitool skill file. Generated Multitool skill
    /// files can be refreshed without this flag.
    #[arg(long, requires = "write")]
    force: bool,
    /// Render the document for a broker rooted here (`serve --root`)
    /// instead of the production layout, so a dev harness's skill file
    /// names the socket it actually serves.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Fetch setup from this hosted broker instead of rendering local
    /// defaults. Requires its current management token.
    #[arg(long)]
    broker: Option<String>,
}

#[derive(Args)]
struct InstructionsArgs {
    /// Render for a broker rooted here instead of the production layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Fetch this hosted broker's authoritative agent setup instead of
    /// rendering local defaults. Requires its management token.
    #[arg(long)]
    broker: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum McpSetupClient {
    /// Codex config.toml.
    Codex,
    /// Claude Code's `claude mcp add` command.
    ClaudeCode,
    /// Claude Desktop's JSON configuration.
    ClaudeDesktop,
}

impl McpSetupClient {
    fn label(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::ClaudeDesktop => "claude-desktop",
        }
    }
}

#[derive(Subcommand)]
enum SetupCommand {
    /// Write or print the agent skill file.
    ///
    /// With --broker, fetches that broker's authoritative setup. Prints to
    /// stdout by default; `--write` writes .claude/skills/multitool/SKILL.md.
    Skill(SkillArgs),
    /// Print agent setup markdown (/instructions).
    ///
    /// Local defaults by default; with --broker, fetches that hosted broker's
    /// authoritative agent setup (requires its management token).
    Instructions(InstructionsArgs),
    /// Connect the desktop app to a headless broker.
    ///
    /// The app's "Local Multitool" runs its own broker; it reaches a broker
    /// started with `aka serve` only as a hosted instance. This prints the
    /// URL and, when one already exists, the management token the app's
    /// connect form needs. It never mints a token: the broker keeps exactly
    /// one, so issuing would disconnect whoever holds the current one.
    Desktop {
        /// Describe the broker rooted here instead of the serve default
        /// (AKA_SERVER_ROOT or ~/.akaserver).
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one short-lived instance per invocation
enum Command {
    /// Connect an agent, MCP client, or the desktop app.
    ///
    /// `aka setup <client>` prints the paste-ready configuration for that
    /// MCP client (codex, claude-code, claude-desktop) and points at the
    /// agent skill. Nothing is written without an explicit subcommand flag
    /// (`aka setup skill --write`).
    #[command(args_conflicts_with_subcommands = true)]
    Setup {
        #[command(subcommand)]
        command: Option<SetupCommand>,
        /// The MCP client to print configuration for.
        #[arg(value_enum)]
        client: Option<McpSetupClient>,
        /// Apply the configuration instead of printing it: register the MCP
        /// server with the client, write the repo-local agent skill, and pin
        /// this directory to the current context when one is set.
        #[arg(long, requires = "client")]
        write: bool,
    },
    /// Write or print the agent skill file.
    ///
    /// With --broker, fetches that broker's authoritative setup. Prints to
    /// stdout by default; `--write` writes .claude/skills/multitool/SKILL.md.
    #[command(hide = true)]
    Skill(SkillArgs),
    /// Print shell completions.
    ///
    /// `aka completions zsh > "${fpath[1]}/_aka"`, or source it from your
    /// shell's rc file. The script is generated from this CLI's own command
    /// tree, so it cannot drift from the commands it completes.
    Completions {
        /// The shell to generate for.
        shell: clap_complete::Shell,
    },
    /// Print agent setup markdown (/instructions).
    ///
    /// Local defaults by default; with --broker, fetches that hosted broker's
    /// authoritative agent setup (requires its management token).
    #[command(hide = true)]
    Instructions(InstructionsArgs),
    /// Run a headless broker.
    ///
    /// Uses its own root (not the desktop app store). Default root is
    /// `~/.akaserver` (data + socket under it). Override with `--root` or
    /// `AKA_SERVER_ROOT` (`--root` wins). The Multitool desktop app keeps
    /// using the production layout (`~/.aka`); agents against this process
    /// need this root's token or the shared agent key over its TCP listener.
    Serve {
        /// Broker root (data + socket under it). Overrides `AKA_SERVER_ROOT`
        /// and the default `~/.akaserver`.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Serve the control plane on this TCP address for agents and the
        /// remote desktop app (default 127.0.0.1:4780). Put your TLS proxy
        /// or tunnel in front of non-loopback listeners; /v1/pair is not
        /// served over TCP.
        #[arg(long, conflicts_with = "no_listen")]
        listen: Option<std::net::SocketAddr>,
        /// Disable the default TCP listener and public URL. The broker still
        /// serves local clients over its Unix socket.
        #[arg(long, conflicts_with_all = ["listen", "public_url", "web_root"])]
        no_listen: bool,
        /// The URL remote clients reach this broker at (your proxy or
        /// tunnel address); advertised in discovery served over TCP. Defaults
        /// to http://localhost:4780 with the default listener. Any loopback
        /// --listen derives the matching localhost URL, which works with
        /// passkeys; IP-literal public URLs do not.
        #[arg(long, conflicts_with = "no_listen", value_parser = parse_public_url)]
        public_url: Option<String>,
        /// Serve the Multitool web app from this directory (the `dist/ui`
        /// a UI build produces). It rides the same listener as the manage
        /// API on purpose: the session cookie, the passkey's relying
        /// party, and the CSRF check are all same-origin.
        #[arg(long, conflicts_with = "no_listen")]
        web_root: Option<PathBuf>,
        /// Bind the PG data plane and API direct endpoints to this
        /// address (e.g. 0.0.0.0 or a LAN IP) for remote agents, instead of
        /// loopback. These legs are plaintext, so a non-loopback value is
        /// refused unless --data-plane-insecure says you accept that; keep it
        /// on a trusted network behind your TLS/tunnel.
        #[arg(long)]
        data_plane_listen: Option<std::net::IpAddr>,
        /// The host to put in returned DSNs and endpoint URLs — what a remote
        /// agent dials (defaults to 127.0.0.1). Usually your broker host's
        /// LAN name or the tunnel address.
        #[arg(long)]
        advertise_host: Option<String>,
        /// Accept that a non-loopback --data-plane-listen puts the Postgres
        /// ticket, statements, and results on the network in clear text. The
        /// bind is refused without this.
        #[arg(long, requires = "data_plane_listen")]
        data_plane_insecure: bool,
        /// Tear a brokered session down after this many seconds with the
        /// backend idle and the client silent (default 300). Raise it for
        /// LISTEN/NOTIFY workloads, which are protocol-idle while waiting.
        #[arg(long, value_name = "SECS", value_parser = parse_positive_seconds)]
        session_idle_timeout: Option<u64>,
        /// Hard ceiling on one brokered session, in seconds (default 3600).
        /// Raise it for long COPY/pg_dump runs, which are severed mid-stream
        /// when it expires.
        #[arg(long, value_name = "SECS", value_parser = parse_positive_seconds)]
        session_max_ttl: Option<u64>,
        /// Record the SQL of each statement on a brokered Postgres session in
        /// the activity log. Off by default: statement text can carry
        /// credentials and personal data into a durable log.
        #[arg(long)]
        audit_pg_statements: bool,
        /// Do not start the MCP host.
        #[arg(long, alias = "no-sidecar")]
        no_mcp: bool,
    },
    /// Run the MCP stdio bridge (normally launched by a configured client).
    ///
    /// Configure clients with `aka setup <client>`. The client then launches
    /// this runtime command, which reads this computer's shared key and
    /// discovers the MCP endpoint itself so configs stay static.
    Mcp {
        /// Bridge to a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Label this client in the user's activity log (e.g. claude-code).
        /// Attribution only, never authorization.
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
    },
    /// Run a command with brokered credentials for a connection.
    ///
    /// One runner for every kind — the connection's kind decides the
    /// dispatch. pg runs the command with the short-lived PG* environment:
    /// `aka run analytics -- psql`. ssh runs the SSH client (ssh, scp, sftp,
    /// git, rsync) with a scoped signing agent and the mandatory broker-safe
    /// options: `aka run production -- ssh production`. cloud mints temporary
    /// credentials into the child's environment. api points AKA_URL and
    /// AKA_TOKEN at the connection's direct endpoint. Credential material
    /// stays out of argv in every form; `aka env` is the no-command variant.
    Run {
        /// The connection's name; its kind decides what the command gets.
        connection: String,
        /// Open against a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Usage commands open sessions on this machine's broker only; this
        /// flag exists to catch the remote guess and explain, never to work.
        #[arg(long, hide = true)]
        broker: Option<String>,
        /// Label this client in the user's activity log (e.g. claude-code).
        /// Attribution only, never authorization.
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
        /// The command to run with the scoped environment; `run` exits with
        /// its status.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Print scoped exports for a connection (run's no-command form).
    ///
    /// pg prints PG* exports with the ticket in PGPASSWORD:
    /// `eval "$(aka env analytics)" && psql`. ssh prints the scoped agent
    /// socket plus the destination, pinned fingerprint, deadline, and
    /// required options. cloud prints temporary credential exports. api
    /// prints AKA_URL and AKA_TOKEN for the connection's direct endpoint.
    /// Prefer `aka run <connection> -- <command>`, which scopes the values to
    /// one child process instead of your shell.
    Env {
        /// The connection's name; its kind decides the exports.
        connection: String,
        /// Open against a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Usage commands open sessions on this machine's broker only; this
        /// flag exists to catch the remote guess and explain, never to work.
        #[arg(long, hide = true)]
        broker: Option<String>,
        /// Label this client in the user's activity log (e.g. claude-code).
        /// Attribution only, never authorization.
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
        /// pg only: `uri` prints a single DSN with the ticket embedded —
        /// visible to anything that can read argv downstream. `env` is the
        /// default export form.
        #[arg(long, value_enum)]
        format: Option<DsnFormat>,
        /// pg only: print only the short-lived ticket, for an explicit
        /// PGPASSWORD assignment. Mutually exclusive with --format.
        #[arg(long, conflicts_with = "format")]
        password_only: bool,
    },
    /// Cloud credential_process plumbing (creds, install).
    ///
    /// Cloud connections hold long-lived AWS/Azure/GCP identity in the vault;
    /// `aka run <connection> -- <command>` is the usual way to use one. These
    /// subcommands integrate with tooling that pulls credentials itself
    /// (credential_process, scripts) and never print the vaulted long-lived
    /// keys. Already-issued sessions cannot be revoked by Multitool — short
    /// TTL is the bound.
    Cloud {
        #[command(subcommand)]
        command: CloudCommand,
    },
    /// Agent socket for auth-required direct endpoints.
    ///
    /// Speaks for a connection's *direct endpoint*, presenting the endpoint
    /// secret the agent protocol gives stock `ssh` no way to send.
    ///
    /// Only needed for an endpoint issued with `--require-auth`: an
    /// unauthenticated endpoint socket can be used directly as
    /// `IdentityAgent`. Every request still reaches the broker and the broker
    /// still asks — this adds the credential, never a decision.
    ///
    /// With a trailing `-- <command…>`, runs that command with SSH_AUTH_SOCK
    /// already pointing at the socket and exits with its status; without one,
    /// prints the socket path and stays in the foreground until interrupted.
    #[command(name = "ssh-agent")]
    SshAgent {
        /// The ssh connection whose endpoint to speak for.
        connection: String,
        /// Use this broker root for local management; with --broker, use its
        /// local management-credential store.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
        /// Bind here instead of a private temporary path, so a
        /// `~/.ssh/config` `IdentityAgent` line can name it. The path outlives
        /// no run: the socket is removed when this command exits.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Run this with SSH_AUTH_SOCK set, then exit with its status.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Add and manage vault secrets.
    ///
    /// Connections reference secrets by name; the value never travels in
    /// argv. The desktop app offers the same management with a UI.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Operator commands, gated by the management token.
    ///
    /// The broker has two credential planes: agents hold the shared agent
    /// key and use connections; admin commands hold the management token
    /// and configure the broker itself (the same plane the desktop app's
    /// remote management uses).
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Add and manage connections.
    ///
    /// The desktop app offers the same management with a UI.
    Conn {
        #[command(subcommand)]
        command: ConnCommand,
    },
    /// List or close live sessions.
    Sessions {
        /// Close this session instead of listing sessions.
        #[arg(long)]
        close: Option<u64>,
        /// Use this broker root for local management; with --broker, use its
        /// local management-credential store.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// The approval inbox: pending and recent approvals/elicitations.
    ///
    /// Lists decision records newest last. Answer a pending id with
    /// `aka approve <id>` or `aka deny <id>`.
    Approvals {
        /// Attach a polling request inbox until Ctrl-C. Answer an id it
        /// prints from another terminal with `aka approve` or `aka deny`.
        #[arg(long)]
        watch: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Approve one pending request for its bounded confirmation window.
    Approve {
        /// The request id (`aka approvals` shows pending ids).
        id: Uuid,
        /// Elicitation answer in NAME=VALUE form; repeat for multiple fields.
        #[arg(
            long = "value",
            value_name = "NAME=VALUE",
            value_parser = parse_field_value
        )]
        values: Vec<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Deny one pending approval or elicitation.
    Deny {
        /// The request id (`aka approvals` shows pending ids).
        id: Uuid,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Join a broker with an invite, storing its context and agent key.
    ///
    /// The operator mints the invite with `aka admin invite`. Paste the URL
    /// it prints — the code rides in the fragment, so joining is one
    /// command — or pass `--invite` (or pipe the code on stdin) with a bare
    /// broker URL. The shared agent key is stored per broker, the context is
    /// defined and made current, and nothing else on this machine changes.
    ///
    /// A local broker needs no login: `local` is the default context.
    Login {
        /// The broker's URL, optionally carrying the invite in its fragment
        /// (`https://broker.example.dev/join#akajoin_…`).
        url: String,
        /// The one-use invite code, when the URL does not carry it.
        #[arg(long)]
        invite: Option<String>,
        /// Name this context (default: the URL's host, up to the first dot).
        #[arg(long)]
        name: Option<String>,
        /// Label this client in the broker's activity log.
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
    },
    /// Forget a broker's stored context and agent key.
    Logout {
        /// The context or broker URL to forget; omit for the current one.
        name: Option<String>,
    },
    /// Show or switch the ambient broker context.
    ///
    /// Contexts decide where commands point when --root/--broker are absent:
    /// `local` (the desktop layout) and `server` (the serve root) are built
    /// in; defined names add a headless root or a hosted broker URL. The
    /// full chain is --root/--broker → AKA_BROKER (name or URL) → a repo
    /// `.aka` pin → the `aka use` default → local.
    Use {
        /// The context to make current: local, server, or a defined name.
        name: Option<String>,
        /// Define <name> as a hosted broker at this manage URL, then make it
        /// current.
        #[arg(long, requires = "name", conflicts_with_all = ["root", "pin", "rm", "unset"])]
        broker: Option<String>,
        /// Define <name> as a broker rooted at this path, then make it
        /// current.
        #[arg(long, requires = "name", conflicts_with_all = ["pin", "rm", "unset"])]
        root: Option<PathBuf>,
        /// Pin the working directory to <name> instead of switching: writes
        /// `./.aka`, which agents and teammates inherit through the chain.
        #[arg(long, requires = "name", conflicts_with_all = ["rm", "unset"])]
        pin: bool,
        /// Remove a defined context.
        #[arg(long, requires = "name", conflicts_with = "unset")]
        rm: bool,
        /// Clear the current context; commands fall back to local.
        #[arg(long, conflicts_with = "name")]
        unset: bool,
    },
    /// List connections with kind, access, and destination at a glance.
    Ls {
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Print, issue/rotate, renew, or revoke a connection's direct endpoint.
    ///
    /// Issuance requires a running local or remote broker to own the
    /// listener; reads and revocation also work as offline edits.
    Endpoint(EndpointArgs),
    /// Broker health and surface.
    ///
    /// Reports whether a broker is running on this layout and what it serves
    /// (MCP host, tools, key file). Exits nonzero when none is up.
    Status {
        /// Check a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Audit trail (newest last).
    ///
    /// Local reads project the append-only log onto the same schema returned
    /// by a remote broker.
    Activity {
        /// Show only the last N entries; 0 shows everything.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Read a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Add a secret. The value is read from stdin (or --value-env), never
    /// from argv, where it would sit in `ps` output and shell history.
    Add {
        /// Secret name, as referenced by connection templates.
        name: String,
        /// Read the value from this environment variable instead of stdin.
        #[arg(long, value_name = "VAR")]
        value_env: Option<String>,
        /// Preserve the input byte-for-byte. By default one trailing CRLF,
        /// LF, or CR (commonly added by echo or a heredoc) is removed.
        #[arg(long)]
        raw: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Create a missing explicit --root before seeding this first secret.
        #[arg(long, requires = "root")]
        create_root: bool,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// List secrets and the connections using them.
    List {
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Rename a secret; every injection template referencing it is
    /// rewritten atomically with the rename.
    Rename {
        /// The secret's current name.
        name: String,
        /// The new name.
        new_name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Rotate a secret's value in place. Like add, the value is read
    /// from stdin or --value-env, never from argv; every connection
    /// referencing the secret picks the new value up on its next use.
    Rotate {
        /// The secret to rotate.
        name: String,
        /// Read the value from this environment variable instead of stdin.
        #[arg(long, value_name = "VAR")]
        value_env: Option<String>,
        /// Preserve the input byte-for-byte. By default one trailing CRLF,
        /// LF, or CR (commonly added by echo or a heredoc) is removed.
        #[arg(long)]
        raw: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Delete a secret. Refused while a connection still uses it.
    Rm {
        /// The secret to delete.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Mint a one-use invite a teammate redeems with `aka login`.
    ///
    /// The invite is what makes handing out the shared agent key safe over
    /// the network: `/v1/pair` stays closed on TCP, and `/v1/join` accepts
    /// only a code an operator minted here. It expires in 15 minutes and is
    /// spent by the first redemption. What it hands back is the same shared
    /// key every agent holds, so it grants no identity of its own.
    ///
    /// Runs against this machine's broker over its own socket, never over
    /// the network: minting it decides who may use this broker's
    /// connections, so it takes local access to the host.
    Invite {
        /// Label this invite in the activity log (e.g. a teammate's name).
        /// Attribution only, never authorization.
        #[arg(long)]
        label: Option<String>,
        /// List outstanding invites instead of minting one.
        #[arg(long, conflicts_with_all = ["label", "cancel"])]
        list: bool,
        /// Void every outstanding invite.
        #[arg(long, conflicts_with = "label")]
        cancel: bool,
        /// Operate on a broker rooted here instead of the serve default.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Show or rotate the shared agent key.
    ///
    /// Agents send this as their Bearer token; remote agents need it from
    /// the operator. Rotation is the broad revocation lever: outstanding
    /// tickets and direct endpoints are revoked and broker-owned sessions
    /// close, for every agent at once.
    #[command(name = "agent-key")]
    AgentKey {
        /// Rotate the key instead: agents' old keys stop working, and
        /// agents that read the token file reconnect on their own.
        /// Offline: stop the broker first.
        #[arg(long)]
        rotate: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Read or update broker settings.
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    /// Store a management token so management commands can drive a broker
    /// while it runs — this machine's broker over its socket, or a hosted
    /// one by URL. The token is read from stdin (or --token-env), never
    /// argv, and is verified against the broker when it is reachable.
    Login {
        /// The hosted broker's manage URL; omit to store the token for
        /// this machine's broker (keyed by its socket path).
        #[arg(long)]
        broker: Option<String>,
        /// Read the token from this environment variable instead of stdin.
        /// For CI, prefer AKA_MANAGE_TOKEN so the token is not persisted.
        #[arg(long, value_name = "VAR")]
        token_env: Option<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Forget a stored management token.
    Logout {
        /// The hosted broker's manage URL; omit for this machine's broker.
        #[arg(long)]
        broker: Option<String>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Rotate this broker's management token and print it once. When the
    /// broker is running, authorizes with the current saved/environment
    /// token or its owner-only first-start token file. Falls back to an
    /// offline issue when the local broker is stopped.
    Token {
        /// Revoke the management token instead (closes the manage API).
        #[arg(long)]
        revoke: bool,
        /// Expire the token this many days after issue (default 30, maximum
        /// 3650). The desktop app re-prompts for a fresh one when it expires.
        #[arg(
            long,
            default_value = "30",
            value_parser = parse_manage_ttl_days
        )]
        ttl_days: Option<u64>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Rotate a hosted broker through its manage API.
        #[arg(long, conflicts_with = "create_root")]
        broker: Option<String>,
        /// Create a missing explicit --root before issuing its first token.
        #[arg(long, requires = "root", conflicts_with = "broker")]
        create_root: bool,
    },
    /// Retire the global management token, or bring it back.
    ///
    /// The last step of the passkey migration: after this, the manage plane
    /// accepts only passkey sessions, device grants, and automation tokens.
    /// Refused while no passkey is enrolled — that would leave nothing able
    /// to sign in.
    #[command(hide = true)]
    Legacy {
        /// Accept the management token again.
        #[arg(long, conflicts_with = "retire")]
        restore: bool,
        /// Stop accepting the management token.
        #[arg(long)]
        retire: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Open passkey enrollment and print the one-use secret.
    ///
    /// Runs against this machine's broker over its own socket, never over
    /// the network: being able to open enrollment is what decides who owns
    /// the broker, so it takes local access to the host rather than a
    /// credential anyone could carry. Hand the printed link to the browser
    /// you want to enroll; it expires in 15 minutes.
    Enroll {
        /// Close an outstanding enrollment instead of opening one.
        #[arg(long)]
        cancel: bool,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SettingsCommand {
    /// Print the broker's effective settings.
    Get {
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Change one or more broker settings.
    Set {
        /// Hide the Dock icon while the menu-bar window is active.
        #[arg(long)]
        menu_bar_hides_dock: Option<bool>,
        /// Ask before trusting an SSH server's host key the first time it is
        /// seen, instead of pinning it silently. Needs an attached approval
        /// surface: with none, the first login to an unpinned server is
        /// refused rather than trusted.
        #[arg(long)]
        confirm_ssh_host_keys: Option<bool>,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one short-lived instance per invocation
enum ConnCommand {
    /// Add a connection agents can name on capability calls.
    Add {
        #[command(subcommand)]
        command: ConnAddCommand,
    },
    /// List configured connections.
    List {
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Show one connection's policy, endpoint, health, and capability fields.
    Show {
        name: String,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        broker: Option<String>,
    },
    /// Update fields on a connection (its kind is fixed). Only the flags
    /// you pass change; changing the destination revokes the tool's direct
    /// endpoints, exactly as in the app.
    ///
    /// Capability fields are kind-scoped: `aka conn update pg <name> --host …`.
    /// Policy is kind-free: `aka conn update <name> --confirm`.
    #[command(args_conflicts_with_subcommands = true)]
    Update {
        #[command(subcommand)]
        command: Option<ConnUpdateCommand>,
        #[command(flatten)]
        policy: ConnPolicyArgs,
    },
    /// Rename a connection without touching its capability fields.
    Rename {
        /// The connection's current name.
        name: String,
        /// The new name.
        new_name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Delete a connection. Its agent access and direct endpoints die with
    /// it; its secrets stay in the vault.
    Rm {
        /// The connection to delete.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Enable agent access for a connection: calls execute immediately,
    /// for every agent at once.
    Enable {
        /// The connection to enable.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Disable agent access for a connection: every agent's calls are
    /// refused with 403 denied_by_policy until re-enabled.
    Disable {
        /// The connection to disable.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
    /// Test a connection against its pinned destination with its stored
    /// credential (the credential travels only on the upstream leg).
    /// Exits nonzero when the test fails.
    Test {
        /// The connection to test.
        name: String,
        /// Operate on a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Manage the broker at this manage-API URL instead of this
        /// machine's.
        #[arg(long)]
        broker: Option<String>,
    },
}

#[derive(Args)]
struct EndpointArgs {
    /// The connection whose endpoint to print.
    name: String,
    /// Issue a new endpoint, or rotate the existing endpoint's secret.
    /// The broker must be running so it can own the endpoint listener.
    #[arg(long, conflicts_with = "revoke")]
    issue: bool,
    /// Extend the existing endpoint for 30 days without changing its
    /// address or secret. The broker must be running.
    #[arg(long, conflicts_with_all = ["issue", "revoke"])]
    renew: bool,
    /// Revoke this connection's issued endpoint. Unlike issuance, this
    /// can be performed as an offline edit while the broker is stopped.
    #[arg(long, conflicts_with_all = ["issue", "renew", "url", "secret"])]
    revoke: bool,
    /// ssh: make the agent socket refuse to list or sign until the caller
    /// presents the endpoint secret, so finding the socket is no longer
    /// enough to use it. Stock `ssh` cannot send the extension that does
    /// this — reach an authenticated endpoint through `aka ssh-agent`.
    #[arg(long, conflicts_with_all = ["revoke", "no_require_auth"])]
    require_auth: bool,
    /// ssh: stop requiring authentication on the agent socket, returning
    /// it to "whoever can open it can sign". Takes a fresh confirmation.
    #[arg(long, conflicts_with = "revoke")]
    no_require_auth: bool,
    /// Print only the pasteable address (the base URL / DSN / agent
    /// socket), for `$(aka endpoint <name> --url)`.
    #[arg(long, conflicts_with = "secret")]
    url: bool,
    /// Print only the endpoint secret (empty for SSH, whose socket path
    /// is the whole capability), for scripting.
    #[arg(long)]
    secret: bool,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Manage the broker at this manage-API URL instead of this machine's.
    #[arg(long)]
    broker: Option<String>,
}

/// The kind-free half of `conn update`: per-connection policy, applying to
/// any kind by name. Capability fields stay on the kind-scoped subcommands
/// so each form shows only relevant flags.
#[derive(Args)]
struct ConnPolicyArgs {
    /// The connection whose policy to change.
    name: Option<String>,
    /// Ask the user to confirm this connection's traffic before it goes
    /// anywhere. What gets confirmed depends on the kind: one request for an
    /// API tool, one `tools/call` for an MCP tool, one session for Postgres.
    /// An attached Multitool app answers prompts; a broker with no attached
    /// approval surface refuses the traffic.
    #[arg(long, conflicts_with = "no_confirm")]
    confirm: bool,
    /// Stop confirming this connection's traffic.
    #[arg(long)]
    no_confirm: bool,
    /// api: `allow` credential-bearing upstream response headers to reach
    /// agents (the default), or `contain` them at the broker boundary.
    #[arg(long, value_enum, value_name = "MODE")]
    response_credentials: Option<ResponseCredentialsMode>,
    /// pg: record this connection's statement SQL in the activity log (`on`),
    /// stop (`off`), or follow the broker-wide default (`default`). Statement
    /// text can carry credentials and personal data into a durable log.
    #[arg(long, value_enum, value_name = "MODE")]
    audit_statements: Option<AuditStatementsMode>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Manage the broker at this manage-API URL instead of this machine's.
    #[arg(long)]
    broker: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
enum ResponseCredentialsMode {
    /// Return credential-bearing upstream response headers to agents.
    Allow,
    /// Strip credential-bearing headers at the broker boundary.
    Contain,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
enum AuditStatementsMode {
    /// Record statement text for this connection.
    On,
    /// Stop recording statement text for this connection.
    Off,
    /// Drop the override and follow the broker-wide default.
    Default,
}

#[derive(Args)]
struct ManagementTarget {
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Manage the broker at this manage-API URL instead of this machine's.
    #[arg(long)]
    broker: Option<String>,
}

#[derive(Args)]
struct CreateTarget {
    #[command(flatten)]
    management: ManagementTarget,
    /// Create a missing explicit --root before seeding this first connection.
    #[arg(long, requires = "root")]
    create_root: bool,
    /// Skip the test that otherwise runs against the pinned destination as
    /// soon as the connection is added. Use it when the destination is not
    /// reachable yet, or when the connection asks for confirmation and no
    /// approval surface is attached.
    #[arg(long)]
    no_test: bool,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // one short-lived instance per invocation
enum ConnAddCommand {
    /// Add an HTTP API or streamable-HTTP MCP connection.
    #[command(after_help = "EXAMPLES
 aka secret add GITHUB_TOKEN < token.txt
 aka conn add api github --host api.github.com --template 'Authorization: Bearer {{GITHUB_TOKEN}}' --test-path /user
 aka conn test github")]
    Api(ConnAddApi),
    /// Add a Postgres connection.
    #[command(after_help = "EXAMPLES
 aka secret add DB_PASSWORD < password.txt
 aka conn add pg analytics --host db.internal --dbname app --user readonly --secret DB_PASSWORD
 aka conn test analytics
 aka run analytics -- psql")]
    Pg(ConnAddPg),
    /// Add an SSH connection.
    #[command(after_help = "EXAMPLES
 aka secret add DEPLOY_KEY < id_ed25519
 aka conn add ssh staging --host staging.internal --user deploy --secret DEPLOY_KEY
 aka conn test staging
 aka run staging -- ssh staging")]
    Ssh(ConnAddSsh),
    /// Add an AWS, Azure, or GCP connection.
    Cloud {
        #[command(subcommand)]
        provider: ConnAddCloudCommand,
    },
}

#[derive(Subcommand)]
enum ConnAddCloudCommand {
    /// Add an AWS connection.
    #[command(after_help = "EXAMPLES
 aka secret add AWS_ACCESS_KEY_ID < key-id.txt
 aka secret add AWS_SECRET_ACCESS_KEY < secret-key.txt
 aka conn add cloud aws deploy --region us-east-1 --access-key-ref AWS_ACCESS_KEY_ID --secret-key-ref AWS_SECRET_ACCESS_KEY
 aka conn test deploy
 aka run deploy -- aws sts get-caller-identity")]
    Aws(ConnAddAws),
    /// Add an Azure connection.
    #[command(after_help = "EXAMPLES
 aka secret add AZURE_CLIENT_SECRET < client-secret.txt
 aka conn add cloud azure infra --tenant-id contoso.example --client-id <app-id> --client-secret-ref AZURE_CLIENT_SECRET
 aka conn test infra
 aka env infra")]
    Azure(ConnAddAzure),
    /// Add a GCP connection.
    #[command(after_help = "EXAMPLES
 aka secret add GCP_SA_KEY < service-account.json
 aka conn add cloud gcp analytics --key-ref GCP_SA_KEY --scope https://www.googleapis.com/auth/cloud-platform
 aka conn test analytics
 aka run analytics -- gcloud storage ls")]
    Gcp(ConnAddGcp),
}

#[derive(Args)]
struct ConnAddApi {
    /// Connection name, what agents name on capability calls.
    name: String,
    /// Upstream host (bare hostname, no scheme/port/path).
    #[arg(long)]
    host: String,
    /// "https" (the default) or "http" (dev/test upstreams).
    #[arg(long)]
    scheme: Option<String>,
    /// Upstream port (defaults to the scheme's port).
    #[arg(long)]
    port: Option<u16>,
    /// Injection template, e.g. 'Authorization: Bearer {{KEY}}'.
    #[arg(long)]
    template: Option<String>,
    /// Optional PEM bundle for a private certificate authority.
    #[arg(long)]
    ca_bundle: Option<String>,
    /// Expose this connection as an MCP server at this JSON-RPC path.
    #[arg(long)]
    mcp_path: Option<String>,
    /// Path fetched by `conn test` (e.g. `/user`).
    #[arg(long)]
    test_path: Option<String>,
    /// Sign requests with AWS SigV4 for this region instead of a template.
    #[arg(long)]
    sigv4_region: Option<String>,
    /// AWS SigV4 service name (e.g. s3, execute-api, bedrock).
    #[arg(long, requires = "sigv4_region")]
    sigv4_service: Option<String>,
    /// Vault secret holding the AWS access key ID.
    #[arg(long, requires = "sigv4_region")]
    sigv4_access_key_ref: Option<String>,
    /// Vault secret holding the AWS secret access key.
    #[arg(long, requires = "sigv4_region")]
    sigv4_secret_key_ref: Option<String>,
    /// Vault secret holding a temporary AWS session token.
    #[arg(long, requires = "sigv4_region")]
    sigv4_session_token_ref: Option<String>,
    /// Vault secret holding a GCP service-account JSON key.
    #[arg(long, conflicts_with = "sigv4_region")]
    gcp_key_ref: Option<String>,
    /// Space-separated scopes for GCP access tokens.
    #[arg(long, requires = "gcp_key_ref")]
    gcp_scope: Option<String>,
    /// PEM client-certificate chain for upstream mTLS.
    #[arg(long, requires = "client_key")]
    client_cert: Option<String>,
    /// PEM private key for --client-cert.
    #[arg(long, requires = "client_cert")]
    client_key: Option<String>,
    #[command(flatten)]
    target: CreateTarget,
}

#[derive(Args)]
struct ConnAddPg {
    /// Connection name, what agents name on capability calls.
    name: String,
    /// Upstream Postgres host.
    #[arg(long)]
    host: String,
    /// Database name.
    #[arg(long)]
    dbname: String,
    /// Login user.
    #[arg(long)]
    user: String,
    /// Vault secret holding the password.
    #[arg(long)]
    secret: String,
    /// Upstream port (default 5432).
    #[arg(long)]
    port: Option<u16>,
    /// disable | prefer | require | verify-ca | verify-full.
    #[arg(long)]
    sslmode: Option<String>,
    /// Optional PEM bundle for a private certificate authority.
    #[arg(long)]
    ca_bundle: Option<String>,
    #[command(flatten)]
    target: CreateTarget,
}

#[derive(Args)]
struct ConnAddSsh {
    /// Connection name, what agents name on capability calls.
    name: String,
    /// Upstream SSH host.
    #[arg(long)]
    host: String,
    /// Login user.
    #[arg(long)]
    user: String,
    /// Vault secret holding the private key.
    #[arg(long)]
    secret: String,
    /// Upstream port (default 22).
    #[arg(long)]
    port: Option<u16>,
    /// Pinned server host key fingerprint. Omit to trust on first use.
    #[arg(long)]
    host_key_fingerprint: Option<String>,
    #[command(flatten)]
    target: CreateTarget,
}

#[derive(Args)]
struct ConnAddAws {
    /// Connection name, what agents name on capability calls.
    name: String,
    /// Default AWS region (e.g. us-east-1).
    #[arg(long)]
    region: String,
    /// Vault secret holding the access key ID.
    #[arg(long)]
    access_key_ref: String,
    /// Vault secret holding the secret access key.
    #[arg(long)]
    secret_key_ref: String,
    /// Vault secret holding an optional session token.
    #[arg(long, requires = "role_arn")]
    session_token_ref: Option<String>,
    /// Assume this role instead of calling GetSessionToken.
    #[arg(long)]
    role_arn: Option<String>,
    /// Optional ExternalId for AssumeRole.
    #[arg(long)]
    external_id: Option<String>,
    /// Requested session TTL in seconds (900–3600, default 900).
    #[arg(long)]
    session_ttl: Option<u64>,
    #[command(flatten)]
    target: CreateTarget,
}

#[derive(Args)]
struct ConnAddAzure {
    /// Connection name, what agents name on capability calls.
    name: String,
    /// Entra tenant ID (GUID or domain).
    #[arg(long)]
    tenant_id: String,
    /// Application (client) ID.
    #[arg(long)]
    client_id: String,
    /// Vault secret holding the client secret.
    #[arg(long)]
    client_secret_ref: String,
    /// Optional default subscription ID.
    #[arg(long)]
    subscription_id: Option<String>,
    /// OAuth scope (default https://management.azure.com/.default).
    #[arg(long)]
    scope: Option<String>,
    /// Requested session TTL in seconds (informational for Azure).
    #[arg(long)]
    session_ttl: Option<u64>,
    #[command(flatten)]
    target: CreateTarget,
}

#[derive(Args)]
struct ConnAddGcp {
    /// Connection name, what agents name on capability calls.
    name: String,
    /// Vault secret holding the service-account JSON key.
    #[arg(long)]
    key_ref: String,
    /// OAuth scope.
    #[arg(long)]
    scope: String,
    /// Optional default project ID.
    #[arg(long)]
    project: Option<String>,
    /// Requested session TTL in seconds (informational for GCP).
    #[arg(long)]
    session_ttl: Option<u64>,
    #[command(flatten)]
    target: CreateTarget,
}

#[derive(Args)]
struct ConnAdd {
    /// Connection name, what agents name on capability calls.
    name: String,
    #[arg(long, value_enum)]
    kind: ConnKind,
    /// api/pg/ssh: upstream host (bare hostname, no scheme/port/path).
    #[arg(long)]
    host: Option<String>,
    /// api: "https" (the default) or "http" (dev/test upstreams).
    #[arg(long)]
    scheme: Option<String>,
    /// Upstream port (api: the scheme's; pg: 5432; ssh: 22).
    #[arg(long)]
    port: Option<u16>,
    /// api: injection template, e.g. 'Authorization: Bearer {{KEY}}' — its
    /// {{refs}} name the secrets.
    /// referencing exactly one secret (default: Authorization Bearer).
    #[arg(long)]
    template: Option<String>,
    /// pg: database name.
    #[arg(long)]
    dbname: Option<String>,
    /// pg/ssh: login user.
    #[arg(long)]
    user: Option<String>,
    /// ssh: pinned server host key fingerprint (SHA256:... or SHA512:...).
    /// Omit it to trust on first use: the key the server presents at the
    /// first agent connection is pinned automatically.
    #[arg(long)]
    host_key_fingerprint: Option<String>,
    /// pg/ssh: name of the one bound secret (api connections derive
    /// theirs from the template).
    #[arg(long)]
    secret: Option<String>,
    /// pg: disable | prefer | require | verify-ca | verify-full
    /// (default: verify-full).
    #[arg(long)]
    sslmode: Option<String>,
    /// pg: optional PEM bundle for a private certificate authority.
    #[arg(long)]
    ca_bundle: Option<String>,
    /// api: expose this connection as an MCP server by giving the upstream's
    /// JSON-RPC path (e.g. `/mcp`). The MCP host then re-exposes its tools;
    /// the credential still rides the pinned host's `/v1/http` plane.
    #[arg(long)]
    mcp_path: Option<String>,
    /// api: the path `conn test` fetches (e.g. `/user`). Most APIs answer
    /// 404 or 403 at the origin root, so a test there proves reachability
    /// and TLS but never exercises the credential. Name a route that reads
    /// the account and the test answers the question it is being asked.
    #[arg(long)]
    test_path: Option<String>,
    /// api: sign each request with AWS SigV4 for this region instead of
    /// injecting a template. Requires --sigv4-service and both credential
    /// refs; replaces --template.
    #[arg(long)]
    sigv4_region: Option<String>,
    /// api: SigV4 signing service name (e.g. s3, execute-api, bedrock).
    #[arg(long, requires = "sigv4_region")]
    sigv4_service: Option<String>,
    /// api: vault secret name holding the AWS access key ID.
    #[arg(long, requires = "sigv4_region")]
    sigv4_access_key_ref: Option<String>,
    /// api: vault secret name holding the AWS secret access key.
    #[arg(long, requires = "sigv4_region")]
    sigv4_secret_key_ref: Option<String>,
    /// api: vault secret name holding a session token (temporary
    /// credentials), signed and sent as x-amz-security-token.
    #[arg(long, requires = "sigv4_region")]
    sigv4_session_token_ref: Option<String>,
    /// api: mint GCP access tokens from the service-account JSON key stored
    /// under this vault secret name instead of injecting a template.
    /// Requires --gcp-scope; replaces --template.
    #[arg(long, conflicts_with = "sigv4_region")]
    gcp_key_ref: Option<String>,
    /// api: space-separated OAuth scopes for minted GCP tokens (e.g.
    /// https://www.googleapis.com/auth/devstorage.read_only).
    #[arg(long, requires = "gcp_key_ref")]
    gcp_scope: Option<String>,
    /// api: PEM client-certificate chain presented on the upstream TLS leg
    /// (mTLS). Requires --client-key.
    #[arg(long, requires = "client_key")]
    client_cert: Option<String>,
    /// api: PEM private key for --client-cert (PKCS#8, PKCS#1, or SEC1).
    #[arg(long, requires = "client_cert")]
    client_key: Option<String>,
    /// cloud: provider (`aws`, `azure`, or `gcp`). Required for --kind cloud.
    #[arg(long)]
    cloud_provider: Option<String>,
    /// cloud/aws: default region (e.g. us-east-1).
    #[arg(long)]
    cloud_region: Option<String>,
    /// cloud/aws: vault secret name holding the access key ID.
    #[arg(long)]
    cloud_access_key_ref: Option<String>,
    /// cloud/aws: vault secret name holding the secret access key.
    #[arg(long)]
    cloud_secret_key_ref: Option<String>,
    /// cloud/aws: optional vault secret name holding a session token
    /// (requires --cloud-role-arn so Multitool can AssumeRole).
    #[arg(long)]
    cloud_session_token_ref: Option<String>,
    /// cloud/aws: when set, AssumeRole into this ARN instead of GetSessionToken.
    #[arg(long)]
    cloud_role_arn: Option<String>,
    /// cloud/aws: optional ExternalId for AssumeRole.
    #[arg(long)]
    cloud_external_id: Option<String>,
    /// cloud/azure: Entra tenant ID (GUID or domain).
    #[arg(long)]
    cloud_tenant_id: Option<String>,
    /// cloud/azure: application (client) ID.
    #[arg(long)]
    cloud_client_id: Option<String>,
    /// cloud/azure: vault secret name holding the client secret.
    #[arg(long)]
    cloud_client_secret_ref: Option<String>,
    /// cloud/azure: optional default subscription ID.
    #[arg(long)]
    cloud_subscription_id: Option<String>,
    /// cloud/azure|gcp: OAuth scope (azure default:
    /// https://management.azure.com/.default; required for gcp).
    #[arg(long)]
    cloud_scope: Option<String>,
    /// cloud/gcp: vault secret name holding the service-account JSON key.
    #[arg(long)]
    cloud_gcp_key_ref: Option<String>,
    /// cloud/gcp: optional default project id for gcloud / client libraries.
    #[arg(long)]
    cloud_project: Option<String>,
    /// cloud: requested session TTL in seconds (900–3600, default 900).
    /// Azure/GCP use the IdP's expires_in; this is informational there.
    #[arg(long)]
    cloud_session_ttl: Option<u64>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Create a missing explicit --root before seeding this first connection.
    #[arg(long, requires = "root")]
    create_root: bool,
    /// Skip the post-add connection test.
    #[arg(long)]
    no_test: bool,
    /// Manage the broker at this manage-API URL instead of this
    /// machine's.
    #[arg(long)]
    broker: Option<String>,
}

impl ConnAdd {
    fn empty(name: String, kind: ConnKind, target: CreateTarget) -> Self {
        let CreateTarget {
            management: ManagementTarget { root, broker },
            create_root,
            no_test,
        } = target;
        Self {
            name,
            kind,
            no_test,
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            secret: None,
            sslmode: None,
            ca_bundle: None,
            mcp_path: None,
            test_path: None,
            sigv4_region: None,
            sigv4_service: None,
            sigv4_access_key_ref: None,
            sigv4_secret_key_ref: None,
            sigv4_session_token_ref: None,
            gcp_key_ref: None,
            gcp_scope: None,
            client_cert: None,
            client_key: None,
            cloud_provider: None,
            cloud_region: None,
            cloud_access_key_ref: None,
            cloud_secret_key_ref: None,
            cloud_session_token_ref: None,
            cloud_role_arn: None,
            cloud_external_id: None,
            cloud_tenant_id: None,
            cloud_client_id: None,
            cloud_client_secret_ref: None,
            cloud_subscription_id: None,
            cloud_scope: None,
            cloud_gcp_key_ref: None,
            cloud_project: None,
            cloud_session_ttl: None,
            root,
            create_root,
            broker,
        }
    }
}

impl ConnAddCommand {
    fn into_args(self) -> ConnAdd {
        match self {
            Self::Api(args) => {
                let mut result = ConnAdd::empty(args.name, ConnKind::Api, args.target);
                result.host = Some(args.host);
                result.scheme = args.scheme;
                result.port = args.port;
                result.template = args.template;
                result.ca_bundle = args.ca_bundle;
                result.mcp_path = args.mcp_path;
                result.test_path = args.test_path;
                result.sigv4_region = args.sigv4_region;
                result.sigv4_service = args.sigv4_service;
                result.sigv4_access_key_ref = args.sigv4_access_key_ref;
                result.sigv4_secret_key_ref = args.sigv4_secret_key_ref;
                result.sigv4_session_token_ref = args.sigv4_session_token_ref;
                result.gcp_key_ref = args.gcp_key_ref;
                result.gcp_scope = args.gcp_scope;
                result.client_cert = args.client_cert;
                result.client_key = args.client_key;
                result
            }
            Self::Pg(args) => {
                let mut result = ConnAdd::empty(args.name, ConnKind::Pg, args.target);
                result.host = Some(args.host);
                result.dbname = Some(args.dbname);
                result.user = Some(args.user);
                result.secret = Some(args.secret);
                result.port = args.port;
                result.sslmode = args.sslmode;
                result.ca_bundle = args.ca_bundle;
                result
            }
            Self::Ssh(args) => {
                let mut result = ConnAdd::empty(args.name, ConnKind::Ssh, args.target);
                result.host = Some(args.host);
                result.user = Some(args.user);
                result.secret = Some(args.secret);
                result.port = args.port;
                result.host_key_fingerprint = args.host_key_fingerprint;
                result
            }
            Self::Cloud { provider } => match provider {
                ConnAddCloudCommand::Aws(args) => {
                    let mut result = ConnAdd::empty(args.name, ConnKind::Cloud, args.target);
                    result.cloud_provider = Some("aws".into());
                    result.cloud_region = Some(args.region);
                    result.cloud_access_key_ref = Some(args.access_key_ref);
                    result.cloud_secret_key_ref = Some(args.secret_key_ref);
                    result.cloud_session_token_ref = args.session_token_ref;
                    result.cloud_role_arn = args.role_arn;
                    result.cloud_external_id = args.external_id;
                    result.cloud_session_ttl = args.session_ttl;
                    result
                }
                ConnAddCloudCommand::Azure(args) => {
                    let mut result = ConnAdd::empty(args.name, ConnKind::Cloud, args.target);
                    result.cloud_provider = Some("azure".into());
                    result.cloud_tenant_id = Some(args.tenant_id);
                    result.cloud_client_id = Some(args.client_id);
                    result.cloud_client_secret_ref = Some(args.client_secret_ref);
                    result.cloud_subscription_id = args.subscription_id;
                    result.cloud_scope = args.scope;
                    result.cloud_session_ttl = args.session_ttl;
                    result
                }
                ConnAddCloudCommand::Gcp(args) => {
                    let mut result = ConnAdd::empty(args.name, ConnKind::Cloud, args.target);
                    result.cloud_provider = Some("gcp".into());
                    result.cloud_gcp_key_ref = Some(args.key_ref);
                    result.cloud_scope = Some(args.scope);
                    result.cloud_project = args.project;
                    result.cloud_session_ttl = args.session_ttl;
                    result
                }
            },
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, Eq, PartialEq)]
enum ConnKind {
    Api,
    Pg,
    Ssh,
    Cloud,
}

impl ConnKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Pg => "pg",
            Self::Ssh => "ssh",
            Self::Cloud => "cloud",
        }
    }
}

#[derive(Subcommand)]
enum CloudCommand {
    /// Print raw credentials for credential_process / scripts.
    ///
    /// Default format is provider-native: AWS prints credential_process JSON
    /// (Version 1). Use --format env for KEY=value lines, or json for the full
    /// broker response.
    Creds {
        /// The cloud connection's name.
        connection: String,
        /// Output shape: `native` (default), `env`, or `json`.
        #[arg(long, value_enum, default_value_t = CloudCredsFormat::Native)]
        format: CloudCredsFormat,
        /// Open against a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Usage commands open sessions on this machine's broker only; this
        /// flag exists to catch the remote guess and explain, never to work.
        #[arg(long, hide = true)]
        broker: Option<String>,
        /// Label this client in the user's activity log.
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
    },
    /// Print an AWS shared-config profile stanza for credential_process.
    Install {
        /// The cloud connection's name.
        connection: String,
        /// Profile name to emit (default: multitool-<connection>).
        #[arg(long)]
        profile: Option<String>,
        /// Open against a broker rooted here instead of the default layout.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Usage commands open sessions on this machine's broker only; this
        /// flag exists to catch the remote guess and explain, never to work.
        #[arg(long, hide = true)]
        broker: Option<String>,
        /// Label this client in the user's activity log (unused for install
        /// text, kept for consistency with other cloud subcommands).
        #[arg(long, value_parser = parse_client_label)]
        client: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum CloudCredsFormat {
    /// Provider-native blob (AWS credential_process JSON).
    Native,
    /// Shell KEY=value lines (not `export`).
    Env,
    /// Full broker `/v1/cloud/session` JSON body.
    Json,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum DsnFormat {
    Env,
    Uri,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointAction {
    Read,
    Issue,
    Renew,
    Revoke,
}

fn endpoint_action(issue: bool, renew: bool, revoke: bool) -> Result<EndpointAction, &'static str> {
    match (issue, renew, revoke) {
        (false, false, false) => Ok(EndpointAction::Read),
        (true, false, false) => Ok(EndpointAction::Issue),
        (false, true, false) => Ok(EndpointAction::Renew),
        (false, false, true) => Ok(EndpointAction::Revoke),
        _ => Err("--issue, --renew, and --revoke are mutually exclusive"),
    }
}

/// The requested socket-authentication posture, or `None` to leave it alone.
/// Clap already refuses both flags together, so this only names the mapping.
fn endpoint_require_auth(require_auth: bool, no_require_auth: bool) -> Option<bool> {
    match (require_auth, no_require_auth) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

fn endpoint_action_supported(action: EndpointAction, online: bool) -> Result<(), &'static str> {
    if matches!(action, EndpointAction::Issue | EndpointAction::Renew) && !online {
        Err(
            "direct endpoint issuance and renewal require a running broker to own the listener; \
             start Multitool for the local store, or `aka serve` / `aka serve --root …` \
             for a headless root, then retry",
        )
    } else {
        Ok(())
    }
}

#[derive(Subcommand)]
enum ConnUpdateCommand {
    /// Update an HTTP API connection.
    Api(ConnUpdateApi),
    /// Update a Postgres connection.
    Pg(ConnUpdatePg),
    /// Update an SSH connection.
    Ssh(ConnUpdateSsh),
}

#[derive(Args)]
struct ConnUpdateApi {
    /// The API connection to update.
    name: String,
    /// Upstream host (bare hostname, no scheme/port/path).
    #[arg(long)]
    host: Option<String>,
    /// "https" or "http" (dev/test upstreams).
    #[arg(long)]
    scheme: Option<String>,
    /// Upstream port.
    #[arg(long)]
    port: Option<u16>,
    /// Injection template, e.g. 'Authorization: Bearer {{KEY}}'.
    #[arg(long)]
    template: Option<String>,
    /// PEM bundle for a private CA; pass '' to clear it.
    #[arg(long)]
    ca_bundle: Option<String>,
    /// Path fetched by `conn test`; pass '' to clear it.
    #[arg(long)]
    test_path: Option<String>,
    #[command(flatten)]
    target: ManagementTarget,
}

#[derive(Args)]
struct ConnUpdatePg {
    /// The Postgres connection to update.
    name: String,
    /// Upstream host.
    #[arg(long)]
    host: Option<String>,
    /// Upstream port.
    #[arg(long)]
    port: Option<u16>,
    /// Database name.
    #[arg(long)]
    dbname: Option<String>,
    /// Login user.
    #[arg(long)]
    user: Option<String>,
    /// Rebind to this vault secret.
    #[arg(long)]
    secret: Option<String>,
    /// disable | prefer | require | verify-ca | verify-full.
    #[arg(long)]
    sslmode: Option<String>,
    /// PEM bundle for a private CA; pass '' to clear it.
    #[arg(long)]
    ca_bundle: Option<String>,
    #[command(flatten)]
    target: ManagementTarget,
}

#[derive(Args)]
struct ConnUpdateSsh {
    /// The SSH connection to update.
    name: String,
    /// Upstream host.
    #[arg(long)]
    host: Option<String>,
    /// Upstream port.
    #[arg(long)]
    port: Option<u16>,
    /// Login user.
    #[arg(long)]
    user: Option<String>,
    /// Rebind to this vault secret.
    #[arg(long)]
    secret: Option<String>,
    /// Pinned host key fingerprint; pass '' to clear the pin.
    #[arg(long)]
    host_key_fingerprint: Option<String>,
    #[command(flatten)]
    target: ManagementTarget,
}

/// `conn update`: the same field flags as `conn add`, all optional — the
/// kind comes from the existing connection and unspecified flags keep
/// their current values.
#[derive(Args)]
struct ConnUpdate {
    /// The connection to update.
    name: String,
    /// api/pg/ssh: upstream host (bare hostname, no scheme/port/path).
    #[arg(long)]
    host: Option<String>,
    /// api: "https" or "http" (dev/test upstreams).
    #[arg(long)]
    scheme: Option<String>,
    /// Upstream port.
    #[arg(long)]
    port: Option<u16>,
    /// api: injection template, e.g. 'Authorization: Bearer {{KEY}}'.
    #[arg(long)]
    template: Option<String>,
    /// pg: database name.
    #[arg(long)]
    dbname: Option<String>,
    /// pg/ssh: login user.
    #[arg(long)]
    user: Option<String>,
    /// ssh: pinned server host key fingerprint (SHA256:... or SHA512:...).
    /// Pass '' to clear the pin: the key the server presents at the next
    /// agent connection is pinned again.
    #[arg(long)]
    host_key_fingerprint: Option<String>,
    /// pg/ssh: rebind to this secret (api connections derive theirs
    /// from the template).
    #[arg(long)]
    secret: Option<String>,
    /// pg: disable | prefer | require | verify-ca | verify-full.
    #[arg(long)]
    sslmode: Option<String>,
    /// pg: PEM bundle for a private certificate authority; pass '' to
    /// clear it.
    #[arg(long)]
    ca_bundle: Option<String>,
    /// api: the path `conn test` fetches (e.g. `/user`); pass '' to fall
    /// back to the MCP path or the origin root.
    #[arg(long)]
    test_path: Option<String>,
    /// Operate on a broker rooted here instead of the default layout.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Manage the broker at this manage-API URL instead of this
    /// machine's.
    #[arg(long)]
    broker: Option<String>,
}

impl ConnUpdate {
    fn empty(name: String, target: ManagementTarget) -> Self {
        Self {
            name,
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            secret: None,
            sslmode: None,
            ca_bundle: None,
            test_path: None,
            root: target.root,
            broker: target.broker,
        }
    }
}

impl ConnUpdateCommand {
    fn into_args(self) -> (ConnKind, ConnUpdate) {
        match self {
            Self::Api(args) => {
                let mut result = ConnUpdate::empty(args.name, args.target);
                result.host = args.host;
                result.scheme = args.scheme;
                result.port = args.port;
                result.template = args.template;
                result.ca_bundle = args.ca_bundle;
                result.test_path = args.test_path;
                (ConnKind::Api, result)
            }
            Self::Pg(args) => {
                let mut result = ConnUpdate::empty(args.name, args.target);
                result.host = args.host;
                result.port = args.port;
                result.dbname = args.dbname;
                result.user = args.user;
                result.secret = args.secret;
                result.sslmode = args.sslmode;
                result.ca_bundle = args.ca_bundle;
                (ConnKind::Pg, result)
            }
            Self::Ssh(args) => {
                let mut result = ConnUpdate::empty(args.name, args.target);
                result.host = args.host;
                result.port = args.port;
                result.user = args.user;
                result.secret = args.secret;
                result.host_key_fingerprint = args.host_key_fingerprint;
                (ConnKind::Ssh, result)
            }
        }
    }
}

fn main() {
    match std::panic::catch_unwind(run_cli) {
        Ok(()) => {}
        Err(payload) => match payload.downcast::<CliExit>() {
            Ok(exit) => std::process::exit(exit.code),
            Err(payload) => std::panic::resume_unwind(payload),
        },
    }
}

fn run_cli() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,aka_core=info".into()),
        )
        .with_writer(std::io::stderr)
        .try_init()
        .ok();
    if std::env::args_os().len() == 1 {
        let color = stdout_use_color();
        let (header, next) = bare_help_frame(color);
        println!("{header}\n");
        let mut command = configured_cli_command(color, false);
        command
            .print_help()
            .unwrap_or_else(|error| die(format!("could not print help: {error}")));
        if let Some(next) = next {
            println!("\n{next}");
        }
        return;
    }
    let cli = parse_cli();
    let json = cli.json;
    JSON_OUTPUT.store(json, Ordering::Relaxed);
    match cli.command {
        Command::Setup {
            command,
            client,
            write,
        } => match (command, client) {
            (Some(SetupCommand::Skill(args)), _) => cmd_skill(args, json),
            (Some(SetupCommand::Instructions(args)), _) => {
                cmd_instructions(args.root, args.broker, json)
            }
            (Some(SetupCommand::Desktop { root }), _) => cmd_setup_desktop(root, json),
            (None, Some(client)) if write => cmd_setup_apply(client, json),
            (None, Some(client)) => {
                cmd_setup_mcp(client, json);
                if !json {
                    guide(format!(
                        "apply all of this: `aka setup {} --write`",
                        client.label()
                    ));
                }
            }
            (None, None) => die_with(
                ExitCode::Usage,
                "name an MCP client (codex, claude-code, claude-desktop) — \
                 `aka setup claude-code` — or a surface: `aka setup skill \
                 --write`, `aka setup instructions`, `aka setup desktop`",
            ),
        },
        Command::Skill(args) => cmd_skill(args, json),
        Command::Completions { shell } => {
            reject_json_for_command(json, "completions");
            use clap::CommandFactory as _;
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(shell, &mut command, name, &mut std::io::stdout());
        }
        Command::Instructions(args) => cmd_instructions(args.root, args.broker, json),
        Command::Serve {
            root,
            listen,
            no_listen,
            public_url,
            web_root,
            data_plane_listen,
            advertise_host,
            data_plane_insecure,
            session_idle_timeout,
            session_max_ttl,
            audit_pg_statements,
            no_mcp,
        } => {
            reject_json_for_command(json, "serve");
            cmd_serve(ServeArgs {
                root,
                listen,
                no_listen,
                public_url,
                web_root,
                data_plane_listen,
                advertise_host,
                data_plane_insecure,
                session_idle_timeout,
                session_max_ttl,
                audit_pg_statements,
                no_mcp,
            })
        }
        Command::Mcp { root, client } => {
            reject_json_for_command(json, "mcp");
            cmd_mcp(root, client)
        }
        Command::Run {
            connection,
            root,
            broker,
            client,
            command,
        } => {
            if let Some(url) = broker {
                refuse_remote_usage("run", "", &url);
            }
            cmd_run(connection, root, client, command, json)
        }
        Command::Env {
            connection,
            root,
            broker,
            client,
            format,
            password_only,
        } => {
            if let Some(url) = broker {
                refuse_remote_usage("env", "", &url);
            }
            cmd_env(connection, root, client, format, password_only, json)
        }
        Command::Cloud { command } => match command {
            CloudCommand::Creds {
                connection,
                format,
                root,
                broker,
                client,
            } => {
                if let Some(url) = broker {
                    refuse_remote_usage("cloud creds", "/v1/cloud/session", &url);
                }
                cmd_cloud_creds(connection, format, root, client, json)
            }
            CloudCommand::Install {
                connection,
                profile,
                root,
                broker,
                client: _,
            } => {
                if let Some(url) = broker {
                    refuse_remote_usage("cloud install", "/v1/cloud/session", &url);
                }
                cmd_cloud_install(connection, profile, root, json)
            }
        },
        Command::SshAgent {
            connection,
            root,
            broker,
            socket,
            command,
        } => {
            reject_json_for_command(json, "ssh-agent");
            cmd_ssh_agent(connection, root, broker, socket, command)
        }
        Command::Secret { command } => match command {
            SecretCommand::Add {
                name,
                value_env,
                raw,
                root,
                create_root,
                broker,
            } => {
                let result = serde_json::json!({ "name": name });
                cmd_secret_add(name, value_env, raw, root, create_root, broker);
                mutation_ok("secret.add", result);
            }
            SecretCommand::List { root, broker } => cmd_secret_list(root, broker, json),
            SecretCommand::Rename {
                name,
                new_name,
                root,
                broker,
            } => {
                let result = serde_json::json!({ "name": name, "new_name": new_name });
                cmd_secret_rename(name, new_name, root, broker);
                mutation_ok("secret.rename", result);
            }
            SecretCommand::Rotate {
                name,
                value_env,
                raw,
                root,
                broker,
            } => {
                let result = serde_json::json!({ "name": name });
                cmd_secret_rotate(name, value_env, raw, root, broker);
                mutation_ok("secret.rotate", result);
            }
            SecretCommand::Rm { name, root, broker } => {
                let result = serde_json::json!({ "name": name });
                cmd_secret_rm(name, root, broker);
                mutation_ok("secret.rm", result);
            }
        },
        Command::Conn { command } => match command {
            ConnCommand::Add { command } => {
                let args = command.into_args();
                let mut result =
                    serde_json::json!({ "name": args.name, "kind": args.kind.as_str() });
                let test = cmd_conn_add(args);
                if let Some(test) = test {
                    result["test"] = test;
                }
                mutation_ok("conn.add", result);
            }
            ConnCommand::List { root, broker } => cmd_conn_list(root, broker, json),
            ConnCommand::Show { name, root, broker } => cmd_conn_show(name, root, broker, json),
            ConnCommand::Update {
                command: Some(command),
                ..
            } => {
                let (kind, args) = command.into_args();
                let result = serde_json::json!({ "name": args.name, "kind": kind.as_str() });
                cmd_conn_update(kind, args);
                mutation_ok("conn.update", result);
            }
            ConnCommand::Update {
                command: None,
                policy,
            } => cmd_conn_policy(policy, json),
            ConnCommand::Rename {
                name,
                new_name,
                root,
                broker,
            } => {
                let result = serde_json::json!({ "name": name, "new_name": new_name });
                cmd_conn_rename(name, new_name, root, broker);
                mutation_ok("conn.rename", result);
            }
            ConnCommand::Rm { name, root, broker } => {
                let result = serde_json::json!({ "name": name });
                cmd_conn_rm(name, root, broker);
                mutation_ok("conn.rm", result);
            }
            ConnCommand::Enable { name, root, broker } => {
                let result = serde_json::json!({ "name": name, "enabled": true });
                cmd_conn_access(name, root, broker, true);
                mutation_ok("conn.enable", result);
            }
            ConnCommand::Disable { name, root, broker } => {
                let result = serde_json::json!({ "name": name, "enabled": false });
                cmd_conn_access(name, root, broker, false);
                mutation_ok("conn.disable", result);
            }
            ConnCommand::Test { name, root, broker } => cmd_conn_test(name, root, broker, json),
        },
        Command::Endpoint(args) => cmd_conn_endpoint(
            ConnEndpointRequest {
                name: args.name,
                issue: args.issue,
                renew: args.renew,
                revoke: args.revoke,
                require_auth: endpoint_require_auth(args.require_auth, args.no_require_auth),
                url: args.url,
                secret: args.secret,
                root: args.root,
                broker: args.broker,
            },
            json,
        ),
        Command::Sessions {
            close,
            root,
            broker,
        } => cmd_sessions(close, root, broker, json),
        Command::Approvals {
            watch,
            root,
            broker,
        } => cmd_requests(watch, None, None, vec![], root, broker, json),
        Command::Approve {
            id,
            values,
            root,
            broker,
        } => cmd_requests(false, Some(id), None, values, root, broker, json),
        Command::Deny { id, root, broker } => {
            cmd_requests(false, None, Some(id), vec![], root, broker, json)
        }
        Command::Ls { root, broker } => cmd_conn_list(root, broker, json),
        Command::Use {
            name,
            broker,
            root,
            pin,
            rm,
            unset,
        } => cmd_use(name, broker, root, pin, rm, unset, json),
        Command::Login {
            url,
            invite,
            name,
            client,
        } => cmd_login(url, invite, name, client, json),
        Command::Logout { name } => cmd_logout(name),
        Command::Admin { command } => match command {
            AdminCommand::Invite {
                label,
                list,
                cancel,
                root,
            } => cmd_admin_invite(label, list, cancel, root, json),
            AdminCommand::AgentKey {
                rotate,
                root,
                broker,
            } => cmd_key(rotate, root, broker, json),
            AdminCommand::Settings { command } => match command {
                SettingsCommand::Get { root, broker } => cmd_settings_get(root, broker, json),
                SettingsCommand::Set {
                    menu_bar_hides_dock,
                    confirm_ssh_host_keys,
                    root,
                    broker,
                } => cmd_settings_set(
                    menu_bar_hides_dock,
                    confirm_ssh_host_keys,
                    root,
                    broker,
                    json,
                ),
            },
            AdminCommand::Login {
                broker,
                token_env,
                root,
            } => {
                let result = serde_json::json!({ "broker": broker });
                cmd_manage_login(broker, token_env, root);
                mutation_ok("admin.login", result);
            }
            AdminCommand::Logout { broker, root } => {
                let result = serde_json::json!({ "broker": broker });
                cmd_manage_logout(broker, root);
                mutation_ok("admin.logout", result);
            }
            AdminCommand::Token {
                revoke,
                ttl_days,
                root,
                broker,
                create_root,
            } => cmd_manage_token(revoke, ttl_days, root, broker, create_root, json),
            AdminCommand::Enroll { cancel, root } => cmd_manage_enroll(cancel, root, json),
            AdminCommand::Legacy {
                restore,
                retire,
                root,
            } => {
                cmd_manage_legacy(restore, retire, root);
                mutation_ok(
                    "admin.legacy",
                    serde_json::json!({ "accepted": restore, "retired": retire }),
                );
            }
        },
        Command::Status { root, broker } => cmd_status(json, root, broker),
        Command::Activity {
            limit,
            root,
            broker,
        } => cmd_activity(limit, json, root, broker),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
enum ExitCode {
    Generic = 1,
    Usage = 2,
    NoBroker = 3,
    Authentication = 4,
    NotFound = 5,
    Conflict = 6,
    RemoteUnreachable = 7,
    TestFailed = 8,
}

#[derive(Debug)]
struct CliExit {
    code: i32,
}

/// Unwind the active command before the process exits. In particular, this
/// gives every `Zeroizing<String>` holding a secret, management token, or
/// short-lived credential a chance to scrub its allocation.
fn exit_with(code: ExitCode) -> ! {
    exit_with_raw(code as i32)
}

/// Exit carrying a status this process did not choose: the exit code of a
/// child command run on the user's behalf. Flattening those to a generic
/// failure would hide the distinctions a caller acts on — `ssh`'s 255 for
/// "could not connect" reads very differently from the remote command's 1.
fn exit_with_raw(code: i32) -> ! {
    std::panic::resume_unwind(Box::new(CliExit { code }))
}

fn die_with(code: ExitCode, message: impl std::fmt::Display) -> ! {
    presentation::error(message, stderr_use_color());
    exit_with(code);
}

fn die(message: impl std::fmt::Display) -> ! {
    die_with(ExitCode::Generic, message)
}

fn manage_error_exit_code(error: &ManageError) -> ExitCode {
    match error {
        ManageError::InvalidSecretName { .. }
        | ManageError::InvalidSite { .. }
        | ManageError::InvalidTotpSeed { .. }
        | ManageError::NotAPassword
        | ManageError::InvalidConnectionName { .. }
        | ManageError::Template { .. }
        | ManageError::UnknownTemplateRef { .. }
        | ManageError::WrongSecretCount { .. }
        | ManageError::InvalidConnectionConfig { .. }
        | ManageError::InvalidSetting { .. }
        | ManageError::InvalidConnectionField { .. }
        | ManageError::KindChange
        | ManageError::EndpointExpired
        | ManageError::EndpointRequiresWiring => ExitCode::Usage,
        ManageError::InvalidManageToken { .. } => ExitCode::Authentication,
        ManageError::SecretNotFound
        | ManageError::ConnectionNotFound
        | ManageError::TotpNotConfigured
        | ManageError::EndpointNotFound => ExitCode::NotFound,
        ManageError::SecretNameTaken { .. }
        | ManageError::ConnectionNameTaken { .. }
        | ManageError::ConnectionTargetTaken { .. }
        | ManageError::ConnectionChanged
        | ManageError::ApprovalConnectionChanged
        | ManageError::SecretInUse { .. }
        | ManageError::EndpointLimit { .. } => ExitCode::Conflict,
        ManageError::Unreachable { .. } => ExitCode::RemoteUnreachable,
        ManageError::OAuth { .. }
        | ManageError::OnePassword { .. }
        | ManageError::Vault { .. }
        | ManageError::RemoteUnsupported { .. }
        | ManageError::Internal { .. } => ExitCode::Generic,
    }
}

fn die_manage(error: ManageError) -> ! {
    die_with(manage_error_exit_code(&error), error)
}

fn print_json(value: &impl serde::Serialize) {
    println!(
        "{}",
        serde_json::to_string(value).expect("CLI result is serializable")
    );
}

static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);

fn mutation_ok(action: &str, result: serde_json::Value) {
    if JSON_OUTPUT.load(Ordering::Relaxed) {
        print_json(&serde_json::json!({
            "ok": true,
            "action": action,
            "result": result,
        }));
    }
}

fn reject_json_for_command(json: bool, command: &str) {
    if json {
        die_with(
            ExitCode::Usage,
            format!(
                "--json is not supported for the streaming or format-specific {command} command"
            ),
        );
    }
}

// ---------------------------------------------------------------------------
// Ambient broker contexts
//
// Contexts name where commands point when --root/--broker are absent, so
// "which broker am I talking to" is decided once instead of per flag. The
// chain below the explicit flags: AKA_BROKER (a context name or URL) → a
// repo pin (the first regular file named `.aka` walking up from the working
// directory) → the `aka use` default → the local desktop layout, which is
// exactly what silent flags meant before contexts existed.

const BROKER_ENV: &str = "AKA_BROKER";
const PIN_FILE: &str = ".aka";

/// Where a command points when its --root/--broker flags are silent.
#[derive(Clone, Debug, PartialEq)]
enum ContextTarget {
    /// The desktop layout (`~/.aka`).
    Local,
    /// A broker rooted at this path (`aka serve --root`).
    Root(PathBuf),
    /// A hosted broker's manage URL.
    Broker(String),
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct ContextsFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    contexts: std::collections::BTreeMap<String, ContextEntry>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ContextEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broker: Option<String>,
}

/// Client-side, broker-independent state: `<config dir>/aka/contexts.json`.
fn contexts_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("aka").join("contexts.json"))
}

fn load_contexts() -> ContextsFile {
    let Some(path) = contexts_path() else {
        return ContextsFile::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|error| {
            die(format!(
                "could not parse {}: {error} — fix or delete it",
                path.display()
            ))
        }),
        Err(_) => ContextsFile::default(),
    }
}

fn save_contexts(file: &ContextsFile) {
    let Some(path) = contexts_path() else {
        die("could not determine the per-user config directory; set HOME");
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| die(format!("could not create {}: {error}", parent.display())));
    }
    let raw = serde_json::to_string_pretty(file).expect("contexts serialize");
    std::fs::write(&path, raw)
        .unwrap_or_else(|error| die(format!("could not write {}: {error}", path.display())));
}

/// Resolve a context name — or a bare URL, which needs no definition — to
/// its target. `local` and `server` are built-ins.
fn named_context_target(file: &ContextsFile, name: &str) -> Result<ContextTarget, String> {
    if name.starts_with("http://") || name.starts_with("https://") {
        return Ok(ContextTarget::Broker(name.to_string()));
    }
    match name {
        "local" => Ok(ContextTarget::Local),
        "server" => {
            let root = std::env::var(SERVER_ROOT_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .map_or_else(default_server_root, Ok)?;
            Ok(ContextTarget::Root(root))
        }
        _ => {
            let entry = file.contexts.get(name).ok_or_else(|| {
                format!(
                    "no context named {name} — `aka use` lists them; define one with \
                     `aka use {name} --broker <url>` or `aka use {name} --root <path>`"
                )
            })?;
            match (&entry.root, &entry.broker) {
                (Some(root), _) => Ok(ContextTarget::Root(root.clone())),
                (None, Some(url)) => Ok(ContextTarget::Broker(url.clone())),
                (None, None) => Err(format!("context {name} names neither a root nor a broker")),
            }
        }
    }
}

/// The repo pin: the first regular file named `.aka` walking up from the
/// working directory (a directory named `.aka`, like the desktop layout in
/// $HOME, is ignored). Its trimmed first line is a context name or URL.
fn repo_pin() -> Option<(PathBuf, String)> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(PIN_FILE);
        if candidate.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&candidate) {
                let value = raw.lines().next().unwrap_or("").trim().to_string();
                if !value.is_empty() {
                    return Some((candidate, value));
                }
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The ambient chain below the explicit flags. The returned source string
/// names why the target was picked, for `via …` transparency lines and
/// refusal messages.
fn ambient_context() -> Option<(String, ContextTarget)> {
    let file = load_contexts();
    if let Ok(value) = std::env::var(BROKER_ENV) {
        let value = value.trim().to_string();
        if !value.is_empty() {
            let target = named_context_target(&file, &value).unwrap_or_else(|message| {
                die_with(ExitCode::Usage, format!("{BROKER_ENV}: {message}"))
            });
            return Some((format!("{BROKER_ENV}={value}"), target));
        }
    }
    if let Some((path, value)) = repo_pin() {
        let target = named_context_target(&file, &value).unwrap_or_else(|message| {
            die_with(
                ExitCode::Usage,
                format!("repo pin {}: {message}", path.display()),
            )
        });
        return Some((format!("repo pin {}", path.display()), target));
    }
    if let Some(current) = &file.current {
        let target = named_context_target(&file, current).unwrap_or_else(|message| {
            die_with(ExitCode::Usage, format!("current context: {message}"))
        });
        return Some((format!("context {current}"), target));
    }
    None
}

/// Explicit flags plus the ambient chain, for management-flavored commands
/// that branch on root-versus-URL themselves (status, activity, agent-key).
/// Explicit flags and the URL environment always win; ambient fills in only
/// when both are silent, exactly like [`management_backend_with_create`].
fn ambient_management_target(
    root: Option<PathBuf>,
    url: Option<String>,
) -> (Option<PathBuf>, Option<String>) {
    let url = effective_broker_url(url);
    if root.is_some() || url.is_some() {
        return (root, url);
    }
    match ambient_context() {
        Some((_, ContextTarget::Root(path))) => (Some(path), None),
        Some((_, ContextTarget::Broker(broker))) => (None, Some(broker)),
        Some((_, ContextTarget::Local)) | None => (None, None),
    }
}

/// The layout usage commands (run, env, mcp) open sessions against. An
/// ambient remote context is refused with the same honesty as an explicit
/// remote flag: the session client speaks only this machine's socket.
fn usage_agent(explicit: Option<&Path>) -> client::Agent {
    if let Some(root) = explicit {
        return client::Agent::Local(Paths::under(root));
    }
    match ambient_context() {
        Some((_, ContextTarget::Root(root))) => client::Agent::Local(Paths::under(&root)),
        Some((source, ContextTarget::Broker(url))) => {
            let url = url.trim_end_matches('/').to_string();
            let key = remote_agent_key(&url).unwrap_or_else(|| {
                die_with(
                    ExitCode::Authentication,
                    format!(
                        "no agent key stored for {url} ({source}) — join it with \
                         `aka login {url}` using an invite from its operator, or \
                         set AKA_AGENT_KEY"
                    ),
                )
            });
            client::Agent::remote(&url, &key)
        }
        Some((_, ContextTarget::Local)) | None => client::Agent::Local(store_paths(None)),
    }
}

/// The shared agent key for a remote broker: the environment wins (CI hands
/// it in without persisting), then the store `aka login` wrote.
fn remote_agent_key(url: &str) -> Option<Zeroizing<String>> {
    if let Ok(key) = std::env::var(AGENT_KEY_ENV) {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return Some(Zeroizing::new(key));
        }
    }
    manage_token_store(&store_paths(None)).load_agent_key(url)
}

/// `aka admin invite`: mint, list, or cancel one-use join codes over this
/// machine's socket. Socket-only like enrollment — see [`AdminCommand`].
fn cmd_admin_invite(
    label: Option<String>,
    list: bool,
    cancel: bool,
    root: Option<PathBuf>,
    json: bool,
) {
    let root = root.or_else(|| match ambient_context() {
        Some((_, ContextTarget::Root(path))) => Some(path),
        _ => None,
    });
    require_existing_root_for_read(root.as_deref(), false);
    let paths = store_paths(root.as_deref());
    let socket = paths.socket_file();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let (method, path) = match (list, cancel) {
        (true, _) => ("GET", "/v1/auth/invites".to_string()),
        (_, true) => ("DELETE", "/v1/auth/invites".to_string()),
        _ => (
            "POST",
            match &label {
                Some(label) => format!("/v1/auth/invites?label={}", urlencode(label)),
                None => "/v1/auth/invites".to_string(),
            },
        ),
    };
    let (status, body) = match runtime.block_on(client::unix_http(
        &socket, method, &path, None, None, None,
    )) {
        Ok(response) => response,
        Err(error) => die_with(
            ExitCode::NoBroker,
            format!(
                "could not reach this machine's broker at {}: {error}\n\
                 Invites are minted on the broker host, so the broker has to be running there.",
                socket.display()
            ),
        ),
    };
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    if status != 200 {
        let detail = parsed
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or(body.trim());
        die(format!("could not change invites: {detail}"));
    }
    if list {
        let invites = parsed["invites"].as_array().cloned().unwrap_or_default();
        if json {
            print_json(&parsed);
            return;
        }
        if invites.is_empty() {
            guide("no outstanding invites");
            return;
        }
        let rows = invites
            .iter()
            .map(|invite| {
                vec![
                    invite["label"].as_str().unwrap_or("—").to_string(),
                    invite["created_at"].as_str().unwrap_or_default().to_string(),
                    invite["expires_at"].as_str().unwrap_or_default().to_string(),
                ]
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            presentation::table(&["label", "created", "expires"], rows)
        );
        return;
    }
    if cancel {
        let cancelled = parsed["cancelled"].as_u64().unwrap_or(0);
        mutation_ok(
            "admin.invite.cancel",
            serde_json::json!({ "cancelled": cancelled }),
        );
        ack(format!("voided {cancelled} outstanding invite(s)"));
        return;
    }
    let invite = parsed["invite"].as_str().unwrap_or_default();
    let public_url = parsed["public_url"].as_str().map(|url| url.trim_end_matches('/'));
    let minutes = parsed["expires_in_seconds"].as_u64().unwrap_or(900) / 60;
    if json {
        mutation_ok(
            "admin.invite.open",
            serde_json::json!({
                "invite": invite,
                "public_url": public_url,
                "expires_in_seconds": parsed["expires_in_seconds"],
            }),
        );
        return;
    }
    ack(format!("one-use invite created (expires in {minutes} min)"));
    match public_url {
        Some(url) => {
            println!("{url}/join#{invite}");
            guide(format!(
                "they run: aka login {url}/join#{invite}\n\
                 The invite is spent by the first redemption; /v1/pair stays \
                 closed over TCP."
            ));
        }
        None => {
            println!("{invite}");
            guide(
                "this broker advertises no public URL, so the code prints \
                 alone — serve with `--public-url` (or `--listen`) and they \
                 run: aka login <url> --invite <code>",
            );
        }
    }
}

/// Percent-encode one query-string value. Only invite labels travel this
/// way, and only over a Unix socket, so the conservative set is enough.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// `aka login <url>`: redeem an invite, store the shared agent key for that
/// broker, and define/select its context.
fn cmd_login(
    url: String,
    invite: Option<String>,
    name: Option<String>,
    client: Option<String>,
    json: bool,
) {
    // The URL the operator pastes carries the code in its fragment, which is
    // never sent to a server — splitting it here is what makes joining one
    // command instead of two.
    let (base, fragment) = match url.split_once('#') {
        Some((base, fragment)) => (base.to_string(), Some(fragment.to_string())),
        None => (url.clone(), None),
    };
    let base = base.trim_end_matches("/join").trim_end_matches('/').to_string();
    let base = match RemoteConfig::normalize_url(&base) {
        Ok(url) => url,
        Err(error) => die_with(ExitCode::Usage, error),
    };
    let invite = invite
        .or(fragment)
        .map(|code| code.trim().to_string())
        .filter(|code| !code.is_empty())
        .unwrap_or_else(|| {
            if presentation::stdin_is_tty() {
                die_with(
                    ExitCode::Usage,
                    "no invite code — paste the URL your operator's `aka admin \
                     invite` printed (it carries the code), or pass --invite <code>",
                );
            }
            let mut code = String::new();
            use std::io::Read as _;
            std::io::stdin()
                .read_to_string(&mut code)
                .unwrap_or_else(|error| die(format!("could not read the invite: {error}")));
            let code = code.trim().to_string();
            if code.is_empty() {
                die_with(ExitCode::Usage, "the invite code on stdin was empty");
            }
            code
        });

    let label = client.unwrap_or_else(|| "aka-cli".to_string());
    let body = serde_json::json!({ "invite": invite, "agent_name": label }).to_string();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let spinner = presentation::Spinner::start_if(!json, format!("joining {base}…"));
    let response = runtime.block_on(async {
        reqwest::Client::new()
            .post(format!("{base}/v1/join"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
    });
    spinner.stop("");
    let response = response.unwrap_or_else(|error| {
        die_with(
            ExitCode::RemoteUnreachable,
            format!("could not reach {base}: {error}"),
        )
    });
    let status = response.status();
    let payload = runtime
        .block_on(response.text())
        .unwrap_or_else(|error| die(format!("could not read {base}'s response: {error}")));
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
    if !status.is_success() {
        let detail = parsed["detail"]
            .as_str()
            .or_else(|| parsed["reason"].as_str())
            .unwrap_or(payload.trim());
        die_with(
            if status.as_u16() == 403 {
                ExitCode::Authentication
            } else {
                ExitCode::Generic
            },
            format!("{base} refused the invite: {detail}"),
        );
    }
    let Some(key) = parsed["token"].as_str().filter(|key| !key.is_empty()) else {
        die("the join response carried no shared key");
    };
    // Prefer the broker's own advertised URL: an operator behind a proxy
    // knows the address clients should record better than the one that
    // happened to be pasted.
    let stored_url = parsed["public_url"]
        .as_str()
        .and_then(|url| RemoteConfig::normalize_url(url).ok())
        .unwrap_or_else(|| base.clone());
    let paths = store_paths(None);
    let store = manage_token_store(&paths);
    if let Err(error) = store.save_agent_key(&stored_url, key) {
        die(format!("could not store the agent key: {error}"));
    }

    let name = name.unwrap_or_else(|| context_name_for(&stored_url));
    let mut file = load_contexts();
    file.contexts.insert(
        name.clone(),
        ContextEntry {
            root: None,
            broker: Some(stored_url.clone()),
        },
    );
    file.current = Some(name.clone());
    save_contexts(&file);

    mutation_ok(
        "login",
        serde_json::json!({
            "broker": stored_url,
            "context": name,
            "agent": parsed["agent"],
            "key_stored_in": store.storage_description(&stored_url),
        }),
    );
    ack(format!(
        "paired with {stored_url} — agent key stored in {}",
        store.storage_description(&stored_url)
    ));
    ack(format!("context {name} saved and made current"));
    guide(format!(
        "management commands still need their own token: `aka admin login \
         --broker {stored_url}`"
    ));
}

/// A context name derived from a broker URL: its host up to the first dot,
/// which is the part a team actually says out loud.
fn context_name_for(url: &str) -> String {
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url);
    let candidate = host.split('.').next().unwrap_or(host);
    let cleaned: String = candidate
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if cleaned.is_empty() || matches!(cleaned.as_str(), "local" | "server") {
        "broker".to_string()
    } else {
        cleaned
    }
}

/// `aka logout`: forget a broker's agent key and context.
fn cmd_logout(name: Option<String>) {
    let mut file = load_contexts();
    let name = name
        .or_else(|| file.current.clone())
        .unwrap_or_else(|| die_with(ExitCode::Usage, "no current context to log out of"));
    let target = named_context_target(&file, &name)
        .unwrap_or_else(|message| die_with(ExitCode::Usage, message));
    let ContextTarget::Broker(url) = target else {
        die_with(
            ExitCode::Usage,
            format!("{name} is a local context; there is no stored key to forget"),
        );
    };
    let paths = store_paths(None);
    let store = manage_token_store(&paths);
    if let Err(error) = store.delete_agent_key(&url) {
        die(format!("could not remove the stored agent key: {error}"));
    }
    file.contexts.remove(&name);
    if file.current.as_deref() == Some(name.as_str()) {
        file.current = None;
    }
    save_contexts(&file);
    mutation_ok(
        "logout",
        serde_json::json!({ "broker": url, "context": name }),
    );
    ack(format!("forgot {name} ({url}) and its stored agent key"));
    guide("its management token, if any, is separate: `aka admin logout`");
}

/// `aka use`: list, switch, define, pin, or remove contexts. All of it is
/// client-side state — no broker is contacted, so pointing somewhere never
/// authenticates or audits anything by itself.
fn cmd_use(
    name: Option<String>,
    broker: Option<String>,
    root: Option<PathBuf>,
    pin: bool,
    rm: bool,
    unset: bool,
    json: bool,
) {
    let mut file = load_contexts();
    if unset {
        file.current = None;
        save_contexts(&file);
        mutation_ok("use.unset", serde_json::json!({ "current": null }));
        ack("cleared the current context — commands point at local again");
        return;
    }
    let Some(name) = name else {
        let resolved = ambient_context();
        if json {
            let contexts: serde_json::Map<String, serde_json::Value> = file
                .contexts
                .iter()
                .map(|(name, entry)| {
                    (
                        name.clone(),
                        serde_json::json!({ "root": entry.root, "broker": entry.broker }),
                    )
                })
                .collect();
            print_json(&serde_json::json!({
                "current": file.current,
                "contexts": contexts,
                "resolved": resolved.as_ref().map(|(source, target)| serde_json::json!({
                    "source": source,
                    "target": match target {
                        ContextTarget::Local => "local".to_string(),
                        ContextTarget::Root(path) => path.display().to_string(),
                        ContextTarget::Broker(url) => url.clone(),
                    },
                })),
            }));
            return;
        }
        let current = file.current.as_deref();
        let mut rows = Vec::new();
        let marker = |on: bool| if on { "*" } else { " " }.to_string();
        rows.push(vec![
            marker(current.is_none() && resolved.is_none()),
            "local".into(),
            "the desktop layout (~/.aka)".into(),
        ]);
        rows.push(vec![
            marker(current == Some("server")),
            "server".into(),
            "the serve root (AKA_SERVER_ROOT or ~/.akaserver)".into(),
        ]);
        for (name, entry) in &file.contexts {
            let target = entry
                .broker
                .clone()
                .or_else(|| entry.root.as_ref().map(|p| p.display().to_string()))
                .unwrap_or_default();
            rows.push(vec![marker(current == Some(name.as_str())), name.clone(), target]);
        }
        println!("{}", presentation::table(&["", "name", "target"], rows));
        match resolved {
            Some((source, target)) => guide(format!(
                "commands currently resolve via {source} → {}",
                match target {
                    ContextTarget::Local => "local".to_string(),
                    ContextTarget::Root(path) => path.display().to_string(),
                    ContextTarget::Broker(url) => url,
                }
            )),
            None => guide("no ambient context — commands point at local (~/.aka)"),
        }
        return;
    };
    if rm {
        if file.contexts.remove(&name).is_none() {
            die_with(
                ExitCode::NotFound,
                format!("no context named {name} to remove"),
            );
        }
        if file.current.as_deref() == Some(name.as_str()) {
            file.current = None;
        }
        save_contexts(&file);
        mutation_ok("use.rm", serde_json::json!({ "name": name }));
        ack(format!("removed context {name}"));
        return;
    }
    if broker.is_some() || root.is_some() {
        if matches!(name.as_str(), "local" | "server") {
            die_with(
                ExitCode::Usage,
                format!("{name} is a built-in context and cannot be redefined"),
            );
        }
        let broker = broker.map(|url| match RemoteConfig::normalize_url(&url) {
            Ok(url) => url,
            Err(error) => die_with(ExitCode::Usage, error),
        });
        file.contexts.insert(
            name.clone(),
            ContextEntry {
                root: root.clone(),
                broker: broker.clone(),
            },
        );
        file.current = Some(name.clone());
        save_contexts(&file);
        mutation_ok(
            "use.define",
            serde_json::json!({ "name": name, "root": root, "broker": broker, "current": name }),
        );
        ack(format!("defined context {name} and made it current"));
        return;
    }
    if let Err(message) = named_context_target(&file, &name) {
        die_with(ExitCode::Usage, message);
    }
    if pin {
        std::fs::write(PIN_FILE, format!("{name}\n"))
            .unwrap_or_else(|error| die(format!("could not write {PIN_FILE}: {error}")));
        mutation_ok("use.pin", serde_json::json!({ "name": name, "file": PIN_FILE }));
        ack(format!(
            "pinned this directory to context {name} — commit {PIN_FILE} so \
             teammates and agents inherit it"
        ));
        return;
    }
    file.current = Some(name.clone());
    save_contexts(&file);
    mutation_ok("use.switch", serde_json::json!({ "current": name }));
    ack(format!("switched to context {name}"));
}

/// One unauthenticated well-known read over a local socket with a short
/// deadline. No pairing, no bearer, no audit entry; a hung broker costs
/// 250ms, not a hang — bare `aka` must never block on a broker.
fn broker_answers(paths: &Paths) -> bool {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime
        .block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                client::unix_http(
                    &paths.socket_file(),
                    "GET",
                    "/.well-known/agent-broker.json",
                    None,
                    None,
                    None,
                ),
            )
            .await
        })
        .map(|result| matches!(result, Ok((200, _))))
        .unwrap_or(false)
}

/// The live line above bare `aka`'s help and, when there is a useful
/// context-specific action, the NEXT hint below it. Everything degrades — no
/// broker is a dim pointer, never an error, and the probe never authenticates
/// so glancing at help leaves no audit trace.
fn bare_help_frame(color: bool) -> (String, Option<String>) {
    let next = |hint: &str, why: &str| {
        format!(
            "{}  {}   {}",
            paint::bold_green(color, "NEXT"),
            paint::bold_cyan(color, hint),
            paint::dim(color, why)
        )
    };
    // An ambient context is the answer to "where do commands point", so it
    // outranks whatever happens to be running locally. No probe: reaching a
    // remote broker can be slow, and bare `aka` must stay instant.
    match ambient_context() {
        Some((source, ContextTarget::Broker(url))) => {
            let url = url.trim_end_matches('/').to_string();
            let joined = remote_agent_key(&url).is_some();
            let header = format!(
                "{} {}",
                paint::bold_green(color, format!("● context → {url}")),
                paint::dim(color, format!("({source})"))
            );
            let hint = if joined {
                next("aka ls", "see what agents can reach there")
            } else {
                next(
                    &format!("aka login {url}"),
                    "no agent key stored yet — redeem an invite",
                )
            };
            return (header, Some(hint));
        }
        Some((source, ContextTarget::Root(root))) => {
            if broker_answers(&Paths::under(&root)) {
                return (
                    format!(
                        "{} {}",
                        paint::bold_green(color, "● broker running —"),
                        paint::dim(color, format!("{} ({source})", root.display()))
                    ),
                    Some(next("aka ls", "see what agents can reach")),
                );
            }
        }
        Some((_, ContextTarget::Local)) | None => {}
    }
    if let Ok(paths) = Paths::default_locations() {
        if broker_answers(&paths) {
            let header = format!(
                "{} {}",
                paint::bold_green(color, "● broker running —"),
                paint::dim(color, paths.socket_file().display().to_string())
            );
            let hint = if Path::new(".claude/skills/multitool/SKILL.md").exists() {
                next("aka ls", "see what agents can reach")
            } else {
                next("aka setup claude-code", "connect an agent to this repo")
            };
            return (header, Some(hint));
        }
    }
    let server_root = std::env::var(SERVER_ROOT_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| default_server_root().ok());
    if let Some(root) = server_root {
        if broker_answers(&Paths::under(&root)) {
            let header = format!(
                "{} {}",
                paint::bold_green(color, "● headless broker running —"),
                paint::dim(color, root.display().to_string())
            );
            let hint = next(
                &format!("aka ls --root {}", root.display()),
                "commands reach this broker with --root",
            );
            return (header, Some(hint));
        }
    }
    (
        paint::dim(color, "no local broker running").to_string(),
        None,
    )
}

fn store_paths(root: Option<&Path>) -> Paths {
    match root {
        Some(root) => Paths::under(root),
        None => Paths::default_locations().unwrap_or_else(|error| {
            die(format!(
                "could not determine the per-user data and socket directories: {error}; \
                 set HOME (and, where applicable, XDG_DATA_HOME), or pass --root"
            ))
        }),
    }
}

/// Default directory for bare `aka serve`: `~/.akaserver`.
fn default_server_root() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| {
        "could not determine the home directory for the default serve root (~/.akaserver); \
         set HOME, pass --root, or set AKA_SERVER_ROOT"
            .to_string()
    })?;
    Ok(home.join(".akaserver"))
}

/// Resolve `aka serve`'s root.
///
/// Precedence: explicit `--root` > non-empty `AKA_SERVER_ROOT` > `default_root`
/// (normally `~/.akaserver`). The env value is used as-is; shells expand `~`
/// when exporting — bare `~` in the process environment is not expanded here.
fn resolve_serve_root(
    explicit: Option<PathBuf>,
    env_value: Option<&str>,
    default_root: PathBuf,
) -> PathBuf {
    if let Some(root) = explicit {
        return root;
    }
    if let Some(value) = env_value {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    default_root
}

const DEFAULT_SERVE_PORT: u16 = 4780;

fn default_serve_listen() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], DEFAULT_SERVE_PORT))
}

fn resolve_serve_network(
    no_listen: bool,
    listen: Option<std::net::SocketAddr>,
    public_url: Option<String>,
) -> (Option<std::net::SocketAddr>, Option<String>) {
    if no_listen {
        return (None, None);
    }
    let listen = listen.unwrap_or_else(default_serve_listen);
    let public_url = public_url.or_else(|| {
        listen
            .ip()
            .is_loopback()
            .then(|| format!("http://localhost:{}", listen.port()))
    });
    (Some(listen), public_url)
}

fn suggested_public_url(addr: std::net::SocketAddr) -> String {
    if addr.ip().is_loopback() {
        format!("http://localhost:{}", addr.port())
    } else {
        "https://broker.example.com".into()
    }
}

fn login_keychain_expected() -> bool {
    #[cfg(target_os = "macos")]
    {
        let api = aka_core::keychain::darwin::SecurityFramework;
        aka_core::keychain::KeychainApi::data_protection_available(&api).is_err()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

fn serve_launch_notice(login_keychain: bool) -> Option<&'static str> {
    login_keychain.then_some(
        "Launching broker… macOS may ask for your password to allow this unsigned aka build to access the login Keychain.",
    )
}

fn print_serve_launch_notice() {
    if let Some(notice) = serve_launch_notice(login_keychain_expected()) {
        eprintln!("{}", paint::dim(stderr_use_color(), notice));
    }
}

/// `--root` / `AKA_SERVER_ROOT` / `~/.akaserver` for a live `serve` process.
fn serve_root_from_flags(explicit: Option<PathBuf>) -> PathBuf {
    let env = std::env::var(SERVER_ROOT_ENV).ok();
    let default = match default_server_root() {
        Ok(path) => path,
        Err(error) => die(error),
    };
    resolve_serve_root(explicit, env.as_deref(), default)
}

/// A typo in `--root` must not make a command silently create and operate on
/// a brand-new broker. Remote commands use the root only as an optional
/// management-token location, so the broker URL remains authoritative.
fn require_existing_root_for_read(root: Option<&Path>, remote: bool) {
    let Some(root) = root.filter(|_| !remote) else {
        return;
    };
    let data_dir = Paths::under(root).data_dir;
    if !data_dir.is_dir() {
        die(format!(
            "{} is not an existing broker root (expected its data directory at {})",
            root.display(),
            data_dir.display()
        ));
    }
}

fn open_vault(
    paths: &Paths,
    root: Option<&Path>,
) -> Result<Arc<dyn SecretVault>, aka_core::error::CoreError> {
    let vault = match root {
        Some(root) => platform_vault_for_root(paths, root),
        None => platform_vault(paths),
    }?;
    if selected_platform_vault_backend(paths) == PlatformVaultBackend::PlaintextDevFile {
        eprintln!(
            "  vault: plaintext dev fallback at {} (set AKA_VAULT_KEY or \
             AKA_VAULT_KEY_FILE)",
            paths.dev_vault_file().display()
        );
    }
    Ok(vault)
}

fn acquire_offline_store_lock(paths: &Paths) -> Result<BrokerInstanceLock, CoreError> {
    paths.ensure()?;
    let instance_lock = match paths.try_acquire_broker_lock_for(BrokerLockRole::Cli)? {
        BrokerLockAttempt::Acquired(lock) => lock,
        BrokerLockAttempt::Held(Some(holder)) if holder.role == BrokerLockRole::Cli => {
            return Err(CoreError::BrokerStateBusy(Some(holder.pid)));
        }
        BrokerLockAttempt::Held(_) => {
            return Err(CoreError::BrokerAlreadyRunning(paths.socket_display()));
        }
    };

    // A broker from before `broker.lock` may still own the rendezvous point.
    // Once the new lease is held, reject a live legacy socket before opening
    // any state; only the expected crash residue is safe to ignore here.
    let socket = paths.socket_file();
    let metadata = match std::fs::symlink_metadata(&socket) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(CoreError::Io(error)),
    };
    if let Some(metadata) = metadata {
        if !metadata.file_type().is_socket() {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to open state while {} is not a Unix socket",
                    socket.display()
                ),
            )));
        }
        match std::os::unix::net::UnixStream::connect(&socket) {
            Ok(_) => return Err(CoreError::BrokerAlreadyRunning(paths.socket_display())),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) => {}
            Err(error) => {
                return Err(CoreError::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                    "failed to probe existing control socket {}; refusing to open state: {error}",
                    socket.display()
                ),
                )))
            }
        }
    }
    Ok(instance_lock)
}

/// Remove exactly the one line ending normally contributed by `echo`, a
/// terminal paste, or a heredoc. Environment and stdin inputs deliberately
/// share this rule; `--raw` preserves every byte.
fn normalize_secret_input(mut value: String, raw: bool) -> String {
    if raw {
        return value;
    }
    let trim = if value.ends_with("\r\n") {
        2
    } else if value.ends_with('\n') || value.ends_with('\r') {
        1
    } else {
        0
    };
    value.truncate(value.len() - trim);
    value
}

/// Read a secret value from `--value-env` or stdin — never argv, where it
/// would sit in `ps` output and shell history.
fn read_secret_value(value_env: &Option<String>, raw: bool) -> SecretValue {
    let value = match value_env {
        Some(var) => match std::env::var(var) {
            Ok(value) => value,
            Err(_) => die(format!("environment variable {var} is not set")),
        },
        None => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                guide("  reading the secret value from stdin; end with Ctrl-D");
            }
            match std::io::read_to_string(std::io::stdin()) {
                Ok(text) => text,
                Err(e) => die(format!("could not read the value from stdin: {e}")),
            }
        }
    };
    let value = Zeroizing::new(normalize_secret_input(value, raw));
    if value.is_empty() {
        die("the secret value is empty");
    }
    value
}

fn cmd_secret_add(
    name: String,
    value_env: Option<String>,
    raw: bool,
    root: Option<PathBuf>,
    create_root: bool,
    url: Option<String>,
) {
    let managed = management_backend_with_create(root, url, create_root);
    let value = read_secret_value(&value_env, raw);
    let byte_len = value.len();
    managed.run(managed.backend.add_secret(name.clone(), value));
    ack(format!("added secret {name} ({byte_len} bytes)"));
}

fn cmd_secret_list(root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let secrets = managed.run(managed.backend.list_secrets());
    if json {
        print_json(&secrets);
        return;
    }
    if secrets.is_empty() {
        ack_dim("no secrets configured (add one with `aka secret add <name>`)");
        return;
    }
    let rows = secrets.into_iter().map(|dto| {
        vec![
            dto.name,
            if dto.used_by_names.is_empty() {
                "—".into()
            } else {
                dto.used_by_names.join(", ")
            },
        ]
    });
    println!("{}", presentation::table(&["name", "used by"], rows));
}

/// A management backend plus the runtime driving it. Every mode routes
/// through the broker's own management layer — the same audit entries and
/// side effects as the app — the modes differ only in how calls reach it.
struct Managed {
    runtime: tokio::runtime::Runtime,
    backend: Arc<dyn ManagementBackend>,
    remote: Option<Arc<RemoteBackend>>,
    profile: Option<serde_json::Value>,
}

impl Managed {
    /// Run one management call to completion; a failure exits with the
    /// broker's own error line.
    fn run<T>(&self, call: impl std::future::Future<Output = ManageResult<T>>) -> T {
        match self.runtime.block_on(call) {
            Ok(value) => value,
            Err(e) => die_manage(e),
        }
    }

    /// Run a call whose failure must not end the command, because something
    /// durable already happened. Only [`cmd_conn_add`]'s post-add test uses
    /// this: the connection exists by then, so exiting nonzero would say it
    /// does not.
    fn try_run<T>(
        &self,
        call: impl std::future::Future<Output = ManageResult<T>>,
    ) -> Result<T, ManageError> {
        self.runtime.block_on(call)
    }

    /// A live desktop-owned broker may show a native confirmation outside
    /// this terminal. Make that wait visible before the request blocks.
    fn run_gated<T>(&self, call: impl std::future::Future<Output = ManageResult<T>>) -> T {
        if self.approval_surface_attached() {
            if presentation::stderr_is_tty() {
                let spinner =
                    presentation::Spinner::start("Waiting for confirmation in the Multitool app…");
                let value = self.run(call);
                spinner.stop("Confirmation received");
                return value;
            }
            guide("waiting for confirmation in the Multitool app…");
        }
        self.run(call)
    }

    fn approval_surface_attached(&self) -> bool {
        self.profile
            .as_ref()
            .and_then(|profile| profile["approval_surface_attached"].as_bool())
            .unwrap_or(false)
    }

    fn require_approval_surface(&self) {
        if self.remote.is_none() {
            die(
                "cannot enable traffic confirmation in an offline/headless edit: no approval \
                 surface is attached",
            );
        }
        if !self.approval_surface_attached() {
            die(
                "cannot enable traffic confirmation: no approval surface is attached; open the \
                 Multitool app and keep its request inbox connected, then retry",
            );
        }
    }
}

fn warn_version_skew(profile: &serde_json::Value) {
    let Some(broker_version) = profile["version"].as_str() else {
        return;
    };
    let cli_version = env!("CARGO_PKG_VERSION");
    if broker_version != cli_version {
        warn_line(format!(
            "warning: broker version {broker_version} differs from aka CLI version {cli_version}; \
             update them together before making changes"
        ));
    }
}

fn manage_token_store(paths: &Paths) -> TokenStore {
    TokenStore::new(paths.manage_tokens_dir())
}

/// Resolve the management token for `key` (a manage URL, or the local
/// socket path): the AKA_MANAGE_TOKEN environment variable wins, then the
/// token stored by `aka admin login`.
fn manage_token(paths: &Paths, key: &str) -> Option<Zeroizing<String>> {
    if let Ok(token) = std::env::var("AKA_MANAGE_TOKEN") {
        let token = Zeroizing::new(token);
        if !token.trim().is_empty() {
            return Some(Zeroizing::new(token.trim().to_string()));
        }
    }
    manage_token_store(paths).load(key)
}

/// Pick how a management command reaches its broker:
/// - `--url` → that broker's manage API over HTTP (a hosted broker, or a
///   local one serving `--listen`);
/// - no URL with a broker running on the socket → its manage API over the
///   Unix socket, so live edits need no stop/start. The management token
///   still authorizes every call: the 0600 socket is shared with agents,
///   which must never reach the manage plane;
/// - no broker running → construct the broker offline, as before.
fn management_backend(root: Option<PathBuf>, url: Option<String>) -> Managed {
    management_backend_with_create(root, url, false)
}

fn effective_broker_url(url: Option<String>) -> Option<String> {
    url.or_else(|| {
        std::env::var("AKA_BROKER_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
    })
}

fn management_backend_with_create(
    root: Option<PathBuf>,
    url: Option<String>,
    create_root: bool,
) -> Managed {
    let mut root = root;
    let mut url = effective_broker_url(url);
    if root.is_none() && url.is_none() {
        match ambient_context() {
            Some((source, ContextTarget::Root(path))) => {
                guide(format!("  managing the broker rooted at {} ({source})", path.display()));
                root = Some(path);
            }
            Some((_, ContextTarget::Broker(broker))) => url = Some(broker),
            Some((_, ContextTarget::Local)) | None => {}
        }
    }
    if !create_root {
        require_existing_root_for_read(root.as_deref(), url.is_some());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    if let Some(url) = url {
        let url = match RemoteConfig::normalize_url(&url) {
            Ok(url) => url,
            Err(e) => die_with(ExitCode::Usage, e),
        };
        let Some(token) = manage_token(&paths, &url) else {
            die_with(
                ExitCode::Authentication,
                format!(
                    "no management token for {url} — set AKA_MANAGE_TOKEN, or store \
                 one with `aka admin login --broker {url}` (issued by `aka \
                 admin token` on the broker host)"
                ),
            );
        };
        let config = match RemoteConfig::new(&url, &token) {
            Ok(config) => config,
            Err(e) => die_with(ExitCode::Usage, e),
        };
        guide(format!("  managing the broker at {url}"));
        let remote = Arc::new(RemoteBackend::new(config));
        let profile = runtime
            .block_on(remote.whoami())
            .unwrap_or_else(|error| die_manage(error));
        warn_version_skew(&profile);
        return Managed {
            runtime,
            backend: remote.clone(),
            remote: Some(remote),
            profile: Some(profile),
        };
    }
    let socket = paths.socket_file();
    let broker_running = runtime
        .block_on(tokio::net::UnixStream::connect(&socket))
        .is_ok();
    if broker_running {
        let key = socket.display().to_string();
        let Some(token) = manage_token(&paths, &key) else {
            die_with(
                ExitCode::Authentication,
                format!(
                    "a broker is running on {key}.\n\
                 To edit it live, run `aka admin token` to consume its \
                 first-start credential or rotate a saved token, store a token \
                 with `aka admin login`, or set AKA_MANAGE_TOKEN."
                ),
            );
        };
        guide(format!("  managing the running broker over {key}"));
        let remote = Arc::new(RemoteBackend::over_unix_socket(socket, &token));
        let profile = runtime
            .block_on(remote.whoami())
            .unwrap_or_else(|error| die_manage(error));
        warn_version_skew(&profile);
        return Managed {
            runtime,
            backend: remote.clone(),
            remote: Some(remote),
            profile: Some(profile),
        };
    }
    let vault = match open_vault(&paths, root.as_deref()) {
        Ok(vault) => vault,
        Err(e) => die(format!("could not open the secret vault: {e}")),
    };
    let events: Arc<dyn BrokerEvents> = Arc::new(OfflineEvents);
    let broker = match runtime.block_on(Broker::new_for_offline_management(
        paths.clone(),
        vault,
        BrokerConfig::default(),
        events,
    )) {
        Ok(broker) => broker,
        Err(CoreError::BrokerAlreadyRunning(_)) => die(format!(
            "a broker started on {} while this command was connecting — retry \
             to manage it live, or stop it for an offline edit",
            paths.socket_file().display()
        )),
        Err(CoreError::BrokerStateBusy(pid)) => die(format!(
            "another CLI process{} is editing this broker state — wait for it to finish, then retry",
            pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
        )),
        Err(e) => die(format!("could not open the broker state: {e}")),
    };
    Managed {
        runtime,
        backend: Arc::new(LocalBackend::new(broker)),
        remote: None,
        profile: None,
    }
}

struct OfflineEvents;
impl BrokerEvents for OfflineEvents {}

/// Parse an id the broker handed out; it minted it, so failure is a wire
/// bug worth naming, not a user error.
fn dto_id(id: &str) -> Uuid {
    id.parse()
        .unwrap_or_else(|_| die(format!("malformed id {id:?} from the broker")))
}

fn secret_dto(managed: &Managed, name: &str) -> SecretDto {
    let secrets = managed.run(managed.backend.list_secrets());
    match secrets.into_iter().find(|s| s.name == name) {
        Some(dto) => dto,
        None => die_with(
            ExitCode::NotFound,
            format!("no secret named {name:?} (see `aka secret list`)"),
        ),
    }
}

fn conn_dto(managed: &Managed, name: &str) -> ConnectionDto {
    let connections = managed.run(managed.backend.list_connections());
    match connections.into_iter().find(|c| c.name == name) {
        Some(dto) => dto,
        None => die_with(
            ExitCode::NotFound,
            format!("no connection named {name:?} (see `aka conn list`)"),
        ),
    }
}

fn cmd_secret_rename(name: String, new_name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = secret_dto(&managed, &name);
    managed.run(managed.backend.edit_secret(
        dto_id(&dto.id),
        aka_core::manage::SecretEditBody {
            new_name: Some(new_name.clone()),
            new_value: None,
            new_site: None,
            new_username: None,
            new_totp: None,
            new_origin: None,
        },
    ));
    ack(format!("renamed secret {name} → {new_name}"));
}

fn cmd_secret_rotate(
    name: String,
    value_env: Option<String>,
    raw: bool,
    root: Option<PathBuf>,
    url: Option<String>,
) {
    let value = read_secret_value(&value_env, raw);
    let byte_len = value.len();
    let managed = management_backend(root, url);
    let dto = secret_dto(&managed, &name);
    managed.run(managed.backend.edit_secret(
        dto_id(&dto.id),
        aka_core::manage::SecretEditBody {
            new_name: None,
            new_value: Some(value.to_string()),
            new_site: None,
            new_username: None,
            new_totp: None,
            new_origin: None,
        },
    ));
    ack(format!(
        "rotated the value of secret {name} ({byte_len} bytes)"
    ));
}

fn cmd_secret_rm(name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = secret_dto(&managed, &name);
    managed.run(managed.backend.delete_secret(dto_id(&dto.id)));
    ack(format!("deleted secret {name}"));
}

/// Add a connection and, unless `--no-test` says otherwise, verify it
/// against its pinned destination straight away. Returns the test's outcome
/// for the `--json` envelope, so one add stays one object on stdout.
fn cmd_conn_add(args: ConnAdd) -> Option<serde_json::Value> {
    let config = match conn_config(&args) {
        Ok(config) => config,
        Err(e) => die_with(ExitCode::Usage, e),
    };
    let managed =
        management_backend_with_create(args.root.clone(), args.broker.clone(), args.create_root);
    // pg/ssh bind at most one secret by name; api and cloud derive theirs
    // from template / provider refs inside add_connection.
    let secrets = match (&args.secret, args.kind) {
        (_, ConnKind::Api | ConnKind::Cloud) => Vec::new(),
        (Some(name), _) => {
            let known = managed.run(managed.backend.list_secrets());
            match known.into_iter().find(|s| s.name == *name) {
                Some(dto) => vec![dto_id(&dto.id)],
                None => die_with(
                    ExitCode::NotFound,
                    format!(
                        "no secret named {name:?} — add it first: \
                         `aka secret add {name}` (value read from stdin; \
                         see `aka secret list`)"
                    ),
                ),
            }
        }
        (None, _) => Vec::new(),
    };
    let name = args.name.clone();
    managed.run_gated(managed.backend.add_connection(ConnectionSpec {
        name: name.clone(),
        config,
        secrets,
    }));
    let dto = conn_dto(&managed, &name);
    ack(format!(
        "added connection {} ({} · {})",
        dto.name, dto.kind, dto.target
    ));
    let report = (!args.no_test).then(|| {
        let spinner = presentation::Spinner::start_if(
            !JSON_OUTPUT.load(Ordering::Relaxed),
            "Testing the connection…",
        );
        // The connection exists by now, so nothing here may end the command:
        // a nonzero exit after a durable mutation would say the add did not
        // happen. Both a failed test and a broker that could not run one are
        // reported and handed back, never fatal.
        let outcome = managed.try_run(managed.backend.test_connection(dto_id(&dto.id)));
        spinner.stop("Connection test complete");
        let color = stderr_use_color();
        let (ok, detail) = match outcome {
            Ok(report) => (report.ok, report.detail),
            Err(error) => (false, format!("could not run the test: {error}")),
        };
        if ok {
            ack(format!("test: {detail}"));
        } else {
            eprintln!("{} {detail}", paint::bold_yellow(color, "test failed:"));
            guide(format!(
                "the connection was added; fix the destination or credential, \
                 then `aka conn test {name}`"
            ));
        }
        serde_json::json!({ "ok": ok, "detail": detail })
    });
    if let Some(report) = &report {
        if report["ok"] == serde_json::json!(true) {
            ack_dim(conn_add_next_step(&args));
        }
    } else {
        ack_dim(conn_add_next_step(&args));
    }
    report
}

/// The natural next command after a successful add, concrete enough to
/// paste. Usage commands only reach a broker on this machine, so a
/// `--broker` add points at `conn test` instead of `dsn`/`ssh`/`cloud`.
fn conn_add_next_step(args: &ConnAdd) -> String {
    let name = &args.name;
    if let Some(url) = &args.broker {
        return format!("try: aka conn test {name} --broker {url}");
    }
    let root = args
        .root
        .as_ref()
        .map(|root| format!(" --root {}", shell_quote(&root.display().to_string())))
        .unwrap_or_default();
    match args.kind {
        ConnKind::Api => format!("try: aka conn test {name}{root}"),
        ConnKind::Pg => format!("try: aka run {name}{root} -- psql"),
        ConnKind::Ssh => format!("try: aka run {name}{root} -- ssh {name}"),
        ConnKind::Cloud => match args.cloud_provider.as_deref() {
            Some("aws") => {
                format!("try: aka run {name}{root} -- aws sts get-caller-identity")
            }
            Some("gcp") => format!("try: aka run {name}{root} -- gcloud storage ls"),
            _ => format!("try: aka env {name}{root}"),
        },
    }
}

/// Build the type-specific config, naming exactly which flag is missing or
/// stray for the kind; the deep validation (hosts, schemes, template refs)
/// stays in the store, one place.
fn conn_config(args: &ConnAdd) -> Result<ConnectionConfig, String> {
    let require = |flag: &str, value: &Option<String>| -> Result<String, String> {
        value
            .clone()
            .ok_or_else(|| format!("--{flag} is required for this kind"))
    };
    let forbid = |present: &[(&str, bool)]| -> Result<(), String> {
        match present.iter().find(|(_, given)| *given) {
            Some((flag, _)) => Err(format!("--{flag} does not apply to this kind")),
            None => Ok(()),
        }
    };
    match args.kind {
        ConnKind::Api => {
            forbid(&[
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("secret", args.secret.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            let signer = match (&args.sigv4_region, &args.gcp_key_ref) {
                (Some(_), _) | (_, Some(_)) if args.template.is_some() => {
                    return Err(
                        "--template does not apply to a signed connection; the signer \
                         computes the Authorization header"
                            .into(),
                    );
                }
                (Some(region), _) => Some(SignerSpec::AwsSigv4 {
                    region: region.clone(),
                    service: require("sigv4-service", &args.sigv4_service)?,
                    access_key_ref: require("sigv4-access-key-ref", &args.sigv4_access_key_ref)?,
                    secret_key_ref: require("sigv4-secret-key-ref", &args.sigv4_secret_key_ref)?,
                    session_token_ref: args.sigv4_session_token_ref.clone(),
                }),
                (_, Some(key_ref)) => Some(SignerSpec::GcpServiceAccount {
                    key_ref: key_ref.clone(),
                    scope: require("gcp-scope", &args.gcp_scope)?,
                }),
                (None, None) => None,
            };
            // Host before template, so a bare `--kind api` still names
            // `--host` as the first thing missing.
            let host = require("host", &args.host)?;
            let template = if signer.is_some() {
                String::new()
            } else {
                require("template", &args.template)?
            };
            Ok(ConnectionConfig::Api {
                host,
                scheme: args.scheme.clone().unwrap_or_else(|| "https".into()),
                port: args.port,
                trusted_ca_bundle_path: args.ca_bundle.clone(),
                template,
                mcp_path: args.mcp_path.clone(),
                test_path: args.test_path.clone(),
                oauth: None,
                signer,
                client_cert_path: args.client_cert.clone(),
                client_key_path: args.client_key.clone(),
            })
        }
        ConnKind::Pg => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
                ("mcp-path", args.mcp_path.is_some()),
                ("test-path", args.test_path.is_some()),
            ])?;
            require("secret", &args.secret)?;
            Ok(ConnectionConfig::Pg {
                host: require("host", &args.host)?,
                port: args.port.unwrap_or(5432),
                dbname: require("dbname", &args.dbname)?,
                user: require("user", &args.user)?,
                sslmode: parse_sslmode(args.sslmode.as_deref())?,
                trusted_ca_bundle_path: args.ca_bundle.clone(),
            })
        }
        ConnKind::Ssh => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("dbname", args.dbname.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
                ("mcp-path", args.mcp_path.is_some()),
                ("test-path", args.test_path.is_some()),
                ("cloud-provider", args.cloud_provider.is_some()),
            ])?;
            require("secret", &args.secret)?;
            Ok(ConnectionConfig::Ssh {
                destination: None,
                host: require("host", &args.host)?,
                port: args.port.unwrap_or(22),
                user: require("user", &args.user)?,
                // Empty = unpinned; the broker pins the observed key at the
                // first agent connection after a trust prompt.
                host_key_fingerprint: args.host_key_fingerprint.clone().unwrap_or_default(),
            })
        }
        ConnKind::Cloud => {
            forbid(&[
                ("host", args.host.is_some()),
                ("scheme", args.scheme.is_some()),
                ("port", args.port.is_some()),
                ("template", args.template.is_some()),
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("secret", args.secret.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
                ("mcp-path", args.mcp_path.is_some()),
                ("test-path", args.test_path.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
                ("sigv4-region", args.sigv4_region.is_some()),
                ("gcp-key-ref", args.gcp_key_ref.is_some()),
                ("client-cert", args.client_cert.is_some()),
            ])?;
            let provider = require("cloud-provider", &args.cloud_provider)?;
            let ttl = args
                .cloud_session_ttl
                .unwrap_or(aka_core::types::DEFAULT_CLOUD_SESSION_TTL_SECS);
            match provider.as_str() {
                "aws" => Ok(ConnectionConfig::Cloud {
                    provider: aka_core::types::CloudProvider::Aws {
                        region: require("cloud-region", &args.cloud_region)?,
                        access_key_ref: require(
                            "cloud-access-key-ref",
                            &args.cloud_access_key_ref,
                        )?,
                        secret_key_ref: require(
                            "cloud-secret-key-ref",
                            &args.cloud_secret_key_ref,
                        )?,
                        session_token_ref: args.cloud_session_token_ref.clone(),
                        role_arn: args.cloud_role_arn.clone(),
                        external_id: args.cloud_external_id.clone(),
                        session_ttl_secs: ttl,
                    },
                }),
                "azure" => Ok(ConnectionConfig::Cloud {
                    provider: aka_core::types::CloudProvider::Azure {
                        tenant_id: require("cloud-tenant-id", &args.cloud_tenant_id)?,
                        client_id: require("cloud-client-id", &args.cloud_client_id)?,
                        client_secret_ref: require(
                            "cloud-client-secret-ref",
                            &args.cloud_client_secret_ref,
                        )?,
                        subscription_id: args.cloud_subscription_id.clone(),
                        scope: args
                            .cloud_scope
                            .clone()
                            .unwrap_or_else(|| "https://management.azure.com/.default".into()),
                        session_ttl_secs: ttl,
                    },
                }),
                "gcp" => Ok(ConnectionConfig::Cloud {
                    provider: aka_core::types::CloudProvider::Gcp {
                        key_ref: require("cloud-gcp-key-ref", &args.cloud_gcp_key_ref)?,
                        scope: require("cloud-scope", &args.cloud_scope)?,
                        project: args.cloud_project.clone(),
                        session_ttl_secs: ttl,
                    },
                }),
                other => Err(format!(
                    "unknown cloud provider {other:?} (supported: aws, azure, gcp)"
                )),
            }
        }
    }
}

fn parse_sslmode(value: Option<&str>) -> Result<PgSslMode, String> {
    Ok(match value {
        None => PgSslMode::default(),
        Some("disable") => PgSslMode::Disable,
        Some("prefer") => PgSslMode::Prefer,
        Some("require") => PgSslMode::Require,
        Some("verify-ca") => PgSslMode::VerifyCa,
        Some("verify-full") => PgSslMode::VerifyFull,
        Some(other) => {
            return Err(format!(
                "unknown sslmode {other:?} (disable | prefer | require | \
                 verify-ca | verify-full)"
            ))
        }
    })
}

/// Listing what agents can reach is the first thing a teammate does after
/// `aka login`, and at that point they hold only the agent key. The
/// management plane carries more (endpoints, health), so it stays the
/// default; when the context is remote and no management token exists, fall
/// back to the catalog the agent plane already serves rather than refusing
/// the daily loop's opening move.
fn cmd_conn_list_agent_plane(json: bool) -> bool {
    if effective_broker_url(None).is_some() {
        return false;
    }
    let Some((_, ContextTarget::Broker(url))) = ambient_context() else {
        return false;
    };
    let url = url.trim_end_matches('/').to_string();
    if manage_token(&store_paths(None), &url).is_some() {
        return false;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let agent = usage_agent(None);
    let body = match runtime.block_on(agent.agent_get("/v1/connections", None)) {
        Ok(body) => body,
        Err(error) => die_with(open_session_exit_code(&error), error),
    };
    let list = body.as_array().cloned().unwrap_or_default();
    if json {
        print_json(&body);
        return true;
    }
    if list.is_empty() {
        ack_dim(format!("no connections are configured on {url}"));
        return true;
    }
    let rows = list
        .iter()
        .map(|row| {
            let mut state = Vec::new();
            if row["wired"].as_bool() != Some(true) {
                state.push("disabled");
            }
            if row["confirm"].as_bool() == Some(true) {
                state.push("confirm: on");
            }
            vec![
                row["name"].as_str().unwrap_or_default().to_string(),
                row["type"].as_str().unwrap_or_default().to_string(),
                row["target"].as_str().unwrap_or_default().to_string(),
                if state.is_empty() {
                    "enabled".to_string()
                } else {
                    state.join(", ")
                },
            ]
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        presentation::table(&["name", "kind", "target", "access"], rows)
    );
    guide(format!(
        "the agent view of {url}; endpoints and health need its management \
         token (`aka admin login --broker {url}`)"
    ));
    true
}

fn cmd_conn_list(root: Option<PathBuf>, url: Option<String>, json: bool) {
    if root.is_none() && url.is_none() && cmd_conn_list_agent_plane(json) {
        return;
    }
    let managed = management_backend(root, url);
    let connections = managed.run(managed.backend.list_connections());
    if json {
        print_json(&connections);
        return;
    }
    if connections.is_empty() {
        ack_dim("no connections configured (add one with `aka conn add`)");
        return;
    }
    let rows = connections.into_iter().map(|dto| {
        let mut state = Vec::new();
        if !dto.agent_access.enabled {
            state.push("disabled");
        }
        if dto.agent_access.confirm {
            state.push(if managed.approval_surface_attached() {
                "confirm: on"
            } else {
                "confirm: on (no approval surface attached — traffic will be refused)"
            });
        }
        if dto.agent_access.expose_response_credentials {
            state.push("response credentials: exposed");
        }
        vec![
            dto.name,
            dto.kind,
            dto.target,
            if state.is_empty() {
                "enabled".into()
            } else {
                state.join(" · ")
            },
        ]
    });
    println!(
        "{}",
        presentation::table(&["name", "kind", "target", "access"], rows)
    );
}

fn cmd_conn_show(name: String, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    if json {
        print_json(&dto);
        return;
    }
    let color = stdout_use_color();
    println!("{}", colon_field(color, "", "name", &dto.name));
    println!("{}", colon_field(color, "", "type", &dto.kind));
    println!("{}", colon_field(color, "", "target", &dto.target));
    println!(
        "{}",
        colon_field(
            color,
            "",
            "credentials",
            if dto.secret_names.is_empty() {
                "none".into()
            } else {
                dto.secret_names.join(", ")
            }
        )
    );
    let access = if dto.agent_access.enabled {
        paint::bold_green(color, "enabled")
    } else {
        paint::bold_yellow(color, "disabled")
    };
    println!("{}", colon_field(color, "", "agent access", access));
    let confirmation = if dto.agent_access.confirm {
        paint::bold_yellow(color, "on")
    } else {
        "off".to_string()
    };
    println!("{}", colon_field(color, "", "confirmation", confirmation));
    if let Some(until) = &dto.agent_access.confirm_window_until {
        let agents = if dto.agent_access.confirm_window_agents.is_empty() {
            "unknown agent".into()
        } else {
            dto.agent_access.confirm_window_agents.join(", ")
        };
        println!(
            "{}",
            colon_field(
                color,
                "",
                "confirmation window",
                format!("until {until} for {agents}")
            )
        );
    }
    if let Some(until) = &dto.agent_access.confirm_cooldown_until {
        println!(
            "{}",
            colon_field(color, "", "denial cooldown", format!("until {until}"))
        );
    }
    if dto.kind == "api" {
        let creds = if dto.agent_access.expose_response_credentials {
            "exposed to agents"
        } else {
            "contained"
        };
        println!(
            "{}",
            colon_field(color, "", "upstream response credentials", creds)
        );
    }
    println!(
        "{}",
        colon_field(
            color,
            "",
            "allowed MCP tools",
            dto.agent_access
                .allowed_tools
                .as_ref()
                .map(|tools| {
                    if tools.is_empty() {
                        "none".into()
                    } else {
                        tools.join(", ")
                    }
                })
                .unwrap_or_else(|| "all".into())
        )
    );
    match &dto.agent_access.endpoint {
        Some(endpoint) => {
            let expiry = if endpoint.expires_at.is_empty() {
                String::new()
            } else {
                format!(", expires {}", endpoint.expires_at)
            };
            println!(
                "{}",
                colon_field(
                    color,
                    "",
                    "direct endpoint",
                    format!(
                        "{} ({}){}{}",
                        endpoint
                            .dsn
                            .as_deref()
                            .unwrap_or("issued; use `aka endpoint` to copy"),
                        endpoint.kind,
                        // Whether the socket is a standing signing oracle for anything
                        // that can open it is the most consequential fact about an SSH
                        // endpoint, so it belongs on the line that reports one.
                        if endpoint.require_auth {
                            ", authenticated"
                        } else {
                            ""
                        },
                        expiry,
                    )
                )
            );
        }
        None => println!("{}", colon_field(color, "", "direct endpoint", "none")),
    }
    match (&dto.last_status, &dto.last_detail, &dto.last_checked_at) {
        (Some(status), detail, checked) => {
            let health = if status == "ok" {
                paint::bold_green(color, status)
            } else {
                paint::bold_yellow(color, status)
            };
            println!("{}", colon_field(color, "", "health", health));
            if let Some(detail) = detail {
                println!("{}", colon_field(color, "", "health detail", detail));
            }
            if let Some(checked) = checked {
                println!("{}", colon_field(color, "", "last checked", checked));
            }
        }
        _ => println!("{}", colon_field(color, "", "health", "untested")),
    }
}

fn cmd_sessions(close: Option<u64>, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    if let Some(id) = close {
        let closed = managed.run(managed.backend.close_session(id));
        if !closed {
            die_with(ExitCode::NotFound, format!("no live session with id {id}"));
        }
        if json {
            print_json(&serde_json::json!({ "closed": true, "id": id }));
        } else {
            ack(format!("closed session {id}"));
        }
        return;
    }
    let sessions = managed.run(managed.backend.sessions());
    if json {
        print_json(&sessions);
    } else if sessions.is_empty() {
        ack_dim("no live sessions");
    } else {
        let rows = sessions.into_iter().map(|session| {
            vec![
                session.id.to_string(),
                session.kind,
                session.connection,
                session.agent,
                session.detail,
            ]
        });
        println!(
            "{}",
            presentation::table(&["id", "kind", "connection", "agent", "detail"], rows)
        );
    }
}

fn cmd_requests(
    watch: bool,
    approve: Option<Uuid>,
    deny: Option<Uuid>,
    values: Vec<String>,
    root: Option<PathBuf>,
    url: Option<String>,
    json: bool,
) {
    let managed = management_backend(root, url);
    if watch {
        if json {
            die_with(
                ExitCode::Usage,
                "--json cannot be combined with the unbounded --watch mode",
            );
        }
        watch_requests(&managed);
        return;
    }
    if let Some(id) = approve.or(deny) {
        answer_request(&managed, id, approve.is_some(), values, json);
        return;
    }
    let requests = managed.run(managed.backend.requests());
    if json {
        print_json(&requests);
    } else if requests.is_empty() {
        ack_dim("no pending or recent requests");
    } else {
        let rows = requests.into_iter().map(|request| {
            let at = request
                .resolved_at
                .as_deref()
                .unwrap_or(&request.requested_at)
                .to_string();
            vec![
                at,
                request.status,
                request.kind,
                request.connection,
                request.agent,
                request.summary,
            ]
        });
        println!(
            "{}",
            presentation::table(
                &["at", "status", "kind", "connection", "agent", "summary"],
                rows,
            )
        );
    }
}

fn answer_request(managed: &Managed, id: Uuid, approve: bool, values: Vec<String>, json: bool) {
    let Some(remote) = managed.remote.clone() else {
        die_with(
            ExitCode::NoBroker,
            "request decisions require a running broker",
        );
    };
    let surface = managed.run(remote.open_approval_surface());
    let surface_id = dto_id(&surface.id);

    let approvals = managed.run(managed.backend.approvals());
    let elicitations = managed.run(managed.backend.elicitations());
    let answered = if approvals.iter().any(|request| request.id == id.to_string()) {
        if !values.is_empty() {
            let _ = managed.run(remote.close_approval_surface(surface_id));
            die_with(
                ExitCode::Usage,
                "--value applies only when approving an elicitation",
            );
        }
        managed.run(managed.backend.respond_approval(
            id,
            if approve {
                aka_api::ApprovalDecisionDto::ApproveWindow
            } else {
                aka_api::ApprovalDecisionDto::Deny
            },
        ))
    } else if elicitations
        .iter()
        .any(|request| request.id == id.to_string())
    {
        let mut fields = std::collections::HashMap::new();
        if approve {
            for value in values {
                let (name, value) = value.split_once('=').expect("validated by clap");
                if fields.insert(name.to_string(), value.to_string()).is_some() {
                    let _ = managed.run(remote.close_approval_surface(surface_id));
                    die_with(
                        ExitCode::Usage,
                        format!("elicitation field {name:?} was supplied more than once"),
                    );
                }
            }
        }
        managed.run(managed.backend.respond_elicitation(id, approve, fields))
    } else {
        let _ = managed.run(remote.close_approval_surface(surface_id));
        die_with(
            ExitCode::NotFound,
            format!("no pending approval or elicitation with id {id}"),
        );
    };
    let _ = managed.run(remote.close_approval_surface(surface_id));
    if !answered {
        die_with(
            ExitCode::Conflict,
            format!("request {id} was already answered, revoked, or expired"),
        );
    }
    let decision = if approve { "approved" } else { "denied" };
    if json {
        print_json(&serde_json::json!({
            "answered": true,
            "id": id,
            "decision": decision,
        }));
    } else {
        ack(format!("{decision} request {id}"));
    }
}

fn watch_requests(managed: &Managed) {
    let Some(remote) = managed.remote.clone() else {
        die_with(
            ExitCode::NoBroker,
            "the request inbox requires a running broker",
        );
    };
    let surface = managed.run(remote.open_approval_surface());
    let surface_id = dto_id(&surface.id);
    guide(
        "request inbox attached; press Ctrl-C to detach\n\
         answer from another terminal with `aka approve <id>` or `aka deny <id>`",
    );

    let backend = managed.backend.clone();
    let result: ManageResult<()> = managed.runtime.block_on(async {
        let mut seen = std::collections::HashSet::new();
        let mut poll = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_millis(
            aka_api::APPROVAL_SURFACE_HEARTBEAT_MS,
        ));
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);
        // The lease minted above covers startup; do not immediately issue a
        // redundant heartbeat.
        poll.tick().await;
        heartbeat.tick().await;
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = heartbeat.tick() => remote.renew_approval_surface(surface_id).await?,
                _ = poll.tick() => {
                    for request in backend.approvals().await? {
                        if seen.insert(request.id.clone()) {
                            println!(
                                "{}  approval  {}  {}  {}",
                                request.id, request.connection, request.agent, request.summary
                            );
                            if let Some(detail) = request.detail {
                                println!("  {detail}");
                            }
                            if let Some(consequence) = request.consequence {
                                println!("  {consequence}");
                            }
                        }
                    }
                    for request in backend.elicitations().await? {
                        if seen.insert(request.id.clone()) {
                            println!(
                                "{}  elicitation  {}  {}  {}",
                                request.id, request.connection, request.agent, request.prompt
                            );
                            for field in request.fields {
                                let required = if field.required { " (required)" } else { "" };
                                println!("  {}{required}", field.name);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    });
    let _ = managed.run(remote.close_approval_surface(surface_id));
    if let Err(error) = result {
        die_manage(error);
    }
    ack_dim("request inbox detached");
}

fn cmd_settings_get(root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let settings = managed.run(managed.backend.settings());
    if json {
        print_json(&settings);
    } else {
        println!("menu bar hides Dock: {}", settings.menu_bar_hides_dock);
        println!(
            "confirm new SSH host keys: {}",
            settings.confirm_ssh_host_keys
        );
    }
}

fn cmd_settings_set(
    menu_bar_hides_dock: Option<bool>,
    confirm_ssh_host_keys: Option<bool>,
    root: Option<PathBuf>,
    url: Option<String>,
    json: bool,
) {
    if menu_bar_hides_dock.is_none() && confirm_ssh_host_keys.is_none() {
        die_with(
            ExitCode::Usage,
            "settings set requires at least one setting flag",
        );
    }
    let managed = management_backend(root, url);
    if let Some(on) = menu_bar_hides_dock {
        managed.run_gated(managed.backend.set_menu_bar_hides_dock(on));
    }
    if let Some(on) = confirm_ssh_host_keys {
        if on {
            managed.require_approval_surface();
        }
        managed.run_gated(managed.backend.set_confirm_ssh_host_keys(on));
    }
    let settings = managed.run(managed.backend.settings());
    if json {
        print_json(&settings);
    } else {
        ack("settings updated");
        println!("menu bar hides Dock: {}", settings.menu_bar_hides_dock);
        println!(
            "confirm new SSH host keys: {}",
            settings.confirm_ssh_host_keys
        );
    }
}

/// The CLI deliberately leaves OAuth-managed capability coordinates to the
/// broker/app flow. Ordinary updates below are field patches, never a
/// reconstruction of the complete config.
fn refuse_oauth_managed(dto: &ConnectionDto) {
    if dto.oauth || dto.oauth_spec.is_some() {
        die(format!(
            "{} is an OAuth-managed connection; edit it in the Multitool app",
            dto.name
        ));
    }
}

/// Build a patch containing only flags the caller supplied. The broker merges
/// it into authoritative state after checking `updated_at`, so fields unknown
/// to this CLI version cannot be reset.
fn connection_config_patch(
    dto: &ConnectionDto,
    args: &ConnUpdate,
    secret_id: Option<Uuid>,
) -> Result<ConnectionConfigPatch, String> {
    let forbid = |present: &[(&str, bool)]| -> Result<(), String> {
        match present.iter().find(|(_, given)| *given) {
            Some((flag, _)) => Err(format!("--{flag} does not apply to this connection's kind")),
            None => Ok(()),
        }
    };
    if args.host.is_none()
        && args.scheme.is_none()
        && args.port.is_none()
        && args.template.is_none()
        && args.dbname.is_none()
        && args.user.is_none()
        && args.host_key_fingerprint.is_none()
        && args.secret.is_none()
        && args.sslmode.is_none()
        && args.ca_bundle.is_none()
        && args.test_path.is_none()
    {
        return Err("conn update requires at least one field flag".into());
    }
    if args.port == Some(0) {
        return Err("--port must be 1–65535".into());
    }
    let (trusted_ca_bundle_path, clear_trusted_ca_bundle) = match &args.ca_bundle {
        Some(path) if path.is_empty() => (None, true),
        Some(path) => (Some(path.clone()), false),
        None => (None, false),
    };
    // An empty string clears, matching --ca-bundle and --host-key-fingerprint.
    let (test_path, clear_test_path) = match &args.test_path {
        Some(path) if path.is_empty() => (None, true),
        Some(path) => (Some(path.clone()), false),
        None => (None, false),
    };
    let patch = ConnectionConfigPatch {
        host: args.host.clone(),
        scheme: args.scheme.clone(),
        port: args.port,
        template: args.template.clone(),
        dbname: args.dbname.clone(),
        user: args.user.clone(),
        sslmode: match args.sslmode.as_deref() {
            Some(value) => Some(parse_sslmode(Some(value))?),
            None => None,
        },
        trusted_ca_bundle_path,
        clear_trusted_ca_bundle,
        host_key_fingerprint: args.host_key_fingerprint.clone(),
        test_path,
        clear_test_path,
        secret_id,
    };
    match dto.kind.as_str() {
        "api" => {
            forbid(&[
                ("dbname", args.dbname.is_some()),
                ("user", args.user.is_some()),
                ("secret", args.secret.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
            ])?;
            Ok(patch)
        }
        "pg" => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("host-key-fingerprint", args.host_key_fingerprint.is_some()),
                ("test-path", args.test_path.is_some()),
            ])?;
            Ok(patch)
        }
        "ssh" => {
            forbid(&[
                ("scheme", args.scheme.is_some()),
                ("template", args.template.is_some()),
                ("dbname", args.dbname.is_some()),
                ("sslmode", args.sslmode.is_some()),
                ("ca-bundle", args.ca_bundle.is_some()),
                ("test-path", args.test_path.is_some()),
            ])?;
            Ok(patch)
        }
        other => Err(format!("unknown connection kind {other:?}")),
    }
}

fn cmd_conn_update(expected_kind: ConnKind, args: ConnUpdate) {
    let managed = management_backend(args.root.clone(), args.broker.clone());
    let dto = conn_dto(&managed, &args.name);
    if dto.kind != expected_kind.as_str() {
        die_with(
            ExitCode::Usage,
            format!(
                "{} is a {} connection; use `aka conn update {} {}`",
                dto.name, dto.kind, dto.kind, dto.name
            ),
        );
    }
    refuse_oauth_managed(&dto);
    let secret_id = match (&args.secret, dto.kind.as_str()) {
        (Some(name), "pg" | "ssh") => Some(dto_id(&secret_dto(&managed, name).id)),
        _ => None,
    };
    let patch = match connection_config_patch(&dto, &args, secret_id) {
        Ok(patch) => patch,
        Err(e) => die_with(ExitCode::Usage, e),
    };
    managed.run_gated(managed.backend.patch_connection(
        dto_id(&dto.id),
        dto.updated_at.clone(),
        patch,
    ));
    let updated = conn_dto(&managed, &dto.name);
    ack(format!(
        "updated connection {} ({} · {})",
        updated.name, updated.kind, updated.target
    ));
    if updated.target != dto.target {
        warn_line("  target changed: its direct endpoints are revoked");
    }
}

fn cmd_conn_rename(name: String, new_name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    managed.run(managed.backend.rename_connection(
        dto_id(&dto.id),
        dto.updated_at,
        new_name.clone(),
    ));
    ack(format!("renamed connection {name} → {new_name}"));
}

fn cmd_conn_rm(name: String, root: Option<PathBuf>, url: Option<String>) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    managed.run(managed.backend.delete_connection(dto_id(&dto.id)));
    ack(format!(
        "deleted connection {name} (its secrets stay in the vault)"
    ));
}

fn cmd_conn_access(name: String, root: Option<PathBuf>, url: Option<String>, enabled: bool) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    let state = if enabled { "enabled" } else { "disabled" };
    let changed = managed.run(managed.backend.set_tool_access(dto_id(&dto.id), enabled));
    if changed {
        ack(format!("agent access {state} for {name}"));
    } else {
        ack_dim(format!("agent access was already {state} for {name}"));
    }
}

/// The policy path of `conn update <name>`: apply each requested toggle in
/// sequence through the same handlers the former per-policy commands used.
fn cmd_conn_policy(args: ConnPolicyArgs, json: bool) {
    let Some(name) = args.name else {
        die_with(
            ExitCode::Usage,
            "name a connection: `aka conn update <name> --confirm`, or update \
             capability fields with `aka conn update <kind> <name> …`",
        );
    };
    let changes = usize::from(args.confirm || args.no_confirm)
        + usize::from(args.response_credentials.is_some())
        + usize::from(args.audit_statements.is_some());
    if changes == 0 {
        die_with(
            ExitCode::Usage,
            format!(
                "nothing to change for {name} — pass --confirm/--no-confirm, \
                 --response-credentials <allow|contain>, or --audit-statements \
                 <on|off|default>; capability fields go through \
                 `aka conn update <kind> {name} …`"
            ),
        );
    }
    if json && changes > 1 {
        die_with(
            ExitCode::Usage,
            "--json takes one policy change per invocation, so the envelope \
             names the action",
        );
    }
    if args.confirm || args.no_confirm {
        let on = args.confirm;
        let result = serde_json::json!({ "name": name, "confirm": on });
        cmd_conn_confirm(name.clone(), args.root.clone(), args.broker.clone(), on);
        mutation_ok("conn.confirm", result);
    }
    if let Some(mode) = args.response_credentials {
        cmd_conn_response_credentials(
            name.clone(),
            args.root.clone(),
            args.broker.clone(),
            mode == ResponseCredentialsMode::Allow,
            mode == ResponseCredentialsMode::Contain,
            json,
        );
    }
    if let Some(mode) = args.audit_statements {
        cmd_conn_audit_statements(
            name,
            args.root,
            args.broker,
            mode == AuditStatementsMode::On,
            mode == AuditStatementsMode::Off,
            mode == AuditStatementsMode::Default,
            json,
        );
    }
}

fn cmd_conn_confirm(name: String, root: Option<PathBuf>, url: Option<String>, on: bool) {
    let managed = management_backend(root, url);
    if on {
        managed.require_approval_surface();
    }
    let dto = conn_dto(&managed, &name);
    let state = if on { "on" } else { "off" };
    let changed = if on {
        managed.run(managed.backend.set_confirm_mode(dto_id(&dto.id), on))
    } else {
        managed.run_gated(managed.backend.set_confirm_mode(dto_id(&dto.id), on))
    };
    if changed {
        ack(format!("traffic confirmation {state} for {name}"));
        if on {
            warn_line(
                "  prompts are answered in the Multitool app; without it, this tool's traffic is refused",
            );
        }
    } else {
        ack_dim(format!(
            "traffic confirmation was already {state} for {name}"
        ));
    }
}

fn cmd_conn_response_credentials(
    name: String,
    root: Option<PathBuf>,
    url: Option<String>,
    allow: bool,
    contain: bool,
    json: bool,
) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    if dto.kind != "api" {
        die_with(
            ExitCode::Usage,
            format!(
                "{name} is a {} connection; upstream response credentials apply to API connections",
                dto.kind
            ),
        );
    }
    if !allow && !contain {
        let exposed = dto.agent_access.expose_response_credentials;
        if json {
            print_json(&serde_json::json!({
                "name": name,
                "expose_response_credentials": exposed,
            }));
        } else {
            println!(
                "{}",
                if exposed {
                    "exposed to agents"
                } else {
                    "contained"
                }
            );
        }
        return;
    }

    let expose = allow;
    let changed = if expose {
        managed.run_gated(
            managed
                .backend
                .set_expose_response_credentials(dto_id(&dto.id), true),
        )
    } else {
        managed.run(
            managed
                .backend
                .set_expose_response_credentials(dto_id(&dto.id), false),
        )
    };
    let state = if expose {
        "exposed to agents"
    } else {
        "contained"
    };
    if changed {
        ack(format!(
            "upstream response credentials are now {state} for {name}"
        ));
        if expose {
            warn_line(
                "  warning: Set-Cookie and authentication response headers can now reach agents",
            );
        }
    } else {
        ack_dim(format!(
            "upstream response credentials were already {state} for {name}"
        ));
    }
    mutation_ok(
        "conn.response-credentials",
        serde_json::json!({
            "name": name,
            "expose_response_credentials": expose,
            "changed": changed,
        }),
    );
}

fn cmd_conn_audit_statements(
    name: String,
    root: Option<PathBuf>,
    url: Option<String>,
    on: bool,
    off: bool,
    default: bool,
    json: bool,
) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    if dto.kind != "pg" {
        die_with(
            ExitCode::Usage,
            format!(
                "{name} is a {} connection; statement recording applies to Postgres",
                dto.kind
            ),
        );
    }
    let requested = match (on, off, default) {
        (true, _, _) => Some(Some(true)),
        (_, true, _) => Some(Some(false)),
        (_, _, true) => Some(None),
        _ => None,
    };
    let Some(requested) = requested else {
        // No flag: report rather than change, so the effective state is
        // readable without guessing at the broker's launch flags.
        let source = match dto.agent_access.audit_statements {
            Some(_) => "set on this tool",
            None => "inherited from the broker default",
        };
        if json {
            print_json(&serde_json::json!({
                "name": name,
                "audit_statements": dto.agent_access.audit_statements,
                "audit_statements_effective": dto.agent_access.audit_statements_effective,
                "source": source,
            }));
        } else {
            println!(
                "statement recording is {} for {name} ({source})",
                if dto.agent_access.audit_statements_effective {
                    "on"
                } else {
                    "off"
                }
            );
        }
        return;
    };
    let changed = managed.run(
        managed
            .backend
            .set_audit_statements(dto_id(&dto.id), requested),
    );
    let updated = conn_dto(&managed, &name);
    let state = if updated.agent_access.audit_statements_effective {
        "on"
    } else {
        "off"
    };
    if changed {
        ack(format!("statement recording {state} for {name}"));
        if updated.agent_access.audit_statements_effective {
            warn_line(
                "  statement text can carry credentials and personal data into the activity log",
            );
        }
    } else {
        ack_dim(format!(
            "statement recording was already {state} for {name}"
        ));
    }
    mutation_ok(
        "conn.audit-statements",
        serde_json::json!({
            "name": name,
            "audit_statements": updated.agent_access.audit_statements,
            "audit_statements_effective": updated.agent_access.audit_statements_effective,
            "changed": changed,
        }),
    );
}

fn cmd_conn_test(name: String, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let managed = management_backend(root, url);
    let dto = conn_dto(&managed, &name);
    let message = if managed.approval_surface_attached() {
        "Waiting for confirmation, then testing the connection…"
    } else {
        "Testing the connection…"
    };
    if !json && !presentation::stderr_is_tty() {
        guide(message);
    }
    let spinner = presentation::Spinner::start_if(!json, message);
    let report = managed.run(managed.backend.test_connection(dto_id(&dto.id)));
    spinner.stop("Connection test complete");
    if json {
        print_json(&report);
    }
    if report.ok {
        if !json {
            let color = stderr_use_color();
            eprintln!("{} {}", paint::bold_green(color, "ok:"), report.detail);
        }
    } else {
        if !json {
            let color = stderr_use_color();
            let prefix = match report.kind {
                Some(kind) => format!("failed ({kind:?}):"),
                None => "failed:".into(),
            };
            eprintln!("{} {}", paint::bold_red(color, &prefix), report.detail);
        }
        exit_with(ExitCode::TestFailed);
    }
}

struct ConnEndpointRequest {
    name: String,
    issue: bool,
    renew: bool,
    revoke: bool,
    require_auth: Option<bool>,
    url: bool,
    secret: bool,
    root: Option<PathBuf>,
    broker: Option<String>,
}

/// Read, issue/rotate, renew, or revoke a direct endpoint through the same management
/// backend as the app. Issuance is deliberately online-only: a short-lived
/// offline broker would drop the newly bound listener as soon as this command
/// exits. Revocation only narrows access, so it remains a safe offline edit.
fn cmd_conn_endpoint(request: ConnEndpointRequest, json: bool) {
    let ConnEndpointRequest {
        name,
        issue,
        renew,
        revoke,
        require_auth,
        url,
        secret,
        root,
        broker,
    } = request;
    let action = endpoint_action(issue, renew, revoke)
        .unwrap_or_else(|message| die_with(ExitCode::Usage, message));
    if json && (url || secret) {
        die_with(
            ExitCode::Usage,
            "--json cannot be combined with --url or --secret",
        );
    }
    let managed = management_backend(root, broker);
    let dto = conn_dto(&managed, &name);
    if let Err(message) = endpoint_action_supported(action, managed.remote.is_some()) {
        die_with(ExitCode::NoBroker, message);
    }
    let connection_id = dto_id(&dto.id);

    if action == EndpointAction::Revoke {
        let Some(endpoint) = dto.agent_access.endpoint.as_ref() else {
            die_with(
                ExitCode::NotFound,
                format!("no direct endpoint is issued for {name}"),
            );
        };
        let endpoint_id = endpoint.endpoint_id.clone();
        let revoked = managed.run(
            managed
                .backend
                .revoke_endpoint(dto_id(&endpoint.endpoint_id)),
        );
        if !revoked {
            die_with(
                ExitCode::NotFound,
                format!("the direct endpoint for {name} was already revoked"),
            );
        }
        if json {
            print_json(&serde_json::json!({
                "connection": name,
                "endpoint_id": endpoint_id,
                "revoked": true,
            }));
        } else {
            ack(format!("revoked direct endpoint for {name}"));
        }
        return;
    }

    let mut info = match action {
        EndpointAction::Issue => managed.run_gated(managed.backend.issue_endpoint(connection_id)),
        EndpointAction::Renew => managed.run_gated(managed.backend.renew_endpoint(connection_id)),
        EndpointAction::Read => match managed.run(managed.backend.get_endpoint(connection_id)) {
            Some(info) => info,
            None => die_with(
                ExitCode::NotFound,
                format!(
                    "no direct endpoint issued for {name} — start the broker and retry with \
                         `aka endpoint {name} --issue`"
                ),
            ),
        },
        EndpointAction::Revoke => unreachable!("revocation returns above"),
    };
    // Applied after issuance so `--issue --require-auth` is one command, and
    // re-read afterwards so the example and secret printed below describe the
    // posture the endpoint actually ends up in rather than the one it had.
    if let Some(require_auth) = require_auth {
        // Only turning it *off* is gated in the broker; announcing a wait for
        // a confirmation that is not coming would be its own small lie.
        let call = managed
            .backend
            .set_endpoint_require_auth(connection_id, require_auth);
        let changed = if require_auth {
            managed.run(call)
        } else {
            managed.run_gated(call)
        };
        if changed {
            guide(format!(
                "the agent socket for {name} {}",
                if require_auth {
                    "now requires the endpoint secret — reach it through `aka ssh-agent`"
                } else {
                    "no longer requires the endpoint secret"
                }
            ));
            if let Some(reread) = managed.run(managed.backend.get_endpoint(connection_id)) {
                info = reread;
            }
        }
    }
    if json {
        print_json(&info);
        return;
    }
    let expired = info.expires_in_secs == Some(0);
    if expired && (url || secret) {
        die_with(
            ExitCode::Usage,
            format!(
                "the direct endpoint for {name} has expired — renew it with \
                 `aka endpoint {name} --renew`"
            ),
        );
    }
    if expired {
        warn_line(format!(
            "expired — renew without changing this address with \
             `aka endpoint {name} --renew`"
        ));
    }
    if action == EndpointAction::Issue {
        ack(format!("issued direct endpoint for {name}"));
    } else if action == EndpointAction::Renew {
        ack(format!("renewed direct endpoint for {name}"));
    }
    // Selectors print exactly one field with no decoration, so a `$(...)`
    // capture carries only the value. `--url` prefers the TCP form when the
    // endpoint has one: it is the address that works from another machine and
    // in drivers with no Unix-socket support, which is what a script capturing
    // this almost always wants.
    if url {
        println!("{}", info.tcp_dsn.as_deref().unwrap_or(&info.dsn));
        return;
    }
    if secret {
        println!("{}", info.secret);
        return;
    }
    // Default: the copy-ready example on stderr (guidance), the address on
    // stdout (the pasteable value), and the secret when the kind has one.
    let color = stderr_use_color();
    eprintln!("{}", paint::dim(color, &info.example));
    println!("{}", info.dsn);
    if let Some(tcp) = &info.tcp_dsn {
        guide("tcp (drivers without unix-socket support, and remote clients):");
        eprintln!("{tcp}");
    }
    if !info.secret.is_empty() {
        eprintln!(
            "{}",
            colon_field(color, "", "endpoint secret", &info.secret)
        );
    }
    if !info.expires_at.is_empty() {
        eprintln!("{}", colon_field(color, "", "expires", &info.expires_at));
    }
}

/// The layout the generated documents describe: the production defaults,
/// or — with `--root` — a dev broker's actual layout.
fn doc_paths(root: Option<PathBuf>) -> Paths {
    match root {
        Some(root) => Paths::under(&root),
        None => Paths::default_locations().unwrap_or_else(|error| {
            die(format!(
                "could not determine the per-user data and socket directories: {error}; \
                 set HOME (and, where applicable, XDG_DATA_HOME), or pass --root"
            ))
        }),
    }
}

const GENERATED_SKILL_MARKER: &str = "<!-- Generated by `aka setup skill`. Do not edit:";
const LEGACY_GENERATED_SKILL_MARKER: &str = "<!-- Generated by `aka skill`. Do not edit:";

fn generated_skill_file(content: &str) -> bool {
    content.contains(GENERATED_SKILL_MARKER) || content.contains(LEGACY_GENERATED_SKILL_MARKER)
}

/// The remote agent-setup snippet is a pure function of the broker URL, and
/// its consumer holds the shared agent key, not a management credential —
/// so render it locally when no token is on hand. With a token, keep the
/// broker's authoritative copy (it knows its canonical public URL).
fn authoritative_agent_setup(root: Option<PathBuf>, broker: String) -> String {
    let paths = store_paths(root.as_deref());
    if manage_token(&paths, &broker).is_none() {
        return aka_core::manage::agent_setup_instructions_remote(&broker);
    }
    let managed = management_backend(root, Some(broker));
    managed.run(managed.backend.agent_setup())
}

fn cmd_instructions(root: Option<PathBuf>, broker: Option<String>, json: bool) {
    let content = match effective_broker_url(broker) {
        Some(broker) => format!("{}\n", authoritative_agent_setup(root, broker).trim()),
        None => wellknown::instructions(&BrokerConfig::default(), &doc_paths(root)),
    };
    if json {
        print_json(&serde_json::json!({ "content": content }));
    } else {
        print!("{content}");
    }
}

fn cmd_skill(args: SkillArgs, json: bool) {
    let content = match effective_broker_url(args.broker) {
        Some(broker) => {
            let setup = authoritative_agent_setup(args.root.clone(), broker);
            wellknown::skill_file_for_broker(&setup)
        }
        None => wellknown::skill_file(&BrokerConfig::default(), &doc_paths(args.root)),
    };
    if !args.write {
        if json {
            print_json(&serde_json::json!({ "content": content }));
        } else {
            print!("{content}");
        }
        return;
    }
    let path = write_skill_file(&content, args.path, args.user, args.force);
    ack(format!("wrote {}", path.display()));
    mutation_ok(
        "skill.write",
        serde_json::json!({ "path": path.display().to_string() }),
    );
}

/// Put the rendered skill document where `--write` says, refusing to
/// clobber a file this CLI did not generate. Returns the path written, so
/// callers own their own reporting — `aka setup <client> --write` folds it
/// into one envelope rather than emitting a second.
fn write_skill_file(
    content: &str,
    path: Option<PathBuf>,
    user: bool,
    force: bool,
) -> PathBuf {
    let path = match (path, user) {
        (Some(path), _) => path,
        (None, true) => dirs::home_dir()
            .unwrap_or_else(|| {
                die("could not determine the home directory; set HOME or pass --path")
            })
            .join(".claude/skills/multitool/SKILL.md"),
        (None, false) => PathBuf::from(".claude/skills/multitool/SKILL.md"),
    };
    if path.exists() && !force {
        let existing = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            die(format!(
                "could not inspect existing skill file {}: {error}",
                path.display()
            ))
        });
        if !generated_skill_file(&existing) {
            die(format!(
                "refusing to overwrite non-Multitool skill file {}; pass --force to replace it",
                path.display()
            ));
        }
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            die(format!("could not create {}: {e}", dir.display()));
        }
    }
    if let Err(e) = std::fs::write(&path, content) {
        die(format!("could not write {}: {e}", path.display()));
    }
    path
}

struct CliEvents;
impl BrokerEvents for CliEvents {}

/// Store a management token for later online edits: keyed by the hosted
/// broker's manage URL, or by the local socket path. Verified against the
/// broker when it is reachable — a rejected token is never stored.
fn cmd_manage_login(url: Option<String>, token_env: Option<String>, root: Option<PathBuf>) {
    let url = effective_broker_url(url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    let token = if token_env.is_none()
        && presentation::stdin_is_tty()
        && presentation::stderr_is_tty()
    {
        let value = presentation::password("Management token (akamgr_…)")
            .unwrap_or_else(|error| die(format!("could not read the management token: {error}")));
        Zeroizing::new(value)
    } else {
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) && token_env.is_none() {
            guide("paste the management token (akamgr_…); end with Ctrl-D");
        }
        read_secret_value(&token_env, false)
    };
    let paths = store_paths(root.as_deref());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let (key, backend) = match url {
        Some(url) => {
            let url = match RemoteConfig::normalize_url(&url) {
                Ok(url) => url,
                Err(e) => die_with(ExitCode::Usage, e),
            };
            let config = match RemoteConfig::new(&url, &token) {
                Ok(config) => config,
                Err(e) => die_with(ExitCode::Usage, e),
            };
            (url, RemoteBackend::new(config))
        }
        None => {
            let socket = paths.socket_file();
            let key = socket.display().to_string();
            (key, RemoteBackend::over_unix_socket(socket, &token))
        }
    };
    match runtime.block_on(backend.whoami()) {
        Ok(profile) => {
            warn_version_skew(&profile);
            ack("token verified against the running broker");
        }
        Err(ManageError::InvalidManageToken { detail }) => die_with(
            ExitCode::Authentication,
            detail.unwrap_or_else(|| {
                "the broker rejected this management token — issue a fresh one with `aka admin token`"
                    .into()
            }),
        ),
        Err(ManageError::Unreachable { .. }) => {
            warn_line("the broker is not reachable right now; storing the token unverified");
        }
        Err(e) => die_manage(e),
    }
    let token_store = manage_token_store(&paths);
    if let Err(e) = token_store.save(&key, &token) {
        die(format!("could not store the token: {e}"));
    }
    ack(format!(
        "management token stored for {key} ({})",
        token_store.storage_description(&key)
    ));
}

fn cmd_manage_logout(url: Option<String>, root: Option<PathBuf>) {
    let url = effective_broker_url(url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    let paths = store_paths(root.as_deref());
    let key = match url {
        Some(url) => match RemoteConfig::normalize_url(&url) {
            Ok(url) => url,
            Err(e) => die_with(ExitCode::Usage, e),
        },
        None => paths.socket_file().display().to_string(),
    };
    if let Err(e) = manage_token_store(&paths).delete(&key) {
        die(format!("could not forget the management token: {e}"));
    }
    ack(format!("management token forgotten for {key}"));
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ManageTokenSource {
    Environment,
    Stored,
    Bootstrap,
}

fn online_manage_token(
    paths: &Paths,
    url: Option<String>,
    revoke: bool,
    ttl_days: Option<u64>,
    runtime: &tokio::runtime::Runtime,
    json: bool,
) {
    let (key, backend, source) = match url {
        Some(url) => {
            let url = match RemoteConfig::normalize_url(&url) {
                Ok(url) => url,
                Err(error) => die_with(ExitCode::Usage, error),
            };
            let (token, source) = if let Ok(token) = std::env::var("AKA_MANAGE_TOKEN") {
                let token = token.trim();
                if token.is_empty() {
                    die_with(
                        ExitCode::Authentication,
                        format!(
                            "AKA_MANAGE_TOKEN is empty; set the current token or run \
                             `aka admin login --broker {url}`"
                        ),
                    );
                }
                (
                    Zeroizing::new(token.to_string()),
                    ManageTokenSource::Environment,
                )
            } else if let Some(token) = manage_token_store(paths).load(&url) {
                (token, ManageTokenSource::Stored)
            } else {
                die_with(
                    ExitCode::Authentication,
                    format!(
                        "no current management token for {url} — set AKA_MANAGE_TOKEN \
                         or store one with `aka admin login --broker {url}`; initial \
                         bootstrap must be run on the broker host"
                    ),
                );
            };
            let config = match RemoteConfig::new(&url, &token) {
                Ok(config) => config,
                Err(error) => die_with(ExitCode::Usage, error),
            };
            (url, RemoteBackend::new(config), source)
        }
        None => {
            let socket = paths.socket_file();
            let key = socket.display().to_string();
            let (token, source) = if let Ok(token) = std::env::var("AKA_MANAGE_TOKEN") {
                let token = token.trim();
                if token.is_empty() {
                    die_with(
                        ExitCode::Authentication,
                        "AKA_MANAGE_TOKEN is empty; set the current token or unset it \
                         to use a saved or first-start token",
                    );
                }
                (
                    Zeroizing::new(token.to_string()),
                    ManageTokenSource::Environment,
                )
            } else if let Some(token) = manage_token_store(paths).load(&key) {
                (token, ManageTokenSource::Stored)
            } else {
                let path = paths.manage_bootstrap_token_file();
                let token = std::fs::read_to_string(&path).unwrap_or_else(|error| {
                    die_with(
                        ExitCode::Authentication,
                        format!(
                            "no saved management token and could not read the first-start \
                             credential {}: {error}",
                            path.display()
                        ),
                    )
                });
                let token = token.trim();
                if token.is_empty() {
                    die_with(
                        ExitCode::Authentication,
                        format!("the first-start credential {} is empty", path.display()),
                    );
                }
                (
                    Zeroizing::new(token.to_string()),
                    ManageTokenSource::Bootstrap,
                )
            };
            (key, RemoteBackend::over_unix_socket(socket, &token), source)
        }
    };

    if revoke {
        let revoked = match runtime.block_on(backend.revoke_management_token()) {
            Ok(true) => {
                if let Err(error) = manage_token_store(paths).delete(&key) {
                    warn_line(format!(
                        "warning: could not forget the saved token for {key}: {error}"
                    ));
                }
                if source == ManageTokenSource::Environment {
                    warn_line("warning: unset AKA_MANAGE_TOKEN; its value is now revoked");
                }
                ack("management token revoked; the manage API is closed");
                true
            }
            Ok(false) => {
                ack_dim("no management token was issued");
                false
            }
            Err(error) => die_manage(error),
        };
        mutation_ok(
            "manage.token.revoke",
            serde_json::json!({ "broker": key, "revoked": revoked }),
        );
        return;
    }

    let days = ttl_days.expect("the CLI always supplies a bounded management-token TTL");
    let issued = runtime
        .block_on(backend.rotate_management_token(days))
        .unwrap_or_else(|error| die_manage(error));
    if !json {
        guide("management token (shown once — the broker stores only its hash):\n");
        println!("{}", issued.token.as_str());
    }
    if source == ManageTokenSource::Environment {
        warn_line(
            "\nwarning: AKA_MANAGE_TOKEN still contains the superseded token; update or unset it",
        );
    } else {
        let store = manage_token_store(paths);
        if let Err(error) = store.save(&key, &issued.token) {
            warn_line(format!(
                "\nwarning: the token was rotated but could not be saved ({error}); \
                 capture the value printed above before it is lost"
            ));
        } else {
            ack(format!(
                "\nmanagement token stored for {key} ({})",
                store.storage_description(&key)
            ));
        }
    }
    if json {
        mutation_ok(
            "manage.token.rotate",
            serde_json::json!({
                "broker": key,
                "token": issued.token.as_str(),
                "expires_at": issued.expires_at,
            }),
        );
    } else {
        eprintln!(
            "{}",
            colon_field(stderr_use_color(), "", "expires", &issued.expires_at)
        );
    }
}

/// Rotate or revoke through a running broker when possible. A stopped local
/// broker retains the explicit offline path for recovery and first setup.
fn cmd_manage_token(
    revoke: bool,
    ttl_days: Option<u64>,
    root: Option<PathBuf>,
    url: Option<String>,
    create_root: bool,
    json: bool,
) {
    let url = effective_broker_url(url);
    if create_root && url.is_some() {
        die_with(
            ExitCode::Usage,
            "--create-root is only valid for offline local issuance; unset AKA_BROKER_URL \
             or omit --broker",
        );
    }
    if !create_root {
        require_existing_root_for_read(root.as_deref(), url.is_some());
    }
    let paths = store_paths(root.as_deref());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let broker_running = match &url {
        Some(_) => true,
        None => runtime
            .block_on(tokio::net::UnixStream::connect(paths.socket_file()))
            .is_ok(),
    };
    if broker_running {
        return online_manage_token(&paths, url, revoke, ttl_days, &runtime, json);
    }

    let _lock = match acquire_offline_store_lock(&paths) {
        Ok(lock) => lock,
        Err(CoreError::BrokerAlreadyRunning(_)) => die_with(
            ExitCode::Conflict,
            format!(
                "a broker is running on {} — stop it first (its in-memory \
                 identity would overwrite this change)",
                paths.socket_file().display()
            ),
        ),
        Err(CoreError::BrokerStateBusy(pid)) => die_with(
            ExitCode::Conflict,
            format!(
                "another CLI process{} is editing this broker state — wait for it to finish, then retry",
                pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
            ),
        ),
        Err(error) => die(format!("could not acquire the broker state lease: {error}")),
    };
    let vault = match open_vault(&paths, root.as_deref()) {
        Ok(vault) => vault,
        Err(e) => die(format!("could not open the secret vault: {e}")),
    };
    let integrity = match runtime.block_on(aka_core::integrity::StateIntegrity::open_for_paths(
        &*vault, &paths,
    )) {
        Ok(integrity) => Arc::new(integrity),
        Err(e) => die(format!("could not open the state integrity key: {e}")),
    };
    let identity = match aka_core::identity::IdentityStore::open(
        paths.identity_file(),
        paths.token_file(),
        Some(&paths.agents_file()),
        BrokerConfig::default().token_ttl,
        integrity.clone(),
    ) {
        Ok(identity) => identity,
        Err(e) => die(format!("could not open the broker identity: {e}")),
    };
    let audit = match aka_core::audit::AuditLog::open_sealed(
        paths.audit_file(),
        paths.audit_seal_file(),
        integrity,
    ) {
        Ok(audit) => audit,
        Err(e) => die(format!("could not open the activity log: {e}")),
    };
    if revoke {
        let revoked = match identity.revoke_manage_token() {
            Ok(true) => {
                if let Err(error) = paths.remove_manage_bootstrap_token() {
                    warn_line(format!(
                        "warning: could not remove {}: {error}",
                        paths.manage_bootstrap_token_file().display()
                    ));
                }
                audit.append(aka_core::audit::AuditEntry::new(
                    aka_core::audit::AuditKind::ManagementTokenRevoked,
                    "Management token revoked",
                ));
                ack("management token revoked; the manage API is closed");
                true
            }
            Ok(false) => {
                ack_dim("no management token was issued");
                false
            }
            Err(e) => die(e),
        };
        mutation_ok(
            "manage.token.revoke",
            serde_json::json!({ "revoked": revoked }),
        );
        return;
    }
    let ttl = ttl_days.map(|days| std::time::Duration::from_secs(days * 86400));
    match identity.issue_manage_token_with_ttl(ttl) {
        Ok(token) => {
            let token = Zeroizing::new(token);
            if let Err(error) = paths.remove_manage_bootstrap_token() {
                warn_line(format!(
                    "warning: could not remove {}: {error}",
                    paths.manage_bootstrap_token_file().display()
                ));
            }
            let mut entry = aka_core::audit::AuditEntry::new(
                aka_core::audit::AuditKind::ManagementTokenIssued,
                "Management token issued",
            )
            .outcome("issued");
            if let Some(expires_at) = identity.manage_token_expires_at() {
                entry = entry.field("expires_at", expires_at.to_rfc3339());
            }
            audit.append(entry);
            if json {
                mutation_ok(
                    "manage.token.rotate",
                    serde_json::json!({
                        "token": token.as_str(),
                        "expires_at": identity
                            .manage_token_expires_at()
                            .map(|value| value.to_rfc3339()),
                    }),
                );
            } else {
                guide("management token (shown once — only its hash is stored):\n");
                println!("{}", token.as_str());
                guide("\nEnter it in the Multitool app to manage this broker remotely.");
                match ttl_days {
                    Some(days) => guide(format!(
                        "Expires in {days} day{}; re-run to rotate, or --revoke to close the manage API.",
                        if days == 1 { "" } else { "s" }
                    )),
                    None => unreachable!("the CLI always supplies a bounded management-token TTL"),
                }
            }
        }
        Err(e) => die(e),
    }
}

/// Open (or cancel) passkey enrollment on this machine's running broker.
///
/// Deliberately socket-only, with no offline fallback. The running broker
/// holds the auth state in memory and rewrites the file on every change, so
/// an offline edit would be silently clobbered by the next session it
/// records — and more to the point, opening enrollment is the one decision
/// that must be made by somebody standing on the host.
fn cmd_manage_enroll(cancel: bool, root: Option<PathBuf>, json: bool) {
    require_existing_root_for_read(root.as_deref(), false);
    let paths = store_paths(root.as_deref());
    let socket = paths.socket_file();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let method = if cancel { "DELETE" } else { "POST" };
    let (status, body) = match runtime.block_on(client::unix_http(
        &socket,
        method,
        "/v1/auth/enrollment",
        None,
        None,
        None,
    )) {
        Ok(response) => response,
        Err(error) => die_with(
            ExitCode::NoBroker,
            format!(
                "could not reach this machine's broker at {}: {error}\n\
                 Enrollment is opened on the broker host, so the broker has to be running there.",
                socket.display()
            ),
        ),
    };
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    if status != 200 {
        let detail = parsed
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or(body.trim());
        die(format!("could not change enrollment: {detail}"));
    }
    if cancel {
        ack("passkey enrollment closed; any outstanding secret is void");
        mutation_ok(
            "manage.enroll.cancel",
            serde_json::json!({ "cancelled": true }),
        );
        return;
    }
    let secret = parsed
        .get("secret")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let already = parsed
        .get("already_enrolled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if already && !json {
        guide("This broker already has a passkey; this enrolls an additional one.\n");
    }
    let sign_in_url = parsed.get("sign_in_url").and_then(|value| value.as_str());
    if json {
        mutation_ok(
            "manage.enroll.open",
            serde_json::json!({
                "secret": secret,
                "sign_in_url": sign_in_url,
                "already_enrolled": already,
                "expires_in_seconds": 900,
            }),
        );
        return;
    }
    match sign_in_url {
        Some(url) => {
            guide("Open this on the device you want to enroll:\n");
            println!("{url}");
            guide("\nand paste this one-use secret when it asks:\n");
        }
        // Without --public-url there is no origin a passkey could be bound
        // to. The secret is still issued — the operator may be about to add
        // one — but saying nothing about the missing URL would be a mystery.
        None => warn_line(
            "Note: this broker has no --public-url, so there is no address a browser \
             can enroll against yet. Bare `aka serve` defaults TCP and its public URL \
             to localhost; otherwise configure --listen and --public-url together.\n\n\
             One-use enrollment secret:\n",
        ),
    }
    println!("{secret}");
    guide("\nIt expires in 15 minutes. Re-run to issue a fresh one, or --cancel to close it.");
}

/// Retire (or restore) the global management token on this machine's broker.
///
/// Socket-only for the same reason enrollment is: this decides what may
/// authenticate, and getting it wrong locks the manage plane. The broker's
/// own guard refuses a retirement with no passkey enrolled; this just
/// reports it.
fn cmd_manage_legacy(restore: bool, retire: bool, root: Option<PathBuf>) {
    if restore == retire {
        die_with(ExitCode::Usage, "choose one of --retire or --restore");
    }
    require_existing_root_for_read(root.as_deref(), false);
    let paths = store_paths(root.as_deref());
    let socket = paths.socket_file();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let body = serde_json::json!({ "legacy_manage_token": restore }).to_string();
    let token = std::env::var("AKA_MANAGE_TOKEN").ok();
    let (status, response) = match runtime.block_on(client::unix_http(
        &socket,
        "PATCH",
        "/v1/manage/settings",
        Some(&body),
        token.as_deref(),
        None,
    )) {
        Ok(response) => response,
        Err(error) => die_with(
            ExitCode::NoBroker,
            format!(
                "could not reach this machine's broker at {}: {error}",
                socket.display()
            ),
        ),
    };
    if status != 200 {
        let parsed: serde_json::Value =
            serde_json::from_str(&response).unwrap_or(serde_json::Value::Null);
        let detail = parsed
            .get("message")
            .or_else(|| parsed.get("detail"))
            .and_then(|value| value.as_str())
            .unwrap_or(response.trim());
        die(format!("could not change the setting: {detail}"));
    }
    if retire {
        ack(
            "the management token is retired; this broker now accepts only passkey \n\
             sign-ins, device grants, and automation tokens",
        );
    } else {
        ack("the management token is accepted again");
    }
}

/// What each capability can do on a broker reached over the network, for
/// the two errors below: usage commands never dial TCP themselves.
fn remote_capability_reality(endpoint: &str) -> &'static str {
    match endpoint {
        "/v1/pg/open" => {
            "Remote Postgres needs the operator to serve the data plane \
             (`aka serve --advertise-host`); agents then open sessions with \
             POST /v1/pg/open and the shared key"
        }
        "/v1/ssh/open" => {
            "SSH sessions are never served over the network; run this on the \
             broker's host"
        }
        "/v1/cloud/session" => {
            "Cloud sessions are not served over the network; run this on the \
             broker's host"
        }
        "" => {
            "Each kind has its own remote story: Postgres needs the \
             operator's data plane (`aka serve --advertise-host`), SSH and \
             cloud sessions are never served over the network, and API \
             connections work remotely through their direct endpoints"
        }
        _ => "API and MCP connections work remotely with the shared key",
    }
}

/// A usage command was pointed at a remote broker. Each capability has a
/// different remote story — tell it instead of clap's generic unknown-flag
/// tip or a "start a broker" hint.
fn refuse_remote_usage(command: &str, endpoint: &str, url: &str) -> ! {
    let url = url.trim_end_matches('/');
    die_with(
        ExitCode::Usage,
        format!(
            "`aka {command}` opens sessions on this machine's broker and cannot \
             target {url}. {} — see {url}/instructions",
            remote_capability_reality(endpoint)
        ),
    )
}

/// Open a capability session on the running broker and hand back the
/// parsed 200 body; any failure dies with the client module's one-liner.
fn open_session(
    endpoint: &str,
    connection: &str,
    root: Option<PathBuf>,
    label: Option<String>,
) -> serde_json::Value {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let agent = usage_agent(root.as_deref());
    match runtime.block_on(agent.open_session(endpoint, connection, label.as_deref())) {
        Ok(body) => body,
        Err(error) => {
            // A remote broker answers `not_served_remotely` for the
            // capabilities that are same-machine by construction. Clap-level
            // guidance cannot know which kind was asked for; the broker does,
            // so translate its refusal into the kind's actual remote story.
            if let client::OpenSessionError::Refused { reason, .. } = &error {
                if reason.as_deref() == Some("not_served_remotely") {
                    let base = agent.describe();
                    die_with(
                        ExitCode::Usage,
                        format!(
                            "{base} does not serve this capability over the \
                             network. {} — see {base}/instructions",
                            remote_capability_reality(endpoint)
                        ),
                    );
                }
            }
            die_with(open_session_exit_code(&error), error)
        }
    }
}

fn open_session_exit_code(error: &client::OpenSessionError) -> ExitCode {
    use client::OpenSessionError;
    match error {
        OpenSessionError::NoBroker { .. } => ExitCode::NoBroker,
        OpenSessionError::Refused { status, reason, .. } => match reason.as_deref() {
            Some("unknown_connection") => ExitCode::NotFound,
            Some(
                "missing_token"
                | "invalid_token"
                | "token_expired"
                | "token_superseded"
                | "denied_by_policy"
                | "approval_denied"
                | "approval_timeout"
                | "approval_unavailable",
            ) => ExitCode::Authentication,
            Some(
                "request_id_mismatch"
                | "outcome_not_replayable"
                | "rate_limited"
                | "ticket_session_limit"
                | "broker_session_limit"
                | "endpoint_busy",
            ) => ExitCode::Conflict,
            _ => match status {
                401 | 403 => ExitCode::Authentication,
                404 => ExitCode::NotFound,
                409 | 429 => ExitCode::Conflict,
                _ => ExitCode::Generic,
            },
        },
        OpenSessionError::RemoteUnreachable { .. } => ExitCode::RemoteUnreachable,
        OpenSessionError::Transport { .. } | OpenSessionError::Malformed(_) => ExitCode::Generic,
    }
}

/// Embed the session ticket as the DSN's password for the explicit legacy
/// `--format uri` output.
fn embed_ticket(dsn: &str, ticket: &str) -> Result<String, String> {
    match dsn.split_once("://ticket@") {
        Some((scheme, rest)) => Ok(format!("{scheme}://ticket:{ticket}@{rest}")),
        None => Err(format!("unexpected DSN shape from the broker: {dsn}")),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Quote one token in an AWS shared-config `credential_process` command.
/// AWS parses this line itself, so use its documented double-quoted form
/// rather than POSIX-shell quoting.
fn aws_process_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn pg_env(dsn: &str, ticket: &str) -> Result<Vec<(String, String)>, String> {
    let parsed = url::Url::parse(dsn).map_err(|e| format!("invalid DSN from the broker: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("the broker's DSN has no host: {dsn}"))?;
    let port = parsed
        .port()
        .ok_or_else(|| format!("the broker's DSN has no port: {dsn}"))?;
    let database = parsed.path().trim_start_matches('/');
    if database.is_empty() {
        return Err(format!("the broker's DSN has no database: {dsn}"));
    }
    Ok([
        ("PGHOST", host.to_string()),
        ("PGPORT", port.to_string()),
        ("PGDATABASE", database.to_string()),
        ("PGUSER", parsed.username().to_string()),
        ("PGPASSWORD", ticket.to_string()),
        ("PGSSLMODE", "disable".to_string()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value))
    .collect())
}

fn pg_env_exports(dsn: &str, ticket: &str) -> Result<String, String> {
    Ok(pg_env(dsn, ticket)?
        .into_iter()
        .map(|(name, value)| format!("export {name}={}", shell_quote(&value)))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn process_command(words: &[String]) -> std::process::Command {
    let Some(program) = words.first().filter(|program| !program.is_empty()) else {
        die_with(ExitCode::Usage, "the command after -- must not be empty");
    };
    let mut child = std::process::Command::new(program);
    child.args(&words[1..]);
    child
}

fn exit_with_child_status(status: std::process::ExitStatus) -> ! {
    match status.code() {
        Some(code) => exit_with_raw(code),
        None => {
            use std::os::unix::process::ExitStatusExt as _;
            exit_with_raw(128 + status.signal().unwrap_or(0))
        }
    }
}

fn run_scoped_command(words: &[String], env: &[(String, Option<String>)]) -> ! {
    let mut child = process_command(words);
    for (name, value) in env {
        match value {
            Some(value) => {
                child.env(name, value);
            }
            None => {
                child.env_remove(name);
            }
        }
    }
    let status = child
        .status()
        .unwrap_or_else(|error| die(format!("could not run {}: {error}", words[0])));
    exit_with_child_status(status)
}

fn reject_json_for_scoped_command(json: bool, command: &[String]) {
    if json && !command.is_empty() {
        die_with(
            ExitCode::Usage,
            "--json cannot be combined with a command after --",
        );
    }
}

/// The connection's kind, looked up on the agent plane so `run`/`env` work
/// with the same shared key their opens use. Dies with a NotFound one-liner
/// when no connection carries the name.
fn connection_kind(connection: &str, root: Option<&Path>, label: Option<&str>) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let agent = usage_agent(root);
    let body = match runtime.block_on(agent.agent_get("/v1/connections", label)) {
        Ok(body) => body,
        Err(error) => die_with(open_session_exit_code(&error), error),
    };
    let Some(list) = body.as_array() else {
        die("the broker's connection list was malformed");
    };
    let kind = list.iter().find_map(|row| {
        (row["name"].as_str() == Some(connection)).then(|| row["type"].as_str().map(str::to_string))
    });
    match kind {
        Some(Some(kind)) => kind,
        Some(None) => die("the broker's connection list carried no kind"),
        None => die_with(
            ExitCode::NotFound,
            format!(
                "no connection is named {connection} — `aka ls` shows what exists"
            ),
        ),
    }
}

/// `aka run <connection> -- <command>`: one runner for every kind. The
/// connection's kind picks the capability; each arm reuses the kind-specific
/// open path unchanged.
fn cmd_run(
    connection: String,
    root: Option<PathBuf>,
    client: Option<String>,
    command: Vec<String>,
    json: bool,
) {
    let kind = connection_kind(&connection, root.as_deref(), client.as_deref());
    match kind.as_str() {
        "pg" => cmd_dsn(connection, root, client, None, false, command, json),
        "ssh" => cmd_ssh(connection, root, client, command, json),
        "cloud" => cmd_cloud_env(connection, root, client, command, json),
        "api" => {
            reject_json_for_scoped_command(json, &command);
            let env = api_endpoint_env(&connection, root)
                .into_iter()
                .map(|(name, value)| (name, Some(value)))
                .collect::<Vec<_>>();
            run_scoped_command(&command, &env);
        }
        other => die(format!(
            "connection {connection} has unsupported kind {other}"
        )),
    }
}

/// `aka env <connection>`: the exports form of `run`, for shells and
/// compatibility. Kind-dispatched exactly like `run` with no trailing
/// command.
fn cmd_env(
    connection: String,
    root: Option<PathBuf>,
    client: Option<String>,
    format: Option<DsnFormat>,
    password_only: bool,
    json: bool,
) {
    let kind = connection_kind(&connection, root.as_deref(), client.as_deref());
    if (format.is_some() || password_only) && kind != "pg" {
        die_with(
            ExitCode::Usage,
            format!(
                "--format and --password-only apply to pg connections; {connection} is {kind}"
            ),
        );
    }
    match kind.as_str() {
        "pg" => cmd_dsn(connection, root, client, format, password_only, vec![], json),
        "ssh" => cmd_ssh(connection, root, client, vec![], json),
        "cloud" => cmd_cloud_env(connection, root, client, vec![], json),
        "api" => {
            let env = api_endpoint_env(&connection, root);
            if json {
                let value = env
                    .iter()
                    .map(|(name, value)| (name.clone(), serde_json::json!(value)))
                    .collect::<serde_json::Map<_, _>>();
                print_json(&serde_json::Value::Object(value));
                return;
            }
            guide(
                "send AKA_TOKEN in place of the real credential; the broker \
                 swaps it in on the upstream leg",
            );
            for (name, value) in env {
                println!("export {name}={}", shell_quote(&value));
            }
        }
        other => die(format!(
            "connection {connection} has unsupported kind {other}"
        )),
    }
}

/// The environment `run`/`env` hand out for an api connection: its direct
/// endpoint's address and secret. The endpoint is a standing capability the
/// user issues; these commands read it, they never mint one.
/// A direct endpoint is a standing credential the *user* issues, so it is
/// read from the management plane rather than handed out to anything holding
/// the agent key. Locally that is free — reaching the socket is the whole
/// gate — but against a remote broker it needs that broker's management
/// token, which a teammate who only ran `aka login` does not have. Say so
/// before the generic "no management token" refusal does.
fn api_endpoint_env(connection: &str, root: Option<PathBuf>) -> Vec<(String, String)> {
    if root.is_none() && effective_broker_url(None).is_none() {
        if let Some((source, ContextTarget::Broker(url))) = ambient_context() {
            let url = url.trim_end_matches('/');
            if manage_token(&store_paths(None), url).is_none() {
                die_with(
                    ExitCode::Authentication,
                    format!(
                        "API connections are reached through a direct endpoint, \
                         which is read from {url}'s management plane ({source}) — \
                         `aka login` stores only the agent key. Store a \
                         management token with `aka admin login --broker {url}`, \
                         or ask the operator for the endpoint's URL and secret."
                    ),
                );
            }
        }
    }
    let managed = management_backend(root, None);
    let dto = conn_dto(&managed, connection);
    if managed.remote.is_none() {
        die_with(
            ExitCode::NoBroker,
            "direct endpoints are served by a running broker; start Multitool \
             for the local store, or `aka serve` for a headless root, then retry",
        );
    }
    let connection_id = dto_id(&dto.id);
    let Some(info) = managed.run(managed.backend.get_endpoint(connection_id)) else {
        die_with(
            ExitCode::NotFound,
            format!(
                "no direct endpoint is issued for {connection} — issue one \
                 with `aka endpoint {connection} --issue`"
            ),
        );
    };
    if info.expires_in_secs == Some(0) {
        die_with(
            ExitCode::Usage,
            format!(
                "the direct endpoint for {connection} has expired — renew it \
                 with `aka endpoint {connection} --renew`"
            ),
        );
    }
    let url = info
        .tcp_dsn
        .clone()
        .unwrap_or_else(|| info.dsn.clone());
    vec![
        ("AKA_URL".to_string(), url),
        ("AKA_TOKEN".to_string(), info.secret),
    ]
}

fn cmd_dsn(
    connection: String,
    root: Option<PathBuf>,
    client: Option<String>,
    format: Option<DsnFormat>,
    password_only: bool,
    command: Vec<String>,
    json: bool,
) {
    reject_json_for_scoped_command(json, &command);
    if json && (format.is_some() || password_only) {
        die_with(
            ExitCode::Usage,
            "--json cannot be combined with --format or --password-only",
        );
    }
    let client = Some(client.unwrap_or_else(|| "multitool-dsn".to_string()));
    let body = open_session("/v1/pg/open", &connection, root, client);
    let (Some(dsn), Some(ticket)) = (body["dsn"].as_str(), body["ticket"].as_str()) else {
        die("the broker's response carried no DSN and ticket");
    };
    if json {
        print_json(&body);
        return;
    }
    if let Some(secs) = body["expires_in_seconds"].as_u64() {
        eprintln!("  ticket expires in {secs}s — connect before then; a later connection needs a fresh open");
    }
    if let Some(note) = body["sslmode_note"].as_str() {
        eprintln!("  note: {note}");
    }
    if !command.is_empty() {
        let env = pg_env(dsn, ticket)
            .unwrap_or_else(|message| die(message))
            .into_iter()
            .map(|(name, value)| (name, Some(value)))
            .collect::<Vec<_>>();
        run_scoped_command(&command, &env);
    }
    if password_only {
        println!("{ticket}");
        return;
    }
    match format.unwrap_or(DsnFormat::Env) {
        DsnFormat::Env => match pg_env_exports(dsn, ticket) {
            Ok(exports) => println!("{exports}"),
            Err(message) => die(message),
        },
        DsnFormat::Uri => match embed_ticket(dsn, ticket) {
            Ok(dsn) => {
                eprintln!("  warning: --format uri puts the ticket in process-visible argv");
                println!("{dsn}");
            }
            Err(message) => die(message),
        },
    }
}

/// The `-o` flags every brokered `ssh` invocation should carry; see the core's
/// definition for why each is present and why `IdentitiesOnly` is not.
use aka_core::capability::ssh::SSH_BROKER_OPTIONS;

/// The stderr lines accompanying `aka ssh`'s socket path.
///
/// Everything here was already in the broker's response and thrown away: the
/// destination to actually type (an imported alias is not `user@host`), the
/// fingerprint the broker enforces (the pinned *host* is not what authorizes
/// anything), the absolute deadline, and the flags without which a local
/// on-disk key can quietly win the login instead. Built separately from
/// printing so the shape is testable.
fn ssh_open_hints(
    body: &serde_json::Value,
    auth_sock: &str,
    now: chrono::DateTime<chrono::Local>,
    include_setup: bool,
) -> Vec<String> {
    let mut lines = Vec::new();
    if let (Some(user), Some(host)) = (body["user"].as_str(), body["host"].as_str()) {
        lines.push(format!("signs only for {user}@{host}"));
    }
    if let Some(secs) = body["expires_in_seconds"].as_u64() {
        // Relative alone leaves nothing to compare a later failure against. The
        // agent protocol has no error channel, so a 61-second-old export reads
        // as "Permission denied (publickey)" and nothing else.
        let deadline = now + chrono::Duration::seconds(secs as i64);
        lines.push(format!(
            "connect within {secs}s — by {} (a later connection needs a fresh open)",
            deadline.format("%H:%M:%S %Z")
        ));
    }
    lines.push(match body["host_key_fingerprint"].as_str() {
        Some(fingerprint) if !fingerprint.is_empty() => {
            format!("server host key pinned to {fingerprint}")
        }
        _ => "server host key not pinned — the first server key seen will be trusted and pinned"
            .to_string(),
    });
    let destination = body["destination"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            let (user, host) = (body["user"].as_str()?, body["host"].as_str()?);
            Some(format!("{user}@{host}"))
        });
    if include_setup {
        let Some(destination) = destination else {
            return lines;
        };
        let port = match body["port"].as_u64() {
            Some(port) if port != 22 => format!(" -p {port}"),
            _ => String::new(),
        };
        let flags = SSH_BROKER_OPTIONS
            .iter()
            .map(|option| format!("-o {option}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(format!("export SSH_AUTH_SOCK=\"{auth_sock}\""));
        lines.push(format!("ssh{port} {flags} {destination}"));
        // The flags above are not optional decoration. `SSH_AUTH_SOCK` alone
        // leaves the default IdentityFile list in place, so a user with a
        // working ~/.ssh/id_ed25519 logs in with no broker involvement and no
        // activity entry — a success that looks brokered and is not. A config
        // block is how that becomes hard to get wrong, and it is also what
        // ssh-config-aware clients (VS Code Remote-SSH, plain `ssh <name>`)
        // can use at all.
        lines.push(String::new());
        lines.push("or add to ~/.ssh/config so plain `ssh` and editors use it too:".to_string());
        lines.extend(ssh_config_block(body, auth_sock, &destination));
    }
    lines
}

fn ssh_scoped_command(words: &[String], auth_sock: &str) -> std::process::Command {
    let Some(program) = words.first().filter(|program| !program.is_empty()) else {
        die_with(ExitCode::Usage, "the command after -- must not be empty");
    };
    let executable = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program);
    let mut child = std::process::Command::new(program);
    match executable {
        "ssh" | "scp" | "sftp" => {
            for option in SSH_BROKER_OPTIONS {
                child.args(["-o", option]);
            }
            child.args(&words[1..]);
        }
        "git" => {
            child.args(&words[1..]);
            child.env(
                "GIT_SSH_COMMAND",
                format!(
                    "ssh {}",
                    SSH_BROKER_OPTIONS
                        .iter()
                        .map(|option| format!("-o {option}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            );
            child.env("GIT_SSH_VARIANT", "ssh");
        }
        "rsync" => {
            child.args(&words[1..]);
            child.env(
                "RSYNC_RSH",
                format!(
                    "ssh {}",
                    SSH_BROKER_OPTIONS
                        .iter()
                        .map(|option| format!("-o {option}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            );
        }
        _ => die_with(
            ExitCode::Usage,
            format!(
                "scoped SSH execution supports ssh, scp, sftp, git, and rsync; \
                 cannot safely configure {executable:?}"
            ),
        ),
    }
    child.env("SSH_AUTH_SOCK", auth_sock);
    child
}

/// A `~/.ssh/config` stanza pointing `IdentityAgent` at the issued socket,
/// carrying the same options as the one-liner above.
fn ssh_config_block(body: &serde_json::Value, auth_sock: &str, destination: &str) -> Vec<String> {
    // An alias with whitespace is not a legal Host pattern; the destination is
    // already the alias when one was imported.
    let alias = destination
        .rsplit('@')
        .next()
        .unwrap_or(destination)
        .replace(char::is_whitespace, "-");
    let mut block = vec![format!("  Host {alias}")];
    if let Some(host) = body["host"].as_str() {
        block.push(format!("    HostName {host}"));
    }
    if let Some(port) = body["port"].as_u64().filter(|port| *port != 22) {
        block.push(format!("    Port {port}"));
    }
    if let Some(user) = body["user"].as_str().filter(|user| !user.is_empty()) {
        block.push(format!("    User {user}"));
    }
    block.push(format!("    IdentityAgent \"{auth_sock}\""));
    for option in SSH_BROKER_OPTIONS {
        let (key, value) = option.split_once('=').unwrap_or((option, ""));
        block.push(format!("    {key} {value}"));
    }
    block
}

fn cloud_session_env(body: &serde_json::Value) -> Vec<(String, Option<String>)> {
    let Some(env) = body["env"].as_object() else {
        die("the broker's response carried no env map");
    };
    env.iter()
        .filter_map(|(name, value)| {
            let value = value.as_str()?;
            if !is_env_var_name(name) {
                die(format!(
                    "the broker returned {name:?} as an environment variable name; \
                     refusing to use an unsafe environment"
                ));
            }
            Some((name.clone(), (!value.is_empty()).then(|| value.to_string())))
        })
        .collect()
}

fn cmd_cloud_env(
    connection: String,
    root: Option<PathBuf>,
    client: Option<String>,
    command: Vec<String>,
    json: bool,
) {
    reject_json_for_scoped_command(json, &command);
    let client = Some(client.unwrap_or_else(|| "multitool-cloud".to_string()));
    let body = open_session("/v1/cloud/session", &connection, root, client);
    if json {
        print_json(&body);
        return;
    }
    if let Some(secs) = body["expires_in_seconds"].as_u64() {
        eprintln!(
            "  session expires in {secs}s — re-run before then; Multitool cannot revoke minted credentials"
        );
    }
    let env = cloud_session_env(&body);
    if !command.is_empty() {
        run_scoped_command(&command, &env);
    }
    for (name, value) in env {
        // Empty AWS_PROFILE clears a sticky profile so minted keys win.
        if let Some(value) = value {
            println!("export {name}={}", shell_quote(&value));
        } else {
            println!("unset {name}");
        }
    }
}

/// Same rule the broker applies to a pushed session
/// ([`aka_core::cloud::is_env_var_name`]), re-checked here because this is
/// the process that actually hands the line to a shell.
fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn cmd_cloud_creds(
    connection: String,
    format: CloudCredsFormat,
    root: Option<PathBuf>,
    client: Option<String>,
    json: bool,
) {
    if json && format != CloudCredsFormat::Json {
        die_with(
            ExitCode::Usage,
            "--json is equivalent to --format json; do not combine them with another --format",
        );
    }
    let client = Some(client.unwrap_or_else(|| "multitool-cloud".to_string()));
    let body = open_session("/v1/cloud/session", &connection, root, client);
    let format = if json { CloudCredsFormat::Json } else { format };
    match format {
        CloudCredsFormat::Json => print_json(&body),
        CloudCredsFormat::Env => {
            let Some(env) = body["env"].as_object() else {
                die("the broker's response carried no env map");
            };
            for (name, value) in env {
                let Some(value) = value.as_str() else {
                    continue;
                };
                // Not eval'd, but this feeds .env files and `env -S`-style
                // readers; hold it to the same shape so the two formats
                // never disagree about what a session exports.
                if !is_env_var_name(name) {
                    die(format!(
                        "the broker returned {name:?} as an environment variable name"
                    ));
                }
                if !value.is_empty() {
                    println!("{name}={value}");
                }
            }
        }
        CloudCredsFormat::Native => {
            let creds = &body["credentials"];
            if creds.is_null() {
                die("the broker's response carried no credentials");
            }
            // credential_process and similar hooks want pure JSON on stdout.
            println!(
                "{}",
                serde_json::to_string(creds).unwrap_or_else(|e| die(e.to_string()))
            );
        }
    }
}

fn cmd_cloud_install(
    connection: String,
    profile: Option<String>,
    root: Option<PathBuf>,
    json: bool,
) {
    // Install only needs to know the connection exists and which provider it
    // is; minting is deferred to credential_process at CLI use time.
    let managed = management_backend(root.clone(), None);
    let dto = conn_dto(&managed, &connection);
    if dto.kind != "cloud" {
        die_with(
            ExitCode::Usage,
            format!(
                "{connection} is a {} connection; cloud install only applies to cloud connections",
                dto.kind
            ),
        );
    }
    let profile_name = profile.unwrap_or_else(|| {
        let slug: String = connection
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        format!("multitool-{slug}")
    });
    // Resolve the multitool binary path for a durable credential_process line.
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "aka".into());
    let mut process = format!(
        "{} cloud creds {}",
        aws_process_quote(&exe),
        aws_process_quote(&connection)
    );
    if let Some(root) = &root {
        process.push_str(&format!(
            " --root {}",
            aws_process_quote(&root.display().to_string())
        ));
    }
    let provider = dto.scheme.as_deref().unwrap_or("");
    match provider {
        // A profile-reuse connection may pin no region at all (host is bare
        // "aws"): the minted credentials carry the profile's own region, so
        // the emitted stanza simply omits the region line.
        "aws" | ""
            if dto
                .host
                .as_deref()
                .is_some_and(|h| h == "aws" || h.starts_with("aws:")) =>
        {
            let region = dto
                .host
                .as_deref()
                .and_then(|h| h.strip_prefix("aws:"))
                .filter(|r| !r.is_empty());
            let region_line = region
                .map(|region| format!("region = {region}\n"))
                .unwrap_or_default();
            if json {
                print_json(&serde_json::json!({
                    "provider": "aws",
                    "profile": profile_name,
                    "region": region,
                    "credential_process": process,
                    "config": format!(
                        "[profile {profile_name}]\n{region_line}credential_process = {process}\n"
                    ),
                }));
                return;
            }
            println!("# Append to ~/.aws/config (or AWS_CONFIG_FILE)");
            println!("[profile {profile_name}]");
            print!("{region_line}");
            println!("credential_process = {process}");
            eprintln!("  then: export AWS_PROFILE={profile_name}");
        }
        "azure" | "gcp" => {
            let mut env_cmd = format!(
                "{} cloud env {}",
                shell_quote(&exe),
                shell_quote(&connection)
            );
            if let Some(root) = &root {
                env_cmd.push_str(&format!(
                    " --root {}",
                    shell_quote(&root.display().to_string())
                ));
            }
            if json {
                print_json(&serde_json::json!({
                    "provider": provider,
                    "shell": format!("eval \"$({env_cmd})\""),
                }));
                return;
            }
            match provider {
                "azure" => {
                    println!("# Short-lived Azure access token (client secret stays in Multitool)");
                    println!("eval \"$({env_cmd})\"");
                    println!("# Then e.g.:");
                    println!(
                        "# az rest --method get --url https://management.azure.com/subscriptions/$AZURE_SUBSCRIPTION_ID?api-version=2020-01-01 --headers Authorization=\"Bearer $AZURE_ACCESS_TOKEN\""
                    );
                }
                _ => {
                    println!(
                        "# Short-lived GCP access token (service-account key stays in Multitool)"
                    );
                    println!("eval \"$({env_cmd})\"");
                    println!("# CLOUDSDK_AUTH_ACCESS_TOKEN is set for gcloud; e.g.:");
                    println!("# gcloud storage ls");
                }
            }
            eprintln!("  re-run before the token expires; Multitool cannot revoke minted tokens");
        }
        other => die_with(
            ExitCode::Usage,
            format!("cloud install does not support provider {other:?}"),
        ),
    }
}

fn cmd_ssh(
    connection: String,
    root: Option<PathBuf>,
    client: Option<String>,
    command: Vec<String>,
    json: bool,
) {
    reject_json_for_scoped_command(json, &command);
    let client = Some(client.unwrap_or_else(|| "multitool-ssh".to_string()));
    let body = open_session("/v1/ssh/open", &connection, root, client);
    let Some(auth_sock) = body["auth_sock"].as_str() else {
        die("the broker's response carried no agent socket path");
    };
    if json {
        print_json(&body);
        return;
    }
    for line in ssh_open_hints(&body, auth_sock, chrono::Local::now(), command.is_empty()) {
        eprintln!("  {line}");
    }
    if !command.is_empty() {
        let status = ssh_scoped_command(&command, auth_sock)
            .status()
            .unwrap_or_else(|error| die(format!("could not run {}: {error}", command[0])));
        exit_with_child_status(status);
    }
    println!("{auth_sock}");
}

/// Serve a local ssh-agent socket that presents a direct endpoint's secret.
///
/// Reads the endpoint through the *gated copy* path when it requires
/// authentication: starting a forwarder hands a standing signing credential to
/// a process, which is the same act as putting it on the clipboard and
/// deserves the same confirmation and the same audit entry. An endpoint that
/// requires nothing takes the ungated read, because prompting for a secret
/// that will not be sent would train the user to click through.
fn cmd_ssh_agent(
    connection: String,
    root: Option<PathBuf>,
    broker: Option<String>,
    socket_path: Option<PathBuf>,
    command: Vec<String>,
) {
    let managed = management_backend(root, broker);
    let dto = conn_dto(&managed, &connection);
    if dto.kind != "ssh" {
        die_with(
            ExitCode::Usage,
            format!(
                "{connection} is a {} connection; only ssh connections have an agent socket",
                dto.kind
            ),
        );
    }
    if managed.remote.is_none() {
        die_with(
            ExitCode::NoBroker,
            "the endpoint socket is served by a running broker; start Multitool for the local \
             store, or `aka serve` / `aka serve --root …` for a headless root, then retry",
        );
    }
    let connection_id = dto_id(&dto.id);
    let Some(info) = managed.run(managed.backend.get_endpoint(connection_id)) else {
        die_with(
            ExitCode::NotFound,
            format!(
                "no direct endpoint is issued for {connection} — issue one with \
                 `aka endpoint {connection} --issue --require-auth`"
            ),
        );
    };
    if info.expires_in_secs == Some(0) {
        die_with(
            ExitCode::Usage,
            format!(
                "the direct endpoint for {connection} has expired — renew it with \
                 `aka endpoint {connection} --renew`"
            ),
        );
    }
    // A secret on an SSH endpoint *is* the require-auth flag: the broker
    // surfaces it only for a socket that will demand it.
    let secret = if info.secret.is_empty() {
        eprintln!(
            "  note: this endpoint does not require authentication; its socket can be used \
             directly as IdentityAgent"
        );
        None
    } else {
        let copied = managed.run_gated(managed.backend.copy_endpoint(connection_id));
        match copied {
            Some(copied) if !copied.secret.is_empty() => {
                Some(std::sync::Arc::new(Zeroizing::new(copied.secret)))
            }
            // Revoked between the two reads; the socket below would be gone
            // too, so say what happened rather than serving a dead path.
            _ => die_with(
                ExitCode::NotFound,
                format!("the direct endpoint for {connection} was revoked while starting"),
            ),
        }
    };
    let upstream = PathBuf::from(&info.dsn);

    managed.runtime.block_on(async move {
        let socket = match socket_path {
            Some(path) => ssh_agent::AgentSocket::bind_at(path),
            None => ssh_agent::AgentSocket::bind(),
        }
        .unwrap_or_else(|error| die(format!("could not bind a local agent socket: {error}")));
        let path = socket.path().display().to_string();
        if command.is_empty() {
            // Same shape as `aka ssh`: guidance on stderr, the one pasteable
            // value on stdout, so `$(…)` captures only the path. Unlike
            // `aka ssh` the path dies with this process, so the export is
            // only useful to another terminal while this one is running.
            eprintln!("  serving {connection}'s endpoint until you press Ctrl-C");
            eprintln!("  in another terminal:  export SSH_AUTH_SOCK=\"{path}\"");
            // Not `$(aka ssh-agent …)`: this command does not exit, so a
            // command substitution around it waits forever. The socket dies
            // with this process, which is also why the path is only useful
            // while it is on screen.
            eprintln!("  or run the client here:  aka ssh-agent {connection} -- ssh ...");
            println!("{path}");
            socket
                .serve(upstream, secret, async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await;
            return;
        }
        let mut child = tokio::process::Command::new(&command[0]);
        child.args(&command[1..]).env("SSH_AUTH_SOCK", &path);
        let mut child = match child.spawn() {
            Ok(child) => child,
            Err(error) => die(format!("could not run {}: {error}", command[0])),
        };
        let mut status = None;
        socket
            .serve(upstream, secret, async {
                status = child.wait().await.ok();
            })
            .await;
        // The command's status is this command's status: `aka ssh-agent x --
        // ssh host` must fail when the ssh does, or a script wrapping it
        // cannot tell.
        let Some(status) = status else { return };
        match status.code() {
            Some(0) => {}
            Some(code) => exit_with_raw(code),
            // Killed by a signal: report it the way a shell does, so a
            // Ctrl-C'd `ssh` is not indistinguishable from one that succeeded.
            None => {
                use std::os::unix::process::ExitStatusExt as _;
                exit_with_raw(128 + status.signal().unwrap_or(0))
            }
        }
    });
}

/// Print the shared agent key, rotating it first when asked. The plain
/// print without `--url` is a file read of the key's plaintext home (the
/// same file agents read), so it works alongside a running broker with no
/// token; rotation and remote reads go through the management backend.
fn print_key(key: &str, json: bool) {
    if json {
        print_json(&serde_json::json!({ "key": key }));
    } else {
        println!("{key}");
    }
}

fn cmd_key(rotate: bool, root: Option<PathBuf>, url: Option<String>, json: bool) {
    let (root, url) = ambient_management_target(root, url);
    if url.is_none() && !rotate {
        require_existing_root_for_read(root.as_deref(), false);
        let paths = store_paths(root.as_deref());
        let token_file = paths.token_file();
        match std::fs::read_to_string(&token_file) {
            Ok(token) if !token.trim().is_empty() => {
                let token = Zeroizing::new(token);
                print_key(token.trim(), json);
            }
            _ => die(format!(
                "no shared key at {} — the broker mints it when it first starts",
                token_file.display()
            )),
        }
        return;
    }
    let managed = management_backend(root, url);
    if rotate {
        managed.run_gated(managed.backend.rotate_key());
        ack("key rotated; agents that read the token file reconnect on their own");
    }
    let key = Zeroizing::new(managed.run(managed.backend.agent_key()));
    print_key(&key, json);
}

#[derive(Debug, serde::Serialize)]
struct StatusTool {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    target: String,
    enabled: bool,
    confirm: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    response_credentials_exposed: bool,
    /// Whether a direct endpoint is issued for this tool.
    ///
    /// Status listed what agents *could* reach through the control plane and
    /// said nothing about standing access already handed out, which is the
    /// longer-lived of the two and the one a reader is more likely to have
    /// forgotten.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    endpoint: bool,
}

impl From<&ConnectionDto> for StatusTool {
    fn from(connection: &ConnectionDto) -> Self {
        Self {
            name: connection.name.clone(),
            kind: connection.kind.clone(),
            target: connection.target.clone(),
            enabled: connection.agent_access.enabled,
            confirm: connection.agent_access.confirm,
            response_credentials_exposed: connection.agent_access.expose_response_credentials,
            endpoint: connection.agent_access.endpoint.is_some(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct StatusReport {
    running: bool,
    transport: String,
    location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    broker_version: Option<String>,
    cli_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_key_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_surface_attached: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    recent_ssh_refusals: Vec<StatusSshRefusal>,
    tools: Vec<StatusTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools_error: Option<String>,
}

#[derive(Debug)]
struct StatusFailure {
    report: Box<StatusReport>,
    code: ExitCode,
    diagnostic: String,
}

#[derive(Debug, serde::Serialize)]
struct StatusSshRefusal {
    connection: String,
    at: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn status_ssh_refusals(entries: &[ActivityDto]) -> Vec<StatusSshRefusal> {
    let mut seen = std::collections::HashSet::new();
    entries
        .iter()
        .filter(|entry| entry.kind.as_deref() == Some("denied"))
        .filter(|entry| entry.protocol.as_deref() == Some("ssh"))
        .filter_map(|entry| {
            let connection = entry.connection.as_ref()?;
            let reason = entry.outcome.as_ref()?;
            if !seen.insert(connection.clone()) {
                return None;
            }
            Some(StatusSshRefusal {
                connection: connection.clone(),
                at: entry.at.clone(),
                reason: reason.clone(),
                detail: entry.detail.clone(),
            })
        })
        .collect()
}

fn status_tools(connections: &[ConnectionDto]) -> Vec<StatusTool> {
    connections.iter().map(StatusTool::from).collect()
}

fn status_heading(transport: &str, location: &str) -> String {
    let desktop_socket = Paths::default_locations()
        .ok()
        .map(|paths| paths.socket_file().display().to_string());
    let broker = if transport == "unix"
        && desktop_socket
            .as_deref()
            .is_some_and(|socket| socket == location)
    {
        "desktop broker"
    } else {
        "broker"
    };
    let location_note = if transport == "manage_api" {
        " (manage API)"
    } else {
        ""
    };
    format!("{broker} running on {location}{location_note}")
}

fn print_status_report(report: &StatusReport) {
    let color = stdout_use_color();
    println!(
        "{}",
        paint::bold_green(color, status_heading(&report.transport, &report.location))
    );
    if let Some(version) = &report.broker_version {
        match report.protocol_version {
            Some(protocol) => println!(
                "{}",
                colon_field(
                    color,
                    "  ",
                    "version",
                    format!(
                        "broker {version}, aka CLI {} (protocol {protocol})",
                        report.cli_version
                    )
                )
            ),
            None => println!(
                "{}",
                colon_field(
                    color,
                    "  ",
                    "version",
                    format!("broker {version}, aka CLI {}", report.cli_version)
                )
            ),
        }
    }
    if let Some(url) = &report.mcp_url {
        println!("{}", colon_field(color, "  ", "MCP host", url));
    } else if report.transport == "unix" {
        println!(
            "{}",
            colon_field(
                color,
                "  ",
                "MCP host",
                paint::bold_yellow(color, "not running")
            )
        );
    }
    if let Some(client_id) = &report.client_id {
        println!("{}", colon_field(color, "  ", "client id", client_id));
    }
    if let Some(path) = &report.shared_key_path {
        let qualifier = match report.shared_key_present {
            Some(true) => "",
            Some(false) => " (not minted yet)",
            None => " (on the broker host)",
        };
        println!(
            "{}",
            colon_field(color, "  ", "shared key", format!("{path}{qualifier}"))
        );
    }
    if let Some(vault) = &report.vault {
        println!("{}", colon_field(color, "  ", "vault", vault));
    }
    if !report.recent_ssh_refusals.is_empty() {
        println!("{}", colon_field(color, "  ", "recent SSH refusals", ""));
        let rows = report.recent_ssh_refusals.iter().map(|refusal| {
            vec![
                refusal.connection.clone(),
                refusal.at.clone(),
                refusal.reason.clone(),
                refusal.detail.clone().unwrap_or_else(|| "—".into()),
            ]
        });
        println!(
            "{}",
            presentation::table(&["connection", "at", "reason", "detail"], rows)
        );
    }
    if let Some(error) = &report.tools_error {
        println!(
            "{}",
            colon_field(
                color,
                "  ",
                "tools",
                paint::bold_yellow(color, format!("unavailable ({error})"))
            )
        );
        return;
    }
    if report.tools.is_empty() {
        println!(
            "{}",
            colon_field(
                color,
                "  ",
                "tools",
                "none configured — add one with `aka conn add pg --help` or the desktop app"
            )
        );
        return;
    }
    println!("{}", colon_field(color, "  ", "tools", ""));
    let approval_surface_attached = report.approval_surface_attached.unwrap_or(false);
    let rows = report.tools.iter().map(|tool| {
        let mut policy = Vec::new();
        if tool.confirm {
            if approval_surface_attached {
                policy.push("confirm: on".to_string());
            } else {
                policy
                    .push("confirm: on; no approval surface — traffic will be refused".to_string());
            }
        }
        // A direct endpoint outlives any session and is revoked separately, so
        // it is named on the row rather than left to the app to reveal.
        if tool.endpoint {
            policy.push("direct endpoint issued".into());
        }
        let access = if tool.enabled { "enabled" } else { "disabled" };
        vec![
            tool.name.clone(),
            tool.kind.clone(),
            tool.target.clone(),
            access.into(),
            if policy.is_empty() {
                "—".into()
            } else {
                policy.join(" · ")
            },
        ]
    });
    println!(
        "{}",
        presentation::table(&["name", "kind", "target", "access", "policy"], rows)
    );
    if !approval_surface_attached {
        if let Some(warning) =
            headless_confirmation_warning(report.tools.iter().filter(|tool| tool.confirm).count())
        {
            eprintln!("{}", paint::bold_yellow(stderr_use_color(), &warning));
        }
    }
}

fn headless_confirmation_warning(count: usize) -> Option<String> {
    (count > 0).then(|| {
        format!(
            "warning: {count} tool{} {} set to confirm traffic and this broker has no approval \
             surface; {} calls will be refused",
            if count == 1 { "" } else { "s" },
            if count == 1 { "is" } else { "are" },
            if count == 1 { "its" } else { "their" },
        )
    })
}

/// `status --broker`: the broker as its manage API reports it.
fn remote_status(root: Option<PathBuf>, url: String) -> StatusReport {
    let managed = management_backend(root, Some(url.clone()));
    let identity = managed.run(managed.backend.identity());
    let connections = managed.run(managed.backend.list_connections());
    let activity = managed.run(managed.backend.activity(100));
    StatusReport {
        running: true,
        transport: "manage_api".into(),
        location: url,
        broker_version: managed
            .profile
            .as_ref()
            .and_then(|profile| profile["version"].as_str())
            .map(str::to_string),
        cli_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: managed
            .profile
            .as_ref()
            .and_then(|profile| profile["protocol_version"].as_u64()),
        mcp_url: managed
            .profile
            .as_ref()
            .and_then(|profile| profile["mcp_url"].as_str())
            .map(str::to_string),
        client_id: Some(identity.client_id),
        shared_key_path: Some(identity.token_path),
        shared_key_present: None,
        vault: None,
        approval_surface_attached: Some(managed.approval_surface_attached()),
        recent_ssh_refusals: status_ssh_refusals(&activity),
        tools: status_tools(&connections),
        tools_error: None,
    }
}

/// Report the backend that owns this store's secrets. On macOS, include which
/// keychain controls prompts; on Linux, make encrypted versus plaintext
/// fallback (and a missing configured master key) explicit.
fn vault_description(paths: &Paths) -> String {
    #[cfg(target_os = "macos")]
    if let Some(keychain) = aka_core::keychain::read_record(&paths.keychain_file()) {
        let note = match keychain {
            aka_core::keychain::Keychain::DataProtection => "no prompts",
            aka_core::keychain::Keychain::Login => "prompts per secret; build is unsigned",
        };
        return format!("macOS {keychain} keychain ({note})");
    }
    let backend = recorded_platform_vault_backend(paths)
        .unwrap_or_else(|| selected_platform_vault_backend(paths));
    match backend {
        PlatformVaultBackend::MacosKeychain => "macOS Keychain (not initialized yet)".into(),
        PlatformVaultBackend::EncryptedFile => {
            let configured =
                selected_platform_vault_backend(paths) == PlatformVaultBackend::EncryptedFile;
            let note = if configured {
                "master key configured"
            } else {
                "set AKA_VAULT_KEY or AKA_VAULT_KEY_FILE"
            };
            format!(
                "encrypted file at {} ({note})",
                paths.encrypted_vault_file().display()
            )
        }
        PlatformVaultBackend::PlaintextDevFile => format!(
            "plaintext dev fallback at {} (set AKA_VAULT_KEY or AKA_VAULT_KEY_FILE)",
            paths.dev_vault_file().display()
        ),
    }
}

fn socket_status_error(socket: &Path, error: &std::io::Error) -> String {
    if error.raw_os_error() == Some(libc::ENOTSOCK) {
        return format!("{} exists but is not a Unix socket", socket.display());
    }
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            format!("no broker is running at {}", socket.display())
        }
        std::io::ErrorKind::PermissionDenied => format!(
            "permission denied opening broker socket {}; check its owner and mode",
            socket.display()
        ),
        _ => format!(
            "could not inspect broker socket {}: {error}",
            socket.display()
        ),
    }
}

fn socket_status_exit_code(error: &std::io::Error) -> ExitCode {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => ExitCode::NoBroker,
        _ => ExitCode::Generic,
    }
}

fn local_status(root: Option<PathBuf>) -> Result<StatusReport, StatusFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let paths = store_paths(root.as_deref());
    let socket = paths.socket_file();
    let key_present = std::fs::metadata(paths.token_file())
        .map(|metadata| metadata.len() > 0)
        .unwrap_or(false);
    let base = || StatusReport {
        running: false,
        transport: "unix".into(),
        location: socket.display().to_string(),
        broker_version: None,
        cli_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: None,
        mcp_url: None,
        client_id: None,
        shared_key_path: Some(paths.token_file().display().to_string()),
        shared_key_present: Some(key_present),
        vault: Some(vault_description(&paths)),
        approval_surface_attached: None,
        recent_ssh_refusals: Vec::new(),
        tools: Vec::new(),
        tools_error: None,
    };
    let manifest = match runtime.block_on(client::unix_http(
        &socket,
        "GET",
        "/.well-known/agent-broker.json",
        None,
        None,
        None,
    )) {
        Ok((200, body)) => {
            serde_json::from_str::<serde_json::Value>(&body).unwrap_or_else(|error| {
                die(format!("the broker returned malformed discovery: {error}"))
            })
        }
        Ok((status, _)) => die(format!(
            "the broker at {} answered discovery with HTTP {status}",
            socket.display()
        )),
        Err(error) => {
            let report = base();
            return Err(StatusFailure {
                report: Box::new(report),
                code: socket_status_exit_code(&error),
                diagnostic: socket_status_error(&socket, &error),
            });
        }
    };

    // Status never authenticates as an agent and never pairs. If an existing
    // management credential is available, use the read-only manage plane for
    // tool detail; otherwise report that subsection as unavailable.
    let manage_key = socket.display().to_string();
    let (client_id, approval_surface_attached, recent_ssh_refusals, tools, tools_error) =
        match manage_token(&paths, &manage_key) {
            Some(token) => {
                let backend = RemoteBackend::over_unix_socket(socket.clone(), &token);
                match runtime.block_on(async {
                    let profile = backend.whoami().await?;
                    let connections = backend.list_connections().await?;
                    let activity = backend.activity(100).await?;
                    Ok::<_, ManageError>((profile, connections, activity))
                }) {
                    Ok((profile, connections, activity)) => (
                        profile["client_id"].as_str().map(str::to_string),
                        profile["approval_surface_attached"].as_bool(),
                        status_ssh_refusals(&activity),
                        status_tools(&connections),
                        None,
                    ),
                    Err(error) => (
                        None,
                        None,
                        Vec::new(),
                        Vec::new(),
                        Some(format!("manage API read failed: {error}")),
                    ),
                }
            }
            None => (
                None,
                None,
                Vec::new(),
                Vec::new(),
                Some(
                    "no management token configured; run `aka admin login` to include tools"
                        .into(),
                ),
            ),
        };
    Ok(StatusReport {
        running: true,
        transport: "unix".into(),
        location: socket.display().to_string(),
        broker_version: manifest["version"].as_str().map(str::to_string),
        cli_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: manifest["protocol_version"].as_u64(),
        mcp_url: manifest["mcp_url"].as_str().map(str::to_string),
        client_id,
        shared_key_path: Some(paths.token_file().display().to_string()),
        shared_key_present: Some(key_present),
        vault: Some(vault_description(&paths)),
        approval_surface_attached,
        recent_ssh_refusals,
        tools,
        tools_error,
    })
}

fn cmd_status(json: bool, root: Option<PathBuf>, url: Option<String>) {
    let (root, url) = ambient_management_target(root, url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    let result = match url {
        Some(url) => Ok(remote_status(root, url)),
        None => local_status(root),
    };
    match result {
        Ok(report) => {
            if report.transport == "unix"
                && report
                    .broker_version
                    .as_deref()
                    .is_some_and(|version| version != report.cli_version)
            {
                eprintln!(
                    "{}",
                    paint::bold_yellow(
                        stderr_use_color(),
                        format!(
                            "warning: broker version {} differs from aka CLI version {}; update them together before making changes",
                            report.broker_version.as_deref().unwrap_or("unknown"),
                            report.cli_version
                        )
                    )
                );
            }
            if json {
                print_json(&report);
            } else {
                print_status_report(&report);
            }
        }
        Err(StatusFailure {
            report,
            code,
            diagnostic,
        }) => {
            if json {
                print_json(&report);
            } else {
                let color = stderr_use_color();
                if let Some(vault) = &report.vault {
                    eprintln!("{}", colon_field(color, "  ", "vault", vault));
                }
                if let Some(path) = &report.shared_key_path {
                    let state = if report.shared_key_present == Some(true) {
                        "present"
                    } else {
                        "not minted yet"
                    };
                    eprintln!(
                        "{}",
                        colon_field(color, "  ", "shared key", format!("{state} at {path}"))
                    );
                }
            }
            die_with(code, diagnostic);
        }
    }
}

/// One formatted line per projected activity entry: timestamp (seconds
/// precision), summary, detail, and the acting agent when recorded.
/// When `color` is on, the timestamp and agent tag are dimmed.
fn format_activity_line(entry: &ActivityDto, color: bool) -> String {
    let ts = entry.at.get(..19).unwrap_or(&entry.at);
    let mut line = format!("{}  {}", paint::dim(color, ts), entry.text);
    if let Some(detail) = &entry.detail {
        line.push_str(&format!(" — {detail}"));
    }
    if let Some(agent) = &entry.agent {
        line.push_str(&format!("  {}", paint::dim(color, format!("[{agent}]"))));
    }
    line
}

fn print_activity(entries: &[ActivityDto], json: bool) {
    if json {
        print_json(&entries);
    } else {
        let color = stdout_use_color();
        for entry in entries {
            println!("{}", format_activity_line(entry, color));
        }
    }
}

/// Remote activity as the manage API renders it.
fn cmd_activity_remote(limit: usize, root: Option<PathBuf>, url: String) -> Vec<ActivityDto> {
    let managed = management_backend(root, Some(url));
    let mut entries = managed.run(managed.backend.activity(limit));
    // The manage API returns newest first; match the local newest-last view.
    entries.reverse();
    entries
}

fn cmd_activity(limit: usize, json: bool, root: Option<PathBuf>, url: Option<String>) {
    let (root, url) = ambient_management_target(root, url);
    require_existing_root_for_read(root.as_deref(), url.is_some());
    if let Some(url) = url {
        let entries = cmd_activity_remote(limit, root, url);
        print_activity(&entries, json);
        return;
    }
    let paths = store_paths(root.as_deref());
    let file = paths.audit_file();
    match std::fs::metadata(&file) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if json {
                print_activity(&[], true);
            } else {
                ack_dim(format!(
                    "no activity recorded yet ({} does not exist)",
                    file.display()
                ));
            }
            return;
        }
        Err(e) => die(format!("could not inspect {}: {e}", file.display())),
    }
    let vault = match open_vault(&paths, root.as_deref()) {
        Ok(vault) => vault,
        Err(e) => die(format!("could not open the secret vault: {e}")),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let integrity = match runtime.block_on(aka_core::integrity::StateIntegrity::open_for_paths(
        &*vault, &paths,
    )) {
        Ok(integrity) => Arc::new(integrity),
        Err(e) => die(format!("could not open the state integrity key: {e}")),
    };
    // Check an existing seal before `open_sealed`: opening is allowed to
    // adopt a genuinely absent legacy seal, but must not turn a damaged seal
    // into a fresh legacy baseline merely because this is a CLI read.
    if paths.audit_seal_file().exists() {
        if let Err(error) = integrity.read_verified(&paths.audit_seal_file()) {
            die(format!("activity log integrity check failed: {error}"));
        }
    }
    let audit =
        match aka_core::audit::AuditLog::open_sealed(file, paths.audit_seal_file(), integrity) {
            Ok(audit) => audit,
            Err(e) => die(format!("could not open the activity log: {e}")),
        };
    let verification = audit.verify();
    match &verification {
        aka_core::audit::AuditIntegrity::Tampered { .. } => die(verification.summary()),
        aka_core::audit::AuditIntegrity::Unsealed { .. } => {
            warn_line(format!("warning: {}", verification.summary()))
        }
        aka_core::audit::AuditIntegrity::Verified { legacy, .. } if *legacy > 0 => {
            warn_line(format!("warning: {}", verification.summary()))
        }
        aka_core::audit::AuditIntegrity::Verified { .. } => {}
    }
    let mut entries = audit.recent(if limit == 0 { usize::MAX } else { limit });
    entries.reverse();
    let entries = entries.iter().map(activity_dto).collect::<Vec<_>>();
    print_activity(&entries, json);
}

fn cmd_mcp(root: Option<PathBuf>, client: Option<String>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let agent = usage_agent(root.as_deref());
    if let Err(message) = runtime.block_on(mcp_bridge::run(agent, client)) {
        die(message);
    }
}

/// `aka setup <client> --write`: do the three things the printed form tells
/// you to do — register the MCP server with the client, write the repo-local
/// agent skill, and pin this directory to the current context.
///
/// Each step reports separately and a failure in one does not abandon the
/// others: the client registration is the only step that shells out, and a
/// missing CLI is a normal outcome (Claude Desktop is configured by editing
/// JSON, not by a command) rather than a reason to skip the skill file.
fn cmd_setup_apply(client: McpSetupClient, json: bool) {
    let label = client.label();
    let mut done: Vec<serde_json::Value> = Vec::new();

    match client {
        McpSetupClient::ClaudeCode => match register_claude_code() {
            Ok(()) => {
                ack("registered MCP server multitool with Claude Code");
                done.push(serde_json::json!({ "step": "mcp", "applied": true }));
            }
            Err(message) => {
                warn_line(format!("could not register with Claude Code: {message}"));
                guide("register it yourself: claude mcp add multitool -- aka mcp --client claude-code");
                done.push(
                    serde_json::json!({ "step": "mcp", "applied": false, "detail": message }),
                );
            }
        },
        // Codex and Claude Desktop are configured by editing a file the user
        // owns and that carries their other servers. Rewriting TOML/JSON in
        // place risks clobbering that, so print the stanza and say where.
        _ => {
            let (target, content) = client_config(client);
            warn_line(format!("{label} is configured by editing {target}"));
            eprintln!("{content}");
            done.push(serde_json::json!({
                "step": "mcp", "applied": false, "target": target,
            }));
        }
    }

    let content = wellknown::skill_file(&BrokerConfig::default(), &doc_paths(None));
    let skill_path = write_skill_file(&content, None, false, false);
    ack(format!("wrote {}", skill_path.display()));
    done.push(serde_json::json!({
        "step": "skill", "applied": true, "path": skill_path.display().to_string(),
    }));

    // Pin only what is already the ambient answer: writing a pin the user
    // did not choose would make this command decide where their agents point.
    let pinned = match ambient_context() {
        Some((source, _)) if source.starts_with("repo pin") => {
            done.push(serde_json::json!({
                "step": "pin", "applied": false, "reason": "already pinned",
            }));
            true
        }
        Some(_) => match load_contexts().current.clone() {
            Some(name) => {
                std::fs::write(PIN_FILE, format!("{name}\n"))
                    .unwrap_or_else(|error| die(format!("could not write {PIN_FILE}: {error}")));
                ack(format!(
                    "pinned this directory to context {name} — commit {PIN_FILE}"
                ));
                done.push(serde_json::json!({ "step": "pin", "applied": true, "context": name }));
                true
            }
            None => {
                done.push(serde_json::json!({ "step": "pin", "applied": false }));
                false
            }
        },
        None => {
            done.push(serde_json::json!({ "step": "pin", "applied": false }));
            false
        }
    };

    mutation_ok(
        "setup.write",
        serde_json::json!({ "client": label, "steps": done }),
    );
    if json {
        return;
    }
    // Only claim what actually happened. A client this command cannot
    // configure, or a repo with no context, leaves a step for the user.
    if pinned {
        guide("agents working in this repo reach this broker automatically");
    } else {
        guide(
            "this repo has no broker context pinned; agents will use the \
             local broker unless you run `aka use <name> --pin`",
        );
    }
}

/// Register the MCP server through the Claude Code CLI, which owns the
/// config file's format and location.
fn register_claude_code() -> Result<(), String> {
    let output = std::process::Command::new("claude")
        .args([
            "mcp",
            "add",
            "multitool",
            "--",
            "aka",
            "mcp",
            "--client",
            "claude-code",
        ])
        .output()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => "the `claude` CLI is not on PATH".to_string(),
            _ => error.to_string(),
        })?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    // Already-registered is success for our purposes: the end state the user
    // asked for is the one they have.
    if detail.contains("already exists") {
        return Ok(());
    }
    Err(if detail.is_empty() {
        format!("claude mcp add exited with {}", output.status)
    } else {
        detail.to_string()
    })
}

/// The paste-ready configuration for a client: where it goes, and what goes
/// there.
fn client_config(client: McpSetupClient) -> (&'static str, &'static str) {
    match client {
        McpSetupClient::Codex => (
            "~/.codex/config.toml",
            "[mcp_servers.multitool]\ncommand = \"aka\"\nargs = [\"mcp\", \"--client\", \"codex\"]\n",
        ),
        McpSetupClient::ClaudeCode => (
            "Claude Code CLI",
            "claude mcp add multitool -- aka mcp --client claude-code\n",
        ),
        McpSetupClient::ClaudeDesktop => (
            "claude_desktop_config.json",
            "{\n  \"mcpServers\": {\n    \"multitool\": {\n      \"command\": \"aka\",\n      \"args\": [\"mcp\", \"--client\", \"claude-desktop\"]\n    }\n  }\n}\n",
        ),
    }
}

fn cmd_setup_mcp(client: McpSetupClient, json: bool) {
    let label = client.label();
    let args = ["mcp", "--client", label];
    let (target, content) = client_config(client);
    let format = match client {
        McpSetupClient::Codex => "toml",
        McpSetupClient::ClaudeCode => "shell",
        McpSetupClient::ClaudeDesktop => "json",
    };
    if json {
        print_json(&serde_json::json!({
            "client": label,
            "target": target,
            "format": format,
            "command": "aka",
            "args": args,
            "content": content,
        }));
    } else {
        print!("{content}");
    }
}

/// `aka setup desktop`: what the desktop app's connect form needs to reach
/// a headless broker. Never mints or rotates the management token — the
/// broker keeps exactly one, so issuing here would silently disconnect
/// whoever holds the current token. Only a token that already exists is
/// surfaced: AKA_MANAGE_TOKEN, the `aka admin login` store, or the
/// first-start bootstrap file, first one the broker accepts.
fn cmd_setup_desktop(root: Option<PathBuf>, json: bool) {
    let root = serve_root_from_flags(root);
    let root_flag = format!(" --root {}", shell_quote(&root.display().to_string()));
    let paths = Paths::under(&root);
    let socket = paths.socket_file();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let manifest = match runtime.block_on(client::unix_http(
        &socket,
        "GET",
        "/.well-known/agent-broker.json",
        None,
        None,
        None,
    )) {
        Ok((200, body)) => {
            serde_json::from_str::<serde_json::Value>(&body).unwrap_or_else(|error| {
                die(format!("the broker returned malformed discovery: {error}"))
            })
        }
        Ok((status, _)) => die(format!(
            "the broker at {} answered discovery with HTTP {status}",
            socket.display()
        )),
        Err(error) => die_with(
            socket_status_exit_code(&error),
            format!(
                "no broker is running at {} — start one: `aka serve{root_flag}`",
                socket.display()
            ),
        ),
    };
    let Some(url) = manifest["base_url"].as_str() else {
        die_with(
            ExitCode::Generic,
            format!(
                "this broker advertises no URL the app could dial — restart it with \
                 the TCP listener (the default): `aka serve{root_flag}`, or set \
                 --public-url for a non-loopback listener"
            ),
        );
    };

    let env_token = std::env::var("AKA_MANAGE_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new);
    let stored_token = manage_token_store(&paths).load(&socket.display().to_string());
    let bootstrap_token = std::fs::read_to_string(paths.manage_bootstrap_token_file())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new);
    let candidates = [
        (env_token, "AKA_MANAGE_TOKEN"),
        (stored_token, "saved by `aka admin login`"),
        (bootstrap_token, "the first-start token file"),
    ];
    let token = candidates.into_iter().find_map(|(token, source)| {
        let token = token?;
        let backend = RemoteBackend::over_unix_socket(socket.clone(), &token);
        runtime
            .block_on(backend.whoami())
            .is_ok()
            .then_some((token, source))
    });

    if json {
        print_json(&serde_json::json!({
            "url": url,
            "token": token.as_ref().map(|(token, _)| token.as_str()),
            "token_source": token.as_ref().map(|(_, source)| *source),
        }));
        return;
    }
    let color = stdout_use_color();
    println!(
        "{}",
        paint::bold_green(color, "Connect the desktop app to this broker")
    );
    println!(
        "{}",
        paint::dim(
            color,
            "The app reaches it as a hosted instance; \"Local Multitool\" is a \
             different broker."
        )
    );
    println!("{}", colon_field(color, "  ", "URL", url));
    match &token {
        Some((token, source)) => println!(
            "{}",
            colon_field(
                color,
                "  ",
                "token",
                format!("{}  ({source})", token.as_str())
            )
        ),
        None => println!(
            "{}",
            colon_field(
                color,
                "  ",
                "token",
                format!(
                    "none found — mint one: `aka admin token{root_flag}` \
                     (minting rotates: a previously issued token stops working)"
                )
            )
        ),
    }
    println!();
    println!(
        "In the app: choose \"Hosted Multitool\" (or \"Connect remote…\" in the broker menu),"
    );
    println!("enter the URL, then open Advanced and paste the token under \"Management token\".");
    println!("Passkeys work too: enroll with `aka admin enroll`, then \"Sign in with passkey\".");
}

/// Everything `aka serve` accepts, bundled so the call site stays legible.
struct ServeArgs {
    root: Option<PathBuf>,
    listen: Option<std::net::SocketAddr>,
    no_listen: bool,
    public_url: Option<String>,
    web_root: Option<PathBuf>,
    data_plane_listen: Option<std::net::IpAddr>,
    advertise_host: Option<String>,
    data_plane_insecure: bool,
    session_idle_timeout: Option<u64>,
    session_max_ttl: Option<u64>,
    audit_pg_statements: bool,
    no_mcp: bool,
}

/// Whether a stream should carry ANSI color. Honors `NO_COLOR` and
/// `CLICOLOR_FORCE`, otherwise follows whether the stream is a TTY.
fn stream_use_color(stream: &impl std::io::IsTerminal) -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| v != "0") {
        return true;
    }
    stream.is_terminal()
}

fn stderr_use_color() -> bool {
    stream_use_color(&std::io::stderr())
}

fn stdout_use_color() -> bool {
    stream_use_color(&std::io::stdout())
}

/// `label: value` line used by status / conn show (and the offline status
/// diagnostic). Indent is applied before the painted label.
fn colon_field(color: bool, indent: &str, label: &str, value: impl std::fmt::Display) -> String {
    let label = paint::bold_cyan(color, label);
    let value = value.to_string();
    if value.is_empty() {
        format!("{indent}{label}:")
    } else {
        format!("{indent}{label}: {value}")
    }
}

/// Successful mutation / action ack on stderr.
fn ack(message: impl std::fmt::Display) {
    if JSON_OUTPUT.load(Ordering::Relaxed) {
        return;
    }
    presentation::success(message, stderr_use_color());
}

/// Soft secondary ack ("already …", empty lists) on stderr.
fn ack_dim(message: impl std::fmt::Display) {
    if JSON_OUTPUT.load(Ordering::Relaxed) {
        return;
    }
    presentation::remark(message, stderr_use_color());
}

/// Operator guidance label on stderr (cyan). Values meant for capture stay
/// on plain stdout separately.
fn guide(message: impl std::fmt::Display) {
    presentation::info(message, stderr_use_color());
}

/// Warning / note on stderr (yellow).
fn warn_line(message: impl std::fmt::Display) {
    presentation::warning(message, stderr_use_color());
}

/// Parse argv with clap's validation and the generated Multitool help view.
fn configured_cli_command(color: bool, long_help: bool) -> clap::Command {
    // Propagate CLI_STYLES from the root command onto every subcommand so
    // `aka serve --help`, `aka conn show --help`, etc. match the
    // top-level palette, and align clap errors with our help renderer.
    // Color is configured before build so clap propagates it to every child.
    let mut cmd = if color {
        Cli::command().color(clap::ColorChoice::Always)
    } else {
        Cli::command().color(clap::ColorChoice::Never)
    };
    presentation::install_help(&mut cmd, color, long_help);
    cmd
}

fn command_line_requests_long_help() -> bool {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    args.iter().any(|arg| arg == "--help") || args.first().is_some_and(|arg| arg == "help")
}

fn parse_cli() -> Cli {
    let cmd = configured_cli_command(stdout_use_color(), command_line_requests_long_help());
    let matches = match cmd.try_get_matches() {
        Ok(matches) => matches,
        Err(error) => {
            let args: Vec<String> = std::env::args().skip(1).collect();
            if let Some(scaffold) = conn_add_scaffold(&error, &args) {
                let _ = error.print();
                eprintln!("{scaffold}");
                exit_with(ExitCode::Usage);
            }
            error.exit()
        }
    };
    match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    }
}

/// A `conn add` missing its required capability flags gets a filled-in,
/// editable scaffold under clap's error — the two commands (vault the
/// secret, add the connection) in place of a wizard. Returns None for
/// every other error so clap's rendering stays untouched.
fn conn_add_scaffold(error: &clap::Error, args: &[String]) -> Option<String> {
    if error.kind() != clap::error::ErrorKind::MissingRequiredArgument {
        return None;
    }
    let mut words = args.iter().map(String::as_str);
    if words.next()? != "conn" || words.next()? != "add" {
        return None;
    }
    let kind = words.next()?;
    // Best-effort name recovery: the first token that is neither a flag nor
    // a flag's value. Booleans here would swallow the name; a placeholder
    // is fine when that happens.
    let mut name = None;
    let mut rest = args.iter().skip(3).map(String::as_str);
    while let Some(token) = rest.next() {
        if let Some(flag) = token.strip_prefix("--") {
            if !flag.contains('=') {
                rest.next();
            }
            continue;
        }
        name = Some(token);
        break;
    }
    let display = name.unwrap_or("<name>");
    let secret: String = {
        let cleaned: String = display
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();
        let base = cleaned.trim_matches('_');
        if base.is_empty() || name.is_none() {
            "SECRET_NAME".to_string()
        } else {
            base.to_string()
        }
    };
    let color = stderr_use_color();
    let body = match kind {
        "pg" => format!(
            "  aka secret add {secret}_PASSWORD < password.txt\n  \
             aka conn add pg {display} \\\n      \
             --host db.internal.example.com --dbname app \\\n      \
             --user agent_ro --secret {secret}_PASSWORD"
        ),
        "ssh" => format!(
            "  aka secret add {secret}_KEY < id_ed25519\n  \
             aka conn add ssh {display} \\\n      \
             --host {display}.internal.example.com --user deploy --secret {secret}_KEY"
        ),
        "api" => format!(
            "  aka secret add {secret}_TOKEN < token.txt\n  \
             aka conn add api {display} \\\n      \
             --host api.example.com \\\n      \
             --template 'Authorization: Bearer {{{{{secret}_TOKEN}}}}' --test-path /user"
        ),
        _ => return None,
    };
    Some(format!(
        "\n{}\n\n{}\n\n{}",
        paint::dim(color, "A complete add looks like:"),
        paint::bold_cyan(color, body),
        paint::dim(
            color,
            "The secret is vaulted by reference and never travels in argv. \
             The desktop app offers the same fields with a UI."
        )
    ))
}

/// Semantic paint helpers retained as a short local name at call sites.
mod paint {
    pub use crate::presentation::{bold_cyan, bold_green, bold_red, bold_yellow, dim};
}

/// How the agent-facing MCP host came up for the serve banner.
#[derive(Debug, Clone, PartialEq, Eq)]
enum McpBannerStatus {
    Disabled,
    Started { addr: std::net::SocketAddr },
    Failed(String),
}

/// Inputs for the `aka serve` ready banner. Formatted once as plain
/// lines (for tests and non-TTY) and printed with optional color on a TTY.
struct ServeBanner {
    socket: PathBuf,
    root: PathBuf,
    /// Leading-space flag fragment, e.g. ` --root '/path'`.
    root_flag: String,
    first_start_manage_token: Option<PathBuf>,
    tcp_addr: Option<std::net::SocketAddr>,
    public_url: Option<String>,
    web_root: Option<PathBuf>,
    advertise_host: Option<String>,
    mcp: McpBannerStatus,
    vault: String,
    headless_warning: Option<String>,
    token_path: PathBuf,
}

impl ServeBanner {
    /// The URL a remote `--broker` flag would use: the public URL when
    /// configured, otherwise the bound TCP address. None when not listening.
    fn manage_url(&self) -> Option<String> {
        match (&self.public_url, self.tcp_addr) {
            (Some(url), _) => Some(url.clone()),
            (None, Some(addr)) => Some(format!("http://{addr}")),
            (None, None) => None,
        }
    }

    /// Plain-text lines (no ANSI). The last line is empty so the process
    /// leaves a blank line before any later log noise.
    fn lines(&self) -> Vec<String> {
        let mut out = vec![
            "Multitool broker ready".into(),
            String::new(),
            format_label("Socket", self.socket.display()),
            format_label("Root", self.root.display()),
        ];
        if let Some(host) = &self.advertise_host {
            out.push(format_label(
                "Data host",
                format!("{host}  (PG leg is plaintext)"),
            ));
        }
        match &self.mcp {
            McpBannerStatus::Disabled => {}
            McpBannerStatus::Started { addr } => {
                out.push(format_label("MCP", addr));
            }
            McpBannerStatus::Failed(error) => {
                out.push(format_label("MCP", format!("not started ({error})")));
            }
        }
        out.push(format_label("Keychain", &self.vault));

        out.push(String::new());

        if let Some(path) = &self.first_start_manage_token {
            out.push(format_label(
                "First token",
                format!(
                    "{}  (0600, expires in {} days)",
                    path.display(),
                    DEFAULT_MANAGE_TOKEN_TTL_DAYS
                ),
            ));
            out.push(format_label(
                "Rotate",
                format!(
                    "aka admin token{} while the broker is live",
                    self.root_flag
                ),
            ));
        } else {
            out.push(format_label(
                "Manage",
                format!(
                    "aka status{}  (every aka command takes --root)",
                    self.root_flag
                ),
            ));
            if let Some(url) = self.manage_url() {
                out.push(format_label(
                    "Remote",
                    format!("the same commands with --broker {url} and a manage token"),
                ));
            }
        }
        if self.manage_url().is_some() {
            out.push(format_label(
                "Desktop",
                format!(
                    "aka setup desktop{}  (the app connects to this broker as remote)",
                    self.root_flag
                ),
            ));
        }
        out.push(format_label(
            "Agent key",
            format!(
                "{}  (agent clients read this to connect)",
                self.token_path.display()
            ),
        ));
        out.push(format_label(
            "Agent docs",
            format!(
                "curl --unix-socket {} http://localhost/instructions",
                self.socket.display()
            ),
        ));
        out.push(format_label(
            "Skill",
            format!(
                "aka setup skill --write{}  (installs these docs for Claude)",
                self.root_flag
            ),
        ));

        if self.tcp_addr.is_some() || self.headless_warning.is_some() {
            out.push(String::new());
        }
        if self.tcp_addr.is_some() {
            out.push(format_label("Note", "/v1/pair is not served on TCP"));
        }
        if let Some(warning) = &self.headless_warning {
            out.push(format_label("Warning", warning));
        }

        // TCP control plane / web UI — own group so the default listener and
        // the explicit --no-listen state are both obvious.
        out.push(String::new());
        match self.tcp_addr {
            Some(addr) => out.push(format_label(
                "TCP",
                format!("{addr}  (plaintext; put TLS in front)"),
            )),
            None => out.push(format_label("TCP", "off (--no-listen)")),
        }
        match (&self.tcp_addr, &self.public_url) {
            (_, Some(url)) => out.push(format_label("Public URL", url)),
            (Some(addr), None) => out.push(format_label(
                "Public URL",
                format!("off — add --public-url {}", suggested_public_url(*addr)),
            )),
            (None, None) => out.push(format_label("Public URL", "off (--no-listen)")),
        }
        match (&self.public_url, &self.web_root) {
            (_, Some(path)) => out.push(format_label("UI", path.display())),
            (Some(_), None) => out.push(format_label("UI", "off — add --web-root dist/ui")),
            (None, None) => out.push(format_label("UI", "off (listening disabled)")),
        }

        out.push(String::new());
        out.push(format_label("Quit", "Ctrl-C or SIGTERM"));
        out.push(String::new());
        out
    }

    fn print(&self) {
        let color = stderr_use_color();
        for line in self.lines() {
            if line.is_empty() {
                eprintln!();
                continue;
            }
            if line == "Multitool broker ready" {
                eprintln!("{}", paint::bold_green(color, &line));
                continue;
            }
            let Some((label, value)) = split_label_line(&line) else {
                eprintln!("{line}");
                continue;
            };
            let is_warn = matches!(label, "Warning" | "Note" | "First token")
                || (label == "MCP" && value.starts_with("not started"))
                || (matches!(label, "TCP" | "Public URL" | "UI") && value.starts_with("off"));
            let is_quit = label == "Quit";
            let padded_label = format!("{label:<11}");
            let label_col = if is_warn {
                paint::bold_yellow(color, &padded_label)
            } else if is_quit {
                paint::dim(color, &padded_label)
            } else {
                paint::bold_cyan(color, &padded_label)
            };
            let value = if is_warn {
                paint::bold_yellow(color, value)
            } else if is_quit {
                paint::dim(color, value)
            } else {
                value.to_string()
            };
            eprintln!("  {label_col} {value}");
        }
    }
}

fn format_label(label: &str, value: impl std::fmt::Display) -> String {
    format!("  {label:<11} {value}")
}

/// Split a `format_label` line into (label, value). Returns None for the
/// title, blank lines, or free-form text.
fn split_label_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("  ")?;
    // Labels are left-aligned in an 11-char field followed by a space.
    if rest.len() < 12 {
        return None;
    }
    let (label_field, value) = rest.split_at(11);
    let value = value.strip_prefix(' ')?;
    let label = label_field.trim_end();
    if label.is_empty()
        || label
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == ' '))
    {
        return None;
    }
    // Multi-word labels we actually use.
    match label {
        "Socket" | "Root" | "TCP" | "Public URL" | "Data host" | "UI" | "MCP" | "Keychain"
        | "First token" | "Rotate" | "Manage" | "Remote" | "Desktop" | "Agent key"
        | "Agent docs" | "Skill" | "Note" | "Warning" | "Quit" => Some((label, value)),
        _ => None,
    }
}

/// Give a never-managed headless broker one bounded, owner-only credential.
/// This is bootstrap, not an unauthenticated API: possession of the file is
/// what lets the host operator make the first authenticated online rotation.
async fn ensure_first_start_management_token(broker: &Broker) -> Result<Option<PathBuf>, String> {
    if broker.identity.manage_token_issued(&broker.workspace) {
        return Ok(None);
    }
    let ttl = std::time::Duration::from_secs(DEFAULT_MANAGE_TOKEN_TTL_DAYS * 86_400);
    let token = Zeroizing::new(
        broker
            .identity
            .issue_manage_token_with_ttl(&broker.workspace, Some(ttl))
            .await
            .map_err(|error| format!("could not issue first-start management token: {error}"))?,
    );
    if let Err(error) = broker.paths.write_manage_bootstrap_token(&token) {
        let rollback = broker.identity.revoke_manage_token(&broker.workspace).await;
        return Err(match rollback {
            Ok(_) => format!("could not write first-start management token: {error}"),
            Err(rollback) => format!(
                "could not write first-start management token: {error}; \
                 could not close the partially opened management plane: {rollback}"
            ),
        });
    }
    let expires_at = broker
        .identity
        .manage_token_expires_at(&broker.workspace)
        .expect("first-start management tokens are bounded");
    broker.audit.append(
        aka_core::audit::AuditEntry::new(
            aka_core::audit::AuditKind::ManagementTokenIssued,
            "First-start management token issued",
        )
        .outcome("bootstrap")
        .field("expires_at", expires_at.to_rfc3339()),
    );
    Ok(Some(broker.paths.manage_bootstrap_token_file()))
}

fn cmd_serve(args: ServeArgs) {
    let ServeArgs {
        root,
        listen,
        no_listen,
        public_url,
        web_root,
        data_plane_listen,
        advertise_host,
        data_plane_insecure,
        session_idle_timeout,
        session_max_ttl,
        audit_pg_statements,
        no_mcp,
    } = args;
    let (listen, public_url) = resolve_serve_network(no_listen, listen, public_url);
    // Headless serve always uses an isolated root (default ~/.akaserver), never
    // the desktop production layout. Vault is always root-scoped on macOS.
    let root = serve_root_from_flags(root);
    let root_flag = format!(" --root {}", shell_quote(&root.display().to_string()));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    // Startup failures here are configuration problems (a socket path over
    // the sun_path limit, an unreadable root, a vault that won't open) —
    // diagnose in one line rather than panicking with a backtrace.
    let fail = |what: &str, e: &dyn std::fmt::Display| -> ! {
        die(format!("{what}: {e}"));
    };
    let paths = Paths::under(&root);
    print_serve_launch_notice();
    let vault = match open_vault(&paths, Some(&root)) {
        Ok(vault) => vault,
        Err(e) => fail("could not open the secret vault", &e),
    };

    let events: Arc<dyn BrokerEvents> = Arc::new(CliEvents);
    // Session lifetimes are deployment-shaped: the defaults suit an
    // interactive desktop, while a nightly `pg_dump` or a LISTEN/NOTIFY worker
    // needs longer ones. They were compile-time constants before, which left
    // those workloads with no way to run at all.
    // Environment first, explicit flags after: a flag always wins.
    let mut config = BrokerConfig::default().overridden_from_env();
    if let Some(secs) = session_idle_timeout {
        config.session_idle_timeout = std::time::Duration::from_secs(secs);
    }
    if let Some(secs) = session_max_ttl {
        config.session_max_ttl = std::time::Duration::from_secs(secs);
    }
    config.audit_pg_statements = audit_pg_statements;
    let broker: Arc<Broker> = match runtime.block_on(Broker::new(paths, vault, config, events)) {
        Ok(broker) => broker,
        Err(e) => fail("could not start the broker", &e),
    };
    let first_start_manage_token =
        match runtime.block_on(ensure_first_start_management_token(&broker)) {
            Ok(path) => path,
            Err(error) => die(error),
        };
    // A web root that is not there would serve every request as a 404 with
    // no hint why, so say so at startup instead.
    if let Some(web_root) = &web_root {
        if public_url.is_none() {
            die("--web-root needs --public-url when --listen is not loopback");
        }
        if !web_root.join("index.html").is_file() {
            die(format!(
                "--web-root {} has no index.html; point it at the dist/ui a UI build produces",
                web_root.display()
            ));
        }
    }
    let options = daemon::ServeOptions {
        listen,
        public_url: public_url.clone(),
        web_root: web_root.clone(),
        data_plane_listen,
        advertise_host: advertise_host.clone(),
        data_plane_insecure,
    };
    let mut daemon = match runtime.block_on(daemon::serve_with(broker.clone(), options)) {
        Ok(daemon) => daemon,
        Err(e) => fail("could not serve the control plane", &e),
    };

    // The agent-facing MCP listener is another task on the broker runtime.
    // Keep its loopback port in discovery so local bridges and the public
    // daemon proxy can reach it without a second process or runtime.
    let (mcp_host, mcp_banner) = if no_mcp {
        (None, McpBannerStatus::Disabled)
    } else {
        match runtime.block_on(aka_core::mcp_host::serve(broker.clone())) {
            Ok(host) => {
                broker.set_mcp_host_port(Some(host.addr().port()));
                let addr = host.addr();
                (Some(host), McpBannerStatus::Started { addr })
            }
            Err(error) => (None, McpBannerStatus::Failed(error.to_string())),
        }
    };

    let confirm_count = broker
        .store
        .list_connections(&broker.workspace)
        .iter()
        .filter(|connection| {
            broker
                .access
                .confirm_mode(&broker.workspace, &connection.id)
                .is_on()
        })
        .count();

    ServeBanner {
        socket: daemon.socket_path.clone(),
        root: root.clone(),
        root_flag,
        first_start_manage_token,
        tcp_addr: daemon.tcp_addr,
        public_url,
        web_root,
        advertise_host,
        mcp: mcp_banner,
        vault: vault_description(&broker.paths),
        headless_warning: headless_confirmation_warning(confirm_count),
        token_path: broker.paths.token_file(),
    }
    .print();

    let signal = runtime.block_on(wait_for_shutdown_signal());
    let color = stderr_use_color();
    eprintln!(
        "  {} {}",
        paint::bold_cyan(color, format!("{:11}", "Shutdown")),
        paint::dim(
            color,
            format!("{signal} received; draining active sessions")
        )
    );
    daemon.stop_accepting();
    let sessions = broker.begin_shutdown();
    let drained =
        runtime.block_on(broker.wait_for_session_drain(std::time::Duration::from_secs(10)));
    if !drained {
        eprintln!(
            "  {} {}",
            paint::bold_yellow(color, format!("{:11}", "Shutdown")),
            paint::bold_yellow(color, "deadline reached with active sessions still closing")
        );
    } else if sessions > 0 {
        eprintln!(
            "  {} drained {sessions} active data-plane session(s)",
            paint::bold_cyan(color, format!("{:11}", "Shutdown")),
        );
    }
    drop(mcp_host);
    drop(daemon);
}

async fn wait_for_shutdown_signal() -> &'static str {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                eprintln!("  warning: SIGINT handler failed: {error}");
            }
            "SIGINT"
        }
        _ = terminate.recv() => "SIGTERM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aka_core::vault::MemoryVault;
    use chrono::TimeZone as _;

    struct TestEvents;
    impl BrokerEvents for TestEvents {}

    #[test]
    fn cli_exit_codes_are_stable() {
        assert_eq!(ExitCode::Generic as i32, 1);
        assert_eq!(ExitCode::Usage as i32, 2);
        assert_eq!(ExitCode::NoBroker as i32, 3);
        assert_eq!(ExitCode::Authentication as i32, 4);
        assert_eq!(ExitCode::NotFound as i32, 5);
        assert_eq!(ExitCode::Conflict as i32, 6);
        assert_eq!(ExitCode::RemoteUnreachable as i32, 7);
        assert_eq!(ExitCode::TestFailed as i32, 8);
    }

    #[test]
    fn generated_help_is_grouped_and_does_not_drift() {
        let help = match configured_cli_command(false, true).try_get_matches_from(["aka", "--help"])
        {
            Ok(_) => panic!("--help unexpectedly parsed as a command"),
            Err(error) => error.to_string(),
        };
        assert!(
            help.contains("GET STARTED")
                && help.contains("OPERATOR")
                && help.contains("RUNTIME"),
            "long help should expose every command group:\n{help}"
        );
        assert!(!help.contains("ADVANCED"), "{help}");
        assert!(
            help.contains("COMMON WORKFLOWS"),
            "long help should retain workflow reference:\n{help}"
        );
        assert!(!help.contains("EXIT CODES"), "{help}");
        assert!(
            help.contains("aka run <conn> -- psql"),
            "workflows should teach the unified runner:\n{help}"
        );
        assert_eq!(
            help.matches("Connect an agent, MCP client, or the desktop app")
                .count(),
            1
        );
        assert!(help.contains("  skill"), "{help}");
        assert!(help.contains("  instructions"), "{help}");

        let short = match configured_cli_command(false, false).try_get_matches_from(["aka", "-h"]) {
            Ok(_) => panic!("-h unexpectedly parsed as a command"),
            Err(error) => error.to_string(),
        };
        assert!(short.contains("GET STARTED"), "{short}");
        assert!(short.contains("EXAMPLES"), "{short}");
        assert!(short.contains("OPERATOR"), "{short}");
        assert!(!short.contains("COMMON WORKFLOWS"), "{short}");

        let nested = match configured_cli_command(false, true)
            .try_get_matches_from(["aka", "conn", "show", "--help"])
        {
            Ok(_) => panic!("nested --help unexpectedly parsed as a command"),
            Err(error) => error.to_string(),
        };
        assert!(nested.contains("aka conn show"), "{nested}");
        assert!(nested.contains("ARGUMENTS"), "{nested}");
        assert!(nested.contains("--broker <BROKER>"), "{nested}");
    }

    #[test]
    fn root_help_styles_match_serve_palette() {
        let cmd = Cli::command();
        let styles = cmd.get_styles();
        // Green headings / cyan literals — same roles as the serve banner.
        assert_eq!(
            styles.get_header().to_string(),
            AnsiColor::Green.on_default().bold().to_string()
        );
        assert_eq!(
            styles.get_literal().to_string(),
            AnsiColor::Cyan.on_default().bold().to_string()
        );
    }

    #[test]
    fn every_subcommand_inherits_cli_styles_after_build() {
        let mut cmd = Cli::command();
        cmd.build();
        let expected_header = CLI_STYLES.get_header().to_string();
        let expected_literal = CLI_STYLES.get_literal().to_string();
        fn check(cmd: &clap::Command, expected_header: &str, expected_literal: &str) {
            assert_eq!(
                cmd.get_styles().get_header().to_string(),
                expected_header,
                "styles missing on {}",
                cmd.get_name()
            );
            assert_eq!(
                cmd.get_styles().get_literal().to_string(),
                expected_literal,
                "styles missing on {}",
                cmd.get_name()
            );
            for sub in cmd.get_subcommands() {
                // Skip clap's auto-added `help` subcommand if present.
                if sub.get_name() == "help" {
                    continue;
                }
                check(sub, expected_header, expected_literal);
            }
        }
        check(&cmd, &expected_header, &expected_literal);
    }

    #[test]
    fn colon_field_paints_label_and_keeps_plain_value() {
        assert_eq!(
            colon_field(false, "  ", "vault", "keychain"),
            "  vault: keychain"
        );
        assert_eq!(colon_field(false, "", "name", "github"), "name: github");
        assert_eq!(colon_field(false, "  ", "tools", ""), "  tools:");
        let colored = colon_field(true, "  ", "MCP host", "http://x");
        assert!(colored.contains('\u{1b}'));
        assert!(colored.contains("MCP host"));
        assert!(colored.contains("http://x"));
    }

    #[test]
    fn generated_help_obeys_color_mode() {
        let colored =
            match configured_cli_command(true, true).try_get_matches_from(["aka", "--help"]) {
                Ok(_) => panic!("--help unexpectedly parsed as a command"),
                Err(error) => error.render().ansi().to_string(),
            };
        assert!(colored.contains('\u{1b}'));

        let plain =
            match configured_cli_command(false, true).try_get_matches_from(["aka", "--help"]) {
                Ok(_) => panic!("--help unexpectedly parsed as a command"),
                Err(error) => error.to_string(),
            };
        assert!(!plain.contains('\u{1b}'));
    }

    #[test]
    fn cli_failures_unwind_sensitive_command_state_before_exiting() {
        struct DropProbe(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failure = std::panic::catch_unwind({
            let dropped = dropped.clone();
            move || {
                let _sensitive_state = DropProbe(dropped);
                exit_with(ExitCode::Authentication);
            }
        })
        .expect_err("CLI exit should unwind to the process boundary");
        let exit = failure
            .downcast::<CliExit>()
            .expect("CLI exit carries its typed status");
        assert_eq!(exit.code, ExitCode::Authentication as i32);
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "sensitive command state must be dropped before process exit"
        );
    }

    #[test]
    fn structured_management_failures_have_specific_exit_codes() {
        assert_eq!(
            manage_error_exit_code(&ManageError::InvalidConnectionName {
                name: "bad/name".into()
            }),
            ExitCode::Usage
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::InvalidManageToken { detail: None }),
            ExitCode::Authentication
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::ConnectionNotFound),
            ExitCode::NotFound
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::ConnectionChanged),
            ExitCode::Conflict
        );
        assert_eq!(
            manage_error_exit_code(&ManageError::Unreachable {
                message: "offline".into()
            }),
            ExitCode::RemoteUnreachable
        );
    }

    #[test]
    fn management_tokens_default_to_a_bounded_ttl() {
        let cli = Cli::try_parse_from(["aka", "admin", "token"]).unwrap();
        let Command::Admin {
            command: AdminCommand::Token {
                ttl_days, revoke, ..
            },
        } = cli.command
        else {
            panic!("wrong command");
        };
        assert!(!revoke);
        assert_eq!(ttl_days, Some(30));
        assert!(parse_manage_ttl_days("0").is_err());
        assert!(parse_manage_ttl_days("3651").is_err());
        assert!(Cli::try_parse_from([
            "aka",
            "admin",
            "token",
            "--broker",
            "https://broker.example.test",
            "--create-root",
            "--root",
            "/tmp/example",
        ])
        .is_err());
    }

    #[test]
    fn serve_root_prefers_explicit_then_env_then_default() {
        let default = PathBuf::from("/default/akaserver");
        assert_eq!(
            resolve_serve_root(
                Some(PathBuf::from("/explicit")),
                Some("/from-env"),
                default.clone()
            ),
            PathBuf::from("/explicit")
        );
        assert_eq!(
            resolve_serve_root(None, Some("/from-env"), default.clone()),
            PathBuf::from("/from-env")
        );
        assert_eq!(
            resolve_serve_root(None, Some("  /from-env  "), default.clone()),
            PathBuf::from("/from-env")
        );
        assert_eq!(resolve_serve_root(None, Some(""), default.clone()), default);
        assert_eq!(
            resolve_serve_root(None, Some("   "), default.clone()),
            default
        );
        assert_eq!(resolve_serve_root(None, None, default.clone()), default);
    }

    #[test]
    fn default_server_root_is_home_akaserver() {
        let root = default_server_root().expect("HOME should be set in tests");
        assert_eq!(
            root.file_name().and_then(|n| n.to_str()),
            Some(".akaserver")
        );
        let paths = Paths::under(&root);
        assert_eq!(paths.data_dir, root.join("data"));
        assert_eq!(paths.socket_dir, root.join("sock"));
    }

    #[test]
    fn serve_network_defaults_are_passkey_compatible_and_can_be_disabled() {
        assert_eq!(
            resolve_serve_network(false, None, None),
            (
                Some("127.0.0.1:4780".parse().unwrap()),
                Some("http://localhost:4780".into())
            )
        );
        let loopback = Some("127.0.0.1:4880".parse().unwrap());
        assert_eq!(
            resolve_serve_network(false, loopback, None),
            (loopback, Some("http://localhost:4880".into()))
        );
        assert_eq!(
            resolve_serve_network(false, loopback, Some("https://broker.example.test".into())),
            (loopback, Some("https://broker.example.test".into()))
        );
        assert_eq!(
            resolve_serve_network(false, Some("0.0.0.0:4780".parse().unwrap()), None),
            (Some("0.0.0.0:4780".parse().unwrap()), None)
        );
        assert_eq!(resolve_serve_network(true, None, None), (None, None));
    }

    #[test]
    fn unsigned_serve_notice_prepares_for_the_login_keychain_prompt() {
        assert_eq!(
            serve_launch_notice(true),
            Some(
                "Launching broker… macOS may ask for your password to allow this unsigned aka build to access the login Keychain."
            )
        );
        assert_eq!(serve_launch_notice(false), None);
    }

    #[test]
    fn status_labels_only_the_production_socket_as_desktop() {
        let desktop = Paths::default_locations().unwrap().socket_file();
        let desktop = desktop.display().to_string();
        assert_eq!(
            status_heading("unix", &desktop),
            format!("desktop broker running on {desktop}")
        );
        assert_eq!(
            status_heading("unix", "/tmp/headless/sock/broker.sock"),
            "broker running on /tmp/headless/sock/broker.sock"
        );
        assert_eq!(
            status_heading("manage_api", "https://broker.example.test"),
            "broker running on https://broker.example.test (manage API)"
        );
    }

    #[test]
    fn agent_plane_labels_and_serve_flags_are_validated_by_clap() {
        assert!(Cli::try_parse_from([
            "aka",
            "env",
            "production",
            "--client",
            "honest\r\nX-Forged: yes",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["aka", "env", "production", "--client", "ci-runner"]).is_ok()
        );
        assert!(Cli::try_parse_from([
            "aka",
            "run",
            "production",
            "--client",
            "honest\r\nX-Forged: yes",
            "--",
            "psql",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "aka",
            "run",
            "production",
            "--client",
            "ci-runner",
            "--",
            "psql",
        ])
        .is_ok());

        assert!(Cli::try_parse_from([
            "aka",
            "serve",
            "--public-url",
            "https://broker.example.test",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["aka", "serve", "--no-listen"]).is_ok());
        assert!(Cli::try_parse_from(["aka", "serve", "--web-root", "dist/ui"]).is_ok());
        for incompatible in ["--listen", "--public-url", "--web-root"] {
            let value = match incompatible {
                "--listen" => "127.0.0.1:4780",
                "--public-url" => "https://broker.example.test",
                _ => "dist/ui",
            };
            assert!(
                Cli::try_parse_from(["aka", "serve", "--no-listen", incompatible, value]).is_err()
            );
        }
        assert!(Cli::try_parse_from(["aka", "serve", "--data-plane-insecure"]).is_err());
        for flag in ["--session-idle-timeout", "--session-max-ttl"] {
            assert!(Cli::try_parse_from(["aka", "serve", flag, "0"]).is_err());
            assert!(Cli::try_parse_from(["aka", "serve", flag, "1"]).is_ok());
        }
        assert!(Cli::try_parse_from(["aka", "serve", "--no-mcp"]).is_ok());
        assert!(Cli::try_parse_from(["aka", "serve", "--no-sidecar"]).is_ok());
        assert!(Cli::try_parse_from([
            "aka",
            "serve",
            "--listen",
            "127.0.0.1:4780",
            "--public-url",
            "not-a-url",
        ])
        .is_err());
    }

    #[test]
    fn structured_open_failures_have_specific_exit_codes() {
        use client::OpenSessionError;
        let refused = |status: u16, reason: &str| OpenSessionError::Refused {
            status,
            reason: Some(reason.to_string()),
            detail: "refused".into(),
        };
        assert_eq!(
            open_session_exit_code(&refused(404, "unknown_connection")),
            ExitCode::NotFound
        );
        assert_eq!(
            open_session_exit_code(&refused(403, "denied_by_policy")),
            ExitCode::Authentication
        );
        assert_eq!(
            open_session_exit_code(&refused(429, "rate_limited")),
            ExitCode::Conflict
        );
        assert_eq!(
            open_session_exit_code(&OpenSessionError::NoBroker {
                socket: "/tmp/missing.sock".into(),
            }),
            ExitCode::NoBroker
        );
    }

    /// SSH-24 and SSH-9. Everything printed here was already in the response
    /// and discarded: the destination an alias-imported tool is reached by, the
    /// fingerprint the broker actually enforces, an absolute deadline (the agent
    /// protocol has no error channel, so an expired socket reads only as
    /// "Permission denied (publickey)"), and the flags without which a local
    /// on-disk key can win the login with no broker involvement.
    #[test]
    fn ssh_open_hints_name_what_the_socket_honors() {
        let now = chrono::Local
            .with_ymd_and_hms(2026, 7, 29, 9, 30, 0)
            .single()
            .expect("an unambiguous local time");
        let body = serde_json::json!({
            "auth_sock": "/tmp/agent-3f1c9a2b04d7e685.sock",
            "destination": "production",
            "host": "prod.example.com",
            "port": 2222,
            "user": "deploy",
            "host_key_fingerprint": "SHA256:abc123",
            "expires_in_seconds": 60,
        });
        let lines = ssh_open_hints(&body, "/tmp/agent-3f1c9a2b04d7e685.sock", now, true);
        let joined = lines.join("\n");
        assert!(
            joined.contains("signs only for deploy@prod.example.com"),
            "{joined}"
        );
        assert!(joined.contains("SHA256:abc123"), "{joined}");
        assert!(joined.contains("connect within 60s"), "{joined}");
        assert!(
            joined.contains("09:31:00"),
            "an absolute deadline: {joined}"
        );
        // The imported alias, not user@host: ~/.ssh/config is what supplies the
        // rest of the routing, and the pinned host may not even be typeable.
        assert!(joined.contains("ssh -p 2222 "), "{joined}");
        assert!(joined.contains(" production\n"), "{joined}");
        for option in SSH_BROKER_OPTIONS {
            assert!(
                joined.contains(&format!("-o {option}")),
                "{option} missing: {joined}"
            );
        }
        assert!(
            !joined.contains("IdentitiesOnly"),
            "that flag breaks the agent: {joined}"
        );

        // The config stanza carries the same authority as the one-liner, in the
        // form ssh-config-aware clients can use: the routing fields plus every
        // broker option, spelled the way a config file spells them.
        assert!(joined.contains("Host production"), "{joined}");
        assert!(joined.contains("HostName prod.example.com"), "{joined}");
        assert!(joined.contains("Port 2222"), "{joined}");
        assert!(joined.contains("User deploy"), "{joined}");
        assert!(
            joined.contains("IdentityAgent \"/tmp/agent-3f1c9a2b04d7e685.sock\""),
            "{joined}"
        );
        for option in SSH_BROKER_OPTIONS {
            let (key, value) = option.split_once('=').unwrap();
            assert!(
                joined.contains(&format!("    {key} {value}")),
                "{option} missing from the config block: {joined}"
            );
        }
    }

    /// An unpinned connection says so rather than staying silent: the next
    /// server key seen becomes the permanent anchor.
    #[test]
    fn ssh_open_hints_say_when_no_host_key_is_pinned() {
        let now = chrono::Local
            .with_ymd_and_hms(2026, 7, 29, 9, 30, 0)
            .single()
            .expect("an unambiguous local time");
        let body = serde_json::json!({
            "host": "prod.example.com",
            "user": "deploy",
            "host_key_fingerprint": serde_json::Value::Null,
        });
        let joined = ssh_open_hints(&body, "/tmp/a.sock", now, true).join("\n");
        assert!(joined.contains("not pinned"), "{joined}");
        assert!(joined.contains("will be trusted and pinned"), "{joined}");
        // No port key at all: port 22 is left implicit rather than spelled out.
        assert!(joined.contains("ssh -o IdentityFile=none"), "{joined}");
    }

    #[test]
    fn offline_store_writer_respects_the_broker_lease() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let broker = runtime
            .block_on(Broker::new(
                paths.clone(),
                Arc::new(MemoryVault::new()),
                BrokerConfig::default(),
                Arc::new(TestEvents),
            ))
            .unwrap();

        assert!(matches!(
            acquire_offline_store_lock(&paths),
            Err(CoreError::BrokerAlreadyRunning(_))
        ));
        drop(broker);
        assert!(acquire_offline_store_lock(&paths).is_ok());
    }

    #[test]
    fn first_start_management_token_is_private_bounded_and_not_reissued() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let broker = runtime
            .block_on(Broker::new(
                paths.clone(),
                Arc::new(MemoryVault::new()),
                BrokerConfig::default(),
                Arc::new(TestEvents),
            ))
            .unwrap();

        let path = runtime
            .block_on(ensure_first_start_management_token(&broker))
            .unwrap()
            .expect("a new broker needs a bootstrap credential");
        let token = std::fs::read_to_string(&path).unwrap();
        broker
            .identity
            .verify_manage(&broker.workspace, token.trim())
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(broker
            .identity
            .manage_token_expires_at(&broker.workspace)
            .is_some());
        assert!(
            runtime
                .block_on(ensure_first_start_management_token(&broker))
                .unwrap()
                .is_none(),
            "restart must not overwrite the only available bootstrap token"
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), token);
    }

    #[test]
    fn offline_store_writer_reports_cli_lock_contention() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let _first = acquire_offline_store_lock(&paths).unwrap();

        assert!(matches!(
            acquire_offline_store_lock(&paths),
            Err(CoreError::BrokerStateBusy(Some(pid))) if pid == std::process::id()
        ));
    }

    #[test]
    fn embed_ticket_fills_the_password_slot() {
        assert_eq!(
            embed_ticket(
                "postgres://ticket@127.0.0.1:5599/app?sslmode=disable",
                "tkt_ab12"
            )
            .unwrap(),
            "postgres://ticket:tkt_ab12@127.0.0.1:5599/app?sslmode=disable"
        );
        // A DSN without the expected placeholder user is a contract change
        // worth failing loudly on, not silently mangling.
        assert!(embed_ticket("postgres://other@host/db", "tkt_x").is_err());
    }

    #[test]
    fn pg_env_output_keeps_the_ticket_out_of_the_connection_arguments() {
        let exports = pg_env_exports(
            "postgres://ticket@127.0.0.1:6543/app_production?sslmode=disable",
            "tkt_secret",
        )
        .unwrap();
        assert!(exports.contains("export PGHOST='127.0.0.1'"));
        assert!(exports.contains("export PGPORT='6543'"));
        assert!(exports.contains("export PGDATABASE='app_production'"));
        assert!(exports.contains("export PGUSER='ticket'"));
        assert!(exports.contains("export PGPASSWORD='tkt_secret'"));
        assert!(exports.contains("export PGSSLMODE='disable'"));
        assert!(!exports.contains("postgres://ticket:tkt_secret"));
    }

    #[test]
    fn pg_environment_is_available_without_rendering_shell_code() {
        let env = pg_env(
            "postgres://ticket@127.0.0.1:6543/app_production?sslmode=disable",
            "tkt_secret",
        )
        .unwrap()
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(env.get("PGHOST").map(String::as_str), Some("127.0.0.1"));
        assert_eq!(env.get("PGPORT").map(String::as_str), Some("6543"));
        assert_eq!(
            env.get("PGPASSWORD").map(String::as_str),
            Some("tkt_secret")
        );
        assert_eq!(env.get("PGSSLMODE").map(String::as_str), Some("disable"));
    }

    #[test]
    fn shell_exports_quote_broker_controlled_values() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn ssh_scoped_commands_force_the_broker_options() {
        let words = ["ssh", "production"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let child = ssh_scoped_command(&words, "/tmp/aka-agent.sock");
        let args = child
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for option in SSH_BROKER_OPTIONS {
            assert!(
                args.windows(2)
                    .any(|pair| pair[0] == "-o" && pair[1] == *option),
                "missing {option}: {args:?}"
            );
        }
        assert_eq!(args.last().map(String::as_str), Some("production"));
        assert!(child.get_envs().any(|(name, value)| {
            name == "SSH_AUTH_SOCK" && value.is_some_and(|value| value == "/tmp/aka-agent.sock")
        }));

        let git_words = ["git", "push"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let git = ssh_scoped_command(&git_words, "/tmp/aka-agent.sock");
        let git_ssh = git
            .get_envs()
            .find(|(name, _)| *name == "GIT_SSH_COMMAND")
            .and_then(|(_, value)| value)
            .expect("git receives a safe SSH command")
            .to_string_lossy();
        for option in SSH_BROKER_OPTIONS {
            assert!(git_ssh.contains(option), "missing {option}: {git_ssh}");
        }
    }

    #[test]
    fn scoped_commands_receive_the_environment_and_return_the_child_status() {
        let words = [
            "/bin/sh",
            "-c",
            "test \"$AKA_SCOPED_TEST\" = expected && exit 17",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let env = vec![("AKA_SCOPED_TEST".to_string(), Some("expected".to_string()))];
        let exit = std::panic::catch_unwind(|| run_scoped_command(&words, &env))
            .expect_err("the child status exits the CLI");
        assert_eq!(exit.downcast::<CliExit>().unwrap().code, 17);
    }

    #[test]
    fn aws_credential_process_quotes_paths_and_connection_names() {
        let command = format!(
            "{} cloud creds {} --root {}",
            aws_process_quote("/Applications/Multitool Preview/aka"),
            aws_process_quote("Production AWS"),
            aws_process_quote("/tmp/vault \"copy\"")
        );
        assert_eq!(
            command,
            "\"/Applications/Multitool Preview/aka\" cloud creds \"Production AWS\" --root \"/tmp/vault \\\"copy\\\"\""
        );
    }

    #[test]
    fn secret_input_strips_one_line_ending_unless_raw() {
        assert_eq!(normalize_secret_input("secret\n".into(), false), "secret");
        assert_eq!(normalize_secret_input("secret\r\n".into(), false), "secret");
        assert_eq!(
            normalize_secret_input("secret\n\n".into(), false),
            "secret\n"
        );
        assert_eq!(normalize_secret_input("secret\n".into(), true), "secret\n");
    }

    #[test]
    fn json_is_global_across_read_commands() {
        let cli = Cli::try_parse_from(["aka", "status", "--json"]).unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Command::Status {
                root: None,
                broker: None,
            }
        ));
        let cli = Cli::try_parse_from(["aka", "--json", "secret", "list"]).unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Command::Secret {
                command: SecretCommand::List { .. }
            }
        ));
    }

    #[test]
    fn endpoint_lifecycle_flags_parse_and_conflict() {
        let cli = Cli::try_parse_from(["aka", "endpoint", "database", "--issue"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Endpoint(EndpointArgs {
                issue: true,
                revoke: false,
                ..
            })
        ));

        let cli = Cli::try_parse_from(["aka", "endpoint", "database", "--revoke"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Endpoint(EndpointArgs {
                issue: false,
                revoke: true,
                ..
            })
        ));

        assert!(
            Cli::try_parse_from(["aka", "endpoint", "database", "--issue", "--revoke"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["aka", "endpoint", "database", "--revoke", "--secret"]).is_err()
        );
    }

    #[test]
    fn conn_add_scaffolds_fill_in_the_missing_command() {
        let missing = clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument);
        let args = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();

        let scaffold =
            conn_add_scaffold(&missing, &args(&["conn", "add", "pg", "analytics"])).unwrap();
        assert!(scaffold.contains("aka secret add ANALYTICS_PASSWORD"), "{scaffold}");
        assert!(scaffold.contains("aka conn add pg analytics"), "{scaffold}");

        // The name survives flags that take values, in either flag form.
        let scaffold = conn_add_scaffold(
            &missing,
            &args(&["conn", "add", "ssh", "--host=x.example.com", "prod"]),
        )
        .unwrap();
        assert!(scaffold.contains("aka conn add ssh prod"), "{scaffold}");

        // Only conn add gets a scaffold, and only for missing arguments.
        assert!(conn_add_scaffold(&missing, &args(&["secret", "add", "X"])).is_none());
        let other = clap::Error::new(clap::error::ErrorKind::UnknownArgument);
        assert!(conn_add_scaffold(&other, &args(&["conn", "add", "pg", "x"])).is_none());
    }

    #[test]
    fn policy_flags_ride_conn_update_without_a_kind() {
        let cli = Cli::try_parse_from([
            "aka",
            "conn",
            "update",
            "github",
            "--response-credentials",
            "allow",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Conn {
                command: ConnCommand::Update {
                    command: None,
                    policy: ConnPolicyArgs {
                        response_credentials: Some(ResponseCredentialsMode::Allow),
                        ..
                    }
                }
            }
        ));

        let cli = Cli::try_parse_from(["aka", "conn", "update", "billing", "--confirm"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Conn {
                command: ConnCommand::Update {
                    command: None,
                    policy: ConnPolicyArgs { confirm: true, .. }
                }
            }
        ));

        assert!(
            Cli::try_parse_from(["aka", "conn", "update", "billing", "--confirm", "--no-confirm"])
                .is_err(),
            "the two confirm flags are opposites"
        );
        assert!(
            Cli::try_parse_from([
                "aka",
                "conn",
                "update",
                "db",
                "--audit-statements",
                "sometimes",
            ])
            .is_err(),
            "audit-statements takes on|off|default"
        );
    }

    #[test]
    fn endpoint_issuance_and_renewal_require_online_broker_but_revocation_does_not() {
        assert_eq!(
            endpoint_action(false, false, false).unwrap(),
            EndpointAction::Read
        );
        assert_eq!(
            endpoint_action(true, false, false).unwrap(),
            EndpointAction::Issue
        );
        assert_eq!(
            endpoint_action(false, true, false).unwrap(),
            EndpointAction::Renew
        );
        assert_eq!(
            endpoint_action(false, false, true).unwrap(),
            EndpointAction::Revoke
        );
        assert!(endpoint_action(true, true, false).is_err());

        let error = endpoint_action_supported(EndpointAction::Issue, false).unwrap_err();
        assert!(error.contains("running broker"));
        assert!(endpoint_action_supported(EndpointAction::Issue, true).is_ok());
        assert!(endpoint_action_supported(EndpointAction::Renew, false).is_err());
        assert!(endpoint_action_supported(EndpointAction::Renew, true).is_ok());
        assert!(endpoint_action_supported(EndpointAction::Read, false).is_ok());
        assert!(endpoint_action_supported(EndpointAction::Revoke, false).is_ok());
        assert!(Cli::try_parse_from([
            "aka",
            "endpoint",
            "production",
            "--renew",
            "--issue",
        ])
        .is_err());
    }

    /// SSH-1 / SEC-28. The two flags are opposites rather than a tri-state,
    /// so an unmentioned posture must stay untouched — `--issue` alone must
    /// not silently take authentication off a socket that had it.
    #[test]
    fn endpoint_authentication_flags_only_speak_when_asked() {
        assert_eq!(endpoint_require_auth(false, false), None);
        assert_eq!(endpoint_require_auth(true, false), Some(true));
        assert_eq!(endpoint_require_auth(false, true), Some(false));

        assert!(Cli::try_parse_from([
            "aka",
            "endpoint",
            "production",
            "--require-auth",
            "--no-require-auth",
        ])
        .is_err());
        // Revocation removes the endpoint, so a posture for it is nonsense.
        assert!(Cli::try_parse_from([
            "aka",
            "endpoint",
            "production",
            "--revoke",
            "--require-auth",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "aka",
            "endpoint",
            "production",
            "--issue",
            "--require-auth",
        ])
        .is_ok());
    }

    /// The forwarder takes its command after `--`, so the flags of the thing
    /// being run (`ssh -o …`) cannot be mistaken for the forwarder's own.
    #[test]
    fn the_ssh_agent_forwarder_passes_its_command_through_untouched() {
        let cli = Cli::try_parse_from([
            "aka",
            "ssh-agent",
            "production",
            "--socket",
            "/tmp/a.sock",
            "--",
            "ssh",
            "-o",
            "IdentitiesOnly=no",
            "prod",
        ])
        .expect("a command after -- parses");
        let Command::SshAgent {
            connection,
            socket,
            command,
            ..
        } = cli.command
        else {
            panic!("expected the ssh-agent command");
        };
        assert_eq!(connection, "production");
        assert_eq!(socket.as_deref(), Some(Path::new("/tmp/a.sock")));
        assert_eq!(command, ["ssh", "-o", "IdentitiesOnly=no", "prod"]);

        let cli = Cli::try_parse_from(["aka", "ssh-agent", "production"]).unwrap();
        let Command::SshAgent { command, .. } = cli.command else {
            panic!("expected the ssh-agent command");
        };
        assert!(
            command.is_empty(),
            "no command means serve in the foreground"
        );
    }

    #[test]
    fn open_commands_accept_a_scoped_child_after_double_dash() {
        let cli = Cli::try_parse_from(["aka", "run", "analytics", "--", "psql", "-c", "select 1"])
            .expect("a scoped child command parses");
        let Command::Run { command, .. } = cli.command else {
            panic!("expected run");
        };
        assert_eq!(command, ["psql", "-c", "select 1"]);

        assert!(
            Cli::try_parse_from(["aka", "run", "analytics"]).is_err(),
            "run without a command is an error; `aka env` is the exports form"
        );

        let cli = Cli::try_parse_from(["aka", "env", "analytics", "--password-only"])
            .expect("env selectors parse");
        let Command::Env { password_only, .. } = cli.command else {
            panic!("expected env");
        };
        assert!(password_only);
        assert!(
            Cli::try_parse_from(["aka", "env", "analytics", "--", "psql"]).is_err(),
            "env takes no trailing command"
        );

        let cli = Cli::try_parse_from([
            "aka",
            "--json",
            "run",
            "production",
            "--",
            "ssh",
            "production",
        ])
        .expect("global output flags still parse after the scoped command");
        let Command::Run { command, .. } = cli.command else {
            panic!("expected run");
        };
        let exit = std::panic::catch_unwind(|| reject_json_for_scoped_command(cli.json, &command))
            .expect_err("JSON and child execution conflict");
        assert_eq!(exit.downcast::<CliExit>().unwrap().code, 2);
    }

    #[test]
    fn connection_mutations_parse_into_kind_specific_arguments() {
        let cli = Cli::try_parse_from([
            "aka",
            "conn",
            "add",
            "pg",
            "analytics",
            "--host",
            "db.example.test",
            "--dbname",
            "app",
            "--user",
            "agent",
            "--secret",
            "DATABASE_PASSWORD",
        ])
        .expect("typed Postgres creation parses");
        let Command::Conn {
            command: ConnCommand::Add { command },
        } = cli.command
        else {
            panic!("expected conn add");
        };
        let args = command.into_args();
        assert_eq!(args.kind, ConnKind::Pg);
        assert_eq!(args.name, "analytics");
        assert_eq!(args.host.as_deref(), Some("db.example.test"));
        assert_eq!(args.dbname.as_deref(), Some("app"));
        assert_eq!(args.secret.as_deref(), Some("DATABASE_PASSWORD"));

        let cli = Cli::try_parse_from([
            "aka",
            "conn",
            "update",
            "ssh",
            "production",
            "--host-key-fingerprint",
            "SHA256:abc",
        ])
        .expect("typed SSH update parses");
        let Command::Conn {
            command:
                ConnCommand::Update {
                    command: Some(command),
                    ..
                },
        } = cli.command
        else {
            panic!("expected conn update");
        };
        let (kind, args) = command.into_args();
        assert_eq!(kind, ConnKind::Ssh);
        assert_eq!(args.name, "production");
        assert_eq!(args.host_key_fingerprint.as_deref(), Some("SHA256:abc"));
    }

    #[test]
    fn typed_connection_help_excludes_other_kinds_fields() {
        let help = match configured_cli_command(false, true)
            .try_get_matches_from(["aka", "conn", "add", "pg", "--help"])
        {
            Ok(_) => panic!("--help unexpectedly parsed as a command"),
            Err(error) => error.to_string(),
        };
        assert!(help.contains("--dbname <DBNAME>"), "{help}");
        assert!(help.contains("--sslmode <SSLMODE>"), "{help}");
        assert!(!help.contains("--sigv4-region"), "{help}");
        assert!(!help.contains("--host-key-fingerprint"), "{help}");
        assert!(!help.contains("--cloud-provider"), "{help}");
    }

    #[test]
    fn status_distinguishes_socket_failure_classes() {
        let socket = Path::new("/tmp/aka.sock");
        assert!(
            socket_status_error(socket, &std::io::Error::from_raw_os_error(libc::ENOTSOCK))
                .contains("not a Unix socket")
        );
        assert!(socket_status_error(
            socket,
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied)
        )
        .contains("permission denied"));
        assert!(socket_status_error(
            socket,
            &std::io::Error::from(std::io::ErrorKind::ConnectionRefused)
        )
        .contains("no broker is running"));
    }

    #[test]
    fn local_status_does_not_pair_or_authenticate_as_an_agent() {
        use std::io::{Read as _, Write as _};

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        paths.ensure().unwrap();
        let listener = std::os::unix::net::UnixListener::bind(paths.socket_file()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]).into_owned();
            let body = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "protocol_version": 1,
                "mcp_url": null,
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            request
        });

        let report = local_status(Some(dir.path().to_path_buf())).unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /.well-known/agent-broker.json "));
        assert!(!request.contains("/v1/pair"));
        assert!(report.running);
        assert!(report.tools.is_empty());
        assert!(report
            .tools_error
            .as_deref()
            .is_some_and(|error| error.contains("no management token")));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["running"], true);
        assert_eq!(json["transport"], "unix");
    }

    #[test]
    fn skill_write_options_are_not_silently_ignored() {
        assert!(Cli::try_parse_from(["aka", "setup", "skill", "--path", "SKILL.md"]).is_err());
        assert!(Cli::try_parse_from(["aka", "setup", "skill", "--user"]).is_err());
        assert!(
            Cli::try_parse_from(["aka", "setup", "skill", "--write", "--path", "SKILL.md"]).is_ok()
        );
        assert!(Cli::try_parse_from([
            "aka",
            "setup",
            "skill",
            "--broker",
            "https://broker.example.test"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "aka",
            "setup",
            "instructions",
            "--broker",
            "https://broker.example.test"
        ])
        .is_ok());
        // Hidden root commands remain parser-compatible for existing scripts.
        assert!(Cli::try_parse_from(["aka", "skill", "--write"]).is_ok());
        assert!(Cli::try_parse_from(["aka", "instructions"]).is_ok());
        assert!(generated_skill_file(&format!(
            "---\nname: multitool\n---\n{GENERATED_SKILL_MARKER} generated -->"
        )));
        assert!(generated_skill_file(&format!(
            "---\nname: multitool\n---\n{LEGACY_GENERATED_SKILL_MARKER} generated -->"
        )));
        assert!(!generated_skill_file("# A hand-written skill\n"));
    }

    fn args(kind: ConnKind) -> ConnAdd {
        ConnAdd {
            name: "test".into(),
            kind,
            no_test: true,
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            secret: None,
            sslmode: None,
            ca_bundle: None,
            mcp_path: None,
            test_path: None,
            sigv4_region: None,
            sigv4_service: None,
            sigv4_access_key_ref: None,
            sigv4_secret_key_ref: None,
            sigv4_session_token_ref: None,
            gcp_key_ref: None,
            gcp_scope: None,
            client_cert: None,
            client_key: None,
            cloud_provider: None,
            cloud_region: None,
            cloud_access_key_ref: None,
            cloud_secret_key_ref: None,
            cloud_session_token_ref: None,
            cloud_role_arn: None,
            cloud_external_id: None,
            cloud_tenant_id: None,
            cloud_client_id: None,
            cloud_client_secret_ref: None,
            cloud_subscription_id: None,
            cloud_scope: None,
            cloud_gcp_key_ref: None,
            cloud_project: None,
            cloud_session_ttl: None,
            root: None,
            create_root: false,
            broker: None,
        }
    }

    #[test]
    fn cloud_aws_builds_a_provider_config() {
        let mut a = args(ConnKind::Cloud);
        assert!(conn_config(&a).unwrap_err().contains("--cloud-provider"));
        a.cloud_provider = Some("aws".into());
        assert!(conn_config(&a).unwrap_err().contains("--cloud-region"));
        a.cloud_region = Some("us-east-1".into());
        a.cloud_access_key_ref = Some("AWS_ACCESS_KEY_ID".into());
        a.cloud_secret_key_ref = Some("AWS_SECRET_ACCESS_KEY".into());
        a.cloud_role_arn = Some("arn:aws:iam::123:role/Agent".into());
        let config = conn_config(&a).unwrap();
        assert!(matches!(
            config,
            ConnectionConfig::Cloud {
                provider: aka_core::types::CloudProvider::Aws {
                    ref region,
                    ref role_arn,
                    ..
                }
            } if region == "us-east-1" && role_arn.as_deref() == Some("arn:aws:iam::123:role/Agent")
        ));
    }

    #[test]
    fn api_names_its_missing_and_stray_flags() {
        let mut a = args(ConnKind::Api);
        assert!(conn_config(&a).unwrap_err().contains("--host"));
        a.host = Some("api.github.com".into());
        assert!(conn_config(&a).unwrap_err().contains("--template"));
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        a.ca_bundle = Some("/etc/api-ca.pem".into());
        let config = conn_config(&a).unwrap();
        assert!(matches!(
            config,
            ConnectionConfig::Api {
                ref scheme,
                trusted_ca_bundle_path: Some(ref path),
                ..
            } if scheme == "https" && path == "/etc/api-ca.pem"
        ));
        // api derives secrets from the template; a stray --secret is a
        // misunderstanding worth naming, not ignoring.
        a.secret = Some("KEY".into());
        assert!(conn_config(&a).unwrap_err().contains("--secret"));
    }

    #[test]
    fn api_builds_a_sigv4_signer_instead_of_a_template() {
        let mut a = args(ConnKind::Api);
        a.host = Some("s3.amazonaws.com".into());
        a.sigv4_region = Some("us-east-1".into());
        // The region alone is not enough: each companion flag is named.
        assert!(conn_config(&a).unwrap_err().contains("--sigv4-service"));
        a.sigv4_service = Some("s3".into());
        assert!(conn_config(&a)
            .unwrap_err()
            .contains("--sigv4-access-key-ref"));
        a.sigv4_access_key_ref = Some("AWS_ACCESS_KEY_ID".into());
        assert!(conn_config(&a)
            .unwrap_err()
            .contains("--sigv4-secret-key-ref"));
        a.sigv4_secret_key_ref = Some("AWS_SECRET_ACCESS_KEY".into());
        // A signer connection needs no --template and renders an empty one.
        let config = conn_config(&a).unwrap();
        assert!(matches!(
            &config,
            ConnectionConfig::Api {
                template,
                signer: Some(SignerSpec::AwsSigv4 { region, service, .. }),
                ..
            } if template.is_empty() && region == "us-east-1" && service == "s3"
        ));
        // The two injection mechanisms are mutually exclusive at the flag
        // level too, rather than being caught only by the store.
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        assert!(conn_config(&a).unwrap_err().contains("--template"));
    }

    #[test]
    fn api_builds_a_gcp_signer_and_names_its_missing_scope() {
        let mut a = args(ConnKind::Api);
        a.host = Some("storage.googleapis.com".into());
        a.gcp_key_ref = Some("GCP_SA_KEY".into());
        assert!(conn_config(&a).unwrap_err().contains("--gcp-scope"));
        a.gcp_scope = Some("https://www.googleapis.com/auth/devstorage.read_only".into());
        let config = conn_config(&a).unwrap();
        assert!(matches!(
            &config,
            ConnectionConfig::Api {
                template,
                signer: Some(SignerSpec::GcpServiceAccount { key_ref, scope }),
                ..
            } if template.is_empty()
                && key_ref == "GCP_SA_KEY"
                && scope == "https://www.googleapis.com/auth/devstorage.read_only"
        ));
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        assert!(conn_config(&a).unwrap_err().contains("--template"));
    }

    #[test]
    fn api_carries_optional_client_certificate_paths() {
        let mut a = args(ConnKind::Api);
        a.host = Some("api.internal".into());
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        a.client_cert = Some("/etc/client.pem".into());
        a.client_key = Some("/etc/client.key".into());
        assert!(matches!(
            conn_config(&a).unwrap(),
            ConnectionConfig::Api {
                client_cert_path: Some(ref cert),
                client_key_path: Some(ref key),
                ..
            } if cert == "/etc/client.pem" && key == "/etc/client.key"
        ));
    }

    #[test]
    fn api_carries_an_optional_mcp_path() {
        let mut a = args(ConnKind::Api);
        a.host = Some("mcp.example.com".into());
        a.template = Some("Authorization: Bearer {{KEY}}".into());
        // Absent by default; set when --mcp-path is given.
        assert!(matches!(
            conn_config(&a).unwrap(),
            ConnectionConfig::Api { mcp_path: None, .. }
        ));
        a.mcp_path = Some("/mcp".into());
        assert!(matches!(
            conn_config(&a).unwrap(),
            ConnectionConfig::Api { mcp_path: Some(ref path), .. } if path == "/mcp"
        ));
        // --mcp-path is an api-only concept; naming it on another kind is an
        // error, not a silent no-op.
        let mut p = args(ConnKind::Pg);
        p.host = Some("db.internal".into());
        p.dbname = Some("app".into());
        p.user = Some("app".into());
        p.secret = Some("PGPASS".into());
        p.mcp_path = Some("/mcp".into());
        assert!(conn_config(&p).unwrap_err().contains("--mcp-path"));
    }

    #[test]
    fn pg_defaults_port_and_sslmode() {
        let mut a = args(ConnKind::Pg);
        a.host = Some("db.internal".into());
        a.dbname = Some("app".into());
        a.user = Some("app".into());
        assert!(conn_config(&a).unwrap_err().contains("--secret"));
        a.secret = Some("PGPASS".into());
        match conn_config(&a).unwrap() {
            ConnectionConfig::Pg { port, sslmode, .. } => {
                assert_eq!(port, 5432);
                assert_eq!(sslmode, PgSslMode::VerifyFull);
            }
            other => panic!("wrong config: {other:?}"),
        }
        a.sslmode = Some("bogus".into());
        assert!(conn_config(&a).unwrap_err().contains("bogus"));
    }

    #[test]
    fn activity_lines_format_with_optional_fields() {
        let entry = ActivityDto {
            icon: "network".into(),
            tone: "blue".into(),
            kind: Some("http_executed".into()),
            text: "claude-code requested github".into(),
            detail: Some("GET api.github.com/user/repos".into()),
            agent: Some("claude-code".into()),
            identity: None,
            session: None,
            connection: Some("github".into()),
            outcome: Some("ok".into()),
            protocol: Some("http".into()),
            duration_ms: None,
            approver: None,
            surface: None,
            confirmation: None,
            at: "2026-07-24T12:00:00.123456Z".into(),
        };
        assert_eq!(
            format_activity_line(&entry, false),
            "2026-07-24T12:00:00  claude-code requested github — GET \
             api.github.com/user/repos  [claude-code]"
        );
        let colored = format_activity_line(&entry, true);
        assert!(colored.contains('\u{1b}'));
        assert!(colored.contains("claude-code requested github"));
        let bare = ActivityDto {
            kind: Some("settings_changed".into()),
            text: "Agent access enabled".into(),
            detail: None,
            agent: None,
            connection: None,
            outcome: None,
            protocol: None,
            at: "-".into(),
            ..entry
        };
        assert_eq!(
            format_activity_line(&bare, false),
            "-  Agent access enabled"
        );
    }

    #[test]
    fn ssh_status_ignores_normal_session_closes_when_finding_refusals() {
        let normal_close = ActivityDto {
            icon: "logOut".into(),
            tone: "neutral".into(),
            kind: Some("session_closed".into()),
            text: "SSH session closed".into(),
            detail: Some("idle timeout".into()),
            agent: Some("codex".into()),
            identity: None,
            session: None,
            connection: Some("deploy".into()),
            outcome: Some("idle_timeout".into()),
            protocol: Some("ssh".into()),
            duration_ms: Some(120_000),
            approver: None,
            surface: None,
            confirmation: None,
            at: "2026-07-30T12:01:00Z".into(),
        };
        let denial = ActivityDto {
            icon: "circleX".into(),
            tone: "danger".into(),
            kind: Some("denied".into()),
            text: "SSH agent connection refused: deploy".into(),
            detail: Some("agent access is disabled".into()),
            agent: Some("endpoint".into()),
            identity: None,
            session: None,
            connection: Some("deploy".into()),
            outcome: Some("denied_by_policy".into()),
            protocol: Some("ssh".into()),
            duration_ms: None,
            approver: None,
            surface: None,
            confirmation: None,
            at: "2026-07-30T12:00:00Z".into(),
        };

        let refusals = status_ssh_refusals(&[normal_close, denial]);
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].reason, "denied_by_policy");
        assert_eq!(refusals[0].at, "2026-07-30T12:00:00Z");
    }

    fn update_args() -> ConnUpdate {
        ConnUpdate {
            name: "test".into(),
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            secret: None,
            sslmode: None,
            ca_bundle: None,
            test_path: None,
            root: None,
            broker: None,
        }
    }

    fn update_dto(kind: &str) -> ConnectionDto {
        use aka_api::AccessDto;
        ConnectionDto {
            id: Uuid::new_v4().to_string(),
            name: "test".into(),
            updated_at: "2026-07-29T12:00:00.000000000Z".into(),
            kind: kind.into(),
            target: "example.com".into(),
            secret_names: vec![],
            oauth: false,
            agent_access: AccessDto {
                enabled: true,
                confirm: false,
                expose_response_credentials: false,
                confirm_window_until: None,
                confirm_window_agents: vec![],
                confirm_cooldown_until: None,
                allowed_tools: None,
                audit_statements: None,
                audit_statements_effective: false,
                endpoint: None,
            },
            host: None,
            scheme: None,
            port: None,
            template: None,
            dbname: None,
            user: None,
            host_key_fingerprint: None,
            destination: None,
            sslmode: None,
            trusted_ca_bundle_path: None,
            mcp_path: None,
            test_path: None,
            account: Some("operator@example.com".into()),
            oauth_spec: None,
            last_status: None,
            last_detail: None,
            last_checked_at: None,
            signer: None,
            client_cert_path: None,
            client_key_path: None,
            cloud: None,
        }
    }

    #[test]
    fn update_sends_only_supplied_fields_and_names_stray_flags() {
        let dto = update_dto("api");
        let mut a = update_args();
        assert!(connection_config_patch(&dto, &a, None)
            .unwrap_err()
            .contains("at least one field flag"));

        a.host = Some("api.example.com".into());
        let patch = connection_config_patch(&dto, &a, None).unwrap();
        assert_eq!(patch.host.as_deref(), Some("api.example.com"));
        assert_eq!(patch.scheme, None);
        assert_eq!(patch.template, None);
        assert_eq!(patch.trusted_ca_bundle_path, None);
        assert!(!patch.clear_trusted_ca_bundle);

        a.dbname = Some("stray".into());
        assert!(connection_config_patch(&dto, &a, None)
            .unwrap_err()
            .contains("--dbname"));
    }

    #[test]
    fn update_represents_explicit_clears_without_rebuilding_config() {
        let mut a = update_args();
        a.ca_bundle = Some(String::new());
        let patch = connection_config_patch(&update_dto("pg"), &a, None).unwrap();
        assert!(patch.clear_trusted_ca_bundle);
        assert_eq!(patch.trusted_ca_bundle_path, None);

        let mut a = update_args();
        a.host_key_fingerprint = Some(String::new());
        let patch = connection_config_patch(&update_dto("ssh"), &a, None).unwrap();
        assert_eq!(patch.host_key_fingerprint.as_deref(), Some(""));
    }

    #[test]
    fn ssh_defaults_port_22() {
        let mut a = args(ConnKind::Ssh);
        a.host = Some("prod.example.com".into());
        a.user = Some("deploy".into());
        a.secret = Some("DEPLOY_KEY".into());
        a.host_key_fingerprint = Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        match conn_config(&a).unwrap() {
            ConnectionConfig::Ssh { port, .. } => assert_eq!(port, 22),
            other => panic!("wrong config: {other:?}"),
        }
    }

    #[test]
    fn mcp_client_labels_are_valid_http_header_values() {
        assert_eq!(parse_client_label("claude-code").unwrap(), "claude-code");
        for invalid in ["", "has space", "line\nbreak", "é", &"x".repeat(65)] {
            assert!(parse_client_label(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn headless_confirmation_warning_is_counted_and_actionable() {
        assert_eq!(headless_confirmation_warning(0), None);
        assert_eq!(
            headless_confirmation_warning(1).as_deref(),
            Some(
                "warning: 1 tool is set to confirm traffic and this broker has no approval \
                 surface; its calls will be refused"
            )
        );
        assert!(headless_confirmation_warning(3)
            .unwrap()
            .contains("3 tools are set"));
    }

    #[test]
    fn serve_banner_labels_listeners_auth_and_quit() {
        let banner = ServeBanner {
            socket: PathBuf::from("/tmp/broker.sock"),
            root: PathBuf::from("/tmp/root"),
            root_flag: " --root '/tmp/root'".into(),
            first_start_manage_token: None,
            tcp_addr: Some("127.0.0.1:4780".parse().unwrap()),
            public_url: Some("http://127.0.0.1:4780".into()),
            web_root: Some(PathBuf::from("dist/ui")),
            advertise_host: None,
            mcp: McpBannerStatus::Started {
                addr: "127.0.0.1:9".parse().unwrap(),
            },
            vault: "macOS login keychain (prompts per secret; build is unsigned)".into(),
            headless_warning: None,
            token_path: PathBuf::from("/tmp/root/sock/token"),
        };
        let text = banner.lines().join("\n");
        assert!(text.starts_with("Multitool broker ready\n"));
        assert!(text.contains("  Socket      /tmp/broker.sock"));
        assert!(text.contains("  Root        /tmp/root"));
        assert!(text.contains("  MCP         127.0.0.1:9"));
        assert!(text.contains("  Keychain    macOS login keychain"));
        assert!(text.contains(
            "  Manage      aka status --root '/tmp/root'  (every aka command takes --root)"
        ));
        assert!(text.contains(
            "  Remote      the same commands with --broker http://127.0.0.1:4780 and a manage token"
        ));
        assert!(text.contains(
            "  Desktop     aka setup desktop --root '/tmp/root'  (the app connects to this broker as remote)"
        ));
        assert!(text
            .contains("  Agent key   /tmp/root/sock/token  (agent clients read this to connect)"));
        assert!(text.contains(
            "  Agent docs  curl --unix-socket /tmp/broker.sock http://localhost/instructions"
        ));
        assert!(text.contains("/v1/pair is not served on TCP"));
        // Optional control-plane group comes after operator + notes.
        let note_at = text.find("  Note        /v1/pair").expect("note");
        let tcp_at = text
            .find("  TCP         127.0.0.1:4780  (plaintext; put TLS in front)")
            .expect("tcp");
        let quit_at = text.find("  Quit        Ctrl-C or SIGTERM").expect("quit");
        assert!(note_at < tcp_at && tcp_at < quit_at);
        assert!(text.contains("  Public URL  http://127.0.0.1:4780"));
        assert!(text.contains("  UI          dist/ui"));
        assert!(!text.contains("…"));
    }

    #[test]
    fn serve_banner_optional_control_plane_off_hints() {
        let banner = ServeBanner {
            socket: PathBuf::from("/tmp/broker.sock"),
            root: PathBuf::from("/tmp/root"),
            root_flag: " --root '/tmp/root'".into(),
            first_start_manage_token: None,
            tcp_addr: None,
            public_url: None,
            web_root: None,
            advertise_host: None,
            mcp: McpBannerStatus::Disabled,
            vault: "encrypted file".into(),
            headless_warning: None,
            token_path: PathBuf::from("/tmp/root/sock/token"),
        };
        let text = banner.lines().join("\n");
        assert!(text.contains("  TCP         off (--no-listen)"));
        assert!(text.contains("  Public URL  off (--no-listen)"));
        assert!(text.contains("  UI          off (listening disabled)"));
        // Not listening: no remote-management or desktop hints, only the
        // local --root form.
        assert!(text.contains("  Manage      aka status --root '/tmp/root'"));
        assert!(!text.contains("  Remote"));
        assert!(!text.contains("  Desktop"));
        assert!(!text.contains("--broker"));
        let skill_at = text.find("  Skill       ").expect("skill");
        let tcp_at = text.find("  TCP         off").expect("tcp off");
        let quit_at = text.find("  Quit        ").expect("quit");
        assert!(skill_at < tcp_at && tcp_at < quit_at);
    }

    #[test]
    fn serve_banner_first_start_token_replaces_manage_block() {
        let banner = ServeBanner {
            socket: PathBuf::from("/s"),
            root: PathBuf::from("/r"),
            root_flag: " --root '/r'".into(),
            first_start_manage_token: Some(PathBuf::from("/r/sock/manage-token")),
            tcp_addr: Some("127.0.0.1:1".parse().unwrap()),
            public_url: Some("http://localhost:1".into()),
            web_root: None,
            advertise_host: Some("agents.example".into()),
            mcp: McpBannerStatus::Failed("bind failed".into()),
            vault: "encrypted file".into(),
            headless_warning: Some("warning: 1 tool is set to confirm traffic".into()),
            token_path: PathBuf::from("/r/sock/token"),
        };
        let text = banner.lines().join("\n");
        assert!(text.contains("  First token /r/sock/manage-token"));
        assert!(text.contains("aka admin token --root '/r' while the broker is live"));
        // First start still points the desktop app at the listener.
        assert!(text.contains("  Desktop     aka setup desktop --root '/r'"));
        assert!(!text.contains("  Manage "));
        assert!(text.contains("  Data host   agents.example  (PG leg is plaintext)"));
        assert!(text.contains("  MCP         not started (bind failed)"));
        assert!(text.contains("  Warning     warning: 1 tool is set to confirm traffic"));
        assert!(text.contains("  TCP         127.0.0.1:1  (plaintext; put TLS in front)"));
        assert!(text.contains("  Public URL  http://localhost:1"));
        assert!(text.contains("  UI          off — add --web-root dist/ui"));
    }

    #[test]
    fn split_label_line_recognizes_multiword_labels() {
        assert_eq!(
            split_label_line("  Public URL  http://example"),
            Some(("Public URL", "http://example"))
        );
        assert_eq!(
            split_label_line("  First token /path  (0600)"),
            Some(("First token", "/path  (0600)"))
        );
        assert_eq!(split_label_line("Multitool broker ready"), None);
        assert_eq!(split_label_line(""), None);
    }
}
