//! Who is on the other end of the control socket, as far as the OS will say.
//!
//! The client label (`X-Multitool-Client`) is a string the caller picks, so it
//! can name itself anything. This module answers the different question the
//! approval surfaces actually want: *which program is this?* — answered by the
//! operating system rather than by the caller.
//!
//! # Two links
//!
//! 1. The process on the socket must be **our own signed helper**, recognized
//!    by the signing team the broker itself was signed with.
//! 2. Only then does the broker walk up to that helper's parent and identify
//!    *it*. That parent is the agent.
//!
//! Link 1 is what makes link 2 meaningful. Without it any process could
//! connect and have its own ancestry read, letting an attacker insert as many
//! intermediate processes as it liked and land on whatever it wanted attested.
//! With it, only the real helper attests, and the real helper's parent is
//! whatever really launched it.
//!
//! Note what the helper does *not* do: it reports nothing. It does not send
//! its parent's pid, name, or signature. The broker reads the peer pid from
//! the socket and walks the process table itself, so a compromised helper
//! cannot lie about its ancestry — it can only fail to be recognized.
//!
//! # Where this works
//!
//! macOS over the Unix socket, and nowhere else. Linux can name an executable
//! but cannot verify it (no signature to check, and same-user `ptrace` can
//! puppet the helper), and a TCP listener's peer is the reverse proxy, not the
//! caller — which is the same limit `HOSTING.md` already documents for the
//! client label. Both report [`AgentIdentity::Unattested`], and the UI renders
//! that as "an agent" rather than inventing a name.
//!
//! The policy — the ancestry walk, what counts as a shell, what to do with an
//! interpreter — lives here and is tested everywhere. Only [`darwin`] needs a
//! signed Mac, mirroring how [`crate::keychain`] splits.

#[cfg(target_os = "macos")]
pub mod darwin;

use serde::{Deserialize, Serialize};

/// How far up the process tree to look before giving up. Deep enough to step
/// over a shell wrapper or two (`sh -c "aka mcp"`, a terminal
/// multiplexer), shallow enough that an unrelated ancestor cannot be reached.
const MAX_DEPTH: usize = 4;

/// Executables that launch other programs without being the program. Walking
/// past these is what lets `sh -c "aka mcp"` still attest as the agent
/// that ran it.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "env", "login", "script",
];

/// Runtimes that host a program rather than being one. Verifying an
/// interpreter's signature proves something about `node`, not about the script
/// it is running — so this stops the walk with nothing attested instead of
/// reporting a name the signature does not cover.
const INTERPRETERS: &[&str] = &[
    "node", "deno", "bun", "python", "python2", "python3", "ruby", "perl", "java", "dotnet",
];

/// What the OS could prove about the agent behind a request.
///
/// The three variants are exactly the three renderings the UI has: a name we
/// can vouch for, an organisation we can vouch for, or nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentIdentity {
    /// Signature verified and the bundle named the program.
    Verified {
        program: String,
        signer: String,
        team_id: String,
        identifier: String,
    },
    /// Signature verified, but there is no bundle to take a display name from.
    /// The ordinary shape for a signed CLI binary, whose `codesign` output
    /// reports `Info.plist=not bound`.
    ///
    /// Deliberately *not* collapsed into `Verified` with a name derived from
    /// the identifier: a guessed product name is the thing this whole design
    /// exists to avoid.
    VerifiedSigner {
        signer: String,
        team_id: String,
        identifier: String,
    },
    /// Nothing was proven. Not an error — the ordinary state on Linux, on a
    /// hosted broker, and for any caller that skips the helper.
    #[default]
    Unattested,
}

impl AgentIdentity {
    pub fn is_attested(&self) -> bool {
        !matches!(self, AgentIdentity::Unattested)
    }

    /// The verified program name, when there is one. `None` covers both
    /// "signer only" and "nothing" — callers that need to tell those apart
    /// match on the enum.
    pub fn program(&self) -> Option<&str> {
        match self {
            AgentIdentity::Verified { program, .. } => Some(program),
            _ => None,
        }
    }

    pub fn team_id(&self) -> Option<&str> {
        match self {
            AgentIdentity::Verified { team_id, .. }
            | AgentIdentity::VerifiedSigner { team_id, .. } => Some(team_id),
            AgentIdentity::Unattested => None,
        }
    }

    /// Short form for the activity log and `tracing`, never for a decision
    /// surface — those match on the enum so they can style each state.
    pub fn audit_label(&self) -> Option<String> {
        match self {
            AgentIdentity::Verified { program, .. } => Some(program.clone()),
            AgentIdentity::VerifiedSigner { signer, .. } => Some(signer.clone()),
            AgentIdentity::Unattested => None,
        }
    }
}

/// One process, as the OS describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    /// Process start time, in microseconds since the epoch. Paired with the
    /// pid this is a stable process handle: a recycled pid gets a different
    /// start time, which is what keeps a pid captured earlier from resolving
    /// to a later, unrelated process.
    pub start_time: u64,
    /// Absolute path to the executing image.
    pub path: String,
}

/// A verified code signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIdentity {
    /// Code-signing identifier, e.g. `com.anthropic.claude-code`.
    pub identifier: String,
    /// Apple Developer team, e.g. `Q6L2SF6YDW`. Absent for ad-hoc signatures.
    pub team_id: Option<String>,
    /// Signing organisation as it should be shown, e.g. `Anthropic, PBC`.
    pub signer: Option<String>,
    /// Bundle display name, when the image is a bundle. A bare signed
    /// executable has none.
    pub program: Option<String>,
}

/// The process on the other end of a socket, captured when the connection was
/// accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerProcess {
    pub pid: i32,
    pub uid: u32,
    pub start_time: u64,
}

/// The operating-system calls attestation needs. Split out so the walk above
/// can be tested with a scripted process table on any platform.
pub trait PlatformAttestor: Send + Sync + std::fmt::Debug {
    /// Process-table lookup. `None` when the process is gone.
    fn process(&self, pid: i32) -> Option<ProcessInfo>;

    /// Verified signing identity of a live process, or `None` when it is
    /// unsigned, tampered with, or no longer the process that was there —
    /// `expect_start` is re-checked against the process table so a recycled
    /// pid cannot answer for the one the caller meant.
    fn code_identity(&self, pid: i32, expect_start: u64) -> Option<CodeIdentity>;

    /// The signing team of the running broker, used to recognize our own
    /// helper. `None` on an unsigned build, which makes every request
    /// unattested — the safe direction, and the normal state in development.
    fn own_team_id(&self) -> Option<String>;
}

/// The platform attestor for this build. macOS gets the real one; everywhere
/// else attestation is unavailable and every caller is unattested.
pub fn platform() -> Option<&'static dyn PlatformAttestor> {
    #[cfg(target_os = "macos")]
    {
        Some(darwin::security_framework())
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The file name of an executable path, for classifying shells and runtimes.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Strip the version suffix Python carries in its file name, so `python3.12`
/// classifies with `python3`. Only Python ships this shape.
fn runtime_stem(base: &str) -> &str {
    match base.starts_with("python") {
        true => base.split('.').next().unwrap_or(base),
        false => base,
    }
}

fn is_shell(path: &str) -> bool {
    SHELLS.contains(&basename(path))
}

fn is_interpreter(path: &str) -> bool {
    INTERPRETERS.contains(&runtime_stem(basename(path)))
}

/// Turn a verified signature into the identity to display.
fn identity_from(code: CodeIdentity) -> AgentIdentity {
    // A signature with no team and no organisation proves possession of *some*
    // key and nothing a user could act on, so it is not worth a green check.
    let (Some(team_id), Some(signer)) = (code.team_id, code.signer) else {
        return AgentIdentity::Unattested;
    };
    match code.program {
        Some(program) => AgentIdentity::Verified {
            program,
            signer,
            team_id,
            identifier: code.identifier,
        },
        None => AgentIdentity::VerifiedSigner {
            signer,
            team_id,
            identifier: code.identifier,
        },
    }
}

/// Resolve the agent behind a socket peer. See the module docs for the two
/// links; this is their implementation.
pub fn attest(platform: &dyn PlatformAttestor, peer: PeerProcess) -> AgentIdentity {
    // Link 1: is the process on the socket our own helper? Compared by signing
    // team rather than identifier, because the desktop app and the CLI are
    // separate identifiers shipped by the same team.
    let Some(own_team) = platform.own_team_id() else {
        return AgentIdentity::Unattested;
    };
    let peer_code = platform.code_identity(peer.pid, peer.start_time);
    let peer_team = peer_code.as_ref().and_then(|code| code.team_id.as_deref());
    if peer_team != Some(own_team.as_str()) {
        return AgentIdentity::Unattested;
    }

    // Link 2: the helper's ancestry. The helper itself is never the answer —
    // the question is what launched it.
    let Some(helper) = platform.process(peer.pid) else {
        return AgentIdentity::Unattested;
    };
    let mut next = helper.ppid;
    for _ in 0..MAX_DEPTH {
        // pid 1 and 0 are the OS, not an agent: reaching them means the real
        // launcher already exited and the helper was reparented.
        if next <= 1 {
            return AgentIdentity::Unattested;
        }
        let Some(info) = platform.process(next) else {
            return AgentIdentity::Unattested;
        };
        if is_shell(&info.path) {
            next = info.ppid;
            continue;
        }
        if is_interpreter(&info.path) {
            return AgentIdentity::Unattested;
        }
        return match platform.code_identity(info.pid, info.start_time) {
            Some(code) => identity_from(code),
            None => AgentIdentity::Unattested,
        };
    }
    AgentIdentity::Unattested
}

/// How long an attestation ticket stays redeemable. The helper mints one at
/// startup and redeems it on its very next request, so this only has to cover
/// process startup — short enough that a ticket leaked from a log is useless.
const TICKET_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// The header carrying an attestation ticket from the helper to the MCP host.
pub const ATTESTATION_HEADER: &str = "x-multitool-attestation";

/// Carries an attested identity from the control socket, where the peer
/// process is visible, to the MCP host, where it is not.
///
/// The MCP session runs over loopback TCP on a port the broker advertises, and
/// a TCP peer says nothing about which program is behind it. So the identity is
/// resolved once on the socket — where it *can* be — and handed over as a
/// short-lived, single-use ticket that the session then owns.
///
/// Single-use matters: a ticket that could be replayed would let a second
/// process adopt the first one's identity by presenting the same string.
#[derive(Debug, Default)]
pub struct AttestationTickets {
    issued: std::sync::Mutex<Vec<(String, AgentIdentity, std::time::Instant)>>,
}

impl AttestationTickets {
    /// Mint a ticket for an identity the socket just resolved. Unattested
    /// identities get no ticket: there is nothing to carry, and minting one
    /// would only invite the MCP host to believe it proved something.
    pub fn issue(&self, identity: AgentIdentity) -> Option<String> {
        if !identity.is_attested() {
            return None;
        }
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).expect("os rng");
        let ticket = format!(
            "akaatt_{}",
            buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let mut issued = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        issued.retain(|(_, _, at)| now.duration_since(*at) < TICKET_TTL);
        // Bounded for the same reason the debounce map is: a caller that mints
        // and never redeems must not grow this without limit.
        if issued.len() >= CACHE_CAP {
            issued.remove(0);
        }
        issued.push((ticket.clone(), identity, now));
        Some(ticket)
    }

    /// Redeem a ticket, consuming it. Returns [`AgentIdentity::Unattested`]
    /// for anything unknown, expired, or already used — the same answer a
    /// caller that never presented one gets.
    pub fn redeem(&self, ticket: &str) -> AgentIdentity {
        let mut issued = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        issued.retain(|(_, _, at)| now.duration_since(*at) < TICKET_TTL);
        match issued.iter().position(|(value, _, _)| value == ticket) {
            Some(index) => issued.remove(index).1,
            None => AgentIdentity::Unattested,
        }
    }
}

/// How many resolved peers to remember. One entry per live agent connection is
/// the realistic working set; the bound only exists so a long-running broker
/// churning through short-lived agents cannot grow this without limit.
const CACHE_CAP: usize = 256;

/// [`attest`] against the running platform, memoized.
///
/// Signature verification costs milliseconds and every agent request would
/// otherwise repeat it for the same process. The `(pid, start_time)` key is
/// stable for a process's lifetime and cannot be reused by a later process, so
/// a hit is always answering for the process the caller meant.
pub fn attest_cached(peer: PeerProcess) -> AgentIdentity {
    /// `(pid, start_time)` → what it resolved to.
    type Memo = Vec<((i32, u64), AgentIdentity)>;
    static CACHE: std::sync::Mutex<Option<Memo>> = std::sync::Mutex::new(None);
    let Some(platform) = platform() else {
        return AgentIdentity::Unattested;
    };
    let key = (peer.pid, peer.start_time);
    {
        let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let entries = guard.get_or_insert_with(Vec::new);
        if let Some((_, identity)) = entries.iter().find(|(k, _)| *k == key) {
            return identity.clone();
        }
    }
    // Resolved outside the lock: a signature check is milliseconds, and holding
    // the mutex across it would serialize every agent connecting at once.
    let identity = attest(platform, peer);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let entries = guard.get_or_insert_with(Vec::new);
    if !entries.iter().any(|(k, _)| *k == key) {
        if entries.len() >= CACHE_CAP {
            // Oldest-first eviction. The set is small and lookups are rare
            // enough that a plain Vec beats the bookkeeping of an LRU.
            entries.remove(0);
        }
        entries.push((key, identity.clone()));
    }
    identity
}

/// Extract the organisation from a certificate common name.
///
/// Apple's leaf CNs read `Developer ID Application: Anthropic, PBC
/// (Q6L2SF6YDW)`; what a user should see is the middle. The team id is already
/// carried separately, so the parenthesised copy is dropped.
pub fn signer_org(common_name: &str) -> Option<String> {
    let after_prefix = common_name
        .split_once(": ")
        .map(|(_, rest)| rest)
        .unwrap_or(common_name)
        .trim();
    let without_team = match after_prefix.rsplit_once('(') {
        Some((left, right)) if right.ends_with(')') => left,
        _ => after_prefix,
    };
    let cleaned = without_team.trim().trim_end_matches(',').trim();
    (!cleaned.is_empty()).then(|| cleaned.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A scripted process table, so the walk is testable off a Mac.
    #[derive(Debug, Default)]
    struct FakePlatform {
        procs: HashMap<i32, ProcessInfo>,
        codes: HashMap<i32, CodeIdentity>,
        own_team: Option<String>,
    }

    impl FakePlatform {
        fn proc(mut self, pid: i32, ppid: i32, path: &str) -> Self {
            self.procs.insert(
                pid,
                ProcessInfo {
                    pid,
                    ppid,
                    start_time: 1000 + pid as u64,
                    path: path.to_string(),
                },
            );
            self
        }

        fn signed(mut self, pid: i32, team: &str, identifier: &str, program: Option<&str>) -> Self {
            self.codes.insert(
                pid,
                CodeIdentity {
                    identifier: identifier.to_string(),
                    team_id: Some(team.to_string()),
                    signer: Some("Anthropic, PBC".to_string()),
                    program: program.map(str::to_string),
                },
            );
            self
        }

        fn own(mut self, team: &str) -> Self {
            self.own_team = Some(team.to_string());
            self
        }

        fn peer(&self, pid: i32) -> PeerProcess {
            PeerProcess {
                pid,
                uid: 501,
                start_time: self.procs[&pid].start_time,
            }
        }
    }

    impl PlatformAttestor for FakePlatform {
        fn process(&self, pid: i32) -> Option<ProcessInfo> {
            self.procs.get(&pid).cloned()
        }
        fn code_identity(&self, pid: i32, expect_start: u64) -> Option<CodeIdentity> {
            let info = self.procs.get(&pid)?;
            (info.start_time == expect_start)
                .then(|| self.codes.get(&pid).cloned())
                .flatten()
        }
        fn own_team_id(&self) -> Option<String> {
            self.own_team.clone()
        }
    }

    /// The helper, signed by our team, launched directly by a signed app.
    fn claude_desktop() -> FakePlatform {
        FakePlatform::default()
            .own("TEAM1")
            .proc(100, 50, "/Applications/Claude.app/Contents/MacOS/Claude")
            .signed(
                100,
                "TEAM1",
                "com.anthropic.claude-desktop",
                Some("Claude Desktop"),
            )
            .proc(200, 100, "/usr/local/bin/aka")
            .signed(200, "TEAM1", "com.aka.multitool", None)
    }

    #[test]
    fn a_signed_parent_with_a_bundle_name_is_verified() {
        let p = claude_desktop();
        assert_eq!(
            attest(&p, p.peer(200)),
            AgentIdentity::Verified {
                program: "Claude Desktop".into(),
                signer: "Anthropic, PBC".into(),
                team_id: "TEAM1".into(),
                identifier: "com.anthropic.claude-desktop".into(),
            }
        );
    }

    #[test]
    fn a_signed_parent_without_a_bundle_reports_only_its_signer() {
        // The ordinary shape for a signed CLI binary: `Info.plist=not bound`.
        let p = claude_desktop().signed(100, "TEAM1", "com.anthropic.claude-code", None);
        assert_eq!(
            attest(&p, p.peer(200)),
            AgentIdentity::VerifiedSigner {
                signer: "Anthropic, PBC".into(),
                team_id: "TEAM1".into(),
                identifier: "com.anthropic.claude-code".into(),
            }
        );
    }

    #[test]
    fn a_caller_that_is_not_our_helper_attests_nothing() {
        // Link 1: without it this process's own ancestry would be walked, and
        // an attacker could stack as many parents as it wanted below a signed
        // one. It is not our helper, so the walk never starts.
        let p = claude_desktop().signed(200, "OTHER", "com.evil.tool", Some("Evil"));
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    #[test]
    fn an_unsigned_caller_attests_nothing() {
        let mut p = claude_desktop();
        p.codes.remove(&200);
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    #[test]
    fn shell_wrappers_are_walked_past() {
        // `claude` → `sh -c "aka mcp"` → helper.
        let p = claude_desktop()
            .proc(150, 100, "/bin/sh")
            .proc(200, 150, "/usr/local/bin/aka");
        assert_eq!(attest(&p, p.peer(200)).program(), Some("Claude Desktop"));
    }

    #[test]
    fn the_walk_is_bounded() {
        // Five shells is one more than MAX_DEPTH allows.
        let p = claude_desktop()
            .proc(101, 100, "/bin/sh")
            .proc(102, 101, "/bin/sh")
            .proc(103, 102, "/bin/sh")
            .proc(104, 103, "/bin/sh")
            .proc(105, 104, "/bin/sh")
            .proc(200, 105, "/usr/local/bin/aka");
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    #[test]
    fn an_interpreter_parent_stops_the_walk() {
        // node is signed, but its signature says nothing about the script it
        // runs — so this must not inherit node's identity, and must not keep
        // walking up to whatever launched node either.
        let p = claude_desktop()
            .proc(150, 100, "/opt/homebrew/bin/node")
            .signed(150, "TEAM9", "org.nodejs.node", Some("Node.js"))
            .proc(200, 150, "/usr/local/bin/aka");
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    #[test]
    fn a_versioned_python_still_classifies_as_an_interpreter() {
        let p = claude_desktop()
            .proc(150, 100, "/opt/homebrew/bin/python3.12")
            .proc(200, 150, "/usr/local/bin/aka");
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    #[test]
    fn an_unsigned_broker_attests_nothing() {
        // Development builds are unsigned. Failing closed here is what keeps a
        // dev broker from inventing verified names.
        let mut p = claude_desktop();
        p.own_team = None;
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    #[test]
    fn a_recycled_pid_does_not_answer_for_the_captured_one() {
        let p = claude_desktop();
        let stale = PeerProcess {
            pid: 200,
            uid: 501,
            start_time: 1, // not the start time the table reports
        };
        assert_eq!(attest(&p, stale), AgentIdentity::Unattested);
    }

    #[test]
    fn reparented_to_launchd_attests_nothing() {
        let p = claude_desktop().proc(200, 1, "/usr/local/bin/aka");
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    #[test]
    fn a_signature_without_a_team_is_not_worth_a_check() {
        // Ad-hoc signatures prove possession of a key and nothing a user could
        // act on.
        let p = claude_desktop();
        let mut adhoc = p.codes.get(&100).cloned().unwrap();
        adhoc.team_id = None;
        let mut p = p;
        p.codes.insert(100, adhoc);
        assert_eq!(attest(&p, p.peer(200)), AgentIdentity::Unattested);
    }

    fn verified() -> AgentIdentity {
        AgentIdentity::Verified {
            program: "Claude Desktop".into(),
            signer: "Anthropic, PBC".into(),
            team_id: "TEAM1".into(),
            identifier: "com.anthropic.claude-desktop".into(),
        }
    }

    #[test]
    fn a_ticket_carries_the_identity_across_once() {
        let tickets = AttestationTickets::default();
        let ticket = tickets.issue(verified()).expect("attested callers get one");
        assert_eq!(tickets.redeem(&ticket), verified());
    }

    #[test]
    fn a_ticket_cannot_be_replayed() {
        // Without single use, a second process could adopt the first one's
        // identity just by presenting the same string.
        let tickets = AttestationTickets::default();
        let ticket = tickets.issue(verified()).unwrap();
        assert!(tickets.redeem(&ticket).is_attested());
        assert_eq!(tickets.redeem(&ticket), AgentIdentity::Unattested);
    }

    #[test]
    fn an_unknown_ticket_is_simply_unattested() {
        // Not an error: the same answer a caller that presented none gets, so
        // a forged string buys nothing a plain connection would not have.
        let tickets = AttestationTickets::default();
        assert_eq!(tickets.redeem("akaatt_deadbeef"), AgentIdentity::Unattested);
    }

    #[test]
    fn nothing_is_issued_for_an_unattested_caller() {
        // Minting one would invite the MCP host to believe a ticket proved
        // something when it carried nothing.
        let tickets = AttestationTickets::default();
        assert!(tickets.issue(AgentIdentity::Unattested).is_none());
    }

    #[test]
    fn issuing_is_bounded() {
        let tickets = AttestationTickets::default();
        for _ in 0..CACHE_CAP + 50 {
            tickets.issue(verified());
        }
        assert!(tickets.issued.lock().unwrap().len() <= CACHE_CAP);
    }

    #[test]
    fn signer_org_reads_an_apple_common_name() {
        assert_eq!(
            signer_org("Developer ID Application: Anthropic, PBC (Q6L2SF6YDW)").as_deref(),
            Some("Anthropic, PBC")
        );
        assert_eq!(
            signer_org("Apple Development: Someone (ABCDE12345)").as_deref(),
            Some("Someone")
        );
        // No recognizable shape: pass it through rather than mangle it.
        assert_eq!(
            signer_org("Anthropic, PBC").as_deref(),
            Some("Anthropic, PBC")
        );
        assert_eq!(signer_org("").as_deref(), None);
    }
}
