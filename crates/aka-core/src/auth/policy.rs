//! What a credential is allowed to do, and when holding it is not enough.
//!
//! The manage plane has one authorization question today — "is this the
//! management token?" — and one answer for every route. Passkey sign-in
//! brings credentials that are not all equal: a browser session, a desktop
//! device grant, and a background refresher that should push a cloud session
//! and nothing else. This module records that difference ahead of the
//! endpoints that will consult it, so no route invents its own rule.
//!
//! Two properties are deliberate.
//!
//! The route table **fails closed by omission**. A route with no entry does
//! not become public; it takes the default for its HTTP method, which is
//! [`Scope::ManageRead`] for a safe method and [`Scope::ManageWrite`] for
//! anything else. Adding a route and forgetting this file yields a route
//! that is too strict, never one that is open to the world.
//!
//! Step-up is **per surface**, not per credential. Revealing a secret in a
//! browser should cost a fresh passkey gesture; revealing one in the desktop
//! app, which is already a device the user authorized and which sits behind
//! that machine's own lock, should not. [`StepUp`] names which of those a
//! route wants rather than leaving each handler to guess.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How recently a browser must have completed a passkey ceremony for a
/// step-up route to accept its session.
///
/// Long enough that a reveal, a copy, and a second look do not each cost a
/// gesture; short enough that an unattended, unlocked laptop is not an open
/// vault an hour later.
pub const RECENT_AUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// One divisible piece of management authority.
///
/// Coarse on purpose. Finer scopes read as safer and are not: an operator
/// who cannot predict which scope a screen needs grants all of them, and the
/// distinctions that matter — reading versus writing, metadata versus secret
/// material, and the background pusher versus a human — get lost among the
/// ones that do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Read the catalog, settings, activity, requests, and sessions. Never
    /// secret material.
    #[serde(rename = "manage:read")]
    ManageRead,
    /// Create, change, and delete connections, credentials, and settings.
    #[serde(rename = "manage:write")]
    ManageWrite,
    /// Read secret material back out: a secret's value, a live 2FA code, the
    /// agent key. The one scope whose routes hand over something the holder
    /// can walk away with.
    #[serde(rename = "secrets:reveal")]
    SecretsReveal,
    /// Answer approvals and elicitations, and hold the approval surface that
    /// makes an agent's parked request answerable at all.
    #[serde(rename = "approvals:respond")]
    ApprovalsRespond,
    /// Push cloud sessions minted on the machine that owns the profile, and
    /// list only the connections that are owed one. The background
    /// refresher's entire authority.
    #[serde(rename = "cloud:push")]
    CloudPush,
    /// Manage who can sign in: passkeys, authorized devices, browser
    /// sessions, automation tokens, and the agent key's rotation.
    #[serde(rename = "identity:manage")]
    IdentityManage,
}

impl Scope {
    /// Every scope, for the owner bundle and for exhaustiveness tests.
    pub const ALL: [Scope; 6] = [
        Scope::ManageRead,
        Scope::ManageWrite,
        Scope::SecretsReveal,
        Scope::ApprovalsRespond,
        Scope::CloudPush,
        Scope::IdentityManage,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::ManageRead => "manage:read",
            Scope::ManageWrite => "manage:write",
            Scope::SecretsReveal => "secrets:reveal",
            Scope::ApprovalsRespond => "approvals:respond",
            Scope::CloudPush => "cloud:push",
            Scope::IdentityManage => "identity:manage",
        }
    }

    pub fn parse(text: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|scope| scope.as_str() == text)
    }

    fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

/// The bitset below is one word. A seventh scope is fine; a thirty-third
/// would shift off the end, and a silently-dropped bit is a silently-granted
/// or silently-denied permission.
const _: () = assert!(Scope::ALL.len() <= u32::BITS as usize);

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of scopes.
///
/// A bitset behind a value type: cheap to copy onto every request, and it
/// cannot be mutated by a handler that happens to hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeSet(u32);

impl ScopeSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Everything: the owner's own session, and the legacy management token
    /// until it is retired.
    pub fn all() -> Self {
        Self::from_iter(Scope::ALL)
    }

    /// What a desktop device is granted when the user authorizes it.
    ///
    /// The full human set, because the desktop app is the surface the
    /// product is: everything the owner can do at that keyboard, they can do
    /// there. What makes it safer than a shared management token is not a
    /// smaller grant but that it is per device, revocable by name, and
    /// carried by a short-lived token behind a rotating refresh grant.
    pub fn desktop() -> Self {
        Self::all()
    }

    /// The background cloud refresher's grant. Deliberately one scope: it
    /// pushes sessions for connections this machine owns and cannot read the
    /// catalog, the vault, or anything else.
    pub fn cloud_pusher() -> Self {
        Self::from_iter([Scope::CloudPush])
    }

    pub fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    pub fn with(self, scope: Scope) -> Self {
        Self(self.0 | scope.bit())
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether every scope in `self` is also in `other`. Used when a token
    /// is minted: a grant may narrow what its parent held, never widen it.
    pub fn is_subset_of(self, other: ScopeSet) -> bool {
        self.0 & !other.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL.into_iter().filter(move |scope| self.contains(*scope))
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = Scope>>(iter: I) -> Self {
        iter.into_iter().fold(Self::empty(), Self::with)
    }
}

/// Serialized as the array of scope strings a token or session carries.
impl Serialize for ScopeSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Unknown scope strings are dropped rather than refused: a grant
        // persisted by a newer broker must still load on an older one, and
        // dropping narrows authority, which is the safe direction.
        let names = Vec::<String>::deserialize(deserializer)?;
        Ok(names.iter().filter_map(|name| Scope::parse(name)).collect())
    }
}

/// Which kind of client is holding the credential.
///
/// Recorded on the principal and in the audit trail, and consulted by
/// [`StepUp::BrowserSession`]. It is derived from *how* the request
/// authenticated, never from a header the client chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientSurface {
    /// A browser on the broker's own origin, carrying a session cookie.
    Web,
    /// The desktop app, carrying an access token from the device grant it
    /// obtained through the browser.
    Desktop,
    /// An interactive terminal that signed in the same way the desktop does.
    Cli,
    /// A named, scoped, noninteractive token.
    Automation,
    /// The global management token, on its way out.
    LegacyManageToken,
}

impl ClientSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientSurface::Web => "web",
            ClientSurface::Desktop => "desktop",
            ClientSurface::Cli => "cli",
            ClientSurface::Automation => "automation",
            ClientSurface::LegacyManageToken => "legacy_manage_token",
        }
    }
}

impl fmt::Display for ClientSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the request proved who it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// A browser session established by a passkey ceremony.
    PasskeySession,
    /// A desktop or CLI access token issued against a device grant.
    DeviceToken,
    /// A named automation token.
    AutomationToken,
    /// The global management token.
    LegacyManageToken,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::PasskeySession => "passkey_session",
            AuthMethod::DeviceToken => "device_token",
            AuthMethod::AutomationToken => "automation_token",
            AuthMethod::LegacyManageToken => "legacy_manage_token",
        }
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether holding the scope is enough, or a fresh gesture is also required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUp {
    /// Any live credential carrying the scope.
    No,
    /// A browser must have completed a passkey ceremony within
    /// [`RECENT_AUTH_WINDOW`]. Device and automation grants are exempt: they
    /// are per-holder and revocable by name, and a browser tab left open on
    /// a shared machine is the threat this addresses.
    BrowserSession,
    /// Every surface re-authenticates, including the desktop. Reserved for
    /// changes to who can sign in at all, and for the irreversible ones —
    /// the operations where the wrong click cannot be taken back and where a
    /// stolen live token should not be sufficient on its own.
    Always,
}

/// What a route demands of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    pub scope: Scope,
    pub step_up: StepUp,
}

impl Requirement {
    const fn read() -> Self {
        Self {
            scope: Scope::ManageRead,
            step_up: StepUp::No,
        }
    }

    const fn write() -> Self {
        Self {
            scope: Scope::ManageWrite,
            step_up: StepUp::No,
        }
    }

    const fn new(scope: Scope, step_up: StepUp) -> Self {
        Self { scope, step_up }
    }
}

/// Routes whose authority is not the default for their method.
///
/// Keyed by the matched *route template* — the pattern axum matched, not the
/// request path — so `/v1/manage/secrets/{id}/reveal` is one entry rather
/// than one per secret, and a path crafted to look like another route cannot
/// pick up its policy.
///
/// `None` in the method position means every method on that route.
const OVERRIDES: &[(Option<&str>, &str, Requirement)] = &[
    // Secret material leaving the broker. The step-up boundary of the whole
    // design: a browser session alone must not be able to drain the vault.
    (
        None,
        "/v1/manage/secrets/{id}/reveal",
        Requirement::new(Scope::SecretsReveal, StepUp::BrowserSession),
    ),
    (
        None,
        "/v1/manage/secrets/{id}/copy-value",
        Requirement::new(Scope::SecretsReveal, StepUp::BrowserSession),
    ),
    (
        None,
        "/v1/manage/secrets/{id}/totp",
        Requirement::new(Scope::SecretsReveal, StepUp::BrowserSession),
    ),
    // The agent key is a bearer credential for the whole agent plane, so
    // reading it is a reveal, not a read.
    (
        None,
        "/v1/manage/identity/agent-key",
        Requirement::new(Scope::SecretsReveal, StepUp::BrowserSession),
    ),
    // Rotation invalidates every running agent's key. Not undoable.
    (
        None,
        "/v1/manage/identity/rotate",
        Requirement::new(Scope::IdentityManage, StepUp::Always),
    ),
    // Who can sign in, and with what.
    (
        None,
        "/v1/manage/management-token",
        Requirement::new(Scope::IdentityManage, StepUp::Always),
    ),
    // Answering for a human. Held by the desktop and the web UI, and by
    // nothing that runs unattended.
    (
        None,
        "/v1/manage/approvals/{id}",
        Requirement::new(Scope::ApprovalsRespond, StepUp::No),
    ),
    (
        None,
        "/v1/manage/elicitations/{id}",
        Requirement::new(Scope::ApprovalsRespond, StepUp::No),
    ),
    (
        None,
        "/v1/manage/approval-surfaces",
        Requirement::new(Scope::ApprovalsRespond, StepUp::No),
    ),
    (
        None,
        "/v1/manage/approval-surfaces/{id}",
        Requirement::new(Scope::ApprovalsRespond, StepUp::No),
    ),
    // Who can sign in, and on what.
    //
    // Reading the lists takes `identity:manage` but no step-up: a user
    // checking which devices are authorized should not have to prove
    // themselves to look.
    (
        Some("GET"),
        "/v1/manage/auth/passkeys",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    (
        Some("GET"),
        "/v1/manage/auth/sessions",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    (
        Some("GET"),
        "/v1/manage/auth/devices",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    (
        Some("GET"),
        "/v1/manage/auth/tokens",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    // `auth/whoami` is how any client renders "signed in as", including one
    // holding a narrow grant. Making it `identity:manage` would mean a
    // cloud-push token could not ask what it is.
    (
        Some("GET"),
        "/v1/manage/auth/whoami",
        Requirement::new(Scope::ManageRead, StepUp::No),
    ),
    // Revocation is the safe direction, and the direction a user reaches for
    // when they think something is wrong. Deliberately no step-up: a
    // confirmation gesture in front of "stop this device from working" buys
    // nothing and costs exactly the wrong seconds.
    (
        Some("DELETE"),
        "/v1/manage/auth/sessions/{id}",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    (
        Some("DELETE"),
        "/v1/manage/auth/devices/{id}",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    (
        Some("DELETE"),
        "/v1/manage/auth/tokens/{id}",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    // Granting, though, is the direction that widens access — and removing
    // the wrong passkey is how somebody locks themselves out.
    (
        Some("DELETE"),
        "/v1/manage/auth/passkeys/{id}",
        Requirement::new(Scope::IdentityManage, StepUp::Always),
    ),
    (
        Some("POST"),
        "/v1/manage/auth/tokens",
        Requirement::new(Scope::IdentityManage, StepUp::Always),
    ),
    (
        Some("PATCH"),
        "/v1/manage/auth/devices/{id}",
        Requirement::new(Scope::IdentityManage, StepUp::No),
    ),
    // The background refresher's two routes, and the reason `cloud:push`
    // exists: pushing a session must not require the authority to read the
    // catalog it belongs to.
    (
        None,
        "/v1/manage/cloud/session",
        Requirement::new(Scope::CloudPush, StepUp::No),
    ),
    (
        None,
        "/v1/manage/cloud/pushable",
        Requirement::new(Scope::CloudPush, StepUp::No),
    ),
];

/// The authority a manage route requires.
///
/// `matched` is the route template axum resolved, e.g.
/// `/v1/manage/secrets/{id}/reveal`.
pub fn requirement(method: &http::Method, matched: &str) -> Requirement {
    for (route_method, route, requirement) in OVERRIDES {
        if *route != matched {
            continue;
        }
        match route_method {
            Some(name) if !method.as_str().eq_ignore_ascii_case(name) => continue,
            _ => return *requirement,
        }
    }
    default_requirement(method)
}

/// What a route with no entry above gets. Safe methods read; everything else
/// writes. Never "nothing".
fn default_requirement(method: &http::Method) -> Requirement {
    match *method {
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS => Requirement::read(),
        _ => Requirement::write(),
    }
}

/// Whether a grant with `held` may take an action requiring `needed`.
///
/// `manage:write` does not imply `manage:read`, and neither implies
/// `secrets:reveal`. Implication is where scope systems quietly become
/// all-or-nothing; the bundles above are the place to be generous, not this
/// function. A grant that should read and write is given both.
pub fn satisfies(held: ScopeSet, needed: Scope) -> bool {
    held.contains(needed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn scope_strings_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for scope in Scope::ALL {
            assert!(seen.insert(scope.as_str()), "duplicate {scope}");
            assert_eq!(Scope::parse(scope.as_str()), Some(scope));
            // The wire form is the same string in both directions, so a
            // persisted grant cannot mean one thing to serde and another to
            // the route table.
            let json = serde_json::to_string(&scope).unwrap();
            assert_eq!(json, format!("\"{}\"", scope.as_str()));
        }
        assert_eq!(Scope::parse("manage:everything"), None);
    }

    #[test]
    fn a_scope_set_holds_only_what_was_put_in_it() {
        let set = ScopeSet::from_iter([Scope::ManageRead, Scope::CloudPush]);
        assert!(set.contains(Scope::ManageRead));
        assert!(set.contains(Scope::CloudPush));
        assert!(!set.contains(Scope::ManageWrite));
        assert!(!set.contains(Scope::SecretsReveal));
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![Scope::ManageRead, Scope::CloudPush]
        );
    }

    #[test]
    fn every_scope_has_its_own_bit() {
        // A collision would silently grant one scope with another.
        assert_eq!(ScopeSet::all().iter().count(), Scope::ALL.len());
        for scope in Scope::ALL {
            let only = ScopeSet::from_iter([scope]);
            for other in Scope::ALL {
                assert_eq!(only.contains(other), other == scope, "{scope} vs {other}");
            }
        }
    }

    #[test]
    fn the_pusher_grant_cannot_reach_anything_else() {
        let pusher = ScopeSet::cloud_pusher();
        assert!(pusher.contains(Scope::CloudPush));
        for scope in Scope::ALL {
            if scope != Scope::CloudPush {
                assert!(!pusher.contains(scope), "pusher must not hold {scope}");
            }
        }
        assert!(pusher.is_subset_of(ScopeSet::desktop()));
    }

    #[test]
    fn subset_is_directional() {
        let read = ScopeSet::from_iter([Scope::ManageRead]);
        let both = ScopeSet::from_iter([Scope::ManageRead, Scope::ManageWrite]);
        assert!(read.is_subset_of(both));
        assert!(!both.is_subset_of(read));
        assert!(ScopeSet::empty().is_subset_of(read));
    }

    #[test]
    fn scope_sets_serialize_as_their_strings() {
        let set = ScopeSet::from_iter([Scope::ManageRead, Scope::CloudPush]);
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, r#"["manage:read","cloud:push"]"#);
        assert_eq!(serde_json::from_str::<ScopeSet>(&json).unwrap(), set);
    }

    #[test]
    fn an_unknown_persisted_scope_narrows_rather_than_failing_to_load() {
        // A grant written by a newer broker must still load here, holding
        // only the scopes this build understands.
        let set: ScopeSet = serde_json::from_str(r#"["manage:read","manage:teleport"]"#).unwrap();
        assert_eq!(set, ScopeSet::from_iter([Scope::ManageRead]));
    }

    #[test]
    fn an_unlisted_route_still_demands_a_scope() {
        assert_eq!(
            requirement(&Method::GET, "/v1/manage/connections"),
            Requirement::read()
        );
        assert_eq!(
            requirement(&Method::POST, "/v1/manage/connections"),
            Requirement::write()
        );
        assert_eq!(
            requirement(&Method::DELETE, "/v1/manage/secrets/{id}"),
            Requirement::write()
        );
        // Including one nobody has written yet.
        assert_eq!(
            requirement(&Method::PATCH, "/v1/manage/something-new"),
            Requirement::write()
        );
    }

    #[test]
    fn revealing_secret_material_needs_the_reveal_scope_and_a_fresh_browser() {
        for route in [
            "/v1/manage/secrets/{id}/reveal",
            "/v1/manage/secrets/{id}/copy-value",
            "/v1/manage/secrets/{id}/totp",
            "/v1/manage/identity/agent-key",
        ] {
            let requirement = requirement(&Method::POST, route);
            assert_eq!(requirement.scope, Scope::SecretsReveal, "{route}");
            assert_eq!(requirement.step_up, StepUp::BrowserSession, "{route}");
        }
    }

    #[test]
    fn changing_who_can_sign_in_always_steps_up() {
        for route in [
            "/v1/manage/identity/rotate",
            "/v1/manage/management-token",
        ] {
            let requirement = requirement(&Method::POST, route);
            assert_eq!(requirement.scope, Scope::IdentityManage, "{route}");
            assert_eq!(requirement.step_up, StepUp::Always, "{route}");
        }
    }

    #[test]
    fn the_refresher_routes_do_not_require_write_authority() {
        // The whole point of `cloud:push`: were these to fall through to the
        // default, the refresher would need `manage:write` and the narrow
        // grant would buy nothing.
        for route in ["/v1/manage/cloud/session", "/v1/manage/cloud/pushable"] {
            let requirement = requirement(&Method::POST, route);
            assert_eq!(requirement.scope, Scope::CloudPush, "{route}");
            assert!(satisfies(ScopeSet::cloud_pusher(), requirement.scope));
        }
        // And a pusher grant reaches nothing else on the plane.
        for route in [
            "/v1/manage/connections",
            "/v1/manage/secrets",
            "/v1/manage/settings",
        ] {
            for method in [Method::GET, Method::POST] {
                let requirement = requirement(&method, route);
                assert!(
                    !satisfies(ScopeSet::cloud_pusher(), requirement.scope),
                    "{method} {route}"
                );
            }
        }
    }

    #[test]
    fn answering_for_a_human_is_its_own_scope() {
        for route in [
            "/v1/manage/approvals/{id}",
            "/v1/manage/elicitations/{id}",
            "/v1/manage/approval-surfaces",
            "/v1/manage/approval-surfaces/{id}",
        ] {
            assert_eq!(
                requirement(&Method::POST, route).scope,
                Scope::ApprovalsRespond,
                "{route}"
            );
        }
    }

    #[test]
    fn scopes_do_not_imply_one_another() {
        let writer = ScopeSet::from_iter([Scope::ManageWrite]);
        assert!(!satisfies(writer, Scope::ManageRead));
        assert!(!satisfies(writer, Scope::SecretsReveal));
        assert!(!satisfies(writer, Scope::IdentityManage));
    }

    #[test]
    fn override_routes_are_written_as_templates() {
        // A literal path here would never match what axum reports, so the
        // entry would silently do nothing and the route would fall through
        // to the method default.
        for (_, route, _) in OVERRIDES {
            assert!(route.starts_with("/v1/manage/"), "{route}");
            for segment in route.split('/') {
                assert!(
                    !segment.contains('{') || segment.starts_with('{') && segment.ends_with('}'),
                    "{route}: {segment} is not a whole path parameter"
                );
            }
        }
    }

    #[test]
    fn no_route_is_listed_twice() {
        let mut seen = std::collections::HashSet::new();
        for (method, route, _) in OVERRIDES {
            assert!(seen.insert((*method, *route)), "duplicate entry for {route}");
        }
    }
}
