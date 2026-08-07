//! Human authentication to the broker.
//!
//! Distinct from two planes that already exist and must stay separate:
//!
//! - the **agent plane**, where an agent key or a capability proves that a
//!   program may make a brokered request. Nothing here changes it. A human
//!   signing in must never become a way to authenticate an agent.
//! - the **manage plane**, which today asks one question — is this the
//!   management token? — of every route. This module lets it ask a better one.
//!
//! What a passkey buys is a person: it authenticates a human to
//! [`PublicOrigin`], and stops there. It is not a bearer token for the
//! manage plane, it does not unlock the vault, and it is not the local app
//! lock (Touch ID on a Mac gates that shell's own windows and has nothing to
//! say about a broker somewhere else). What it produces is a *session*, and
//! sessions are what carry [`Scope`]s.
//!
//! [`policy`] is deliberately written before the endpoints that consult it,
//! so the answer to "what may this credential do?" lives in one table rather
//! than accreting across ninety handlers.

pub mod origin;
pub mod passkey;
pub mod policy;
pub mod routes;
pub mod store;
pub mod webapp;

pub use origin::{OriginError, PublicOrigin};
pub use passkey::{Assertion, RelyingParty};
pub use policy::{
    requirement, satisfies, AuthMethod, ClientSurface, Requirement, Scope, ScopeSet, StepUp,
    RECENT_AUTH_WINDOW,
};
pub use store::{
    Account, AuthError, AuthResult, AuthStore, AutomationToken, BrowserSession, DeviceGrant,
    IssuedDevice, IssuedSession, IssuedTokens, StoredCredential, Verified,
};
