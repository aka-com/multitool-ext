//! The WebAuthn relying party, and the two ceremonies it runs.
//!
//! Thin by design. Everything security-relevant here *refuses flexibility*:
//! one origin, one RP id, user verification required, and no configuration
//! surface through which an operator could relax either. webauthn-rs handles
//! the cryptography and the structural checks — that the client data hashes
//! the challenge we issued, that the authenticator data's RP-id hash matches,
//! that the signature verifies, that the counter did not regress — and we call
//! its safe API rather than its `_unsafe_experts_only` one.
//!
//! Ceremony state never leaves memory; see [`crate::auth::store`].

use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder,
};

use crate::auth::origin::{OriginError, PublicOrigin};
use crate::auth::store::{AuthError, AuthResult};

/// What the browser's account picker shows next to a passkey.
const RP_NAME: &str = "Multitool";

/// A relying party bound to one origin.
pub struct RelyingParty {
    webauthn: Webauthn,
    origin: PublicOrigin,
}

impl RelyingParty {
    /// Build the relying party for a configured origin.
    ///
    /// Subdomains are not allowed (the default, restated here because the
    /// alternative would silently widen every credential to every sibling
    /// host), and neither is any port but the configured one.
    pub fn new(origin: PublicOrigin) -> Result<Self, OriginError> {
        let url: url::Url = origin
            .as_str()
            .parse()
            .map_err(|_| OriginError::Malformed(origin.as_str().to_string()))?;
        let webauthn = WebauthnBuilder::new(origin.rp_id(), &url)
            .and_then(|builder| {
                builder
                    .rp_name(RP_NAME)
                    .allow_subdomains(false)
                    .allow_any_port(false)
                    .build()
            })
            .map_err(|_| OriginError::Malformed(origin.as_str().to_string()))?;
        Ok(Self { webauthn, origin })
    }

    pub fn origin(&self) -> &PublicOrigin {
        &self.origin
    }

    /// Offer to create a passkey for `account`.
    ///
    /// `exclude` is every credential already enrolled, so an authenticator
    /// the user has already used declines rather than silently creating a
    /// second credential they will never be asked for.
    pub fn start_registration(
        &self,
        handle: uuid::Uuid,
        name: &str,
        display_name: &str,
        exclude: Vec<Passkey>,
    ) -> AuthResult<(CreationChallengeResponse, PasskeyRegistration)> {
        let exclude = (!exclude.is_empty())
            .then(|| exclude.iter().map(|key| key.cred_id().clone()).collect());
        self.webauthn
            .start_passkey_registration(handle, name, display_name, exclude)
            .map_err(|error| {
                tracing::warn!("could not start a passkey registration: {error}");
                AuthError::Ceremony("this broker could not offer a passkey")
            })
    }

    pub fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> AuthResult<Passkey> {
        self.webauthn
            .finish_passkey_registration(response, state)
            .map_err(|error| {
                // The detail names the origin, the RP id, or the attestation
                // — none of which a caller who failed the check should be
                // told, and all of which an operator needs.
                tracing::warn!("a passkey registration did not verify: {error}");
                AuthError::Ceremony("the new passkey did not verify")
            })
    }

    /// Offer a sign-in against the account's enrolled passkeys.
    ///
    /// The credential list is sent because this broker has one account: there
    /// is no username to ask for, and listing them lets a security key that
    /// holds no discoverable credential still work.
    pub fn start_authentication(
        &self,
        credentials: &[Passkey],
    ) -> AuthResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        if credentials.is_empty() {
            return Err(AuthError::NotEnrolled);
        }
        self.webauthn
            .start_passkey_authentication(credentials)
            .map_err(|error| {
                tracing::warn!("could not start a passkey sign-in: {error}");
                AuthError::Ceremony("this broker could not offer a sign-in")
            })
    }

    /// Verify an assertion.
    ///
    /// User verification is required by [`Webauthn::start_passkey_authentication`],
    /// and re-asserted here rather than assumed: a passkey that proves only
    /// presence is a device somebody is holding, not a person who unlocked
    /// it, and step-up would mean nothing if that were enough.
    pub fn finish_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> AuthResult<Assertion> {
        let result = self
            .webauthn
            .finish_passkey_authentication(response, state)
            .map_err(|error| {
                tracing::warn!("a passkey assertion did not verify: {error}");
                AuthError::Ceremony("that passkey did not verify")
            })?;
        if !result.user_verified() {
            return Err(AuthError::Ceremony(
                "that passkey proved presence but not the person holding it",
            ));
        }
        Ok(Assertion(result))
    }
}

/// A verified assertion.
///
/// Opaque on purpose: the counter, backup state, and backup eligibility have
/// to be written back to the stored credential *together*, and webauthn-rs
/// exposes exactly one method that does so consistently. Handing out the
/// individual fields would invite a caller to persist some and drop others,
/// and the counter is the spec's clone signal.
pub struct Assertion(webauthn_rs::prelude::AuthenticationResult);

impl Assertion {
    /// Which enrolled passkey answered.
    pub fn credential_id(&self) -> &[u8] {
        self.0.cred_id().as_slice()
    }

    pub(crate) fn result(&self) -> &webauthn_rs::prelude::AuthenticationResult {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(url: &str) -> Result<RelyingParty, OriginError> {
        RelyingParty::new(PublicOrigin::from_configured_public_url(Some(url)).unwrap())
    }

    #[test]
    fn a_relying_party_binds_to_the_configured_origin() {
        let rp = party("https://broker.example").unwrap();
        assert_eq!(rp.origin().rp_id(), "broker.example");
        assert_eq!(rp.origin().as_str(), "https://broker.example");
    }

    #[test]
    fn loopback_development_still_builds() {
        let rp = party("http://localhost:4780").unwrap();
        assert_eq!(rp.origin().rp_id(), "localhost");
    }

    #[test]
    fn a_registration_challenge_names_this_relying_party_and_demands_verification() {
        let rp = party("https://broker.example").unwrap();
        let (challenge, _state) = rp
            .start_registration(uuid::Uuid::new_v4(), "owner", "Owner", Vec::new())
            .unwrap();
        let options = &challenge.public_key;
        assert_eq!(options.rp.id, "broker.example");
        assert_eq!(options.rp.name, RP_NAME);
        let selection = options
            .authenticator_selection
            .as_ref()
            .expect("passkeys pin the authenticator selection");
        // Asserted on the serialized value, which is what the browser acts
        // on — and which is nameable here without depending on
        // webauthn-rs-core directly for one enum.
        assert_eq!(
            serde_json::to_value(selection.user_verification).unwrap(),
            serde_json::json!("required"),
            "a passkey that only proves presence would make step-up meaningless"
        );
    }

    #[test]
    fn an_authentication_challenge_with_no_enrolled_passkey_says_so() {
        let rp = party("https://broker.example").unwrap();
        assert!(matches!(
            rp.start_authentication(&[]),
            Err(AuthError::NotEnrolled)
        ));
    }

    #[test]
    fn each_challenge_is_fresh() {
        // A reused challenge is a replayable assertion.
        let rp = party("https://broker.example").unwrap();
        let handle = uuid::Uuid::new_v4();
        let (first, _) = rp
            .start_registration(handle, "owner", "Owner", Vec::new())
            .unwrap();
        let (second, _) = rp
            .start_registration(handle, "owner", "Owner", Vec::new())
            .unwrap();
        assert_ne!(
            first.public_key.challenge.as_slice(),
            second.public_key.challenge.as_slice()
        );
    }

    #[test]
    fn the_user_handle_is_the_opaque_id_not_a_name() {
        // What lands on the authenticator and syncs to the user's other
        // devices must not identify them off this broker.
        let rp = party("https://broker.example").unwrap();
        let handle = uuid::Uuid::new_v4();
        let (challenge, _) = rp
            .start_registration(handle, "owner", "Owner", Vec::new())
            .unwrap();
        assert_eq!(challenge.public_key.user.id.as_slice(), handle.as_bytes());
    }
}
