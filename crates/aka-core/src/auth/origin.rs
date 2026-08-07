//! The one origin this broker is a WebAuthn relying party for.
//!
//! A passkey is bound to a relying-party id, and the browser will only offer
//! it to a page whose origin matches. That makes the RP id a security
//! parameter, not a display string: whoever chooses it chooses which site's
//! passkeys unlock this broker.
//!
//! So it is chosen once, by the operator, through `serve --public-url` — the
//! same URL discovery already advertises — and never inferred from a request.
//! There is deliberately no constructor taking a `Host` header: a proxy that
//! forwards an attacker-chosen `Host` would otherwise let that attacker run a
//! ceremony against an RP id of their choosing and register a passkey the
//! real origin would never have offered.

use std::fmt;

/// Why a configured public URL cannot host passkey authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginError {
    /// `serve --public-url` was not given, so there is no canonical origin.
    NotConfigured,
    /// Not a URL, or one without a host.
    Malformed(String),
    /// Plain HTTP somewhere a browser will not treat as a secure context.
    /// WebAuthn is unavailable there, so failing here beats failing in the
    /// browser with a bare `NotAllowedError`.
    Insecure,
    /// The host is an IP literal. WebAuthn RP ids are domains: the spec has
    /// no way to express one for an address, and browsers refuse the
    /// ceremony outright.
    IpLiteral,
}

impl OriginError {
    /// What the operator should do about it.
    pub fn detail(&self) -> String {
        match self {
            Self::NotConfigured => "passkey sign-in needs the URL people reach this broker at; \
                 start it with `multitool serve --listen … --public-url https://broker.example`"
                .into(),
            Self::Malformed(url) => format!(
                "{url:?} is not an origin; --public-url takes a scheme, host, \
                 and optional port, e.g. https://broker.example"
            ),
            Self::Insecure => "passkeys require https (browsers make an exception only for \
                 localhost); put your TLS proxy or tunnel in front of the listener \
                 and point --public-url at it"
                .into(),
            Self::IpLiteral => "passkeys are bound to a domain name, so an IP address cannot be \
                 a relying party; give --public-url a hostname"
                .into(),
        }
    }
}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail())
    }
}

impl std::error::Error for OriginError {}

/// A canonical, operator-chosen origin and the relying-party id derived from
/// it.
///
/// The RP id is the origin's host and nothing else. WebAuthn permits a
/// registrable suffix (`app.broker.example` claiming `broker.example`), which
/// widens a credential to every sibling host — worth having only for a
/// multi-host deployment, and a footgun until then. This broker serves one
/// host, so it claims one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicOrigin {
    /// Serialized origin: scheme, host, and non-default port. No trailing
    /// slash — this is compared against the `origin` a browser reports,
    /// which never carries one.
    origin: String,
    rp_id: String,
}

impl PublicOrigin {
    /// Derive the relying party from the operator's `--public-url`.
    ///
    /// The one entry point, and it takes configuration. See the module note
    /// on why nothing here reads a request header.
    pub fn from_configured_public_url(url: Option<&str>) -> Result<Self, OriginError> {
        let raw = url.map(str::trim).filter(|url| !url.is_empty());
        let raw = raw.ok_or(OriginError::NotConfigured)?;
        let parsed: url::Url = raw
            .parse()
            .map_err(|_| OriginError::Malformed(raw.to_string()))?;

        let host = parsed.host().ok_or_else(|| {
            // A URL can parse with no host (`mailto:`, `file:`); an origin
            // cannot exist without one.
            OriginError::Malformed(raw.to_string())
        })?;
        let (host_text, is_ip, is_loopback) = match host {
            url::Host::Domain(domain) => (
                domain.to_ascii_lowercase(),
                false,
                domain.eq_ignore_ascii_case("localhost"),
            ),
            url::Host::Ipv4(address) => (address.to_string(), true, address.is_loopback()),
            url::Host::Ipv6(address) => (format!("[{address}]"), true, address.is_loopback()),
        };

        match parsed.scheme() {
            "https" => {}
            // Browsers treat loopback as a secure context, which is what
            // makes a local tunnel and the dev loop workable.
            "http" if is_loopback => {}
            "http" => return Err(OriginError::Insecure),
            _ => return Err(OriginError::Malformed(raw.to_string())),
        }
        // Checked after the scheme so `http://192.0.2.1` reports the problem
        // an operator can act on first.
        if is_ip {
            return Err(OriginError::IpLiteral);
        }

        // `url` already drops the default port for the scheme, which is what
        // a browser's `origin` does too.
        let origin = match parsed.port() {
            Some(port) => format!("{}://{host_text}:{port}", parsed.scheme()),
            None => format!("{}://{host_text}", parsed.scheme()),
        };
        Ok(Self {
            origin,
            rp_id: host_text,
        })
    }

    /// The serialized origin, exactly as a browser reports it.
    pub fn as_str(&self) -> &str {
        &self.origin
    }

    /// The relying-party id passkeys are bound to.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Absolute URL for an absolute path on this origin (redirect targets,
    /// links in setup text).
    ///
    /// A path missing its leading slash would otherwise concatenate onto the
    /// host — `https://broker.exampleauthorize` — which resolves to a
    /// different origin rather than failing.
    pub fn url(&self, path: &str) -> String {
        debug_assert!(path.starts_with('/'), "{path:?} is not an absolute path");
        match path.strip_prefix('/') {
            Some(rest) => format!("{}/{rest}", self.origin),
            None => format!("{}/{path}", self.origin),
        }
    }

    /// Whether a request's `Origin` header is this exact origin.
    ///
    /// Byte equality on the serialized form. Origin comparison is defined as
    /// a tuple match, and every browser serializes it the same canonical way
    /// this type does, so anything that is not equal is not us. In
    /// particular there is no suffix or subdomain leniency: `evil.broker.example`
    /// is a different origin and reads as one.
    pub fn matches(&self, origin: &str) -> bool {
        self.origin == origin
    }
}

impl fmt::Display for PublicOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(url: &str) -> Result<PublicOrigin, OriginError> {
        PublicOrigin::from_configured_public_url(Some(url))
    }

    #[test]
    fn an_https_host_becomes_the_relying_party() {
        let public = origin("https://broker.example").unwrap();
        assert_eq!(public.as_str(), "https://broker.example");
        assert_eq!(public.rp_id(), "broker.example");
        assert_eq!(
            public.url("/authorize"),
            "https://broker.example/authorize"
        );
    }

    #[test]
    fn the_host_is_lowercased_and_the_default_port_dropped() {
        // Both are how a browser serializes an origin, so both have to match
        // ours or every ceremony fails an origin check for no reason.
        let public = origin("https://Broker.Example:443").unwrap();
        assert_eq!(public.as_str(), "https://broker.example");
        assert_eq!(public.rp_id(), "broker.example");
    }

    #[test]
    fn a_non_default_port_stays_part_of_the_origin() {
        let public = origin("https://broker.example:8443").unwrap();
        assert_eq!(public.as_str(), "https://broker.example:8443");
        // The port is not part of an RP id — a passkey is bound to the host.
        assert_eq!(public.rp_id(), "broker.example");
    }

    #[test]
    fn loopback_http_is_allowed_because_browsers_allow_it() {
        let public = origin("http://localhost:4780").unwrap();
        assert_eq!(public.as_str(), "http://localhost:4780");
        assert_eq!(public.rp_id(), "localhost");
    }

    #[test]
    fn plain_http_off_loopback_is_refused() {
        assert_eq!(origin("http://broker.example"), Err(OriginError::Insecure));
    }

    #[test]
    fn ip_literals_cannot_be_a_relying_party() {
        assert_eq!(origin("https://192.0.2.10"), Err(OriginError::IpLiteral));
        assert_eq!(origin("https://[2001:db8::1]"), Err(OriginError::IpLiteral));
        // Loopback by address is still an address: browsers refuse an RP id
        // for it even though the context is secure.
        assert_eq!(origin("http://127.0.0.1:4780"), Err(OriginError::IpLiteral));
    }

    #[test]
    fn an_absent_or_empty_url_is_not_configured() {
        assert_eq!(
            PublicOrigin::from_configured_public_url(None),
            Err(OriginError::NotConfigured)
        );
        assert_eq!(
            PublicOrigin::from_configured_public_url(Some("   ")),
            Err(OriginError::NotConfigured)
        );
    }

    #[test]
    fn other_schemes_are_malformed_not_insecure() {
        assert!(matches!(
            origin("ftp://broker.example"),
            Err(OriginError::Malformed(_))
        ));
        assert!(matches!(
            origin("broker.example"),
            Err(OriginError::Malformed(_))
        ));
    }

    #[test]
    fn matching_is_exact_and_not_suffix_based() {
        let public = origin("https://broker.example").unwrap();
        assert!(public.matches("https://broker.example"));
        assert!(!public.matches("https://evil.broker.example"));
        assert!(!public.matches("https://broker.example.evil.test"));
        assert!(!public.matches("http://broker.example"));
        // A trailing slash is a URL, not an origin; browsers never send one.
        assert!(!public.matches("https://broker.example/"));
    }
}
