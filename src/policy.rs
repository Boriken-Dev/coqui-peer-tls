use alloc::sync::Arc;
use core::fmt;
use core::str::FromStr;

use rustls::SupportedProtocolVersion;
use rustls::crypto::CryptoProvider;

use crate::error::PeerError;
use coqui_peer::{Digest, PeerId, WaitingLimits};

/// The version of the serialized form of [`Policy`] (`policy_version`).
pub const POLICY_VERSION: u32 = 1;

/// A TLS protocol version. rustls offers 1.2 and 1.3 only: SSL 3, TLS 1.0 and 1.1 cannot be
/// offered by this crate, and asking for them is an error, never ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TlsVersion {
    /// TLS 1.2, text `"1.2"`.
    V1_2,
    /// TLS 1.3, text `"1.3"`.
    V1_3,
}

impl TlsVersion {
    /// The text form: `1.2` or `1.3`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1_2 => "1.2",
            Self::V1_3 => "1.3",
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TlsVersion {
    type Err = PeerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "1.2" => Ok(Self::V1_2),
            "1.3" => Ok(Self::V1_3),
            "1.0" | "1.1" | "ssl3" | "SSL3" => Err(PeerError::Policy(
                "TLS before 1.2 is not supported: rustls offers only TLS 1.2 and 1.3".to_owned(),
            )),
            _ => Err(PeerError::Policy(
                "unknown TLS version; supported: \"1.2\", \"1.3\"".to_owned(),
            )),
        }
    }
}

/// A setting looser than the strict preset, as plain data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Weakening {
    /// The setting's name: a [`Policy`] field, or
    /// [`CLIENT_AUTH_SETTING`](crate::CLIENT_AUTH_SETTING) for a server that does not
    /// authenticate its clients at the TLS layer.
    pub setting: String,
    /// Its current value as text.
    pub value: String,
    /// The strict value as text.
    pub strict: String,
}

/// What a TLS configuration and a trust decision are allowed to do.
///
/// Start from [`Policy::strict`], [`Policy::compatible`], [`Policy::legacy`] or a policy of
/// your own, then change any field. [`Default`] is strict. Nothing is silently weakened: [`weakened`](Policy::weakened) lists every setting
/// looser than strict, and the configuration builders return that list.
///
/// With the `serde` feature a policy reads and writes the versioned form documented in the
/// crate README (`policy_version = 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// A name for this policy, such as the preset it started from. Informational: it
    /// changes nothing, and a consumer may name its own.
    pub name: String,
    /// TLS versions offered and accepted. Non-empty.
    pub tls_versions: Vec<TlsVersion>,
    /// An allow-list of cipher suites by IANA name, for example `TLS13_AES_256_GCM_SHA384`.
    /// `None` allows every suite the ring provider has for [`tls_versions`](Self::tls_versions).
    /// An unknown name is an error that lists the supported ones.
    pub cipher_suites: Option<Vec<String>>,
    /// An allow-list of key-exchange groups by name, for example `X25519`; `None` allows all
    /// the provider has.
    pub kx_groups: Option<Vec<String>>,
    /// Digests a pin may use. Pins are compared in constant time whatever their digest.
    pub pin_digests: Vec<Digest>,
    /// Whether a pinned certificate must be inside its validity dates.
    pub check_validity: bool,
    /// Whether a pinned peer may present a chain; strict refuses one.
    pub allow_chain_when_pinned: bool,
    /// Whether TLS sessions may be resumed. A resumed handshake skips the certificate
    /// verifiers, so a peer removed from the trust store or no longer pinned can reconnect
    /// on a session it already holds. Every preset leaves it off.
    pub allow_resumption: bool,
    /// Whether a TLS 1.2 connection must use the extended master secret (RFC 7627). Without it
    /// a TLS 1.2 session's keys and exporter are not bound to its handshake, which an attacker
    /// can use to synchronise two sessions (the triple handshake). Every preset sets it; TLS 1.3
    /// needs nothing like it.
    pub require_ems: bool,
    /// Waiting entries one source address may hold.
    pub waiting_per_source: usize,
    /// Waiting entries the store may hold.
    pub waiting_total: usize,
    /// Seconds before the same certificate from the same source is recorded again.
    pub waiting_rerecord_secs: u64,
    /// An ordered access control list for connecting clients, applied by every server
    /// configuration built under this policy: by address when the `ClientHello` arrives
    /// ([`Refusal::AddressDenied`](crate::Refusal::AddressDenied)) and by the client
    /// certificate's fingerprint before the trust store is consulted
    /// ([`Refusal::PeerDenied`](crate::Refusal::PeerDenied)). Its fingerprints may be written
    /// in any spelling a [`PeerId`] parses, and are made canonical where a policy is read or
    /// a configuration built; a rule naming something else, or a digest other than SHA-256,
    /// is an error there. `None` for none.
    #[cfg(feature = "acl")]
    pub acl: Option<coqui_net_acl::Acl>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::strict()
    }
}

impl Policy {
    /// The strict preset: TLS 1.3 only; pins SHA-256, SHA-384 or SHA-512; validity dates
    /// checked; no chain on a pinned path; no session resumption; waiting queues capped. The
    /// default.
    pub fn strict() -> Self {
        Self {
            name: "strict".to_owned(),
            tls_versions: vec![TlsVersion::V1_3],
            cipher_suites: None,
            kx_groups: None,
            pin_digests: vec![Digest::Sha256, Digest::Sha384, Digest::Sha512],
            check_validity: true,
            allow_chain_when_pinned: false,
            allow_resumption: false,
            require_ems: true,
            waiting_per_source: 16,
            waiting_total: 1_000,
            waiting_rerecord_secs: 60,
            #[cfg(feature = "acl")]
            acl: None,
        }
    }

    /// Strict, and TLS 1.2 with ECDHE and AEAD suites as well.
    pub fn compatible() -> Self {
        Self {
            name: "compatible".to_owned(),
            tls_versions: vec![TlsVersion::V1_2, TlsVersion::V1_3],
            ..Self::strict()
        }
    }

    /// Compatible, and SHA-1 pins accepted, for interoperability with old peers only.
    pub fn legacy() -> Self {
        let mut policy = Self::compatible();
        policy.name = "legacy".to_owned();
        policy.pin_digests.push(Digest::Sha1);
        policy
    }

    /// The built-in preset called `name`: `strict`, `compatible` or `legacy`.
    ///
    /// # Errors
    ///
    /// [`PeerError::Policy`] for any other name.
    pub fn preset(name: &str) -> Result<Self, PeerError> {
        match name.trim() {
            "strict" => Ok(Self::strict()),
            "compatible" => Ok(Self::compatible()),
            "legacy" => Ok(Self::legacy()),
            _ => Err(PeerError::Policy(
                "unknown profile; built in: strict, compatible, legacy".to_owned(),
            )),
        }
    }
}

fn list<T: fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

impl Policy {
    /// Every setting looser than the strict preset, as plain data. Empty for strict.
    pub fn weakened(&self) -> Vec<Weakening> {
        self.weakened_against(&Self::strict())
    }

    /// Every setting looser than `baseline`, as plain data, for a consumer whose own default
    /// is not strict.
    pub fn weakened_against(&self, baseline: &Self) -> Vec<Weakening> {
        let strict = baseline;
        let mut found = Vec::new();
        let mut note = |setting: &str, value: String, strict: String| {
            found.push(Weakening {
                setting: setting.to_owned(),
                value,
                strict,
            });
        };
        if self
            .tls_versions
            .iter()
            .any(|v| !strict.tls_versions.contains(v))
        {
            note(
                "tls_versions",
                list(&self.tls_versions),
                list(&strict.tls_versions),
            );
        }
        if self
            .pin_digests
            .iter()
            .any(|d| !strict.pin_digests.contains(d))
        {
            note(
                "pin_digests",
                list(&self.pin_digests),
                list(&strict.pin_digests),
            );
        }
        if !self.check_validity {
            note("check_validity", "false".to_owned(), "true".to_owned());
        }
        if self.allow_chain_when_pinned {
            note(
                "allow_chain_when_pinned",
                "true".to_owned(),
                "false".to_owned(),
            );
        }
        if self.allow_resumption && !strict.allow_resumption {
            note("allow_resumption", "true".to_owned(), "false".to_owned());
        }
        if !self.require_ems && strict.require_ems {
            note("require_ems", "false".to_owned(), "true".to_owned());
        }
        if self.waiting_per_source > strict.waiting_per_source {
            note(
                "waiting_per_source",
                self.waiting_per_source.to_string(),
                strict.waiting_per_source.to_string(),
            );
        }
        if self.waiting_total > strict.waiting_total {
            note(
                "waiting_total",
                self.waiting_total.to_string(),
                strict.waiting_total.to_string(),
            );
        }
        if self.waiting_rerecord_secs < strict.waiting_rerecord_secs {
            note(
                "waiting_rerecord_secs",
                self.waiting_rerecord_secs.to_string(),
                strict.waiting_rerecord_secs.to_string(),
            );
        }
        #[cfg(feature = "acl")]
        if let Some(acl) = &self.acl {
            found.extend(acl.weakened().into_iter().map(|w| Weakening {
                setting: w.setting,
                value: w.value,
                strict: w.strict,
            }));
        }
        found
    }

    /// Whether the access control list admits, by address, a client from `source` to `local`
    /// that will present a certificate: a rule naming a fingerprint defers to the handshake.
    /// Without a list, every address is admitted. For a host that refuses a connection before
    /// its handshake, such as a quinn `Incoming`.
    ///
    /// # Errors
    ///
    /// [`Refusal::AddressDenied`](crate::Refusal::AddressDenied) with the deciding rule.
    #[cfg(feature = "acl")]
    pub fn admits_address(
        &self,
        source: core::net::SocketAddr,
        local: core::net::SocketAddr,
    ) -> Result<(), crate::Refusal> {
        match &self.acl {
            Some(acl) => crate::gate::decide_address(acl, source, local, true),
            None => Ok(()),
        }
    }

    /// [`admits_address`](Policy::admits_address) for a client that proves no identity at the
    /// TLS layer: rules naming a fingerprint cannot match it.
    ///
    /// # Errors
    ///
    /// [`Refusal::AddressDenied`](crate::Refusal::AddressDenied) with the deciding rule.
    #[cfg(feature = "acl")]
    pub fn admits_anonymous(
        &self,
        source: core::net::SocketAddr,
        local: core::net::SocketAddr,
    ) -> Result<(), crate::Refusal> {
        match &self.acl {
            Some(acl) => crate::gate::decide_address(acl, source, local, false),
            None => Ok(()),
        }
    }

    /// The limits for a trust store's waiting queue.
    pub fn waiting_limits(&self) -> WaitingLimits {
        WaitingLimits {
            per_source: self.waiting_per_source,
            total: self.waiting_total,
            rerecord: core::time::Duration::from_secs(self.waiting_rerecord_secs),
        }
    }

    /// Whether this policy lets a pin use the digest of `fingerprint`.
    ///
    /// # Errors
    ///
    /// [`PeerError::Policy`] naming the digest and the allowed ones.
    pub fn check_pin(&self, fingerprint: &PeerId) -> Result<(), PeerError> {
        if self.pin_digests.contains(&fingerprint.digest()) {
            return Ok(());
        }
        Err(PeerError::Policy(format!(
            "a {} pin is not allowed by this policy; allowed digests: {}",
            fingerprint.digest(),
            list(&self.pin_digests)
        )))
    }

    /// The protocol versions to build a configuration with.
    pub(crate) fn protocol_versions(
        &self,
    ) -> Result<Vec<&'static SupportedProtocolVersion>, PeerError> {
        if self.tls_versions.is_empty() {
            return Err(PeerError::Policy("tls_versions is empty".to_owned()));
        }
        self.tls_versions
            .iter()
            .map(|version| match version {
                TlsVersion::V1_3 => Ok(&rustls::version::TLS13),
                #[cfg(feature = "tls12")]
                TlsVersion::V1_2 => Ok(&rustls::version::TLS12),
                #[cfg(not(feature = "tls12"))]
                TlsVersion::V1_2 => Err(PeerError::Policy(
                    "TLS 1.2 was requested but this build lacks the `tls12` feature".to_owned(),
                )),
            })
            .collect()
    }

    /// The ring provider narrowed to this policy's versions, suites and groups.
    ///
    /// # Errors
    ///
    /// [`PeerError::Policy`] for an unknown suite or group name (listing the supported ones),
    /// or when a selected version is left with no suite.
    pub fn crypto_provider(&self) -> Result<Arc<CryptoProvider>, PeerError> {
        let ring = rustls::crypto::ring::default_provider();
        let suite_name = |suite: &rustls::SupportedCipherSuite| {
            suite
                .suite()
                .as_str()
                .map_or_else(|| format!("{:?}", suite.suite()), str::to_owned)
        };
        let group_name =
            |group: &&'static dyn rustls::crypto::SupportedKxGroup| format!("{:?}", group.name());
        if let Some(wanted) = &self.cipher_suites {
            let known: Vec<String> = ring.cipher_suites.iter().map(suite_name).collect();
            if let Some(position) = wanted.iter().position(|name| !known.contains(name)) {
                return Err(PeerError::Policy(format!(
                    "cipher_suites[{position}] is not a supported cipher suite; supported: {}",
                    known.join(", ")
                )));
            }
        }
        if let Some(wanted) = &self.kx_groups {
            let known: Vec<String> = ring.kx_groups.iter().map(group_name).collect();
            if let Some(position) = wanted.iter().position(|name| !known.contains(name)) {
                return Err(PeerError::Policy(format!(
                    "kx_groups[{position}] is not a supported key-exchange group; supported: {}",
                    known.join(", ")
                )));
            }
        }
        let cipher_suites: Vec<rustls::SupportedCipherSuite> = ring
            .cipher_suites
            .iter()
            .filter(|suite| {
                let version = match suite {
                    rustls::SupportedCipherSuite::Tls13(_) => TlsVersion::V1_3,
                    // Without the `tls12` feature rustls has no TLS 1.2 variant to match.
                    #[allow(unreachable_patterns)]
                    _ => TlsVersion::V1_2,
                };
                self.tls_versions.contains(&version)
                    && self
                        .cipher_suites
                        .as_ref()
                        .is_none_or(|wanted| wanted.contains(&suite_name(suite)))
            })
            .copied()
            .collect();
        for version in &self.tls_versions {
            let present = cipher_suites.iter().any(|suite| match suite {
                rustls::SupportedCipherSuite::Tls13(_) => *version == TlsVersion::V1_3,
                // Without the `tls12` feature rustls has no TLS 1.2 variant to match.
                #[allow(unreachable_patterns)]
                _ => *version == TlsVersion::V1_2,
            });
            if !present {
                return Err(PeerError::Policy(format!(
                    "TLS {version} is allowed but no allowed cipher suite is for it"
                )));
            }
        }
        let kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = ring
            .kx_groups
            .iter()
            .filter(|group| {
                self.kx_groups
                    .as_ref()
                    .is_none_or(|wanted| wanted.contains(&group_name(group)))
            })
            .copied()
            .collect();
        if kx_groups.is_empty() {
            return Err(PeerError::Policy(
                "no key-exchange group is allowed".to_owned(),
            ));
        }
        Ok(Arc::new(CryptoProvider {
            cipher_suites,
            kx_groups,
            ..ring
        }))
    }

    /// The cipher suite IANA names the ring provider supports, for choosing
    /// [`cipher_suites`](Self::cipher_suites) from.
    pub fn supported_cipher_suites() -> Vec<String> {
        rustls::crypto::ring::default_provider()
            .cipher_suites
            .iter()
            .map(|suite| {
                suite
                    .suite()
                    .as_str()
                    .map_or_else(|| format!("{:?}", suite.suite()), str::to_owned)
            })
            .collect()
    }

    /// The key-exchange group names the ring provider supports, for choosing
    /// [`kx_groups`](Self::kx_groups) from.
    pub fn supported_kx_groups() -> Vec<String> {
        rustls::crypto::ring::default_provider()
            .kx_groups
            .iter()
            .map(|group| format!("{:?}", group.name()))
            .collect()
    }
}

#[cfg(feature = "serde")]
mod text {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{POLICY_VERSION, Policy, TlsVersion};
    use coqui_peer::Digest;

    macro_rules! as_text {
        ($type:ty) => {
            impl Serialize for $type {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serializer.collect_str(self)
                }
            }
            impl<'de> Deserialize<'de> for $type {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    String::deserialize(deserializer)?
                        .parse()
                        .map_err(D::Error::custom)
                }
            }
        };
    }
    as_text!(TlsVersion);

    /// The serialized form, version 1. On reading, every field but `policy_version` is
    /// optional and starts from the named `profile` (strict when absent).
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Document {
        #[serde(default = "version")]
        policy_version: u32,
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        tls_versions: Option<Vec<TlsVersion>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cipher_suites: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kx_groups: Option<Vec<String>>,
        #[serde(default)]
        pin_digests: Option<Vec<Digest>>,
        #[serde(default)]
        check_validity: Option<bool>,
        #[serde(default)]
        allow_chain_when_pinned: Option<bool>,
        #[serde(default)]
        allow_resumption: Option<bool>,
        #[serde(default)]
        require_ems: Option<bool>,
        #[serde(default)]
        waiting_per_source: Option<usize>,
        #[serde(default)]
        waiting_total: Option<usize>,
        #[serde(default)]
        waiting_rerecord_secs: Option<u64>,
        #[cfg(feature = "acl")]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        acl: Option<coqui_net_acl::Acl>,
    }

    fn version() -> u32 {
        POLICY_VERSION
    }

    impl Serialize for Policy {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            Document {
                policy_version: POLICY_VERSION,
                profile: Some(self.name.clone()),
                tls_versions: Some(self.tls_versions.clone()),
                cipher_suites: self.cipher_suites.clone(),
                kx_groups: self.kx_groups.clone(),
                pin_digests: Some(self.pin_digests.clone()),
                check_validity: Some(self.check_validity),
                allow_chain_when_pinned: Some(self.allow_chain_when_pinned),
                allow_resumption: Some(self.allow_resumption),
                require_ems: Some(self.require_ems),
                waiting_per_source: Some(self.waiting_per_source),
                waiting_total: Some(self.waiting_total),
                waiting_rerecord_secs: Some(self.waiting_rerecord_secs),
                #[cfg(feature = "acl")]
                acl: self.acl.clone(),
            }
            .serialize(serializer)
        }
    }

    impl Document {
        /// The policy this document describes: every field it names, over `base`.
        fn over<E: serde::de::Error>(self, base: Policy) -> Result<Policy, E> {
            if self.policy_version != POLICY_VERSION {
                return Err(E::custom(format!(
                    "policy_version {} is not supported; this build reads {POLICY_VERSION}",
                    self.policy_version
                )));
            }
            let mut policy = base;
            if let Some(name) = self.profile {
                policy.name = name;
            }
            if let Some(value) = self.tls_versions {
                policy.tls_versions = value;
            }
            if self.cipher_suites.is_some() {
                policy.cipher_suites = self.cipher_suites;
            }
            if self.kx_groups.is_some() {
                policy.kx_groups = self.kx_groups;
            }
            if let Some(value) = self.pin_digests {
                policy.pin_digests = value;
            }
            if let Some(value) = self.check_validity {
                policy.check_validity = value;
            }
            if let Some(value) = self.allow_chain_when_pinned {
                policy.allow_chain_when_pinned = value;
            }
            if let Some(value) = self.allow_resumption {
                policy.allow_resumption = value;
            }
            if let Some(value) = self.require_ems {
                policy.require_ems = value;
            }
            if let Some(value) = self.waiting_per_source {
                policy.waiting_per_source = value;
            }
            if let Some(value) = self.waiting_total {
                policy.waiting_total = value;
            }
            if let Some(value) = self.waiting_rerecord_secs {
                policy.waiting_rerecord_secs = value;
            }
            #[cfg(feature = "acl")]
            if let Some(acl) = self.acl {
                policy.acl = Some(crate::gate::canonical(&acl).map_err(E::custom)?);
            }
            Ok(policy)
        }
    }

    impl Policy {
        /// Reads a policy document over `base` instead of a built-in preset: the fields it
        /// names replace the base's, and the rest are kept. A consumer with its own default
        /// profile reads its configuration with this.
        ///
        /// # Errors
        ///
        /// The deserializer's error for an unknown key, a value of the wrong type or a
        /// `policy_version` other than 1.
        pub fn deserialize_over<'de, D: Deserializer<'de>>(
            base: Policy,
            deserializer: D,
        ) -> Result<Policy, D::Error> {
            Document::deserialize(deserializer)?.over(base)
        }
    }

    impl<'de> Deserialize<'de> for Policy {
        /// Starts from the built-in preset the `profile` key names (strict when absent).
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let document = Document::deserialize(deserializer)?;
            let base = match &document.profile {
                Some(name) => Policy::preset(name).map_err(D::Error::custom)?,
                None => Policy::strict(),
            };
            document.over(base)
        }
    }
}
