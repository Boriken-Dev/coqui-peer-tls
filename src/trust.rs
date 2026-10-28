use alloc::sync::Arc;
use core::net::SocketAddr;
#[cfg(feature = "ca")]
use core::time::Duration;
#[cfg(feature = "ca")]
use std::sync::{Mutex, PoisonError};
#[cfg(feature = "ca")]
use std::time::Instant;

use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

use crate::error::{PeerError, Refusal};
use crate::policy::Policy;
use crate::roots::Roots;
use coqui_peer::{Digest, PeerId, TrustStore, WaitingLimits};

/// A set of pinned certificate fingerprints: fixed, or the accepted peers of a
/// [`TrustStore`].
///
/// A fixed pin matches a certificate by hashing it with the pin's own digest, and every pin
/// is compared in constant time whatever its digest. A store holds SHA-256 pins.
#[derive(Debug, Clone)]
pub struct Pins(PinsKind);

#[derive(Debug, Clone)]
enum PinsKind {
    Fixed(Vec<PeerId>),
    Store(TrustStore),
}

impl Pins {
    /// Exactly these fingerprints.
    pub fn fixed(fingerprints: impl IntoIterator<Item = PeerId>) -> Self {
        Self(PinsKind::Fixed(fingerprints.into_iter().collect()))
    }

    /// The peers accepted in `store`, read at every handshake. A server using this also
    /// records refused peers that proved their key as waiting in the store.
    pub fn store(store: TrustStore) -> Self {
        Self(PinsKind::Store(store))
    }

    /// Whether the certificate with this DER encoding is pinned.
    pub fn matches(&self, der: &[u8]) -> bool {
        match &self.0 {
            PinsKind::Fixed(pins) => {
                // Every pin is compared, in constant time, whatever matches first.
                let mut found = false;
                for digest in [Digest::Sha256, Digest::Sha384, Digest::Sha512, Digest::Sha1] {
                    let mut ours = None;
                    for pin in pins.iter().filter(|pin| pin.digest() == digest) {
                        let ours = ours.get_or_insert_with(|| digest.of(der));
                        found |= pin == ours;
                    }
                }
                found
            }
            PinsKind::Store(store) => {
                let id = PeerId::of(der);
                store
                    .accepted_key(&id)
                    .is_some_and(|key| key.method == crate::METHOD)
            }
        }
    }

    /// Whether the certificate is the pending successor of an accepted certificate in a
    /// store-backed set.
    fn pending_successor(&self, der: &[u8]) -> bool {
        match &self.0 {
            PinsKind::Store(store) => store
                .successor_key(&PeerId::of(der))
                .is_some_and(|key| key.method == crate::METHOD),
            PinsKind::Fixed(_) => false,
        }
    }

    /// Records that the holder of a pending successor proved it in the handshake, then promotes
    /// it unless the store's rotation options require approval. Whether it is now accepted.
    fn prove(&self, der: &[u8]) -> bool {
        let PinsKind::Store(store) = &self.0 else {
            return false;
        };
        let id = PeerId::of(der);
        if store.prove_successor(&id).is_err() {
            return false;
        }
        !store.rotation().require_approval && store.promote_successor(&id).is_ok()
    }

    fn check_digests(&self, policy: &Policy) -> Result<(), PeerError> {
        if let PinsKind::Fixed(pins) = &self.0 {
            pins.iter().try_for_each(|pin| policy.check_pin(pin))?;
        }
        Ok(())
    }

    fn with_limits(&self, limits: WaitingLimits) -> Self {
        match &self.0 {
            PinsKind::Store(store) => Self(PinsKind::Store(store.clone().with_limits(limits))),
            PinsKind::Fixed(_) => self.clone(),
        }
    }

    fn records_waiting(&self) -> bool {
        matches!(self.0, PinsKind::Store(_))
    }

    /// Why a certificate these pins do not match is refused.
    fn refusal(&self) -> Refusal {
        match self.0 {
            PinsKind::Fixed(_) => Refusal::NotPinned,
            PinsKind::Store(_) => Refusal::NotAccepted,
        }
    }

    fn record_waiting(&self, der: &[u8], source: Option<SocketAddr>) {
        if let PinsKind::Store(store) = &self.0
            && let Ok(key) = crate::certificate_key(der)
        {
            store.record_waiting(&key, source);
        }
    }
}

/// A CA trust policy: certificates signed by the CAs in a PEM file whose subject and
/// subject alternative names match optional globs.
#[cfg(feature = "ca")]
#[derive(Debug, Clone)]
pub struct CaPolicy {
    /// PEM file with the trusted CA certificates.
    pub ca_file: std::path::PathBuf,
    /// Globs matched against the subject, rendered as by `x509-parser`; empty matches any.
    pub subject: Vec<String>,
    /// Globs matched against the DNS, email, URI and IP subject alternative names; empty
    /// matches any.
    pub san: Vec<String>,
}

#[cfg(feature = "ca")]
type MaybeCa = Option<crate::ca::Ca>;
#[cfg(not(feature = "ca"))]
type MaybeCa = Option<()>;

/// Whom to trust.
///
/// Every policy requires the peer to prove it holds the certificate's key in the handshake.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Trust {
    /// Only pinned certificates.
    Pinned(Pins),
    /// Certificates signed by a CA and matching name globs. Server role only.
    #[cfg(feature = "ca")]
    Ca(CaPolicy),
    /// A pinned certificate, or one the CA policy trusts. Server role only.
    #[cfg(feature = "ca")]
    PinnedOrCa {
        /// The pinned certificates.
        pins: Pins,
        /// The CA policy.
        ca: CaPolicy,
    },
    /// Any certificate whose key the peer proves; the caller decides from the returned
    /// [`PeerIdentity`](crate::PeerIdentity) afterwards.
    AnyWithKeyProof,
    /// A server certificate that chains to these roots and is valid for the name dialled:
    /// the web PKI, as a browser trusts a server. Client role only.
    Roots(Roots),
    /// A pinned server certificate, or one the roots trust for the name dialled. A pinned
    /// certificate is taken as [`Pinned`](Trust::Pinned) takes it, whatever its name. Client
    /// role only.
    PinnedOrRoots {
        /// The pinned certificates.
        pins: Pins,
        /// The roots.
        roots: Roots,
    },
}

/// What the pinned path additionally requires, from the [`Policy`].
#[derive(Debug, Clone, Copy)]
struct PinnedChecks {
    validity: bool,
    chain_allowed: bool,
}

impl PinnedChecks {
    fn of(policy: &Policy) -> Self {
        Self {
            validity: policy.check_validity,
            chain_allowed: policy.allow_chain_when_pinned,
        }
    }
}

impl Trust {
    /// The verifier a server uses for client certificates, under the strict policy.
    ///
    /// # Errors
    ///
    /// As [`client_cert_verifier_with`](Trust::client_cert_verifier_with).
    pub fn client_cert_verifier(&self) -> Result<Arc<PeerClientVerifier>, PeerError> {
        self.client_cert_verifier_with(&Policy::default())
    }

    /// The verifier a server uses for client certificates.
    ///
    /// It has no connection's addresses, so it cannot apply a policy's access control list:
    /// a policy with one is refused rather than ignored. Hand the policy to a configuration
    /// builder ([`server_config_with`](crate::server_config_with),
    /// [`ServerConfigs`](crate::ServerConfigs)), which applies it, or use
    /// [`client_cert_verifier_for`](Trust::client_cert_verifier_for).
    ///
    /// # Errors
    ///
    /// [`PeerError::Unsupported`] for [`Roots`](Trust::Roots) and
    /// [`PinnedOrRoots`](Trust::PinnedOrRoots), which only clients apply;
    /// [`PeerError::CaFile`] / [`PeerError::TrustPattern`] when the CA file or globs
    /// are unusable; [`PeerError::Policy`] when a pin uses a digest the policy refuses, the
    /// policy cannot build a crypto provider, or the policy has an access control list.
    pub fn client_cert_verifier_with(
        &self,
        policy: &Policy,
    ) -> Result<Arc<PeerClientVerifier>, PeerError> {
        #[cfg(feature = "acl")]
        if policy.acl.is_some() {
            return Err(PeerError::Policy(
                "a client verifier without addresses cannot apply the policy's acl; build a \
                 server configuration or use client_cert_verifier_for"
                    .to_owned(),
            ));
        }
        self.client_verifier(policy, None).map(Arc::new)
    }

    /// The verifier a server uses for one connection's client certificate, from `source` to
    /// `local`: for a host whose connections reach rustls without this crate's accept helpers,
    /// such as quinn, which runs the verifier on threads of its own.
    ///
    /// Waiting entries are recorded under `source`. With the `acl` feature, a policy's access
    /// control list is applied to the certificate's fingerprint from these addresses before
    /// the pins or the store are consulted ([`Refusal::PeerDenied`]), so a denied client is
    /// never recorded as waiting. The list's address rules are not applied here; a host checks
    /// them before the handshake with [`Policy::admits_address`], or uses
    /// [`ServerConfigs::for_connection`](crate::ServerConfigs::for_connection), which applies
    /// both.
    ///
    /// # Errors
    ///
    /// As [`client_cert_verifier_with`](Trust::client_cert_verifier_with), and
    /// [`PeerError::Policy`] when a rule of the access control list names something that is not
    /// a SHA-256 peer id.
    pub fn client_cert_verifier_for(
        &self,
        policy: &Policy,
        source: SocketAddr,
        local: SocketAddr,
    ) -> Result<Arc<dyn ClientCertVerifier>, PeerError> {
        let verifier: Arc<dyn ClientCertVerifier> =
            Arc::new(self.client_verifier(policy, Some(source))?);
        #[cfg(feature = "acl")]
        if let Some(acl) = &policy.acl {
            let gate = crate::gate::Gate::new(
                Arc::new(crate::gate::canonical(acl)?),
                Some((source, local)),
                None,
            );
            return Ok(Arc::new(crate::gate::PeerGate {
                inner: verifier,
                gate,
            }));
        }
        #[cfg(not(feature = "acl"))]
        let _ = local;
        Ok(verifier)
    }

    /// The client verifier, recording waiting entries under `source` when it is given and
    /// under the scope's otherwise.
    pub(crate) fn client_verifier(
        &self,
        policy: &Policy,
        source: Option<SocketAddr>,
    ) -> Result<PeerClientVerifier, PeerError> {
        let provider = policy.crypto_provider()?;
        let (pins, ca, any): (Option<Pins>, MaybeCa, bool) = match self {
            Self::Pinned(pins) => (Some(pins.clone()), None, false),
            #[cfg(feature = "ca")]
            Self::Ca(ca) => (None, Some(crate::ca::Ca::load(ca, &provider)?), false),
            #[cfg(feature = "ca")]
            Self::PinnedOrCa { pins, ca } => (
                Some(pins.clone()),
                Some(crate::ca::Ca::load(ca, &provider)?),
                false,
            ),
            Self::AnyWithKeyProof => (None, None, true),
            Self::Roots(_) | Self::PinnedOrRoots { .. } => return Err(PeerError::Unsupported),
        };
        if let Some(pins) = &pins {
            pins.check_digests(policy)?;
        }
        let pins = pins.map(|pins| pins.with_limits(policy.waiting));
        #[cfg(not(feature = "ca"))]
        let _ = ca;
        Ok(PeerClientVerifier {
            parts: Arc::new(ClientParts {
                pins,
                #[cfg(feature = "ca")]
                ca,
                any,
                checks: PinnedChecks::of(policy),
                provider,
            }),
            source,
            #[cfg(feature = "ca")]
            ca_trusted: Mutex::default(),
        })
    }

    /// The verifier a client uses for the server certificate, under the strict policy.
    ///
    /// # Errors
    ///
    /// As [`server_cert_verifier_with`](Trust::server_cert_verifier_with).
    pub fn server_cert_verifier(&self) -> Result<Arc<PeerServerVerifier>, PeerError> {
        self.server_cert_verifier_with(&Policy::default())
    }

    /// The verifier a client uses for the server certificate.
    ///
    /// # Errors
    ///
    /// [`PeerError::Unsupported`] for CA policies, which only servers apply;
    /// [`PeerError::Policy`] when a pin uses a digest the policy refuses;
    /// [`PeerError::Io`] when a roots bundle file cannot be read, [`PeerError::Certificate`]
    /// when it holds no certificate or one that cannot be a root, or the platform verifier
    /// cannot start.
    pub fn server_cert_verifier_with(
        &self,
        policy: &Policy,
    ) -> Result<Arc<PeerServerVerifier>, PeerError> {
        let provider = policy.crypto_provider()?;
        let (pins, roots, any) = match self {
            Self::Pinned(pins) => (Some(pins.clone()), None, false),
            Self::AnyWithKeyProof => (None, None, true),
            Self::Roots(roots) => (None, Some(roots.verifier(&provider)?), false),
            Self::PinnedOrRoots { pins, roots } => {
                (Some(pins.clone()), Some(roots.verifier(&provider)?), false)
            }
            #[cfg(feature = "ca")]
            Self::Ca(_) | Self::PinnedOrCa { .. } => return Err(PeerError::Unsupported),
        };
        if let Some(pins) = &pins {
            pins.check_digests(policy)?;
        }
        Ok(Arc::new(PeerServerVerifier {
            pins,
            roots,
            any,
            checks: PinnedChecks::of(policy),
            provider,
        }))
    }
}

/// Verifies the certificate a server presents to a dialing client.
///
/// A pinned certificate is taken because it is pinned, and because the server proves in the
/// handshake that it holds the key; its name is not checked. Validity dates and the absence
/// of a chain are checked as the [`Policy`] says, after the pin matched. With
/// [`Roots`](Trust::Roots), a certificate no pin matches is taken when its chain, dates and
/// name verify against the roots for the server name dialled.
#[derive(Debug)]
pub struct PeerServerVerifier {
    pins: Option<Pins>,
    roots: Option<Arc<dyn ServerCertVerifier>>,
    any: bool,
    checks: PinnedChecks,
    provider: Arc<CryptoProvider>,
}

impl PeerServerVerifier {
    /// After a valid signature: a pending successor the server just proved is recorded as
    /// proven, and promoted unless the store waits for approval, when it is refused.
    fn settle_successor(&self, certificate: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        if let Some(pins) = &self.pins
            && !self.any
            && !pins.matches(certificate.as_ref())
            && pins.pending_successor(certificate.as_ref())
            && !pins.prove(certificate.as_ref())
        {
            return Err(pins.refusal().into_rustls());
        }
        Ok(())
    }
}

impl ServerCertVerifier for PeerServerVerifier {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.any {
            return Ok(ServerCertVerified::assertion());
        }
        if self
            .pins
            .as_ref()
            .is_some_and(|pins| pins.matches(certificate.as_ref()))
        {
            check_pinned(certificate, intermediates, now, self.checks)?;
            Ok(ServerCertVerified::assertion())
        } else if self
            .pins
            .as_ref()
            .is_some_and(|pins| pins.pending_successor(certificate.as_ref()))
        {
            // Settled only once the signature below proves the server holds its key.
            check_pinned(certificate, intermediates, now, self.checks)?;
            Ok(ServerCertVerified::assertion())
        } else if let Some(roots) = &self.roots {
            roots
                .verify_server_cert(certificate, intermediates, name, ocsp_response, now)
                .map_err(crate::roots::refusal_of)
        } else {
            let refusal = self.pins.as_ref().map_or(Refusal::NotPinned, Pins::refusal);
            Err(refusal.into_rustls())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.provider.signature_verification_algorithms;
        let verified = verify_tls12_signature(message, certificate, signed, algorithms)?;
        self.settle_successor(certificate)?;
        Ok(verified)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.provider.signature_verification_algorithms;
        let verified = verify_tls13_signature(message, certificate, signed, algorithms)?;
        self.settle_successor(certificate)?;
        Ok(verified)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Verifies the certificate a client presents to a listening server.
///
/// With a store-backed pin set, a certificate that is neither pinned nor trusted by the CA
/// policy is not refused when it is presented: rustls calls
/// [`verify_client_cert`](ClientCertVerifier::verify_client_cert) before the client's
/// `CertificateVerify` signature, so the client has not yet shown it holds the key. The decision
/// is deferred to the signature check, which records the certificate as waiting only once the
/// signature verifies, and then refuses the handshake.
#[derive(Debug)]
pub struct PeerClientVerifier {
    parts: Arc<ClientParts>,
    /// The source waiting entries are recorded under, for a verifier made for one connection;
    /// `None` reads the scope the accept helpers set.
    source: Option<SocketAddr>,
    /// Certificates the CA policy trusted at presentation, whose signature is still to come.
    /// The signature check receives only the certificate, not the chain the CA policy needed,
    /// so this is how it tells a trusted certificate from a deferred one.
    #[cfg(feature = "ca")]
    ca_trusted: Mutex<Vec<(PeerId, Instant)>>,
}

/// What a client verifier decides by, shared by the verifiers made for single connections.
#[derive(Debug)]
struct ClientParts {
    pins: Option<Pins>,
    #[cfg(feature = "ca")]
    ca: Option<crate::ca::Ca>,
    any: bool,
    checks: PinnedChecks,
    provider: Arc<CryptoProvider>,
}

/// How long a CA-trusted certificate waits for its signature before being forgotten.
#[cfg(feature = "ca")]
const CA_TRUSTED_TTL: Duration = Duration::from_secs(30);
/// Bound on certificates awaiting their signature.
#[cfg(feature = "ca")]
const CA_TRUSTED_MAX: usize = 4096;

impl PeerClientVerifier {
    /// The same verifier for one connection, recording waiting entries under `source`.
    pub(crate) fn for_source(&self, source: SocketAddr) -> Self {
        Self {
            parts: Arc::clone(&self.parts),
            source: Some(source),
            #[cfg(feature = "ca")]
            ca_trusted: Mutex::default(),
        }
    }

    /// Whether unpinned, untrusted certificates are deferred to the signature check.
    fn defers(&self) -> bool {
        !self.parts.any && self.parts.pins.as_ref().is_some_and(Pins::records_waiting)
    }

    fn pinned(&self, der: &[u8]) -> bool {
        self.parts
            .pins
            .as_ref()
            .is_some_and(|pins| pins.matches(der))
    }

    /// Why a certificate that is neither pinned nor CA-trusted is refused.
    fn refusal(&self) -> Refusal {
        match &self.parts.pins {
            Some(pins) if pins.records_waiting() => Refusal::NotAccepted,
            #[cfg(feature = "ca")]
            _ if self.parts.ca.is_some() => Refusal::NotTrusted,
            Some(pins) => pins.refusal(),
            None => Refusal::NotPinned,
        }
    }

    #[cfg(feature = "ca")]
    fn note_ca_trusted(&self, der: &[u8]) {
        let mut waiting = self
            .ca_trusted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        waiting.retain(|(_, at)| now.duration_since(*at) < CA_TRUSTED_TTL);
        if waiting.len() < CA_TRUSTED_MAX {
            waiting.push((PeerId::of(der), now));
        }
    }

    /// Consumes one note for `der`; whether there was one.
    fn take_ca_trusted(&self, der: &[u8]) -> bool {
        #[cfg(feature = "ca")]
        {
            let fingerprint = PeerId::of(der);
            let mut waiting = self
                .ca_trusted
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            waiting.retain(|(_, at)| now.duration_since(*at) < CA_TRUSTED_TTL);
            if let Some(index) = waiting.iter().position(|(had, _)| *had == fingerprint) {
                waiting.swap_remove(index);
                return true;
            }
        }
        #[cfg(not(feature = "ca"))]
        let _ = der;
        false
    }

    /// After the signature check: a valid signature means the peer holds the key, so a
    /// deferred certificate is recorded as waiting and refused. An invalid one is refused
    /// without a record.
    fn settle(
        &self,
        certificate: &CertificateDer<'_>,
        verified: Result<HandshakeSignatureValid, rustls::Error>,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if !self.defers() {
            return verified;
        }
        let trusted = self.take_ca_trusted(certificate.as_ref());
        let verified = verified?;
        if trusted || self.pinned(certificate.as_ref()) {
            return Ok(verified);
        }
        if let Some(pins) = &self.parts.pins
            && pins.pending_successor(certificate.as_ref())
        {
            // Announced by an accepted peer, and now proven: promoted, or recorded as proven
            // for the caller to approve. Not a stranger to queue either way.
            return pins
                .prove(certificate.as_ref())
                .then_some(verified)
                .ok_or_else(|| self.refusal().into_rustls());
        }
        if let Some(pins) = &self.parts.pins {
            pins.record_waiting(
                certificate.as_ref(),
                self.source.or_else(crate::source::current),
            );
        }
        Err(self.refusal().into_rustls())
    }
}

impl ClientCertVerifier for PeerClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        #[cfg(feature = "ca")]
        if let Some(ca) = &self.parts.ca {
            return ca.root_hint_subjects();
        }
        &[]
    }

    fn verify_client_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.parts.any {
            return Ok(ClientCertVerified::assertion());
        }
        if self.pinned(certificate.as_ref()) {
            check_pinned(certificate, intermediates, now, self.parts.checks)?;
            return Ok(ClientCertVerified::assertion());
        }
        if self
            .parts
            .pins
            .as_ref()
            .is_some_and(|pins| pins.pending_successor(certificate.as_ref()))
        {
            // Settled in `settle`, once the signature proves the client holds its key.
            check_pinned(certificate, intermediates, now, self.parts.checks)?;
            return Ok(ClientCertVerified::assertion());
        }
        #[cfg(feature = "ca")]
        if let Some(ca) = &self.parts.ca
            && ca.trusts(certificate, intermediates, now)?
        {
            if self.defers() {
                self.note_ca_trusted(certificate.as_ref());
            }
            return Ok(ClientCertVerified::assertion());
        }
        #[cfg(not(feature = "ca"))]
        let _ = (intermediates, now);
        if self.defers() {
            // Not recorded here: the client has not yet proved it holds the key.
            return Ok(ClientCertVerified::assertion());
        }
        Err(self.refusal().into_rustls())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.parts.provider.signature_verification_algorithms;
        let verified = verify_tls12_signature(message, certificate, signed, algorithms);
        self.settle(certificate, verified)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.parts.provider.signature_verification_algorithms;
        let verified = verify_tls13_signature(message, certificate, signed, algorithms);
        self.settle(certificate, verified)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parts
            .provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// What a pinned certificate must also be, checked only after its pin matched: alone (no
/// chain, since there is no CA to chain to) and within its validity dates. A custom verifier
/// loses rustls's own date check, and a pin does not change when a certificate expires.
fn check_pinned(
    certificate: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    checks: PinnedChecks,
) -> Result<(), rustls::Error> {
    if !checks.chain_allowed && !intermediates.is_empty() {
        return Err(Refusal::ChainWhenPinned.into_rustls());
    }
    if !checks.validity {
        return Ok(());
    }
    let (not_before, not_after) = crate::x509::validity(certificate.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    if now < not_before {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidYet,
        ));
    }
    if now > not_after {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        ));
    }
    Ok(())
}
