use core::fmt;
#[cfg(feature = "generate")]
use core::time::Duration;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::crypto_provider;
use crate::error::PeerError;
use coqui_peer::PeerId;

/// A verified peer: the certificate the other side proved it holds the key of.
///
/// Returned by [`dial`](crate::dial) and [`accept`](crate::accept) after the handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The certificate's fingerprint.
    pub fingerprint: PeerId,
    /// The certificate, DER encoded.
    pub certificate: Vec<u8>,
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PeerIdentity")
            .field(&self.fingerprint)
            .finish()
    }
}

/// This side's certificate and its private key, with the intermediates that issued the
/// certificate when it has any.
///
/// A peer identity is one self-issued certificate ([`from_pem`](Identity::from_pem)). A server
/// a browser reaches under web PKI presents a CA-issued certificate with its intermediates
/// ([`from_pem_chain`](Identity::from_pem_chain)). The fingerprint is always the leaf
/// certificate's.
///
/// On disk it is one PEM file: the certificate block, then a PKCS#8 `PRIVATE KEY` block.
pub struct Identity {
    fingerprint: PeerId,
    certificate: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identity")
            .field(&self.fingerprint)
            .finish()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            fingerprint: self.fingerprint,
            certificate: self.certificate.clone(),
            intermediates: self.intermediates.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl Identity {
    /// Reads one certificate and its matching private key from PEM text.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when either is missing, malformed or not a pair, or when more
    /// than one certificate is present.
    pub fn from_pem(text: &str) -> Result<Self, PeerError> {
        // A chain is refused: an identity is one self-issued certificate.
        if CertificateDer::pem_slice_iter(text.as_bytes()).count() != 1 {
            return Err(PeerError::Certificate);
        }
        Self::from_pem_chain(text)
    }

    /// Reads a certificate, the intermediates that issued it and the leaf's private key from
    /// PEM text: the leaf certificate first, then each issuer in order up to (not necessarily
    /// including) the root, and one private key in any block position.
    ///
    /// A configuration built from it presents the whole chain. The fingerprint is the leaf's.
    /// A peer that pins this identity refuses the chain unless its policy sets
    /// [`allow_chain_when_pinned`](crate::Policy::allow_chain_when_pinned). One certificate
    /// alone gives the same identity as [`from_pem`](Identity::from_pem).
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when there is no certificate or no key, either is malformed,
    /// or the key is not the first certificate's.
    pub fn from_pem_chain(text: &str) -> Result<Self, PeerError> {
        let mut certificates = CertificateDer::pem_slice_iter(text.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PeerError::Certificate)?;
        if certificates.is_empty() {
            return Err(PeerError::Certificate);
        }
        let key =
            PrivateKeyDer::from_pem_slice(text.as_bytes()).map_err(|_| PeerError::Certificate)?;
        // rustls refuses a key whose public key is not the first certificate's.
        ServerConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| PeerError::Tls)?
            .with_no_client_auth()
            .with_single_cert(certificates.clone(), key.clone_key())
            .map_err(|_| PeerError::Certificate)?;
        let certificate = certificates.remove(0);
        Ok(Self {
            fingerprint: PeerId::of(certificate.as_ref()),
            certificate,
            intermediates: certificates,
            key,
        })
    }

    /// The identity as PEM text: the certificate, its intermediates in order, then the PKCS#8
    /// private key. Text with intermediates reads back with
    /// [`from_pem_chain`](Identity::from_pem_chain) only.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when the key is not PKCS#8.
    pub fn to_pem(&self) -> Result<String, PeerError> {
        let PrivateKeyDer::Pkcs8(key) = &self.key else {
            return Err(PeerError::Certificate);
        };
        let mut pem = encode_pem("CERTIFICATE", self.certificate.as_ref());
        for intermediate in &self.intermediates {
            pem.push_str(&encode_pem("CERTIFICATE", intermediate.as_ref()));
        }
        pem.push_str(&encode_pem("PRIVATE KEY", key.secret_pkcs8_der()));
        Ok(pem)
    }

    /// Reads the identity file at `path`; `None` when it is absent. The file holds one
    /// certificate; a chain is refused as by [`from_pem`](Identity::from_pem).
    ///
    /// # Errors
    ///
    /// [`PeerError::Io`] when it cannot be read, [`PeerError::Certificate`] when invalid.
    pub fn read(path: &Path) -> Result<Option<Self>, PeerError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_pem(&text).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(PeerError::Io(error)),
        }
    }

    /// Writes the identity file without replacing an existing one, readable by its owner
    /// alone (`0600` on Unix). Parent directories are created.
    ///
    /// # Errors
    ///
    /// [`PeerError::Io`] with kind `AlreadyExists` when `path` exists.
    pub fn write_new(&self, path: &Path) -> Result<(), PeerError> {
        let parent = path.parent().ok_or(PeerError::Path)?;
        fs::create_dir_all(parent).map_err(PeerError::Io)?;
        let pem = self.to_pem()?;
        let temporary = temporary_path(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(PeerError::Io)?;
        let result = file
            .write_all(pem.as_bytes())
            .and_then(|()| file.sync_all())
            // A hard link fails when `path` exists, so an existing identity is never replaced.
            .and_then(|()| fs::hard_link(&temporary, path));
        drop(file);
        let _ = fs::remove_file(&temporary);
        result.map_err(PeerError::Io)
    }

    /// The certificate's fingerprint: what a peer pins.
    pub fn fingerprint(&self) -> PeerId {
        self.fingerprint
    }

    /// The certificate, DER encoded.
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// The intermediates presented after the certificate, DER encoded, in order; none for an
    /// identity read by [`from_pem`](Identity::from_pem) or generated.
    pub fn intermediates_der(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.intermediates.iter().map(AsRef::as_ref)
    }

    /// This identity as the value a remote peer sees after a handshake.
    pub fn peer_identity(&self) -> PeerIdentity {
        PeerIdentity {
            fingerprint: self.fingerprint,
            certificate: self.certificate.as_ref().to_vec(),
        }
    }

    /// The certificate followed by its intermediates, as a configuration presents them.
    pub(crate) fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        let mut chain = Vec::with_capacity(1 + self.intermediates.len());
        chain.push(self.certificate.clone());
        chain.extend(self.intermediates.iter().cloned());
        chain
    }

    pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

#[cfg(feature = "generate")]
impl Identity {
    /// Creates a self-signed ECDSA P-256 identity without writing it, valid for rcgen's
    /// default period (decades).
    ///
    /// Every generated certificate has the common name `coqui-peer`, a DNS subjectAltName
    /// [`SERVER_NAME`](crate::SERVER_NAME), a subjectKeyIdentifier and basicConstraints
    /// `CA:FALSE`. Peers pin it by fingerprint, so the name is not checked.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when key generation fails.
    pub fn generate() -> Result<Self, PeerError> {
        Self::generate_from(Self::parameters()?)
    }

    /// Creates a self-signed ECDSA P-256 identity valid from now for `validity`, without
    /// writing it.
    ///
    /// For WebTransport's `serverCertificateHashes`, which accepts only a certificate whose
    /// whole validity period is at most 14 days: pass at most `Duration::from_secs(14 * 86_400)`,
    /// and replace the identity before it expires. A peer whose clock runs behind sees the
    /// certificate as not yet valid; [`generate_with`](Identity::generate_with) can start the
    /// period earlier, within the same 14 days.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when `validity` is under one second or out of range, or key
    /// generation fails.
    pub fn generate_valid_for(validity: Duration) -> Result<Self, PeerError> {
        if validity < Duration::from_secs(1) {
            return Err(PeerError::Certificate);
        }
        let now = SystemTime::now();
        let not_after = now.checked_add(validity).ok_or(PeerError::Certificate)?;
        Self::generate_with(now, not_after)
    }

    /// Creates a self-signed ECDSA P-256 identity valid from `not_before` to `not_after`,
    /// without writing it. Certificates hold whole seconds: both are truncated to the second.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when `not_after` is not at least one second after
    /// `not_before`, either is before 1970 or out of range, or key generation fails.
    pub fn generate_with(not_before: SystemTime, not_after: SystemTime) -> Result<Self, PeerError> {
        let seconds = |at: SystemTime| -> Result<time::OffsetDateTime, PeerError> {
            let since = at
                .duration_since(UNIX_EPOCH)
                .map_err(|_| PeerError::Certificate)?;
            let since = i64::try_from(since.as_secs()).map_err(|_| PeerError::Certificate)?;
            time::OffsetDateTime::from_unix_timestamp(since).map_err(|_| PeerError::Certificate)
        };
        let (not_before, not_after) = (seconds(not_before)?, seconds(not_after)?);
        if not_after <= not_before {
            return Err(PeerError::Certificate);
        }
        let mut parameters = Self::parameters()?;
        parameters.not_before = not_before;
        parameters.not_after = not_after;
        Self::generate_from(parameters)
    }

    /// rcgen writes the subjectKeyIdentifier only beside basicConstraints, hence
    /// `ExplicitNoCa`. Chrome's `serverCertificateHashes` verifier refuses a certificate
    /// with no extensions.
    fn parameters() -> Result<rcgen::CertificateParams, PeerError> {
        let mut parameters = rcgen::CertificateParams::new(vec![crate::SERVER_NAME.to_owned()])
            .map_err(|_| PeerError::Certificate)?;
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "coqui-peer");
        parameters.is_ca = rcgen::IsCa::ExplicitNoCa;
        Ok(parameters)
    }

    fn generate_from(parameters: rcgen::CertificateParams) -> Result<Self, PeerError> {
        let key = rcgen::KeyPair::generate().map_err(|_| PeerError::Certificate)?;
        let certificate = parameters
            .self_signed(&key)
            .map_err(|_| PeerError::Certificate)?;
        Self::from_pem(&format!("{}{}", certificate.pem(), key.serialize_pem()))
    }

    /// Reads the identity file at `path`, creating and writing a new identity when absent.
    /// Two processes racing to create it end with the same identity.
    ///
    /// # Errors
    ///
    /// As [`read`](Identity::read) and [`write_new`](Identity::write_new).
    pub fn open_or_create(path: &Path) -> Result<Self, PeerError> {
        if let Some(identity) = Self::read(path)? {
            return Ok(identity);
        }
        let identity = Self::generate()?;
        match identity.write_new(path) {
            Ok(()) => Ok(identity),
            Err(PeerError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                Self::read(path)?.ok_or(PeerError::Certificate)
            }
            Err(error) => Err(error),
        }
    }
}

/// Encodes DER as a PEM block with 64-character lines and LF line endings.
pub(crate) fn encode_pem(label: &str, der: &[u8]) -> String {
    let encoded = data_encoding::BASE64.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(core::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

pub(crate) fn temporary_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{}.tmp", std::process::id(), nonce));
    path.with_file_name(name)
}

#[cfg(all(test, feature = "generate"))]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn window(identity: &Identity) -> (i64, i64) {
        crate::x509::validity(identity.certificate_der()).unwrap()
    }

    #[test]
    fn a_short_lived_identity_has_the_requested_window() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let identity = Identity::generate_valid_for(Duration::from_secs(14 * DAY)).unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (not_before, not_after) = window(&identity);
        let not_before = u64::try_from(not_before).unwrap();
        assert!((before..=after).contains(&not_before));
        assert_eq!(u64::try_from(not_after).unwrap() - not_before, 14 * DAY);
        assert_eq!(identity.intermediates_der().len(), 0);
    }

    #[test]
    fn an_explicit_window_is_kept_to_the_second() {
        let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000) + Duration::from_millis(700);
        let end = start + Duration::from_secs(3 * DAY);
        let identity = Identity::generate_with(start, end).unwrap();
        assert_eq!(
            window(&identity),
            (1_800_000_000, 1_800_000_000 + 3 * 86_400)
        );
    }

    /// Chrome's `serverCertificateHashes` verifier refuses a certificate with no extensions.
    #[test]
    fn generated_identities_carry_a_server_name_and_a_key_identifier() {
        use x509_parser::extensions::{GeneralName, ParsedExtension};

        let start = SystemTime::now();
        for identity in [
            Identity::generate().unwrap(),
            Identity::generate_valid_for(Duration::from_secs(14 * DAY)).unwrap(),
            Identity::generate_with(start, start + Duration::from_secs(DAY)).unwrap(),
        ] {
            let (_, certificate) =
                x509_parser::parse_x509_certificate(identity.certificate_der()).unwrap();
            let names: Vec<_> = certificate
                .subject_alternative_name()
                .unwrap()
                .expect("a subjectAltName")
                .value
                .general_names
                .clone();
            assert_eq!(names, vec![GeneralName::DNSName(crate::SERVER_NAME)]);
            let key_identifier = certificate
                .extensions()
                .iter()
                .find_map(|extension| match extension.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                    _ => None,
                })
                .expect("a subjectKeyIdentifier");
            assert!(!key_identifier.is_empty());
            let constraints = certificate.basic_constraints().unwrap().unwrap();
            assert!(!constraints.value.ca);
            // The fingerprint names the certificate as made, extensions included.
            assert_eq!(
                identity.fingerprint(),
                PeerId::of(identity.certificate_der())
            );
        }
    }

    #[test]
    fn an_empty_or_inverted_window_is_refused() {
        assert!(matches!(
            Identity::generate_valid_for(Duration::ZERO),
            Err(PeerError::Certificate)
        ));
        assert!(matches!(
            Identity::generate_valid_for(Duration::from_millis(999)),
            Err(PeerError::Certificate)
        ));
        let now = SystemTime::now();
        assert!(matches!(
            Identity::generate_with(now, now - Duration::from_secs(60)),
            Err(PeerError::Certificate)
        ));
    }
}
