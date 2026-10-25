use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::crypto_provider;
use crate::error::PeerError;
use coqui_peer::PeerId as Fingerprint;

/// A verified peer: the certificate the other side proved it holds the key of.
///
/// Returned by [`dial`](crate::dial) and [`accept`](crate::accept) after the handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The certificate's fingerprint.
    pub fingerprint: Fingerprint,
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

/// This side's self-issued certificate and its private key.
///
/// On disk it is one PEM file: the certificate block, then a PKCS#8 `PRIVATE KEY` block.
pub struct Identity {
    fingerprint: Fingerprint,
    certificate: CertificateDer<'static>,
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
        let certificate =
            CertificateDer::from_pem_slice(text.as_bytes()).map_err(|_| PeerError::Certificate)?;
        let key =
            PrivateKeyDer::from_pem_slice(text.as_bytes()).map_err(|_| PeerError::Certificate)?;
        ServerConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| PeerError::Tls)?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key.clone_key())
            .map_err(|_| PeerError::Certificate)?;
        Ok(Self {
            fingerprint: Fingerprint::of(certificate.as_ref()),
            certificate,
            key,
        })
    }

    /// The identity as PEM text: the certificate, then the PKCS#8 private key.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when the key is not PKCS#8.
    pub fn to_pem(&self) -> Result<String, PeerError> {
        let PrivateKeyDer::Pkcs8(key) = &self.key else {
            return Err(PeerError::Certificate);
        };
        Ok(format!(
            "{}{}",
            encode_pem("CERTIFICATE", self.certificate.as_ref()),
            encode_pem("PRIVATE KEY", key.secret_pkcs8_der())
        ))
    }

    /// Reads the identity file at `path`; `None` when it is absent.
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
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The certificate, DER encoded.
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// This identity as the value a remote peer sees after a handshake.
    pub fn peer_identity(&self) -> PeerIdentity {
        PeerIdentity {
            fingerprint: self.fingerprint,
            certificate: self.certificate.as_ref().to_vec(),
        }
    }

    pub(crate) fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }

    pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

#[cfg(feature = "generate")]
impl Identity {
    /// Creates a self-signed ECDSA P-256 identity without writing it.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when key generation fails.
    pub fn generate() -> Result<Self, PeerError> {
        let key = rcgen::KeyPair::generate().map_err(|_| PeerError::Certificate)?;
        let mut parameters = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|_| PeerError::Certificate)?;
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "coqui-peer");
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
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
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
