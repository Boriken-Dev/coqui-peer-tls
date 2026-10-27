//! Server verification by certificate authorities, as a browser does: the web PKI.

use alloc::sync::Arc;
use core::fmt;
use std::path::PathBuf;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{CertificateError, RootCertStore};

use crate::error::{PeerError, Refusal};

/// The certificate authorities a client verifies a server against: the chain up to one of
/// them, every certificate's validity dates and the server name the client dialled.
///
/// This is the web PKI trust model, a different one from pinning: any server that one of
/// these authorities issued a certificate for the dialled name is trusted. Dial with a name
/// ([`dial_named`](crate::dial_named), [`TlsHandshake::client_named`](crate::TlsHandshake::client_named),
/// or rustls with a `ServerName`); [`dial`](crate::dial) names [`SERVER_NAME`](crate::SERVER_NAME),
/// which no authority issues, so it is refused with [`Refusal::NameMismatch`]. Names are
/// always checked and dates always are, whatever [`Policy::check_validity`](crate::Policy::check_validity)
/// says (that setting applies to pinned certificates).
#[derive(Clone)]
pub struct Roots(RootsKind);

#[derive(Clone)]
enum RootsKind {
    Pem(String),
    File(PathBuf),
    #[cfg(feature = "platform-roots")]
    Platform,
}

impl fmt::Debug for Roots {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            RootsKind::Pem(text) => formatter
                .debug_struct("Roots::Pem")
                .field("bytes", &text.len())
                .finish(),
            RootsKind::File(path) => formatter.debug_tuple("Roots::File").field(path).finish(),
            #[cfg(feature = "platform-roots")]
            RootsKind::Platform => formatter.write_str("Roots::Platform"),
        }
    }
}

impl Roots {
    /// The CA certificates in this PEM text (a bundle): every `CERTIFICATE` block is a root,
    /// other blocks and text between them are ignored.
    pub fn bundle_pem(text: impl Into<String>) -> Self {
        Self(RootsKind::Pem(text.into()))
    }

    /// The CA certificates in the PEM file at `path`, read when the verifier is built (by
    /// [`Trust::server_cert_verifier_with`](crate::Trust::server_cert_verifier_with) or a
    /// client configuration), as by [`bundle_pem`](Roots::bundle_pem).
    pub fn bundle_file(path: impl Into<PathBuf>) -> Self {
        Self(RootsKind::File(path.into()))
    }

    /// The operating system's roots and certificate verifier (rustls-platform-verifier):
    /// the Windows, macOS, iOS or Android verifier, or the system's CA bundle checked by
    /// webpki elsewhere. It may also check revocation where the platform does.
    ///
    /// On Android the host initializes rustls-platform-verifier from its JVM first
    /// (`rustls_platform_verifier::android::init_*`); otherwise a handshake panics.
    #[cfg(feature = "platform-roots")]
    pub fn platform() -> Self {
        Self(RootsKind::Platform)
    }

    /// The verifier these roots give, over `provider`.
    pub(crate) fn verifier(
        &self,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Arc<dyn ServerCertVerifier>, PeerError> {
        let text = match &self.0 {
            RootsKind::Pem(text) => text.as_bytes().to_vec(),
            RootsKind::File(path) => std::fs::read(path).map_err(PeerError::Io)?,
            #[cfg(feature = "platform-roots")]
            RootsKind::Platform => {
                let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
                    .map_err(|_| PeerError::Certificate)?;
                return Ok(Arc::new(verifier));
            }
        };
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(&text) {
            roots
                .add(certificate.map_err(|_| PeerError::Certificate)?)
                .map_err(|_| PeerError::Certificate)?;
        }
        if roots.is_empty() {
            return Err(PeerError::Certificate);
        }
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| PeerError::Certificate)?;
        Ok(verifier)
    }
}

/// The error a roots verifier's refusal becomes: a wrong name is [`Refusal::NameMismatch`];
/// dates, revocation and encoding stay rustls's own, as on the pinned path; any other
/// certificate failure (unknown issuer, bad signature, wrong purpose, a platform's own
/// reason) is [`Refusal::NotTrusted`].
pub(crate) fn refusal_of(error: rustls::Error) -> rustls::Error {
    let rustls::Error::InvalidCertificate(reason) = &error else {
        return error;
    };
    match reason {
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            Refusal::NameMismatch.into_rustls()
        }
        CertificateError::Expired
        | CertificateError::ExpiredContext { .. }
        | CertificateError::NotValidYet
        | CertificateError::NotValidYetContext { .. }
        | CertificateError::Revoked
        | CertificateError::BadEncoding => error,
        _ => Refusal::NotTrusted.into_rustls(),
    }
}
