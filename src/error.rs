use std::fmt;
use std::io;

/// Sanitized failures while loading, storing or using a peer identity. No message holds
/// key material or a path.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerError {
    /// A peer id is malformed.
    InvalidId,
    /// A certificate or its private key is missing or invalid.
    Certificate,
    /// A TLS configuration or handshake was refused.
    Tls,
    /// A fingerprint is an MD5 digest, which no policy allows.
    WeakDigest,
    /// A policy setting is invalid or unsupported; the message names it and lists what is
    /// supported. It never holds key material.
    Policy(String),
    /// A trust glob is malformed.
    TrustPattern,
    /// The peer is not waiting for acceptance.
    NotWaiting,
    /// The peer was already accepted.
    AlreadyAccepted,
    /// The path does not name a file inside a directory.
    Path,
    /// The trust policy cannot be used in this role.
    Unsupported,
    /// A filesystem or stream operation failed.
    Io(io::Error),
}

impl fmt::Display for PeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidId => "peer id is invalid",
            Self::Certificate => "certificate or private key is invalid",
            Self::Tls => "TLS configuration or handshake failed",
            Self::WeakDigest => "fingerprint is an MD5 digest, which is not supported",
            Self::Policy(message) => message,
            Self::TrustPattern => "certificate trust pattern is invalid",
            Self::NotWaiting => "certificate is not waiting for acceptance",
            Self::AlreadyAccepted => "certificate is already accepted",
            Self::Path => "path must have a parent directory",
            Self::Unsupported => "trust policy is not supported in this role",
            Self::Io(_) => "storage or stream operation failed",
        })
    }
}

impl From<coqui_peer::Error> for PeerError {
    fn from(error: coqui_peer::Error) -> Self {
        match error {
            coqui_peer::Error::InvalidId => Self::InvalidId,
            coqui_peer::Error::WeakDigest => Self::WeakDigest,
            coqui_peer::Error::UnknownDigest(_) => Self::Policy(error.to_string()),
            coqui_peer::Error::NotWaiting => Self::NotWaiting,
            coqui_peer::Error::AlreadyAccepted => Self::AlreadyAccepted,
            coqui_peer::Error::Io(error) => Self::Io(error),
            _ => Self::Certificate,
        }
    }
}

impl std::error::Error for PeerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl PeerError {
    /// The trust refusal behind this error, when a handshake failed because this side's
    /// verifier refused the peer's certificate. The refused side sees only the TLS alert, so
    /// its own error carries none.
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::Io(error) => error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .and_then(Refusal::from_rustls),
            _ => None,
        }
    }
}

/// Why a verifier of this crate refused a peer's certificate.
///
/// A verifier returns it inside
/// `rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(..)))`, so rustls
/// sends the `certificate_unknown` alert; [`Refusal::from_rustls`] and
/// [`PeerError::refusal`] take it back out. Expired and not-yet-valid certificates are
/// rustls's own `CertificateError::Expired` and `NotValidYet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Refusal {
    /// The certificate matches no fixed pin.
    NotPinned,
    /// The certificate is not one the trust store accepted. A server with a store-backed pin
    /// set records it as waiting, within the store's limits, once the peer proved its key.
    NotAccepted,
    /// The certificate matches no pin, and the CA policy does not trust its chain or names,
    /// or the [`Roots`](crate::Roots) do not trust its chain (an unknown issuer, a bad
    /// signature, a certificate not for server authentication).
    NotTrusted,
    /// A pinned peer presented a certificate chain, which the policy does not allow
    /// ([`Policy::allow_chain_when_pinned`](crate::Policy::allow_chain_when_pinned)).
    ChainWhenPinned,
    /// The server's chain is trusted by the [`Roots`](crate::Roots), but the certificate is
    /// not for the server name the client dialled.
    NameMismatch,
}

impl Refusal {
    /// The refusal inside `error`, when one of this crate's verifiers produced it.
    pub fn from_rustls(error: &rustls::Error) -> Option<Self> {
        match error {
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other)) => {
                other.0.downcast_ref::<Self>().copied()
            }
            _ => None,
        }
    }

    /// The rustls error a verifier returns for this refusal.
    pub(crate) fn into_rustls(self) -> rustls::Error {
        rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
            std::sync::Arc::new(self),
        )))
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotPinned => "peer certificate matches no pinned fingerprint",
            Self::NotAccepted => "peer certificate is not an accepted peer of the trust store",
            Self::NotTrusted => {
                "peer certificate matches no pin and is not trusted by the CA policy or roots"
            }
            Self::ChainWhenPinned => {
                "pinned peer presented a certificate chain, which the policy does not allow"
            }
            Self::NameMismatch => "server certificate is not valid for the name dialled",
        })
    }
}

impl std::error::Error for Refusal {}
