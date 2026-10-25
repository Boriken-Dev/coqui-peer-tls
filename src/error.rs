use std::fmt;
use std::io;

/// Sanitized failures while loading, storing or using a peer identity. No message holds
/// key material or a path.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerError {
    /// A fingerprint is malformed.
    InvalidFingerprint,
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
            Self::InvalidFingerprint => "certificate fingerprint is invalid",
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
            coqui_peer::Error::InvalidId => Self::InvalidFingerprint,
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
