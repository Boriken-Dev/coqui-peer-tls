use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};

use crate::error::PeerError;
use crate::fingerprint::Fingerprint;
use crate::identity::PeerIdentity;

/// The server name sent in the handshake. Trust is by fingerprint, so the name carries no
/// meaning; it only has to be a valid DNS name.
pub const SERVER_NAME: &str = "coqui-peer.invalid";

pub(crate) fn identity_of(
    certificates: Option<&[CertificateDer<'static>]>,
) -> Result<PeerIdentity, PeerError> {
    let certificate = certificates
        .and_then(<[_]>::first)
        .ok_or(PeerError::Certificate)?;
    Ok(PeerIdentity {
        fingerprint: Fingerprint::of_certificate(certificate.as_ref()),
        certificate: certificate.as_ref().to_vec(),
    })
}

/// Dials a peer over `io`, completing the handshake before returning.
///
/// Returns the encrypted stream and the verified peer. `io` is any blocking byte stream.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails, including a refused peer certificate.
pub fn dial<S: Read + Write>(
    config: Arc<ClientConfig>,
    mut io: S,
) -> Result<(StreamOwned<ClientConnection, S>, PeerIdentity), PeerError> {
    let name = ServerName::try_from(SERVER_NAME).map_err(|_| PeerError::Tls)?;
    let mut connection = ClientConnection::new(config, name).map_err(|_| PeerError::Tls)?;
    while connection.is_handshaking() {
        connection.complete_io(&mut io).map_err(PeerError::Io)?;
    }
    let peer = identity_of(connection.peer_certificates())?;
    Ok((StreamOwned::new(connection, io), peer))
}

/// Accepts a peer over `io`, completing the handshake before returning.
///
/// A client whose certificate the configured [`Trust`](crate::Trust) refuses fails the
/// handshake; when the trust is a store-backed pin set it is recorded as waiting first.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails.
pub fn accept<S: Read + Write>(
    config: Arc<ServerConfig>,
    mut io: S,
) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError> {
    let mut connection = ServerConnection::new(config).map_err(|_| PeerError::Tls)?;
    while connection.is_handshaking() {
        connection.complete_io(&mut io).map_err(PeerError::Io)?;
    }
    let peer = identity_of(connection.peer_certificates())?;
    Ok((StreamOwned::new(connection, io), peer))
}
