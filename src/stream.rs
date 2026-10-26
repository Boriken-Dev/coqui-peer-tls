use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};

use crate::error::PeerError;
use crate::identity::PeerIdentity;
use crate::source::with_source;
use coqui_peer::PeerId as Fingerprint;

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
        fingerprint: Fingerprint::of(certificate.as_ref()),
        certificate: certificate.as_ref().to_vec(),
    })
}

/// Dials a peer over `io`, completing the handshake before returning.
///
/// Returns the encrypted stream and the verified peer. `io` is any blocking byte stream.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails, including a refused peer certificate;
/// [`PeerError::refusal`] says why this side refused one.
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

/// A stream that can name the remote address it is connected to.
///
/// [`accept`] uses it to record where a refused peer came from. A stream without an address,
/// or one that is not TCP, is accepted with [`accept_from`].
pub trait PeerAddr {
    /// The remote address, when known.
    fn peer_addr(&self) -> Option<SocketAddr>;
}

impl PeerAddr for TcpStream {
    fn peer_addr(&self) -> Option<SocketAddr> {
        TcpStream::peer_addr(self).ok()
    }
}

/// Accepts a peer over `io`, completing the handshake before returning.
///
/// A client whose certificate the configured [`Trust`](crate::Trust) refuses fails the
/// handshake; when the trust is a store-backed pin set and the client proved it holds the
/// certificate's key, it is recorded as waiting under the address of `io`.
///
/// It returns a verified client, so it needs one: with a configuration from
/// [`server_config_without_client_auth`](crate::server_config_without_client_auth) it fails
/// with [`PeerError::Certificate`] after the handshake. Accept those with
/// [`TlsHandshake::finish_unauthenticated`](crate::TlsHandshake::finish_unauthenticated), or
/// with rustls's or tokio-rustls's own acceptor, which need nothing from this crate.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails; [`PeerError::refusal`] says why this side
/// refused the peer certificate, when it did.
pub fn accept<S: Read + Write + PeerAddr>(
    config: Arc<ServerConfig>,
    io: S,
) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError> {
    let source = io.peer_addr();
    accept_as(config, io, source)
}

/// [`accept`] for a stream that is not a [`TcpStream`], with the address it came from given.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails; [`PeerError::refusal`] says why this side
/// refused the peer certificate, when it did.
pub fn accept_from<S: Read + Write>(
    config: Arc<ServerConfig>,
    io: S,
    source: SocketAddr,
) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError> {
    accept_as(config, io, Some(source))
}

fn accept_as<S: Read + Write>(
    config: Arc<ServerConfig>,
    mut io: S,
    source: Option<SocketAddr>,
) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError> {
    let mut connection = ServerConnection::new(config).map_err(|_| PeerError::Tls)?;
    with_source(source, || {
        while connection.is_handshaking() {
            connection.complete_io(&mut io).map_err(PeerError::Io)?;
        }
        Ok::<(), PeerError>(())
    })?;
    let peer = identity_of(connection.peer_certificates())?;
    Ok((StreamOwned::new(connection, io), peer))
}
