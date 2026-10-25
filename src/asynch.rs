//! Async dial and accept over `tokio-rustls`, for any `AsyncRead + AsyncWrite` stream.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::server::ClientHello;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsConnector, client, server};

use crate::error::PeerError;
use crate::identity::PeerIdentity;
use crate::stream::{SERVER_NAME, identity_of};

/// Dials a peer over `io`, completing the handshake before returning.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails, including a refused peer certificate.
pub async fn dial<S>(
    config: Arc<ClientConfig>,
    io: S,
) -> Result<(client::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(SERVER_NAME).map_err(|_| PeerError::Tls)?;
    let stream = TlsConnector::from(config)
        .connect(name, io)
        .await
        .map_err(PeerError::Io)?;
    let peer = identity_of(stream.get_ref().1.peer_certificates())?;
    Ok((stream, peer))
}

/// Accepts a peer over `io`, completing the handshake before returning.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails.
pub async fn accept<S>(
    config: Arc<ServerConfig>,
    io: S,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = tokio_rustls::TlsAcceptor::from(config)
        .accept(io)
        .await
        .map_err(PeerError::Io)?;
    let peer = identity_of(stream.get_ref().1.peer_certificates())?;
    Ok((stream, peer))
}

/// Accepts a peer over `io`, choosing the configuration from the ClientHello (for example
/// by its offered ALPN protocols), so one port can serve peers and other clients.
///
/// # Errors
///
/// [`PeerError::Io`] when the hello cannot be read or the handshake fails.
pub async fn accept_with<S>(
    io: S,
    select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io)
        .await
        .map_err(PeerError::Io)?;
    let config = select(&start.client_hello());
    let stream = start.into_stream(config).await.map_err(PeerError::Io)?;
    let peer = identity_of(stream.get_ref().1.peer_certificates())?;
    Ok((stream, peer))
}
