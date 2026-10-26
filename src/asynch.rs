//! Async dial and accept over `tokio-rustls`, for any `AsyncRead + AsyncWrite` stream.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::server::ClientHello;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsConnector, client, server};

use crate::error::PeerError;
use crate::identity::PeerIdentity;
use crate::source::with_source;
use crate::stream::{PeerAddr, SERVER_NAME, identity_of};

/// Dials a peer over `io`, completing the handshake before returning.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails, including a refused peer certificate;
/// [`PeerError::refusal`] says why this side refused one.
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

impl PeerAddr for tokio::net::TcpStream {
    fn peer_addr(&self) -> Option<SocketAddr> {
        tokio::net::TcpStream::peer_addr(self).ok()
    }
}

/// Polls `future` with `source` as the address the verifiers record, since their callbacks
/// run inside the poll.
async fn sourced<F: Future>(source: Option<SocketAddr>, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| with_source(source, || future.as_mut().poll(context))).await
}

/// Accepts a peer over `io`, completing the handshake before returning.
///
/// A peer that proved its key and is refused by a store-backed pin set is recorded as waiting
/// under the address of `io`.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails; [`PeerError::refusal`] says why this side
/// refused the peer certificate, when it did.
pub async fn accept<S>(
    config: Arc<ServerConfig>,
    io: S,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin + PeerAddr,
{
    let source = io.peer_addr();
    accept_as(config, io, source).await
}

/// [`accept`] for a stream that is not a TCP stream, with the address it came from given.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails; [`PeerError::refusal`] says why this side
/// refused the peer certificate, when it did.
pub async fn accept_from<S>(
    config: Arc<ServerConfig>,
    io: S,
    source: SocketAddr,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_as(config, io, Some(source)).await
}

async fn accept_as<S>(
    config: Arc<ServerConfig>,
    io: S,
    source: Option<SocketAddr>,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = sourced(source, tokio_rustls::TlsAcceptor::from(config).accept(io))
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
/// [`PeerError::Io`] when the hello cannot be read or the handshake fails;
/// [`PeerError::refusal`] says why this side refused the peer certificate, when it did.
pub async fn accept_with<S>(
    io: S,
    select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin + PeerAddr,
{
    let source = io.peer_addr();
    accept_with_as(io, source, select).await
}

/// [`accept_with`] for a stream that is not a TCP stream, with the address it came from given.
///
/// # Errors
///
/// [`PeerError::Io`] when the hello cannot be read or the handshake fails;
/// [`PeerError::refusal`] says why this side refused the peer certificate, when it did.
pub async fn accept_with_from<S>(
    io: S,
    source: SocketAddr,
    select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_with_as(io, Some(source), select).await
}

async fn accept_with_as<S>(
    io: S,
    source: Option<SocketAddr>,
    select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>,
) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io)
        .await
        .map_err(PeerError::Io)?;
    let config = select(&start.client_hello());
    let stream = sourced(source, start.into_stream(config))
        .await
        .map_err(PeerError::Io)?;
    let peer = identity_of(stream.get_ref().1.peer_certificates())?;
    Ok((stream, peer))
}
