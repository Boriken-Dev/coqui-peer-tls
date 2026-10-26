//! Async dial and accept over `tokio-rustls`, for any `AsyncRead + AsyncWrite` stream.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::server::ClientHello;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsConnector, client, server};

use std::time::Duration;

use coqui_peer::pair::{
    Paired, Pairing, PairingDesk, PairingJoiner, PairingResponder, Rotation, Shown,
};
use coqui_peer::{PeerId, TrustStore};

use crate::error::PeerError;
use crate::identity::{Identity, PeerIdentity};
use crate::pairing::{PairConfig, ResponderTrust};
use crate::source::with_source;
use crate::stream::{PeerAddr, default_name, identity_of};

/// Dials a peer over `io`, completing the handshake before returning. The server name sent
/// is [`SERVER_NAME`](crate::SERVER_NAME); [`dial_named`] sends another.
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
    dial_named(config, default_name()?, io).await
}

/// [`dial`] sending `name` as the server name, as [`crate::dial_named`] does.
///
/// # Errors
///
/// [`PeerError::Io`] when the handshake fails, including a refused server certificate;
/// [`PeerError::refusal`] says why this side refused one.
pub async fn dial_named<S>(
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    io: S,
) -> Result<(client::TlsStream<S>, PeerIdentity), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

/// Writes one framed message, as [`announce`](crate::announce) and the pairing exchange do.
async fn write_frame<S: AsyncWrite + Unpin>(io: &mut S, message: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let length = u32::try_from(message.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(message).await?;
    io.flush().await
}

/// Reads one framed message of at most [`coqui_peer::MAX_MESSAGE`] bytes.
async fn read_frame<S: AsyncRead + Unpin>(io: &mut S) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut length = [0u8; 4];
    io.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length > coqui_peer::MAX_MESSAGE {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut message = vec![0u8; length];
    io.read_exact(&mut message).await?;
    Ok(message)
}

/// The asynchronous [`PairDial`](crate::PairDial).
#[derive(Debug)]
pub struct PairDial<S> {
    tls: client::TlsStream<S>,
    joiner: PairingJoiner,
}

impl<S: AsyncRead + AsyncWrite + Unpin> PairDial<S> {
    /// What to show a person now, as [`crate::PairDial::shown`].
    pub fn shown(&self) -> Option<&Shown> {
        self.joiner.shown()
    }

    /// Runs the exchange to its end and accepts the responder in `store`, as
    /// [`crate::PairDial::finish`].
    ///
    /// # Errors
    ///
    /// As [`crate::PairDial::finish`].
    pub async fn finish(mut self, store: &TrustStore) -> Result<Paired, PeerError> {
        join_until(&mut self.tls, &mut self.joiner, |_| false).await?;
        let paired = self.joiner.finish()?;
        match store.accept_key(&paired.peer) {
            Ok(_) | Err(coqui_peer::Error::AlreadyAccepted) => {}
            Err(error) => return Err(error.into()),
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.tls).await;
        Ok(paired)
    }
}

async fn join_until<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut client::TlsStream<S>,
    joiner: &mut PairingJoiner,
    stop: impl Fn(&PairingJoiner) -> bool,
) -> Result<(), PeerError> {
    loop {
        while let Some(message) = joiner.transmit() {
            write_frame(tls, &message).await.map_err(PeerError::Io)?;
        }
        if joiner.is_complete() || stop(joiner) {
            return Ok(());
        }
        let message = read_frame(tls).await.map_err(PeerError::Io)?;
        if let Err(error) = joiner.receive(&message) {
            while let Some(message) = joiner.transmit() {
                let _ = write_frame(tls, &message).await;
            }
            return Err(error.into());
        }
    }
}

/// [`crate::pair_dial`] over an async stream.
///
/// # Errors
///
/// As [`crate::pair_dial`].
pub async fn pair_dial<S>(
    stream: S,
    identity: &Identity,
    pairing: Pairing,
    responder: &ResponderTrust,
    config: &PairConfig,
) -> Result<PairDial<S>, PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (client, name) = crate::pair_client_config(identity, &pairing, responder, config)?;
    let (tls, peer) = dial_named(Arc::new(client), name, stream).await?;
    let connection = tls.get_ref().1;
    let exporter = connection
        .export_keying_material([0u8; 32], crate::EXPORTER_LABEL, Some(&[]))
        .map_err(|_| PeerError::Tls)?;
    let channel = crate::pairing::channel(connection, exporter, identity, &peer, &config.alpn)?;
    let mut dial = PairDial {
        tls,
        joiner: pairing.join(channel)?,
    };
    join_until(&mut dial.tls, &mut dial.joiner, |joiner| {
        joiner.shown().is_some()
    })
    .await?;
    Ok(dial)
}

/// [`crate::pair_accept`] over an async stream; it waits for the operator without blocking
/// the runtime, and sweeps `desk` every second meanwhile so expiry is seen.
///
/// # Errors
///
/// As [`crate::pair_accept`].
pub async fn pair_accept<S>(
    stream: S,
    identity: &Identity,
    store: &TrustStore,
    desk: &PairingDesk,
    config: &PairConfig,
) -> Result<Paired, PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin + PeerAddr,
{
    let source = stream.peer_addr();
    pair_accept_as(stream, source, identity, store, desk, config).await
}

/// [`pair_accept`] for a stream that is not a TCP stream, with the address it came from given.
///
/// # Errors
///
/// As [`crate::pair_accept`].
pub async fn pair_accept_from<S>(
    stream: S,
    source: SocketAddr,
    identity: &Identity,
    store: &TrustStore,
    desk: &PairingDesk,
    config: &PairConfig,
) -> Result<Paired, PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pair_accept_as(stream, Some(source), identity, store, desk, config).await
}

async fn pair_accept_as<S>(
    stream: S,
    source: Option<SocketAddr>,
    identity: &Identity,
    store: &TrustStore,
    desk: &PairingDesk,
    config: &PairConfig,
) -> Result<Paired, PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server = Arc::new(crate::pair_server_config(identity, config)?);
    let (tls, _) = accept_as(server, stream, source).await?;
    pair_respond(tls, source, identity, store, desk, config).await
}

/// Runs the responder's side of pairing on a connection already accepted with
/// [`pair_server_config`](crate::pair_server_config) (for example chosen by
/// [`accept_with`] for a client that offered the pairing ALPN), as `identity`, for a client
/// from `source`.
///
/// # Errors
///
/// As [`crate::pair_accept`].
pub async fn pair_respond<S>(
    mut tls: server::TlsStream<S>,
    source: Option<SocketAddr>,
    identity: &Identity,
    store: &TrustStore,
    desk: &PairingDesk,
    config: &PairConfig,
) -> Result<Paired, PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connection = tls.get_ref().1;
    let peer = identity_of(connection.peer_certificates())?;
    let exporter = connection
        .export_keying_material([0u8; 32], crate::EXPORTER_LABEL, Some(&[]))
        .map_err(|_| PeerError::Tls)?;
    let channel = crate::pairing::channel(connection, exporter, identity, &peer, &config.alpn)?;
    let mut responder = PairingResponder::new(channel, store, desk, source);
    let result = respond(&mut tls, &mut responder, desk).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
    result?;
    Ok(responder.finish()?)
}

async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut server::TlsStream<S>,
    responder: &mut PairingResponder,
    desk: &PairingDesk,
) -> Result<(), PeerError> {
    loop {
        while let Some(message) = responder.transmit() {
            write_frame(tls, &message).await.map_err(PeerError::Io)?;
        }
        if responder.is_complete() {
            return Ok(());
        }
        let step = match responder.awaiting() {
            Some(ticket) => {
                let decision = loop {
                    let wait = tokio::time::timeout(Duration::from_secs(1), desk.decided(ticket));
                    match wait.await {
                        Ok(decision) => break decision,
                        Err(_) => desk.sweep(),
                    }
                };
                responder.resume(decision)
            }
            None => {
                let message = read_frame(tls).await.map_err(PeerError::Io)?;
                responder.receive(&message)
            }
        };
        if let Err(error) = step {
            while let Some(message) = responder.transmit() {
                let _ = write_frame(tls, &message).await;
            }
            return Err(error.into());
        }
    }
}

/// [`crate::announce`] over an async stream.
///
/// # Errors
///
/// As [`crate::announce`].
pub async fn announce<S: AsyncWrite + Unpin>(
    stream: &mut S,
    successor: &Identity,
) -> Result<(), PeerError> {
    let key = crate::certificate_key(successor.certificate_der())?;
    write_frame(stream, &Rotation::announce(&key))
        .await
        .map_err(PeerError::Io)
}

/// [`crate::receive_announcement`] over an async stream.
///
/// # Errors
///
/// As [`crate::receive_announcement`].
pub async fn receive_announcement<S: AsyncRead + Unpin>(
    stream: &mut S,
    store: &TrustStore,
    sender: &PeerIdentity,
) -> Result<PeerId, PeerError> {
    let message = read_frame(stream).await.map_err(PeerError::Io)?;
    crate::pairing::record_announcement(&message, store, sender)
}
