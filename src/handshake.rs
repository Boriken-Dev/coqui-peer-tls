use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

use coqui_peer::{Established, Framing, Handshake, Method};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

use crate::certificate::certificate_key;
use crate::error::PeerError;
use crate::source::with_source;
use crate::stream::{SERVER_NAME, identity_of};

/// The TLS method: client and server configurations, each optional, that start handshakes.
///
/// ```no_run
/// # fn demo(client: rustls::ClientConfig, server: rustls::ServerConfig) {
/// let method = coqui_peer_tls::Tls::new()
///     .with_client(std::sync::Arc::new(client))
///     .with_server(std::sync::Arc::new(server));
/// # let _ = method;
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct Tls {
    client: Option<Arc<ClientConfig>>,
    server: Option<Arc<ServerConfig>>,
}

impl Tls {
    /// A method that can neither dial nor accept until configured.
    pub fn new() -> Self {
        Self::default()
    }

    /// This method able to dial with `config` (see [`client_config`](crate::client_config)).
    #[must_use]
    pub fn with_client(mut self, config: Arc<ClientConfig>) -> Self {
        self.client = Some(config);
        self
    }

    /// This method able to accept with `config` (see [`server_config`](crate::server_config)).
    #[must_use]
    pub fn with_server(mut self, config: Arc<ServerConfig>) -> Self {
        self.server = Some(config);
        self
    }
}

impl Method for Tls {
    type Handshake = TlsHandshake;

    fn name(&self) -> &'static str {
        crate::METHOD
    }

    fn initiate(&self) -> Result<TlsHandshake, PeerError> {
        let config = self.client.clone().ok_or(PeerError::Unsupported)?;
        TlsHandshake::client(config)
    }

    fn respond(&self, source: Option<SocketAddr>) -> Result<TlsHandshake, PeerError> {
        let config = self.server.clone().ok_or(PeerError::Unsupported)?;
        TlsHandshake::server(config, source)
    }
}

/// One TLS handshake, driven by the caller: rustls's own sans-IO connection.
///
/// A server records a refused, key-proven client as waiting under the `source` it was given,
/// exactly as [`accept`](crate::accept) does. After [`finish`](Handshake::finish) the
/// [`session`](Established::session) is the finished [`rustls::Connection`], which keeps any
/// application data that arrived with the last handshake bytes.
#[derive(Debug)]
pub struct TlsHandshake {
    connection: Connection,
    source: Option<SocketAddr>,
}

impl TlsHandshake {
    /// A handshake as the dialing side.
    ///
    /// # Errors
    ///
    /// [`PeerError::Tls`] when the connection cannot be created.
    pub fn client(config: Arc<ClientConfig>) -> Result<Self, PeerError> {
        let name = ServerName::try_from(SERVER_NAME).map_err(|_| PeerError::Tls)?;
        let connection = ClientConnection::new(config, name).map_err(|_| PeerError::Tls)?;
        Ok(Self {
            connection: connection.into(),
            source: None,
        })
    }

    /// A handshake as the accepting side; `source` is where the peer connected from.
    ///
    /// # Errors
    ///
    /// [`PeerError::Tls`] when the connection cannot be created.
    pub fn server(
        config: Arc<ServerConfig>,
        source: Option<SocketAddr>,
    ) -> Result<Self, PeerError> {
        let connection = ServerConnection::new(config).map_err(|_| PeerError::Tls)?;
        Ok(Self {
            connection: connection.into(),
            source,
        })
    }
}

impl Handshake for TlsHandshake {
    type Output = Connection;
    type Error = PeerError;

    fn framing(&self) -> Framing {
        Framing::Stream
    }

    fn receive(&mut self, input: &[u8]) -> Result<(), PeerError> {
        let mut cursor = Cursor::new(input);
        while usize::try_from(cursor.position()).unwrap_or(usize::MAX) < input.len() {
            let read = self
                .connection
                .read_tls(&mut cursor)
                .map_err(PeerError::Io)?;
            with_source(self.source, || self.connection.process_new_packets()).map_err(
                |error| PeerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            )?;
            if read == 0 {
                return Err(PeerError::Tls);
            }
        }
        Ok(())
    }

    fn transmit(&mut self) -> Result<Option<Vec<u8>>, PeerError> {
        if !self.connection.wants_write() {
            return Ok(None);
        }
        let mut out = Vec::new();
        self.connection.write_tls(&mut out).map_err(PeerError::Io)?;
        Ok((!out.is_empty()).then_some(out))
    }

    fn is_complete(&self) -> bool {
        !self.connection.is_handshaking()
    }

    fn finish(self) -> Result<Established<Connection>, PeerError> {
        if self.connection.is_handshaking() {
            return Err(PeerError::Tls);
        }
        let peer = identity_of(self.connection.peer_certificates())?;
        Ok(Established {
            peer: peer.fingerprint,
            key: Some(certificate_key(&peer.certificate)?),
            session: self.connection,
        })
    }
}
