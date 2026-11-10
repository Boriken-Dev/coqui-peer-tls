//! Short forms of the builders for the tests: each is one expression over `ServerBuilder`,
//! `ClientBuilder` and `Addressed`, so a test reads as a configuration, not as a builder chain.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use coqui_builder::builder::BuildError;
use coqui_peer_tls::{
    Addressed, Alpn, Built, ClientAuth, ClientBuilder, Identity, PeerClientVerifier, PeerError,
    PeerIdentity, PeerServerVerifier, Policy, ServerAuth, ServerBuilder, Trust,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, ServerConfig, ServerConnection, StreamOwned};

/// A client configuration under the default policy that presents `identity` and verifies the
/// server by `trust`.
pub fn client_config(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
) -> Result<ClientConfig, PeerError> {
    ClientBuilder::new()
        .server(trust.clone())
        .identity(identity)
        .alpn(alpns(alpn))
        .build()
        .map_err(flat)
        .map(|built| built.config)
}

/// A client configuration under `policy`.
pub fn client_config_with(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    ClientBuilder::new()
        .server(trust.clone())
        .identity(identity)
        .alpn(alpns(alpn))
        .policy(policy.clone())
        .build()
        .map_err(flat)
}

/// A client configuration under the default policy that presents no certificate.
pub fn client_config_without_identity(
    trust: &Trust,
    alpn: &[&[u8]],
) -> Result<ClientConfig, PeerError> {
    ClientBuilder::new()
        .server(trust.clone())
        .alpn(alpns(alpn))
        .build()
        .map_err(flat)
        .map(|built| built.config)
}

/// A client configuration under `policy` that presents no certificate.
pub fn client_config_without_identity_with(
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    ClientBuilder::new()
        .server(trust.clone())
        .alpn(alpns(alpn))
        .policy(policy.clone())
        .build()
        .map_err(flat)
}

/// A client configuration under `policy` that verifies the server with `verifier`, presenting
/// `identity` or, for `None`, no certificate.
pub fn client_config_with_verifier(
    identity: Option<&Identity>,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    let mut builder = ClientBuilder::new()
        .server(ServerAuth::Verifier(verifier))
        .alpn(alpns(alpn))
        .policy(policy.clone());
    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }
    builder.build().map_err(flat)
}

/// A server configuration under the default policy that presents `identity` and requires a client
/// certificate trusted by `trust`.
pub fn server_config(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
) -> Result<ServerConfig, PeerError> {
    ServerBuilder::new()
        .identity(identity)
        .client_auth(ClientAuth::Required(trust.clone()))
        .alpn(alpns(alpn))
        .build()
        .map_err(flat)
        .map(|built| built.config)
}

/// A server configuration under `policy`, shared by every connection it accepts.
pub fn server_config_with(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ServerConfig>, PeerError> {
    ServerBuilder::new()
        .identity(identity)
        .client_auth(ClientAuth::Required(trust.clone()))
        .alpn(alpns(alpn))
        .policy(policy.clone())
        .build()
        .map_err(flat)
}

/// A server configuration under the default policy that asks for no client certificate.
pub fn server_config_without_client_auth(
    identity: &Identity,
    alpn: &[&[u8]],
) -> Result<ServerConfig, PeerError> {
    ServerBuilder::new()
        .identity(identity)
        .client_auth(ClientAuth::None)
        .alpn(alpns(alpn))
        .build()
        .map_err(flat)
        .map(|built| built.config)
}

/// `server_config_without_client_auth` under `policy`.
pub fn server_config_without_client_auth_with(
    identity: &Identity,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ServerConfig>, PeerError> {
    ServerBuilder::new()
        .identity(identity)
        .client_auth(ClientAuth::None)
        .alpn(alpns(alpn))
        .policy(policy.clone())
        .build()
        .map_err(flat)
}

/// A server configuration under `policy` that verifies clients with `verifier`.
pub fn server_config_with_verifier(
    identity: &Identity,
    verifier: Arc<dyn ClientCertVerifier>,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ServerConfig>, PeerError> {
    ServerBuilder::new()
        .identity(identity)
        .client_auth(ClientAuth::Verifier(verifier))
        .alpn(alpns(alpn))
        .policy(policy.clone())
        .build()
        .map_err(flat)
}

type Accepted<S> = Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError>;

/// The stream `accept` wraps, as the stream it was given.
fn unwrapped<S: Read + Write>(
    accepted: Result<(StreamOwned<ServerConnection, Addressed<S>>, PeerIdentity), PeerError>,
) -> Accepted<S> {
    let (stream, peer) = accepted?;
    Ok((
        StreamOwned::new(stream.conn, stream.sock.into_inner()),
        peer,
    ))
}

/// Accepts over a stream that is not a TCP stream, with the address it came from given.
pub fn accept_from<S: Read + Write>(
    config: Arc<ServerConfig>,
    io: S,
    source: SocketAddr,
) -> Accepted<S> {
    unwrapped(coqui_peer_tls::accept(config, Addressed::new(io, source)))
}

/// As `accept_from`, with the local address the connection arrived at as well.
pub fn accept_at<S: Read + Write>(
    config: Arc<ServerConfig>,
    io: S,
    source: SocketAddr,
    local: SocketAddr,
) -> Accepted<S> {
    unwrapped(coqui_peer_tls::accept(
        config,
        Addressed::new(io, source).local(local),
    ))
}

/// The configurations of a listener, one per connection, presenting `identity` and requiring a
/// client certificate `trust` accepts.
pub fn server_configs(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<coqui_peer_tls::ServerConfigs, PeerError> {
    ServerBuilder::new()
        .identity(identity)
        .client_auth(ClientAuth::Required(trust.clone()))
        .alpn(alpns(alpn))
        .policy(policy.clone())
        .configs()
        .map_err(flat)
}

/// The verifiers `Trust` once built, each one expression over the verifier builders.
pub trait TrustVerifiers {
    /// The client verifier under the default policy, with no addresses.
    fn client_cert_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, PeerError>;
    /// The client verifier under `policy`, with no addresses.
    fn client_cert_verifier_with(
        &self,
        policy: &Policy,
    ) -> Result<Arc<dyn ClientCertVerifier>, PeerError>;
    /// The client verifier under `policy` for one connection's addresses.
    fn client_cert_verifier_for(
        &self,
        policy: &Policy,
        source: SocketAddr,
        local: SocketAddr,
    ) -> Result<Arc<dyn ClientCertVerifier>, PeerError>;
    /// The server verifier under the default policy.
    fn server_cert_verifier(&self) -> Result<Arc<dyn ServerCertVerifier>, PeerError>;
    /// The server verifier under `policy`.
    fn server_cert_verifier_with(
        &self,
        policy: &Policy,
    ) -> Result<Arc<dyn ServerCertVerifier>, PeerError>;
}

impl TrustVerifiers for Trust {
    fn client_cert_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, PeerError> {
        PeerClientVerifier::builder(self).build()
    }

    fn client_cert_verifier_with(
        &self,
        policy: &Policy,
    ) -> Result<Arc<dyn ClientCertVerifier>, PeerError> {
        PeerClientVerifier::builder(self)
            .policy(policy.clone())
            .build()
    }

    fn client_cert_verifier_for(
        &self,
        policy: &Policy,
        source: SocketAddr,
        local: SocketAddr,
    ) -> Result<Arc<dyn ClientCertVerifier>, PeerError> {
        PeerClientVerifier::builder(self)
            .policy(policy.clone())
            .addresses(source, local)
            .build()
    }

    fn server_cert_verifier(&self) -> Result<Arc<dyn ServerCertVerifier>, PeerError> {
        let verifier: Arc<dyn ServerCertVerifier> =
            PeerServerVerifier::new(self, &Policy::default())?;
        Ok(verifier)
    }

    fn server_cert_verifier_with(
        &self,
        policy: &Policy,
    ) -> Result<Arc<dyn ServerCertVerifier>, PeerError> {
        let verifier: Arc<dyn ServerCertVerifier> = PeerServerVerifier::new(self, policy)?;
        Ok(verifier)
    }
}

/// The protocol names a test gives as bytes, as the builders take them.
pub fn alpns(names: &[&[u8]]) -> Vec<Alpn> {
    names
        .iter()
        .map(|name| Alpn::try_from(*name).expect("a test's protocol name is text"))
        .collect()
}

/// A builder's failure as the crate's error; a test supplies every input.
pub fn flat(error: BuildError<PeerError>) -> PeerError {
    match error {
        BuildError::Failed(error) => error,
        other => panic!("{other}"),
    }
}
