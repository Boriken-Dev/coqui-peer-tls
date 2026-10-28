//! Server configurations built for one connection each: addresses from the host, session state
//! shared from one base, and the refusal kept for a host that sees only the alert.
#![cfg(feature = "generate")]

use std::sync::Arc;

use coqui_peer::Handshake;
use coqui_peer_tls::{
    Identity, PeerError, Policy, ServerConfigs, TlsHandshake, Trust, client_config_with,
};
use rustls::{Connection, HandshakeKind};

const ALPN: &[u8] = b"connection-test/1";

fn at(text: &str) -> std::net::SocketAddr {
    text.parse().expect("an address")
}

/// Runs a client handshake against a server one in memory until both are complete and the
/// server's session tickets reached the client; the client's connection.
fn handshake(mut server: TlsHandshake, mut dialer: TlsHandshake) -> Result<Connection, PeerError> {
    for _ in 0..16 {
        while let Some(bytes) = dialer.transmit()? {
            server.receive(&bytes)?;
        }
        while let Some(bytes) = server.transmit()? {
            dialer.receive(&bytes)?;
        }
        // A TLS 1.3 server queues its tickets on the client's Finished, so they are drained
        // in the same round that completes it.
        if server.is_complete() && dialer.is_complete() {
            break;
        }
    }
    Ok(dialer.finish()?.session)
}

fn resumable() -> Policy {
    let mut policy = Policy::modern();
    policy.allow_resumption = true;
    policy
}

#[test]
fn two_connections_from_one_base_share_their_sessions() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let policy = resumable();
    let configs = ServerConfigs::new(&identity, &Trust::AnyWithKeyProof, &[ALPN], &policy)?;
    let client_config =
        Arc::new(client_config_with(&client, &Trust::AnyWithKeyProof, &[ALPN], &policy)?.config);
    let mut kinds = Vec::new();
    for port in [4000, 4001] {
        let connection =
            configs.for_connection(at(&format!("192.0.2.7:{port}")), at("198.51.100.1:443"))?;
        let session = handshake(
            TlsHandshake::server(connection.config(), None)?,
            TlsHandshake::client(Arc::clone(&client_config))?,
        )?;
        kinds.push(session.handshake_kind());
    }
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
    Ok(())
}

#[test]
fn connections_from_separate_bases_do_not_resume() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let policy = resumable();
    let client_config =
        Arc::new(client_config_with(&client, &Trust::AnyWithKeyProof, &[ALPN], &policy)?.config);
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let configs = ServerConfigs::new(&identity, &Trust::AnyWithKeyProof, &[ALPN], &policy)?;
        let connection = configs.for_connection(at("192.0.2.7:4000"), at("198.51.100.1:443"))?;
        let session = handshake(
            TlsHandshake::server(connection.config(), None)?,
            TlsHandshake::client(Arc::clone(&client_config))?,
        )?;
        kinds.push(session.handshake_kind());
    }
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Full)]
    );
    Ok(())
}

#[test]
fn without_resumption_no_connection_resumes() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let configs = ServerConfigs::new(
        &identity,
        &Trust::AnyWithKeyProof,
        &[ALPN],
        &Policy::modern(),
    )?;
    let client_config = Arc::new(
        client_config_with(&client, &Trust::AnyWithKeyProof, &[ALPN], &resumable())?.config,
    );
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let connection = configs.for_connection(at("192.0.2.7:4000"), at("198.51.100.1:443"))?;
        let session = handshake(
            TlsHandshake::server(connection.config(), None)?,
            TlsHandshake::client(Arc::clone(&client_config))?,
        )?;
        kinds.push(session.handshake_kind());
    }
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Full)]
    );
    Ok(())
}

#[cfg(feature = "acl")]
#[test]
fn a_resumed_session_still_meets_the_address_rules() -> Result<(), PeerError> {
    use coqui_net_acl::{Acl, Action, Rule};
    use coqui_peer_tls::Refusal;

    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let mut policy = resumable();
    policy.acl = Some(Acl {
        rules: vec![Rule::new(
            Action::Deny,
            "203.0.113.0/24".parse().expect("a network"),
        )],
        default: Action::Permit,
    });
    let configs = ServerConfigs::new(&identity, &Trust::AnyWithKeyProof, &[ALPN], &policy)?;
    let client_config =
        Arc::new(client_config_with(&client, &Trust::AnyWithKeyProof, &[ALPN], &policy)?.config);
    let admitted = configs.for_connection(at("192.0.2.7:4000"), at("198.51.100.1:443"))?;
    handshake(
        TlsHandshake::server(admitted.config(), None)?,
        TlsHandshake::client(Arc::clone(&client_config))?,
    )?;
    // The client holds a ticket now; from a denied address it is refused at the hello.
    let denied = configs.for_connection(at("203.0.113.9:4000"), at("198.51.100.1:443"))?;
    let refused = handshake(
        TlsHandshake::server(denied.config(), None)?,
        TlsHandshake::client(client_config)?,
    );
    assert!(refused.is_err());
    assert_eq!(
        denied.refusal(),
        Some(Refusal::AddressDenied { rule: Some(0) })
    );
    Ok(())
}
