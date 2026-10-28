//! A peer that lost trust is refused at its next connection: TLS session resumption, which
//! would skip the certificate check, is off unless the policy allows it.
#![cfg(all(feature = "generate", feature = "tokio"))]

use std::sync::Arc;

use coqui_peer_tls::{
    CLIENT_AUTH_SETTING, Identity, PeerError, Pins, Policy, TlsVersion, Trust, TrustStore,
    TrustStoreExt, asynch, client_config_with, client_config_without_identity_with,
    server_config_with, server_config_without_client_auth_with,
};
use rustls::{ClientConfig, HandshakeKind, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"resumption-test/1";

/// A handshake and an echo; the kind of handshake each side saw, or its error.
async fn link(
    server: &Arc<ServerConfig>,
    client: &Arc<ClientConfig>,
) -> (
    Result<HandshakeKind, PeerError>,
    Result<HandshakeKind, PeerError>,
) {
    let (near, far) = tokio::io::duplex(16384);
    let server = server.clone();
    let accepting = tokio::spawn(async move {
        let (mut stream, _) = asynch::accept_from(server, far, ([192, 0, 2, 1], 1).into()).await?;
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).await.map_err(PeerError::Io)?;
        stream.write_all(&ping).await.map_err(PeerError::Io)?;
        stream.flush().await.map_err(PeerError::Io)?;
        Ok(stream.get_ref().1.handshake_kind().unwrap())
    });
    let dialed = async {
        let (mut stream, _) = asynch::dial(client.clone(), near).await?;
        stream.write_all(b"ping").await.map_err(PeerError::Io)?;
        let mut pong = [0u8; 4];
        stream.read_exact(&mut pong).await.map_err(PeerError::Io)?;
        Ok(stream.get_ref().1.handshake_kind().unwrap())
    }
    .await;
    (accepting.await.unwrap(), dialed)
}

fn policy(version: TlsVersion) -> Policy {
    let mut policy = Policy::intermediate();
    policy.tls_versions = vec![version];
    policy
}

fn store() -> (tempfile::TempDir, TrustStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    (directory, store)
}

/// A server trusting the clients its store accepted refuses a client removed from it, even
/// though the client remembers the session it had.
async fn server_refuses_a_removed_client(version: TlsVersion) {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (_directory, peers) = store();
    let id = peers.accept_certificate(client.certificate_der()).unwrap();
    let policy = policy(version);
    let trust = Trust::Pinned(Pins::store(peers.clone()));
    let server_config = Arc::new(
        server_config_with(&server, &trust, &[ALPN], &policy)
            .unwrap()
            .config,
    );
    let server_pin = Trust::Pinned(Pins::fixed([server.fingerprint()]));
    let client_config = Arc::new(
        client_config_with(&client, &server_pin, &[ALPN], &policy)
            .unwrap()
            .config,
    );

    let (accepted, dialed) = link(&server_config, &client_config).await;
    assert_eq!(accepted.unwrap(), HandshakeKind::Full);
    assert_eq!(dialed.unwrap(), HandshakeKind::Full);

    assert!(peers.remove(&id).unwrap());
    let (accepted, _) = link(&server_config, &client_config).await;
    assert!(
        accepted.is_err(),
        "TLS {version}: a removed client was let in by a {:?} handshake",
        accepted.unwrap()
    );
}

/// A client trusting the servers its store accepted refuses a server removed from it, even
/// though it remembers the session it had.
async fn client_refuses_a_removed_server(version: TlsVersion) {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (_directory, peers) = store();
    let id = peers.accept_certificate(server.certificate_der()).unwrap();
    let policy = policy(version);
    let client_pin = Trust::Pinned(Pins::fixed([client.fingerprint()]));
    let server_config = Arc::new(
        server_config_with(&server, &client_pin, &[ALPN], &policy)
            .unwrap()
            .config,
    );
    let trust = Trust::Pinned(Pins::store(peers.clone()));
    let client_config = Arc::new(
        client_config_with(&client, &trust, &[ALPN], &policy)
            .unwrap()
            .config,
    );

    let (accepted, dialed) = link(&server_config, &client_config).await;
    assert_eq!(accepted.unwrap(), HandshakeKind::Full);
    assert_eq!(dialed.unwrap(), HandshakeKind::Full);

    assert!(peers.remove(&id).unwrap());
    let (_, dialed) = link(&server_config, &client_config).await;
    assert!(
        dialed.is_err(),
        "TLS {version}: a removed server was trusted by a {:?} handshake",
        dialed.unwrap()
    );
}

#[tokio::test]
async fn a_removed_client_is_refused_over_tls13() {
    server_refuses_a_removed_client(TlsVersion::V1_3).await;
}

#[tokio::test]
async fn a_removed_client_is_refused_over_tls12() {
    server_refuses_a_removed_client(TlsVersion::V1_2).await;
}

#[tokio::test]
async fn a_removed_server_is_refused_over_tls13() {
    client_refuses_a_removed_server(TlsVersion::V1_3).await;
}

#[tokio::test]
async fn a_removed_server_is_refused_over_tls12() {
    client_refuses_a_removed_server(TlsVersion::V1_2).await;
}

/// A second connection between two trusted peers is a full handshake under every preset, and
/// a resumed one only when the policy allows it, which it then reports as a weakening.
#[tokio::test]
async fn resumption_is_an_opt_in_reported_as_a_weakening() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let server_pin = Trust::Pinned(Pins::fixed([server.fingerprint()]));
    let client_pin = Trust::Pinned(Pins::fixed([client.fingerprint()]));
    for policy in [Policy::modern(), Policy::intermediate(), Policy::legacy()] {
        assert!(!policy.allow_resumption);
        let built = server_config_with(&server, &client_pin, &[ALPN], &policy).unwrap();
        let server_config = Arc::new(built.config);
        let client_config = Arc::new(
            client_config_with(&client, &server_pin, &[ALPN], &policy)
                .unwrap()
                .config,
        );
        for _ in 0..2 {
            let (accepted, dialed) = link(&server_config, &client_config).await;
            assert_eq!(accepted.unwrap(), HandshakeKind::Full, "{}", policy.name);
            assert_eq!(dialed.unwrap(), HandshakeKind::Full, "{}", policy.name);
        }
    }

    let mut policy = Policy::modern();
    policy.allow_resumption = true;
    let built = server_config_with(&server, &client_pin, &[ALPN], &policy).unwrap();
    assert_eq!(built.weakened.len(), 1);
    assert_eq!(built.weakened[0].setting, "allow_resumption");
    assert_eq!(built.weakened[0].value, "true");
    let server_config = Arc::new(built.config);
    let client_config = Arc::new(
        client_config_with(&client, &server_pin, &[ALPN], &policy)
            .unwrap()
            .config,
    );
    let (accepted, _) = link(&server_config, &client_config).await;
    assert_eq!(accepted.unwrap(), HandshakeKind::Full);
    let (accepted, dialed) = link(&server_config, &client_config).await;
    assert_eq!(accepted.unwrap(), HandshakeKind::Resumed);
    assert_eq!(dialed.unwrap(), HandshakeKind::Resumed);
}

/// A handshake and an echo with a server that asks for no client certificate, accepted by
/// tokio-rustls directly; the kind of handshake each side saw.
async fn link_server_tls(
    server: &Arc<ServerConfig>,
    client: &Arc<ClientConfig>,
) -> (HandshakeKind, HandshakeKind) {
    let (near, far) = tokio::io::duplex(16384);
    let acceptor = tokio_rustls::TlsAcceptor::from(server.clone());
    let accepting = tokio::spawn(async move {
        let mut stream = acceptor.accept(far).await.unwrap();
        assert!(stream.get_ref().1.peer_certificates().is_none());
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).await.unwrap();
        stream.write_all(&ping).await.unwrap();
        stream.flush().await.unwrap();
        stream.get_ref().1.handshake_kind().unwrap()
    });
    let (mut stream, _) = asynch::dial(client.clone(), near).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong).await.unwrap();
    let dialed = stream.get_ref().1.handshake_kind().unwrap();
    (accepting.await.unwrap(), dialed)
}

/// Server TLS keeps resumption off under every preset and either version, and resumes only
/// when the policy allows it, reported beside the missing client authentication.
#[tokio::test]
async fn server_tls_configurations_resume_only_when_allowed() {
    let server = Identity::generate().unwrap();
    let server_pin = Trust::Pinned(Pins::fixed([server.fingerprint()]));
    let presets = [
        Policy::modern(),
        Policy::intermediate(),
        Policy::legacy(),
        policy(TlsVersion::V1_2),
    ];
    for policy in presets {
        assert!(!policy.allow_resumption);
        let server_config = Arc::new(
            server_config_without_client_auth_with(&server, &[ALPN], &policy)
                .unwrap()
                .config,
        );
        let client_config = Arc::new(
            client_config_without_identity_with(&server_pin, &[ALPN], &policy)
                .unwrap()
                .config,
        );
        for _ in 0..2 {
            let (accepted, dialed) = link_server_tls(&server_config, &client_config).await;
            assert_eq!(accepted, HandshakeKind::Full, "{}", policy.name);
            assert_eq!(dialed, HandshakeKind::Full, "{}", policy.name);
        }
    }

    let mut policy = Policy::modern();
    policy.allow_resumption = true;
    let built = server_config_without_client_auth_with(&server, &[ALPN], &policy).unwrap();
    let settings: Vec<&str> = built
        .weakened
        .iter()
        .map(|weakening| weakening.setting.as_str())
        .collect();
    assert_eq!(settings, ["allow_resumption", CLIENT_AUTH_SETTING]);
    let server_config = Arc::new(built.config);
    let built = client_config_without_identity_with(&server_pin, &[ALPN], &policy).unwrap();
    assert_eq!(built.weakened.len(), 1);
    let client_config = Arc::new(built.config);
    let (accepted, _) = link_server_tls(&server_config, &client_config).await;
    assert_eq!(accepted, HandshakeKind::Full);
    let (accepted, dialed) = link_server_tls(&server_config, &client_config).await;
    assert_eq!(accepted, HandshakeKind::Resumed);
    assert_eq!(dialed, HandshakeKind::Resumed);
}
