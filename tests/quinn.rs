//! A QUIC host (quinn) with a policy access control list: a configuration per incoming
//! connection, decided from the addresses quinn reports, the refusal kept for the host.
#![cfg(all(feature = "acl", feature = "generate"))]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use coqui_net_acl::{Acl, Action, Rule};
use coqui_peer_tls::{
    Identity, PeerError, Policy, Refusal, SERVER_NAME, ServerConfigs, Trust, client_config,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

const ALPN: &[u8] = b"quinn-test/1";

fn policy(rules: Vec<Rule>, default: Action) -> Policy {
    let mut policy = Policy::strict();
    policy.acl = Some(Acl { rules, default });
    policy
}

fn rule(action: Action, source: &str, fingerprint: Option<String>) -> Rule {
    let mut rule = Rule::new(action, source.parse().expect("a network"));
    rule.fingerprint = fingerprint;
    rule
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// What the server saw of one connection: whether it was established, and the refusal kept.
async fn serve_one(
    endpoint: quinn::Endpoint,
    configs: ServerConfigs,
) -> Result<(bool, Option<Refusal>), PeerError> {
    let incoming = endpoint.accept().await.expect("an incoming connection");
    let source = incoming.remote_address();
    let local = SocketAddr::new(
        incoming.local_ip().expect("the local address"),
        endpoint.local_addr().map_err(PeerError::Io)?.port(),
    );
    let connection = configs.for_connection(source, local)?;
    let crypto = QuicServerConfig::try_from(connection.config()).expect("a QUIC configuration");
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let established = match incoming.accept_with(Arc::new(config)) {
        Ok(connecting) => connecting.await.is_ok(),
        Err(_) => false,
    };
    Ok((established, connection.refusal()))
}

/// Dials the server as `client` and waits until the server ends the connection.
async fn dial(server: SocketAddr, client: &Identity) -> Result<(), PeerError> {
    let mut endpoint = quinn::Endpoint::client(loopback()).map_err(PeerError::Io)?;
    let tls = client_config(client, &Trust::AnyWithKeyProof, &[ALPN])?;
    let crypto = QuicClientConfig::try_from(tls).expect("a QUIC configuration");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connecting = endpoint
        .connect(server, SERVER_NAME)
        .expect("a connection attempt");
    // A refused client certificate surfaces after the client's own handshake has ended.
    if let Ok(connection) = connecting.await {
        connection.closed().await;
    }
    endpoint.wait_idle().await;
    Ok(())
}

async fn attempt(policy: &Policy, client: &Identity) -> Result<(bool, Option<Refusal>), PeerError> {
    let identity = Identity::generate()?;
    let configs = ServerConfigs::new(&identity, &Trust::AnyWithKeyProof, &[ALPN], policy)?;
    let tls = Arc::new(
        QuicServerConfig::try_from(Arc::new(coqui_peer_tls::server_config(
            &identity,
            &Trust::AnyWithKeyProof,
            &[ALPN],
        )?))
        .expect("a QUIC configuration"),
    );
    let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(tls), loopback())
        .map_err(PeerError::Io)?;
    let address = endpoint.local_addr().map_err(PeerError::Io)?;
    let served = tokio::spawn(serve_one(endpoint.clone(), configs));
    let dialled = tokio::time::timeout(std::time::Duration::from_secs(20), dial(address, client))
        .await
        .expect("the client finishes");
    let (established, refusal) = served.await.expect("the server task")?;
    dialled?;
    endpoint.close(0u32.into(), b"done");
    Ok((established, refusal))
}

#[tokio::test]
async fn an_admitted_address_connects() -> Result<(), PeerError> {
    let client = Identity::generate()?;
    let policy = policy(
        vec![rule(Action::Permit, "127.0.0.0/8", None)],
        Action::Deny,
    );
    assert_eq!(attempt(&policy, &client).await?, (true, None));
    Ok(())
}

#[tokio::test]
async fn a_denied_address_is_refused_with_its_rule() -> Result<(), PeerError> {
    let client = Identity::generate()?;
    let policy = policy(
        vec![rule(Action::Deny, "127.0.0.0/8", None)],
        Action::Permit,
    );
    assert_eq!(
        attempt(&policy, &client).await?,
        (false, Some(Refusal::AddressDenied { rule: Some(0) }))
    );
    Ok(())
}

#[tokio::test]
async fn a_denied_certificate_is_refused_with_its_rule() -> Result<(), PeerError> {
    let client = Identity::generate()?;
    let policy = policy(
        vec![rule(
            Action::Deny,
            "127.0.0.0/8",
            Some(client.fingerprint().to_string()),
        )],
        Action::Permit,
    );
    assert_eq!(
        attempt(&policy, &client).await?,
        (false, Some(Refusal::PeerDenied { rule: Some(0) }))
    );
    Ok(())
}
