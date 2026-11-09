//! The configuration builders: the settings by name, and the client authentication as a value. Run with
//! `--all-features`.
#![cfg(all(feature = "generate", feature = "tokio"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coqui_peer_tls::{
    Addressed, ClientAuth, ClientBuilder, Identity, PairConfig, PeerClientVerifier, PeerError,
    PeerId, PeerServerVerifier, Pins, Policy, ServerAuth, ServerBuilder, Trust, accept, dial,
};

const ALPN: &[u8] = b"builder/1";

fn pinned(fingerprint: PeerId) -> Trust {
    Trust::Pinned(Pins::fixed([fingerprint]))
}

/// One echo over loopback; the server's view of the client's fingerprint, if it presented one.
fn echo(server: rustls::ServerConfig, client: rustls::ClientConfig) -> Option<PeerId> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let (mut stream, peer) = accept(Arc::new(server), socket).ok()?;
        let mut four = [0u8; 4];
        stream.read_exact(&mut four).ok()?;
        stream.write_all(&four).ok()?;
        stream.flush().ok()?;
        Some(peer.fingerprint)
    });
    let socket = TcpStream::connect(address).unwrap();
    let (mut stream, _) = dial(Arc::new(client), socket).ok()?;
    stream.write_all(b"ping").ok()?;
    stream.flush().ok()?;
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).ok()?;
    assert_eq!(stream.conn.alpn_protocol(), Some(ALPN));
    served.join().unwrap()
}

#[test]
fn a_required_client_certificate_is_pinned_both_ways() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let built_server =
        ServerBuilder::new(&server, ClientAuth::Required(pinned(client.fingerprint())))
            .alpn([ALPN])
            .build()
            .unwrap();
    assert!(built_server.non_defaults.is_empty());
    let built_client = ClientBuilder::new(pinned(server.fingerprint()))
        .identity(&client)
        .alpn([ALPN])
        .build()
        .unwrap();
    assert_eq!(
        echo(built_server.config, built_client.config),
        Some(client.fingerprint())
    );
}

#[test]
fn no_client_auth_is_a_value_the_server_takes() {
    let server = Identity::generate().unwrap();
    let built_server = ServerBuilder::new(&server, ClientAuth::None)
        .alpn([ALPN])
        .build()
        .unwrap();
    let built_client = ClientBuilder::new(pinned(server.fingerprint()))
        .alpn([ALPN])
        .build()
        .unwrap();
    assert_eq!(echo(built_server.config, built_client.config), None);
}

#[test]
fn a_verifier_of_the_hosts_own_is_a_value_each_side_takes() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let client_verifier = PeerClientVerifier::builder(&pinned(client.fingerprint()))
        .build()
        .unwrap();
    let server_verifier =
        PeerServerVerifier::new(&pinned(server.fingerprint()), &Policy::default()).unwrap();
    let built_server = ServerBuilder::new(&server, ClientAuth::Verifier(client_verifier))
        .alpn([ALPN])
        .build()
        .unwrap();
    let built_client = ClientBuilder::new(ServerAuth::Verifier(server_verifier))
        .identity(&client)
        .alpn([ALPN])
        .build()
        .unwrap();
    assert_eq!(
        echo(built_server.config, built_client.config),
        Some(client.fingerprint())
    );
}

#[test]
fn the_policy_reaches_the_configuration_and_its_non_defaults_are_reported() {
    let server = Identity::generate().unwrap();
    let policy = {
        let mut policy = Policy::default();
        policy.allow_resumption = true;
        policy
    };
    let builder = ServerBuilder::new(&server, ClientAuth::None).policy(policy.clone());
    assert_eq!(builder.non_defaults().len(), 1);
    let built = builder.build().unwrap();
    assert_eq!(built.non_defaults.len(), 1);
    assert_eq!(built.non_defaults[0].setting, "allow_resumption");
    let client = ClientBuilder::new(pinned(server.fingerprint()))
        .policy(policy)
        .build()
        .unwrap();
    assert_eq!(client.non_defaults[0].setting, "allow_resumption");
}

#[test]
fn a_policy_the_provider_cannot_serve_is_refused_at_build() {
    let server = Identity::generate().unwrap();
    let policy = {
        let mut policy = Policy::default();
        policy.cipher_suites = Some(vec!["NOT_A_SUITE".to_owned()]);
        policy
    };
    assert!(matches!(
        ServerBuilder::new(&server, ClientAuth::None)
            .policy(policy)
            .build(),
        Err(PeerError::Policy(_))
    ));
}

#[test]
fn a_listener_takes_a_configuration_per_connection() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let configs = ServerBuilder::new(&server, ClientAuth::Required(pinned(client.fingerprint())))
        .alpn([ALPN])
        .configs()
        .unwrap();
    let source = "127.0.0.1:50000".parse().unwrap();
    let local = "127.0.0.1:7000".parse().unwrap();
    let connection = configs.for_connection(source, local).unwrap();
    let built_client = ClientBuilder::new(pinned(server.fingerprint()))
        .identity(&client)
        .alpn([ALPN])
        .build()
        .unwrap();
    let seen = echo(
        Arc::try_unwrap(connection.config()).unwrap_or_else(|shared| (*shared).clone()),
        built_client.config,
    );
    assert_eq!(seen, Some(client.fingerprint()));
}

#[test]
fn pair_config_is_plain_data_assigned_by_field() {
    let mut config = PairConfig::default();
    config.alpn = b"mine/1".to_vec();
    config.timeout = Duration::from_secs(5);
    config.policy = Policy::modern();
    assert_eq!(config.alpn, b"mine/1");
    assert_eq!(config.timeout, Duration::from_secs(5));
    assert_eq!(config.policy, Policy::modern());
    assert_ne!(config, PairConfig::default());
}

/// The window a generated certificate carries, in Unix seconds.
fn window(identity: &Identity) -> (i64, i64) {
    let (_, certificate) = x509_parser::parse_x509_certificate(identity.certificate_der()).unwrap();
    let validity = certificate.validity();
    (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    )
}

fn seconds(at: SystemTime) -> i64 {
    i64::try_from(at.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap()
}

#[test]
fn the_identity_builder_covers_each_way_to_say_a_window() {
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let end = start + Duration::from_secs(86_400);
    let explicit = Identity::builder()
        .not_before(start)
        .not_after(end)
        .generate()
        .unwrap();
    assert_eq!(window(&explicit), (seconds(start), seconds(end)));
    let from_start = Identity::builder()
        .not_before(start)
        .valid_for(Duration::from_secs(86_400))
        .generate()
        .unwrap();
    assert_eq!(window(&from_start), (seconds(start), seconds(end)));
    let before = seconds(SystemTime::now());
    let from_now = Identity::builder()
        .valid_for(Duration::from_secs(3600))
        .generate()
        .unwrap();
    let (not_before, not_after) = window(&from_now);
    assert!(not_before >= before && not_before <= before + 5);
    assert_eq!(not_after - not_before, 3600);
    assert!(Identity::builder().generate().is_ok());
    assert!(matches!(
        Identity::builder().valid_for(Duration::ZERO).generate(),
        Err(PeerError::Certificate)
    ));
}

#[test]
fn the_identity_builder_keeps_one_end_and_the_last_setter_wins() {
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let end = start + Duration::from_secs(7200);
    let by_length_last = Identity::builder()
        .not_before(start)
        .not_after(start + Duration::from_secs(60))
        .valid_for(Duration::from_secs(7200))
        .generate()
        .unwrap();
    assert_eq!(window(&by_length_last), (seconds(start), seconds(end)));
    let by_end_last = Identity::builder()
        .not_before(start)
        .valid_for(Duration::from_secs(60))
        .not_after(end)
        .generate()
        .unwrap();
    assert_eq!(window(&by_end_last), (seconds(start), seconds(end)));
}

/// A stream wrapped in `Addressed` is accepted as a TCP stream is.
#[test]
fn an_addressed_stream_is_accepted() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let built_server =
        ServerBuilder::new(&server, ClientAuth::Required(pinned(client.fingerprint())))
            .alpn([ALPN])
            .build()
            .unwrap();
    let built_client = ClientBuilder::new(pinned(server.fingerprint()))
        .identity(&client)
        .alpn([ALPN])
        .build()
        .unwrap();
    let server_config = Arc::new(built_server.config);
    let client_config = Arc::new(built_client.config);
    let source: std::net::SocketAddr = "127.0.0.1:50000".parse().unwrap();
    let local: std::net::SocketAddr = "127.0.0.1:7000".parse().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::clone(&server_config);
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let wrapped = Addressed::new(socket, source).local(local);
        let (stream, peer) = accept(config, wrapped).ok()?;
        let mut stream = rustls::StreamOwned::new(stream.conn, stream.sock.into_inner());
        let mut four = [0u8; 4];
        stream.read_exact(&mut four).ok()?;
        stream.write_all(&four).ok()?;
        stream.flush().ok()?;
        Some(peer.fingerprint)
    });
    let socket = TcpStream::connect(address).unwrap();
    let (mut stream, _) = dial(Arc::clone(&client_config), socket).unwrap();
    stream.write_all(b"ping").unwrap();
    stream.flush().unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).unwrap();
    assert_eq!(served.join().unwrap(), Some(client.fingerprint()));
}
