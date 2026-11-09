//! The configuration builders: the settings by name, the client authentication as a value, and
//! the old functions as wrappers over them. Run with `--all-features`.
#![cfg(all(feature = "generate", feature = "tokio"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coqui_peer_tls::{
    ClientAuth, ClientBuilder, Identity, PairConfig, PeerError, PeerId, Pins, Policy,
    ServerBuilder, Trust, accept, dial,
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
fn a_verifier_of_the_hosts_own_replaces_the_trust() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let client_verifier = pinned(client.fingerprint()).client_cert_verifier().unwrap();
    let server_verifier = pinned(server.fingerprint()).server_cert_verifier().unwrap();
    let built_server = ServerBuilder::new(&server, ClientAuth::Verifier(client_verifier))
        .alpn([ALPN])
        .build()
        .unwrap();
    // The trust given to `new` is not read once a verifier is set: this one pins nobody.
    let built_client = ClientBuilder::new(pinned(client.fingerprint()))
        .verifier(server_verifier)
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
    let policy = Policy {
        allow_resumption: true,
        ..Policy::default()
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
    let policy = Policy {
        cipher_suites: Some(vec!["NOT_A_SUITE".to_owned()]),
        ..Policy::default()
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
fn the_pair_config_builder_sets_each_field_by_name() {
    let defaults = PairConfig::builder().build();
    assert_eq!(defaults, PairConfig::default());
    let built = PairConfig::builder()
        .alpn(b"mine/1".to_vec())
        .timeout(Duration::from_secs(5))
        .policy(Policy::modern())
        .build();
    assert_eq!(built.alpn, b"mine/1");
    assert_eq!(built.timeout, Duration::from_secs(5));
    assert_eq!(built.policy, Policy::modern());
}

#[test]
fn the_identity_builder_covers_each_way_to_say_a_window() {
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let end = start + Duration::from_secs(86_400);
    let explicit = Identity::builder()
        .not_before(start)
        .not_after(end)
        .build()
        .unwrap();
    let from_start = Identity::builder()
        .not_before(start)
        .valid_for(Duration::from_secs(86_400))
        .build()
        .unwrap();
    let window = |identity: &Identity| {
        let text = identity.to_pem().unwrap();
        assert!(text.contains("CERTIFICATE"));
    };
    window(&explicit);
    window(&from_start);
    let from_now = Identity::builder()
        .valid_for(Duration::from_secs(3600))
        .build()
        .unwrap();
    assert_eq!(from_now.intermediates_der().len(), 0);
    assert!(Identity::builder().build().is_ok());
    // A length and an end at once say the window twice.
    assert!(matches!(
        Identity::builder()
            .valid_for(Duration::from_secs(60))
            .not_after(SystemTime::now())
            .build(),
        Err(PeerError::Certificate)
    ));
    assert!(matches!(
        Identity::builder().valid_for(Duration::ZERO).build(),
        Err(PeerError::Certificate)
    ));
}

/// The old functions are one-line wrappers: the same connection works through them.
#[test]
#[allow(deprecated)]
fn the_old_functions_build_the_same_configurations() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let old_server =
        coqui_peer_tls::server_config(&server, &pinned(client.fingerprint()), &[ALPN]).unwrap();
    let old_client =
        coqui_peer_tls::client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap();
    assert_eq!(echo(old_server, old_client), Some(client.fingerprint()));

    let old_server = coqui_peer_tls::server_config_without_client_auth(&server, &[ALPN]).unwrap();
    let old_client =
        coqui_peer_tls::client_config_without_identity(&pinned(server.fingerprint()), &[ALPN])
            .unwrap();
    assert_eq!(echo(old_server, old_client), None);

    let policy = Policy {
        allow_resumption: true,
        ..Policy::default()
    };
    let built = coqui_peer_tls::server_config_with(
        &server,
        &pinned(client.fingerprint()),
        &[ALPN],
        &policy,
    )
    .unwrap();
    assert_eq!(built.non_defaults.len(), 1);
    let _ = coqui_peer_tls::ServerConfigs::without_client_auth(&server, &[ALPN], &policy).unwrap();
    let _ = Identity::generate_valid_for(Duration::from_secs(3600)).unwrap();
}
