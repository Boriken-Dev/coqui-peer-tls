//! Handshakes between real identities. Run with `--all-features`.
#![cfg(all(feature = "generate", feature = "ca", feature = "tokio"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use coqui_peer::{
    CaPolicy, Fingerprint, Identity, Pins, Trust, TrustStore, accept, client_config, dial,
    server_config,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

const ALPN: &[u8] = b"test-proto/1";

fn pinned(fingerprint: Fingerprint) -> Trust {
    Trust::Pinned(Pins::fixed([fingerprint]))
}

/// Runs the server side on a thread; returns whether the handshake and an echo succeeded.
fn serve(
    listener: TcpListener,
    config: rustls::ServerConfig,
) -> thread::JoinHandle<Option<Fingerprint>> {
    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let (mut stream, peer) = accept(Arc::new(config), socket).ok()?;
        let mut byte = [0u8; 4];
        stream.read_exact(&mut byte).ok()?;
        stream.write_all(&byte).ok()?;
        stream.flush().ok()?;
        Some(peer.fingerprint)
    })
}

fn echo(address: std::net::SocketAddr, config: rustls::ClientConfig) -> Option<Fingerprint> {
    let socket = TcpStream::connect(address).unwrap();
    let (mut stream, peer) = dial(Arc::new(config), socket).ok()?;
    stream.write_all(b"ping").ok()?;
    stream.flush().ok()?;
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).ok()?;
    assert_eq!(&back, b"ping");
    assert_eq!(stream.conn.alpn_protocol(), Some(ALPN));
    Some(peer.fingerprint)
}

#[test]
fn pinned_peers_talk_and_learn_each_others_fingerprint() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = serve(
        listener,
        server_config(&server, &pinned(client.fingerprint()), &[ALPN]).unwrap(),
    );
    let seen = echo(
        address,
        client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap(),
    );
    assert_eq!(seen, Some(server.fingerprint()));
    assert_eq!(served.join().unwrap(), Some(client.fingerprint()));
}

#[test]
fn a_wrong_pin_refuses_the_handshake_on_either_side() {
    let (server, client, other) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    // The client pins the wrong server.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = serve(
        listener,
        server_config(&server, &pinned(client.fingerprint()), &[ALPN]).unwrap(),
    );
    assert_eq!(
        echo(
            address,
            client_config(&client, &pinned(other.fingerprint()), &[ALPN]).unwrap()
        ),
        None
    );
    assert_eq!(served.join().unwrap(), None);
    // The server pins the wrong client.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = serve(
        listener,
        server_config(&server, &pinned(other.fingerprint()), &[ALPN]).unwrap(),
    );
    assert_eq!(
        echo(
            address,
            client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap()
        ),
        None
    );
    assert_eq!(served.join().unwrap(), None);
}

#[test]
fn an_unknown_peer_that_proved_its_key_waits_and_is_let_in_once_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let trust = Trust::Pinned(Pins::store(store.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = serve(listener, server_config(&server, &trust, &[ALPN]).unwrap());
    let refused = echo(
        address,
        client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap(),
    );
    assert_eq!(served.join().unwrap(), None);
    let _ = refused;
    assert_eq!(store.waiting().unwrap(), vec![client.fingerprint()]);

    store.accept(&client.fingerprint()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = serve(listener, server_config(&server, &trust, &[ALPN]).unwrap());
    let seen = echo(
        address,
        client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap(),
    );
    assert_eq!(seen, Some(server.fingerprint()));
    assert_eq!(served.join().unwrap(), Some(client.fingerprint()));
}

#[test]
fn any_certificate_with_key_proof_is_taken_and_named() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = serve(
        listener,
        server_config(&server, &Trust::AnyWithKeyProof, &[ALPN]).unwrap(),
    );
    let seen = echo(
        address,
        client_config(&client, &Trust::AnyWithKeyProof, &[ALPN]).unwrap(),
    );
    assert_eq!(seen, Some(server.fingerprint()));
    assert_eq!(served.join().unwrap(), Some(client.fingerprint()));
}

fn expired_identity() -> Identity {
    let key = KeyPair::generate().unwrap();
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.not_before = rcgen::date_time_ymd(2001, 1, 1);
    parameters.not_after = rcgen::date_time_ymd(2002, 1, 1);
    let certificate = parameters.self_signed(&key).unwrap();
    Identity::from_pem(&format!("{}{}", certificate.pem(), key.serialize_pem())).unwrap()
}

#[test]
fn a_pinned_certificate_outside_its_dates_is_refused() {
    let (server, expired) = (Identity::generate().unwrap(), expired_identity());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = serve(
        listener,
        server_config(&server, &pinned(expired.fingerprint()), &[ALPN]).unwrap(),
    );
    assert_eq!(
        echo(
            address,
            client_config(&expired, &pinned(server.fingerprint()), &[ALPN]).unwrap()
        ),
        None
    );
    assert_eq!(served.join().unwrap(), None);
}

#[test]
fn a_pinned_peer_presenting_a_chain_is_refused() {
    let (server, other) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let verifier = pinned(server.fingerprint()).server_cert_verifier().unwrap();
    let certificate = CertificateDer::from(server.certificate_der().to_vec());
    let extra = CertificateDer::from(other.certificate_der().to_vec());
    let name = ServerName::try_from("coqui-peer.invalid").unwrap();
    let now = UnixTime::now();
    assert!(
        verifier
            .verify_server_cert(&certificate, &[], &name, &[], now)
            .is_ok()
    );
    assert!(
        verifier
            .verify_server_cert(&certificate, &[extra], &name, &[], now)
            .is_err()
    );
}

#[test]
fn an_identity_file_with_a_chain_is_refused() {
    let (one, two) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let pem = format!(
        "{}{}",
        one.to_pem().unwrap(),
        two.to_pem()
            .unwrap()
            .split("-----BEGIN PRIVATE KEY")
            .next()
            .unwrap()
    );
    assert!(Identity::from_pem(&pem).is_err());
}

#[test]
fn identities_are_created_once_and_kept_private() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested").join("identity.pem");
    let first = Identity::open_or_create(&path).unwrap();
    assert_eq!(
        Identity::open_or_create(&path).unwrap().fingerprint(),
        first.fingerprint()
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(text.contains("-----BEGIN PRIVATE KEY-----\n"));
    assert!(!text.contains('\r'));
    assert!(!format!("{first:?}").contains("PRIVATE"));
    assert!(
        first.write_new(&path).is_err(),
        "an identity is never replaced"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

fn ca() -> (String, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().unwrap();
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(DnType::CommonName, "test CA");
    let certificate = parameters.self_signed(&key).unwrap();
    (certificate.pem(), Issuer::new(parameters, key))
}

fn signed(issuer: &Issuer<'_, KeyPair>, common_name: &str) -> Identity {
    let key = KeyPair::generate().unwrap();
    let mut parameters = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    parameters
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let certificate = parameters.signed_by(&key, issuer).unwrap();
    Identity::from_pem(&format!("{}{}", certificate.pem(), key.serialize_pem())).unwrap()
}

#[test]
fn a_ca_signed_client_connects_when_subject_and_san_match() {
    let directory = tempfile::tempdir().unwrap();
    let (ca_pem, issuer) = ca();
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(&ca_file, ca_pem).unwrap();
    let server = Identity::generate().unwrap();
    let client = signed(&issuer, "Client One");
    let policy = |subject: &str| CaPolicy {
        ca_file: ca_file.clone(),
        subject: vec![subject.to_owned()],
        san: vec!["localhost".to_owned()],
    };
    for (subject, connects) in [("*Client One*", true), ("*Somebody Else*", false)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let served = serve(
            listener,
            server_config(&server, &Trust::Ca(policy(subject)), &[ALPN]).unwrap(),
        );
        let seen = echo(
            address,
            client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap(),
        );
        assert_eq!(seen.is_some(), connects, "{subject}");
        assert_eq!(served.join().unwrap().is_some(), connects, "{subject}");
    }
    // A CA policy is applied by servers only.
    assert!(client_config(&client, &Trust::Ca(policy("*")), &[ALPN]).is_err());
}

#[tokio::test]
async fn async_dial_and_accept_over_any_stream() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let server_config =
        Arc::new(server_config(&server, &pinned(client.fingerprint()), &[ALPN]).unwrap());
    let client_config =
        Arc::new(client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap());
    let (near, far) = tokio::io::duplex(8192);
    let accepting = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, peer) = coqui_peer::asynch::accept(server_config, far)
            .await
            .unwrap();
        let mut byte = [0u8; 4];
        stream.read_exact(&mut byte).await.unwrap();
        stream.write_all(&byte).await.unwrap();
        stream.flush().await.unwrap();
        peer.fingerprint
    });
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut stream, peer) = coqui_peer::asynch::dial(client_config, near).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    assert_eq!(peer.fingerprint, server.fingerprint());
    assert_eq!(accepting.await.unwrap(), client.fingerprint());
}

#[tokio::test]
async fn accept_with_chooses_the_configuration_from_the_hello() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let chosen = Arc::new(server_config(&server, &pinned(client.fingerprint()), &[ALPN]).unwrap());
    let client_config =
        Arc::new(client_config(&client, &pinned(server.fingerprint()), &[ALPN]).unwrap());
    let (near, far) = tokio::io::duplex(8192);
    let accepting = tokio::spawn(async move {
        let (stream, peer) = coqui_peer::asynch::accept_with(far, |hello| {
            assert_eq!(hello.alpn().unwrap().next(), Some(ALPN));
            chosen
        })
        .await
        .unwrap();
        drop(stream);
        peer.fingerprint
    });
    let (_stream, peer) = coqui_peer::asynch::dial(client_config, near).await.unwrap();
    assert_eq!(peer.fingerprint, server.fingerprint());
    assert_eq!(accepting.await.unwrap(), client.fingerprint());
}
