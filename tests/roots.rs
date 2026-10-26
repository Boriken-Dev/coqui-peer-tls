//! A client verifying a server by the web PKI: a chain to the roots, validity dates and the
//! server name dialled. Every certificate comes from a throwaway test CA.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use coqui_peer::Handshake;
use coqui_peer_tls::{
    Fingerprint, Identity, PeerError, PeerIdentity, Pins, Policy, Refusal, Roots, TlsHandshake,
    Trust, client_config_without_identity, client_config_without_identity_with, dial, dial_named,
    server_config, server_config_without_client_auth, server_config_without_client_auth_with,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair, date_time_ymd,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, HandshakeKind, ServerConfig, ServerConnection, StreamOwned};

/// A root CA and the leaves it issues.
struct Ca {
    root: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    fn new(name: &str) -> Self {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let root = parameters.self_signed(&key).unwrap();
        Self {
            root,
            issuer: Issuer::new(parameters, key),
        }
    }

    fn roots(&self) -> Roots {
        Roots::bundle_pem(self.root.pem())
    }

    /// A server identity for `localhost` and `127.0.0.1`, valid for rcgen's default period.
    fn leaf(&self) -> Identity {
        self.leaf_with(|_| {})
    }

    fn leaf_with(&self, change: impl FnOnce(&mut CertificateParams)) -> Identity {
        let mut parameters =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "test server");
        change(&mut parameters);
        let key = KeyPair::generate().unwrap();
        let leaf = parameters.signed_by(&key, &self.issuer).unwrap();
        Identity::from_pem_chain(&format!("{}{}", leaf.pem(), key.serialize_pem())).unwrap()
    }
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

/// Serves `count` connections that echo four bytes; the kind of each handshake.
fn serve(
    config: ServerConfig,
    count: usize,
) -> (SocketAddr, JoinHandle<Vec<io::Result<HandshakeKind>>>) {
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        (0..count)
            .map(|_| {
                let (socket, _) = listener.accept()?;
                let connection = ServerConnection::new(config.clone()).map_err(io::Error::other)?;
                let mut stream = StreamOwned::new(connection, socket);
                let mut ping = [0u8; 4];
                stream.read_exact(&mut ping)?;
                stream.write_all(&ping)?;
                stream.flush()?;
                Ok(stream.conn.handshake_kind().unwrap())
            })
            .collect()
    });
    (address, served)
}

/// Dials `name`, pings and checks the echo; the verified server and the handshake kind.
fn ping(
    address: SocketAddr,
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
) -> Result<(PeerIdentity, HandshakeKind), PeerError> {
    let socket = TcpStream::connect(address).unwrap();
    let (mut stream, peer) = dial_named(config.clone(), name, socket)?;
    stream.write_all(b"ping").map_err(PeerError::Io)?;
    stream.flush().map_err(PeerError::Io)?;
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).map_err(PeerError::Io)?;
    assert_eq!(&back, b"ping");
    Ok((peer, stream.conn.handshake_kind().unwrap()))
}

fn client(trust: &Trust) -> Arc<ClientConfig> {
    Arc::new(client_config_without_identity(trust, &[]).unwrap())
}

/// The rustls error inside a failed dial.
fn rustls_error(error: &PeerError) -> Option<&rustls::Error> {
    match error {
        PeerError::Io(error) => error.get_ref()?.downcast_ref::<rustls::Error>(),
        _ => None,
    }
}

#[test]
fn a_server_whose_chain_and_name_verify_is_accepted() {
    let ca = Ca::new("test root");
    let server = ca.leaf();
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap(), 2);
    let config = client(&Trust::Roots(ca.roots()));

    let (peer, _) = ping(address, &config, localhost()).unwrap();
    assert_eq!(peer.fingerprint, server.fingerprint());
    assert_eq!(peer.certificate, server.certificate_der());
    let ip = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let (peer, _) = ping(address, &config, ip).unwrap();
    assert_eq!(peer.fingerprint, server.fingerprint());
    assert!(served.join().unwrap().iter().all(Result::is_ok));
}

#[test]
fn a_server_certificate_for_another_name_is_a_name_mismatch() {
    let ca = Ca::new("test root");
    let (address, served) = serve(
        server_config_without_client_auth(&ca.leaf(), &[]).unwrap(),
        2,
    );
    let config = client(&Trust::Roots(ca.roots()));

    let other = ServerName::try_from("example.invalid").unwrap();
    let refused = ping(address, &config, other).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NameMismatch));
    // `dial` names SERVER_NAME, which the certificate does not.
    let socket = TcpStream::connect(address).unwrap();
    let refused = dial(config, socket).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NameMismatch));
    assert!(served.join().unwrap().iter().all(Result::is_err));
}

#[test]
fn a_server_from_another_ca_is_not_trusted() {
    let (ca, other) = (Ca::new("test root"), Ca::new("other root"));
    let (address, served) = serve(
        server_config_without_client_auth(&ca.leaf(), &[]).unwrap(),
        1,
    );
    let refused = ping(address, &client(&Trust::Roots(other.roots())), localhost()).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NotTrusted));
    assert!(served.join().unwrap()[0].is_err());
}

#[test]
fn an_expired_server_certificate_is_refused() {
    let ca = Ca::new("test root");
    let expired = ca.leaf_with(|parameters| {
        parameters.not_before = date_time_ymd(2020, 1, 1);
        parameters.not_after = date_time_ymd(2021, 1, 1);
    });
    let (address, served) = serve(server_config_without_client_auth(&expired, &[]).unwrap(), 1);
    let refused = ping(address, &client(&Trust::Roots(ca.roots())), localhost()).unwrap_err();
    assert!(
        matches!(
            rustls_error(&refused),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ))
        ),
        "{refused:?}"
    );
    assert_eq!(refused.refusal(), None);
    assert!(served.join().unwrap()[0].is_err());

    // Dates are checked whatever the policy says about pinned certificates.
    let mut policy = Policy::strict();
    policy.check_validity = false;
    let (address, served) = serve(server_config_without_client_auth(&expired, &[]).unwrap(), 1);
    let config = client_config_without_identity_with(&Trust::Roots(ca.roots()), &[], &policy)
        .unwrap()
        .config;
    assert!(ping(address, &Arc::new(config), localhost()).is_err());
    assert!(served.join().unwrap()[0].is_err());
}

#[test]
fn a_verified_server_is_verified_again_on_every_connection() {
    let ca = Ca::new("test root");
    let mut lenient = Policy::strict();
    lenient.allow_resumption = true;
    let server = server_config_without_client_auth_with(&ca.leaf(), &[], &lenient)
        .unwrap()
        .config;
    let trust = Trust::Roots(ca.roots());

    let (address, served) = serve(server.clone(), 2);
    let config = client(&trust);
    assert_eq!(
        ping(address, &config, localhost()).unwrap().1,
        HandshakeKind::Full
    );
    assert_eq!(
        ping(address, &config, localhost()).unwrap().1,
        HandshakeKind::Full
    );
    served.join().unwrap();

    // The same server resumes a client whose policy allows it, so the test can tell.
    let (address, served) = serve(server, 2);
    let resuming = Arc::new(
        client_config_without_identity_with(&trust, &[], &lenient)
            .unwrap()
            .config,
    );
    assert_eq!(
        ping(address, &resuming, localhost()).unwrap().1,
        HandshakeKind::Full
    );
    assert_eq!(
        ping(address, &resuming, localhost()).unwrap().1,
        HandshakeKind::Resumed
    );
    served.join().unwrap();
}

#[test]
fn the_handshake_names_the_server_and_establishes_its_leaf_fingerprint() {
    let ca = Ca::new("test root");
    let server = ca.leaf();
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap(), 1);
    let handshake = TlsHandshake::client_named(client(&Trust::Roots(ca.roots())), localhost());
    let mut socket = TcpStream::connect(address).unwrap();
    let mut handshake = handshake.unwrap();
    let mut buffer = [0u8; 16 * 1024];
    while !handshake.is_complete() {
        while let Some(out) = handshake.transmit().unwrap() {
            socket.write_all(&out).unwrap();
        }
        if handshake.is_complete() {
            break;
        }
        let read = socket.read(&mut buffer).unwrap();
        handshake.receive(&buffer[..read]).unwrap();
    }
    while let Some(out) = handshake.transmit().unwrap() {
        socket.write_all(&out).unwrap();
    }
    let established = handshake.finish().unwrap();
    assert_eq!(established.peer, server.fingerprint());
    drop(socket);
    let _ = served.join();
}

#[cfg(feature = "generate")]
#[test]
fn pinned_or_roots_takes_a_pinned_server_by_any_name_and_a_rooted_one_by_its_name() {
    let ca = Ca::new("test root");
    let (rooted, pinned) = (ca.leaf(), Identity::generate().unwrap());
    let trust = Trust::PinnedOrRoots {
        pins: Pins::fixed([pinned.fingerprint()]),
        roots: ca.roots(),
    };
    let config = client(&trust);

    let (address, served) = serve(server_config_without_client_auth(&pinned, &[]).unwrap(), 1);
    let socket = TcpStream::connect(address).unwrap();
    let (mut stream, peer) = dial(config.clone(), socket).unwrap();
    assert_eq!(peer.fingerprint, pinned.fingerprint());
    stream.write_all(b"ping").unwrap();
    stream.read_exact(&mut [0u8; 4]).unwrap();
    served.join().unwrap();

    let (address, served) = serve(server_config_without_client_auth(&rooted, &[]).unwrap(), 2);
    assert_eq!(
        ping(address, &config, localhost()).unwrap().0.fingerprint,
        rooted.fingerprint()
    );
    let other = ServerName::try_from("example.invalid").unwrap();
    let refused = ping(address, &config, other).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NameMismatch));
    served.join().unwrap();

    let stranger = Ca::new("other root").leaf();
    let (address, served) = serve(
        server_config_without_client_auth(&stranger, &[]).unwrap(),
        1,
    );
    let refused = ping(address, &config, localhost()).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NotTrusted));
    served.join().unwrap();
}

#[test]
fn pinned_trust_still_ignores_the_name() {
    let ca = Ca::new("test root");
    let server = ca.leaf();
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap(), 1);
    let config = client(&Trust::Pinned(Pins::fixed([server.fingerprint()])));
    let other = ServerName::try_from("example.invalid").unwrap();
    let (peer, _) = ping(address, &config, other).unwrap();
    assert_eq!(peer.fingerprint, Fingerprint::of(server.certificate_der()));
    served.join().unwrap();
}

#[test]
fn roots_are_for_clients_and_a_bundle_must_hold_a_root() {
    let ca = Ca::new("test root");
    let server = ca.leaf();
    for trust in [
        Trust::Roots(ca.roots()),
        Trust::PinnedOrRoots {
            pins: Pins::fixed([server.fingerprint()]),
            roots: ca.roots(),
        },
    ] {
        assert!(matches!(
            server_config(&server, &trust, &[]),
            Err(PeerError::Unsupported)
        ));
    }

    let empty = Trust::Roots(Roots::bundle_pem("no certificate here\n"));
    assert!(matches!(
        client_config_without_identity(&empty, &[]),
        Err(PeerError::Certificate)
    ));
    let directory = tempfile::tempdir().unwrap();
    let missing = Trust::Roots(Roots::bundle_file(directory.path().join("absent.pem")));
    assert!(matches!(
        client_config_without_identity(&missing, &[]),
        Err(PeerError::Io(_))
    ));
    let path = directory.path().join("roots.pem");
    std::fs::write(&path, format!("# test root\n{}", ca.root.pem())).unwrap();
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap(), 1);
    let config = client(&Trust::Roots(Roots::bundle_file(&path)));
    ping(address, &config, localhost()).unwrap();
    served.join().unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn the_async_dial_names_the_server() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let ca = Ca::new("test root");
    let server = ca.leaf();
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap(), 2);
    let config = client(&Trust::Roots(ca.roots()));

    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut stream, peer) =
        coqui_peer_tls::asynch::dial_named(config.clone(), localhost(), socket)
            .await
            .unwrap();
    assert_eq!(peer.fingerprint, server.fingerprint());
    stream.write_all(b"ping").await.unwrap();
    stream.read_exact(&mut [0u8; 4]).await.unwrap();

    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let other = ServerName::try_from("example.invalid").unwrap();
    let refused = coqui_peer_tls::asynch::dial_named(config, other, socket)
        .await
        .unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NameMismatch));
    drop(stream);
    served.join().unwrap();
}

/// The test CA is in no operating system's store.
#[cfg(feature = "platform-roots")]
#[test]
fn the_platform_roots_do_not_trust_a_test_ca() {
    let ca = Ca::new("test root");
    let (address, served) = serve(
        server_config_without_client_auth(&ca.leaf(), &[]).unwrap(),
        1,
    );
    let refused = ping(
        address,
        &client(&Trust::Roots(Roots::platform())),
        localhost(),
    )
    .unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NotTrusted), "{refused:?}");
    served.join().unwrap();
}
