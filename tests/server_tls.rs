//! Server TLS: the server proves itself by certificate and the client presents none. Covers
//! the configurations, the handshake that finishes without a peer certificate, identities
//! with a chain and short-lived generated identities.
#![cfg(feature = "generate")]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use coqui_peer::Handshake;
use coqui_peer_tls::{
    CLIENT_AUTH_SETTING, Identity, PeerError, PeerId, PeerIdentity, Pins, Policy, Refusal,
    TlsHandshake, Trust, accept, client_config, client_config_without_identity,
    client_config_without_identity_with, dial, server_config, server_config_without_client_auth,
    server_config_without_client_auth_with,
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::{Connection, ServerConfig, StreamOwned};

const ALPN: &[u8] = b"server-tls-test/1";

fn pinned(fingerprint: PeerId) -> Trust {
    Trust::Pinned(Pins::fixed([fingerprint]))
}

/// Runs a handshake over `io` until it is complete, as `coqui_peer::complete_stream` does.
fn complete(mut handshake: TlsHandshake, io: &mut TcpStream) -> Result<TlsHandshake, PeerError> {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        while let Some(out) = handshake.transmit()? {
            io.write_all(&out).map_err(PeerError::Io)?;
        }
        if handshake.is_complete() {
            return Ok(handshake);
        }
        let read = io.read(&mut buffer).map_err(PeerError::Io)?;
        if read == 0 {
            return Err(PeerError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        if let Err(error) = handshake.receive(&buffer[..read]) {
            while let Ok(Some(out)) = handshake.transmit() {
                let _ = io.write_all(&out);
            }
            return Err(error);
        }
    }
}

/// Accepts one connection with the sans-IO handshake, finishes it allowing a client without a
/// certificate and echoes four bytes. Returns what the server learned of its peer.
fn serve(
    config: ServerConfig,
) -> (
    SocketAddr,
    JoinHandle<Result<Option<PeerIdentity>, PeerError>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (mut socket, from) = listener.accept().unwrap();
        let handshake = TlsHandshake::server(Arc::new(config), Some(from))?;
        let (connection, peer) = complete(handshake, &mut socket)?.finish_unauthenticated()?;
        let Connection::Server(connection) = connection else {
            panic!("a server handshake yields a server connection");
        };
        let mut stream = StreamOwned::new(connection, socket);
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).map_err(PeerError::Io)?;
        stream.write_all(&ping).map_err(PeerError::Io)?;
        stream.flush().map_err(PeerError::Io)?;
        Ok(peer)
    });
    (address, served)
}

/// Dials, pings and checks the echo; the server the client verified and what it presented.
fn ping(
    address: SocketAddr,
    config: rustls::ClientConfig,
) -> Result<(PeerIdentity, Vec<Vec<u8>>), PeerError> {
    let socket = TcpStream::connect(address).unwrap();
    let (mut stream, peer) = dial(Arc::new(config), socket)?;
    stream.write_all(b"ping").map_err(PeerError::Io)?;
    stream.flush().map_err(PeerError::Io)?;
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).map_err(PeerError::Io)?;
    assert_eq!(&back, b"ping");
    let presented = stream
        .conn
        .peer_certificates()
        .unwrap()
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    Ok((peer, presented))
}

#[test]
fn a_client_without_identity_reaches_a_server_tls_server_that_reports_no_peer() {
    let server = Identity::generate().unwrap();
    let built =
        server_config_without_client_auth_with(&server, &[ALPN], &Policy::modern()).unwrap();
    assert_eq!(built.weakened.len(), 1);
    assert_eq!(built.weakened[0].setting, CLIENT_AUTH_SETTING);
    assert_eq!(built.weakened[0].value, "none");
    assert_eq!(built.weakened[0].strict, "certificate");
    let (address, served) = serve(built.config);

    let client = client_config_without_identity(&pinned(server.fingerprint()), &[ALPN]).unwrap();
    let (seen, presented) = ping(address, client).unwrap();
    assert_eq!(seen.fingerprint, server.fingerprint());
    assert_eq!(presented, vec![server.certificate_der().to_vec()]);
    assert_eq!(served.join().unwrap().unwrap(), None);
}

#[test]
fn a_mutual_client_on_a_server_tls_server_is_still_not_authenticated() {
    // The server asks for no certificate, so the client sends none even when it has one.
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap());
    let config = client_config(&client, &pinned(server.fingerprint()), &[]).unwrap();
    ping(address, config).unwrap();
    assert_eq!(served.join().unwrap().unwrap(), None);
}

#[test]
fn finish_unauthenticated_reports_the_client_of_a_mutual_server() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (address, served) =
        serve(server_config(&server, &pinned(client.fingerprint()), &[]).unwrap());
    let config = client_config(&client, &pinned(server.fingerprint()), &[]).unwrap();
    ping(address, config).unwrap();
    let peer = served.join().unwrap().unwrap().unwrap();
    assert_eq!(peer.fingerprint, client.fingerprint());
}

#[test]
fn the_trait_finish_still_needs_a_peer_certificate() {
    let server = Identity::generate().unwrap();
    let config = Arc::new(server_config_without_client_auth(&server, &[]).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (mut socket, from) = listener.accept().unwrap();
        let handshake = complete(
            TlsHandshake::server(config, Some(from)).unwrap(),
            &mut socket,
        );
        handshake.unwrap().finish()
    });
    let client = client_config_without_identity(&pinned(server.fingerprint()), &[]).unwrap();
    let socket = TcpStream::connect(address).unwrap();
    let (_stream, _) = dial(Arc::new(client), socket).unwrap();
    assert!(matches!(
        served.join().unwrap(),
        Err(PeerError::Certificate)
    ));
}

#[test]
fn a_mutual_tls_server_refuses_a_client_without_identity() {
    let (server, other) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let config = Arc::new(server_config(&server, &pinned(other.fingerprint()), &[]).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        accept(config, socket).map(|(_, peer)| peer)
    });
    let client = client_config_without_identity(&pinned(server.fingerprint()), &[]).unwrap();
    // A TLS 1.3 client finishes before the server has judged it, so the refusal can arrive
    // only when it next reads.
    let dialed = ping(address, client);
    assert!(served.join().unwrap().is_err());
    assert!(dialed.is_err());
}

#[test]
fn a_client_without_identity_refuses_a_server_it_does_not_pin() {
    let (server, other) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap());
    let client = client_config_without_identity(&pinned(other.fingerprint()), &[]).unwrap();
    let refused = ping(address, client).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NotPinned));
    assert!(served.join().unwrap().is_err());
}

#[test]
fn a_short_lived_identity_serves_a_pinning_client() {
    let server = Identity::generate_valid_for(Duration::from_secs(14 * 86_400)).unwrap();
    let (address, served) = serve(server_config_without_client_auth(&server, &[]).unwrap());
    let client = client_config_without_identity(&pinned(server.fingerprint()), &[]).unwrap();
    let (seen, _) = ping(address, client).unwrap();
    assert_eq!(seen.fingerprint, server.fingerprint());
    assert_eq!(served.join().unwrap().unwrap(), None);
}

struct Chain {
    leaf: Certificate,
    intermediate: Certificate,
    key: KeyPair,
}

impl Chain {
    /// A root CA, an intermediate it signed and a leaf the intermediate signed.
    fn new() -> Self {
        let root_key = KeyPair::generate().unwrap();
        let root = Issuer::new(ca_parameters("test root"), root_key);
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate_parameters = ca_parameters("test intermediate");
        let intermediate = intermediate_parameters
            .signed_by(&intermediate_key, &root)
            .unwrap();
        let intermediate_issuer = Issuer::new(intermediate_parameters, intermediate_key);
        let key = KeyPair::generate().unwrap();
        let mut parameters = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "test leaf");
        let leaf = parameters.signed_by(&key, &intermediate_issuer).unwrap();
        Self {
            leaf,
            intermediate,
            key,
        }
    }

    fn pem(&self) -> String {
        format!(
            "{}{}{}",
            self.leaf.pem(),
            self.intermediate.pem(),
            self.key.serialize_pem()
        )
    }
}

fn ca_parameters(name: &str) -> CertificateParams {
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.distinguished_name.push(DnType::CommonName, name);
    parameters
}

#[test]
fn a_chained_identity_keeps_the_leaf_fingerprint_and_its_intermediates() {
    let chain = Chain::new();
    assert!(matches!(
        Identity::from_pem(&chain.pem()),
        Err(PeerError::Certificate)
    ));
    let identity = Identity::from_pem_chain(&chain.pem()).unwrap();
    assert_eq!(identity.fingerprint(), PeerId::of(chain.leaf.der()));
    assert_eq!(identity.certificate_der(), chain.leaf.der().as_ref());
    let intermediates: Vec<&[u8]> = identity.intermediates_der().collect();
    assert_eq!(intermediates, vec![chain.intermediate.der().as_ref()]);

    let again = Identity::from_pem_chain(&identity.to_pem().unwrap()).unwrap();
    assert_eq!(again.fingerprint(), identity.fingerprint());
    assert_eq!(again.intermediates_der().len(), 1);

    let single = Identity::generate().unwrap();
    let read = Identity::from_pem_chain(&single.to_pem().unwrap()).unwrap();
    assert_eq!(read.fingerprint(), single.fingerprint());
    assert_eq!(read.intermediates_der().len(), 0);
}

#[test]
fn a_chained_identity_file_reads_back_with_its_chain() {
    let chain = Chain::new();
    let identity = Identity::from_pem_chain(&chain.pem()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.pem");
    identity.write_new(&path).unwrap();
    let read = Identity::read(&path).unwrap().unwrap();
    assert_eq!(read.fingerprint(), identity.fingerprint());
    let intermediates: Vec<&[u8]> = read.intermediates_der().collect();
    assert_eq!(intermediates, vec![chain.intermediate.der().as_ref()]);
    // An existing chained file is opened, not replaced by a generated identity.
    let opened = Identity::open_or_create(&path).unwrap();
    assert_eq!(opened.fingerprint(), identity.fingerprint());
    assert_eq!(opened.intermediates_der().len(), 1);
}

#[test]
fn a_chain_whose_first_certificate_is_not_the_keys_is_refused() {
    let chain = Chain::new();
    let other = KeyPair::generate().unwrap();
    let wrong_key = format!(
        "{}{}{}",
        chain.leaf.pem(),
        chain.intermediate.pem(),
        other.serialize_pem()
    );
    assert!(matches!(
        Identity::from_pem_chain(&wrong_key),
        Err(PeerError::Certificate)
    ));
    let wrong_order = format!(
        "{}{}{}",
        chain.intermediate.pem(),
        chain.leaf.pem(),
        chain.key.serialize_pem()
    );
    assert!(matches!(
        Identity::from_pem_chain(&wrong_order),
        Err(PeerError::Certificate)
    ));
    assert!(matches!(
        Identity::from_pem_chain(&chain.key.serialize_pem()),
        Err(PeerError::Certificate)
    ));
}

#[test]
fn a_server_presents_its_whole_chain() {
    let chain = Chain::new();
    let identity = Identity::from_pem_chain(&chain.pem()).unwrap();
    let (address, served) = serve(server_config_without_client_auth(&identity, &[]).unwrap());
    let client = client_config_without_identity(&Trust::AnyWithKeyProof, &[]).unwrap();
    let (seen, presented) = ping(address, client).unwrap();
    assert_eq!(seen.fingerprint, identity.fingerprint());
    assert_eq!(
        presented,
        vec![chain.leaf.der().to_vec(), chain.intermediate.der().to_vec()]
    );
    assert_eq!(served.join().unwrap().unwrap(), None);
}

#[test]
fn a_pinning_client_refuses_a_chain_unless_its_policy_allows_one() {
    let chain = Chain::new();
    let identity = Identity::from_pem_chain(&chain.pem()).unwrap();
    let trust = pinned(identity.fingerprint());

    let (address, served) = serve(server_config_without_client_auth(&identity, &[]).unwrap());
    let refused = ping(
        address,
        client_config_without_identity(&trust, &[]).unwrap(),
    )
    .unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::ChainWhenPinned));
    assert!(served.join().unwrap().is_err());

    let mut policy = Policy::modern();
    policy.allow_chain_when_pinned = true;
    let built = client_config_without_identity_with(&trust, &[], &policy).unwrap();
    assert_eq!(built.weakened.len(), 1);
    assert_eq!(built.weakened[0].setting, "allow_chain_when_pinned");
    let (address, served) = serve(server_config_without_client_auth(&identity, &[]).unwrap());
    let (_, presented) = ping(address, built.config).unwrap();
    assert_eq!(presented.len(), 2);
    assert_eq!(served.join().unwrap().unwrap(), None);
}
