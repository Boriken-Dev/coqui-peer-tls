//! A waiting entry is recorded only for a client that proved it holds the certificate's key.
#![cfg(all(feature = "generate", feature = "ca"))]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use coqui_peer::{
    CaPolicy, Identity, Pins, Policy, Trust, TrustStore, accept, client_config_with,
    crypto_provider, dial, server_config_with,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, SignatureScheme, SupportedProtocolVersion};

type Versions<'a> = &'a [&'static SupportedProtocolVersion];

/// Presents a certificate signed with a key that is not its own.
#[derive(Debug)]
struct Impostor(Arc<CertifiedKey>);

impl ResolvesClientCert for Impostor {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn impostor(victim: &Identity, versions: Versions<'_>) -> ClientConfig {
    let other = KeyPair::generate().unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(other.serialize_der()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
    let certificate = CertificateDer::from(victim.certificate_der().to_vec());
    let verifier = Trust::AnyWithKeyProof.server_cert_verifier().unwrap();
    ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(Impostor(Arc::new(CertifiedKey::new(
            vec![certificate],
            signing,
        )))))
}

fn ca_file(directory: &Path) -> (PathBuf, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().unwrap();
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .distinguished_name
        .push(DnType::CommonName, "test CA");
    let pem = parameters.self_signed(&key).unwrap().pem();
    let path = directory.join("ca.pem");
    std::fs::write(&path, pem).unwrap();
    (path, Issuer::new(parameters, key))
}

fn ca_signed(issuer: &Issuer<'_, KeyPair>) -> Identity {
    let key = KeyPair::generate().unwrap();
    let parameters = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let certificate = parameters.signed_by(&key, issuer).unwrap();
    Identity::from_pem(&format!("{}{}", certificate.pem(), key.serialize_pem())).unwrap()
}

/// The server trust: store-backed pins alone, or with a CA policy beside them.
fn trust(store: &TrustStore, ca: Option<&Path>) -> Trust {
    let pins = Pins::store(store.clone());
    match ca {
        None => Trust::Pinned(pins),
        Some(path) => Trust::PinnedOrCa {
            pins,
            ca: CaPolicy {
                ca_file: path.to_owned(),
                subject: Vec::new(),
                san: Vec::new(),
            },
        },
    }
}

/// Whether the server accepted the handshake of `client`.
fn handshake(server: &Identity, trust: &Trust, policy: &Policy, client: ClientConfig) -> bool {
    let config = server_config_with(server, trust, &[], policy)
        .unwrap()
        .config;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        accept(Arc::new(config), socket).is_ok()
    });
    let socket = TcpStream::connect(address).unwrap();
    let _ = dial(Arc::new(client), socket);
    served.join().unwrap()
}

fn genuine(client: &Identity, policy: &Policy) -> ClientConfig {
    client_config_with(client, &Trust::AnyWithKeyProof, &[], policy)
        .unwrap()
        .config
}

fn stolen_certificate_is_not_recorded(policy: &Policy, versions: Versions<'_>) {
    for with_ca in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = TrustStore::open(directory.path()).unwrap();
        let (ca, _) = ca_file(directory.path());
        let (server, victim) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let trust = trust(&store, with_ca.then_some(ca.as_path()));
        let accepted = handshake(&server, &trust, policy, impostor(&victim, versions));
        assert!(!accepted, "ca: {with_ca}");
        assert!(store.waiting().unwrap().is_empty(), "ca: {with_ca}");
    }
}

fn genuine_unknown_client_is_recorded(policy: &Policy) {
    for with_ca in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = TrustStore::open(directory.path()).unwrap();
        let (ca, _) = ca_file(directory.path());
        let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let trust = trust(&store, with_ca.then_some(ca.as_path()));
        let accepted = handshake(&server, &trust, policy, genuine(&client, policy));
        assert!(!accepted, "ca: {with_ca}");
        assert_eq!(
            store.waiting().unwrap(),
            vec![client.fingerprint()],
            "ca: {with_ca}"
        );
    }
}

#[test]
fn a_stolen_certificate_is_refused_and_not_recorded_over_tls13() {
    stolen_certificate_is_not_recorded(&Policy::default(), &[&rustls::version::TLS13]);
}

#[test]
fn a_genuine_unknown_client_is_recorded_after_its_signature_verifies() {
    genuine_unknown_client_is_recorded(&Policy::default());
}

#[test]
fn a_ca_trusted_client_beside_pins_connects_and_is_not_recorded() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    let (ca, issuer) = ca_file(directory.path());
    let (server, client) = (Identity::generate().unwrap(), ca_signed(&issuer));
    let trust = trust(&store, Some(&ca));
    let policy = Policy::default();
    assert!(handshake(
        &server,
        &trust,
        &policy,
        genuine(&client, &policy)
    ));
    assert!(store.waiting().unwrap().is_empty());
}

#[cfg(feature = "tls12")]
#[test]
fn a_stolen_certificate_is_refused_and_not_recorded_over_tls12() {
    stolen_certificate_is_not_recorded(&Policy::compatible(), &[&rustls::version::TLS12]);
}

#[cfg(feature = "tls12")]
#[test]
fn a_genuine_unknown_client_is_recorded_over_tls12() {
    let mut policy = Policy::compatible();
    policy.tls_versions = vec![coqui_peer::TlsVersion::V1_2];
    genuine_unknown_client_is_recorded(&policy);
}
