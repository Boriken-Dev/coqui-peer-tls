//! Configurations around a verifier of the host's own: the policy's versions apply, the whole
//! chain is presented, and the identity's key is available to build them.
#![cfg(feature = "generate")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use coqui_peer_tls::{
    Identity, PeerError, Policy, TlsVersion, Trust, client_config_with_verifier,
    server_config_with_verifier,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConnection, DigitallySignedStruct, DistinguishedName, ProtocolVersion, ServerConnection,
    SignatureScheme, StreamOwned,
};

const ALPN: &[u8] = b"custom-verifier-test/1";

/// A leaf, signed by an intermediate, signed by a root: the leaf and intermediate as PEM with
/// the leaf's key, and the DER of both.
fn chain() -> (String, Vec<Vec<u8>>) {
    let ca = |name: &str| {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).expect("parameters");
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.distinguished_name.push(DnType::CommonName, name);
        parameters
    };
    let root = Issuer::new(ca("root"), KeyPair::generate().expect("a key"));
    let intermediate_key = KeyPair::generate().expect("a key");
    let intermediate = ca("intermediate")
        .signed_by(&intermediate_key, &root)
        .expect("signed");
    let issuer = Issuer::new(ca("intermediate"), intermediate_key);
    let key = KeyPair::generate().expect("a key");
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("parameters")
        .signed_by(&key, &issuer)
        .expect("signed");
    (
        format!(
            "{}{}{}",
            leaf.pem(),
            intermediate.pem(),
            key.serialize_pem()
        ),
        vec![leaf.der().to_vec(), intermediate.der().to_vec()],
    )
}

/// The host's own verifier: this crate's, counting the certificates it is shown.
#[derive(Debug)]
struct Counting {
    inner: Arc<dyn ClientCertVerifier>,
    seen: Arc<AtomicUsize>,
}

impl ClientCertVerifier for Counting {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.seen.fetch_add(1, Ordering::SeqCst);
        self.inner
            .verify_client_cert(certificate, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signed)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[test]
fn a_custom_verifier_under_a_tls12_policy_negotiates_tls12_and_presents_the_chain()
-> Result<(), PeerError> {
    let (pem, presented) = chain();
    let server_identity = Identity::from_pem_chain(&pem)?;
    let client_identity = Identity::generate()?;
    let mut policy = Policy::intermediate();
    policy.tls_versions = vec![TlsVersion::V1_2];
    policy.allow_chain_when_pinned = true;

    let seen = Arc::new(AtomicUsize::new(0));
    let verifier = Arc::new(Counting {
        inner: Trust::AnyWithKeyProof.client_cert_verifier_with(&policy)?,
        seen: Arc::clone(&seen),
    });
    let server = server_config_with_verifier(&server_identity, verifier, &[ALPN], &policy)?;
    assert!(
        server
            .weakened
            .iter()
            .any(|w| w.setting == "allow_chain_when_pinned")
    );
    let client = client_config_with_verifier(
        Some(&client_identity),
        Trust::AnyWithKeyProof.server_cert_verifier_with(&policy)?,
        &[ALPN],
        &policy,
    )?;

    let listener = TcpListener::bind("127.0.0.1:0").map_err(PeerError::Io)?;
    let address = listener.local_addr().map_err(PeerError::Io)?;
    let server_config = Arc::new(server.config);
    let served = thread::spawn(move || -> Result<Vec<Vec<u8>>, PeerError> {
        let (socket, _) = listener.accept().map_err(PeerError::Io)?;
        let connection = ServerConnection::new(server_config).map_err(|_| PeerError::Tls)?;
        let mut stream = StreamOwned::new(connection, socket);
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).map_err(PeerError::Io)?;
        stream.write_all(&ping).map_err(PeerError::Io)?;
        Ok(stream
            .conn
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|certificate| certificate.to_vec())
            .collect())
    });

    let socket = TcpStream::connect(address).map_err(PeerError::Io)?;
    let name = rustls::pki_types::ServerName::try_from(coqui_peer_tls::SERVER_NAME)
        .map_err(|_| PeerError::Tls)?;
    let connection =
        ClientConnection::new(Arc::new(client.config), name).map_err(|_| PeerError::Tls)?;
    let mut stream = StreamOwned::new(connection, socket);
    stream.write_all(b"ping").map_err(PeerError::Io)?;
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).map_err(PeerError::Io)?;
    assert_eq!(&echo, b"ping");
    assert_eq!(
        stream.conn.protocol_version(),
        Some(ProtocolVersion::TLSv1_2)
    );
    let seen_by_client: Vec<Vec<u8>> = stream
        .conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|certificate| certificate.to_vec())
        .collect();
    assert_eq!(seen_by_client, presented);
    let seen_by_server = served.join().expect("no panic")?;
    assert_eq!(
        seen_by_server,
        vec![client_identity.certificate_der().to_vec()]
    );
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn the_chain_and_key_accessors_build_a_configuration_without_printing_the_key()
-> Result<(), PeerError> {
    let (pem, presented) = chain();
    let identity = Identity::from_pem_chain(&pem)?;
    let chain: Vec<Vec<u8>> = identity
        .certificate_chain()
        .iter()
        .map(|certificate| certificate.to_vec())
        .collect();
    assert_eq!(chain, presented);
    let key = identity.private_key_der();
    assert!(format!("{key:?}").contains("elided"));
    rustls::ServerConfig::builder_with_provider(coqui_peer_tls::crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| PeerError::Tls)?
        .with_no_client_auth()
        .with_single_cert(identity.certificate_chain(), key)
        .map_err(|_| PeerError::Certificate)?;
    Ok(())
}
