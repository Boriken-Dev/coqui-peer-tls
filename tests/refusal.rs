//! A refused certificate is a typed `Refusal` inside `rustls::Error::InvalidCertificate`, which
//! the refusing side reads back from the rustls error or from `PeerError::refusal`.
#![cfg(all(feature = "generate", feature = "tokio"))]

use std::sync::Arc;

use coqui_peer_tls::{
    Identity, PeerError, Pins, Refusal, Trust, TrustStore, TrustStoreExt, asynch, client_config,
    server_config,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"refusal-test/1";

fn der(identity: &Identity) -> CertificateDer<'static> {
    CertificateDer::from(identity.certificate_der().to_vec())
}

fn pinned(identity: &Identity) -> Trust {
    Trust::Pinned(Pins::fixed([identity.fingerprint()]))
}

/// What the client verifier of `trust` says about `certificate` presented with `chain`.
fn client_verdict(
    trust: &Trust,
    certificate: &Identity,
    chain: &[CertificateDer<'_>],
) -> Result<(), rustls::Error> {
    let verifier = trust.client_cert_verifier().unwrap();
    verifier
        .verify_client_cert(&der(certificate), chain, UnixTime::now())
        .map(|_| ())
}

/// What the server verifier of `trust` says about `certificate` presented with `chain`.
fn server_verdict(
    trust: &Trust,
    certificate: &Identity,
    chain: &[CertificateDer<'_>],
) -> Result<(), rustls::Error> {
    let verifier = trust.server_cert_verifier().unwrap();
    let name = ServerName::try_from(coqui_peer_tls::SERVER_NAME).unwrap();
    verifier
        .verify_server_cert(&der(certificate), chain, &name, &[], UnixTime::now())
        .map(|_| ())
}

fn refusal(verdict: Result<(), rustls::Error>) -> Refusal {
    let error = verdict.unwrap_err();
    assert!(
        matches!(
            error,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(_))
        ),
        "{error:?}"
    );
    Refusal::from_rustls(&error).unwrap()
}

#[test]
fn each_verifier_refuses_with_a_typed_reason() {
    let (known, stranger) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let trust = pinned(&known);
    assert_eq!(
        refusal(server_verdict(&trust, &stranger, &[])),
        Refusal::NotPinned
    );
    assert_eq!(
        refusal(client_verdict(&trust, &stranger, &[])),
        Refusal::NotPinned
    );
    assert!(server_verdict(&trust, &known, &[]).is_ok());

    let chain = [der(&stranger)];
    assert_eq!(
        refusal(server_verdict(&trust, &known, &chain)),
        Refusal::ChainWhenPinned
    );
    assert_eq!(
        refusal(client_verdict(&trust, &known, &chain)),
        Refusal::ChainWhenPinned
    );

    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    store.accept_certificate(known.certificate_der()).unwrap();
    let trust = Trust::Pinned(Pins::store(store));
    assert_eq!(
        refusal(server_verdict(&trust, &stranger, &[])),
        Refusal::NotAccepted
    );
    assert!(server_verdict(&trust, &known, &[]).is_ok());
}

#[cfg(feature = "ca")]
#[test]
fn a_certificate_the_ca_policy_does_not_trust_is_not_trusted() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let directory = tempfile::tempdir().unwrap();
    let key = KeyPair::generate().unwrap();
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(&ca_file, parameters.self_signed(&key).unwrap().pem()).unwrap();
    let ca = coqui_peer_tls::CaPolicy {
        ca_file,
        subject: Vec::new(),
        san: Vec::new(),
    };
    let stranger = Identity::generate().unwrap();
    assert_eq!(
        refusal(client_verdict(&Trust::Ca(ca), &stranger, &[])),
        Refusal::NotTrusted
    );
}

#[test]
fn the_message_says_why() {
    let message = Refusal::from_rustls(&{
        let trust = pinned(&Identity::generate().unwrap());
        server_verdict(&trust, &Identity::generate().unwrap(), &[]).unwrap_err()
    })
    .unwrap()
    .to_string();
    assert_eq!(message, "peer certificate matches no pinned fingerprint");
    assert_eq!(
        Refusal::from_rustls(&rustls::Error::HandshakeNotComplete),
        None
    );
}

/// A handshake and an echo; each side's error.
async fn link(
    server: rustls::ServerConfig,
    client: rustls::ClientConfig,
) -> (Result<(), PeerError>, Result<(), PeerError>) {
    let (near, far) = tokio::io::duplex(16384);
    let accepting = tokio::spawn(async move {
        let (mut stream, _) =
            asynch::accept_from(Arc::new(server), far, ([192, 0, 2, 1], 1).into()).await?;
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).await.map_err(PeerError::Io)?;
        stream.write_all(&ping).await.map_err(PeerError::Io)?;
        stream.flush().await.map_err(PeerError::Io)
    });
    let dialed = async {
        let (mut stream, _) = asynch::dial(Arc::new(client), near).await?;
        stream.write_all(b"ping").await.map_err(PeerError::Io)?;
        let mut pong = [0u8; 4];
        stream.read_exact(&mut pong).await.map_err(PeerError::Io)?;
        Ok(())
    }
    .await;
    (accepting.await.unwrap(), dialed)
}

#[tokio::test]
async fn the_refusing_side_reads_the_refusal_from_its_error() {
    let (server, client, stranger) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );

    // The server does not know the client.
    let (accepted, dialed) = link(
        server_config(&server, &pinned(&stranger), &[ALPN]).unwrap(),
        client_config(&client, &pinned(&server), &[ALPN]).unwrap(),
    )
    .await;
    assert_eq!(accepted.unwrap_err().refusal(), Some(Refusal::NotPinned));
    assert_eq!(dialed.unwrap_err().refusal(), None);

    // The client does not know the server, which the client's store has not accepted.
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    let (accepted, dialed) = link(
        server_config(&server, &pinned(&client), &[ALPN]).unwrap(),
        client_config(&client, &Trust::Pinned(Pins::store(store)), &[ALPN]).unwrap(),
    )
    .await;
    assert_eq!(dialed.unwrap_err().refusal(), Some(Refusal::NotAccepted));
    assert_eq!(accepted.unwrap_err().refusal(), None);

    // A server with a store records the unknown client that proved its key, and refuses it.
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    let (accepted, _) = link(
        server_config(&server, &Trust::Pinned(Pins::store(store.clone())), &[ALPN]).unwrap(),
        client_config(&client, &pinned(&server), &[ALPN]).unwrap(),
    )
    .await;
    assert_eq!(accepted.unwrap_err().refusal(), Some(Refusal::NotAccepted));
    assert_eq!(store.waiting().unwrap()[0].id, client.fingerprint());
}
