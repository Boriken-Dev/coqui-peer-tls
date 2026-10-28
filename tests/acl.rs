//! A policy's access control list, applied by every server configuration built under it: by
//! address at the `ClientHello`, by fingerprint before the trust store is consulted.
#![cfg(all(feature = "acl", feature = "generate"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use coqui_net_acl::{Acl, Action, IpNet, Rule};
use coqui_peer::Handshake;
use coqui_peer_tls::{
    Identity, PeerError, PeerId, PeerIdentity, Pins, Policy, Refusal, ServerConfigs, TlsHandshake,
    Trust, TrustStore, accept, accept_from, client_config, client_config_without_identity, dial,
    server_config_with, server_config_with_verifier,
};
use rustls::{AlertDescription, ServerConfig};

const ALPN: &[u8] = b"acl-test/1";

fn rule(action: Action, source: &str) -> Rule {
    Rule::new(action, source.parse().expect("a network"))
}

fn named(action: Action, source: &str, fingerprint: String) -> Rule {
    let mut rule = rule(action, source);
    rule.fingerprint = Some(fingerprint);
    rule
}

fn policy(rules: Vec<Rule>, default: Action) -> Policy {
    let mut policy = Policy::strict();
    policy.acl = Some(Acl { rules, default });
    policy
}

/// Accepts one connection with `accept`, then echoes four bytes.
fn serve(config: ServerConfig) -> (SocketAddr, JoinHandle<Result<PeerIdentity, PeerError>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let address = listener.local_addr().expect("an address");
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().map_err(PeerError::Io)?;
        let (mut stream, peer) = accept(Arc::new(config), socket)?;
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).map_err(PeerError::Io)?;
        stream.write_all(&ping).map_err(PeerError::Io)?;
        stream.flush().map_err(PeerError::Io)?;
        Ok(peer)
    });
    (address, served)
}

/// Dials as `client`, pings and reads the echo.
fn ping(address: SocketAddr, client: &Identity) -> Result<(), PeerError> {
    let config = client_config(client, &Trust::AnyWithKeyProof, &[ALPN])?;
    let socket = TcpStream::connect(address).map_err(PeerError::Io)?;
    let (mut stream, _) = dial(Arc::new(config), socket)?;
    stream.write_all(b"ping").map_err(PeerError::Io)?;
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).map_err(PeerError::Io)?;
    Ok(())
}

/// The TLS alert the other side sent, when that is the error.
fn alert(error: &PeerError) -> Option<AlertDescription> {
    let PeerError::Io(error) = error else {
        return None;
    };
    match error.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::AlertReceived(alert) => Some(*alert),
        _ => None,
    }
}

fn server(identity: &Identity, policy: &Policy) -> Result<ServerConfig, PeerError> {
    Ok(server_config_with(identity, &Trust::AnyWithKeyProof, &[ALPN], policy)?.config)
}

#[test]
fn without_a_list_every_client_is_admitted() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let (address, served) = serve(server(&identity, &Policy::strict())?);
    ping(address, &Identity::generate()?)?;
    served.join().expect("no panic")?;
    Ok(())
}

#[test]
fn a_permitted_address_and_peer_is_admitted() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let policy = policy(
        vec![named(
            Action::Permit,
            "127.0.0.0/8",
            client.fingerprint().to_string(),
        )],
        Action::Deny,
    );
    let (address, served) = serve(server(&identity, &policy)?);
    ping(address, &client)?;
    assert_eq!(
        served.join().expect("no panic")?.fingerprint,
        client.fingerprint()
    );
    Ok(())
}

#[test]
fn a_denied_address_is_refused_at_the_hello_with_access_denied() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let policy = policy(
        vec![rule(Action::Deny, "127.0.0.1"), rule(Action::Permit, "any")],
        Action::Permit,
    );
    let (address, served) = serve(server(&identity, &policy)?);
    let refused = ping(address, &Identity::generate()?).expect_err("denied");
    assert_eq!(alert(&refused), Some(AlertDescription::AccessDenied));
    assert_eq!(refused.refusal(), None);
    let server_side = served.join().expect("no panic").expect_err("denied");
    assert_eq!(
        server_side.refusal(),
        Some(Refusal::AddressDenied { rule: Some(0) })
    );
    Ok(())
}

#[test]
fn a_denied_peer_is_refused_by_its_fingerprint_in_any_spelling() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    // Grouped base32 in the list; the verifier decides by the canonical `sha256:<hex>`.
    let policy = policy(
        vec![
            named(
                Action::Deny,
                "any",
                client.fingerprint().to_base32_grouped(),
            ),
            rule(Action::Permit, "any"),
        ],
        Action::Deny,
    );
    let (address, served) = serve(server(&identity, &policy)?);
    let refused = ping(address, &client).expect_err("denied");
    assert_eq!(alert(&refused), Some(AlertDescription::CertificateUnknown));
    let server_side = served.join().expect("no panic").expect_err("denied");
    assert_eq!(
        server_side.refusal(),
        Some(Refusal::PeerDenied { rule: Some(0) })
    );
    // Another client from the same address passes the rule.
    let (address, served) = serve(server(&identity, &policy)?);
    ping(address, &Identity::generate()?)?;
    served.join().expect("no panic")?;
    Ok(())
}

#[test]
fn a_client_the_list_denies_is_never_recorded_as_waiting() -> Result<(), PeerError> {
    let directory = tempfile::tempdir().map_err(PeerError::Io)?;
    let store = TrustStore::open(directory.path())?;
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let policy = policy(
        vec![named(Action::Deny, "any", client.fingerprint().hex())],
        Action::Permit,
    );
    let trust = Trust::Pinned(Pins::store(store.clone()));
    let config = server_config_with(&identity, &trust, &[ALPN], &policy)?.config;
    let (address, served) = serve(config);
    assert!(ping(address, &client).is_err());
    let server_side = served.join().expect("no panic").expect_err("denied");
    assert_eq!(
        server_side.refusal(),
        Some(Refusal::PeerDenied { rule: Some(0) })
    );
    assert!(store.waiting()?.is_empty());
    Ok(())
}

#[test]
fn a_rule_that_is_no_sha256_id_refuses_the_configuration() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let sha384 = coqui_peer::Digest::Sha384.of(identity.certificate_der());
    for fingerprint in ["not an id".to_owned(), sha384.to_string()] {
        let policy = policy(
            vec![named(Action::Permit, "any", fingerprint)],
            Action::Deny,
        );
        let refused = server(&identity, &policy).expect_err("refused");
        assert!(matches!(refused, PeerError::Policy(_)), "{refused:?}");
    }
    Ok(())
}

#[test]
fn a_list_needing_the_local_address_refuses_a_connection_without_one() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let mut by_port = rule(Action::Permit, "any");
    by_port.port = Some("1-65535".parse().expect("a range"));
    let policy = policy(vec![by_port], Action::Deny);
    let config = Arc::new(server(&identity, &policy)?);
    let listener = TcpListener::bind("127.0.0.1:0").map_err(PeerError::Io)?;
    let address = listener.local_addr().map_err(PeerError::Io)?;
    let served = thread::spawn(move || -> Result<(), PeerError> {
        let (socket, from) = listener.accept().map_err(PeerError::Io)?;
        // accept_from knows the source only.
        accept_from(config, socket, from).map(|_| ())
    });
    assert!(ping(address, &Identity::generate()?).is_err());
    let server_side = served.join().expect("no panic").expect_err("refused");
    assert_eq!(server_side.refusal(), Some(Refusal::AddressUnknown));
    Ok(())
}

#[test]
fn a_configuration_for_one_connection_decides_without_a_scope() -> Result<(), PeerError> {
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let policy = policy(
        vec![named(
            Action::Deny,
            "192.0.2.0/24",
            client.fingerprint().to_string(),
        )],
        Action::Permit,
    );
    // As a quinn host would: the addresses are the configuration's, no accept helper runs.
    let source: SocketAddr = "192.0.2.7:4000".parse().expect("an address");
    let local: SocketAddr = "198.51.100.1:443".parse().expect("an address");
    assert_eq!(policy.admits_address(source, local), Ok(()));
    let configs = ServerConfigs::new(&identity, &Trust::AnyWithKeyProof, &[ALPN], &policy)?;
    let config = configs.for_connection(source, local)?;
    let client_config = client_config(&client, &Trust::AnyWithKeyProof, &[ALPN])?;
    let mut server = TlsHandshake::server(config.config(), None)?;
    let mut dialer = TlsHandshake::client(Arc::new(client_config))?;
    let refused = 'pump: loop {
        while let Some(bytes) = dialer.transmit()? {
            if let Err(error) = server.receive(&bytes) {
                break 'pump Some(error);
            }
        }
        while let Some(bytes) = server.transmit()? {
            let _ = dialer.receive(&bytes);
        }
        if server.is_complete() && dialer.is_complete() {
            break None;
        }
    };
    let refused = refused.expect("the peer is denied from that source");
    assert_eq!(
        refused.refusal(),
        Some(Refusal::PeerDenied { rule: Some(0) })
    );
    assert_eq!(
        config.refusal(),
        Some(Refusal::PeerDenied { rule: Some(0) })
    );
    Ok(())
}

#[test]
fn a_policy_checks_an_address_before_any_handshake() {
    let policy = policy(
        vec![
            rule(Action::Deny, "10.0.0.0/8"),
            named(Action::Permit, "any", PeerId::of(b"x").to_string()),
        ],
        Action::Deny,
    );
    let local: SocketAddr = "192.0.2.1:443".parse().expect("an address");
    let at = |source: &str| source.parse::<SocketAddr>().expect("an address");
    assert_eq!(
        policy.admits_address(at("10.1.1.1:1"), local),
        Err(Refusal::AddressDenied { rule: Some(0) })
    );
    // A client that will present a certificate is deferred to it; one that will not is not.
    assert_eq!(policy.admits_address(at("192.0.2.9:1"), local), Ok(()));
    assert_eq!(
        policy.admits_anonymous(at("192.0.2.9:1"), local),
        Err(Refusal::AddressDenied { rule: None })
    );
    assert_eq!(
        Policy::strict().admits_anonymous(at("10.1.1.1:1"), local),
        Ok(())
    );
    let _ = IpNet::Any;
}

#[test]
fn a_verifier_for_one_connection_records_waiting_entries_under_its_source() -> Result<(), PeerError>
{
    let directory = tempfile::tempdir().map_err(PeerError::Io)?;
    let store = TrustStore::open(directory.path())?;
    let identity = Identity::generate()?;
    let client = Identity::generate()?;
    let source: SocketAddr = "192.0.2.7:4000".parse().expect("an address");
    let local: SocketAddr = "198.51.100.1:443".parse().expect("an address");
    let trust = Trust::Pinned(Pins::store(store.clone()));
    let verifier = trust.client_cert_verifier_for(&Policy::strict(), source, local)?;
    let config = coqui_peer_tls::server_config_with_verifier(
        &identity,
        verifier,
        &[ALPN],
        &Policy::strict(),
    )?;
    let mut server = TlsHandshake::server(Arc::new(config.config), None)?;
    let mut dialer = TlsHandshake::client(Arc::new(client_config(
        &client,
        &Trust::AnyWithKeyProof,
        &[ALPN],
    )?))?;
    'pump: for _ in 0..16 {
        while let Some(bytes) = dialer.transmit()? {
            if server.receive(&bytes).is_err() {
                break 'pump;
            }
        }
        while let Some(bytes) = server.transmit()? {
            let _ = dialer.receive(&bytes);
        }
    }
    let waiting = store.waiting()?;
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].id, client.fingerprint());
    assert_eq!(waiting[0].source, Some(source));
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn a_policy_read_from_text_holds_canonical_fingerprints() -> Result<(), PeerError> {
    let id = Identity::generate()?.fingerprint();
    let text = format!(
        "[acl]\ndefault = \"deny\"\n\n[[acl.rule]]\naction = \"permit\"\nfingerprint = \"{}\"\n",
        id.to_base32_grouped()
    );
    let policy: Policy = toml::from_str(&text).expect("a policy");
    let acl = policy.acl.expect("a list");
    assert_eq!(acl.rules[0].fingerprint, Some(id.to_string()));
    let refused = toml::from_str::<Policy>(
        "[acl]\n[[acl.rule]]\naction = \"permit\"\nfingerprint = \"secret-text\"\n",
    )
    .expect_err("not an id");
    assert!(refused.to_string().contains("acl rule 0"), "{refused}");
    assert!(!refused.to_string().contains("secret-text"), "{refused}");
    Ok(())
}

/// A verifier that lets a client present no certificate, as a host's own may.
#[derive(Debug)]
struct Optional(Arc<dyn rustls::server::danger::ClientCertVerifier>);

impl rustls::server::danger::ClientCertVerifier for Optional {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        certificate: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.0.verify_client_cert(certificate, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signed: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, certificate, signed)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signed: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, certificate, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// Runs a server and a client handshake against each other in memory: the server's error, if
/// it refused.
fn pump(
    server: &mut TlsHandshake,
    dialer: &mut TlsHandshake,
) -> Result<Option<PeerError>, PeerError> {
    for _ in 0..16 {
        while let Some(bytes) = dialer.transmit()? {
            if let Err(error) = server.receive(&bytes) {
                return Ok(Some(error));
            }
        }
        while let Some(bytes) = server.transmit()? {
            let _ = dialer.receive(&bytes);
        }
        if server.is_complete() && dialer.is_complete() {
            return Ok(None);
        }
    }
    Ok(None)
}

#[test]
fn a_rule_naming_a_fingerprint_never_admits_a_client_without_a_certificate() -> Result<(), PeerError>
{
    let identity = Identity::generate()?;
    let allowed = Identity::generate()?;
    // Only the holder of `allowed` may connect.
    let policy = policy(
        vec![named(
            Action::Permit,
            "0.0.0.0/0",
            allowed.fingerprint().to_string(),
        )],
        Action::Deny,
    );
    let inner = Trust::AnyWithKeyProof.client_cert_verifier_with(&Policy::strict())?;
    let verifier = Arc::new(Optional(inner));
    let config = server_config_with_verifier(&identity, verifier, &[ALPN], &policy)?;
    let source: SocketAddr = "192.0.2.7:4000".parse().expect("an address");
    let mut server = TlsHandshake::server(Arc::new(config.config), Some(source))?;
    let anonymous = client_config_without_identity(&Trust::AnyWithKeyProof, &[ALPN])?;
    let mut dialer = TlsHandshake::client(Arc::new(anonymous))?;
    let refused = pump(&mut server, &mut dialer)?.expect("an anonymous client is refused");
    assert_eq!(
        refused.refusal(),
        Some(Refusal::AddressDenied { rule: None })
    );
    Ok(())
}
