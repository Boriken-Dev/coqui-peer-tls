//! Profiles and policy: what each preset negotiates, what overrides restrict, and what is
//! reported as weaker. Run with `--all-features`.
#![cfg(all(feature = "generate", feature = "tokio", feature = "tls12"))]

use std::sync::Arc;

use coqui_peer::{
    Built, Digest, Identity, PeerError, Pins, Policy, TlsVersion, Trust, asynch,
    client_config_with, server_config_with,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"policy-test/1";

fn pinned(identity: &Identity) -> Trust {
    Trust::Pinned(Pins::fixed([identity.fingerprint()]))
}

/// A handshake and an echo between two built configurations.
async fn exchange(
    server_config: rustls::ServerConfig,
    client_config: rustls::ClientConfig,
) -> bool {
    let (near, far) = tokio::io::duplex(8192);
    let accepting = tokio::spawn(async move {
        let (mut stream, _) = asynch::accept(Arc::new(server_config), far).await.ok()?;
        let mut byte = [0u8; 4];
        stream.read_exact(&mut byte).await.ok()?;
        stream.write_all(&byte).await.ok()?;
        stream.flush().await.ok()
    });
    let dialed = async {
        let (mut stream, _) = asynch::dial(Arc::new(client_config), near).await.ok()?;
        stream.write_all(b"ping").await.ok()?;
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.ok()
    }
    .await;
    accepting.await.unwrap().is_some() && dialed.is_some()
}

/// Runs a handshake and an echo over an in-memory stream between a server under
/// `server_policy` and a client under `client_policy`; the negotiated version and suite on
/// success.
async fn connect(
    server_policy: &Policy,
    client_policy: &Policy,
) -> Option<(rustls::ProtocolVersion, String)> {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let Built {
        config: server_config,
        ..
    } = server_config_with(&server, &pinned(&client), &[ALPN], server_policy).ok()?;
    let Built {
        config: client_config,
        ..
    } = client_config_with(&client, &pinned(&server), &[ALPN], client_policy).ok()?;
    let (near, far) = tokio::io::duplex(8192);
    let accepting = tokio::spawn(async move {
        let (mut stream, _) = asynch::accept(Arc::new(server_config), far).await.ok()?;
        let mut byte = [0u8; 4];
        stream.read_exact(&mut byte).await.ok()?;
        stream.write_all(&byte).await.ok()?;
        stream.flush().await.ok()?;
        Some(())
    });
    let dialed = async {
        let (mut stream, _) = asynch::dial(Arc::new(client_config), near).await.ok()?;
        stream.write_all(b"ping").await.ok()?;
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.ok()?;
        let connection = stream.get_ref().1;
        let suite = connection.negotiated_cipher_suite()?;
        Some((
            connection.protocol_version()?,
            suite.suite().as_str().unwrap_or("?").to_owned(),
        ))
    }
    .await;
    let accepted = accepting.await.unwrap();
    accepted.and(dialed)
}

#[tokio::test]
async fn each_profile_builds_a_working_pair() {
    // A consumer's own profile is just a function returning a policy.
    let mut mine = Policy::strict();
    mine.name = "mine".to_owned();
    mine.pin_digests = vec![Digest::Sha256];
    for policy in [
        Policy::strict(),
        Policy::compatible(),
        Policy::legacy(),
        mine,
    ] {
        let (version, _) = connect(&policy, &policy)
            .await
            .unwrap_or_else(|| panic!("{} pair failed", policy.name));
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_3, "{}", policy.name);
    }
}

#[tokio::test]
async fn strict_is_tls13_only_and_compatible_also_speaks_tls12() {
    let strict = Policy::default();
    let compatible = Policy::compatible();
    let mut only_12 = compatible.clone();
    only_12.tls_versions = vec![TlsVersion::V1_2];
    // A client limited to 1.2 reaches a compatible server, over 1.2 and an AEAD suite.
    let (version, suite) = connect(&compatible, &only_12).await.expect("1.2 works");
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    assert!(
        suite.contains("GCM") || suite.contains("CHACHA20"),
        "{suite}"
    );
    // A strict server refuses it.
    assert!(connect(&strict, &only_12).await.is_none());
    // And a strict client cannot reach a server that only speaks 1.2.
    assert!(connect(&only_12, &strict).await.is_none());
}

#[tokio::test]
async fn cipher_suites_can_be_restricted_and_a_mismatch_fails() {
    let with = |suite: &str| {
        let mut policy = Policy::strict();
        policy.cipher_suites = Some(vec![suite.to_owned()]);
        policy
    };
    let aes = with("TLS13_AES_128_GCM_SHA256");
    let chacha = with("TLS13_CHACHA20_POLY1305_SHA256");
    let (_, suite) = connect(&aes, &aes).await.expect("matching suites");
    assert_eq!(suite, "TLS13_AES_128_GCM_SHA256");
    let (_, suite) = connect(&chacha, &chacha).await.expect("matching suites");
    assert_eq!(suite, "TLS13_CHACHA20_POLY1305_SHA256");
    assert!(connect(&aes, &chacha).await.is_none());
}

#[test]
fn unknown_suites_groups_and_versions_are_clear_errors_that_list_what_is_supported() {
    let mut policy = Policy::strict();
    policy.cipher_suites = Some(vec!["TLS_RSA_WITH_RC4_128_SHA".to_owned()]);
    let Err(PeerError::Policy(message)) = policy.crypto_provider() else {
        panic!("an unknown suite must be an error");
    };
    assert!(
        message.contains("TLS_RSA_WITH_RC4_128_SHA")
            && message.contains("TLS13_AES_128_GCM_SHA256")
    );
    assert!(Policy::supported_cipher_suites().contains(&"TLS13_AES_256_GCM_SHA384".to_owned()));

    let mut policy = Policy::strict();
    policy.kx_groups = Some(vec!["nonsense".to_owned()]);
    assert!(matches!(
        policy.crypto_provider(),
        Err(PeerError::Policy(_))
    ));
    assert!(Policy::supported_kx_groups().contains(&"X25519".to_owned()));
    let mut policy = Policy::strict();
    policy.kx_groups = Some(vec!["X25519".to_owned()]);
    assert!(policy.crypto_provider().is_ok());

    // TLS 1.2 allowed but every allowed suite is a 1.3 one.
    let mut policy = Policy::compatible();
    policy.cipher_suites = Some(vec!["TLS13_AES_128_GCM_SHA256".to_owned()]);
    assert!(matches!(
        policy.crypto_provider(),
        Err(PeerError::Policy(_))
    ));

    let Err(PeerError::Policy(message)) = "1.1".parse::<TlsVersion>() else {
        panic!("TLS 1.1 must be an error");
    };
    assert!(message.contains("only TLS 1.2 and 1.3"));
    assert!("1.0".parse::<TlsVersion>().is_err());
    let mut empty = Policy::strict();
    empty.tls_versions.clear();
    assert!(empty.crypto_provider().is_ok());
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    assert!(client_config_with(&client, &pinned(&server), &[ALPN], &empty).is_err());
}

#[tokio::test]
async fn a_sha1_pin_is_accepted_only_when_the_policy_allows_it() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let sha1_pin = |identity: &Identity| {
        Trust::Pinned(Pins::fixed([
            Digest::Sha1.of_certificate(identity.certificate_der())
        ]))
    };
    // Strict refuses to build with a SHA-1 pin, and names the digest.
    let strict = Policy::default();
    let Err(PeerError::Policy(message)) =
        server_config_with(&server, &sha1_pin(&client), &[ALPN], &strict)
    else {
        panic!("a sha1 pin must be refused under strict");
    };
    assert!(message.contains("sha1") && message.contains("sha256"));
    // Compatible refuses too; legacy accepts, and the handshake works.
    assert!(
        server_config_with(&server, &sha1_pin(&client), &[ALPN], &Policy::compatible()).is_err()
    );
    let legacy = Policy::legacy();
    let Built {
        config: server_config,
        weakened,
    } = server_config_with(&server, &sha1_pin(&client), &[ALPN], &legacy).unwrap();
    assert!(weakened.iter().any(|w| w.setting == "pin_digests"));
    let Built {
        config: client_config,
        ..
    } = client_config_with(&client, &sha1_pin(&server), &[ALPN], &legacy).unwrap();
    assert!(exchange(server_config, client_config).await);
    // A SHA-384 pin is fine under strict.
    let sha384 = Trust::Pinned(Pins::fixed([
        Digest::Sha384.of_certificate(client.certificate_der())
    ]));
    assert!(server_config_with(&server, &sha384, &[ALPN], &strict).is_ok());
}

#[test]
fn weakening_is_reported_as_plain_data() {
    assert!(Policy::default().weakened().is_empty());
    let compatible = Policy::compatible().weakened();
    assert_eq!(compatible.len(), 1);
    assert_eq!(
        (
            compatible[0].setting.as_str(),
            compatible[0].value.as_str(),
            compatible[0].strict.as_str()
        ),
        ("tls_versions", "1.2,1.3", "1.3")
    );
    let mut policy = Policy::legacy();
    policy.check_validity = false;
    policy.allow_chain_when_pinned = true;
    policy.waiting_per_source = 64;
    let settings: Vec<String> = policy.weakened().into_iter().map(|w| w.setting).collect();
    assert_eq!(
        settings,
        [
            "tls_versions",
            "pin_digests",
            "check_validity",
            "allow_chain_when_pinned",
            "waiting_per_source"
        ]
    );
    // The builders hand the same list back.
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let built = client_config_with(&client, &pinned(&server), &[ALPN], &policy).unwrap();
    assert_eq!(built.weakened, policy.weakened());
    // Fields are plain: stricter-than-default overrides are not weakenings.
    let mut tighter = Policy::strict();
    tighter.pin_digests = vec![Digest::Sha256];
    tighter.waiting_per_source = 4;
    assert!(tighter.weakened().is_empty());
}

#[tokio::test]
async fn validity_checking_can_be_switched_off_by_policy() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut parameters = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.not_before = rcgen::date_time_ymd(2001, 1, 1);
    parameters.not_after = rcgen::date_time_ymd(2002, 1, 1);
    let certificate = parameters.self_signed(&key).unwrap();
    let expired =
        Identity::from_pem(&format!("{}{}", certificate.pem(), key.serialize_pem())).unwrap();
    let server = Identity::generate().unwrap();
    let run = |policy: Policy| {
        let (server, expired) = (server.clone(), expired.clone());
        async move {
            let server_config = server_config_with(&server, &pinned(&expired), &[ALPN], &policy)
                .unwrap()
                .config;
            let client_config = client_config_with(&expired, &pinned(&server), &[ALPN], &policy)
                .unwrap()
                .config;
            exchange(server_config, client_config).await
        }
    };
    assert!(!run(Policy::default()).await);
    let mut lax = Policy::strict();
    lax.check_validity = false;
    assert!(run(lax).await);
}
