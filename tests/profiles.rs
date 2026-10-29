//! Cipher profiles: what each allows, how a set of them combines, and what a peer outside
//! them is refused.
#![cfg(feature = "generate")]

use std::collections::BTreeSet;
use std::sync::Arc;

use coqui_peer::Handshake;
use coqui_peer_tls::{
    CipherProfile, Identity, PeerError, Policy, TlsHandshake, TlsVersion, Trust,
    client_config_with, server_config_with,
};
use rustls::{Connection, SignatureScheme};

const ALPN: &[u8] = b"profiles-test/1";

fn with(profiles: &[CipherProfile]) -> Policy {
    Policy {
        cipher_profiles: profiles.to_vec(),
        ..Policy::default()
    }
}

fn suites(policy: &Policy) -> BTreeSet<String> {
    let provider = policy.crypto_provider().expect("a provider");
    provider
        .cipher_suites
        .iter()
        .map(|suite| format!("{:?}", suite.suite()))
        .collect()
}

fn groups(policy: &Policy) -> Vec<String> {
    let provider = policy.crypto_provider().expect("a provider");
    provider
        .kx_groups
        .iter()
        .map(|group| format!("{:?}", group.name()))
        .collect()
}

fn schemes(policy: &Policy) -> Vec<SignatureScheme> {
    policy
        .crypto_provider()
        .expect("a provider")
        .signature_verification_algorithms
        .supported_schemes()
}

/// A P-384 identity, as the CNSA profiles need.
fn p384() -> Identity {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("a key");
    let certificate = rcgen::CertificateParams::new(vec!["coqui-peer.invalid".to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    Identity::from_pem(&format!("{}{}", certificate.pem(), key.serialize_pem()))
        .expect("an identity")
}

/// Handshakes a server under `server_policy` with a client under `client_policy`, in memory;
/// the client's connection, or the error that ended it.
fn connect(
    server_policy: &Policy,
    server: &Identity,
    client_policy: &Policy,
    client: &Identity,
) -> Result<Connection, PeerError> {
    let server_config =
        server_config_with(server, &Trust::AnyWithKeyProof, &[ALPN], server_policy)?.config;
    let client_config =
        client_config_with(client, &Trust::AnyWithKeyProof, &[ALPN], client_policy)?.config;
    let mut accepting = TlsHandshake::server(Arc::new(server_config), None)?;
    let mut dialing = TlsHandshake::client(Arc::new(client_config))?;
    for _ in 0..16 {
        while let Some(bytes) = dialing.transmit()? {
            accepting.receive(&bytes)?;
        }
        while let Some(bytes) = accepting.transmit()? {
            dialing.receive(&bytes)?;
        }
        if accepting.is_complete() && dialing.is_complete() {
            break;
        }
    }
    Ok(dialing.finish()?.session)
}

#[test]
fn every_preset_allows_mozilla_on_ring() {
    for policy in [Policy::modern(), Policy::intermediate(), Policy::legacy()] {
        assert_eq!(policy.cipher_profiles, [CipherProfile::Mozilla]);
        assert_eq!(policy.crypto, coqui_peer_tls::Crypto::Ring);
    }
}

#[test]
fn profile_names_round_trip_and_an_unknown_one_lists_the_known() {
    for profile in CipherProfile::ALL {
        assert_eq!(profile.as_str().parse::<CipherProfile>().unwrap(), *profile);
    }
    let Err(PeerError::Policy(message)) = "fips".parse::<CipherProfile>() else {
        panic!("an unknown profile is refused");
    };
    assert!(message.contains("fips-140-3-compliant") && message.contains("cnsa-2.0"));
}

#[test]
fn fips_140_3_compliant_offers_no_chacha20_x25519_alone_or_ed25519() {
    let policy = with(&[CipherProfile::Fips1403Compliant]);
    assert!(
        !suites(&policy)
            .iter()
            .any(|suite| suite.contains("CHACHA20"))
    );
    assert!(!groups(&policy).contains(&"X25519".to_owned()));
    assert!(!schemes(&policy).contains(&SignatureScheme::ED25519));
    assert!(schemes(&policy).contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
}

#[test]
fn fips_140_3_compliant_refuses_a_chacha20_only_or_x25519_only_peer() -> Result<(), PeerError> {
    let (server, client) = (Identity::generate()?, Identity::generate()?);
    let fips = with(&[CipherProfile::Fips1403Compliant]);
    let chacha = Policy {
        cipher_suites: Some(vec![
            "TLS13_CHACHA20_POLY1305_SHA256".to_owned(),
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_owned(),
        ]),
        ..Policy::default()
    };
    assert!(connect(&fips, &server, &chacha, &client).is_err());
    let x25519 = Policy {
        kx_groups: Some(vec!["X25519".to_owned()]),
        ..Policy::default()
    };
    assert!(connect(&fips, &server, &x25519, &client).is_err());
    // A default peer meets it.
    connect(&fips, &server, &Policy::default(), &client)?;
    Ok(())
}

#[test]
fn fips_140_2_compliant_is_fips_140_3_compliant_on_ring() {
    let three = with(&[CipherProfile::Fips1403Compliant]);
    let two = with(&[CipherProfile::Fips1402Compliant]);
    assert_eq!(suites(&three), suites(&two));
    assert_eq!(groups(&three), groups(&two));
    assert_eq!(schemes(&three), schemes(&two));
}

#[test]
fn a_set_with_mozilla_offers_what_mozilla_offers() {
    let mozilla = with(&[CipherProfile::Mozilla]);
    let both = with(&[CipherProfile::Fips1403Compliant, CipherProfile::Mozilla]);
    assert_eq!(suites(&both), suites(&mozilla));
    assert_eq!(
        groups(&both).into_iter().collect::<BTreeSet<_>>(),
        groups(&mozilla).into_iter().collect::<BTreeSet<_>>()
    );
    assert_eq!(schemes(&both), schemes(&mozilla));
    // Preference follows the first listed: the FIPS groups come first.
    assert_eq!(groups(&both)[0], "secp256r1");
    assert_eq!(groups(&mozilla)[0], "X25519");
}

#[test]
fn cnsa_1_refuses_a_p256_only_peer_and_meets_a_p384_one() -> Result<(), PeerError> {
    let (server, client) = (p384(), p384());
    let cnsa = with(&[CipherProfile::Cnsa1]);
    assert_eq!(groups(&cnsa), ["secp384r1"]);
    let p256 = Policy {
        kx_groups: Some(vec!["secp256r1".to_owned()]),
        ..Policy::default()
    };
    assert!(connect(&cnsa, &server, &p256, &client).is_err());
    let session = connect(&cnsa, &server, &cnsa, &client)?;
    assert_eq!(
        session.negotiated_cipher_suite().map(|suite| suite.suite()),
        Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
    // A generated (P-256) identity cannot sign for it.
    let generated = Identity::generate()?;
    assert!(connect(&cnsa, &generated, &cnsa, &client).is_err());
    Ok(())
}

#[test]
fn cnsa_2_needs_aws_lc() {
    let cnsa = with(&[CipherProfile::Cnsa2]);
    let Err(PeerError::Policy(message)) = cnsa.check() else {
        panic!("ring has no ML-KEM or ML-DSA");
    };
    assert!(
        message.contains("cnsa-2.0 needs crypto = aws-lc"),
        "{message}"
    );
}

#[test]
fn a_profile_set_leaving_no_suite_for_a_version_drops_it() {
    // CNSA 1.0 under TLS 1.3 only still has its 1.3 suite; with TLS 1.2 only, its 1.2 ones.
    let mut only_12 = with(&[CipherProfile::Cnsa1]);
    only_12.tls_versions = vec![TlsVersion::V1_2];
    assert!(
        suites(&only_12)
            .iter()
            .all(|suite| suite.starts_with("TLS_ECDHE"))
    );
    let empty = Policy {
        cipher_profiles: Vec::new(),
        ..Policy::default()
    };
    assert!(matches!(empty.check(), Err(PeerError::Policy(_))));
}

#[cfg(not(feature = "fips"))]
#[test]
fn the_validated_profile_needs_the_fips_feature() {
    const { assert!(!CipherProfile::FIPS_VALIDATED_AVAILABLE) };
    let validated = with(&[CipherProfile::Fips1403Validated]);
    let Err(PeerError::Policy(message)) = validated.check() else {
        panic!("this build has no FIPS module");
    };
    assert_eq!(message, "this build has no FIPS module: feature fips");
}

#[cfg(not(feature = "aws-lc"))]
#[test]
fn aws_lc_needs_its_feature() {
    let policy = Policy {
        crypto: coqui_peer_tls::Crypto::AwsLc,
        ..Policy::default()
    };
    const { assert!(!coqui_peer_tls::Crypto::AWS_LC_AVAILABLE) };
    assert!(matches!(policy.check(), Err(PeerError::Policy(_))));
}

#[cfg(feature = "aws-lc")]
mod aws_lc {
    use super::*;
    use coqui_peer_tls::Crypto;

    fn on_aws_lc(profiles: &[CipherProfile]) -> Policy {
        Policy {
            crypto: Crypto::AwsLc,
            ..with(profiles)
        }
    }

    fn ml_dsa_87() -> Identity {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/mldsa87.pem"),
        )
        .expect("the ML-DSA-87 vector");
        Identity::from_pem(&text).expect("an identity")
    }

    #[test]
    fn fips_140_2_compliant_lacks_the_ml_kem_groups() {
        let three = on_aws_lc(&[CipherProfile::Fips1403Compliant]);
        let two = on_aws_lc(&[CipherProfile::Fips1402Compliant]);
        assert!(groups(&three).iter().any(|group| group.contains("MLKEM")));
        assert!(!groups(&two).iter().any(|group| group.contains("MLKEM")));
        assert_eq!(groups(&two), ["secp256r1", "secp384r1"]);
        assert_eq!(suites(&three), suites(&two));
    }

    #[test]
    fn mozilla_on_aws_lc_prefers_the_hybrid_group() {
        assert_eq!(
            groups(&on_aws_lc(&[CipherProfile::Mozilla]))[0],
            "X25519MLKEM768"
        );
    }

    #[test]
    fn cnsa_2_negotiates_tls13_with_mlkem1024_and_ml_dsa_87() -> Result<(), PeerError> {
        let cnsa = on_aws_lc(&[CipherProfile::Cnsa2]);
        assert_eq!(groups(&cnsa), ["MLKEM1024"]);
        assert_eq!(schemes(&cnsa), [SignatureScheme::ML_DSA_87]);
        let (server, client) = (ml_dsa_87(), ml_dsa_87());
        let session = connect(&cnsa, &server, &cnsa, &client)?;
        assert_eq!(
            session.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            session
                .negotiated_key_exchange_group()
                .map(|group| group.name()),
            Some(rustls::NamedGroup::MLKEM1024)
        );
        // A P-384 identity cannot sign for it.
        assert!(connect(&cnsa, &p384(), &cnsa, &client).is_err());
        Ok(())
    }
}

#[cfg(feature = "fips")]
mod fips {
    use super::*;

    #[test]
    fn the_validated_profile_builds_configurations_rustls_reports_fips() -> Result<(), PeerError> {
        const { assert!(CipherProfile::FIPS_VALIDATED_AVAILABLE) };
        let identity = Identity::generate()?;
        let validated = with(&[CipherProfile::Fips1403Validated]);
        let server = server_config_with(&identity, &Trust::AnyWithKeyProof, &[ALPN], &validated)?;
        let client = client_config_with(&identity, &Trust::AnyWithKeyProof, &[ALPN], &validated)?;
        assert!(server.config.fips());
        assert!(client.config.fips());
        Ok(())
    }

    #[test]
    fn listed_with_mozilla_it_keeps_only_what_the_module_approves() {
        let both = with(&[CipherProfile::Mozilla, CipherProfile::Fips1403Validated]);
        assert!(!suites(&both).iter().any(|suite| suite.contains("CHACHA20")));
        assert!(!groups(&both).contains(&"X25519".to_owned()));
        assert!(both.crypto_provider().expect("a provider").fips());
    }

    #[test]
    fn a_validated_configuration_rustls_does_not_report_fips_is_refused() -> Result<(), PeerError> {
        let identity = Identity::generate()?;
        // TLS 1.2 without the extended master secret is not FIPS.
        let loose = Policy {
            require_ems: false,
            ..with(&[CipherProfile::Fips1403Validated])
        };
        let Err(PeerError::Policy(message)) =
            server_config_with(&identity, &Trust::AnyWithKeyProof, &[ALPN], &loose)
        else {
            panic!("a configuration rustls does not report FIPS is refused");
        };
        assert!(message.starts_with("fips-140-3-validated"), "{message}");
        Ok(())
    }
}
