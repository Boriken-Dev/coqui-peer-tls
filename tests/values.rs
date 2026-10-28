//! The public types are thread-safe, and policy errors name what was expected without quoting
//! the input.

use coqui_peer_tls::{
    Built, Identity, PairConfig, PeerClientVerifier, PeerError, PeerIdentity, PeerServerVerifier,
    Pins, Policy, Refusal, ResponderTrust, Roots, Tls, TlsHandshake, TlsVersion, Trust, Weakening,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    assert_send_sync::<Built<rustls::ServerConfig>>();
    assert_send_sync::<Identity>();
    assert_send_sync::<PairConfig>();
    assert_send_sync::<PeerClientVerifier>();
    assert_send_sync::<PeerError>();
    assert_send_sync::<PeerIdentity>();
    assert_send_sync::<PeerServerVerifier>();
    assert_send_sync::<Pins>();
    assert_send_sync::<Policy>();
    assert_send_sync::<Refusal>();
    assert_send_sync::<ResponderTrust>();
    assert_send_sync::<Roots>();
    assert_send_sync::<Tls>();
    assert_send_sync::<TlsHandshake>();
    assert_send_sync::<TlsVersion>();
    assert_send_sync::<Trust>();
    assert_send_sync::<Weakening>();
}

#[test]
fn a_refused_policy_name_is_not_quoted_back() {
    let secret = "s3cret-value";
    for error in [
        secret.parse::<TlsVersion>().expect_err("not a version"),
        Policy::preset(secret).expect_err("not a preset"),
    ] {
        assert!(matches!(error, PeerError::Policy(_)));
        assert!(!error.to_string().contains(secret), "{error}");
    }
    let mut policy = Policy::modern();
    policy.cipher_suites = Some(vec![secret.to_owned()]);
    let error = policy.crypto_provider().expect_err("not a suite");
    assert!(error.to_string().contains("cipher_suites[0]"), "{error}");
    assert!(!error.to_string().contains(secret), "{error}");
    let mut policy = Policy::modern();
    policy.kx_groups = Some(vec![secret.to_owned()]);
    let error = policy.crypto_provider().expect_err("not a group");
    assert!(!error.to_string().contains(secret), "{error}");
}

#[test]
fn the_default_server_name_is_server_name() {
    let expected = rustls::pki_types::ServerName::try_from(coqui_peer_tls::SERVER_NAME)
        .expect("a DNS name")
        .to_owned();
    assert_eq!(coqui_peer_tls::default_server_name(), expected);
}

#[test]
fn a_policy_reports_weakenings_with_coqui_peers_type() {
    let mut policy = Policy::modern();
    policy.allow_resumption = true;
    let weakened: Vec<coqui_peer::Weakening> = policy.weakened();
    assert_eq!(
        weakened,
        [coqui_peer::Weakening::new(
            "allow_resumption",
            "true",
            "false"
        )]
    );
}

#[cfg(feature = "acl")]
#[test]
fn an_acl_weakening_is_converted_field_for_field() {
    let mut policy = Policy::modern();
    policy.acl = Some(coqui_net_acl::Acl {
        rules: Vec::new(),
        default: coqui_net_acl::Action::Permit,
    });
    assert_eq!(
        policy.weakened(),
        [Weakening::new("acl.default", "permit", "deny")]
    );
}

#[test]
fn a_policy_holds_its_waiting_limits_as_one_value() {
    let mut policy = Policy::modern();
    assert_eq!(policy.waiting, coqui_peer::WaitingLimits::default());
    policy.waiting.total = 5_000;
    policy.waiting.rerecord = core::time::Duration::from_secs(5);
    let settings: Vec<String> = policy.weakened().into_iter().map(|w| w.setting).collect();
    assert_eq!(settings, ["waiting_total", "waiting_rerecord_secs"]);
}

#[cfg(feature = "ca")]
#[test]
fn a_ca_file_that_cannot_be_read_is_named_in_the_error() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("missing-ca.pem");
    let trust = Trust::Ca(coqui_peer_tls::CaPolicy {
        ca_file: path.clone(),
        subject: Vec::new(),
        san: Vec::new(),
    });
    let refused = trust.client_cert_verifier().expect_err("no file");
    assert!(matches!(
        &refused,
        PeerError::CaFile { path: Some(named), certificate: None, read: Some(_) } if *named == path
    ));
    assert!(refused.to_string().contains("missing-ca.pem"), "{refused}");
}
