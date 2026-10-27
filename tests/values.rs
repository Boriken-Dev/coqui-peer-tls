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
    let mut policy = Policy::strict();
    policy.cipher_suites = Some(vec![secret.to_owned()]);
    let error = policy.crypto_provider().expect_err("not a suite");
    assert!(error.to_string().contains("cipher_suites[0]"), "{error}");
    assert!(!error.to_string().contains(secret), "{error}");
    let mut policy = Policy::strict();
    policy.kx_groups = Some(vec![secret.to_owned()]);
    let error = policy.crypto_provider().expect_err("not a group");
    assert!(!error.to_string().contains(secret), "{error}");
}
