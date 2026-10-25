//! The serialized form of `Policy` (format version 1) pinned by committed files in
//! `tests/vectors/policy/`, in TOML and in JSON, for implementations in other languages.
//!
//! Regenerating them is a format change:
//! `cargo test -p coqui-peer-tls --all-features --test policy_vectors -- --ignored regenerate`
#![cfg(all(feature = "serde", feature = "acl"))]

use std::fs;
use std::path::{Path, PathBuf};

use coqui_peer_tls::Policy;
use coqui_peer_tls::acl::{Acl, Action, IpNet, Rule};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/policy")
}

/// The policies the vectors hold: each preset, and one with an ACL.
fn policies() -> Vec<(&'static str, Policy)> {
    let mut routed = Policy::compatible();
    routed.cipher_suites = Some(vec![
        "TLS13_AES_256_GCM_SHA384".to_owned(),
        "TLS13_CHACHA20_POLY1305_SHA256".to_owned(),
    ]);
    routed.kx_groups = Some(vec!["X25519".to_owned()]);
    routed.waiting_per_source = 8;
    let mut permit = Rule::new(Action::Permit, "10.9.0.0/16".parse::<IpNet>().unwrap());
    permit.destination = Some("10.6.20.5".parse().unwrap());
    permit.port = Some("7000-7100".parse().unwrap());
    permit.log = true;
    let mut named = Rule::new(Action::Permit, IpNet::Any);
    named.fingerprint = Some(format!("sha256:{}", "ab".repeat(32)));
    routed.acl = Some(Acl {
        rules: vec![permit, named, Rule::new(Action::Deny, IpNet::Any)],
        default: Action::Deny,
    });
    vec![
        ("strict", Policy::strict()),
        ("compatible", Policy::compatible()),
        ("legacy", Policy::legacy()),
        ("acl", routed),
    ]
}

fn toml_of(policy: &Policy) -> String {
    toml::to_string(policy).unwrap()
}

fn json_of(policy: &Policy) -> String {
    let mut text = serde_json::to_string_pretty(policy).unwrap();
    text.push('\n');
    text
}

#[test]
fn each_vector_reads_back_to_its_policy_in_both_encodings_byte_for_byte() {
    for (name, policy) in policies() {
        let toml_text = fs::read_to_string(directory().join(format!("{name}.toml"))).unwrap();
        let json_text = fs::read_to_string(directory().join(format!("{name}.json"))).unwrap();
        assert_eq!(
            toml::from_str::<Policy>(&toml_text).unwrap(),
            policy,
            "{name}.toml"
        );
        assert_eq!(
            serde_json::from_str::<Policy>(&json_text).unwrap(),
            policy,
            "{name}.json"
        );
        assert_eq!(
            toml_of(&policy),
            toml_text,
            "{name}.toml is not the canonical text"
        );
        assert_eq!(
            json_of(&policy),
            json_text,
            "{name}.json is not the canonical text"
        );
    }
}

#[test]
fn a_document_may_name_a_profile_and_override_fields_and_nothing_else() {
    let policy: Policy = toml::from_str(
        "profile = \"compatible\"\ncheck_validity = false\npin_digests = [\"sha256\"]\n",
    )
    .unwrap();
    assert_eq!(policy.name, "compatible");
    assert!(!policy.check_validity);
    assert_eq!(policy.tls_versions.len(), 2);
    assert_eq!(policy.pin_digests.len(), 1);
    assert_eq!(toml::from_str::<Policy>("").unwrap(), Policy::default());
    for bad in [
        "policy_version = 2",
        "surprise = 1",
        "profile = \"lax\"",
        "tls_versions = [\"1.1\"]",
        "pin_digests = [\"md5\"]",
        "[acl]\ndefault = \"maybe\"",
    ] {
        assert!(toml::from_str::<Policy>(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_acl_example_reads_like_a_router_listing() {
    let (_, policy) = policies().pop().unwrap();
    assert_eq!(
        policy.acl.unwrap().to_string(),
        format!(
            "10 permit 10.9.0.0/16 destination 10.6.20.5 port 7000-7100 log\n\
             20 permit any fingerprint sha256:{}\n\
             30 deny any\n\
             default deny\n",
            "ab".repeat(32)
        )
    );
}

#[test]
#[ignore = "rewrites the committed vectors"]
fn regenerate() {
    fs::create_dir_all(directory()).unwrap();
    for (name, policy) in policies() {
        fs::write(directory().join(format!("{name}.toml")), toml_of(&policy)).unwrap();
        fs::write(directory().join(format!("{name}.json")), json_of(&policy)).unwrap();
    }
}

#[test]
fn a_consumer_reads_a_document_over_its_own_profile() {
    let mut mine = Policy::compatible();
    mine.name = "mine".to_owned();
    mine.waiting_total = 50;
    let policy = Policy::deserialize_over(
        mine,
        toml::Deserializer::parse("check_validity = false").unwrap(),
    )
    .unwrap();
    assert_eq!(policy.name, "mine");
    assert_eq!(policy.waiting_total, 50);
    assert!(!policy.check_validity);
    assert_eq!(policy.tls_versions.len(), 2);
    assert!(Policy::preset("mine").is_err());
}
