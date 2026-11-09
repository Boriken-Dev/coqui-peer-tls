//! The serialized form of `Policy` pinned by committed files in `tests/vectors/policy/`, in
//! TOML and in JSON, for implementations in other languages.
//!
//! Regenerating them is a format change:
//! `cargo test -p coqui-peer-tls --all-features --test policy_vectors -- --ignored regenerate`
#![cfg(feature = "acl")]

use std::fs;
use std::path::{Path, PathBuf};

use coqui_peer_tls::acl::{Acl, Action, IpNet, Rule};
use coqui_peer_tls::{CipherProfile, Crypto, Policy};
use guatiao_serde::Presentation;
use guatiao_serde::text::{json, toml};

fn plain() -> Presentation {
    Presentation::new()
}

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/policy")
}

/// The policies the vectors hold: each preset, and one with an ACL.
fn policies() -> Vec<(&'static str, Policy)> {
    let mut routed = Policy::intermediate();
    routed.cipher_suites = Some(vec![
        "TLS13_AES_256_GCM_SHA384".to_owned(),
        "TLS13_CHACHA20_POLY1305_SHA256".to_owned(),
    ]);
    routed.kx_groups = Some(vec!["X25519".to_owned()]);
    routed.waiting.per_source = 8;
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
    let profiles = {
        let mut policy = Policy::default();
        policy.cipher_profiles = vec![CipherProfile::Fips1403Compliant, CipherProfile::Cnsa1];
        policy.crypto = Crypto::AwsLc;
        policy
    };
    vec![
        ("modern", Policy::modern()),
        ("intermediate", Policy::intermediate()),
        ("legacy", Policy::legacy()),
        ("acl", routed),
        ("profiles", profiles),
    ]
}

fn toml_of(policy: &Policy) -> String {
    toml::to_string_of(policy, plain()).unwrap()
}

fn json_of(policy: &Policy) -> String {
    let mut text = json::to_string_pretty_of(policy, plain()).unwrap();
    text.push('\n');
    text
}

fn from_toml(text: &str) -> Result<Policy, guatiao_serde::text::Error> {
    toml::from_str_as(text, plain())
}

#[test]
fn each_vector_reads_back_to_its_policy_in_both_encodings_byte_for_byte() {
    for (name, policy) in policies() {
        let toml_text = fs::read_to_string(directory().join(format!("{name}.toml"))).unwrap();
        let json_text = fs::read_to_string(directory().join(format!("{name}.json"))).unwrap();
        assert_eq!(from_toml(&toml_text).unwrap(), policy, "{name}.toml");
        assert_eq!(
            json::from_str_as::<Policy>(&json_text, plain()).unwrap(),
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
fn a_document_names_what_differs_from_the_intermediate_preset_and_nothing_else() {
    let policy =
        from_toml("check_validity = false\npin_digests = [\"sha256\"]\nallow_resumption = true\n")
            .unwrap();
    assert!(!policy.check_validity);
    assert!(policy.allow_resumption);
    assert_eq!(policy.tls_versions.len(), 2);
    assert_eq!(policy.pin_digests.len(), 1);
    assert_eq!(from_toml("").unwrap(), Policy::default());
    for bad in [
        "policy_version = 1",
        "profile = \"modern\"",
        "surprise = 1",
        "tls_versions = [\"1.1\"]",
        "pin_digests = [\"md5\"]",
        "cipher_profiles = [\"lax\"]",
        "waiting = { surprise = 1 }",
        "[acl]\ndefault = \"maybe\"",
    ] {
        assert!(from_toml(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_flat_waiting_key_is_refused_loudly() {
    assert!(from_toml("waiting_total = 5").is_err());
    let policy = from_toml("[waiting]\ntotal = 5\n").unwrap();
    assert_eq!(policy.waiting.total, 5);
    assert_eq!(
        policy.waiting.per_source,
        Policy::default().waiting.per_source
    );
}

#[test]
fn the_acl_example_reads_like_a_router_listing() {
    let (_, policy) = policies()
        .into_iter()
        .find(|(name, _)| *name == "acl")
        .unwrap();
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
    let mut mine = Policy::intermediate();
    mine.waiting.total = 50;
    mine.waiting.per_source = 3;
    let document = guatiao_serde::text::toml::from_str(
        "check_validity = false",
        guatiao::Alloc::rust(),
        plain(),
    )
    .unwrap();
    let policy = Policy::from_value_over(&mine, &document).unwrap();
    assert_eq!(policy.waiting.total, 50);
    assert!(!policy.check_validity);
    assert_eq!(policy.tls_versions.len(), 2);
    assert!(Policy::preset("mine").is_err());
}

#[cfg(feature = "serde")]
#[test]
fn the_serde_impls_forward_to_the_same_form() {
    let (_, policy) = policies()
        .into_iter()
        .find(|(n, _)| *n == "legacy")
        .unwrap();
    let text = ::toml::to_string(&policy).unwrap();
    assert_eq!(text, toml_of(&policy));
    assert_eq!(::toml::from_str::<Policy>(&text).unwrap(), policy);
    let over = Policy::deserialize_over(
        Policy::modern(),
        ::toml::Deserializer::parse("check_validity = false").unwrap(),
    )
    .unwrap();
    assert!(!over.check_validity);
    assert_eq!(over.tls_versions, Policy::modern().tls_versions);
}

fn value_of(text: &str) -> guatiao::Value {
    guatiao_serde::text::toml::from_str(text, guatiao::Alloc::rust(), plain()).unwrap()
}

#[test]
fn a_nested_key_over_a_base_replaces_that_key_and_keeps_its_siblings() {
    let mut mine = Policy::intermediate();
    mine.waiting.total = 50;
    mine.waiting.per_source = 3;
    mine.pin_digests = vec![coqui_peer_tls::Digest::Sha256];
    let policy = Policy::from_value_over(
        &mine,
        &value_of(
            "[waiting]
per_source = 9
",
        ),
    )
    .unwrap();
    assert_eq!(policy.waiting.per_source, 9);
    assert_eq!(policy.waiting.total, 50);
    assert_eq!(policy.waiting.rerecord, mine.waiting.rerecord);
    assert_eq!(policy.pin_digests, mine.pin_digests);
    // A list replaces whole.
    let policy = Policy::from_value_over(&mine, &value_of("pin_digests = [\"sha384\"]")).unwrap();
    assert_eq!(policy.pin_digests, [coqui_peer_tls::Digest::Sha384]);
    // A duration is a number of seconds in a hand-written document.
    let policy = Policy::from_value_over(
        &mine,
        &value_of(
            "[waiting]
rerecord = 5",
        ),
    )
    .unwrap();
    assert_eq!(policy.waiting.rerecord, core::time::Duration::from_secs(5));
}

#[test]
fn non_defaults_name_every_changed_setting_by_its_key_path() {
    assert!(Policy::default().non_defaults().is_empty());
    let mut policy = Policy::default();
    policy.cipher_suites = Some(vec!["TLS13_AES_256_GCM_SHA384".to_owned()]);
    policy.kx_groups = Some(vec!["X25519".to_owned()]);
    policy.cipher_profiles = vec![CipherProfile::Cnsa1];
    policy.crypto = Crypto::AwsLc;
    policy.waiting.per_source = 100;
    policy.waiting.total = 5_000;
    policy.waiting.rerecord = core::time::Duration::from_secs(1);
    let settings: Vec<String> = policy
        .non_defaults()
        .into_iter()
        .map(|setting| setting.setting)
        .collect();
    assert_eq!(
        settings,
        [
            "cipher_profiles",
            "cipher_suites",
            "crypto",
            "kx_groups",
            "waiting.per_source",
            "waiting.rerecord",
            "waiting.total"
        ]
    );
}

/// The alpha.1 keys are unknown keys: a stored document is rewritten once.
#[test]
fn the_alpha_1_keys_are_refused() {
    for document in [
        "policy_version = 1",
        "profile = \"legacy\"",
        "waiting_per_source = 4",
        "waiting_total = 4",
        "waiting_rerecord_secs = 4",
    ] {
        assert!(
            Policy::from_value_over(&Policy::default(), &value_of(document)).is_err(),
            "{document}"
        );
    }
}
