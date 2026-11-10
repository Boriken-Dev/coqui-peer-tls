//! The text form of `Policy` pinned by committed files in `tests/vectors/policy/`, in TOML and in
//! JSON, for implementations in other languages. The files are data: they are read, never
//! written, by this crate.
#![cfg(feature = "acl")]

use std::fs;
use std::path::{Path, PathBuf};

use coqui_builder::Partial;
use coqui_peer_tls::acl::{Acl, Action, IpNet, Rule};
use coqui_peer_tls::{CipherProfile, Crypto, Policy};

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

fn partial_of_toml(text: &str) -> Result<Partial<Policy>, String> {
    toml::from_str(text).map_err(|error| error.to_string())
}

fn from_toml(text: &str) -> Result<Policy, String> {
    partial_of_toml(text)?
        .build()
        .map_err(|missing| missing.to_string())
}

fn from_json(text: &str) -> Result<Policy, String> {
    serde_json::from_str::<Partial<Policy>>(text)
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|missing| missing.to_string())
}

/// A document read over `base`, as a consumer with its own default profile reads one.
fn over(base: &Policy, text: &str) -> Result<Policy, String> {
    let mut partial = Partial::from(base.clone());
    partial.overlay(partial_of_toml(text)?);
    partial.build().map_err(|missing| missing.to_string())
}

#[test]
fn each_vector_reads_to_its_policy_in_both_encodings() {
    for (name, policy) in policies() {
        let toml_text = fs::read_to_string(directory().join(format!("{name}.toml"))).unwrap();
        let json_text = fs::read_to_string(directory().join(format!("{name}.json"))).unwrap();
        assert_eq!(from_toml(&toml_text).unwrap(), policy, "{name}.toml");
        assert_eq!(from_json(&json_text).unwrap(), policy, "{name}.json");
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
fn a_consumer_reads_a_document_over_its_own_profile() {
    let mut mine = Policy::intermediate();
    mine.waiting.total = 50;
    mine.waiting.per_source = 3;
    let policy = over(&mine, "check_validity = false").unwrap();
    assert_eq!(policy.waiting.total, 50);
    assert!(!policy.check_validity);
    assert_eq!(policy.tls_versions.len(), 2);
    assert!(Policy::preset("mine").is_err());
}

#[cfg(feature = "serde")]
#[test]
fn the_serde_impls_read_the_same_form() {
    let (_, policy) = policies()
        .into_iter()
        .find(|(n, _)| *n == "legacy")
        .unwrap();
    let text = fs::read_to_string(directory().join("legacy.toml")).unwrap();
    assert_eq!(::toml::from_str::<Policy>(&text).unwrap(), policy);
    let text = fs::read_to_string(directory().join("legacy.json")).unwrap();
    assert_eq!(serde_json::from_str::<Policy>(&text).unwrap(), policy);
    let over = Policy::deserialize_over(
        Policy::modern(),
        ::toml::Deserializer::parse("check_validity = false").unwrap(),
    )
    .unwrap();
    assert!(!over.check_validity);
    assert_eq!(over.tls_versions, Policy::modern().tls_versions);
    assert!(::toml::from_str::<Policy>("surprise = 1").is_err());
}

#[cfg(feature = "serde")]
#[test]
fn a_policy_read_through_serde_has_its_acl_fingerprints_made_canonical() {
    let shouted = format!(
        "[acl]\ndefault = \"deny\"\n[[acl.rule]]\naction = \"permit\"\nsource = \"any\"\nfingerprint = \"SHA256:{}\"\n",
        "AB".repeat(32)
    );
    let policy = ::toml::from_str::<Policy>(&shouted).unwrap();
    let rules = policy.acl.unwrap().rules;
    assert_eq!(
        rules[0].fingerprint.as_deref(),
        Some(format!("sha256:{}", "ab".repeat(32)).as_str())
    );
    let bad = "[acl]\ndefault = \"deny\"\n[[acl.rule]]\naction = \"permit\"\nsource = \"any\"\nfingerprint = \"nonsense\"\n";
    assert!(::toml::from_str::<Policy>(bad).is_err());
}

#[test]
fn a_nested_key_over_a_base_replaces_that_key_and_keeps_its_siblings() {
    let mut mine = Policy::intermediate();
    mine.waiting.total = 50;
    mine.waiting.per_source = 3;
    mine.pin_digests = vec![coqui_peer_tls::Digest::Sha256];
    let policy = over(&mine, "[waiting]\nper_source = 9\n").unwrap();
    assert_eq!(policy.waiting.per_source, 9);
    assert_eq!(policy.waiting.total, 50);
    assert_eq!(policy.waiting.rerecord, mine.waiting.rerecord);
    assert_eq!(policy.pin_digests, mine.pin_digests);
    // A list replaces whole.
    let policy = over(&mine, "pin_digests = [\"sha384\"]").unwrap();
    assert_eq!(policy.pin_digests, [coqui_peer_tls::Digest::Sha384]);
    // A duration is a number of seconds in a hand-written document.
    let policy = over(&mine, "[waiting]\nrerecord = 5").unwrap();
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

#[test]
fn an_access_list_inside_a_policy_is_one_entry() {
    let (_, policy) = policies()
        .into_iter()
        .find(|(name, _)| *name == "acl")
        .unwrap();
    let settings: Vec<String> = policy
        .non_defaults()
        .into_iter()
        .map(|setting| setting.setting)
        .collect();
    assert_eq!(
        settings,
        ["acl", "cipher_suites", "kx_groups", "waiting.per_source"]
    );
    let inner = coqui_builder::non_defaults(policy.acl.as_ref().unwrap());
    assert!(!inner.is_empty());
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
        assert!(from_toml(document).is_err(), "{document}");
    }
}
