//! The builders' settings as one value type: read from TOML, JSON and YAML through
//! `guatiao-serde`, described by a schema whose defaults are the real ones, and handed to the
//! builders whole. Run with `--all-features`.
#![cfg(feature = "generate")]

use std::time::Duration;

use coqui_peer_tls::{
    ClientAuth, ClientBuilder, Identity, PAIR_ALPN, PairConfig, Policy, ServerBuilder, TlsSettings,
    Trust,
};
use guatiao::{FromValue, Schema, ToValue};
use guatiao_serde::Presentation;
use guatiao_serde::text::{json, toml, yaml};

fn plain() -> Presentation {
    Presentation::new()
}

const TOML: &str = r#"alpn = ["h2", "coqui/1"]

[policy]
tls_versions = ["1.3"]
allow_resumption = true

[policy.waiting]
total = 7
"#;

fn expected() -> TlsSettings {
    let mut policy = Policy::modern();
    policy.allow_resumption = true;
    policy.waiting.total = 7;
    let mut settings = TlsSettings::default();
    settings.alpn = vec!["h2".to_owned(), "coqui/1".to_owned()];
    settings.policy = policy;
    settings
}

#[test]
fn settings_read_from_toml() {
    let settings: TlsSettings = toml::from_str_as(TOML, plain()).unwrap();
    assert_eq!(settings, expected());
}

#[test]
fn settings_round_trip_through_toml_json_and_yaml() {
    let settings = expected();
    let text = toml::to_string_of(&settings, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<TlsSettings>(&text, plain()).unwrap(),
        settings
    );
    let text = json::to_string_pretty_of(&settings, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<TlsSettings>(&text, plain()).unwrap(),
        settings
    );
    let text = yaml::to_string_of(&settings, plain()).unwrap();
    assert_eq!(
        yaml::from_str_as::<TlsSettings>(&text, plain()).unwrap(),
        settings
    );
}

#[test]
fn settings_read_from_json() {
    let settings: TlsSettings = json::from_str_as(
        r#"{"alpn": ["h2", "coqui/1"],
            "policy": {"tls_versions": ["1.3"], "allow_resumption": true,
                       "waiting": {"total": 7}}}"#,
        plain(),
    )
    .unwrap();
    assert_eq!(settings, expected());
}

#[test]
fn an_empty_document_is_the_defaults_and_an_unknown_key_is_refused() {
    assert_eq!(
        toml::from_str_as::<TlsSettings>("", plain()).unwrap(),
        TlsSettings::default()
    );
    assert!(toml::from_str_as::<TlsSettings>("alpm = []", plain()).is_err());
    assert!(toml::from_str_as::<TlsSettings>("[policy]\nsurprise = 1", plain()).is_err());
}

#[test]
fn the_schema_carries_the_defaults_a_document_leaves_out() {
    let schema = TlsSettings::schema().unwrap();
    let policy = Policy::schema().unwrap();
    for (field, key) in [("tls_versions", "1.2"), ("require_ems", "true")] {
        let found = guatiao::schema::SchemaRef::new(&policy)
            .unwrap()
            .find(field)
            .unwrap_or_else(|| panic!("{field} is in the schema"));
        assert!(found.default().is_some(), "{field} has a default ({key})");
    }
    assert!(
        guatiao::schema::SchemaRef::new(&schema)
            .unwrap()
            .find("alpn")
            .is_some()
    );
    let value = Policy::default().to_value().unwrap();
    guatiao::schema::validate_value(
        guatiao::schema::FieldRef::new("policy", &policy).unwrap(),
        &value,
    )
    .ok();
    assert_eq!(Policy::from_value(&value).unwrap(), Policy::default());
}

#[test]
fn the_builders_accept_settings_whole() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let settings: TlsSettings = toml::from_str_as(TOML, plain()).unwrap();
    let built = ServerBuilder::new(&server, ClientAuth::None)
        .settings(settings.clone())
        .build()
        .unwrap();
    assert_eq!(
        built.config.alpn_protocols,
        vec![b"h2".to_vec(), b"coqui/1".to_vec()]
    );
    assert_eq!(built.non_defaults[0].setting, "allow_resumption");
    let built = ClientBuilder::new(Trust::AnyWithKeyProof)
        .identity(&client)
        .settings(settings)
        .build()
        .unwrap();
    assert_eq!(built.config.alpn_protocols.len(), 2);
}

#[test]
fn pair_config_is_its_own_settings_type() {
    let config: PairConfig = toml::from_str_as(
        "alpn = \"mine/1\"\ntimeout = 5\n[policy]\ntls_versions = [\"1.3\"]\n",
        plain(),
    )
    .unwrap();
    assert_eq!(config.alpn, b"mine/1");
    assert_eq!(config.timeout, Duration::from_secs(5));
    assert_eq!(config.policy.tls_versions, Policy::modern().tls_versions);
    assert_eq!(
        toml::from_str_as::<PairConfig>("", plain()).unwrap(),
        PairConfig::default()
    );
    assert_eq!(PairConfig::default().alpn, PAIR_ALPN);
    let text = json::to_string_of(&config, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<PairConfig>(&text, plain()).unwrap(),
        config
    );
}

#[test]
fn an_alpn_entry_is_text_of_one_to_255_bytes() {
    assert!(toml::from_str_as::<TlsSettings>("alpn = [\"\"]", plain()).is_err());
    let long = "a".repeat(256);
    assert!(toml::from_str_as::<TlsSettings>(&format!("alpn = [\"{long}\"]"), plain()).is_err());
    let longest = "a".repeat(255);
    let settings: TlsSettings =
        toml::from_str_as(&format!("alpn = [\"{longest}\"]"), plain()).unwrap();
    assert_eq!(settings.alpn, [longest]);
    assert!(toml::from_str_as::<PairConfig>("alpn = \"\"", plain()).is_err());
}

#[test]
fn the_last_setter_wins_between_settings_alpn_and_policy() {
    let server = Identity::generate().unwrap();
    let mut settings = TlsSettings::default();
    settings.alpn = vec!["from-settings/1".to_owned()];
    settings.policy = Policy::modern();
    let after = ServerBuilder::new(&server, ClientAuth::None)
        .alpn([b"early/1"])
        .settings(settings.clone())
        .build()
        .unwrap();
    assert_eq!(
        after.config.alpn_protocols,
        vec![b"from-settings/1".to_vec()]
    );
    let before = ServerBuilder::new(&server, ClientAuth::None)
        .settings(settings)
        .alpn([b"late/1"])
        .policy(Policy::legacy())
        .build()
        .unwrap();
    assert_eq!(before.config.alpn_protocols, vec![b"late/1".to_vec()]);
    assert_eq!(before.non_defaults.len(), 2);
}

#[test]
fn pair_config_round_trips_as_text_with_its_timeout() {
    let mut config = PairConfig::default();
    config.alpn = b"mine/1".to_vec();
    config.timeout = Duration::from_millis(2500);
    config.policy = Policy::modern();
    let text = toml::to_string_of(&config, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<PairConfig>(&text, plain()).unwrap(),
        config
    );
    let text = json::to_string_pretty_of(&config, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<PairConfig>(&text, plain()).unwrap(),
        config
    );
    let text = yaml::to_string_of(&config, plain()).unwrap();
    assert_eq!(
        yaml::from_str_as::<PairConfig>(&text, plain()).unwrap(),
        config
    );
}

/// The derives give each settings type the value traits and the usual ones.
#[test]
fn the_settings_types_carry_the_derived_traits() {
    fn value_type<
        T: ToValue + FromValue + Schema + Clone + Default + PartialEq + core::fmt::Debug,
    >() {
    }
    fn plain_data<T: Send + Sync>() {}
    value_type::<TlsSettings>();
    value_type::<Policy>();
    value_type::<PairConfig>();
    plain_data::<TlsSettings>();
    plain_data::<Policy>();
    plain_data::<PairConfig>();
}
