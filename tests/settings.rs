//! The builders' settings as one value type: read from TOML and JSON into a `Partial`, whose
//! defaults are the real ones, and handed to the builders whole. Run with `--all-features`.
#![cfg(feature = "generate")]

use std::time::Duration;

use coqui_builder::{Describe, Partial};
use coqui_peer_tls::{
    Alpn, ClientAuth, ClientBuilder, Identity, PAIR_ALPN, PairConfig, PeerError, Policy,
    ServerBuilder, TlsSettings, Trust,
};

fn alpn(name: &str) -> Alpn {
    Alpn::try_from(name).unwrap()
}

fn from_toml<T: Describe>(text: &str) -> Result<T, String> {
    toml::from_str::<Partial<T>>(text)
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|missing| missing.to_string())
}

fn from_json<T: Describe>(text: &str) -> Result<T, String> {
    serde_json::from_str::<Partial<T>>(text)
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|missing| missing.to_string())
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
    settings.alpn = vec![alpn("h2"), alpn("coqui/1")];
    settings.policy = policy;
    settings
}

#[test]
fn settings_read_from_toml() {
    assert_eq!(from_toml::<TlsSettings>(TOML).unwrap(), expected());
}

#[test]
fn settings_read_from_json() {
    let settings: TlsSettings = from_json(
        r#"{"alpn": ["h2", "coqui/1"],
            "policy": {"tls_versions": ["1.3"], "allow_resumption": true,
                       "waiting": {"total": 7}}}"#,
    )
    .unwrap();
    assert_eq!(settings, expected());
}

#[test]
fn an_empty_document_is_the_defaults_and_an_unknown_key_is_refused() {
    assert_eq!(
        from_toml::<TlsSettings>("").unwrap(),
        TlsSettings::default()
    );
    assert!(from_toml::<TlsSettings>("alpm = []").is_err());
    assert!(from_toml::<TlsSettings>("[policy]\nsurprise = 1").is_err());
}

#[test]
fn a_key_a_document_leaves_out_is_the_intermediate_preset() {
    assert_eq!(from_toml::<Policy>("").unwrap(), Policy::default());
    assert_eq!(
        from_toml::<Policy>("tls_versions = [\"1.3\"]\ncipher_profiles = [\"mozilla\"]").unwrap(),
        Policy::modern()
    );
}

#[test]
fn the_builders_accept_settings_whole() {
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let settings: TlsSettings = from_toml(TOML).unwrap();
    let built = ServerBuilder::new()
        .identity(&server)
        .client_auth(ClientAuth::None)
        .fill(Partial::from(settings.clone()))
        .build()
        .unwrap();
    assert_eq!(
        built.config.alpn_protocols,
        vec![b"h2".to_vec(), b"coqui/1".to_vec()]
    );
    assert_eq!(built.non_defaults()[0].setting, "allow_resumption");
    let built = ClientBuilder::new()
        .server(Trust::AnyWithKeyProof)
        .identity(&client)
        .fill(Partial::from(settings))
        .build()
        .unwrap();
    assert_eq!(built.config.alpn_protocols.len(), 2);
}

#[test]
fn pair_config_is_its_own_settings_type() {
    let config: PairConfig =
        from_toml("alpn = \"mine/1\"\ntimeout = 5\n[policy]\ntls_versions = [\"1.3\"]\n").unwrap();
    assert_eq!(config.alpn, alpn("mine/1"));
    assert_eq!(config.timeout, Some(Duration::from_secs(5)));
    assert_eq!(config.policy.tls_versions, Policy::modern().tls_versions);
    assert_eq!(from_toml::<PairConfig>("").unwrap(), PairConfig::default());
    assert_eq!(PairConfig::default().alpn.as_bytes(), PAIR_ALPN);
}

#[test]
fn a_pairing_timeout_reads_as_a_duration_or_never() {
    let config: PairConfig = from_toml("timeout = \"2500ms\"").unwrap();
    assert_eq!(config.timeout, Some(Duration::from_millis(2500)));
    let config: PairConfig = from_json(r#"{"timeout": "never"}"#).unwrap();
    assert_eq!(config.timeout, None);
    assert_eq!(
        PairConfig::default().timeout,
        Some(Duration::from_secs(15 * 60))
    );
}

#[test]
fn an_alpn_entry_is_text_of_one_to_255_bytes() {
    assert!(from_toml::<TlsSettings>("alpn = [\"\"]").is_err());
    let long = "a".repeat(256);
    assert!(from_toml::<TlsSettings>(&format!("alpn = [\"{long}\"]")).is_err());
    let longest = "a".repeat(255);
    let settings: TlsSettings = from_toml(&format!("alpn = [\"{longest}\"]")).unwrap();
    assert_eq!(settings.alpn, [alpn(&longest)]);
    assert!(from_toml::<PairConfig>("alpn = \"\"").is_err());
}

#[test]
fn an_alpn_converts_from_text_and_from_utf8_bytes_only() {
    assert_eq!(Alpn::try_from(b"h2".as_slice()).unwrap().as_str(), "h2");
    assert_eq!(Alpn::try_from("h2").unwrap().as_bytes(), b"h2");
    assert!(matches!(
        Alpn::try_from(&[0xff, 0xfe][..]),
        Err(PeerError::Policy(_))
    ));
    assert!(Alpn::try_from(&[][..]).is_err());
    assert!(Alpn::try_from("").is_err());
    assert!(Alpn::try_from(&[b'a'; 256][..]).is_err());
    assert!(Alpn::try_from(&[b'a'; 255][..]).is_ok());
    coqui_builder::describe::assert_round_trip(&[alpn("h2"), alpn("coqui/1"), alpn("a b")]);
}

#[test]
fn the_last_write_wins_between_fill_alpn_and_policy() {
    let server = Identity::generate().unwrap();
    let mut settings = TlsSettings::default();
    settings.alpn = vec![alpn("from-settings/1")];
    settings.policy = Policy::modern();
    let after = ServerBuilder::new()
        .identity(&server)
        .client_auth(ClientAuth::None)
        .alpn(vec![alpn("early/1")])
        .fill(Partial::from(settings.clone()))
        .build()
        .unwrap();
    assert_eq!(
        after.config.alpn_protocols,
        vec![b"from-settings/1".to_vec()]
    );
    let before = ServerBuilder::new()
        .identity(&server)
        .client_auth(ClientAuth::None)
        .fill(Partial::from(settings))
        .alpn(vec![alpn("late/1")])
        .policy(Policy::legacy())
        .build()
        .unwrap();
    assert_eq!(before.config.alpn_protocols, vec![b"late/1".to_vec()]);
    assert_eq!(before.non_defaults().len(), 2);
}

#[test]
fn a_builders_own_non_defaults_carry_the_group_and_list_alpn() {
    let server = Identity::generate().unwrap();
    let builder = ServerBuilder::new()
        .identity(&server)
        .client_auth(ClientAuth::None)
        .alpn(vec![alpn("h2")])
        .policy(Policy::modern());
    let keys: Vec<String> = builder
        .non_defaults()
        .into_iter()
        .map(|found| found.setting)
        .collect();
    assert_eq!(keys, ["alpn", "policy.tls_versions"]);
    let built = builder.build().unwrap();
    let keys: Vec<String> = built
        .non_defaults()
        .into_iter()
        .map(|found| found.setting)
        .collect();
    assert_eq!(keys, ["tls_versions"]);
}

/// The derives give each settings type the usual traits.
#[test]
fn the_settings_types_carry_the_derived_traits() {
    fn value_type<T: Describe + Clone + Default + PartialEq + core::fmt::Debug>() {}
    fn plain_data<T: Send + Sync>() {}
    value_type::<TlsSettings>();
    value_type::<Policy>();
    value_type::<PairConfig>();
    plain_data::<TlsSettings>();
    plain_data::<Policy>();
    plain_data::<PairConfig>();
}
