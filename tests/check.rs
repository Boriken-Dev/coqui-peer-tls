//! `Policy::check` refuses what a configuration build would, without building one.

use coqui_peer_tls::{PeerError, Policy};

#[test]
fn every_preset_passes_its_check() -> Result<(), PeerError> {
    for name in ["modern", "intermediate", "legacy"] {
        Policy::preset(name)?.check()?;
    }
    Ok(())
}

#[test]
fn an_unusable_setting_fails_the_check_as_a_build_would() {
    let mut empty = Policy::default();
    empty.tls_versions.clear();
    assert!(matches!(empty.check(), Err(PeerError::Policy(_))));

    let suites = Policy {
        cipher_suites: Some(vec!["TLS_NULL_WITH_NULL_NULL".to_owned()]),
        ..Policy::default()
    };
    let refused = suites.check().expect_err("an unknown suite");
    assert!(
        refused.to_string().contains("cipher_suites[0]"),
        "{refused}"
    );

    let groups = Policy {
        kx_groups: Some(Vec::new()),
        ..Policy::default()
    };
    assert!(matches!(groups.check(), Err(PeerError::Policy(_))));
}

#[cfg(feature = "acl")]
#[test]
fn a_list_naming_something_that_is_no_peer_id_fails_the_check() {
    use coqui_net_acl::{Acl, Action, Rule};

    let mut rule = Rule::new(Action::Permit, "10.0.0.0/8".parse().expect("a network"));
    rule.fingerprint = Some("not-a-fingerprint".to_owned());
    let policy = Policy {
        acl: Some(Acl {
            rules: vec![rule],
            default: Action::Deny,
        }),
        ..Policy::default()
    };
    let refused = policy.check().expect_err("a rule that can never match");
    assert!(refused.to_string().contains("acl rule 0"), "{refused}");
}
