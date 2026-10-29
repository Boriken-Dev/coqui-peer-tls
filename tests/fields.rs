//! A certificate's identifying fields, and CA trust matching subject alternative names
//! through them, IP addresses included however the certificate carries them.
#![cfg(all(feature = "fields", feature = "generate"))]

use coqui_peer_tls::{CertificateFields, PeerError, San};
use rcgen::{CertificateParams, DnType, KeyPair, OtherNameValue, SanType};

const UPN: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 20, 2, 3];

fn certificate(sans: Vec<SanType>) -> Vec<u8> {
    let key = KeyPair::generate().expect("a key");
    let mut parameters = CertificateParams::new(Vec::<String>::new()).expect("parameters");
    parameters.subject_alt_names = sans;
    parameters
        .distinguished_name
        .push(DnType::CommonName, "Client One");
    parameters
        .distinguished_name
        .push(DnType::OrganizationName, "Coqui");
    parameters.serial_number = Some(vec![0, 0x12, 0xab].into());
    parameters.not_before = rcgen::date_time_ymd(2001, 2, 3);
    parameters.not_after = rcgen::date_time_ymd(2101, 2, 3);
    parameters
        .self_signed(&key)
        .expect("a certificate")
        .der()
        .to_vec()
}

fn ip(text: &str) -> SanType {
    SanType::IpAddress(text.parse().expect("an address"))
}

fn dns(text: &str) -> SanType {
    SanType::DnsName(text.try_into().expect("a DNS name"))
}

#[test]
fn every_san_kind_is_read_into_the_map() -> Result<(), PeerError> {
    let der = certificate(vec![
        dns("client.example"),
        SanType::Rfc822Name("one@example.com".try_into().expect("an email")),
        SanType::URI("spiffe://example/client".try_into().expect("a URI")),
        ip("10.0.0.9"),
        ip("2001:db8:0:0:0:0:0:1"),
        ip("::ffff:192.0.2.4"),
        SanType::OtherName((
            UPN.to_vec(),
            OtherNameValue::Utf8String("one@corp.example".into()),
        )),
        SanType::OtherName((vec![1, 2, 3, 4], OtherNameValue::Utf8String("x".into()))),
        dns("10.0.0.1"),
    ]);
    let fields = CertificateFields::parse(&der)?;
    assert!(
        fields
            .sans
            .contains(&San::Upn("one@corp.example".to_owned()))
    );
    let map = fields.to_map();
    let get = |key: &str| map.get(key).cloned().unwrap_or_default();
    assert_eq!(get("subject.cn"), ["Client One"]);
    assert_eq!(get("subject.o"), ["Coqui"]);
    assert!(get("subject")[0].contains("CN=Client One"));
    assert_eq!(get("issuer.cn"), ["Client One"]);
    assert_eq!(get("san.dns"), ["client.example", "10.0.0.1"]);
    assert_eq!(get("san.dns.ip"), ["10.0.0.1"]);
    assert_eq!(get("san.email"), ["one@example.com"]);
    assert_eq!(get("san.uri"), ["spiffe://example/client"]);
    assert_eq!(get("san.ip"), ["10.0.0.9", "2001:db8::1", "192.0.2.4"]);
    assert_eq!(get("san.upn"), ["one@corp.example"]);
    // The [0] wrapper, then a UTF8String "x".
    assert_eq!(get("san.other.1.2.3.4"), ["a0030c0178"]);
    assert_eq!(get("serial"), ["12ab"]);
    assert_eq!(
        get("fingerprint"),
        [coqui_peer_tls::PeerId::of(&der).canonical()]
    );
    assert_eq!(get("not_before"), ["981158400"]);
    assert_eq!(get("not_after"), ["4136832000"]);
    // Debug shows the fingerprint only.
    let shown = format!("{fields:?}");
    assert!(
        shown.contains("sha256:") && !shown.contains("Client One"),
        "{shown}"
    );
    Ok(())
}

#[test]
fn malformed_der_is_a_certificate_error() {
    assert!(matches!(
        CertificateFields::parse(&[0x30, 0x03, 0x02, 0x01]),
        Err(PeerError::Certificate)
    ));
    let mut der = certificate(Vec::new());
    der.push(0);
    assert!(matches!(
        CertificateFields::parse(&der),
        Err(PeerError::Certificate)
    ));
}

#[test]
fn a_dns_name_that_is_an_ip_literal_says_so() {
    assert_eq!(
        San::Dns("10.0.0.1".to_owned()).ip(),
        Some("10.0.0.1".parse().unwrap())
    );
    assert_eq!(
        San::Dns("0:0:0:0:0:0:0:1".to_owned()).ip(),
        Some("::1".parse().unwrap())
    );
    assert_eq!(San::Dns("host.example".to_owned()).ip(), None);
}

#[cfg(feature = "ca")]
mod ca {
    use super::*;
    use coqui_peer_tls::{CaPolicy, Policy, Refusal, Trust};
    use rcgen::{BasicConstraints, IsCa, Issuer};

    struct Authority {
        directory: tempfile::TempDir,
        issuer: Issuer<'static, KeyPair>,
    }

    impl Authority {
        fn new() -> Self {
            let key = KeyPair::generate().expect("a key");
            let mut parameters = CertificateParams::new(Vec::<String>::new()).expect("parameters");
            parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            parameters
                .distinguished_name
                .push(DnType::CommonName, "test CA");
            let pem = parameters.self_signed(&key).expect("a CA").pem();
            let directory = tempfile::tempdir().expect("a directory");
            std::fs::write(directory.path().join("ca.pem"), pem).expect("written");
            Self {
                directory,
                issuer: Issuer::new(parameters, key),
            }
        }

        fn leaf(&self, sans: Vec<SanType>) -> Vec<u8> {
            let key = KeyPair::generate().expect("a key");
            let mut parameters = CertificateParams::new(Vec::<String>::new()).expect("parameters");
            parameters.subject_alt_names = sans;
            parameters
                .signed_by(&key, &self.issuer)
                .expect("a certificate")
                .der()
                .to_vec()
        }

        fn admits(&self, san: &[&str], ip_in_dns: bool, leaf: &[u8]) -> bool {
            let policy = CaPolicy {
                san: san.iter().map(|glob| (*glob).to_owned()).collect(),
                ip_in_dns,
                ..CaPolicy::new(self.directory.path().join("ca.pem"))
            };
            match Trust::Ca(policy).verify_client_chain(&Policy::default(), leaf, &[]) {
                Ok(()) => true,
                Err(error) => {
                    assert_eq!(error.refusal(), Some(Refusal::NotTrusted), "{error:?}");
                    false
                }
            }
        }
    }

    #[test]
    fn an_ip_glob_matches_an_ip_san() {
        let authority = Authority::new();
        let leaf = authority.leaf(vec![ip("10.0.0.9")]);
        assert!(authority.admits(&["10.0.0.*"], true, &leaf));
        assert!(authority.admits(&["ip:10.0.0.9"], false, &leaf));
        assert!(!authority.admits(&["10.0.1.*"], true, &leaf));
        assert!(!authority.admits(&["dns:10.0.0.*"], true, &leaf));
    }

    #[test]
    fn an_ip_in_a_dns_san_matches_an_ip_glob_unless_strict() {
        let authority = Authority::new();
        let only_dns = authority.leaf(vec![dns("10.0.0.1")]);
        assert!(authority.admits(&["ip:10.0.0.1"], true, &only_dns));
        assert!(!authority.admits(&["ip:10.0.0.1"], false, &only_dns));
        // Unprefixed, the DNS name matches as text either way.
        assert!(authority.admits(&["10.0.0.1"], false, &only_dns));
        let only_ip = authority.leaf(vec![ip("10.0.0.1")]);
        assert!(authority.admits(&["ip:10.0.0.1"], false, &only_ip));
        assert!(!authority.admits(&["dns:10.0.0.1"], true, &only_ip));
        let both = authority.leaf(vec![dns("10.0.0.1"), ip("10.0.0.1")]);
        assert!(authority.admits(&["ip:10.0.0.1"], false, &both));
        assert!(authority.admits(&["dns:10.0.0.1"], false, &both));
    }

    #[test]
    fn ipv6_matches_however_either_side_writes_it() {
        let authority = Authority::new();
        let expanded_san = authority.leaf(vec![ip("2001:db8:0:0:0:0:0:7")]);
        assert!(authority.admits(&["ip:2001:db8::7"], true, &expanded_san));
        assert!(authority.admits(&["2001:0db8:0000::7"], true, &expanded_san));
        let in_dns = authority.leaf(vec![dns("2001:db8:0:0:0:0:0:7")]);
        assert!(authority.admits(&["ip:2001:db8::7"], true, &in_dns));
        assert!(!authority.admits(&["ip:2001:db8::7"], false, &in_dns));
        let mapped = authority.leaf(vec![ip("::ffff:10.0.0.1")]);
        assert!(authority.admits(&["ip:10.0.0.1"], true, &mapped));
    }

    #[test]
    fn a_chain_from_another_ca_is_not_trusted_and_a_pinned_one_passes() {
        let authority = Authority::new();
        let stranger = Authority::new().leaf(vec![dns("client.example")]);
        assert!(!authority.admits(&[], true, &stranger));
        let pinned = Trust::PinnedOrCa {
            pins: coqui_peer_tls::Pins::fixed([coqui_peer_tls::PeerId::of(&stranger)]),
            ca: CaPolicy::new(authority.directory.path().join("ca.pem")),
        };
        // Pinned: chain and dates checked, no CA needed.
        pinned
            .verify_client_chain(&Policy::default(), &stranger, &[])
            .expect("a pinned certificate passes");
        assert!(matches!(
            Trust::AnyWithKeyProof.verify_client_chain(&Policy::default(), &stranger, &[]),
            Err(PeerError::Unsupported)
        ));
    }
}
