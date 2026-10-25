//! The committed vectors in `tests/vectors/` pin the on-disk and text formats byte for byte,
//! so implementations in other languages can check themselves against the same files.
//!
//! Regenerating them is a format change:
//! `cargo test -p coqui-peer-tls --features generate -- --ignored regenerate_vectors`

use std::fs;
use std::path::{Path, PathBuf};

use coqui_peer_tls::{Fingerprint, Identity};

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read(name: &str) -> String {
    fs::read_to_string(vectors().join(name)).unwrap()
}

#[test]
fn each_certificate_has_the_committed_fingerprint_in_every_spelling() {
    for name in ["a", "b"] {
        let identity = Identity::from_pem(&read(&format!("identity-{name}.pem"))).unwrap();
        let expected = read(&format!("identity-{name}.fingerprint"));
        let lines: Vec<&str> = expected.lines().collect();
        assert_eq!(lines.len(), 3, "sha256 form, bare hex, grouped base32");
        let fingerprint = identity.fingerprint();
        assert_eq!(fingerprint.canonical(), lines[0]);
        assert_eq!(fingerprint.hex(), lines[1]);
        assert_eq!(fingerprint.to_base32_grouped(), lines[2]);
        assert_eq!(fingerprint.to_string(), lines[0]);
        for line in lines {
            assert_eq!(line.parse::<Fingerprint>().unwrap(), fingerprint);
        }
        // An identity file round-trips byte for byte: certificate block, then PKCS#8 key.
        assert_eq!(
            identity.to_pem().unwrap(),
            read(&format!("identity-{name}.pem"))
        );
    }
}

#[cfg(feature = "generate")]
#[test]
#[ignore = "rewrites the committed vectors"]
fn regenerate_vectors() {
    let root = vectors();
    fs::create_dir_all(&root).unwrap();
    for name in ["a", "b"] {
        let identity = Identity::generate().unwrap();
        let pem = identity.to_pem().unwrap();
        let fingerprint = identity.fingerprint();
        fs::write(root.join(format!("identity-{name}.pem")), &pem).unwrap();
        fs::write(
            root.join(format!("identity-{name}.fingerprint")),
            format!(
                "{}\n{}\n{}\n",
                fingerprint.canonical(),
                fingerprint.hex(),
                fingerprint.to_base32_grouped()
            ),
        )
        .unwrap();
    }
}
