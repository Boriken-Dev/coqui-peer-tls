//! The committed vectors in `tests/vectors/` pin the on-disk and text formats byte for byte,
//! so implementations in other languages can check themselves against the same files.
//!
//! Regenerating them is a format change:
//! `cargo test -p coqui-peer-tls --features generate -- --ignored regenerate_vectors`

use std::fs;
use std::path::{Path, PathBuf};

use coqui_peer_tls::{Fingerprint, Identity, TrustStore};

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read(name: &str) -> String {
    fs::read_to_string(vectors().join(name)).unwrap()
}

/// The certificate block alone of an identity file.
fn certificate_block(pem: &str) -> &str {
    let end =
        pem.find("-----END CERTIFICATE-----\n").unwrap() + "-----END CERTIFICATE-----\n".len();
    &pem[..end]
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
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

#[test]
fn the_sample_trust_store_reads_as_committed() {
    let (a, b) = (
        Identity::from_pem(&read("identity-a.pem"))
            .unwrap()
            .fingerprint(),
        Identity::from_pem(&read("identity-b.pem"))
            .unwrap()
            .fingerprint(),
    );
    let directory = tempfile::tempdir().unwrap();
    copy_tree(&vectors().join("store"), directory.path());
    let store = TrustStore::open(directory.path()).unwrap();
    assert_eq!(store.accepted().unwrap(), vec![a]);
    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].fingerprint, b);
    assert_eq!(waiting[0].source, Some("192.0.2.7:4000".parse().unwrap()));
    assert!(store.is_accepted(&a) && !store.is_accepted(&b));
    store.accept(&b).unwrap();
    assert!(store.is_accepted(&b));
    assert!(store.waiting().unwrap().is_empty());
    // Files are named by bare lowercase hex and hold one certificate block.
    let accepted = directory
        .path()
        .join("peers/accepted")
        .join(format!("{}.pem", b.hex()));
    assert_eq!(
        fs::read_to_string(accepted).unwrap(),
        certificate_block(&read("identity-b.pem"))
    );
}

#[cfg(feature = "generate")]
#[test]
#[ignore = "rewrites the committed vectors"]
fn regenerate_vectors() {
    let root = vectors();
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("store/peers/accepted")).unwrap();
    fs::create_dir_all(root.join("store/peers/waiting")).unwrap();
    for (name, section) in [("a", "accepted"), ("b", "waiting")] {
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
        fs::write(
            root.join("store/peers")
                .join(section)
                .join(format!("{}.pem", fingerprint.hex())),
            if section == "waiting" {
                format!("Source: 192.0.2.7:4000\n{}", certificate_block(&pem))
            } else {
                certificate_block(&pem).to_owned()
            },
        )
        .unwrap();
    }
}
