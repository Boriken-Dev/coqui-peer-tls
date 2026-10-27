//! Identity files: created once, by exactly one of several concurrent callers, owner-only.
#![cfg(feature = "generate")]

use std::sync::{Arc, Barrier};
use std::thread;

use coqui_peer_tls::{Identity, PeerError};

#[test]
fn concurrent_open_or_create_calls_agree_on_one_identity() -> Result<(), PeerError> {
    for round in 0..20 {
        let directory = tempfile::tempdir().map_err(PeerError::Io)?;
        let path = Arc::new(directory.path().join("identity.pem"));
        let start = Arc::new(Barrier::new(8));
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let (path, start) = (Arc::clone(&path), Arc::clone(&start));
                thread::spawn(move || {
                    start.wait();
                    Identity::open_or_create(&path).map(|identity| identity.fingerprint())
                })
            })
            .collect();
        let fingerprints: Vec<_> = callers
            .into_iter()
            .map(|caller| caller.join().expect("no panic"))
            .collect::<Result<_, _>>()?;
        assert!(
            fingerprints.windows(2).all(|pair| pair[0] == pair[1]),
            "round {round}: {fingerprints:?}"
        );
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .map_err(PeerError::Io)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<_, _>>()
            .map_err(PeerError::Io)?;
        assert_eq!(names, ["identity.pem"], "round {round}");
    }
    Ok(())
}

#[test]
fn write_new_never_replaces_an_identity() -> Result<(), PeerError> {
    let directory = tempfile::tempdir().map_err(PeerError::Io)?;
    let path = directory.path().join("nested/identity.pem");
    let first = Identity::generate()?;
    first.write_new(&path)?;
    let refused = Identity::generate()?.write_new(&path);
    assert!(
        matches!(&refused, Err(PeerError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists),
        "{refused:?}"
    );
    assert_eq!(
        Identity::read(&path)?.map(|identity| identity.fingerprint()),
        Some(first.fingerprint())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map_err(PeerError::Io)?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    Ok(())
}
