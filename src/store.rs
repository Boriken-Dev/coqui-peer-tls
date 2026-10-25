use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::error::PeerError;
use crate::fingerprint::Fingerprint;
use crate::identity::{encode_pem, temporary_path};

const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Bounds on the waiting queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitingLimits {
    /// Entries one source address may hold; the oldest of its own is replaced.
    pub per_source: usize,
    /// Entries the whole directory may hold; past it nothing is recorded.
    pub total: usize,
    /// How long the same certificate from the same source is not recorded again.
    pub rerecord: Duration,
}

impl Default for WaitingLimits {
    fn default() -> Self {
        Self {
            per_source: 16,
            total: 1_000,
            rerecord: Duration::from_secs(60),
        }
    }
}

/// Persistent certificate pins: peers an operator accepted, and peers that were turned
/// away and wait to be accepted.
///
/// On-disk layout (format version 1), under `<state_dir>/peers/`:
///
/// ```text
/// accepted/<64 lowercase hex>.pem   one CERTIFICATE block; the name is its fingerprint
/// waiting/<64 lowercase hex>.pem    the same, for a peer that proved its key and was refused
/// ```
///
/// Accepting moves a file from `waiting/` to `accepted/` after checking that the
/// certificate inside hashes to the name. Names in the grouped base32 spelling are also
/// read, so a store written by an earlier layout keeps working; new files are always
/// written with the hex name.
#[derive(Debug, Clone)]
pub struct TrustStore {
    root: PathBuf,
    seen: Arc<Mutex<Seen>>,
    limits: WaitingLimits,
}

/// Waiting entries recorded by this process, per source address, oldest first.
#[derive(Debug, Default)]
struct Seen {
    sources: HashMap<Option<IpAddr>, VecDeque<(Fingerprint, Instant)>>,
}

impl TrustStore {
    /// Opens (creating when absent) the store under `<state_dir>/peers`.
    ///
    /// # Errors
    ///
    /// [`PeerError::Io`] when the directories cannot be created.
    pub fn open(state_dir: &Path) -> Result<Self, PeerError> {
        let root = state_dir.join("peers");
        fs::create_dir_all(root.join("accepted")).map_err(PeerError::Io)?;
        fs::create_dir_all(root.join("waiting")).map_err(PeerError::Io)?;
        Ok(Self {
            root,
            seen: Arc::default(),
            limits: WaitingLimits::default(),
        })
    }

    /// This store with other bounds on its waiting queue (the default is the strict
    /// profile's: 16 per source, 1000 in all, 60 seconds).
    #[must_use]
    pub fn with_limits(mut self, limits: WaitingLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Fingerprints awaiting operator acceptance, sorted.
    ///
    /// # Errors
    ///
    /// [`PeerError::Io`] when the directory cannot be read.
    pub fn waiting(&self) -> Result<Vec<Fingerprint>, PeerError> {
        self.list("waiting")
    }

    /// Accepted fingerprints, sorted.
    ///
    /// # Errors
    ///
    /// [`PeerError::Io`] when the directory cannot be read.
    pub fn accepted(&self) -> Result<Vec<Fingerprint>, PeerError> {
        self.list("accepted")
    }

    /// Accepts a waiting peer by its full fingerprint.
    ///
    /// # Errors
    ///
    /// [`PeerError::NotWaiting`], [`PeerError::AlreadyAccepted`], or
    /// [`PeerError::Certificate`] when the stored certificate does not hash to the name.
    pub fn accept(&self, fingerprint: &Fingerprint) -> Result<(), PeerError> {
        if self.is_accepted(fingerprint) {
            return Err(PeerError::AlreadyAccepted);
        }
        let source = self
            .existing("waiting", fingerprint)
            .ok_or(PeerError::NotWaiting)?;
        let text = fs::read_to_string(&source).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                PeerError::NotWaiting
            } else {
                PeerError::Io(error)
            }
        })?;
        let certificate =
            CertificateDer::from_pem_slice(text.as_bytes()).map_err(|_| PeerError::Certificate)?;
        if Fingerprint::of_certificate(certificate.as_ref()) != *fingerprint {
            return Err(PeerError::Certificate);
        }
        fs::rename(source, self.path("accepted", fingerprint)).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                PeerError::NotWaiting
            } else {
                PeerError::Io(error)
            }
        })
    }

    /// Accepts a certificate directly, without it having waited.
    ///
    /// # Errors
    ///
    /// [`PeerError::Certificate`] when `der` is too large, [`PeerError::Io`] on write failure.
    pub fn accept_certificate(&self, der: &[u8]) -> Result<Fingerprint, PeerError> {
        if der.len() > MAX_CERTIFICATE_BYTES {
            return Err(PeerError::Certificate);
        }
        let fingerprint = Fingerprint::of_certificate(der);
        let path = self.path("accepted", &fingerprint);
        write_new(&path, &encode_pem("CERTIFICATE", der)).map_err(PeerError::Io)?;
        let _ = fs::remove_file(self.path("waiting", &fingerprint));
        Ok(fingerprint)
    }

    /// Removes an accepted or waiting peer; `true` when something was removed.
    ///
    /// # Errors
    ///
    /// [`PeerError::Io`] when a file cannot be removed.
    pub fn remove(&self, fingerprint: &Fingerprint) -> Result<bool, PeerError> {
        let mut removed = false;
        for section in ["accepted", "waiting"] {
            if let Some(path) = self.existing(section, fingerprint) {
                fs::remove_file(path).map_err(PeerError::Io)?;
                removed = true;
            }
        }
        Ok(removed)
    }

    /// Whether `fingerprint` is accepted and its stored certificate really hashes to it.
    pub fn is_accepted(&self, fingerprint: &Fingerprint) -> bool {
        let Some(path) = self.existing("accepted", fingerprint) else {
            return false;
        };
        let Ok(text) = fs::read_to_string(path) else {
            return false;
        };
        CertificateDer::from_pem_slice(text.as_bytes())
            .is_ok_and(|der| Fingerprint::of_certificate(der.as_ref()) == *fingerprint)
    }

    /// Records a refused peer's certificate as waiting. Failures are not reported to the peer.
    ///
    /// Bounded: oversized certificates are ignored; one `source` address holds at most 16
    /// entries (its oldest is replaced); the same certificate from the same source is
    /// recorded at most once a minute; the directory holds at most 1000. `None` is the
    /// source of callers that do not know it, which share one bucket.
    pub fn record_waiting(&self, der: &[u8], fingerprint: &Fingerprint, source: Option<IpAddr>) {
        if der.len() > MAX_CERTIFICATE_BYTES || self.existing("waiting", fingerprint).is_some() {
            return;
        }
        let Ok(entries) = fs::read_dir(self.root.join("waiting")) else {
            return;
        };
        if entries.take(self.limits.total).count() >= self.limits.total {
            return;
        }
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let held = seen.sources.entry(source).or_default();
        let now = Instant::now();
        if held
            .iter()
            .any(|(had, at)| had == fingerprint && now.duration_since(*at) < self.limits.rerecord)
        {
            return;
        }
        held.retain(|(had, _)| had != fingerprint);
        held.push_back((*fingerprint, now));
        while held.len() > self.limits.per_source {
            if let Some((old, _)) = held.pop_front() {
                let _ = fs::remove_file(self.path("waiting", &old));
            }
        }
        let _ = write_new(
            &self.path("waiting", fingerprint),
            &encode_pem("CERTIFICATE", der),
        );
    }

    fn list(&self, section: &str) -> Result<Vec<Fingerprint>, PeerError> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(self.root.join(section)).map_err(PeerError::Io)? {
            let path = entry.map_err(PeerError::Io)?.path();
            if path.extension().is_some_and(|extension| extension == "pem")
                && let Some(Ok(id)) = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(str::parse::<Fingerprint>)
                && !ids.contains(&id)
            {
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn path(&self, section: &str, fingerprint: &Fingerprint) -> PathBuf {
        self.root
            .join(section)
            .join(format!("{}.pem", fingerprint.hex()))
    }

    /// The file for `fingerprint` in `section`, under either accepted spelling of the name.
    fn existing(&self, section: &str, fingerprint: &Fingerprint) -> Option<PathBuf> {
        let current = self.path(section, fingerprint);
        if current.is_file() {
            return Some(current);
        }
        let legacy = self
            .root
            .join(section)
            .join(format!("{}.pem", fingerprint.to_base32_grouped()));
        legacy.is_file().then_some(legacy)
    }
}

/// Writes `text` to `path` unless it exists, atomically.
fn write_new(path: &Path, text: &str) -> io::Result<()> {
    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::hard_link(&temporary, path));
    drop(file);
    let _ = fs::remove_file(&temporary);
    result
}
