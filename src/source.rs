//! The address a handshake came from, made visible to the verifiers.
//!
//! rustls shares one verifier between every connection of a `ServerConfig` and does not
//! expose it, so the verifier cannot be given a per-connection value. Its callbacks run
//! synchronously inside the handshake call that the accept helpers make, on the calling
//! thread, so the helpers scope the address around exactly those calls.

use std::cell::Cell;
use std::net::SocketAddr;

thread_local! {
    static CURRENT: Cell<Option<SocketAddr>> = const { Cell::new(None) };
}

struct Restore(Option<SocketAddr>);

impl Drop for Restore {
    fn drop(&mut self) {
        CURRENT.with(|current| current.set(self.0));
    }
}

/// Runs `work` with `source` as the address the verifiers record waiting entries under.
///
/// [`accept`](crate::accept), [`accept_from`](crate::accept_from) and their async forms call
/// this around the handshake; a host that drives rustls itself wraps each call that can reach
/// a [`PeerClientVerifier`](crate::PeerClientVerifier) (for example `process_new_packets`).
/// Outside it, entries are recorded without a source.
pub fn with_source<R>(source: Option<SocketAddr>, work: impl FnOnce() -> R) -> R {
    let _restore = Restore(CURRENT.with(|current| current.replace(source)));
    work()
}

pub(crate) fn current() -> Option<SocketAddr> {
    CURRENT.with(Cell::get)
}
