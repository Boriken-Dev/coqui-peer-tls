//! Waiting entries carry the address the handshake came from, and the caps are per source.
#![cfg(all(feature = "generate", feature = "tokio"))]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use coqui_peer_tls::{
    Identity, Pins, Policy, Trust, TrustStore, TrustStoreExt, WaitingLimits, accept, accept_from,
    client_config, dial, server_config, server_config_with,
};

fn store() -> (tempfile::TempDir, TrustStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    (directory, store)
}

fn record(store: &TrustStore, identity: &Identity, source: &str) {
    let source: SocketAddr = source.parse().unwrap();
    store.record_waiting_certificate(identity.certificate_der(), Some(source));
}

#[test]
fn one_source_filling_its_cap_does_not_block_another() {
    let (_directory, store) = store();
    let store = store.with_limits(WaitingLimits {
        per_source: 2,
        total: 100,
        rerecord: Duration::from_secs(60),
    });
    let noisy: Vec<Identity> = (0..3).map(|_| Identity::generate().unwrap()).collect();
    for identity in &noisy {
        record(&store, identity, "192.0.2.1:1000");
    }
    let quiet = Identity::generate().unwrap();
    record(&store, &quiet, "192.0.2.2:2000");

    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 3);
    let from = |ip: &str| {
        waiting
            .iter()
            .filter(|entry| {
                entry
                    .source
                    .is_some_and(|source| source.ip().to_string() == ip)
            })
            .count()
    };
    assert_eq!(from("192.0.2.1"), 2);
    assert_eq!(from("192.0.2.2"), 1);
    // The oldest of the noisy source was replaced; the quiet one is untouched.
    assert!(
        waiting
            .iter()
            .all(|entry| entry.id != noisy[0].fingerprint())
    );
    assert!(waiting.iter().any(|entry| entry.id == quiet.fingerprint()));
}

#[test]
fn the_rerecord_interval_holds_per_source() {
    let (_directory, store) = store();
    let identity = Identity::generate().unwrap();
    record(&store, &identity, "192.0.2.1:1000");
    store.remove(&identity.fingerprint()).unwrap();

    // Same certificate, same source address, inside the interval: not recorded again.
    record(&store, &identity, "192.0.2.1:1001");
    assert!(store.waiting().unwrap().is_empty());
    // Another source is not held back by the first one's interval.
    record(&store, &identity, "192.0.2.2:2000");
    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].source, Some("192.0.2.2:2000".parse().unwrap()));
}

#[test]
fn the_recorded_address_is_the_one_the_client_connected_from() {
    let (_directory, store) = store();
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let trust = Trust::Pinned(Pins::store(store.clone()));
    let config = Arc::new(server_config(&server, &trust, &[]).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        accept(config, socket).is_ok()
    });
    let socket = TcpStream::connect(address).unwrap();
    let local = socket.local_addr().unwrap();
    let server_trust = Trust::Pinned(Pins::fixed([server.fingerprint()]));
    let config = client_config(&client, &server_trust, &[]).unwrap();
    let _ = dial(Arc::new(config), socket);
    assert!(!served.join().unwrap());

    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].id, client.fingerprint());
    assert_eq!(waiting[0].source, Some(local));
}

#[test]
fn accept_from_records_the_address_it_is_given() {
    let (_directory, store) = store();
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let trust = Trust::Pinned(Pins::store(store.clone()));
    let config = Arc::new(
        server_config_with(&server, &trust, &[], &Policy::default())
            .unwrap()
            .config,
    );
    let given: SocketAddr = "192.0.2.7:4000".parse().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        accept_from(config, socket, given).is_ok()
    });
    let socket = TcpStream::connect(address).unwrap();
    let server_trust = Trust::Pinned(Pins::fixed([server.fingerprint()]));
    let config = client_config(&client, &server_trust, &[]).unwrap();
    let _ = dial(Arc::new(config), socket);
    assert!(!served.join().unwrap());
    assert_eq!(store.waiting().unwrap()[0].source, Some(given));
}

#[tokio::test]
async fn async_accept_from_records_the_address_it_is_given() {
    let (_directory, store) = store();
    let (server, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let trust = Trust::Pinned(Pins::store(store.clone()));
    let server_config = Arc::new(server_config(&server, &trust, &[]).unwrap());
    let server_trust = Trust::Pinned(Pins::fixed([server.fingerprint()]));
    let client_config = Arc::new(client_config(&client, &server_trust, &[]).unwrap());
    let given: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
    let (near, far) = tokio::io::duplex(8192);
    let accepting = tokio::spawn(async move {
        coqui_peer_tls::asynch::accept_from(server_config, far, given)
            .await
            .is_ok()
    });
    let _ = coqui_peer_tls::asynch::dial(client_config, near).await;
    assert!(!accepting.await.unwrap());
    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].source, Some(given));
}
