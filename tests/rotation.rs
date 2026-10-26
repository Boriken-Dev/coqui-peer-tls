//! Key rotation over TLS: a peer announces its successor certificate over a connection its
//! current one authenticated; the first handshake that proves the successor promotes it, and
//! the old certificate is refused from its retirement time on. Clients and servers alike.
#![cfg(all(feature = "generate", feature = "tokio"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coqui_peer_tls::{
    Clock, Identity, PeerError, PeerId, PeerIdentity, Pins, Refusal, RotationEvent,
    RotationOptions, Trust, TrustStore, TrustStoreExt, accept, announce, asynch, client_config,
    dial, receive_announcement, server_config,
};

const APP: &[u8] = b"app/1";
const T0: u64 = 1_800_000_000;
const DAY: u64 = 24 * 3600;

#[derive(Clone)]
struct Hand(Arc<AtomicU64>);

impl Hand {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(T0)))
    }

    fn clock(&self) -> Clock {
        let now = self.0.clone();
        Clock::from_fn(move || UNIX_EPOCH + Duration::from_secs(now.load(Ordering::SeqCst)))
    }

    fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

fn store(hand: &Hand) -> (tempfile::TempDir, TrustStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path())
        .unwrap()
        .with_clock(hand.clock());
    (directory, store)
}

/// Serves one connection with `config`; `then` runs on the accepted stream.
fn serve<T: Send + 'static>(
    config: rustls::ServerConfig,
    then: impl FnOnce(&mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>, PeerIdentity) -> T
    + Send
    + 'static,
) -> (SocketAddr, thread::JoinHandle<Result<T, PeerError>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let (mut stream, peer) = accept(Arc::new(config), socket)?;
        let result = then(&mut stream, peer);
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        Ok(result)
    });
    (address, handle)
}

/// A server whose clients are the accepted peers of `store`.
fn pinned_server(identity: &Identity, store: &TrustStore) -> rustls::ServerConfig {
    server_config(identity, &Trust::Pinned(Pins::store(store.clone())), &[APP]).unwrap()
}

/// Dials as `client`, trusting `server` by a fixed pin, and closes.
fn connect(
    address: SocketAddr,
    client: &Identity,
    server: &PeerId,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, PeerError> {
    let config = client_config(client, &Trust::Pinned(Pins::fixed([*server])), &[APP]).unwrap();
    let (stream, _) = dial(Arc::new(config), TcpStream::connect(address).unwrap())?;
    Ok(stream)
}

/// Connects as `client` and returns the server's verdict.
fn handshake(
    server: &Identity,
    store: &TrustStore,
    client: &Identity,
) -> Result<PeerId, PeerError> {
    let (address, served) = serve(pinned_server(server, store), |_, peer| peer.fingerprint);
    if let Ok(mut stream) = connect(address, client, &server.fingerprint()) {
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }
    served.join().unwrap()
}

#[test]
fn a_client_rotates_and_its_old_certificate_retires() {
    let hand = Hand::new();
    let (_directory, store) = store(&hand);
    let server = Identity::generate().unwrap();
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    store.accept_certificate(old.certificate_der()).unwrap();

    // The old certificate announces the new one.
    let watched = store.clone();
    let (address, served) = serve(pinned_server(&server, &store), move |stream, peer| {
        receive_announcement(stream, &watched, &peer)
    });
    let mut stream = connect(address, &old, &server.fingerprint()).unwrap();
    announce(&mut stream, &new).unwrap();
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    drop(stream);
    assert_eq!(served.join().unwrap().unwrap().unwrap(), new.fingerprint());
    assert!(!store.is_accepted(&new.fingerprint()));

    // The first handshake with the new certificate promotes it.
    assert_eq!(handshake(&server, &store, &new).unwrap(), new.fingerprint());
    assert!(store.is_accepted(&new.fingerprint()));
    let retires = UNIX_EPOCH + Duration::from_secs(T0 + DAY);
    assert_eq!(
        store.take_rotation_events(),
        [
            RotationEvent::Announced {
                old: old.fingerprint(),
                new: new.fingerprint()
            },
            RotationEvent::Promoted {
                old: old.fingerprint(),
                new: new.fingerprint(),
                retires
            }
        ]
    );

    // The old one works until it retires, and not after.
    assert!(handshake(&server, &store, &old).is_ok());
    hand.advance(DAY);
    let refused = handshake(&server, &store, &old).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NotAccepted));
    assert!(handshake(&server, &store, &new).is_ok());
}

#[test]
fn a_successor_waits_for_approval_when_the_store_requires_it() {
    let hand = Hand::new();
    let (_directory, store) = store(&hand);
    let store = store.with_rotation(RotationOptions {
        require_approval: true,
        ..RotationOptions::default()
    });
    let server = Identity::generate().unwrap();
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    store.accept_certificate(old.certificate_der()).unwrap();
    let key = coqui_peer_tls::certificate_key(new.certificate_der()).unwrap();
    store.announce_successor(&old.fingerprint(), &key).unwrap();

    let refused = handshake(&server, &store, &new).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NotAccepted));
    // Not queued as a stranger either: it is a pending successor.
    assert!(store.waiting().unwrap().is_empty());

    store.promote_successor(&new.fingerprint()).unwrap();
    assert!(handshake(&server, &store, &new).is_ok());
}

#[test]
fn a_server_rotates_towards_a_client_that_pins_it() {
    let hand = Hand::new();
    let (_directory, client_store) = store(&hand);
    let client = Identity::generate().unwrap();
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    client_store
        .accept_certificate(old.certificate_der())
        .unwrap();
    let trusting = Trust::Pinned(Pins::store(client_store.clone()));

    // The server, still on its old certificate, announces the new one.
    let config = server_config(&old, &Trust::AnyWithKeyProof, &[APP]).unwrap();
    let announced = new.clone();
    let (address, served) = serve(config, move |stream, _| {
        announce(stream, &announced).unwrap();
    });
    let config = client_config(&client, &trusting, &[APP]).unwrap();
    let (mut stream, peer) = dial(Arc::new(config), TcpStream::connect(address).unwrap()).unwrap();
    assert_eq!(
        receive_announcement(&mut stream, &client_store, &peer).unwrap(),
        new.fingerprint()
    );
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    drop(stream);
    served.join().unwrap().unwrap();

    // The server switches; the client takes the new certificate and promotes it.
    let config = server_config(&new, &Trust::AnyWithKeyProof, &[APP]).unwrap();
    let (address, served) = serve(config, |_, _| ());
    let config = client_config(&client, &trusting, &[APP]).unwrap();
    let (mut stream, peer) = dial(Arc::new(config), TcpStream::connect(address).unwrap()).unwrap();
    assert_eq!(peer.fingerprint, new.fingerprint());
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    drop(stream);
    served.join().unwrap().unwrap();
    assert!(client_store.is_accepted(&new.fingerprint()));
    assert_eq!(client_store.retiring().unwrap()[0].id, old.fingerprint());

    // An unannounced certificate is still refused.
    let stranger = Identity::generate().unwrap();
    let config = server_config(&stranger, &Trust::AnyWithKeyProof, &[APP]).unwrap();
    let (address, _served) = serve(config, |_, _| ());
    let config = client_config(&client, &trusting, &[APP]).unwrap();
    let refused = dial(Arc::new(config), TcpStream::connect(address).unwrap()).unwrap_err();
    assert_eq!(refused.refusal(), Some(Refusal::NotAccepted));
}

#[test]
fn an_announcement_from_a_peer_that_is_not_accepted_is_refused() {
    let hand = Hand::new();
    let (_directory, store) = store(&hand);
    let server = Identity::generate().unwrap();
    let (sender, successor) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    // The server takes anyone here, so only the store can refuse the announcement.
    let config = server_config(&server, &Trust::AnyWithKeyProof, &[APP]).unwrap();
    let watched = store.clone();
    let (address, served) = serve(config, move |stream, peer| {
        receive_announcement(stream, &watched, &peer)
    });
    let mut stream = connect(address, &sender, &server.fingerprint()).unwrap();
    announce(&mut stream, &successor).unwrap();
    stream.conn.send_close_notify();
    stream.flush().unwrap();
    drop(stream);
    let outcome = served.join().unwrap().unwrap();
    assert!(matches!(
        outcome,
        Err(PeerError::Pairing(
            coqui_peer_tls::pair::PairingError::Local(coqui_peer::Error::NotAccepted)
        ))
    ));
    assert!(store.successors().unwrap().is_empty());
}

#[test]
fn renewal_is_due_within_the_margin() {
    let now = SystemTime::now();
    let identity = Identity::generate_with(now, now + Duration::from_secs(3600)).unwrap();
    assert!(!identity.renew_before_at(Duration::from_secs(1800), now));
    assert!(identity.renew_before_at(Duration::from_secs(3600), now));
    assert!(identity.renew_before_at(Duration::ZERO, now + Duration::from_secs(3600)));
    assert!(
        !Identity::generate()
            .unwrap()
            .renew_before(Duration::from_secs(DAY))
    );
}

#[tokio::test]
async fn an_async_announcement_is_recorded() {
    let hand = Hand::new();
    let (_directory, store) = store(&hand);
    let server = Identity::generate().unwrap();
    let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    store.accept_certificate(old.certificate_der()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(pinned_server(&server, &store));
    let watched = store.clone();
    let served = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut stream, peer) = asynch::accept(config, socket).await.unwrap();
        asynch::receive_announcement(&mut stream, &watched, &peer).await
    });
    let config = client_config(
        &old,
        &Trust::Pinned(Pins::fixed([server.fingerprint()])),
        &[APP],
    )
    .unwrap();
    let (mut stream, _) = asynch::dial(
        Arc::new(config),
        tokio::net::TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    asynch::announce(&mut stream, &new).await.unwrap();
    assert_eq!(served.await.unwrap().unwrap(), new.fingerprint());
    assert_eq!(store.successors().unwrap()[0].new, new.fingerprint());
}
