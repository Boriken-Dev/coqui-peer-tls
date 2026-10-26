//! Pairing over TLS on loopback TCP: invitations, PINs, the device flow, a relaying attacker,
//! the pairing ALPN kept apart from the app's, and the device's own TLS policy. Blocking and
//! tokio. Run with `--all-features`.
#![cfg(all(feature = "generate", feature = "pin", feature = "tokio"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use coqui_peer_tls::pair::{
    CodeAlphabet, PairRefusal, Paired, Pairing, PairingCode, PairingDesk, PairingError, Pin,
    PinRole, Shown,
};
use coqui_peer_tls::{
    Clock, Identity, InvitationOptions, PairConfig, PeerError, Pins, ResponderTrust, Trust,
    TrustStore, accept, asynch, client_config, dial, pair_accept, pair_client_config, pair_dial,
    pair_server_config, random, server_config,
};

const APP: &[u8] = b"app/1";
const T0: u64 = 1_800_000_000;

/// A clock the test moves by hand.
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

/// One device: an identity and a trust store.
struct Device {
    _directory: tempfile::TempDir,
    identity: Identity,
    store: TrustStore,
}

fn device(hand: &Hand) -> Device {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path())
        .unwrap()
        .with_clock(hand.clock());
    Device {
        _directory: directory,
        identity: Identity::generate().unwrap(),
        store,
    }
}

fn desk(hand: &Hand) -> PairingDesk {
    PairingDesk::new(random()).with_clock(hand.clock())
}

/// Accepts one pairing connection on a thread.
fn responder(
    server: &Device,
    desk: &PairingDesk,
    config: PairConfig,
) -> (SocketAddr, thread::JoinHandle<Result<Paired, PeerError>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (identity, store, desk) = (server.identity.clone(), server.store.clone(), desk.clone());
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        pair_accept(socket, &identity, &store, &desk, &config)
    });
    (address, handle)
}

fn refusal(result: &Result<Paired, PeerError>) -> Option<PairRefusal> {
    result.as_ref().err().and_then(PeerError::pair_refusal)
}

/// Both stores pin each other: an app connection succeeds both ways.
fn app_connection_works(server: &Device, client: &Device) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = server_config(
        &server.identity,
        &Trust::Pinned(Pins::store(server.store.clone())),
        &[APP],
    )
    .unwrap();
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let (mut stream, peer) = accept(Arc::new(config), socket)?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).map_err(PeerError::Io)?;
        Ok::<_, PeerError>(peer.fingerprint)
    });
    let config = client_config(
        &client.identity,
        &Trust::Pinned(Pins::store(client.store.clone())),
        &[APP],
    )
    .unwrap();
    let (mut stream, peer) = dial(Arc::new(config), TcpStream::connect(address).unwrap()).unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();
    assert_eq!(peer.fingerprint, server.identity.fingerprint());
    assert_eq!(
        served.join().unwrap().unwrap(),
        client.identity.fingerprint()
    );
}

#[test]
fn an_invitation_pairs_and_both_sides_then_pin_each_other() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let invitation = server
        .store
        .invite(&random(), InvitationOptions::default(), "laptop")
        .unwrap();
    let (address, served) = responder(&server, &desk, PairConfig::default());
    let pairing = Pairing::invitation(server.identity.fingerprint(), invitation.secret);
    let dial = pair_dial(
        TcpStream::connect(address).unwrap(),
        &client.identity,
        pairing,
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    )
    .unwrap();
    assert!(dial.shown().is_none());
    let paired = dial.finish(&client.store).unwrap();
    assert_eq!(paired.peer.bytes, server.identity.certificate_der());
    assert_eq!(
        served.join().unwrap().unwrap().peer.bytes,
        client.identity.certificate_der()
    );
    app_connection_works(&server, &client);

    // The secret is used up.
    let (address, served) = responder(&server, &desk, PairConfig::default());
    let again = pair_dial(
        TcpStream::connect(address).unwrap(),
        &device(&hand).identity,
        Pairing::invitation(server.identity.fingerprint(), invitation.secret),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    )
    .map(|_| ());
    assert!(matches!(
        again,
        Err(PeerError::Pairing(PairingError::Refused(
            PairRefusal::WrongCode
        )))
    ));
    assert_eq!(
        refusal(&served.join().unwrap()),
        Some(PairRefusal::WrongCode)
    );
}

#[test]
fn an_invitation_is_sent_only_to_the_pinned_inviter() {
    let hand = Hand::new();
    let (impostor, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let (address, served) = responder(&impostor, &desk, PairConfig::default());
    let result = pair_dial(
        TcpStream::connect(address).unwrap(),
        &client.identity,
        Pairing::invitation(Identity::generate().unwrap().fingerprint(), [7; 32]),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    );
    let error = result.err().unwrap();
    assert_eq!(error.refusal(), Some(coqui_peer_tls::Refusal::NotPinned));
    assert!(served.join().unwrap().is_err());
}

fn shown_pin(dial: &coqui_peer_tls::PairDial<TcpStream>) -> PairingCode {
    match dial.shown() {
        Some(Shown::Pin(code)) => code.clone(),
        other => panic!("expected a PIN, got {other:?}"),
    }
}

#[test]
fn a_joiner_shows_its_pin_with_a_slot() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let (address, served) = responder(&server, &desk, PairConfig::default());
    let pin = Pin::generate(&CodeAlphabet::pin(), &random()).unwrap();
    let dial = pair_dial(
        TcpStream::connect(address).unwrap(),
        &client.identity,
        Pairing::pin(pin.clone(), PinRole::Shown),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    )
    .unwrap();
    let code = shown_pin(&dial);
    assert_eq!(code.pin, pin);
    let slots = desk.slots();
    assert_eq!(slots.len(), 1);
    assert_eq!(Some(slots[0].slot), code.slot);
    assert_eq!(slots[0].peer, client.identity.fingerprint());
    desk.submit_code(&code).unwrap();
    dial.finish(&client.store).unwrap();
    served.join().unwrap().unwrap();
    app_connection_works(&server, &client);
}

fn typed(
    server: &Device,
    client: &Device,
    desk: &PairingDesk,
    pin: &Pin,
    config: &PairConfig,
) -> (Result<Paired, PeerError>, Result<Paired, PeerError>) {
    let (address, served) = responder(server, desk, config.clone());
    let joined = pair_dial(
        TcpStream::connect(address).unwrap(),
        &client.identity,
        Pairing::pin(pin.clone(), PinRole::Typed),
        &ResponderTrust::Unverified,
        config,
    )
    .and_then(|dial| dial.finish(&client.store));
    (joined, served.join().unwrap())
}

#[test]
fn the_server_shows_a_pin_the_joiner_types() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let shown = desk.show_pin().unwrap();
    let (joined, served) = typed(&server, &client, &desk, &shown.pin, &PairConfig::default());
    joined.unwrap();
    served.unwrap();
    app_connection_works(&server, &client);
}

#[test]
fn a_wrong_pin_is_refused_and_burns_the_pin() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let shown = desk.show_pin().unwrap();
    let other = if shown.pin.as_str() == "000000" {
        "000001"
    } else {
        "000000"
    };
    let wrong = Pin::parse(&CodeAlphabet::pin(), other).unwrap();
    let (joined, served) = typed(&server, &client, &desk, &wrong, &PairConfig::default());
    assert_eq!(refusal(&joined), Some(PairRefusal::WrongCode));
    assert_eq!(refusal(&served), Some(PairRefusal::WrongCode));
    let (joined, _) = typed(&server, &client, &desk, &shown.pin, &PairConfig::default());
    assert_eq!(refusal(&joined), Some(PairRefusal::Exhausted));
    assert!(!server.store.is_accepted(&client.identity.fingerprint()));
    assert!(!client.store.is_accepted(&server.identity.fingerprint()));
}

#[cfg(feature = "tls12")]
#[test]
fn pairing_runs_under_the_devices_own_tls_1_2_policy() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let mut policy = coqui_peer_tls::Policy::compatible();
    policy.tls_versions = vec![coqui_peer_tls::TlsVersion::V1_2];
    let config = PairConfig {
        policy,
        ..PairConfig::default()
    };
    let shown = desk.show_pin().unwrap();
    let (joined, served) = typed(&server, &client, &desk, &shown.pin, &config);
    joined.unwrap();
    served.unwrap();
}

#[test]
fn a_relay_between_two_tls_connections_is_refused_on_both_sides() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let shown = desk.show_pin().unwrap();
    let (server_address, served) = responder(&server, &desk, PairConfig::default());

    // The attacker terminates the joiner's connection with its own certificate, opens another
    // to the server, and relays every pairing message unchanged.
    let attacker = Identity::generate().unwrap();
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let front_address = front.local_addr().unwrap();
    let relay = thread::spawn(move || {
        let config = PairConfig::default();
        let (socket, _) = front.accept().unwrap();
        let inner = Arc::new(pair_server_config(&attacker, &config).unwrap());
        let (mut near, _) = coqui_peer_tls::accept(inner, socket).unwrap();
        let (outer, name) = pair_client_config(
            &attacker,
            &Pairing::pin(
                Pin::parse(&CodeAlphabet::pin(), "000000").unwrap(),
                PinRole::Typed,
            ),
            &ResponderTrust::Unverified,
            &config,
        )
        .unwrap();
        let (mut far, _) = coqui_peer_tls::dial_named(
            Arc::new(outer),
            name,
            TcpStream::connect(server_address).unwrap(),
        )
        .unwrap();
        // Hello, Ready, Pake, Reply, then whatever ends it; until either side closes.
        let mut turn = 0;
        loop {
            let moved = if turn % 2 == 0 {
                relay_frame(&mut near, &mut far)
            } else {
                relay_frame(&mut far, &mut near)
            };
            if !moved {
                break;
            }
            turn += 1;
        }
    });
    let joined = pair_dial(
        TcpStream::connect(front_address).unwrap(),
        &client.identity,
        Pairing::pin(shown.pin, PinRole::Typed),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    )
    .and_then(|dial| dial.finish(&client.store));
    let served = served.join().unwrap();
    relay.join().unwrap();
    // The joiner's key in its first message is not the certificate the server's leg proved,
    // so the server stops there; the joiner sees its connection end.
    assert!(matches!(
        served,
        Err(PeerError::Pairing(PairingError::Protocol))
    ));
    assert!(joined.is_err());
    assert!(server.store.accepted().unwrap().is_empty());
    assert!(client.store.accepted().unwrap().is_empty());
}

/// Copies one length-prefixed frame from `from` to `to`; `false` when `from` closed.
fn relay_frame(from: &mut impl Read, to: &mut impl Write) -> bool {
    let mut length = [0u8; 4];
    if from.read_exact(&mut length).is_err() {
        return false;
    }
    let mut message = vec![0u8; u32::from_be_bytes(length) as usize];
    if from.read_exact(&mut message).is_err() {
        return false;
    }
    to.write_all(&length).is_ok() && to.write_all(&message).is_ok() && to.flush().is_ok()
}

#[test]
fn only_the_pairing_alpn_admits_an_unknown_certificate() {
    let hand = Hand::new();
    let (server, stranger) = (device(&hand), device(&hand));
    // The app's own configuration still refuses a certificate nobody accepted.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let app = server_config(
        &server.identity,
        &Trust::Pinned(Pins::store(server.store.clone())),
        &[APP],
    )
    .unwrap();
    let served = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        accept(Arc::new(app), socket).map(|_| ())
    });
    let client = client_config(
        &stranger.identity,
        &Trust::Pinned(Pins::fixed([server.identity.fingerprint()])),
        &[APP],
    )
    .unwrap();
    // Under TLS 1.3 the client finishes first; the refusal reaches it on its first read.
    let dialled = dial(Arc::new(client), TcpStream::connect(address).unwrap());
    if let Ok((mut stream, _)) = dialled {
        let mut byte = [0u8; 1];
        assert!(!matches!(stream.read(&mut byte), Ok(1)));
    }
    let refused = served.join().unwrap().unwrap_err();
    assert_eq!(
        refused.refusal(),
        Some(coqui_peer_tls::Refusal::NotAccepted)
    );

    // A pairing server does not speak the app's ALPN.
    let desk = desk(&hand);
    let (address, served) = responder(&server, &desk, PairConfig::default());
    let client = client_config(&stranger.identity, &Trust::AnyWithKeyProof, &[APP]).unwrap();
    assert!(dial(Arc::new(client), TcpStream::connect(address).unwrap()).is_err());
    assert!(served.join().unwrap().is_err());
}

// The device flow.

type Dialled = Result<coqui_peer_tls::PairDial<TcpStream>, PeerError>;
type Served = thread::JoinHandle<Result<Paired, PeerError>>;

fn device_dial(
    server: &Device,
    client: &Device,
    desk: &PairingDesk,
    pairing: Pairing,
    trust: ResponderTrust,
) -> (Dialled, Served) {
    let (address, served) = responder(server, desk, PairConfig::default());
    let dial = pair_dial(
        TcpStream::connect(address).unwrap(),
        &client.identity,
        pairing,
        &trust,
        &PairConfig::default(),
    );
    (dial, served)
}

fn user_code(dial: &coqui_peer_tls::PairDial<TcpStream>) -> String {
    match dial.shown() {
        Some(Shown::UserCode { code, .. }) => code.as_str().to_owned(),
        other => panic!("expected a user code, got {other:?}"),
    }
}

#[test]
fn an_approved_device_pairs() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let trust = ResponderTrust::pinned(server.identity.fingerprint());
    let (dial, served) = device_dial(&server, &client, &desk, Pairing::device("tv"), trust);
    let dial = dial.unwrap();
    let found = desk.find_device("operator", &user_code(&dial)).unwrap();
    assert_eq!(found.peer, client.identity.fingerprint());
    assert_eq!(found.label, "tv");
    assert!(found.source.is_some_and(|source| source.ip().is_loopback()));
    desk.approve(&found).unwrap();
    dial.finish(&client.store).unwrap();
    served.join().unwrap().unwrap();
    app_connection_works(&server, &client);
}

#[test]
fn a_denied_device_is_told_so() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let trust = ResponderTrust::pinned(server.identity.fingerprint());
    let (dial, served) = device_dial(&server, &client, &desk, Pairing::device(""), trust);
    let dial = dial.unwrap();
    let found = desk.find_device("operator", &user_code(&dial)).unwrap();
    desk.deny(&found).unwrap();
    assert_eq!(
        refusal(&dial.finish(&client.store)),
        Some(PairRefusal::Denied)
    );
    assert_eq!(refusal(&served.join().unwrap()), Some(PairRefusal::Denied));
    assert!(!server.store.is_accepted(&client.identity.fingerprint()));
}

#[test]
fn an_unapproved_device_expires() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let trust = ResponderTrust::pinned(server.identity.fingerprint());
    let (dial, served) = device_dial(&server, &client, &desk, Pairing::device(""), trust);
    let dial = dial.unwrap();
    hand.advance(600);
    desk.sweep();
    assert_eq!(
        refusal(&dial.finish(&client.store)),
        Some(PairRefusal::Expired)
    );
    assert_eq!(refusal(&served.join().unwrap()), Some(PairRefusal::Expired));
}

#[test]
fn wrong_user_codes_are_throttled() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let trust = ResponderTrust::pinned(server.identity.fingerprint());
    let (dial, served) = device_dial(&server, &client, &desk, Pairing::device(""), trust);
    let dial = dial.unwrap();
    let right = user_code(&dial);
    let wrong = if right == "BBBBBBBB" {
        "CCCCCCCC"
    } else {
        "BBBBBBBB"
    };
    for _ in 0..5 {
        assert!(matches!(
            desk.find_device("mallory", wrong),
            Err(PairingError::Refused(PairRefusal::WrongCode))
        ));
    }
    assert!(matches!(
        desk.find_device("mallory", &right),
        Err(PairingError::Refused(PairRefusal::Throttled))
    ));
    let found = desk.find_device("operator", &right).unwrap();
    desk.approve(&found).unwrap();
    dial.finish(&client.store).unwrap();
    served.join().unwrap().unwrap();
}

#[test]
fn the_device_flow_refuses_an_unverified_responder_unless_allowed() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    // Refused before the handshake: nobody accepts on the other end.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let refused = pair_dial(
        TcpStream::connect(listener.local_addr().unwrap()).unwrap(),
        &client.identity,
        Pairing::device(""),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    );
    assert!(matches!(
        refused.map(|_| ()),
        Err(PeerError::Pairing(PairingError::Unverified))
    ));
    // Trust::AnyWithKeyProof verifies nothing either.
    assert!(matches!(
        pair_client_config(
            &client.identity,
            &Pairing::device(""),
            &ResponderTrust::Verified {
                trust: Box::new(Trust::AnyWithKeyProof),
                name: None
            },
            &PairConfig::default()
        ),
        Err(PeerError::Pairing(PairingError::Unverified))
    ));

    let (dial, served) = device_dial(
        &server,
        &client,
        &desk,
        Pairing::device("").allow_unverified(true),
        ResponderTrust::Unverified,
    );
    let dial = dial.unwrap();
    let found = desk.find_device("operator", &user_code(&dial)).unwrap();
    desk.approve(&found).unwrap();
    dial.finish(&client.store).unwrap();
    served.join().unwrap().unwrap();
}

// tokio.

async fn async_responder(
    server: &Device,
    desk: &PairingDesk,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<Result<Paired, PeerError>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (identity, store, desk) = (server.identity.clone(), server.store.clone(), desk.clone());
    let handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        asynch::pair_accept(socket, &identity, &store, &desk, &PairConfig::default()).await
    });
    (address, handle)
}

#[tokio::test]
async fn async_invitation_and_shown_pin_pair() {
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let invitation = server
        .store
        .invite(&random(), InvitationOptions::default(), "")
        .unwrap();
    let (address, served) = async_responder(&server, &desk).await;
    let dial = asynch::pair_dial(
        tokio::net::TcpStream::connect(address).await.unwrap(),
        &client.identity,
        Pairing::invitation(server.identity.fingerprint(), invitation.secret),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    )
    .await
    .unwrap();
    dial.finish(&client.store).await.unwrap();
    served.await.unwrap().unwrap();

    let other = device(&hand);
    let (address, served) = async_responder(&server, &desk).await;
    let pin = Pin::generate(&CodeAlphabet::pin(), &random()).unwrap();
    let dial = asynch::pair_dial(
        tokio::net::TcpStream::connect(address).await.unwrap(),
        &other.identity,
        Pairing::pin(pin, PinRole::Shown),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    )
    .await
    .unwrap();
    let Some(Shown::Pin(code)) = dial.shown().cloned() else {
        panic!("expected a PIN")
    };
    desk.submit_code(&code).unwrap();
    dial.finish(&other.store).await.unwrap();
    served.await.unwrap().unwrap();
    assert!(server.store.is_accepted(&other.identity.fingerprint()));
}

#[tokio::test]
async fn async_device_flow_on_the_apps_own_port() {
    // One port: a client offering the pairing ALPN gets the pairing configuration, any other
    // the app's.
    let hand = Hand::new();
    let (server, client, desk) = (device(&hand), device(&hand), desk(&hand));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let pair = Arc::new(pair_server_config(&server.identity, &PairConfig::default()).unwrap());
    let app = Arc::new(
        server_config(
            &server.identity,
            &Trust::Pinned(Pins::store(server.store.clone())),
            &[APP],
        )
        .unwrap(),
    );
    let (identity, store, served_desk) =
        (server.identity.clone(), server.store.clone(), desk.clone());
    let served = tokio::spawn(async move {
        let mut outcomes = Vec::new();
        for _ in 0..2 {
            let (socket, source) = listener.accept().await.unwrap();
            let (pair, app) = (pair.clone(), app.clone());
            let accepted = asynch::accept_with(socket, move |hello| {
                let wants_pairing = hello
                    .alpn()
                    .is_some_and(|mut offered| offered.any(|p| p == coqui_peer_tls::PAIR_ALPN));
                if wants_pairing { pair } else { app }
            })
            .await;
            match accepted {
                Ok((tls, _))
                    if tls.get_ref().1.alpn_protocol() == Some(coqui_peer_tls::PAIR_ALPN) =>
                {
                    let paired = asynch::pair_respond(
                        tls,
                        Some(source),
                        &identity,
                        &store,
                        &served_desk,
                        &PairConfig::default(),
                    )
                    .await;
                    outcomes.push(paired.map(|_| ()));
                }
                Ok(_) => outcomes.push(Ok(())),
                Err(error) => outcomes.push(Err(error)),
            }
        }
        outcomes
    });
    let dial = asynch::pair_dial(
        tokio::net::TcpStream::connect(address).await.unwrap(),
        &client.identity,
        Pairing::device("phone"),
        &ResponderTrust::pinned(server.identity.fingerprint()),
        &PairConfig::default(),
    )
    .await
    .unwrap();
    let Some(Shown::UserCode { code, .. }) = dial.shown().cloned() else {
        panic!("expected a user code")
    };
    let found = desk.find_device("operator", code.as_str()).unwrap();
    desk.approve(&found).unwrap();
    dial.finish(&client.store).await.unwrap();

    // Now paired, the client connects to the same port with the app's ALPN.
    let config = client_config(
        &client.identity,
        &Trust::Pinned(Pins::store(client.store.clone())),
        &[APP],
    )
    .unwrap();
    let (_, peer) = asynch::dial(
        Arc::new(config),
        tokio::net::TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(peer.fingerprint, server.identity.fingerprint());
    let outcomes = served.await.unwrap();
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
}

// Timeouts. A stall shows only as a read that times out, so these use the system clock and
// timeouts of a fraction of a second.

/// A TLS pairing connection to `address` as `client` that sends the PIN-mode first message and
/// then stalls; returns the stream and the frames it receives until the server closes.
fn stalling_joiner(address: SocketAddr, client: &Device) -> Vec<Vec<u8>> {
    let (config, name) = pair_client_config(
        &client.identity,
        &Pairing::pin(
            Pin::parse(&CodeAlphabet::pin(), "000000").unwrap(),
            PinRole::Typed,
        ),
        &ResponderTrust::Unverified,
        &PairConfig::default(),
    )
    .unwrap();
    let (mut tls, _) =
        coqui_peer_tls::dial_named(Arc::new(config), name, TcpStream::connect(address).unwrap())
            .unwrap();
    let own = coqui_peer_tls::certificate_key(client.identity.certificate_der()).unwrap();
    let hello = Pairing::pin(
        Pin::parse(&CodeAlphabet::pin(), "000000").unwrap(),
        PinRole::Typed,
    )
    .join(coqui_peer_tls::pair::Channel {
        local: own,
        remote: None,
        verified: false,
        binding: None,
    })
    .unwrap()
    .transmit()
    .unwrap();
    tls.write_all(&(hello.len() as u32).to_be_bytes()).unwrap();
    tls.write_all(&hello).unwrap();
    tls.flush().unwrap();
    let mut frames = Vec::new();
    loop {
        let mut length = [0u8; 4];
        if tls.read_exact(&mut length).is_err() {
            return frames;
        }
        let mut frame = vec![0u8; u32::from_be_bytes(length) as usize];
        if tls.read_exact(&mut frame).is_err() {
            return frames;
        }
        frames.push(frame);
    }
}

/// The refusal frame for `Expired`: version, tag, reason.
const EXPIRED: [u8; 3] = [1, 8, 2];

#[test]
fn a_joiner_that_stalls_is_told_expired_and_its_place_freed() {
    let hand = Hand::new();
    let (server, client) = (device(&hand), device(&hand));
    let desk = PairingDesk::new(random())
        .with_options(coqui_peer_tls::pair::PairingOptions {
            pin_ttl: Duration::from_millis(300),
            ..Default::default()
        })
        .unwrap()
        .with_limits(coqui_peer_tls::pair::DeskLimits {
            pending_per_source: 1,
            ..Default::default()
        });
    desk.show_pin().unwrap();
    let (address, served) = responder(&server, &desk, PairConfig::default());
    let frames = stalling_joiner(address, &client);
    // Ready, then the refusal once the PIN run's deadline passed.
    assert_eq!(frames.len(), 2, "{frames:?}");
    assert_eq!(frames[1], EXPIRED);
    assert_eq!(refusal(&served.join().unwrap()), Some(PairRefusal::Expired));
    // Its place is free: the same source is admitted again.
    desk.show_pin().unwrap();
    let (address, served) = responder(&server, &desk, PairConfig::default());
    assert_eq!(stalling_joiner(address, &client)[1], EXPIRED);
    assert_eq!(refusal(&served.join().unwrap()), Some(PairRefusal::Expired));
}

#[test]
fn a_dialer_gives_up_after_its_timeout() {
    let hand = Hand::new();
    let client = device(&hand);
    // A server that accepts the connection and never speaks.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let held = thread::spawn(move || listener.accept().map(|(socket, _)| socket));
    let config = PairConfig {
        timeout: Duration::from_millis(200),
        ..PairConfig::default()
    };
    let shown = Pin::parse(&CodeAlphabet::pin(), "000000").unwrap();
    let result = pair_dial(
        TcpStream::connect(address).unwrap(),
        &client.identity,
        Pairing::pin(shown, PinRole::Typed),
        &ResponderTrust::Unverified,
        &config,
    );
    let Err(PeerError::Io(error)) = result.map(|_| ()) else {
        panic!("expected a timeout");
    };
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        "{error:?}"
    );
    drop(held.join());
}

#[tokio::test]
async fn async_a_joiner_that_stalls_is_told_expired() {
    let hand = Hand::new();
    let (server, client) = (device(&hand), device(&hand));
    let desk = PairingDesk::new(random())
        .with_options(coqui_peer_tls::pair::PairingOptions {
            pin_ttl: Duration::from_millis(300),
            ..Default::default()
        })
        .unwrap();
    desk.show_pin().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (identity, store, served_desk) =
        (server.identity.clone(), server.store.clone(), desk.clone());
    let served = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        asynch::pair_accept(
            socket,
            &identity,
            &store,
            &served_desk,
            &PairConfig::default(),
        )
        .await
    });
    let frames = tokio::task::spawn_blocking(move || stalling_joiner(address, &client))
        .await
        .unwrap();
    assert_eq!(frames.last().map(Vec::as_slice), Some(&EXPIRED[..]));
    assert_eq!(refusal(&served.await.unwrap()), Some(PairRefusal::Expired));
}
