//! The TLS method driven through the sans-IO traits of `coqui-peer`, over a byte stream and
//! over a message transport.
#![cfg(feature = "generate")]

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use coqui_peer::{DriveError, MessageTransport, Method, drive_messages, drive_stream};
use coqui_peer_tls::{
    Identity, Pins, Refusal, Tls, Trust, TrustStore, client_config, server_config,
};

fn pinned(identity: &Identity) -> Trust {
    Trust::Pinned(Pins::fixed([identity.fingerprint()]))
}

fn method(client: &Identity, server: &Identity, client_trust: &Trust, server_trust: &Trust) -> Tls {
    Tls::new()
        .with_client(Arc::new(client_config(client, client_trust, &[]).unwrap()))
        .with_server(Arc::new(server_config(server, server_trust, &[]).unwrap()))
}

#[test]
fn a_mutual_handshake_over_a_stream_yields_the_verified_peers() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let tls = method(&client, &server, &pinned(&server), &pinned(&client));
    assert_eq!(tls.name(), "tls");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepting = tls.clone();
    let served = thread::spawn(move || {
        let (mut socket, from) = listener.accept().unwrap();
        let handshake = accepting.respond(Some(from)).unwrap();
        drive_stream(handshake, &mut socket).unwrap().peer
    });
    let mut socket = TcpStream::connect(address).unwrap();
    let established = drive_stream(tls.initiate().unwrap(), &mut socket).unwrap();
    assert_eq!(established.peer, server.fingerprint());
    assert_eq!(
        established.key.unwrap().bytes,
        server.certificate_der().to_vec()
    );
    assert!(!established.session.is_handshaking());
    assert_eq!(served.join().unwrap(), client.fingerprint());
}

struct Pipe {
    out: mpsc::Sender<Vec<u8>>,
    inbox: mpsc::Receiver<Vec<u8>>,
}

impl MessageTransport for Pipe {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.out
            .send(message.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
    fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.inbox
            .recv()
            .map_err(|_| io::ErrorKind::UnexpectedEof.into())
    }
}

#[test]
fn the_same_handshake_runs_over_messages() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let tls = method(&client, &server, &pinned(&server), &pinned(&client));
    let (to_server, server_inbox) = mpsc::channel();
    let (to_client, client_inbox) = mpsc::channel();
    let accepting = tls.clone();
    let served = thread::spawn(move || {
        let mut pipe = Pipe {
            out: to_client,
            inbox: server_inbox,
        };
        drive_messages(accepting.respond(None).unwrap(), &mut pipe)
            .unwrap()
            .peer
    });
    let mut pipe = Pipe {
        out: to_server,
        inbox: client_inbox,
    };
    let established = drive_messages(tls.initiate().unwrap(), &mut pipe).unwrap();
    assert_eq!(established.peer, server.fingerprint());
    assert_eq!(served.join().unwrap(), client.fingerprint());
}

#[test]
fn an_unpinned_peer_is_refused_and_a_proven_one_waits_under_its_source() {
    let directory = tempfile::tempdir().unwrap();
    let store = TrustStore::open(directory.path()).unwrap();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let server_trust = Trust::Pinned(Pins::store(store.clone()));
    let tls = method(&client, &server, &pinned(&server), &server_trust);
    let (to_server, server_inbox) = mpsc::channel();
    let (to_client, client_inbox) = mpsc::channel();
    let accepting = tls.clone();
    let source = "192.0.2.9:5000".parse().unwrap();
    let served = thread::spawn(move || {
        let mut pipe = Pipe {
            out: to_client,
            inbox: server_inbox,
        };
        match drive_messages(accepting.respond(Some(source)).unwrap(), &mut pipe) {
            Err(DriveError::Handshake(error)) => error.refusal(),
            _ => None,
        }
    });
    let mut pipe = Pipe {
        out: to_server,
        inbox: client_inbox,
    };
    let dialed = drive_messages(tls.initiate().unwrap(), &mut pipe);
    assert_eq!(served.join().unwrap(), Some(Refusal::NotAccepted));
    // TLS 1.3 lets the client finish first, so it may or may not see the refusal.
    let _ = dialed;

    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].id, client.fingerprint());
    assert_eq!(waiting[0].source, Some(source));
    let key = store.waiting_key(&client.fingerprint()).unwrap();
    assert_eq!(
        (key.method.as_str(), key.label.as_str()),
        ("tls", "CERTIFICATE")
    );
}

#[test]
fn a_method_without_a_role_cannot_start_it() {
    let client = Identity::generate().unwrap();
    let server = Identity::generate().unwrap();
    let only_client = Tls::new().with_client(Arc::new(
        client_config(&client, &pinned(&server), &[]).unwrap(),
    ));
    assert!(only_client.initiate().is_ok());
    assert!(only_client.respond(None).is_err());
    assert!(Tls::new().initiate().is_err());
}
