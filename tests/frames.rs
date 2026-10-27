//! Announcements and pairing messages use coqui-peer's frames, and its `ReadTimeout`.

use std::io::{self, Cursor};

use coqui_peer_tls::{
    Identity, PeerError, PeerIdentity, TrustStore, announce, receive_announcement,
};

fn sender() -> Result<PeerIdentity, PeerError> {
    let pem = include_str!("vectors/identity-a.pem");
    Ok(Identity::from_pem(pem)?.peer_identity())
}

#[test]
fn an_announcement_declaring_more_than_the_frame_limit_is_refused_unread() -> Result<(), PeerError>
{
    let directory = tempfile::tempdir().map_err(PeerError::Io)?;
    let store = TrustStore::open(directory.path())?;
    let length = u32::try_from(coqui_peer::MAX_MESSAGE + 1).expect("fits");
    let mut stream = Cursor::new(length.to_be_bytes().to_vec());
    let refused = receive_announcement(&mut stream, &store, &sender()?);
    assert!(
        matches!(&refused, Err(PeerError::Io(error)) if error.kind() == io::ErrorKind::InvalidData),
        "{refused:?}"
    );
    Ok(())
}

#[test]
fn an_announcement_is_one_coqui_peer_frame() -> Result<(), PeerError> {
    let successor = Identity::from_pem(include_str!("vectors/identity-b.pem"))?;
    let mut wire = Vec::new();
    announce(&mut wire, &successor)?;
    let message = coqui_peer::read_frame(&mut Cursor::new(&wire)).map_err(PeerError::Io)?;
    assert_eq!(message.len() + 4, wire.len());
    Ok(())
}

#[test]
fn the_read_timeout_trait_is_coqui_peers() {
    fn bounded<T: coqui_peer::ReadTimeout>() {}
    fn pairing<T: coqui_peer_tls::ReadTimeout>() {
        bounded::<T>();
    }
    pairing::<std::net::TcpStream>();
}
