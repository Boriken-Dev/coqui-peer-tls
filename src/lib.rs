#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

extern crate alloc;

#[cfg(feature = "tokio")]
pub mod asynch;
#[cfg(feature = "ca")]
mod ca;
mod certificate;
mod config;
mod connection;
mod error;
#[cfg(feature = "acl")]
mod gate;
mod handshake;
mod identity;
mod pairing;
mod policy;
mod profiles;
mod roots;
mod source;
mod stream;
mod trust;
mod x509;

pub use certificate::{METHOD, TrustStoreExt, certificate_key};
pub use config::{
    Built, CLIENT_AUTH_SETTING, client_config, client_config_with, client_config_with_verifier,
    client_config_without_identity, client_config_without_identity_with, crypto_provider,
    server_config, server_config_with, server_config_with_verifier,
    server_config_without_client_auth, server_config_without_client_auth_with,
};
pub use connection::{ConnectionConfig, ServerConfigs};
#[cfg(feature = "acl")]
pub use coqui_net_acl as acl;
pub use coqui_peer::pair;
pub use coqui_peer::{
    Clock, Digest, Invitation, InvitationOptions, KeyMaterial, PeerId, Random, ReadTimeout,
    RotationEvent, RotationOptions, TrustStore, WaitingEntry, WaitingLimits, Weakening,
    WriteTimeout,
};
pub use error::{PeerError, Refusal};
pub use handshake::{Tls, TlsHandshake};
pub use identity::{Identity, PeerIdentity};
pub use pairing::{
    EXPORTER_LABEL, PAIR_ALPN, PairConfig, PairDial, ResponderTrust, announce, pair_accept,
    pair_accept_from, pair_client_config, pair_dial, pair_server_config, random,
    receive_announcement,
};
pub use policy::{POLICY_VERSION, Policy, TlsVersion};
pub use profiles::{CipherProfile, Crypto};
pub use roots::Roots;
pub use source::{with_addresses, with_source};
pub use stream::{
    PeerAddr, SERVER_NAME, accept, accept_at, accept_from, default_server_name, dial, dial_named,
};
#[cfg(feature = "ca")]
pub use trust::CaPolicy;
pub use trust::{PeerClientVerifier, PeerServerVerifier, Pins, Trust};
