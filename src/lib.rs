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
#[cfg(feature = "fields")]
mod fields;
#[cfg(feature = "acl")]
mod gate;
mod handshake;
mod identity;
mod pairing;
mod policy;
mod profiles;
mod roots;
mod settings;
mod source;
mod stream;
mod trust;
mod x509;

pub use certificate::{METHOD, TrustStoreExt, certificate_key};
pub use config::{Built, ClientAuth, ClientBuilder, ServerAuth, ServerBuilder, crypto_provider};
#[allow(deprecated)]
pub use config::{
    client_config, client_config_with, client_config_with_verifier, client_config_without_identity,
    client_config_without_identity_with, server_config, server_config_with,
    server_config_with_verifier, server_config_without_client_auth,
    server_config_without_client_auth_with,
};
pub use connection::{ConnectionConfig, ServerConfigs};
#[cfg(feature = "acl")]
pub use coqui_net_acl as acl;
pub use coqui_peer::NonDefault;
#[allow(deprecated)]
pub use coqui_peer::Weakening;
pub use coqui_peer::pair;
pub use coqui_peer::{
    Clock, Digest, Invitation, InvitationOptions, KeyMaterial, PeerId, Random, ReadTimeout,
    RotationEvent, RotationOptions, TrustStore, WaitingEntry, WaitingLimits, WriteTimeout,
};
pub use error::{PeerError, Refusal};
#[cfg(feature = "fields")]
pub use fields::{CertificateFields, Name, San};
pub use handshake::{Tls, TlsHandshake};
#[cfg(feature = "generate")]
pub use identity::IdentityBuilder;
pub use identity::{Identity, PeerIdentity};
#[allow(deprecated)]
pub use pairing::pair_accept_from;
pub use pairing::{
    EXPORTER_LABEL, PAIR_ALPN, PairConfig, PairDial, ResponderTrust, announce, pair_accept,
    pair_client_config, pair_dial, pair_server_config, random, receive_announcement,
};
#[allow(deprecated)]
pub use policy::POLICY_VERSION;
pub use policy::{Policy, TlsVersion};
pub use profiles::{CipherProfile, Crypto};
pub use roots::Roots;
pub use settings::TlsSettings;
pub use source::with_addresses;
#[allow(deprecated)]
pub use source::with_source;
pub use stream::{Addressed, PeerAddr, SERVER_NAME, accept, default_server_name, dial, dial_named};
#[allow(deprecated)]
pub use stream::{accept_at, accept_from};
#[cfg(feature = "ca")]
pub use trust::CaPolicy;
pub use trust::{PeerClientVerifier, PeerClientVerifierBuilder, PeerServerVerifier, Pins, Trust};
