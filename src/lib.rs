//! Mutual-TLS peer identity, with no RPC layer: the TLS method of [`coqui_peer`].
//!
//! Each side has a self-issued certificate ([`Identity`]) and tells the other only its
//! SHA-256 [`Fingerprint`], the [`PeerId`] of the core crate. [`dial`] and [`accept`] (and,
//! with the `tokio` feature, `asynch::dial` and `asynch::accept`) return an authenticated,
//! encrypted byte stream together with the verified [`PeerIdentity`]. [`Tls`] is the same
//! method as a sans-IO [`coqui_peer::Method`], for message transports and the drivers of the
//! core crate.
//!
//! Server TLS is the other mode: the server proves itself by certificate and the client
//! presents none ([`server_config_without_client_auth`], [`client_config_without_identity`]),
//! so the application authenticates the client inside the channel.
//!
//! | Item | Purpose |
//! | --- | --- |
//! | [`Fingerprint`] | The core crate's `PeerId`: `sha256:HEX` and grouped base32 spellings. |
//! | [`Identity`] | Certificate and key as one PEM file; `generate` and `open_or_create` with the `generate` feature. |
//! | [`TrustStore`] | The core crate's store of accepted and waiting peers; certificates stored under the method name `tls`. |
//! | [`Trust`], [`Pins`], [`Roots`] | Whom to trust: pinned, CA (`ca` feature), pinned or CA, any with key proof; a server by the web PKI (roots). |
//! | [`PeerClientVerifier`], [`PeerServerVerifier`] | The rustls verifiers as values, for other TLS stacks. |
//! | [`Refusal`] | Why a verifier refused a certificate, read back with [`PeerError::refusal`]. |
//! | [`client_config`], [`server_config`] | TLS 1.3 configurations with ALPN as a parameter. |
//! | [`server_config_without_client_auth`], [`client_config_without_identity`] | Server TLS: the server proves itself by certificate, the client inside the channel. |
//! | [`Tls`], [`TlsHandshake`] | The method and handshake of [`coqui_peer`]. |
//!
//! Nothing here installs a process-wide crypto provider: every configuration receives the
//! ring provider explicitly.
//!
//! # Features
//!
//! `default = []`. `tls12` adds TLS 1.2, `generate` adds rcgen, `ca` adds x509-parser and
//! globset, `tokio` adds tokio-rustls, `serde` the text form of [`Policy`], `platform-roots`
//! adds rustls-platform-verifier for `Roots::platform`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

#[cfg(feature = "tokio")]
pub mod asynch;
#[cfg(feature = "ca")]
mod ca;
mod certificate;
mod config;
mod error;
mod handshake;
mod identity;
mod policy;
mod roots;
mod source;
mod stream;
mod trust;
mod x509;

pub use certificate::{METHOD, TrustStoreExt, certificate_key};
pub use config::{
    Built, CLIENT_AUTH_SETTING, client_config, client_config_with, client_config_without_identity,
    client_config_without_identity_with, crypto_provider, server_config, server_config_with,
    server_config_without_client_auth, server_config_without_client_auth_with,
};
#[cfg(feature = "acl")]
pub use coqui_net_acl as acl;
pub use coqui_peer::{Digest, KeyMaterial, PeerId, TrustStore, WaitingEntry, WaitingLimits};
pub use error::{PeerError, Refusal};
pub use handshake::{Tls, TlsHandshake};
pub use identity::{Identity, PeerIdentity};
pub use policy::{POLICY_VERSION, Policy, TlsVersion, Weakening};
pub use roots::Roots;
pub use source::with_source;
pub use stream::{PeerAddr, SERVER_NAME, accept, accept_from, dial, dial_named};
#[cfg(feature = "ca")]
pub use trust::CaPolicy;
pub use trust::{PeerClientVerifier, PeerServerVerifier, Pins, Trust};

/// The SHA-256 id of a certificate: the [`PeerId`] of the core crate, kept under its former
/// name so pins and code written against it keep working. Parsing, display and equality are
/// the core crate's.
pub type Fingerprint = PeerId;
