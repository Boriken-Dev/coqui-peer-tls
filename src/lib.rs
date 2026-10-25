//! Mutual-TLS peer identity, with no RPC layer.
//!
//! Each side has a self-issued certificate ([`Identity`]) and tells the other only its
//! SHA-256 [`Fingerprint`]. [`dial`] and [`accept`] (and, with the `tokio` feature,
//! `asynch::dial` and `asynch::accept`) return an authenticated, encrypted byte stream
//! together with the verified [`PeerIdentity`].
//!
//! | Item | Purpose |
//! | --- | --- |
//! | [`Fingerprint`] | Certificate hash in `sha256:HEX` and grouped base32 spellings. |
//! | [`Identity`] | Certificate and key as one PEM file; `generate` and `open_or_create` with the `generate` feature. |
//! | [`TrustStore`] | Accepted and waiting peers as files under `peers/`. |
//! | [`Trust`], [`Pins`] | Whom to trust: pinned, CA (`ca` feature), pinned or CA, any with key proof. |
//! | [`PeerClientVerifier`], [`PeerServerVerifier`] | The rustls verifiers as values, for other TLS stacks. |
//! | [`client_config`], [`server_config`] | TLS 1.3 configurations with ALPN as a parameter. |
//!
//! Nothing here installs a process-wide crypto provider: every configuration receives the
//! ring provider explicitly.
//!
//! # Features
//!
//! `default = ["tls12"]`. `generate` adds rcgen, `ca` adds x509-parser and globset, `tokio` adds
//! tokio-rustls.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

#[cfg(feature = "tokio")]
pub mod asynch;
#[cfg(feature = "ca")]
mod ca;
mod config;
mod error;
mod fingerprint;
mod identity;
mod policy;
mod store;
mod stream;
mod trust;
mod x509;

pub use config::{
    Built, client_config, client_config_with, crypto_provider, server_config, server_config_with,
};
#[cfg(feature = "acl")]
pub use coqui_net_acl as acl;
pub use error::PeerError;
pub use fingerprint::{Digest, Fingerprint};
pub use identity::{Identity, PeerIdentity};
pub use policy::{POLICY_VERSION, Policy, TlsVersion, Weakening};
pub use store::{TrustStore, WaitingLimits};
pub use stream::{SERVER_NAME, accept, dial};
#[cfg(feature = "ca")]
pub use trust::CaPolicy;
pub use trust::{PeerClientVerifier, PeerServerVerifier, Pins, Trust};
