use std::sync::Arc;

use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::server::NoServerSessionStorage;
use rustls::{ClientConfig, ServerConfig};

use crate::error::PeerError;
use crate::identity::Identity;
use crate::policy::{Policy, Weakening};
use crate::trust::Trust;

/// The default ring crypto provider, passed explicitly to every configuration built here.
/// Nothing in this crate installs a process-wide default.
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A built configuration and the settings of its [`Policy`] that are looser than strict, so
/// a host can surface them. Nothing is printed by this crate.
#[derive(Debug)]
pub struct Built<T> {
    /// The configuration.
    pub config: T,
    /// Every setting looser than strict; empty under the strict profile.
    pub weakened: Vec<Weakening>,
}

/// A client configuration under the strict policy (TLS 1.3 only) that presents `identity`
/// and verifies the server by `trust` (pinned, or any certificate with key proof).
///
/// `alpn` lists the application protocols offered, most preferred first. Session resumption
/// is off: every connection verifies the server's certificate.
///
/// # Errors
///
/// As [`client_config_with`].
pub fn client_config(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
) -> Result<ClientConfig, PeerError> {
    client_config_with(identity, trust, alpn, &Policy::default()).map(|built| built.config)
}

/// A client configuration under `policy`. Session resumption is off unless
/// [`Policy::allow_resumption`] is set, which then keeps rustls's default session cache.
///
/// # Errors
///
/// [`PeerError::Unsupported`] for CA trust; [`PeerError::Policy`] when the policy asks for
/// something the ring provider or this build cannot do; [`PeerError::Certificate`] or
/// [`PeerError::Tls`] when the configuration cannot be built.
pub fn client_config_with(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    let verifier = trust.server_cert_verifier_with(policy)?;
    let versions = policy.protocol_versions()?;
    let mut config = ClientConfig::builder_with_provider(policy.crypto_provider()?)
        .with_protocol_versions(&versions)
        .map_err(|_| PeerError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.certificate()], identity.key())
        .map_err(|_| PeerError::Certificate)?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    if !policy.allow_resumption {
        config.resumption = Resumption::disabled();
    }
    Ok(Built {
        config,
        weakened: policy.weakened(),
    })
}

/// A server configuration under the strict policy that presents `identity` and requires a
/// client certificate trusted by `trust`. Session resumption is off: every connection
/// verifies the client's certificate.
///
/// # Errors
///
/// As [`server_config_with`].
pub fn server_config(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
) -> Result<ServerConfig, PeerError> {
    server_config_with(identity, trust, alpn, &Policy::default()).map(|built| built.config)
}

/// A server configuration under `policy`. Session resumption is off unless
/// [`Policy::allow_resumption`] is set, which then keeps rustls's default session cache and
/// TLS 1.3 tickets.
///
/// # Errors
///
/// [`PeerError::Certificate`], [`PeerError::TrustPattern`], [`PeerError::Policy`] or
/// [`PeerError::Tls`] when the configuration cannot be built.
pub fn server_config_with(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ServerConfig>, PeerError> {
    let verifier = trust.client_cert_verifier_with(policy)?;
    let versions = policy.protocol_versions()?;
    let mut config = ServerConfig::builder_with_provider(policy.crypto_provider()?)
        .with_protocol_versions(&versions)
        .map_err(|_| PeerError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.certificate()], identity.key())
        .map_err(|_| PeerError::Certificate)?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    if !policy.allow_resumption {
        // No session cache for TLS 1.2 session ids or TLS 1.3 stateful tickets, and no
        // tickets sent; the builder's ticketer already produces none.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
    }
    Ok(Built {
        config,
        weakened: policy.weakened(),
    })
}
