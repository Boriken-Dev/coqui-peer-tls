use alloc::sync::Arc;
use core::net::SocketAddr;

use rustls::client::Resumption;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::server::NoServerSessionStorage;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, ServerConfig};

use crate::error::PeerError;
use crate::identity::Identity;
use crate::policy::Policy;
use crate::trust::Trust;
use coqui_peer::Weakening;

/// The [`Weakening::setting`] a server configuration without client authentication reports.
pub const CLIENT_AUTH_SETTING: &str = "client_auth";

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
    /// Every setting looser than strict; empty under the strict profile with mutual TLS.
    pub weakened: Vec<Weakening>,
}

/// A client configuration under the strict policy (TLS 1.3 only) that presents `identity`
/// and verifies the server by `trust`: pinned, by [`Roots`](crate::Roots) for the name
/// dialled ([`dial_named`](crate::dial_named)), pinned or roots, or any certificate with key
/// proof.
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
/// something the ring provider or this build cannot do; [`PeerError::Io`] or
/// [`PeerError::Certificate`] when the roots cannot be loaded; [`PeerError::Certificate`] or
/// [`PeerError::Tls`] when the configuration cannot be built.
pub fn client_config_with(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    build_client(Some(identity), trust, alpn, policy)
}

/// A client configuration under the strict policy that presents no certificate, for a
/// server built with [`server_config_without_client_auth`]. The server is verified by
/// `trust` exactly as in [`client_config`]; this side proves itself, if at all, inside the
/// encrypted channel. A server that requires a client certificate refuses it.
///
/// # Errors
///
/// As [`client_config_without_identity_with`].
pub fn client_config_without_identity(
    trust: &Trust,
    alpn: &[&[u8]],
) -> Result<ClientConfig, PeerError> {
    client_config_without_identity_with(trust, alpn, &Policy::default()).map(|built| built.config)
}

/// [`client_config_without_identity`] under `policy`, with the same handling of versions,
/// suites, groups and resumption as [`client_config_with`].
///
/// # Errors
///
/// [`PeerError::Unsupported`] for CA trust; [`PeerError::Policy`] when the policy asks for
/// something the ring provider or this build cannot do; [`PeerError::Io`] or
/// [`PeerError::Certificate`] when the roots cannot be loaded; [`PeerError::Tls`] when the
/// configuration cannot be built.
pub fn client_config_without_identity_with(
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    build_client(None, trust, alpn, policy)
}

/// A client configuration under `policy` that verifies the server with `verifier`, a verifier
/// of the host's own (one of this crate's wrapped, for example). It presents `identity` and its
/// intermediates, or no certificate for `None`, and handles versions, suites, groups, the
/// extended master secret, ALPN and resumption as [`client_config_with`] does.
///
/// # Errors
///
/// [`PeerError::Policy`] when the policy asks for something the ring provider or this build
/// cannot do; [`PeerError::Certificate`] or [`PeerError::Tls`] when the configuration cannot be
/// built.
pub fn client_config_with_verifier(
    identity: Option<&Identity>,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    build_client_with(identity, verifier, alpn, policy)
}

fn build_client(
    identity: Option<&Identity>,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    let verifier = trust.server_cert_verifier_with(policy)?;
    build_client_with(identity, verifier, alpn, policy)
}

fn build_client_with(
    identity: Option<&Identity>,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ClientConfig>, PeerError> {
    let versions = policy.protocol_versions()?;
    let builder = ClientConfig::builder_with_provider(policy.crypto_provider()?)
        .with_protocol_versions(&versions)
        .map_err(|_| PeerError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match identity {
        Some(identity) => builder
            .with_client_auth_cert(identity.certificate_chain(), identity.private_key_der())
            .map_err(|_| PeerError::Certificate)?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    // rustls has the setting only where it can offer TLS 1.2.
    #[cfg(feature = "tls12")]
    {
        config.require_ems = policy.require_ems;
    }
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
    build_server(identity, Some(verifier), alpn, policy, None)
}

/// [`server_config_with`] for one connection, from `source` to `local`: for a host whose
/// connections reach rustls without this crate's accept helpers, such as quinn, which runs the
/// verifier on threads of its own and takes a configuration per incoming connection.
///
/// Waiting entries are recorded under `source`, and a policy's access control list (feature
/// `acl`) is decided from these addresses: by address when the `ClientHello` arrives, and by
/// the certificate's fingerprint before the trust store is consulted. A host that can refuse a
/// connection before its handshake (a quinn `Incoming`) checks
/// [`Policy::admits_address`](crate::Policy::admits_address) first: a refusal inside the
/// handshake reaches it as rustls's own error.
///
/// # Errors
///
/// As [`server_config_with`].
pub fn server_config_for(
    identity: &Identity,
    trust: &Trust,
    alpn: &[&[u8]],
    policy: &Policy,
    source: SocketAddr,
    local: SocketAddr,
) -> Result<Built<ServerConfig>, PeerError> {
    let verifier = Arc::new(trust.client_verifier(policy, Some(source))?);
    build_server(
        identity,
        Some(verifier),
        alpn,
        policy,
        Some((source, local)),
    )
}

/// A server configuration under the strict policy that presents `identity` and asks for no
/// client certificate: the server proves itself, the client does not at the TLS layer.
///
/// **The application must authenticate the client inside the encrypted channel** (a key
/// proof, a token) before trusting it. A handshake with this configuration finishes with no
/// peer certificate: see [`TlsHandshake::finish_unauthenticated`](crate::TlsHandshake::finish_unauthenticated).
/// Session resumption is off.
///
/// # Errors
///
/// As [`server_config_without_client_auth_with`].
pub fn server_config_without_client_auth(
    identity: &Identity,
    alpn: &[&[u8]],
) -> Result<ServerConfig, PeerError> {
    server_config_without_client_auth_with(identity, alpn, &Policy::default())
        .map(|built| built.config)
}

/// [`server_config_without_client_auth`] under `policy`, with the same handling of versions,
/// suites, groups, ALPN and resumption as [`server_config_with`].
///
/// [`Built::weakened`] always holds a [`Weakening`] with setting [`CLIENT_AUTH_SETTING`],
/// value `none` and strict value `certificate`, after the policy's own.
///
/// # Errors
///
/// [`PeerError::Certificate`], [`PeerError::Policy`] or [`PeerError::Tls`] when the
/// configuration cannot be built.
pub fn server_config_without_client_auth_with(
    identity: &Identity,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ServerConfig>, PeerError> {
    let mut built = build_server(identity, None, alpn, policy, None)?;
    built.weakened.push(Weakening {
        setting: CLIENT_AUTH_SETTING.to_owned(),
        value: "none".to_owned(),
        strict: "certificate".to_owned(),
    });
    Ok(built)
}

/// A server configuration under `policy` that verifies clients with `verifier`, a verifier of
/// the host's own (one of this crate's wrapped, for example). It presents `identity` and its
/// intermediates, and handles versions, suites, groups, the extended master secret, ALPN and
/// resumption as [`server_config_with`] does.
///
/// # Errors
///
/// [`PeerError::Policy`] when the policy asks for something the ring provider or this build
/// cannot do; [`PeerError::Certificate`] or [`PeerError::Tls`] when the configuration cannot be
/// built.
pub fn server_config_with_verifier(
    identity: &Identity,
    verifier: Arc<dyn ClientCertVerifier>,
    alpn: &[&[u8]],
    policy: &Policy,
) -> Result<Built<ServerConfig>, PeerError> {
    build_server(identity, Some(verifier), alpn, policy, None)
}

/// A server configuration; with a policy access control list, `verifier` is wrapped to decide
/// each certificate and the certificate resolver to decide each `ClientHello`, from
/// `addresses`, or from the scope the accept helpers set when `None`.
fn build_server(
    identity: &Identity,
    verifier: Option<Arc<dyn ClientCertVerifier>>,
    alpn: &[&[u8]],
    policy: &Policy,
    addresses: Option<(SocketAddr, SocketAddr)>,
) -> Result<Built<ServerConfig>, PeerError> {
    #[cfg(feature = "acl")]
    let gate = match &policy.acl {
        Some(acl) => Some(crate::gate::Gate::new(
            crate::gate::canonical(acl)?,
            addresses,
        )),
        None => None,
    };
    #[cfg(not(feature = "acl"))]
    let _ = addresses;
    #[cfg(feature = "acl")]
    let verifier = match (&gate, verifier) {
        (Some(gate), Some(inner)) => Some(Arc::new(crate::gate::PeerGate {
            inner,
            gate: gate.clone(),
        }) as Arc<dyn ClientCertVerifier>),
        (_, verifier) => verifier,
    };
    #[cfg(feature = "acl")]
    let identified = verifier.is_some();
    let versions = policy.protocol_versions()?;
    let builder = ServerConfig::builder_with_provider(policy.crypto_provider()?)
        .with_protocol_versions(&versions)
        .map_err(|_| PeerError::Tls)?;
    let builder = match verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(identity.certificate_chain(), identity.private_key_der())
        .map_err(|_| PeerError::Certificate)?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    // rustls has the setting only where it can offer TLS 1.2.
    #[cfg(feature = "tls12")]
    {
        config.require_ems = policy.require_ems;
    }
    if !policy.allow_resumption {
        // No session cache for TLS 1.2 session ids or TLS 1.3 stateful tickets, and no
        // tickets sent; the builder's ticketer already produces none.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
    }
    #[cfg(feature = "acl")]
    if let Some(gate) = gate {
        config.cert_resolver = Arc::new(crate::gate::AddressGate {
            inner: Arc::clone(&config.cert_resolver),
            gate,
            identified,
        });
    }
    Ok(Built {
        config,
        weakened: policy.weakened(),
    })
}
