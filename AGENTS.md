# `coqui-peer-tls` — API header

Header-file-style reference for the `coqui-peer-tls` crate: every public item with its signature,
contract and gotchas, so the crate can be used without reading its source. It ships inside the
package and is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/coqui-peer-tls>.

| Feature | Adds | Needed for | Default |
| --- | --- | --- | --- |
| `tls12` | rustls `tls12` | `Policy::compatible()`, `legacy()`, any policy allowing TLS 1.2 | off |
| `generate` | `rcgen`, `time` | `Identity::generate`, `generate_valid_for`, `generate_with`, `open_or_create` | off |
| `ca` | `x509-parser`, `globset` | `Trust::Ca`, `Trust::PinnedOrCa`, `CaPolicy` | off |
| `tokio` | `tokio` (`net`, `io-util`, `time`), `tokio-rustls`, `coqui-peer/tokio` | module `asynch` | off |
| `pin` | `coqui-peer/pin` | PIN pairing (`Pairing::pin`) | off |
| `serde` | `serde`, `coqui-peer/serde`, `coqui-net-acl/serde` | the text form of `Policy`, `PeerId` as text; the consumer picks the format | off |
| `acl` | `coqui-net-acl` | `Policy::acl` and its enforcement, `coqui_peer_tls::acl` | off |
| `platform-roots` | `rustls-platform-verifier` | `Roots::platform` | off |

MSRV Rust 1.89. A default build depends on `coqui-peer` and `rustls` (0.23.27 or later, ring
provider). Version `0.0.0-alpha.0` is a pre-release; the API may change in any release before
1.0. This is the TLS method of `coqui-peer` (the core: `PeerId`, `TrustStore`, the sans-IO
`Handshake`, `Weakening`); its API header ships in that crate.

Imports: everything is at the crate root, including re-exports of `coqui-peer`'s `Clock`,
`Digest`, `Invitation`, `InvitationOptions`, `KeyMaterial`, `PeerId`, `Random`, `ReadTimeout`,
`RotationEvent`, `RotationOptions`, `TrustStore`, `WaitingEntry`, `WaitingLimits` and
`Weakening`. Public modules: `asynch` (feature `tokio`), `pair` (`coqui_peer::pair`
re-exported) and `acl` (`coqui_net_acl` re-exported, feature `acl`).

No `unsafe` code (`#![forbid(unsafe_code)]`). Process-wide state: one thread-local holding the
addresses of the handshake call in progress (`with_source`, `with_addresses`). Nothing installs
a process-wide crypto provider, and nothing reads a file or an environment variable unless the
caller passes a path. TLS 1.3 is the default; TLS 1.2 only when a policy allows it.

## Ids (`coqui_peer_tls::{PeerId, Digest}`, from `coqui-peer`)

```rust
pub use coqui_peer::{Digest, PeerId, KeyMaterial, TrustStore, WaitingEntry, WaitingLimits};
// PeerId: Copy, Eq (constant time), Ord, Hash, Display = "sha256:<hex>", FromStr
```

The id of a certificate is `PeerId::of(der)` (SHA-256) or `Digest::Sha384.of(der)`. Text
forms, `canonical()`, `hex()`, `to_base32_grouped()` and the parsing rules (`sha256:<hex>`, bare
hex, colon pairs, grouped base32; MD5 is `PeerError::WeakDigest`) are the core crate's. Whether a
policy lets a pin use a digest is a `Policy` matter.

## Identity (`coqui_peer_tls::{Identity, PeerIdentity}`)

```rust
pub struct Identity;                       // Clone; Debug shows only the fingerprint
impl Identity {
    pub fn from_pem(text: &str) -> Result<Identity, PeerError>;       // exactly one certificate + its key
    pub fn from_pem_chain(text: &str) -> Result<Identity, PeerError>; // leaf, its intermediates in order, the leaf's key
    pub fn to_pem(&self) -> Result<String, PeerError>;                // certificate, intermediates, then PKCS#8 key
    pub fn read(path: &Path) -> Result<Option<Identity>, PeerError>;  // None when absent; a chain is read
    pub fn write_new(&self, path: &Path) -> Result<(), PeerError>;    // never replaces; 0600; creates parents
    pub fn fingerprint(&self) -> PeerId;                               // the leaf's
    pub fn certificate_der(&self) -> &[u8];                           // the leaf
    pub fn intermediates_der(&self) -> impl ExactSizeIterator<Item = &[u8]>;   // empty unless from_pem_chain
    pub fn peer_identity(&self) -> PeerIdentity;
    pub fn certificate_chain(&self) -> Vec<CertificateDer<'static>>;  // leaf, then intermediates
    pub fn private_key_der(&self) -> PrivateKeyDer<'static>;          // a copy; Debug elides it
    // feature generate: self-signed ECDSA P-256, CN "coqui-peer", DNS SAN SERVER_NAME,
    // subjectKeyIdentifier, basicConstraints CA:FALSE
    pub fn generate() -> Result<Identity, PeerError>;                 // rcgen's default validity (decades)
    pub fn generate_valid_for(validity: Duration) -> Result<Identity, PeerError>;           // from now
    pub fn generate_with(not_before: SystemTime, not_after: SystemTime) -> Result<Identity, PeerError>;
    pub fn open_or_create(path: &Path) -> Result<Identity, PeerError>;
}
pub struct PeerIdentity { pub fingerprint: PeerId, pub certificate: Vec<u8> }   // DER
```

- **Chains.** `from_pem_chain` takes a CA-issued leaf with its intermediates (a web-PKI server a
  browser reaches over `wss://`); every configuration built from the identity presents the
  whole chain. The key must be the first certificate's, or `PeerError::Certificate`. The
  fingerprint is the leaf's. A peer that pins it refuses the chain (`Refusal::ChainWhenPinned`)
  unless its policy sets `allow_chain_when_pinned`; `AnyWithKeyProof` takes it. `from_pem`
  refuses a chain; `read` and `open_or_create` read a file holding one (leaf first), so a
  chained identity written with `write_new` reads back as it was.
- **Short-lived identities.** `generate_valid_for(d)` is valid from now to now + `d`;
  `generate_with` takes both ends. Times are truncated to whole seconds; a window under one
  second, an end before the start, or a time before 1970 is `PeerError::Certificate`. Any
  positive length is accepted. WebTransport's `serverCertificateHashes` accepts only a
  certificate whose whole validity period is at most 14 days: pass at most
  `Duration::from_secs(14 * 86_400)` and replace it before it expires; a peer whose clock runs
  behind sees it as not yet valid until its start.
- **Extensions.** Every generated certificate carries a subjectAltName (`SERVER_NAME`), a
  subjectKeyIdentifier and basicConstraints `CA:FALSE`. Chrome's `serverCertificateHashes`
  verifier refuses a certificate with no extensions. Pins name the certificate as made, so
  pinning is unaffected.

## Trust (`coqui_peer_tls::{Trust, Pins, CaPolicy, Roots}`)

```rust
#[non_exhaustive]
pub enum Trust { Pinned(Pins), Ca(CaPolicy), PinnedOrCa { pins: Pins, ca: CaPolicy }, AnyWithKeyProof,
                 Roots(Roots), PinnedOrRoots { pins: Pins, roots: Roots } }
impl Pins { pub fn fixed(impl IntoIterator<Item = PeerId>) -> Pins; pub fn store(TrustStore) -> Pins;
            pub fn matches(&self, der: &[u8]) -> bool; }
pub struct CaPolicy { pub ca_file: PathBuf, pub subject: Vec<String>, pub san: Vec<String> }  // feature ca
pub struct Roots;    // Clone, Debug (a PEM bundle shows only its length)
impl Roots {
    pub fn bundle_pem(text: impl Into<String>) -> Roots;     // every CERTIFICATE block is a root
    pub fn bundle_file(path: impl Into<PathBuf>) -> Roots;   // read when the verifier is built
    pub fn platform() -> Roots;                              // feature platform-roots
}
impl Trust {
    pub fn client_cert_verifier(&self) -> Result<Arc<PeerClientVerifier>, PeerError>;           // strict policy
    pub fn client_cert_verifier_with(&self, &Policy) -> Result<Arc<PeerClientVerifier>, PeerError>;  // a policy with an acl: PeerError::Policy
    pub fn server_cert_verifier(&self) -> Result<Arc<PeerServerVerifier>, PeerError>;
    pub fn server_cert_verifier_with(&self, &Policy) -> Result<Arc<PeerServerVerifier>, PeerError>;
}
```

`PeerClientVerifier` implements rustls `ClientCertVerifier`, `PeerServerVerifier` implements
`ServerCertVerifier`; hand them to any rustls-based stack. Every policy requires the peer to
prove its key. Names are not checked on the pinned path; roots always check them.

- A fixed pin matches by hashing the certificate with the pin's digest; every pin is compared
  in constant time. A store holds SHA-256 pins.
- After a pin matches: no intermediates unless `allow_chain_when_pinned`, then validity dates
  unless `check_validity` is false. The pin check comes first; certificates are parsed only
  after.
- `Ca` and `PinnedOrCa` apply to servers (client certificates); `server_cert_verifier*`
  returns `PeerError::Unsupported` for them. CA trust checks the chain and the globs.
- `Roots` and `PinnedOrRoots` apply to clients (the server's certificate);
  `client_cert_verifier*` returns `PeerError::Unsupported` for them. This is the web PKI, a
  different trust model from pinning: any server a root issued a certificate for the dialled
  name is trusted. The chain, every certificate's dates (always, whatever `check_validity`
  says) and the server name are checked, by rustls's `WebPkiServerVerifier` over the bundle,
  or by the operating system's verifier with `platform()` (which may also check revocation).
  Nothing skips the name check. Dial with the host's name: `dial_named`,
  `asynch::dial_named`, `TlsHandshake::client_named`, or rustls / quinn with a `ServerName`;
  `dial` names `SERVER_NAME`, which no root issues, so it is refused (`NameMismatch`).
- `PinnedOrRoots` takes a pinned certificate as `Pinned` does, whatever its name; any other
  certificate must pass the roots. A wrong name is `Refusal::NameMismatch`; an expired or
  not-yet-valid one rustls's `Expired*` / `NotValidYet*`, and `Revoked` and `BadEncoding` stay
  rustls's own too; any other chain failure (unknown issuer, bad signature, a leaf not for
  server authentication, a platform's own reason) is `Refusal::NotTrusted`.
- A bundle (and a `CaPolicy::ca_file`) is read when the verifier is built
  (`server_cert_verifier*`, `client_config*`; `client_cert_verifier*`, `server_config*`):
  every failure is `PeerError::CaFile { path, certificate, read }` naming the file (`None` for
  `bundle_pem`), and the certificate that is malformed or cannot be a trust anchor by its
  position from 0, or `read` with the I/O error when the file cannot be read; neither when it
  holds no certificate. `Display`: `CA file <path>: certificate 1 is malformed or cannot be a
  trust anchor`, `... cannot be read`, `... holds no certificate`. `platform()` failing to start (no system roots on Linux) is
  `PeerError::Certificate`. On Android the host initializes rustls-platform-verifier from its
  JVM first (`rustls_platform_verifier::android::init_*`), or a handshake panics.
- `AnyWithKeyProof` takes any certificate whose key is proven; the caller decides from
  `PeerIdentity` afterwards.
- With a store-backed pin set, alone or beside a CA policy, an untrusted client is recorded
  as waiting only after its handshake signature verifies (TLS 1.3 and 1.2), then refused:
  every waiting entry is key-proven. `verify_client_cert` runs before that signature, so it
  records nothing. A stolen public certificate fails the handshake and leaves no entry.
- The recorded source is the address the handshake came from. `accept` (sync and `asynch`,
  `accept_with`) requires `PeerAddr`, implemented for `std::net::TcpStream` and
  `tokio::net::TcpStream`; any other stream uses `accept_from(config, io, SocketAddr)` /
  `asynch::accept_from` / `asynch::accept_with_from`. `with_source(Option<SocketAddr>, f)`
  scopes the address for a host that drives rustls itself; outside it, entries have no source.
  Caps are per source: an IPv4 address, or an IPv6 /64 (`TrustStore::with_ipv6_prefix`); the
  full `SocketAddr` is stored.
- A pin whose digest the policy does not list is `PeerError::Policy` when the verifier is built.
- A refusal is `rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc<Refusal>)))`
  (alert `certificate_unknown`); a pinned certificate outside its dates is rustls's `Expired` /
  `NotValidYet`, one whose dates cannot be read `BadEncoding`. See Errors.
- The verifiers are not called on a resumed session. The configurations built here turn
  resumption off (see Policy); a stack that takes only the verifiers must turn it off itself
  (server `session_storage = NoServerSessionStorage`, `send_tls13_tickets = 0`; client
  `resumption = Resumption::disabled()`), or a peer that lost trust can resume.

## Trust store and certificates (`coqui_peer_tls::{TrustStore, TrustStoreExt}`)

The store, `WaitingEntry { id, source }`, `WaitingLimits`, the pairing flow and the rule that a
peer is recorded only after it proved its key are `coqui-peer`'s; see its API header. This
crate keeps certificates in it as `KeyMaterial` with method `tls` and label `CERTIFICATE`:

```rust
pub const METHOD: &str = "tls";
pub fn certificate_key(der: &[u8]) -> Result<KeyMaterial, PeerError>;
pub trait TrustStoreExt {
    fn accept_certificate(&self, der: &[u8]) -> Result<PeerId, PeerError>;
    fn record_waiting_certificate(&self, der: &[u8], source: Option<SocketAddr>);
}                                                  // implemented for TrustStore
```

A store-backed `Pins` counts a peer as accepted only when its entry names method `tls`.
`record_waiting` is bounded as in the core: per source IP, the rerecord interval, a total.

## Policy (`coqui_peer_tls::Policy`)

```rust
pub struct Policy {
    pub name: String,                          // informational; "strict", "compatible", "legacy" or your own
    pub tls_versions: Vec<TlsVersion>,         // #[non_exhaustive] enum TlsVersion { V1_2, V1_3 }
    pub cipher_suites: Option<Vec<String>>,    // IANA names; None = all for the versions
    pub kx_groups: Option<Vec<String>>,        // e.g. "X25519"; None = all
    pub pin_digests: Vec<Digest>,
    pub check_validity: bool,
    pub allow_chain_when_pinned: bool,
    pub allow_resumption: bool,                // a resumed session skips the verifiers
    pub require_ems: bool,                     // TLS 1.2: the extended master secret (RFC 7627)
    pub waiting: WaitingLimits,                // per_source 16, total 1000, rerecord 60 s
    pub acl: Option<coqui_net_acl::Acl>,       // feature acl; applied by every server configuration
}
impl Default for Policy { /* Policy::strict() */ }
impl Policy {
    pub fn strict() -> Policy;  pub fn compatible() -> Policy;  pub fn legacy() -> Policy;
    pub fn preset(name: &str) -> Result<Policy, PeerError>;
    pub fn weakened(&self) -> Vec<Weakening>;
    pub fn weakened_against(&self, baseline: &Policy) -> Vec<Weakening>;
    pub fn check_pin(&self, fingerprint: &PeerId) -> Result<(), PeerError>;
    pub fn crypto_provider(&self) -> Result<Arc<CryptoProvider>, PeerError>;
    pub fn supported_cipher_suites() -> Vec<String>;
    pub fn supported_kx_groups() -> Vec<String>;
    pub fn deserialize_over<'de, D: Deserializer<'de>>(base: Policy, d: D) -> Result<Policy, D::Error>;  // feature serde
}
pub use coqui_peer::Weakening;    // { setting, value, strict }, Weakening::new; setting: a field, or "client_auth"
pub const POLICY_VERSION: u32 = 1;
impl TlsVersion { pub const fn as_str(self) -> &'static str; }   // "1.2", "1.3"; also Display; FromStr refuses others
```

| Field | strict | compatible | legacy |
| --- | --- | --- | --- |
| `tls_versions` | 1.3 | 1.2, 1.3 | 1.2, 1.3 |
| `pin_digests` | sha256, sha384, sha512 | same | plus sha1 |
| `check_validity` | true | true | true |
| `allow_chain_when_pinned` | false | false | false |
| `allow_resumption` | false | false | false |
| `require_ems` | true | true | true |
| `waiting` (`per_source`, `total`, `rerecord`) | 16, 1000, 60 s | same | same |
| `cipher_suites`, `kx_groups`, `acl` | none | none | none |

`crypto_provider` narrows the ring provider to the policy's versions, suites and groups; an
unknown name, or a version left with no suite, is `PeerError::Policy` whose message lists the
supported names. `weakened` reports `tls_versions` including 1.2, `pin_digests` beyond
sha256/384/512, `check_validity` false, `allow_chain_when_pinned` true, `allow_resumption`
true, `require_ems` false, larger waiting caps or a shorter rerecord time, and an ACL with a
`permit` default.

`allow_resumption` false (every preset) builds configurations with resumption off at both ends:
the server keeps no session cache and sends no TLS 1.3 tickets, the client keeps no sessions, so
every connection runs the verifiers and a peer removed from the store or no longer pinned is
refused at its next connection. True keeps rustls's defaults (a 256-session cache, two TLS 1.3
tickets) and lets a peer that lost trust reconnect on a session it holds.

### Text form, version 1 (feature `serde`)

Build a `Policy` in code (constructors and public fields); the text form is optional. The crate
parses no format itself: with `serde` the consumer reads it with its own `toml` or `serde_json`.

TOML or JSON object. Keys: `policy_version` (must be 1 when present), `profile` (a built-in
preset name to start from; unknown names are errors; free text when read with
`deserialize_over`), `tls_versions` (`"1.2"`, `"1.3"`), `cipher_suites`, `kx_groups`,
`pin_digests` (`"sha256"`, `"sha384"`, `"sha512"`, `"sha1"`), `check_validity`,
`allow_chain_when_pinned`, `allow_resumption`, `require_ems`, `waiting_per_source`,
`waiting_total`, `waiting_rerecord_secs` (the fields of `waiting`, the last in whole seconds), and
`acl` (see `coqui-net-acl`). Unknown keys are errors; absent keys keep the preset. Writing
always names every field. `tests/vectors/policy/{strict,compatible,legacy,acl}.{toml,json}`
are byte-exact.

## Access control (`Policy::acl`, feature `acl`)

Every server configuration built under a policy with `acl: Some(..)` applies it:
`server_config(_with)`, `server_config_with_verifier`, `server_config_without_client_auth_with`,
`ServerConfigs::for_connection` and `pair_server_config`.

- **By address, at the `ClientHello`**: the certificate resolver is wrapped and answers only an
  admitted connection. When every client must present a certificate, `Acl::decide` (a rule
  naming a fingerprint defers to the certificate); otherwise `Acl::decide_anonymous`: server TLS
  (`server_config_without_client_auth_with`), and a host verifier whose
  `client_auth_mandatory()` is false, since its client may send no certificate and the
  fingerprint check would never run. So under optional client authentication a rule naming a
  fingerprint never admits a client. A denial is `Refusal::AddressDenied` and no certificate is
  sent.
- **By fingerprint, in the client verifier**: `Acl::decide_peer` with the certificate's
  canonical `sha256:<hex>`, before pins, CA policy or trust store are consulted, so a denied
  client is never recorded as waiting. A denial is `Refusal::PeerDenied`.
- **Fingerprints are canonical.** Rules may be written in any spelling `PeerId` parses (hex,
  colon pairs, grouped base32); they are rewritten to `sha256:<hex>` when a policy is read from
  text and when a configuration is built. A rule naming something that is not a SHA-256 peer id
  is `PeerError::Policy` there ("acl rule N: ...").
- **Addresses.** A configuration shared by connections reads them from the scope the accept
  helpers set: `accept` takes both from a `PeerAddr` (`TcpStream`, tokio's too), `accept_from`
  the source only, `accept_at` and `asynch::accept_at` both, `TlsHandshake::server(.., source)`
  the source and `.with_local(local)` the local address, `with_addresses` both for a host
  driving rustls itself. Without a source, or without a local address when a rule names a
  destination or port, the connection is refused (`Refusal::AddressUnknown`); a missing local
  address is fine when no rule reads it. A configuration for one connection
  (`ServerConfigs::for_connection`, `Trust::client_cert_verifier_for`) holds its addresses and
  needs no scope: for quinn, which runs the verifier on its own threads.
- `Policy::admits_address(source, local)` / `admits_anonymous` give the address decision
  without a handshake, for a host that refuses a connection before it (a quinn `Incoming`).
- Session resumption skips both checks, as it skips the verifiers: it is off unless
  `allow_resumption`.

```rust
pub fn with_addresses<R>(source: Option<SocketAddr>, local: Option<SocketAddr>, work: impl FnOnce() -> R) -> R;
pub trait PeerAddr { fn peer_addr(&self) -> Option<SocketAddr>; fn local_addr(&self) -> Option<SocketAddr> { None } }
pub fn accept_at<S: Read + Write>(Arc<ServerConfig>, S, source: SocketAddr, local: SocketAddr) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError>;
// feature tokio: asynch::accept_at(Arc<ServerConfig>, S, SocketAddr, SocketAddr), async
impl TlsHandshake { pub fn with_local(self, local: SocketAddr) -> TlsHandshake; }
impl Trust { pub fn client_cert_verifier_for(&self, &Policy, source: SocketAddr, local: SocketAddr) -> Result<Arc<dyn ClientCertVerifier>, PeerError>; }
impl Policy {   // feature acl
    pub fn admits_address(&self, source: SocketAddr, local: SocketAddr) -> Result<(), Refusal>;
    pub fn admits_anonymous(&self, source: SocketAddr, local: SocketAddr) -> Result<(), Refusal>;
}
```

`client_cert_verifier_for` records waiting entries under its `source` (no scope needed) and,
with an ACL, refuses a denied fingerprint before the pins; it does not apply the address rules,
which `ServerConfigs::for_connection` (both) or `Policy::admits_address` (before the handshake)
do. `client_cert_verifier_with` has no addresses, so it refuses a policy with an ACL
(`PeerError::Policy`) rather than ignore it.

### Configurations per connection (`coqui_peer_tls::{ServerConfigs, ConnectionConfig}`)

```rust
pub struct ServerConfigs;   // Clone (shares the session state), Debug
impl ServerConfigs {
    pub fn new(&Identity, &Trust, alpn: &[&[u8]], &Policy) -> Result<ServerConfigs, PeerError>;
    pub fn with_verifier(&Identity, Arc<dyn ClientCertVerifier>, alpn: &[&[u8]], &Policy) -> Result<ServerConfigs, PeerError>;
    pub fn without_client_auth(&Identity, alpn: &[&[u8]], &Policy) -> Result<ServerConfigs, PeerError>;
    pub fn weakened(&self) -> &[Weakening];
    pub fn for_connection(&self, source: SocketAddr, local: SocketAddr) -> Result<ConnectionConfig, PeerError>;
}
pub struct ConnectionConfig;   // Clone, Debug
impl ConnectionConfig {
    pub fn config(&self) -> Arc<ServerConfig>;   // quinn: QuicServerConfig::try_from(config)
    pub fn refusal(&self) -> Option<Refusal>;    // the first refusal of this connection's handshake
}
```

For a host that builds a configuration per connection (quinn's `Incoming::accept_with`). The
three constructors build what `server_config_with`, `server_config_with_verifier` and
`server_config_without_client_auth_with` build, and check the identity and policy once (their
errors are those functions'); `weakened` is what `Built::weakened` would hold.
`for_connection` then gives one connection's configuration: waiting entries recorded under
`source`, the ACL decided from `source` and `local` (by address at the `ClientHello`, by
fingerprint before the store), and every configuration from one `ServerConfigs` sharing one
session cache and ticketer, so with `allow_resumption` a client resumes across connections
(separate `ServerConfigs` never share sessions). quinn reports a failed server handshake only by
its alert; `refusal()` gives this side's typed reason: `AddressDenied` / `AddressUnknown` at the
hello, `PeerDenied` and every trust refusal in the verifier (a host verifier's too, when it
returns a `Refusal`). Check `Policy::admits_address` before `accept_with` to refuse without a
handshake.

## Configurations and streams (`coqui_peer_tls`, `coqui_peer_tls::asynch`)

```rust
pub struct Built<T> { pub config: T, pub weakened: Vec<Weakening> }
pub fn client_config(&Identity, &Trust, alpn: &[&[u8]]) -> Result<ClientConfig, PeerError>;
pub fn server_config(&Identity, &Trust, alpn: &[&[u8]]) -> Result<ServerConfig, PeerError>;
pub fn client_config_with(&Identity, &Trust, &[&[u8]], &Policy) -> Result<Built<ClientConfig>, PeerError>;
pub fn server_config_with(&Identity, &Trust, &[&[u8]], &Policy) -> Result<Built<ServerConfig>, PeerError>;
// server TLS: the server presents a certificate, the client none
pub fn server_config_without_client_auth(&Identity, alpn: &[&[u8]]) -> Result<ServerConfig, PeerError>;
pub fn server_config_without_client_auth_with(&Identity, &[&[u8]], &Policy) -> Result<Built<ServerConfig>, PeerError>;
pub fn client_config_without_identity(&Trust, alpn: &[&[u8]]) -> Result<ClientConfig, PeerError>;
pub fn client_config_without_identity_with(&Trust, &[&[u8]], &Policy) -> Result<Built<ClientConfig>, PeerError>;
// a verifier of the host's own, under the policy; the whole chain presented
pub fn server_config_with_verifier(&Identity, Arc<dyn ClientCertVerifier>, alpn: &[&[u8]], &Policy) -> Result<Built<ServerConfig>, PeerError>;
pub fn client_config_with_verifier(Option<&Identity>, Arc<dyn ServerCertVerifier>, alpn: &[&[u8]], &Policy) -> Result<Built<ClientConfig>, PeerError>;
pub const CLIENT_AUTH_SETTING: &str = "client_auth";
pub fn crypto_provider() -> Arc<CryptoProvider>;       // default ring provider
pub const SERVER_NAME: &str = "coqui-peer.invalid";
pub fn default_server_name() -> ServerName<'static>;   // SERVER_NAME as rustls takes it
pub fn dial<S: Read + Write>(Arc<ClientConfig>, S) -> Result<(StreamOwned<ClientConnection, S>, PeerIdentity), PeerError>;
pub fn dial_named<S: Read + Write>(Arc<ClientConfig>, ServerName<'static>, S) -> Result<(StreamOwned<ClientConnection, S>, PeerIdentity), PeerError>;
pub fn accept<S: Read + Write + PeerAddr>(Arc<ServerConfig>, S) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError>;
pub fn accept_from<S: Read + Write>(Arc<ServerConfig>, S, source: SocketAddr) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError>;
pub trait PeerAddr { fn peer_addr(&self) -> Option<SocketAddr>; }   // std and tokio TcpStream
pub fn with_source<R>(Option<SocketAddr>, impl FnOnce() -> R) -> R;
// feature tokio, module asynch:
pub async fn dial<S>(Arc<ClientConfig>, S) -> Result<(client::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn dial_named<S>(Arc<ClientConfig>, ServerName<'static>, S) -> Result<(client::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept<S: PeerAddr>(Arc<ServerConfig>, S) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept_from<S>(Arc<ServerConfig>, S, SocketAddr) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept_with_from<S>(S, SocketAddr, select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept_with<S: PeerAddr>(S, select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
```

`server_config_with_verifier` and `client_config_with_verifier` build exactly what
`server_config_with` and `client_config_with` build (the policy's versions, suites, groups,
extended master secret and resumption, the identity's whole chain, ALPN) around a verifier the
host supplies, typically one of this crate's wrapped; `Built::weakened` is the policy's. A host
building a rustls or quinn configuration by hand takes the identity's `certificate_chain()` and
`private_key_der()`.

Both complete the handshake before returning, so a refused certificate is an error and the
returned `PeerIdentity` is verified. `dial` sends `SERVER_NAME`, which pinned trust ignores
(trust by fingerprint); `dial_named` sends the name given, which `Roots` check. The returned
peer's fingerprint is the leaf certificate's however the server was verified. `accept_with`
chooses the server configuration from the ClientHello, for example by ALPN, so one port serves
peers and other clients.

### Server TLS

The server proves itself by certificate; the client presents none and **must be
authenticated by the application inside the encrypted channel** (a key proof, a token) before
it is trusted. For browsers (`wss://`, WebTransport), which cannot present a chosen client
certificate, and hosts without an identity of their own.

- `server_config_without_client_auth*` handle versions, suites, groups, ALPN and resumption as
  `server_config_with` does (resumption off unless `allow_resumption`) and request no client
  certificate. `Built::weakened` always ends with `Weakening { setting: "client_auth" (=
  CLIENT_AUTH_SETTING), value: "none", strict: "certificate" }`, after the policy's own.
- `client_config_without_identity*` verify the server by `Trust` exactly as `client_config*`
  (pins or a store; roots; `AnyWithKeyProof`; CA is `Unsupported`) and present no
  certificate. A mutual-TLS server refuses such a client. Its `weakened` is the policy's only.
- The server finishes with `TlsHandshake::finish_unauthenticated` (below), or any rustls /
  tokio-rustls acceptor: there is no client verifier, so `with_source` has nothing to scope.
  `accept`, `accept_from` and the `asynch` accepts return a verified client, so with this
  configuration they fail with `PeerError::Certificate` after the handshake. `dial` and
  `TlsHandshake::finish` on the client side work as in mutual TLS.

## The method (`coqui_peer_tls::{Tls, TlsHandshake}`)

```rust
pub struct Tls;      // Clone, Default
impl Tls { pub fn new() -> Tls; pub fn with_client(self, Arc<ClientConfig>) -> Tls; pub fn with_server(self, Arc<ServerConfig>) -> Tls; }
impl coqui_peer::Method for Tls { /* name() = "tls"; initiate(); respond(source: Option<SocketAddr>) */ }
pub struct TlsHandshake;   // client(Arc<ClientConfig>), server(Arc<ServerConfig>, Option<SocketAddr>)
impl TlsHandshake {
    pub fn client_named(Arc<ClientConfig>, ServerName<'static>) -> Result<TlsHandshake, PeerError>;   // client() sends SERVER_NAME
    pub fn finish_unauthenticated(self) -> Result<(rustls::Connection, Option<PeerIdentity>), PeerError>;
}
impl coqui_peer::Handshake for TlsHandshake { /* Output = rustls::Connection, Framing::Stream */ }
```

`receive` feeds rustls (`read_tls`, `process_new_packets`); `transmit` drains `write_tls`;
`is_complete` is `!is_handshaking()`. `finish` gives `Established { peer, key: Some(certificate),
session: Connection }`; the connection keeps application data that arrived with the last
handshake bytes. The server handshake scopes its `source` around each `receive`, so waiting
entries carry the address exactly as `accept` does. A role without a configuration is
`PeerError::Unsupported`. Run it with `coqui_peer::drive_stream` / `drive_messages` (the
latter needs a reliable, ordered message channel) or the `tokio` forms.

`finish` needs a peer certificate (`PeerError::Certificate` without one), so a server-TLS server
drives its handshake with `coqui_peer::complete_stream` / `complete_messages` (or the
`receive`/`transmit` loop itself) and calls `finish_unauthenticated`: the connection, and
`Some` verified peer only when the client sent a certificate. With a configuration from
`server_config_without_client_auth*` it is always `None`, meaning not authenticated. Before
completion it is `PeerError::Tls`.

## Pairing and rotation over TLS (`coqui_peer_tls`, `coqui_peer_tls::pair`)

The `coqui-peer` pairing exchange (re-exported as `coqui_peer_tls::pair`; its API header has the
modes, options, desk, throttles, their costs and the security model) on a connection of its
own, and key rotation over an authenticated one. TLS settings are the device's own `Policy`;
nothing here sets a version or suite.

```rust
pub use coqui_peer::pair;                    // Pairing, PairingDesk, PairingOptions, DeskLimits, Pin, ...
pub use coqui_peer::{Clock, Random, Invitation, InvitationOptions, RotationOptions, RotationEvent};
pub const PAIR_ALPN: &[u8] = b"coqui-pair/1";
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-coqui-pair";
pub struct PairConfig { pub policy: Policy, pub alpn: Vec<u8>, pub timeout: Duration }  // strict, PAIR_ALPN, 15 min
pub use coqui_peer::ReadTimeout;            // fn set_read_timeout(&self, Option<Duration>) -> io::Result<()>; TcpStream
#[non_exhaustive] pub enum ResponderTrust { Unverified, Verified { trust: Box<Trust>, name: Option<ServerName<'static>> } }
impl ResponderTrust { pub fn pinned(id: PeerId) -> ResponderTrust; }
pub fn random() -> Random;                   // the TLS provider's secure random source
pub fn pair_server_config(&Identity, &PairConfig) -> Result<ServerConfig, PeerError>;
pub fn pair_client_config(&Identity, &Pairing, &ResponderTrust, &PairConfig) -> Result<(ClientConfig, ServerName<'static>), PeerError>;
pub fn pair_dial<S: Read + Write + ReadTimeout>(S, &Identity, Pairing, &ResponderTrust, &PairConfig) -> Result<PairDial<S>, PeerError>;
impl<S> PairDial<S> { pub fn shown(&self) -> Option<&Shown>; pub fn finish(self, &TrustStore) -> Result<Paired, PeerError>; }
pub fn pair_accept<S: Read + Write + PeerAddr + ReadTimeout>(S, &Identity, &TrustStore, &PairingDesk, &PairConfig) -> Result<Paired, PeerError>;
pub fn pair_accept_from<S: Read + Write + ReadTimeout>(S, SocketAddr, &Identity, &TrustStore, &PairingDesk, &PairConfig) -> Result<Paired, PeerError>;
pub fn announce(&mut impl Write, successor: &Identity) -> Result<(), PeerError>;
pub fn receive_announcement(&mut impl Read, &TrustStore, sender: &PeerIdentity) -> Result<PeerId, PeerError>;
impl Identity { pub fn renew_before(&self, margin: Duration) -> bool; pub fn renew_before_at(&self, Duration, SystemTime) -> bool; }
// feature tokio, module asynch: pair_dial -> asynch::PairDial (shown, async finish), pair_accept,
// pair_accept_from, pair_respond(server::TlsStream<S>, Option<SocketAddr>, &Identity, &TrustStore,
// &PairingDesk, &PairConfig), announce, receive_announcement
```

**Pairing connection.** `pair_server_config` admits any client certificate whose key is proven,
under `PairConfig::alpn` only; the app's own configurations stay as strict as they are, so an
unknown certificate offering the app's ALPN is still refused. Both ends check that the pairing
ALPN was negotiated (`PeerError::Tls` otherwise), then run the exchange with both certificates as
`Channel::local`/`remote` and the exporter (`EXPORTER_LABEL`, 32 bytes, empty context) as the
binding. Messages are `coqui_peer` frames (`write_frame` / `read_frame`: a four-byte big-endian
length, at most `coqui_peer::MAX_MESSAGE`).
The connection carries only the exchange and then closes; both sides reconnect with the app's
ALPN and their stores. One port can serve both: `asynch::accept_with` choosing
`pair_server_config` when the ClientHello offers the pairing ALPN, then `asynch::pair_respond`.

**Joiner.** `pair_dial` handshakes and runs the exchange until there is something to show
(`shown()`: its PIN with the slot, or the device-flow user code) or the end; `finish` runs the rest
(for a shown code, until the operator acts at the responder), `accept_key`s the responder's
certificate in the joiner's store, and closes. The responder's certificate is checked by:
an invitation, a pin of the inviter whatever `ResponderTrust` says; a PIN, `ResponderTrust` (the
PIN authenticates the responder, so `Unverified` is enough); the device flow, `Verified` trust
(pins, a store, or roots with the host's `name`), and `Unverified` or `Trust::AnyWithKeyProof` is
`PeerError::Pairing(PairingError::Unverified)` before connecting unless
`Pairing::allow_unverified(true)`, at the cost stated in `coqui-peer`'s header. The channel
handed to the exchange is `verified` exactly when the inviter was pinned or the trust was
`Verified` with anything but `AnyWithKeyProof`.

**Responder.** `pair_accept` handshakes, then runs the responder until done: redeeming an
invitation, taking the shown PIN, or waiting for the operator through the desk. The blocking form
blocks in `PairingDesk::wait` (rechecks expiry every second on the system clock); the async form
awaits `PairingDesk::decided` and sweeps the desk every second meanwhile. On success the joiner's
certificate is accepted in the store before the joiner is told. The address of the stream is the
source the desk throttles by (`pair_accept_from` for other streams).

**Timeouts.** One side's whole exchange, its TLS handshake included, takes at most
`PairConfig::timeout` (15 minutes by default, longer than the default `device_ttl`;
`Duration::MAX` waits forever): the joiner's `pair_dial` and `finish` together, the responder's
`pair_accept` (or `asynch::pair_respond` from its call). Each responder read also waits at most
until the responder's own deadline (`PairingResponder::time_left`: `pin_ttl` or `device_ttl` from
the joiner's first message); past it the joiner is told `Expired` and its slot, code and pending
place are freed. A stalled transport ends with `PeerError::Io` (`TimedOut` or `WouldBlock`). The
blocking forms set the timeouts through `ReadTimeout`, implemented for `TcpStream`; a stream that
cannot time out implements it as a no-op and is bounded by its caller. The async forms use
`tokio::time::timeout`. A frame's buffer grows as its bytes arrive, so a declared length (at
most `coqui_peer::MAX_MESSAGE`) costs nothing until it is sent.

**What each TLS version gives.** TLS 1.3 (the strict policy): the exporter is unique to the
connection, so a relay between two connections fails the PIN confirmation. TLS 1.2 (a policy
that allows it, feature `tls12`): the exporter is unique only with the extended master secret,
which every preset requires (`Policy::require_ems`, applied to every configuration built here,
pairing's included); a policy that turns it off is reported by `weakened()`, and then the
confirmation still covers both certificates, which a relay cannot replace with its own without
failing it.

**Rotation.** A peer sends `announce(stream, &successor)` over a connection its current
certificate authenticated; the other side calls `receive_announcement(stream, store, &peer)`,
which records the successor (`TrustStore::announce_successor`; a peer that is not accepted, or
is retiring, is `PeerError::Pairing(PairingError::Local(coqui_peer::Error::NotAccepted))`). A
store-backed `Pins` then admits the successor: the verifier lets it through presentation
(after `check_pinned`'s chain and date checks), and once its handshake signature verifies,
records the proof (`prove_successor`) and promotes it (`promote_successor`), so the
predecessor retires after `RotationOptions::retire_after`. With
`RotationOptions::require_approval` the handshake is refused (`NotAccepted`) after the proof
is recorded, and the caller promotes it when it approves (`promote_successor` refuses a
successor nobody proved unless `allow_unproven`); it is not recorded as waiting. This
works both ways: a server verifying clients by its store, and a client pinning its server by
its store. `take_rotation_events` returns what happened. `Identity::renew_before(margin)` says
when the certificate ends within `margin` (an unreadable one is due).

## On-disk formats

For peers in other languages. All files are UTF-8 with LF line endings.

- **Identity file** — one PEM file: the leaf's `CERTIFICATE` block, the intermediates'
  `CERTIFICATE` blocks in order (a chained identity only), then a PKCS#8 `PRIVATE KEY` block;
  64-character base64 lines. Mode `0600` on Unix. `read` and `open_or_create` read either
  shape; `from_pem` takes the single-certificate one only.
- **Certificate id** (`PeerId`) — SHA-256 of the certificate's DER encoding. Canonical text
  `sha256:<64 lowercase hex>` (`openssl x509 -outform DER | sha256sum` gives the hex).
  Grouped base32 (RFC 4648 alphabet, no padding, 52 characters, groups of four joined by `-`)
  is a display form.
- **Trust store** — `coqui-peer`'s format (see its header): certificates are kept as
  `peers/{accepted,waiting}/<64 hex>.pem` with header lines `Method: tls` and (waiting)
  `Source: <ip>:<port>`, then one `CERTIFICATE` block whose DER hashes to the name. The store
  vectors live in that crate.
- **Vectors** — `tests/vectors/identity-{a,b}.pem` and `identity-{a,b}.fingerprint` (three
  lines: canonical, bare hex, grouped base32) are checked by `tests/vectors.rs`; the policy
  vectors under `tests/vectors/policy/` are byte-exact text forms (TOML and JSON, read in
  tests through dev-dependencies only).

## Errors

```rust
#[non_exhaustive] pub enum PeerError { InvalidId, Certificate, Tls, WeakDigest, Policy(String),
    TrustPattern, NotWaiting, AlreadyAccepted, Path, Unsupported, Pairing(pair::PairingError), Io(io::Error),
    CaFile { path: Option<PathBuf>, certificate: Option<usize>, read: Option<io::Error> } }
impl PeerError { pub fn refusal(&self) -> Option<Refusal>; pub fn pair_refusal(&self) -> Option<pair::PairRefusal>; }
#[non_exhaustive] pub enum Refusal {      // Copy, Eq, Hash, Display, std::error::Error
    NotPinned,         // matches no fixed pin
    NotAccepted,       // not accepted in the trust store (a store-backed server records it as waiting)
    NotTrusted,        // no pin, and the CA policy or the roots do not trust its chain
    ChainWhenPinned,   // a pinned peer sent a chain and allow_chain_when_pinned is false
    NameMismatch,      // the roots trust the server's chain, but not for the name dialled
    AddressDenied { rule: Option<usize> },   // the policy's ACL denies the addresses (rule index; None = default)
    PeerDenied { rule: Option<usize> },      // the policy's ACL denies the client certificate from these addresses
    AddressUnknown,    // the policy has an ACL and the source, or a local address a rule needs, is unknown
}
impl Refusal { pub fn from_rustls(error: &rustls::Error) -> Option<Refusal>; }
```

What each refusal looks like (server side unless stated; the refused side never gets a
`Refusal`, only the alert):

| Refusal | Decided | Server (`accept*`, `asynch::accept*`, `TlsHandshake::receive`) | Alert sent | Client sees |
| --- | --- | --- | --- | --- |
| `AddressDenied { rule }` | at the `ClientHello`, before any certificate | `PeerError::Io`, kind `PermissionDenied`; `refusal()` is it | `access_denied` | `PeerError::Io` with `rustls::Error::AlertReceived(AccessDenied)` |
| `AddressUnknown`, at the hello | at the `ClientHello` | as `AddressDenied` | `access_denied` | as `AddressDenied` |
| `PeerDenied { rule }` | in the client verifier, before pins, CA or store; nothing recorded as waiting | `PeerError::Io`, kind `InvalidData`, wrapping `rustls::Error::InvalidCertificate(CertificateError::Other(..))`; `refusal()` is it | `certificate_unknown` | `PeerError::Io` with `AlertReceived(CertificateUnknown)` |
| `AddressUnknown`, in a verifier | in the client verifier | as `PeerDenied` | `certificate_unknown` | as `PeerDenied` |
| `NotPinned`, `NotAccepted`, `NotTrusted`, `ChainWhenPinned` | in the verifier | as `PeerDenied` | `certificate_unknown` | as `PeerDenied` |
| `NameMismatch` (a client refusing a server) | in the client's server verifier | the client: as `PeerDenied` | `certificate_unknown` | the server: `AlertReceived(CertificateUnknown)` |
| `PeerDenied`, `AddressUnknown` with `ServerConfigs::for_connection` / `client_cert_verifier_for` (quinn) | in the verifier, from the addresses the configuration or verifier holds | the host's rustls error `InvalidCertificate(CertificateError::Other(..))`; `Refusal::from_rustls` is it, and `ConnectionConfig::refusal()` | `certificate_unknown` | as `PeerDenied` |
| `AddressDenied` with `ServerConfigs::for_connection` | at the `ClientHello`, from the configuration's addresses | rustls's own `Error::General`; `ConnectionConfig::refusal()` is it; check `Policy::admits_address` first | `access_denied` | as `AddressDenied` |
| no `Refusal`: an unusable CA or roots file | when the configuration or verifier is built, before any connection | `PeerError::CaFile { path, certificate, read }` | none | nothing |

A host driving rustls or quinn itself sees the verifier's refusals as rustls errors
(`Refusal::from_rustls` takes them out), and an address refusal at the hello as rustls's own
`Error::General` with `access_denied` sent. With `ServerConfigs::for_connection`,
`ConnectionConfig::refusal()` gives either; a host can also check `Policy::admits_address`
before the handshake, to refuse before reading a byte.

A failed handshake in `dial`, `accept` and `asynch` is `PeerError::Io` wrapping the rustls error;
`refusal()` digs the `Refusal` out of it (`TlsHandshake` errors too). Only the refusing side has
one: the refused side sees the TLS alert, so its `refusal()` is `None`. A host driving rustls
itself calls `Refusal::from_rustls`. `Display` of `PeerError` names the category only, never key
material or a path.

## Gotchas

- TLS 1.0 and 1.1 and non-AEAD suites cannot be offered; asking is `PeerError::Policy`.
- A CA policy applies to servers only, `Roots` to clients only. Pairing (waiting entries) is
  a server-side feature.
- `Roots` with `dial` (or `TlsHandshake::client`) is always refused: they send
  `SERVER_NAME`. Use the `_named` entries.
- A server-TLS server has no client verifier: no pins, no CA, no waiting entries. A client
  pinning its server works the same in both modes.
- `PeerId` equality is constant time; compare through it, not through `to_string()`.
- `PeerError`, `Refusal`, `Trust`, `TlsVersion` and `ResponderTrust` are `#[non_exhaustive]`:
  a `match` needs a `_` arm.
- With a policy ACL, a connection whose addresses the configuration cannot learn is refused
  (`Refusal::AddressUnknown`): accept through `accept`, `accept_at`, `TlsHandshake::with_local`
  or `with_addresses`, or build the configuration for the connection
  (`ServerConfigs::for_connection`). A `PeerAddr` implementation that does not override
  `local_addr` gives none.
- `client_cert_verifier_with` refuses a policy with an ACL; the configurations built here apply
  it.
- Under optional client authentication (a host verifier whose `client_auth_mandatory()` is
  false) a client is decided by address as one that proves no identity: a rule naming a
  fingerprint never admits it, even when it then presents that certificate.
- Session resumption skips the verifiers and the ACL: leave `allow_resumption` off where a peer
  or an address can lose its access.
