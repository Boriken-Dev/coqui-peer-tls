# `coqui-peer` — API header

Header-file-style reference for the `coqui-peer` crate: every public item with its signature,
contract and gotchas, so the crate can be used without reading its source. It ships inside the
package and is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/coqui-access>.

| Feature | Adds | Default |
| --- | --- | --- |
| `tls12` | rustls `tls12` (needed by `Policy::compatible()` and `legacy()`) | off |
| `generate` | `rcgen`: `Identity::generate`, `Identity::open_or_create` | off |
| `ca` | `x509-parser`, `globset`: `Trust::Ca`, `Trust::PinnedOrCa`, `CaPolicy` | off |
| `tokio` | `tokio`, `tokio-rustls`: module `asynch` | off |
| `serde` | `serde`: text form of `Policy` | off |
| `acl` | `coqui-net-acl`: `Policy::acl`, re-exported as `coqui_peer::acl` | off |

MSRV Rust 1.89. A default build depends on `rustls` (ring provider), `sha1`, `sha2`, `subtle`
and `data-encoding`. No `unsafe` code. Nothing installs a process-wide crypto provider, and
nothing reads a file or an environment variable unless the caller passes a path. TLS 1.3 is
the default; TLS 1.2 only when a policy allows it.

## Fingerprint, Digest

```rust
pub enum Digest { Sha256, Sha384, Sha512, Sha1 }
impl Digest { pub const fn name(self) -> &'static str; pub const fn size(self) -> usize;
              pub fn of_certificate(self, der: &[u8]) -> Fingerprint; }   // FromStr: "sha256", ...; "md5" is an error
pub struct Fingerprint;      // Copy, Eq (constant time), Ord, Hash, Display = canonical, FromStr
impl Fingerprint {
    pub fn of_certificate(der: &[u8]) -> Fingerprint;      // SHA-256
    pub fn from_bytes(bytes: [u8; 32]) -> Fingerprint;     // SHA-256
    pub fn digest(&self) -> Digest;  pub fn as_bytes(&self) -> &[u8];
    pub fn hex(&self) -> String;                           // 64 lowercase hex for sha256
    pub fn canonical(&self) -> String;                     // "sha256:<hex>", also Display
    pub fn to_base32_grouped(&self) -> String;             // sha256 only: 13 groups of 4, '-' separated
}
```

`FromStr` accepts `sha256:<hex>` (also `sha384:`, `sha512:`, `sha1:`), bare hex of 64, 96, 128
or 40 characters, colon-separated hex pairs (`AA:BB:...`, with or without the `sha256:`
prefix), and 52 base32 characters for SHA-256. An MD5 digest (name `md5` or 32 hex characters)
is `PeerError::WeakDigest`. Whether a policy lets a pin use a digest is a `Policy` matter.

## Identity (`Identity`, `PeerIdentity`)

```rust
pub struct Identity;                       // Clone; Debug shows only the fingerprint
impl Identity {
    pub fn from_pem(text: &str) -> Result<Identity, PeerError>;       // exactly one certificate + its key
    pub fn to_pem(&self) -> Result<String, PeerError>;                // certificate, then PKCS#8 key
    pub fn read(path: &Path) -> Result<Option<Identity>, PeerError>;  // None when absent
    pub fn write_new(&self, path: &Path) -> Result<(), PeerError>;    // never replaces; 0600; creates parents
    pub fn fingerprint(&self) -> Fingerprint;
    pub fn certificate_der(&self) -> &[u8];
    pub fn peer_identity(&self) -> PeerIdentity;
    pub fn generate() -> Result<Identity, PeerError>;                 // feature generate: ECDSA P-256, CN "coqui-peer"
    pub fn open_or_create(path: &Path) -> Result<Identity, PeerError>; // feature generate
}
pub struct PeerIdentity { pub fingerprint: Fingerprint, pub certificate: Vec<u8> }   // DER
```

## Trust (`Trust`, `Pins`, `CaPolicy`)

```rust
pub enum Trust { Pinned(Pins), Ca(CaPolicy), PinnedOrCa { pins: Pins, ca: CaPolicy }, AnyWithKeyProof }
impl Pins { pub fn fixed(impl IntoIterator<Item = Fingerprint>) -> Pins; pub fn store(TrustStore) -> Pins;
            pub fn matches(&self, der: &[u8]) -> bool; }
pub struct CaPolicy { pub ca_file: PathBuf, pub subject: Vec<String>, pub san: Vec<String> }  // feature ca
impl Trust {
    pub fn client_cert_verifier(&self) -> Result<Arc<PeerClientVerifier>, PeerError>;           // strict policy
    pub fn client_cert_verifier_with(&self, &Policy) -> Result<Arc<PeerClientVerifier>, PeerError>;
    pub fn server_cert_verifier(&self) -> Result<Arc<PeerServerVerifier>, PeerError>;
    pub fn server_cert_verifier_with(&self, &Policy) -> Result<Arc<PeerServerVerifier>, PeerError>;
}
```

`PeerClientVerifier` implements rustls `ClientCertVerifier`, `PeerServerVerifier` implements
`ServerCertVerifier`; hand them to any rustls-based stack. Every policy requires the peer to
prove its key. Names are not checked on the pinned path.

- A fixed pin matches by hashing the certificate with the pin's digest; every pin is compared
  in constant time. A store holds SHA-256 pins.
- After a pin matches: no intermediates unless `allow_chain_when_pinned`, then validity dates
  unless `check_validity` is false. The pin check comes first; certificates are parsed only
  after.
- `Ca` and `PinnedOrCa` apply to servers (client certificates); `server_cert_verifier*`
  returns `PeerError::Unsupported` for them. CA trust checks the chain and the globs.
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
  Caps are per source IP address; the full `SocketAddr` is stored.
- A pin whose digest the policy does not list is `PeerError::Policy` when the verifier is built.

## TrustStore

```rust
pub struct TrustStore;                     // Clone
pub struct WaitingLimits { pub per_source: usize, pub total: usize, pub rerecord: Duration }   // Default: 16, 1000, 60 s
impl TrustStore {
    pub fn open(state_dir: &Path) -> Result<TrustStore, PeerError>;     // creates <state_dir>/peers/{accepted,waiting}
    pub fn with_limits(self, limits: WaitingLimits) -> TrustStore;
    pub fn waiting(&self) -> Result<Vec<WaitingEntry>, PeerError>;   // WaitingEntry { fingerprint, source: Option<SocketAddr> }
    pub fn accepted(&self) -> Result<Vec<Fingerprint>, PeerError>;
    pub fn accept(&self, fingerprint: &Fingerprint) -> Result<(), PeerError>;   // waiting -> accepted
    pub fn accept_certificate(&self, der: &[u8]) -> Result<Fingerprint, PeerError>;
    pub fn remove(&self, fingerprint: &Fingerprint) -> Result<bool, PeerError>;
    pub fn is_accepted(&self, fingerprint: &Fingerprint) -> bool;
    pub fn record_waiting(&self, der: &[u8], fingerprint: &Fingerprint, source: Option<SocketAddr>);
}
```

`accept` checks that the stored certificate hashes to its file name
(`NotWaiting`, `AlreadyAccepted`, `Certificate`). `record_waiting` is bounded: at most
`per_source` entries per source (the oldest of that source is replaced), the same certificate
from the same source at most every `rerecord`, `total` in all, certificates over 64 KiB
ignored. Callers that pass `source: None` share one bucket.

## Policy

```rust
pub struct Policy {
    pub name: String,                          // informational; "strict", "compatible", "legacy" or your own
    pub tls_versions: Vec<TlsVersion>,         // V1_2, V1_3
    pub cipher_suites: Option<Vec<String>>,    // IANA names; None = all for the versions
    pub kx_groups: Option<Vec<String>>,        // e.g. "X25519"; None = all
    pub pin_digests: Vec<Digest>,
    pub check_validity: bool,
    pub allow_chain_when_pinned: bool,
    pub waiting_per_source: usize, pub waiting_total: usize, pub waiting_rerecord_secs: u64,
    pub acl: Option<coqui_net_acl::Acl>,       // feature acl
}
impl Default for Policy { /* Policy::strict() */ }
impl Policy {
    pub fn strict() -> Policy;  pub fn compatible() -> Policy;  pub fn legacy() -> Policy;
    pub fn preset(name: &str) -> Result<Policy, PeerError>;
    pub fn weakened(&self) -> Vec<Weakening>;
    pub fn weakened_against(&self, baseline: &Policy) -> Vec<Weakening>;
    pub fn check_pin(&self, fingerprint: &Fingerprint) -> Result<(), PeerError>;
    pub fn waiting_limits(&self) -> WaitingLimits;
    pub fn crypto_provider(&self) -> Result<Arc<CryptoProvider>, PeerError>;
    pub fn supported_cipher_suites() -> Vec<String>;
    pub fn supported_kx_groups() -> Vec<String>;
    pub fn deserialize_over<'de, D: Deserializer<'de>>(base: Policy, d: D) -> Result<Policy, D::Error>;  // feature serde
}
pub struct Weakening { pub setting: String, pub value: String, pub strict: String }
pub const POLICY_VERSION: u32 = 1;
```

| Field | strict | compatible | legacy |
| --- | --- | --- | --- |
| `tls_versions` | 1.3 | 1.2, 1.3 | 1.2, 1.3 |
| `pin_digests` | sha256, sha384, sha512 | same | plus sha1 |
| `check_validity` | true | true | true |
| `allow_chain_when_pinned` | false | false | false |
| `waiting_per_source`, `waiting_total`, `waiting_rerecord_secs` | 16, 1000, 60 | same | same |
| `cipher_suites`, `kx_groups`, `acl` | none | none | none |

`crypto_provider` narrows the ring provider to the policy's versions, suites and groups; an
unknown name, or a version left with no suite, is `PeerError::Policy` whose message lists the
supported names. `weakened` reports `tls_versions` including 1.2, `pin_digests` beyond
sha256/384/512, `check_validity` false, `allow_chain_when_pinned` true, larger waiting caps or
a shorter rerecord time, and an ACL with a `permit` default.

### Text form, version 1 (feature `serde`)

TOML or JSON object. Keys: `policy_version` (must be 1 when present), `profile` (a built-in
preset name to start from; unknown names are errors; free text when read with
`deserialize_over`), `tls_versions` (`"1.2"`, `"1.3"`), `cipher_suites`, `kx_groups`,
`pin_digests` (`"sha256"`, `"sha384"`, `"sha512"`, `"sha1"`), `check_validity`,
`allow_chain_when_pinned`, `waiting_per_source`, `waiting_total`, `waiting_rerecord_secs`, and
`acl` (see `coqui-net-acl`). Unknown keys are errors; absent keys keep the preset. Writing
always names every field. `tests/vectors/policy/{strict,compatible,legacy,acl}.{toml,json}`
are byte-exact.

## Configurations and streams

```rust
pub struct Built<T> { pub config: T, pub weakened: Vec<Weakening> }
pub fn client_config(&Identity, &Trust, alpn: &[&[u8]]) -> Result<ClientConfig, PeerError>;
pub fn server_config(&Identity, &Trust, alpn: &[&[u8]]) -> Result<ServerConfig, PeerError>;
pub fn client_config_with(&Identity, &Trust, &[&[u8]], &Policy) -> Result<Built<ClientConfig>, PeerError>;
pub fn server_config_with(&Identity, &Trust, &[&[u8]], &Policy) -> Result<Built<ServerConfig>, PeerError>;
pub fn crypto_provider() -> Arc<CryptoProvider>;       // default ring provider
pub const SERVER_NAME: &str = "coqui-peer.invalid";
pub fn dial<S: Read + Write>(Arc<ClientConfig>, S) -> Result<(StreamOwned<ClientConnection, S>, PeerIdentity), PeerError>;
pub fn accept<S: Read + Write + PeerAddr>(Arc<ServerConfig>, S) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError>;
pub fn accept_from<S: Read + Write>(Arc<ServerConfig>, S, source: SocketAddr) -> Result<(StreamOwned<ServerConnection, S>, PeerIdentity), PeerError>;
pub trait PeerAddr { fn peer_addr(&self) -> Option<SocketAddr>; }   // std and tokio TcpStream
pub fn with_source<R>(Option<SocketAddr>, impl FnOnce() -> R) -> R;
// feature tokio, module asynch:
pub async fn dial<S>(Arc<ClientConfig>, S) -> Result<(client::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept<S: PeerAddr>(Arc<ServerConfig>, S) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept_from<S>(Arc<ServerConfig>, S, SocketAddr) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept_with_from<S>(S, SocketAddr, select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
pub async fn accept_with<S: PeerAddr>(S, select: impl FnOnce(&ClientHello<'_>) -> Arc<ServerConfig>) -> Result<(server::TlsStream<S>, PeerIdentity), PeerError>;
```

Both complete the handshake before returning, so a refused certificate is an error and the
returned `PeerIdentity` is verified. The server name sent is `SERVER_NAME`; trust is by
fingerprint, never by name. `accept_with` chooses the server configuration from the
ClientHello, for example by ALPN, so one port serves peers and other clients.

## Errors

`PeerError` (non-exhaustive): `InvalidFingerprint`, `WeakDigest` (MD5), `Certificate`, `Tls`,
`Policy(String)`, `TrustPattern`, `NotWaiting`, `AlreadyAccepted`, `Path`, `Unsupported`,
`Io(io::Error)`. `Display` never includes key material or paths.

## On-disk formats (version 2)

For peers in other languages. All files are UTF-8 with LF line endings.

- **Identity file** — one PEM file: a `CERTIFICATE` block, then a PKCS#8 `PRIVATE KEY` block;
  exactly one certificate (a chain is refused); 64-character base64 lines. Mode `0600`.
- **Fingerprint** — SHA-256 of the certificate's DER encoding. Canonical text
  `sha256:<64 lowercase hex>` (`openssl x509 -outform DER | sha256sum` gives the hex).
  Grouped base32 (RFC 4648 alphabet, no padding, 52 characters, groups of four joined by `-`)
  is a display form.
- **Trust store** — under `<state_dir>/peers/`: `accepted/<64 lowercase hex>.pem` and
  `waiting/<64 lowercase hex>.pem`, each one `CERTIFICATE` block whose DER hashes to the name.
  A waiting file may start with one line `Source: <ip>:<port>` (IPv6 as `[addr]:port`), the
  address the handshake came from; version 1 files have none and read with no source.
  `:` is not valid in Windows file names, so the name has no `sha256:` prefix. File names in
  the grouped base32 spelling are also read. Accepting moves a file from `waiting` to
  `accepted`, rewritten as the bare certificate block.
- **Vectors** — `tests/vectors/identity-{a,b}.pem`, `identity-{a,b}.fingerprint` (three lines:
  canonical, bare hex, grouped base32) and `tests/vectors/store/peers/...` are checked by
  `tests/vectors.rs`; other implementations can check against the same bytes.

Format changes bump a version and the changelog; version 1 files stay readable (the text form of `Policy` is still version 1).

## Gotchas

- TLS 1.0 and 1.1 and non-AEAD suites cannot be offered; asking is `PeerError::Policy`.
- A CA policy applies to servers only. Pairing (waiting entries) is a server-side feature.
- `Fingerprint` equality is constant time; compare through it, not through `to_string()`.
