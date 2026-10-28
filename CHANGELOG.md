# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `ServerConfigs` and `ConnectionConfig`: server configurations built per connection from one
  listener's identity, ALPN list and policy (`new`, `with_verifier`, `without_client_auth`,
  then `for_connection(source, local)`), for hosts such as quinn that take a configuration per
  incoming connection. Waiting entries are recorded under the connection's source, the policy's
  access control list is decided from its addresses with no thread-local scope, every
  configuration of one `ServerConfigs` shares a session cache and ticketer (with
  `allow_resumption` a client resumes across connections), and `ConnectionConfig::refusal`
  gives the typed `Refusal` the handshake ended with, which quinn reports only as an alert.

### Removed

- `server_config_for`: use `ServerConfigs::new(identity, trust, alpn, policy)?
  .for_connection(source, local)?.config()`.

### Fixed

- A server configuration around a host verifier whose client authentication is optional
  (`client_auth_mandatory()` false) let a client that sent no certificate through an access
  control list whose rule names a fingerprint: the address check deferred to a certificate
  check that never ran. Such a configuration now decides by address as for a client that proves
  no identity, so a fingerprint rule never admits a client there.

## [0.0.0-alpha.0] - 2026-10-27

The first pre-release, published to crates.io after `coqui-net-acl` and `coqui-peer`
`0.0.0-alpha.0`. The API may change in any release before 1.0.

### Added

- The TLS method of [coqui-peer](https://crates.io/crates/coqui-peer): mutual-TLS peer
  identity over rustls (0.23.27 or later, ring provider passed explicitly; nothing installs a
  process-wide provider). A certificate's id is the core crate's `PeerId`.
- `Identity`: certificate and key as one PEM file (`from_pem`, `read`, `write_new`, `to_pem`),
  CA-issued leaves with intermediates (`from_pem_chain`, `intermediates_der`; `read` and
  `open_or_create` read a chained file), the chain and the key for hosts building their own
  configurations (`certificate_chain`, `private_key_der`, whose `Debug` elides the key), and,
  with `generate`, self-signed ECDSA P-256 identities (`generate`, `generate_valid_for`,
  `generate_with`, `open_or_create`) carrying a subjectAltName `SERVER_NAME`, a
  subjectKeyIdentifier and basicConstraints `CA:FALSE`. Identity files are written owner-only
  with coqui-peer's atomic no-replace write; concurrent `open_or_create` calls agree on one
  identity.
- `Trust`: `Pinned` (fixed pins or a `TrustStore`), `Ca` and `PinnedOrCa` (feature `ca`) for
  client certificates, `Roots` and `PinnedOrRoots` (web PKI, with `Roots::bundle_pem`,
  `bundle_file` and, with `platform-roots`, `platform`) for servers, and `AnyWithKeyProof`;
  `PeerClientVerifier` and `PeerServerVerifier` as rustls verifiers for other stacks, and
  `Trust::client_cert_verifier_for`, a verifier for one connection's addresses. A store-backed
  server records an untrusted client as waiting only after its handshake signature verified.
  Certificates are kept in the store as `KeyMaterial` with method `tls` (`certificate_key`,
  `TrustStoreExt`). An unusable CA or roots file is `PeerError::CaFile`, naming the file and the
  certificate.
- `Refusal` (`NotPinned`, `NotAccepted`, `NotTrusted`, `ChainWhenPinned`, `NameMismatch`,
  `AddressDenied`, `PeerDenied`, `AddressUnknown`), read back with `Refusal::from_rustls` and
  `PeerError::refusal`.
- `Policy` with the `strict` (default), `compatible` and `legacy` presets: TLS versions, cipher
  suites, key-exchange groups, pin digests, validity checks, chains on the pinned path,
  session resumption (off in every preset), the extended master secret for TLS 1.2 (required in
  every preset), the waiting queue's limits (`waiting: WaitingLimits`) and, with `acl`, an
  access control list from `coqui-net-acl`. `weakened()` lists every setting looser than
  strict, as coqui-peer's `Weakening`. With `serde`, a text form (`policy_version` 1) in the
  format the consumer picks. Errors name the setting and list what is supported without
  quoting the input.
- The policy's access control list is applied by every server configuration: by address at the
  `ClientHello`, and by the client certificate's fingerprint before the trust store is
  consulted; rule fingerprints in any `PeerId` spelling are made canonical.
  `Policy::admits_address` and `admits_anonymous` decide by address before a handshake.
- Configurations with ALPN as a parameter: `client_config[_with]`, `server_config[_with]`,
  around a verifier of the host's own (`server_config_with_verifier`,
  `client_config_with_verifier`), for one connection's addresses (`server_config_for`), and
  server TLS where only the server presents a certificate
  (`server_config_without_client_auth[_with]`, `client_config_without_identity[_with]`,
  `TlsHandshake::finish_unauthenticated`).
- Blocking `dial`, `dial_named`, `accept`, `accept_from`, `accept_at` and, with `tokio`, their
  `asynch` forms plus `accept_with` (configuration chosen from the ClientHello);
  `with_source` and `with_addresses` for hosts that drive rustls themselves; `PeerAddr` with
  the local address; `default_server_name()`.
- `Tls` and `TlsHandshake` (`with_local`): the sans-IO `coqui_peer::Method` and `Handshake`
  over rustls's own sans-IO connection.
- Pairing over TLS: `pair_dial` (two steps: `PairDial::shown`, then `finish`), `pair_accept`,
  `pair_accept_from` and, with `tokio`, their `asynch` forms plus `asynch::pair_respond`;
  `pair_server_config`, `pair_client_config`, `PairConfig` (the device's `Policy`, the pairing
  ALPN, a timeout of 15 minutes by default), `ResponderTrust`, the exporter binding
  (`EXPORTER_LABEL`) and `random()`. Messages are coqui-peer frames; blocking pairing takes a
  `ReadTimeout` stream (coqui-peer's trait, implemented for `TcpStream`). PIN pairing needs the
  `pin` feature. The exchange, the desk and the options are `coqui-peer`'s, re-exported as
  `pair`.
- Key rotation: `announce`, `receive_announcement` and their `asynch` forms; store-backed `Pins`
  admit a pending successor and promote it once its handshake signature verifies (or refuse it
  until approved under `RotationOptions::require_approval`); `Identity::renew_before`.

[Unreleased]: https://github.com/Boriken-Dev/coqui-peer-tls/compare/v0.0.0-alpha.0...HEAD
[0.0.0-alpha.0]: https://github.com/Boriken-Dev/coqui-peer-tls/releases/tag/v0.0.0-alpha.0
