# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


### Added

- The TLS method of [coqui-peer](https://github.com/Boriken-Dev/coqui-peer): mutual-TLS peer
  identity over rustls (0.23.27 or later, ring provider passed explicitly; nothing installs a
  process-wide provider). A certificate's id is the core crate's `PeerId`.
- `Identity`: certificate and key as one PEM file (`from_pem`, `read`, `write_new`, `to_pem`),
  CA-issued leaves with intermediates (`from_pem_chain`, `intermediates_der`), and, with
  `generate`, self-signed ECDSA P-256 identities (`generate`, `generate_valid_for`,
  `generate_with`, `open_or_create`) carrying a subjectAltName `SERVER_NAME`, a
  subjectKeyIdentifier and basicConstraints `CA:FALSE`.
- `Trust`: `Pinned` (fixed pins or a `TrustStore`), `Ca` and `PinnedOrCa` (feature `ca`) for
  client certificates, `Roots` and `PinnedOrRoots` (web PKI, with `Roots::bundle_pem`,
  `bundle_file` and, with `platform-roots`, `platform`) for servers, and `AnyWithKeyProof`;
  `PeerClientVerifier` and `PeerServerVerifier` as rustls verifiers for other stacks. A
  store-backed server records an untrusted client as waiting only after its handshake
  signature verified. Certificates are kept in the store as `KeyMaterial` with method `tls`
  (`certificate_key`, `TrustStoreExt`).
- `Refusal` (`NotPinned`, `NotAccepted`, `NotTrusted`, `ChainWhenPinned`, `NameMismatch`), sent
  as `certificate_unknown` and read back with `Refusal::from_rustls` and `PeerError::refusal`.
- `Policy` with the `strict` (default), `compatible` and `legacy` presets: TLS versions, cipher
  suites, key-exchange groups, pin digests, validity checks, chains on the pinned path,
  session resumption (off in every preset), waiting limits and, with `acl`, an access list
  from `coqui-net-acl`. `weakened()` lists every setting looser than strict. With `serde`, a
  text form (`policy_version` 1) in the format the consumer picks.
- Configurations with ALPN as a parameter: `client_config[_with]`, `server_config[_with]`, and
  server TLS where only the server presents a certificate
  (`server_config_without_client_auth[_with]`, `client_config_without_identity[_with]`,
  `TlsHandshake::finish_unauthenticated`).
- Blocking `dial`, `dial_named`, `accept`, `accept_from` and, with `tokio`, their `asynch`
  forms plus `accept_with` (configuration chosen from the ClientHello); `with_source` for
  hosts that drive rustls themselves.
- `Tls` and `TlsHandshake`: the sans-IO `coqui_peer::Method` and `Handshake` over rustls's own
  sans-IO connection.

Depend on this repository by revision:
`coqui-peer-tls = { git = "https://github.com/Boriken-Dev/coqui-peer-tls", rev = "<commit>" }`.
The crate is not published to crates.io.
