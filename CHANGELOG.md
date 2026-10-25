# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Tls` and `TlsHandshake` implement the sans-IO `coqui_peer::Method` and `Handshake`
  traits over rustls's own sans-IO connection. `dial`, `accept` and `asynch` are unchanged.

### Changed

- The method-independent parts moved to
  [Boriken-Dev/coqui-peer](https://github.com/Boriken-Dev/coqui-peer), which this crate now
  depends on by revision: `Fingerprint` is `coqui_peer::PeerId` (a type alias here, so pins
  and imports keep working; `Fingerprint::of_certificate` and `Digest::of_certificate` are
  `PeerId::of` and `Digest::of`), and `TrustStore`, `WaitingEntry { id, source }`,
  `WaitingLimits` and the pairing flow are the core crate's. Certificates are kept in the store
  as `KeyMaterial` under the method name `tls`; `TrustStoreExt::accept_certificate` and
  `record_waiting_certificate` take a DER certificate. The store's on-disk format is version 3
  (a `Method:` line); versions 1 and 2 still read. The certificate vectors stay here, the id
  and store vectors moved with the code.

- The crate moved out of the `coqui-access` repository into this one, with its history, and
  was renamed from `coqui-peer` to `coqui-peer-tls` (library `coqui_peer_tls`). The API is
  otherwise unchanged. Depend on this repository instead of
  [Boriken-Dev/coqui-access](https://github.com/Boriken-Dev/coqui-access):
  `coqui-peer-tls = { git = "https://github.com/Boriken-Dev/coqui-peer-tls", rev = "<commit>" }`,
  and replace `coqui_peer::` with `coqui_peer_tls::` in imports. The crate is still not
  published to crates.io.
- The optional `acl` feature takes `coqui-net-acl` from
  [Boriken-Dev/coqui-net-acl](https://github.com/Boriken-Dev/coqui-net-acl), pinned by revision.
