# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The crate moved out of the `coqui-access` repository into this one, with its history, and
  was renamed from `coqui-peer` to `coqui-peer-tls` (library `coqui_peer_tls`). The API is
  otherwise unchanged. Depend on this repository instead of
  [Boriken-Dev/coqui-access](https://github.com/Boriken-Dev/coqui-access):
  `coqui-peer-tls = { git = "https://github.com/Boriken-Dev/coqui-peer-tls", rev = "<commit>" }`,
  and replace `coqui_peer::` with `coqui_peer_tls::` in imports. The crate is still not
  published to crates.io.
- The optional `acl` feature takes `coqui-net-acl` from
  [Boriken-Dev/coqui-net-acl](https://github.com/Boriken-Dev/coqui-net-acl), pinned by revision.
