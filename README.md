# coqui-peer-tls

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-peer-tls/rust/coqui_peer_tls/index.html)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-peer-tls/test.yml)](https://github.com/Boriken-Dev/coqui-peer-tls/actions/workflows/test.yml)

**Mutual-TLS identity between peers, with no RPC layer.** Each side has a self-issued
certificate and tells the other only its fingerprint. You get back an authenticated, encrypted
byte stream and the verified peer identity; nothing is installed process-wide, and nothing is
read from a file or the environment unless you give it a path. This is the TLS method of
[`coqui-peer`](https://github.com/Boriken-Dev/coqui-peer), which holds the peer id, the trust
store and the sans-IO handshake trait; this crate adds X.509 and rustls on top. See the
[documentation](https://boriken-dev.github.io/coqui-peer-tls/).

## Features

- **Fingerprints** — `Fingerprint` is the `PeerId` of `coqui-peer`: SHA-256 of the
  certificate, written `sha256:<hex>`; grouped base32 for screens; SHA-384, SHA-512 and
  (legacy) SHA-1 pins can be read.
- **Trust you choose** — pinned fingerprints, a CA with subject and SAN globs, both, or any
  certificate whose key the peer proves.
- **Pairing** — a peer that proves its key and is not trusted is recorded as waiting in the
  `coqui-peer` `TrustStore` (certificates are kept under the method name `tls`); an operator
  accepts it by fingerprint.
- **Policy** — strict by default (TLS 1.3 only), with `compatible` and `legacy` presets and
  fields you can change; a policy is a plain value you can build, name and store.
- **Verifiers as values** — hand the rustls verifiers to another TLS stack.
- **A `coqui-peer` method** — `Tls` and `TlsHandshake` implement the sans-IO `Method` and
  `Handshake` traits, so the same TLS runs over message transports (WebSocket messages,
  datagrams on a reliable channel) with the core crate's drivers.
- **Streams** — blocking `dial`/`accept` over any `Read + Write`; async over any
  `AsyncRead + AsyncWrite` with `tokio`. `accept` reads the peer address from a TCP stream;
  other streams use `accept_from`.
- **Server TLS** — `server_config_without_client_auth` and `client_config_without_identity`:
  the server proves itself by certificate, the client presents none and is authenticated by
  your application inside the channel (browsers over `wss://` and WebTransport, hosts without
  an identity). The server's `weakened` list says so (`client_auth = none`), and
  `TlsHandshake::finish_unauthenticated` finishes its handshake with no peer certificate.
- **Web PKI and WebTransport identities** — `Identity::from_pem_chain` presents a CA-issued
  leaf with its intermediates; `Identity::generate_valid_for` makes a short-lived
  certificate for WebTransport's `serverCertificateHashes` (at most 14 days there).

## Installation

```bash
cargo add coqui-peer-tls --git https://github.com/Boriken-Dev/coqui-peer-tls
```

| Feature | Adds | Needed for |
| --- | --- | --- |
| `tls12` | rustls `tls12` | the `compatible` and `legacy` presets |
| `generate` | `rcgen`, `time` | `Identity::generate`, `generate_valid_for`, `generate_with`, `open_or_create` |
| `ca` | `x509-parser`, `globset` | `Trust::Ca`, `Trust::PinnedOrCa` |
| `tokio` | `tokio`, `tokio-rustls` | `asynch::dial`, `accept`, `accept_from`, `accept_with`, `accept_with_from` |
| `serde` | `serde`, `coqui-peer/serde` | reading and writing a `Policy` and `Fingerprint` as text, in the format you choose |
| `acl` | `coqui-net-acl` | an access control list inside a `Policy` |

## Quick start

```rust,ignore
use std::sync::Arc;
use coqui_peer_tls::{Identity, Pins, Trust, client_config, dial, server_config, accept};

let me = Identity::open_or_create(path)?;                 // `generate` feature
let trust = Trust::Pinned(Pins::fixed(["sha256:3f15...".parse()?]));
let config = client_config(&me, &trust, &[b"my-protocol/1"])?;   // strict: TLS 1.3 only
let (stream, peer) = dial(Arc::new(config), tcp_stream)?;        // peer.fingerprint
```

## Profiles and policy

`Policy::default()` is strict and works as it is. `Policy::strict()`, `compatible()` and
`legacy()` are constructors for plain values; start from one, or from a policy of your own,
and change any public field. `weakened()` lists, as data, every setting looser than strict
(`weakened_against(&baseline)` compares with a baseline you choose); `client_config_with` and
`server_config_with` return that list beside the configuration, and
`server_config_without_client_auth_with` adds `client_auth = none` to it. Nothing is printed.

| Field | `strict` | `compatible` | `legacy` |
| --- | --- | --- | --- |
| `tls_versions` | `1.3` | `1.2`, `1.3` | `1.2`, `1.3` |
| `cipher_suites` | all the provider has for those versions | same | same |
| `kx_groups` | all | all | all |
| `pin_digests` | sha256, sha384, sha512 | same | plus sha1 |
| `check_validity` | true | true | true |
| `allow_chain_when_pinned` | false | false | false |
| `allow_resumption` | false | false | false |
| `waiting_per_source` / `waiting_total` / `waiting_rerecord_secs` | 16 / 1000 / 60 | same | same |
| `acl` | none | none | none |

Session resumption is off in every preset: rustls does not check the peer's certificate again
on a resumed session, so a peer removed from the trust store could reconnect on a session it
held. `allow_resumption = true` turns it back on and is reported by `weakened()`.

rustls offers TLS 1.2 and 1.3 only. TLS 1.0, 1.1 and non-AEAD suites cannot be offered by
this crate, and asking for them is an error that lists what is supported. MD5 pins are never
accepted. Cipher suites are chosen by IANA name from `Policy::supported_cipher_suites()`.

Build a policy in code first; this is the whole API:

```rust,ignore
let mut policy = Policy::compatible();
policy.pin_digests.push(Digest::Sha1);
policy.waiting_per_source = 4;
let built = server_config_with(&identity, &trust, &[b"my-protocol/1"], &policy)?;
for weaker in &built.weakened { log::warn!("{} = {}", weaker.setting, weaker.value); }
```

With the `serde` feature a `Policy` also reads and writes a versioned text form (version 1).
The crate parses no format itself: enable `serde` and call your own `toml::from_str` or
`serde_json::from_str`. The fields are:

```toml
policy_version = 1
profile = "compatible"          # a built-in preset to start from; a name only for your own
tls_versions = ["1.2", "1.3"]
cipher_suites = ["TLS13_AES_256_GCM_SHA384"]   # optional
kx_groups = ["X25519"]                          # optional
pin_digests = ["sha256", "sha384", "sha512"]
check_validity = true
allow_chain_when_pinned = false
allow_resumption = false
waiting_per_source = 16
waiting_total = 1000
waiting_rerecord_secs = 60

[acl]                           # optional, with the `acl` feature; see coqui-net-acl
default = "deny"

[[acl.rule]]
action = "permit"
source = "10.9.0.0/16"
destination = "10.6.20.5"
```

Every key is optional; absent keys keep the preset. `Policy::deserialize_over(base, d)` reads
a document over your own base policy. Committed examples for every preset are in
`tests/vectors/policy/`.

## API overview

| Item | Purpose |
| --- | --- |
| `Identity`, `PeerIdentity` | This side's certificate and key; the verified other side. |
| `Fingerprint`, `Digest` | Certificate hashes and their text forms. |
| `Trust`, `Pins`, `CaPolicy` | Whom to trust. |
| `PeerClientVerifier`, `PeerServerVerifier` | The rustls verifiers as values. |
| `Refusal`, `PeerError::refusal` | Why this side refused a peer's certificate, as a value. |
| `TrustStore`, `WaitingLimits` | Accepted and waiting peers as files. |
| `Policy`, `Weakening` | What is allowed, and what is looser than strict. |
| `client_config(_with)`, `server_config(_with)`, `Built` | TLS configurations, ALPN as a parameter. |
| `dial`, `accept`, `asynch::*` | Encrypted streams plus the peer. |

## Limits and future work

- A waiting entry is recorded only after the peer proves it holds the certificate's key, with
  pins alone or beside a CA policy. Each entry stores the address the handshake came from:
  `accept` takes it from a TCP stream, `accept_from` takes it for any other stream, and the
  per-source caps (`waiting_per_source`, `waiting_rerecord_secs`) apply per IPv4 address or
  per IPv6 /64 (`TrustStore::with_ipv6_prefix`).
- Not provided: a handshake probe (`Unknown | Online | Rejected | Offline`), a helper for
  reading and writing one connection from two threads, and QUIC with datagrams.
- `coqui-net-acl` is its own crate, not part of this one: it needs no TLS and is used on
  plaintext listeners too. Evaluate it at accept time and again with `decide_peer` after
  `accept` returns the fingerprint.

## Development

```bash
cargo fmt --all --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/LICENSE).
