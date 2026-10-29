# coqui-peer-tls

[![Version](https://img.shields.io/crates/v/coqui-peer-tls.svg)](https://crates.io/crates/coqui-peer-tls)
[![Rust version](https://img.shields.io/crates/msrv/coqui-peer-tls.svg)](https://crates.io/crates/coqui-peer-tls)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/LICENSE)
[![Docs](https://img.shields.io/docsrs/coqui-peer-tls)](https://docs.rs/coqui-peer-tls)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-peer-tls/test.yml)](https://github.com/Boriken-Dev/coqui-peer-tls/actions/workflows/test.yml)

**Mutual-TLS identity between peers, with no RPC layer.** Each side has a self-issued
certificate and tells the other only its fingerprint; you get back an authenticated, encrypted
byte stream and the verified peer. This is the TLS method of
[`coqui-peer`](https://crates.io/crates/coqui-peer), which holds the peer id, the trust store
and the sans-IO handshake trait; this crate adds X.509 and rustls. See the
[documentation](https://boriken-dev.github.io/coqui-peer-tls/).

> **Status: alpha.** `0.0.0-alpha.0` is a pre-release: the API may change in any release
> before 1.0.

## Features

- **Certificate ids**: a certificate's id is `coqui-peer`'s `PeerId`, the SHA-256 of the
  certificate, written `sha256:<hex>`; SHA-384, SHA-512 and SHA-1 pins can be read.
- **Trust you choose**: pinned fingerprints, a CA with subject and SAN globs, both, or any
  certificate whose key the peer proves; a client can verify a server by the web PKI, with a
  CA bundle or the operating system's verifier, alone or beside pins.
- **Pairing**: an untrusted peer that proves its key is recorded as waiting in the trust store,
  and an operator accepts it by fingerprint; or two devices pair by an invitation, a PIN or a
  device flow on a connection of their own, bound to it by the TLS exporter.
- **Key rotation**: a peer announces its successor certificate; store-backed pins promote it
  once proven and retire the old one after a window you choose.
- **Policy**: `intermediate` by default (TLS 1.2 and 1.3), with `modern` (TLS 1.3 only) and
  `legacy` presets; settings looser than the default are reported as data, never refused. A policy can carry an access control list,
  applied by address at the `ClientHello` and by fingerprint before the trust store.
- **Your own stack**: the rustls verifiers as values, configurations around a verifier of your
  own, per-connection configurations for quinn, and the identity's chain and key.
- **Streams**: blocking `dial` and `accept` over any `Read + Write`, async ones over tokio; the
  sans-IO `coqui-peer` method for message transports.
- **Server TLS**: the server proves itself by certificate and the client authenticates inside
  the channel (browsers over `wss://` and WebTransport); short-lived identities for
  WebTransport's `serverCertificateHashes`.
- Nothing installs a process-wide crypto provider, and nothing reads a file or the environment
  unless you give it a path.

## Installation

```bash
cargo add coqui-peer-tls@0.0.0-alpha.0
```

| Feature | Adds | Needed for | Default |
| --- | --- | --- | --- |
| `generate` | `rcgen`, `time` | `Identity::generate`, `generate_valid_for`, `generate_with`, `open_or_create` | off |
| `ca` | `x509-parser`, `globset` | `Trust::Ca`, `Trust::PinnedOrCa`, `CaPolicy` | off |
| `tokio` | `tokio`, `tokio-rustls`, `coqui-peer/tokio` | module `asynch`: async dial, accept, pairing and rotation | off |
| `pin` | `coqui-peer/pin` | PIN pairing | off |
| `serde` | `serde`, `coqui-peer/serde`, `coqui-net-acl/serde` | reading and writing a `Policy` and `PeerId` as text | off |
| `acl` | `coqui-net-acl` | an access control list inside a `Policy` | off |
| `platform-roots` | `rustls-platform-verifier` | `Roots::platform`: servers verified by the operating system | off |
| `aws-lc` | rustls's aws-lc-rs provider (AWS-LC, built from C) | `crypto = "aws-lc"`: ML-KEM key exchange, ML-DSA, the `cnsa-2.0` profile | off |
| `fips` | `aws-lc` and rustls's `fips` (AWS-LC's FIPS module) | the `fips-140-3-validated` profile; global, see Development | off |

Rust 1.89 or later. A default build depends on `coqui-peer`, `rustls` (0.23.27 or later, ring
provider) and `rustls-webpki`, which rustls already uses.

## Quick start

Dial a peer you pinned, with an identity read from a file:

```rust,no_run
use std::sync::Arc;
use coqui_peer_tls::{Identity, Pins, Trust, client_config, dial};

let me = Identity::read("identity.pem".as_ref())?.expect("an identity file");
let trust = Trust::Pinned(Pins::fixed([
    "sha256:630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd".parse()?,
]));
let config = client_config(&me, &trust, &[b"my-protocol/1"])?; // default: TLS 1.2 and 1.3
let socket = std::net::TcpStream::connect("192.0.2.7:7000")?;
let (stream, peer) = dial(Arc::new(config), socket)?;
println!("connected to {}", peer.fingerprint);
# drop(stream);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Dial a server with a CA-issued certificate, verified by the web PKI for its name:

```rust,no_run
use std::sync::Arc;
use coqui_peer_tls::{Roots, Trust, client_config_without_identity, dial_named};
use rustls::pki_types::ServerName;

let trust = Trust::Roots(Roots::bundle_file("/etc/ssl/certs/ca-certificates.crt"));
let config = client_config_without_identity(&trust, &[b"my-protocol/1"])?;
let name = ServerName::try_from("example.com")?.to_owned();
let socket = std::net::TcpStream::connect("example.com:443")?;
let (stream, server) = dial_named(Arc::new(config), name, socket)?;
# drop((stream, server));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Roots are a different trust model from pins: any server one of the roots issued a certificate
for the dialled name is trusted. The chain, the dates and the name are always checked.

## API overview

| Module | Purpose |
| --- | --- |
| `coqui_peer_tls` | `Identity`, `PeerIdentity`; `Trust`, `Pins`, `CaPolicy`, `Roots` and their verifiers; `Policy`; the configuration builders, `Built`, and `ServerConfigs` / `ConnectionConfig` for a configuration per connection; `dial`, `accept` and their variants; `Tls` and `TlsHandshake`; pairing over TLS; rotation; `PeerError`, `Refusal`; re-exports of `coqui-peer`'s ids, store and `Weakening`. |
| `coqui_peer_tls::asynch` | Async dial, accept, pairing and rotation over tokio (`tokio`). |
| `coqui_peer_tls::pair` | `coqui-peer`'s pairing exchange, re-exported. |
| `coqui_peer_tls::acl` | `coqui-net-acl`, re-exported (`acl`). |

## Profiles and policy

`Policy::default()` is `intermediate` and works as it is. `Policy::modern()`, `intermediate()`
and `legacy()` are plain values; start from one and change any public field. `weakened()` lists
every setting looser than the default, as data; `client_config_with` and `server_config_with`
return that list beside the configuration. Nothing is printed.

| Field | `modern` | `intermediate` (default) | `legacy` |
| --- | --- | --- | --- |
| `tls_versions` | `1.3` | `1.2`, `1.3` | `1.2`, `1.3` |
| `cipher_suites`, `kx_groups` | all the provider has | same | same |
| `pin_digests` | sha256, sha384, sha512 | same | plus sha1 |
| `check_validity` | true | true | true |
| `allow_chain_when_pinned` | false | false | false |
| `allow_resumption` | false | false | false |
| `require_ems` | true | true | false |
| `waiting` (`per_source` / `total` / `rerecord`) | 16 / 1000 / 60 s | same | same |
| `acl` | none | none | none |

Allowing TLS 1.2 costs nothing between peers that speak 1.3: they negotiate 1.3, and TLS 1.3's
downgrade protection keeps an attacker from forcing 1.2; every 1.2 suite offered is ECDHE with
an AEAD cipher, and the extended master secret is required. `modern` refuses peers that speak
only 1.2; choose it to keep client certificates from passive observers (TLS 1.2 sends them
unencrypted) when such peers exist. `legacy` adds SHA-1 pins and TLS 1.2 without the extended
master secret; a peer that cannot take a TLS 1.3 `ClientHello` at all is served by
`tls_versions = ["1.2"]`.

### Cipher profiles

Apart from the versions, a policy lists the algorithm profiles it allows
(`cipher_profiles`, default `["mozilla"]`) and the provider that runs them (`crypto`, `ring` or,
with the `aws-lc` feature, `aws-lc`). What is offered is the union of the allowed profiles in
the order of the first listed, narrowed to the versions, the provider and any `cipher_suites` /
`kx_groups` list; a version left with no suite is dropped. Each profile is named for exactly
what it claims:

| Profile | What it is |
| --- | --- |
| `mozilla` | Mozilla's server-side TLS guideline 6.0, intermediate. The default. |
| `fips-140-3-compliant` | FIPS 140-3 approved algorithm selection; not a validated module. |
| `fips-140-2-compliant` | The same without the ML-KEM groups, which only a 140-3 module can have approved; not a validated module. Every FIPS 140-2 certificate is on the CMVP Historical List since September 2026. |
| `fips-140-3-validated` | AWS-LC's FIPS module; validated only as its CMVP certificate and tested operating environments state. Needs the `fips` feature; a configuration rustls does not report FIPS is refused. |
| `cnsa-1.0` | CNSSP 15 / RFC 9151 as far as rustls goes: AES-256-GCM, P-384, SHA-384. |
| `cnsa-2.0` | CNSA 2.0 (ML-KEM-1024, ML-DSA-87, AES-256) in the shape of draft-becker-cnsa2-tls-profile-05; needs `crypto = "aws-lc"`. |

The CNSA profiles need an identity of your own (P-384 or RSA 3072+, or ML-DSA-87): generated
identities are P-256. The crate's API header lists every algorithm and what each profile does
not meet.

Session resumption is off in every preset: rustls does not check the peer's certificate again
on a resumed session, so a peer removed from the trust store could reconnect on a session it
held. TLS 1.0, 1.1 and non-AEAD suites cannot be offered; MD5 pins are never accepted.

```rust,no_run
use coqui_peer_tls::{Digest, Identity, Policy, Trust, server_config_with};

let identity = Identity::read("identity.pem".as_ref())?.expect("an identity file");
let mut policy = Policy::default();
policy.pin_digests.push(Digest::Sha1);
policy.waiting.per_source = 4;
let built = server_config_with(&identity, &Trust::AnyWithKeyProof, &[b"my-protocol/1"], &policy)?;
for weaker in &built.weakened {
    eprintln!("{} = {} (default: {})", weaker.setting, weaker.value, weaker.strict);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

With the `serde` feature a `Policy` also reads and writes a versioned text form (version 1),
in the format you choose:

```toml
policy_version = 1
profile = "intermediate"        # a built-in preset to start from
tls_versions = ["1.2", "1.3"]
cipher_profiles = ["mozilla"]   # allowed algorithm profiles
crypto = "ring"                 # or "aws-lc", with the `aws-lc` feature
pin_digests = ["sha256", "sha384", "sha512"]
allow_resumption = false
require_ems = true
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

Every key is optional; absent keys keep the preset. Committed examples for every preset are in
the repository's `tests/vectors/policy/`.

## Access control

A policy's access control list (feature `acl`) is applied by every server configuration built
under it: by address when the `ClientHello` arrives, before any certificate is sent, and by the
client certificate's fingerprint before the trust store is consulted, so a denied client is
never recorded as waiting. Fingerprint rules may be written in any spelling a `PeerId` parses.
The refusals are `Refusal::AddressDenied`, `PeerDenied` and `AddressUnknown`. For quinn,
`ServerConfigs` builds a configuration per connection from its addresses, sharing one session
cache, and keeps the refusal its handshake ended with (`ConnectionConfig::refusal`), since
quinn reports only the alert; `Trust::client_cert_verifier_for` is the verifier alone, and
`Policy::admits_address` decides before the handshake. Under optional client authentication a
rule naming a fingerprint never admits a client.

## Limits

- A waiting entry is recorded only after the peer proves it holds the certificate's key. Each
  entry stores the address the handshake came from, and the per-source caps
  (`waiting.per_source`, `waiting.rerecord`) apply per IPv4 address or per IPv6 /64.
- Not provided: a handshake probe, a helper for reading and writing one connection from two
  threads, and QUIC datagrams.

## Development

```bash
ALL=generate,ca,tokio,pin,serde,acl,platform-roots,aws-lc   # every feature but fips
cargo fmt --all --check
cargo clippy --all-targets --features $ALL -- -D warnings
cargo +1.89 clippy --all-targets --features $ALL -- -D warnings
cargo test --features $ALL
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --features $ALL
cargo +nightly-2026-09-21 public-api --features $ALL -sss --color never | diff -u tools/public-api.txt -
cargo test --features fips          # needs CMake and Go
```

`aws-lc` builds AWS-LC from C (a C compiler; clang on Windows ARM64). `fips` builds AWS-LC's
FIPS module (aws-lc-fips-sys: CMake and Go, and on Windows bindgen with libclang, NASM and
Ninja) and has global effect: rustls's `fips` feature changes defaults for every crate in the
build. If bindgen fails with `ParseQuote is not implemented for syn::File`, cargo paired bindgen
0.73 with prettyplease 0.3; `cargo update -p prettyplease --precise 0.2.37` fixes the lockfile.
The `fips` feature adds no item to the API, so the snapshot is taken without it.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` runs the release workflow: the tests and a strict documentation
build gate a GitHub release, marked as a pre-release when the version has a `-` suffix. The
crate is published to crates.io with `cargo publish` by a maintainer, after `coqui-net-acl` and
`coqui-peer`.

## License

MPL-2.0; see [LICENSE](https://github.com/Boriken-Dev/coqui-peer-tls/blob/main/LICENSE).
