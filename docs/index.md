# coqui-peer-tls

Mutual-TLS identity between peers, with no RPC layer. Each side has a self-issued certificate
and tells the other only its fingerprint. You get back an authenticated, encrypted byte stream
and the verified peer identity, with pinned, CA and key-proof trust (and, for a client,
servers verified by the web PKI), a trust store with a
waiting queue for pairing, and policy presets (`strict`, `compatible`, `legacy`).

The crate is not published to crates.io; depend on it by git revision:

```toml
coqui-peer-tls = { git = "https://github.com/Boriken-Dev/coqui-peer-tls", rev = "<commit>" }
```

The API reference is under [Rust API](https://boriken-dev.github.io/coqui-peer-tls/rust/index.html).
The source, the API header (`AGENTS.md`) and the changelog are in the
[repository](https://github.com/Boriken-Dev/coqui-peer-tls).
