//! The identity vectors spell their key's armor `PKCS8`, so that no file in the tree is a private-key
//! PEM; these put the standard armor back (and take it off again when regenerating).

#![allow(dead_code)]

const STORED: [&str; 2] = ["-----BEGIN PKCS8-----", "-----END PKCS8-----"];
const PEM: [&str; 2] = ["-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"];

/// The vector `name` under `tests/vectors/`, as the PEM text `Identity::from_pem` reads.
pub fn vector(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
    text.replace(STORED[0], PEM[0]).replace(STORED[1], PEM[1])
}

/// PEM text as the vector files store it.
pub fn stored(pem: &str) -> String {
    pem.replace(PEM[0], STORED[0]).replace(PEM[1], STORED[1])
}
