//! The settings of the configuration builders as one value type, and the field conversions the
//! settings types share. Behind the `guatiao` feature.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Display;
use core::str::FromStr;

use guatiao::schema::KindBuilder;
use guatiao::{Alloc, FromValue, MapError, Schema, ToValue, Value, ValueError};

use crate::policy::Policy;

/// What a configuration builder takes whole through `settings`: the application protocols and
/// the [`Policy`], in the form a file, a form or a peer fills.
///
/// Identities, trust and verifiers are not settings: they hold keys and code, so a builder
/// takes them as arguments. Every key is optional; an absent one is the default (no ALPN,
/// [`Policy::default`]), and an unknown key is refused.
///
/// With the `guatiao` feature this reads and writes as a guatiao value
/// (`TlsSettings::from_value`, `to_value`, `schema`), and `guatiao_serde::text::{toml, json,
/// yaml}` read and write its text.
#[derive(ToValue, FromValue, Schema, Debug, Clone, Default, PartialEq, Eq)]
#[map(deny_unknown_fields)]
#[non_exhaustive]
pub struct TlsSettings {
    /// The application protocols offered, most preferred first, as text (`h2`, `coqui/1`). A
    /// protocol that is not text is set with the builder's `alpn`.
    #[map(default)]
    pub alpn: Vec<String>,
    /// The policy configurations are built under.
    #[map(default)]
    pub policy: Policy,
}

impl TlsSettings {
    /// Settings that offer `alpn` under `policy`.
    pub fn new(alpn: Vec<String>, policy: Policy) -> Self {
        Self { alpn, policy }
    }

    /// The protocols as the bytes a configuration carries.
    pub(crate) fn alpn_bytes(&self) -> Vec<Vec<u8>> {
        self.alpn
            .iter()
            .map(|text| text.as_bytes().to_vec())
            .collect()
    }
}

fn bad(expected: String) -> MapError {
    MapError::BadValue {
        key: String::new(),
        expected,
    }
}

/// `#[map(with = ..)]` for a `Vec` of a type with a text form (`Display` out, `FromStr` in).
pub(crate) mod texts {
    use super::*;

    pub(crate) fn to_value_in<T: Display>(items: &[T], alloc: Alloc) -> Result<Value, ValueError> {
        items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .to_value_in(alloc)
    }

    pub(crate) fn from_value<T: FromStr>(value: &Value) -> Result<Vec<T>, MapError>
    where
        T::Err: Display,
    {
        Vec::<String>::from_value(value)?
            .iter()
            .map(|text| text.parse().map_err(|error: T::Err| bad(error.to_string())))
            .collect()
    }

    pub(crate) fn kind(alloc: Alloc) -> KindBuilder {
        Vec::<String>::kind(alloc)
    }
}

/// `#[map(with = ..)]` for the optional access control list, which has a serde form and no
/// guatiao one.
#[cfg(feature = "acl")]
pub(crate) mod acl {
    use super::*;

    use coqui_net_acl::Acl;

    pub(crate) use guatiao_serde::adapt::to_value_in;

    /// Reads the list and writes its fingerprints in canonical form, as a configuration build
    /// does; a rule naming something else is refused here.
    pub(crate) fn from_value(value: &Value) -> Result<Option<Acl>, MapError> {
        match guatiao_serde::adapt::from_value::<Option<Acl>>(value)? {
            Some(acl) => crate::gate::canonical(&acl)
                .map(Some)
                .map_err(|error| bad(error.to_string())),
            None => Ok(None),
        }
    }

    pub(crate) fn kind(alloc: Alloc) -> KindBuilder {
        KindBuilder::any_in(alloc).description("an ordered access control list; absent for none")
    }
}

/// `#[map(with = ..)]` for [`WaitingLimits`](coqui_peer::WaitingLimits): a map of its three
/// bounds, the interval in whole seconds.
pub(crate) mod waiting {
    use super::*;
    use coqui_peer::WaitingLimits;
    use core::time::Duration;

    #[derive(ToValue, FromValue, Schema)]
    #[map(deny_unknown_fields)]
    struct Bounds {
        /// Entries kept for one source.
        #[map(default = defaults().per_source)]
        per_source: usize,
        /// Entries kept in all.
        #[map(default = defaults().total)]
        total: usize,
        /// Seconds before the same certificate from the same source is recorded again.
        #[map(default = defaults().rerecord.as_secs())]
        rerecord_secs: u64,
    }

    fn defaults() -> WaitingLimits {
        WaitingLimits::default()
    }

    pub(crate) fn to_value_in(limits: &WaitingLimits, alloc: Alloc) -> Result<Value, ValueError> {
        Bounds {
            per_source: limits.per_source,
            total: limits.total,
            rerecord_secs: limits.rerecord.as_secs(),
        }
        .to_value_in(alloc)
    }

    pub(crate) fn from_value(value: &Value) -> Result<WaitingLimits, MapError> {
        let bounds = Bounds::from_value(value)?;
        Ok(WaitingLimits {
            per_source: bounds.per_source,
            total: bounds.total,
            rerecord: Duration::from_secs(bounds.rerecord_secs),
        })
    }

    pub(crate) fn kind(alloc: Alloc) -> KindBuilder {
        Bounds::kind(alloc)
    }
}

/// `#[map(with = ..)]` for the pairing ALPN, bytes held as text.
pub(crate) mod alpn_text {
    use super::*;

    pub(crate) fn to_value_in(alpn: &[u8], alloc: Alloc) -> Result<Value, ValueError> {
        String::from_utf8(alpn.to_vec())
            .map_err(|_| ValueError::Unrepresentable)?
            .to_value_in(alloc)
    }

    pub(crate) fn from_value(value: &Value) -> Result<Vec<u8>, MapError> {
        Ok(String::from_value(value)?.into_bytes())
    }

    pub(crate) fn kind(alloc: Alloc) -> KindBuilder {
        String::kind(alloc).min_length(1)
    }
}
