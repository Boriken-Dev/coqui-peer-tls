use std::fmt;
use std::sync::Arc;

use globset::{Glob, GlobSet, GlobSetBuilder};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{DistinguishedName, RootCertStore};

use crate::error::PeerError;
use crate::trust::CaPolicy;

/// A loaded CA policy.
pub(crate) struct Ca {
    verifier: Arc<dyn ClientCertVerifier>,
    subjects: Option<GlobSet>,
    sans: Option<GlobSet>,
}

impl fmt::Debug for Ca {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Ca").finish_non_exhaustive()
    }
}

impl Ca {
    pub(crate) fn load(
        policy: &CaPolicy,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Self, PeerError> {
        let mut roots = RootCertStore::empty();
        for certificate in
            CertificateDer::pem_file_iter(&policy.ca_file).map_err(|_| PeerError::Certificate)?
        {
            roots
                .add(certificate.map_err(|_| PeerError::Certificate)?)
                .map_err(|_| PeerError::Certificate)?;
        }
        if roots.is_empty() {
            return Err(PeerError::Certificate);
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| PeerError::Certificate)?;
        Ok(Self {
            verifier,
            subjects: compile(&policy.subject)?,
            sans: compile(&policy.san)?,
        })
    }

    pub(crate) fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.verifier.root_hint_subjects()
    }

    /// Whether the chain verifies against the CA roots and the names match the globs.
    pub(crate) fn trusts(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<bool, rustls::Error> {
        Ok(self
            .verifier
            .verify_client_cert(certificate, intermediates, now)
            .is_ok()
            && self.names_match(certificate)?)
    }

    fn names_match(&self, certificate: &CertificateDer<'_>) -> Result<bool, rustls::Error> {
        if self.subjects.is_none() && self.sans.is_none() {
            return Ok(true);
        }
        let bad = || rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
        let (_, certificate) =
            x509_parser::parse_x509_certificate(certificate.as_ref()).map_err(|_| bad())?;
        if let Some(subjects) = &self.subjects
            && !subjects.is_match(certificate.subject().to_string())
        {
            return Ok(false);
        }
        if let Some(sans) = &self.sans {
            let extension = certificate.subject_alternative_name().map_err(|_| bad())?;
            let matched = extension
                .into_iter()
                .flat_map(|extension| extension.value.general_names.iter())
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(name)
                    | x509_parser::extensions::GeneralName::RFC822Name(name)
                    | x509_parser::extensions::GeneralName::URI(name) => Some((*name).to_owned()),
                    x509_parser::extensions::GeneralName::IPAddress(address) => {
                        Some(format!("{address:?}"))
                    }
                    _ => None,
                })
                .any(|name| sans.is_match(name));
            if !matched {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn compile(patterns: &[String]) -> Result<Option<GlobSet>, PeerError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(|_| PeerError::TrustPattern)?);
    }
    builder
        .build()
        .map(Some)
        .map_err(|_| PeerError::TrustPattern)
}
