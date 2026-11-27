use serde::{Deserialize, Serialize};
use tracing::warn;
use x509_parser::prelude::*;

use crate::probes::sanitize;

/// Extracted metadata from a server's TLS certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    /// Outside its validity window right now (expired or not yet valid).
    pub expired: bool,
    /// Subject == issuer: nobody vouches for this certificate.
    pub self_signed: bool,
}

impl TlsCertInfo {
    /// Placeholder when the handshake worked but the certificate couldn't be read.
    pub fn unknown() -> Self {
        Self {
            subject: "Unknown (TLS handshake OK)".into(),
            issuer: "Unknown".into(),
            not_before: String::new(),
            not_after: String::new(),
            expired: false,
            self_signed: false,
        }
    }
}

/// Parse a raw X.509 DER certificate into human-readable metadata.
/// All text fields are sanitized: they are chosen by the (possibly hostile) server.
pub fn parse_cert(der: &[u8]) -> Option<TlsCertInfo> {
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => Some(TlsCertInfo {
            subject: sanitize(&cert.subject().to_string()),
            issuer: sanitize(&cert.issuer().to_string()),
            not_before: cert.validity().not_before.to_datetime().to_string(),
            not_after: cert.validity().not_after.to_datetime().to_string(),
            expired: !cert.validity().is_valid(),
            self_signed: cert.subject() == cert.issuer(),
        }),
        Err(e) => {
            warn!(error = %e, "failed to parse X.509 certificate DER");
            None
        }
    }
}
