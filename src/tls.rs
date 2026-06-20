use serde::{Deserialize, Serialize};
use tracing::warn;
use x509_parser::prelude::*;

/// Extracted metadata from a server's TLS certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

/// Parse a raw X.509 DER certificate into human-readable metadata.
pub fn parse_cert(der: &[u8]) -> Option<TlsCertInfo> {
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            
            // Format timestamps into UTC RFC 3339 style strings for clarity.
            // x509-parser uses `time::OffsetDateTime` via the `time` crate feature
            // but we can just use the standard timestamp directly.
            let not_before = cert.validity().not_before.to_datetime().to_string();
            let not_after = cert.validity().not_after.to_datetime().to_string();

            Some(TlsCertInfo {
                subject,
                issuer,
                not_before,
                not_after,
            })
        }
        Err(e) => {
            warn!(error = %e, "failed to parse X.509 certificate DER");
            None
        }
    }
}
