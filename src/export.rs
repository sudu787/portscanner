use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::{Result, RustScanError};
use crate::scanner::ScanResult;

/// A flattened export record matching the exact requirements.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportRecord {
    pub host: String,
    pub hostname: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    /// Product and version recognised from the reply.
    pub version: Option<String>,
    pub banner: Option<String>,
    pub tls: bool,
    pub tls_subject: Option<String>,
    pub tls_issuer: Option<String>,
    pub tls_not_after: Option<String>,
    pub cert_expired: Option<bool>,
    pub cert_self_signed: Option<bool>,
    /// Deprecated protocol the server still accepts (`TLSv1.0`, …).
    pub legacy_tls: Option<String>,
    pub status: String,
}

impl ExportRecord {
    /// Maps a raw `ScanResult` and its individual port into an `ExportRecord`.
    pub fn from_scan_result(
        ip: &str,
        hostname: Option<&String>,
        port_result: &crate::scanner::PortResult,
    ) -> Self {
        let cert = port_result.tls_cert.as_ref();
        Self {
            host: ip.to_string(),
            hostname: hostname.cloned(),
            port: port_result.port,
            protocol: if port_result.protocol == crate::service::Transport::Udp {
                "udp"
            } else {
                "tcp"
            }
            .to_string(),
            service: port_result.service.name.to_string(),
            version: port_result.version.clone(),
            banner: port_result.banner.clone(),
            tls: port_result.tls,
            tls_subject: cert.map(|c| c.subject.clone()),
            tls_issuer: cert.map(|c| c.issuer.clone()),
            tls_not_after: cert.map(|c| c.not_after.clone()),
            cert_expired: cert.map(|c| c.expired),
            cert_self_signed: cert.map(|c| c.self_signed),
            legacy_tls: port_result.legacy_tls.map(String::from),
            status: port_result.status.as_str().to_string(),
        }
    }
}

/// Convert a list of `ScanResult`s into a list of `ExportRecord`s.
pub fn flatten_results(results: &[ScanResult]) -> Vec<ExportRecord> {
    let mut flat = Vec::new();
    for r in results {
        let ip_str = r.target.to_string();
        for p in r.open_ports() {
            flat.push(ExportRecord::from_scan_result(
                &ip_str,
                r.hostname.as_ref(),
                p,
            ));
        }
    }
    flat
}

/// Export to JSON array
pub fn export_json(path: &str, results: &[ScanResult]) -> Result<()> {
    let flat_results = flatten_results(results);
    let file = File::create(Path::new(path)).map_err(RustScanError::Io)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &flat_results).map_err(|e| RustScanError::Io(e.into()))?;
    Ok(())
}

/// Neutralise CSV/formula injection: a cell starting with `= + - @ \t \r` is
/// executed as a formula by Excel/LibreOffice. Banners, certificate fields and
/// PTR hostnames come from the scanned host, so they are attacker-controlled.
pub fn csv_safe(s: &str) -> String {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    }
}

/// Export to CSV format
pub fn export_csv(path: &str, results: &[ScanResult]) -> Result<()> {
    let flat_results = flatten_results(results);
    let mut wtr = csv::Writer::from_path(path).map_err(|e| RustScanError::Io(e.into()))?;
    for mut record in flat_results {
        for field in [
            &mut record.hostname,
            &mut record.version,
            &mut record.banner,
            &mut record.tls_subject,
            &mut record.tls_issuer,
        ]
        .into_iter()
        .flatten()
        {
            *field = csv_safe(field);
        }
        wtr.serialize(record)
            .map_err(|e| RustScanError::Io(e.into()))?;
    }
    wtr.flush().map_err(RustScanError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{PortResult, PortStatus};
    use crate::service::{ServiceInfo, Transport};

    #[test]
    fn csv_safe_neutralises_formulas() {
        assert_eq!(csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0");
        assert_eq!(csv_safe("@SUM(1)"), "'@SUM(1)");
        assert_eq!(csv_safe("+1"), "'+1");
        assert_eq!(csv_safe("SSH-2.0-OpenSSH"), "SSH-2.0-OpenSSH");
        assert_eq!(csv_safe(""), "");
    }

    #[test]
    fn test_export_record_mapping() {
        let pr = PortResult {
            port: 80,
            protocol: Transport::Tcp,
            status: PortStatus::Open,
            service: ServiceInfo {
                name: "http",
                transport: Transport::Tcp,
                description: "web server",
            },
            banner: Some("nginx".to_string()),
            tls: false,
            tls_cert: None,
            legacy_tls: None,
            version: None,
        };

        let rec = ExportRecord::from_scan_result("127.0.0.1", None, &pr);
        assert_eq!(rec.host, "127.0.0.1");
        assert_eq!(rec.port, 80);
        assert_eq!(rec.status, "open");
        assert_eq!(rec.banner.as_deref(), Some("nginx"));
    }
}
