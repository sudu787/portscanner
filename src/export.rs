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
    pub service: String,
    pub banner: Option<String>,
    pub tls_subject: Option<String>,
    pub tls_issuer: Option<String>,
    pub status: String,
}

impl ExportRecord {
    /// Maps a raw `ScanResult` and its individual port into an `ExportRecord`.
    pub fn from_scan_result(ip: &str, hostname: Option<&String>, port_result: &crate::scanner::PortResult) -> Self {
        let (tls_subj, tls_iss) = if let Some(cert) = &port_result.tls_cert {
            (Some(cert.subject.clone()), Some(cert.issuer.clone()))
        } else {
            (None, None)
        };

        let status_str = match port_result.status {
            crate::scanner::PortStatus::Open => "open",
            crate::scanner::PortStatus::Closed => "closed",
            crate::scanner::PortStatus::Filtered => "filtered",
            crate::scanner::PortStatus::OpenFiltered => "open|filtered",
        };

        Self {
            host: ip.to_string(),
            hostname: hostname.cloned(),
            port: port_result.port,
            service: port_result.service.name.to_string(),
            banner: port_result.banner.clone(),
            tls_subject: tls_subj,
            tls_issuer: tls_iss,
            status: status_str.to_string(),
        }
    }
}

/// Convert a list of `ScanResult`s into a list of `ExportRecord`s.
fn flatten_results(results: &[ScanResult]) -> Vec<ExportRecord> {
    let mut flat = Vec::new();
    for r in results {
        let ip_str = r.target.to_string();
        for p in r.open_ports() {
            flat.push(ExportRecord::from_scan_result(&ip_str, r.hostname.as_ref(), p));
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

/// Export to CSV format
pub fn export_csv(path: &str, results: &[ScanResult]) -> Result<()> {
    let flat_results = flatten_results(results);
    let mut wtr = csv::Writer::from_path(path).map_err(|e| RustScanError::Io(e.into()))?;
    for record in flat_results {
        wtr.serialize(record).map_err(|e| RustScanError::Io(e.into()))?;
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
    fn test_export_record_mapping() {
        let pr = PortResult {
            port: 80,
            protocol: Transport::Tcp,
            status: PortStatus::Open,
            service: ServiceInfo { name: "http", transport: Transport::Tcp, description: "web server" },
            banner: Some("nginx".to_string()),
            tls: false,
            tls_cert: None,
        };
        
        let rec = ExportRecord::from_scan_result("127.0.0.1", None, &pr);
        assert_eq!(rec.host, "127.0.0.1");
        assert_eq!(rec.port, 80);
        assert_eq!(rec.status, "open");
        assert_eq!(rec.banner.as_deref(), Some("nginx"));
    }
}
