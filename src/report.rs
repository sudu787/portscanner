use askama::Template;
use std::fs;
use std::time::Duration;

use crate::errors::{Result, RustScanError};
use crate::export::ExportRecord;
use crate::scanner::ScanResult;

#[derive(Template)]
#[template(path = "report.html")]
pub struct ReportTemplate<'a> {
    pub current_time: String,
    pub total_hosts: usize,
    pub total_open_ports: usize,
    pub elapsed: String,
    pub records: Vec<ExportRecord>,
    _phantom: std::marker::PhantomData<&'a ()>, // In case we need lifetimes later
}

pub fn generate_html_report(
    path: &str,
    results: &[ScanResult],
    total_elapsed: Duration,
) -> Result<()> {
    // 1. Calculate Summary Stats
    let total_hosts = results.len();
    let total_open_ports: usize = results.iter().map(|r| r.open_ports().count()).sum();
    let elapsed = format!("{:.2}s", total_elapsed.as_secs_f64());

    // Format UTC time (simple manual format since we don't have chrono)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
        + " UNIX epoch";

    // 2. Flatten records for the table using our existing export struct
    let mut records = Vec::new();
    for r in results {
        let ip_str = r.target.to_string();
        for p in r.open_ports() {
            records.push(ExportRecord::from_scan_result(
                &ip_str,
                r.hostname.as_ref(),
                p,
            ));
        }
    }

    // 3. Render Askama Template
    let template = ReportTemplate {
        current_time,
        total_hosts,
        total_open_ports,
        elapsed,
        records,
        _phantom: std::marker::PhantomData,
    };

    let html_string = template.render().map_err(|e| {
        RustScanError::Io(std::io::Error::other(e.to_string()))
    })?;

    // 4. Save to Disk or Stdout
    if path.is_empty() {
        println!("{}", html_string);
    } else {
        fs::write(path, html_string).map_err(RustScanError::Io)?;
    }

    Ok(())
}
