/// cli.rs — Command-line interface definition and validation for rustscan-rs
///
/// Built with `clap` (derive API).  After parsing, `CliArgs::validate()`
/// performs semantic checks that clap's declarative layer cannot express,
/// returning typed `RustScanError` variants so the caller can handle each
/// failure precisely.
use clap::Parser;

use crate::errors::{Result, RustScanError};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Lowest acceptable port number (RFC 793).
/// Reserved for Phase 4 input validation on banner/TLS flags.
#[allow(dead_code)]
pub const PORT_MIN: u16 = 1;
/// Highest acceptable port number (RFC 793).
/// Reserved for Phase 4 input validation on banner/TLS flags.
#[allow(dead_code)]
pub const PORT_MAX: u16 = 65535;

/// Default starting port for a scan.
pub const DEFAULT_START_PORT: u16 = 1;
/// Default ending port for a scan.
pub const DEFAULT_END_PORT: u16 = 1024;

/// Default connection timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 1_500;
/// Upper ceiling for timeouts (5 minutes).
pub const MAX_TIMEOUT_MS: u64 = 300_000;

/// Default number of concurrent tasks.
pub const DEFAULT_CONCURRENCY: usize = 1_000;
/// Hard upper limit to prevent accidental resource exhaustion.
pub const MAX_CONCURRENCY: usize = 65_535;

// ─── CLI Definition ───────────────────────────────────────────────────────────

/// rustscan-rs — A high-performance async port scanner written in Rust.
///
/// Scans TCP ports on a target host as fast as your network allows.
/// By default it probes ports 1–1024 with 1 000 concurrent tasks and a
/// 1 500 ms per-connection timeout.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustscan-rs",
    version,
    author,
    about = "A high-performance, async port scanner written in Rust",
    long_about = None,
    help_template = "\
{before-help}{name} {version}
{author-with-newline}
{about-with-newline}
\x1b[1;32mUSAGE:\x1b[0m
  {usage}

\x1b[1;32mARGUMENTS:\x1b[0m
{positionals}
\x1b[1;32mOPTIONS:\x1b[0m
{options}{after-help}
"
)]
pub struct CliArgs {
    // ── Positional ─────────────────────────────────────────────────────────
    /// Target IP address or hostname to scan.
    ///
    /// Examples: 192.168.1.1  scanme.nmap.org
    #[arg(value_name = "TARGET")]
    pub target: String,

    // ── Port range ─────────────────────────────────────────────────────────
    /// First port of the scan range (1–65535).
    #[arg(
        long,
        value_name = "PORT",
        default_value_t = DEFAULT_START_PORT,
        help = "Starting port of the scan range"
    )]
    pub start_port: u16,

    /// Last port of the scan range (1–65535).
    #[arg(
        long,
        value_name = "PORT",
        default_value_t = DEFAULT_END_PORT,
        help = "Ending port of the scan range"
    )]
    pub end_port: u16,

    // ── Timing ─────────────────────────────────────────────────────────────
    /// Connection timeout in milliseconds (1–300 000).
    #[arg(
        long,
        value_name = "MS",
        default_value_t = DEFAULT_TIMEOUT_MS,
        help = "Per-connection timeout in milliseconds"
    )]
    pub timeout: u64,

    // ── Concurrency ────────────────────────────────────────────────────────
    /// Number of concurrent TCP probes in flight at once (1–65535).
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_CONCURRENCY,
        help = "Maximum number of concurrent probe tasks"
    )]
    pub concurrency: usize,

    // ── Output formats ─────────────────────────────────────────────────────
    /// Emit results as machine-readable JSON.
    #[arg(long, help = "Output results in JSON format", value_name = "FILE", num_args = 0..=1, default_missing_value = "", conflicts_with_all = ["csv", "html"])]
    pub json: Option<String>,

    /// Emit results as CSV (comma-separated values).
    #[arg(long, help = "Output results in CSV format", value_name = "FILE", num_args = 0..=1, default_missing_value = "", conflicts_with_all = ["json", "html"])]
    pub csv: Option<String>,

    /// Emit results as a self-contained HTML report.
    #[arg(long, help = "Output results as an HTML report", value_name = "FILE", num_args = 0..=1, default_missing_value = "", conflicts_with_all = ["json", "csv"])]
    pub html: Option<String>,

    // ── Probing options ────────────────────────────────────────────────────
    /// Perform a UDP scan.
    #[arg(long, help = "Perform a UDP scan")]
    pub udp: bool,

    /// Perform a TCP scan (default if neither --tcp nor --udp is provided).
    #[arg(long, help = "Perform a TCP scan")]
    pub tcp: bool,

    /// Attempt to grab the service banner on open ports.
    #[arg(long, help = "Attempt service banner grabbing on open ports")]
    pub banner: bool,

    /// Resolve the target hostname to its IP address and display it.
    #[arg(long, help = "Resolve the target hostname via DNS before scanning")]
    pub resolve_dns: bool,

    /// Attempt a TLS handshake on open ports to detect TLS-wrapped services.
    #[arg(long, help = "Probe open ports for TLS support")]
    pub tls: bool,

    // ── Verbosity ──────────────────────────────────────────────────────────
    /// Increase log verbosity.  Repeat for more detail (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, help = "Increase verbosity (use -v, -vv, -vvv)")]
    pub verbose: u8,
}

// ─── Output Format Helper ─────────────────────────────────────────────────────

/// The output serialization format chosen by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain human-readable text (default).
    Text,
    /// JSON (`--json`).
    Json,
    /// CSV (`--csv`).
    Csv,
    /// HTML report (`--html`).
    Html,
}

// ─── Validation ───────────────────────────────────────────────────────────────

impl CliArgs {
    /// Returns true if a TCP scan should be performed.
    pub fn do_tcp(&self) -> bool {
        self.tcp || !self.udp
    }

    /// Returns true if a UDP scan should be performed.
    pub fn do_udp(&self) -> bool {
        self.udp
    }
    /// Perform semantic validation that clap's declarative API cannot express.
    ///
    /// This is intentionally kept separate from parsing so that unit tests can
    /// construct `CliArgs` values by hand and test validation independently.
    ///
    /// # Errors
    ///
    /// Returns a [`RustScanError`] variant when:
    /// - `start_port > end_port`
    /// - either port is 0 (clap allows 0 as a `u16`)
    /// - `timeout` is 0 or exceeds [`MAX_TIMEOUT_MS`]
    /// - `concurrency` is 0 or exceeds [`MAX_CONCURRENCY`]
    /// - `target` is an empty string
    pub fn validate(&self) -> Result<()> {
        self.validate_target()?;
        self.validate_ports()?;
        self.validate_timeout()?;
        self.validate_concurrency()?;
        Ok(())
    }

    /// Derive the output format selected by the user.
    pub fn output_format(&self) -> OutputFormat {
        if self.json.is_some() {
            OutputFormat::Json
        } else if self.csv.is_some() {
            OutputFormat::Csv
        } else if self.html.is_some() {
            OutputFormat::Html
        } else {
            OutputFormat::Text
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────

    fn validate_target(&self) -> Result<()> {
        let t = self.target.trim();
        if t.is_empty() {
            return Err(RustScanError::InvalidTarget {
                target: self.target.clone(),
            });
        }
        Ok(())
    }

    fn validate_ports(&self) -> Result<()> {
        // clap already stores ports as u16, so the 0–65535 type range is
        // guaranteed.  We only need to reject 0 and inverted ranges.
        if self.start_port == 0 {
            return Err(RustScanError::PortOutOfRange {
                port: self.start_port as u32,
            });
        }
        if self.end_port == 0 {
            return Err(RustScanError::PortOutOfRange {
                port: self.end_port as u32,
            });
        }
        if self.start_port > self.end_port {
            return Err(RustScanError::InvalidPortRange {
                start: self.start_port,
                end: self.end_port,
            });
        }
        Ok(())
    }

    fn validate_timeout(&self) -> Result<()> {
        if self.timeout == 0 || self.timeout > MAX_TIMEOUT_MS {
            return Err(RustScanError::InvalidTimeout { ms: self.timeout });
        }
        Ok(())
    }

    fn validate_concurrency(&self) -> Result<()> {
        if self.concurrency == 0 || self.concurrency > MAX_CONCURRENCY {
            return Err(RustScanError::InvalidConcurrency {
                value: self.concurrency,
                max: MAX_CONCURRENCY,
            });
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid `CliArgs` for use in unit tests.
    fn valid_args() -> CliArgs {
        CliArgs {
            target: "127.0.0.1".to_string(),
            start_port: 1,
            end_port: 1024,
            timeout: DEFAULT_TIMEOUT_MS,
            concurrency: DEFAULT_CONCURRENCY,
            json: None,
            csv: None,
            html: None,
            banner: false,
            resolve_dns: false,
            tls: false,
            tcp: true,
            udp: false,
            verbose: 0,
        }
    }

    #[test]
    fn valid_configuration_passes() {
        assert!(valid_args().validate().is_ok());
    }

    #[test]
    fn inverted_port_range_fails() {
        let mut args = valid_args();
        args.start_port = 1024;
        args.end_port = 1;
        let err = args.validate().unwrap_err();
        assert!(matches!(err, RustScanError::InvalidPortRange { .. }));
    }

    #[test]
    fn zero_start_port_fails() {
        let mut args = valid_args();
        args.start_port = 0;
        let err = args.validate().unwrap_err();
        assert!(matches!(err, RustScanError::PortOutOfRange { .. }));
    }

    #[test]
    fn zero_timeout_fails() {
        let mut args = valid_args();
        args.timeout = 0;
        let err = args.validate().unwrap_err();
        assert!(matches!(err, RustScanError::InvalidTimeout { .. }));
    }

    #[test]
    fn timeout_at_ceiling_passes() {
        let mut args = valid_args();
        args.timeout = MAX_TIMEOUT_MS;
        assert!(args.validate().is_ok());
    }

    #[test]
    fn timeout_above_ceiling_fails() {
        let mut args = valid_args();
        args.timeout = MAX_TIMEOUT_MS + 1;
        assert!(matches!(
            args.validate().unwrap_err(),
            RustScanError::InvalidTimeout { .. }
        ));
    }

    #[test]
    fn zero_concurrency_fails() {
        let mut args = valid_args();
        args.concurrency = 0;
        assert!(matches!(
            args.validate().unwrap_err(),
            RustScanError::InvalidConcurrency { .. }
        ));
    }

    #[test]
    fn concurrency_at_max_passes() {
        let mut args = valid_args();
        args.concurrency = MAX_CONCURRENCY;
        assert!(args.validate().is_ok());
    }

    #[test]
    fn concurrency_above_max_fails() {
        let mut args = valid_args();
        args.concurrency = MAX_CONCURRENCY + 1;
        assert!(matches!(
            args.validate().unwrap_err(),
            RustScanError::InvalidConcurrency { .. }
        ));
    }

    #[test]
    fn empty_target_fails() {
        let mut args = valid_args();
        args.target = "   ".to_string();
        assert!(matches!(
            args.validate().unwrap_err(),
            RustScanError::InvalidTarget { .. }
        ));
    }

    #[test]
    fn output_format_defaults_to_text() {
        assert_eq!(valid_args().output_format(), OutputFormat::Text);
    }

    #[test]
    fn output_format_json() {
        let mut args = valid_args();
        args.json = Some("".to_string());
        assert_eq!(args.output_format(), OutputFormat::Json);
    }
}
