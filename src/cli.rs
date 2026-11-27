//! cli.rs — Command-line interface definition and validation for rustscan-rs
//!
//! Built with `clap` (derive API).  After parsing, `CliArgs::validate()`
//! performs semantic checks that clap's declarative layer cannot express.
use clap::Parser;

use crate::errors::{Result, RustScanError};
use crate::ports;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Default starting port for a scan (when no `-p` / `--top-ports` is given).
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
/// Upper bound for `--retries`.
pub const MAX_RETRIES: u8 = 10;

// ─── CLI Definition ───────────────────────────────────────────────────────────

/// rustscan-rs — a fast async port scanner with built-in service, TLS and
/// UDP analysis. No root privileges required.
#[derive(Parser, Debug, Clone)]
#[command(name = "rustscan-rs", version, author, about, long_about = None)]
pub struct CliArgs {
    // ── Targets ────────────────────────────────────────────────────────────
    /// Targets: IPs, CIDR ranges or hostnames (e.g. 10.0.0.1 10.0.1.0/24 example.com).
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Read targets from a file (one per line, `#` comments allowed; `-` = stdin).
    #[arg(short = 'L', long = "target-file", value_name = "FILE")]
    pub target_file: Option<String>,

    /// Hosts / CIDR ranges to skip (comma-separated).
    #[arg(long, value_name = "HOSTS", value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Scan every address a hostname resolves to (default: first IPv4, else first).
    #[arg(long)]
    pub all_addrs: bool,

    /// Skip host discovery and scan every host (default for single hosts).
    #[arg(long = "no-discovery", alias = "Pn")]
    pub no_discovery: bool,

    // ── Ports ──────────────────────────────────────────────────────────────
    /// Ports to scan: `22,80,443`, `1-1000`, `8000-`, or `-` for all 65535.
    #[arg(short, long, value_name = "SPEC", conflicts_with_all = ["top_ports", "start_port", "end_port"])]
    pub ports: Option<String>,

    /// Scan the N most commonly exposed ports.
    #[arg(long, value_name = "N", conflicts_with_all = ["start_port", "end_port"])]
    pub top_ports: Option<usize>,

    /// Ports to leave out (same syntax as `-p`).
    #[arg(long, value_name = "SPEC")]
    pub exclude_ports: Option<String>,

    /// First port of a contiguous range (legacy; prefer `-p`).
    #[arg(long, value_name = "PORT", default_value_t = DEFAULT_START_PORT)]
    pub start_port: u16,

    /// Last port of a contiguous range (legacy; prefer `-p`).
    #[arg(long, value_name = "PORT", default_value_t = DEFAULT_END_PORT)]
    pub end_port: u16,

    // ── Timing ─────────────────────────────────────────────────────────────
    /// Per-connection timeout in milliseconds.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_TIMEOUT_MS)]
    pub timeout: u64,

    /// Maximum number of probes in flight at once (across all hosts).
    #[arg(short, long, value_name = "N", default_value_t = DEFAULT_CONCURRENCY)]
    pub concurrency: usize,

    /// Re-send a probe that timed out up to N more times (cuts false negatives).
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub retries: u8,

    /// Maximum new probes per second (default: unlimited).
    #[arg(long, value_name = "PPS")]
    pub rate: Option<u32>,

    /// Probe in ascending order instead of a randomised order.
    #[arg(long)]
    pub sequential: bool,

    // ── Output ─────────────────────────────────────────────────────────────
    /// JSON output. With FILE: write JSON there; without: JSON on stdout.
    #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = "")]
    pub json: Option<String>,

    /// CSV output. With FILE: write CSV there; without: CSV on stdout.
    #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = "")]
    pub csv: Option<String>,

    /// HTML report. With FILE: write it there; without: HTML on stdout.
    #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = "")]
    pub html: Option<String>,

    /// Don't stream open ports to stderr while scanning.
    #[arg(short, long)]
    pub quiet: bool,

    // ── Probing options ────────────────────────────────────────────────────
    /// Scan UDP ports (uses protocol-specific payloads for DNS, NTP, SNMP, ...).
    #[arg(long)]
    pub udp: bool,

    /// Scan TCP ports (default unless only --udp is given).
    #[arg(long)]
    pub tcp: bool,

    /// Half-open SYN scan over raw sockets (Linux; root or CAP_NET_RAW).
    /// Faster, one socket for the whole scan, not logged by services.
    #[arg(long, visible_alias = "sS")]
    pub syn: bool,

    /// After the scan, run nmap on just the open ports for deep version
    /// detection (needs nmap installed; text output only).
    #[arg(long)]
    pub nmap: bool,

    /// Arguments for the --nmap hand-off.
    #[arg(
        long,
        value_name = "ARGS",
        default_value = "-sV",
        allow_hyphen_values = true
    )]
    pub nmap_args: String,

    /// Grab banners on open ports and identify services from them.
    #[arg(long)]
    pub banner: bool,

    /// Reverse-resolve each host via DNS (PTR).
    #[arg(long)]
    pub resolve_dns: bool,

    /// Probe open TCP ports for TLS: certificate, expiry, self-signed, legacy TLS 1.0/1.1.
    #[arg(long)]
    pub tls: bool,

    /// Increase log verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

// ─── Output Format Helper ─────────────────────────────────────────────────────

/// The format printed on stdout. File exports (`--json FILE` …) are extra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
    Html,
}

// ─── Validation ───────────────────────────────────────────────────────────────

impl CliArgs {
    pub fn do_tcp(&self) -> bool {
        self.tcp || !self.udp
    }

    pub fn do_udp(&self) -> bool {
        self.udp
    }

    /// Semantic validation that clap's declarative API cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.targets.iter().all(|t| t.trim().is_empty()) && self.target_file.is_none() {
            return Err(RustScanError::InvalidTarget {
                target: self.targets.join(" "),
            });
        }
        self.port_list()?;
        if self.timeout == 0 || self.timeout > MAX_TIMEOUT_MS {
            return Err(RustScanError::InvalidTimeout { ms: self.timeout });
        }
        if self.concurrency == 0 || self.concurrency > MAX_CONCURRENCY {
            return Err(RustScanError::InvalidConcurrency {
                value: self.concurrency,
                max: MAX_CONCURRENCY,
            });
        }
        if self.retries > MAX_RETRIES {
            return Err(RustScanError::InvalidOption(format!(
                "--retries must be at most {MAX_RETRIES}"
            )));
        }
        if self.rate == Some(0) {
            return Err(RustScanError::InvalidOption("--rate must be > 0".into()));
        }
        let stdout_formats = [&self.json, &self.csv, &self.html]
            .iter()
            .filter(|o| o.as_deref() == Some(""))
            .count();
        if self.syn && !self.do_tcp() {
            return Err(RustScanError::InvalidOption(
                "--syn is a TCP scan; add --tcp or drop --syn".into(),
            ));
        }
        if self.nmap && self.output_format() != OutputFormat::Text {
            return Err(RustScanError::InvalidOption(
                "--nmap prints nmap's report, so it needs text output on stdout \
                 (write JSON/CSV/HTML to files instead)"
                    .into(),
            ));
        }
        if stdout_formats > 1 {
            return Err(RustScanError::InvalidOption(
                "only one of --json/--csv/--html can go to stdout; give the others a FILE".into(),
            ));
        }
        Ok(())
    }

    /// The final, de-duplicated list of ports to probe.
    pub fn port_list(&self) -> Result<Vec<u16>> {
        let mut list = if let Some(spec) = &self.ports {
            ports::parse_ports(spec)?
        } else if let Some(n) = self.top_ports {
            if n == 0 {
                return Err(RustScanError::InvalidOption(
                    "--top-ports must be > 0".into(),
                ));
            }
            ports::top_ports(n)
        } else {
            if self.start_port == 0 || self.end_port == 0 {
                return Err(RustScanError::PortOutOfRange { port: 0 });
            }
            if self.start_port > self.end_port {
                return Err(RustScanError::InvalidPortRange {
                    start: self.start_port,
                    end: self.end_port,
                });
            }
            (self.start_port..=self.end_port).collect()
        };
        if let Some(spec) = &self.exclude_ports {
            let excluded = ports::parse_ports(spec)?;
            list.retain(|p| excluded.binary_search(p).is_err());
        }
        if list.is_empty() {
            return Err(RustScanError::InvalidOption(
                "every port was excluded — nothing to scan".into(),
            ));
        }
        Ok(list)
    }

    /// Which format goes to stdout: the export flag given without a FILE.
    pub fn output_format(&self) -> OutputFormat {
        if self.json.as_deref() == Some("") {
            OutputFormat::Json
        } else if self.csv.as_deref() == Some("") {
            OutputFormat::Csv
        } else if self.html.as_deref() == Some("") {
            OutputFormat::Html
        } else {
            OutputFormat::Text
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> CliArgs {
        CliArgs::try_parse_from(std::iter::once("rustscan-rs").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn valid_configuration_passes() {
        assert!(parse(&["127.0.0.1"]).validate().is_ok());
    }

    #[test]
    fn default_ports_are_1_to_1024() {
        assert_eq!(
            parse(&["h"]).port_list().unwrap(),
            (1..=1024).collect::<Vec<_>>()
        );
    }

    #[test]
    fn port_spec_and_exclusions() {
        let a = parse(&["h", "-p", "20-25,80", "--exclude-ports", "22,23"]);
        assert_eq!(a.port_list().unwrap(), vec![20, 21, 24, 25, 80]);
        let a = parse(&["h", "--top-ports", "2"]);
        assert_eq!(a.port_list().unwrap(), vec![80, 443]);
    }

    #[test]
    fn excluding_everything_fails() {
        assert!(parse(&["h", "-p", "80", "--exclude-ports", "80"])
            .validate()
            .is_err());
    }

    #[test]
    fn ports_conflicts_with_range_flags() {
        let r = CliArgs::try_parse_from(["x", "h", "-p", "80", "--start-port", "1"]);
        assert!(r.is_err());
    }

    #[test]
    fn inverted_port_range_fails() {
        let err = parse(&["h", "--start-port", "1024", "--end-port", "1"])
            .validate()
            .unwrap_err();
        assert!(matches!(err, RustScanError::InvalidPortRange { .. }));
    }

    #[test]
    fn zero_start_port_fails() {
        let err = parse(&["h", "--start-port", "0"]).validate().unwrap_err();
        assert!(matches!(err, RustScanError::PortOutOfRange { .. }));
    }

    #[test]
    fn timeout_bounds() {
        assert!(matches!(
            parse(&["h", "--timeout", "0"]).validate().unwrap_err(),
            RustScanError::InvalidTimeout { .. }
        ));
        assert!(parse(&["h", "--timeout", &MAX_TIMEOUT_MS.to_string()])
            .validate()
            .is_ok());
        assert!(
            parse(&["h", "--timeout", &(MAX_TIMEOUT_MS + 1).to_string()])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn concurrency_bounds() {
        assert!(matches!(
            parse(&["h", "-c", "0"]).validate().unwrap_err(),
            RustScanError::InvalidConcurrency { .. }
        ));
        assert!(parse(&["h", "-c", &MAX_CONCURRENCY.to_string()])
            .validate()
            .is_ok());
        assert!(parse(&["h", "-c", &(MAX_CONCURRENCY + 1).to_string()])
            .validate()
            .is_err());
    }

    #[test]
    fn retries_and_rate_bounds() {
        assert!(parse(&["h", "--retries", "11"]).validate().is_err());
        assert!(parse(&["h", "--rate", "0"]).validate().is_err());
        assert!(parse(&["h", "--rate", "500", "--retries", "3"])
            .validate()
            .is_ok());
    }

    #[test]
    fn empty_target_fails() {
        assert!(matches!(
            parse(&["   "]).validate().unwrap_err(),
            RustScanError::InvalidTarget { .. }
        ));
        assert!(parse(&[]).validate().is_err());
        assert!(parse(&["-L", "targets.txt"]).validate().is_ok());
    }

    #[test]
    fn syn_and_nmap_validation() {
        assert!(parse(&["h", "--syn"]).validate().is_ok());
        assert!(parse(&["h", "--sS"]).syn);
        assert!(parse(&["h", "--syn", "--udp"]).validate().is_err());
        assert!(parse(&["h", "--syn", "--udp", "--tcp"]).validate().is_ok());
        assert!(parse(&["h", "--nmap"]).validate().is_ok());
        assert!(parse(&["h", "--nmap", "--json"]).validate().is_err());
        assert!(parse(&["h", "--nmap", "--json", "f.json"])
            .validate()
            .is_ok());
        assert_eq!(parse(&["h", "--nmap-args", "-sV -sC"]).nmap_args, "-sV -sC");
    }

    #[test]
    fn output_format_selection() {
        assert_eq!(parse(&["h"]).output_format(), OutputFormat::Text);
        assert_eq!(parse(&["h", "--json"]).output_format(), OutputFormat::Json);
        // A file export keeps text on stdout.
        assert_eq!(
            parse(&["h", "--json", "o.json"]).output_format(),
            OutputFormat::Text
        );
        // Several file exports at once are fine; two stdout formats are not.
        assert!(parse(&["h", "--json", "a", "--csv", "b", "--html", "c"])
            .validate()
            .is_ok());
        assert!(parse(&["h", "--json", "--csv"]).validate().is_err());
    }
}
