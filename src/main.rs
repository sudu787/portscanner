/// main.rs — Entry point for rustscan-rs
///
/// Responsibilities:
///   1. Parse and validate CLI arguments.
///   2. Initialise the tracing subscriber.
///   3. Expand the target spec (IP / CIDR / hostname) via `targets::parse_target`.
///   4. For each resolved IP, build a `ScanConfig` and drive `scan_host()`.
///   5. Print results to stdout (text or JSON).
///
/// Multi-host workflow (CIDR):
///   "192.168.1.0/24"
///     │
///     └─ targets::parse_target  →  ResolvedTarget { addrs: [.0, .1, ..., .255] }
///          │
///          └─ for each addr → scan_host() → ScanResult
///               │
///               └─ collect Vec<ScanResult> → print_text_multi / print_json_multi

mod cli;
pub mod dns;
pub mod errors;
pub mod export;
pub mod output;
pub mod probes;
pub mod report;
pub mod scanner;
pub mod service;
pub mod targets;
pub mod tls;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use cli::{CliArgs, OutputFormat};
use scanner::{scan_host, ScanConfig, ScanResult};
use targets::{parse_target, ResolvedTarget, TargetKind};

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Install default crypto provider for rustls (fixes panic when multiple features are enabled)
    rustls::crypto::ring::default_provider().install_default().ok();

    // ── 1. Parse & validate ───────────────────────────────────────────────
    let args = CliArgs::parse();
    args.validate()
        .context("invalid arguments — run with --help for usage")?;

    // ── 2. Initialise tracing ─────────────────────────────────────────────
    init_tracing(args.verbose);

    debug!(
        target      = %args.target,
        start_port  = args.start_port,
        end_port    = args.end_port,
        timeout_ms  = args.timeout,
        concurrency = args.concurrency,
        "effective configuration"
    );

    // ── 3. Parse target spec (synchronous: IP / CIDR / hostname) ─────────
    let mut resolved = parse_target(&args.target)
        .with_context(|| format!("could not parse target '{}'", args.target))?;

    // ── 4. DNS-resolve hostnames (async) ──────────────────────────────────
    if let TargetKind::Hostname(_) = &resolved.kind {
        let addr = resolve_hostname(&args.target)
            .await
            .with_context(|| format!("DNS resolution failed for '{}'", args.target))?;
        info!(hostname = %args.target, resolved = %addr, "hostname resolved");
        resolved = resolved.with_addr(addr);
    }

    // ── 5. Print startup banner ───────────────────────────────────────────
    print_banner(&args, &resolved);

    // ── 6. Scan each address in the target list ───────────────────────────
    let port_count = (args.end_port as u32) - (args.start_port as u32) + 1;
    let total_start = Instant::now();
    let mut all_results: Vec<ScanResult> = Vec::with_capacity(resolved.addrs.len());

    for (idx, &addr) in resolved.addrs.iter().enumerate() {
        if resolved.is_multi_host() {
            info!(
                host  = %addr,
                idx   = idx + 1,
                total = resolved.addrs.len(),
                "scanning host"
            );
        }

        let config = Arc::new(ScanConfig {
            addr,
            start_port:  args.start_port,
            end_port:    args.end_port,
            timeout:     Duration::from_millis(args.timeout),
            concurrency: args.concurrency,
            banner:      args.banner,
            tls:         args.tls,
            tcp:         args.do_tcp(),
            udp:         args.do_udp(),
            resolve_dns: args.resolve_dns,
        });

        info!(
            "scanning {} ports on {} (concurrency={}, timeout={}ms)",
            port_count, addr, args.concurrency, args.timeout
        );

        let result = scan_host(config)
            .await
            .with_context(|| format!("scan failed for {addr}"))?;

        all_results.push(result);
    }

    let total_elapsed = total_start.elapsed();

    // ── 7. Emit results ───────────────────────────────────────────────────
    match args.output_format() {
        OutputFormat::Json => output::print_json_multi(&args.target, &all_results, total_elapsed)?,
        OutputFormat::Csv  => output::print_csv_multi(&all_results),
        OutputFormat::Html => report::generate_html_report("", &all_results, total_elapsed)?,
        OutputFormat::Text => output::print_text_multi(&resolved, &all_results, total_elapsed),
    }

    // ── 5. File Export ───────────────────────────────────────────────────
    if let Some(path) = &args.json {
        if !path.is_empty() {
            export::export_json(path, &all_results)?;
            info!("Exported JSON to {}", path);
        }
    }
    
    if let Some(path) = &args.csv {
        if !path.is_empty() {
            export::export_csv(path, &all_results)?;
            info!("Exported CSV to {}", path);
        }
    }

    if let Some(path) = &args.html {
        if !path.is_empty() {
            report::generate_html_report(path, &all_results, total_elapsed)?;
            info!("Exported HTML report to {}", path);
        }
    }

    Ok(())
}

// ─── DNS resolution ───────────────────────────────────────────────────────────

/// Resolve a hostname to an `IpAddr` using a blocking DNS lookup on Tokio's
/// blocking thread-pool, so the async executor is never stalled.
async fn resolve_hostname(hostname: &str) -> Result<IpAddr> {
    let lookup = format!("{hostname}:0"); // port 0 = dummy for ToSocketAddrs
    let lookup_owned = lookup.clone();

    let addrs = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        lookup_owned
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).collect::<Vec<_>>())
    })
    .await
    .context("DNS resolver panicked")?
    .with_context(|| format!("DNS lookup failed for '{lookup}'"))?;

    let fallback = addrs.first().copied();
    addrs
        .into_iter()
        .find(|ip| ip.is_ipv4())
        .or(fallback)
        .context("DNS returned no addresses")
}

// ─── End of output handlers ───────────────────────────────────────────────────

// ─── Tracing initialiser ──────────────────────────────────────────────────────

fn init_tracing(verbosity: u8) {
    let default_level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .compact()
        .init();

    debug!("tracing initialised at level '{default_level}'");
}

// ─── Startup banner ───────────────────────────────────────────────────────────

fn print_banner(args: &CliArgs, resolved: &ResolvedTarget) {
    if args.output_format() == OutputFormat::Json {
        return;
    }

    const BOLD:   &str = "\x1b[1m";
    const CYAN:   &str = "\x1b[36m";
    const GREEN:  &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    const RESET:  &str = "\x1b[0m";

    eprintln!();
    eprintln!(
        "{BOLD}{CYAN}rustscan-rs{RESET} v{} — high-performance async port scanner",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("{CYAN}─────────────────────────────────────────────────{RESET}");
    eprintln!("  {YELLOW}Target      :{RESET} {}", resolved.display_label());
    eprintln!("  {YELLOW}Port range  :{RESET} {}–{}", args.start_port, args.end_port);
    eprintln!("  {YELLOW}Timeout     :{RESET} {} ms", args.timeout);
    eprintln!("  {YELLOW}Concurrency :{RESET} {} tasks", args.concurrency);

    let mut extras = Vec::new();
    if args.banner      { extras.push("banner-grab"); }
    if args.resolve_dns { extras.push("dns-resolve"); }
    if args.tls         { extras.push("tls-probe"); }
    if !extras.is_empty() {
        eprintln!("  {YELLOW}Probes      :{RESET} {}", extras.join(", "));
    }

    let fmt_label = match args.output_format() {
        OutputFormat::Text => "text (default)",
        OutputFormat::Json => "json",
        OutputFormat::Csv  => "csv",
        OutputFormat::Html => "html",
    };
    eprintln!("  {YELLOW}Output      :{RESET} {fmt_label}");

    if args.verbose == 0 && args.output_format() == OutputFormat::Text {
        eprintln!("\n  {GREEN}hint:{RESET} use -v for informational logging, -vv for debug");
    }

    eprintln!("{CYAN}─────────────────────────────────────────────────{RESET}");
    eprintln!();

    if args.concurrency > 10_000 {
        warn!(
            concurrency = args.concurrency,
            "concurrency is very high — ensure your OS file-descriptor limits are raised"
        );
    }

    if resolved.is_multi_host() {
        warn!(
            hosts = resolved.addrs.len(),
            "multi-host scan — {} sequential host scans will be performed",
            resolved.addrs.len()
        );
    }
}
