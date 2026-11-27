//! main.rs — Entry point for rustscan-rs
//!
//!   targets (args / -L file) ─► expand CIDRs, resolve hostnames, apply --exclude
//!     ─► host discovery (multi-host only, unless --no-discovery)
//!     ─► scanner::scan_targets (one shared concurrency budget)
//!     ─► stdout format (text/json/csv/html) + any file exports

mod cli;
pub mod dns;
pub mod errors;
pub mod export;
pub mod output;
pub mod ports;
pub mod probes;
pub mod report;
pub mod scanner;
pub mod service;
pub mod syn;
pub mod targets;
pub mod tls;

use std::io::BufRead;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use ipnetwork::IpNetwork;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use cli::{CliArgs, OutputFormat};
use scanner::{ScanConfig, Target};
use targets::{parse_target, TargetKind};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args = CliArgs::parse();
    args.validate()
        .context("invalid arguments — run with --help for usage")?;
    init_tracing(args.verbose);

    let ports = args.port_list()?;
    let specs = collect_specs(&args)?;
    let label = specs.join(", ");
    let mut targets = expand_targets(&specs, &args).await?;
    let multi = targets.len() > 1;
    if targets.is_empty() {
        bail!("no targets left to scan (all excluded or unresolvable)");
    }

    let config = ScanConfig {
        ports,
        timeout: Duration::from_millis(args.timeout),
        concurrency: args.concurrency,
        retries: args.retries,
        rate: args.rate,
        randomize: !args.sequential,
        banner: args.banner,
        tls: args.tls,
        tcp: args.do_tcp(),
        udp: args.do_udp(),
        resolve_dns: args.resolve_dns,
        live: !args.quiet && args.output_format() == OutputFormat::Text,
    };

    print_banner(&args, &label, &targets, &config);
    let start = Instant::now();

    let discovery = targets.len() > 1 && !args.no_discovery;
    let before = targets.len();
    let say_up = |up: usize| {
        info!(up, total = before, "host discovery done");
        if args.output_format() == OutputFormat::Text && !args.quiet {
            eprintln!("Host discovery: {up}/{before} hosts up (use --no-discovery to scan all)");
        }
    };

    // SYN mode with an enlarged raw send buffer (root) discovers inline:
    // SYNs are cheap, so scan every host and drop the ones that never
    // answered. Otherwise SYNs to dead local hosts would pile up in ARP
    // queues and crowd out live ones, so ping with connects first.
    let inline = args.syn && discovery && syn::inline_discovery_ok();
    if discovery && !inline {
        targets = scanner::discover(targets, &config, scanner::DISCOVERY_PORTS).await;
        say_up(targets.len());
    }
    let results = if args.syn {
        let mut results = scanner::syn_scan_targets(&targets, &config).await?;
        if inline {
            results.retain(|r| !r.ports.is_empty() || r.closed > 0);
            say_up(results.len());
        }
        results
    } else {
        scanner::scan_targets(&targets, &config).await
    };
    let elapsed = start.elapsed();

    match args.output_format() {
        OutputFormat::Json => output::print_json_multi(&label, &results, elapsed, multi)?,
        OutputFormat::Csv => output::print_csv_multi(&results)?,
        OutputFormat::Html => report::generate_html_report("", &results, elapsed)?,
        OutputFormat::Text => output::print_text_multi(&label, &results, elapsed),
    }

    for (flag, write) in [
        (
            &args.json,
            export::export_json as fn(&str, &[scanner::ScanResult]) -> _,
        ),
        (&args.csv, export::export_csv),
    ] {
        if let Some(path) = flag.as_deref().filter(|p| !p.is_empty()) {
            write(path, &results).with_context(|| format!("writing {path}"))?;
            info!("exported {path}");
        }
    }
    if let Some(path) = args.html.as_deref().filter(|p| !p.is_empty()) {
        report::generate_html_report(path, &results, elapsed)
            .with_context(|| format!("writing {path}"))?;
        info!("exported {path}");
    }
    if args.nmap {
        run_nmap(&results, &args.nmap_args)?;
    }
    Ok(())
}

/// Hand the open TCP ports to nmap for deep version detection: the fast
/// sweep finds the ports, nmap only spends time on the few that matter.
/// `RUSTSCAN_NMAP` overrides the nmap binary (used by tests).
fn run_nmap(results: &[scanner::ScanResult], nmap_args: &str) -> Result<()> {
    let bin = std::env::var("RUSTSCAN_NMAP").unwrap_or_else(|_| "nmap".into());
    for r in results {
        let ports: Vec<String> = r
            .ports
            .iter()
            .filter(|p| {
                p.status == scanner::PortStatus::Open && p.protocol == service::Transport::Tcp
            })
            .map(|p| p.port.to_string())
            .collect();
        if ports.is_empty() {
            continue;
        }
        let mut cmd = std::process::Command::new(&bin);
        cmd.args(nmap_args.split_whitespace())
            .arg("-Pn") // we already know the host is up
            .arg("-p")
            .arg(ports.join(","))
            .arg(&r.target);
        eprintln!(
            "\n[nmap] {bin} {nmap_args} -Pn -p {} {}",
            ports.join(","),
            r.target
        );
        let status = cmd
            .status()
            .with_context(|| format!("could not run `{bin}` — is nmap installed and on PATH?"))?;
        if !status.success() {
            warn!(host = %r.target, %status, "nmap exited with an error");
        }
    }
    Ok(())
}

// ─── Targets ──────────────────────────────────────────────────────────────────

/// Positional targets plus lines from `-L FILE` (`-` = stdin).
fn collect_specs(args: &CliArgs) -> Result<Vec<String>> {
    let mut specs: Vec<String> = args
        .targets
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if let Some(path) = &args.target_file {
        let reader: Box<dyn BufRead> = if path == "-" {
            Box::new(std::io::stdin().lock())
        } else {
            Box::new(std::io::BufReader::new(
                std::fs::File::open(path).with_context(|| format!("opening {path}"))?,
            ))
        };
        for line in reader.lines() {
            let line = line?;
            let line = line.split('#').next().unwrap_or("").trim();
            specs.extend(line.split_whitespace().map(String::from));
        }
    }
    if specs.is_empty() {
        bail!("no targets given");
    }
    Ok(specs)
}

/// Expand CIDRs, resolve hostnames, drop `--exclude`d addresses and duplicates.
async fn expand_targets(specs: &[String], args: &CliArgs) -> Result<Vec<Target>> {
    let excluded: Vec<IpNetwork> = args
        .exclude
        .iter()
        .map(|e| e.trim().parse::<IpNetwork>())
        .collect::<std::result::Result<_, _>>()
        .context("--exclude takes IPs or CIDR ranges")?;

    let mut out: Vec<Target> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |t: Target| {
        if !excluded.iter().any(|n| n.contains(t.addr)) && seen.insert(t.addr) {
            out.push(t);
        }
    };

    for spec in specs {
        let parsed =
            parse_target(spec).with_context(|| format!("could not parse target '{spec}'"))?;
        match parsed.kind {
            TargetKind::Hostname(host) => {
                let addrs = match dns::resolve_host(&host).await {
                    Ok(a) if !a.is_empty() => a,
                    Ok(_) | Err(_) if specs.len() > 1 => {
                        warn!(host = %host, "DNS resolution failed — skipping");
                        continue;
                    }
                    Ok(_) => bail!("DNS returned no addresses for '{host}'"),
                    Err(e) => bail!("DNS resolution failed for '{host}': {e}"),
                };
                let picked: Vec<IpAddr> = if args.all_addrs {
                    addrs
                } else {
                    if addrs.len() > 1 {
                        info!(host = %host, using = %addrs[0], others = addrs.len() - 1, "host has several addresses (use --all-addrs to scan all)");
                    }
                    vec![addrs[0]]
                };
                for addr in picked {
                    push(Target {
                        addr,
                        name: Some(host.clone()),
                    });
                }
            }
            _ => parsed.addrs.into_iter().for_each(|a| push(Target::ip(a))),
        }
    }
    Ok(out)
}

// ─── Tracing ──────────────────────────────────────────────────────────────────

fn init_tracing(verbosity: u8) {
    let default_level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .compact()
        .init();
}

// ─── Startup banner ───────────────────────────────────────────────────────────

#[allow(non_snake_case)]
fn print_banner(args: &CliArgs, label: &str, targets: &[Target], config: &ScanConfig) {
    if args.output_format() != OutputFormat::Text || args.quiet {
        return;
    }
    use std::io::IsTerminal;
    let on = output::use_color(std::io::stderr().is_terminal());
    let (BOLD, CYAN, YELLOW, RESET) = (
        output::paint(on, "\x1b[1m"),
        output::paint(on, "\x1b[36m"),
        output::paint(on, "\x1b[33m"),
        output::paint(on, "\x1b[0m"),
    );

    let ports = &config.ports;
    let port_desc = if ports.len() == 1 {
        ports[0].to_string()
    } else if ports.len() == ports[ports.len() - 1] as usize - ports[0] as usize + 1 {
        format!(
            "{}-{} ({} ports)",
            ports[0],
            ports[ports.len() - 1],
            ports.len()
        )
    } else {
        format!("{} ports", ports.len())
    };

    eprintln!();
    eprintln!(
        "{BOLD}{CYAN}rustscan-rs{RESET} v{} — async port scanner",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("{CYAN}─────────────────────────────────────────────────{RESET}");
    eprintln!(
        "  {YELLOW}Targets     :{RESET} {label} ({} host{})",
        targets.len(),
        if targets.len() == 1 { "" } else { "s" }
    );
    eprintln!("  {YELLOW}Ports       :{RESET} {port_desc}");
    eprintln!(
        "  {YELLOW}Timing      :{RESET} {} ms timeout, {} retries, {} in flight{}",
        args.timeout,
        args.retries,
        args.concurrency,
        args.rate
            .map(|r| format!(", {r} probes/s"))
            .unwrap_or_default()
    );
    let mut extras = vec![if args.do_udp() && args.do_tcp() {
        "tcp+udp"
    } else if args.do_udp() {
        "udp"
    } else {
        "tcp"
    }];
    if args.banner {
        extras.push("banner/service-id");
    }
    if args.tls {
        extras.push("tls+legacy-tls");
    }
    if args.syn {
        extras.push("syn (half-open)");
    }
    if args.nmap {
        extras.push("nmap hand-off");
    }
    if args.resolve_dns {
        extras.push("rdns");
    }
    eprintln!("  {YELLOW}Probes      :{RESET} {}", extras.join(", "));
    eprintln!("{CYAN}─────────────────────────────────────────────────{RESET}");

    if args.concurrency > 10_000 {
        warn!("concurrency is very high — make sure your OS file-descriptor limit allows it");
    }
}
