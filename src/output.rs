/// output.rs — Rendering engines for scan results
///
/// ═══════════════════════════════════════════════════════════════════════════
/// SUPPORTED FORMATS
/// ═══════════════════════════════════════════════════════════════════════════
///
/// - Text: Human-readable terminal output with ANSI colours.
/// - JSON: Machine-readable schema (single and multi-host).
/// - CSV:  Comma-separated values for spreadsheet tools.
/// - HTML: Self-contained graphical report.
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, to_string_pretty};

use crate::scanner::{PortStatus, ScanResult};

// ─── Colours ──────────────────────────────────────────────────────────────────

/// Colour only when writing to a terminal and `NO_COLOR` is unset
/// (<https://no-color.org>). Piped or redirected output stays plain, so it
/// works with grep/awk and in files.
pub fn use_color(stream_is_terminal: bool) -> bool {
    stream_is_terminal && std::env::var_os("NO_COLOR").is_none()
}

/// `code` when colour is on, else "".
pub fn paint(on: bool, code: &'static str) -> &'static str {
    if on {
        code
    } else {
        ""
    }
}

// ─── Text Output ──────────────────────────────────────────────────────────────

#[allow(non_snake_case)]
pub fn print_text_multi(label: &str, results: &[ScanResult], total_elapsed: Duration) {
    use std::io::IsTerminal;
    let on = use_color(std::io::stdout().is_terminal());
    let (BOLD, GREEN, RED, CYAN, YELLOW, DIM, RESET) = (
        paint(on, "\x1b[1m"),
        paint(on, "\x1b[32m"),
        paint(on, "\x1b[31m"),
        paint(on, "\x1b[36m"),
        paint(on, "\x1b[33m"),
        paint(on, "\x1b[2m"),
        paint(on, "\x1b[0m"),
    );

    let multi = results.len() > 1;

    if multi {
        // ── Multi-host header ─────────────────────────────────────────────
        println!();
        println!("{BOLD}{CYAN}Scan Results — {}{RESET}", label);
        println!("{CYAN}══════════════════════════════════════════════════{RESET}");
        println!("  {YELLOW}Hosts scanned  :{RESET} {}", results.len());
        let hosts_with_open = results.iter().filter(|r| r.open_count() > 0).count();
        println!(
            "  {YELLOW}Hosts with open:{RESET} {}{}{}",
            if hosts_with_open == 0 { RED } else { GREEN },
            hosts_with_open,
            RESET
        );
        println!(
            "  {YELLOW}Total elapsed  :{RESET} {:.2}s",
            total_elapsed.as_secs_f64()
        );
        println!("{CYAN}══════════════════════════════════════════════════{RESET}");
        println!();
    }

    // ── Per-host blocks ───────────────────────────────────────────────────
    for result in results {
        let open: Vec<_> = result.open_ports().collect();

        if multi {
            if let Some(h) = &result.hostname {
                println!("{BOLD}{CYAN}  ┌─ {} ({}){RESET}", h, result.target);
            } else {
                println!("{BOLD}{CYAN}  ┌─ {}{RESET}", result.target);
            }
        } else {
            println!();
            if let Some(h) = &result.hostname {
                println!(
                    "{BOLD}{CYAN}Scan Results — {} ({} / {}){RESET}",
                    label, h, result.target
                );
            } else {
                println!(
                    "{BOLD}{CYAN}Scan Results — {} ({}){RESET}",
                    label, result.target
                );
            }
        }

        println!("{CYAN}  ────────────────────────────────────────{RESET}");
        println!("  {YELLOW}Ports scanned :{RESET} {}", result.total_ports);
        println!(
            "  {YELLOW}Open ports    :{RESET} {}{}{}",
            if result.open_count() == 0 { RED } else { GREEN },
            result.open_count(),
            RESET
        );
        println!(
            "  {YELLOW}Closed/filt.  :{RESET} {} / {}",
            result.closed, result.filtered
        );
        if result.errors > 0 {
            println!(
                "  {YELLOW}Probe errors  :{RESET} {RED}{} (results incomplete){RESET}",
                result.errors
            );
        }
        if !multi {
            println!(
                "  {YELLOW}Elapsed       :{RESET} {:.2}s",
                result.elapsed.as_secs_f64()
            );
        }
        println!("{CYAN}  ────────────────────────────────────────{RESET}");

        if open.is_empty() {
            println!("  {DIM}No open ports in range.{RESET}");
        } else {
            println!("  {BOLD}{GREEN}OPEN PORTS:{RESET}");
            // Column widths: port (5), tls (3), service name (12), description / banner
            println!(
                "  {DIM}  {:<5} {:<3} {:<12} DESCRIPTION / BANNER{RESET}",
                "PORT", "TLS", "SERVICE"
            );
            println!("  {DIM}  {}{RESET}", "─".repeat(55));
            for pr in &open {
                let svc = pr.service;
                let tls_marker = if pr.tls { "🔒" } else { " " };
                let ambiguous = if pr.status == PortStatus::OpenFiltered {
                    "(open|filtered) "
                } else {
                    ""
                };
                let desc = match &pr.banner {
                    Some(b) => format!("{}{RESET}", b), // Banner overrides description if present
                    None => format!(
                        "{}{RESET}",
                        if svc.is_known() { svc.description } else { "" }
                    ),
                };

                let proto_str = match pr.protocol {
                    crate::service::Transport::Tcp => "tcp",
                    crate::service::Transport::Udp => "udp",
                    crate::service::Transport::TcpUdp => "tcp/udp",
                };

                println!(
                    "    {GREEN}▶{RESET}  {BOLD}{:<8}{RESET} {}   {CYAN}{:<12}{RESET} {DIM}{ambiguous}{desc}",
                    format!("{}/{}", pr.port, proto_str),
                    tls_marker,
                    svc.name,
                );

                // Print TLS Certificate if grabbed
                if let Some(cert) = &pr.tls_cert {
                    println!(
                        "        {DIM}└─ TLS Cert: {} ({}) — Expires: {}{RESET}",
                        cert.subject, cert.issuer, cert.not_after
                    );
                    if cert.expired {
                        println!("        {RED}⚠  certificate is expired / not yet valid{RESET}");
                    }
                    if cert.self_signed {
                        println!("        {YELLOW}⚠  certificate is self-signed{RESET}");
                    }
                }
                if let Some(v) = pr.legacy_tls {
                    println!("        {RED}⚠  accepts deprecated {v}{RESET}");
                }
            }
        }
        println!();
    }
}

// ─── JSON Output ──────────────────────────────────────────────────────────────

/// `multi`: the user asked for more than one host (CIDR, several targets, `-L`).
/// It picks the document shape, so the schema does not change when discovery
/// happens to leave a single host up.
pub fn print_json_multi(
    spec: &str,
    results: &[ScanResult],
    total_elapsed: Duration,
    multi: bool,
) -> Result<()> {
    let host_docs: Vec<_> = results
        .iter()
        .map(|r| {
            let open_ports: Vec<u16> = r.open_ports().map(|p| p.port).collect();
            // Only open / open|filtered ports are retained; closed and
            // filtered are reported as counts.
            let ports: Vec<_> = r
                .ports
                .iter()
                .map(|p| {
                    json!({
                        "port":        p.port,
                        "protocol":    if p.protocol == crate::service::Transport::Udp { "udp" } else { "tcp" },
                        "status":      p.status.as_str(),
                        "tls":         p.tls,
                        "tls_cert":    p.tls_cert,
                        "legacy_tls":  p.legacy_tls,
                        "banner":      p.banner,
                        "service": {
                            "name":        p.service.name,
                            "transport":   format!("{:?}", p.service.transport),
                            "description": p.service.description,
                            "known":       p.service.is_known(),
                        },
                    })
                })
                .collect();

            json!({
                "host":        r.target,
                "hostname":    r.hostname,
                "total_ports": r.total_ports,
                "open_count":  r.open_count(),
                "elapsed_ms":  r.elapsed.as_millis(),
                "closed_count":   r.closed,
                "filtered_count": r.filtered,
                "error_count":    r.errors,
                "open_ports":  open_ports,
                "ports":       ports,
            })
        })
        .collect();

    let doc = if !multi && results.len() == 1 {
        json!({
            "rustscan_rs": {
                "target":       spec,
                "resolved_ip":  results[0].target,
                "hostname":     results[0].hostname,
                "total_ports":  results[0].total_ports,
                "open_count":   results[0].open_count(),
                "elapsed_ms":   results[0].elapsed.as_millis(),
                "closed_count":   results[0].closed,
                "filtered_count": results[0].filtered,
                "error_count":    results[0].errors,
                "open_ports":   host_docs[0]["open_ports"].clone(),
                "ports":        host_docs[0]["ports"].clone(),
            }
        })
    } else {
        let total_open: usize = results.iter().map(|r| r.open_count()).sum();
        json!({
            "rustscan_rs": {
                "target_spec":       spec,
                "hosts_scanned":     results.len(),
                "total_open_ports":  total_open,
                "total_elapsed_ms":  total_elapsed.as_millis(),
                "hosts":             host_docs,
            }
        })
    };

    println!("{}", to_string_pretty(&doc)?);
    Ok(())
}

// ─── CSV Output ───────────────────────────────────────────────────────────────

/// CSV to stdout. Only open / open|filtered ports are listed. The `csv` crate
/// handles quoting; `csv_safe` neutralises spreadsheet formulas in
/// attacker-controlled fields (banner, PTR hostname).
pub fn print_csv_multi(results: &[ScanResult]) -> Result<()> {
    use crate::export::csv_safe;

    let mut wtr = csv::Writer::from_writer(std::io::stdout());
    wtr.write_record([
        "Host", "Hostname", "Port", "Status", "TLS", "Service", "Banner",
    ])?;

    for r in results {
        for p in r.open_ports() {
            let status = match p.status {
                PortStatus::Open => "open",
                PortStatus::Closed => "closed",
                PortStatus::Filtered => "filtered",
                PortStatus::OpenFiltered => "open|filtered",
            };
            let proto_str = match p.protocol {
                crate::service::Transport::Tcp => "tcp",
                crate::service::Transport::Udp => "udp",
                crate::service::Transport::TcpUdp => "tcp/udp",
            };
            wtr.write_record([
                r.target.as_str(),
                &csv_safe(r.hostname.as_deref().unwrap_or("")),
                &format!("{}/{}", p.port, proto_str),
                status,
                if p.tls { "true" } else { "false" },
                p.service.name,
                &csv_safe(p.banner.as_deref().unwrap_or("")),
            ])?;
        }
    }
    wtr.flush()?;
    Ok(())
}
