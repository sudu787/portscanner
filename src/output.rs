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
use crate::targets::ResolvedTarget;

// ─── Text Output ──────────────────────────────────────────────────────────────

pub fn print_text_multi(
    resolved: &ResolvedTarget,
    results: &[ScanResult],
    total_elapsed: Duration,
) {
    const BOLD:   &str = "\x1b[1m";
    const GREEN:  &str = "\x1b[32m";
    const RED:    &str = "\x1b[31m";
    const CYAN:   &str = "\x1b[36m";
    const YELLOW: &str = "\x1b[33m";
    const DIM:    &str = "\x1b[2m";
    const RESET:  &str = "\x1b[0m";

    let multi = results.len() > 1;

    if multi {
        // ── Multi-host header ─────────────────────────────────────────────
        println!();
        println!(
            "{BOLD}{CYAN}Scan Results — {}{RESET}",
            resolved.display_label()
        );
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
            println!("{BOLD}{CYAN}  ┌─ {}{RESET}", result.target);
        } else {
            println!();
            println!(
                "{BOLD}{CYAN}Scan Results — {} ({}){RESET}",
                resolved.spec, result.target
            );
        }

        println!("{CYAN}  ────────────────────────────────────────{RESET}");
        println!("  {YELLOW}Ports scanned :{RESET} {}", result.total_ports);
        println!(
            "  {YELLOW}Open ports    :{RESET} {}{}{}",
            if open.is_empty() { RED } else { GREEN },
            open.len(),
            RESET
        );
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
                "  {DIM}  {:<5} {:<3} {:<12} {}{RESET}",
                "PORT", "TLS", "SERVICE", "DESCRIPTION / BANNER"
            );
            println!("  {DIM}  {}{RESET}", "─".repeat(55));
            for pr in &open {
                let svc = pr.service;
                let tls_marker = if pr.is_tls { "🔒" } else { " " };
                let desc = match &pr.banner {
                    Some(b) => format!("{}{RESET}", b), // Banner overrides description if present
                    None    => format!("{}{RESET}", if svc.is_known() { svc.description } else { "" }),
                };

                let proto_str = match pr.protocol {
                    crate::service::Transport::Tcp => "tcp",
                    crate::service::Transport::Udp => "udp",
                    crate::service::Transport::TcpUdp => "tcp/udp",
                };

                println!(
                    "    {GREEN}▶{RESET}  {BOLD}{:<8}{RESET} {}   {CYAN}{:<12}{RESET} {DIM}{}",
                    format!("{}/{}", pr.port, proto_str),
                    tls_marker,
                    svc.name,
                    desc
                );
            }
        }
        println!();
    }
}

// ─── JSON Output ──────────────────────────────────────────────────────────────

pub fn print_json_multi(
    spec: &str,
    results: &[ScanResult],
    total_elapsed: Duration,
) -> Result<()> {
    let host_docs: Vec<_> = results
        .iter()
        .map(|r| {
            let open_ports: Vec<u16> = r.open_ports().map(|p| p.port).collect();
            let all_ports: Vec<_> = r
                .ports
                .iter()
                .map(|p| {
                    json!({
                        "port":        p.port,
                        "status":      match p.status {
                            PortStatus::Open         => "open",
                            PortStatus::Closed       => "closed",
                            PortStatus::Filtered     => "filtered",
                            PortStatus::OpenFiltered => "open|filtered",
                        },
                        "is_tls":      p.is_tls,
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
                "total_ports": r.total_ports,
                "open_count":  r.open_count(),
                "elapsed_ms":  r.elapsed.as_millis(),
                "open_ports":  open_ports,
                "all_ports":   all_ports,
            })
        })
        .collect();

    let doc = if results.len() == 1 {
        json!({
            "rustscan_rs": {
                "target":       spec,
                "resolved_ip":  results[0].target,
                "total_ports":  results[0].total_ports,
                "open_count":   results[0].open_count(),
                "elapsed_ms":   results[0].elapsed.as_millis(),
                "open_ports":   results[0].open_ports().map(|p| p.port).collect::<Vec<u16>>(),
                "all_ports":    host_docs[0]["all_ports"].clone(),
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

pub fn print_csv_multi(results: &[ScanResult]) {
    // Print standard CSV header
    println!("Host,Port,Status,TLS,Service,Banner");

    for r in results {
        // In CSV mode, it's typically best to only export open ports
        // to prevent generating massive files for full range scans.
        for p in r.open_ports() {
            let status = match p.status {
                PortStatus::Open         => "open",
                PortStatus::Closed       => "closed",
                PortStatus::Filtered     => "filtered",
                PortStatus::OpenFiltered => "open|filtered",
            };
            
            let tls_str = if p.is_tls { "true" } else { "false" };
            
            // Escape quotes inside banners
            let banner = p.banner.as_deref().unwrap_or("");
            let banner_escaped = banner.replace('"', "\"\"");

            let proto_str = match p.protocol {
                crate::service::Transport::Tcp => "tcp",
                crate::service::Transport::Udp => "udp",
                crate::service::Transport::TcpUdp => "tcp/udp",
            };

            println!(
                "{},{}/{},{},{},{},\"{}\"",
                r.target, p.port, proto_str, status, tls_str, p.service.name, banner_escaped
            );
        }
    }
}

// ─── HTML Output ──────────────────────────────────────────────────────────────

pub fn print_html_multi(spec: &str, results: &[ScanResult], elapsed: Duration) {
    println!("<!DOCTYPE html>");
    println!("<html lang=\"en\">");
    println!("<head>");
    println!("  <meta charset=\"UTF-8\">");
    println!("  <title>Scan Report: {}</title>", spec);
    println!("  <style>");
    println!("    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; color: #333; background: #f9f9f9; }}");
    println!("    h1, h2 {{ color: #111; }}");
    println!("    .summary {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 30px; }}");
    println!("    .host-block {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 30px; }}");
    println!("    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}");
    println!("    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #eee; }}");
    println!("    th {{ background: #fdfdfd; font-weight: 600; color: #555; }}");
    println!("    .badge-open {{ background: #e6f4ea; color: #1e8e3e; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}");
    println!("    .badge-tls {{ background: #fce8e6; color: #d93025; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; margin-left: 5px; }}");
    println!("    code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }}");
    println!("  </style>");
    println!("</head>");
    println!("<body>");
    
    // Summary block
    let total_hosts = results.len();
    let total_open: usize = results.iter().map(|r| r.open_count()).sum();
    
    println!("  <h1>Rustscan-rs Report</h1>");
    println!("  <div class=\"summary\">");
    println!("    <p><strong>Target:</strong> {}</p>", spec);
    println!("    <p><strong>Hosts Scanned:</strong> {}</p>", total_hosts);
    println!("    <p><strong>Total Open Ports:</strong> {}</p>", total_open);
    println!("    <p><strong>Total Elapsed Time:</strong> {:.2}s</p>", elapsed.as_secs_f64());
    println!("  </div>");

    // Per-host blocks
    for result in results {
        println!("  <div class=\"host-block\">");
        println!("    <h2>Host: {}</h2>", result.target);
        
        if result.open_count() == 0 {
            println!("    <p>No open ports found.</p>");
        } else {
            println!("    <table>");
            println!("      <thead>");
            println!("        <tr>");
            println!("          <th>Port</th>");
            println!("          <th>Service</th>");
            println!("          <th>Description / Banner</th>");
            println!("        </tr>");
            println!("      </thead>");
            println!("      <tbody>");
            
            for p in result.open_ports() {
                println!("        <tr>");
                let proto_str = match p.protocol {
                    crate::service::Transport::Tcp => "tcp",
                    crate::service::Transport::Udp => "udp",
                    crate::service::Transport::TcpUdp => "tcp/udp",
                };
                print!("          <td><span class=\"badge-open\">{}/{}</span>", p.port, proto_str);
                if p.is_tls {
                    print!("<span class=\"badge-tls\">TLS</span>");
                }
                println!("</td>");
                
                println!("          <td>{}</td>", p.service.name);
                
                print!("          <td>");
                if let Some(ref banner) = p.banner {
                    // Primitive escaping for HTML
                    let safe_banner = banner.replace('<', "&lt;").replace('>', "&gt;");
                    print!("<code>{}</code>", safe_banner);
                } else {
                    print!("{}", p.service.description);
                }
                println!("</td>");
                println!("        </tr>");
            }
            
            println!("      </tbody>");
            println!("    </table>");
        }
        
        println!("  </div>");
    }

    println!("</body>");
    println!("</html>");
}
