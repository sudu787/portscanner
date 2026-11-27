//! End-to-end tests: run the real `rustscan-rs` binary against local TCP,
//! UDP and TLS servers started by the test, and check what it reports.
//! Everything is on loopback, so this works offline and in CI.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn scanner() -> Command {
    let mut c = Command::cargo_bin("rustscan-rs").unwrap();
    c.timeout(Duration::from_secs(60));
    c
}

/// Run a scan with `--json` on stdout and return the `rustscan_rs` document.
fn scan_json(args: &[&str]) -> Value {
    let out = scanner().args(args).arg("--json").assert().success();
    let doc: Value = serde_json::from_slice(&out.get_output().stdout).expect("stdout is JSON");
    doc["rustscan_rs"].clone()
}

/// TCP server that, per connection, optionally waits for the client to
/// speak first and then sends `reply`.
fn serve_tcp(reply: &'static [u8], client_speaks_first: bool) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            thread::spawn(move || {
                if client_speaks_first {
                    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
                    let mut buf = [0u8; 512];
                    if !matches!(s.read(&mut buf), Ok(n) if n > 0) {
                        return; // a plain connect probe: no request
                    }
                }
                let _ = s.write_all(reply);
                thread::sleep(Duration::from_millis(200));
            });
        }
    });
    port
}

/// A port with nothing listening on it.
fn closed_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// UDP server that answers every datagram.
fn serve_udp() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((_, from)) = s.recv_from(&mut buf) {
            let _ = s.send_to(b"pong", from);
        }
    });
    port
}

/// TLS 1.2/1.3 server with a fresh self-signed certificate.
fn serve_tls() -> u16 {
    serve_tls_with(None)
}

/// TLS server that, after the handshake, answers any request with `reply`.
fn serve_tls_with(reply: Option<&'static [u8]>) -> u16 {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(vec!["e2e.test".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let cfg = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)
            .unwrap(),
    );
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let cfg = Arc::clone(&cfg);
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(3))).ok();
                let mut conn = rustls::ServerConnection::new(cfg).unwrap();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut s).is_err() {
                        return;
                    }
                }
                if let Some(reply) = reply {
                    let mut buf = [0u8; 512];
                    let _ = conn.complete_io(&mut s); // read the request
                    let _ = conn.reader().read(&mut buf);
                    let _ = conn.writer().write_all(reply);
                }
                let _ = conn.complete_io(&mut s);
            });
        }
    });
    port
}

fn port_entry(doc: &Value, port: u16) -> Value {
    doc["ports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["port"] == port)
        .unwrap_or_else(|| panic!("port {port} not reported: {doc:#}"))
        .clone()
}

// ── Input validation ──────────────────────────────────────────────────────────

#[test]
fn rejects_invalid_input() {
    for args in [
        vec!["127.0.0.1", "--start-port", "0"],
        vec!["127.0.0.1", "--end-port", "65536"],
        vec!["127.0.0.1", "--start-port", "100", "--end-port", "50"],
        vec!["192.168.1.0/35"],
        vec!["127.0.0.1", "-p", "10-5"],
        vec!["127.0.0.1", "-p", "80", "--exclude-ports", "80"],
        vec!["127.0.0.1", "--retries", "99"],
        vec!["127.0.0.1", "--json", "--csv"],
        vec![],
    ] {
        scanner()
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::is_empty().not());
    }
}

// ── Core scanning ─────────────────────────────────────────────────────────────

#[test]
fn reports_open_and_counts_closed_tcp() {
    let open = serve_tcp(b"", false);
    let closed = closed_tcp_port();
    let spec = format!("{open},{closed}");
    let doc = scan_json(&["127.0.0.1", "-p", &spec, "--timeout", "2500"]);

    assert_eq!(doc["total_ports"], 2);
    assert_eq!(doc["open_count"], 1);
    assert_eq!(port_entry(&doc, open)["status"], "open");
    // Closed ports are counted, not listed.
    assert_eq!(doc["ports"].as_array().unwrap().len(), 1);
    let not_open = doc["closed_count"].as_u64().unwrap() + doc["filtered_count"].as_u64().unwrap();
    assert_eq!(not_open, 1);
    assert_eq!(doc["error_count"], 0);
}

#[test]
fn hostname_target_resolves_and_is_reported() {
    let open = serve_tcp(b"", false);
    let doc = scan_json(&["localhost", "-p", &open.to_string()]);
    assert_eq!(doc["hostname"], "localhost");
    assert!(doc["resolved_ip"].as_str().unwrap().len() > 2);
}

#[test]
fn top_ports_and_exclude_ports() {
    let doc = scan_json(&[
        "127.0.0.1",
        "--top-ports",
        "5",
        "--exclude-ports",
        "80",
        "--timeout",
        "300",
    ]);
    assert_eq!(doc["total_ports"], 4);
}

#[test]
fn udp_open_and_closed() {
    let open = serve_udp();
    let closed = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let spec = format!("{open},{closed}");
    let doc = scan_json(&["127.0.0.1", "--udp", "-p", &spec, "--timeout", "1000"]);
    let p = port_entry(&doc, open);
    assert_eq!(p["status"], "open");
    assert_eq!(p["protocol"], "udp");
    // ICMP port-unreachable → closed on every OS (the old Linux bug said open|filtered).
    assert_eq!(doc["closed_count"], 1, "{doc:#}");
}

#[test]
fn target_file_with_comments_and_exclude() {
    let open = serve_tcp(b"", false);
    let dir = tempdir().unwrap();
    let list = dir.path().join("targets.txt");
    fs::write(&list, "# my targets\n127.0.0.1  # loopback\n\n192.0.2.7\n").unwrap();
    let doc = scan_json(&[
        "-L",
        list.to_str().unwrap(),
        "--exclude",
        "192.0.2.0/24",
        "-p",
        &open.to_string(),
    ]);
    // Only one host left → single-host document.
    assert_eq!(doc["resolved_ip"], "127.0.0.1");
    assert_eq!(doc["open_count"], 1);
}

#[test]
fn host_discovery_skips_dead_hosts() {
    let open = serve_tcp(b"", false);
    let out = scanner()
        .args(["127.0.0.1", "192.0.2.1", "-p", &open.to_string()])
        .args(["--timeout", "2500", "--json"])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    let doc = &doc["rustscan_rs"];
    assert_eq!(
        doc["hosts_scanned"], 1,
        "TEST-NET host should be dropped: {doc:#}"
    );
    assert_eq!(doc["hosts"][0]["host"], "127.0.0.1");
}

#[test]
fn no_discovery_scans_every_host() {
    let open = serve_tcp(b"", false);
    let doc = scan_json(&[
        "127.0.0.1",
        "192.0.2.1",
        "--no-discovery",
        "-p",
        &open.to_string(),
        "--timeout",
        "300",
        "--retries",
        "0",
    ]);
    assert_eq!(doc["hosts_scanned"], 2);
}

// ── Service identification & banners ──────────────────────────────────────────

#[test]
fn banner_identifies_ssh_on_nonstandard_port() {
    let port = serve_tcp(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n", false);
    let doc = scan_json(&["127.0.0.1", "-p", &port.to_string(), "--banner"]);
    let p = port_entry(&doc, port);
    assert_eq!(p["service"]["name"], "SSH", "{p:#}");
    assert_eq!(p["banner"], "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3");
}

#[test]
fn http_banner_includes_server_header() {
    let port = serve_tcp(
        b"HTTP/1.1 200 OK\r\nDate: today\r\nServer: e2e-httpd/1.0\r\n\r\n",
        true,
    );
    let doc = scan_json(&["127.0.0.1", "-p", &port.to_string(), "--banner"]);
    let p = port_entry(&doc, port);
    assert_eq!(p["service"]["name"], "HTTP");
    assert_eq!(p["banner"], "HTTP/1.1 200 OK | Server: e2e-httpd/1.0");
    assert_eq!(p["version"], "e2e-httpd 1.0");
}

#[test]
fn version_from_mysql_handshake() {
    // Handshake v10: length, seq 0, protocol 10, "8.0.36" NUL, thread id ...
    let port = serve_tcp(
        b"J\x00\x00\x00\x0a8.0.36\x00\x08\x00\x00\x00abcdefgh\x00\xff\xf7",
        false,
    );
    let doc = scan_json(&["127.0.0.1", "-p", &port.to_string(), "--banner"]);
    let p = port_entry(&doc, port);
    assert_eq!(p["service"]["name"], "MYSQL", "{p:#}");
    assert_eq!(p["version"], "MySQL 8.0.36");
}

#[test]
fn redis_on_odd_port_is_asked_for_its_version() {
    // Rejects the HTTP probe like Redis does, answers INFO.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(3))).ok();
                let mut buf = [0u8; 512];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    let reply: &[u8] = if buf[..n].starts_with(b"INFO") {
                        b"$40
# Server
redis_version:7.2.4
mode:x
"
                    } else {
                        b"-ERR unknown command 'HEAD'
"
                    };
                    let _ = s.write_all(reply);
                }
            });
        }
    });
    let doc = scan_json(&["127.0.0.1", "-p", &port.to_string(), "--banner"]);
    let p = port_entry(&doc, port);
    assert_eq!(p["service"]["name"], "REDIS", "{p:#}");
    assert_eq!(p["version"], "Redis 7.2.4");
}

#[test]
fn https_server_header_read_through_tls() {
    let port = serve_tls_with(Some(
        b"HTTP/1.1 200 OK
Server: nginx/1.25.3

",
    ));
    let doc = scan_json(&["127.0.0.1", "-p", &port.to_string(), "--banner", "--tls"]);
    let p = port_entry(&doc, port);
    assert_eq!(p["tls"], true, "{p:#}");
    assert_eq!(p["service"]["name"], "HTTPS");
    assert_eq!(p["version"], "nginx 1.25.3");
}

#[test]
fn terminal_escapes_in_banners_are_stripped() {
    let port = serve_tcp(b"\x1b]0;pwned\x07\x1b[2Jhello\r\n", false);
    let out = scanner()
        .args(["127.0.0.1", "-p", &port.to_string(), "--banner"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(stdout.contains("hello"));
    // Piped output (not a terminal) carries no colour codes at all.
    assert!(
        !stdout.contains('\x1b'),
        "ANSI codes in piped output: {stdout:?}"
    );
    assert!(stdout.contains("Ports scanned : 1"), "plain text greppable");
    assert!(
        !stdout.contains("\x1b]0;pwned"),
        "OSC escape leaked to terminal"
    );
    assert!(
        !stdout.contains("\x1b[2J"),
        "clear-screen escape leaked to terminal"
    );
}

// ── TLS ───────────────────────────────────────────────────────────────────────

#[test]
fn tls_reports_certificate_and_flags() {
    let port = serve_tls();
    let doc = scan_json(&["127.0.0.1", "-p", &port.to_string(), "--tls"]);
    let p = port_entry(&doc, port);
    assert_eq!(p["tls"], true, "{p:#}");
    // Unknown (ephemeral) port, but the handshake proves it's TLS.
    assert_eq!(p["service"]["name"], "SSL/TLS");
    assert_eq!(p["tls_cert"]["self_signed"], true);
    assert_eq!(p["tls_cert"]["expired"], false);
    // rustls refuses TLS 1.1 → no legacy finding.
    assert!(p["legacy_tls"].is_null());
}

#[test]
fn plain_tcp_port_is_not_tls() {
    let port = serve_tcp(b"hello\r\n", false);
    let doc = scan_json(&["127.0.0.1", "-p", &port.to_string(), "--tls"]);
    assert_eq!(port_entry(&doc, port)["tls"], false);
}

// ── Output & exports ──────────────────────────────────────────────────────────

#[test]
fn live_results_stream_to_stderr_unless_quiet() {
    let port = serve_tcp(b"", false);
    let expected = format!("Open 127.0.0.1:{port}");
    scanner()
        .args(["127.0.0.1", "-p", &port.to_string()])
        .assert()
        .success()
        .stderr(predicate::str::contains(expected.clone()));
    scanner()
        .args(["127.0.0.1", "-p", &port.to_string(), "-q"])
        .assert()
        .success()
        .stderr(predicate::str::contains(expected).not());
}

#[test]
fn all_exports_at_once_with_text_on_stdout() {
    let port = serve_tcp(b"<script>alert(1)</script>\r\n", false);
    let dir = tempdir().unwrap();
    let (j, c, h) = (
        dir.path().join("r.json"),
        dir.path().join("r.csv"),
        dir.path().join("r.html"),
    );
    let out = scanner()
        .args(["127.0.0.1", "-p", &port.to_string(), "--banner", "-q"])
        .args(["--json", j.to_str().unwrap()])
        .args(["--csv", c.to_str().unwrap()])
        .args(["--html", h.to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(stdout.contains("Scan Results"), "text stays on stdout");
    assert!(
        !stdout.contains("<html"),
        "HTML must not be dumped to stdout"
    );

    let json: Value = serde_json::from_str(&fs::read_to_string(&j).unwrap()).unwrap();
    assert_eq!(json[0]["port"], port);
    assert_eq!(json[0]["protocol"], "tcp");

    assert!(fs::read_to_string(&c).unwrap().contains(&port.to_string()));

    let html = fs::read_to_string(&h).unwrap();
    // Named (&lt;) or numeric (&#60;) entities are both fine.
    assert!(
        html.contains("&lt;script&gt;alert(1)") || html.contains("&#60;script&#62;alert(1)"),
        "banner must be present and HTML-escaped"
    );
    assert!(!html.contains("<script>alert(1)"), "XSS via banner");
}

#[test]
fn csv_formula_injection_is_neutralised() {
    let port = serve_tcp(b"=HYPERLINK(\"http://evil\",\"x\")\r\n", false);
    let dir = tempdir().unwrap();
    let f = dir.path().join("out.csv");
    let out = scanner()
        .args(["127.0.0.1", "-p", &port.to_string(), "--banner", "--csv"])
        .args([f.to_str().unwrap(), "-q"])
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&out.get_output().stdout).contains("Scan Results"));
    let file = fs::read_to_string(&f).unwrap();
    assert!(file.contains("'=HYPERLINK"), "{file}");

    // stdout CSV too
    let out = scanner()
        .args(["127.0.0.1", "-p", &port.to_string(), "--banner", "--csv"])
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&out.get_output().stdout).contains("'=HYPERLINK"));
}

// ── nmap hand-off ─────────────────────────────────────────────────────────────

/// `--nmap` must call nmap with exactly the open TCP ports. A stand-in script
/// records its arguments, so the test doesn't need nmap installed.
#[test]
fn nmap_handoff_receives_only_open_ports() {
    let open = serve_tcp(b"", false);
    let closed = closed_tcp_port();
    let dir = tempdir().unwrap();
    let out = dir.path().join("args.txt");
    let fake = if cfg!(windows) {
        let f = dir.path().join("nmap.cmd");
        fs::write(&f, format!("@echo %* > \"{}\"\r\n", out.display())).unwrap();
        f
    } else {
        let f = dir.path().join("nmap");
        fs::write(
            &f,
            format!("#!/bin/sh\necho \"$@\" > '{}'\n", out.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        }
        f
    };
    scanner()
        .env("RUSTSCAN_NMAP", &fake)
        .args(["127.0.0.1", "-p", &format!("{open},{closed}"), "-q"])
        .args(["--nmap", "--nmap-args", "-sV -sC"])
        .assert()
        .success();
    let args = fs::read_to_string(&out).unwrap();
    assert_eq!(
        args.trim(),
        format!("-sV -sC -Pn -p {open} 127.0.0.1"),
        "nmap got: {args}"
    );
}

#[test]
fn nmap_handoff_reports_missing_nmap() {
    let open = serve_tcp(b"", false);
    scanner()
        .env("RUSTSCAN_NMAP", "definitely-not-a-real-nmap-binary")
        .args(["127.0.0.1", "-p", &open.to_string(), "-q", "--nmap"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is nmap installed"));
}
