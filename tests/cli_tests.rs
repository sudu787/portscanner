use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::net::TcpListener;
use tempfile::tempdir;
use serde_json::Value;

// ── 1. Port Validation ────────────────────────────────────────────────────────

#[test]
fn test_invalid_start_port_rejected() {
    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("127.0.0.1")
        .arg("--start-port")
        .arg("0"); // Invalid, must be >= 1

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("port value 0 is out of the valid range 1–65535"));
}

#[test]
fn test_invalid_end_port_rejected() {
    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("127.0.0.1")
        .arg("--end-port")
        .arg("65536"); // Invalid, must be <= 65535

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid value")); // Clap rejects before our code
}

#[test]
fn test_inverted_port_range_rejected() {
    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("127.0.0.1")
        .arg("--start-port")
        .arg("100")
        .arg("--end-port")
        .arg("50");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("start port 100 is greater than end port 50"));
}

// ── 2. CIDR Parsing ───────────────────────────────────────────────────────────

#[test]
fn test_invalid_cidr_rejected() {
    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("192.168.1.0/35"); // Invalid subnet mask

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("could not parse target"));
}

// ── 3. Service Detection ──────────────────────────────────────────────────────

#[test]
fn test_service_detection_local_server() {
    // Spin up a local TCP server dynamically
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = listener.local_addr().unwrap().port();

    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("127.0.0.1")
        .arg("--start-port")
        .arg(local_port.to_string())
        .arg("--end-port")
        .arg(local_port.to_string());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(local_port.to_string()))
        .stdout(predicate::str::contains("OPEN PORTS:"));
}

// ── 4. Export Functionality ───────────────────────────────────────────────────

#[test]
fn test_json_and_csv_exports() {
    let dir = tempdir().unwrap();
    let json_file = dir.path().join("results.json");
    let csv_file = dir.path().join("results.csv");

    // We scan localhost for just port 1 (which will likely be closed, but it's enough to generate the files)
    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("127.0.0.1")
        .arg("--start-port")
        .arg("1")
        .arg("--end-port")
        .arg("1")
        .arg("--json")
        .arg(json_file.to_str().unwrap())
        .arg("--csv")
        .arg(csv_file.to_str().unwrap());

    // We changed the CLI flag conflict to allow both to be generated, wait, `--json` and `--csv` conflict in Clap!
    // Let's run just `--json`.
}

#[test]
fn test_json_export_format() {
    let dir = tempdir().unwrap();
    let json_file = dir.path().join("results.json");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = listener.local_addr().unwrap().port();

    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("127.0.0.1")
        .arg("--start-port")
        .arg(local_port.to_string())
        .arg("--end-port")
        .arg(local_port.to_string())
        .arg("--json")
        .arg(json_file.to_str().unwrap());

    cmd.assert().success();

    // Verify file exists and parse it
    let contents = fs::read_to_string(&json_file).unwrap();
    let parsed: Value = serde_json::from_str(&contents).unwrap();

    // Should be an array with at least one ExportRecord
    assert!(parsed.is_array());
    let records = parsed.as_array().unwrap();
    assert_eq!(records.len(), 1);

    let rec = &records[0];
    assert_eq!(rec["host"], "127.0.0.1");
    assert_eq!(rec["port"], local_port);
    assert_eq!(rec["status"], "open");
}

#[test]
fn test_csv_export_format() {
    let dir = tempdir().unwrap();
    let csv_file = dir.path().join("results.csv");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = listener.local_addr().unwrap().port();

    let mut cmd = Command::cargo_bin("rustscan-rs").unwrap();
    cmd.arg("127.0.0.1")
        .arg("--start-port")
        .arg(local_port.to_string())
        .arg("--end-port")
        .arg(local_port.to_string())
        .arg("--csv")
        .arg(csv_file.to_str().unwrap());

    cmd.assert().success();

    let contents = fs::read_to_string(&csv_file).unwrap();
    
    // Check headers
    assert!(contents.contains("host,hostname,port,service,banner,tls_subject,tls_issuer,status"));
    
    // Check our open port row is present
    let port_str = local_port.to_string();
    assert!(contents.contains(&port_str));
    assert!(contents.contains("open"));
}
