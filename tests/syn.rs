//! End-to-end SYN-scan tests. They need raw sockets (Linux + root or
//! CAP_NET_RAW on the binary), so they are `#[ignore]`d by default.
//! CI runs them with: `sudo setcap cap_net_raw+ep target/debug/rustscan-rs`
//! then `cargo test --test syn -- --ignored`.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use serde_json::Value;

fn syn_json(args: &[&str]) -> Value {
    let out = Command::cargo_bin("rustscan-rs")
        .unwrap()
        .timeout(Duration::from_secs(60))
        .args(args)
        .args(["--syn", "--json", "--timeout", "500"])
        .assert()
        .success();
    serde_json::from_slice::<Value>(&out.get_output().stdout).unwrap()["rustscan_rs"].clone()
}

fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
#[ignore = "needs CAP_NET_RAW"]
fn syn_finds_open_and_closed() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let open = l.local_addr().unwrap().port();
    let closed = closed_port();
    let doc = syn_json(&["127.0.0.1", "-p", &format!("{open},{closed}")]);
    assert_eq!(doc["open_ports"], serde_json::json!([open]), "{doc:#}");
    assert_eq!(
        doc["closed_count"], 1,
        "RST must be read as closed: {doc:#}"
    );
    assert_eq!(doc["filtered_count"], 0);
}

#[test]
#[ignore = "needs CAP_NET_RAW"]
fn syn_full_range_matches_listeners() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut want = vec![
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    ];
    want.sort_unstable();
    let doc = syn_json(&["127.0.0.1", "-p", "-", "-q"]);
    let got: Vec<u64> = doc["open_ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    for w in &want {
        assert!(got.contains(&(*w as u64)), "missing {w}: {got:?}");
    }
    assert_eq!(doc["total_ports"], 65535);
}

#[test]
#[ignore = "needs CAP_NET_RAW"]
fn syn_then_banner_identifies_service() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
            thread::sleep(Duration::from_millis(200));
        }
    });
    let doc = syn_json(&["127.0.0.1", "-p", &port.to_string(), "--banner"]);
    assert_eq!(doc["ports"][0]["service"]["name"], "SSH", "{doc:#}");
}
