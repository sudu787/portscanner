# rustscan-rs

[![CI](https://github.com/sudu787/portscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/sudu787/portscanner/actions/workflows/ci.yml)
[![Release](https://github.com/sudu787/portscanner/actions/workflows/release.yml/badge.svg)](https://github.com/sudu787/portscanner/releases)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A fast TCP/UDP port scanner in Rust. It has a no-root async connect scan, a
**SYN scan** on Linux, macOS and Windows (IPv4 and IPv6), and the first layer
of analysis that RustScan and naabu leave to nmap: **service and version
detection, TLS certificate checks, legacy-TLS detection and protocol-aware UDP
probes**. For deeper analysis,
`--nmap` hands only the open ports to nmap. It ships as one static binary.

Measured over a real network path to a firewalled target, scanning all 65,535
ports (details in [docs/COMPARISON.md](docs/COMPARISON.md)):

| | rustscan-rs `--syn` | masscan | rustscan-rs (no root) | nmap `-sT` | nmap `-sS` |
|---|---|---|---|---|---|
| Time (median of 3) | **3.6 s** | 5.9 s | 14.0 s | 24.3 s | 24.9 s |
| Open ports found (of 10) | 10 | 10 | 10 | 10 | 10 |

On a /24 with 16 live hosts (ports 1–1000, 37 open), rustscan-rs took 3.3 s
(connect) and 3.6 s (SYN), against 6.7 s for nmap and 7.4 s for masscan. All
tools found 37/37.

Example output (illustrative; the hostname and addresses are documentation placeholders):

```text
$ rustscan-rs scanme.example.com --top-ports 100 --banner --tls
Open 203.0.113.10:22
Open 203.0.113.10:443
Open 203.0.113.10:80

Scan Results — scanme.example.com (scanme.example.com / 203.0.113.10)
  ────────────────────────────────────────
  Ports scanned : 100
  Open ports    : 3
  Closed/filt.  : 2 / 95
  ────────────────────────────────────────
  OPEN PORTS:
    PORT  TLS SERVICE      DESCRIPTION / BANNER
    ▶  22/tcp         SSH          SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
    ▶  80/tcp         HTTP         HTTP/1.1 301 Moved Permanently | Server: nginx/1.24.0
    ▶  443/tcp   🔒   HTTPS        Secure HTTP (HTTP over TLS/SSL)
        └─ TLS Cert: CN=scanme.example.com (CN=R11, O=Let's Encrypt, C=US) — Expires: ...
        ⚠  accepts deprecated TLSv1.0
```

## Features

- **Fast**: Tokio async connect scan, one concurrency budget shared across all
  hosts, port × host order randomised, memory O(hosts + open ports).
- **SYN scan** (`--syn`, IPv4 and IPv6): half-open scanning with stateless
  SYN-cookie reply matching (the masscan approach). Linux uses raw sockets
  (root or `CAP_NET_RAW`); macOS uses libpcap (root) and Windows uses
  [Npcap](https://npcap.com), both loaded at run time, so the binary still
  runs without them. Services never log a connection. Banner and TLS probes
  then run only on the open ports.
- **Version detection** (`--banner`): port-aware probes (HTTP, Redis `INFO`,
  memcached, PostgreSQL SSLRequest, MySQL/MariaDB handshake, HTTP inside TLS)
  and signatures for common products, e.g. `OpenSSH 9.6p1 (Ubuntu-3ubuntu13)`,
  `Apache httpd 2.4.7 (Ubuntu)`, `nginx 1.25.3`, `Redis 7.2.4`, `MySQL 8.0.36`,
  `Exim smtpd 4.96`, `vsftpd 3.0.5`. No nmap needed. Its signature set is
  smaller than nmap's, so use `--nmap` for exhaustive `-sV`.
- **nmap hand-off** (`--nmap`, `--nmap-args "-sV -sC"`): after the sweep, runs
  nmap on just the open ports, so you get nmap's version and OS detection and
  NSE scripts without nmap scanning every port.
- **Accurate**: retries probes that time out (`--retries`); filters out
  loopback self-connect false positives; reports closed UDP ports correctly on
  Linux, macOS and Windows.
- **Self-tuning**: if the OS runs out of sockets, buffers or ephemeral ports,
  concurrency shrinks automatically and the affected probes are retried. A
  full 65,535-port scan at `-c 60000` on Windows completes with 0 failed probes
  instead of thousands.
- **Targets**: IPs, CIDR, IPv6, hostnames (`--all-addrs` scans every A/AAAA
  record), several at once, from a file or stdin (`-L`), with `--exclude`.
- **Ports**: `-p 22,80,8000-8100`, `-p -` for all ports, `--top-ports N`,
  `--exclude-ports`.
- **Host discovery** for multi-host scans. A TCP ping counts any answer,
  including RST, as "up"; skip it with `--no-discovery`.
- **Service ID** (`--banner`): identifies SSH, HTTP (with the `Server:`
  header), SMTP, FTP, POP3, IMAP, VNC, Redis, MySQL, RTSP and SIP from what the
  service actually says, not just from the port number.
- **TLS audit** (`--tls`): certificate subject, issuer and expiry, plus
  expired and self-signed flags. Sends SNI for hostname targets and **detects
  servers that still accept SSLv3 / TLS 1.0 / TLS 1.1**.
- **UDP** (`--udp`): real DNS, NTP, SNMP, NetBIOS, SSDP, mDNS and TFTP requests,
  so live services answer instead of showing up as `open|filtered`.
- **Output**: coloured text with live `Open ip:port` lines as ports are found,
  or JSON, CSV or HTML. All three can be written to files in one run.
- **Safe output**: banners, certificates and PTR names are stripped of control
  and terminal-escape characters; CSV cells are protected against formula
  injection; the HTML report is auto-escaped.

See **[docs/COMPARISON.md](docs/COMPARISON.md)** for the full feature matrix
against nmap, masscan, RustScan and naabu, the benchmark setup, and where those
tools are still the better choice.

## Install

**Prebuilt binaries** for Linux (x86_64 glibc and musl, aarch64), macOS
(Intel and Apple silicon) and Windows are on the
[Releases](https://github.com/sudu787/portscanner/releases) page, with
`SHA256SUMS.txt`.

**Docker** (multi-arch, runs as a non-root user):

```bash
docker run --rm ghcr.io/sudu787/portscanner 192.168.1.10 --top-ports 1000
```

**From source** (Rust ≥ 1.88):

```bash
cargo install --git https://github.com/sudu787/portscanner --locked
```

## Usage

```bash
# Common ports on a host, with service ID and the TLS audit
rustscan-rs example.com --top-ports 100 --banner --tls

# Every TCP port, fast (no root)
rustscan-rs 10.0.0.5 -p - -c 5000

# Every TCP port, fastest: SYN scan (root / CAP_NET_RAW; Npcap on Windows)
sudo rustscan-rs 10.0.0.5 -p - --syn
# …or grant the capability once and run it as a normal user:
sudo setcap cap_net_raw+ep "$(command -v rustscan-rs)"

# Fast sweep, then nmap version/script detection on only the open ports
rustscan-rs 10.0.0.5 -p - --syn --nmap --nmap-args "-sV -sC"

# A subnet: host discovery first, then the top 1000 ports on live hosts
rustscan-rs 10.0.0.0/24 --top-ports 1000

# Targets from a file, minus a range, politely (200 probes/s, 2 retries)
rustscan-rs -L targets.txt --exclude 10.0.0.0/28 --rate 200 --retries 2

# UDP services
rustscan-rs 10.0.0.1 --udp -p 53,123,161,137,1900,5353

# Text on screen and all three reports as files
rustscan-rs 10.0.0.0/24 --banner --tls --json scan.json --csv scan.csv --html scan.html

# JSON to stdout for pipelines
rustscan-rs 10.0.0.1 -p 1-1000 --json | jq '.rustscan_rs.open_ports'
```

`--json`, `--csv` and `--html` without a file name print that format to stdout
instead of text. Put the target before these flags, or after `--`, so it isn't
taken as a file name.

| Option | Default | Meaning |
|---|---|---|
| `-p, --ports SPEC` | `1-1024` | `22,80,443`, `1-1000`, `8000-`, `-` (all) |
| `--top-ports N` | | the N most commonly exposed ports |
| `--exclude-ports SPEC` | | ports to leave out |
| `-L, --target-file FILE` | | targets from a file (`-` = stdin), `#` comments allowed |
| `--exclude HOSTS` | | IPs / CIDRs to skip (comma-separated) |
| `--all-addrs` | off | scan every address a hostname resolves to |
| `--no-discovery` | off | scan all hosts without the TCP ping first |
| `-c, --concurrency N` | `1000` | probes in flight (keep ≤ your open-file limit) |
| `--timeout MS` | `1500` | per-probe timeout |
| `--retries N` | `1` | re-sends after a timeout |
| `--rate PPS` | unlimited | max new probes per second |
| `--sequential` | off | don't randomise probe order |
| `--tcp` / `--udp` | TCP | protocols to scan (both allowed) |
| `--syn` (`--sS`) | off | half-open SYN scan (Linux: root / `CAP_NET_RAW`; macOS: root; Windows: Npcap) |
| `--nmap` | off | run nmap on the open TCP ports afterwards (text output) |
| `--nmap-args ARGS` | `-sV` | arguments for the nmap hand-off |
| `--banner` | off | banner grab, service ID and product version |
| `--tls` | off | TLS / certificate / legacy-TLS audit |
| `--resolve-dns` | off | reverse DNS (PTR) for each host |
| `-q, --quiet` | off | no banner / live lines on stderr |
| `-v` … `-vvv` | warn | log verbosity (stderr) |

### JSON output

A single target produces `{"rustscan_rs": {target, resolved_ip, hostname,
total_ports, open_count, closed_count, filtered_count, error_count, open_ports,
ports: [...]}}`. Several targets produce `{"rustscan_rs": {target_spec,
hosts_scanned, total_open_ports, hosts: [...]}}`. Each port entry has `port`,
`protocol`, `status` (`open` or `open|filtered`), `service`, `version`, `banner`, `tls`,
`tls_cert` (`subject`, `issuer`, `not_after`, `expired`, `self_signed`) and
`legacy_tls`. Closed and filtered ports are counted, not listed, which keeps
large scans small.

## Accuracy notes

- The default is a **connect scan**, which completes the TCP handshake, so
  services may log it. `--syn` never completes a handshake: the kernel resets
  every SYN-ACK for us. macOS and Windows don't let raw sockets do this, so
  there whole frames are sent and captured through libpcap / Npcap. The
  link-layer header (gateway or neighbour MAC) is learnt by capturing one UDP
  datagram the OS sends to each target, so dead LAN hosts are skipped.
- `filtered` means no answer within `--timeout` after `--retries` re-sends. On
  lossy or rate-limited networks, raise `--retries` or lower `--rate`.
- UDP `open|filtered` means silence: the port may be open, or a firewall may
  be dropping probes. Services with a built-in payload (DNS, NTP, SNMP, …)
  answer, so they show up as `open`.
- **Windows** connect scans: Windows retries a SYN that gets an RST, so closed
  ports take about a second to report. `--syn` (Npcap) avoids this: a full
  65,535-port loopback scan takes 4.4 s instead of 200 s.
- When the OS runs out of sockets, concurrency adapts on its own and the scan
  warns with the value that worked (`pass -c N`). Any probe that still fails
  is counted under `Probe errors` instead of aborting the scan.

## Development

```bash
cargo test                 # unit + end-to-end tests (tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all
# SYN end-to-end tests. Linux: CAP_NET_RAW on the binary; macOS: run as
# root; Windows: Npcap installed.
cargo test --test syn --no-run && sudo setcap cap_net_raw+ep target/debug/rustscan-rs
cargo test --test syn -- --ignored
# Linux, exercising the libpcap (macOS/Windows) code path; loopback needs
# route_localnet=1 and accept_local=1 on lo (see .github/workflows/ci.yml):
RUSTSCAN_SYN_BACKEND=pcap cargo test --test syn -- --ignored
```

`tests/e2e.rs` runs the real binary against TCP, UDP and TLS servers that it
starts on loopback. It covers service ID, the TLS and certificate flags, UDP
open/closed, host discovery, target files, exports, and the CSV/HTML/terminal
injection defences.

### CI/CD

- **CI** (`.github/workflows/ci.yml`, every push and PR): fmt, clippy with
  `-D warnings`, tests on Linux, macOS and Windows, the privileged SYN tests
  (via `setcap`, never running cargo as root), an MSRV check (1.88), a
  `cargo audit` advisory gate, and a Docker build. The Docker job smoke-tests
  both a connect scan and a SYN scan as the image's non-root user. A single
  `CI passed` job is meant to be the required branch-protection check.
- **Release** (`.github/workflows/release.yml`, on a `vX.Y.Z` tag): checks the
  tag matches `Cargo.toml`, runs the tests, builds 6 targets, publishes a
  GitHub Release with archives and `SHA256SUMS.txt`, and pushes a multi-arch
  image to `ghcr.io`.
- **Dependabot** keeps Cargo, GitHub Actions and Docker base images current.

To cut a release: bump `version` in `Cargo.toml`, commit, then
`git tag v0.2.0 && git push --tags`.

## Security & ethics

Scan only systems you own or are explicitly authorised to test. High
`--concurrency` without `--rate` can look like a DoS to old firewalls. TLS
probing intentionally skips certificate validation so it can inspect bad
certificates; it never sends application data.

## License

MIT
