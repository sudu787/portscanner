# RustScan-rs

A high-performance, asynchronous port scanner written in Rust using Tokio. It supports both TCP connect and UDP scanning, automatic service identification, CIDR network ranges, DNS resolution, and advanced output formats (JSON, CSV, HTML).

## Features

- **Blazing Fast Concurrency**: Built on `tokio` and `futures` with a Semaphore-based budget governor. Set custom concurrency limits (default: 1000) to control file descriptor and memory usage.
- **TCP & UDP Scanning**: Run full TCP connect scans, or lightweight UDP probe scans without requiring root/administrator privileges on Windows. Use `--tcp` and/or `--udp` flags.
- **CIDR & Network Ranges**: Scan entire subnets effortlessly (e.g., `192.168.1.0/24`). Safety limits prevent accidental DDoS-scale scans (max `/16` or 65,536 hosts).
- **DNS Resolution**: Supply hostnames (e.g., `scanme.nmap.org`), and `rustscan-rs` automatically resolves them asynchronously before scanning.
- **Service Detection**: Automatically identifies common services running on discovered ports (e.g., 22 -> SSH, 80 -> HTTP) and maps unknown ports accurately.
- **TLS Detection**: Send a lightweight TLS ClientHello probe (`--tls`) to identify secure endpoints—even those with self-signed or invalid certificates!
- **Banner Grabbing**: Pass `--banner` to connect, wait briefly, and capture initial server greeting bytes (e.g., SSH, FTP, SMTP banners).
- **Multiple Output Formats**: View results in Terminal (colorized text), structured JSON (`--json`), CSV (`--csv`), or standalone HTML reports (`--html`).

## Installation

Ensure you have [Rust and Cargo installed](https://rustup.rs/). Then, clone the repository and build:

```bash
git clone https://github.com/sudu787/portscanner.git
cd portscanner
cargo build --release
```

## Usage

Run the scanner locally via `cargo run` or using the compiled binary.

### Basic Scan
Scan a single IP address (default ports 1-1024, TCP only):
```bash
cargo run -- 192.168.1.10
```

### Scan a CIDR Range
Scan a local subnet:
```bash
cargo run -- 192.168.1.0/24
```

### Specific Ports
Use the `--start-port` and `--end-port` flags to define a range:
```bash
cargo run -- 10.0.0.5 --start-port 80 --end-port 443
```

### TCP and UDP Scanning
Scan both protocols simultaneously:
```bash
cargo run -- 127.0.0.1 --tcp --udp
```

### Advanced Features (TLS, Banners, and Custom Output)
Scan a hostname, check for TLS (`--tls`), grab banners (`--banner`), and export to JSON:
```bash
cargo run -- scanme.nmap.org --tls --banner --json
```

### Help Menu
View all available options:
```bash
cargo run -- --help
```

```
Usage: rustscan-rs [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Target IP address, hostname, or CIDR network (e.g., 192.168.1.1, scanme.nmap.org, 10.0.0.0/24)

Options:
  --start-port <PORT>        First port of the scan range [default: 1]
  --end-port <PORT>          Last port of the scan range [default: 1024]
  --timeout <MS>             Connection timeout per port in ms [default: 1500]
  -c, --concurrency <CONCURRENCY> Max concurrent connections [default: 1000]
      --tcp                      Scan TCP ports (Default if neither --tcp nor --udp are provided)
      --udp                      Scan UDP ports
      --tls                      Probe open TCP ports for TLS/SSL handshakes
      --banner                   Attempt to grab service banners from open TCP ports
      --json                     Output results in JSON format
      --csv                      Output results in CSV format
      --html                     Output results as an HTML report
  -v, --verbose...               Increase logging verbosity (e.g., -v, -vv)
  -h, --help                     Print help
  -V, --version                  Print version
```

## Architecture

`rustscan-rs` is designed for safe, asynchronous execution:
- **`src/main.rs`**: Handles CLI orchestration, setup, and output.
- **`src/cli.rs`**: Uses `clap` to parse arguments and validate input logic.
- **`src/scanner.rs`**: The core scanning engine. Manages `tokio` tasks and an FD-budget Semaphore.
- **`src/targets.rs`**: Resolves hostnames and safely expands CIDR network notations up to 65,536 hosts.
- **`src/probes.rs`**: Contains application-layer logic for Banner Grabbing and custom TLS handshaking using `rustls`.
- **`src/service.rs`**: Fast lookup table mapping ports to standard `Transport` variants and known service names.
- **`src/output.rs`**: Rendering engine translating raw scan metrics into Terminal, JSON, CSV, and HTML formats.
