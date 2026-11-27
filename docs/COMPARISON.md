# How rustscan-rs compares

The scanners people reach for fall into two camps:

- **Discovery front-ends** find open ports fast, then hand off to nmap for
  anything deeper: [RustScan](https://github.com/RustScan/RustScan),
  [naabu](https://github.com/projectdiscovery/naabu),
  [masscan](https://github.com/robertdavidgraham/masscan) and ZMap.
- **nmap** does deep analysis: version detection, OS fingerprinting and the NSE
  scripting engine.

rustscan-rs covers both halves:

- **Discovery:** a no-root connect scan, a raw-socket SYN scan (`--syn`), and
  the discovery features of RustScan and naabu.
- **Built-in analysis**, the first layer the others leave to nmap: banner-based
  service ID, a TLS certificate audit, legacy-TLS detection, and protocol-aware
  UDP probes.
- **Deep analysis:** `--nmap` hands only the open ports to nmap.

## Benchmark 1: one firewalled host, all ports

**Setup.** Two Docker containers on a bridge network (Debian bookworm, Docker on
Windows). The target runs 10 TCP services, and an iptables `DROP` rule silently
discards ports 30000–60000.

**Ground truth.** 10 open, 30,001 filtered, 35,524 closed.

**Method.** Each command ran 3 times; the table shows the median. Every tool
found **exactly the same 10 open ports in every run**. Both rustscan-rs modes
also reported exactly 35,524 closed and 30,001 filtered, with 0 errors.

| Command (all 65,535 TCP ports) | Root? | Median | Runs (s) |
|---|---|---|---|
| `rustscan-rs T -p - --syn --timeout 1000` | CAP_NET_RAW | **3.56 s** | 3.29, 3.56, 3.56 |
| `masscan T -p1-65535 --rate 100000 --wait 2` (1.3.2) | yes | 5.91 s | 5.91, 5.69, 6.17 |
| `rustscan-rs T -p - -c 5000 --timeout 1000` (connect) | **no** | 14.03 s | 14.03, 14.03, 14.03 |
| `nmap -sT -p- -T4 -Pn -n T` (7.93) | no | 24.28 s | 24.11, 24.28, 24.29 |
| `nmap -sS -p- -T4 -Pn -n T` (7.93) | yes | 24.89 s | 24.96, 24.89, 24.88 |

- **SYN mode** was 1.7× faster than masscan and 7× faster than `nmap -sS`.
- **Without root**, rustscan-rs was 1.7× faster than nmap's connect scan.
- **Scope.** This setup favours none of the tools, but it is one target on a
  fast virtual link. masscan is built for millions of hosts, and its
  `--wait 2` here is shorter than its default 10 s.

### Benchmark 2: subnet with mostly dead addresses

**Setup.** A /24 with 16 live hosts and 238 dead addresses. Every host runs
services on 22 and 80, half also on 443, and a third firewall ports 100–900
with `DROP`. Every tool scanned ports 1–1000 on the whole /24, excluding the
gateway and the scanner itself. All tools ran as root.

**Ground truth.** 37 open ports.

| Command | Root? | Median | Runs (s) | Found |
|---|---|---|---|---|
| `rustscan-rs N -p 1-1000 -c 5000` (connect) | **no** | **3.28 s** | 3.28, 3.25, 3.28 | 37 ×3 |
| `rustscan-rs N -p 1-1000 --syn` | yes | 3.55 s | 3.28, 3.55, 3.97 | 37 ×3 |
| `nmap -sT -p1-1000 -T4 N` | no | 6.73 s | 6.61, 6.73, 6.73 | 37 ×3 |
| `nmap -sS -p1-1000 -T4 N` | yes | 6.74 s | 6.72, 6.74, 6.74 | 37 ×3 |
| `masscan N -p1-1000 --rate 100000 --wait 2` | yes | 7.43 s | 7.16, 7.43, 7.44 | 37 ×3 |

**About masscan.** Its numbers come from a container without `CAP_NET_ADMIN`.
In the `NET_ADMIN` container, 2 of 3 masscan runs hung until my 60 s cap and
one found 36/37.

**What this benchmark found in rustscan-rs** (fixed before these numbers):

1. **`--syn --no-discovery` failed** on the broadcast address, and later on
   `ENOBUFS`.
2. **SYNs queued for dead local hosts filled the raw socket's ~208 KB send
   buffer**, which crowded out live hosts. That cost 10 of 37 ports.

The fix has three parts:

- As root, the send buffer is enlarged with `SO_SNDBUFFORCE`, and SYN mode
  discovers hosts inline. `--syn --no-discovery` then scans all 254 addresses
  in 3.6 s and finds 37/37.
- With only `CAP_NET_RAW`, SYN mode pings with connects first: 7.4 s, 37/37.
- Forcing `--no-discovery` without root prints a warning, because live hosts
  can be missed.

**Deep analysis, end to end.** `rustscan-rs --syn --nmap` (the default
`-sV` runs on the 10 open ports only) took **216.6 s**. `nmap -sS -sV -p-` took
238.0 s. Both identified the same 10 services. Most of that time is nmap's
version probes waiting on services that never answer. The hand-off saves the
port-discovery part (about 21 s here), and the saving grows with the size of
the port and host range.

**Loopback overhead** (one container, 2 listeners, 65,535 ports, connect scan).
rustscan-rs took 0.61 s and `nmap -sT -T4` took 1.71 s, with the same open
ports. This loopback benchmark is how the TCP self-connect false-positive bug
was found and fixed.

## Feature matrix

| | rustscan-rs | RustScan | naabu | masscan | nmap |
|---|---|---|---|---|---|
| Works without root | **yes** (connect) | yes | connect only | no | connect only |
| SYN (half-open) scan | ✅ `--syn` (Linux, macOS, Windows/Npcap) | ❌ | ✅ | ✅ | ✅ |
| Port lists, ranges, `-` | ✅ | ✅ | ✅ | ✅ | ✅ |
| Top-N common ports | ✅ `--top-ports` | ✅ | ✅ | ✅ | ✅ |
| Exclude ports / hosts | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
| Targets from file / stdin | ✅ `-L` | ✅ | ✅ | ✅ | ✅ |
| CIDR, IPv6, multi-A DNS | ✅ (SYN too) | ✅ | ✅ | partial | ✅ |
| Host discovery | ✅ TCP ping (RST = up) | ❌ (nmap) | ✅ | ❌ | ✅ |
| Rate limit / retries | ✅ / ✅ | ❌ / ✅ | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
| Randomised probe order | ✅ default | ✅ | ✅ | ✅ | ✅ |
| Adapts to OS socket limits | ✅ auto-shrinks | ❌ | — | n/a | ✅ |
| Live results while scanning | ✅ | ✅ | ✅ | ✅ | partial |
| Banner grab | ✅ | ❌ (nmap) | ❌ (nmap) | 11 protocols | ✅ |
| Service ID from banner | ✅ ~15 signatures |
| Product version (no nmap) | ✅ ~30 signatures + port probes | ❌ | ❌ | ❌ | ✅ thousands |
| Hand open ports to nmap | ✅ `--nmap` | ✅ | ✅ | ❌ | n/a |
| TLS detection + certificate | ✅ SNI-aware | ❌ | ❌ | partial | ✅ (NSE) |
| Expired / self-signed cert flags | ✅ | ❌ | ❌ | ❌ | ✅ (NSE) |
| Legacy SSLv3/TLS 1.0/1.1 detection | ✅ built in | ❌ | ❌ | ❌ | ✅ (NSE) |
| UDP with protocol payloads | ✅ DNS, NTP, SNMP, NetBIOS, SSDP, mDNS, TFTP | ✅ | ✅ | ✅ | ✅ |
| Correct closed-UDP on Linux *and* Windows | ✅ | — | — | — | ✅ |
| Loopback self-connect false positives | ✅ filtered out | — | — | n/a | ✅ |
| JSON / CSV / HTML at the same time | ✅ | JSON | JSON/CSV | JSON/XML/… | XML/grep/normal |
| CSV formula-injection safe | ✅ | — | ❌ | — | n/a |
| Terminal-escape safe output | ✅ | — | — | — | ✅ |
| OS fingerprinting / NSE scripts | via `--nmap` | via nmap | via nmap | ❌ | ✅ |

`—` = not checked / not applicable. Competitor columns come from each project's
own documentation; please open an issue if something is out of date.

## Where the others still win

- **nmap**: its own databases (thousands of version probes, OS fingerprints,
  NSE scripts) are unmatched. rustscan-rs's built-in version detection covers
  the common products (OpenSSH, Apache, nginx, IIS, Redis, MySQL/MariaDB,
  Exim, Postfix, vsftpd, …); for the long tail use `--nmap`.
- **masscan / ZMap**: at internet scale, with millions of hosts and a custom
  TCP stack at millions of packets per second, they remain the tools to use.
  rustscan-rs `--syn` uses the kernel's raw sockets.
- **SYN scanning** on Windows needs Npcap installed, and on macOS root. BSDs
  other than macOS aren't tested. IPv6 SYN skips packets with extension
  headers.
- **Scale of these benchmarks.** They used two Docker networks on one machine:
  one host and 16 hosts. They show the trend, not internet-scale numbers.
