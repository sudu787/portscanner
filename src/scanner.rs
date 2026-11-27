//! scanner.rs — Async TCP/UDP scanning engine for rustscan-rs
//!
//! ## Concurrency model
//!
//! One `Semaphore` with `concurrency` permits governs *all* probes across
//! *all* hosts (permits = sockets in flight = file descriptors). The spawning
//! loop walks ports × hosts lazily — port-major, so load is spread across
//! hosts instead of hammering one at a time — in a shuffled order unless
//! `--sequential` is given. Nothing proportional to `hosts × ports` is ever
//! materialised: each task records its outcome straight into its host's
//! accumulator, and only open / open|filtered ports are kept; closed and
//! filtered ones are just counted. Memory is O(hosts + open ports).
//!
//! `--rate` adds a token interval in front of every spawn; `--retries`
//! re-sends probes that timed out, which is where false negatives come from.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, Semaphore};
use tokio::time::{timeout, MissedTickBehavior};
use tracing::{debug, trace, warn};

use crate::errors::RustScanError;
use crate::probes::{detect_legacy_tls, detect_tls, grab_banner, udp_payload};
use crate::service::{detect_service, identify_banner, ServiceInfo, Transport};

// ─── Public types ─────────────────────────────────────────────────────────────

/// The state of a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortStatus {
    /// Handshake succeeded (TCP) or the service answered (UDP).
    Open,
    /// RST (TCP) or ICMP port-unreachable (UDP).
    Closed,
    /// No answer / host or network unreachable.
    Filtered,
    /// UDP probe got no answer: open and silent, or firewalled.
    OpenFiltered,
}

impl PortStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortStatus::Open => "open",
            PortStatus::Closed => "closed",
            PortStatus::Filtered => "filtered",
            PortStatus::OpenFiltered => "open|filtered",
        }
    }
}

/// The result of probing a single port.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Transport,
    pub status: PortStatus,
    /// Service: identified from the banner when possible, else the port-based guess.
    pub service: ServiceInfo,
    /// Sanitized banner (first line; plus `Server:` for HTTP).
    pub banner: Option<String>,
    /// Does the port speak TLS (modern or legacy)?
    pub tls: bool,
    /// Certificate details from a TLS 1.2/1.3 handshake.
    pub tls_cert: Option<crate::tls::TlsCertInfo>,
    /// `Some("TLSv1.0")` etc. when the server still accepts a deprecated protocol.
    pub legacy_tls: Option<&'static str>,
}

/// Aggregated results for one host.
#[derive(Debug)]
pub struct ScanResult {
    /// The scanned IP address.
    pub target: String,
    /// PTR name (with `--resolve-dns`) or the hostname the user gave.
    pub hostname: Option<String>,
    /// Number of probes requested for this host (ports × protocols).
    pub total_ports: u32,
    /// Wall-clock time of the whole scan.
    pub elapsed: Duration,
    /// Open and open|filtered ports, sorted by (port, protocol).
    pub ports: Vec<PortResult>,
    pub closed: u32,
    pub filtered: u32,
    /// Probes that failed with an OS error (or never completed).
    pub errors: u32,
}

impl ScanResult {
    /// Ports worth reporting: open and open|filtered.
    pub fn open_ports(&self) -> impl Iterator<Item = &PortResult> {
        self.ports
            .iter()
            .filter(|r| r.status == PortStatus::Open || r.status == PortStatus::OpenFiltered)
    }

    /// Confirmed open ports only (excludes ambiguous open|filtered).
    pub fn open_count(&self) -> usize {
        self.ports
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .count()
    }
}

/// One host to scan. `name` is the hostname the user typed, if any (used as
/// TLS SNI and as the display name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub addr: IpAddr,
    pub name: Option<String>,
}

impl Target {
    pub fn ip(addr: IpAddr) -> Self {
        Self { addr, name: None }
    }
}

/// All parameters of a scan (shared by every host).
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub ports: Vec<u16>,
    pub timeout: Duration,
    /// Probes in flight at once, across all hosts.
    pub concurrency: usize,
    /// Extra attempts for probes that timed out.
    pub retries: u8,
    /// Max new probes per second.
    pub rate: Option<u32>,
    /// Shuffle port and host order.
    pub randomize: bool,
    pub banner: bool,
    pub tls: bool,
    pub tcp: bool,
    pub udp: bool,
    pub resolve_dns: bool,
    /// Print `Open ip:port` to stderr the moment a port is found.
    pub live: bool,
}

/// Per-probe options (cheap to clone into each task).
#[derive(Debug, Clone)]
pub struct ProbeOpts {
    pub timeout: Duration,
    pub retries: u8,
    pub banner: bool,
    pub tls: bool,
    pub sni: Option<Arc<str>>,
}

// ─── scan_port() ──────────────────────────────────────────────────────────────

/// Probe one port. Network outcomes (refused, timeout, unreachable) are
/// `Ok`; only unexpected OS errors (EMFILE, ENOBUFS, …) are `Err`.
pub async fn scan_port(
    addr: IpAddr,
    port: u16,
    protocol: Transport,
    opts: &ProbeOpts,
) -> Result<PortResult, RustScanError> {
    let sa = SocketAddr::new(addr, port);
    trace!(%sa, ?protocol, "probing");

    let mut result = PortResult {
        port,
        protocol,
        status: PortStatus::Filtered,
        service: detect_service(port, protocol),
        banner: None,
        tls: false,
        tls_cert: None,
        legacy_tls: None,
    };

    match protocol {
        Transport::Udp => result.status = probe_udp(sa, opts).await?,
        _ => {
            let Some(mut stream) = connect_tcp(sa, opts, &mut result.status).await? else {
                return Ok(result);
            };
            result.status = PortStatus::Open;
            if opts.banner {
                result.banner =
                    grab_banner(&mut stream, opts.timeout.min(Duration::from_secs(2))).await;
            }
            drop(stream);
            if opts.tls {
                result.tls_cert = detect_tls(addr, port, opts.timeout, opts.sni.as_deref()).await;
                result.legacy_tls = detect_legacy_tls(addr, port, opts.timeout).await;
                result.tls = result.tls_cert.is_some() || result.legacy_tls.is_some();
            }
            if let Some(svc) = result
                .banner
                .as_deref()
                .and_then(|b| identify_banner(b, result.tls))
            {
                result.service = svc;
            } else if result.tls
                && (!result.service.is_known() || result.service.name == "EPHEMERAL")
            {
                result.service = crate::service::TLS_SERVICE;
            }
        }
    }
    Ok(result)
}

/// TCP connect with retries on timeout. `Ok(None)` = not open (status set).
async fn connect_tcp(
    sa: SocketAddr,
    opts: &ProbeOpts,
    status: &mut PortStatus,
) -> Result<Option<TcpStream>, RustScanError> {
    use io::ErrorKind::*;
    for attempt in 0..=opts.retries {
        match timeout(opts.timeout, TcpStream::connect(sa)).await {
            Err(_) => trace!(%sa, attempt, "timeout"),
            Ok(Ok(stream)) => {
                // TCP self-connect: on loopback, when the destination port
                // equals our own ephemeral source port, the kernel connects
                // the socket to itself. Nothing is listening — not open.
                if is_self_connect(stream.local_addr().ok(), sa) {
                    *status = PortStatus::Closed;
                    return Ok(None);
                }
                return Ok(Some(stream));
            }
            Ok(Err(e)) => match e.kind() {
                ConnectionRefused => {
                    *status = PortStatus::Closed;
                    return Ok(None);
                }
                // A timeout reported by the OS is retryable like ours.
                TimedOut => trace!(%sa, attempt, "os timeout"),
                HostUnreachable | NetworkUnreachable | PermissionDenied => {
                    *status = PortStatus::Filtered;
                    return Ok(None);
                }
                // Resource exhaustion is handled by adaptive concurrency in
                // `scan_targets`; anything else is a genuine probe error.
                _ => return Err(os_error(format!("tcp {sa}"), e)),
            },
        }
    }
    *status = PortStatus::Filtered;
    Ok(None)
}

/// Classify an unexpected socket error. Running out of file descriptors,
/// buffers or ephemeral ports is retryable with less concurrency.
fn os_error(ctx: String, e: io::Error) -> RustScanError {
    use io::ErrorKind::*;
    // EMFILE/ENFILE (24/23), ENOBUFS (Linux 105, macOS 55),
    // WSAEMFILE (10024), WSAENOBUFS (10055).
    let resource = matches!(e.kind(), AddrInUse | AddrNotAvailable | OutOfMemory)
        || matches!(e.raw_os_error(), Some(23 | 24 | 55 | 105 | 10024 | 10055));
    if resource {
        RustScanError::ResourceExhausted(format!("{ctx}: {e}"))
    } else {
        RustScanError::Io(io::Error::new(e.kind(), format!("{ctx}: {e}")))
    }
}

async fn probe_udp(sa: SocketAddr, opts: &ProbeOpts) -> Result<PortStatus, RustScanError> {
    use io::ErrorKind::*;
    let io_err = |what: &str, e: io::Error| os_error(format!("udp {what} {sa}"), e);
    let bind = if sa.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind).await.map_err(|e| io_err("bind", e))?;
    socket.connect(sa).await.map_err(|e| io_err("connect", e))?;
    if is_self_connect(socket.local_addr().ok(), sa) {
        // We would just read back our own datagram.
        return Ok(PortStatus::Closed);
    }

    let payload = udp_payload(sa.port());
    let mut buf = [0u8; 1500];
    for _ in 0..=opts.retries {
        if let Err(e) = socket.send(payload).await {
            // ICMP from a previous attempt can surface on send, too.
            if matches!(e.kind(), ConnectionRefused | ConnectionReset) {
                return Ok(PortStatus::Closed);
            }
            return Err(io_err("send", e));
        }
        match timeout(opts.timeout, socket.recv(&mut buf)).await {
            Err(_) => continue, // silence: retry
            Ok(Ok(_)) => return Ok(PortStatus::Open),
            // ICMP port-unreachable: ECONNREFUSED on Linux/macOS, WSAECONNRESET on Windows.
            Ok(Err(e)) if matches!(e.kind(), ConnectionRefused | ConnectionReset) => {
                return Ok(PortStatus::Closed)
            }
            Ok(Err(e)) if e.kind() == PermissionDenied => return Ok(PortStatus::Filtered),
            Ok(Err(e)) => {
                trace!(%sa, error = %e, "udp recv error");
                return Ok(PortStatus::OpenFiltered);
            }
        }
    }
    Ok(PortStatus::OpenFiltered)
}

// ─── scan_targets() ───────────────────────────────────────────────────────────

/// Adaptive concurrency never shrinks below this many sockets.
const MIN_CONCURRENCY: usize = 32;
/// Re-attempts of a probe that hit OS resource exhaustion.
const RESOURCE_RETRIES: u32 = 8;

/// Retire one concurrency slot unless already at the floor. (A plain CAS
/// loop: `fetch_update` is deprecated on new Rust, `try_update` is too new
/// for the MSRV.)
fn try_shrink(capacity: &AtomicUsize) -> bool {
    let mut c = capacity.load(SeqCst);
    while c > MIN_CONCURRENCY {
        match capacity.compare_exchange_weak(c, c - 1, SeqCst, SeqCst) {
            Ok(_) => return true,
            Err(now) => c = now,
        }
    }
    false
}

/// Completion tracking without keeping a handle per task (memory stays flat).
struct Pending {
    count: AtomicUsize,
    done: Notify,
}

/// Decrements `Pending` when a task ends, including by panic.
struct TaskGuard(Arc<Pending>);

impl TaskGuard {
    fn new(p: &Arc<Pending>) -> Self {
        p.count.fetch_add(1, SeqCst);
        Self(Arc::clone(p))
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, SeqCst) == 1 {
            // `notify_one` stores a permit, so a wakeup can't be lost.
            self.0.done.notify_one();
        }
    }
}

#[derive(Default)]
struct HostAcc {
    ports: Vec<PortResult>,
    closed: u32,
    filtered: u32,
    errors: u32,
    first_error: Option<String>,
}

/// Scan every port of every target, sharing one concurrency budget.
/// Never fails as a whole: per-probe errors are counted per host.
pub async fn scan_targets(targets: &[Target], config: &ScanConfig) -> Vec<ScanResult> {
    let start = Instant::now();
    let mut protocols = Vec::new();
    if config.tcp || !config.udp {
        protocols.push(Transport::Tcp);
    }
    if config.udp {
        protocols.push(Transport::Udp);
    }

    let mut ports = config.ports.clone();
    let mut host_order: Vec<usize> = (0..targets.len()).collect();
    if config.randomize {
        shuffle(&mut ports);
        shuffle(&mut host_order);
    }

    let accs: Arc<Vec<Mutex<HostAcc>>> =
        Arc::new(targets.iter().map(|_| Mutex::default()).collect());
    let sems = Arc::new(Semaphore::new(config.concurrency));
    // Live pool size; shrinks when the OS runs out of sockets.
    let capacity = Arc::new(AtomicUsize::new(config.concurrency));
    // Outstanding tasks + 1 for the spawner itself (see the wait below).
    let pending = Arc::new(Pending {
        count: AtomicUsize::new(1),
        done: Notify::new(),
    });
    let mut ticker = config.rate.map(|r| {
        let mut t = tokio::time::interval(Duration::from_secs_f64(1.0 / r as f64));
        t.set_missed_tick_behavior(MissedTickBehavior::Delay);
        t
    });
    let opts: Vec<ProbeOpts> = targets
        .iter()
        .map(|t| ProbeOpts {
            timeout: config.timeout,
            retries: config.retries,
            banner: config.banner,
            tls: config.tls,
            sni: t.name.as_deref().map(Arc::from),
        })
        .collect();

    for &port in &ports {
        for &h in &host_order {
            for &protocol in &protocols {
                if let Some(t) = ticker.as_mut() {
                    t.tick().await;
                }
                let permit = Arc::clone(&sems)
                    .acquire_owned()
                    .await
                    .expect("semaphore is never closed");
                let addr = targets[h].addr;
                let opts = opts[h].clone();
                let accs = Arc::clone(&accs);
                let live = config.live;
                let sems = Arc::clone(&sems);
                let capacity = Arc::clone(&capacity);
                let guard = TaskGuard::new(&pending);
                tokio::spawn(async move {
                    let _guard = guard;
                    let mut permit = permit;
                    let mut outcome = scan_port(addr, port, protocol, &opts).await;
                    // Adaptive concurrency: the OS ran out of sockets/buffers,
                    // so permanently retire this slot (down to a floor), wait
                    // for a free one and try again.
                    for round in 1..=RESOURCE_RETRIES {
                        if !matches!(outcome, Err(RustScanError::ResourceExhausted(_))) {
                            break;
                        }
                        if try_shrink(&capacity) {
                            permit.forget();
                        } else {
                            drop(permit);
                        }
                        tokio::time::sleep(Duration::from_millis(25 * round as u64)).await;
                        permit = Arc::clone(&sems)
                            .acquire_owned()
                            .await
                            .expect("semaphore is never closed");
                        outcome = scan_port(addr, port, protocol, &opts).await;
                    }
                    drop(permit);
                    let mut acc = accs[h].lock().unwrap_or_else(|p| p.into_inner());
                    match outcome {
                        Ok(pr) => match pr.status {
                            PortStatus::Closed => acc.closed += 1,
                            PortStatus::Filtered => acc.filtered += 1,
                            PortStatus::Open | PortStatus::OpenFiltered => {
                                if live && pr.status == PortStatus::Open {
                                    let proto = if protocol == Transport::Udp {
                                        "/udp"
                                    } else {
                                        ""
                                    };
                                    eprintln!("Open {}{proto}", SocketAddr::new(addr, port));
                                }
                                acc.ports.push(pr);
                            }
                        },
                        Err(e) => {
                            acc.errors += 1;
                            acc.first_error.get_or_insert_with(|| e.to_string());
                        }
                    }
                });
            }
        }
    }

    // Drop the spawner's own token; the last finished task (or we) wakes us.
    if pending.count.fetch_sub(1, SeqCst) != 1 {
        pending.done.notified().await;
    }
    let elapsed = start.elapsed();
    let final_capacity = capacity.load(SeqCst);
    if final_capacity < config.concurrency {
        warn!(
            "OS socket limit reached: concurrency adapted {} → {final_capacity}; pass -c {final_capacity} to avoid the slowdown",
            config.concurrency
        );
    }
    let total = (config.ports.len() * protocols.len()) as u32;

    let ptrs: Vec<Option<String>> = if config.resolve_dns {
        futures::future::join_all(targets.iter().map(|t| crate::dns::reverse_dns(t.addr))).await
    } else {
        vec![None; targets.len()]
    };

    targets
        .iter()
        .zip(ptrs)
        .enumerate()
        .map(|(i, (t, ptr))| {
            let mut acc = std::mem::take(&mut *accs[i].lock().unwrap_or_else(|p| p.into_inner()));
            acc.ports
                .sort_unstable_by_key(|p| (p.port, p.protocol == Transport::Udp));
            // Anything not accounted for (e.g. a panicked task) is an error too.
            let seen = acc.ports.len() as u32 + acc.closed + acc.filtered + acc.errors;
            acc.errors += total.saturating_sub(seen);
            if acc.errors > 0 {
                warn!(
                    target = %t.addr,
                    errors = acc.errors,
                    first_error = acc.first_error.as_deref().unwrap_or("task did not complete"),
                    "{} probes failed, results are incomplete (try a lower --concurrency)",
                    acc.errors
                );
            }
            debug!(target = %t.addr, open = acc.ports.len(), closed = acc.closed, filtered = acc.filtered, "host done");
            ScanResult {
                target: t.addr.to_string(),
                hostname: ptr.or_else(|| t.name.clone()),
                total_ports: total,
                elapsed,
                ports: acc.ports,
                closed: acc.closed,
                filtered: acc.filtered,
                errors: acc.errors,
            }
        })
        .collect()
}

// ─── SYN scan ─────────────────────────────────────────────────────────────────

fn open_tcp_result(port: u16) -> PortResult {
    PortResult {
        port,
        protocol: Transport::Tcp,
        status: PortStatus::Open,
        service: detect_service(port, Transport::Tcp),
        banner: None,
        tls: false,
        tls_cert: None,
        legacy_tls: None,
    }
}

/// Half-open TCP scan over raw sockets (see `syn.rs`). Banner / TLS probes
/// then run only against the ports the SYN sweep found open, and UDP (if
/// requested) goes through the regular engine.
pub async fn syn_scan_targets(
    targets: &[Target],
    config: &ScanConfig,
) -> Result<Vec<ScanResult>, RustScanError> {
    use crate::syn::{syn_scan_blocking, SynParams};
    use futures::StreamExt;

    let start = Instant::now();
    let v4: Vec<std::net::Ipv4Addr> = targets
        .iter()
        .map(|t| match t.addr {
            IpAddr::V4(a) => Ok(a),
            IpAddr::V6(a) => Err(RustScanError::InvalidOption(format!(
                "SYN scan is IPv4-only; {a} needs a connect scan (drop --syn)"
            ))),
        })
        .collect::<Result<_, _>>()?;
    let params = SynParams {
        timeout: config.timeout,
        retries: config.retries,
        rate: config.rate,
        randomize: config.randomize,
        live: config.live,
    };
    let ports = config.ports.clone();
    let hosts = tokio::task::spawn_blocking(move || syn_scan_blocking(&v4, &ports, &params))
        .await
        .map_err(|e| RustScanError::Io(io::Error::other(e)))?
        .map_err(RustScanError::Io)?;

    let mut results = Vec::with_capacity(targets.len());
    for (t, host) in targets.iter().zip(hosts) {
        let opts = ProbeOpts {
            timeout: config.timeout,
            retries: config.retries,
            banner: config.banner,
            tls: config.tls,
            sni: t.name.as_deref().map(Arc::from),
        };
        let ports: Vec<PortResult> = if config.banner || config.tls {
            futures::stream::iter(host.open.iter().copied())
                .map(|port| {
                    let opts = &opts;
                    async move {
                        match scan_port(t.addr, port, Transport::Tcp, opts).await {
                            // The SYN sweep's verdict stands; keep the probe data.
                            Ok(mut pr) => {
                                pr.status = PortStatus::Open;
                                pr
                            }
                            Err(_) => open_tcp_result(port),
                        }
                    }
                })
                .buffered(config.concurrency.min(256))
                .collect()
                .await
        } else {
            host.open.iter().map(|&p| open_tcp_result(p)).collect()
        };
        results.push(ScanResult {
            target: t.addr.to_string(),
            hostname: t.name.clone(),
            total_ports: config.ports.len() as u32,
            elapsed: Duration::ZERO,
            ports,
            closed: host.closed,
            filtered: host.filtered,
            errors: 0,
        });
    }

    if config.udp {
        let udp_cfg = ScanConfig {
            tcp: false,
            resolve_dns: false,
            ..config.clone()
        };
        for (r, u) in results
            .iter_mut()
            .zip(scan_targets(targets, &udp_cfg).await)
        {
            r.ports.extend(u.ports);
            r.ports
                .sort_unstable_by_key(|p| (p.port, p.protocol == Transport::Udp));
            r.total_ports += u.total_ports;
            r.closed += u.closed;
            r.filtered += u.filtered;
            r.errors += u.errors;
        }
    }
    if config.resolve_dns {
        let ptrs =
            futures::future::join_all(targets.iter().map(|t| crate::dns::reverse_dns(t.addr)))
                .await;
        for (r, ptr) in results.iter_mut().zip(ptrs) {
            r.hostname = ptr.or(r.hostname.take());
        }
    }
    let elapsed = start.elapsed();
    results.iter_mut().for_each(|r| r.elapsed = elapsed);
    Ok(results)
}

// ─── Host discovery ───────────────────────────────────────────────────────────

/// Ports used to decide whether a host is up (any answer, even RST, counts).
pub const DISCOVERY_PORTS: &[u16] = &[
    80, 443, 22, 445, 3389, 21, 25, 53, 135, 139, 8080, 8443, 23, 110, 143, 3306, 5900,
];

/// Keep only hosts that answer on any of `ports` (open *or* closed — an RST
/// proves the host is alive). Unprivileged equivalent of nmap's ping scan.
pub async fn discover(targets: Vec<Target>, config: &ScanConfig, ports: &[u16]) -> Vec<Target> {
    let probe = ScanConfig {
        ports: ports.to_vec(),
        retries: 0,
        banner: false,
        tls: false,
        tcp: true,
        udp: false,
        resolve_dns: false,
        live: false,
        ..config.clone()
    };
    let results = scan_targets(&targets, &probe).await;
    targets
        .into_iter()
        .zip(results)
        .filter(|(_, r)| !r.ports.is_empty() || r.closed > 0)
        .map(|(t, _)| t)
        .collect()
}

fn is_self_connect(local: Option<SocketAddr>, remote: SocketAddr) -> bool {
    local == Some(remote)
}

/// In-place Fisher–Yates with a xorshift PRNG seeded from std's random hasher
/// keys. Not cryptographic — only meant to avoid sequential, IDS-obvious order.
pub(crate) fn shuffle<T>(v: &mut [T]) {
    use std::hash::{BuildHasher, Hasher};
    let mut x = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
        | 1;
    for i in (1..v.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.swap(i, (x % (i as u64 + 1)) as usize);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn opts(ms: u64) -> ProbeOpts {
        ProbeOpts {
            timeout: Duration::from_millis(ms),
            retries: 0,
            banner: false,
            tls: false,
            sni: None,
        }
    }

    fn config(ports: Vec<u16>) -> ScanConfig {
        ScanConfig {
            ports,
            timeout: Duration::from_millis(300),
            concurrency: 16,
            retries: 0,
            rate: None,
            randomize: true,
            banner: false,
            tls: false,
            tcp: true,
            udp: false,
            resolve_dns: false,
            live: false,
        }
    }

    /// Every probed port must land in exactly one bucket.
    fn accounted(r: &ScanResult) -> u32 {
        r.ports.len() as u32 + r.closed + r.filtered + r.errors
    }

    fn make_result(statuses: &[(u16, PortStatus)]) -> ScanResult {
        ScanResult {
            target: "127.0.0.1".into(),
            hostname: None,
            total_ports: statuses.len() as u32,
            elapsed: Duration::from_millis(1),
            ports: statuses
                .iter()
                .map(|(p, s)| PortResult {
                    port: *p,
                    protocol: Transport::Tcp,
                    status: s.clone(),
                    service: detect_service(*p, Transport::Tcp),
                    banner: None,
                    tls: false,
                    tls_cert: None,
                    legacy_tls: None,
                })
                .collect(),
            closed: 0,
            filtered: 0,
            errors: 0,
        }
    }

    #[tokio::test]
    async fn closed_port_returns_closed_or_filtered() {
        let r = scan_port(LOCAL, 1, Transport::Tcp, &opts(500))
            .await
            .unwrap();
        assert_eq!(r.port, 1);
        assert!(matches!(
            r.status,
            PortStatus::Closed | PortStatus::Filtered
        ));
    }

    /// TEST-NET-1 (192.0.2.0/24, RFC 5737) is not routable — always Filtered.
    #[tokio::test]
    async fn unreachable_address_returns_filtered() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let r = scan_port(ip, 80, Transport::Tcp, &opts(100)).await.unwrap();
        assert_eq!(r.status, PortStatus::Filtered);
    }

    /// ICMP port-unreachable must map to Closed on every OS.
    #[tokio::test]
    async fn closed_udp_port_returns_closed() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port(); // socket dropped: port now closed
        let r = scan_port(LOCAL, port, Transport::Udp, &opts(500))
            .await
            .unwrap();
        assert_eq!(r.status, PortStatus::Closed);
    }

    #[tokio::test]
    async fn answering_udp_service_is_open() {
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut b = [0u8; 64];
            if let Ok((_, from)) = srv.recv_from(&mut b) {
                let _ = srv.send_to(b"pong", from);
            }
        });
        let r = scan_port(LOCAL, port, Transport::Udp, &opts(1000))
            .await
            .unwrap();
        assert_eq!(r.status, PortStatus::Open);
    }

    #[test]
    fn open_count_counts_only_open_ports() {
        let scan = make_result(&[
            (22, PortStatus::Open),
            (80, PortStatus::Open),
            (161, PortStatus::OpenFiltered),
        ]);
        assert_eq!(scan.open_count(), 2);
        assert_eq!(scan.open_ports().count(), 3);
    }

    #[tokio::test]
    async fn scan_keeps_only_open_ports_and_accounts_for_all() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let results = scan_targets(
            &[Target::ip(LOCAL)],
            &config(vec![open - 2, open - 1, open]),
        )
        .await;
        let r = &results[0];
        assert!(r.ports.iter().all(|p| p.status == PortStatus::Open));
        assert!(r.ports.iter().any(|p| p.port == open));
        assert_eq!(r.total_ports, 3);
        assert_eq!(accounted(r), 3);
    }

    #[tokio::test]
    async fn multi_host_results_are_per_host_and_complete() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let targets = [Target::ip(LOCAL), Target::ip("192.0.2.1".parse().unwrap())];
        let mut cfg = config(vec![open, 9]);
        cfg.concurrency = 1; // forces queueing through the semaphore
        cfg.timeout = Duration::from_millis(200);
        let results = scan_targets(&targets, &cfg).await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].target, "127.0.0.1");
        assert!(results[0].ports.iter().any(|p| p.port == open));
        assert_eq!(accounted(&results[0]), 2);
        assert_eq!(results[1].filtered, 2, "TEST-NET host is silent");
    }

    #[tokio::test]
    async fn udp_and_tcp_both_scanned() {
        let mut cfg = config(vec![9]);
        cfg.udp = true;
        let r = &scan_targets(&[Target::ip(LOCAL)], &cfg).await[0];
        assert_eq!(r.total_ports, 2);
        assert_eq!(accounted(r), 2);
    }

    #[tokio::test]
    async fn rate_limit_spaces_out_probes() {
        let mut cfg = config((1..=10).collect());
        cfg.rate = Some(20); // 10 probes at 20/s ≥ 450 ms
        let t = Instant::now();
        scan_targets(&[Target::ip(LOCAL)], &cfg).await;
        assert!(
            t.elapsed() >= Duration::from_millis(400),
            "{:?}",
            t.elapsed()
        );
    }

    #[tokio::test]
    async fn discovery_drops_silent_hosts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let up = Target::ip(LOCAL);
        let down = Target::ip("192.0.2.1".parse().unwrap());
        let mut cfg = config(vec![]);
        cfg.timeout = Duration::from_millis(200);
        let alive = discover(vec![up.clone(), down], &cfg, &[port]).await;
        assert_eq!(alive, vec![up]);
    }

    #[test]
    fn resource_errors_are_classified_as_retryable() {
        let res =
            |e: io::Error| matches!(os_error("x".into(), e), RustScanError::ResourceExhausted(_));
        assert!(res(io::Error::from_raw_os_error(if cfg!(windows) {
            10055
        } else {
            24
        })));
        assert!(res(io::Error::from(io::ErrorKind::AddrNotAvailable)));
        assert!(!res(io::Error::from(io::ErrorKind::InvalidInput)));
    }

    /// A tiny pool still finishes every probe (guards the completion tracker).
    #[tokio::test]
    async fn completes_with_minimal_concurrency() {
        let mut cfg = config((1..=8).collect());
        cfg.concurrency = 1;
        cfg.timeout = Duration::from_millis(100);
        let r = &scan_targets(&[Target::ip(LOCAL)], &cfg).await[0];
        assert_eq!(accounted(r), 8);
    }

    #[test]
    fn capacity_shrinks_to_floor_only() {
        let c = AtomicUsize::new(MIN_CONCURRENCY + 1);
        assert!(try_shrink(&c));
        assert!(!try_shrink(&c));
        assert_eq!(c.load(SeqCst), MIN_CONCURRENCY);
    }

    #[tokio::test]
    async fn syn_scan_rejects_ipv6() {
        let err = syn_scan_targets(&[Target::ip("::1".parse().unwrap())], &config(vec![80]))
            .await
            .unwrap_err();
        assert!(matches!(err, RustScanError::InvalidOption(_)));
    }

    #[test]
    fn self_connect_is_detected() {
        let a: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        assert!(is_self_connect(Some(a), a));
        assert!(!is_self_connect(
            Some("127.0.0.1:40001".parse().unwrap()),
            a
        ));
        assert!(!is_self_connect(None, a));
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut v: Vec<u32> = (0..1000).collect();
        shuffle(&mut v);
        assert_ne!(v, (0..1000).collect::<Vec<_>>(), "should not stay sorted");
        v.sort_unstable();
        assert_eq!(v, (0..1000).collect::<Vec<_>>());
    }
}
