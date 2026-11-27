//! syn.rs — Half-open (SYN) scanning, IPv4 and IPv6.
//!
//! The same technique as `nmap -sS`, masscan and naabu: send a bare SYN,
//! read the answer straight off the wire, never finish the handshake.
//!   SYN-ACK → open     RST → closed     silence (after retries) → filtered
//! It is faster than a connect scan, uses no file descriptor per probe and is
//! not logged by the services themselves (no connection is ever accepted).
//!
//! Replies are matched statelessly, masscan-style: every SYN carries a
//! sequence number derived from (secret, target IP, target port), and only
//! replies whose ACK equals that cookie + 1 are accepted. Per-probe state is
//! one byte, so even large scans stay small.
//!
//! Two ways onto the wire, one engine:
//! - **Linux**: raw sockets (root or `CAP_NET_RAW`).
//! - **macOS / Windows** (and Linux with `RUSTSCAN_SYN_BACKEND=pcap`):
//!   libpcap / Npcap, loaded at run time. Their kernels don't hand TCP to raw
//!   sockets (and Windows won't send it), so whole frames are injected and
//!   replies captured. The link-layer header for each target is learnt by
//!   capturing one ordinary UDP datagram the OS sends there — the OS does
//!   the ARP / neighbour lookup and routing for us.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// TCP header we send: 20 bytes + one MSS option, like a real SYN.
pub const TCP_HDR_LEN: usize = 24;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// Probe state, one byte per (host, port).
pub const UNANSWERED: u8 = 0;
pub const OPEN: u8 = 1;
pub const CLOSED: u8 = 2;

/// Upper bound on hosts × ports in one SYN scan (1 byte of state each).
pub const MAX_PROBES: usize = 400_000_000;

/// Parameters of a SYN scan.
#[derive(Debug, Clone)]
pub struct SynParams {
    pub timeout: Duration,
    pub retries: u8,
    pub rate: Option<u32>,
    pub randomize: bool,
    pub live: bool,
}

/// Outcome per host (same order as the input addresses).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SynHost {
    pub open: Vec<u16>,
    pub closed: u32,
    pub filtered: u32,
}

/// Stateless sequence number for (dst, dport) — a SYN cookie.
pub fn cookie(secret: u32, dst: IpAddr, dport: u16) -> u32 {
    let a = match dst {
        IpAddr::V4(a) => u32::from(a),
        IpAddr::V6(a) => a.octets().chunks(4).fold(0u32, |h, c| {
            h.rotate_left(7) ^ u32::from_be_bytes([c[0], c[1], c[2], c[3]])
        }),
    };
    let x = a ^ (((dport as u32) << 16) | dport as u32) ^ secret;
    let x = x.wrapping_mul(0x9E37_79B1);
    x ^ (x >> 15)
}

/// Internet checksum, continuing from a partial sum.
fn sum16(mut sum: u32, bytes: &[u8]) -> u32 {
    for ch in bytes.chunks(2) {
        sum += u16::from_be_bytes([ch[0], *ch.get(1).unwrap_or(&0)]) as u32;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// TCP checksum over the IPv4 (RFC 793) or IPv6 (RFC 8200) pseudo-header.
/// Both sum to the same words: addresses, protocol 6, segment length.
pub fn tcp_checksum(src: IpAddr, dst: IpAddr, segment: &[u8]) -> u16 {
    let mut sum = sum16(0, &octets(src));
    sum = sum16(sum, &octets(dst));
    sum = sum16(sum, &[0, 6]);
    sum = sum16(sum, &(segment.len() as u16).to_be_bytes());
    fold(sum16(sum, segment))
}

/// A SYN segment (TCP header only).
pub fn build_syn(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, seq: u32) -> [u8; TCP_HDR_LEN] {
    let mut h = [0u8; TCP_HDR_LEN];
    h[0..2].copy_from_slice(&sport.to_be_bytes());
    h[2..4].copy_from_slice(&dport.to_be_bytes());
    h[4..8].copy_from_slice(&seq.to_be_bytes());
    h[12] = ((TCP_HDR_LEN / 4) as u8) << 4; // data offset in 32-bit words
    h[13] = SYN;
    h[14..16].copy_from_slice(&64240u16.to_be_bytes()); // window, like Linux
    h[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
    let c = tcp_checksum(src, dst, &h);
    h[16..18].copy_from_slice(&c.to_be_bytes());
    h
}

/// IPv4 / IPv6 header for a TCP payload of `len` bytes (for frame injection).
pub fn ip_header(src: IpAddr, dst: IpAddr, len: usize, id: u16) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = vec![0x45, 0];
            h.extend(((20 + len) as u16).to_be_bytes());
            h.extend(id.to_be_bytes());
            h.extend([0x40, 0, 64, 6, 0, 0]); // DF, TTL 64, TCP, checksum
            h.extend(s.octets());
            h.extend(d.octets());
            let c = fold(sum16(0, &h));
            h[10..12].copy_from_slice(&c.to_be_bytes());
            h
        }
        _ => {
            let mut h = vec![0x60, 0, 0, 0];
            h.extend((len as u16).to_be_bytes());
            h.extend([6, 64]); // next header TCP, hop limit 64
            h.extend(octets(src));
            h.extend(octets(dst));
            h
        }
    }
}

/// The fields of an incoming TCP segment we care about.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub src: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub ack: u32,
    pub flags: u8,
}

/// Parse a bare TCP segment from `src` (raw IPv6 sockets strip the IP header).
pub fn parse_tcp(src: IpAddr, tcp: &[u8]) -> Option<Reply> {
    if tcp.len() < 20 {
        return None;
    }
    Some(Reply {
        src,
        sport: u16::from_be_bytes([tcp[0], tcp[1]]),
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
    })
}

/// Parse an IPv4 or IPv6 packet carrying TCP (no IPv6 extension headers).
pub fn parse_reply(pkt: &[u8]) -> Option<Reply> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 && pkt[9] == 6 => {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            (ihl >= 20).then_some(())?;
            parse_tcp(src.into(), pkt.get(ihl..)?)
        }
        6 if pkt.len() >= 40 && pkt[6] == 6 => {
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            parse_tcp(src.into(), &pkt[40..])
        }
        _ => None,
    }
}

/// SYN-ACK → open, RST → closed, anything else (e.g. our own SYN looping
/// back on `lo`) → ignored.
pub fn classify(flags: u8) -> Option<u8> {
    if flags & (SYN | ACK) == SYN | ACK {
        Some(OPEN)
    } else if flags & RST != 0 {
        Some(CLOSED)
    } else {
        None
    }
}

/// Which local address the kernel would use to reach `dst` (no packet sent).
pub fn source_addr_for(dst: IpAddr) -> io::Result<IpAddr> {
    let any: IpAddr = match dst {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let s = std::net::UdpSocket::bind((any, 0))?;
    s.connect((dst, 53))?;
    Ok(s.local_addr()?.ip())
}

/// Run a SYN scan (blocking — call via `spawn_blocking`).
pub fn syn_scan_blocking(
    addrs: &[IpAddr],
    ports: &[u16],
    p: &SynParams,
) -> io::Result<Vec<SynHost>> {
    let n = addrs.len() * ports.len();
    if n > MAX_PROBES {
        return Err(io::Error::other(format!(
            "SYN scan of {n} probes is too large — split the target range"
        )));
    }
    #[cfg(target_os = "linux")]
    if !use_pcap() {
        return linux::scan(addrs, ports, p);
    }
    frames::scan(addrs, ports, p)
}

/// Linux uses raw sockets unless `RUSTSCAN_SYN_BACKEND=pcap`.
#[cfg(target_os = "linux")]
fn use_pcap() -> bool {
    std::env::var_os("RUSTSCAN_SYN_BACKEND").is_some_and(|v| v == "pcap")
}

/// True when SYN mode can safely probe dead hosts too (root with
/// CAP_NET_ADMIN, so the raw socket's send buffer can be enlarged). Then
/// multi-host SYN scans discover hosts inline; otherwise they use the
/// connect-based ping first.
pub fn inline_discovery_ok() -> bool {
    #[cfg(target_os = "linux")]
    {
        !use_pcap() && linux::big_send_buffer()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// ─── Engine (shared by both backends) ─────────────────────────────────────────

/// What happened to one SYN.
pub(crate) enum Sent {
    Ok,
    /// Queue still full after `MAX_BACKOFF` (transient pressure clears
    /// faster than that; an unresolved neighbour's ARP queue doesn't).
    QueueFull,
    /// Refused outright (no route, local firewall, ARP failed).
    Unreachable,
}

/// How long one probe waits out a full send queue before giving up.
const MAX_BACKOFF: Duration = Duration::from_millis(10);

/// Per-scan secret and source port.
struct Session {
    secret: u32,
    sport: u16,
}

impl Session {
    fn new() -> Self {
        use std::hash::{BuildHasher, Hasher};
        let secret = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish() as u32;
        // Fixed, random-ish source port: the kernel has no socket on it, so
        // it answers SYN-ACKs with RST for us — the "half-open" part.
        Self {
            secret,
            sport: 40000 + (secret % 20000) as u16,
        }
    }
}

/// A receiver: returns the next TCP reply, or `None` after a short timeout
/// (so the loop can notice the scan has ended).
type Rx<'a> = Box<dyn FnMut() -> Option<Reply> + Send + 'a>;

/// Send every probe (with retries), match replies, tally per host.
///
/// `send(host, segment)` puts one TCP segment on the wire; `srcs[h]` is the
/// local address for host `h` (`None` = unreachable, skipped). `forced`:
/// the send path can't be starved by dead hosts (see the Linux backend).
#[allow(clippy::too_many_arguments)]
fn engine(
    addrs: &[IpAddr],
    srcs: &[Option<IpAddr>],
    ports: &[u16],
    p: &SynParams,
    sess: &Session,
    forced: bool,
    mut send: impl FnMut(usize, &[u8]) -> io::Result<Sent>,
    receivers: Vec<Rx<'_>>,
) -> io::Result<Vec<SynHost>> {
    use std::collections::HashMap;

    let n = addrs.len() * ports.len();
    let host_idx: HashMap<IpAddr, usize> = addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect();
    let mut port_idx = vec![u32::MAX; 65536];
    for (i, &port) in ports.iter().enumerate() {
        port_idx[port as usize] = i as u32;
    }
    let state: Vec<AtomicU8> = (0..n).map(|_| AtomicU8::new(UNANSWERED)).collect();
    let stop = AtomicBool::new(false);
    // Replies seen per host (lets the sender tell dead hosts from busy ones).
    let answered: Vec<AtomicU32> = (0..addrs.len()).map(|_| AtomicU32::new(0)).collect();
    let np = ports.len();
    let mut warned = false;

    let mut order_ports = ports.to_vec();
    let mut order_hosts: Vec<usize> = (0..addrs.len()).collect();
    if p.randomize {
        crate::scanner::shuffle(&mut order_ports);
        crate::scanner::shuffle(&mut order_hosts);
    }

    std::thread::scope(|s| -> io::Result<()> {
        // ── Receivers ─────────────────────────────────────────────────────
        for mut rx in receivers {
            let (stop, host_idx, port_idx, state, answered) =
                (&stop, &host_idx, &port_idx, &state, &answered);
            s.spawn(move || {
                while !stop.load(Relaxed) {
                    let Some(r) = rx() else { continue };
                    if r.dport != sess.sport {
                        continue;
                    }
                    let (Some(&h), pi) = (host_idx.get(&r.src), port_idx[r.sport as usize]) else {
                        continue;
                    };
                    if pi == u32::MAX
                        || r.ack != cookie(sess.secret, r.src, r.sport).wrapping_add(1)
                    {
                        continue; // not an answer to one of our probes
                    }
                    let Some(v) = classify(r.flags) else { continue };
                    let slot = &state[h * np + pi as usize];
                    if slot
                        .compare_exchange(UNANSWERED, v, Relaxed, Relaxed)
                        .is_ok()
                    {
                        answered[h].fetch_add(1, Relaxed);
                        if v == OPEN && p.live {
                            eprintln!("Open {}", std::net::SocketAddr::new(r.src, r.sport));
                        }
                    }
                }
            });
        }

        // ── Sender ────────────────────────────────────────────────────────
        let result = (|| -> io::Result<()> {
            let gap = p.rate.map(|r| Duration::from_secs_f64(1.0 / r as f64));
            let mut next = Instant::now();
            for pass in 0..=p.retries {
                // Hosts given up on *for this pass*. Reset each pass, so a
                // live host whose ARP was merely slow gets every port
                // re-sent in the retry pass instead of being lost.
                let mut skip = vec![false; addrs.len()];
                let pass_start = Instant::now();
                let mut sent = 0usize;
                for &port in &order_ports {
                    let pi = port_idx[port as usize] as usize;
                    for &h in &order_hosts {
                        if state[h * np + pi].load(Relaxed) != UNANSWERED {
                            continue;
                        }
                        let Some(src) = srcs[h] else { continue };
                        if skip[h] {
                            continue;
                        }
                        if let Some(gap) = gap {
                            let now = Instant::now();
                            if next > now {
                                std::thread::sleep(next - now);
                            }
                            next = next.max(now) + gap;
                        }
                        let dst = addrs[h];
                        let seg =
                            build_syn(src, dst, sess.sport, port, cookie(sess.secret, dst, port));
                        match send(h, &seg)? {
                            Sent::Ok => sent += 1,
                            // Global backpressure. With a forced-big buffer
                            // it's rare and transient: lose only this probe,
                            // the next pass re-sends it. Otherwise dead
                            // hosts would stall every send, so skip
                            // never-answered hosts for this pass (a live one
                            // may be crowded out — warned once).
                            Sent::QueueFull => {
                                if !forced && answered[h].load(Relaxed) == 0 {
                                    skip[h] = true;
                                    if !warned {
                                        warned = true;
                                        tracing::warn!(
                                            "SYN send buffer is limited (no CAP_NET_ADMIN): many dead \
                                             local hosts can crowd out live ones — run as root, or keep \
                                             host discovery on"
                                        );
                                    }
                                }
                            }
                            // A definitive "no route / ARP failed" for a host
                            // that never answered: skip it for this pass.
                            Sent::Unreachable => {
                                if answered[h].load(Relaxed) == 0 {
                                    skip[h] = true;
                                }
                            }
                        }
                    }
                }
                tracing::debug!(
                    pass,
                    sent,
                    send_ms = pass_start.elapsed().as_millis() as u64,
                    "syn pass sent"
                );
                if sent == 0 {
                    break; // everything answered
                }
                // Give the last replies time to arrive.
                std::thread::sleep(p.timeout);
            }
            Ok(())
        })();
        stop.store(true, Relaxed);
        result
    })?;

    Ok((0..addrs.len())
        .map(|h| {
            let mut host = SynHost::default();
            for (pi, &port) in ports.iter().enumerate() {
                match state[h * np + pi].load(Relaxed) {
                    OPEN => host.open.push(port),
                    CLOSED => host.closed += 1,
                    _ => host.filtered += 1,
                }
            }
            host
        })
        .collect())
}

// ─── Linux: raw sockets ───────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Read;
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    fn raw_socket(domain: Domain) -> io::Result<Socket> {
        let sock = Socket::new(domain, Type::RAW, Some(Protocol::TCP)).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(
                    e.kind(),
                    "SYN scan needs root or CAP_NET_RAW (e.g. `sudo setcap cap_net_raw+ep $(which rustscan-rs)`) — or drop --syn",
                )
            } else {
                e
            }
        })?;
        sock.set_recv_buffer_size(16 << 20).ok();
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        Ok(sock)
    }

    pub fn scan(addrs: &[IpAddr], ports: &[u16], p: &SynParams) -> io::Result<Vec<SynHost>> {
        // One raw socket per address family in use. IPv4 raw sockets read
        // whole IP packets; IPv6 ones only the TCP segment (+ source).
        let s4 = addrs
            .iter()
            .any(IpAddr::is_ipv4)
            .then(|| raw_socket(Domain::IPV4))
            .transpose()?;
        let s6 = addrs
            .iter()
            .any(IpAddr::is_ipv6)
            .then(|| raw_socket(Domain::IPV6))
            .transpose()?;
        let forced = [&s4, &s6]
            .into_iter()
            .flatten()
            .all(|s| force_send_buffer(s, SEND_BUFFER));

        // `None` = no usable route (e.g. a broadcast address inside a CIDR):
        // that host is skipped and its ports end up filtered.
        let srcs: Vec<Option<IpAddr>> = addrs.iter().map(|a| source_addr_for(*a).ok()).collect();

        let mut receivers: Vec<Rx> = Vec::new();
        if let Some(s) = &s4 {
            let mut rx = s.try_clone()?;
            let mut buf = [0u8; 4096];
            receivers.push(Box::new(move || {
                let len = rx.read(&mut buf).ok()?;
                parse_reply(&buf[..len])
            }));
        }
        if let Some(s) = &s6 {
            let rx = s.try_clone()?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 4096];
            receivers.push(Box::new(move || {
                let (len, from) = rx.recv_from(&mut buf).ok()?;
                // SAFETY: recv_from initialised the first `len` bytes.
                let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), len) };
                parse_tcp(from.as_socket()?.ip(), data)
            }));
        }

        let sess = Session::new();
        engine(
            addrs,
            &srcs,
            ports,
            p,
            &sess,
            forced,
            |h, seg| {
                let dst = addrs[h];
                let sock = if dst.is_ipv4() { &s4 } else { &s6 };
                send(sock.as_ref().expect("socket per family"), seg, dst)
            },
            receivers,
        )
    }

    const SEND_BUFFER: libc::c_int = 64 << 20;

    /// A big send buffer keeps SYNs queued for unresolved (dead) neighbours
    /// from starving sends to live hosts. `SO_SNDBUFFORCE` ignores the
    /// `wmem_max` cap but needs CAP_NET_ADMIN (i.e. root); without it fall
    /// back to plain `SO_SNDBUF`. Returns whether the big buffer took effect.
    fn force_send_buffer(sock: &Socket, bytes: libc::c_int) -> bool {
        use std::os::fd::AsRawFd;
        // SAFETY: valid fd, pointer to a live c_int of the given size.
        let forced = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUFFORCE,
                (&bytes as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        } == 0;
        if !forced {
            sock.set_send_buffer_size(bytes as usize).ok();
        }
        forced
    }

    /// Can this process open a raw socket *and* get the big send buffer?
    /// Then SYN mode can discover hosts inline instead of a connect ping.
    pub fn big_send_buffer() -> bool {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
            .map(|s| force_send_buffer(&s, SEND_BUFFER))
            .unwrap_or(false)
    }

    /// Send one SYN, waiting out kernel backpressure.
    fn send(sock: &Socket, pkt: &[u8], dst: IpAddr) -> io::Result<Sent> {
        // Port 0: raw IPv6 sockets reject any other value.
        let to = SockAddr::from(SocketAddr::new(dst, 0));
        let started = Instant::now();
        loop {
            match sock.send_to(pkt, &to) {
                Ok(_) => return Ok(Sent::Ok),
                // ENOBUFS / EAGAIN: send buffer or queue full — wait.
                Err(e) if matches!(e.raw_os_error(), Some(105 | 11)) => {
                    if started.elapsed() >= MAX_BACKOFF {
                        return Ok(Sent::QueueFull);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::PermissionDenied
                            | io::ErrorKind::NetworkUnreachable
                            | io::ErrorKind::HostUnreachable
                    ) =>
                {
                    return Ok(Sent::Unreachable)
                }
                Err(e) => return Err(e),
            }
        }
    }
}

// ─── Frame injection via libpcap / Npcap ──────────────────────────────────────

mod frames {
    use super::*;
    use crate::pcap::{device_for, Capture};
    use std::collections::HashMap;

    /// Bytes before the IP header for a link type, or `None` if unsupported.
    pub fn link_len(dlt: i32) -> Option<usize> {
        match dlt {
            0 | 108 => Some(4),       // NULL / LOOP: address family (BSD & Npcap loopback)
            1 => Some(14),            // Ethernet
            12 | 14 | 101 => Some(0), // raw IP
            _ => None,
        }
    }

    /// Offset of the IP header in a captured frame (skips one 802.1Q tag).
    pub fn ip_offset(frame: &[u8], l2: usize) -> usize {
        if l2 == 14 && frame.get(12..14) == Some(&[0x81, 0x00]) {
            18
        } else {
            l2
        }
    }

    /// Destination of an outbound UDP packet: (dst address, dst port).
    pub fn udp_dst(ip: &[u8]) -> Option<(IpAddr, u16)> {
        let (dst, udp): (IpAddr, &[u8]) = match ip.first()? >> 4 {
            4 if ip.len() >= 20 && ip[9] == 17 => {
                let ihl = (ip[0] & 0x0f) as usize * 4;
                (
                    Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).into(),
                    ip.get(ihl..)?,
                )
            }
            6 if ip.len() >= 40 && ip[6] == 17 => (
                Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?).into(),
                &ip[40..],
            ),
            _ => return None,
        };
        Some((dst, u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?])))
    }

    pub fn scan(addrs: &[IpAddr], ports: &[u16], p: &SynParams) -> io::Result<Vec<SynHost>> {
        let srcs: Vec<Option<IpAddr>> = addrs.iter().map(|a| source_addr_for(*a).ok()).collect();
        // One capture device per source address; scan each group in turn.
        let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (h, src) in srcs.iter().enumerate() {
            if let Some(src) = src {
                groups.entry(device_for(*src)?).or_default().push(h);
            }
        }
        let mut out = vec![
            SynHost {
                filtered: ports.len() as u32,
                ..Default::default()
            };
            addrs.len()
        ];
        for (dev, hosts) in groups {
            let sub: Vec<IpAddr> = hosts.iter().map(|&h| addrs[h]).collect();
            let sub_srcs: Vec<Option<IpAddr>> = hosts.iter().map(|&h| srcs[h]).collect();
            for (h, r) in hosts
                .into_iter()
                .zip(scan_device(&dev, &sub, &sub_srcs, ports, p)?)
            {
                out[h] = r;
            }
        }
        Ok(out)
    }

    fn scan_device(
        dev: &str,
        addrs: &[IpAddr],
        srcs: &[Option<IpAddr>],
        ports: &[u16],
        p: &SynParams,
    ) -> io::Result<Vec<SynHost>> {
        let sess = Session::new();
        // Separate handles for injecting and capturing: a pcap_t isn't
        // meant to be used from two threads at once.
        let mut tx = Capture::open(dev)?;
        let mut rx = Capture::open(dev)?;
        let l2 = link_len(tx.datalink()).ok_or_else(|| {
            io::Error::other(format!(
                "SYN scan: unsupported link type {} on {dev}",
                tx.datalink()
            ))
        })?;
        rx.filter(&format!("tcp dst port {}", sess.sport))?;

        let learn = learn_link_headers(&mut tx, l2, addrs, srcs, sess.sport.wrapping_add(1), p)?;
        // A host whose header couldn't be learnt (dead on-link neighbour:
        // the OS never sent the frame) is skipped → filtered.
        let srcs: Vec<Option<IpAddr>> = srcs
            .iter()
            .zip(&learn)
            .map(|(s, l)| s.filter(|_| l.is_some()))
            .collect();

        let receiver: Rx = Box::new(move || {
            let f = rx.next_frame()?;
            parse_reply(f.get(ip_offset(f, l2)..)?)
        });
        let mut id = sess.secret as u16;
        let mut frame = Vec::with_capacity(96);
        engine(
            addrs,
            &srcs,
            ports,
            p,
            &sess,
            true,
            |h, seg| {
                let (Some(src), Some(head)) = (srcs[h], &learn[h]) else {
                    return Ok(Sent::Unreachable);
                };
                id = id.wrapping_add(1);
                frame.clear();
                frame.extend_from_slice(head);
                frame.extend(ip_header(src, addrs[h], seg.len(), id));
                frame.extend_from_slice(seg);
                let started = Instant::now();
                loop {
                    match tx.send(&frame) {
                        Ok(()) => return Ok(Sent::Ok),
                        Err(_) if started.elapsed() < MAX_BACKOFF => {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        Err(_) => return Ok(Sent::QueueFull),
                    }
                }
            },
            vec![receiver],
        )
    }

    /// Learn each target's link-layer header (MACs / loopback family) by
    /// having the OS send it an empty UDP datagram and capturing the frame.
    fn learn_link_headers(
        cap: &mut Capture,
        l2: usize,
        addrs: &[IpAddr],
        srcs: &[Option<IpAddr>],
        port: u16,
        p: &SynParams,
    ) -> io::Result<Vec<Option<Vec<u8>>>> {
        let mut out = vec![None; addrs.len()];
        cap.filter(&format!("udp dst port {port}"))?;
        let idx: HashMap<IpAddr, usize> = addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        let v4 = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0));
        let v6 = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0));
        let mut pending = 0;
        for (a, s) in addrs.iter().zip(srcs) {
            let sock = if a.is_ipv4() { &v4 } else { &v6 };
            if let (Some(_), Ok(sock)) = (s, sock) {
                pending += sock.send_to(&[], (*a, port)).is_ok() as usize;
            }
        }
        // ARP / neighbour discovery for a live LAN host takes milliseconds;
        // a dead one never resolves.
        let deadline = Instant::now()
            + p.timeout
                .clamp(Duration::from_secs(1), Duration::from_secs(3));
        while pending > 0 && Instant::now() < deadline {
            let Some(f) = cap.next_frame() else { continue };
            let off = ip_offset(f, l2);
            let Some((dst, dport)) = f.get(off..).and_then(udp_dst) else {
                continue;
            };
            if let (true, Some(&h)) = (dport == port, idx.get(&dst)) {
                if out[h].is_none() {
                    out[h] = Some(f[..off].to_vec());
                    pending -= 1;
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const SRC6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const DST6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    #[test]
    fn syn_checksum_verifies() {
        for (s, d) in [
            (SRC.into(), DST.into()),
            (IpAddr::V6(SRC6), IpAddr::V6(DST6)),
        ] {
            let pkt = build_syn(s, d, 40000, 443, 0xdead_beef);
            // Summing a segment that includes its own checksum yields 0.
            assert_eq!(tcp_checksum(s, d, &pkt), 0);
            assert_eq!(pkt[13], SYN);
            assert_eq!(pkt[12] >> 4, 6, "data offset = 6 words (24 bytes)");
        }
    }

    #[test]
    fn checksum_matches_known_vector() {
        // Odd-length segment exercises the padding path.
        let seg = [0x01, 0x02, 0x03];
        // pseudo: 0a00 0001 0a00 0002 0006 0003 + 0102 0300
        let manual: u32 = 0x0a00 + 0x0001 + 0x0a00 + 0x0002 + 0x0006 + 0x0003 + 0x0102 + 0x0300;
        assert_eq!(tcp_checksum(SRC.into(), DST.into(), &seg), !(manual as u16));
    }

    #[test]
    fn ipv4_header_checksum_and_lengths() {
        let h = ip_header(SRC.into(), DST.into(), TCP_HDR_LEN, 7);
        assert_eq!(h.len(), 20);
        assert_eq!(fold(sum16(0, &h)), 0, "header checksum verifies");
        assert_eq!(u16::from_be_bytes([h[2], h[3]]), 44);
        let h6 = ip_header(SRC6.into(), DST6.into(), TCP_HDR_LEN, 7);
        assert_eq!((h6.len(), h6[0] >> 4, h6[5], h6[6]), (40, 6, 24, 6));
    }

    #[test]
    fn cookie_is_deterministic_and_spread() {
        let d: IpAddr = DST.into();
        assert_eq!(cookie(7, d, 80), cookie(7, d, 80));
        assert_ne!(cookie(7, d, 80), cookie(7, d, 81));
        assert_ne!(cookie(7, d, 80), cookie(8, d, 80));
        assert_ne!(cookie(7, DST6.into(), 80), cookie(7, SRC6.into(), 80));
    }

    fn reply(flags: u8, ack: u32) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // IPv4, IHL 5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&DST.octets()); // reply comes from target
        p[16..20].copy_from_slice(&SRC.octets());
        p[20..22].copy_from_slice(&443u16.to_be_bytes());
        p[22..24].copy_from_slice(&40000u16.to_be_bytes());
        p[28..32].copy_from_slice(&ack.to_be_bytes());
        p[33] = flags;
        p
    }

    #[test]
    fn parses_and_classifies_replies() {
        let r = parse_reply(&reply(SYN | ACK, 42)).unwrap();
        assert_eq!(
            r,
            Reply {
                src: DST.into(),
                sport: 443,
                dport: 40000,
                ack: 42,
                flags: SYN | ACK
            }
        );
        assert_eq!(classify(SYN | ACK), Some(OPEN));
        assert_eq!(classify(RST | ACK), Some(CLOSED));
        assert_eq!(classify(SYN), None, "our own SYN looped back on lo");
        assert!(parse_reply(&[0x45; 10]).is_none());
        let mut udp = reply(0, 0);
        udp[9] = 17;
        assert!(parse_reply(&udp).is_none());
    }

    #[test]
    fn parses_ipv6_replies() {
        let mut p = ip_header(DST6.into(), SRC6.into(), 20, 0);
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&22u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&40000u16.to_be_bytes());
        tcp[8..12].copy_from_slice(&9u32.to_be_bytes());
        tcp[13] = RST | ACK;
        p.extend(tcp);
        let r = parse_reply(&p).unwrap();
        assert_eq!(
            (r.src, r.sport, r.ack, r.flags),
            (DST6.into(), 22, 9, RST | ACK)
        );
    }

    #[test]
    fn frame_helpers() {
        assert_eq!(frames::link_len(1), Some(14));
        assert_eq!(frames::link_len(0), Some(4));
        assert_eq!(frames::link_len(113), None, "Linux cooked: can't inject");
        let mut eth = vec![0u8; 12];
        eth.extend([0x81, 0x00, 0, 1, 0x08, 0x00]);
        assert_eq!(frames::ip_offset(&eth, 14), 18, "VLAN tag skipped");
        // Outbound UDP to [fd00::2]:5555
        let mut v6 = ip_header(SRC6.into(), DST6.into(), 8, 0);
        v6[6] = 17;
        v6.extend([0x9c, 0x40, 0x15, 0xb3, 0, 8, 0, 0]);
        assert_eq!(frames::udp_dst(&v6), Some((DST6.into(), 5555)));
    }

    #[test]
    fn loopback_source_address() {
        assert_eq!(
            source_addr_for(Ipv4Addr::LOCALHOST.into()).unwrap(),
            IpAddr::from(Ipv4Addr::LOCALHOST)
        );
    }
}
