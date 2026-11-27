//! syn.rs — Half-open (SYN) scanning over raw sockets.
//!
//! The same technique as `nmap -sS`, masscan and naabu: send a bare SYN,
//! read the answer straight off a raw socket, never finish the handshake.
//!   SYN-ACK → open     RST → closed     silence (after retries) → filtered
//! It is faster than a connect scan, uses no file descriptor per probe and is
//! not logged by the services themselves (no connection is ever accepted).
//!
//! Replies are matched statelessly, masscan-style: every SYN carries a
//! sequence number derived from (secret, target IP, target port), and only
//! replies whose ACK equals that cookie + 1 are accepted. Per-probe state is
//! one byte, so even large scans stay small.
//!
//! Linux only (BSD/macOS don't deliver TCP to raw sockets); needs root or
//! `CAP_NET_RAW`. IPv4 only.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

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
pub fn cookie(secret: u32, dst: Ipv4Addr, dport: u16) -> u32 {
    let x = u32::from(dst) ^ (((dport as u32) << 16) | dport as u32) ^ secret;
    let x = x.wrapping_mul(0x9E37_79B1);
    x ^ (x >> 15)
}

/// RFC 793 checksum over the IPv4 pseudo-header and the TCP segment.
pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for ch in bytes.chunks(2) {
            sum += u16::from_be_bytes([ch[0], *ch.get(1).unwrap_or(&0)]) as u32;
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&[0, 6]); // zero, protocol TCP
    add(&(segment.len() as u16).to_be_bytes());
    add(segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A SYN segment (TCP header only — the kernel adds the IP header).
pub fn build_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
) -> [u8; TCP_HDR_LEN] {
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

/// The fields of an incoming IPv4/TCP packet we care about.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub ack: u32,
    pub flags: u8,
}

/// Parse a raw IPv4 packet (as read from a raw socket) carrying TCP.
pub fn parse_reply(pkt: &[u8]) -> Option<Reply> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    let tcp = pkt.get(ihl..)?;
    if ihl < 20 || tcp.len() < 20 {
        return None;
    }
    Some(Reply {
        src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        sport: u16::from_be_bytes([tcp[0], tcp[1]]),
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
    })
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
pub fn source_addr_for(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0")?;
    s.connect((dst, 53))?;
    match s.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(io::Error::other("no IPv4 route")),
    }
}

/// Run a SYN scan (blocking — call via `spawn_blocking`).
#[cfg(target_os = "linux")]
pub fn syn_scan_blocking(
    addrs: &[Ipv4Addr],
    ports: &[u16],
    p: &SynParams,
) -> io::Result<Vec<SynHost>> {
    linux::scan(addrs, ports, p)
}

/// True when SYN mode can safely probe dead hosts too (root with
/// CAP_NET_ADMIN, so the raw socket's send buffer can be enlarged). Then
/// multi-host SYN scans discover hosts inline; otherwise they use the
/// connect-based ping first.
pub fn inline_discovery_ok() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::big_send_buffer()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(not(target_os = "linux"))]
pub fn syn_scan_blocking(
    _addrs: &[Ipv4Addr],
    _ports: &[u16],
    _p: &SynParams,
) -> io::Result<Vec<SynHost>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SYN scan needs Linux raw sockets — drop --syn to use a connect scan",
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering::Relaxed};
    use std::time::Instant;

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    pub fn scan(addrs: &[Ipv4Addr], ports: &[u16], p: &SynParams) -> io::Result<Vec<SynHost>> {
        let n = addrs.len() * ports.len();
        if n > MAX_PROBES {
            return Err(io::Error::other(format!(
                "SYN scan of {n} probes is too large — split the target range"
            )));
        }
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).map_err(|e| {
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
        let forced = force_send_buffer(&sock, SEND_BUFFER);
        let mut warned = false;
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        let rx = sock.try_clone()?;

        let secret = {
            use std::hash::{BuildHasher, Hasher};
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish() as u32
        };
        // Fixed, random-ish source port: the kernel has no socket on it, so
        // it answers SYN-ACKs with RST for us — the "half-open" part.
        let sport = 40000 + (secret % 20000) as u16;

        // `None` = no usable route (e.g. a broadcast address inside a CIDR):
        // that host is skipped and its ports end up filtered.
        let srcs: Vec<Option<Ipv4Addr>> = addrs.iter().map(|a| source_addr_for(*a).ok()).collect();
        let host_idx: HashMap<Ipv4Addr, usize> =
            addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        let mut port_idx = vec![u32::MAX; 65536];
        for (i, &port) in ports.iter().enumerate() {
            port_idx[port as usize] = i as u32;
        }
        let state: Vec<AtomicU8> = (0..n).map(|_| AtomicU8::new(UNANSWERED)).collect();
        let stop = AtomicBool::new(false);
        // Replies seen per host (lets the sender tell dead hosts from busy ones).
        let answered: Vec<AtomicU32> = (0..addrs.len()).map(|_| AtomicU32::new(0)).collect();
        let np = ports.len();

        let mut order_ports = ports.to_vec();
        let mut order_hosts: Vec<usize> = (0..addrs.len()).collect();
        if p.randomize {
            crate::scanner::shuffle(&mut order_ports);
            crate::scanner::shuffle(&mut order_hosts);
        }

        std::thread::scope(|s| -> io::Result<()> {
            // ── Receiver ──────────────────────────────────────────────────
            s.spawn(|| {
                let mut rx = &rx;
                let mut buf = [0u8; 4096];
                while !stop.load(Relaxed) {
                    let len = match rx.read(&mut buf) {
                        Ok(len) => len,
                        Err(_) => continue, // read timeout: re-check `stop`
                    };
                    let Some(r) = parse_reply(&buf[..len]) else {
                        continue;
                    };
                    if r.dport != sport {
                        continue;
                    }
                    let (Some(&h), pi) = (host_idx.get(&r.src), port_idx[r.sport as usize]) else {
                        continue;
                    };
                    if pi == u32::MAX || r.ack != cookie(secret, r.src, r.sport).wrapping_add(1) {
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
                            eprintln!("Open {}:{}", r.src, r.sport);
                        }
                    }
                }
            });

            // ── Sender ────────────────────────────────────────────────────
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
                            let pkt = build_syn(src, dst, sport, port, cookie(secret, dst, port));
                            match send(&sock, &pkt, dst)? {
                                Sent::Ok => sent += 1,
                                // ENOBUFS is *global* backpressure: SYNs
                                // queued for unresolved (dead) neighbours
                                // fill our socket's send buffer. With the
                                // enlarged buffer it's rare and transient:
                                // lose only this probe, the next pass
                                // re-sends it. With the stock ~208 KB buffer
                                // dead hosts would stall every send, so skip
                                // never-answered hosts for this pass (a live
                                // one may be crowded out — warned once).
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
                                // A definitive "no route / ARP failed" for a
                                // host that never answered: skip it for the
                                // rest of this pass.
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

    /// What happened to one SYN.
    enum Sent {
        Ok,
        /// Queue still full after `MAX_BACKOFF` (transient pressure clears
        /// faster than that; an unresolved neighbour's ARP queue doesn't).
        QueueFull,
        /// Kernel refused it outright (no route, local firewall, ARP failed).
        Unreachable,
    }

    /// How long one probe waits out ENOBUFS/EAGAIN before giving up.
    const MAX_BACKOFF: Duration = Duration::from_millis(10);

    /// Send one SYN, waiting out kernel backpressure.
    fn send(sock: &Socket, pkt: &[u8], dst: Ipv4Addr) -> io::Result<Sent> {
        let to = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
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

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    #[test]
    fn syn_checksum_verifies() {
        let pkt = build_syn(SRC, DST, 40000, 443, 0xdead_beef);
        // Summing a segment that includes its own checksum yields 0.
        assert_eq!(tcp_checksum(SRC, DST, &pkt), 0);
        assert_eq!(pkt[13], SYN);
        assert_eq!(pkt[12] >> 4, 6, "data offset = 6 words (24 bytes)");
    }

    #[test]
    fn checksum_matches_known_vector() {
        // Odd-length segment exercises the padding path.
        let seg = [0x01, 0x02, 0x03];
        // pseudo: 0a00 0001 0a00 0002 0006 0003 + 0102 0300
        let manual: u32 = 0x0a00 + 0x0001 + 0x0a00 + 0x0002 + 0x0006 + 0x0003 + 0x0102 + 0x0300;
        assert_eq!(tcp_checksum(SRC, DST, &seg), !(manual as u16));
    }

    #[test]
    fn cookie_is_deterministic_and_spread() {
        assert_eq!(cookie(7, DST, 80), cookie(7, DST, 80));
        assert_ne!(cookie(7, DST, 80), cookie(7, DST, 81));
        assert_ne!(cookie(7, DST, 80), cookie(8, DST, 80));
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
                src: DST,
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
    fn loopback_source_address() {
        assert_eq!(
            source_addr_for(Ipv4Addr::LOCALHOST).unwrap(),
            Ipv4Addr::LOCALHOST
        );
    }
}
