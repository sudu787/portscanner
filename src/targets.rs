/// targets.rs — Target specification parsing and CIDR expansion
///
/// ═══════════════════════════════════════════════════════════════════════════
/// ARCHITECTURE
/// ═══════════════════════════════════════════════════════════════════════════
///
/// This module is the single entry-point for turning whatever the user typed
/// on the command line into a concrete list of `IpAddr` values that the
/// scanner can consume.
///
/// Parsing pipeline:
///
///   &str (raw CLI argument)
///     │
///     ├─ parse::<IpAddr>()  succeeds → TargetKind::Single
///     │
///     ├─ contains '/'
///     │    └─ parse::<IpNetwork>()
///     │          ├─ ok  → size check → TargetKind::Network
///     │          └─ err → RustScanError::InvalidCidr
///     │
///     └─ otherwise → TargetKind::Hostname (DNS resolved by caller)
///
///
/// Why keep DNS out of this module?
/// ─────────────────────────────────
/// DNS resolution is `async` (it goes to the network).  `targets.rs` is
/// intentionally synchronous so it can be called from both async code
/// (`main`) and unit tests without a Tokio runtime.  The caller (`main.rs`)
/// handles DNS via `spawn_blocking`.
///
///
/// Address iteration for CIDR ranges:
/// ────────────────────────────────────
/// `ipnetwork::IpNetwork` implements `IntoIterator<Item = IpAddr>`.
/// For an IPv4 /24 it yields all 256 addresses (network address,
/// 254 host addresses, and the broadcast address).  A port scanner
/// typically wants all of them — network and broadcast addresses can
/// still respond on some services.
///
///
/// Safety limits:
/// ──────────────
/// Expanding a /8 yields 16 million addresses.  Scanning each on even a
/// single port at 1 000 concurrent tasks would take hours and could be
/// considered a denial-of-service attack.  We therefore reject prefixes
/// that would expand to more than MAX_CIDR_HOSTS addresses.
/// The caller can override this in the future with `--force-large-range`.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use tracing::warn;

use crate::errors::{Result, RustScanError};

// ─── Safety constants ─────────────────────────────────────────────────────────

/// Warn the user when a CIDR range expands to more than this many hosts.
/// Scanning a /24 (256 hosts) is the most common LAN use-case; anything
/// larger deserves an explicit notice.
pub const CIDR_WARN_THRESHOLD: u64 = 256;

/// Hard upper limit on the number of addresses we will expand from a single
/// CIDR token.  A /16 yields 65 536 addresses × N ports each — that is
/// already a very large scan.  Larger ranges are rejected to prevent accidents.
pub const MAX_CIDR_HOSTS: u64 = 65_536; // equivalent to a /16

// ─── Public types ─────────────────────────────────────────────────────────────

/// What kind of target the user specified, before DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetKind {
    /// A bare IP address — no parsing overhead, used directly.
    Single(IpAddr),
    /// A CIDR network, already expanded to the full address list.
    Network(IpNetwork),
    /// A hostname string that requires async DNS resolution by the caller.
    Hostname(String),
}

/// The result of parsing a target string: the kind and the expanded IPs.
///
/// For `Hostname` targets, `addrs` is empty until the caller performs DNS
/// resolution and calls [`ResolvedTarget::with_addr`].
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    /// The original string exactly as the user typed it.
    pub spec: String,
    /// What kind of target was detected.
    pub kind: TargetKind,
    /// IP addresses to scan.  Empty for unresolved hostnames.
    pub addrs: Vec<IpAddr>,
}

impl ResolvedTarget {
    /// True when `addrs` contains more than one address (CIDR or multi-A DNS).
    pub fn is_multi_host(&self) -> bool {
        self.addrs.len() > 1
    }

    /// A short human-readable label for display in the startup banner.
    ///
    /// Examples:
    ///   - "192.168.1.1"
    ///   - "192.168.1.0/24 (256 hosts)"
    ///   - "scanme.nmap.org → 45.33.32.156"
    pub fn display_label(&self) -> String {
        match &self.kind {
            TargetKind::Single(ip) => ip.to_string(),
            TargetKind::Network(net) => {
                format!("{} ({} hosts)", net, self.addrs.len())
            }
            TargetKind::Hostname(h) => {
                if self.addrs.is_empty() {
                    h.clone()
                } else {
                    format!("{h} → {}", self.addrs[0])
                }
            }
        }
    }

    /// Replace the empty address list with the result of a DNS lookup.
    /// Used by `main.rs` after resolving a hostname.
    pub fn with_addr(mut self, addr: IpAddr) -> Self {
        self.addrs = vec![addr];
        self
    }
}

// ─── parse_target() ───────────────────────────────────────────────────────────

/// Parse a raw target string into a [`ResolvedTarget`].
///
/// # Parsing order
///
/// 1. **Bare IP** (`192.168.1.1`) — parsed directly, no allocation.
/// 2. **CIDR range** (contains `/`) — validated, size-checked, expanded.
/// 3. **Hostname** (`scanme.nmap.org`) — stored as-is; caller resolves DNS.
///
/// # Errors
///
/// | Condition | Error |
/// |-----------|-------|
/// | `/` present but notation is invalid | [`RustScanError::InvalidCidr`] |
/// | Expanded address count > [`MAX_CIDR_HOSTS`] | [`RustScanError::CidrTooLarge`] |
///
/// A plain hostname never returns `Err` here — DNS failures surface later.
pub fn parse_target(s: &str) -> Result<ResolvedTarget> {
    let s = s.trim();

    // ── 1. Bare IP address ────────────────────────────────────────────────
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ResolvedTarget {
            spec:  s.to_string(),
            kind:  TargetKind::Single(ip),
            addrs: vec![ip],
        });
    }

    // ── 2. CIDR notation ─────────────────────────────────────────────────
    if s.contains('/') {
        return parse_cidr(s);
    }

    // ── 3. Hostname (DNS resolution deferred to caller) ───────────────────
    Ok(ResolvedTarget {
        spec:  s.to_string(),
        kind:  TargetKind::Hostname(s.to_string()),
        addrs: vec![],
    })
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Parse a string that contains `/` as a CIDR network.
fn parse_cidr(s: &str) -> Result<ResolvedTarget> {
    // Parse the CIDR notation string.
    let network: IpNetwork = s.parse().map_err(|e: ipnetwork::IpNetworkError| RustScanError::InvalidCidr {
        input:  s.to_string(),
        reason: e.to_string(),
    })?;

    // Calculate how many addresses this range contains.
    let count = address_count(network);

    // Reject dangerously large ranges before allocating.
    if count > MAX_CIDR_HOSTS {
        return Err(RustScanError::CidrTooLarge {
            input: s.to_string(),
            count,
            max: MAX_CIDR_HOSTS,
        });
    }

    // Warn on large-but-allowed ranges.
    if count > CIDR_WARN_THRESHOLD {
        warn!(
            range  = s,
            hosts  = count,
            "large CIDR range — this scan will probe {} hosts", count
        );
    }

    // `IpNetwork` is `Copy`, so `into_iter()` does not move it.
    let addrs: Vec<IpAddr> = network.into_iter().collect();

    Ok(ResolvedTarget {
        spec:  s.to_string(),
        kind:  TargetKind::Network(network),
        addrs,
    })
}

/// Compute the number of addresses in a network without iterating all of them.
///
/// Uses bit-shifting on the prefix length to avoid allocating.
///
/// | Prefix | IPv4 count |
/// |--------|------------|
/// | /32    | 1          |
/// | /24    | 256        |
/// | /16    | 65 536     |
/// | /8     | 16 777 216 |
/// | /0     | 4 294 967 296 (capped at u64::MAX) |
fn address_count(network: IpNetwork) -> u64 {
    match network {
        IpNetwork::V4(n) => {
            let host_bits = 32u32.saturating_sub(n.prefix() as u32);
            // 1u64 << 32 is valid (= 4 294 967 296).
            1u64.checked_shl(host_bits).unwrap_or(u64::MAX)
        }
        IpNetwork::V6(n) => {
            let host_bits = 128u32.saturating_sub(n.prefix() as u32);
            // Shift by ≥ 64 would overflow u64 — cap it.
            if host_bits >= 64 {
                u64::MAX
            } else {
                1u64 << host_bits
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Single IP ─────────────────────────────────────────────────────────

    #[test]
    fn ipv4_single_host_parsed_correctly() {
        let t = parse_target("192.168.1.1").unwrap();
        assert_eq!(t.addrs, vec!["192.168.1.1".parse::<IpAddr>().unwrap()]);
        assert!(!t.is_multi_host());
        assert!(matches!(t.kind, TargetKind::Single(_)));
    }

    #[test]
    fn ipv6_single_host_parsed_correctly() {
        let t = parse_target("::1").unwrap();
        assert_eq!(t.addrs, vec!["::1".parse::<IpAddr>().unwrap()]);
        assert!(matches!(t.kind, TargetKind::Single(_)));
    }

    #[test]
    fn loopback_parsed_correctly() {
        let t = parse_target("127.0.0.1").unwrap();
        assert_eq!(t.addrs.len(), 1);
        assert_eq!(t.addrs[0].to_string(), "127.0.0.1");
    }

    // ── CIDR ranges ───────────────────────────────────────────────────────

    #[test]
    fn cidr_slash32_yields_one_address() {
        let t = parse_target("10.0.0.1/32").unwrap();
        assert_eq!(t.addrs.len(), 1);
        assert!(matches!(t.kind, TargetKind::Network(_)));
    }

    #[test]
    fn cidr_slash30_yields_four_addresses() {
        // /30 = 4 addresses: network, 2 hosts, broadcast
        let t = parse_target("10.0.0.0/30").unwrap();
        assert_eq!(t.addrs.len(), 4);
        let ips: Vec<String> = t.addrs.iter().map(|a| a.to_string()).collect();
        assert!(ips.contains(&"10.0.0.0".to_string()));
        assert!(ips.contains(&"10.0.0.3".to_string()));
    }

    #[test]
    fn cidr_slash24_yields_256_addresses() {
        let t = parse_target("192.168.1.0/24").unwrap();
        assert_eq!(t.addrs.len(), 256);
        // First address = network address
        assert_eq!(t.addrs[0].to_string(), "192.168.1.0");
        // Last address = broadcast
        assert_eq!(t.addrs[255].to_string(), "192.168.1.255");
    }

    #[test]
    fn cidr_addresses_are_in_ascending_order() {
        let t = parse_target("10.0.0.0/28").unwrap(); // 16 addresses
        for window in t.addrs.windows(2) {
            assert!(window[0] < window[1], "addresses must be ascending");
        }
    }

    #[test]
    fn cidr_slash16_at_exact_limit_is_accepted() {
        // /16 = 65 536 addresses, exactly at MAX_CIDR_HOSTS
        let t = parse_target("10.0.0.0/16").unwrap();
        assert_eq!(t.addrs.len(), 65_536);
    }

    #[test]
    fn cidr_slash15_exceeds_limit_and_is_rejected() {
        // /15 = 131 072 addresses, above MAX_CIDR_HOSTS
        let err = parse_target("10.0.0.0/15").unwrap_err();
        assert!(matches!(err, RustScanError::CidrTooLarge { .. }));
    }

    #[test]
    fn invalid_cidr_notation_returns_error() {
        let err = parse_target("192.168.1.0/99").unwrap_err();
        assert!(matches!(err, RustScanError::InvalidCidr { .. }));
    }

    #[test]
    fn invalid_cidr_octets_returns_error() {
        let err = parse_target("999.999.999.0/24").unwrap_err();
        assert!(matches!(err, RustScanError::InvalidCidr { .. }));
    }

    // ── Hostnames ─────────────────────────────────────────────────────────

    #[test]
    fn hostname_stored_as_is() {
        let t = parse_target("scanme.nmap.org").unwrap();
        assert!(matches!(t.kind, TargetKind::Hostname(_)));
        assert!(t.addrs.is_empty(), "hostname addrs should be empty until DNS");
    }

    #[test]
    fn localhost_hostname_stored_as_hostname() {
        let t = parse_target("localhost").unwrap();
        assert!(matches!(t.kind, TargetKind::Hostname(_)));
    }

    // ── Display label ─────────────────────────────────────────────────────

    #[test]
    fn display_label_single() {
        let t = parse_target("1.2.3.4").unwrap();
        assert_eq!(t.display_label(), "1.2.3.4");
    }

    #[test]
    fn display_label_network_includes_count() {
        let t = parse_target("10.0.0.0/24").unwrap();
        assert_eq!(t.display_label(), "10.0.0.0/24 (256 hosts)");
    }

    #[test]
    fn display_label_hostname_before_resolution() {
        let t = parse_target("example.com").unwrap();
        assert_eq!(t.display_label(), "example.com");
    }

    #[test]
    fn display_label_hostname_after_resolution() {
        let t = parse_target("example.com")
            .unwrap()
            .with_addr("1.2.3.4".parse().unwrap());
        assert_eq!(t.display_label(), "example.com → 1.2.3.4");
    }

    // ── address_count helper ──────────────────────────────────────────────

    #[test]
    fn address_count_slash32() {
        let n: IpNetwork = "192.168.1.1/32".parse().unwrap();
        assert_eq!(address_count(n), 1);
    }

    #[test]
    fn address_count_slash24() {
        let n: IpNetwork = "10.0.0.0/24".parse().unwrap();
        assert_eq!(address_count(n), 256);
    }

    #[test]
    fn address_count_slash16() {
        let n: IpNetwork = "10.0.0.0/16".parse().unwrap();
        assert_eq!(address_count(n), 65_536);
    }

    #[test]
    fn address_count_slash0() {
        let n: IpNetwork = "0.0.0.0/0".parse().unwrap();
        // 2^32 = 4_294_967_296, fits in u64
        assert_eq!(address_count(n), 4_294_967_296u64);
    }
}
