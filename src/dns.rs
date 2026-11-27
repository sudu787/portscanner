use std::net::IpAddr;
use std::time::Duration;

use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tracing::debug;

use crate::probes::sanitize;

/// OS resolvers can retry for a long time; one slow PTR must not stall a scan.
const RDNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Reverse DNS (PTR) lookup on the blocking pool, with a hard timeout.
/// The name is sanitized: PTR records are controlled by whoever owns the IP.
pub async fn reverse_dns(ip: IpAddr) -> Option<String> {
    let lookup = spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());
    match timeout(RDNS_TIMEOUT, lookup).await {
        Ok(Ok(Some(name))) => {
            let name = sanitize(&name);
            // getnameinfo echoes the IP back when there is no PTR record.
            (!name.is_empty() && name != ip.to_string()).then_some(name)
        }
        _ => {
            debug!(target = %ip, "reverse DNS: no answer");
            None
        }
    }
}

/// Forward-resolve a hostname to all its addresses (IPv4 first, then IPv6),
/// de-duplicated, preserving resolver order within each family.
pub async fn resolve_host(host: &str) -> std::io::Result<Vec<IpAddr>> {
    let lookup = format!("{host}:0");
    let addrs = spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        lookup
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(std::io::Error::other)??;

    let mut out: Vec<IpAddr> = Vec::new();
    for ip in addrs
        .iter()
        .filter(|a| a.is_ipv4())
        .chain(addrs.iter().filter(|a| a.is_ipv6()))
    {
        if !out.contains(ip) {
            out.push(*ip);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn reverse_dns_localhost_does_not_panic() {
        if let Some(h) = reverse_dns(IpAddr::V4(Ipv4Addr::LOCALHOST)).await {
            assert!(!h.is_empty());
        }
    }

    #[tokio::test]
    async fn resolve_localhost() {
        let addrs = resolve_host("localhost").await.unwrap();
        assert!(addrs.iter().any(|a| a.is_loopback()));
    }

    /// Needs internet access; run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn reverse_dns_google_dns() {
        let h = reverse_dns("8.8.8.8".parse().unwrap()).await.unwrap();
        assert!(h.contains("google") || h.contains("dns"));
    }
}
