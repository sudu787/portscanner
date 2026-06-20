use std::net::IpAddr;
use tokio::task::spawn_blocking;
use tracing::debug;

/// Attempts a reverse DNS lookup to find the hostname associated with an IP address.
///
/// Because reverse DNS relies on OS-level `getnameinfo` (which is blocking),
/// this function offloads the work to a `tokio::task::spawn_blocking` thread
/// to prevent stalling the async executor.
///
/// Returns `Some(hostname)` if a PTR record exists and resolves successfully.
/// Returns `None` if the lookup fails or times out (handled by the OS).
pub async fn reverse_dns(ip: IpAddr) -> Option<String> {
    debug!(target = %ip, "attempting reverse DNS lookup");

    let handle = spawn_blocking(move || {
        dns_lookup::lookup_addr(&ip).ok()
    });

    match handle.await {
        Ok(Some(hostname)) => {
            debug!(target = %ip, resolved = %hostname, "reverse DNS successful");
            Some(hostname)
        }
        Ok(None) => {
            debug!(target = %ip, "reverse DNS failed (no PTR record)");
            None
        }
        Err(e) => {
            debug!(target = %ip, error = %e, "spawn_blocking failed for reverse DNS");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn reverse_dns_localhost() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let hostname = reverse_dns(ip).await;
        // Depending on the OS, this might resolve to "localhost" or something similar.
        // It should at least not panic.
        if let Some(h) = hostname {
            assert!(!h.is_empty());
        }
    }

    #[tokio::test]
    async fn reverse_dns_google_dns() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let hostname = reverse_dns(ip).await;
        // Typically resolves to "dns.google"
        if let Some(h) = hostname {
            assert!(h.contains("google") || h.contains("dns"));
        }
    }
}
