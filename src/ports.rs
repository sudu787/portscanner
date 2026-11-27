//! ports.rs — Port specification parsing (`-p`, `--top-ports`, `--exclude-ports`).

use crate::errors::{Result, RustScanError};

/// Commonly exposed TCP/UDP ports, most common first. Curated for this
/// project from public service registries and typical internet exposure;
/// `--top-ports N` takes the first N.
pub const TOP_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 23, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 587, 8888, 199, 1720, 465, 548, 113, 81, 10000, 514, 5060, 179, 8443, 8000, 554, 1433,
    515, 8008, 5666, 646, 5000, 631, 8081, 2049, 88, 79, 5800, 106, 2121, 6000, 513, 990, 5357,
    427, 543, 544, 389, 636, 1521, 5432, 6379, 27017, 9200, 11211, 2375, 2376, 6443, 10250, 5672,
    15672, 9092, 2181, 8086, 9090, 3000, 5601, 8500, 1883, 8883, 502, 102, 20000, 47808, 161, 162,
    123, 137, 138, 500, 1900, 5353, 69, 520, 1434, 4500, 3268, 3269, 5985, 5986, 873, 9100, 2082,
    2083, 2086, 2087, 8009, 8010, 8082, 8083, 8088, 8089, 8090, 8181, 8880, 9000, 9001, 9043, 9443,
    7001, 7002, 4443, 4848, 5222, 5269, 6667, 1080, 3128, 8118, 1194, 1701, 1812, 2222, 2200, 4444,
    5555, 6666, 7070, 7777, 8291, 8728, 9999, 49152, 49153, 49154, 32768, 1025, 1026, 1027, 2000,
    2001, 37, 7, 9, 13, 17, 19, 512, 2100, 3260, 3690, 4369, 5038, 5044, 5061, 5984, 6082, 7474,
    8020, 8161, 8333, 8545, 9042, 9160, 9418, 11300, 25565, 50000, 50070, 61616, 1099, 2483, 2484,
    3050, 3299, 3478, 4000, 4040, 4786, 5009, 5050, 5190, 6380, 6881, 7000, 7443, 8001, 8002, 8085,
    8180, 8200, 8800, 8834, 9080, 9091, 9300, 10443, 2379, 2380, 10255, 30000,
];

/// Parse a port spec like `22,80,443,8000-8100`, `-` (all) or `all`.
/// Returns sorted, de-duplicated ports.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let err = |reason: String| RustScanError::InvalidPortSpec {
        spec: spec.to_string(),
        reason,
    };
    let spec_t = spec.trim();
    if spec_t == "-" || spec_t.eq_ignore_ascii_case("all") {
        return Ok((1..=65535).collect());
    }

    let mut ports = Vec::new();
    for part in spec_t.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let parse = |s: &str| -> Result<u16> {
            match s.trim().parse::<u16>() {
                Ok(0) | Err(_) => Err(err(format!("'{s}' is not a port in 1-65535"))),
                Ok(p) => Ok(p),
            }
        };
        match part.split_once('-') {
            Some((a, b)) => {
                // "-1000" / "1000-" are open-ended ranges, like nmap.
                let lo = if a.trim().is_empty() { 1 } else { parse(a)? };
                let hi = if b.trim().is_empty() {
                    65535
                } else {
                    parse(b)?
                };
                if lo > hi {
                    return Err(err(format!("range {lo}-{hi} is inverted")));
                }
                ports.extend(lo..=hi);
            }
            None => ports.push(parse(part)?),
        }
    }
    if ports.is_empty() {
        return Err(err("no ports given".into()));
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// The first `n` entries of [`TOP_PORTS`] (capped at its length).
pub fn top_ports(n: usize) -> Vec<u16> {
    let mut seen = std::collections::HashSet::new();
    TOP_PORTS
        .iter()
        .copied()
        .filter(|p| seen.insert(*p))
        .take(n)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists_and_ranges() {
        assert_eq!(parse_ports("80, 22,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-3,2,10").unwrap(), vec![1, 2, 3, 10]);
        assert_eq!(parse_ports("65534-").unwrap(), vec![65534, 65535]);
        assert_eq!(parse_ports("-3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_ports("-").unwrap().len(), 65535);
        assert_eq!(parse_ports("all").unwrap().len(), 65535);
    }

    #[test]
    fn rejects_bad_specs() {
        for bad in ["0", "70000", "abc", "10-5", "", ","] {
            assert!(parse_ports(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn top_ports_are_unique_and_capped() {
        let all = top_ports(usize::MAX);
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "TOP_PORTS has duplicates");
        assert!(all.len() >= 200);
        assert_eq!(top_ports(3), vec![80, 443, 22]);
    }
}
