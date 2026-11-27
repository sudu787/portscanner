/// service.rs — Port-to-service mapping for rustscan-rs
///
/// ═══════════════════════════════════════════════════════════════════════════
/// DESIGN RATIONALE
/// ═══════════════════════════════════════════════════════════════════════════
///
/// Port-to-service identification is **static knowledge** — it does not
/// require any I/O and never changes during a scan.  This makes it an ideal
/// candidate for a compile-time `match` expression, which the Rust compiler
/// typically optimises into a jump table (O(1) lookup) or a binary search
/// (O(log n)) with absolutely no heap allocation.
///
/// Two alternatives were considered:
///
///   HashMap<u16, ServiceInfo>  — runtime allocation, hash overhead per lookup,
///                                harder to see the full database at a glance.
///
///   phf::Map<u16, ServiceInfo> — perfect hash, zero runtime cost, but adds
///                                a build-time dependency.  Not worth it when
///                                a `match` on integers is equally fast.
///
///   `match` expression         — ✓ chosen. Zero deps, zero allocation,
///                                compiler verifies exhaustiveness, readable.
///
/// ═══════════════════════════════════════════════════════════════════════════
/// SCOPE
/// ═══════════════════════════════════════════════════════════════════════════
///
/// This module provides **port-based** (layer 4) service hints.
/// It is intentionally NOT banner-based identification — that is Phase 5
/// (banner grabbing).  A port-based guess is fast but can be wrong:
/// an admin might run HTTP on port 9999 or SSH on port 2222.
/// The output layer should always label this data as "likely" or "typical".
use serde::Serialize;

// ─── Public types ─────────────────────────────────────────────────────────────

/// Transport-layer protocol the service is typically associated with.
///
/// We only probe TCP, but recording the IANA protocol is useful context
/// (e.g., DNS on UDP 53 vs TCP 53 for zone transfers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Transport {
    Tcp,
    Udp,
    /// Service uses both TCP and UDP on the same port.
    TcpUdp,
}

/// Static metadata describing the typical service on a port.
///
/// All string fields are `&'static str` — they point directly into the binary's
/// read-only data segment.  The struct is `Copy`, so passing it around is free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ServiceInfo {
    /// Short IANA-style service name, e.g. `"HTTP"`, `"SSH"`, `"Unknown"`.
    pub name: &'static str,
    /// Which protocol(s) this service normally uses.
    pub transport: Transport,
    /// One-line human-readable description.
    pub description: &'static str,
}

impl ServiceInfo {
    // Private constructor — all instances are created inside `detect_service`.
    const fn new(name: &'static str, transport: Transport, description: &'static str) -> Self {
        Self {
            name,
            transport,
            description,
        }
    }

    /// Returns `true` if this port is in the well-known service database.
    #[inline]
    pub fn is_known(self) -> bool {
        self.name != "Unknown"
    }

    /// A short display string combining name and description.
    ///
    /// Example: `"HTTP — HyperText Transfer Protocol"`
    /// Used by the text output layer and Phase 5 banner reporting.
    #[allow(dead_code)]
    pub fn display(self) -> String {
        if self.is_known() {
            format!("{} — {}", self.name, self.description)
        } else {
            "Unknown".to_string()
        }
    }
}

// ─── detect_service() ─────────────────────────────────────────────────────────

/// Map a TCP port number to its most commonly associated service.
///
/// # Performance
///
/// This is a single `match` on a `u16`.  The compiler generates a jump table
/// for dense arms and a branch tree for sparse ones.  In practice this compiles
/// to 1–3 CPU instructions: no allocation, no hash, no cache miss.
///
/// # Accuracy
///
/// Port-based detection is a heuristic, not a guarantee.  Any service can
/// listen on any port.  Use banner grabbing (Phase 5) for confirmed detection.
///
/// # Database
///
/// Sources: IANA Service Name and Transport Protocol Port Number Registry
/// and common DevOps/security tooling defaults.
pub fn detect_service(port: u16, target_proto: Transport) -> ServiceInfo {
    use Transport::{Tcp, TcpUdp, Udp};

    let info = match port {
        // ── Well-known ports (0–1023) ──────────────────────────────────────

        //  20 — FTP data channel (active mode)
        20 => ServiceInfo::new("FTP-DATA", Tcp, "File Transfer Protocol — data channel"),
        //  21 — FTP control channel
        21 => ServiceInfo::new("FTP", Tcp, "File Transfer Protocol — control"),
        //  22 — Secure Shell
        22 => ServiceInfo::new("SSH", Tcp, "Secure Shell — encrypted remote login"),
        //  23 — Telnet (plaintext, legacy)
        23 => ServiceInfo::new("TELNET", Tcp, "Telnet — unencrypted remote login (legacy)"),
        //  25 — SMTP mail submission between servers
        25 => ServiceInfo::new("SMTP", Tcp, "Simple Mail Transfer Protocol"),
        //  53 — DNS (small queries UDP; zone transfers TCP)
        53 => ServiceInfo::new("DNS", TcpUdp, "Domain Name System"),
        //  67 — DHCP server
        67 => ServiceInfo::new("DHCP", Udp, "Dynamic Host Configuration Protocol — server"),
        //  68 — DHCP client
        68 => ServiceInfo::new(
            "DHCP-CLIENT",
            Udp,
            "Dynamic Host Configuration Protocol — client",
        ),
        //  69 — Trivial FTP (firmware upgrades, PXE boot)
        69 => ServiceInfo::new("TFTP", Udp, "Trivial File Transfer Protocol"),
        //  80 — HTTP
        80 => ServiceInfo::new("HTTP", Tcp, "HyperText Transfer Protocol"),
        //  88 — Kerberos authentication
        88 => ServiceInfo::new("KERBEROS", TcpUdp, "Kerberos authentication"),
        //  110 — POP3 mail retrieval
        110 => ServiceInfo::new("POP3", Tcp, "Post Office Protocol v3"),
        //  111 — ONC RPC portmapper
        111 => ServiceInfo::new("RPCBIND", TcpUdp, "ONC RPC portmapper"),
        //  119 — NNTP (Usenet)
        119 => ServiceInfo::new("NNTP", Tcp, "Network News Transfer Protocol"),
        //  123 — NTP time sync (UDP only in practice)
        123 => ServiceInfo::new("NTP", Udp, "Network Time Protocol"),
        //  135 — Windows RPC endpoint mapper
        135 => ServiceInfo::new("MSRPC", Tcp, "Microsoft RPC endpoint mapper"),
        //  137 — NetBIOS name service
        137 => ServiceInfo::new("NETBIOS-NS", TcpUdp, "NetBIOS Name Service"),
        //  138 — NetBIOS datagram service
        138 => ServiceInfo::new("NETBIOS-DGM", Udp, "NetBIOS Datagram Service"),
        //  139 — NetBIOS session service (SMB over NetBIOS)
        139 => ServiceInfo::new("NETBIOS-SSN", Tcp, "NetBIOS Session Service"),
        //  143 — IMAP email access
        143 => ServiceInfo::new("IMAP", Tcp, "Internet Message Access Protocol"),
        //  161 — SNMP agent (UDP)
        161 => ServiceInfo::new("SNMP", Udp, "Simple Network Management Protocol — agent"),
        //  162 — SNMP trap receiver
        162 => ServiceInfo::new("SNMPTRAP", Udp, "Simple Network Management Protocol — trap"),
        //  179 — BGP inter-AS routing
        179 => ServiceInfo::new("BGP", Tcp, "Border Gateway Protocol"),
        //  194 — IRC
        194 => ServiceInfo::new("IRC", TcpUdp, "Internet Relay Chat"),
        //  389 — LDAP directory
        389 => ServiceInfo::new("LDAP", TcpUdp, "Lightweight Directory Access Protocol"),
        //  443 — HTTPS
        443 => ServiceInfo::new("HTTPS", Tcp, "HTTP over TLS/SSL"),
        //  445 — SMB direct (Windows file/printer sharing)
        445 => ServiceInfo::new("SMB", Tcp, "Server Message Block — Windows file sharing"),
        //  465 — SMTPS (SMTP over TLS — legacy port)
        465 => ServiceInfo::new("SMTPS", Tcp, "SMTP over TLS (legacy)"),
        //  514 — Syslog (UDP); RSH (TCP) — context-dependent
        514 => ServiceInfo::new("SYSLOG", Udp, "System log / Remote Shell"),
        //  515 — LPD print spooler
        515 => ServiceInfo::new("LPD", Tcp, "Line Printer Daemon"),
        //  587 — SMTP mail submission (client → server)
        587 => ServiceInfo::new("SUBMISSION", Tcp, "SMTP mail submission (RFC 6409)"),
        //  631 — IPP (CUPS printing)
        631 => ServiceInfo::new("IPP", TcpUdp, "Internet Printing Protocol (CUPS)"),
        //  636 — LDAPS (LDAP over TLS)
        636 => ServiceInfo::new("LDAPS", Tcp, "LDAP over TLS/SSL"),
        //  873 — rsync
        873 => ServiceInfo::new("RSYNC", Tcp, "rsync file synchronisation"),
        //  902 — VMware ESXi / Workstation authentication
        902 => ServiceInfo::new("VMWARE", Tcp, "VMware ESXi / Workstation"),
        //  989 — FTPS data (FTP over TLS)
        989 => ServiceInfo::new("FTPS-DATA", Tcp, "FTP over TLS — data channel"),
        //  990 — FTPS control (FTP over TLS)
        990 => ServiceInfo::new("FTPS", Tcp, "FTP over TLS — control channel"),
        //  993 — IMAPS (IMAP over TLS)
        993 => ServiceInfo::new("IMAPS", Tcp, "IMAP over TLS/SSL"),
        //  995 — POP3S (POP3 over TLS)
        995 => ServiceInfo::new("POP3S", Tcp, "POP3 over TLS/SSL"),

        // ── Registered ports (1024–49151) ─────────────────────────────────

        //  1080 — SOCKS proxy
        1080 => ServiceInfo::new("SOCKS", Tcp, "SOCKS proxy"),
        //  1194 — OpenVPN
        1194 => ServiceInfo::new("OPENVPN", TcpUdp, "OpenVPN"),
        //  1433 — Microsoft SQL Server
        1433 => ServiceInfo::new("MSSQL", Tcp, "Microsoft SQL Server"),
        //  1521 — Oracle Database listener
        1521 => ServiceInfo::new("ORACLE-DB", Tcp, "Oracle Database listener"),
        //  1723 — PPTP VPN
        1723 => ServiceInfo::new("PPTP", Tcp, "Point-to-Point Tunnelling Protocol"),
        //  2049 — NFS
        2049 => ServiceInfo::new("NFS", TcpUdp, "Network File System"),
        //  2181 — Apache ZooKeeper client port
        2181 => ServiceInfo::new("ZOOKEEPER", Tcp, "Apache ZooKeeper — client"),
        //  2375 — Docker daemon (unencrypted — dangerous if exposed)
        2375 => ServiceInfo::new("DOCKER", Tcp, "Docker daemon — UNENCRYPTED, high risk"),
        //  2376 — Docker daemon (TLS)
        2376 => ServiceInfo::new("DOCKER-TLS", Tcp, "Docker daemon over TLS"),
        //  2379 — etcd client API (Kubernetes control plane)
        2379 => ServiceInfo::new("ETCD", Tcp, "etcd client API"),
        //  2380 — etcd peer communication
        2380 => ServiceInfo::new("ETCD-PEER", Tcp, "etcd peer communication"),
        //  3000 — Grafana / common dev server port
        3000 => ServiceInfo::new("GRAFANA", Tcp, "Grafana dashboards / dev HTTP server"),
        //  3306 — MySQL / MariaDB
        3306 => ServiceInfo::new("MYSQL", Tcp, "MySQL / MariaDB database"),
        //  3389 — Windows Remote Desktop Protocol
        3389 => ServiceInfo::new("RDP", Tcp, "Windows Remote Desktop Protocol"),
        //  4369 — RabbitMQ Erlang port mapper (epmd)
        4369 => ServiceInfo::new("EPMD", Tcp, "Erlang Port Mapper Daemon (RabbitMQ)"),
        //  5000 — Flask / UPnP
        5000 => ServiceInfo::new("HTTP-ALT", Tcp, "Common dev HTTP / UPnP"),
        //  5040 — Windows User Data Access (WinRT)
        5040 => ServiceInfo::new("WIN-UDA", Tcp, "Windows User Data Access service"),
        //  5357 — WSDAPI (Windows device discovery)
        5357 => ServiceInfo::new("WSDAPI", Tcp, "Web Services for Devices (Windows)"),
        //  5432 — PostgreSQL
        5432 => ServiceInfo::new("POSTGRESQL", Tcp, "PostgreSQL database"),
        //  5672 — RabbitMQ AMQP
        5672 => ServiceInfo::new("AMQP", Tcp, "RabbitMQ / AMQP message broker"),
        //  5900 — VNC remote desktop
        5900 => ServiceInfo::new("VNC", Tcp, "Virtual Network Computing — remote desktop"),
        //  5984 — Apache CouchDB HTTP API
        5984 => ServiceInfo::new("COUCHDB", Tcp, "Apache CouchDB HTTP API"),
        //  6379 — Redis in-memory store
        6379 => ServiceInfo::new("REDIS", Tcp, "Redis in-memory data store"),
        //  6443 — Kubernetes API server
        6443 => ServiceInfo::new("KUBE-API", Tcp, "Kubernetes API server (TLS)"),
        //  7001 — Oracle WebLogic
        7001 => ServiceInfo::new("WEBLOGIC", Tcp, "Oracle WebLogic Server"),
        //  7680 — Windows Delivery Optimization P2P
        7680 => ServiceInfo::new("WIN-DO", Tcp, "Windows Update Delivery Optimisation"),
        //  8080 — HTTP alternate (proxy, dev servers, Tomcat)
        8080 => ServiceInfo::new("HTTP-PROXY", Tcp, "HTTP alternate / Tomcat / proxy"),
        //  8443 — HTTPS alternate
        8443 => ServiceInfo::new("HTTPS-ALT", Tcp, "HTTPS alternate port"),
        //  8888 — Jupyter Notebook
        8888 => ServiceInfo::new("JUPYTER", Tcp, "Jupyter Notebook / common HTTP alt"),
        //  9000 — SonarQube / PHP-FPM
        9000 => ServiceInfo::new("SONARQUBE", Tcp, "SonarQube / PHP-FPM"),
        //  9090 — Prometheus metrics
        9090 => ServiceInfo::new("PROMETHEUS", Tcp, "Prometheus metrics server"),
        //  9092 — Apache Kafka broker
        9092 => ServiceInfo::new("KAFKA", Tcp, "Apache Kafka broker"),
        //  9200 — Elasticsearch HTTP API
        9200 => ServiceInfo::new("ELASTICSEARCH", Tcp, "Elasticsearch HTTP API"),
        //  9300 — Elasticsearch cluster transport
        9300 => ServiceInfo::new("ES-CLUSTER", Tcp, "Elasticsearch cluster transport"),
        //  9527 — VMware Horizon View (or app-specific)
        9527 => ServiceInfo::new("VMWARE-VIEW", Tcp, "VMware Horizon View / app-specific"),
        //  10250 — Kubernetes kubelet API
        10250 => ServiceInfo::new("KUBELET", Tcp, "Kubernetes kubelet API"),
        //  10255 — Kubernetes kubelet read-only API (deprecated)
        10255 => ServiceInfo::new(
            "KUBELET-RO",
            Tcp,
            "Kubernetes kubelet read-only (deprecated)",
        ),
        //  11211 — Memcached
        11211 => ServiceInfo::new("MEMCACHED", TcpUdp, "Memcached in-memory cache"),
        //  15672 — RabbitMQ management UI
        15672 => ServiceInfo::new("RABBITMQ-UI", Tcp, "RabbitMQ management HTTP UI"),
        //  16443 — MicroK8s API server
        16443 => ServiceInfo::new("MICROK8S", Tcp, "MicroK8s Kubernetes API server"),
        //  27017 — MongoDB primary
        27017 => ServiceInfo::new("MONGODB", Tcp, "MongoDB database"),
        //  27018 — MongoDB shard
        27018 => ServiceInfo::new("MONGODB-SHARD", Tcp, "MongoDB sharded cluster"),
        //  50000 — SAP Application Server
        50000 => ServiceInfo::new("SAP", Tcp, "SAP Application Server"),

        // ── Dynamic / ephemeral range hint ────────────────────────────────
        //  49152–65535 = IANA dynamic/private range.  These are typically
        //  OS-assigned ephemeral ports — valid connection endpoints but not
        //  associated with a named service.
        49152..=65535 => ServiceInfo::new("EPHEMERAL", Tcp, "OS-assigned ephemeral / dynamic port"),

        // ── Fallthrough ────────────────────────────────────────────────────
        _ => ServiceInfo::new("Unknown", TcpUdp, "No service mapping for this port"),
    };

    // If a service is theoretically TcpUdp, but we scanned it specifically
    // as Udp, refine the output transport hint so the output layer knows
    // it was a UDP scan.
    if info.transport == TcpUdp {
        ServiceInfo::new(info.name, target_proto, info.description)
    } else {
        info
    }
}

/// Label for a port whose handshake proved TLS but whose service is unknown.
pub const TLS_SERVICE: ServiceInfo = ServiceInfo::new(
    "SSL/TLS",
    Transport::Tcp,
    "TLS-wrapped service (confirmed by handshake)",
);

// ─── identify_banner() ────────────────────────────────────────────────────────

/// Identify the service from what it actually said, independent of the port.
/// Returns `None` when the banner matches no known signature, in which case
/// the port-based guess from [`detect_service`] stands.
pub fn identify_banner(banner: &str, tls: bool) -> Option<ServiceInfo> {
    use Transport::Tcp;
    let b = banner.trim_start();
    let lower = b.to_ascii_lowercase();
    let has = |s: &str| lower.contains(s);

    let info = if b.starts_with("SSH-") {
        ServiceInfo::new("SSH", Tcp, "Secure Shell (from banner)")
    } else if b.starts_with("HTTP/") {
        if tls {
            ServiceInfo::new("HTTPS", Tcp, "HTTP over TLS (from banner)")
        } else {
            ServiceInfo::new("HTTP", Tcp, "HTTP server (from banner)")
        }
    } else if b.starts_with("RTSP/") {
        ServiceInfo::new("RTSP", Tcp, "Real Time Streaming Protocol (from banner)")
    } else if b.starts_with("SIP/") {
        ServiceInfo::new("SIP", Tcp, "Session Initiation Protocol (from banner)")
    } else if b.starts_with("220") && (has("smtp") || has("mail")) {
        ServiceInfo::new("SMTP", Tcp, "Mail server (from banner)")
    } else if b.starts_with("220") && has("ftp") {
        ServiceInfo::new("FTP", Tcp, "FTP server (from banner)")
    } else if b.starts_with("+OK") {
        ServiceInfo::new("POP3", Tcp, "POP3 mail server (from banner)")
    } else if b.starts_with("* OK") || b.starts_with("* PREAUTH") {
        ServiceInfo::new("IMAP", Tcp, "IMAP mail server (from banner)")
    } else if b.starts_with("RFB ") {
        ServiceInfo::new("VNC", Tcp, "VNC remote framebuffer (from banner)")
    } else if b.starts_with("PostgreSQL") {
        ServiceInfo::new("POSTGRESQL", Tcp, "PostgreSQL database (from handshake)")
    } else if b.starts_with("VERSION ") {
        ServiceInfo::new("MEMCACHED", Tcp, "Memcached (from banner)")
    } else if b.starts_with("Redis ")
        || b.starts_with("-ERR")
        || b.starts_with("-NOAUTH")
        || b.starts_with("-DENIED")
    {
        ServiceInfo::new("REDIS", Tcp, "Redis key-value store (from banner)")
    } else if b.starts_with("@RSYNCD") {
        ServiceInfo::new("RSYNC", Tcp, "rsync daemon (from banner)")
    } else if b.starts_with("AMQP") {
        ServiceInfo::new("AMQP", Tcp, "AMQP message broker (from banner)")
    } else if has("mysql") || has("mariadb") {
        ServiceInfo::new("MYSQL", Tcp, "MySQL / MariaDB (from banner)")
    } else if b.starts_with("220") {
        ServiceInfo::new("FTP/SMTP", Tcp, "220 greeting — FTP or SMTP (from banner)")
    } else {
        return None;
    };
    Some(info)
}

// ─── detect_version() ─────────────────────────────────────────────────────────

/// Product signatures: (regex, product). Capture 1 = version, capture 2 =
/// extra info (distro, build); both optional. Product `*` = take the product
/// name from capture 1 and the version from capture 2 (generic fallbacks).
/// First match wins, so specific rules go before generic ones.
const VERSION_RULES: &[(&str, &str)] = &[
    // SSH
    (r"SSH-[\d.]+-OpenSSH_([\w.]+)(?:[ -]+(\S+))?", "OpenSSH"),
    (r"SSH-[\d.]+-dropbear_([\w.]+)", "Dropbear sshd"),
    (r"SSH-[\d.]+-libssh[_-]([\w.]+)", "libssh"),
    // FTP
    (r"(?i)\(vsFTPd ([\d.]+)\)", "vsftpd"),
    (r"ProFTPD ([\d.]+\w*)", "ProFTPD"),
    (
        r"FileZilla Server(?: version)? ([\d.]+\w*)",
        "FileZilla ftpd",
    ),
    (r"Pure-FTPd", "Pure-FTPd"),
    (r"Microsoft FTP Service", "Microsoft ftpd"),
    // Mail
    (r"ESMTP Exim ([\d.]+)", "Exim smtpd"),
    (r"ESMTP Postfix()(?: \(([^)]+)\))?", "Postfix smtpd"),
    (r"Sendmail ([\d.]+/[\d.]+|[\d.]+)", "Sendmail"),
    (
        r"Microsoft ESMTP MAIL Service(?:, Version: ([\d.]+))?",
        "Microsoft ESMTP",
    ),
    (r"Dovecot", "Dovecot"),
    (r"Cyrus (?:IMAP|POP3)\S* v?([\d.]+)", "Cyrus"),
    // Databases / caches
    (r"^MySQL ([\w.+~-]+)", "MySQL"),
    (r"^MariaDB ([\w.+~-]+)", "MariaDB"),
    (r"^PostgreSQL", "PostgreSQL"),
    (r"redis_version:([\d.]+)", "Redis"),
    (r"(?m)^VERSION ([\d.]+)", "memcached"),
    // Remote desktop
    (r"^RFB 0*(\d+\.\d+)", "VNC (RFB protocol)"),
    // HTTP (from the `Server:` header)
    (r"(?i)Server: nginx/([\d.]+)(?: \(([^)]+)\))?", "nginx"),
    (
        r"(?i)Server: Apache/([\d.]+)(?: \(([^)]+)\))?",
        "Apache httpd",
    ),
    (r"(?i)Server: Microsoft-IIS/([\d.]+)", "Microsoft IIS httpd"),
    (r"(?i)Server: lighttpd/([\d.]+)", "lighttpd"),
    (r"(?i)Server: openresty/([\d.]+)", "OpenResty"),
    (r"(?i)Server: Apache-Coyote/([\d.]+)", "Apache Tomcat"),
    (r"(?i)Server: Jetty\(([\w.-]+)\)", "Jetty"),
    (r"(?i)Server: Caddy", "Caddy"),
    (r"(?i)Server: ([A-Za-z][\w.-]*)/(\d[\w.-]*)", "*"),
    (r"(?i)Server: ([A-Za-z][\w.-]*)", "*"),
];

static VERSION_RES: std::sync::LazyLock<Vec<(regex::Regex, &'static str)>> =
    std::sync::LazyLock::new(|| {
        VERSION_RULES
            .iter()
            .map(|(re, p)| (regex::Regex::new(re).expect("valid version rule"), *p))
            .collect()
    });

/// Product and version from what a service said, e.g. `"OpenSSH 9.6p1
/// (Ubuntu-3ubuntu13)"` or `"nginx 1.24.0"`. `None` if no signature matches.
pub fn detect_version(text: &str) -> Option<String> {
    VERSION_RES.iter().find_map(|(re, product)| {
        let c = re.captures(text)?;
        let cap = |i| {
            c.get(i)
                .map(|m: regex::Match| m.as_str())
                .filter(|s| !s.is_empty())
        };
        let (product, version, extra) = if *product == "*" {
            (cap(1)?, cap(2), None)
        } else {
            (*product, cap(1), cap(2))
        };
        let mut s = product.to_string();
        if let Some(v) = version {
            s += " ";
            s += v;
        }
        if let Some(e) = extra {
            s += &format!(" ({e})");
        }
        Some(crate::probes::sanitize(&s))
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_product_versions() {
        let v = |s: &str| detect_version(s);
        assert_eq!(
            v("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13").as_deref(),
            Some("OpenSSH 9.6p1 (Ubuntu-3ubuntu13)")
        );
        assert_eq!(v("SSH-2.0-OpenSSH_8.0").as_deref(), Some("OpenSSH 8.0"));
        assert_eq!(
            v("SSH-2.0-dropbear_2022.83").as_deref(),
            Some("Dropbear sshd 2022.83")
        );
        assert_eq!(v("220 (vsFTPd 3.0.5)").as_deref(), Some("vsftpd 3.0.5"));
        assert_eq!(
            v("220 ProFTPD 1.3.5e Server (Debian)").as_deref(),
            Some("ProFTPD 1.3.5e")
        );
        assert_eq!(
            v("220 mx.example.com ESMTP Exim 4.96 Mon, 1 Jan").as_deref(),
            Some("Exim smtpd 4.96")
        );
        assert_eq!(
            v("220 mail ESMTP Postfix (Ubuntu)").as_deref(),
            Some("Postfix smtpd (Ubuntu)")
        );
        assert_eq!(v("+OK Dovecot (Ubuntu) ready.").as_deref(), Some("Dovecot"));
        assert_eq!(v("MySQL 8.0.36").as_deref(), Some("MySQL 8.0.36"));
        assert_eq!(
            v("$3000\r\n# Server\r\nredis_version:7.2.4\r\n").as_deref(),
            Some("Redis 7.2.4")
        );
        assert_eq!(v("VERSION 1.6.21\r\n").as_deref(), Some("memcached 1.6.21"));
        assert_eq!(
            v("RFB 003.008").as_deref(),
            Some("VNC (RFB protocol) 3.008")
        );
        assert_eq!(
            v("HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)").as_deref(),
            Some("Apache httpd 2.4.7 (Ubuntu)")
        );
        assert_eq!(
            v("HTTP/1.1 200 OK | Server: nginx/1.24.0").as_deref(),
            Some("nginx 1.24.0")
        );
        assert_eq!(
            v("HTTP/1.1 404 | Server: Microsoft-IIS/10.0").as_deref(),
            Some("Microsoft IIS httpd 10.0")
        );
        assert_eq!(
            v("HTTP/1.0 200 | Server: SimpleHTTP/0.6 Python/3.12").as_deref(),
            Some("SimpleHTTP 0.6")
        );
        assert_eq!(
            v("HTTP/1.1 200 | Server: cloudflare").as_deref(),
            Some("cloudflare")
        );
        assert_eq!(v("hello world"), None);
        // Remote text can't smuggle escapes through.
        assert_eq!(v("Server: evil/1\x1b[31m").as_deref(), Some("evil 1"));
    }

    #[test]
    fn identifies_services_from_banners() {
        let id = |b: &str| identify_banner(b, false).map(|s| s.name);
        assert_eq!(id("SSH-2.0-OpenSSH_9.6"), Some("SSH"));
        assert_eq!(id("HTTP/1.1 200 OK | Server: nginx"), Some("HTTP"));
        assert_eq!(
            identify_banner("HTTP/1.1 200 OK", true).unwrap().name,
            "HTTPS"
        );
        assert_eq!(id("220 mx.example.com ESMTP Postfix"), Some("SMTP"));
        assert_eq!(id("220 (vsFTPd 3.0.5)"), Some("FTP"));
        assert_eq!(id("+OK Dovecot ready."), Some("POP3"));
        assert_eq!(id("* OK [CAPABILITY IMAP4rev1] ready"), Some("IMAP"));
        assert_eq!(id("RFB 003.008"), Some("VNC"));
        assert_eq!(id("-ERR unknown command 'HEAD'"), Some("REDIS"));
        assert_eq!(id("hello world"), None);
    }

    // ── Known ports ───────────────────────────────────────────────────────

    #[test]
    fn ftp_detected_on_port_21() {
        let s = detect_service(21, Transport::Tcp);
        assert_eq!(s.name, "FTP");
        assert_eq!(s.transport, Transport::Tcp);
        assert!(s.is_known());
    }

    #[test]
    fn ssh_detected_on_port_22() {
        let s = detect_service(22, Transport::Tcp);
        assert_eq!(s.name, "SSH");
        assert!(s.is_known());
    }

    #[test]
    fn http_detected_on_port_80() {
        let s = detect_service(80, Transport::Tcp);
        assert_eq!(s.name, "HTTP");
    }

    #[test]
    fn https_detected_on_port_443() {
        let s = detect_service(443, Transport::Tcp);
        assert_eq!(s.name, "HTTPS");
    }

    #[test]
    fn smb_detected_on_port_445() {
        let s = detect_service(445, Transport::Tcp);
        assert_eq!(s.name, "SMB");
    }

    #[test]
    fn mysql_detected_on_port_3306() {
        let s = detect_service(3306, Transport::Tcp);
        assert_eq!(s.name, "MYSQL");
    }

    #[test]
    fn rdp_detected_on_port_3389() {
        let s = detect_service(3389, Transport::Tcp);
        assert_eq!(s.name, "RDP");
        assert!(s.is_known());
    }

    #[test]
    fn postgresql_detected_on_port_5432() {
        let s = detect_service(5432, Transport::Tcp);
        assert_eq!(s.name, "POSTGRESQL");
    }

    #[test]
    fn redis_detected_on_port_6379() {
        let s = detect_service(6379, Transport::Tcp);
        assert_eq!(s.name, "REDIS");
    }

    #[test]
    fn http_proxy_detected_on_port_8080() {
        let s = detect_service(8080, Transport::Tcp);
        assert_eq!(s.name, "HTTP-PROXY");
    }

    #[test]
    fn mongodb_detected_on_port_27017() {
        let s = detect_service(27017, Transport::Tcp);
        assert_eq!(s.name, "MONGODB");
    }

    // ── Mixed-protocol ports ──────────────────────────────────────────────

    #[test]
    fn dns_is_tcp_udp() {
        // if probed as TCP, it will refine to TCP
        assert_eq!(detect_service(53, Transport::Tcp).transport, Transport::Tcp);
    }

    #[test]
    fn ntp_is_udp() {
        assert_eq!(
            detect_service(123, Transport::Udp).transport,
            Transport::Udp
        );
    }

    // ── Unknown / ephemeral ───────────────────────────────────────────────

    #[test]
    fn unknown_port_returns_unknown() {
        let s = detect_service(31337, Transport::Tcp);
        assert_eq!(s.name, "Unknown");
        assert!(!s.is_known());
    }

    #[test]
    fn port_zero_returns_unknown() {
        let s = detect_service(0, Transport::Tcp);
        assert!(!s.is_known());
    }

    #[test]
    fn ephemeral_port_has_ephemeral_label() {
        // 49152 is the start of IANA's dynamic/private port range
        let s = detect_service(49152, Transport::Tcp);
        assert_eq!(s.name, "EPHEMERAL");
        // Even though it's in our DB, is_known() is false for EPHEMERAL
        // by checking name != "Unknown" — EPHEMERAL IS effectively "known"
        // as a category.
        assert!(s.is_known()); // "EPHEMERAL" is a known category
    }

    #[test]
    fn high_dynamic_port_is_ephemeral() {
        let s = detect_service(60000, Transport::Tcp);
        assert_eq!(s.name, "EPHEMERAL");
    }

    #[test]
    fn max_port_is_ephemeral() {
        let s = detect_service(65535, Transport::Tcp);
        assert_eq!(s.name, "EPHEMERAL");
    }

    // ── ServiceInfo helpers ───────────────────────────────────────────────

    #[test]
    fn display_known_service_includes_name_and_description() {
        let s = detect_service(22, Transport::Tcp); // SSH
        let d = s.display();
        assert!(d.contains("SSH"));
        assert!(d.contains("Secure Shell"));
    }

    #[test]
    fn display_unknown_returns_unknown_string() {
        let s = detect_service(31337, Transport::Tcp);
        assert_eq!(s.display(), "Unknown");
    }

    #[test]
    fn service_info_is_copy() {
        let s = detect_service(80, Transport::Tcp);
        let s2 = s; // copy, not move
        let _s3 = s; // original still usable
        assert_eq!(s2.name, "HTTP");
    }

    // ── Spot-check the full required list from the spec ───────────────────

    #[test]
    fn required_ports_all_known() {
        let required = [
            21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080,
        ];
        for port in required {
            let s = detect_service(port, Transport::Tcp);
            assert!(
                s.is_known(),
                "port {port} should be known, got '{}'",
                s.name
            );
        }
    }
}
