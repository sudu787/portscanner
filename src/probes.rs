//! probes.rs — Active service probing (banners, TLS, legacy TLS, UDP payloads)
//!
//! `scanner.rs` does a raw TCP connect as fast as possible. If the port is
//! open and probing is enabled, the open `TcpStream` is passed here for banner
//! grabbing. TLS probes open *fresh* connections because a handshake has to
//! start from byte 0.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

// ─── Sanitising remote text ───────────────────────────────────────────────────

/// Drop control characters (ANSI escapes, CR/LF, NUL …) and Unicode bidi
/// overrides from text that came off the network (banners, certificate
/// fields, PTR names) so it can't rewrite the user's terminal or reports.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .collect::<String>()
        .trim()
        .to_string()
}

// ─── Banner Grabbing ──────────────────────────────────────────────────────────

const BANNER_MAX: usize = 4096;

/// Read until the peer goes quiet for `first_wait` (then a shorter idle gap)
/// or `BANNER_MAX` bytes arrive.
async fn read_some<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    first_wait: Duration,
) {
    let mut chunk = [0u8; 2048];
    let mut wait = first_wait;
    while buf.len() < BANNER_MAX {
        match timeout(wait, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => break,
        }
        wait = Duration::from_millis(150);
    }
}

const HTTP_PROBE: &[u8] = b"HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";
/// PostgreSQL SSLRequest: the server answers a single `S` or `N`.
const PG_SSL_REQUEST: &[u8] = &[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

/// What to send to a service that doesn't speak first.
fn active_probe(port: u16) -> &'static [u8] {
    match port {
        6379 => b"INFO server\r\n",
        11211 => b"version\r\n",
        5432 => PG_SSL_REQUEST,
        _ => HTTP_PROBE,
    }
}

/// Banner plus the product/version recognised in the service's reply.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Grab {
    pub banner: Option<String>,
    pub version: Option<String>,
}

/// Try to grab a banner from an open TCP stream and identify the product.
///
/// 1. Passive read: many services (SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL)
///    speak first.
/// 2. Active probe: otherwise a port-specific request (Redis, memcached,
///    PostgreSQL), or HTTP for everything else.
/// 3. A line protocol that rejected the HTTP probe with `-ERR` is Redis:
///    ask it for `INFO server` to get the version.
pub async fn grab_banner(stream: &mut TcpStream, port: u16, wait: Duration) -> Grab {
    let mut buf = Vec::new();
    read_some(stream, &mut buf, wait).await;
    if buf.is_empty() && stream.write_all(active_probe(port)).await.is_ok() {
        read_some(stream, &mut buf, wait).await;
    }
    if buf.starts_with(b"-ERR") && stream.write_all(b"INFO server\r\n").await.is_ok() {
        read_some(stream, &mut buf, wait).await;
    }
    grab_from(port, &buf)
}

/// Turn a service's raw reply into banner + version.
pub fn grab_from(port: u16, raw: &[u8]) -> Grab {
    let banner = binary_banner(port, raw).or_else(|| summarize_banner(raw));
    let version = banner
        .as_deref()
        .and_then(crate::service::detect_version)
        .or_else(|| crate::service::detect_version(&String::from_utf8_lossy(raw)));
    Grab { banner, version }
}

/// Banners of binary protocols, which a "first text line" summary mangles.
fn binary_banner(port: u16, raw: &[u8]) -> Option<String> {
    // MySQL / MariaDB handshake v10: 3-byte length, seq, 0x0a, version\0
    if raw.len() > 6 && raw[4] == 0x0a && raw[3] == 0 {
        let ver = raw[5..].split(|&b| b == 0).next()?;
        if !ver.is_empty() && ver.iter().all(|b| b.is_ascii_graphic()) {
            let ver = sanitize(&String::from_utf8_lossy(ver));
            return Some(if ver.contains("MariaDB") {
                // MariaDB prefixes "5.5.5-" for old replication clients.
                format!("MariaDB {}", ver.trim_start_matches("5.5.5-"))
            } else {
                format!("MySQL {ver}")
            });
        }
    }
    // Redis `INFO` reply: bulk-string length line, then key:value lines.
    let text = String::from_utf8_lossy(raw);
    if let Some(line) = text.lines().find(|l| l.starts_with("redis_version:")) {
        return Some(format!("Redis {}", sanitize(&line[14..])));
    }
    if port == 5432 && matches!(raw, b"S" | b"N") {
        return Some("PostgreSQL (answered SSLRequest)".into());
    }
    None
}

/// First line of the banner; for HTTP also the `Server:` header, which is
/// where the product/version actually lives.
pub fn summarize_banner(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();
    let first = sanitize(lines.next().unwrap_or(""));
    if first.is_empty() {
        return None;
    }
    // Invalid UTF-8 = a binary protocol; its bytes mean nothing on screen.
    if first.contains('\u{FFFD}') {
        return Some(format!("(binary, {} bytes)", data.len()));
    }
    if first.starts_with("HTTP/") {
        if let Some(server) = lines.find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("server").then(|| sanitize(v))
        }) {
            return Some(format!("{first} | Server: {server}"));
        }
    }
    Some(first)
}

// ─── TLS Detection ────────────────────────────────────────────────────────────

/// Attempt a modern (TLS 1.2/1.3) handshake and extract the certificate.
///
/// Certificate *validity* is deliberately not enforced: we want to see
/// expired / self-signed / wrong-name certs, not reject them. `sni` is the
/// hostname the user typed (if any) so SNI-routed hosts return the right
/// certificate; for bare IPs no SNI is sent.
///
/// With `http` set, also send an HTTP request through the tunnel and return
/// the raw reply (for the `Server:` header of HTTPS services).
pub async fn detect_tls(
    addr: IpAddr,
    port: u16,
    wait: Duration,
    sni: Option<&str>,
    http: bool,
) -> Option<(crate::tls::TlsCertInfo, Vec<u8>)> {
    let stream = timeout(wait, TcpStream::connect((addr, port)))
        .await
        .ok()?
        .ok()?;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    let server_name = sni
        .and_then(|h| ServerName::try_from(h.to_string()).ok())
        .unwrap_or(ServerName::IpAddress(addr.into()));

    let connector = TlsConnector::from(Arc::new(config));
    let mut tls_stream = timeout(wait, connector.connect(server_name, stream))
        .await
        .ok()?
        .ok()?;

    // An unparseable certificate still means the port speaks TLS.
    let info = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|c| crate::tls::parse_cert(c.as_ref()))
        .unwrap_or_else(crate::tls::TlsCertInfo::unknown);
    let mut raw = Vec::new();
    if http && tls_stream.write_all(HTTP_PROBE).await.is_ok() {
        read_some(&mut tls_stream, &mut raw, wait.min(Duration::from_secs(2))).await;
    }
    Some((info, raw))
}

/// Does the server still accept SSLv3 / TLS 1.0 / TLS 1.1? rustls can't speak
/// those, so send a hand-built ClientHello capped at TLS 1.1 and read the
/// ServerHello version. A modern server answers with a `protocol_version`
/// alert → `None`.
pub async fn detect_legacy_tls(addr: IpAddr, port: u16, wait: Duration) -> Option<&'static str> {
    let mut s = timeout(wait, TcpStream::connect((addr, port)))
        .await
        .ok()?
        .ok()?;
    s.write_all(&legacy_client_hello()).await.ok()?;
    let mut head = [0u8; 11];
    timeout(wait, s.read_exact(&mut head)).await.ok()?.ok()?;
    parse_server_hello_version(&head)
}

/// TLS 1.1-max ClientHello without extensions (as old servers expect).
fn legacy_client_hello() -> Vec<u8> {
    const SUITES: [u16; 10] = [
        0xc014, 0xc013, 0x0039, 0x0033, 0x0035, 0x002f, 0x000a, 0x0005, 0x0004,
        0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ];
    let mut body = vec![0x03, 0x02]; // client_version = TLS 1.1
    body.extend([0x5a; 32]); // random: not security relevant for a probe
    body.push(0); // empty session id
    body.extend(((SUITES.len() * 2) as u16).to_be_bytes());
    for s in SUITES {
        body.extend(s.to_be_bytes());
    }
    body.extend([1, 0]); // one compression method: null

    let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8]; // ClientHello
    hs.extend(body);
    let mut rec = vec![0x16, 0x03, 0x01]; // handshake record, TLS 1.0 framing
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

/// `16 03 xx LL LL | 02 LL LL LL | VV VV` → negotiated legacy version.
pub fn parse_server_hello_version(b: &[u8]) -> Option<&'static str> {
    if b.len() < 11 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x02 {
        return None;
    }
    match (b[9], b[10]) {
        (3, 0) => Some("SSLv3"),
        (3, 1) => Some("TLSv1.0"),
        (3, 2) => Some("TLSv1.1"),
        _ => None,
    }
}

// ─── UDP payloads ─────────────────────────────────────────────────────────────

/// NTP v3 client request (mode 3).
const NTP_REQ: [u8; 48] = {
    let mut a = [0u8; 48];
    a[0] = 0x1b;
    a
};

/// A protocol-correct request for well-known UDP services, so real servers
/// answer (an empty/garbage datagram is silently dropped by DNS, NTP, SNMP …
/// and the port would look `open|filtered`).
pub fn udp_payload(port: u16) -> &'static [u8] {
    match port {
        // DNS: standard query, root NS
        53 => b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",
        // TFTP: read request for a dummy file — any reply (even an error) = open
        69 => b"\x00\x01rustscan\x00octet\x00",
        123 => &NTP_REQ,
        // NetBIOS name service: NBSTAT query for "*"
        137 => b"\x80\xf0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
        // SNMPv1 GetRequest sysDescr.0, community "public"
        161 => b"\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00",
        // SSDP / UPnP discovery
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
        // mDNS: PTR _services._dns-sd._udp.local
        5353 => b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
        _ => b"\x00",
    }
}

// ─── Danger: Null Verifier ────────────────────────────────────────────────────

/// A rustls certificate verifier that approves everything.
///
/// **SECURITY WARNING**: never use this for real traffic — it defeats MITM
/// protection. It is only safe here because we merely inspect the handshake.
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
            ED448,
        ]
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_keeps_first_line() {
        let raw = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\nSome other junk";
        assert_eq!(
            summarize_banner(raw).unwrap(),
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        );
    }

    #[test]
    fn summarize_adds_http_server_header() {
        let raw = b"HTTP/1.1 200 OK\r\nDate: x\r\nserver: nginx/1.25.3\r\n\r\n";
        assert_eq!(
            summarize_banner(raw).unwrap(),
            "HTTP/1.1 200 OK | Server: nginx/1.25.3"
        );
    }

    #[test]
    fn binary_banner_is_not_printed_raw() {
        assert_eq!(
            summarize_banner(b"\xa3;rk\xf0\x9fX").as_deref(),
            Some("(binary, 7 bytes)")
        );
        assert_eq!(
            summarize_banner("caf\u{e9}".as_bytes()).as_deref(),
            Some("caf\u{e9}")
        );
    }

    #[test]
    fn binary_greetings_become_versions() {
        let g = grab_from(
            3306,
            b"J\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB-0+deb12u1\x00\x08",
        );
        assert_eq!(
            g.banner.as_deref(),
            Some("MariaDB 10.11.6-MariaDB-0+deb12u1")
        );
        assert_eq!(
            g.version.as_deref(),
            Some("MariaDB 10.11.6-MariaDB-0+deb12u1")
        );
        assert_eq!(
            grab_from(5432, b"N").banner.as_deref(),
            Some("PostgreSQL (answered SSLRequest)")
        );
        assert_eq!(grab_from(9999, b"N").version, None, "only on 5432");
        let redis = grab_from(
            6379,
            b"$9
# Server
redis_version:6.2.1
",
        );
        assert_eq!(redis.version.as_deref(), Some("Redis 6.2.1"));
        assert_eq!(grab_from(80, b""), Grab::default());
    }

    #[test]
    fn sanitize_strips_terminal_escapes_and_bidi() {
        assert_eq!(sanitize("\x1b[31mred\x1b[0m\u{202E}x\0"), "[31mred[0mx");
        assert_eq!(sanitize("CN=exämple.com"), "CN=exämple.com");
        assert!(summarize_banner(b"\x00\x1b\r\n").is_none());
    }

    #[test]
    fn client_hello_lengths_are_consistent() {
        let h = legacy_client_hello();
        let rec_len = u16::from_be_bytes([h[3], h[4]]) as usize;
        assert_eq!(rec_len, h.len() - 5);
        let hs_len = ((h[6] as usize) << 16) | ((h[7] as usize) << 8) | h[8] as usize;
        assert_eq!(hs_len, rec_len - 4);
        assert_eq!((h[9], h[10]), (3, 2), "advertises TLS 1.1 max");
    }

    #[test]
    fn parses_server_hello_versions() {
        let hello = |v: u8| [0x16, 3, 1, 0, 0x4a, 0x02, 0, 0, 0x46, 3, v];
        assert_eq!(parse_server_hello_version(&hello(1)), Some("TLSv1.0"));
        assert_eq!(parse_server_hello_version(&hello(2)), Some("TLSv1.1"));
        assert_eq!(parse_server_hello_version(&hello(0)), Some("SSLv3"));
        // protocol_version alert from a modern server
        assert_eq!(
            parse_server_hello_version(&[0x15, 3, 3, 0, 2, 2, 70, 0, 0, 0, 0]),
            None
        );
        assert_eq!(parse_server_hello_version(b"HTTP/1.1 400"), None);
    }

    #[test]
    fn snmp_payload_ber_lengths() {
        let p = udp_payload(161);
        assert_eq!(p[1] as usize, p.len() - 2);
        assert_eq!(udp_payload(123).len(), 48);
        assert_eq!(udp_payload(9), b"\x00");
    }
}
