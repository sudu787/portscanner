/// probes.rs — Active and passive service probing
///
/// ═══════════════════════════════════════════════════════════════════════════
/// PROBING ARCHITECTURE
/// ═══════════════════════════════════════════════════════════════════════════
///
/// Rustscan-rs separates connection speed from deep inspection.
/// `scanner.rs` does a raw TCP connect as fast as possible. If the port is
/// open and probing is enabled, the active `TcpStream` is passed here for
/// banner grabbing.
///
/// TLS detection establishes a *fresh* TCP connection because the OpenSSL/rustls
/// state machines expect to negotiate from byte 0.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ─── Banner Grabbing ──────────────────────────────────────────────────────────

/// Try to grab a banner from an open TCP stream.
///
/// 1. Passive read: waits 500ms for a welcome banner (SSH, FTP, SMTP).
/// 2. Active probe: if no data, sends a minimal HTTP request and waits again.
pub async fn grab_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 1024];

    // 1. Passive read
    // Many services (SSH, FTP, SMTP) announce themselves immediately.
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        if n > 0 {
            return Some(clean_banner(&buf[..n]));
        }
    }

    // 2. Active HTTP probe
    // Web servers wait for the client to speak first. We send a simple HEAD request.
    let probe = b"HEAD / HTTP/1.0\r\n\r\n";
    if stream.write_all(probe).await.is_ok() {
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
            if n > 0 {
                return Some(clean_banner(&buf[..n]));
            }
        }
    }

    None
}

/// Strip control characters and return only the first line of the banner.
fn clean_banner(data: &[u8]) -> String {
    let raw = String::from_utf8_lossy(data);
    raw.lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() && c.is_ascii())
        .collect::<String>()
        .trim()
        .to_string()
}

// ─── TLS Detection ────────────────────────────────────────────────────────────

/// Attempt a TLS handshake against the target port.
///
/// We use a custom verifier that explicitly ignores ALL certificate errors
/// (expired, wrong domain, self-signed, etc.). We do not care if the certificate
/// is mathematically valid — we only care if the port *speaks* TLS.
pub async fn detect_tls(addr: IpAddr, port: u16, timeout: Duration) -> Option<crate::tls::TlsCertInfo> {
    let connect_future = TcpStream::connect((addr, port));
    let stream = match tokio::time::timeout(timeout, connect_future).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Construct the permissive TLS configuration
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    // rustls requires SNI (Server Name Indication) by default.
    // If the target is an IP address, we just pass a dummy name so the handshake starts.
    let server_name = ServerName::try_from("rustscan.local")
        .expect("dummy domain is valid");

    let connector = TlsConnector::from(Arc::new(config));
    let handshake_future = connector.connect(server_name, stream);

    // If the handshake completes within the timeout, it's TLS.
    // (Even with our permissive verifier, a non-TLS server will cause the
    // handshake to fail with a protocol error when we send the ClientHello).
    match tokio::time::timeout(timeout, handshake_future).await {
        Ok(Ok(tls_stream)) => {
            if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
                if let Some(first_cert) = certs.first() {
                    return crate::tls::parse_cert(first_cert.as_ref());
                }
            }
            // Handshake succeeded but no certificate could be extracted or parsed
            Some(crate::tls::TlsCertInfo {
                subject: "Unknown (TLS Handshake OK)".into(),
                issuer: "Unknown".into(),
                not_before: "".into(),
                not_after: "".into(),
            })
        }
        _ => None,
    }
}

// ─── Danger: Null Verifier ────────────────────────────────────────────────────

/// A rustls certificate verifier that approves absolutely everything.
///
/// **SECURITY WARNING**: Never use this in production code that relies on TLS
/// for actual secrecy or authentication. It completely defeats MITM protection.
/// It is only safe here because we are merely probing the protocol type.
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
    fn clean_banner_removes_newlines_and_control_chars() {
        let raw = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\nSome other junk";
        let cleaned = clean_banner(raw);
        assert_eq!(cleaned, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5");
    }

    #[test]
    fn clean_banner_handles_binary_garbage() {
        let raw = [0xff, 0x00, 0x1b, b'H', b'T', b'T', b'P', 0x00];
        let cleaned = clean_banner(&raw);
        assert_eq!(cleaned, "HTTP");
    }
}
