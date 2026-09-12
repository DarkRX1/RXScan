//! Native TLS observation for Phase 7 service intelligence.
//!
//! Uses `rustls` (pure Rust) as a TLS *client* with an observe-only
//! certificate verifier: trust is never evaluated, the presented chain is
//! recorded as evidence. No cipher enumeration, no session resumption games,
//! no client authentication.
//!
//! Every handshake honors a wall-clock budget, short socket timeouts (prompt
//! cancellation), and bounded chain bytes. Failures stay failures — a TLS
//! error never becomes an HTTPS classification.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsLibError, SignatureScheme,
};

use crate::execution::CancellationToken;

/// Safely observed TLS handshake facts.
#[derive(Debug, Clone)]
pub struct TlsObservation {
    pub negotiated_version: String,
    pub cipher_suite: String,
    /// Presented chain (leaf first), DER bytes, bounded by the caller.
    pub peer_certs_der: Vec<Vec<u8>>,
    pub latency: Duration,
}

/// Why a TLS attempt did not produce an observation.
#[derive(Debug, Clone)]
pub enum TlsFailure {
    Cancelled,
    Timeout,
    ConnectionFailed(String),
    HandshakeFailed(String),
}

/// Observe-only verifier: records the presented chain, asserts nothing about
/// trust. Signature checks are waived (scanner context, not a browser).
#[derive(Debug)]
struct ObserveOnlyVerifier {
    seen: Mutex<Option<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for ObserveOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsLibError> {
        let mut chain = Vec::with_capacity(intermediates.len() + 1);
        chain.push(end_entity.as_ref().to_vec());
        chain.extend(intermediates.iter().map(|cert| cert.as_ref().to_vec()));
        *self.seen.lock().expect("verifier lock") = Some(chain);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsLibError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsLibError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// An established TLS session retained for compositional probing
/// (HTTP/SMTP inside TLS). The handshake observation travels with it.
pub struct EstablishedTls {
    stream: TcpStream,
    conn: ClientConnection,
    pub observation: TlsObservation,
}

impl EstablishedTls {
    /// Send one bounded HTTP request inside the session, read a bounded
    /// response. No redirects followed, no crawling — one exchange.
    pub fn http_get(
        &mut self,
        host_label: &str,
        max_bytes: usize,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, String> {
        let request = format!(
            "GET / HTTP/1.0\r\nHost: {host_label}\r\nConnection: close\r\nUser-Agent: rxscan-phase7\r\n\r\n"
        );
        self.exchange_http(request.as_bytes(), max_bytes, timeout, cancel)
    }

    /// Send arbitrary bounded request bytes inside the session and read a
    /// bounded response. Powers Phase 8 HTTP/1.1 exchanges (GET/HEAD with
    /// explicit paths) over the same observation-only session primitive.
    /// Tolerates close-without-notify after bytes arrive; errors only when
    /// nothing was received at all.
    pub fn exchange_http(
        &mut self,
        request: &[u8],
        max_bytes: usize,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, String> {
        self.stream
            .set_write_timeout(Some(Duration::from_millis(500)))
            .map_err(|error| error.to_string())?;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|error| error.to_string())?;
        let started = Instant::now();
        {
            let mut tls = rustls::Stream::new(&mut self.conn, &mut self.stream);
            tls.write_all(request)
                .map_err(|error| format!("tls write: {error}"))?;
            tls.flush().map_err(|error| format!("tls flush: {error}"))?;
            let mut response = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                if cancel.is_cancelled() {
                    return Err("cancelled".to_owned());
                }
                if started.elapsed() >= timeout {
                    break;
                }
                match tls.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => {
                        let room = max_bytes.saturating_sub(response.len());
                        if room == 0 {
                            break;
                        }
                        response.extend_from_slice(&chunk[..count.min(room)]);
                        if response.len() >= max_bytes {
                            break;
                        }
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // Expected for keep-alive servers; fall through.
                        break;
                    }
                    // Servers routinely close without close_notify (and some
                    // reset after answering). Bytes already received still
                    // count as evidence; only a fully empty reply errors.
                    Err(_) if !response.is_empty() => break,
                    Err(error) => return Err(format!("tls read: {error}")),
                }
            }
            Ok(response)
        }
    }

    /// Send one bounded line-oriented exchange inside the session (EHLO for
    /// SMTPS composition). Returns raw bytes, bounded.
    pub fn exchange_lines(
        &mut self,
        send: &[u8],
        max_bytes: usize,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, String> {
        self.stream
            .set_write_timeout(Some(Duration::from_millis(500)))
            .map_err(|error| error.to_string())?;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|error| error.to_string())?;
        let started = Instant::now();
        let mut tls = rustls::Stream::new(&mut self.conn, &mut self.stream);
        // Read the inside-TLS greeting first (SMTP servers greet on connect).
        let mut response = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            if cancel.is_cancelled() {
                return Err("cancelled".to_owned());
            }
            if started.elapsed() >= timeout || response.len() >= max_bytes {
                break;
            }
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let room = max_bytes.saturating_sub(response.len());
                    if room == 0 {
                        break;
                    }
                    response.extend_from_slice(&chunk[..count.min(room)]);
                    if response.ends_with(b"\n") {
                        break;
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                // Tolerate close-without-notify after bytes arrived.
                Err(_) if !response.is_empty() => break,
                Err(error) => return Err(format!("tls read: {error}")),
            }
        }
        if !send.is_empty() {
            tls.write_all(send)
                .map_err(|error| format!("tls write: {error}"))?;
            tls.flush().map_err(|error| format!("tls flush: {error}"))?;
            loop {
                if cancel.is_cancelled() {
                    return Err("cancelled".to_owned());
                }
                if started.elapsed() >= timeout || response.len() >= max_bytes {
                    break;
                }
                match tls.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => {
                        let room = max_bytes.saturating_sub(response.len());
                        if room == 0 {
                            break;
                        }
                        response.extend_from_slice(&chunk[..count.min(room)]);
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    // Tolerate close-without-notify after bytes arrived.
                    Err(_) if !response.is_empty() => break,
                    Err(error) => return Err(format!("tls read: {error}")),
                }
            }
        }
        Ok(response)
    }
}

/// Perform a bounded TLS handshake against `ip:port`.
///
/// `server_name` feeds SNI (hostname targets) or stays empty for IP literals
/// (no SNI is sent for IPs). Returns the session on success so callers may
/// compose application probes inside it.
pub fn connect_tls(
    ip: IpAddr,
    port: u16,
    server_name: Option<&str>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<EstablishedTls, TlsFailure> {
    if cancel.is_cancelled() {
        return Err(TlsFailure::Cancelled);
    }
    let timeout = timeout.clamp(Duration::from_millis(200), Duration::from_secs(10));
    let started = Instant::now();
    let address = SocketAddr::new(ip, port);
    // Short connect slice keeps cancellation prompt even for filtered hosts.
    let connect_budget = timeout.min(Duration::from_millis(1500));
    let stream = TcpStream::connect_timeout(&address, connect_budget)
        .map_err(|error| classify_connect_error(&error, started.elapsed()))?;
    if cancel.is_cancelled() {
        return Err(TlsFailure::Cancelled);
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| TlsFailure::HandshakeFailed(error.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| TlsFailure::HandshakeFailed(error.to_string()))?;

    let name: ServerName<'static> = match server_name {
        Some(host) if !host.parse::<IpAddr>().is_ok() => ServerName::try_from(host.to_owned())
            .map_err(|_| TlsFailure::HandshakeFailed(format!("invalid SNI hostname '{host}'")))?,
        _ => match ip {
            IpAddr::V4(v4) => ServerName::IpAddress(rustls::pki_types::IpAddr::V4(v4.into())),
            IpAddr::V6(v6) => ServerName::IpAddress(rustls::pki_types::IpAddr::V6(v6.into())),
        },
    };
    let verifier = std::sync::Arc::new(ObserveOnlyVerifier {
        seen: Mutex::new(None),
    });
    let provider = default_provider();
    let config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .map_err(|error| TlsFailure::HandshakeFailed(format!("tls versions: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let mut conn = ClientConnection::new(std::sync::Arc::new(config), name)
        .map_err(|error| TlsFailure::HandshakeFailed(error.to_string()))?;
    let mut stream = stream;
    loop {
        if cancel.is_cancelled() {
            return Err(TlsFailure::Cancelled);
        }
        if started.elapsed() >= timeout {
            return Err(TlsFailure::Timeout);
        }
        match conn.complete_io(&mut stream) {
            Ok(_) => {
                if !conn.is_handshaking() {
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                return Err(TlsFailure::HandshakeFailed(trim_tls_error(&error)));
            }
        }
    }
    let version = conn
        .protocol_version()
        .map(|version| match u16::from(version) {
            0x0301 => "TLSv1.0".to_owned(),
            0x0302 => "TLSv1.1".to_owned(),
            0x0303 => "TLSv1.2".to_owned(),
            0x0304 => "TLSv1.3".to_owned(),
            other => format!("TLS(0x{other:04x})"),
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "unknown".to_owned());
    let chain = verifier
        .seen
        .lock()
        .expect("verifier lock")
        .clone()
        .unwrap_or_default();
    Ok(EstablishedTls {
        stream,
        conn,
        observation: TlsObservation {
            negotiated_version: version,
            cipher_suite: cipher,
            peer_certs_der: chain,
            latency: started.elapsed(),
        },
    })
}

fn classify_connect_error(error: &std::io::Error, _elapsed: Duration) -> TlsFailure {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::TimedOut => TlsFailure::Timeout,
        _ => {
            let message = error.to_string().to_ascii_lowercase();
            if message.contains("timed out") {
                TlsFailure::Timeout
            } else {
                TlsFailure::ConnectionFailed(trim_tls_error(error))
            }
        }
    }
}

fn trim_tls_error(error: &std::io::Error) -> String {
    let mut text = error.to_string();
    if text.len() > 300 {
        text.truncate(300);
    }
    text
}
