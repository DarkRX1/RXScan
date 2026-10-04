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
use serde::{Deserialize, Serialize};

use crate::execution::CancellationToken;

/// Safely observed TLS handshake facts.
#[derive(Debug, Clone)]
pub struct TlsObservation {
    pub negotiated_version: String,
    pub cipher_suite: String,
    /// Presented chain (leaf first), DER bytes, bounded by the caller.
    pub peer_certs_der: Vec<Vec<u8>>,
    pub latency: Duration,
    /// Negotiated ALPN protocol, if the server selected one.
    pub alpn: Option<String>,
    /// Server name sent via SNI (`None` means no SNI: IP literal target).
    pub sni: Option<String>,
}

// ---------------- certificate identity (correlation engine) ----------------
//
// A normalized, stable certificate entity for cross-observation correlation.
// Identity is the SHA-256 of the leaf DER (`cert:sha256:<hex>`): the same
// certificate presented on two ports yields one entity, enabling reuse
// analysis. Fields come straight from parsing; anything unobservable via the
// client handshake API is absent (no client-certificate-request visibility,
// no cipher enumeration) rather than inferred.

/// Maximum leaf DER bytes parsed for identity (bounded parsing).
pub const MAX_IDENTITY_DER_BYTES: usize = 16 * 1024;

/// Normalized certificate identity: stable entity for graph correlation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertificateIdentity {
    /// SHA-256 over leaf DER (hex). Stable graph identity.
    pub sha256: String,
    pub subject: String,
    pub issuer: String,
    #[serde(default)]
    pub sans_dns: Vec<String>,
    #[serde(default)]
    pub sans_ip: Vec<String>,
    /// Serial number as even-length lowercase hex.
    pub serial_hex: String,
    pub not_before_epoch: i64,
    pub not_after_epoch: i64,
    /// Public-key algorithm (common name or dotted OID).
    pub public_key_algorithm: String,
    /// Nominal key size in bits, derived from the encoded key length
    /// (leading-zero byte discounted). Encoding-derived, not a parsed
    /// cryptographic measurement — reported as observed fact.
    pub public_key_bits_nominal: usize,
    /// Signature algorithm (common name or dotted OID).
    pub signature_algorithm: String,
    /// Presented chain length (leaf + intermediates as observed).
    pub chain_len: usize,
    /// DN-equality heuristic (subject DER == issuer DER). A reuse/correlation
    /// hint, never a trust verdict.
    pub self_signed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

impl CertificateIdentity {
    /// Stable graph entity id.
    pub fn entity_id(&self) -> String {
        format!("cert:sha256:{}", self.sha256)
    }

    /// Build from a leaf DER plus handshake context. Returns `None` when
    /// parsing fails or input is empty/unbounded (handshake-only evidence
    /// still stands on its own; absence of identity is not an error).
    /// Never panics on untrusted bytes.
    pub fn from_parts(
        leaf_der: &[u8],
        chain_len: usize,
        alpn: Option<&str>,
        sni: Option<&str>,
    ) -> Option<Self> {
        if leaf_der.is_empty() || leaf_der.len() > MAX_IDENTITY_DER_BYTES {
            return None;
        }
        let (_, cert) = x509_parser::parse_x509_certificate(leaf_der).ok()?;
        let tbs = &cert.tbs_certificate;
        let mut sans_dns = Vec::new();
        let mut sans_ip = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(pattern) => {
                        let pattern = pattern.to_string();
                        if !pattern.is_empty()
                            && pattern.len() <= 253
                            && sans_dns.len() < 64
                            && !sans_dns.contains(&pattern)
                        {
                            sans_dns.push(pattern);
                        }
                    }
                    x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                        if let Ok(ip) = ip_from_bytes(bytes) {
                            let text = ip.to_string();
                            if sans_ip.len() < 64 && !sans_ip.contains(&text) {
                                sans_ip.push(text);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let fingerprint = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(leaf_der);
            hex_bytes(&hasher.finalize())
        };
        let serial_hex = {
            let raw = tbs.serial.to_bytes_be();
            let mut hex = String::with_capacity(raw.len() * 2);
            for byte in &raw {
                hex.push_str(&format!("{byte:02x}"));
            }
            if hex.is_empty() { "00".to_owned() } else { hex }
        };
        let (key_algorithm, key_bits) = public_key_facts(&tbs.subject_pki);
        let self_signed = tbs.subject.as_raw() == tbs.issuer.as_raw();
        Some(Self {
            sha256: fingerprint,
            subject: truncate_observed(&tbs.subject.to_string(), 512),
            issuer: truncate_observed(&tbs.issuer.to_string(), 512),
            sans_dns,
            sans_ip,
            serial_hex,
            not_before_epoch: tbs.validity.not_before.timestamp(),
            not_after_epoch: tbs.validity.not_after.timestamp(),
            public_key_algorithm: key_algorithm,
            public_key_bits_nominal: key_bits,
            signature_algorithm: algorithm_name(&tbs.signature.algorithm.to_string()),
            chain_len,
            self_signed,
            alpn: alpn
                .filter(|value| !value.trim().is_empty())
                .map(|value| truncate_observed(value, 64)),
            sni: sni
                .filter(|value| !value.trim().is_empty())
                .map(|value| truncate_observed(value, 253)),
        })
    }
}

fn ip_from_bytes(bytes: &[u8]) -> Result<IpAddr, ()> {
    match bytes.len() {
        4 => Ok(IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Ok(IpAddr::from(octets))
        }
        _ => Err(()),
    }
}

fn truncate_observed(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Common asymmetric-algorithm OIDs to short names; anything else stays a
/// dotted OID (honest, never guessed).
fn algorithm_name(dotted_oid: &str) -> String {
    match dotted_oid {
        "1.2.840.113549.1.1.1" => "rsaEncryption".to_owned(),
        "1.2.840.10045.2.1" => "ecPublicKey".to_owned(),
        "1.2.840.10040.4.1" => "dsa".to_owned(),
        "1.3.101.110" => "X25519".to_owned(),
        "1.3.101.111" => "X448".to_owned(),
        "1.3.101.112" => "Ed25519".to_owned(),
        "1.3.101.113" => "Ed448".to_owned(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".to_owned(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".to_owned(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".to_owned(),
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".to_owned(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_owned(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_owned(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".to_owned(),
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1".to_owned(),
        _ => format!("oid:{dotted_oid}"),
    }
}

fn public_key_facts(spki: &x509_parser::x509::SubjectPublicKeyInfo) -> (String, usize) {
    let algorithm = algorithm_name(&spki.algorithm.algorithm.to_string());
    let raw = &spki.subject_public_key.data;
    // BIT STRING content: discount one leading zero pad byte when present.
    let effective = match raw.first() {
        Some(0x00) if raw.len() > 1 => &raw[1..],
        _ => raw.as_ref(),
    };
    (algorithm, effective.len().saturating_mul(8))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------- TLS posture (assessment from evidence) ----------------
//
// Posture states are factual conditions established from the handshake and
// certificate observations above — never vulnerability verdicts. Each flag
// names checkable evidence. "now" is always caller-supplied (scan time or
// project time), so assessments stay deterministic and re-derivable.

/// Factual TLS posture states. Absence of a flag means its condition was
/// not established, never that the opposite holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPostureFlag {
    DeprecatedProtocolObserved,
    CertificateExpired,
    CertificateNotYetValid,
    HostnameMismatch,
    SelfSigned,
    ShortKey,
    WeakSignatureAlgorithm,
}

impl std::fmt::Display for TlsPostureFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::DeprecatedProtocolObserved => "deprecated_protocol_observed",
            Self::CertificateExpired => "certificate_expired",
            Self::CertificateNotYetValid => "certificate_not_yet_valid",
            Self::HostnameMismatch => "hostname_mismatch",
            Self::SelfSigned => "self_signed",
            Self::ShortKey => "short_key",
            Self::WeakSignatureAlgorithm => "weak_signature_algorithm",
        };
        f.write_str(name)
    }
}

/// Structured TLS posture observation for one endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPosture {
    pub endpoint: String,
    #[serde(default)]
    pub versions_observed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_cipher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    pub client_cert_requested: bool,
    #[serde(default)]
    pub assessment: Vec<TlsPostureFlag>,
}

impl TlsPosture {
    /// Short Rsa/Ec key-size floor: RSA below 2048 bits or EC below 224
    /// bits counts as short. Other algorithms are not judged (absent
    /// evidence, absent flag).
    pub fn short_key_bits(algorithm: &str, bits: usize) -> bool {
        let algorithm = algorithm.to_ascii_lowercase();
        if algorithm.contains("rsa") {
            bits < 2048
        } else if algorithm.contains("ec")
            || algorithm.contains("ecdsa")
            || algorithm.contains("ed25519")
            || algorithm.contains("ed448")
            || algorithm.contains("x25519")
            || algorithm.contains("x448")
        {
            bits < 224
        } else {
            false
        }
    }

    /// Weak signature algorithms: MD5- or SHA-1-based (conservative
    /// substring match on the normalized name; unknown names pass).
    pub fn weak_signature_algorithm(name: &str) -> bool {
        let name = name.to_ascii_lowercase().replace(['-', '_'], "");
        name.contains("md5") || name.contains("sha1")
    }

    /// Deprecated protocol versions: TLS 1.0/1.1 (and anything older).
    pub fn deprecated_protocol(version: &str) -> bool {
        matches!(
            version.trim(),
            "TLSv1.0" | "TLSv1.1" | "TLSv1" | "SSLv2" | "SSLv3" | "SSLv23"
        )
    }
}

/// Assess posture from handshake facts. Pure and deterministic; `now_epoch`
/// is seconds since the Unix epoch (caller clock). Every flag requires
/// positive evidence; unparseable inputs yield fewer flags, never errors.
#[allow(clippy::too_many_arguments)]
pub fn assess_posture(
    endpoint: &str,
    negotiated_version: Option<&str>,
    negotiated_cipher: Option<&str>,
    alpn: Option<&str>,
    identity: Option<&CertificateIdentity>,
    hostname_match: Option<bool>,
    now_epoch: i64,
) -> TlsPosture {
    let mut assessment = Vec::new();
    if negotiated_version.is_some_and(TlsPosture::deprecated_protocol) {
        assessment.push(TlsPostureFlag::DeprecatedProtocolObserved);
    }
    if let Some(identity) = identity {
        if now_epoch >= identity.not_after_epoch {
            assessment.push(TlsPostureFlag::CertificateExpired);
        } else if now_epoch < identity.not_before_epoch {
            assessment.push(TlsPostureFlag::CertificateNotYetValid);
        }
        if TlsPosture::short_key_bits(
            &identity.public_key_algorithm,
            identity.public_key_bits_nominal,
        ) {
            assessment.push(TlsPostureFlag::ShortKey);
        }
        if TlsPosture::weak_signature_algorithm(&identity.signature_algorithm) {
            assessment.push(TlsPostureFlag::WeakSignatureAlgorithm);
        }
        if identity.self_signed {
            assessment.push(TlsPostureFlag::SelfSigned);
        }
    }
    if hostname_match == Some(false) {
        assessment.push(TlsPostureFlag::HostnameMismatch);
    }
    TlsPosture {
        endpoint: endpoint.chars().take(256).collect(),
        versions_observed: negotiated_version
            .filter(|version| !version.trim().is_empty())
            .map(|version| vec![version.chars().take(32).collect()])
            .unwrap_or_default(),
        negotiated_cipher: negotiated_cipher
            .filter(|cipher| !cipher.trim().is_empty())
            .map(|cipher| cipher.chars().take(64).collect()),
        alpn: alpn
            .filter(|alpn| !alpn.trim().is_empty())
            .map(|alpn| alpn.chars().take(64).collect()),
        certificate_id: identity.map(|identity| identity.entity_id()),
        // The client handshake path never observes a CertificateRequest
        // frame distinctly; recorded as false (honest absence, not proof
        // that none was sent).
        client_cert_requested: false,
        assessment,
    }
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
    // ALPN as negotiated (bounded, lossy): evidence of offered protocols.
    let alpn = conn
        .alpn_protocol()
        .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
        .filter(|protocol| !protocol.trim().is_empty() && protocol.len() <= 64)
        .map(|protocol| protocol.trim().to_owned());
    // SNI as sent: hostname targets send SNI, IP literals do not.
    let sni = match server_name {
        Some(host) if host.parse::<IpAddr>().is_err() => {
            let host = host.trim().trim_end_matches('.');
            (!host.is_empty() && host.len() <= 253).then(|| host.to_owned())
        }
        _ => None,
    };
    Ok(EstablishedTls {
        stream,
        conn,
        observation: TlsObservation {
            negotiated_version: version,
            cipher_suite: cipher,
            peer_certs_der: chain,
            latency: started.elapsed(),
            alpn,
            sni,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_for_test() -> CertificateIdentity {
        CertificateIdentity {
            sha256: "ab".repeat(32),
            subject: "CN=test".to_owned(),
            issuer: "CN=test".to_owned(),
            sans_dns: vec!["test.example".to_owned()],
            sans_ip: vec![],
            serial_hex: "01".to_owned(),
            not_before_epoch: 1_700_000_000,
            not_after_epoch: 1_800_000_000,
            public_key_algorithm: "rsaEncryption".to_owned(),
            public_key_bits_nominal: 2048,
            signature_algorithm: "sha256WithRSAEncryption".to_owned(),
            chain_len: 1,
            self_signed: true,
            alpn: Some("h2".to_owned()),
            sni: Some("test.example".to_owned()),
        }
    }

    #[test]
    fn posture_flags_only_established_conditions() {
        // Healthy modern endpoint: only the self-signed fact fires.
        let posture = assess_posture(
            "10.0.0.1:443",
            Some("TLSv1.3"),
            Some("TLS13_AES_256_GCM_SHA384"),
            Some("h2"),
            Some(&identity_for_test()),
            Some(true),
            1_750_000_000,
        );
        assert_eq!(posture.assessment, vec![TlsPostureFlag::SelfSigned]);
        assert_eq!(posture.versions_observed, vec!["TLSv1.3".to_owned()]);
        assert!(!posture.client_cert_requested);
        // Expired + deprecated + mismatch + weak sig + short key.
        let mut weak = identity_for_test();
        weak.public_key_bits_nominal = 1024;
        weak.signature_algorithm = "sha1WithRSAEncryption".to_owned();
        let posture = assess_posture(
            "10.0.0.1:443",
            Some("TLSv1.0"),
            None,
            None,
            Some(&weak),
            Some(false),
            1_900_000_000,
        );
        for flag in [
            TlsPostureFlag::DeprecatedProtocolObserved,
            TlsPostureFlag::CertificateExpired,
            TlsPostureFlag::HostnameMismatch,
            TlsPostureFlag::SelfSigned,
            TlsPostureFlag::ShortKey,
            TlsPostureFlag::WeakSignatureAlgorithm,
        ] {
            assert!(posture.assessment.contains(&flag), "missing {flag}");
        }
        // Not-yet-valid, and unknown names pass through silently.
        let mut future = identity_for_test();
        future.not_before_epoch = 1_900_000_000;
        future.not_after_epoch = 2_000_000_000;
        future.self_signed = false;
        let posture = assess_posture(
            "10.0.0.1:443",
            Some("TLSv1.2"),
            None,
            None,
            Some(&future),
            None,
            1_750_000_000,
        );
        assert_eq!(
            posture.assessment,
            vec![TlsPostureFlag::CertificateNotYetValid]
        );
        // No identity, no evidence: empty assessment, never an error.
        let posture = assess_posture("10.0.0.1:443", None, None, None, None, None, 0);
        assert!(posture.assessment.is_empty());
        assert!(posture.versions_observed.is_empty());
    }

    #[test]
    fn posture_predicates_are_conservative() {
        assert!(TlsPosture::deprecated_protocol("TLSv1.0"));
        assert!(TlsPosture::deprecated_protocol("TLSv1.1"));
        assert!(!TlsPosture::deprecated_protocol("TLSv1.2"));
        assert!(!TlsPosture::deprecated_protocol("TLSv1.3"));
        assert!(!TlsPosture::deprecated_protocol("unknown"));
        assert!(TlsPosture::weak_signature_algorithm(
            "sha1WithRSAEncryption"
        ));
        assert!(TlsPosture::weak_signature_algorithm("md5WithRSAEncryption"));
        assert!(!TlsPosture::weak_signature_algorithm(
            "sha256WithRSAEncryption"
        ));
        assert!(!TlsPosture::weak_signature_algorithm("Ed25519"));
        assert!(!TlsPosture::weak_signature_algorithm("oid:1.2.3"));
        assert!(TlsPosture::short_key_bits("rsaEncryption", 1024));
        assert!(!TlsPosture::short_key_bits("rsaEncryption", 2048));
        assert!(TlsPosture::short_key_bits("ecPublicKey", 160));
        assert!(!TlsPosture::short_key_bits("ecPublicKey", 256));
        assert!(!TlsPosture::short_key_bits("mystery-alg", 128));
    }
}
