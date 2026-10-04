//! SSH intelligence: structured observations from the SSH transport
//! without authentication.
//!
//! What this module does:
//! * parses server identification strings (`SSH-2.0-OpenSSH_9.8 ...`)
//!   into protocol/product/version/platform evidence;
//! * performs a bounded Curve25519 key-exchange handshake to capture the
//!   server's host key material (public key only), negotiated algorithm
//!   lists, and selected algorithms;
//! * normalizes host keys into stable `sshkey:sha256:` identities for
//!   cross-endpoint correlation and rotation tracking.
//!
//! What it never does: authenticate, open channels/sessions, execute
//! commands, brute-force anything, or verify the exchange signature (the
//! key is recorded *as presented*; exchange authentication is out of scope
//! and the fact is recorded honestly on every observation).
//!
//! All network behavior is bounded: caller-supplied deadline, short socket
//! timeouts, prompt cancellation, capped algorithm lists and packet sizes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::execution::CancellationToken;

/// Maximum single SSH packet accepted (bounded parsing).
pub const MAX_SSH_PACKET_BYTES: usize = 32 * 1024;
/// Maximum algorithm names retained per list (bounded output).
pub const MAX_ALGORITHMS_PER_LIST: usize = 32;
/// Maximum single algorithm name length.
pub const MAX_ALGORITHM_NAME_LEN: usize = 64;
/// Overall wall budget for the KEX capture inside one probe.
pub const MAX_KEX_CAPTURE: Duration = Duration::from_secs(3);

/// Parsed server identification string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshIdentification {
    pub protocol_version: String,
    pub software: String,
    pub product: Option<String>,
    pub version: Option<String>,
    /// Platform tokens from the comment section (`Ubuntu`, `Debian`,
    /// `FreeBSD`, …) — OS-hint evidence, never identity.
    pub platform_tokens: Vec<String>,
}

/// Parse `SSH-2.0-OpenSSH_9.8 Ubuntu-1`-style identification strings.
/// Returns `None` when the line is not a well-formed SSH ident string
/// (malformed input classifies nothing).
pub fn parse_identification(line: &str) -> Option<SshIdentification> {
    let line = line.trim_end_matches(['\r', '\n']);
    let rest = line.strip_prefix("SSH-")?;
    let (proto, rest) = rest.split_once('-')?;
    if proto != "2.0" && proto != "1.99" {
        return None;
    }
    if rest.is_empty() || rest.len() > 255 || !rest.is_ascii() {
        return None;
    }
    let (software, comment) = match rest.split_once(' ') {
        Some((software, comment)) => (software, Some(comment)),
        None => (rest, None),
    };
    if software.is_empty() {
        return None;
    }
    let (product, version) = split_software(software);
    let mut platform_tokens = Vec::new();
    if let Some(comment) = comment {
        for token in comment.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
            let token = token.trim_matches(['(', ')', '[', ']', '.', ',', ';']);
            if (3..=32).contains(&token.len())
                && token.chars().any(|c| c.is_ascii_alphabetic())
                && platform_tokens.len() < 8
                && !platform_tokens.contains(&token.to_owned())
            {
                platform_tokens.push(token.to_owned());
            }
        }
    }
    Some(SshIdentification {
        protocol_version: proto.to_owned(),
        software: software.to_owned(),
        product,
        version,
        platform_tokens,
    })
}

/// Split `OpenSSH_9.8` / `dropbear_2022.83` / `libssh-0.10` into
/// (product, version). Bare names without versions yield product-only.
fn split_software(software: &str) -> (Option<String>, Option<String>) {
    // Underscore form first: `OpenSSH_9.8`, `dropbear_2022.83`.
    if let Some((product, version)) = software.split_once('_') {
        if !product.is_empty()
            && !version.is_empty()
            && version.len() <= 32
            && version.bytes().any(|b| b.is_ascii_digit())
        {
            return (Some(product.to_owned()), Some(version.to_owned()));
        }
    }
    // Dash form with digit-led remainder: `libssh-0.10`, `AsyncSSH-2.1`.
    if let Some((product, version)) = software.split_once('-') {
        if !product.is_empty()
            && !version.is_empty()
            && version.len() <= 32
            && version.bytes().next().is_some_and(|b| b.is_ascii_digit())
        {
            return (Some(product.to_owned()), Some(version.to_owned()));
        }
    }
    // Bare product token (bounded, safe alphabet) or nothing.
    if !software.is_empty()
        && software.len() <= 64
        && software
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
    {
        return (Some(software.to_owned()), None);
    }
    (None, None)
}

/// Normalized SSH host key: stable cross-endpoint identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshHostKeyFacts {
    /// Key algorithm name as presented (`ssh-ed25519`, …).
    pub key_type: String,
    /// Nominal key size in bits (encoding-derived for RSA/ECDSA).
    pub bits: usize,
    /// SHA-256 over the raw host-key blob (stable identity).
    pub sha256: String,
    /// Stable graph entity id (`sshkey:sha256:<hex>`).
    pub entity_id: String,
}

impl SshHostKeyFacts {
    pub fn entity_id_for(sha256_hex: &str) -> String {
        format!("sshkey:sha256:{}", sha256_hex.trim().to_ascii_lowercase())
    }
}

/// Server algorithm advertisement observed during KEXINIT.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKexFacts {
    #[serde(default)]
    pub kex_algorithms: Vec<String>,
    #[serde(default)]
    pub host_key_algorithms: Vec<String>,
    #[serde(default)]
    pub ciphers: Vec<String>,
    #[serde(default)]
    pub macs: Vec<String>,
    #[serde(default)]
    pub compression: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_kex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_host_key: Option<String>,
    /// The exchange signature is NOT verified by this scanner (no
    /// authentication material is ever handled); recorded honestly.
    pub signature_verified: bool,
}

/// Parse an SSH host-key blob (`string alg, <key fields>`) into facts.
/// Supports `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`. Anything else
/// yields `None` (recorded as unparsed, never guessed).
pub fn parse_host_key(blob: &[u8]) -> Option<SshHostKeyFacts> {
    let mut cursor = SshCursor { bytes: blob };
    let alg = cursor.take_string()?;
    let alg_name = std::str::from_utf8(alg).ok()?;
    if alg_name.len() > MAX_ALGORITHM_NAME_LEN {
        return None;
    }
    let (key_type, bits) = match alg_name {
        "ssh-ed25519" => {
            let key = cursor.take_string()?;
            if key.len() != 32 {
                return None;
            }
            ("ssh-ed25519".to_owned(), 256)
        }
        "ecdsa-sha2-nistp256" => {
            let curve = cursor.take_string()?;
            if curve != b"nistp256" {
                return None;
            }
            let point = cursor.take_string()?;
            if point.len() != 65 || point.first() != Some(&0x04) {
                return None;
            }
            ("ecdsa-sha2-nistp256".to_owned(), 256)
        }
        "ssh-rsa" => {
            let e = cursor.take_mpint()?;
            let n = cursor.take_mpint()?;
            if e.is_empty() || n.is_empty() || n.len() > 512 {
                return None;
            }
            let mut bits = n.len() * 8;
            if n.first() == Some(&0) {
                bits = bits.saturating_sub(8);
            }
            ("ssh-rsa".to_owned(), bits)
        }
        _ => return None,
    };
    if !cursor.rest().is_empty() {
        return None;
    }
    let sha256 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(blob);
        hex_bytes(&hasher.finalize())
    };
    Some(SshHostKeyFacts {
        key_type,
        bits,
        entity_id: SshHostKeyFacts::entity_id_for(&sha256),
        sha256,
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

struct SshCursor<'a> {
    bytes: &'a [u8],
}

impl<'a> SshCursor<'a> {
    fn take_u32(&mut self) -> Option<u32> {
        if self.bytes.len() < 4 {
            return None;
        }
        let (head, tail) = self.bytes.split_at(4);
        self.bytes = tail;
        Some(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
    }

    fn take_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.bytes.len() < len {
            return None;
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Some(head)
    }

    fn take_string(&mut self) -> Option<&'a [u8]> {
        let len = self.take_u32()? as usize;
        if len > MAX_SSH_PACKET_BYTES {
            return None;
        }
        self.take_bytes(len)
    }

    fn take_mpint(&mut self) -> Option<&'a [u8]> {
        self.take_string()
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes
    }
}

fn parse_name_list(data: &[u8]) -> Option<(Vec<String>, &[u8])> {
    let mut cursor = SshCursor { bytes: data };
    let raw = cursor.take_string()?;
    let text = std::str::from_utf8(raw).ok()?;
    let mut out = Vec::new();
    for name in text.split(',') {
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_ALGORITHM_NAME_LEN {
            continue;
        }
        if out.len() >= MAX_ALGORITHMS_PER_LIST {
            break;
        }
        out.push(name.to_owned());
    }
    Some((out, cursor.rest()))
}

#[derive(Debug, Clone)]
struct ServerKexInit {
    kex: Vec<String>,
    host_key: Vec<String>,
    ciphers: Vec<String>,
    macs: Vec<String>,
    compression: Vec<String>,
}

fn parse_kexinit(payload: &[u8]) -> Option<ServerKexInit> {
    // MSG_KEXINIT(20) || cookie(16) || 10 name-lists || bool || uint32.
    if payload.first() != Some(&20) || payload.len() < 17 {
        return None;
    }
    let mut rest = &payload[17..];
    let mut lists = Vec::with_capacity(10);
    for _ in 0..10 {
        let (names, tail) = parse_name_list(rest)?;
        lists.push(names);
        rest = tail;
    }
    if rest.len() < 5 {
        return None;
    }
    let mut drain = lists.into_iter();
    Some(ServerKexInit {
        kex: drain.next().unwrap_or_default(),
        host_key: drain.next().unwrap_or_default(),
        ciphers: {
            let c2s = drain.next().unwrap_or_default();
            let s2c = drain.next().unwrap_or_default();
            let mut merged = c2s;
            for name in s2c {
                if !merged.contains(&name) && merged.len() < MAX_ALGORITHMS_PER_LIST {
                    merged.push(name);
                }
            }
            merged
        },
        macs: {
            let c2s = drain.next().unwrap_or_default();
            let s2c = drain.next().unwrap_or_default();
            let mut merged = c2s;
            for name in s2c {
                if !merged.contains(&name) && merged.len() < MAX_ALGORITHMS_PER_LIST {
                    merged.push(name);
                }
            }
            merged
        },
        compression: {
            let c2s = drain.next().unwrap_or_default();
            let s2c = drain.next().unwrap_or_default();
            let mut merged = c2s;
            for name in s2c {
                if !merged.contains(&name) && merged.len() < MAX_ALGORITHMS_PER_LIST {
                    merged.push(name);
                }
            }
            merged
        },
    })
}

fn read_packet(
    stream: &mut TcpStream,
    deadline: Instant,
    cancel: &CancellationToken,
    budget: Duration,
    started: Instant,
) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    read_exact_bounded(stream, &mut len_buf, deadline, cancel, budget, started)?;
    let packet_len = u32::from_be_bytes(len_buf) as usize;
    if !(12..=MAX_SSH_PACKET_BYTES).contains(&packet_len) {
        return Err(format!("ssh: unacceptable packet length {packet_len}"));
    }
    let mut packet = vec![0u8; packet_len];
    read_exact_bounded(stream, &mut packet, deadline, cancel, budget, started)?;
    let padding_len = packet[0] as usize;
    if padding_len >= packet.len() {
        return Err("ssh: bad packet padding".to_owned());
    }
    Ok(packet[1..packet.len() - padding_len].to_vec())
}

fn read_exact_bounded(
    stream: &mut TcpStream,
    mut buf: &mut [u8],
    deadline: Instant,
    cancel: &CancellationToken,
    budget: Duration,
    started: Instant,
) -> Result<(), String> {
    while !buf.is_empty() {
        if cancel.is_cancelled() {
            return Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline || started.elapsed() >= budget {
            return Err("ssh: kex capture budget exhausted".to_owned());
        }
        match stream.read(buf) {
            Ok(0) => return Err("ssh: connection closed during kex".to_owned()),
            Ok(count) => {
                buf = &mut buf[count..];
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(format!("ssh: kex read: {error}")),
        }
    }
    Ok(())
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn send_packet(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    // Minimal padding to an 8-byte boundary (block size unknown pre-kex).
    let mut packet_len = payload.len() + 1;
    let pad = 8 - (packet_len % 8);
    let pad = if pad < 4 { pad + 8 } else { pad };
    packet_len += pad;
    let mut packet = Vec::with_capacity(4 + packet_len);
    packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
    packet.push(pad as u8);
    packet.extend_from_slice(payload);
    packet.extend(std::iter::repeat_n(0u8, pad));
    stream
        .write_all(&packet)
        .map_err(|error| format!("ssh: kex write: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("ssh: kex flush: {error}"))?;
    Ok(())
}

/// Attempt a bounded Curve25519 key exchange on an already-bannered SSH
/// connection to capture the server host key and algorithm lists.
///
/// The caller must have consumed the server identification line already;
/// this function sends the client ident string, KEXINIT, and one ECDH init,
/// then parses the single ECDH reply. Returns `None` when the server does
/// not offer a supported KEX/host-key combination (honest miss, never an
/// error that taints banner classification).
#[allow(clippy::too_many_lines)]
pub fn capture_host_key(
    stream: &mut TcpStream,
    task_deadline: Instant,
    cancel: &CancellationToken,
) -> Option<(SshHostKeyFacts, SshKexFacts)> {
    let started = Instant::now();
    let budget = MAX_KEX_CAPTURE.min(task_deadline.saturating_duration_since(started));
    if budget < Duration::from_millis(200) {
        return None;
    }
    let deadline = started + budget;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    // Client identification string first (protocol order).
    stream.write_all(b"SSH-2.0-rxscan\r\n").ok()?;
    stream.flush().ok()?;
    // Minimal client KEXINIT offering Curve25519 + common host keys.
    let mut payload = vec![20u8];
    payload.extend_from_slice(&[0u8; 16]);
    for list in [
        "curve25519-sha256,curve25519-sha256@libssh.org",
        "ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa",
        "aes128-ctr,aes256-ctr,aes128-gcm@openssh.com",
        "aes128-ctr,aes256-ctr,aes128-gcm@openssh.com",
        "hmac-sha2-256,hmac-sha2-512",
        "hmac-sha2-256,hmac-sha2-512",
        "none",
        "none",
        "",
        "",
    ] {
        put_string(&mut payload, list.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&0u32.to_be_bytes());
    send_packet(stream, &payload).ok()?;
    // Server KEXINIT.
    let server_payload = read_packet(stream, deadline, cancel, budget, started).ok()?;
    let server = parse_kexinit(&server_payload)?;
    // Select Curve25519 (either name form) and a parseable host key.
    let selected_kex = ["curve25519-sha256", "curve25519-sha256@libssh.org"]
        .into_iter()
        .find(|name| server.kex.iter().any(|offered| offered == name))?
        .to_owned();
    let selected_host_key = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
        .into_iter()
        .find(|name| server.host_key.iter().any(|offered| offered == name))?
        .to_owned();
    // Ephemeral X25519 keypair.
    let secret = curve25519_dalek::Scalar::from_bytes_mod_order(rand_bytes());
    let public = (curve25519_dalek::EdwardsPoint::mul_base(&secret)).compress();
    let mut init = vec![30u8];
    put_string(&mut init, public.as_bytes());
    send_packet(stream, &init).ok()?;
    // Single ECDH reply: host key blob + ephemeral key + signature.
    let reply = read_packet(stream, deadline, cancel, budget, started).ok()?;
    if reply.first() != Some(&31) {
        return None;
    }
    let mut cursor = SshCursor { bytes: &reply[1..] };
    let host_key_blob = cursor.take_string()?;
    let facts = parse_host_key(host_key_blob)?;
    if facts.key_type != selected_host_key {
        // Server switched algorithms mid-handshake: do not trust the mix.
        return None;
    }
    let kex = SshKexFacts {
        kex_algorithms: server.kex,
        host_key_algorithms: server.host_key,
        ciphers: server.ciphers,
        macs: server.macs,
        compression: server.compression,
        selected_kex: Some(selected_kex),
        selected_host_key: Some(selected_host_key),
        signature_verified: false,
    };
    Some((facts, kex))
}

fn rand_bytes() -> [u8; 32] {
    // Best-effort ephemeral randomness from available entropy sources.
    // Uniqueness per connection is what matters, not CSPRNG strength of
    // the throwaway scalar (the exchange is unauthenticated either way).
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut seed = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    now.hash(&mut hasher);
    // Stir twice for 64 bits of state; chains are independent per call.
    let first = hasher.finish();
    first.hash(&mut hasher);
    let second = hasher.finish();
    seed[..8].copy_from_slice(&first.to_le_bytes());
    seed[8..16].copy_from_slice(&second.to_le_bytes());
    seed[16..24].copy_from_slice(&(first ^ 0x9E3779B97F4A7C15).to_le_bytes());
    seed[24..32].copy_from_slice(&(second ^ 0xBF58476D1CE4E5B9).to_le_bytes());
    seed
}

/// One SSH host-key observation streamed as an `ssh_host_key` JSONL record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshHostKeyRecord {
    pub endpoint: String,
    pub key: SshHostKeyFacts,
    pub kex: SshKexFacts,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, bytes);
        out
    }

    fn kexinit_payload(kex: &str, host_key: &str) -> Vec<u8> {
        let mut payload = vec![20u8];
        payload.extend_from_slice(&[7u8; 16]);
        for list in [
            kex,
            host_key,
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ] {
            put_string(&mut payload, list.as_bytes());
        }
        payload.push(0);
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload
    }

    #[test]
    fn ident_parsing_extracts_platform_tokens() {
        let parsed = parse_identification("SSH-2.0-OpenSSH_9.8 Ubuntu-1\r\n").unwrap();
        assert_eq!(parsed.protocol_version, "2.0");
        assert_eq!(parsed.product.as_deref(), Some("OpenSSH"));
        assert_eq!(parsed.version.as_deref(), Some("9.8"));
        assert!(
            parsed
                .platform_tokens
                .iter()
                .any(|t| t == "Ubuntu-1" || t == "Ubuntu")
        );
        assert!(parse_identification("HELLO NOT SSH\r\n").is_none());
        assert!(parse_identification("SSH-3.0-foo\r\n").is_none());
        assert!(parse_identification("SSH-2.0-\r\n").is_none());
        // Adversarial input never panics.
        assert!(parse_identification(&"A".repeat(10_000)).is_none());
        assert!(parse_identification("SSH-2.0-\u{1F600}\r\n").is_none());
    }

    #[test]
    fn host_key_parsing_covers_key_types() {
        // ssh-ed25519: alg + 32-byte key.
        let mut blob = ssh_string(b"ssh-ed25519");
        blob.extend(ssh_string(&[9u8; 32]));
        let facts = parse_host_key(&blob).unwrap();
        assert_eq!(facts.key_type, "ssh-ed25519");
        assert_eq!(facts.bits, 256);
        assert_eq!(facts.sha256.len(), 64);
        assert_eq!(
            facts.entity_id,
            SshHostKeyFacts::entity_id_for(&facts.sha256)
        );
        // ssh-rsa: e + n.
        let mut blob = ssh_string(b"ssh-rsa");
        blob.extend(ssh_string(&[0x01, 0x00, 0x01]));
        let mut n = vec![0u8];
        n.extend([0xAAu8; 256]);
        blob.extend(ssh_string(&n));
        let facts = parse_host_key(&blob).unwrap();
        assert_eq!(facts.key_type, "ssh-rsa");
        assert_eq!(facts.bits, 2048);
        // Unknown algorithm / trailing garbage rejected.
        let mut blob = ssh_string(b"ssh-dss");
        blob.extend(ssh_string(b"key"));
        assert!(parse_host_key(&blob).is_none());
        let mut blob = ssh_string(b"ssh-ed25519");
        blob.extend(ssh_string(&[9u8; 32]));
        blob.push(0xFF);
        assert!(parse_host_key(&blob).is_none());
        assert!(parse_host_key(&[]).is_none());
        assert!(parse_host_key(&[0u8; 40_000]).is_none());
    }

    #[test]
    fn kexinit_parsing_is_strict_and_bounded() {
        let payload = kexinit_payload(
            "curve25519-sha256,ecdh-sha2-nistp256",
            "ssh-ed25519,ssh-rsa",
        );
        let parsed = parse_kexinit(&payload).unwrap();
        assert!(parsed.kex.contains(&"curve25519-sha256".to_owned()));
        assert!(parsed.host_key.contains(&"ssh-rsa".to_owned()));
        assert!(parse_kexinit(&[]).is_none());
        assert!(parse_kexinit(&[20u8; 5]).is_none());
        assert!(parse_kexinit(&[99u8; 64]).is_none());
    }

    #[test]
    fn semver_free_version_tokens_stay_honest() {
        let (product, version) = split_software("dropbear_2022.83");
        assert_eq!(product.as_deref(), Some("dropbear"));
        assert_eq!(version.as_deref(), Some("2022.83"));
        let (product, version) = split_software("OpenSSH");
        assert_eq!(product.as_deref(), Some("OpenSSH"));
        assert_eq!(version, None);
    }
}
