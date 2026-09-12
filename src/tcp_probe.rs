//! Bounded TCP reachability probing (host liveness only, NOT port scanning).
//!
//! A small configurable set of ports (level-derived, default ≤5) is probed
//! with `TcpStream::connect_timeout`. Any TCP response — connect success or
//! RST/refused — is credible `Alive` evidence even when ICMP is blocked.
//! Timeouts are `Unknown`, host/net-unreachable errors are `Unreachable`.
//!
//! Every probe honors timeout, cancellation (prompt, via a bounded helper
//! thread so a blocking connect cannot hang the scheduler), a single attempt
//! per port (outer scheduler retries provide the retry bound), concurrency
//! via the scheduler (probes run sequentially within a host), budget
//! accounting (caller caps ports ≤8), and resource cleanup (sockets dropped,
//! helper threads bounded by the per-probe timeout).

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::discovery::{DiscoveryTechnique, ProbeOutcome, ProbeRecord};
use crate::execution::CancellationToken;

/// Trait for TCP reachability (real + fake/mock backends for tests).
pub trait TcpProber: Send + Sync {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> ProbeOutcome;
}

/// Native prober using `TcpStream::connect_timeout` with prompt cancellation.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeTcpProber;

impl NativeTcpProber {
    fn connect_once(ip: IpAddr, port: u16, timeout: Duration) -> Result<Duration, std::io::Error> {
        let address = SocketAddr::new(ip, port);
        let started = Instant::now();
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        let latency = started.elapsed();
        drop(stream);
        Ok(latency)
    }
}

impl TcpProber for NativeTcpProber {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> ProbeOutcome {
        if cancel.is_cancelled() {
            return ProbeOutcome::Cancelled;
        }
        if port == 0 {
            return ProbeOutcome::Unavailable {
                reason: "invalid TCP probe port 0".to_owned(),
            };
        }
        let timeout = timeout.clamp(Duration::from_millis(100), Duration::from_secs(10));
        // Run the blocking connect on a helper thread so cancellation is
        // prompt: the main thread polls cancel every 10ms while the helper
        // remains bounded by `timeout`. No hanging sockets, no leaked
        // workers beyond the per-probe timeout.
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = Self::connect_once(ip, port, timeout);
            let _ = sender.send(result);
        });
        let started = Instant::now();
        loop {
            if cancel.is_cancelled() {
                return ProbeOutcome::Cancelled;
            }
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(Ok(latency)) => {
                    return ProbeOutcome::Success {
                        latency,
                        detail: format!(
                            "TCP connect to {}:{} succeeded in {}ms; host is reachable",
                            ip,
                            port,
                            latency.as_millis()
                        ),
                    };
                }
                Ok(Err(error)) => {
                    return map_connect_error(ip, port, error);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if started.elapsed() >= timeout + Duration::from_millis(50) {
                        return ProbeOutcome::Timeout;
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return ProbeOutcome::Unavailable {
                        reason: "TCP probe worker exited unexpectedly".to_owned(),
                    };
                }
            }
        }
    }
}

fn map_connect_error(ip: IpAddr, port: u16, error: std::io::Error) -> ProbeOutcome {
    match error.kind() {
        ErrorKind::ConnectionRefused => ProbeOutcome::Success {
            latency: Duration::from_millis(0),
            detail: format!(
                "TCP connection refused (RST) on {}:{}; host responded so it is reachable (port closed)",
                ip, port
            ),
        },
        ErrorKind::ConnectionReset => ProbeOutcome::Success {
            latency: Duration::from_millis(0),
            detail: format!(
                "TCP connection reset (RST) on {}:{}; host responded so it is reachable",
                ip, port
            ),
        },
        ErrorKind::TimedOut => ProbeOutcome::Timeout,
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => ProbeOutcome::Unreachable {
            detail: format!("{}:{} unreachable ({})", ip, port, error),
        },
        // `NoRouteToHost` is unstable as ErrorKind on some toolchains; match
        // the message for "no route" / "unreachable" conservatively.
        _ => {
            let message = error.to_string().to_ascii_lowercase();
            if message.contains("no route to host")
                || message.contains("network is unreachable")
                || message.contains("host is unreachable")
            {
                ProbeOutcome::Unreachable {
                    detail: format!("{}:{} unreachable ({})", ip, port, error),
                }
            } else if message.contains("timed out") || message.contains("timeout") {
                ProbeOutcome::Timeout
            } else {
                // Conservative: unknown errors are Unknown-via-Timeout shape
                // at the record layer (caller correlates). Preserve detail.
                ProbeOutcome::Timeout
            }
        }
    }
}

/// Probe each port once, sequentially, stopping early on `Alive` success or
/// cancellation. Single attempt per port keeps retries bounded; the
/// scheduler's outer retry policy provides the retry bound.
pub fn tcp_probe_ports(
    prober: &dyn TcpProber,
    ip: IpAddr,
    ports: &[u16],
    timeout: Duration,
    cancel: &CancellationToken,
    deadline: Option<Instant>,
) -> Vec<ProbeRecord> {
    let mut records = Vec::new();
    for port in ports.iter().take(8) {
        if cancel.is_cancelled() {
            records.push(ProbeRecord {
                technique: DiscoveryTechnique::TcpConnect,
                target: ip,
                port: Some(*port),
                outcome: ProbeOutcome::Cancelled,
                latency: None,
            });
            break;
        }
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining < Duration::from_millis(50) {
                break;
            }
        }
        let outcome = prober.probe(ip, *port, timeout, cancel);
        let latency = match &outcome {
            ProbeOutcome::Success { latency, .. } => Some(*latency),
            _ => None,
        };
        let is_success = matches!(outcome, ProbeOutcome::Success { .. });
        let is_cancelled = matches!(outcome, ProbeOutcome::Cancelled);
        records.push(ProbeRecord {
            technique: DiscoveryTechnique::TcpConnect,
            target: ip,
            port: Some(*port),
            outcome,
            latency,
        });
        if is_success || is_cancelled {
            break;
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_maps_to_alive_not_dead() {
        let error = std::io::Error::new(ErrorKind::ConnectionRefused, "refused");
        let outcome = map_connect_error("127.0.0.1".parse().unwrap(), 9, error);
        assert!(matches!(outcome, ProbeOutcome::Success { .. }));
    }

    #[test]
    fn timeout_maps_to_timeout() {
        let error = std::io::Error::new(ErrorKind::TimedOut, "timed out");
        let outcome = map_connect_error("127.0.0.1".parse().unwrap(), 80, error);
        assert!(matches!(outcome, ProbeOutcome::Timeout));
    }
}
