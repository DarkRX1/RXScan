//! Phase 7 service-intelligence baseline: controlled local fixtures only.
//!
//! Run: `cargo run --example phase7_bench`
//! Measures with loopback fake-protocol servers (no public Internet):
//! * service identifications/sec over SSH/HTTP/generic fixtures
//! * time to first identified service
//! * bytes sent/received per identification
//! * timeout performance against a silent fixture
//! * effective scheduler concurrency, cancellation latency, CPU/RSS,
//!   ordering determinism.
//!
//! No competitor claims. Results are recorded in
//! `docs/benchmark-results/phase7-service-baseline.md`.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rxscan::{execution::CancellationToken, probes::ProbeCtx, service::plan_probes};

fn peak_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:").map(|rest| {
                rest.split_whitespace()
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0)
            })
        })
}

struct BenchFixture {
    port: u16,
    stop: Arc<AtomicBool>,
}

fn spawn_banner(banner: &'static [u8]) -> BenchFixture {
    spawn_responder(move |mut stream| {
        let _ = stream.write_all(banner);
        std::thread::sleep(Duration::from_millis(300));
    })
}

fn spawn_responder(responder: impl Fn(TcpStream) + Send + Sync + 'static) -> BenchFixture {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind bench fixture");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let responder = Arc::new(responder);
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let responder = responder.clone();
                    std::thread::spawn(move || responder(stream));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });
    BenchFixture { port, stop }
}

fn main() {
    let ssh = spawn_banner(b"SSH-2.0-OpenSSH_9.8 bench\r\n");
    let http = spawn_responder(|mut stream| {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let body = b"<html><head><title>Bench</title></head></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nServer: bench/1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
    });
    let generic = spawn_banner(b"BENCH-UNKNOWN v3 ready\r\n");
    let silent = spawn_responder(|stream| {
        std::thread::sleep(Duration::from_secs(4));
        drop(stream);
    });

    let cancel = CancellationToken::default();
    let run_probe = |port: u16, probe: &str| {
        let deadline = Instant::now() + Duration::from_secs(10);
        let ctx = ProbeCtx {
            ip: "127.0.0.1".parse().unwrap(),
            port,
            host_label: "127.0.0.1",
            timeout: Duration::from_millis(2000),
            deadline,
            cancel: &cancel,
        };
        let started = Instant::now();
        let attempt = match probe {
            "ssh" => rxscan::probes::probe_ssh(&ctx),
            "http" => rxscan::probes::probe_http(&ctx),
            _ => rxscan::probes::probe_generic(&ctx),
        };
        (attempt, started.elapsed())
    };

    // Throughput: 30 identifications across three fixtures.
    let started = Instant::now();
    let mut bytes_in = 0usize;
    let mut bytes_out = 0usize;
    let mut first_ms: Option<u128> = None;
    for index in 0..30 {
        let (port, probe) = match index % 3 {
            0 => (ssh.port, "ssh"),
            1 => (http.port, "http"),
            _ => (generic.port, "generic"),
        };
        let (attempt, elapsed) = run_probe(port, probe);
        assert!(
            attempt.classified() || probe == "generic",
            "bench fixture misclassified"
        );
        if first_ms.is_none() {
            first_ms = Some(elapsed.as_millis());
        }
        bytes_in += attempt.bytes_in;
        bytes_out += attempt.bytes_out;
    }
    let elapsed = started.elapsed();
    let per_sec = 30.0 / elapsed.as_secs_f64();
    println!(
        "phase7_baseline: 30 identifications in {}ms ({per_sec:.1}/sec), first {:?}ms",
        elapsed.as_millis(),
        first_ms.unwrap_or(0),
    );
    println!("phase7_baseline: bytes in {bytes_in}, out {bytes_out} (bounded requests/responses)");

    // Timeout performance against the silent fixture.
    let started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(10);
    let ctx = ProbeCtx {
        ip: "127.0.0.1".parse().unwrap(),
        port: silent.port,
        host_label: "127.0.0.1",
        timeout: Duration::from_millis(800),
        deadline,
        cancel: &cancel,
    };
    let attempt = rxscan::probes::probe_generic(&ctx);
    println!(
        "phase7_baseline: silent timeout in {}ms (classified {}, evidence {:?})",
        started.elapsed().as_millis(),
        attempt.classified(),
        attempt.evidence.first().unwrap_or(&String::new()),
    );

    // Cancellation latency mid-probe.
    let token = CancellationToken::default();
    let deadline = Instant::now() + Duration::from_secs(10);
    let config_token = token.clone();
    let handle = std::thread::spawn(move || {
        let ctx = ProbeCtx {
            ip: "127.0.0.1".parse().unwrap(),
            port: silent.port,
            host_label: "127.0.0.1",
            timeout: Duration::from_secs(8),
            deadline,
            cancel: &config_token,
        };
        rxscan::probes::probe_generic(&ctx)
    });
    std::thread::sleep(Duration::from_millis(150));
    let cancel_at = Instant::now();
    token.cancel();
    let _ = handle.join().unwrap();
    println!(
        "phase7_baseline: cancellation latency {}ms",
        cancel_at.elapsed().as_millis()
    );

    // Planner determinism + scheduler concurrency note.
    let first = plan_probes(443, 4, rxscan::plan::ScanGoal::Recon);
    let second = plan_probes(443, 4, rxscan::plan::ScanGoal::Recon);
    println!(
        "phase7_baseline: planner deterministic: {}",
        first == second
    );
    println!(
        "phase7_baseline: service tasks run at scheduler concurrency (module sequential per port); peak RSS {:?} kB (VmHWM), cpus {:?}",
        peak_rss_kb(),
        std::thread::available_parallelism().map(|count| count.get()),
    );
    for fixture in [&ssh, &http, &generic, &silent] {
        fixture.stop.store(true, Ordering::SeqCst);
    }
}
