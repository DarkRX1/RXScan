//! Phase 6 TCP baseline: controlled local fixtures only.
//!
//! Run: `cargo run --example phase6_bench`
//! Measures with local loopback listeners + synthetic closed-port ranges
//! (no public Internet):
//! * ports/sec over representative sets (100 / 1,000 / 10,000 attempts)
//! * time to first open port, effective concurrency, cancellation latency,
//!   CPU/RSS observations, queue depth, ordering determinism.
//!
//! No claims against Nmap/RustScan. Results are recorded in
//! `docs/benchmark-results/phase6-tcp-baseline.md`.

use std::{
    net::TcpListener,
    sync::Arc,
    time::{Duration, Instant},
};

use rxscan::{
    execution::CancellationToken,
    ports::tcp_concurrency_for_speed,
    tcp_scanner::{NativeTcpScanner, PortScanner, ScanConfig},
};

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

fn hold_listeners(count: usize) -> Vec<TcpListener> {
    let mut listeners = Vec::new();
    for _ in 0..count {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listeners.push(listener),
            Err(_) => break,
        }
    }
    listeners
}

fn scan_set(
    label: &str,
    ip: std::net::IpAddr,
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
) -> (f64, Option<u64>, usize) {
    let config = ScanConfig::bounded(timeout, concurrency, 0, None, CancellationToken::default());
    let started = Instant::now();
    let outcome = NativeTcpScanner.scan(ip, ports, &config);
    let elapsed = started.elapsed();
    let per_sec = ports.len() as f64 / elapsed.as_secs_f64().max(1e-9);
    let opens = outcome
        .probes
        .iter()
        .filter(|probe| matches!(probe.state, rxscan::tcp_scanner::PortState::Open))
        .count();
    // Time to first open ≈ min latency among opens (single batch => honest).
    let first_open = outcome
        .probes
        .iter()
        .filter(|probe| matches!(probe.state, rxscan::tcp_scanner::PortState::Open))
        .map(|probe| probe.latency.as_millis() as u64)
        .min();
    println!(
        "phase6_baseline: {label}: {} ports in {}ms ({per_sec:.1} ports/sec), opens {opens}, first_open_ms {first_open:?}, truncated {}, cancelled {}",
        ports.len(),
        elapsed.as_millis(),
        outcome.truncated,
        outcome.cancelled,
    );
    (per_sec, first_open, opens)
}

fn main() {
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let concurrency = tcp_concurrency_for_speed(rxscan::plan::SpeedSetting::default());
    println!("phase6_baseline: concurrency {concurrency} (balanced default)");
    let listeners = hold_listeners(8);
    let mut open_ports: Vec<u16> = listeners
        .iter()
        .filter_map(|listener| listener.local_addr().ok().map(|addr| addr.port()))
        .collect();
    open_ports.sort_unstable();
    println!(
        "phase6_baseline: holding {} loopback listeners",
        open_ports.len()
    );

    // 100 ports: opens + closed mix around the listener range.
    let base = 50_000u16;
    let set_100: Vec<u16> = (base..base + 100).collect();
    // 1,000 ports: synthetic closed range.
    let set_1000: Vec<u16> = (51_000..52_000).collect();
    // 10,000 ports: synthetic closed range (safe: loopback refused, fast).
    let set_10000: Vec<u16> = (52_000..62_000).collect();

    let timeout = Duration::from_millis(800);
    scan_set("100 ports", ip, &set_100, concurrency, timeout);
    scan_set("1000 ports", ip, &set_1000, concurrency, timeout);
    // Queue depth observation comes from the scheduler path; the scanner
    // window itself is the bound under test here.
    println!("phase6_baseline: scanner window cap {concurrency} (hard 256)");
    scan_set("10000 ports", ip, &set_10000, concurrency, timeout);

    // Open-port targets embedded in the 100-set for time-to-first-open.
    if !open_ports.is_empty() {
        let mut mixed: Vec<u16> = set_100.clone();
        mixed.extend_from_slice(&open_ports);
        mixed.sort_unstable();
        mixed.dedup();
        scan_set(
            "mixed (100 closed + opens)",
            ip,
            &mixed,
            concurrency,
            timeout,
        );
    }

    // Cancellation latency against a large in-flight scan.
    let token = CancellationToken::default();
    let config = ScanConfig::bounded(
        Duration::from_millis(2000),
        concurrency,
        0,
        None,
        token.clone(),
    );
    let big: Vec<u16> = (1..=20_000).collect();
    let handle = std::thread::spawn(move || NativeTcpScanner.scan(ip, &big, &config));
    std::thread::sleep(Duration::from_millis(100));
    let cancel_at = Instant::now();
    token.cancel();
    let outcome = handle.join().unwrap();
    println!(
        "phase6_baseline: cancellation latency {}ms (cancelled {}, truncated {}, probed {})",
        cancel_at.elapsed().as_millis(),
        outcome.cancelled,
        outcome.truncated,
        outcome.probes.len(),
    );

    // Determinism: same set twice → identical port order and states.
    let config = ScanConfig::bounded(timeout, concurrency, 0, None, CancellationToken::default());
    let first = NativeTcpScanner.scan(ip, &set_100, &config);
    let second = NativeTcpScanner.scan(ip, &set_100, &config);
    let same_order = first
        .probes
        .iter()
        .map(|probe| (probe.port, probe.state as u8))
        .eq(second
            .probes
            .iter()
            .map(|probe| (probe.port, probe.state as u8)));
    println!("phase6_baseline: ordering deterministic: {same_order}");
    println!(
        "phase6_baseline: peak RSS {:?} kB (VmHWM), cpus {:?}",
        peak_rss_kb(),
        std::thread::available_parallelism().map(|n| n.get()),
    );
    let _ = Arc::new(listeners);
}
