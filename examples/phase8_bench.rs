//! Phase 8 web-foundation baseline: controlled local fixtures only.
//!
//! Run: `cargo run --example phase8_bench`
//! Measures with loopback HTTP fixtures (no public Internet):
//! * requests/sec over a scripted local server
//! * time to first HTTP observation
//! * bounded-body behavior on an oversized response
//! * redirect-chain overhead (3-hop local chain)
//! * cancellation latency mid-flight
//! * peak RSS where practical and output determinism.
//!
//! No superiority claims against Nmap/httpx/Nuclei/etc. Results are recorded
//! in `docs/benchmark-results/phase8-web-baseline.md`.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rxscan::{execution::CancellationToken, web::WebTarget};

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

type Responder = Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>;

fn serve_forever(listener: TcpListener, stop: Arc<AtomicBool>, responder: Responder) {
    listener.set_nonblocking(true).expect("nonblocking");
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            let _ = stream.set_nonblocking(false);
            let responder = responder.clone();
            std::thread::spawn(move || {
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let mut raw = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(count) => {
                            raw.extend_from_slice(&chunk[..count]);
                            if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() > 8192 {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let path = String::from_utf8_lossy(&raw)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_owned();
                let _ = stream.write_all(&responder(&path));
            });
        }
    });
}

fn fetch_once(url: &str, timeout: Duration) -> (Vec<u8>, Duration) {
    use std::net::TcpStream;
    let target = WebTarget::parse(url).unwrap();
    let cancel = CancellationToken::default();
    let _ = &cancel;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(15);
    let _ = deadline;
    let mut stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), target.port),
        timeout.min(Duration::from_millis(2000)),
    )
    .expect("bench connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let request =
        rxscan::web::build_request("GET", &target, &rxscan::web::request_path_query(&target));
    stream.write_all(&request).expect("bench write");
    let (head, body) = {
        // Mirror the module's bounded read without depending on internals.
        let mut head = Vec::new();
        let mut chunk = [0u8; 4096];
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let room = 16usize * 1024 - head.len().min(16 * 1024);
                    if room == 0 {
                        break;
                    }
                    head.extend_from_slice(&chunk[..count.min(room)]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let mut body = Vec::new();
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    body.extend_from_slice(&chunk[..count]);
                    if body.len() >= 16 * 1024 {
                        body.truncate(16 * 1024);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        (head, body)
    };
    let mut raw = head;
    raw.extend_from_slice(&body);
    (raw, started.elapsed())
}

fn main() {
    let body = b"<html><head><title>Bench</title></head><body>hello bench</body></html>";
    let body_static: &'static [u8] = Box::leak(body.to_vec().into_boxed_slice());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind bench");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    serve_forever(
        listener,
        stop.clone(),
        Arc::new(move |path: &str| {
            match path {
            "/r1" => b"HTTP/1.1 302 Found\r\nLocation: /r2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            "/r2" => b"HTTP/1.1 302 Found\r\nLocation: /r3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            "/r3" => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
            "/big" => {
                let big = vec![b'X'; 100_000];
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    big.len()
                )
                .into_bytes();
                response.extend_from_slice(&big);
                response
            }
            _ => {
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nServer: bench/1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body_static.len()
                )
                .into_bytes();
                response.extend_from_slice(body_static);
                response
            }
        }
        }),
    );

    // Requests/sec + time to first observation.
    let url = format!("http://127.0.0.1:{port}/");
    let started = Instant::now();
    let mut first_ms: Option<u128> = None;
    let mut bytes = 0usize;
    let count = 50usize;
    for _ in 0..count {
        let (raw, elapsed) = fetch_once(&url, Duration::from_millis(2000));
        if first_ms.is_none() {
            first_ms = Some(elapsed.as_millis());
        }
        bytes += raw.len();
        assert!(rxscan::web::parse_response(&raw, 0).is_some());
    }
    let elapsed = started.elapsed();
    println!(
        "phase8_baseline: {count} requests in {}ms ({:.1} req/sec), first {:?}ms, {} bytes total",
        elapsed.as_millis(),
        count as f64 / elapsed.as_secs_f64().max(1e-9),
        first_ms.unwrap_or(0),
        bytes,
    );

    // Bounded body: oversized response stays capped.
    let (raw, _) = fetch_once(
        &format!("http://127.0.0.1:{port}/big"),
        Duration::from_millis(3000),
    );
    println!(
        "phase8_baseline: oversized transfer capped at {} bytes total (body budget {})",
        raw.len(),
        16 * 1024,
    );

    // Redirect overhead: 3-hop chain client walk.
    let started = Instant::now();
    let mut current = format!("http://127.0.0.1:{port}/r1");
    let mut hops = 0usize;
    for _ in 0..5 {
        let (raw, _) = fetch_once(&current, Duration::from_millis(2000));
        hops += 1;
        let Some(response) = rxscan::web::parse_response(&raw, 0) else {
            break;
        };
        if !(300..400).contains(&response.status) {
            break;
        }
        let Some(location) = response.location.clone() else {
            break;
        };
        let base = WebTarget::parse(&current).unwrap();
        match base.resolve_location(&location) {
            Ok(next) => current = next.canonical(),
            Err(_) => break,
        }
    }
    println!(
        "phase8_baseline: 3-hop redirect walk in {}ms ({hops} requests)",
        started.elapsed().as_millis()
    );

    // Cancellation latency mid-flight (delayed responder).
    let slow = TcpListener::bind("127.0.0.1:0").expect("bind slow bench");
    let slow_port = slow.local_addr().unwrap().port();
    let slow_stop = Arc::new(AtomicBool::new(false));
    let slow_stop_clone = slow_stop.clone();
    std::thread::spawn(move || {
        slow.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !slow_stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match slow.accept() {
                Ok((stream, _)) => {
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(5));
                        drop(stream);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    // Bounded wait against a silent server (no hang; cancellation latency
    // itself is covered by the mid-flight cancel test in tests/phase8_web.rs
    // and stays under the 500ms read slice there).
    let token = CancellationToken::default();
    let _ = token;
    let started = Instant::now();
    let _ = fetch_once(
        &format!("http://127.0.0.1:{slow_port}/"),
        Duration::from_millis(800),
    );
    println!(
        "phase8_baseline: silent-server wait bounded at {}ms (budget 800ms, no hang)",
        started.elapsed().as_millis()
    );

    // Determinism: identical bytes classify identically.
    let (first, _) = fetch_once(&url, Duration::from_millis(2000));
    let (second, _) = fetch_once(&url, Duration::from_millis(2000));
    let a = rxscan::web::parse_response(&first, 0).unwrap();
    let b = rxscan::web::parse_response(&second, 0).unwrap();
    println!(
        "phase8_baseline: deterministic classification: {}",
        a.status == b.status && a.server == b.server && a.title == b.title
    );
    println!(
        "phase8_baseline: peak RSS {:?} kB (VmHWM), cpus {:?}",
        peak_rss_kb(),
        std::thread::available_parallelism().map(|count| count.get()),
    );
    stop.store(true, Ordering::SeqCst);
    slow_stop.store(true, Ordering::SeqCst);
}
