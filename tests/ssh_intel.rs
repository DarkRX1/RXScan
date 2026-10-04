//! SSH intelligence: host-key capture, algorithm recording, correlation.
//!
//! A minimal in-test SSH server speaks just enough transport (ident +
//! KEXINIT + ECDH reply with a fixed Ed25519 host key) to prove bounded
//! capture. No authentication ever occurs in either direction.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use clap::Parser;
use rxscan::cli::Cli;
use rxscan::execution::{
    CancellationToken, Module, ModuleContext, ModuleOutput, PolicyScopeGuard, RetryPolicy,
    ScopeGuard, Task, TaskKind, TaskScopeTarget,
};
use rxscan::model::{Provenance, Timestamp};
use rxscan::plan::{ScanPlan, SpeedSetting};
use rxscan::service_probe::{ServicePolicy, ServiceProbeModule};

const TEST_HOST_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn packetize(payload: &[u8]) -> Vec<u8> {
    let mut packet_len = payload.len() + 1;
    let mut pad = 8 - (packet_len % 8);
    if pad < 4 {
        pad += 8;
    }
    packet_len += pad;
    let mut packet = Vec::with_capacity(4 + packet_len);
    packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
    packet.push(pad as u8);
    packet.extend_from_slice(payload);
    packet.extend(std::iter::repeat_n(0u8, pad));
    packet
}

fn server_kexinit() -> Vec<u8> {
    let mut payload = vec![20u8];
    payload.extend_from_slice(&[0xABu8; 16]);
    for list in [
        "curve25519-sha256,ecdh-sha2-nistp256",
        "ssh-ed25519,ssh-rsa",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ] {
        ssh_string(&mut payload, list.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&0u32.to_be_bytes());
    packetize(&payload)
}

fn read_packet(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let packet_len = u32::from_be_bytes(len_buf) as usize;
    if packet_len > 32768 {
        return None;
    }
    let mut packet = vec![0u8; packet_len];
    stream.read_exact(&mut packet).ok()?;
    let pad = packet[0] as usize;
    if pad >= packet.len() {
        return None;
    }
    Some(packet[1..packet.len() - pad].to_vec())
}

struct SshFixture {
    port: u16,
    received: Arc<std::sync::Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
}

impl SshFixture {
    fn spawn(banner: &'static [u8], speak_kex: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let received_thread = received.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(25);
            while !stop_thread.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let received = received_thread.clone();
                std::thread::spawn(move || {
                    let _ = stream.write_all(banner);
                    // Read client ident line.
                    let mut line = Vec::new();
                    let mut byte = [0u8; 1];
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    loop {
                        match stream.read(&mut byte) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                line.push(byte[0]);
                                received.lock().unwrap().push(byte[0]);
                                if byte[0] == b'\n' || line.len() > 255 {
                                    break;
                                }
                            }
                        }
                    }
                    if !speak_kex {
                        return;
                    }
                    // Client KEXINIT packet.
                    let mut stream = stream;
                    let kex = match read_packet(&mut stream) {
                        Some(packet) => packet,
                        None => return,
                    };
                    received.lock().unwrap().extend_from_slice(&kex);
                    let _ = stream.write_all(&server_kexinit());
                    // Client ECDH init.
                    let ecdh = match read_packet(&mut stream) {
                        Some(packet) => packet,
                        None => return,
                    };
                    received.lock().unwrap().extend_from_slice(&ecdh);
                    // ECDH reply with the fixed test host key.
                    let mut host_key_blob = Vec::new();
                    ssh_string(&mut host_key_blob, b"ssh-ed25519");
                    ssh_string(&mut host_key_blob, &TEST_HOST_KEY);
                    let mut reply = vec![31u8];
                    ssh_string(&mut reply, &host_key_blob);
                    ssh_string(&mut reply, &[0x42u8; 32]);
                    let mut sig = Vec::new();
                    ssh_string(&mut sig, b"ssh-ed25519");
                    ssh_string(&mut sig, &[0x99u8; 64]);
                    ssh_string(&mut reply, &sig);
                    let _ = stream.write_all(&packetize(&reply));
                    std::thread::sleep(Duration::from_millis(300));
                });
            }
        });
        Self {
            port,
            received,
            stop,
        }
    }

    fn received_bytes(&self) -> Vec<u8> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for SshFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn plan_for_ports(ports: &str) -> ScanPlan {
    let cli =
        Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", ports, "--level", "4"]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn provenance_for(plan: &ScanPlan) -> Provenance {
    Provenance::new("test.module", "7.0.0", plan.stable_id(), Timestamp(0)).unwrap()
}

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

fn service_task_for(plan: &ScanPlan, port: u16) -> Task {
    let guard = AllowAll;
    let parent = rxscan::tcp_discovery::port_asset_id(
        &rxscan::tcp_discovery::parent_asset_id_for_ip(&"127.0.0.1".parse().unwrap()),
        "tcp",
        port,
    );
    Task::new_with_params(
        TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(10_000),
        RetryPolicy::default(),
        "rxscan.service",
        provenance_for(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("address".to_owned(), "127.0.0.1".to_owned()),
            ("port".to_owned(), port.to_string()),
            ("transport".to_owned(), "tcp".to_owned()),
            ("parent_asset".to_owned(), parent),
            ("probes".to_owned(), "ssh".to_owned()),
        ]),
        &guard,
    )
    .unwrap()
}

fn block_on_service(
    module: &ServiceProbeModule,
    context: ModuleContext,
) -> Result<ModuleOutput, rxscan::execution::ModuleError> {
    use std::task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Waker};
    unsafe fn raw_waker(thread: std::thread::Thread) -> RawWaker {
        unsafe fn clone(data: *const ()) -> RawWaker {
            let thread = unsafe { &*(data as *const std::thread::Thread) };
            unsafe { raw_waker(thread.clone()) }
        }
        unsafe fn wake(data: *const ()) {
            let thread = unsafe { Box::from_raw(data as *mut std::thread::Thread) };
            thread.unpark();
        }
        unsafe fn wake_by_ref(data: *const ()) {
            unsafe { (&*(data as *const std::thread::Thread)).unpark() };
        }
        unsafe fn drop_waker(data: *const ()) {
            drop(unsafe { Box::from_raw(data as *mut std::thread::Thread) });
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
        RawWaker::new(Box::into_raw(Box::new(thread)) as *const (), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(raw_waker(std::thread::current())) };
    let mut task_context = TaskContext::from_waker(&waker);
    let mut future = module.execute(context);
    loop {
        match future.as_mut().poll(&mut task_context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn expected_key_sha256() -> String {
    use sha2::{Digest, Sha256};
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, &TEST_HOST_KEY);
    let mut hasher = Sha256::new();
    hasher.update(&blob);
    let digest = hasher.finalize();
    let mut out = String::new();
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn ssh_host_key_captured_with_algorithms_and_no_auth() {
    let fixture = SshFixture::spawn(b"SSH-2.0-OpenSSH_9.8 TestOS-1\r\n", true);
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(
        ServicePolicy::new(plan.level, plan.goal, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let task = service_task_for(&plan, fixture.port);
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    // Host key captured with the exact test key identity.
    let key_event = output
        .events
        .iter()
        .find(|event| format!("{:?}", event.kind) == "SshHostKeyObserved")
        .expect("host key event");
    let data = &key_event.details.data;
    assert_eq!(data["key_type"], "ssh-ed25519");
    assert_eq!(data["bits"], 256);
    assert_eq!(data["sha256"], expected_key_sha256().as_str());
    assert_eq!(data["signature_verified"], false);
    assert!(
        data["kex_algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name == "curve25519-sha256")
    );
    // Stable global asset + relationship with provenance.
    assert!(
        output
            .assets
            .iter()
            .any(|asset| asset.id.0.starts_with("asset_ssh_host_key_")
                && asset.identity == format!("sshkey:sha256:{}", expected_key_sha256()))
    );
    assert!(
        key_event
            .relationships
            .iter()
            .any(|rel| { format!("{:?}", rel.kind) == "PresentsSshHostKey" })
    );
    // Server saw ident + KEXINIT + ECDH init, and nothing else: no
    // authentication, no channels, no session traffic.
    let received = fixture.received_bytes();
    assert!(received.starts_with(b"SSH-2.0-rxscan\r\n"));
    let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
    for forbidden in [
        "password", "auth", "exec", "shell", "pty", "login", "none\r",
    ] {
        assert!(!text.contains(forbidden), "forbidden bytes: {forbidden}");
    }
}

#[test]
fn ssh_kex_miss_preserves_banner_classification() {
    // Banner-only server: KEX capture fails gracefully, banner still
    // classifies with product/version, no host key recorded.
    let fixture = SshFixture::spawn(b"SSH-2.0-OpenSSH_9.8\r\n", false);
    let plan = plan_for_ports(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::new(
        ServicePolicy::new(plan.level, plan.goal, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let task = service_task_for(&plan, fixture.port);
    let output = block_on_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .unwrap();
    let observation = output
        .evidence
        .iter()
        .find(|evidence| {
            evidence.details.data.get("protocol").is_some() && evidence.source == "rxscan.service"
        })
        .map(|evidence| evidence.details.data.clone())
        .expect("observation");
    assert_eq!(observation["protocol"], "ssh");
    assert_eq!(observation["product_hint"], "OpenSSH");
    assert!(
        !output
            .events
            .iter()
            .any(|event| { format!("{:?}", event.kind) == "SshHostKeyObserved" })
    );
}
