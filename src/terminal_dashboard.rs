//! Live terminal dashboard for long-running CLI workflows.
//!
//! A pure frame renderer plus a small feed over the existing terminal
//! primitives (`terminal.rs` stays authoritative for styling). The
//! dashboard replaces only the transient TTY progress line on color
//! terminals; pipes, `NO_COLOR`, `--color never`, JSON, and JSONL paths
//! are byte-identical to before (nothing is written unless
//! [`dashboard_visible`] holds).
//!
//! Cancel key: `q` / `Esc` / `Ctrl-C` through an optional Unix raw-mode
//! input watcher ([`spawn_cancel_watcher`], restores termios on drop).
//! Other platforms keep SIGINT through the existing process cancel flag;
//! the dashboard shows the same hint everywhere (documented platform
//! difference, not a silent behavior gap).

use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use crate::terminal::{TerminalCapabilities, paint};

/// Maximum streamed findings kept (ring; oldest drops first).
pub const MAX_FEED_FINDINGS: usize = 8;
/// Minimum milliseconds between frame redraws (bounded stderr traffic).
pub const DRAW_THROTTLE_MS: u64 = 250;

/// One streamed finding for the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedFinding {
    pub status: String,
    pub label: String,
    pub detail: String,
}

/// Point-in-time dashboard data (rendered, never mutated by rendering).
#[derive(Debug, Clone)]
pub struct DashboardSnapshot {
    pub title: String,
    pub completed: usize,
    pub total: usize,
    pub findings: Vec<FeedFinding>,
    pub workers_max: usize,
    pub deadline_total: Option<Duration>,
    pub elapsed: Duration,
    pub cancelled: bool,
    pub done: bool,
    pub note: String,
}

struct FeedInner {
    title: String,
    completed: usize,
    total: usize,
    findings: VecDeque<FeedFinding>,
    workers_max: usize,
    deadline_total: Option<Duration>,
    started: Instant,
    done: bool,
    note: String,
}

/// Thread-safe dashboard feed. The run loop pushes progress and findings;
/// rendering snapshots and draws at most every [`DRAW_THROTTLE_MS`].
pub struct DashboardFeed {
    inner: Mutex<FeedInner>,
    cancelled: Arc<AtomicBool>,
    last_draw: Mutex<Instant>,
}

impl DashboardFeed {
    pub fn new(title: String, workers_max: usize, cancelled: Arc<AtomicBool>) -> Self {
        let now = Instant::now();
        Self {
            inner: Mutex::new(FeedInner {
                title,
                completed: 0,
                total: 0,
                findings: VecDeque::new(),
                workers_max: workers_max.max(1),
                deadline_total: None,
                started: now,
                done: false,
                note: String::new(),
            }),
            cancelled,
            last_draw: Mutex::new(now - Duration::from_secs(3600)),
        }
    }

    /// Shared cancel flag (same atomic the core polls).
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn set_progress(&self, completed: usize, total: usize) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.completed = completed;
            inner.total = total;
        }
    }

    pub fn set_deadline(&self, total: Duration) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.deadline_total = Some(total);
        }
    }

    pub fn set_note(&self, note: String) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.note = note.chars().take(160).collect();
        }
    }

    /// Stream one finding (masked by the caller). Ring-capped.
    pub fn push_finding(&self, status: String, label: String, detail: String) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner.findings.len() >= MAX_FEED_FINDINGS {
                inner.findings.pop_front();
            }
            inner.findings.push_back(FeedFinding {
                status,
                label,
                detail,
            });
        }
    }

    pub fn complete(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.done = true;
        }
    }

    pub fn is_done(&self) -> bool {
        self.inner.lock().is_ok_and(|inner| inner.done)
    }

    pub fn snapshot(&self) -> DashboardSnapshot {
        let inner = self.inner.lock().expect("dashboard feed lock");
        DashboardSnapshot {
            title: inner.title.clone(),
            completed: inner.completed,
            total: inner.total,
            findings: inner.findings.iter().cloned().collect(),
            workers_max: inner.workers_max,
            deadline_total: inner.deadline_total,
            elapsed: inner.started.elapsed(),
            cancelled: self.is_cancelled(),
            done: inner.done,
            note: inner.note.clone(),
        }
    }

    /// True when a redraw is due under the throttle.
    pub fn draw_due(&self) -> bool {
        self.last_draw
            .lock()
            .is_ok_and(|last| last.elapsed().as_millis() >= u128::from(DRAW_THROTTLE_MS))
    }

    pub fn mark_drawn(&self) {
        if let Ok(mut last) = self.last_draw.lock() {
            *last = Instant::now();
        }
    }

    #[cfg(test)]
    fn mark_drawn_for_test(&self) {
        if let Ok(mut last) = self.last_draw.lock() {
            *last = Instant::now() - Duration::from_secs(3600);
        }
    }
}

/// Visible only on color terminals — exactly where the legacy transient
/// progress line printed. Every other path keeps byte-identical output.
pub fn dashboard_visible(caps: &TerminalCapabilities) -> bool {
    caps.tty && caps.color
}

/// One key byte from the watcher. Returns true when consumed as cancel.
pub fn handle_key(feed: &DashboardFeed, byte: u8) -> bool {
    match byte {
        b'q' | b'Q' | 0x1b | 0x03 => {
            feed.cancel();
            true
        }
        _ => false,
    }
}

/// Render one dashboard frame (pure). Honors `caps` color/width/ascii;
/// never emits ANSI unless `caps.color` holds.
pub fn render_frame(snapshot: &DashboardSnapshot, caps: TerminalCapabilities) -> String {
    use crate::terminal::{Style, section_heading, workflow_header};
    let color = caps.color;
    let width = caps.width.clamp(40, 200);
    let mut out = String::new();
    out.push_str(&workflow_header(caps, "SEARCH", None));
    out.push('\n');
    out.push_str(&paint(
        color,
        Style::Muted,
        &truncate(&snapshot.title, width),
    ));
    out.push('\n');
    // Progress bar (text-proportioned; percent always printed as text).
    let total = snapshot.total.max(1);
    let done = snapshot.completed.min(total);
    let percent = done * 100 / total;
    let bar_width = width.min(60).saturating_sub(12).max(8);
    let filled = done * bar_width / total;
    let bar: String = (0..bar_width)
        .map(|i| if i < filled { '#' } else { '-' })
        .collect();
    out.push_str(&format!("progress [{bar}] {done}/{total} ({percent}%)\n",));
    // Workers, elapsed, deadline, budget.
    let mut status = format!(
        "workers ≤ {} (budget) · elapsed {}",
        snapshot.workers_max,
        format_duration(snapshot.elapsed),
    );
    if let Some(deadline) = snapshot.deadline_total {
        let remaining = deadline.saturating_sub(snapshot.elapsed);
        status.push_str(&format!(" · deadline {} left", format_duration(remaining)));
    }
    out.push_str(&paint(color, Style::Muted, &truncate(&status, width)));
    out.push('\n');
    // Streaming findings feed (newest last, ring-capped upstream).
    out.push_str(&section_heading(caps, "Findings feed"));
    out.push('\n');
    if snapshot.findings.is_empty() {
        out.push_str(&paint(color, Style::Muted, "  (no findings yet)"));
        out.push('\n');
    } else {
        for finding in &snapshot.findings {
            let mark = match finding.status.to_ascii_lowercase().as_str() {
                "confirmed" => "+",
                "possible" => "~",
                _ => "·",
            };
            let style = match finding.status.to_ascii_lowercase().as_str() {
                "confirmed" => Style::Success,
                "possible" => Style::Warning,
                _ => Style::Muted,
            };
            let line = format!(
                "  {mark} {} · {} · {}",
                finding.status, finding.label, finding.detail
            );
            out.push_str(&paint(color, style, &truncate(&line, width)));
            out.push('\n');
        }
    }
    if snapshot.cancelled {
        out.push_str(&paint(
            color,
            Style::Warning,
            "CANCELLED — finishing current work…",
        ));
        out.push('\n');
    }
    if !snapshot.note.is_empty() {
        out.push_str(&paint(
            color,
            Style::Muted,
            &truncate(&snapshot.note, width),
        ));
        out.push('\n');
    }
    if !snapshot.done {
        out.push_str(&paint(color, Style::Muted, "press q (or Ctrl-C) to cancel"));
        out.push('\n');
    }
    out
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        format!("{}m {:02}s", (secs as u64) / 60, (secs as u64) % 60)
    }
}

// ---------------------------------------------------------------------------
// Unix cancel-key watcher (raw mode, restores termios on drop).
// ---------------------------------------------------------------------------

/// RAII raw-mode guard for stdin. Construction fails gracefully (non-TTY,
/// closed stdin) — callers fall back to SIGINT-only cancellation.
#[cfg(unix)]
pub struct RawModeGuard {
    fd: std::os::unix::io::RawFd,
    original: libc::termios,
    valid: bool,
}

#[cfg(unix)]
impl RawModeGuard {
    pub fn stdin() -> Result<Self, String> {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        // SAFETY: isatty takes a bare fd, no pointers.
        let is_tty = unsafe { libc::isatty(fd) == 1 };
        if !is_tty {
            return Err("stdin is not a TTY".to_owned());
        }
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr writes only `original` on success.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err("tcgetattr failed".to_owned());
        }
        let mut raw = original;
        // cfmakeraw equivalent without pulling extra symbols.
        raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
        raw.c_oflag &= !libc::OPOST;
        raw.c_cflag |= libc::CS8;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: raw is a valid termios derived from the live settings.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err("tcsetattr failed".to_owned());
        }
        Ok(Self {
            fd,
            original,
            valid: true,
        })
    }
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.valid {
            // SAFETY: restoring settings captured from this fd; result
            // ignored during teardown by design.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
}

/// Spawn the cancel-key watcher: polls stdin (100 ms) for `q`/`Esc`/
/// `Ctrl-C` until the feed completes or cancels. Returns `None` when
/// stdin is not a usable TTY (SIGINT path still works).
/// Cancellation takes effect at the next scheduler wave boundary (the
/// progress hook propagates the feed flag to the core cancel flag),
/// matching SIGINT's granularity for in-flight providers.
#[cfg(unix)]
pub fn spawn_cancel_watcher(feed: Arc<DashboardFeed>) -> Option<std::thread::JoinHandle<()>> {
    use std::os::unix::io::AsRawFd;
    let guard = RawModeGuard::stdin().ok()?;
    // Move the guard into the thread so raw mode lasts exactly as long.
    Some(std::thread::spawn(move || {
        let _guard = guard;
        let fd = std::io::stdin().as_raw_fd();
        let mut byte = [0u8; 1];
        loop {
            if feed.is_done() || feed.is_cancelled() {
                break;
            }
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll takes a valid single-element array and timeout.
            let ready = unsafe { libc::poll(&mut poll_fd, 1, 100) };
            if ready > 0 && poll_fd.revents & libc::POLLIN != 0 {
                // SAFETY: reading one byte into a one-byte buffer.
                let read = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
                if read == 1 {
                    if matches!(byte[0], b'q' | b'Q' | 0x1b | 0x03) {
                        feed.cancel();
                        break;
                    }
                } else if read == 0 {
                    break; // EOF: nothing more to watch.
                }
            }
        }
    }))
}

#[cfg(not(unix))]
pub fn spawn_cancel_watcher(_feed: Arc<DashboardFeed>) -> Option<std::thread::JoinHandle<()>> {
    // No console raw mode here: SIGINT via the process flag still cancels.
    None
}

// ---------------------------------------------------------------------------
// Search workflow session: thin, writer-injected glue the CLI uses.
// All logic lives here so tests drive it without a TTY or the network.
// ---------------------------------------------------------------------------

/// Live dashboard session for one username search. Draws the initial
/// frame on [`SearchDashboardSession::begin`], redraws (throttled) on
/// [`SearchDashboardSession::on_wave`], streams findings via
/// [`SearchDashboardSession::on_observation`], and closes the frame on
/// [`SearchDashboardSession::finish`]. Writes nothing unless the caps
/// are TTY+color ([`dashboard_visible`]).
pub struct SearchDashboardSession {
    feed: Arc<DashboardFeed>,
    caps: TerminalCapabilities,
}

impl SearchDashboardSession {
    pub fn begin(
        title: String,
        workers_max: usize,
        deadline: Duration,
        caps: TerminalCapabilities,
        cancelled: Arc<AtomicBool>,
    ) -> Option<Arc<Self>> {
        if !dashboard_visible(&caps) {
            return None;
        }
        let feed = DashboardFeed::new(title, workers_max, cancelled);
        feed.set_deadline(deadline);
        let session = Arc::new(Self {
            feed: Arc::new(feed),
            caps,
        });
        session.draw_initial(&mut std::io::stderr());
        Some(session)
    }

    /// Test seam: begin with an explicit writer instead of stderr.
    pub fn begin_to(
        title: String,
        workers_max: usize,
        deadline: Duration,
        caps: TerminalCapabilities,
        cancelled: Arc<AtomicBool>,
        writer: &mut dyn std::io::Write,
    ) -> Option<Arc<Self>> {
        if !dashboard_visible(&caps) {
            return None;
        }
        let feed = DashboardFeed::new(title, workers_max, cancelled);
        feed.set_deadline(deadline);
        let session = Arc::new(Self {
            feed: Arc::new(feed),
            caps,
        });
        session.draw_initial(writer);
        Some(session)
    }

    fn draw_initial(&self, writer: &mut dyn std::io::Write) {
        let frame = render_frame(&self.feed.snapshot(), self.caps);
        let _ = write!(writer, "\x1b[H\x1b[J{frame}");
        let _ = writer.flush();
        self.feed.mark_drawn();
    }

    pub fn feed(&self) -> &Arc<DashboardFeed> {
        &self.feed
    }

    pub fn on_wave(&self, completed: usize, total: usize, writer: &mut dyn std::io::Write) {
        if self.feed.is_cancelled() {
            return;
        }
        self.feed.set_progress(completed, total);
        if self.feed.draw_due() {
            let frame = render_frame(&self.feed.snapshot(), self.caps);
            let _ = write!(writer, "\x1b[H\x1b[J{frame}");
            let _ = writer.flush();
            self.feed.mark_drawn();
        }
    }

    pub fn on_observation(&self, status: String, label: String, detail: String) {
        self.feed.push_finding(status, label, detail);
    }

    pub fn finish(&self, writer: &mut dyn std::io::Write) {
        self.feed.complete();
        let _ = writeln!(writer);
        let _ = writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(color: bool, tty: bool) -> TerminalCapabilities {
        TerminalCapabilities {
            color,
            ascii: false,
            width: 100,
            tty,
        }
    }

    fn snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            title: "exampleuser".to_owned(),
            completed: 12,
            total: 48,
            findings: vec![
                FeedFinding {
                    status: "confirmed".to_owned(),
                    label: "example-provider".to_owned(),
                    detail: "conf 90".to_owned(),
                },
                FeedFinding {
                    status: "possible".to_owned(),
                    label: "other-provider".to_owned(),
                    detail: "conf 50".to_owned(),
                },
            ],
            workers_max: 8,
            deadline_total: Some(Duration::from_secs(25)),
            elapsed: Duration::from_millis(3200),
            cancelled: false,
            done: false,
            note: String::new(),
        }
    }

    #[test]
    fn frame_shows_progress_budget_deadline_and_feed() {
        let text = render_frame(&snapshot(), caps(true, true));
        assert!(text.contains("12/48"));
        assert!(text.contains("25%"));
        assert!(text.contains("workers"));
        assert!(text.contains("deadline"));
        assert!(text.contains("example-provider"));
        assert!(text.contains("press q"));
        assert!(text.contains('\x1b'), "color caps must style");
    }

    #[test]
    fn frame_without_color_has_no_ansi() {
        let text = render_frame(&snapshot(), caps(false, true));
        assert!(!text.contains('\x1b'), "plain caps must not style");
        assert!(text.contains("12/48"));
        assert!(text.contains("example-provider"));
    }

    #[test]
    fn cancelled_and_done_states_render() {
        let mut snap = snapshot();
        snap.cancelled = true;
        assert!(render_frame(&snap, caps(false, true)).contains("CANCELLED"));
        snap.cancelled = false;
        snap.done = true;
        assert!(!render_frame(&snap, caps(false, true)).contains("press q"));
    }

    #[test]
    fn feed_ring_caps_findings() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let feed = DashboardFeed::new("t".to_owned(), 4, cancelled);
        for i in 0..20 {
            feed.push_finding("possible".to_owned(), format!("p{i}"), "d".to_owned());
        }
        let snap = feed.snapshot();
        assert_eq!(snap.findings.len(), MAX_FEED_FINDINGS);
        assert_eq!(snap.findings.last().unwrap().label, "p19");
        feed.set_progress(3, 10);
        assert_eq!(feed.snapshot().completed, 3);
        feed.complete();
        assert!(feed.is_done());
    }

    #[test]
    fn keys_cancel_selectively() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let feed = DashboardFeed::new("t".to_owned(), 4, cancelled);
        assert!(!handle_key(&feed, b'a'));
        assert!(!feed.is_cancelled());
        assert!(handle_key(&feed, b'q'));
        assert!(feed.is_cancelled());
    }

    #[test]
    fn visibility_is_tty_and_color_only() {
        assert!(dashboard_visible(&caps(true, true)));
        assert!(!dashboard_visible(&caps(false, true)));
        assert!(!dashboard_visible(&caps(true, false)));
        assert!(!dashboard_visible(&caps(false, false)));
    }

    #[test]
    #[cfg(unix)]
    fn raw_guard_fails_gracefully_without_tty() {
        // Test stdin is not a TTY (or tcsetattr fails): must Err, never
        // panic, and Drop of a non-guard never runs raw syscalls.
        let _ = RawModeGuard::stdin().err().map(|detail| {
            assert!(!detail.is_empty());
        });
    }

    #[test]
    fn session_streams_waves_and_findings_to_writer() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut out = Vec::new();
        let session = SearchDashboardSession::begin_to(
            "exampleuser".to_owned(),
            8,
            Duration::from_secs(25),
            caps(true, true),
            Arc::clone(&cancelled),
            &mut out,
        )
        .expect("visible caps start a session");
        // Waves update progress; findings stream into the feed.
        session.on_observation(
            "confirmed".to_owned(),
            "demo-provider".to_owned(),
            "conf 90".to_owned(),
        );
        // Force redraws past the throttle for determinism.
        session.feed().mark_drawn_for_test();
        session.on_wave(24, 48, &mut out);
        session.feed().mark_drawn_for_test();
        session.on_wave(48, 48, &mut out);
        session.finish(&mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("progress"), "frames must render progress");
        assert!(text.contains("24/48"));
        assert!(text.contains("demo-provider"), "feed must stream findings");
        assert!(
            text.contains("deadline"),
            "frames must show deadline status"
        );
        assert!(text.contains("workers"), "frames must show worker budget");
    }

    #[test]
    fn session_writes_nothing_when_invisible() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut out = Vec::new();
        let session = SearchDashboardSession::begin_to(
            "exampleuser".to_owned(),
            8,
            Duration::from_secs(25),
            caps(false, false),
            Arc::clone(&cancelled),
            &mut out,
        );
        assert!(session.is_none(), "piped caps must not start a session");
        assert!(out.is_empty());
    }
}
