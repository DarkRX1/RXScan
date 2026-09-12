# Phase 5 host-discovery baseline

- Date: 2026-09-12
- RXScan version: 0.1.0 (Phase 5 host discovery)
- Fixture class: controlled local only — `127.0.0.0/29` CIDR lowering plus 50
  simulated loopback hosts via deterministic fake ICMP/TCP backends; one real
  loopback check (`127.0.0.1` / `::1`) covered separately in tests. No public
  Internet traffic.
- Command: `cargo run --example phase5_bench`
- Host: Linux DarkRX 7.0.12 x86_64, rustc 1.98.1
- Scope: `127.0.0.0/29`, level 3, discover mode, balanced speed

## Results (controlled local, no superiority claims)

- CIDR lowering: `127.0.0.0/29` yields 6 host tasks (usable `.1`–`.6` in
  deterministic order); large ranges stay bounded by `max_hosts` (default 256).
- Scheduler throughput: ~64 hosts/s (50 simulated hosts in ~777ms, effective
  concurrency cap 1 under balanced speed with `max_concurrency` 4; per-host
  probes sequential: 2x fake ICMP + 1x fake TCP RST).
- Correctness: 50 completed, 0 failed/cancelled/timed-out/skipped (fake RST =
  Alive). Real loopback (`127.0.0.1`, `::1`) reports Alive via ICMP echo or
  TCP RST with confidence 85–95; timeout-only hosts report Unknown (never
  false Dead).
- Bounded concurrency: effective cap 1 observed max 1 (within cap; faster
  speeds raise the cap up to `max_concurrency`, never unlimited).
- Queue: capacity 64 (derived `max(max_concurrency*16, max_concurrency+4)`);
  saturation remains backpressure (stay `Pending`), not fatal.
- Cancellation latency: 0ms for pre-cancelled discovery task (bound <500ms
  asserted in tests).
- Timeout behavior: 150ms task timeout with 800ms slow fake frees the slot
  promptly (`TimedOut`, no double-count, orphan bounded) — see
  `timeout_is_bounded_and_frees_scheduler_slot`.
- Task determinism: same CIDR plan lowers deterministically
  (`lowering deterministic: true`); duplicate seeds do not multiply tasks.
- Peak RSS (VmHWM): ~7928 kB during 50-host run.

## Notes

- This is a discovery-correctness/regression baseline, not a network-performance claim.
- No Internet or external fixture-server traffic occurred.
- Real ICMP uses unprivileged `SOCK_DGRAM` ping sockets (no shell `ping`);
  permission failures return structured `Unavailable` and fall back to TCP.
  ARP / IPv6 Neighbor Discovery are deferred and never faked.
- Future phases must re-baseline with controlled fixtures per `docs/BENCHMARK_PLAN.md`.
