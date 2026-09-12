# RXScan threat model

RXScan is for authorized, scoped, non-destructive reconnaissance. Its central risks and required controls are:

| Risk | Required control | Phase |
| --- | --- | --- |
| Scope expansion or crawler drift | Scope Guard at proposal, queue, and execution | 1, then enforced by 3 |
| Oversized scope/workload | host/probe estimates, confirmation, budgets (`max_hosts` default 256; Level 5 bounded) | 4–5 |
| Hostile or malformed responses | timeouts, response caps, parser isolation, crash containment; ICMP/TCP parsers validate type/code and never trust payload | 5 onward |
| Queue/retry/memory exhaustion | bounded queues, cancellation, capped retries (ICMP 1–3, TCP 1/port ≤8), backpressure | 3–5 |
| Secrets or memory exhaustion in artifacts | bounded (64 KiB) evidence capture with truncation metadata; redaction policy/classification | 2, 20 |
| Malicious or compromised packs | hashes, compatibility gates, signatures/trust policy | 22 |
| Task-ID collisions merging distinct work | canonical SHA-256 task identity over all execution-relevant fields (kind, module, scope, params, priority, timeout, retry, asset, parent, deps, plan) | 4 |
| Timeout reporting clean while workers leak | timed-out tasks free their slot immediately; orphans bounded by task budget; late results discarded without double-count; modules MUST observe cancellation with bounded I/O timeouts | 4–5 |
| Retry-delay starvation / head-of-line blocking | retry-delayed tasks never block other ready tasks; queue saturation is backpressure (stay `Pending`), not fatal | 4 |
| Unbounded output / disk exhaustion | JSONL writer byte cap (`max_evidence_bytes`); safe filesystem error handling without panics | 4 |
| False-dead misclassification (ICMP blocked ≠ dead) | explicit `Alive`/`Unreachable`/`Unknown` model; ICMP timeout alone yields Unknown with evidence; TCP RST/connect required for Alive-via-TCP | 5 |
| Privilege confusion (raw sockets) | unprivileged ping sockets tried first; permission failures degrade to structured `Unavailable` and TCP fallback; never report Unreachable from missing privileges; TCP scanning is unprivileged connect-only (no raw SYN) | 5–6 |
| Closed/timeout conflation | explicit `Open`/`Closed`/`FilteredOrTimedOut`/`Error` port states; timeouts never reported as closed; retries only for filtered (≤1) | 6 |
| FD/thread exhaustion on huge scans | one task per target with a bounded non-blocking window (16–128, hard 256); no thread per port; FD cleanup + backoff; per-port detail truncated for huge scans | 6 |

Modules never receive authority to bypass policy. Discovery may be recorded without authorizing active work against a new asset.

## Phase 5 executor safety notes

- No arbitrary shell execution; no `ping` subprocess. Native `SOCK_DGRAM` ICMP echo plus `TcpStream::connect_timeout` with helper-thread cancellation so blocking connects cannot hang the scheduler.
- Scope Guard cannot be bypassed (lowering + admission + promotion + dispatch checks; stale scope → `Skipped`; host module re-checks immediately before network execution; CIDR/DNS-derived addresses re-checked and never expand scope; exclusions always win).
- Modules cannot self-schedule (only `DecisionEngine` proposes follow-ups; Phase 5 uses `NoFollowUps`; Phase 6 owns port-scan expansion).
- Minimal `unsafe` for ICMP socket syscalls (`socket`/`sendto`/`recvfrom`/`setsockopt`/`close`, `__errno_location`) with owned-FD cleanup on every path; no other new `unsafe`. The pre-existing hand-rolled `block_on` waker remains a cooperative parking executor; real I/O uses bounded timeouts plus prompt cancellation checks, closing sockets/resources on cancel.
- Bounded queues, retries, evidence, execution time, hosts, and probe sets are centrally enforced and configurable with hard safety ceilings (`max_hosts` 100000, discovery ports ≤8, ICMP attempts ≤3, TCP ports ≤5 at L5).
- ARP / IPv6 Neighbor Discovery are deferred (require raw link-layer access); technique variants exist but execution returns `Unavailable` and never fakes support.

## Phase 6 executor safety notes

- No shell/external scanner dependency; no raw SYN. Native non-blocking TCP connects (`socket`/`connect`/`poll`/`getsockopt`, `fcntl` non-blocking) with owned-FD cleanup on every path and EMFILE/ENFILE/ENOMEM backoff.
- One scheduler task per target (never 65k tasks); bounded internal window (speed 16–128, hard 256 concurrent FDs); per-port timeouts (200–3000ms) plus task-deadline truncation with partial results; ~25ms poll slices for prompt cancel; retries only for filtered (≤1), never for refused/open/cancel.
- Scope Guard cannot be bypassed (lowering/admission/promotion/dispatch/module checks; hostname-derived IPs filtered; follow-up proposals pre-checked and best-effort admitted so duplicates/out-of-scope/budget-exhausted never abort the run).
- Modules never self-schedule (Decision Engine V1 proposes host→port; port tasks never chain further; service/HTTP/SSH handoff deferred to Phase 7).
- Output stays bounded (per-open assets/evidence/findings; per-port detail only for ≤256-port scans; huge scans emit opens + summary; JSONL byte cap; terminal shows opens only).
- Service boundary: open means open; no banner reads, no version claims (enforced by test).
