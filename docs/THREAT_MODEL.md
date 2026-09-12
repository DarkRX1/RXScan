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
| Privilege confusion (raw sockets) | unprivileged ping sockets tried first; permission failures degrade to structured `Unavailable` and TCP fallback; never report Unreachable from missing privileges | 5 |

Modules never receive authority to bypass policy. Discovery may be recorded without authorizing active work against a new asset.

## Phase 5 executor safety notes

- No arbitrary shell execution; no `ping` subprocess. Native `SOCK_DGRAM` ICMP echo plus `TcpStream::connect_timeout` with helper-thread cancellation so blocking connects cannot hang the scheduler.
- Scope Guard cannot be bypassed (lowering + admission + promotion + dispatch checks; stale scope → `Skipped`; host module re-checks immediately before network execution; CIDR/DNS-derived addresses re-checked and never expand scope; exclusions always win).
- Modules cannot self-schedule (only `DecisionEngine` proposes follow-ups; Phase 5 uses `NoFollowUps`; Phase 6 owns port-scan expansion).
- Minimal `unsafe` for ICMP socket syscalls (`socket`/`sendto`/`recvfrom`/`setsockopt`/`close`, `__errno_location`) with owned-FD cleanup on every path; no other new `unsafe`. The pre-existing hand-rolled `block_on` waker remains a cooperative parking executor; real I/O uses bounded timeouts plus prompt cancellation checks, closing sockets/resources on cancel.
- Bounded queues, retries, evidence, execution time, hosts, and probe sets are centrally enforced and configurable with hard safety ceilings (`max_hosts` 100000, discovery ports ≤8, ICMP attempts ≤3, TCP ports ≤5 at L5).
- ARP / IPv6 Neighbor Discovery are deferred (require raw link-layer access); technique variants exist but execution returns `Unavailable` and never fakes support.
