# RXScan threat model

RXScan is for authorized, scoped, non-destructive reconnaissance. Its central risks and required controls are:

| Risk | Required control | Phase |
| --- | --- | --- |
| Scope expansion or crawler drift | Scope Guard at proposal, queue, and execution | 1, then enforced by 3 |
| Oversized scope/workload | host/probe estimates, confirmation, budgets | 4 |
| Hostile or malformed responses | timeouts, response caps, parser isolation, crash containment | 5 onward |
| Queue/retry/memory exhaustion | bounded queues, cancellation, capped retries, backpressure | 3–4 |
| Secrets or memory exhaustion in artifacts | bounded (64 KiB) evidence capture with truncation metadata; redaction policy/classification | 2, 20 |
| Malicious or compromised packs | hashes, compatibility gates, signatures/trust policy | 22 |
| Task-ID collisions merging distinct work | canonical SHA-256 task identity over all execution-relevant fields (kind, module, scope, params, priority, timeout, retry, asset, parent, deps, plan) | 4 |
| Timeout reporting clean while workers leak | timed-out tasks free their slot immediately; orphans bounded by task budget; late results discarded without double-count; modules MUST observe cancellation with bounded I/O timeouts | 4 |
| Retry-delay starvation / head-of-line blocking | retry-delayed tasks never block other ready tasks; queue saturation is backpressure (stay `Pending`), not fatal | 4 |
| Unbounded output / disk exhaustion | JSONL writer byte cap (`max_evidence_bytes`); safe filesystem error handling without panics | 4 |

Modules never receive authority to bypass policy. Discovery may be recorded without authorizing active work against a new asset.

## Phase 4 executor safety notes

- No arbitrary shell execution; no network execution in Phase 4.
- Scope Guard cannot be bypassed (lowering + admission + promotion + dispatch checks; stale scope → `Skipped`).
- Modules cannot self-schedule (only `DecisionEngine` proposes follow-ups; Phase 4 uses `NoFollowUps`).
- No new `unsafe` code in Phase 4. The pre-existing hand-rolled `block_on` waker is a cooperative parking executor for stub/control modules only; its `RawWaker` follows the owned/borrowed wake contract (`wake` consumes, `wake_by_ref` borrows). Future real I/O must not block worker threads indefinitely and must use bounded timeouts plus prompt cancellation checks, closing sockets/resources on cancel.
- Bounded queues, retries, evidence, and execution time are centrally enforced and configurable with hard safety ceilings.
