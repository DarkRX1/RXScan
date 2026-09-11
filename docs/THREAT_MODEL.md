# RXScan threat model

RXScan is for authorized, scoped, non-destructive reconnaissance. Its central risks and required controls are:

| Risk | Required control | Phase |
| --- | --- | --- |
| Scope expansion or crawler drift | Scope Guard at proposal, queue, and execution | 1, then enforced by 3 |
| Oversized scope/workload | host/probe estimates, confirmation, budgets | 4 |
| Hostile or malformed responses | timeouts, response caps, parser isolation, crash containment | 5 onward |
| Queue/retry/memory exhaustion | bounded queues, cancellation, capped retries, backpressure | 3–4 |
| Secrets in artifacts | redaction policy and evidence classification | 2, 20 |
| Malicious or compromised packs | hashes, compatibility gates, signatures/trust policy | 22 |

Modules never receive authority to bypass policy. Discovery may be recorded without authorizing active work against a new asset.
