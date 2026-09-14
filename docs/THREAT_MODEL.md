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
| Credential exposure / destructive protocol actions | no-authentication design: only passive reads plus one safe exchange per protocol (GET / EHLO / PING / SSLRequest / ClientHello); exact-bytes allowlist test forbids AUTH/USER/PASS/LOGIN and destructive verbs | 7 |
| Service misidentification (port-guessing) | port hints order probes only; classifications require handshake/banner evidence with graded confidence; unknown stays unknown; silent stays silent | 7 |
| Unbounded handshake/memory blowup | per-probe wall budgets plus task-deadline truncation, 2–32KiB read caps with truncation flags, fixed small writes, no cipher enumeration | 7 |
| Crawler scope drift / recursive explosion | confirmed-endpoint eligibility, Decision Engine-only recursion, same-origin follow-ups, hard depth/page/request/candidate caps, per-request scope checks, out-of-scope observations without contact | 9 |
| Unsafe web interaction | forms observed but never submitted; no parameter mutation, credentials, JavaScript execution, headless browser, wordlists, fuzzing, or vulnerability payloads | 9 |
| Baseline probe drift / accidental discovery | inert same-origin synthetic paths only, two-sample hard cap, Decision Engine-only admission, no wordlists or sensitive path names | 10 |
| False duplicate/soft-404 claims | conservative signatures, bounded similarity thresholds, two-sample missing-path baseline, inconclusive state for weak signals | 10 |
| Managed content discovery becoming fuzzing | small reviewed built-in set, explicit streamed user file, no placeholders/mutation/method enumeration/forms/payloads, hard candidate/request caps | 11 |
| Contextual fuzzing becoming exploit fuzzing | observed GET query context required, inert one-parameter mutations, sensitive-name skip list, no POST/forms/cookies/headers/path traversal/payload banks, neutral behavior-delta output only | 12 |
| DNS intelligence expanding scope or becoming enumeration | explicit/observed scoped hostnames only, bounded query/record/domain caps, DNS observations do not authorize third-party active follow-up, no brute-force subdomain enumeration, no zone transfer automation | 13 |
| Checkpoint resume widening authority or replaying unsafe state | checkpoint file treated as untrusted input, schema/size/count validation before execution, persisted scope is authoritative maximum, resume goes through Scheduler, completed work stays completed, raw bodies/packets/secrets excluded | 14 |
| Diffing corrupt checkpoints or producing false removals | both inputs pass Phase 14 validation first, diff is offline, stable semantic keys ignore timestamps/paths/speed, missing entities require comparable coverage for confirmed removal, network-error states downgrade certainty | 15 |
| Candidate path escape | same-origin URL construction, traversal/authority/control/backslash rejection, canonical dedup, scope check before every contact | 11 |

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

## Phase 7 executor safety notes

- No authentication, no mail relay, no queries, no destructive commands: the exact bytes each probe may send are documented in `src/probes.rs` and enforced by an allowlist test (passive reads for SSH/FTP/MySQL/generic; single GET / EHLO / PING / SSLRequest / ClientHello otherwise).
- One task per open port with a sequential bounded probe plan (first classification wins; TLS compositions reuse the session); per-probe wall budgets plus task-deadline truncation with partial results; prompt cancellation; no inner retries (timeouts become evidence).
- Scope Guard cannot be bypassed (lowering/admission/promotion/dispatch/module checks; service tasks carry Ip scope with derived-address re-checks; hostname-derived IPs filtered; proposals pre-checked and best-effort admitted).
- TLS via rustls observe-only verifier (trust never evaluated; chain recorded as evidence); no cipher-suite enumeration; certificates parsed with bounded x509-parser and fingerprinted with SHA-256.
- Output stays bounded (per-classified-service assets/evidence/findings; unknown-with-banner evidence only; silent runs emit events alone; JSONL byte cap; terminal shows the service table only).

## Phase 8 executor safety notes

- Single request per URL over one connection (explicit HEAD/GET, `Connection: close`); no link extraction paths are ever requested — a no-crawl boundary test asserts advertised-but-unplanned URLs see zero contacts.
- Redirects re-enter the Scope Guard per hop with visited-set loop detection and a hard hop cap; out-of-scope destinations are recorded with `followed: false` and never resolved to sockets (canary-listener test proves zero contact).
- Response handling is capped at every layer (header count/bytes, body bytes with surplus handoff so single-segment head+body reads cannot defeat the cap, cookie count/size, endpoint identity length, findings/tasks); truncation is flagged in evidence; malformed input is a miss with notes, never a panic or a guess.
- TLS reuses the Phase 7 observe-only session primitive (trust never evaluated); certificates are parsed bounded and fingerprinted; no cipher enumeration, no security grading, no version claims beyond observed strings.
- Cookies are observations only (no jar, no replay); server/product strings are raw observations, never precise version claims; unknown stays unknown.

## Phase 9 crawler safety notes

- Crawl root eligibility is evidence-gated: only confirmed HTTP/HTTPS endpoint observations from Phase 8 can become root crawl tasks, and only the Decision Engine may propose them.
- Recursive crawl is bounded by level-derived depth/page budgets carried in task params (`depth`, `pages_left`) and centrally planned by `plan_followups`; scheduler `max_tasks` remains the global cap.
- Every candidate is resolved through Phase 8 `WebTarget` canonicalization before deduplication. Fragments are discarded for network identity; query strings are preserved; same-origin follow-ups require identical scheme, host, and port.
- Scope checks happen before task admission, immediately before execution, before each request, before redirect following, before JavaScript/robots/sitemap retrieval, and before Decision Engine follow-up admission. Out-of-scope candidates are typed observations and never contacted.
- HTML/robots/sitemap/JavaScript parsing is bounded and fail-safe. Malformed content yields fewer observations, never panics or speculative endpoints.
- Forms are observation only: method/action/input metadata is recorded, but RXScan never submits, mutates, authenticates, or infers vulnerabilities from forms.
- Static JavaScript extraction is conservative literal scanning from explicitly referenced in-scope scripts at L4+. No JavaScript execution, DOM emulation, dynamic instrumentation, or headless browser exists.

## Phase 10 baseline safety notes

- Baseline tasks reuse Phase 8 `WebTarget` and HTTP/TLS primitives; there is no separate raw HTTP stack. Redirects are capped, loop-checked, and scope-checked before follow.
- Synthetic missing-resource paths are deterministic per task, clearly inert, same-origin, and capped at two samples/origin. Scan-lifetime origin state is keyed by scheme + canonical host + effective port so equivalent origins do not repeat synthetic characterization across separate completion batches. Synthetic paths are never drawn from dictionaries and never include admin, backup, secret, traversal, injection, shell, or authentication strings.
- Baseline classification is evidence-backed and conservative. Soft-404/wildcard observations require repeated missing-path evidence; weak or mixed signals remain `Inconclusive`.
- Parameter handling is inventory only. Names and value-shape classes may be recorded; values are not mutated, replayed, submitted, fuzzed, or turned into vulnerability claims.
- Similarity work is bounded by proposal/comparison caps plus compact scan-lifetime indexes. Exact/normalized hashes are primary signals; template similarity uses small capped buckets and requires compatible status/MIME, matching title/structure, close length, and enough body material to avoid collapsing unrelated short pages.

## Phase 11 managed content discovery safety notes

- Content discovery is native Rust and uses the existing Phase 8 web primitives. There is no second HTTP client, external scanner, Python/Java/Node runtime, browser, database, LLM, or subprocess fuzzing tool.
- Candidate files are streamed line-by-line. RXScan never loads the full wordlist into memory; line length, candidates read, candidates admitted, requests, dedup entries, events, evidence, findings, and response bytes are capped.
- Candidates are resource paths only. Absolute URLs, authorities, backslashes, control characters, traversal components, and oversized/malformed lines are rejected before URL construction.
- Baseline-aware filtering uses Phase 10 normalized missing-resource signatures. A success status alone is insufficient to classify content as discovered.
- Content discovery shares the scan-lifetime contacted-request registry with crawl/baseline modules so canonical duplicate GET URLs are not contacted repeatedly. This registry is not an authorization mechanism; scope checks still run at every contact boundary.
- Content modules never self-schedule; discovered endpoints are typed events that return to the Decision Engine for existing crawl/baseline follow-ups.

## Phase 12 contextual fuzzing safety notes

- Contextual fuzzing is native Rust and reuses Phase 8 `WebTarget` and HTTP/TLS primitives plus Phase 10 signatures. There is no second HTTP client, external scanner, browser, database, Python/Java/Node runtime, LLM, or subprocess fuzzing tool.
- A fuzz task requires existing evidence: a baseline response signature for an endpoint with an observed non-sensitive GET query parameter. Unobserved parameter names are not invented.
- Mutations are inert and bounded: omission, empty value, tiny numeric/boolean alternatives, and short `rxscan_<token>` text values. One parameter changes per request; pairwise/cartesian mutation is not implemented.
- Sensitive names containing password/passwd/token/csrf/secret/otp/auth/session are skipped. POST forms, GET-form active submission, cookies, headers, path-variable fuzzing, traversal strings, injection payloads, credential attacks, and vulnerability checks are deferred or explicitly out of scope.
- Results are behavior observations only: status/content-type/redirect/body/template changes and exact inert-token reflection. RXScan does not infer XSS, SQL injection, auth bypass, SSRF, command injection, or any confirmed vulnerability from Phase 12 deltas.

## Phase 13 DNS safety notes

- DNS uses bounded native UDP queries and defensive packet parsing. Raw DNS packets are dropped after typed records/evidence are extracted.
- A, AAAA, CNAME, MX, NS, TXT, and PTR observations enrich the asset graph; they do not by themselves authorize active scanning of referenced third-party infrastructure.
- A/AAAA follow-ups are proposed only by the Decision Engine and only when the resulting IP independently satisfies central scope.
- TXT is informational and byte-bounded. RXScan does not scrape secrets or infer DNS/mail vulnerabilities.
- Wildcard DNS, SRV, AXFR/IXFR, public resolver rotation, subdomain brute force, DNS amplification, spoofing, and takeover checks are NOT IMPLEMENTED.

## Phase 14 persistence safety notes

- Checkpoints are untrusted JSON input. RXScan validates schema version, file size, counts, task scope, graph references, and registry bounds before any resume execution.
- Checkpoints persist semantic state only. They do not contain sockets, thread handles, raw HTTP bodies, raw DNS packets, TLS sessions, credentials, cookies, or wordlists.
- Resume cannot widen persisted scope. Running/ready tasks are restored as pending/interrupted rather than falsely completed.
- Phase 14 does not implement encrypted checkpoints, tamper-proof signatures, automatic crash recovery, or checkpoint history storage.

## Phase 15 diff safety notes

- Diff inputs are untrusted checkpoints and must pass Phase 14 validation before normalization.
- Diff never contacts checkpoint-provided targets, starts Scheduler work, executes commands, mutates checkpoints, or widens scope.
- Diff records are capped at 10000 detailed entries. Aggregate counts continue and truncation is explicit.
- Phase 15 reports semantic change only. It does not assign severity, risk, regression status, or Phase 16 prioritization.

## Phase 16 analysis safety notes

- Analysis inputs are validated scan states and optional diff records. Checkpoint loading reuses Phase 14 validation; invalid input fails before analysis and before any network work.
- Analysis is offline: it never starts host discovery, TCP, service, DNS, HTTP, crawl, content discovery, or fuzz modules.
- Attention score is not severity, exploitability, CVSS, or vulnerability likelihood. Inconclusive Phase 15 certainty remains inconclusive and receives an uncertainty penalty rather than an upgraded conclusion.
- Generated labels are bounded and control characters are stripped. Signals keep evidence/asset references rather than copying raw HTTP bodies, DNS packets, banners, credentials, cookies, or large evidence bodies.
- Output is capped and sorted deterministically. Phase 16 does not implement report templates, alerts, dashboards, or historical project storage.
