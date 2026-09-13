# Configuration

Phase 1–10 support explicit TOML layers:

```text
built-in defaults < --config GLOBAL.toml < --project-config PROJECT.toml < CLI
```

Profiles and runtime overrides are planned additions. Supported keys are `goal`, `level`, `speed`, `profile`, `scope`, `exclude`, `ports`, `all_ports`, plus budgets `max_tasks`, `max_retries`, `max_concurrency`, `max_execution_time`, `max_evidence_bytes`, `max_hosts`, and discovery key `discovery_ports`.

```toml
goal = "web"
level = 3
speed = 40
scope = ["example.test"]
exclude = ["admin.example.test"]
ports = "80,443"
max_tasks = 1000
max_retries = 1000
max_concurrency = 4
max_execution_time = "60s"
max_evidence_bytes = "64MiB"
max_hosts = 256
discovery_ports = "80,443"
wordlist = "paths.txt"
```

`level` must be 1–5. `speed` is `slow`, `balanced`, `fast`, `auto`, or 0–100. A CLI value always wins. Lists from a higher layer replace lower-layer lists so a project cannot silently inherit a broader scope.

## Phase 5 budgets

Minimal budget surface (all optional; defaults apply when unset):

| CLI flag | TOML key | Units | Default | Hard limit |
| --- | --- | --- | --- | --- |
| `--max-tasks N` | `max_tasks` | tasks | 1000 | 100000 |
| `--max-retries N` | `max_retries` | retries | 1000 | 100000 |
| `--max-concurrency N` | `max_concurrency` | workers | 4 | 64 |
| `--max-execution-time DURATION` | `max_execution_time` | duration → ms | 60000ms | 3600000ms (1h) |
| `--max-evidence-bytes BYTES` | `max_evidence_bytes` | bytes | 67108864 (64MiB) | 1073741824 (1GiB) |
| `--max-hosts N` | `max_hosts` | hosts from CIDR | 256 | 100000 |

Duration forms: `<n>ms`, `<n>s`, `<n>m`, `<n>h` (case-insensitive), or a bare number meaning seconds (e.g. `60s`, `5m`, `1h`, `500ms`, `60`). Byte forms: bare integers (bytes) or `<n><suffix>` with `B`, `KB`/`MB`/`GB` (1000-based), `KiB`/`MiB`/`GiB` (1024-based), e.g. `67108864`, `64MiB`, `10MB`. TOML also accepts integers for these two keys (interpreted as seconds/bytes).

Invalid values fail fast (exit 2): zero/negative-equivalent, values exceeding hard safety limits, malformed durations/sizes. Queue capacity is derived deterministically (`max(max_concurrency*16, max_concurrency+4)` capped by `max_tasks`); no separate flag exists.

## Phase 5 output

- `--output <path>`: write typed JSONL to a file (created/truncated). Filesystem errors are clean errors (exit 1), never panics. Output is bounded by `max_evidence_bytes`. Host-discovery results (assets, `DiscoveryStarted`/`ProbeAttempted`/`ProbeSucceeded`/`ProbeTimedOut`/`ProbeUnavailable`/`HostStateConcluded`/`HostDiscovered` events, evidence with target/address/state/confidence/techniques/latency/evidence/provenance/timestamp) flow into the same envelope.
- `--format jsonl`: output format selector. Only `jsonl` is supported; any other value fails fast. Without `--output`, `--format jsonl` writes JSONL to stdout (human summary goes to stderr to keep stdout pure JSONL).

## Phase 6 TCP port policy

- `--ports 22,80,443` / `--ports 1-1024` selects explicit lists/ranges (normalized, deduped, sorted; overlaps scan once). `--all-ports` scans 1–65,535 as ONE task (never 65k tasks). Invalid input (port 0, >65535, reversed/malformed) fails fast (exit 2).
- No `--ports`/`--all-ports` means automatic `common` selection by level (see `src/ports.rs`, profile `COMMON_PORTS_V1`): L1 `[80,443]`, L2 `[22,80,443,8080,8443]`, L3 standard 10 ports, L4 full 20-port profile, L5 broad 32 ports. Explicit selection always overrides level breadth.
- `--speed` never changes the port set (only concurrency 16–128/hard 256, pacing, per-port timeout 200–3000ms, filtered-only retry ≤1). Speed 100 stays bounded.
- Port states: `open` (connect success), `closed` (refused/reset), `filtered_or_timed_out` (timeout; never misclassified as closed), `error` (unreachable/permission/resource). Retries only for filtered (≤1); refused/open never retried; cancel never retried.
- Decision Engine V1: Alive → propose port scan (when port-eligible); Unknown → propose when explicit ports or level ≥3 (ICMP may be blocked); Unreachable → skip. Modules never self-schedule.
- Output: terminal prioritizes opens (`HOST`/`PORT STATE` table); JSONL carries per-open assets/evidence/findings plus a scan summary (huge scans emit opens + summary, not per-closed-port floods). Open means open — no service/version claims (Phase 7).

## Level and speed

- `--level 1–5` is investigation breadth/depth (see `src/level.rs` v1 policy plus `src/discovery.rs` host breadth). Level 1 is validation-only for all goals; higher levels add host/port/service/DNS/HTTP/TLS/fingerprint/content/crawl/fuzz intents filtered by `--goal`. Host-discovery breadth per level: L1 minimal (`icmp x1 + tcp [80]`), L2 (`icmp x1 + tcp [80,443]`), L3 standard (`icmp x2 + tcp [22,80,443]`), L4 broader (`icmp x2 + tcp [22,80,443,8080]`), L5 deepest bounded (`icmp x3 + tcp [22,80,443,8080,8443]`). Level 5 is bounded, never unbounded. Explicit `--ping`/`--discover`/`--udp`/`--ports`/`--all-ports` add their intent even if the level would not otherwise include it.
- `--speed slow|balanced|fast|auto|0–100` is execution pressure: concurrency ceiling, retry defaults, default task timeout, and per-probe ICMP/TCP timeouts (300–3000ms). Speed 100 is still capped by `max_concurrency` and hard budgets (never unlimited) and never changes Alive/Unknown/Unreachable meaning. `auto` v1 is a conservative deterministic baseline identical to `balanced` and is reported honestly as non-adaptive in `--explain`; adaptive feedback is Phase 4.1+ work.

## Host discovery policy

- `--ping` prioritizes ICMP reachability (L1 ICMP-only; L2+ ICMP plus single-port TCP fallback).
- `--discover` uses the configured multi-probe policy (L1 promoted to L2 breadth so it is always multi-probe).
- No flag (lightweight) follows level breadth directly.
- `discovery_ports` (TOML/profile only, e.g. `"80,443"`) replaces the level-derived TCP set (bounded to 8 ports, sorted). No CLI flag by design; use profiles/configuration for advanced discovery tuning.
- `max_hosts` caps CIDR host generation (default 256, one /24). Large scopes truncate deterministically to the first permitted addresses in order.
- ICMP requires no privileges to run overall: unprivileged ping sockets are tried natively (no shell `ping`); permission failures return structured `ICMP probe unavailable: insufficient privileges …` and TCP fallback proceeds. ICMP timeout alone yields Unknown, never false Dead.
- ARP (local IPv4) and IPv6 Neighbor Discovery are deferred sub-capabilities: technique variants exist, execution returns `Unavailable`, support is never faked.

## Phase 7 service policy

- No new CLI flags or TOML keys: service probing follows the existing `--level`, `--goal`, `--speed`, `--ports`/`--all-ports`, scope, and budget policy. `--explain` reports the service probe policy alongside discovery and TCP policy.
- Probe selection (see `src/service.rs` planner): known ports try their likely probe first (22→SSH, 80-family→HTTP, 443/8443→TLS, 21→FTP, 25/587→SMTP, 6379→Redis, 3306→MySQL, 5432→PostgreSQL); unknown ports get the passive generic probe first, plus HTTP at L3+ (L2+ for web/API goals). Level caps breadth (L1 single probe … L5 ≤6); speed sets the per-probe wall budget only (500–5000ms) and never the truth criteria.
- HTTPS requires HTTP-inside-TLS evidence on the same session (never TLS-alone); SMTPS composes analogously on SMTP-likely ports. Port hints order probes; identity always comes from handshake bytes.
- Byte budgets: banners ≤2KiB, HTTP headers/body ≤16KiB each, certificate chains ≤32KiB, SMTP replies ≤4KiB; requests are fixed payloads under 160B (one GET, one EHLO, one PING, one 8-byte SSLRequest, TLS ClientHello). Truncation is flagged in evidence.
- Authentication boundary: no USER/PASS/AUTH/LOGIN bytes are ever sent and no destructive commands exist (asserted by an exact-bytes allowlist test). Product/version hints are raw observed strings; the technology fingerprint engine remains a later phase.
- Depth over count: SSH, HTTP, TLS/HTTPS, FTP, and SMTP were completed first (each with recognition, negative, and bounds tests). Redis, MySQL, and PostgreSQL are included only because each is a minimal safe exchange (one PING / passive handshake / one 8-byte SSLRequest) with dedicated handshake tests and the same allowlist coverage — no scope or quality compromise.
- Strict unknown handling: port numbers order probes but never prove identity (hint≠proof is regression-tested both directions). Generic banners stay Unknown unless the bytes satisfy a concrete grammar (SSH identification string with valid version and line terminator); bare prefixes, malformed versions, and unterminated fragments stay Unknown with banners preserved. Failed TLS compositions are recorded as notes, never upgraded.
- Deferred seams (registered as documentation, not probes): IMAP, POP3, LDAP, MQTT, RDP, SMB, DNS-over-TCP, RPC, NTP, Kerberos.

## Phase 8 web policy

- No new CLI flags or TOML keys: web probing follows the existing `--level`, `--goal`, `--speed`, `--ports`, scope, and budget policy. `--explain` reports the web probe policy alongside the other policies.
- Canonical URLs fill scheme/host defaults (`http://h/` ≡ `http://h:80/`), bracket IPv6, preserve path case and query verbatim, and resolve relative `Location` values per RFC 3986; malformed destinations stop with notes. Endpoint IDs hash the full canonical URL, so distinct scheme/host/port/path identities never collide.
- Redirects: L1–L2 record only (no follows), L3 follows ≤2, L4–L5 follow ≤4 (hard cap 5). Every destination is scope-checked before contact and visited-set loop-checked; out-of-scope hops are recorded, never contacted. Chains appear in typed evidence/events.
- HTTP/1.1 with explicit `Host` (non-default ports kept, IPv6 bracketed); HEAD at L1–L2 (headers only), GET from L3 up (bounded body/title). One request per URL, one exchange per connection; cookies observed bounded (≤8, values ≤256B), never replayed.
- Bounds: ≤64 headers, 16KiB header/body halves, 1KiB body samples, 4 start URLs and 8 findings per task, connect/response timeouts from speed, task-deadline truncation, cancellation, evidence budget. Truncation is flagged, never silent.
- Speed sets timeouts/concurrency only: identical response bytes classify identically at any speed (regression-tested). Level sets breadth only.
- Service boundary: only findings with `service: http|https` propose web work; `HttpProbe` completions propose nothing — Phase 8 has no crawling follow-ups by construction.

## Phase 9 crawl policy

- No new CLI flags or TOML keys: crawling follows existing `--level`, `--goal`, `--speed`, scope, and scheduler budgets. Explicit future crawler tuning may override level defaults but will remain capped by hard ceilings.
- Crawl eligibility: only confirmed `EndpointObserved` HTTP/HTTPS output from `HttpProbe` can seed a root crawl. Port hints, protocol guesses, and arbitrary URLs do not bypass the Decision Engine.
- Level matrix: L1 root-only extraction (depth 0, 1 page/root, no robots/sitemap/JS fetch); L2 shallow same-origin crawl (depth 1, 5 pages/root); L3 normal crawl (depth 2, 15 pages/root, robots enabled); L4 deeper crawl (depth 3, 40 pages/root, robots+sitemap+static-JS extraction); L5 deepest Phase 9 crawl (depth 4, 100 pages/root). Hard ceilings: depth 6, 200 pages/root.
- Extraction/request caps: links 20 at L1, 50 at L2, 100 at L3+ (hard 100); forms 20/page; inputs 50/form; scripts 20/page; images 50/page; HTML 128KiB; JavaScript 64KiB; robots 32KiB; sitemap entries 500/document; sitemap files 3/root; crawl proposals 64/completion. Phase 8 redirect caps still apply per fetch.
- `--speed` affects pressure only: connection/response timeout, scheduler concurrency, retry/backoff. It does not change link/form/script/robots/sitemap interpretation, canonicalization, or endpoint classifications.
- Forms are observation-only. RXScan records action/method/input names/types and scope status, but never submits forms, creates values, logs in, mutates parameters, or infers vulnerabilities from a form.
- Static resources are not recursively fetched by default. Scripts may be fetched at L4+ only when explicitly referenced and in scope; images/styles/frames are recorded as relationships. JavaScript is scanned only for conservative string literals; it is never executed.

## Phase 10 baseline policy

- No new CLI flags or TOML keys: baseline intelligence follows existing `--level`, `--goal`, `--speed`, scope, and scheduler budgets. Future tuning may expose explicit caps but may not exceed hard ceilings.
- Baseline eligibility: confirmed `EndpointObserved` and in-scope `EndpointDiscovered` events may propose `Baseline` tasks through the Decision Engine. The baseline module does not enqueue follow-up work.
- Level matrix: L1 basic response signature and endpoint classification; L2 exact duplicate-ready signatures; L3 normalized signatures plus two inert missing-path samples per origin; L4 bounded similarity/template signals and parameter inventory; L5 deterministic interestingness score with structured factors.
- Hard caps: response body bytes used for signatures 64KiB; synthetic missing-path requests 2/origin; origin baseline registry 512 origins; signature representative index 1024 entries; template candidate buckets 8 representatives; endpoint baseline proposals 128/completion; parameter records 32/task; baseline findings 8/task. Redirect caps, header/body caps, deadlines, retries, and cancellation reuse Phase 8 web policy and scheduler limits.
- Synthetic paths are same-origin only and shaped as `/__rxscan_baseline_<token>__`. They characterize missing-resource behavior; they are not directory discovery, wordlists, sensitive path guessing, traversal, injection, or fuzzing.
- Normalization is conservative: lowercasing, whitespace collapse, tag-adjacent whitespace cleanup, and obvious long numeric/request-ID runs. It avoids collapsing unrelated short pages with the same title.
- `--speed` affects pressure only: concurrency, task timeout, connection timeout, response timeout, retry/backoff. It does not change fingerprint algorithms, similarity thresholds, endpoint classes, soft-404 interpretation, wildcard interpretation, parameter value classes, or interestingness scoring.
- Parameter inventory records names, source (`query` currently; form metadata remains Phase 9 observation evidence), method, and value shape class. RXScan does not mutate values, submit forms, fuzz parameters, or retain secret semantics as findings.

## Phase 11 managed content discovery policy

- `-w, --wordlist FILE` or TOML `wordlist = "paths.txt"` supplies an explicit managed content candidate file. Files are read incrementally with `BufRead`; RXScan does not load the whole file into memory.
- The built-in candidate set contains exactly 12 ordinary resource names: `/`, `/index.html`, `/robots.txt`, `/sitemap.xml`, `/login`, `/docs/`, `/api/`, `/status`, `/health`, `/assets/`, `/static/`, `/app.js`. It contributes well under 1KiB of static string data and intentionally excludes credentials, traversal strings, backups, exploit payloads, and secret-hunting permutations.
- Candidate normalization trims whitespace, ignores blank lines and leading `#` comments, removes fragments, collapses duplicate slashes, preserves query strings, and adds a leading slash. It rejects lines over 512 bytes, absolute URLs, authorities, backslashes, control characters, malformed values, and `.`/`..` traversal components including simple encoded-dot forms.
- Level matrix: L1 disabled; L2 first 4 built-in candidates, request cap 8; L3 first 8 built-ins, request cap 32; L4 all built-ins plus user file, request cap 64; L5 all built-ins plus user file, request cap 128. Hard caps are candidates read 2000, admitted 512, response bytes 64KiB, discovered endpoints 64, events 256, evidence 128, findings 16, dedup entries 1024.
- Phase 11 classification reuses Phase 10 origin-baseline normalized hashes when available. A 200 response matching missing-resource baseline is `soft_not_found`/`wildcard_like`, not a discovered endpoint. A bounded scan-lifetime contacted-request registry (4096 entries) prevents redundant canonical GET contacts where semantics permit reuse, including crawler/content duplicates; at capacity it stops tracking new entries and scanning remains scope-checked and bounded by normal budgets.
- `--speed` affects only connection/response timeouts, retry/backoff, and scheduler pressure. It never changes candidate contents, normalization, baseline classification, dedup identity, or evidence meaning.

## Phase 12 contextual fuzzing policy

- No new CLI flags or TOML keys: contextual fuzzing follows existing `--goal fuzz|custom`, `--level`, `--speed`, scope, and scheduler budgets.
- Eligibility: `Baseline` outputs with `ResponseSignatureObserved` for an endpoint containing a concrete non-sensitive GET query parameter may propose `Fuzz` tasks through the Decision Engine. Fuzz modules never enqueue follow-up work.
- Active contexts: GET query parameters only. GET-form active fuzzing, POST forms, cookies, headers, and path-variable fuzzing are RESERVED.
- Level matrix: L1-L2 disabled; L3 one observed parameter with up to two mutations and at most two fuzz tasks per origin; L4 up to three parameters with up to three mutations each and at most four fuzz tasks per origin; L5 up to four parameters with up to four mutations each and at most eight fuzz tasks per origin. Existing goal/level eligibility and scheduler budgets still apply; L5 is bounded.
- Mutation classes: `OmittedValue`, `EmptyValue`, `AlternateNumericBoundary`, `AlternateBoolean`, `ShortRandomToken`, and `AlternateBenignScalar`. Mutations are inert, one parameter at a time, and keep unrelated query parameters unchanged.
- Sensitive names containing password/passwd/token/csrf/secret/otp/auth/session are skipped. Skips are typed observations when a fuzz task is explicitly created for such an input.
- Hard caps: 4 parameters/endpoint, 4 mutations/parameter, 8 mutations/task, 8 requests/task, 8 fuzz tasks/origin, 256 tracked fuzz origins/scan, 64KiB response bytes, 64 events/task, 16 evidence records/task, 4 neutral findings/task, 64 task-local dedup keys, plus the 4096-entry scan-lifetime contacted-request registry.
- `--speed` affects only pressure: connection/response timeouts, retry/backoff, and scheduler pressure. It never changes mutation values, safety filtering, delta thresholds, signature normalization, or evidence meaning.

## Phase 13 DNS policy

- No new CLI flags or TOML keys: DNS uses existing `--goal`, `--level`, `--speed`, scope, and scheduler budgets. Production uses system resolver configuration by default; tests and benchmarks can pass an explicit resolver task parameter.
- Hostnames canonicalize by lowercasing, trimming one root dot, validating label length/characters, and rejecting empty/oversized/malformed names. IDNA is NOT IMPLEMENTED.
- Level matrix: L1-L2 query A/AAAA/CNAME only; L3 adds MX/NS; L4-L5 add TXT/PTR observations. UDP truncation is observable as `Truncated`; TCP fallback, wildcard DNS, SRV, DoH/DoT, custom resolver CLI UX, subdomain brute force, and AXFR/IXFR are NOT IMPLEMENTED.
- Hard caps: 512-byte UDP packet, 16 records/response, 48 records/task, 64 events/task, 32 evidence records/task, 8 CNAME hops, 256 TXT bytes/record, 1024 TXT bytes/task, 4096 scan-lifetime DNS query keys, 256 tracked domains, and 32 DNS tasks/domain.
- `--speed` affects DNS timeout/retry pressure only. It does not change record types, hostname eligibility, task identity, scope, retained relationships, or interpretation.
