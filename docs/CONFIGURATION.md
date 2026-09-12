# Configuration

Phase 1–5 support explicit TOML layers:

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
