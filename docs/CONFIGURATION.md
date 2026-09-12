# Configuration

Phase 1–4 support explicit TOML layers:

```text
built-in defaults < --config GLOBAL.toml < --project-config PROJECT.toml < CLI
```

Profiles and runtime overrides are planned additions. Supported keys are `goal`, `level`, `speed`, `profile`, `scope`, `exclude`, `ports`, `all_ports`, plus Phase 4 budgets `max_tasks`, `max_retries`, `max_concurrency`, `max_execution_time`, and `max_evidence_bytes`.

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
```

`level` must be 1–5. `speed` is `slow`, `balanced`, `fast`, `auto`, or 0–100. A CLI value always wins. Lists from a higher layer replace lower-layer lists so a project cannot silently inherit a broader scope.

## Phase 4 budgets

Minimal budget surface (all optional; defaults apply when unset):

| CLI flag | TOML key | Units | Default | Hard limit |
| --- | --- | --- | --- | --- |
| `--max-tasks N` | `max_tasks` | tasks | 1000 | 100000 |
| `--max-retries N` | `max_retries` | retries | 1000 | 100000 |
| `--max-concurrency N` | `max_concurrency` | workers | 4 | 64 |
| `--max-execution-time DURATION` | `max_execution_time` | duration → ms | 60000ms | 3600000ms (1h) |
| `--max-evidence-bytes BYTES` | `max_evidence_bytes` | bytes | 67108864 (64MiB) | 1073741824 (1GiB) |

Duration forms: `<n>ms`, `<n>s`, `<n>m`, `<n>h` (case-insensitive), or a bare number meaning seconds (e.g. `60s`, `5m`, `1h`, `500ms`, `60`). Byte forms: bare integers (bytes) or `<n><suffix>` with `B`, `KB`/`MB`/`GB` (1000-based), `KiB`/`MiB`/`GiB` (1024-based), e.g. `67108864`, `64MiB`, `10MB`. TOML also accepts integers for these two keys (interpreted as seconds/bytes).

Invalid values fail fast (exit 2): zero/negative-equivalent, values exceeding hard safety limits, malformed durations/sizes. Queue capacity is derived deterministically (`max(max_concurrency*16, max_concurrency+4)` capped by `max_tasks`); no separate flag exists in Phase 4.

## Phase 4 output

- `--output <path>`: write typed JSONL to a file (created/truncated). Filesystem errors are clean errors (exit 1), never panics. Output is bounded by `max_evidence_bytes`.
- `--format jsonl`: output format selector. Only `jsonl` is supported; any other value fails fast. Without `--output`, `--format jsonl` writes JSONL to stdout (human summary goes to stderr to keep stdout pure JSONL).

## Level and speed

- `--level 1–5` is investigation breadth/depth (see `src/level.rs` v1 policy). Level 1 is validation-only for all goals; higher levels add host/port/service/DNS/HTTP/TLS/fingerprint/content/crawl/fuzz intents filtered by `--goal`. Explicit `--ping`/`--discover`/`--udp`/`--ports`/`--all-ports` add their intent even if the level would not otherwise include it.
- `--speed slow|balanced|fast|auto|0–100` is execution pressure: concurrency ceiling, retry defaults, and default task timeout. Speed 100 is still capped by `max_concurrency` (never unlimited). `auto` v1 is a conservative deterministic baseline identical to `balanced` and is reported honestly as non-adaptive in `--explain`; adaptive feedback is Phase 4.1+ work.
