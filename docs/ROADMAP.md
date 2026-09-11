# RXScan roadmap

Each phase requires tests, benchmark/regression evidence where applicable, documentation, and an explicit exit review.

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0 | Architecture, tooling, fixtures, benchmark discipline, CI | Complete |
| 1 | Target model, CLI, Scope Guard, config, ScanPlan | Complete |
| 2 | Events, findings, stable asset IDs, relationships | Planned |
| 3 | Reactive scheduler, queues, cancellation, backpressure | Planned |
| 4 | Speed governor, budgets, adaptive control | Planned |
| 5–10 | Discovery, TCP, UDP, probes, TLS/fingerprints, HTTP | Planned |
| 11–15 | DNS, crawler, baseline, content, fuzzing | Planned |
| 16–19 | Decision engine, API workflows, checks, graph/correlation | Planned |
| 20–24 | Outputs, resume/diff/projects, packs, benchmark lab, releases | Planned |

## MVP v0.1 gate

TargetSpec, Scope Guard, ScanPlan, stable IDs/events, scheduler, speed/budgets, host discovery, TCP, basic SSH/HTTP/HTTPS/TLS fingerprinting, managed content discovery, basic path fuzzing, JSON output, tests, and benchmark baseline.

## Phase 1 exit criteria

- IPv4, IPv6, hostname, URL, CIDR, file, and stdin target inputs normalize safely.
- Scope is deny-by-default; exclusions override allowances and excluded seeds fail before execution.
- Explicit global and project TOML configuration resolve deterministically; CLI overrides them.
- Goals, level 1–5, and speed presets/0–100/auto are represented independently in `ScanPlan`.
- `--explain` describes choices and deferred capability.
