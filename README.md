# RXScan — Reactive Recon Scanner

Simple outside. Serious inside.

RXScan is a native Rust, policy-driven reconnaissance engine for systems you
own or are authorized to assess. It is a standalone binary with no runtime
dependencies beyond the OS C library: no Python, no Docker, no external
scanners, no daemons, no telemetry.

```bash
cargo install --path .
rxscan https://target.test --explain
rxscan 127.0.0.1 --scope 127.0.0.0/8 --level 2 --ports 80,443
```

## What it does

- Structured host discovery (ICMP echo + TCP reachability, unprivileged).
- TCP connect port scanning (one bounded task per target, never 65k tasks).
- Service identification over native handshakes (SSH/HTTP/TLS/FTP/SMTP/
  Redis/MySQL/PostgreSQL/generic) without authentication.
- Bounded HTTP/1.1 observations, redirects, certificates; bounded crawling
  of confirmed endpoints (forms/robots/sitemaps observed, never submitted
  or executed).
- Response baselines, managed content discovery (embedded + user wordlists),
  and safe single-parameter GET fuzzing from observed inputs.
- Native UDP DNS observations (A/AAAA/CNAME/MX/NS/TXT/PTR).
- Typed JSONL output, versioned checkpoints with resume, offline scan diff,
  deterministic attention analysis, offline reports (human/JSON/JSONL/raw),
  and an offline multi-scan project graph with bounded queries.

## What it does NOT do

No exploitation, no vulnerability checks, no credential attacks or brute
force, no stealth/evasion, no POST/form submission, no JavaScript execution,
no UDP port scanning, no cipher enumeration, no plugin ecosystem, no GUI,
no auto-update, no analytics. See `docs/ROADMAP.md` for the full boundary.

## Install

Prerelease v0.1.0, Linux x86_64 only (the only tested platform):

```bash
cargo install --path .
# or: cargo build --release && ./target/release/rxscan --version
```

Requires Rust 1.85+. No other runtime. Uninstall: delete the binary
(`cargo uninstall rxscan` if installed via Cargo).

## First scan (loopback)

```bash
rxscan 127.0.0.1 --scope 127.0.0.1 --level 1 --ports 9
rxscan 127.0.0.1 --scope 127.0.0.1 --level 2 --ports 80,443 \
  --checkpoint scan.rxscan --output scan.jsonl
rxscan report --format json scan.rxscan
```

## Level vs speed

- `--level 1-5` controls breadth and depth (which modules run, how deep).
- `--speed slow|balanced|fast|auto|0-100` controls pressure only
  (concurrency, timeouts, retries). Speed never changes what is scanned.

## Scope and safety

RXScan only contacts what is in scope. The explicit target is always
authorized; `--scope` adds rules, `--exclude` removes them. Discovered URLs,
redirects, and DNS names outside scope are recorded but never contacted.
Out-of-scope work is rejected before any network contact. A typo'd target
outside your intent is still *your* explicit target — double-check it.
Only assess systems you own or are authorized to assess.

## Checkpoint / resume / diff / analyze / report / project

```bash
rxscan ... --checkpoint scan.rxscan        # atomic save after the run
rxscan --resume scan.rxscan --checkpoint scan2.rxscan
rxscan diff old.rxscan new.rxscan
rxscan analyze scan.rxscan
rxscan report --format jsonl scan.rxscan
rxscan project create lab.rxproj
rxscan project add lab.rxproj scan.rxscan
rxscan project neighbors lab.rxproj <entity-id>
```

`diff`, `analyze`, `report`, and `project` are fully offline
(`network_requests=0`). Exit codes: `0` success, `2` usage/config error,
`1` invalid input or runtime failure. Interruption (Ctrl+C) stops promptly;
prior checkpoint/output files are never replaced by partial runs.

## Platform support and limitations

- Tested: Linux x86_64, Rust 1.85, unprivileged user. No macOS/Windows proof.
- Bounded by design: hard caps on tasks, concurrency (scheduler 64, TCP 256
  sockets), hosts (default 256), evidence, registries, checkpoint (8 MiB),
  and project files (16 MiB). Caps reject with clear errors; they are not
  tunable beyond the documented budgets.
- ICMP may degrade to `Unknown` without privileges; nothing requires root.
- Prerelease: no signed artifacts, no crates.io publication, no man page,
  no shell completions. See `CHANGELOG.md` and `docs/RELEASE_CHECKLIST.md`.

Further reading: `docs/ARCHITECTURE.md`, `docs/CONFIGURATION.md`,
`docs/THREAT_MODEL.md`, `docs/IMPLEMENTATION_STATUS.md`,
`docs/benchmark-results/phase20-release-gate.md`, `SECURITY.md`.
