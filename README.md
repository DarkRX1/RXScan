<p align="center">
  <img src="RXScanlogo.png" alt="RXScan" width="460">
</p>

<h1 align="center">RXScan</h1>

<p align="center">
  <strong>Raw Excess Scan</strong>
</p>

<p align="center">
  Fast, bounded reconnaissance and evidence correlation in Rust.
</p>

<p align="center">
  <a href="https://github.com/DarkRX1/RXScan/releases">
    <img src="https://img.shields.io/github/v/release/DarkRX1/RXScan?style=flat-square&label=release" alt="Release">
  </a>
  <a href="https://github.com/DarkRX1/RXScan/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/DarkRX1/RXScan/ci.yml?style=flat-square&label=build" alt="Build">
  </a>
  <img src="https://img.shields.io/badge/Rust-1.85%2B-orange?style=flat-square" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square" alt="Linux">
</p>

<p align="center">
  <strong>Scan</strong> ·
  <strong>Search</strong> ·
  <strong>Investigate</strong> ·
  <strong>Correlate</strong> ·
  <strong>Persist</strong> ·
  <strong>Explain</strong>
</p>

---

## Overview

RXScan is a reconnaissance and evidence engine built in Rust.

It combines bounded network scanning, service identification, public-source search, investigation, correlation, and persistent project intelligence behind one evidence-driven workflow.

```text
Search → Discover → Scan → Fingerprint → Enrich → Correlate → Explain → Persist → Compare
```

RXScan is designed around a simple rule:

> **Report what was observed, preserve uncertainty, and never make the output stronger than the evidence.**

It is built for authorized reconnaissance without credential guessing, brute force, exploitation, authentication bypass, or destructive actions.

---

## Quick Start

### Scan a target

```bash
rxscan example.test
```

Scan selected ports:

```bash
rxscan example.test --ports 22,80,443
```

Scan all TCP ports:

```bash
rxscan example.test --all-ports
```

Add bounded UDP discovery:

```bash
rxscan example.test --udp
```

Explain exactly what RXScan plans to do:

```bash
rxscan example.test --explain
```

### Search public sources

```bash
rxscan search --username exampleuser
```

RXScan prioritizes useful positive findings in normal terminal output:

```text
RXSCAN  /  PUBLIC SEARCH                              PASSIVE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGET

  Username    exampleuser
  Providers   100
  Network     Disabled

FINDINGS

  ✓ github / exampleuser
    Profile    https://github.com/exampleuser
    high · 94% · public profile

  ? example-site / exampleuser
    Candidate  https://example.test/u/exampleuser
    low · 25% · weak evidence

  + additional findings

COVERAGE

  Completed      99 / 100
  Confirmed      14
  Possible       11
  Blocked        20
  Unknown        49
```

Confirmed profiles, observed resources, and unverified candidate URLs are represented differently so the terminal does not imply more certainty than RXScan actually has.

Use:

```bash
rxscan search --username exampleuser --all
```

for the complete human result set, or:

```bash
rxscan search --username exampleuser --explain
```

to inspect execution and classification reasoning.

### Investigate an identity

```bash
rxscan investigate --username exampleuser
```

Investigation correlates public evidence into entities and relationships while remaining passive by default.

```text
ACCOUNTS

  GitHub / exampleuser
  ├─ Profile
  │  https://github.com/exampleuser
  └─ Confidence
     high · 94%

CORRELATION

  ENTITY                 REFERENCES
  ─────────────────────  ──────────
  example.test                    8
  api.example.test                3
```

Secondary static assets and implementation-level graph details stay out of the default view while remaining available through detailed output.

---

## Why RXScan?

Traditional reconnaissance often means switching between unrelated tools and manually correlating their output.

RXScan instead keeps observations connected.

| Capability | RXScan |
|---|---|
| Host discovery | ✓ |
| TCP connect scanning | ✓ |
| Linux IPv4 raw SYN | ✓ |
| Native bounded UDP discovery | ✓ |
| Service identification | ✓ |
| HTTP / TLS / SSH intelligence | ✓ |
| DNS observations | ✓ |
| Public-source username search | ✓ |
| Investigation workflows | ✓ |
| Evidence graph | ✓ |
| Relationship correlation | ✓ |
| Persistent projects | ✓ |
| Coverage-aware diffing | ✓ |
| JSON / JSONL | ✓ |
| Explainable planning | ✓ |
| Global execution budgets | ✓ |
| Credential brute force | **No** |
| Automatic exploitation | **No** |

RXScan favors **bounded evidence collection and correlation** over aggressive or destructive behavior.

---

## Network Reconnaissance

RXScan normalizes targets, applies scope policy, performs bounded discovery, scans ports, identifies services, and schedules evidence-triggered follow-ups.

### TCP

Supported TCP selection includes:

```bash
rxscan example.test --ports 443
rxscan example.test --ports 22,80,443
rxscan example.test --ports 1-1024
rxscan example.test --ports 22,80,443,8000-8100
rxscan example.test --all-ports
```

`--scan-mode` controls the TCP mechanism:

```bash
rxscan example.test --scan-mode auto
rxscan example.test --scan-mode connect
rxscan example.test --scan-mode syn
```

`auto` selects raw SYN where supported and permitted, otherwise falling back to connect scanning with the effective mechanism and reason preserved in evidence.

### UDP

UDP is explicit opt-in:

```bash
rxscan example.test --udp
```

UDP discovery is bounded and conservative.

Silence is uncertainty.

RXScan does **not** reinterpret an unanswered UDP probe as proof that a port is open or closed.

### Service identification

Open ports can trigger evidence-based service identification.

RXScan can recognize and collect bounded observations for protocols including:

- SSH
- HTTP / HTTPS
- TLS
- FTP
- SMTP / SMTPS
- Redis
- MySQL
- PostgreSQL
- SMB
- RDP
- MongoDB
- MQTT
- generic / unknown services

When useful evidence exists, the human report exposes it directly:

```text
PORTS

  22/tcp  OPEN  SSH
    Product    OpenSSH
    Version    9.x

  443/tcp OPEN  HTTPS
    Endpoint   https://example.test/
    Product    nginx
    TLS name   example.test
```

Fields are shown only when supported by collected evidence.

Unknown services remain unknown rather than inheriting identity from their port number.

---

## Public-Source Search

RXScan includes a bounded public-source search engine with a curated provider corpus.

```bash
rxscan search --username exampleuser
```

Search results distinguish outcomes such as:

- confirmed
- possible
- not found
- unknown
- blocked
- rate limited
- authentication required
- error
- cancelled
- unscanned

An HTTP `200` alone is never treated as sufficient proof that an account exists.

Normal terminal output prioritizes confirmed and possible findings while provider failures and negative outcomes remain summarized under coverage.

---

## Investigation & Correlation

Search findings can be correlated into an evidence graph containing entities such as:

- usernames
- accounts
- email addresses
- domains
- hostnames
- IP addresses
- URLs
- network endpoints
- services
- web endpoints
- certificates
- SSH host keys
- software identities
- DNS observations
- repositories
- organizations
- ASNs

Relationships preserve provenance and confidence instead of silently merging weak identities.

Investigation is passive by default.

Network activity discovered from public-source evidence requires explicit network enablement and scope authorization.

---

## Evidence-First Design

RXScan separates:

```text
observation
    ↓
evidence
    ↓
classification
    ↓
correlation
    ↓
human interpretation
```

This matters because reconnaissance is full of ambiguous signals.

RXScan therefore follows several rules:

- port numbers alone do not create service confidence;
- HTTP success alone does not prove an account exists;
- UDP silence does not prove open or closed;
- weak identity similarity does not automatically merge entities;
- certificate reuse relates assets rather than merging hosts;
- unknown versions remain unknown during vulnerability correlation;
- incomplete coverage does not become a false removal during project diffing.

---

## Scope & Safety

RXScan is intended for systems you own or are explicitly authorized to assess.

Scope is enforced before network contact.

```bash
rxscan example.test --scope example.test
```

Additional authorized scope can be explicitly provided:

```bash
rxscan example.test --scope api.example.test
```

Targets can also be excluded:

```bash
rxscan example.test --exclude api.example.test
```

### Permanent boundaries

RXScan does not provide:

- credential guessing
- password brute force
- authentication bypass
- automatic exploitation
- destructive actions
- malware deployment
- session theft

Public-source investigation does not automatically become active network scanning.

---

## Execution Is Bounded

RXScan is designed to remain bounded even when the requested target space is large.

Controls include:

```text
--max-tasks
--max-retries
--max-concurrency
--max-hosts
--max-execution-time
--max-evidence-bytes
```

For example:

```bash
rxscan example.test --all-ports --max-execution-time 30s
```

When a deadline or resource budget is reached, RXScan preserves partial evidence and reports unscanned work rather than pretending the scan completed.

---

## Output

### Human

Interactive terminals automatically receive RXScan's styled human report.

No theme setup is required.

```bash
rxscan example.test
```

Color behavior can be controlled explicitly:

```bash
rxscan --color auto example.test
rxscan --color always example.test
rxscan --color never example.test
```

`auto` is the default.

`NO_COLOR` is respected.

### Explain

```bash
rxscan example.test --explain
```

`--explain` exposes planning, policy, budgets, fallbacks, and reasoning that are intentionally omitted from the normal findings-first report.

### JSONL

```bash
rxscan example.test --format jsonl
```

or:

```bash
rxscan example.test --output scan.jsonl
```

Machine-readable output remains ANSI-free and is not truncated by human presentation limits.

### Checkpoints

```bash
rxscan example.test --checkpoint scan.rxscan
```

Resume:

```bash
rxscan --resume scan.rxscan
```

---

## Projects & History

RXScan can persist reconnaissance into a project database:

```bash
rxscan example.test --project-db project.db
```

Project intelligence supports persisted evidence, graph relationships, coverage-aware history, classification provenance, and change tracking.

The core rule for historical comparison is:

> **Absence without equivalent coverage is unknown, not removal.**

This prevents incomplete scans from creating false change events.

---

## Intelligence

RXScan can derive bounded intelligence from collected evidence, including:

### Operating system candidates

Passive OS correlation uses observed service/banner evidence.

No active OS fingerprint probe is required.

### Device candidates

Device role/vendor/model inference remains evidence-gated and confidence-bounded.

### SSH identity

RXScan can parse SSH banners and collect bounded host-key evidence without authentication.

### TLS posture

TLS intelligence can include observed certificate and handshake facts such as:

- certificate identity
- certificate reuse
- expiry state
- hostname mismatch
- self-signed state
- deprecated protocol evidence
- weak signature evidence
- short-key evidence

RXScan does not claim exhaustive cipher enumeration.

### Software inventory

Observed services can produce normalized software identities for correlation and history.

### Vulnerability correlation

RXScan supports offline vulnerability correlation against configured datasets.

Matches are potential correlations based on observed software identity/version—not exploitation results or vulnerability verdicts.

---

## Installation

### From source

RXScan requires Rust **1.85 or newer**.

```bash
git clone https://github.com/DarkRX1/RXScan.git
cd RXScan
cargo install --path . --locked
```

Verify:

```bash
rxscan --version
```

### Build manually

```bash
cargo build --release --locked
./target/release/rxscan --help
```

The currently supported/tested runtime target is Linux.

---

## Release

The current published release line is **1.x**.

See:

**GitHub → Releases**

for published versions and release notes.

Historical note: earlier 1.x tags may contain package metadata that predates the corrected 1.x package versioning. Current releases should be evaluated using their committed package metadata and release notes.

---

## Useful Commands

<details>
<summary><strong>Network scanning</strong></summary>

```bash
rxscan example.test
rxscan example.test --ports 22,80,443
rxscan example.test --all-ports
rxscan example.test --udp
rxscan example.test --scan-mode auto
rxscan example.test --explain
```

</details>

<details>
<summary><strong>Public search</strong></summary>

```bash
rxscan search --username exampleuser
rxscan search --username exampleuser --all
rxscan search --username exampleuser --explain
```

</details>

<details>
<summary><strong>Investigation</strong></summary>

```bash
rxscan investigate --username exampleuser
```

</details>

<details>
<summary><strong>Machine output</strong></summary>

```bash
rxscan example.test --format jsonl
rxscan example.test --output scan.jsonl
rxscan example.test --checkpoint scan.rxscan
```

</details>

---

## Capabilities

Inspect capabilities available in the current build/runtime:

```bash
rxscan capabilities
```

RXScan reports capabilities rather than silently assuming they exist.

Platform-, privilege-, and capability-dependent behavior is represented explicitly.

---

## Configuration

RXScan supports global and project configuration:

```bash
rxscan --config rxscan.toml example.test
rxscan --project-config project.toml example.test
```

CLI arguments take precedence where applicable.

---

## Development

Build:

```bash
cargo build --release --locked
```

Run the complete test suite:

```bash
cargo test --locked
```

Engineering gates:

```bash
cargo fmt --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
git diff --check
cargo run -- search lint
```

Tests should prefer deterministic local fixtures over public Internet dependencies.

Network behavior should be proven through local synthetic services whenever practical.

---

## Project Principles

RXScan development follows a few core principles:

**Evidence over assumption.**  
Claims should be traceable to observations.

**Bounded by default.**  
Concurrency, retries, tasks, evidence, and execution time remain controlled.

**Uncertainty is information.**  
Unknown, filtered, blocked, incomplete, and unscanned are meaningful states.

**Passive does not silently become active.**  
Public investigation and network scanning remain distinct unless explicitly bridged.

**Human output is findings-first.**  
The normal terminal tells you what RXScan found and where.

**Machine output is complete.**  
Presentation limits do not discard structured evidence.

**Explainability matters.**  
`--explain` exposes why RXScan planned or classified something the way it did.

---

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for planned work.

---

## Contributing

Contributions should remain evidence-driven, bounded, deterministic, and testable.

When changing network behavior:

- use local fixtures where possible;
- avoid public Internet dependencies in tests;
- preserve scope enforcement;
- preserve cancellation/deadline behavior;
- do not strengthen claims without stronger evidence;
- add regression coverage for behavior changes.

Before submitting changes:

```bash
cargo fmt --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
git diff --check
cargo run -- search lint
```

---

## Authorization

> RXScan is intended only for systems and resources you own or are explicitly authorized to assess.

Scope controls reduce accidental contact, but authorization remains the operator's responsibility.

---

## License

MIT. See [`LICENSE`](LICENSE).

<p align="center">
  <sub>RXScan · Raw Excess Scan · Evidence-driven reconnaissance in Rust</sub>
</p>
