<p align="center">
  <img src="RXScanlogo.png" width="360" alt="RXScan">
</p>

<h1 align="center">RXScan</h1>

<p align="center">
  <b>Raw Excess Scan</b><br>
  Fast, bounded reconnaissance in Rust.
</p>

<p align="center">
  <a href="https://github.com/DarkRX1/RXScan/releases"><img src="https://img.shields.io/github/v/release/DarkRX1/RXScan?style=flat-square" alt="release"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-orange?style=flat-square" alt="rust">
  <img src="https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square" alt="linux">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="license"></a>
</p>

---

RXScan is a reconnaissance tool for network discovery, service identification,
public-source search, and evidence correlation.

It keeps observations typed and bounded so scan results can be explained,
persisted, compared, and correlated without turning weak signals into stronger
claims than the evidence supports.

```text
search → discover → scan → identify → correlate → persist
```

## Install

RXScan requires Rust 1.85+ and currently targets Linux.

```bash
git clone https://github.com/DarkRX1/RXScan.git
cd RXScan
cargo install --path . --locked
```

Check the installation:

```bash
rxscan --version
rxscan --help
```

Published versions are available under
[Releases](https://github.com/DarkRX1/RXScan/releases).

## Usage

A normal scan needs only a target:

```bash
rxscan example.test
```

Common variations:

```bash
# selected ports
rxscan example.test --ports 22,80,443

# port range
rxscan example.test --ports 1-1024

# full TCP range
rxscan example.test --all-ports

# opt-in UDP discovery
rxscan example.test --udp

# show the effective plan and reasoning
rxscan example.test --explain
```

Public-source username search:

```bash
rxscan search --username exampleuser
```

Investigation:

```bash
rxscan investigate --username exampleuser
```

Machine-readable output:

```bash
rxscan example.test --format jsonl
rxscan example.test --output scan.jsonl
rxscan example.test --checkpoint scan.rxscan
```

## What the output looks like

RXScan's default output is findings-first. Diagnostic and planner detail stays
behind `--explain`.

```text
RXSCAN / RECON

TARGET

  Host        example.test
  Profile     Level 3 · Balanced
  Duration    184ms

PORTS

  22/tcp   OPEN   SSH
    Product    OpenSSH
    Version    9.x

  443/tcp  OPEN   HTTPS
    Endpoint   https://example.test/
    Product    nginx
    TLS name   example.test

SUMMARY

  TCP      100 attempted · 2 open
  Services 2 identified
```

Search output follows the same rule:

```text
RXSCAN / PUBLIC SEARCH                              PASSIVE

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

COVERAGE

  Completed    99 / 100
  Confirmed    13
  Possible     11
```

`Profile`, `Resource`, and `Candidate` have different meanings. RXScan does not
present a generated or generic provider URL as though it were an observed
profile.

## Scanning

The default:

```bash
rxscan example.test
```

runs the `recon` workflow at level 3 with balanced execution pressure.

It performs bounded host discovery, scans the level-derived TCP set, identifies
open services, and runs follow-ups justified by the resulting evidence.

Explicit ports always override the automatic set:

```bash
rxscan example.test --ports 22,80,443,8000-8100
```

TCP scan mechanism can be selected with:

```bash
rxscan example.test --scan-mode auto
rxscan example.test --scan-mode connect
rxscan example.test --scan-mode syn
```

`auto` uses raw SYN where the current platform and privileges permit it and
falls back to connect scanning otherwise. The requested mode, effective
mechanism, and fallback reason are recorded rather than hidden.

UDP is never enabled implicitly:

```bash
rxscan example.test --udp
```

UDP responses are classified conservatively. In particular, silence is
`open|filtered` uncertainty rather than proof of an open or closed port.

## Service identification

RXScan identifies services from observed protocol behavior rather than port
numbers alone.

Current probes include:

| Area | Support |
| --- | --- |
| SSH | banner and host-key evidence |
| HTTP / HTTPS | status, headers, redirects, title, links and web metadata |
| TLS | handshake and certificate observations |
| FTP / SMTP | bounded protocol identification |
| Redis | unauthenticated identification |
| MySQL / PostgreSQL | handshake identification |
| SMB / RDP | protocol identification |
| MongoDB / MQTT | protocol identification |
| Unknown services | bounded generic fingerprints |

No authentication is performed by these probes.

Web evidence can trigger bounded crawling, baseline checks, managed content
discovery, robots/sitemap inspection, and other workflow-dependent follow-ups.

## Search and investigation

RXScan also has a public-source search pipeline:

```bash
rxscan search --username exampleuser
```

Normal output emphasizes useful findings. Use `--all` for the full human result
set:

```bash
rxscan search --username exampleuser --all
```

or `--explain` for execution/classification detail:

```bash
rxscan search --username exampleuser --explain
```

Search outcomes preserve uncertainty:

```text
confirmed
possible
not found
unknown
blocked
rate limited
auth required
error
cancelled
unscanned
```

A successful HTTP response alone is not enough to confirm an account.

Investigation correlates collected evidence:

```bash
rxscan investigate --username exampleuser
```

The default view keeps the useful account/resource relationships visible while
secondary web assets stay out of the way. Complete evidence remains available
through detailed and machine-readable output.

Investigation is passive unless network activity is explicitly enabled and
authorized by scope.

## Scope

Network contact is scope-checked before execution.

```bash
rxscan example.test --scope example.test
```

Additional permitted targets can be added explicitly:

```bash
rxscan example.test \
  --scope example.test \
  --scope api.example.test
```

Exclusions are applied before network contact:

```bash
rxscan example.test --exclude api.example.test
```

RXScan does not automatically scan infrastructure simply because a public
search discovered a relationship to it.

## Execution bounds

Scanning is deliberately bounded.

Depending on the workflow, limits cover concurrency, tasks, retries, hosts,
execution time, evidence size, crawling, content discovery, and follow-up work.

For example:

```bash
rxscan example.test --all-ports --max-execution-time 30s
```

When execution is cut short, RXScan retains partial evidence and accounts for
work that was not scanned. It does not report an incomplete run as complete.

## Evidence model

A few rules matter throughout the codebase:

- a port number does not identify a service;
- HTTP 200 does not confirm a public account;
- UDP silence does not mean open;
- weak identity matches are not automatically merged;
- shared certificates and SSH keys create relationships, not identity;
- missing data without equivalent coverage is not treated as removal;
- human formatting never changes the underlying machine evidence.

This is also why normal output distinguishes things such as:

```text
Profile     observed identity-specific profile
Resource    observed account/resource endpoint
Candidate   identity-specific location not confirmed
unknown     insufficient service evidence
unscanned   work not executed
```

## Persistence

Scans can be checkpointed:

```bash
rxscan example.test --checkpoint scan.rxscan
```

RXScan also supports persisted project data, offline reporting, analysis,
diffing, graph relationships, and per-entity explanation.

Examples:

```bash
rxscan report scan.rxscan
rxscan diff old.rxscan new.rxscan
```

Project/history logic is coverage-aware so a smaller follow-up scan does not
silently turn unseen assets into removals.

## Current support

**Working**

- target normalization and deny-by-default scope enforcement
- ICMP/TCP host discovery
- ARP/NDP and local-neighbor evidence
- TCP connect scanning
- Linux IPv4 raw SYN
- bounded native UDP discovery
- service identification
- HTTP, TLS and DNS observation
- crawling and managed content discovery
- public-source username search
- investigation and evidence correlation
- checkpoints and resume
- JSONL
- offline analysis/reporting/diff
- project graph and entity explanation

**Known limits**

- raw SYN is Linux IPv4 only
- TLS observation is not exhaustive cipher-suite enumeration
- DNS does not currently retry truncated UDP responses over TCP
- active OS/device fingerprint probes are not implemented
- browser-assisted inspection and POST workflows are not implemented
- Windows and macOS are not currently supported

Run:

```bash
rxscan capabilities
```

to inspect capabilities for the current build/runtime.

## Safety

RXScan is for systems and resources you own or are explicitly authorized to
assess.

It intentionally does not provide:

- credential brute forcing
- authentication bypass
- automatic exploitation
- destructive actions
- malware deployment
- session theft

Scope enforcement helps prevent accidental contact. It does not replace the
operator's responsibility to have authorization.

## Development

```bash
cargo build --release --locked
cargo test --locked
```

Full engineering gates:

```bash
cargo fmt --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
git diff --check
cargo run -- search lint
```

Network tests should use deterministic local fixtures instead of depending on
public Internet services.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for planned work.

## Contributing

Keep changes bounded and evidence-driven.

If a change adds or strengthens a claim, add executable evidence for that claim.
If it changes network behavior, test cancellation, deadlines, accounting, and
scope. Prefer local protocol fixtures over external dependencies.

## License

MIT — see [`LICENSE`](LICENSE).
