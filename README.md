<p align="center">
  <img src="RXScanlogo.png" alt="RXScan" width="360">
</p>

<h1 align="center">RXScan</h1>

<p align="center">
  <b>Reconnaissance &amp; Evidence Engine</b><br>
  Bounded reconnaissance and evidence correlation in Rust.
</p>

<p align="center">
  <a href="https://github.com/DarkRX1/RXScan/releases"><img src="https://img.shields.io/github/v/release/DarkRX1/RXScan?style=flat-square&label=release" alt="release"></a>
  <img src="https://img.shields.io/badge/Rust-1.85%2B-orange?style=flat-square" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square" alt="Linux">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT"></a>
</p>

---

RXScan combines network reconnaissance, public-source search, investigation,
and evidence correlation in one CLI.

It can discover hosts and ports, identify observed services, collect bounded
protocol and web evidence, search public providers, correlate findings, and
persist results for later analysis and comparison.

RXScan is intentionally conservative about what it reports. A port number does
not identify a service, an HTTP success does not by itself confirm an account,
and incomplete coverage is kept distinct from a negative result.

## Quick start

Build and install from the repository:

```bash
git clone https://github.com/DarkRX1/RXScan.git
cd RXScan
cargo install --path . --locked
```

Check the installed build:

```bash
rxscan --version
rxscan --help
```

Run a normal reconnaissance scan:

```bash
rxscan example.test
```

Search public sources:

```bash
rxscan search --username exampleuser
```

Investigate and correlate public findings:

```bash
rxscan investigate --username exampleuser
```

Those are the three main entry points:

```text
rxscan TARGET
rxscan search ...
rxscan investigate ...
```

## Network scanning

The default scan uses the `recon` workflow, level 3, and balanced execution
settings.

```bash
rxscan example.test
```

Specify ports when you want exact port selection:

```bash
rxscan example.test --ports 22,80,443
rxscan example.test --ports 1-1024
rxscan example.test --ports 22,80,443,8000-8100
```

Scan the complete TCP port range:

```bash
rxscan example.test --all-ports
```

UDP discovery is explicit:

```bash
rxscan example.test --udp
```

Show the effective plan and additional execution detail:

```bash
rxscan example.test --explain
```

### TCP scan modes

RXScan supports:

```bash
rxscan example.test --scan-mode auto
rxscan example.test --scan-mode connect
rxscan example.test --scan-mode syn
```

TCP connect scanning is the portable scan path currently used by RXScan on its
supported platform.

Raw SYN scanning is available for IPv4 on Linux when the required capability
is available. When the requested SYN path cannot be used, RXScan reports the
effective fallback rather than silently presenting a connect scan as SYN.

### UDP

UDP scanning uses bounded native probes and remains opt-in.

Current protocol-aware UDP discovery includes small probes for services such as
DNS, NTP, and SSDP.

UDP silence is not reported as proof that a port is open or closed. RXScan
preserves the resulting `open|filtered` uncertainty.

## Service identification

RXScan identifies services from observed protocol behavior instead of assigning
a service solely from its port number.

Current native identification covers common protocols including:

- SSH
- HTTP and HTTPS
- TLS
- FTP
- SMTP
- Redis
- MySQL
- PostgreSQL
- SMB
- RDP
- MongoDB
- MQTT
- bounded unknown-service fingerprints

Depending on the protocol and available evidence, observations may include
product/version information, banners, HTTP endpoints and titles, TLS
certificate facts, SSH identity information, and normalized technology
evidence.

Unknown services remain unknown when RXScan does not have enough evidence to
identify them.

No authentication is required for these identification probes.

## Public-source search

Username search is available through:

```bash
rxscan search --username exampleuser
```

Normal output concentrates on useful positive and uncertain findings instead
of printing every negative provider result.

A finding can distinguish between an observed profile, another observed
resource, and an unconfirmed candidate location.

For example:

```text
FINDINGS

  ✓ provider / exampleuser
    Profile    https://example.test/exampleuser
    high · 94% · public profile

  ? another-provider / exampleuser
    Candidate  https://example.test/u/exampleuser
    low · 25% · weak evidence
```

The labels are intentional:

| Label | Meaning |
| --- | --- |
| `Profile` | observed identity-specific public profile |
| `Resource` | observed identity-specific resource that is not necessarily a public profile |
| `Candidate` | identity-specific location that has not been confirmed |

Generic provider homepages or API endpoints are not presented as confirmed
profile URLs.

RXScan also keeps provider outcomes such as blocked, rate-limited, unknown,
error, and unscanned distinct rather than converting them into false negative
results.

Show the complete human result set with:

```bash
rxscan search --username exampleuser --all
```

Show additional execution and classification detail with:

```bash
rxscan search --username exampleuser --explain
```

## Investigation

Public findings can be passed through RXScan's investigation and correlation
pipeline:

```bash
rxscan investigate --username exampleuser
```

The default view focuses on accounts, useful URLs, confidence, and meaningful
relationships.

Secondary web resources such as static JavaScript, stylesheets, fonts, and
images are retained when relevant to the underlying evidence but do not
dominate the default human report.

Detailed views can expose more of the collected relationship data.

Investigation remains passive by default. Discovering a network target through
public evidence does not automatically authorize or trigger a network scan.

## Evidence and correlation

RXScan stores observations as typed evidence used by its reporting,
investigation, graph, history, and analysis paths.

Several rules are deliberately enforced throughout the project:

- port numbers alone do not establish service identity;
- HTTP `200` alone does not establish that a public account exists;
- UDP silence is uncertainty;
- weak identity evidence does not automatically merge entities;
- shared infrastructure can create relationships without implying identity;
- incomplete coverage is not treated as proof that a previously observed
  entity disappeared;
- presentation filtering does not remove the underlying machine evidence.

This distinction between observation and interpretation is a core part of
RXScan's design.

## HTTP, TLS, and DNS observations

For confirmed web services, RXScan can collect bounded HTTP observations such
as:

- status and headers
- redirects
- page title
- content type and response size
- cookies
- links
- forms
- scripts
- `robots.txt`
- `sitemap.xml`

Workflow and evidence can also permit bounded crawling, baseline checks,
managed content discovery, and contextual GET-query follow-ups.

DNS observation supports bounded record collection including:

- A
- AAAA
- CNAME
- MX
- NS
- TXT
- PTR
- SRV

TLS observation records handshake and certificate evidence. It is not an
exhaustive TLS cipher-suite scanner.

## Scope

Network activity is subject to RXScan's scope policy.

Additional permitted targets can be supplied explicitly:

```bash
rxscan example.test --scope example.test
```

Targets can also be excluded:

```bash
rxscan example.test --exclude api.example.test
```

Out-of-scope work is rejected before the corresponding network contact.

Scope enforcement reduces accidental contact. It does not replace the
operator's responsibility to have authorization.

## Bounded execution

RXScan places limits around work such as scheduling, concurrency, retries,
execution time, host expansion, evidence collection, and follow-up activity.

When a deadline or other execution limit prevents work from running, RXScan
keeps completed evidence and accounts for the remaining work instead of
presenting the run as fully completed.

This also applies to partial network scans.

## Output

Human output is intended for interactive use:

```bash
rxscan example.test
```

Color is automatic when appropriate for the terminal and can be controlled
with:

```bash
rxscan --color auto example.test
rxscan --color always example.test
rxscan --color never example.test
```

`--explain` exposes additional planner, policy, accounting, and reasoning
information that is intentionally omitted from the normal findings-first view.

Machine-readable output is available separately:

```bash
rxscan example.test --format jsonl
rxscan example.test --output scan.jsonl
```

Machine output does not contain terminal ANSI styling.

Scans can also write checkpoints:

```bash
rxscan example.test --checkpoint scan.rxscan
```

## Persistence and offline workflows

RXScan supports persisted evidence and offline workflows including reporting,
analysis, comparison, and project graph operations.

Examples:

```bash
rxscan report scan.rxscan
rxscan diff old.rxscan new.rxscan
```

Historical comparison is coverage-aware. If a later scan did not cover the
same target or evidence surface, absence alone is not interpreted as a
confirmed removal.

## Current platform support

RXScan currently targets Linux.

Raw SYN scanning is Linux/IPv4-specific. Other scan paths and protocol
features have their own capability requirements.

Run:

```bash
rxscan capabilities
```

to inspect what the current build/runtime can use.

Known limitations include:

- active OS fingerprint coverage is limited;
- no NSE-equivalent scripting ecosystem;
- raw SYN is currently Linux IPv4 only;
- TLS observation is not exhaustive cipher-suite enumeration;
- DNS does not currently provide every behavior of a dedicated DNS scanner;
- public-provider coverage is finite and providers change, block, or
  rate-limit without notice — verification states are in
  `rxscan search providers` and `docs/PROVIDER_CONTRACT.md`;
- Windows and macOS are not currently supported targets for the RXScan CLI.

RXScan is a young project. It should not be treated as having the protocol
coverage, fingerprint corpus, platform breadth, or operational history of
long-established network scanners.

## What RXScan does not do

RXScan is a reconnaissance tool, not an exploitation framework.

It does not provide automatic:

- credential brute forcing
- password guessing
- authentication bypass
- destructive actions
- exploitation
- malware deployment
- session theft

Network scanning should only be used against systems you own or are explicitly
authorized to assess.

## Building from source

Requirements:

- Rust 1.85 or newer
- Linux for the currently supported runtime

Build:

```bash
cargo build --release --locked
```

Run:

```bash
./target/release/rxscan --help
```

Test:

```bash
cargo test --locked
```

Full project checks are owned by [`docs/TESTING.md`](docs/TESTING.md)
(canonical gate list). The short version:

```bash
cargo test --locked
cargo run --locked -- search lint
```

Network tests should use deterministic local fixtures rather than depending on
public Internet services.

## Local web interface

RXScan also ships a loopback-only local console served by the binary itself:

```bash
rxscan web
rxscan web --port 8901
rxscan web --no-open
```

The application lives at `/` (with `/app` as an alias) and the versioned
typed API at `/api/v1` on the same origin. Binding defaults to loopback;
remote binding requires the explicit dangerous `--allow-remote` flag and is
never recommended.

## Releases

Published releases and their notes are available on the
[GitHub Releases](https://github.com/DarkRX1/RXScan/releases) page.

The `v1.0.0` and `v1.0.1` tags were published with incorrect `0.1.0` Cargo
package metadata. Those historical tags are intentionally left unchanged.

`v1.0.2` is the first correctly versioned 1.x release.

Development on `master` may contain changes newer than the latest published
release.

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md).

The roadmap describes planned work and should not be read as a list of current
capabilities.

## Documentation

README is an index; details live in `docs/`:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — CLI/Web/Core map and flows
- [`docs/EVIDENCE_MODEL.md`](docs/EVIDENCE_MODEL.md) — observation, confidence, candidate vs confirmed
- [`docs/PROVIDER_CONTRACT.md`](docs/PROVIDER_CONTRACT.md) — verification states and evidence rules
- [`docs/SEARCH_CORPUS.md`](docs/SEARCH_CORPUS.md) — dynamic counts and scale design
- [`docs/TESTING.md`](docs/TESTING.md) — exact gates, local vs hosted CI
- [`SECURITY.md`](SECURITY.md) — reporting, boundaries, non-goals
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution requirements
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — planned work (not current capabilities)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Keep changes bounded, evidence-driven, and testable.

For network behavior, prefer deterministic local fixtures. Avoid tests that
depend on arbitrary public services.

New detection claims should have executable evidence behind them, and changes
to scanning behavior should preserve scope, deadlines, cancellation, partial
results, and accounting.

## License

MIT. See [`LICENSE`](LICENSE).
