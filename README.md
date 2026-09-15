# RXScan

RXScan - Raw Excess Scan.
Fast, bounded reconnaissance in Rust.

## What It Does

RXScan normalizes a target, enforces scope, performs bounded host discovery,
scans TCP ports with native connect probes, identifies services from observed
protocol behavior, and records typed evidence for later reporting, diffing,
analysis, and project graph workflows.

Current scanning includes:

- host discovery with ICMP echo and TCP reachability evidence
- TCP connect scanning for default, explicit, range, mixed, and all-port sets
- service probing for SSH, HTTP, TLS/HTTPS, FTP, SMTP/SMTPS, Redis, MySQL,
  PostgreSQL, and bounded unknown-service fingerprints
- HTTP observations for status, headers, redirects, title, content type,
  response size, cookies, links, forms, scripts, robots.txt, and sitemap.xml
- DNS observations for A, AAAA, CNAME, MX, NS, TXT, and PTR records
- bounded crawling, baseline response checks, managed content discovery, and
  inert contextual GET query fuzzing when confirmed web evidence permits
- JSONL output, checkpoints/resume, offline diff, offline analysis, offline
  reports, and an offline project graph

## Quick Start

```bash
rxscan TARGET
rxscan --ports 22,80,443 TARGET
rxscan --ports 1-1024 TARGET
rxscan --all-ports TARGET
rxscan --goal web TARGET
rxscan --explain TARGET
```

The default `rxscan TARGET` scan uses goal `recon`, level `3`, balanced speed,
bounded host discovery, and TCP scanning against a level-derived common set.

## Installation

RXScan is currently a prerelease source build. Tested release artifacts are not
published yet.

```bash
cargo install --path . --locked
rxscan --version
```

Requires Rust 1.85 or newer. The currently tested runtime target is Linux
x86_64.

## Examples

```bash
rxscan 127.0.0.1 --scope 127.0.0.1 --ports 22,80,443
rxscan 127.0.0.1 --scope 127.0.0.1 --ports 8000-8100
rxscan example.test --goal services --level 4 --speed 70
rxscan https://example.test --goal web --checkpoint scan.rxscan --output scan.jsonl
rxscan report scan.rxscan
rxscan diff old.rxscan new.rxscan
```

Only scan systems you own or are explicitly authorized to assess.

## Default contract (`rxscan TARGET`)

The default scan is workflow `recon`, level `3`, balanced speed. It always:

- normalizes the target and enforces deny-by-default scope;
- runs bounded host discovery (lightweight: ICMP echo x2 plus TCP
  reachability on 22, 80, 443);
- runs TCP discovery over exactly `common-100` (100 ports, profile `v1`);
- runs service identification for every open port found;
- runs evidence-triggered follow-ups the evidence justifies at Recon/Level 3
  (identified HTTP(S) services -> web observation; confirmed endpoints ->
  crawl/baseline/content);
- prints a human summary whose counts come from the same typed
  `PortScanCompleted` / `ServiceIdentified` state as JSONL.

It never: scans UDP unless `--udp` is passed, enumerates TLS ciphers, fingerprints OS/devices,
authenticates, submits forms, runs JavaScript, assesses vulnerabilities,
fuzzes (fuzz follow-ups require workflow `full`), or exceeds its budgets.
Default behavior depends only on this contract, never on accidental planner
details; `rxscan --explain TARGET` shows the effective plan.

UDP discovery (`--udp`, explicit opt-in) uses connected sockets, a bounded
socket window, and tiny protocol probes (DNS/NTP/SSDP); silence is reported
as `open|filtered` uncertainty, never as open or closed.

## Scan Controls

`TARGET` may be an IP address, hostname, URL, CIDR, `-` for standard input, or
targets supplied with `--targets FILE`.

`--goal` selects a canonical workflow: `recon` (default), `discover`,
`ports`, `services`, `web`, or `full`. Historical names (`discovery`,
`service-map`, `inventory`, `baseline`, `monitoring`, `web-discovery`,
`api`, `api-discovery`, `content`, `fuzz`, `research`, `custom`) remain
accepted as compatibility aliases; `--explain` shows the canonical workflow
they map to.

`--level 1-5` controls breadth and depth. `--speed slow|balanced|fast|auto|0-100`
controls execution pressure only. Speed changes concurrency, timeouts, and
retry pacing; it does not change the intended ports or findings.

`--ports` accepts single ports, comma lists, ranges, and mixed input such as
`22,80,443,8000-8100`. Explicit ports are operator intent and are not replaced
by goal defaults. `--all-ports` scans TCP ports 1 through 65535 as one bounded
port-discovery task, not 65535 scheduler tasks.

Default TCP policy:

- level 1: validation-focused unless ports are explicit
- level 2 through 3: `common-100`
- level 4 through 5: `common-1000`, the well-known range 1-1000

Higher levels deepen service, DNS, web, content, crawl, and fuzz follow-up
within fixed bounds.

`--scope` adds permitted hosts, URLs, IPs, or CIDRs. `--exclude` removes them.
Out-of-scope work is rejected before network contact.

## Output

Normal output is human-readable and derived from the same typed state used for
JSONL and checkpoints.

```text
RXScan

Target: 127.0.0.1
Workflow: recon
Level: 3
Speed: Balanced

HOST 127.0.0.1
PORT      SERVICE     PRODUCT
22/tcp    ssh         OpenSSH
8080/tcp  http        nginx

TCP discovery (level-automatic): 100 requested, 100 attempted, 2 open, 98 closed, 0 filtered/timed out, 0 errors, 0 unscanned [TCP scan time: 13ms max per task]
Services: 2 identified
Duration: 412ms

Diagnostics
  tasks: 5 completed, 0 failed, 0 cancelled, 0 timed out, 0 skipped
  jsonl bytes: 0
```

Machine output:

```bash
rxscan TARGET --format jsonl
rxscan TARGET --output scan.jsonl
rxscan TARGET --checkpoint scan.rxscan
```

## Current Capabilities

Working: target normalization, scope guard, bounded scheduler, speed governor,
host discovery, native TCP connect scanning, service probes, TLS observation,
DNS observation, HTTP probing, crawling, content discovery, contextual GET
fuzzing, persistence/resume, diff, analysis, reporting, and project graph.

Partial: adaptive pressure control is deterministic rather than feedback-driven;
TLS captures handshake and certificate facts but not cipher-suite enumeration;
DNS has bounded record lookups but no TCP fallback after UDP truncation.

Not implemented: SYN scanning, OS/device fingerprinting,
browser-assisted inspection, POST workflows, vulnerability assessment,
prebuilt release artifacts, Windows/macOS support, GUI, plugins, and updater.

Permanent boundaries: no automatic exploitation, no destructive actions, and no
credential brute forcing.

## Roadmap

See `docs/ROADMAP.md` for planned scanner, distribution, and product work.

## Authorization

RXScan is for systems you own or are authorized to test. Scope controls are
enforced by the scanner, but authorization is still the operator's
responsibility.

## Building From Source

```bash
cargo build --release --locked
./target/release/rxscan --help
cargo test --locked
```

The release check is:

```bash
scripts/release-check.sh
```

## Contributing

Keep changes evidence-driven and bounded. Add local fixtures for network
behavior, avoid public Internet dependencies in tests, and do not claim
protocol or platform support without executable proof.

## License

MIT. See `LICENSE`.
