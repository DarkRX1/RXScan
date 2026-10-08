# OS Fingerprinting

RXScan infers operating systems from evidence, never from a single hint.
The product is the evidence graph; the OS label is a conclusion over that
evidence, reported with confidence, coverage, conflicts, gaps, and
provenance — or as `Unknown` when the evidence cannot support a claim.

## What it does

- Collects typed OS observations (network-stack facts plus contextual
  service/application hints) with address family, probe identity,
  provenance, and quality attached.
- Matches observations against versioned data-driven fingerprint packs
  (`fingerprints/os/v1/*.json`, overridable with `RXSCAN_OS_DIR`).
- Scores deterministically: same evidence + same corpus = same result,
  regardless of evidence or fingerprint order.
- Explains every candidate: matched evidence, conflicting evidence,
  unavailable evidence kinds, coverage, and provenance labels.
- Persists structured OS evidence to project databases and the
  correlation graph; history diffs treat OS changes cautiously
  (evidence changed vs. host OS definitely changed).

## Invocation

```bash
rxscan 192.0.2.10 --os
rxscan 192.0.2.10 --os --explain
rxscan capabilities
```

`--os` is explicit and off by default: recon defaults never become
silently more active. The web GUI and API expose the same core through
the `os` scan option and the `operating_systems` result field; no
scoring is duplicated in JavaScript. Machine output streams typed
`os_candidate` JSONL records (additive; deterministic ordering; no ANSI).

## Active probe plan

Small, bounded, explainable. Per in-scope host, at most
`MAX_OS_PROBES_PER_HOST` (6) probes:

1. Reuse one proven-open TCP port from scan evidence (handshake sample).
2. Reuse one proven-closed TCP port (reset-behavior sample).
3. Fill only the remainder from a deterministic fallback set
   (`80, 443, 22`) — never an all-ports scan, no retries, no expansion.
4. ICMP echo rides the same budget only where the platform supports it.

If open/closed-port evidence is unavailable, the plan records what was
missing, lowers coverage/confidence, and returns `Unknown` when needed.

Safety contract: normal TCP/ICMP observations only. No exploitation,
authentication attempts, brute force, fuzzing, evasion, spoofing,
amplification, or destructive packets. `ScopeGuard` stays authoritative
(out-of-scope targets see zero network activity), cancellation and
deadlines bound the phase, and no privilege escalation is attempted.

## Privileged vs unprivileged

The inference engine runs on whatever evidence exists. Raw header
observation (TTL/Hop Limit, window, MSS, options) requires the
raw-packet capability. When it is unavailable, the run degrades
honestly: passive evidence remains, coverage/confidence drop, the
limitation is exposed in human output, JSONL, and capabilities — the
workflow never fails.

`rxscan capabilities` reports the OS inference engine, the active-probe
state (with the exact runtime reason), and the dynamic `os_corpus`
count. Counts are always loaded from the packs, never hard-coded.

## Observed vs derived

`OBSERVED`: "received IPv4 TTL = 64".
`DERIVED`: "compatible initial-TTL families: A/B".

Derived values are reasoning, never persisted as observations. Routing,
NAT, proxies, load balancers, firewalls, tunnels, virtualization, and
middleboxes can alter or obscure stack evidence; the scorer tolerates
contradictory and incomplete evidence, and explicit contradictions can
veto candidates.

## Confidence

Shared with project intelligence bands: `high` (≥75), `medium` (≥50),
`low` (<50), `unknown` (no defensible evidence). One TTL observation or
one service banner can never report high confidence: lone application
hints cap at 65, and anything above 70 requires at least two
independent evidence classes. Exact OS versions are reported only when
evidence genuinely distinguishes them; otherwise the family stands
alone. The global OS ceiling is 90 — broad classification, never
false precision.

## Corpus reality (development master)

The production corpus (`fingerprints/os/v1/`) currently holds
banner/service-context rules (SSH banners, HTTP server tokens, service
products) with small, defensible weights. There are deliberately no
network-stack rules (TTL/window/option-order signatures): those require
RXScan-controlled measured fixtures or lab captures with documented
provenance, and inventing them from "sounds right" defaults is
forbidden. Synthetic packs exist only in tests and are never presented
as real OS knowledge.

Corpus validation rejects duplicate IDs (within and across packs),
invalid schema versions, impossible ranges, invalid weights, unbounded
strings, and missing provenance; unknown observation keys are linted
and classify at most as weak hints. Counts are dynamic everywhere.

## Limitations (stated plainly)

OS inference can be affected by NAT, proxies, load balancers,
firewalls, packet normalization, tunnels, virtualization, unusual
kernel/network configuration, routing distance (TTL/Hop Limit decay),
insufficient open/closed-port evidence, and unavailable raw-socket
privileges. IPv6 models Hop Limit with distinct semantics; where a
probe family is unsupported on a platform it is reported unavailable,
never faked. Windows/macOS builds stay clean through the capability
boundary even when raw capture is a Linux-only path.
