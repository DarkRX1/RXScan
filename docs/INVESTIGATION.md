# RXScan passive investigation (Phase D)

`rxscan investigate` turns isolated username-search observations into a
bounded, explainable reconnaissance graph. It is **public/passive by
default** and **never port scans** infrastructure discovered during
investigation.

## Search vs investigate

| | `rxscan search` | `rxscan investigate` |
| --- | --- | --- |
| Question | Does this username exist on these providers? | Starting from this public identifier, what public entities exist, how are they related, and why? |
| Output | Per-provider outcomes + account graph | Evidence graph: entities, relationships, provenance, budgets |
| Contact | Bounded HTTPS to provider profile pages | Bounded HTTPS profile fetches + DNS queries |
| Network scan | Never | Never (passive default) |

Investigation reuses the search subsystem for `Username -> Account`; it
does not implement a second username scanner.

## Passive vs direct network

Default contact classes: `passive_public`, `public_http`, `dns_query`.
DNS resolution is a `DnsQuery`, not a scan.

Forbidden by default: `direct_network`, `authenticated_api`. A
discovered `IpAddress` **stops** at `RESOLVES_TO` — it never triggers SYN
scans, service probes, or TLS probing unless the operator passes the
explicit opt-in `investigate --network --scope CIDR` bridge (authorized
targets only) or `--exposure` enrichment. Passive remains the default.

`rxscan investigate --username exampleuser` does **not** port scan
anything. Ever.

## Workflow

```text
rxscan investigate --username exampleuser [--depth N] [--explain]
rxscan investigate --username exampleuser --depth 3 --json
rxscan investigate --username exampleuser --depth 3 --jsonl
rxscan investigate --username exampleuser --project-db project.db
rxscan investigate --domain example.test --explain
rxscan investigate --url https://example.test/ --explain
rxscan investigate transforms [--json]
```

Username investigation is the primary path. Domain and URL seeds exist
only where the transform graph cleanly supports them.

## Transforms

| ID | Accepts | Produces | Contact | Depth cost |
| --- | --- | --- | --- | --- |
| `username_to_account` | username | account | public_http | 1 |
| `account_to_url` | account | url, email | public_http | 1 |
| `url_to_domain` | url | domain, ip | passive (pure) | 0 |
| `url_to_repository` | url | repository, organization | passive (pure) | 0 |
| `domain_to_dns` | domain | ip, hostname, dns_record | dns_query | 1 |

Pure transforms cost zero depth: the domain behind a URL appears at the
same depth as the URL itself. Entity creation is never network contact.

Only meaningful positive search outcomes (`confirmed`/`probable`/
`possible`) become `HAS_ACCOUNT` relationships. `not_found`, `blocked`,
`unknown`, `rate_limited`, and friends stay observations, never accounts.

Profile extraction keeps only explicit links (canonical profile URL,
`href`/`src` links, bare `https://` URLs) plus clearly public emails.
Full HTML is never retained. Repositories are identities only (owner,
name, URL, organization) — nothing is cloned, no history is scraped.

## Depth semantics

```text
depth 0: seed only
depth 1: Username -> Account
depth 2: Account -> Url / Domain / Repository
depth 3: Domain -> DNS / Hostname / IP
```

Default depth is 2; maximum is 5. DNS-derived hostnames are recorded but
never re-expanded (no subdomain brute-forcing, no namespace
enumeration). Cycles are prevented per `(transform, entity)` pair, not by
depth alone.

## Budgets

Defaults: 500 entities, 1000 relationships, 150 HTTP requests, 100 DNS
queries. Hard ceilings: 5000 / 10000 / 1000 / 1000. Search provider
requests performed inside an investigation count toward the HTTP budget.
When a budget is reached, expansion stops, the partial graph is
preserved, and truncation is reported with one or more reasons:
`entity_budget`, `relationship_budget`, `http_budget`, `dns_budget`,
`deadline`, `cancellation`.

`--explain` is plan-only: it contacts nothing.

## Confidence and identity discipline

Each relationship carries its own evidence-derived confidence (explicit
profile website: strong; username merely in page text: weak). Confidence
is never merged across hops. Sharing a username, display name, avatar,
or domain word is evidence of reuse, never proof of identity — accounts
are never auto-merged, and no person entities are inferred.

## Provenance and explanation
Every entity and relationship records source entity, transform ID,
provider/source, contact class, timestamp, evidence, confidence, and
depth. `explain_entity` walks the chain back to the seed, e.g.:

```text
1. username:exampleuser (operator-supplied seed)
2. --has_account--> account:provider-a:exampleuser (profile markers matched)
3. --links_to--> endpoint:https://example.test/ (explicit profile link)
4. --references--> domain:example.test (URL host)
```

## Structured output

- `--json`: full report (run metadata, seed, entities, relationships,
  observations, accounting, budgets, truncation, `network_scans: 0`,
  `pivots`).
- `--jsonl`: typed records (`investigation_start`, `entity`,
  `relationship`, `observation`, `investigation_summary`), one valid JSON
  object per line, deterministic order, no ANSI, graceful broken pipe.
- Human output is bounded (top accounts/links, correlations, pivots,
  truncation); use `--all` or JSON/JSONL for complete data.

## Suggested pivots

`report.pivots` (core `suggest_pivots`, shared by CLI, `--json`, and the
Web `/api/v1/investigations` job result) answers "what can I investigate
next, and why?" Every pivot cites one observed relationship:

```text
api.example.test
  reason: observed certificate SAN
  source: certificate transparency
  state: observed historical/passive evidence
  action: investigate
```

Rules:

- seed and already-expanded entities are never suggested;
- same investigated name under another entity kind is not a new lead;
- IP pivots are `network_candidate: true` with
  `action: investigate (passive); scan requires explicit --network --scope`
  — discovery never authorizes contact, and no pivot is ever an
  authorized scan by itself;
- bounded (`MAX_INVESTIGATE_PIVOTS = 32`, 10 shown by default), sorted by
  `(target_kind, target_value)`, deterministic across reloads;
- a pivot is a lead, never a finding: pivot confidence caps at 90 and the
  state is always observed evidence, never confirmed identity.

## Project persistence

`--project-db project.db` persists the investigation run, seed, entities,
relationships, evidence, provenance, and truncation into the existing
versioned SQLite project graph (no second database). Coverage records
which transforms and DNS names actually completed, so later diffs report
`UNKNOWN` for uncovered providers instead of inventing removals:

- new account / removed link / new domain / new repository / changed DNS
  are derived from consecutive persisted runs;
- a provider blocked in the later run yields `UNKNOWN`, never
  "account removed".

## Security boundaries

- HTTPS-only contact (loopback HTTP exists only in fixture tests);
  `file:`, `ftp:`, `data:`, `javascript:`, and custom schemes are never
  contacted.
- Literal loopback / RFC1918 / link-local / special addresses are never
  contacted; observed URLs stay text/entities at most.
- Every redirect destination repeats DNS validation and address pinning
  inside the hardened search HTTP client (same policy as search — no
  weaker second client, no DNS-rebinding regression).
- No telemetry: graphs, seeds, and results stay local.

All examples use reserved/synthetic values (`example.test`,
`192.0.2.10`, `2001:db8::10`).

## Observation classes (Stage 4)

Every relationship carries `observation_class`:

```text
observed  directly seen evidence (provider confirmed account,
          profile contains link, DNS answered)
derived   normalization of observed data (URL host to domain,
          forge URL pattern to repository identity)
inferred  interpretive verdicts only; the transform engine never emits
          these, and they are never presented as observed fact
```

## Exposure enrichment (Stage 3)

```bash
rxscan investigate --username exampleuser --exposure
```

Opt-in defensive exposure lookup for the seed identifier. External
providers that receive identifiers run only with `--exposure`; see
`docs/EXPOSURE.md`. Secrets are never retained; the human summary ends
with `secrets stored: 0`.

## DOT export (Stage 4)

Library function `investigate::render_dot` renders the evidence graph in
DOT format (deterministic, bounded). GraphML is deferred.

## Project history (Stage 5)

```bash
rxscan project-db diff --db project.db <old-run> <new-run>
rxscan project-db explain --db project.db domain:example.test
```

Consecutive investigation persists diff as Added/Removed at both
entity and relationship level. Removal is coverage-gated per producing
transform: an account missing from the new run reads as Removed only
when the new run completed `investigate.username_to_account`; a
truncated, blocked, or deadline-cut run leaves UNKNOWN, never a fake
disappearance. Every investigation run carries a unique run id, so
same-second reruns append history instead of overwriting it.

## Authorized network bridge (Stage 6)

```bash
rxscan investigate --username exampleuser --network --scope example.test
```

All of the following are required together, or no network contact
happens: explicit `--network`, explicit valid `--scope` (repeatable;
`--exclude` removes), Scope Guard authorization per IP, and pivot
budget (`--max-network-pivots`, default 10, hard max 100).

Pivot candidates are DNS-derived IP addresses only. Out-of-scope
addresses stay graph entities (`pivot_authorized=false`) and are never
contacted. Each probed IP consumes one pivot unit and performs bounded
TCP connect checks over ports 80, 443, 22, 8080, 8443 — host discovery
plus port presence only. There is no service probing, no TLS/SSH
handshake, and no UDP work in pivots; silence is uncertainty, never a
negative claim. Every pivot is recorded as a `network_pivot`
observation; open ports become `Port` entities with `LISTENS_ON` edges.
`--explain` shows the bridge plan without contacting anything.
