# Evidence model

How RXScan turns observations into claims without overstating them.
Implementation: `src/search.rs` (public-source classification),
`src/terminal.rs` (presentation honesty), `src/web_api.rs` (same core
over HTTP), plus the network evidence pipeline
(`src/service.rs`, `src/web.rs`, `src/tls.rs`, `src/dns.rs`,
`src/graph.rs`). All examples below are synthetic reserved values.

## Observation vs evidence vs conclusion

- **Observation**: something directly seen (a TCP handshake, an HTTP
  status line, a DNS answer, a provider response body).
  Example: `192.0.2.10:443` completed a TCP handshake.
- **Evidence**: an observation recorded with provenance (what module,
  what provider version, what timestamp, what input produced it).
- **Conclusion** (finding): an interpretation of evidence with a
  confidence, e.g. "SSH service on `192.0.2.10:22`" or "possible
  account `exampleuser` on provider P".

Observation != conclusion. Every conclusion must point at the evidence
behind it; `--explain` shows the reasoning that the default
findings-first view omits.

## Provenance

Every piece of evidence carries where it came from: module or
provider ID plus provider version, the input (target, username
`exampleuser`), and when it was seen. Provenance is what lets
`rxscan diff` and history distinguish "observed again" from "seen
once, never re-covered". Presentation filtering (`--all` off) never
removes the underlying machine evidence.

## Confidence and source independence

Confidence grades evidence strength; it is not severity and it never
sums across dependent sources. Corroboration means distinct evidence
classes (e.g. banner content plus a TLS certificate fact), and the
strongest source wins with a cap — piling three copies of the same
observation does not raise confidence. Weak identity evidence never
merges entities: two observations that merely look similar stay
separate until independent evidence justifies a relationship.

## Contradiction

Conflicting evidence is preserved, not averaged away. A provider
claiming "exists" while its absence marker also fires is a definition
bug (lint error), not a tie to break by voting. Shared
infrastructure (one certificate, one IP, one ASN such as `AS64500`)
creates a relationship without implying identical entities.

## Relationship

Relationships link entities with a typed edge and a reason, e.g.
account `exampleuser` —[observed-at]→ `https://example.test/u/exampleuser`.
Edges are bounded, deduplicated (strongest confidence kept), and carry
provenance. Reuse relates; it never silently merges hosts or persons.

## Candidate vs confirmed

- **Confirmed/profile**: an identity-specific public profile observed
  with identity evidence (username-anchored marker, canonical profile
  object, API identity match). Rendered `Profile` / `✓`.
- **Resource**: an identity-specific observed resource that is not
  necessarily a public profile (e.g. a user's public repository list
  at `https://api.example.test/users/exampleuser/repos`). Rendered
  `Resource`.
- **Candidate**: an identity-specific location that has NOT been
  confirmed (`https://example.test/u/exampleuser` fetched but body
  inconclusive). Rendered `Candidate` / `?`. Both `Possible` and the
  stronger-but-still-uncertain `Probable` render in this family:
  status grades identity confidence while URL kind grades what the
  URL observation shows, and neither upgrades the other.
- **Provider endpoint**: a generic homepage or API root with no
  identity content. Never presented as a profile URL.

A generated URL is not an observed profile. HTTP 200 alone confirms
nothing.

## Passive vs active

- **Passive** (default for search/investigation): bounded HTTPS fetches
  of public provider pages plus DNS queries. No port scans, no service
  probes, no TLS probing of discovered infrastructure.
- **Active** (explicit only): network scans against operator-supplied
  targets within scope (`rxscan 192.0.2.10`, `investigate --network
  --scope …` with authorization, `--exposure` enrichment opt-in).

Passive discovery does not automatically authorize or trigger active
scanning. Discovering `192.0.2.10` (or `user@example.test`, or an
organization link) through public evidence only records the entity;
contact beyond passive collection requires an explicit, scoped,
authorized operator decision.

## Five rules with examples

1. **Port 443 != HTTPS proof.** An open TCP port is a transport fact.
   Only an observed TLS handshake / HTTP response on that port (see
   `src/service.rs`, `src/tls.rs`) earns a service identity — and
   even then, product/version require banner or certificate evidence.
2. **UDP silence != closed.** An unanswered UDP probe to
   `192.0.2.10:53` is `open|filtered` uncertainty (see
   `src/udp_discovery.rs`), preserved through retries and reported
   as uncertainty — never as proof of absence.
3. **Username URL != identity proof.**
   `https://example.test/exampleuser` returning 200 with no
   username-anchored marker is at most a candidate, usually unknown.
   Confirmation needs the marker contract in
   `docs/PROVIDER_CONTRACT.md`.
4. **Shared certificate != identical host.** Two hosts presenting the
   same leaf SHA-256 get a shared `cert:sha256` entity with
   `PRESENTS_CERTIFICATE` edges (see `src/graph.rs`) — related, not
   merged.
5. **OSINT-discovered IP != authorization to scan it.**
   `investigate --username exampleuser` resolving a domain to
   `192.0.2.10` stops at `RESOLVES_TO`. Port scanning it requires
   `investigate --network --scope 192.0.2.10/32` plus real-world
   authorization; scope enforcement rejects out-of-scope work before
   contact, and lack of enforcement-bypass is a security-scope issue
   (see `SECURITY.md`).
