# Security Policy

RXScan 1.x is built for authorized, scoped, non-destructive reconnaissance
and ships no exploit, credential, or evasion capability.

## Supported status

Best-effort maintainer response on the latest published release and on
current `master`. No long-term-support branch exists yet.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not
disclose it publicly before the maintainer responds. Use the hosting
provider's private vulnerability-reporting feature for this repository
(GitHub Security Advisories / private reporting) so the report stays
confined to the maintainer.

No dedicated security contact address is published in this file; do not
trust one quoted from any other source.

## Scope of interest

Real secrets or credential material, scope bypasses, server-side request
forgery via provider definitions or investigation inputs, unsafe provider
definitions, command execution, parser vulnerabilities (DNS/HTTP/TLS/
JSON/TOML), file-atomicity paths, sensitive-data persistence, and
dependency/supply-chain problems (`cargo tree`, `Cargo.lock`).

## Secret handling

A publicly committed secret is compromised: rotate/revoke it rather than
relying on removal from `HEAD`. Historical exposure remains retrievable
from Git history and published tags; rotation/revocation is the security
boundary.

## Security boundaries

- Passive public-source collection (`search`, default `investigate`):
  bounded HTTPS fetches of public provider pages plus DNS queries. No
  port scans, no service probes, no authentication, no CAPTCHA/rate-limit
  evasion, no proxy rotation, no private/internal destinations (every
  redirect hop is resolved, validated, and pinned).
- Active network contact (scan workflows, `investigate --network
  --scope`, `--exposure` enrichment): only against operator-supplied,
  in-scope, authorized targets. Passive discovery does not automatically
  authorize or trigger active scanning — a discovered IP stops at
  `RESOLVES_TO` until an explicit scoped decision is made.
- Scope controls: deny-by-default Scope Guard enforced at lowering,
  admission, promotion, and dispatch; derived addresses re-checked and
  never expand scope. Out-of-scope work is rejected before contact.
- Provider HTTP restrictions / SSRF protections: `https://` only,
  bounded redirects (≤5) with per-hop scope checks, bounded bodies,
  per-provider timeouts. Unsafe provider definitions are a
  vulnerability-reportable issue.
- Loopback GUI/API (`rxscan web`): binds `127.0.0.1` by default; the
  `Host` header must be loopback and unsafe methods require an absent
  or loopback `Origin` (no CORS emitted). Non-loopback bind requires
  the explicit dangerous `--allow-remote` flag and stays
  unauthenticated — never expose it to a network. There is no command
  execution endpoint. Provider-controlled values render as text, never
  as HTML/commands.
- Cancellation/deadlines: Ctrl+C reaches the real scheduler; API jobs
  cancel through `/api/v1/jobs/:id/cancel`; partial evidence is kept
  and unfinished work is accounted, never fabricated as complete.

## Non-goals (not provided, not planned as capabilities)

Credential guessing, brute force, authentication bypass, exploitation,
stolen-credential ingestion, anti-bot bypass/evasion, destructive
actions, malware deployment, session theft.
