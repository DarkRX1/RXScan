# Security Policy

RXScan is prerelease software (v0.1.0). It is built for authorized,
scoped, non-destructive reconnaissance and ships no exploit, credential,
or evasion capability.

## Supported status

Best-effort maintainer response on the latest prerelease commit. No
long-term-support branch exists yet.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not
disclose it publicly before the maintainer responds. Contact the
maintainer through the private channel by which you obtained RXScan
(for repository checkouts, use the hosting provider's private
vulnerability-reporting feature if enabled for this repository).

No dedicated security contact address is published in this file; do not
trust one quoted from any other source.

## Scope of interest

Unsafe blocks (documented in the release notes), scope enforcement,
parser hardening (DNS/HTTP/TLS/JSON/TOML), file-atomicity paths, and
dependency supply chain (`cargo tree`, `Cargo.lock`).
