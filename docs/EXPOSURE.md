# RXScan defensive exposure intelligence (Stage 3)

`rxscan exposure` correlates an operator-supplied identifier against
legitimate, configured exposure sources: breach intelligence,
infostealer/malware observations, credential- and session-exposure
indicators, paste exposures, and operator-supplied local datasets.

## Non-goals (hard boundaries)

RXScan does not scrape criminal leak forums, bypass access controls, or
provide a credential marketplace interface. Exposure may report that
credential/session material was exposed; it must never extract, display,
persist, or replay that material.

## Usage

```bash
rxscan exposure --email user@example.test
rxscan exposure --username exampleuser --dataset cases.json
rxscan exposure --domain example.test --explain
rxscan exposure --email user@example.test --json
rxscan exposure --email user@example.test --jsonl
rxscan exposure --email user@example.test --project-db project.db
```

Investigation integration (opt-in only):

```bash
rxscan investigate --username exampleuser --exposure
rxscan investigate --username exampleuser --exposure \
  --exposure-dataset cases.json
```

Ordinary passive investigation never queries external exposure
providers. `--explain` always discloses which providers would send the
identifier to a third party before any contact.

## Provider model

| Provider | Contact | Sends identifier | Auth |
| --- | --- | --- | --- |
| `local-dataset` | local dataset | never (local-only) | none |
| `http-api` | authenticated API | yes (explicit opt-in) | `RXSCAN_EXPOSURE_ENDPOINT` + `RXSCAN_EXPOSURE_TOKEN` env |

Credentials come only from the environment. They are never printed,
persisted into the project DB, or included in JSON/JSONL output.
Without configuration, capabilities report `credential_not_configured`
and lookups degrade to explicit `unavailable` observations.

## Local datasets

Operator-supplied JSON, bounded (1 MiB, 1000 entries), local-only, never
uploaded:

```json
{"exposures": [
  {"identifier_type": "email", "identifier": "user@example.test",
   "source": "operator-list", "source_name": "LocalBreach",
   "exposure_type": "breach", "affected_domain": "example.test",
   "malware_family": null, "exposure_date": "2024-01-01",
   "confidence": 80, "record": {}}
]}
```

The optional `record` object passes through the same secret
normalization as API responses: secrets classify the exposure, then are
dropped.

## Safe normalized fields

Persisted exposure metadata is limited to:

```text
source, source/breach name, exposure type, identifier type,
identifier SHA-256 (raw identifiers never persist),
affected/targeted domain, provider-reported malware family,
first/last observed, exposure date, exposed field TYPES,
confidence, provenance
```

Example field types: `email`, `username`, `password`, `browser_session`.
The word `password` means "the provider reports password material was
exposed" — RXScan stores a boolean, never the value.

Prohibited from persistence, display, logs, and graph:

```text
plaintext passwords, password hashes, session cookies,
authentication tokens, refresh tokens, API keys, recovery codes,
private keys, payment card data, security answers,
raw stealer-log secret material
```

Normalization maps them to:

```text
credential_material_exposed = true/false
session_material_exposed    = true/false
secret_material_retained    = false (invariant, always false)
```

Raw provider responses are never stored (`store_raw_response` has no
opt-in in this phase).

## Graph relations

```text
identifier --EXPOSED_IN--> breach/credential/session/paste exposure
identifier --OBSERVED_IN--> infostealer/malware observation
exposure   --REPORTED_BY--> exposure source
exposure   --AFFECTS--> domain (breach scope)
exposure   --TARGETED_DOMAIN--> domain (malware scope)
```

Raw credentials are never graph entities.

## Coverage-aware absence

A provider that reports nothing yields a `no_match` observation
("checked and clean"), distinct from `unavailable` / `malformed` /
`authentication_required` / `rate_limited` ("not checked"). Later diffs
never turn "not checked" into "exposure disappeared".

All examples use synthetic values only.
