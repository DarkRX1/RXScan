# RXScan Extension SDK (v1)

Versioned interface for adding **service fingerprint packs** and **bounded
public-source transforms** without touching the core. No `dlopen`, no
WASM, no subprocesses: extensions are JSON manifests plus in-process Rust
traits, and every contact flows through a grant-enforcing context.

## Interface version

`EXTENSION_SDK_VERSION = 1` (`src/extension_sdk.rs`). Manifests declare
`"sdk_version": 1`; any other version is a schema mismatch (fail fast,
never partial load). The registry rejects duplicate ids.

## Manifest

```json
{
  "sdk_version": 1,
  "id": "demo-rdss",
  "version": "0.1.0",
  "kind": "public_transform",
  "description": "What the extension does, in one sentence.",
  "requires": {
    "contact": "public_http",
    "hosts": ["127.0.0.1"],
    "max_requests": 4
  }
}
```

- `kind`: `"fingerprint_pack"` or `"public_transform"`.
- `requires.contact`: `"local_only"` (no contact at all), `"dns"`, or
  `"public_http"`. Contact without at least one host is malformed.
- `requires.hosts`: exact hostnames or IP literals (lowercased, at most
  64). Matching is exact — subdomains are not implied.
- `requires.max_requests`: 1–1000 per grant.

Load manifests with `extensions::load_extension_manifest` (64 KiB cap,
strict validation). A worked manifest lives at
`fixtures/extension_example/manifest.json`.

## Permission model (declare → grant → enforce)

1. The manifest **declares** needed contact and hosts.
2. The operator **grants** a subset via `ScopeGrant::compile(manifest,
   allow_contact, allowed_hosts)`. Every required host must be allowed;
   there are no partial grants — unmet requirements fail compilation
   with `PermissionDenied`.
3. Every contact attempt calls `ScopeGrant::check` first: undeclared
   contact classes, ungranted hosts, and exhausted budgets are rejected
   with `PermissionDenied`/`BudgetExceeded` **before any packet moves**.
   Denied attempts never consume budget.

Grants are also deadline- and cancellation-aware: expired deadlines and
set cancel flags fail fast with `Deadline`/`Cancelled`.

## Fingerprint packs

`extension_sdk::load_extension_fingerprints(id, dir)` validates the
directory with the same loader as built-in packs (`schema_version`,
bounded rules, duplicate detection) and stamps the extension id as
provenance. Rules match with `FingerprintPack::match_observation` and
carry their static confidence (1–95, never 100). A fixture pack lives at
`fixtures/extension_example/fingerprints/demo.json`.

## Public transforms

Implement `ExtensionTransform`:

```rust
fn manifest(&self) -> &ExtensionManifest;
fn execute(&self, ctx: &ExtensionContext<'_>, input: &TransformInput)
    -> Result<ExtensionOutput, ExtensionError>;
```

- Inputs are plain values (entity id, stored kind, label, attributes).
- Outputs use id suffixes; the SDK namespaces them as
  `ext:<manifest-id>:<suffix>` so extensions can never collide with core
  entity ids.
- Relationships cite stored relation names; confidence is capped by
  `cap_extension_confidence` (≤ 70, below native observation strength).
- Contact only through `ctx.http_get(host, port, path)` (HTTPS except
  loopback literals, 256 KiB body cap, 10 s timeout) and
  `ctx.dns_lookup(host)` (≤ 16 addresses). Both enforce the grant.

The worked example is `examples/extension_hello.rs`
(`cargo run --example extension_hello`): a loopback HTTP document, a
deny-by-default refusal with zero contact, then a granted run deriving
one namespaced entity. Fully offline and deterministic.

## Bounds (all enforced)

| Resource | Bound |
|---|---|
| Manifest file | 64 KiB, strict JSON schema |
| Hosts per manifest | 64, exact match |
| Requests per grant | manifest `max_requests`, ≤ 1000 |
| HTTP body | 256 KiB |
| HTTP timeout | min(remaining deadline, 10 s) |
| DNS answers | 16 addresses |
| Entity suffix | 256 chars, namespaced |
| Derived confidence | ≤ 70 |

## Security notes

- Extensions run in-process with the operator's privileges: install only
  manifests you reviewed (the `requires` block is the trust decision).
- Transforms never see raw sockets, credentials, or the core network
  stack — only the two bounded context methods.
- Secret material must never enter extension outputs; the core display
  maskers still apply downstream, but extensions should avoid logging
  response bodies containing credentials.
