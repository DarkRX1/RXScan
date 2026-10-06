# Search corpus maintenance

The provider/vector count is dynamic registry state, never an
architecture limit. Do not present any current number as a maximum.

## Current state (regenerate, never hardcode)

```bash
cargo run --locked -- search stats
cargo run --locked -- search providers
cargo run --locked -- search lint
```

Counts (providers, vectors, per-category, per-health-state) derive
from the live registry at runtime. Tests assert reconciliation
(buckets sum to the registry size; category totals sum to the loaded
count), never exact totals — see `tests/phase22_search_corpus.rs`.
If the corpus grows or shrinks, the tests still pass unchanged.

## Provider vs search vector

- A **provider** is a definition: one `metadata.id` in
  `search/providers/v1/username/<category>.json`.
- A **search vector** is a queryable unit derived from a provider
  (`username_search_vectors` in `src/search.rs`). Today the mapping
  is 1:1, but the registry keeps both counts distinct
  (`providers_configured` vs `vectors_registered`) so future
  multi-vector providers never inflate either number.
- An **email/domain/hostname/IP/ASN/URL/repo/org vector** is a
  separate registry, currently honestly unpopulated for email
  (`email_vectors 0`) — the architecture exists, the corpus does not
  yet. Data model != provider coverage.

## Scale design

- Registry size is independent from concurrency: planning
  (`plan_username_providers`) derives its denominator dynamically
  from the scheduled set; the scheduler runs a bounded worker pool
  regardless of corpus size.
- Category filtering (`--category`, Sources panel) and provider
  allow/deny lists (`--provider`, `--exclude-provider`) narrow the
  real plan before any contact; unknown IDs are typed errors.
- Execution stays bounded (per-provider timeouts, redirect caps,
  body caps, global deadline, cancellation); partial evidence is
  retained and unfinished work is honestly accounted, never
  fabricated as complete.
- Presentation defaults to findings-first (confirmed + possible);
  complete provider outcomes require `--all`, reasoning requires
  `--explain`. Default output never dumps thousands of routine
  negatives, at any corpus size.

## Scale proof (synthetic only)

`tests/search_scale.rs` (`SCALE_VECTORS = 3_000` distinct synthetic
providers) proves: validation passes at 3,000 definitions, planning
slices thousands without contact, the scheduler completes thousands
with bounded concurrency, terminal output stays bounded, and machine
output reconciles without ANSI. This proves the architecture handles
thousands of vectors — it does NOT mean RXScan ships thousands of
real providers. Real-provider count is whatever `search stats`
reports today; integrity comes before corpus-size claims
(see `docs/PROVIDER_CONTRACT.md` for why weak providers are rejected
rather than bulk-imported).
