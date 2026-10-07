# RXScan MCP readiness (design boundary, not implemented)

A future constrained MCP/tool interface is feasible without changing the
deterministic core. This document fixes the operation boundary so a later
implementation is straightforward — and explicitly out of scope until
there is clear value that justifies the dependency/maintenance cost.

## Safe read-first operations

| Tool | Core backing (exists today) |
| --- | --- |
| `search entity` | `search` engine + provider registry (`src/search.rs`) |
| `investigate entity` | `run_investigation` / `run_investigation_with` (`src/investigate.rs`) |
| `get evidence` | `InvestigationReport.observations`, entity provenance |
| `get relationships` | `InvestigationReport.relationships`, `ScanGraph.link` |
| `get project history` | project DB reads (`src/project_db.rs`, `src/project.rs`) |
| `explain finding` | `explain_entity`, observation chains |
| `list capabilities` | `rxscan capabilities`, corpus `search stats` |

Constraints inherited from the core (non-negotiable for any MCP layer):

- Same evidence objects the CLI/Web consume — no second logic path, no
  text scraping (`docs/ARCHITECTURE.md`).
- Passive by default. Active scan operations (`rxscan TARGET`,
  `investigate --network`) retain explicit scope/authorization boundaries:
  scope allowlists, `--allow-remote`-style explicitness for loopback
  escape, bounded budgets, deadlines, cancellation.
- No generic command-execution tool. Tools map 1:1 to the operations
  above with typed inputs (entity kind + value, depth, budgets).
- Bounded inputs/outputs (entity caps, `MAX_INVESTIGATE_PIVOTS`,
  pagination) so a tool call cannot pull an unbounded graph.
- Loopback-first transport posture mirrors `rxscan web` (`SECURITY.md`).
- Secret handling follows `src/repo_intel.rs` precedent: metadata only,
  never secret values.

## Suggested shape (when built)

- Read tools return the same serde JSON the CLI `--json` emits, plus a
  `citations` array of evidence/provenance IDs per claim.
- Write/scan tools require an explicit `scope` argument validated by the
  existing Scope Guard before any contact, and return the standard
  accounting block (completed vs unscanned work).

Status: design documented. No MCP server implemented; the deterministic
RXScan core remains authoritative.
