# RXScan architecture

RXScan is a native Rust, policy-driven reactive reconnaissance engine: **simple outside, serious inside**. It is not a wrapper around external scanners.

```text
Target / Scope -> ScanPlan Compiler -> Reactive Scheduler <-> Speed + Budgets
                                                    -> Modules -> Typed Events / Findings
                                                    -> Evidence Store -> Decision Engine
                                                    -> scoped task proposals -> Scheduler
```

The Decision Engine proposes work only. The Scope Guard, policy validation, budget validation, and scheduler admission must approve every task before execution.

## Phase 0–1 boundary

`cli` captures operator intent. `config` resolves explicit global then project TOML configuration. `target` converts seeds into `TargetSpec`; `scope` applies deny-by-default scope; `plan` creates an immutable and explainable `ScanPlan`. No active networking occurs in these phases.

`--level` is investigation breadth/depth; `--speed` is execution pressure. They are deliberately independent. Stable asset/event/finding identity begins in Phase 2, before execution modules.

## Security invariants

- No task may execute beyond central scope.
- No module may schedule arbitrary follow-up work.
- Future operations require timeout, cancellation, response cap, retry cap, and budget accounting.
- Typed data crosses module boundaries; terminal output is never an API.
- Findings retain provenance, timestamps, confidence, and stable identities.

## Repository ownership

- Foundation: `cli`, `config`, `target`, `scope`, `plan`
- Control plane: `events`, `findings`, `scheduler`, `speed`, `budgets`, `decision`
- Modules: `network`, `dns`, `fingerprint`, `web`, `checks`
- Persistence/output: `graph`, `storage`, `output`
