# Phase 2 model baseline

- Date: 2026-09-11
- RXScan version: 0.1.0 (Phase 2 data model)
- Fixture class: deterministic in-process model, serialization, scope, and bounded-evidence tests
- Network I/O: none
- Result: correctness baseline for deterministic identity and bounded record handling; this phase has no throughput claim.

The model has a 64 KiB detail cap for both evidence and event records. Future producer benchmarks must report truncation counts and retained-byte totals.
