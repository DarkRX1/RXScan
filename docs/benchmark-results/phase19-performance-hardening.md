# Phase 19 Performance / Large-Scale Hardening

Phase 19 breaks RXScan under realistic scale, then fixes proven bottlenecks.
It adds no reconnaissance capability, no production dependency, and no tuning
knob. Every optimization preserves semantic truth (level = breadth/depth,
speed = pressure); structural caps carry the regression proof, timings are
observational.

```sh
cargo run --example phase19_bench
cargo test --test phase19_performance
cargo build --release && stat -c '%s' target/release/rxscan
```

Environment for all numbers below: `Linux 7.0.12-1-aegis-offensive`,
12 logical CPUs (`available_parallelism=12`), loopback/synthetic fixtures
only, no public targets, no competitor benchmarks.

## Measured output (`cargo run --example phase19_bench`, release)

```text
phase19_bench
os_kernel=Linux 7.0.12-1-aegis-offensive
build_mode=release
available_parallelism=12
threads_used_peak=4
wall_ms=1956
cpu_time_ms=1380
peak_rss_kb=104060
current_rss_kb=104060
scheduler_tasks_proposed=1500
scheduler_tasks_completed=1500
scheduler_queue_peak=64
scheduler_queue_capacity=64
scheduler_active_peak=4
scheduler_wall_ms=459
scheduler_cancel_to_stop_ms=0
tcp_ports_represented=65535
tcp_resolve_ms=0
tcp_active_peak=32
tcp_fd_peak=32
tcp_fd_hard_cap=256
tcp_fd_before=4
tcp_fd_after=4
web_requests=128
content_events=256
content_ms=269
crawl_candidates=3000
crawl_links_extracted=100
crawl_links_truncated=true
crawl_proposals=64
crawl_skipped_pages=2936
crawl_plan_ms=1
extract_ms=0
content_candidates=300
content_dedup_avoided=0
fuzz_mutations=2048
fuzz_ms=0
dns_queries=100
checkpoint_bytes=4645445
checkpoint_save_ms=21
checkpoint_load_ms=23
diff_records=1
diff_ms=29
analysis_candidates=2001
analysis_signals_emitted=100
analysis_ms=16
report_jsonl_records=2003
report_jsonl_bytes=341678
report_render_ms=13
project_bytes=11677588
project_open_ms=72
project_fingerprint_ms=21
project_query_ms=450
project_queue_peak=2048
project_visited_peak=4096
project_expansions=2048
project_exhaustive=false
incremental_import_ms=135
project_save_ms=80
release_binary_size_bytes=8305344
new_production_dependency_count=0
```

Debug build of the same bench: `wall_ms=37432` (same structure, same caps;
debug is observational only). `content_dedup_avoided=0` because the bench
wordlist uses 300 unique lines; duplicate collapse is proven by
`duplicate_wordlist_lines_contact_each_path_once` in
`tests/phase19_performance.rs` (3000 identical lines -> exactly 1 contact).

Reading notes:

- `threads_used_peak=4` of 12 CPUs: bounded coexistence, not saturation.
  `cpu_time_ms=1380` vs `wall_ms=1956` (ratio 0.7) confirms efficiency rather
  than monopolization.
- `peak_rss_kb=104060` is the composite bench process holding a 1500-task
  scheduler, a 4.6 MiB checkpoint (x2 plus parsed forms), and an 11.7 MiB
  project simultaneously — a worst-case composite, not a single scan. Real
  scans hold far less at once (per-section peaks are much smaller; e.g. the
  scheduler section completes before the project section starts).
- `project_exhaustive=false` with all three graph peaks exactly at their caps
  is the guards working as designed under a 4000-fan-out hub, not a failure:
  the deterministic smallest prefix is still emitted.
- `scheduler_cancel_to_stop_ms=0`: a 1000-task workload cancelled before
  `run()` drains with zero executions and zero retained outputs.

## Baselines (pre-change, same machine)

- Binary: P18 accepted `8,210,768` bytes; `rxscan --help` ~1ms.
- Scheduler/report peaks (`queue_peak`, `active_peak`), TCP `fd_peak`:
  did not exist (added by P19 as pure observability).
- Functional behavior P0–P18: all suites green before and after (see totals).

## Measured bottlenecks found (and fixed)

1. **Scheduler final sweep was O(N²).** `Scheduler::run` reconciled terminal
   tasks with `Vec::contains` per task (`src/execution.rs`). At
   `MAX_TASKS_HARD_LIMIT=100_000` that is ~10^10 comparisons.
   Symptom: final-sweep cost grows quadratically with admitted tasks.
   Fix: build five `HashSet<TaskId>` once, keep BTreeMap emission order.
   Identical output, linear sweep.
2. **Diff port-coverage expansion materialized up to 65,535 heap Strings.**
   `Coverage::record_task` expanded `start..=end` into one `String` + one
   `BTreeSet` node per port (`src/diff.rs`). Symptom: diffing an `--all-ports`
   checkpoint paid 65k allocations per PortDiscovery task before comparing
   anything. Fix: verbatim single-port tokens stay in the exact-match set;
   ranges merge into a sorted disjoint interval list with binary-search
   `port_covered()`. Membership truth is identical for canonical ports
   (verified by `all_ports_diff_coverage_is_compact_and_correct` plus the
   full P15 suite); one interval covers `1-65535`.
3. **Checkpoint save held the whole serialization in RAM.** `save_checkpoint`
   built a full `Vec<u8>` via `to_vec_pretty`, then wrote it
   (`src/persistence.rs`). Symptom: peak save memory scaled with checkpoint
   size on top of the live state. Fix: stream `to_writer_pretty` through an
   8 KiB `BufWriter` straight to the temp file (same pretty formatter, byte-
   identical output), enforce the 8 MiB cap from the finished temp file, and
   remove the temp file on overflow so oversize behavior (error, no output
   left behind) is preserved. Full P14 suite green unchanged.
4. **Repeated canonicalization inside sort comparators.** `open_ports_from_
   output` re-rendered both IP addresses to `String` on every comparison
   (`src/decision.rs`); `crawl::plan_followups` re-ran URL canonicalization
   per comparison and per dedup probe (`src/crawl.rs`). Symptom: O(n log n)
   redundant allocations for large open/candidate sets (2000-fact extraction
   measured in tests). Fix: `sort_by_cached_key` / precomputed keys — byte-
   identical ordering (string-order semantics kept deliberately; `IpAddr::Ord`
   would reorder v4/v6 differently), linear allocations.
5. **Output path cloned every module output to sort it.** `write_outputs`
   (`src/run.rs`) did `module_outputs.to_vec()` (four Vecs per output)
   before sorting by task ID. Fix: sort borrowed references. Identical bytes.

Audited and deliberately NOT changed (no demonstrated problem):

- `normalize_body` tail loop (`src/baseline.rs`): the `while contains`
  replace loop always terminates after at most one effective pass (each pass
  removes every remaining occurrence; passes cannot recreate the patterns),
  so it is 2x O(n), not quadratic.
- Project neighbor traversal keeps the documented no-adjacency-map design:
  per-expansion full relationship scan is O(expansions x relationships),
  bounded by `MAX_GRAPH_QUERY_EXPANSIONS=2048`. Measured: 450ms release for a
  cap-hitting 4000-fan-out hub query. A transient sorted index would be faster
  but spends megabytes of temporary memory per query against the P18 memory
  policy; rejected (see below).
- `promote_ready_tasks` scans all tasks per tick: the filter is allocation-
  free field checks and the scan cannot be skipped without changing
  `QueueSaturated` event emission truth. Bounded, documented.
- `VecEventSink` is unbounded in count but each task emits a constant number
  of small events, so it is bounded by policy via `max_tasks` (<=100k).
- Task-ID SHA-256 over canonical JSON, per-task evidence accounting, and
  owned-`Task` dispatch clones are load-bearing (identity guarantees, thread
  ownership) and were not weakened.

## Optimizations implemented (production diff summary)

- `src/execution.rs`: `SchedulerReport::{queue_peak, active_peak}` additive
  observability (O(1) counters); final sweep HashSet membership.
- `src/tcp_scanner.rs`: `ScanOutcome::fd_peak` (peak `pending.len()`),
  always `<= max_concurrent <= 256`.
- `src/decision.rs`, `src/crawl.rs`: cached sort keys, same order.
- `src/diff.rs`: interval port-coverage, same membership truth.
- `src/persistence.rs`: streaming checkpoint save, byte-identical output.
- `src/run.rs`: sort borrowed outputs, identical bytes.
- `tests/phase6_tcp.rs`: 4 fake-scanner literals gain `fd_peak: 0` (fakes
  hold no real sockets).

## Rejected optimizations (with reason)

- Full per-query adjacency `HashMap` for project neighbors: trades the
  documented bounded-memory design for speed; measured release cost (450ms
  worst-case, caps hit) does not justify megabytes of transient index memory.
- Global canonicalization cache: unbounded by nature; violates the no-giant-
  cache rule for unmeasured gain.
- Weaker task identity (fewer hashed fields / cheaper hash): breaks
  determinism and collision-resistance guarantees for speed.
- rayon/async runtime/allocator replacement: zero measured justification;
  dependency count stays 10 production / 1 dev.
- Skipping `QueueSaturated` events under saturation: would change observable
  backpressure truth to save log volume.
- Raising any hard cap (queue, concurrency, registries, evidence) for
  throughput: caps are the product, not the obstacle.

## Scale proofs (all loopback/synthetic, no public targets)

- Scheduler: 3000 tasks, terminal accounting exact, `queue_peak <= capacity`,
  `active_peak <= concurrency`; tiny queue (4) drains 200 tasks loss-free.
- Fairness: 60 bounded high-priority follow-up arrivals; the eligible
  low-priority task still completes.
- Cancellation: 3000-task workload cancelled before run stops in 0ms bench /
  bounded test time with 0 executions, 0 retained outputs, no follow-ups.
- Deadline: retry-backoff workload with a 150ms global budget cancels
  remaining work promptly; all 20 tasks accounted, attempts cut short of the
  100-attempt ceiling.
- 65,535 ports: `resolve_ports(All)` = 65,535 entries in 0ms; lowering emits
  exactly 1 `PortDiscovery` task; pre-cancelled full-vector scan accounts
  65,535 probes+unscanned with `fd_peak <= 32`; no 65k tasks/threads/sockets.
- FD: real loopback scans report `fd_peak <= configured <= 256` for every
  speed; `ScanConfig::bounded` clamps absurd inputs to 256/1; FD count before
  equals after (no leak).
- Exhaustion: child process under `prlimit --nofile=64` with 40 held FDs
  completes a 100-port scan with every port accounted (`probes=100`,
  `unscanned=0`, `fd_peak=21`), no panic, no spin.
- Host discovery: `/8` expansion with `max_hosts=64` stays bounded during
  lowering, before allocation.
- Service: `plan_probes` length `<= MAX_PROBES_PER_PORT` for levels 1..5 and
  takes no speed input; only `service_timeout_for_speed` varies.
- HTTP: 300-line live wordlist run capped at exactly 128 requests / 256
  events; slow (200ms) + 200 KiB + 100-header peer stays bounded and capped.
- Crawl: 3000-link/duplicate/fragment/cycle soup extracts to exactly the
  100-link cap with `truncated_links=true`; 3000 followup candidates plan to
  64 proposals deterministically across runs.
- Content: 3000-line wordlist stops at the 2000-line read cap; 3000 duplicate
  lines contact `/admin` exactly once.
- Fuzz: per-origin cap holds at exactly 8, re-claim is free, global cap holds
  at exactly 256 origins.
- DNS: 5000 duplicate claims collapse to 1 tracked query; 3000 mixed claims
  stay <= 201; per-domain cap holds at exactly 32; `forget_query` releases
  for retry.
- Persistence: 3000-task checkpoint round-trips with identical ID sets under
  the 8 MiB cap (bench: 4,645,445 bytes, save 21ms, load 23ms release).
- Resume: 60-task mixed-state checkpoint restores 60 with only the 15
  `Succeeded` outputs re-attached; nothing completed repeats.
- Diff: 2000-asset states diff with zero false removals and an exact Added
  record (bench: 1 record, 29ms release).
- Analysis: 1500-asset state ranks deterministically across runs with stable
  aggregate counts (bench: 2001 candidates, 100 signals, 16ms release).
- Report: 1200-task JSONL streams the exact expected record count; a 50us-
  per-write slow sink completes bounded (bench: 2003 records, 341,678 bytes,
  13ms release).
- Project: 11,677,588-byte fixture (5.6x the P18 2.09 MiB fixture, under the
  16 MiB cap): open 72ms, fingerprint 21ms, incremental import 135ms, save
  80ms; hub query hits all three work caps exactly
  (queue 2048 / visited 4096 / expansions 2048, `exhaustive=false`) with the
  deterministic prefix still emitted; duplicate import stays a no-op;
  `fingerprint_whole_state_clones=0`; P18 single-thread/offline invariants hold.
- Duplicates: 5000 duplicate task admissions all rejected as `DuplicateTask`;
  5000 fragment-variant URLs canonicalize to 1; DNS/project duplicates above.
- Level/speed: levels 1..5 x speeds slow/balanced/fast/0/100 produce
  identical lowered PortDiscovery params per level (breadth differs across
  levels); task IDs embed timeout/retry pressure by design, so the invariant
  is checked on semantic params, not ID digests. Service probe shape has no
  speed input at all.
- IPv6: 50 `::1` tasks complete; mixed v4/v6 open-port facts sort/dedup
  deterministically.
- Malformed: 5 MiB garbage checkpoint, corrupt project, and 11-byte DNS
  packet all rejected promptly without panic.
- Failure storm: 400 non-retryable failures run exactly once each; 200
  retryable failures stop at exactly 400 attempts (2/task).
- Backpressure: slow-sink JSONL render completes with exact bytes.
- Startup laziness: `--help` exits 0, prints help, creates no files.
- Multitasking: governor concurrency derives from speed+budget only
  (`Fast+4 -> 3`, `Numeric(100)+4 -> 4`), never from `available_parallelism`;
  TCP concurrency caps likewise; bench uses 4 threads of 12.
- Offline: diff/analyze/report/project all report `network_requests=0`.

## Queue / channel inventory (caps and overflow)

| Structure | Default cap | Hard cap | Overflow |
| --- | --- | --- | --- |
| `TaskQueue` (priority-ready) | `(conc*16).max(conc+4).min(max_tasks)` | via `MAX_TASKS_HARD_LIMIT=100k` (max 1024 at conc 64) | `QueueSaturated`; tasks stay `Pending`, retried next tick |
| `Scheduler.tasks` registry | `max_tasks=1000` | 100_000 | `BudgetExhausted`, fail-fast for initial, best-effort skip for follow-ups |
| `completed_outputs` | `<= max_tasks` entries | 100_000 | same budget gate |
| `SchedulerReport` vectors | `<= max_tasks` ids | 100_000 | accounting only |
| `VecEventSink.events` | ~constant per task | via `max_tasks` | grows only with admitted tasks |
| `ModuleOutput` evidence bytes | 64 MiB | 1 GiB | `BudgetExhausted` |
| worker `mpsc` channel | `<= active + orphans` buffered | via concurrency+tasks | never blocks; late results discarded |
| per-tick `deferred`/`candidates`/`timed_out` temps | `<= queue` / `<= tasks` / `<= active` | same | freed per tick |
| TCP `pending` map + `poll_fds` | `max_concurrent` (16..128 by speed) | 256 | window simply stops filling; EMFILE adds 20ms backoff |
| TCP `queue`/`probes` | input ports (<=65_535) | `MAX_PORTS_PER_TASK` | freed per task; `unscanned` counted on cancel |
| crawl/content/fuzz/DNS per-task vecs | per-module ADMITTED/REQUEST/EVENT caps | hard consts | `budget` stop markers, truncation flags |
| project query `seen`/`queue`/`candidates` | 4096 / 2048 / edge 8192 | same consts | `exhaustive=false`, deterministic prefix |

No hidden unbounded queue: every grow-with-work container above is derived
from an explicit budget or hard constant.

## Registry-cap inventory (exact max + one-over behavior)

| Registry | Max | One-over |
| --- | --- | --- |
| `ContactRegistry` | 4096 entries | fail-open `true`, untracked (documented) |
| `DnsRegistry` queries | 4096 | fail-closed latch, count frozen |
| `DnsRegistry` domains | 256 | new domain refused |
| per-domain tasks | 32 (`MAX_DNS_TASKS_PER_DOMAIN_HARD`) | refused |
| `FuzzOriginBudget` origins | 256 | refused |
| per-origin plans | 8 (`MAX_FUZZ_TASKS_PER_ORIGIN_HARD`) | refused |
| `OriginBaselineRegistry` | 512 | latch, documented |
| `BaselineSimilarityRegistry` | 1024 index / 8 per bucket | early-return / capped |
| checkpoint tasks/outputs/assets/relationships/events | 100_000 each (findings 10_000) | `SizeLimit`/`Invalid` |
| diff records | 10_000 | truncated with counts |
| analysis signals | 10_000 | truncated with counts |
| report top-N / human detail | 100 / 20 | clamped/truncated |
| project collections | 10k scans … 500k observations | first-reached cap rejects |
| project graph query | depth 3 / limit 1000 / visited 4096 / queue 2048 / expansions 2048 / edges 8192 | `exhaustive=false` + deterministic prefix |

## Clone / allocation audit (production, exact)

`rg` counts: 609 `.clone()` + 694 `.to_owned()` + 120 `.to_string()` across
`src/`. Hottest files: `service_probe` (54), `baseline` (54), `crawl` (48),
`project` (45), `decision` (43), `web_probe` (41), `execution` (40).
Classification of hot-path clones:

- Necessary: owned `Task` per worker thread (`execution.rs` dispatch),
  `Arc<Module>` shares, `CancellationToken` shares, SHA-256 identity
  serialization input, per-entity hashes on project import, owned evidence
  strings crossing the module boundary.
- Small/irrelevant: short identifiers, labels, single headers, per-probe
  detail strings (bounded, freed per task).
- Avoidable and removed: `write_outputs` full-output clone (now borrows),
  diff 65k port-`String` expansion (now intervals), per-comparison
  canonicalization allocs in two sorts (now cached keys), whole-checkpoint
  serialization buffer (now streamed). The final-sweep change adds up to 5xN
  small `TaskId` clones once to remove an O(N^2) scan — a measured net win.

## Sort / nested-loop audit

- One `sort+dedup` per TCP port vector (u16, trivial); one `sort_by_key` per
  outcome; per-page candidate sorts (n ~= 150, keys now precomputed);
  per-node peer sorts in project queries (degree-sized); BTreeMap-ordered
  report/diff dedup (first-wins documented).
- No unrestricted O(N^2): scheduler final sweep fixed to O(N); diff
  comparison is O((N+M) log(N+M)) union walk; analysis has no all-pairs
  correlation; project import diff-ref matching is O(D x E) only when diff
  refs are attached (bench passes none); neighbor traversal is O(expansions
  x relationships) under the 2048-expansion cap by documented design.
- No stack recursion proportional to attacker input: crawl/DNS/graph use
  explicit bounded queues; `resolve_scan_candidates` recurses at most once
  (Url -> Host).

## Complexity / memory / thread / FD / network audits

- Worst cases: target normalization O(n); task admission O(log N) + SHA;
  queue push/pop O(log C); TCP port iteration O(P) with O(1) extra; asset/
  relationship insertion O(log N); crawl/content dedup O(1); fuzz planning
  O(params) capped; DNS registry O(1); checkpoint save O(S) streaming /
  load O(S); diff O((N+M) log(N+M)); analysis O(signals); JSONL O(records)
  streaming; project import O(A log E + R); lookup O(1); graph query
  O(expansions x R) capped.
- Largest retained structures: `Scheduler.tasks` (<=100k), event sink
  (<=~5x tasks), per-task `probes` (<=65k small structs, freed per scan),
  128 KiB crawl bodies / 64 KiB content bodies (locals, dropped per fetch),
  16 KiB probe stash, checkpoint file stream (8 KiB buffer), project
  collections (16 MiB file cap dominates).
- Threads: no pools, no persistent workers. One short-lived thread per
  task-attempt plus transient per-probe helper threads inside bounded
  timeouts; max simultaneous scheduler workers = effective concurrency
  (<=64 hard, 4 in the bench on a 12-CPU box). Project = 1 thread.
- FDs: sustained per-scan ceiling = TCP `max_concurrent` (<=256 hard,
  16..128 by speed); one UDP socket per DNS query (dropped on return); one
  socket per HTTP fetch (dropped per fetch); measured `fd_peak=32` at
  concurrency 32, before == after (no leak); EMFILE degrades to bounded
  Error/backoff outcomes (proven in a 64-FD child process).
- Offline commands (`diff`, `analyze`, `report`, `project`) hold
  `network_requests=0` in code and in every measurement.

## Regression harness (`tests/phase19_performance.rs`, 43 tests)

Structural assertions only (caps, counts, determinism, bounded stop with
generous thresholds — no microsecond gates):

```text
large_scheduler_stays_bounded_and_accounts_every_task
sustained_high_priority_arrivals_do_not_starve_low_priority
mass_precancellation_is_bounded_and_admits_no_new_work
expired_global_deadline_stops_loaded_run_promptly
per_task_timeouts_under_load_free_slots_promptly
retryable_failure_storm_does_not_exceed_attempt_budget
non_retryable_failure_storm_runs_each_task_once
all_ports_is_one_task_not_65535_tasks
all_ports_diff_coverage_is_compact_and_correct
real_socket_scan_reports_peak_within_hard_bound
tcp_concurrency_policy_is_capped_for_every_speed
cancelled_scan_returns_bounded_partial_outcome
fd_pressure_still_accounts_every_port_without_panic
descriptor_exhaustion_returns_bounded_result
tiny_queue_still_drains_without_loss_or_deadlock
speed_changes_pressure_not_port_truth
service_probe_plan_is_bounded_and_speed_independent_in_shape
cidr_host_cap_is_enforced_before_runaway_allocation
huge_link_set_is_capped_deduped_and_deterministic
large_wordlist_streams_with_candidate_and_request_caps
duplicate_wordlist_lines_contact_each_path_once
slow_and_oversized_http_responses_stay_bounded
open_port_fact_extraction_scales_without_allocation_blowup
fuzz_origin_budgets_enforce_per_origin_and_global_caps
dns_registry_dedups_repeats_and_holds_domain_caps
dns_module_serves_many_types_from_local_fixture_with_dedup
contact_registry_holds_exact_cap_with_documented_fail_open
large_checkpoint_roundtrips_with_bounded_size
resume_does_not_repeat_completed_work
large_diff_has_no_false_removals_and_stays_capped
analysis_over_candidate_cap_keeps_counts_and_determinism
jsonl_report_streams_exact_record_counts
slow_output_sink_does_not_break_bounded_render
large_project_import_query_save_hold_p18_bounds
duplicate_storm_collapses_before_deep_work
equivalent_workloads_produce_stable_ids
worker_caps_do_not_follow_available_parallelism
ipv6_targets_flow_through_scheduler_and_sort
large_malformed_inputs_fail_bounded_without_panic
out_of_scope_work_is_rejected_before_any_execution
help_path_has_no_persistent_side_effects
offline_commands_report_zero_network_requests
tcp_closed_heavy_outcome_stays_compact_in_reporting
```

Full suite: 22 targets, 0 failures (lib 55 + all phase suites incl. 43 new).

## Methodology

- RSS: `/proc/self/status` `VmHWM` = peak, `VmRSS` = current; never confused.
- CPU time: `/proc/self/stat` fields 14+15 (utime+stime) divided by
  `getconf CLK_TCK`; reported as `cpu_time_ms=<n>` or `unavailable`
  off-Linux. No dependency, no fake numbers.
- Startup: 15 samples of release `rxscan --help`: min 0.97ms, median
  1.17ms, max 1.34ms. Help initializes no network/TLS/DNS/crawler/project
  state and creates no files (asserted by test).
- Binary: release `8,305,344` bytes vs P18 `8,210,768` = `+94,576` (+1.15%)
  for peak observability, interval coverage, and streaming save. No
  correctness traded for size.
- Dependencies: 10 production / 1 dev — unchanged (+0/+0).

## Known remaining performance limitations

- External mid-run `cancel_all` is not reachable while `run()` holds `&mut`
  (no caller, including the CLI, cancels a running scheduler from another
  thread). In-run cancellation is fully covered by per-task tokens,
  per-task timeouts, and the global execution budget — all stressed under
  load here. A shared-ownership cancel handle is future work, not P19.
- Project neighbor traversal is O(expansions x relationships) by documented
  design (no transient adjacency index); worst measured release 450ms for a
  cap-hitting hub query.
- `VecEventSink` grows with admitted tasks (bounded by policy via
  `max_tasks`, not by a separate event cap).
- All-open 65k hosts would emit one asset/event/evidence/finding per open
  port (only closed/filtered collapse to counts); realistic open sets are
  small and the scheduler/evidence budgets still bound the run.
- Debug-build timings are 5–20x release; CI timing assertions are structural
  only for this reason.

## What P19 did NOT do

No new protocols, payload classes, DNS enumeration, exploit checks, crawler
capabilities, tuning knobs, async runtime, rayon, allocator, database,
packaging, installers, man pages, or release workflow. No public targets. No
competitor comparisons. Speed still changes pressure, level still changes
breadth/depth — proven by the cross-matrix test, not claimed.
