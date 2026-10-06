# Testing and release gates

## Exact gates

Run from a clean checkout (or the working tree under review):

```bash
cargo fmt --check
cargo check --locked
cargo check --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
cargo run --locked -- search lint
node --check app/rxscan.js
git diff --check
cargo package --list
```

What each gate proves:

- `fmt --check`: tree matches rustfmt; a failure after syntax work may
  indicate truncation — inspect the diff before running mutating `fmt`.
- `check --locked` / `--all-targets --all-features`: library, binary,
  tests, examples, and benches compile against the pinned lockfile.
- `clippy -D warnings`: no lint regressions; do not suppress globally
  to make the gate green.
- `test --locked`: full suite (unit + integration). Never `#[ignore]`,
  delete, or weaken a failing test; fix the cause.
- `build --release --locked`: the shippable artifact compiles optimized.
- `search lint`: embedded provider corpus has zero errors
  (`errors 0`; warnings are advisory short-marker notes, not hidden
  failures). Details: `docs/PROVIDER_CONTRACT.md`.
- `node --check`: RXScan GUI bundle parses (portfolio scripts are a
  separate project and are never part of this bundle).
- `git diff --check`: no whitespace errors in the proposed change.
- `package --list`: crate contents match the `include`/`exclude`
  policy in `Cargo.toml` (GUI, corpus, fingerprints in; portfolio,
  runtime state, secrets out).

Flaky-test policy: the historically suspicious TCP fixture
(`tests/phase6_tcp.rs`, serialized full-default scans) is stressed
repeatedly, e.g. five consecutive runs of the focused tests. A
failure is investigated as a race/timing/state bug — never hidden
with bigger sleeps, removed concurrency coverage, or weakened
assertions.

## Local gates vs hosted CI

- "Local gates passed" = the commands above passed on this machine.
- "Hosted GitHub CI passed" = the `CI` workflow in
  `.github/workflows/ci.yml` ran green on the hosted runner for the
  commit under review.

These are different facts. Local verification and hosted execution
differ in environment, timing, and toolchain provisioning. Never write
"CI green" or "all gates pass" based solely on local execution.
Documentation may say "local release gates passed" only when the exact
commands above actually passed.

## Deterministic network-test policy

- Local fixtures only: loopback listeners on OS-assigned ephemeral
  ports (`127.0.0.1:0` / `[::1]:0`); the test reads back the assigned
  port and targets exactly that port. No arbitrary Internet services.
- Readiness synchronization: bind proves listener readiness; server
  threads signal via channels or the test polls with a bounded
  deadline (e.g. web-API tests poll `/api/v1/health` up to 10 s).
  No `spawn; sleep(100ms); hope`.
- Bounded deadlines everywhere; deterministic shutdown and thread
  join. Where shared :---locked test state is genuinely required
  (default-port scans that would otherwise cross-find fixtures), it
  is scoped tightly with an explanatory comment
  (`tests/phase6_tcp.rs::DEFAULT_SCAN_LOCK`); poison failures fail
  loudly rather than hiding the root cause.
- Synthetic values only: `example.test`, `exampleuser`,
  `user@example.test`, `192.0.2.10`, `198.51.100.20`, `203.0.113.x`,
  `2001:db8::10`, `AS64500`, `example-org/example-project`.
  Loopback `127.0.0.1`/`::1` stays where genuine local integration
  requires it.
