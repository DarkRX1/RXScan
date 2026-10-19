# RXScan Mission Contract

## AMENDMENT rev 2
- Test baseline: 1408 passed / 0 failed / 0 ignored (library 478 + integration ~930)

## GATE PARITY
- CI pins Rust 1.85.0. Run all gates with `cargo +1.85.0 ...`
- Clippy caches aggressively. Sub-second runs after edits are false passes.
- A green run on any toolchain is not the pinned one. Use `--locked` everywhere.

## RESERVED VALUES
- Only acceptable in tracked files: example.test, example.com, *.invalid,
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, 555-01xx, 127.0.0.1
- 203.0.113.0/24 is a /24, not a /16.
- A privacy-gate PASS is not evidence when a file is wildcard-exempt. Show the grep.

## WILDCARD ALLOWLIST ENTRIES
- Entries with `*` value-sha256-prefix require justification and maintainer sign-off.

## LOCKED BUILDS
- CI runs cargo with `--locked`. Any Cargo.toml change requires committing Cargo.lock.

## FROZEN FILES (clause 11)
- Frozen: root index.html, js/, css/, _headers/, certificates/, dashboard PNGs
- Editable: app/*
- Flag-and-ask rule applies to frozen files.

## PRIVACY GATE
- Permanent generic secret/identity scanner over tracked files.
- Run `sh scripts/privacy_gate.sh` before every commit.

## HISTORY POLICY
- Published tags (present on a remote) are never moved, recreated, or deleted.
- A tag created locally but never pushed may be repositioned before its first push;
  the reposition is recorded in the release checklist.

## TEST INTEGRITY
- No test weakening, deletion, or `#[ignore]` allowed.
- No blank `#[allow(...)]` or disabled lints to get clippy green.

## ICON SOURCE OF TRUTH
- Root `rxscan-icons/` is STAGING ONLY, untracked, never referenced by code.
- Tracked pack is `app/assets/icons/`.

## PHASE EXECUTION
- One commit per phase. Re-read this contract at the start of each phase.
