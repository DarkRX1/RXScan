# Reconnaissance depth verification (unreleased work)

- Date: 2026-10-04
- RXScan version: 0.1.0 (unreleased recon-depth work on top of Phase 21)
- Fixture class: controlled local only — loopback listeners, synthetic DNS
  packets, in-memory fingerprint matching, single-host project files. No
  public Internet traffic.
- Commands:
  `cargo fmt --check`
  `cargo clippy --all-targets --all-features -- -D warnings`
  `cargo test --locked`

## Results (controlled local, no superiority claims)

- Full suite: 708+ tests pass, 0 failures (baseline before work: all green).
- Fingerprint corpus: 265 rules across 13 packs, up from 5 rules in 2 packs.
  Every rule matches
  its own pattern; protocol gating and malformed-input tests pass.
- New protocol probes (SMB/RDP/MongoDB/MQTT) verified against loopback
  fixtures: correct classification, no authentication bytes observed.
- UDP Wave-2 grammars (TFTP/SIP/IKE/mDNS/SNMP-response/QUIC-indicator)
  verified as pure parser tests plus live loopback classification.
- Host discovery: active ARP/NDP packet parsing, link-scope classification,
  SYN/ACK technique confidence, and corroboration capping verified as unit
  tests.
- DNS SRV: wire-format round trip plus typed service-discovery relation.
- `rxscan project explain` verified against constructed project state
  (conclusion, evidence scans, findings, changes, bounded neighbors).
- Coverage-aware vulnerability resolution: reason-labeled removals
  (resolved_by_software_change/dataset_changed/coverage_insufficient/
  unknown) instead of blanket "upgraded or out of range".

## Notes

- This is a correctness/regression record, not a network-performance claim.
- No Internet or external fixture-server traffic occurred.
- Raw SYN is implemented for IPv4 on capable Linux hosts. Unsupported hosts,
  insufficient privilege, and IPv6 use an explicitly reported connect
  fallback.
