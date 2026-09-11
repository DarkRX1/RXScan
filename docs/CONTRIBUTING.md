# Contributing

Work one phase at a time. Do not introduce external scanner dependencies into the core engine or bypass the Scope Guard.

Before submitting a phase run:

```bash
cargo fmt --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Add tests and a controlled fixture or benchmark record appropriate to the change. Update the architecture, roadmap, status, threat model, and benchmark documentation when behavior or risk changes.
