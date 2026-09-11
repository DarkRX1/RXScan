# Configuration

Phase 1 supports explicit TOML layers:

```text
built-in defaults < --config GLOBAL.toml < --project-config PROJECT.toml < CLI
```

Profiles and runtime overrides are planned additions. Supported keys are `goal`, `level`, `speed`, `profile`, `scope`, `exclude`, `ports`, and `all_ports`.

```toml
goal = "web"
level = 3
speed = 40
scope = ["example.test"]
exclude = ["admin.example.test"]
ports = "80,443"
```

`level` must be 1–5. `speed` is `slow`, `balanced`, `fast`, `auto`, or 0–100. A CLI value always wins. Lists from a higher layer replace lower-layer lists so a project cannot silently inherit a broader scope.
