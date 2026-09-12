# RXScan — Reactive Recon Scanner

Simple outside. Serious inside.

RXScan is being built as a standalone, native Rust reconnaissance platform. Phases 0–2 establish typed target normalization, a central deny-by-default scope policy, TOML configuration precedence, an inspectable scan-plan compiler, and a stable asset/event/evidence/finding model. It does not execute network activity yet; that begins after the reactive scheduler, budgets, and network phases are in place.

```text
rxscan https://target.test --explain
```

See [the architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), [configuration](docs/CONFIGURATION.md), and [threat model](docs/THREAT_MODEL.md).

## Phase 1 planning

```bash
rxscan https://target.test --goal web --level 3 --speed balanced --explain
rxscan target.test --config ~/.config/rxscan/config.toml --project-config ./rxscan.toml --explain
```

`--level` controls investigation depth; `--speed` controls execution pressure. They are independent.

## Preserved prototype

Operator portfolio: public cyber lab + private intelligence vault.

Visual language follows [satvik.live/about](https://www.satvik.live/about) (matrix terminal, Fira Code, card layout, clock | SECURE). Content does not dump a CV into the hero.

## Run

```bash
python3 -m http.server 4173
```

Open `http://127.0.0.1:4173`.

## Routes

| Path | Layer |
| --- | --- |
| `#/` | Public identity |
| `#/about` | Supporting evidence (education, youth work, earlier digital work) |
| `#/projects` | Sanitized cyber work |
| `#/console` | Private console (auth) |
| `#/console/cs-031` | Technical case study |

Demo operator key: `darkrx` (change `passphrase` in `js/data.js` before hosting). Session only — not a real security boundary.
