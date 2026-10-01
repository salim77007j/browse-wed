# browse-wed Engine

[![build-test](https://github.com/salim77007j/browse-wed/actions/workflows/build-test.yml/badge.svg)](https://github.com/salim77007j/browse-wed/actions/workflows/build-test.yml)
![License](https://img.shields.io/badge/license-MPL--2.0-blue)

**A privacy-first, ultra-lightweight browser engine core in Rust.** This
repository is the *engine and backend* — the UI is a separate consumer
that binds to [`bw-api`](docs/API.md) and needs zero Rust knowledge to do
so.

```text
h1/h2/h3 + QUIC + TLS 1.3 + DoH/DoT     partitioned cookies/LS/IDB (CHIPS)
tracker blocking BELOW the network      per-site QuickJS runtimes, 64MiB caps
anti-fingerprinting at engine level     tab suspension -> ~100 bytes/tab
```

## Measured, not promised

Full methodology and numbers: [`benchmarks/README.md`](benchmarks/README.md).
Run everything yourself: `cargo run -p bw-bench --release --bin engine_perf`.

| Metric | browse-wed v0.1 | Notes |
|---|---|---|
| **Engine cold start** | **1.95 ms** | all subsystems staged |
| **Idle RSS (100 tabs, 50 suspended)** | **10.1 MB** | vs ~150–300 MB for one Chrome blank tab |
| **100 tabs opened** | 595 µs (0.1 µs/tab) | with real page data |
| **50 tabs suspended** | 622 µs | heaps dropped in one call |
| **Tracker-block decision** | 109–190 ns | flat from 18 → 2,018 rules |
| **HTML parse** | 77 MiB/s | tokenizer + tree |
| **HTTP cache hit** | 1.3 µs | 1,000 entries |

For head-to-head against Chrome/Firefox/Brave on your machine:
[`benchmarks/scripts/compare_browsers.sh`](benchmarks/scripts/compare_browsers.sh).

## Why it is fast and small

1. **Blocking happens before I/O.** Filter-set decisions run before DNS,
   sockets, and TLS. A blocked tracker costs *zero* kernel work — the
   structural advantage over extension-based blocking.
2. **Suspension is deletion.** A background tab's JS heap is freed *in one
   call* and its DOM dropped wholesale. A suspended tab is its session
   entry: ~100 bytes.
3. **Budgets derive from the machine.** The memory governor re-measures
   available RAM on every sweep; cache budgets are fractions of reality,
   not constants that fit the developer's laptop.
4. **No V8.** Per-site QuickJS-ng runtimes: 64 MiB heap caps, interrupt
   timeouts, zero cross-site heap coupling — with glue-code throughput
   that pages actually notice only in compute kernels.
5. **Everything is `#![forbid(unsafe_code)]`** except two audited FFI
   surfaces (QuickJS bindings, RAM detection), which CI runs under
   ASan/LSan + Valgrind on every push.

## Quick start

```bash
cargo build --workspace
cargo test  --workspace          # unit + integration + fuzz harnesses
cargo run  -p bw-bench --release --bin engine_perf
```

Requires Rust 1.85+ (stable) and a C compiler (QuickJS-ng builds from
source). Windows (MSVC) and Linux are first-class — CI builds and tests
both on every push. Details: [`docs/BUILDING.md`](docs/BUILDING.md).

## Repository layout

| Path | Contents |
|---|---|
| [`engine/`](engine) | tab registry, memory governor, sessions, page pipeline |
| [`networking/`](networking) | the fetch pipeline: policy → cache → cookies → h1/h2/h3 |
| [`storage/`](storage) | CHIPS-partitioned cookies/LS/IDB + HTTP cache (redb) |
| [`privacy/`](privacy) | filter engine, cosmetic rules, anti-fingerprinting, safe browsing |
| [`js-engine/`](js-engine) | QuickJS-ng worker thread, per-site runtimes |
| [`rendering/`](rendering) | HTML tokenizer, DOM, CSS cascade, fonts |
| [`api/`](api) | **the UI contract** — commands + events, pure serde |
| [`tests/`](tests) | integration suite + property-fuzz harnesses |
| [`benchmarks/`](benchmarks) | criterion suites, engine harness, browser comparison |
| [`docs/`](docs) | architecture, API, building, privacy, security, roadmap |

## Connecting a UI (the short version)

```rust
let api = bw_api::BrowserApi::start(options).await?;
let mut events = api.subscribe();                       // event stream
let tab = api.command(Command::NewTab).await?["tab"].as_u64().unwrap();
api.command(Command::Navigate { tab, url: "https://example.com".into() }).await?;
```

Commands and events are plain JSON — bind from Rust, Tauri, Electron, or
a socket. The complete contract (every command, every event shape, every
error tag, a Tauri snippet): [`docs/API.md`](docs/API.md).

## Documentation

* [Architecture](docs/ARCHITECTURE.md) — the crate map, fetch pipeline,
  threading and memory models
* [API reference](docs/API.md) — the UI contract, end to end
* [Building](docs/BUILDING.md) — prerequisites, sanitizers, tooling
* [Privacy model](docs/PRIVACY.md) — every layer, and how to verify each
* [Security policy](docs/SECURITY.md) — threat model, fuzzing, Safe
  Browsing update protocol
* [Roadmap](docs/ROADMAP.md) — v0.2 renderer, process isolation, platform
  breadth

## Honest scope

This is the **engine core** (v0.1). It fetches, parses, styles, blocks,
partitions, executes, suspends, persists — with the privacy and memory
model fully enforced. The full layout/paint/compositor pipeline, DOM/JS
web-API bindings, and OS-process sandboxing are the v0.2+ track, designed
for in [ROADMAP.md](docs/ROADMAP.md) — not hand-waved.

## License

MPL-2.0 — see [LICENSE](LICENSE).
