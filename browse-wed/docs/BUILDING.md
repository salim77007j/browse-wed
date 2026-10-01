# Building the browse-wed Engine

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Rust | 1.85+ (stable) | `rustup` recommended; `rust-toolchain.toml` pins the toolchain |
| C compiler + make | any | QuickJS-ng builds from source via `rquickjs-sys` |
| Python 3 | 3.8+ | only for the browser-comparison script |

Windows: MSVC Build Tools (the `x86_64-pc-windows-msvc` target) — the
standard `rustup` default install includes everything needed.

## Quick start

```bash
git clone https://github.com/salim77007j/browse-wed
cd browse-wed
cargo build --workspace            # debug build of all crates
cargo test  --workspace            # 226 tests: unit, integration, fuzz harnesses
cargo run  -p bw-bench --release --bin engine_perf   # cold-start / RAM numbers
```

First build compiles QuickJS-ng (C) and the TLS/QUIC stack; expect a few
minutes. Subsequent builds are incremental.

## Workspace layout

```
engine/       tab registry, memory governor, session, page pipeline
networking/   fetch pipeline, h1/h2/h3, TLS 1.3, DoH/DoT DNS, policy
storage/      partitioned cookies / LS / IDB / HTTP cache (redb)
privacy/      filter engine, cosmetic rules, anti-fp, safe browsing
js-engine/    QuickJS-ng worker thread, per-site runtimes
rendering/    HTML tokenizer, DOM, CSS cascade, fonts
api/          the UI contract (commands + events)
tests/        integration suite + property-fuzz harnesses
benchmarks/   criterion suites, engine_perf, browser comparison
docs/         this documentation
ci -> .github/workflows/
```

## Common tasks

```bash
# Formatting + linting (CI enforces both with -D warnings)
cargo fmt --all
cargo clippy --workspace --all-targets -- -- -D warnings

# Full test suite including release-mode pass
cargo test --workspace
cargo test --workspace --release

# Benchmarks
cargo bench -p bw-bench                                   # all criterion suites
cargo bench -p bw-bench --bench privacy                   # one suite
cargo run  -p bw-bench --release --bin engine_perf        # wall-clock claims

# Fuzz harnesses (they are regular tests — see tests/src/fuzz.rs)
cargo test -p bw-tests --test fuzz
```

## Memory sanitizers (Linux)

CI runs both on every push; locally:

```bash
rustup toolchain install nightly
RUSTFLAGS="-Zsanitizer=address -Zsanitizer=leak" \
  cargo +nightly test -p bw-js -p bw-engine --tests --target x86_64-unknown-linux-gnu

# Valgrind as a second opinion on the integration suite:
cargo build --workspace --tests
valgrind --leak-check=full --error-exitcode=99 \
  $(ls -t target/debug/deps/integration-* | grep -v '\.d$' | head -1)
```

The sanitizer jobs cover every crate containing audited `unsafe` (the
QuickJS FFI boundary in `bw-js`, libc/Win32 memory detection in
`bw-engine`); all other crates are `#![forbid(unsafe_code)]` and are
exercised under ASan via the integration suite.

## Comparing against Chrome/Firefox/Brave

On a machine with the browsers installed:

```bash
benchmarks/scripts/compare_browsers.sh          # full (60 s settles)
benchmarks/scripts/compare_browsers.sh --quick  # 15 s settles
```

Prints a Markdown table: cold start, idle RSS, 20-tab RSS, local page
load. Methodology in `benchmarks/README.md`.

## Profile data

Everything the engine persists lives under the profile directory:

```
<profile>/site-data.redb    cookies, LS, IDB, cache index (ACID)
<profile>/session.json      open tabs + histories (atomic writes)
```

Deleting the directory is a complete reset. No data is written anywhere
else — no registry, no dotfiles, no telemetry.
