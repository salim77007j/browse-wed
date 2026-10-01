# Worklog

---
Task ID: 1
Agent: Super Z (main agent)
Task: Resume and complete the browse-wed browser engine (previous session was interrupted mid-build; nothing had been pushed)

Work Log:
- Installed Rust 1.98.1 stable (rustup + clippy + rustfmt); verified GitHub repo was empty; pushed early backups
- Repaired the 3 pre-existing crates (storage/privacy/rendering): fixed swash 0.2.10 + fontdb 0.24 API drift, tokenizer raw-text off-by-one, tree-builder head/body text routing, CSS specificity group semantics, rgba rounding, fontdb generic-family probing → 98 tests green, clippy -D warnings clean
- Built bw-network (9 modules): config/dns(DoH/DoT+happy-eyeballs+CNAME)/tls(TLS1.3 rustls)/connector(custom tower service: DNS→TCP→TLS with ALPN reporting via TokioIo+hyper::rt)/http(pooled h1/h2)/h3(quinn+h3, stale reconnect, no 0-RTT)/policy(filters+safebrowsing+HSTS+Alt-Svc+loopback exemption)/fetch(full pipeline: policy-before-IO, cache, CHIPS cookies, redirects, fallback, timings) → 31 tests
- Built bw-js: SiteRuntime (64MiB heap cap, 1MiB stack, atomic-deadline interrupt handler, promise draining, error taxonomy), bridge (console→tracing, performance.now 5µs coarsening, crypto.getRandomValues all int TypedArrays via safe JS-level element access, per-site seeded Math.random), JsValue boundary (depth-capped cycle-proof), JsEngine as dedicated worker thread (browser-style single JS thread, LRU 8 runtimes, suspension) → 32 tests
- Built bw-engine: tab state machine + back/forward history, MemoryGovernor (sysconf/GlobalMemoryStatusEx, RAM-derived budgets, pressure tiers), session.json atomic persistence + stage-timed Startup, page pipeline (PageDom newtype adapter for orphan rule), BrowserEngine facade with sweep_idle suspension + load_local (about:-pages) → 26 tests
- Built bw-api: Command enum (serde JSON round-trippable) + Event broadcast (1024-slot) + BrowserApi + background sweeper service → 9 tests
- Tests crate: 10 integration tests over a local HTTP/1.1 responder through the full BrowserApi surface (DOM/title, cache reuse, cookies flowing back, redirects on pooled connections, pre-DNS tracker blocking, suspension, session round trip, JS exec, 404 history, back/forward) + 10 stable-toolchain property-fuzz harnesses (~20k hostile inputs)
- Benchmarks: 4 criterion suites (parsers/privacy/storage/javascript) + engine_perf harness + compare_browsers.sh. REAL MEASURED: cold start 1.95ms, idle RSS 10.1MB @ 100 tabs/50 suspended, 100 tabs 595µs, 50 suspends 622µs, filter decide 109–190ns flat 18→2018 rules, HTML 77MiB/s, cache hit 1.3µs
- Docs: ARCHITECTURE/API/BUILDING/PRIVACY/SECURITY/ROADMAP + README + MPL-2.0 LICENSE
- CI: .github/workflows/build-test.yml — fmt-check, clippy -D warnings (ubuntu+windows), tests debug+release (ubuntu+windows), bench suite with artifact upload, ASan+LSan (nightly) on unsafe-bearing crates, valgrind on integration binary
- Final validation: cargo fmt --check clean, clippy --workspace --all-targets -D warnings clean, 226 tests green
- 13 commits pushed to https://github.com/salim77007j/browse-wed (branch main)

Stage Summary:
- Deliverable: complete 9-crate Rust browser engine core at github.com/salim77007j/browse-wed
- 226 tests, zero warnings, clippy strict-clean, fuzz harnesses in CI, sanitizers in CI
- Key decisions: QuickJS-ng over V8 (per-site heaps that drop in one call), dedicated JS worker thread over rquickjs "parallel" global lock, blocking before any I/O, CHIPS partitioning everywhere, loopback exempt from https-upgrade, error pages stay in history
- Known follow-ups (documented in docs/ROADMAP.md): full layout/paint pipeline (v0.2), OS process isolation (v0.2), DOM/JS web API bindings (v0.3), full PSL
- SECURITY: user's GitHub token ghp_xgU5... was pasted in chat twice — user said they will rotate it after completion; must be treated as burned
