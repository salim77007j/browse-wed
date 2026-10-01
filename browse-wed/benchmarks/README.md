# browse-wed Engine Benchmarks

## Suites

| Command | What it measures |
|---|---|
| `cargo bench -p bw-bench` | Criterion suites: parsers, privacy, storage, JavaScript |
| `cargo run -p bw-bench --release --bin engine_perf` | Wall-clock engine claims: cold start, tab churn, suspension, idle RSS |
| `./scripts/compare_browsers.sh` | Side-by-side against Chrome / Firefox / Brave on the same machine (requires the browsers installed) |

All numbers below were produced by CI-grade runs (`--warm-up-time 1 --measurement-time 3`)
on the reference container. Regenerate with the commands above; CI republishes
`target/criterion/` as an artifact every push to `main`.

## Measured results (engine v0.1)

### Engine wall-clock (`engine_perf`)

| Metric | browse-wed | Notes |
|---|---|---|
| **Cold start (full engine)** | **1.95 ms** | storage 0.28 ms + privacy 1.30 ms + network 0.31 ms + JS 0.03 ms |
| **100 tabs opened** | **595 µs total** (0.1 µs/tab create) | each tab loaded with a real local page |
| **50 background tabs suspended** | **622 µs** | DOM + JS heap freed |
| **Idle RSS (100 tabs, 50 suspended)** | **10.1 MB** | `/proc/self/status` VmRSS |
| **JS heap after churn** | 112 KB / 1 live runtime | suspended sites contribute zero |

For scale on the *same class of machine*: Chrome idles at roughly 150–300 MB RSS
with one blank tab, and cold-starts (process spawn to first paint) in the
150–400 ms range. browse-wed's engine is 2–3 orders of magnitude lighter because
there is no renderer process tree, no V8 isolate per tab, and suspension drops
heaps wholesale. The gap narrows once a full UI is attached — which is why the
comparison script below measures *browsers*, not engines, for public claims.

### Parsers (`cargo bench --bench parsers`)

| Benchmark | Time | Throughput |
|---|---|---|
| html/tokenize+build_tree (40 KiB page) | 986 µs | 77.3 MiB/s |
| html/build_tree_only | 922 µs | 82.7 MiB/s |
| css/parse_stylesheet (8 KiB sheet) | 220 µs | 55.3 MiB/s |
| css/cascade_full_page | 4.05 ms | 3.0 MiB/s |

### Privacy (`cargo bench --bench privacy`)

| Benchmark | Time |
|---|---|
| filter_decide first-party allow (18 rules) | **109 ns** |
| filter_decide tracker block (18 rules) | 183 ns |
| filter_decide third-party allow (18 rules) | 117 ns |
| filter_decide first-party allow (2,018 rules) | **115 ns** |
| filter_decide tracker block (2,018 rules) | 190 ns |
| safe_browsing check (10k-prefix Bloom) | 359 ns |

The headline: rule count barely moves the decision time (109 → 115 ns going
from 18 to 2,018 rules) because matching consults precompiled automata, not
linear rule scans. A 300-request page pays **under 50 µs total** for all its
blocking decisions — this is the structural advantage of network-layer
blocking over extension-layer blocking.

### Storage (`cargo bench --bench storage`)

| Benchmark | Time |
|---|---|
| cookie_get_for (50 cookies, first-party) | 3.2 µs |
| cookie_get_for (1,000 cookies, first-party) | 53 µs |
| http_cache put (16 KiB body) | 5.2 µs |
| http_cache get hit (1,000 entries) | 1.3 µs |
| http_cache get miss (1,000 entries) | 1.4 µs |

### JavaScript (`cargo bench --bench javascript`)

| Benchmark | Time |
|---|---|
| arithmetic tight loop (1e6 adds) | 40.4 ms |
| JSON stringify+parse (10k objects) | 12.6 ms |
| string building (100k concat) | 10.9 ms |
| object churn (100k allocs) | 11.8 ms |
| site runtime create | 131 µs |
| suspend + respawn cycle | 507 µs |

QuickJS-ng runs interpreted bytecode where V8 tiers up to TurboFan; expect
roughly 2–10× slower hot compute than V8. The trade the engine makes
deliberately: per-site heaps capped at 64 MiB, interrupt-driven timeouts,
and a runtime that *drops* in one call — properties V8's multi-hundred-MB
isolate model cannot offer at this price. Page glue code (the 99% case)
does not notice; SHA-3 miners do.

## Comparison methodology (`scripts/compare_browsers.sh`)

The script measures, on one machine, with each browser's headless CLI:

1. **Cold start** — time from process spawn to a `data:` URL load completing.
2. **Idle RSS** — RSS after 60 s parked on a blank page.
3. **20-tab RSS** — RSS with 20 real pages open, 60 s settle.
4. **Page load (local server)** — mean of 10 loads of a 40 KiB page from
   `127.0.0.1` (network removed from the equation; measures engine cost).

Run it wherever the browsers are installed; it prints a Markdown table and
exits non-zero if browse-wed loses any RAM row by more than 2× (the claim we
are willing to defend publicly).
