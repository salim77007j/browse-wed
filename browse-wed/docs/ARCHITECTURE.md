# browse-wed Engine Architecture

> Status: v0.1 — engine core complete. The UI is a separate consumer of
> `bw-api`; nothing in this document requires it.

## The ten-second version

browse-wed is a **privacy-first, memory-frugal browser engine** in nine Rust
crates. It speaks HTTP/1.1, HTTP/2 and HTTP/3 (QUIC) over TLS 1.3 with
DoH/DoT DNS, blocks trackers *below* the network layer, partitions all site
data (CHIPS), runs JavaScript in per-site QuickJS-ng runtimes with hard
memory/time caps, and suspends background tabs to ~100 bytes each.

```text
┌─────────────────────────── bw-api (UI contract) ──────────────────────────┐
│  Command (serde) ──► BrowserApi ──► Event (broadcast)                    │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   │
┌────────────────────────── bw-engine (orchestrator) ───────────────────────┐
│ TabRegistry   MemoryGovernor   SessionStore   PagePipeline   sweep_idle  │
└───┬───────────────┬────────────────┬───────────────┬────────────────┬─────┘
    │               │                │               │                │
┌───▼────┐  ┌───────▼──────┐  ┌──────▼─────┐  ┌──────▼─────┐  ┌──────▼─────┐
│bw-net- │  │ bw-storage   │  │ bw-privacy │  │ bw-js      │  │ bw-render  │
│work    │  │ cookies/LS/  │  │ filters/   │  │ QuickJS-ng │  │ tokenizer/ │
│ h1/h2/ │  │ IDB/cache    │  │ cosmetic/  │  │ worker     │  │ DOM/CSS    │
│ h3/DNS │  │ over redb    │  │ fp/safe-   │  │ thread     │  │ fonts      │
│        │  │              │  │ browsing   │  │            │  │            │
└────────┘  └──────────────┘  └────────────┘  └────────────┘  └────────────┘
```

## Crate map

| Crate | Responsibility | Key guarantee |
|---|---|---|
| `bw-api` | UI contract: commands in, events out, all serde | No engine type escapes |
| `bw-engine` | Tabs, governor, session, page pipeline, suspension | Idle tabs cost ~0 RAM |
| `bw-network` | Fetch pipeline: policy→cache→cookies→h1/h2/h3 | Blocked requests cost 0 I/O |
| `bw-storage` | Partitioned cookies/LS/IDB + HTTP cache over redb | All site data partitioned |
| `bw-privacy` | Filters, cosmetic, anti-fingerprint, safe browsing | Zero I/O, deterministic |
| `bw-js` | Per-site QuickJS runtimes on a worker thread | 64 MiB heap cap, timeouts |
| `bw-render` | HTML tokenizer, DOM, CSS cascade, fonts | Never panics on hostile input |

## The fetch pipeline (the heart)

Every resource request flows through `bw-network::fetch::FetchService::fetch`
in this exact order — the order *is* the privacy and performance model:

1. **Policy check** (`bw-privacy` filter set + Safe Browsing Bloom). Runs
   before any socket exists: a blocked tracker costs zero DNS queries, zero
   TLS handshakes, zero kernel buffers. Measured: **109–190 ns per decision**,
   flat from 18 to 2,018 rules.
2. **HTTPS upgrade / HSTS** from the learned policy state (loopback exempt).
3. **HTTP cache lookup** — fresh hits short-circuit before transport.
4. **Header assembly** — UA, accepts, `Sec-Fetch-*`, and the cookie line from
   the *partitioned* jar (`get_for(url, top_level_site, secure)`).
5. **Transport selection** — HTTP/3 when Alt-Svc advertised it (QUIC via
   quinn), else the pooled h1/h2 client; ALPN decides h2 vs h1.1.
   On h3 failure: automatic fallback to h1/h2 (RFC 9114 racing behavior).
6. **Redirects** (≤ 10, re-checked against policy, method rewritten per
   RFC 9110).
7. **Set-Cookie absorption** through CHIPS partitioning — third-party
   cookies without a partition key are rejected at storage time.
8. **Learning** — HSTS and Alt-Svc from response headers.
9. **Cache storage** when cacheable.

Every response carries `FetchTiming` (dns/connect/tls/ttfb/total) — the
same numbers the UI performance panel and the benchmark suite consume.

## Threading model

| Concern | Owner |
|---|---|
| Network I/O | tokio runtime (multi-thread), pooled connections |
| JavaScript | **one dedicated worker thread** owns all QuickJS runtimes |
| Storage | redb's ACID engine, called from async context via brief locks |
| Page DOM | owned per-tab inside the engine's state mutex |
| UI events | `tokio::sync::broadcast` (1024-slot ring, many subscribers) |

JavaScript deliberately does **not** use rquickjs's `parallel` feature: its
global lock would let one long script stall every site. The worker-thread
model is what browsers actually do — zero locks on the execution path,
site isolation by construction.

## Memory model

The [`MemoryGovernor`](../engine/src/memory.rs) derives every budget from
**available RAM** (re-measured on each sweep):

* HTTP cache memory budget = 5% of available (≤ 192 MiB),
* JS heap cap = 64 MiB per site (32 MiB under 2 GiB available),
* background tabs older than 5 min (default) are suspended: DOM dropped,
  JS heap dropped in one call, ~100-byte session entry retained,
* high pressure → sweep suspends *all* backgrounded tabs regardless of age.

Measured at v0.1: **cold start 1.95 ms**, **100 tabs in 595 µs**, **idle RSS
10.1 MB** with 50 suspended tabs (see `benchmarks/README.md`).

## Process model

v0.1 is single-process with strict *logical* isolation: per-site JS heaps,
partitioned storage, worker-thread confinement. OS-level site isolation
(process-per-site) is the v0.2 roadmap item — see `docs/ROADMAP.md` for the
design (spawn the engine per profile + sandbox via OS primitives).

## What is deliberately NOT here

Honest scope notes for reviewers:

* **Layout/paint**: `bw-render` parses, cascades and font-metrics; a full
  layout engine + GPU compositor is the v0.2 track. The DOM/CSS pipeline
  is real; the raster pipeline ships the font system and paints through
  tiny-skia primitives.
* **V8-class JS throughput**: QuickJS-ng is 2–10× slower on hot compute.
  The trade buys per-site heaps that *drop* in one call and hard caps.
* **Safe Browsing updates**: the local Bloom DB and prefix protocol exist;
  the update fetcher is engine-level plumbing the UI wires to its update
  channel (docs/SECURITY.md).
