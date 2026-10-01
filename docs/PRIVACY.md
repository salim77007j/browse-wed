# The browse-wed Privacy Model

Privacy is enforced at the **engine layer**, not bolted on with extension
APIs. This document explains each mechanism, where it lives, and how to
verify it.

## Layer 0: blocking before I/O

`bw-network::fetch` checks every request against the compiled filter set
(`bw-privacy::filter`) *before* DNS, before sockets, before TLS. This is
the structural advantage over extension-based blocking (uBlock on Chrome
intercepts only after the network stack has created request objects and
often after DNS prefetch). Measured cost per decision: **109–190 ns**
at both 18 and 2,018 rules (see `benchmarks/README.md`) — the automata
(Aho-Corasick + domain buckets + compiled regexes) do not degrade with
list size.

Filter syntax: uBlock/EasyList-compatible (`||host^`, `$script,image`,
`$third-party`, exceptions `@@`, plain patterns). The engine ships a
curated starter list; the UI layer installs full lists (EasyList,
EasyPrivacy) by handing raw rule text to the engine — no proprietary
format, no phone-home.

**Verify:** integration test `tracker_navigation_blocked_without_wire`
asserts a blocked navigation issues *zero DNS queries*.

## Layer 1: partitioned storage (CHIPS)

Every storage surface in `bw-storage` is keyed by (top-level site, origin):

* **Cookies** — full RFC 6265bis jar with `Partitioned` support. A
  third-party cookie without a partition key is **rejected at storage
  time**; partitioned cookies are only ever returned to their own
  partition. Third-party cookies can be refused entirely
  (`set_allow_third_party(false)` — the engine default allows only
  partitioned ones through).
* **LocalStorage / IndexedDB** — per-(partition, origin) keyspaces.
* **HTTP cache** — keyed by URL + Vary; the memory budget scales with
  available RAM (the governor re-derives it on every sweep).
* **"Forget this site"** — `Storage::purge_site` removes every trace of a
  (partition, origin) across all four surfaces in one ACID transaction.

**Verify:** `bw-storage` test `purge_site_removes_everything`; the
cookie CHIPS tests cover rejection and partition-scoped retrieval.

## Layer 2: CNAME uncloaking

Trackers hide behind first-party-looking subdomains
(`metrics.your-site.com` → CNAME → `tracker.example`). The DNS manager
exposes the full CNAME chain; `bw-privacy::cname::Uncloaker` detects
chains crossing into known tracker apex domains, and the request is
re-run through the filter set with the *effective* host. The uncloaker
ships a default tracker-suffix set and accepts additional domains.

## Layer 3: anti-fingerprinting

`bw-privacy::fingerprint::FpEngine` derives a stable per-(site, session)
seed and computes every spoofed signal:

| Surface | Behaviour |
|---|---|
| Canvas | per-site farbling (`farble_canvas`) — deterministic noise |
| Audio | per-sample farbling (`farble_audio`) |
| WebGL | per-site vendor/renderer strings (`webgl_strings`) |
| Navigator | fixed hardwareConcurrency/deviceMemory per site |
| Screen | rounded dimensions |
| Fonts | allowlist-only font enumeration |
| Timezone | coarsened |
| WebRTC | policy enum incl. full disable (`WebRtcPolicy`) |
| `Math.random` | per-site seed (re-seeded at runtime in `bw-js`) |
| `performance.now` | 5 µs coarsening (timing-attack resistant) |

The seed is derived from a **per-session key** (rotated every engine
start): stable within a site for the session (sites don't break),
uncorrelated across sites (cross-site tracking impossible), and
non-persistent (cross-session linkability impossible).

**Mode:** `FpMode::{Off, Balanced, Maximum}` — the engine default is
Balanced.

## Layer 4: transport privacy

* **TLS 1.3** (rustls, pure Rust) with modern AEAD suites only — no CBC,
  no RSA key exchange. In-memory session resumption only: no persisted
  tickets (they are linkable identifiers).
* **QUIC/HTTP-3 without 0-RTT** — 0-RTT is replayable; disabled
  explicitly in `bw-network::h3`.
* **DNS-over-HTTPS / DNS-over-TLS** — the resolver manager bootstraps the
  secure resolver once through the system resolver, then encrypts every
  query. Defaults offered: Cloudflare, Quad9, Google; the privacy preset
  picks Quad9.
* **HTTPS upgrades** for navigations + HSTS honouring (loopback exempt,
  like every mainstream browser).
* **Safe Browsing** — local Bloom filter over 4-byte URL-hash prefixes;
  **full URLs never leave the device**. The only wire format is
  fixed-length hash prefixes (see SECURITY.md for the update protocol).

## Layer 5: JavaScript containment

Per-site QuickJS runtimes with **hard caps**: 64 MiB heap, 1 MiB stack,
interrupt-driven wall-clock timeouts. One site's leaky script cannot eat
the engine; a spinning script dies at its deadline; a suspended tab's
heap is freed *entirely* in one call. Script execution lives on a
dedicated worker thread — one site cannot observe another's timing.

## What we do NOT do

Honest limits (v0.1):

* No full PSL (public suffix list) — registrable-domain logic uses the
  last-two-labels approximation. A `co.uk`-style edge case can
  over-partition (safe direction: more partitioning, not less).
* No HTTP referer trimming, no `Sec-GPC` yet — both are engine-level and
  queued for v0.2 (they belong in the fetch header assembly).
* No safe-browsing update client — the local DB + protocol exist; wiring
  it to an update source is a UI-layer decision (which list provider,
  which cadence) documented in SECURITY.md.

## Telemetry

**None.** No metrics file, no crash reporter, no "usage statistics", no
DNS beacon. The engine's diagnostics counters (`stats()`) are in-process
and in-memory only; the UI that ships them is the UI's choice — the
engine never opens a socket that the fetch pipeline did not open for a
page's own benefit.
