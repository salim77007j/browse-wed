# Roadmap

The engine core (v0.1) is complete and green: fetch pipeline with h1/h2/h3,
TLS 1.3, DoH/DoT, privacy enforcement at every layer, per-site JS with hard
caps, tab lifecycle with suspension, sessions, tests, benchmarks, CI.

What follows is the honest, ordered path from "engine core" to "the browser
that replaces your browser". Ordering is by user-visible impact per unit of
engineering risk.

## v0.2 — the renderer (the big one)

A production layout + paint + compositor pipeline on top of `bw-render`:

* **Layout**: full block/flex/grid layout over the existing cascade output
  (the CSS engine already computes the inputs; block+flex skeletons exist
  in the style structs).
* **Text**: full shaping via swash (kerning, ligatures, bidi runs) — the
  current cmap-level shaping is the known gap.
* **Paint**: retained tile raster through tiny-skia → GPU upload path for
  the UI's compositor.
* **Compositor contract**: the engine hands the UI damaged tile regions;
  60 FPS scrolling is a UI/engine shared budget, measured, not asserted.
* **Incrementalism**: style diffing + dirty-region layout so a DOM change
  does not re-layout the world.

## v0.2 — OS process isolation

Site isolation with OS teeth:

* engine-per-profile already isolates JS heaps and storage logically;
  v0.2 moves page workers into separate OS processes with sandboxing
  (seccomp/landlock on Linux, AppContainer on Windows),
* the fetch pipeline stays in the broker process — policy enforcement
  remains non-bypassable by design.

## v0.3 — web platform breadth

* `fetch()`/XHR bindings into the JS bridge (wired to the existing
  `FetchService`, inheriting all policy/cookies/partitioning),
* DOM bindings (the arena DOM already models the tree; expose the WebIDL
  surface incrementally),
* events, storage APIs (`localStorage` bindings over the partitioned
  backend that already exists),
* service workers — engine-level design: one per site, same worker-thread
  confinement as page JS.

## v0.3 — network polish

* **Full PSL** for registrable-domain logic (replacing last-two-labels),
* HTTP/2/3 connection coalescing across same-IP origins,
* ECH (Encrypted Client Hello) when rustls lands it,
* early-hints (103) handling,
* preload scanner (tokenize ahead of tree building for speculative fetch).

## v0.4 — extension surface

A privacy-preserving extension model is an *engine* API question:
content-blocking declarations (declarativeNetRequest-style) compile
directly into the existing filter engine; no imperative network
interception is exposed, by policy.

## Non-goals (explicit)

* Telemetry of any kind.
* 0-RTT QUIC (replay hazard).
* Persisted TLS session tickets (linkable identifier).
* Chrome extension compatibility wholesale — the security model differs.
