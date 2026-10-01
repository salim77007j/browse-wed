# Security Policy & Threat Model

## Reporting

Open a private security advisory via GitHub's "Report a vulnerability"
on this repository, or contact the maintainer directly. Please include a
reproducer; fuzz harnesses in `tests/src/fuzz.rs` make those trivial to
write. We aim for a 72-hour first response.

## Memory safety posture

| Surface | Posture |
|---|---|
| Everything except QuickJS FFI + RAM detection | `#![forbid(unsafe_code)]` — enforced per module, not just claimed |
| QuickJS FFI (`bw-js`) | One audited unsafe surface area: `rquickjs` bindings. Contained on a dedicated worker thread with heap/stack/time caps |
| System RAM detection (`bw-engine::memory`) | Two audited FFI calls: `sysconf` (Unix) / `GlobalMemoryStatusEx` (Windows) |
| Third-party C in the tree | QuickJS-ng (via rquickjs-sys) — memory-capped per site, fuzzed input paths, sandboxed by runtime limits |

CI enforces **ASan + LSan** (nightly, `-Zsanitizer=address,leak`) on the
unsafe-bearing crates and **Valgrind** on the integration suite, every
push. A leak or an invalid access fails the build.

## Threat model

### 1. Hostile web content (primary)

* **Malformed HTML/CSS** — the tokenizer and CSS parser never panic on
  arbitrary bytes; verified by 2,000-iteration seeded fuzz harnesses per
  parser in CI (`tests/src/fuzz.rs`). Malformed input degrades to text,
  exactly like a browser.
* **Pathological nesting** — the tree builder bounds stack depth
  structurally (arena, no recursion on hostile depth); tested with
  200-deep inputs and fuzzed structure.
* **JS resource exhaustion** — per-site 64 MiB heap cap, 1 MiB stack cap,
  interrupt-driven wall-clock deadlines. `while(true){}` dies at its
  timeout; allocation bombs die at the heap cap; recursion bombs die at
  the stack cap. All three are pinned by tests
  (`infinite_loop_times_out`, `memory_limit_enforced`,
  `deep_recursion_hits_stack_cap`).
* **Timing side channels** — `performance.now` coarsened to 5 µs; JS
  confined to one worker thread (no shared-cache timing against the
  network stack's threads).

### 2. Hostile network input

* **TLS** — rustls (pure Rust) with TLS 1.3 + modern suites; certificate
  verification is **never** disabled; the only configuration knob is the
  ALPN list.
* **HTTP parsers** — hyper (h1/h2) and h3/quinn (RFC 9000/9114 stacks)
  are the industry-battle-tested implementations; our code around them
  is `forbid(unsafe)` and bounds bodies (64 MiB h3 path cap).
* **DNS** — hickory with DoH/DoT; the manager itself adds no parsing
  beyond URL shapes it validates at config time.

### 3. Tracking & fingerprinting

See `docs/PRIVACY.md` — enforced at the engine layer (network blocking,
CHIPS partitioning, CNAME uncloaking, per-session fingerprint seeds,
QUIC without 0-RTT, no persisted TLS tickets).

### 4. Local attack surface

* **Profile data** — one ACID redb file + one session JSON, atomic
  writes. No execution of profile data; deleting the directory is a
  complete reset.
* **Safe Browsing DB** — a Bloom filter + full-hash set persisted via
  `to_bytes`; deserialization (`from_bytes`) is total and validated
  (fuzzed). Corrupt DB files yield `None`, never UB.

### 5. Supply chain

* Direct dependencies are small, focused, widely-audited crates
  (tokio, hyper, rustls, quinn, hickory, redb, rquickjs, tiny-skia,
  fontdb, swash, aho-corasick). No framework, no macro-magic crates.
* `Cargo.lock` is committed; CI builds exactly the locked graph.
* No build-time script execution beyond QuickJS-ng's own Makefile via
  rquickjs-sys (CC invocation), which is the standard, audited path.

## Safe Browsing update protocol (privacy-preserving)

The engine ships the data structure and the check path; an updater
(periodic task owned by the UI layer) speaks this protocol:

1. **Never** send full URLs. Send 4-byte SHA-256 prefixes of the
   canonicalized URL, over the engine's own fetch pipeline (which itself
   uses DoH + TLS 1.3).
2. The response is a list of (prefix, full 32-byte hash, TTL). The DB's
   `apply_prefixes`/`add_full_hash` ingest it locally.
3. A prefix match with no confirming full hash yields `Unverified` —
   navigations escalate to a UI warning, never a silent block
   (Bloom false positives must not break the web).
4. Updates are logged to the in-memory stats only; nothing persists
   about which prefixes were queried.

## Fuzzing

`tests/src/fuzz.rs` runs in CI on every push (stable toolchain,
deterministic seeds — a failure is reproducible by seed). The input
types derive `Arbitrary`, so lifting any harness into a coverage-guided
`cargo-fuzz` target is mechanical when continuous fuzzing infrastructure
is desired:

| Harness | Target surface |
|---|---|
| `fuzz_html_tokenizer_never_panics` | tokenizer + tree builder + traversal |
| `fuzz_html_idempotent_text_tail` | re-tokenization determinism |
| `fuzz_css_parser_never_panics` | CSS parse + cascade |
| `fuzz_filter_rules_never_panic` | rule parse + compile + decide |
| `fuzz_cosmetic_selectors_never_panic` | selector parse + match |
| `fuzz_safebrowsing_canonicalize_and_bloom` | canonicalize + Bloom + serialize |
| `fuzz_set_cookie_parsing_never_panics` | Set-Cookie parse + jar ops |
| `fuzz_cname_chains_never_panic` | uncloaker inspection |
| `fuzz_hsts_and_alt_svc_parsing` | policy header parsing |
| `fuzz_structured_filter_decisions` | `Arbitrary`-generated full-path cases |
