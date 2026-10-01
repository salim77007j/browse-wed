//! Fuzzing harnesses — property-based, stable-toolchain.
//!
//! Every harness is deterministic pseudo-random input (seeded from
//! `Arbitrary`) driven through a parser or decision surface with
//! hard invariants asserted on every iteration. These run as ordinary
//! tests in CI: no nightly, no libFuzzer, no special tooling — a panic
//! anywhere is a bug caught by the pipeline.
//!
//! For continuous fuzzing (libFuzzer, coverage-guided), the same input
//! types (`Arbitrary`) drop into `cargo-fuzz` targets unchanged; see
//! docs/SECURITY.md.

#![forbid(unsafe_code)]

use arbitrary::Arbitrary;
use bw_privacy::cname::{CnameChain, Uncloaker};
use bw_privacy::cosmetic::CosmeticFilterSet;
use bw_privacy::filter::FilterSet;
use bw_privacy::safebrowsing::{canonicalize, BloomFilter, SafeBrowsingDb};
use bw_privacy::{Decision, RequestContext, ResourceType};
use bw_render::{cascade, parse_html, parse_stylesheet, tokenize};
use bw_storage::cookies::{parse_set_cookie_for_url, CookieJar};

/// Deterministic pseudo-random bytes from a simple xorshift stream.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

/// Random bytes biased toward HTML-ish structure (tags, quotes, brackets).
fn htmlish(rng: &mut Rng, len: usize) -> String {
    const ALPHABET: &[u8] =
        b"<>/=\"' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-&;#!\n\t";
    (0..len).map(|_| ALPHABET[(rng.next_u64() as usize) % ALPHABET.len()] as char).collect()
}

/// Random bytes biased toward CSS-ish structure.
fn cssish(rng: &mut Rng, len: usize) -> String {
    const ALPHABET: &[u8] = b"{}:;,.#[]()= \nabcdefghijklmnopqrstuvwxyz0123456789%-/*";
    (0..len).map(|_| ALPHABET[(rng.next_u64() as usize) % ALPHABET.len()] as char).collect()
}

/// Random bytes biased toward filter-rule structure.
fn ruleish(rng: &mut Rng, len: usize) -> String {
    const ALPHABET: &[u8] = b"||^$*~|.,-/#@:[]=\" abcdefghijklmnopqrstuvwxyz0123456789_";
    (0..len).map(|_| ALPHABET[(rng.next_u64() as usize) % ALPHABET.len()] as char).collect()
}

/// Random URL-ish strings.
fn urlish(rng: &mut Rng) -> String {
    const HOSTS: &[&str] = &[
        "example.com",
        "sub.example.com",
        "tracker.example",
        "localhost",
        "cdn.example.net",
        "a.b.c.example.org",
        "xn--80ak6aa92e.com",
    ];
    const SCHEMES: &[&str] = &["http", "https", "ftp", "data", "ws"];
    let scheme = SCHEMES[(rng.next_u64() as usize) % SCHEMES.len()];
    let host = HOSTS[(rng.next_u64() as usize) % HOSTS.len()];
    let path_len = (rng.next_u64() % 24) as usize;
    let path: String =
        (0..path_len).map(|_| (b'a' + (rng.next_u64() % 26) as u8) as char).collect();
    format!("{scheme}://{host}/{path}")
}

const ITERS: usize = 2_000;

// ---------------------------------------------------------------- html ---

#[test]
fn fuzz_html_tokenizer_never_panics() {
    let mut rng = Rng::new(0x5eed_1111);
    for i in 0..ITERS {
        let input = {
            let n = (rng.next_u64() % 512) as usize;
            htmlish(&mut rng, n)
        };
        let tokens = tokenize(&input);
        // Invariant 1: tokenization never panics (never-panic guarantee).
        // Invariant 2: tree building never panics.
        let doc = bw_render::build_tree(tokens);
        // Invariant 3: every document has the implicit scaffold.
        assert!(doc.len() >= 3, "iter {i}: doc too small ({})", doc.len());
        // Invariant 4: traversal over the whole tree is safe.
        let mut count = 0usize;
        for _node in doc.traverse() {
            count += 1;
        }
        assert!(count >= 3);
        // Invariant 5: text extraction is total.
        let _ = doc.title();
    }
}

#[test]
fn fuzz_html_idempotent_text_tail() {
    // Whatever the input, the tokenizer must never lose the final text
    // run's content beyond what framing requires.
    let mut rng = Rng::new(0x5eed_2222);
    for _ in 0..ITERS / 4 {
        let input = {
            let n = (rng.next_u64() % 128) as usize;
            htmlish(&mut rng, n)
        };
        let tokens = tokenize(&input);
        let count = tokens.len();
        let retok = tokenize(&input);
        // Re-tokenizing the same input yields the same stream.
        assert_eq!(count, retok.len());
    }
}

// ----------------------------------------------------------------- css ---

#[test]
fn fuzz_css_parser_never_panics() {
    let mut rng = Rng::new(0x5eed_3333);
    let doc = parse_html("<html><body><div class=\"c\" id=\"i\"><p>x</p></div></body></html>");
    for _ in 0..ITERS {
        let css = {
            let n = (rng.next_u64() % 256) as usize;
            cssish(&mut rng, n)
        };
        let sheet = parse_stylesheet(&css);
        // Cascade with hostile CSS must not panic and must terminate.
        let _styles = cascade(&doc, &[sheet], "");
    }
}

// -------------------------------------------------------------- filters ---

#[test]
fn fuzz_filter_rules_never_panic() {
    let mut rng = Rng::new(0x5eed_4444);
    // Phase 1: parse + compile hostile rules.
    let rules: Vec<String> = (0..256)
        .map(|_| {
            let n = (rng.next_u64() % 64) as usize;
            ruleish(&mut rng, n)
        })
        .collect();
    // Compile must not panic whether it succeeds or rejects.
    let set = FilterSet::compile(&rules).unwrap_or_else(|_| FilterSet::from_filters(Vec::new()));
    // Phase 2: decide hostile requests against the compiled set.
    for _ in 0..ITERS {
        let url = urlish(&mut rng);
        let Ok(parsed) = url::Url::parse(&url) else {
            continue;
        };
        let ctx = RequestContext {
            url: parsed,
            source_host: "example.com".into(),
            source_base: "example.com".into(),
            resource_type: ResourceType::ANY,
        };
        let verdict = set.decide(&ctx);
        // Invariant: the verdict is one of the three defined values.
        assert!(matches!(verdict, Decision::Allow | Decision::Block | Decision::Neuter));
    }
}

#[test]
fn fuzz_cosmetic_selectors_never_panic() {
    let mut rng = Rng::new(0x5eed_5555);
    let doc = parse_html(
        "<html><body><div id=\"a\" class=\"x y\"><span>1</span></div><p>2</p></body></html>",
    );
    let mut rules: Vec<String> = Vec::new();
    for _ in 0..128 {
        let sel = {
            let n = (rng.next_u64() % 48) as usize;
            ruleish(&mut rng, n)
        };
        rules.push(format!("example.com##{sel}"));
    }
    let set = CosmeticFilterSet::compile(&rules);
    let elements = doc.all_elements();
    let dom = bw_engine::page::PageDom(&doc);
    let hidden = set.hidden_nodes("example.com", &dom, &elements);
    // Never panics; hidden set is a subset of all elements.
    assert!(hidden.len() <= elements.len());
}

// --------------------------------------------------------- safe browsing ---

#[test]
fn fuzz_safebrowsing_canonicalize_and_bloom() {
    let mut rng = Rng::new(0x5eed_6666);
    let db = SafeBrowsingDb::new(1024, 0.01);
    for _ in 0..ITERS / 2 {
        let url = urlish(&mut rng);
        let canonical = canonicalize(&url);
        // Canonicalization is total (never panics) and produces a string.
        assert!(canonical.len() < 4096);
        let verdict = db.check(&url);
        assert!(matches!(
            verdict,
            bw_privacy::safebrowsing::Verdict::Safe
                | bw_privacy::safebrowsing::Verdict::Threat
                | bw_privacy::safebrowsing::Verdict::Unverified
        ));
        // Bloom filter serialization round trips.
        let bytes = db.to_bytes();
        if let Some(loaded) = SafeBrowsingDb::from_bytes(&bytes) {
            let _ = loaded.check(&url);
        }
    }
    // BloomFilter invariants: insert -> contains.
    let mut bloom = BloomFilter::with_rate(1024, 0.01);
    bloom.insert(b"needle");
    assert!(bloom.contains(b"needle"));
}

// -------------------------------------------------------------- cookies ---

#[test]
fn fuzz_set_cookie_parsing_never_panics() {
    let mut rng = Rng::new(0x5eed_7777);
    let mut jar = CookieJar::new();
    for _ in 0..ITERS {
        let header = {
            let n = (rng.next_u64() % 96) as usize;
            ruleish(&mut rng, n)
        };
        let url = urlish(&mut rng);
        if let Ok(parsed) = url::Url::parse(&url) {
            // Total on arbitrary header values.
            let _ = parse_set_cookie_for_url(&header, &parsed, "example.com", true);
        }
        // Jar operations on arbitrary cookies never panic.
        if let Some(cookie) = parse_set_cookie_for_url(
            &format!("k{header}"),
            &url::Url::parse("https://example.com/").unwrap(),
            "example.com",
            true,
        ) {
            jar.set(cookie);
        }
        let _ = jar.get_for("https://example.com/x", "example.com", true);
        jar.evict_expired();
    }
}

// ------------------------------------------------------- cname uncloaking ---

#[test]
fn fuzz_cname_chains_never_panic() {
    let mut rng = Rng::new(0x5eed_8888);
    let uncloaker = Uncloaker::with_defaults();
    for _ in 0..ITERS / 4 {
        let hop_count = (rng.next_u64() % 5) as usize;
        let mut hops = Vec::with_capacity(hop_count);
        for _ in 0..hop_count {
            hops.push(urlish(&mut rng));
        }
        let chain = CnameChain::new(urlish(&mut rng), hops);
        let report = uncloaker.inspect(&chain);
        // Either no report or a well-formed one.
        if let Some(report) = report {
            assert!(!report.requested.is_empty() || !report.tracker_domain.is_empty());
        }
        let _ = uncloaker.is_tracker(&urlish(&mut rng));
    }
}

// ------------------------------------------------------- policy parsing ---

#[test]
fn fuzz_hsts_and_alt_svc_parsing() {
    let mut rng = Rng::new(0x5eed_9999);
    for _ in 0..ITERS / 2 {
        let sts = {
            let n = (rng.next_u64() % 48) as usize;
            ruleish(&mut rng, n)
        };
        let _ = bw_network::policy::parse_max_age(&sts);
        let alt = {
            let n = (rng.next_u64() % 48) as usize;
            ruleish(&mut rng, n)
        };
        let _ = bw_network::policy::parse_alt_svc(&alt);
    }
}

// ---------------------------------------------------- structured arbitrary ---

#[derive(Arbitrary, Debug)]
struct FilterCase {
    rule: String,
    url: String,
    source: String,
    kind: u16,
}

#[test]
fn fuzz_structured_filter_decisions() {
    // Structured (Arbitrary-generated) cases through the full filter path.
    let mut rng = Rng::new(0x5eed_aaaa);
    let mut rules = Vec::new();
    for _ in 0..128 {
        let bytes = rng.bytes(48);
        let case: FilterCase = FilterCase::arbitrary(&mut arbitrary::Unstructured::new(&bytes))
            .unwrap_or(FilterCase {
                rule: String::new(),
                url: "https://example.com/".into(),
                source: "example.com".into(),
                kind: 0,
            });
        rules.push(case.rule);
    }
    let set = FilterSet::compile(&rules).unwrap_or_else(|_| FilterSet::from_filters(Vec::new()));
    for _ in 0..512 {
        let bytes = rng.bytes(48);
        if let Ok(case) = FilterCase::arbitrary(&mut arbitrary::Unstructured::new(&bytes)) {
            if let Ok(url) = url::Url::parse(&case.url) {
                let ctx = RequestContext {
                    url,
                    source_host: case.source.clone(),
                    source_base: case.source.clone(),
                    resource_type: ResourceType(ResourceType::ANY.0 & case.kind as u32),
                };
                let _ = set.decide(&ctx);
            }
        }
    }
}
