//! Privacy hot paths: the per-request decision cost.
//!
//! The filter engine's `decide()` runs for EVERY subresource of EVERY
//! page — a 3 MiB page with 300 requests pays this 300 times. The
//! promise "blocking at the network layer beats extension blocking"
//! rests on these numbers being sub-microsecond.

use bw_privacy::filter::FilterSet;
use bw_privacy::safebrowsing::SafeBrowsingDb;
use bw_privacy::{RequestContext, ResourceType};
use criterion::{criterion_group, criterion_main, Criterion};

fn starter_list() -> Vec<&'static str> {
    vec![
        "||doubleclick.net^",
        "||google-analytics.com^",
        "||googletagmanager.com^$script",
        "||googlesyndication.com^",
        "||facebook.net^$script,third-party",
        "||scorecardresearch.com^",
        "||adnxs.com^",
        "||criteo.com^",
        "||taboola.com^",
        "||outbrain.com^",
        "||advertising.com^",
        "||2mdn.net^",
        "||adservice.google.com^",
        "||analytics.tiktok.com^",
        "||bam.nr-data.net^",
        "-banner-ad.",
        "/analytics.js",
        "/pagead/",
    ]
}

/// An EasyList-scale rule count (exercise the bucket structures).
fn large_list() -> Vec<String> {
    let mut rules = starter_list().iter().map(|s| s.to_string()).collect::<Vec<_>>();
    for i in 0..2000 {
        rules.push(format!("||tracker{i}.example^"));
        rules.push(format!("/ad-slot-{i}/"));
    }
    rules
}

fn ctx(url: &str) -> RequestContext {
    RequestContext {
        url: url::Url::parse(url).unwrap(),
        source_host: "news.example.com".to_string(),
        source_base: "example.com".to_string(),
        resource_type: ResourceType::SCRIPT,
    }
}

fn bench_privacy(c: &mut Criterion) {
    let small = FilterSet::compile(starter_list()).expect("valid rules");
    let large_rules = large_list();
    let large = FilterSet::compile(&large_rules).expect("valid rules");

    let first_party = ctx("https://news.example.com/app.js");
    let tracker = ctx("https://doubleclick.net/pixel?id=1");
    let third_party_clean = ctx("https://cdn.jsdelivr.net/npm/lib.js");
    let deep_tracker = ctx("https://tracker1999.example/x.js");

    let mut group = c.benchmark_group("filter_decide");

    group.bench_function("first_party_allow/starter_list", |b| {
        b.iter(|| small.decide(&first_party));
    });
    group.bench_function("tracker_block/starter_list", |b| {
        b.iter(|| small.decide(&tracker));
    });
    group.bench_function("third_party_allow/starter_list", |b| {
        b.iter(|| small.decide(&third_party_clean));
    });
    group.bench_function("first_party_allow/2k_rules", |b| {
        b.iter(|| large.decide(&first_party));
    });
    group.bench_function("tracker_block/2k_rules", |b| {
        b.iter(|| large.decide(&deep_tracker));
    });
    group.finish();

    // Safe browsing: 10k-prefix Bloom filter.
    let mut sb = SafeBrowsingDb::new(10_000, 0.001);
    let mut prefixes = Vec::new();
    for i in 0..2000u32 {
        prefixes.push([0x11, 0x22, 0x33, i as u8]);
    }
    sb.apply_prefixes(prefixes);
    let mut group = c.benchmark_group("safe_browsing");
    group.bench_function("check_known_host", |b| {
        b.iter(|| sb.check("https://suspicious.example.net/path"));
    });
    group.finish();
}

criterion_group!(benches, bench_privacy);
criterion_main!(benches);
