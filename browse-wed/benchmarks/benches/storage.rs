//! Storage hot paths: per-request cookie matching and cache operations.
//!
//! `CookieJar::get_for` runs on every outgoing request; the cache
//! `get`/`put` pair runs on every loadable resource. Both must stay in
//! the nanosecond-to-low-microsecond range or they become visible in
//! page-load traces.

use bw_storage::cache::{CacheMeta, HttpCache};
use bw_storage::cookies::{Cookie, CookieJar, SameSite};
use criterion::{criterion_group, criterion_main, Criterion};

fn cookie(name: &str, domain: &str, partition: Option<&str>) -> Cookie {
    Cookie {
        name: name.to_string(),
        value: "x".repeat(24),
        domain: domain.to_string(),
        path: "/".to_string(),
        expires: None,
        secure: true,
        http_only: false,
        same_site: SameSite::Lax,
        host_only: false,
        partition_key: partition.map(|p| p.to_string()),
        creation_time: std::time::SystemTime::now(),
    }
}

fn jar_with(n: usize) -> CookieJar {
    let mut jar = CookieJar::new();
    for i in 0..n {
        let domain =
            if i % 3 == 0 { "site.example".to_string() } else { format!("t{i}.cdn.example") };
        jar.set(cookie(
            &format!("k{i}"),
            &domain,
            if i % 2 == 0 { None } else { Some("site.example") },
        ));
    }
    jar
}

fn bench_storage(c: &mut Criterion) {
    let jar_50 = jar_with(50);
    let jar_1000 = jar_with(1000);

    let mut group = c.benchmark_group("cookie_get_for");
    group.bench_function("50_cookies_first_party", |b| {
        b.iter(|| jar_50.get_for("https://site.example/page", "site.example", true));
    });
    group.bench_function("1000_cookies_first_party", |b| {
        b.iter(|| jar_1000.get_for("https://site.example/page", "site.example", true));
    });
    group.finish();

    let cache = HttpCache::new(64 * 1024 * 1024, 256 * 1024 * 1024);
    let body: Vec<u8> = vec![0x42; 16 * 1024];
    let meta = |len: usize| CacheMeta {
        status: 200,
        content_type: "application/javascript".into(),
        etag: Some("\"v1\"".into()),
        last_modified: None,
        expires_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        vary: Vec::new(),
        body_len: len,
        stored_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Pre-populate 1000 entries.
    for i in 0..1000 {
        cache.put(&format!("https://cdn.example/r/{i}.js"), None, meta(1024), vec![7; 1024]);
    }

    let mut group = c.benchmark_group("http_cache");
    group.bench_function("put_16k_body", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i += 1;
            cache.put(
                &format!("https://cdn.example/w/{i}.js"),
                None,
                meta(body.len()),
                body.clone(),
            );
        });
    });
    group.bench_function("get_hit_1000_entries", |b| {
        b.iter(|| cache.get_fresh("https://cdn.example/r/500.js", None));
    });
    group.bench_function("get_miss_1000_entries", |b| {
        b.iter(|| cache.get_fresh("https://cdn.example/absent.js", None));
    });
    group.finish();
}

criterion_group!(benches, bench_storage);
criterion_main!(benches);
