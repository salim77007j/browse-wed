//! JavaScript engine hot paths.
//!
//! QuickJS-ng is not V8 and does not pretend to be; the promise that
//! matters for a privacy-first browser is *bounded, predictable* script
//! cost: per-site isolation with hard memory caps and interrupt-driven
//! timeouts — plus enough throughput for the 99% of page scripts that
//! are glue code, not compute kernels. These benches pin the numbers.

use bw_js::{JsEngine, RuntimeLimits, SiteRuntime};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_javascript(c: &mut Criterion) {
    let rt = SiteRuntime::new("https://bench.example", RuntimeLimits::default()).unwrap();

    let mut group = c.benchmark_group("quickjs_eval");

    group.bench_function("arithmetic_tight_loop_1e6", |b| {
        b.iter(|| {
            // IIFE: repeated evals must not collide in the global lexical scope.
            rt.exec("(() => { let s = 0; for (let i = 0; i < 1e6; i++) s += i; return s; })()")
                .unwrap()
        });
    });

    group.bench_function("json_parse_10k", |b| {
        // 10k-element array stringify+parse round trip.
        b.iter(|| {
            rt.exec(
                r#"(() => {
                const a = new Array(10000).fill(0).map((_, i) => ({ id: i, v: i * 2 }));
                return JSON.parse(JSON.stringify(a)).length;
                })()"#,
            )
            .unwrap()
        });
    });

    group.bench_function("string_build_100k", |b| {
        b.iter(|| {
            rt.exec(
                r#"(() => {
                let s = '';
                for (let i = 0; i < 100000; i++) s += 'x';
                return s.length;
                })()"#,
            )
            .unwrap()
        });
    });

    group.bench_function("object_churn_100k", |b| {
        b.iter(|| {
            rt.exec(
                r#"
                let keep = 0;
                for (let i = 0; i < 100000; i++) { const o = { a: i, b: { c: i } }; keep += o.b.c; }
                keep
            "#,
            )
            .unwrap()
        });
    });
    group.finish();

    // Engine-level: runtime creation cost (the suspension/restore path).
    let engine = JsEngine::new(RuntimeLimits::default());
    let mut group = c.benchmark_group("runtime_lifecycle");
    group.bench_function("site_runtime_create", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i += 1;
            let rt = SiteRuntime::new(&format!("https://s{i}.example"), RuntimeLimits::default())
                .unwrap();
            std::hint::black_box(&rt);
        });
    });
    group.bench_function("suspend_and_respawn", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i += 1;
            let site = format!("https://cycle{i}.example");
            engine.exec(&site, "globalThis.x = new Array(1000).fill(1);").unwrap();
            engine.suspend_site(&site).unwrap();
            engine.exec(&site, "1").unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_javascript);
criterion_main!(benches);
