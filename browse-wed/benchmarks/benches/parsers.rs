//! Parser hot paths: HTML tokenization, tree building, CSS cascade.
//!
//! These are the paths every page load pays; the numbers that matter for
//! "page load faster than Chromium" claims are dominated by network +
//! parse + style. The fixtures are a realistic mid-size page.

use bw_render::{cascade, parse_html, parse_stylesheet};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

/// A realistic mid-size page (~40 KiB, deeply nested, mixed content).
fn sample_html() -> String {
    let mut html = String::with_capacity(48 * 1024);
    html.push_str("<!doctype html><html><head><title>Bench Page</title>");
    html.push_str("<style>body{margin:0} .row{display:flex} .cell{padding:8px}</style>");
    html.push_str("</head><body>");
    for row in 0..80 {
        html.push_str("<div class=\"row\" data-row=\"");
        html.push_str(&row.to_string());
        html.push_str("\">");
        for cell in 0..10 {
            html.push_str("<div class=\"cell\"><p>Cell ");
            html.push_str(&cell.to_string());
            html.push_str(
                " content with <a href=\"/x\">a link</a> and <b>bold</b> text.</p></div>",
            );
        }
        html.push_str("</div>");
    }
    html.push_str("<script>console.log('done');</script></body></html>");
    html
}

/// A realistic stylesheet (~8 KiB).
fn sample_css() -> String {
    let mut css = String::with_capacity(10 * 1024);
    for i in 0..200 {
        css.push_str(&format!(
            ".c{i} {{ color: #{:02x}{:02x}{:02x}; margin: {i}px {i}px; padding: 2px 4px; }}\n",
            i % 256,
            (i * 7) % 256,
            (i * 13) % 256
        ));
    }
    css.push_str("div.row > div.cell p { font-size: 14px; line-height: 1.4; }\n");
    css.push_str("#main .content a:hover { text-decoration: underline; }\n");
    css
}

fn bench_parsers(c: &mut Criterion) {
    let html = sample_html();

    let mut group = c.benchmark_group("html");
    group.throughput(Throughput::Bytes(html.len() as u64));
    group.bench_function("tokenize+build_tree", |b| {
        b.iter(|| parse_html(&html));
    });
    // Tree building alone (tokens pre-computed).
    let tokens = bw_render::tokenize(&html);
    group.bench_function("build_tree_only", |b| {
        b.iter(|| bw_render::build_tree(tokens.clone()));
    });
    group.finish();

    let css = sample_css();
    let mut group = c.benchmark_group("css");
    group.throughput(Throughput::Bytes(css.len() as u64));
    group.bench_function("parse_stylesheet", |b| {
        b.iter(|| parse_stylesheet(&css));
    });
    // Full style pipeline: parse DOM + cascade.
    let doc = parse_html(&html);
    group.bench_function("cascade_full_page", |b| {
        b.iter(|| cascade(&doc, &[], ""));
    });
    group.finish();
}

criterion_group!(benches, bench_parsers);
criterion_main!(benches);
