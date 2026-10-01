//! Engine-level performance harness (not criterion — wall-clock claims):
//!
//! * **cold start** — engine bring-up, stage-timed,
//! * **tab churn** — create/navigate-background-suspend cycles,
//! * **idle memory** — RSS after N suspended tabs (the RAM promise).
//!
//! Run: `cargo run -p bw-bench --release --bin engine_perf`
//! Output: JSON to stdout + `target/criterion/engine_perf.json` for CI.

use std::time::{Duration, Instant};

use bw_engine::{BrowserEngine, EngineConfig, GovernorPolicy, MemoryPressure, TabState};
use bw_network::NetworkConfig;

const TAB_PAGE: &str = r#"
<html><head><title>Tab</title></head>
<body><div class="row"><p>cell content</p></div></body></html>
"#;

fn main() {
    let mut report = serde_json::Map::new();

    // ---- Cold start ------------------------------------------------------
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let profile = tempfile::tempdir().expect("temp profile");

    let started = Instant::now();
    let engine = rt.block_on(async {
        BrowserEngine::new(EngineConfig {
            profile_dir: profile.path().to_path_buf(),
            network: NetworkConfig {
                // No DNS bootstrap in the harness: deterministic numbers.
                dns: bw_network::DnsMode::System,
                ..NetworkConfig::default()
            },
            governor: GovernorPolicy::default(),
            network_filter_rules: bw_engine::starter_network_filters()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            cosmetic_filter_rules: bw_engine::starter_cosmetic_filters()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ..EngineConfig::default()
        })
        .await
        .expect("engine start")
    });
    let cold_start = started.elapsed();

    let startup = engine.startup();
    report.insert("cold_start_ms".into(), serde_json::json!(cold_start.as_secs_f64() * 1000.0));
    report.insert("startup_stages_ms".into(), startup.as_millis_map());
    println!("cold start: {:.2?}", cold_start);

    // ---- Tab churn -------------------------------------------------------
    rt.block_on(async {
        let churn_started = Instant::now();
        const TABS: u64 = 100;
        let mut tab_create_us = Vec::new();
        for i in 0..TABS {
            let t0 = Instant::now();
            let id = engine.new_tab().await;
            tab_create_us.push(t0.elapsed().as_micros() as f64);
            // Load a local page (about:-style) so tabs hold real page data.
            engine.load_local(id, &format!("about:tab{i}"), TAB_PAGE).await.unwrap();
            if i % 2 == 0 {
                engine.background_tab(id).await.unwrap();
            }
        }
        let churn = churn_started.elapsed();
        let mean_create_us = tab_create_us.iter().sum::<f64>() / tab_create_us.len() as f64;
        report.insert("tab_create_mean_us".into(), serde_json::json!(mean_create_us));
        report.insert("hundred_tabs_ms".into(), serde_json::json!(churn.as_secs_f64() * 1000.0));
        println!("100 tabs opened in {:.2?} (mean create {:.1} us)", churn, mean_create_us);

        // ---- Suspension sweep -------------------------------------------
        // Age all background tabs past the threshold instantly.
        let sweep_started = Instant::now();
        {
            // Force threshold to zero by direct suspension measurement:
            // backgrounded tabs get suspended by sweep only after the
            // configured idle time; simulate elapsed time by suspending
            // through the engine's explicit path (same cost profile).
            let tabs = engine.tabs_snapshot().await;
            let backgrounded: Vec<_> =
                tabs.iter().filter(|t| t.state == TabState::Backgrounded).map(|t| t.id).collect();
            for id in backgrounded {
                engine.suspend_tab(id).await.unwrap();
            }
        }
        let sweep = sweep_started.elapsed();
        report.insert("suspend_50_tabs_ms".into(), serde_json::json!(sweep.as_secs_f64() * 1000.0));
        println!("50 background tabs suspended in {:.2?}", sweep);

        let counts = engine.tab_counts().await;
        assert_eq!(counts.suspended, 50, "sweep failed");
        assert_eq!(counts.blank + counts.loaded + counts.loading, 50);

        // ---- JS heap after suspension -----------------------------------
        let js = engine.exec_js("https://churn.example", "1 + 1").unwrap();
        assert_eq!(js, bw_js::JsValue::Number(2.0));
        let stats = engine.stats().await;
        report.insert("js_live_runtimes".into(), serde_json::json!(stats.js.live_runtimes));
        report.insert("js_total_heap_bytes".into(), serde_json::json!(stats.js.total_heap_bytes));
        report.insert("memory_pressure".into(), serde_json::json!(format!("{:?}", stats.pressure)));
        println!(
            "js runtimes after churn: {} (heap {} bytes), pressure {:?}",
            stats.js.live_runtimes, stats.js.total_heap_bytes, stats.pressure
        );
        let _ = MemoryPressure::Low;
    });

    // ---- Idle memory ------------------------------------------------------
    // RSS is the honest number; /proc/self/status works on Linux.
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                report.insert("idle_rss".into(), serde_json::json!(rest.trim()));
                println!("idle RSS: {}", rest.trim());
            }
        }
    }

    // ---- Persist ----------------------------------------------------------
    report.insert(
        "generated_at_unix".into(),
        serde_json::json!(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()),
    );
    let out = serde_json::to_string_pretty(&serde_json::Value::Object(report)).unwrap();
    println!("\n{out}");
    let _ = std::fs::create_dir_all("target/criterion");
    std::fs::write("target/criterion/engine_perf.json", out).ok();
    let _ = Duration::ZERO;
}
