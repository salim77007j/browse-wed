//! # bw-engine — the browse-wed engine core
//!
//! The orchestrator that every other crate exists to serve. [`BrowserEngine`]
//! owns the whole stack and exposes the operations a browser actually has:
//! open tabs, navigate, go back/forward, background, suspend, restore.
//!
//! ```text
//! ┌──────────────────────────── BrowserEngine ────────────────────────────┐
//! │  TabRegistry          navigation state machine, histories             │
//! │  MemoryGovernor       RAM-derived budgets + suspension policy         │
//! │  FetchService (bw-network)   policy → cache → cookies → h1/h2/h3      │
//! │  Storage (bw-storage)        cookies / LS / IDB / HTTP cache (redb)   │
//! │  JsEngine (bw-js)            per-site QuickJS worker thread           │
//! │  FilterSet / CosmeticFilterSet / SafeBrowsing / FpEngine (bw-privacy) │
//! │  PageData (bw-render)        DOM + cosmetic hidden-set per tab        │
//! └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## The two RAM promises, mechanically kept
//!
//! 1. **Idle RAM is low.** Background tabs older than the governor's
//!    threshold are swept ([`BrowserEngine::sweep_idle`]): their JS runtime
//!    is dropped (frees the whole QuickJS heap in one call) and their page
//!    DOM is dropped (arena freed wholesale). A suspended tab costs its
//!    session entry — ~100 bytes.
//! 2. **Cache scales with the machine.** The HTTP cache budget is a
//!    fraction of *available* RAM (re-measured by every sweep), not a
//!    compile-time constant that fits only the developer's laptop.
//!
//! ## Startup
//!
//! Engine bring-up is stage-timed ([`session::Startup`]); the benchmark
//! suite asserts on those numbers. Every stage is constructed lazily
//! enough to keep cold start in the tens of milliseconds.

// Unsafe policy: all modules are `#![forbid(unsafe_code)]` except
// `memory`, whose audited libc/Win32 FFI reads system RAM.
pub mod memory;
pub mod page;
pub mod session;
pub mod tab;

use std::sync::Arc;
use std::time::Duration;

use bw_js::{JsEngine, JsValue, RuntimeLimits};
use bw_network::fetch::{CacheMode, FetchRequest, FetchResponse, FetchService};
use bw_network::NetworkConfig;
use bw_privacy::cosmetic::CosmeticFilterSet;
use bw_privacy::fingerprint::{FpEngine, FpMode};
use bw_privacy::filter::FilterSet;
use bw_privacy::safebrowsing::SafeBrowsingDb;
use bw_storage::cache::HttpCache;
use bw_storage::cookies::CookieJar;
use bw_storage::{Storage, StorageConfig};
use tokio::sync::Mutex;
use url::Url;

pub use memory::{GovernorPolicy, MemoryGovernor, MemoryPressure, MemorySnapshot};
pub use page::{PageData, PageStats};
pub use session::{SessionError, SessionFile, Startup};
pub use tab::{HistoryEntry, TabCounts, TabEntry, TabId, TabRegistry, TabState};

/// Engine-level errors.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Storage/profile failure.
    #[error("storage: {0}")]
    Storage(#[from] bw_storage::StorageError),
    /// Network stack failure.
    #[error("network: {0}")]
    Network(#[from] bw_network::NetworkError),
    /// Navigation/fetch failure.
    #[error("fetch: {0}")]
    Fetch(#[from] bw_network::FetchError),
    /// Bad URL / request shape.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// Session persistence failure.
    #[error("session: {0}")]
    Session(#[from] SessionError),
    /// Tab not found.
    #[error("no such tab")]
    NoSuchTab,
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Profile directory (site data + session live here).
    pub profile_dir: std::path::PathBuf,
    /// Networking configuration.
    pub network: NetworkConfig,
    /// Memory governor policy.
    pub governor: GovernorPolicy,
    /// Raw network filter rules (uBlock syntax), compiled at startup.
    pub network_filter_rules: Vec<String>,
    /// Raw cosmetic filter rules (`host##selector`), compiled at startup.
    pub cosmetic_filter_rules: Vec<String>,
    /// Anti-fingerprinting mode.
    pub fingerprint_mode: FpMode,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            profile_dir: std::env::temp_dir().join(format!(
                "browse-wed-profile-{}",
                std::process::id()
            )),
            network: NetworkConfig::default(),
            governor: GovernorPolicy::default(),
            network_filter_rules: Vec::new(),
            cosmetic_filter_rules: Vec::new(),
            fingerprint_mode: FpMode::Balanced,
        }
    }
}

impl EngineConfig {
    /// A privacy-forward configuration: DoH, HTTPS upgrades, the built-in
    /// starter filter list.
    pub fn privacy_default(profile_dir: impl Into<std::path::PathBuf>) -> EngineConfig {
        EngineConfig {
            profile_dir: profile_dir.into(),
            network: NetworkConfig::privacy_default(),
            governor: GovernorPolicy::default(),
            network_filter_rules: starter_network_filters()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            cosmetic_filter_rules: starter_cosmetic_filters()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            fingerprint_mode: FpMode::Balanced,
        }
    }
}

/// A minimal, curated starter filter list (the engine never phones home
/// for lists; the UI layer may install EasyList/EasyPrivacy later).
pub fn starter_network_filters() -> &'static [&'static str] {
    &[
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
    ]
}

/// Starter cosmetic filters.
pub fn starter_cosmetic_filters() -> &'static [&'static str] {
    &[
        "##[id*=\"google_ads\"]",
        "##[class*=\"ad-banner\"]",
        "##[class*=\"ad-slot\"]",
        "##iframe[src*=\"doubleclick\"]",
        "##ins.adsbygoogle",
        "##div[data-ad]",
        "##[aria-label=\"Advertisement\"]",
    ]
}

/// The outcome of one navigation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NavigationOutcome {
    /// Final URL (after redirects / upgrades).
    pub final_url: String,
    /// HTTP status (or synthetic status for policy blocks).
    pub status: u16,
    /// Page title (empty when blocked / non-HTML).
    pub title: String,
    /// Response body size in bytes.
    pub body_len: usize,
    /// Wire protocol that served the response.
    pub protocol: String,
    /// Served from HTTP cache?
    pub from_cache: bool,
    /// Page node statistics (zeros for non-HTML).
    pub page: PageStats,
    /// Elements hidden by cosmetic filters.
    pub cosmetic_hidden: usize,
    /// Privacy blocks during this navigation.
    pub blocked: u64,
    /// Total navigation time in milliseconds.
    pub total_ms: f64,
}

/// What a tab currently holds in memory.
struct LiveTab {
    page: PageData,
}

/// The browser engine.
pub struct BrowserEngine {
    config: EngineConfig,
    storage: Storage,
    fetch: Arc<FetchService>,
    js: JsEngine,
    cookies: Arc<Mutex<CookieJar>>,
    cache: Arc<HttpCache>,
    filters: Arc<FilterSet>,
    cosmetics: CosmeticFilterSet,
    safe_browsing: Arc<SafeBrowsingDb>,
    fingerprint: Mutex<FpEngine>,
    tabs: Mutex<TabRegistry>,
    governor: Mutex<MemoryGovernor>,
    live: Mutex<std::collections::HashMap<TabId, LiveTab>>,
    startup: Startup,
}

impl BrowserEngine {
    /// Bring the whole engine up, stage-timed. Must run inside a tokio
    /// runtime (the network stack is async).
    pub async fn new(config: EngineConfig) -> Result<Arc<BrowserEngine>, EngineError> {
        let mut timer = session::StartupTimer::new();

        // --- Stage: storage ------------------------------------------------
        let mut storage_config = StorageConfig::new(&config.profile_dir);
        // Budgets are refined after the governor measures RAM below; the
        // constructor's defaults only need to be *valid*.
        storage_config.memory_cache_budget = 32 * 1024 * 1024;
        storage_config.disk_cache_budget = 256 * 1024 * 1024;
        let storage = Storage::open(storage_config)?;
        timer.stage(session::stage_storage);

        // --- Stage: privacy ------------------------------------------------
        let filters = Arc::new(
            FilterSet::compile(&config.network_filter_rules)
                .map_err(|e| EngineError::InvalidUrl(format!("filter compile: {e}")))?,
        );
        let cosmetics = CosmeticFilterSet::compile(&config.cosmetic_filter_rules);
        // Empty local Safe Browsing DB; prefix updates arrive via the
        // update channel (see docs/PRIVACY.md — never raw URLs).
        let safe_browsing = Arc::new(SafeBrowsingDb::new(0, 0.001));
        let fingerprint = Mutex::new(FpEngine::from_key(fingerprint_session_key()));
        timer.stage(session::stage_privacy);

        // --- Stage: memory governor + budgets -------------------------------
        let governor = MemoryGovernor::new(config.governor);
        storage.cache_handle().set_memory_budget(governor.http_cache_memory_budget());
        let js_limits = RuntimeLimits {
            memory_limit: governor.js_heap_limit(),
            ..RuntimeLimits::default()
        };
        let cookies = Arc::new(Mutex::new(CookieJar::load(storage.db())?));
        let cache = storage.cache_handle();

        // --- Stage: network -------------------------------------------------
        let fetch = FetchService::new(
            config.network.clone(),
            Arc::clone(&filters),
            Arc::clone(&safe_browsing),
            Arc::clone(&cache),
            Arc::clone(&cookies),
        )
        .await?;
        timer.stage(session::stage_network);

        // --- Stage: javascript ----------------------------------------------
        let js = JsEngine::new(js_limits);
        timer.stage(session::stage_javascript);

        // --- Stage: rendering ------------------------------------------------
        // The font scan happens lazily per-page; record the (tiny) fixed
        // setup cost here to keep the stage honest.
        timer.stage(session::stage_rendering);

        let startup = timer.finish();
        Ok(Arc::new(BrowserEngine {
            config,
            storage,
            fetch,
            js,
            cookies,
            cache,
            filters,
            cosmetics,
            safe_browsing,
            fingerprint,
            tabs: Mutex::new(TabRegistry::new()),
            governor: Mutex::new(governor),
            live: Mutex::new(std::collections::HashMap::new()),
            startup,
        }))
    }

    /// Cold-start report.
    pub fn startup(&self) -> &Startup {
        &self.startup
    }

    /// Open a new tab; returns its id.
    pub async fn new_tab(&self) -> TabId {
        self.tabs.lock().await.create()
    }

    /// Close a tab and drop everything it holds.
    pub async fn close_tab(&self, id: TabId) -> bool {
        let existed = self.tabs.lock().await.close(id);
        if existed {
            self.live.lock().await.remove(&id);
            if let Some(site) = self.tabs.lock().await.get(id).and_then(|t| t.site.clone()) {
                let _ = self.js.suspend_site(&site);
            }
        }
        existed
    }

    /// Navigate a tab to `url`.
    pub async fn navigate(&self, id: TabId, url_str: &str) -> Result<NavigationOutcome, EngineError> {
        let url = Url::parse(url_str).map_err(|e| EngineError::InvalidUrl(e.to_string()))?;
        // Only http(s) is navigable at engine level.
        if !matches!(url.scheme(), "http" | "https") {
            return Err(EngineError::InvalidUrl(format!("scheme {} not navigable", url.scheme())));
        }
        {
            let mut tabs = self.tabs.lock().await;
            let tab = tabs.get_mut(id).ok_or(EngineError::NoSuchTab)?;
            tab.state = TabState::Loading;
        }
        let mut req = FetchRequest::navigation(url);
        req.cache_mode = CacheMode::Default;
        let response = self.fetch.fetch(req).await?;
        let outcome = self.absorb_response(id, response).await?;
        Ok(outcome)
    }

    /// Process a fetched response into tab state + page data.
    async fn absorb_response(
        &self,
        id: TabId,
        response: FetchResponse,
    ) -> Result<NavigationOutcome, EngineError> {
        let url = response.final_url.clone();
        let host = url.host_str().unwrap_or_default().to_string();
        let site = format!("{}://{}", url.scheme(), host);
        let content_type = response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let is_html = content_type.contains("text/html");

        let page = if is_html {
            let html = String::from_utf8_lossy(&response.body);
            Some(page::build_page(&html, &host, &self.cosmetics))
        } else {
            None
        };

        let outcome = NavigationOutcome {
            final_url: url.as_str().to_string(),
            status: response.status.as_u16(),
            title: page.as_ref().map(|p| p.title.clone()).unwrap_or_default(),
            body_len: response.body.len(),
            protocol: response.protocol.to_string(),
            from_cache: response.from_cache,
            page: page.as_ref().map(|p| p.stats).unwrap_or_default(),
            cosmetic_hidden: page.as_ref().map(|p| p.hidden.len()).unwrap_or(0),
            blocked: response.blocked_reason.is_some() as u64,
            total_ms: response.timing.total_ms,
        };

        {
            let mut tabs = self.tabs.lock().await;
            if let Some(tab) = tabs.get_mut(id) {
                tab.state = if response.status.is_success() {
                    TabState::Loaded
                } else {
                    TabState::Blank
                };
                tab.site = Some(site.clone());
                if response.status.is_success() {
                    tab.push_history(url.as_str().to_string(), outcome.title.clone());
                }
            }
        }
        if let Some(page) = page {
            self.live.lock().await.insert(id, LiveTab { page });
        }
        // Persist cookies absorbed by the fetch pipeline.
        let jar = self.cookies.lock().await;
        let _ = jar.persist(self.storage.db());
        drop(jar);
        Ok(outcome)
    }

    /// Go back in a tab's history; returns the URL navigated to.
    pub async fn go_back(&self, id: TabId) -> Result<Option<String>, EngineError> {
        let target = {
            let mut tabs = self.tabs.lock().await;
            let tab = tabs.get_mut(id).ok_or(EngineError::NoSuchTab)?;
            tab.go_back()
        };
        match target {
            Some(url) => {
                let _ = self.navigate(id, &url).await?;
                Ok(Some(url))
            }
            None => Ok(None),
        }
    }

    /// Go forward in a tab's history.
    pub async fn go_forward(&self, id: TabId) -> Result<Option<String>, EngineError> {
        let target = {
            let mut tabs = self.tabs.lock().await;
            let tab = tabs.get_mut(id).ok_or(EngineError::NoSuchTab)?;
            tab.go_forward()
        };
        match target {
            Some(url) => {
                let _ = self.navigate(id, &url).await?;
                Ok(Some(url))
            }
            None => Ok(None),
        }
    }

    /// Mark a tab backgrounded (starts the suspension clock).
    pub async fn background_tab(&self, id: TabId) -> Result<(), EngineError> {
        self.tabs
            .lock()
            .await
            .get_mut(id)
            .ok_or(EngineError::NoSuchTab)?
            .background();
        Ok(())
    }

    /// Activate a tab (wakes suspended tabs by re-navigating).
    pub async fn activate_tab(&self, id: TabId) -> Result<Option<String>, EngineError> {
        let wake_url = {
            let mut tabs = self.tabs.lock().await;
            let tab = tabs.get_mut(id).ok_or(EngineError::NoSuchTab)?;
            let was_suspended = tab.state == TabState::Suspended;
            tab.activate();
            if was_suspended {
                tab.current_url().map(|s| s.to_string())
            } else {
                None
            }
        };
        match wake_url {
            Some(url) => {
                let _ = self.navigate(id, &url).await?;
                Ok(Some(url))
            }
            None => Ok(None),
        }
    }

    /// Suspend a tab immediately: drop its DOM and JS heap.
    pub async fn suspend_tab(&self, id: TabId) -> Result<bool, EngineError> {
        let site = {
            let mut tabs = self.tabs.lock().await;
            tabs.get_mut(id)
                .ok_or(EngineError::NoSuchTab)?
                .suspend_and_site()
        };
        let page_dropped = self.live.lock().await.remove(&id).is_some();
        let js_dropped = match site {
            Some(s) => self.js.suspend_site(&s).unwrap_or(false),
            None => false,
        };
        Ok(page_dropped || js_dropped)
    }

    /// Sweep all backgrounded tabs whose idle time exceeded the governor's
    /// threshold. Returns the number of tabs suspended. Also refreshes the
    /// memory snapshot and re-derives cache budgets.
    pub async fn sweep_idle(&self) -> Result<usize, EngineError> {
        let (due, pressure) = {
            let mut governor = self.governor.lock().await;
            governor.refresh();
            self.cache.set_memory_budget(governor.http_cache_memory_budget());
            let pressure = governor.pressure();
            let tabs = self.tabs.lock().await;
            let due: Vec<TabId> = tabs
                .all()
                .iter()
                .filter(|t| t.state == TabState::Backgrounded)
                .filter(|t| governor.should_suspend(unix_bg_since(t)))
                .map(|t| t.id)
                .collect();
            (due, pressure)
        };
        // Under high pressure, suspend ALL backgrounded tabs regardless of age.
        let aggressive = pressure == MemoryPressure::High;
        let due = if aggressive {
            self.tabs
                .lock()
                .await
                .all()
                .iter()
                .filter(|t| t.state == TabState::Backgrounded)
                .map(|t| t.id)
                .collect()
        } else {
            due
        };
        let mut suspended = 0;
        for id in due {
            if self.suspend_tab(id).await? {
                suspended += 1;
            }
        }
        Ok(suspended)
    }

    /// Run a script in a site's JS context (engine-level helper for the
    /// API layer; the page pipeline calls it for inline scripts).
    pub fn exec_js(&self, site: &str, source: &str) -> Result<JsValue, bw_js::JsEngineError> {
        self.js.exec(site, source)
    }

    /// Snapshot of tab states.
    pub async fn tab_counts(&self) -> TabCounts {
        self.tabs.lock().await.counts()
    }

    /// All tabs (serialized snapshot) — for the UI and session save.
    pub async fn tabs_snapshot(&self) -> Vec<TabEntry> {
        self.tabs.lock().await.all().to_vec()
    }

    /// The active page data for a tab (None when suspended / non-HTML).
    pub async fn page_data(&self, id: TabId) -> Option<PageStats> {
        self.live.lock().await.get(&id).map(|t| t.page.stats)
    }

    /// Save the session to the profile directory.
    pub async fn save_session(&self) -> Result<(), EngineError> {
        let (tabs, next_id) = {
            let tabs = self.tabs.lock().await;
            let next = tabs
                .all()
                .last()
                .map(|t| t.id.0 + 1)
                .unwrap_or(1);
            (tabs.all().to_vec(), next)
        };
        let session = SessionFile {
            version: 1,
            tabs,
            next_tab_id: next_id,
            saved_at_unix: memory::unix_now_secs(),
        };
        session::save_session(&self.config.profile_dir, &session)?;
        Ok(())
    }

    /// Engine-wide statistics bundle (for the UI diagnostics panel and
    /// the benchmark suite).
    pub async fn stats(&self) -> EngineStats {
        let governor = self.governor.lock().await;
        let tabs = self.tabs.lock().await.counts();
        let live_pages = self.live.lock().await.len();
        let js = self.js.stats().unwrap_or_default();
        let dns = self.fetch.dns().stats();
        let policy = self.fetch.policy().stats();
        EngineStats {
            startup: self.startup.as_millis_map(),
            memory: governor.snapshot(),
            pressure: governor.pressure(),
            tabs,
            live_pages,
            cache_memory_budget: governor.http_cache_memory_budget(),
            js,
            dns_queries: dns.queries,
            dns_failures: dns.failures,
            policy_checked: policy.checked,
            policy_blocked: policy.blocked,
            policy_upgraded: policy.upgraded,
        }
    }

    /// The network config (for the UI's settings panel).
    pub fn network_config(&self) -> &NetworkConfig {
        &self.config.network
    }

    /// The fingerprint policy engine (engine-level farbling decisions).
    pub fn fingerprint(&self) -> &Mutex<FpEngine> {
        &self.fingerprint
    }

    /// The shared filter set (devtools / UI list manager).
    pub fn filters(&self) -> &Arc<FilterSet> {
        &self.filters
    }

    /// The shared Safe Browsing database (prefix updates go here).
    pub fn safe_browsing(&self) -> &Arc<SafeBrowsingDb> {
        &self.safe_browsing
    }

    /// The shared cookie jar (engine-level access).
    pub fn cookies(&self) -> &Arc<Mutex<CookieJar>> {
        &self.cookies
    }
}

fn unix_bg_since(tab: &TabEntry) -> std::time::SystemTime {
    use std::time::UNIX_EPOCH;
    let secs = tab.backgrounded_at.unwrap_or(0);
    if secs == 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_secs(secs)
    }
}

fn fingerprint_session_key() -> [u8; 16] {
    // Per-process key: stable within the session, rotated per start —
    // cross-session linkability is exactly what we avoid.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(std::process::id().to_le_bytes());
    h.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            .to_le_bytes(),
    );
    let digest = h.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// Aggregate engine statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EngineStats {
    /// Cold-start stage timings (milliseconds).
    pub startup: serde_json::Value,
    /// System memory snapshot.
    pub memory: MemorySnapshot,
    /// Current memory pressure tier.
    pub pressure: MemoryPressure,
    /// Tab state counts.
    pub tabs: TabCounts,
    /// Pages currently held in memory (non-suspended).
    pub live_pages: usize,
    /// HTTP cache memory budget (bytes).
    pub cache_memory_budget: usize,
    /// JS engine stats.
    pub js: bw_js::JsEngineStats,
    /// DNS queries issued.
    pub dns_queries: u64,
    /// DNS failures.
    pub dns_failures: u64,
    /// Requests checked by policy.
    pub policy_checked: u64,
    /// Requests blocked by policy.
    pub policy_blocked: u64,
    /// URLs upgraded to https.
    pub policy_upgraded: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_network::DnsMode;

    fn config() -> EngineConfig {
        EngineConfig {
            profile_dir: std::env::temp_dir().join(format!(
                "bw-engine-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )),
            network: NetworkConfig {
                dns: DnsMode::System,
                ..NetworkConfig::default()
            },
            governor: GovernorPolicy {
                background_suspend_after: Duration::from_millis(50),
                ..GovernorPolicy::default()
            },
            network_filter_rules: starter_network_filters().iter().map(|s| s.to_string()).collect(),
            cosmetic_filter_rules: starter_cosmetic_filters().iter().map(|s| s.to_string()).collect(),
            fingerprint_mode: FpMode::Balanced,
        }
    }

    #[tokio::test]
    async fn engine_starts_with_stage_timings() {
        let engine = BrowserEngine::new(config()).await.unwrap();
        let startup = engine.startup();
        assert!(startup.total > Duration::ZERO);
        assert!(startup.storage > Duration::ZERO || startup.privacy > Duration::ZERO);
    }

    #[tokio::test]
    async fn tab_lifecycle_and_suspension() {
        let engine = BrowserEngine::new(config()).await.unwrap();
        let id = engine.new_tab().await;
        assert_eq!(engine.tab_counts().await.blank, 1);

        // Insert a page directly (no network in unit tests).
        let page = page::build_page(
            "<html><head><title>Local</title></head><body><p>hi</p><div class=\"ad-slot\">x</div></body></html>",
            "local.test",
            &CosmeticFilterSet::compile(["##.ad-slot"]),
        );
        engine
            .live
            .lock()
            .await
            .insert(id, LiveTab { page });
        {
            let mut tabs = engine.tabs.lock().await;
            tabs.get_mut(id).unwrap().state = TabState::Loaded;
            tabs.get_mut(id)
                .unwrap()
                .push_history("https://local.test/".into(), "Local".into());
        }
        assert_eq!(engine.page_data(id).await.map(|s| s.elements), Some(6));

        // Background → sweep → suspended, page dropped.
        engine.background_tab(id).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        let suspended = engine.sweep_idle().await.unwrap();
        assert_eq!(suspended, 1);
        assert_eq!(engine.tab_counts().await.suspended, 1);
        assert!(engine.page_data(id).await.is_none());

        // Session entry survives suspension.
        let tabs = engine.tabs_snapshot().await;
        assert_eq!(tabs[0].current_url(), Some("https://local.test/"));
    }

    #[tokio::test]
    async fn session_save_and_stats() {
        let engine = BrowserEngine::new(config()).await.unwrap();
        let a = engine.new_tab().await;
        let b = engine.new_tab().await;
        {
            let mut tabs = engine.tabs.lock().await;
            tabs.get_mut(a).unwrap().push_history("https://x/".into(), "X".into());
            tabs.get_mut(b).unwrap().push_history("https://y/".into(), "Y".into());
        }
        engine.save_session().await.unwrap();
        let loaded = session::load_session(&engine.config.profile_dir)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.tabs.len(), 2);
        assert_eq!(loaded.next_tab_id, 3);

        let stats = engine.stats().await;
        assert_eq!(stats.tabs.blank, 2);
        assert!(stats.memory.total_bytes > 0);
    }

    #[tokio::test]
    async fn js_through_engine() {
        let engine = BrowserEngine::new(config()).await.unwrap();
        let v = engine.exec_js("https://site.example", "6 * 7").unwrap();
        assert_eq!(v, JsValue::Number(42.0));
    }

    #[tokio::test]
    async fn close_tab_removes_everything() {
        let engine = BrowserEngine::new(config()).await.unwrap();
        let id = engine.new_tab().await;
        engine
            .live
            .lock()
            .await
            .insert(id, LiveTab { page: page::build_page("<p>x</p>", "t", &CosmeticFilterSet::compile(Vec::<String>::new())) });
        assert!(engine.close_tab(id).await);
        assert!(!engine.close_tab(id).await);
        assert_eq!(engine.tab_counts().await.blank, 0);
    }
}
