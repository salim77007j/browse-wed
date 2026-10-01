//! Application glue: engine bridge, UI state machine, snapshot/apply UI sync.
//!
//! Threading contract:
//! * Slint owns the main thread; property writes happen ONLY in
//!   `apply_ui` (main thread, via `invoke_from_event_loop` or callbacks).
//! * Tokio owns the engine; every mutation happens under the `App` lock.
//! * CPU layout/paint runs under the same lock (bounded, few ms).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bw_api::{BrowserApi, Command, EngineOptions, Event};
use bw_engine::TabId;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel, Weak};
use tokio::sync::Mutex as AsyncMutex;

use crate::downloads::{DlState, Download, DownloadManager};
use crate::favicon::FaviconCache;
use crate::prefs::Prefs;
use crate::render::PageSurface;
use crate::stores::{relative_time, BookmarkStore, HistoryStore};

/// Accent presets (cycled from settings).
pub const ACCENTS: &[&str] =
    &["#1a73e8", "#8430ce", "#d03050", "#e8710a", "#1e8e3e", "#0b7285", "#5f6368"];

/// UI-side tab view-model entry (engine TabId + chrome-layer state).
#[derive(Clone)]
pub struct UiTab {
    pub id: u64,
    pub title: String,
    pub url: String,
    pub pinned: bool,
    pub group: String,
    pub loading: bool,
    pub suspended: bool,
    pub security: String,
    pub blocked: u64,
    pub favicon: Option<crate::imgdata::RgbaImage>,
    pub error: Option<(String, String)>,
    pub blocked_page: Option<String>,
}

#[derive(Default, Clone, Copy)]
pub struct PrivacyCounters {
    pub trackers: u64,
    pub ads: u64,
    pub upgrades: u64,
    pub dns: u64,
    pub fingerprints: u64,
}

/// Tab view data (favicon as raw RGBA — slint::Image is main-thread-only).
#[derive(Clone)]
pub struct TabView {
    pub id: u64,
    pub title: String,
    pub url: String,
    pub active: bool,
    pub loading: bool,
    pub pinned: bool,
    pub suspended: bool,
    pub blocked: u64,
    pub group: String,
    pub favicon: Option<crate::imgdata::RgbaImage>,
}

/// Bookmark view data.
#[derive(Clone)]
pub struct BmView {
    pub id: u64,
    pub title: String,
    pub url: String,
    pub folder: String,
    pub favicon: Option<crate::imgdata::RgbaImage>,
}

/// History view data.
#[derive(Clone)]
pub struct HistView {
    pub id: u64,
    pub title: String,
    pub url: String,
    pub visited: String,
    pub favicon: Option<crate::imgdata::RgbaImage>,
}

/// Speed-dial view data.
#[derive(Clone)]
pub struct DialView {
    pub title: String,
    pub url: String,
    pub bg: u32,
    pub favicon: Option<crate::imgdata::RgbaImage>,
}

/// Everything the window needs to render — produced under the App lock,
/// applied on the main thread.
#[allow(dead_code)]
pub struct UiSnapshot {
    pub tabs: Vec<TabView>,
    pub active_title: String,
    pub active_url: String,
    pub security: String,
    pub loading: bool,
    pub view: crate::ActiveView,
    pub zoom: i32,
    pub error: Option<(String, String)>,
    pub blocked_host: Option<String>,
    pub suspended: bool,
    pub bookmarked: bool,
    pub can_back: bool,
    pub can_forward: bool,
    pub bands: Vec<crate::render::BandView>,
    pub page_height: i32,
    pub page_background: slint::Color,
    pub find_open: bool,
    pub find_text: String,
    pub match_count: i32,
    pub match_current: i32,
    pub hover_link: String,
    pub status_text: String,
    pub suggestions: Vec<crate::SuggestionItem>,
    pub suggestion_selected: i32,
    pub suggestions_open: bool,
    pub bar_bookmarks: Vec<BmView>,
    pub all_bookmarks: Vec<BmView>,
    pub history: Vec<HistView>,
    pub downloads: Vec<crate::DownloadItem>,
    pub dial: Vec<DialView>,
    pub logs: Vec<crate::DevtoolsLog>,
    pub filters: Vec<crate::FilterRow>,
    pub permissions: Vec<crate::PermissionRow>,
    pub session_restore_available: bool,
    // prefs mirror
    pub theme_mode: String,
    pub accent: slint::Color,
    pub bookmarks_bar: bool,
    pub search_engine: String,
    pub homepage: String,
    pub profile_dir: String,
    pub suspend_secs: i32,
    pub startup_restore: bool,
    pub cookie_policy: String,
    pub clear_on_exit: bool,
    pub adblock: bool,
    pub trackerlist: bool,
    pub cosmetic: bool,
    pub fingerprint: bool,
    pub doh: bool,
    pub https_only: bool,
    pub safebrowsing: bool,
    // stats
    pub trackers_blocked: i32,
    pub ads_blocked: i32,
    pub https_upgrades: i32,
    pub dns_queries: i32,
    pub fingerprints_defeated: i32,
    pub memory_mb: i32,
    pub tabs_open: i32,
    pub memory_pressure: String,
    pub live_pages: i32,
    pub suspended_tabs: i32,
    pub cache_mb: i32,
    pub js_heap_mb: i32,
    // devtools page stats
    pub page_nodes: i32,
    pub page_elements: i32,
    pub page_scripts: i32,
    pub page_stylesheets: i32,
    pub page_images: i32,
    pub cosmetic_hidden: i32,
    pub blocked_count: i32,
    pub protocol: String,
    pub load_time: String,
    pub devtools_open: bool,
    pub menu_open: bool,
    pub omnibox_focus_pulse: i32,
}

pub struct App {
    pub api: Arc<BrowserApi>,
    pub engine: Arc<bw_engine::BrowserEngine>,
    pub profile: PathBuf,
    pub prefs: Prefs,
    pub bookmarks: BookmarkStore,
    pub history: HistoryStore,
    pub favicons: Arc<Mutex<FaviconCache>>,
    pub downloads: Arc<DownloadManager>,
    pub tabs: Vec<UiTab>,
    pub active: u64,
    pub closed_stack: Vec<UiTab>,
    pub surfaces: HashMap<u64, PageSurface>,
    pub scroll: i32,
    pub viewport_h: f32,
    pub viewport_w: f32,
    pub zoom: i32,
    pub view: crate::ActiveView,
    pub privacy: PrivacyCounters,
    pub blocked_total: u64,
    pub logs: Vec<crate::DevtoolsLog>,
    pub api_tabs_snapshot: Vec<bw_engine::TabEntry>,
    // panel search filters
    pub bookmark_search: Option<String>,
    pub history_search: Option<String>,
    pub omnibox_focus_pulse: i32,
    // omnibox state
    pub omnibox_text: String,
    pub suggestions: Vec<crate::search::Suggestion>,
    pub suggestions_open: bool,
    pub suggestion_selected: i32,
    // find state
    pub find_open: bool,
    pub find_text: String,
    pub hover_link: String,
    // overlays
    pub devtools_open: bool,
    pub menu_open: bool,
    // page stats for devtools
    pub page_stats: Option<bw_engine::PageStats>,
    pub protocol: String,
    pub load_time: String,
    // custom filter rules (the "extension" surface)
    pub custom_filters: Vec<(u64, String, bool, u64)>,
    pub next_filter_id: u64,
}

impl App {
    pub async fn start() -> Result<Arc<AsyncMutex<App>>, Box<dyn std::error::Error>> {
        let profile = std::env::var("BW_PROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_config().join("browse-wed"));
        std::fs::create_dir_all(&profile)?;
        let prefs = Prefs::load(&profile);
        let bookmarks = BookmarkStore::load(&profile);
        let history = HistoryStore::load(&profile);

        // Custom filter rules ("extensions") compile into the engine at boot.
        let custom_filters: Vec<String> =
            std::fs::read_to_string(profile.join("custom-filters.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<(String, bool)>>(&s).ok())
                .map(|v| v.into_iter().filter(|(_, on)| *on).map(|(r, _)| r).collect())
                .unwrap_or_default();

        let options = EngineOptions {
            profile_dir: Some(profile.to_string_lossy().into_owned()),
            privacy_preset: true,
            doh_url: if prefs.doh { Some(prefs.doh_url.clone()) } else { None },
            background_suspend_secs: prefs.suspend_secs,
            max_active_tabs: 24,
            extra_network_filters: custom_filters,
        };
        let api = BrowserApi::start(options).await?;
        let engine = api.engine().clone();
        api.start_background_services();
        let downloads = DownloadManager::new(engine.clone(), profile.join("downloads"));

        let app = Arc::new(AsyncMutex::new(App {
            api,
            engine,
            profile: profile.clone(),
            prefs,
            bookmarks,
            history,
            favicons: Arc::new(Mutex::new(FaviconCache::new(&profile))),
            downloads,
            tabs: vec![],
            active: 0,
            closed_stack: vec![],
            surfaces: HashMap::new(),
            scroll: 0,
            viewport_h: 700.0,
            viewport_w: 1200.0,
            zoom: 100,
            view: crate::ActiveView::NewTab,
            privacy: PrivacyCounters::default(),
            blocked_total: 0,
            logs: vec![],
            api_tabs_snapshot: vec![],
            bookmark_search: None,
            history_search: None,
            omnibox_focus_pulse: 0,
            omnibox_text: String::new(),
            suggestions: vec![],
            suggestions_open: false,
            suggestion_selected: -1,
            find_open: false,
            find_text: String::new(),
            hover_link: String::new(),
            devtools_open: false,
            menu_open: false,
            page_stats: None,
            protocol: "—".into(),
            load_time: "—".into(),
            custom_filters: vec![],
            next_filter_id: 1,
        }));

        {
            let mut a = app.lock().await;
            a.new_tab().await;
        }
        Ok(app)
    }

    pub async fn new_tab(&mut self) -> u64 {
        let id = match self.api.command(Command::NewTab).await {
            Ok(v) => v["tab"].as_u64().unwrap_or(0),
            Err(_) => 0,
        };
        self.tabs.push(UiTab {
            id,
            title: String::new(),
            url: String::new(),
            pinned: false,
            group: String::new(),
            loading: false,
            suspended: false,
            security: "local".into(),
            blocked: 0,
            favicon: None,
            error: None,
            blocked_page: None,
        });
        self.surfaces.insert(id, PageSurface::new(&self.profile));
        self.active = id;
        self.view = crate::ActiveView::NewTab;
        self.zoom = 100;
        self.scroll = 0;
        id
    }

    pub fn theme_is_dark(&self) -> bool {
        self.prefs.theme_mode == "dark"
    }

    pub fn with_favicons<R>(&self, f: impl FnOnce(&mut FaviconCache) -> R) -> R {
        let mut guard = self.favicons.lock().unwrap();
        f(&mut guard)
    }

    pub fn log_devtools(&mut self, level: &str, text: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (h, m) = ((now / 3600) % 24, (now / 60) % 60);
        self.logs.push(crate::DevtoolsLog {
            level: level.into(),
            text: text.into(),
            at: format!("{h:02}:{m:02}").into(),
        });
        if self.logs.len() > 200 {
            self.logs.drain(0..self.logs.len() - 200);
        }
    }
}

fn home_config() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(x);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config")
}

// ------------------------------------------------------------------ events

async fn handle_event(app: &Arc<AsyncMutex<App>>, weak: &Weak<crate::BrowserWindow>, event: Event) {
    let snap = {
        let mut a = app.lock().await;
        match event {
            Event::TabOpened { tab } => {
                if !a.tabs.iter().any(|t| t.id == tab) {
                    a.tabs.push(UiTab {
                        id: tab,
                        title: String::new(),
                        url: String::new(),
                        pinned: false,
                        group: String::new(),
                        loading: false,
                        suspended: false,
                        security: "local".into(),
                        blocked: 0,
                        favicon: None,
                        error: None,
                        blocked_page: None,
                    });
                    let profile = a.profile.clone();
                    a.surfaces.insert(tab, PageSurface::new(&profile));
                }
            }
            Event::TabClosed { tab } => {
                if let Some(idx) = a.tabs.iter().position(|t| t.id == tab) {
                    let closed = a.tabs.remove(idx);
                    a.closed_stack.push(closed);
                    if a.closed_stack.len() > 25 {
                        a.closed_stack.remove(0);
                    }
                }
                a.surfaces.remove(&tab);
                if a.tabs.is_empty() {
                    a.new_tab().await;
                } else if a.active == tab {
                    a.active = a.tabs.first().map(|t| t.id).unwrap_or(0);
                    a.activate_tab_internal().await;
                }
            }
            Event::NavigationCompleted { tab, outcome } => {
                let blocked = outcome.blocked;
                a.blocked_total += blocked;
                if let Some(t) = a.tabs.iter_mut().find(|t| t.id == tab) {
                    t.loading = false;
                    t.title = if outcome.title.is_empty() {
                        outcome.final_url.clone()
                    } else {
                        outcome.title.clone()
                    };
                    t.url = outcome.final_url.clone();
                    t.security = if outcome.final_url.starts_with("https") {
                        "secure".into()
                    } else if outcome.final_url.starts_with("http") {
                        "insecure".into()
                    } else {
                        "local".into()
                    };
                    t.blocked = blocked;
                    t.error = None;
                    t.blocked_page =
                        if blocked > 0 { Some(outcome.final_url.clone()) } else { None };
                    t.suspended = false;
                }
                if blocked > 0 {
                    a.privacy.trackers += blocked;
                }
                a.history.record(&outcome.title, &outcome.final_url);
                a.page_stats = Some(outcome.page);
                a.protocol = outcome.protocol.clone();
                a.load_time = format!("{:.1} ms", outcome.total_ms);
                if a.active == tab {
                    a.view = crate::ActiveView::Page;
                    a.install_page_model(tab).await;
                }

                // Favicon (best-effort; next periodic tick paints it).
                let url = outcome.final_url.clone();
                let engine = a.engine.clone();
                let favicons = a.favicons.clone();
                tokio::spawn(async move {
                    if let Some((bytes, _)) = crate::favicon::fetch_bytes(&engine, &url).await {
                        let img = crate::favicon::decode_image(&bytes);
                        let mut fc = favicons.lock().unwrap();
                        fc.store(&url, &bytes, img);
                    }
                });
            }
            Event::NavigationFailed { tab, error } => {
                if let Some(t) = a.tabs.iter_mut().find(|t| t.id == tab) {
                    t.loading = false;
                    t.error = Some(("Can't reach this page".into(), error.clone()));
                }
                a.view = crate::ActiveView::Page;
                a.log_devtools("error", &error);
            }
            Event::TabsSuspended { .. } => {
                a.resync_tab_states().await;
            }
            Event::MemoryPressure { .. } => {}
            Event::SessionSaved => {
                a.log_devtools("info", "Session saved");
            }
        }
        snapshot_ui(&a)
    };
    apply_snapshot(snap, weak);
}

impl App {
    async fn activate_tab_internal(&mut self) {
        let tab = self.active;
        let _ = self.api.command(Command::ActivateTab { tab }).await;
        self.resync_tab_states().await;
        // Restoring a suspended tab re-navigates (cache hit) — the event
        // pump refreshes the surface.
        if let Some(t) = self.tabs.iter().find(|t| t.id == tab) {
            if !t.url.is_empty() {
                self.view = crate::ActiveView::Page;
            } else {
                self.view = crate::ActiveView::NewTab;
            }
        }
    }

    pub async fn install_page_model(&mut self, tab: u64) {
        if let Some(model) = self.engine.page_snapshot(TabId(tab)).await {
            let dark = self.theme_is_dark();
            let width = self.viewport_w;
            if let Some(surface) = self.surfaces.get_mut(&tab) {
                surface.set_page(model, width, dark);
                self.scroll = 0;
            }
            let engine = self.engine.clone();
            if let Some(surface) = self.surfaces.get_mut(&tab) {
                surface.pump_images(&engine).await;
            }
        }
    }

    pub async fn resync_tab_states(&mut self) {
        let snapshot = self.api.tabs().await;
        self.api_tabs_snapshot = snapshot.clone();
        for t in &mut self.tabs {
            if let Some(e) = snapshot.iter().find(|e| e.id.0 == t.id) {
                let was = t.suspended;
                t.suspended = matches!(e.state, bw_engine::TabState::Suspended);
                if t.suspended && !was {
                    // DOM dropped — surface can drop its copy too.
                    if let Some(surface) = self.surfaces.get_mut(&t.id) {
                        surface.clear_page();
                    }
                }
                if t.suspended && t.title.is_empty() {
                    if let Some(u) = e.history.get(e.history_cursor.unwrap_or(0)) {
                        t.title = u.title.clone();
                        t.url = u.url.clone();
                    }
                }
            }
        }
    }

    /// Rebuild bands for the current scroll and return them (called under
    /// the App lock; painting is CPU work of a few ms).
    pub fn rebuild_bands(&mut self) -> Vec<crate::render::BandView> {
        let tab = self.active;
        let dark = self.theme_is_dark();
        let scroll = self.scroll;
        let vh = self.viewport_h as i32;
        match self.surfaces.get_mut(&tab) {
            Some(surface) => surface.bands_for_scroll(scroll, vh, dark),
            None => vec![],
        }
    }
}

// ------------------------------------------------------------- periodic UI

async fn refresh_periodic(app: &Arc<AsyncMutex<App>>, weak: &Weak<crate::BrowserWindow>) {
    let snap = {
        let mut a = app.lock().await;
        a.api_tabs_snapshot = a.api.tabs().await;
        let stats = a.api.stats().await;
        a.privacy.dns = stats.dns_queries;
        a.privacy.upgrades = stats.policy_upgraded;
        let blocked_now = stats.policy_blocked;
        let delta = blocked_now.saturating_sub(a.blocked_total);
        if delta > 0 {
            a.privacy.trackers += delta;
            a.blocked_total = blocked_now;
        }
        // Tab suspension resync (cheap).
        let suspended_ids: Vec<(u64, bool)> = a
            .api_tabs_snapshot
            .iter()
            .map(|e| (e.id.0, matches!(e.state, bw_engine::TabState::Suspended)))
            .collect();
        for t in &mut a.tabs {
            if let Some((_, sus)) = suspended_ids.iter().find(|(id, _)| *id == t.id) {
                t.suspended = *sus;
            }
        }
        // Image pump for the active page (bounded per tick).
        let tab = a.active;
        if a.view == crate::ActiveView::Page {
            let engine = a.engine.clone();
            if let Some(surface) = a.surfaces.get_mut(&tab) {
                if surface.pump_images(&engine).await {
                    // new pixels → new bands next snapshot
                }
            }
        }
        snapshot_ui(&a)
    };
    apply_snapshot(snap, weak);
}

// -------------------------------------------------------------- snapshot

fn dial_color_hex(url: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in url.as_bytes() {
        h = ((h << 5) + h) ^ (*b as u32);
    }
    let hue = (h % 360) as f32;
    let (r, g, b) = {
        let s = 0.45f32;
        let l = 0.55f32;
        let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
        let hp = hue / 60.0;
        let x = c * (1.0 - (hp % 2.0 - 1.0).abs());
        let (r1, g1, b1) = match hp as u32 {
            0 => (c, x, 0.0),
            1 => (x, c, 0.0),
            2 => (0.0, c, x),
            3 => (0.0, x, c),
            4 => (x, 0.0, c),
            _ => (c, 0.0, x),
        };
        let m = l - c / 2.0;
        (((r1 + m) * 255.0) as u32, ((g1 + m) * 255.0) as u32, ((b1 + m) * 255.0) as u32)
    };
    0xff00_0000 | (r << 16) | (g << 8) | b
}

pub fn parse_hex(hex: &str) -> slint::Color {
    let h = hex.trim_start_matches('#');
    if h.len() == 6 {
        if let Ok(v) = u32::from_str_radix(h, 16) {
            return slint::Color::from_argb_encoded(0xff00_0000 | v);
        }
    }
    slint::Color::from_argb_encoded(0xff1a_73e8)
}

fn bookmark_item(b: &crate::stores::Bookmark, a: &App) -> BmView {
    BmView {
        id: b.id,
        title: b.title.clone(),
        url: b.url.clone(),
        folder: b.folder.clone(),
        favicon: a
            .with_favicons(|fc| fc.get(&b.url))
            .or_else(|| Some(crate::favicon::letter(&b.url))),
    }
}

fn dl_to_item(d: &Download) -> crate::DownloadItem {
    let progress = match d.state {
        DlState::Done => 3.0,
        DlState::Failed | DlState::Cancelled => 4.0,
        DlState::Paused => 0.0,
        DlState::Active => match d.total {
            Some(t) if t > 0 => d.received as f32 / t as f32,
            _ => 0.02,
        },
    };
    crate::DownloadItem {
        id: d.id as i32,
        filename: SharedString::from(d.filename.clone()),
        url: SharedString::from(d.url.clone()),
        progress,
        total_bytes: d.total.unwrap_or(0) as i32,
        received_bytes: d.received as i32,
        paused: matches!(d.state, DlState::Paused),
        speed: SharedString::from(if d.bytes_per_sec > 0 {
            format!("{:.1} MB/s", d.bytes_per_sec as f64 / (1024.0 * 1024.0))
        } else {
            String::new()
        }),
        icon: SharedString::from("file"),
    }
}

/// Build the full UI snapshot from app state.
pub fn snapshot_ui(a: &App) -> UiSnapshot {
    let tabs: Vec<TabView> = a
        .tabs
        .iter()
        .map(|t| TabView {
            id: t.id,
            title: if t.title.is_empty() { "New Tab".to_string() } else { t.title.clone() },
            url: t.url.clone(),
            active: t.id == a.active,
            loading: t.loading,
            pinned: t.pinned,
            suspended: t.suspended,
            blocked: t.blocked,
            group: t.group.clone(),
            favicon: t.favicon.clone(),
        })
        .collect();

    let active_tab = a.tabs.iter().find(|t| t.id == a.active).cloned();
    let (
        title,
        url,
        security,
        loading,
        error,
        blocked_host,
        suspended,
        bookmarked,
        can_back,
        can_forward,
    ) = match &active_tab {
        Some(t) => {
            let entry = a.api_tabs_snapshot.iter().find(|e| e.id.0 == t.id);
            (
                if t.title.is_empty() { "New Tab".into() } else { t.title.clone() },
                t.url.clone(),
                t.security.clone(),
                t.loading,
                t.error.clone(),
                t.blocked_page.clone(),
                t.suspended && !t.url.is_empty(),
                !t.url.is_empty() && a.bookmarks.contains(&t.url),
                entry.map(|e| e.history_cursor.unwrap_or(0) > 0).unwrap_or(false),
                entry
                    .map(|e| (e.history_cursor.unwrap_or(0) as i64) < e.history.len() as i64 - 1)
                    .unwrap_or(false),
            )
        }
        None => (
            "New Tab".into(),
            String::new(),
            "local".into(),
            false,
            None,
            None,
            false,
            false,
            false,
            false,
        ),
    };

    // Active page bands (built by rebuild_bands on paint triggers).
    let (page_height, page_background, find_count, find_cur, cosmetic_hidden) =
        match a.surfaces.get(&a.active) {
            Some(surface) => {
                let bg = surface.laid.background;
                let dark = a.prefs.theme_mode == "dark";
                let lum = (bg[0] as u32 * 299 + bg[1] as u32 * 587 + bg[2] as u32 * 114) / 1000;
                let c = if bg[3] < 0x80 || !(10..=245).contains(&lum) {
                    if dark {
                        slint::Color::from_argb_encoded(0xff1b_1b1f)
                    } else {
                        slint::Color::from_argb_encoded(0xffff_ffff)
                    }
                } else {
                    slint::Color::from_argb_encoded(
                        ((bg[3] as u32) << 24)
                            | ((bg[0] as u32) << 16)
                            | ((bg[1] as u32) << 8)
                            | bg[2] as u32,
                    )
                };
                let (n, cur) = surface.find_status();
                (surface.page_height(), c, n, cur, surface.cosmetic_hidden())
            }
            None => (100, slint::Color::from_argb_encoded(0xffff_ffff), 0, 0, 0),
        };

    let bar: Vec<BmView> = a
        .bookmarks
        .bookmarks
        .iter()
        .filter(|b| b.folder == "bar")
        .rev()
        .take(12)
        .map(|b| bookmark_item(b, a))
        .collect();

    let all: Vec<BmView> = a
        .bookmarks
        .bookmarks
        .iter()
        .filter(|b| {
            a.bookmark_search.as_deref().is_none_or(|q| {
                let q = q.to_lowercase();
                b.title.to_lowercase().contains(&q) || b.url.to_lowercase().contains(&q)
            })
        })
        .map(|b| bookmark_item(b, a))
        .collect();

    let hist: Vec<HistView> = a
        .history
        .entries
        .iter()
        .rev()
        .filter(|e| {
            a.history_search.as_deref().is_none_or(|q| {
                let q = q.to_lowercase();
                e.title.to_lowercase().contains(&q) || e.url.to_lowercase().contains(&q)
            })
        })
        .take(200)
        .map(|e| HistView {
            id: e.id,
            title: if e.title.is_empty() { e.url.clone() } else { e.title.clone() },
            url: e.url.clone(),
            visited: relative_time(e.visited_unix),
            favicon: a
                .with_favicons(|fc| fc.get(&e.url))
                .or_else(|| Some(crate::favicon::letter(&e.url))),
        })
        .collect();

    let dial: Vec<DialView> = {
        let tops = if !a.prefs.speed_dial.is_empty() {
            a.prefs.speed_dial.clone()
        } else {
            a.history.top_sites(8)
        };
        tops.iter()
            .take(8)
            .map(|(u, t)| DialView {
                title: t.clone(),
                url: u.clone(),
                bg: dial_color_hex(u),
                favicon: a
                    .with_favicons(|fc| fc.get(u))
                    .or_else(|| Some(crate::favicon::letter(u))),
            })
            .collect()
    };

    let logs: Vec<crate::DevtoolsLog> = a
        .logs
        .iter()
        .map(|l| crate::DevtoolsLog {
            level: l.level.clone(),
            text: l.text.clone(),
            at: l.at.clone(),
        })
        .collect();

    let filters: Vec<crate::FilterRow> = a
        .custom_filters
        .iter()
        .map(|(id, rule, on, hits)| crate::FilterRow {
            id: *id as i32,
            rule: SharedString::from(rule.clone()),
            hits: *hits as i32,
            enabled: *on,
        })
        .collect();

    let suggestions: Vec<crate::SuggestionItem> = a
        .suggestions
        .iter()
        .map(|s| crate::SuggestionItem {
            kind: SharedString::from(s.kind),
            text: SharedString::from(s.text.clone()),
            secondary: SharedString::from(s.secondary.clone()),
        })
        .collect();

    let downloads: Vec<crate::DownloadItem> =
        a.downloads.try_snapshot().iter().map(dl_to_item).collect();

    let stats = PrivacySnapshot::of(a);

    let ps = a.page_stats.unwrap_or_default();

    UiSnapshot {
        tabs,
        active_title: title,
        active_url: url,
        security,
        loading,
        view: a.view,
        zoom: a.zoom,
        error,
        blocked_host,
        suspended,
        bookmarked,
        can_back,
        can_forward,
        bands: vec![],
        page_height,
        page_background,
        find_open: a.find_open,
        find_text: a.find_text.clone(),
        match_count: find_count,
        match_current: find_cur,
        hover_link: a.hover_link.clone(),
        status_text: String::new(),
        suggestions,
        suggestion_selected: a.suggestion_selected,
        suggestions_open: a.suggestions_open,
        bar_bookmarks: bar,
        all_bookmarks: all,
        history: hist,
        downloads,
        dial,
        logs,
        filters,
        permissions: vec![],
        session_restore_available: !a.history.entries.is_empty() && a.prefs.restore_session,
        theme_mode: a.prefs.theme_mode.clone(),
        accent: parse_hex(&a.prefs.accent),
        bookmarks_bar: a.prefs.bookmarks_bar,
        search_engine: a.prefs.search_engine.clone(),
        homepage: a.prefs.homepage.clone(),
        profile_dir: a.profile.to_string_lossy().into_owned(),
        suspend_secs: a.prefs.suspend_secs as i32,
        startup_restore: a.prefs.restore_session,
        cookie_policy: a.prefs.cookie_policy.clone(),
        clear_on_exit: a.prefs.clear_on_exit,
        adblock: a.prefs.adblock,
        trackerlist: a.prefs.trackerlist,
        cosmetic: a.prefs.cosmetic,
        fingerprint: a.prefs.fingerprint,
        doh: a.prefs.doh,
        https_only: a.prefs.https_only,
        safebrowsing: a.prefs.safebrowsing,
        trackers_blocked: stats.trackers as i32,
        ads_blocked: stats.ads as i32,
        https_upgrades: stats.upgrades as i32,
        dns_queries: stats.dns as i32,
        fingerprints_defeated: stats.fingerprints as i32,
        memory_mb: 0,
        tabs_open: a.tabs.len() as i32,
        memory_pressure: String::new(),
        live_pages: 0,
        suspended_tabs: 0,
        cache_mb: 0,
        js_heap_mb: 0,
        page_nodes: ps.nodes as i32,
        page_elements: ps.elements as i32,
        page_scripts: ps.scripts as i32,
        page_stylesheets: ps.stylesheets as i32,
        page_images: ps.images as i32,
        cosmetic_hidden,
        blocked_count: active_tab.map(|t| t.blocked as i32).unwrap_or(0),
        protocol: a.protocol.clone(),
        load_time: a.load_time.clone(),
        devtools_open: a.devtools_open,
        menu_open: a.menu_open,
        omnibox_focus_pulse: a.omnibox_focus_pulse,
    }
}

struct PrivacySnapshot {
    trackers: u64,
    ads: u64,
    upgrades: u64,
    dns: u64,
    fingerprints: u64,
}

impl PrivacySnapshot {
    fn of(a: &App) -> Self {
        PrivacySnapshot {
            trackers: a.privacy.trackers,
            ads: a.privacy.ads,
            upgrades: a.privacy.upgrades,
            dns: a.privacy.dns,
            fingerprints: a.privacy.fingerprints,
        }
    }
}

/// Push a snapshot into the window (main thread ONLY).
pub fn apply_snapshot(s: UiSnapshot, weak: &Weak<crate::BrowserWindow>) {
    let Some(ui) = weak.upgrade() else { return };
    let band_data: Vec<crate::BandData> = s
        .bands
        .iter()
        .map(|b| crate::BandData {
            image: b.rgba.as_ref().map(|r| r.to_slint()).unwrap_or_default(),
            height: b.height,
        })
        .collect();
    if !band_data.is_empty() {
        ui.set_bands(ModelRc::new(VecModel::from(band_data)));
    }
    {
        let theme = ui.global::<crate::Theme>();
        theme.set_dark(s.theme_mode == "dark");
        theme.set_accent(s.accent);
    }
    let tabs: Vec<crate::TabItem> = s
        .tabs
        .iter()
        .map(|t| crate::TabItem {
            id: t.id as i32,
            title: SharedString::from(t.title.clone()),
            url: SharedString::from(t.url.clone()),
            favicon: t.favicon.as_ref().map(|f| f.to_slint()).unwrap_or_default(),
            active: t.active,
            loading: t.loading,
            pinned: t.pinned,
            suspended: t.suspended,
            blocked: t.blocked as i32,
            group: if t.group.is_empty() {
                slint::Color::from_argb_encoded(0)
            } else {
                parse_hex(&t.group)
            },
            audio: false,
        })
        .collect();
    ui.set_tabs(ModelRc::new(VecModel::from(tabs)));
    ui.set_active_title(SharedString::from(s.active_title));
    ui.set_active_url(SharedString::from(s.active_url));
    ui.set_security(SharedString::from(s.security));
    ui.set_loading(s.loading);
    ui.set_view(s.view);
    ui.set_zoom_percent(s.zoom);
    ui.set_error_visible(s.error.is_some());
    if let Some((t, d)) = &s.error {
        ui.set_error_title(SharedString::from(t.clone()));
        ui.set_error_detail(SharedString::from(d.clone()));
    }
    ui.set_blocked_visible(s.blocked_host.is_some());
    if let Some(h) = &s.blocked_host {
        ui.set_blocked_host(SharedString::from(h.clone()));
    }
    ui.set_suspended_visible(s.suspended);
    ui.set_bookmarked(s.bookmarked);
    ui.set_can_go_back(s.can_back);
    ui.set_can_go_forward(s.can_forward);
    ui.set_page_height(s.page_height);
    ui.set_page_background(s.page_background);
    ui.set_find_open(s.find_open);
    ui.set_find_text(SharedString::from(s.find_text.clone()));
    ui.set_match_count(s.match_count);
    ui.set_match_current(s.match_current);
    ui.set_hover_link(SharedString::from(s.hover_link.clone()));
    ui.set_suggestions(ModelRc::new(VecModel::from(s.suggestions)));
    ui.set_suggestions_open(s.suggestions_open);
    let conv_bm = |b: &BmView| crate::BookmarkItem {
        id: b.id as i32,
        title: SharedString::from(b.title.clone()),
        url: SharedString::from(b.url.clone()),
        favicon: b.favicon.as_ref().map(|f| f.to_slint()).unwrap_or_default(),
        folder: SharedString::from(b.folder.clone()),
        pinned: false,
    };
    let bar: Vec<crate::BookmarkItem> = s.bar_bookmarks.iter().map(&conv_bm).collect();
    let all: Vec<crate::BookmarkItem> = s.all_bookmarks.iter().map(conv_bm).collect();
    ui.set_bar_bookmarks(ModelRc::new(VecModel::from(bar)));
    ui.set_all_bookmarks(ModelRc::new(VecModel::from(all)));

    let hist: Vec<crate::HistoryItem> = s
        .history
        .iter()
        .map(|e| crate::HistoryItem {
            id: e.id as i32,
            title: SharedString::from(e.title.clone()),
            url: SharedString::from(e.url.clone()),
            visited: SharedString::from(e.visited.clone()),
            favicon: e.favicon.as_ref().map(|f| f.to_slint()).unwrap_or_default(),
        })
        .collect();
    ui.set_history_entries(ModelRc::new(VecModel::from(hist)));
    if !s.downloads.is_empty() {
        ui.set_downloads(ModelRc::new(VecModel::from(s.downloads)));
    }
    let dial: Vec<crate::SpeedDialItem> = s
        .dial
        .iter()
        .map(|d| crate::SpeedDialItem {
            title: SharedString::from(d.title.clone()),
            url: SharedString::from(d.url.clone()),
            favicon: d.favicon.as_ref().map(|f| f.to_slint()).unwrap_or_default(),
            bg: slint::Color::from_argb_encoded(d.bg),
        })
        .collect();
    ui.set_dial(ModelRc::new(VecModel::from(dial)));
    ui.set_devtools_logs(ModelRc::new(VecModel::from(s.logs)));
    ui.set_filters(ModelRc::new(VecModel::from(s.filters)));
    ui.set_session_restore_available(s.session_restore_available);
    ui.set_theme_mode(SharedString::from(s.theme_mode));
    ui.set_accent_color(s.accent);
    ui.set_bookmarks_bar_visible(s.bookmarks_bar);
    ui.set_search_engine_name(SharedString::from(s.search_engine));
    ui.set_homepage(SharedString::from(s.homepage));
    ui.set_profile_dir(SharedString::from(s.profile_dir));
    ui.set_suspend_secs(s.suspend_secs);
    ui.set_startup_restore(s.startup_restore);
    ui.set_cookie_policy(SharedString::from(s.cookie_policy));
    ui.set_clear_on_exit(s.clear_on_exit);
    ui.set_adblock_on(s.adblock);
    ui.set_trackerlist_on(s.trackerlist);
    ui.set_cosmetic_on(s.cosmetic);
    ui.set_fingerprint_on(s.fingerprint);
    ui.set_doh_on(s.doh);
    ui.set_https_only(s.https_only);
    ui.set_safebrowsing_on(s.safebrowsing);
    ui.set_trackers_blocked(s.trackers_blocked);
    ui.set_ads_blocked(s.ads_blocked);
    ui.set_https_upgrades(s.https_upgrades);
    ui.set_dns_queries(s.dns_queries);
    ui.set_fingerprints_defeated(s.fingerprints_defeated);
    ui.set_tabs_open(s.tabs_open);
    ui.set_memory_mb(s.memory_mb);
    ui.set_memory_pressure(SharedString::from(s.memory_pressure));
    ui.set_live_pages(s.live_pages);
    ui.set_suspended_tabs(s.suspended_tabs);
    ui.set_cache_mb(s.cache_mb);
    ui.set_js_heap_mb(s.js_heap_mb);
    ui.set_page_nodes(s.page_nodes);
    ui.set_page_elements(s.page_elements);
    ui.set_page_scripts(s.page_scripts);
    ui.set_page_stylesheets(s.page_stylesheets);
    ui.set_page_images(s.page_images);
    ui.set_cosmetic_hidden(s.cosmetic_hidden);
    ui.set_blocked_count(s.blocked_count);
    ui.set_protocol(SharedString::from(s.protocol));
    ui.set_load_time(SharedString::from(s.load_time));
    ui.set_devtools_open(s.devtools_open);
    ui.set_menu_open(s.menu_open);
    ui.set_omnibox_focus_pulse(s.omnibox_focus_pulse);
}

// ------------------------------------------------------------------- run

pub fn run(ui: crate::BrowserWindow) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(3)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let app: Arc<AsyncMutex<App>> = rt.block_on(async { App::start().await }).unwrap_or_else(|e| {
        eprintln!("engine start failed: {e}");
        std::process::exit(1);
    });

    callbacks::wire_callbacks(&ui, &rt, Arc::clone(&app));

    // Initial UI state.
    {
        let weak = ui.as_weak();
        let appx = Arc::clone(&app);
        rt.spawn(async move {
            let snap = {
                let a = appx.lock().await;
                snapshot_ui(&a)
            };
            slint::invoke_from_event_loop(move || apply_snapshot(snap, &weak)).ok();
        });
    }

    // Engine event pump.
    let weak = ui.as_weak();
    let app2 = Arc::clone(&app);
    let mut events = {
        let a = app2.blocking_lock();
        a.api.subscribe()
    };
    rt.spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => handle_event(&app2, &weak, event).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });

    // Periodic refresh (downloads, stats, suspension, images).
    let weak2 = ui.as_weak();
    let app3 = Arc::clone(&app);
    rt.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            refresh_periodic(&app3, &weak2).await;
        }
    });

    ui.run().expect("slint run failed");
}

mod callbacks;
