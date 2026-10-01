//! # bw-api — the UI-facing browser API
//!
//! This crate is the **contract between the engine and any UI** (native
//! toolkit, Electron/Tauri host, remote debugging client). It wraps
//! [`bw_engine::BrowserEngine`] in a transport-friendly command/event
//! surface:
//!
//! * **Commands** ([`Command`]) — plain, `serde`-serializable values a UI
//!   sends in (from JSON-RPC, IPC, or direct calls). Every command maps to
//!   exactly one engine operation.
//! * **Events** ([`Event`]) — what the UI listens for (tab lifecycle,
//!   navigation results, memory pressure), broadcast over a
//!   `tokio::sync::broadcast` channel.
//! * **Snapshot polling** — [`BrowserApi::stats`] and
//!   [`BrowserApi::tabs`] give complete UI state in one call.
//!
//! ## Binding pattern for the UI implementer
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use bw_api::{BrowserApi, Command, EngineOptions};
//!
//! // 1. Boot (inside a tokio runtime).
//! let opts = EngineOptions::default(); // or privacy_default(...)
//! let api = BrowserApi::start(opts).await?;
//!
//! // 2. Subscribe to events BEFORE issuing commands.
//! let mut events = api.subscribe();
//!
//! // 3. Drive the browser with commands (replies are JSON values).
//! let tab = api.command(Command::NewTab).await?["tab"].as_u64().unwrap();
//! let nav = Command::Navigate { tab, url: "https://example.com".into() };
//! api.command(nav).await?;
//!
//! // 4. Render the event stream.
//! while let Ok(event) = events.recv().await {
//!     println!("{event:?}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! No engine type ever leaks through this boundary — every payload is a
//! plain serializable struct, so a UI in another process/language binds
//! through JSON with zero Rust knowledge.

#![forbid(unsafe_code)]

use std::sync::Arc;

use bw_engine::{BrowserEngine, EngineConfig, GovernorPolicy, MemoryPressure, TabEntry, TabId};
use bw_network::DnsMode;
use tokio::sync::{broadcast, Mutex};

pub use bw_engine::{NavigationOutcome, PageStats, Startup};
pub use bw_js::{JsEngineStats, JsValue};

/// Options for starting the engine (the serializable mirror of
/// `bw_engine::EngineConfig` + runtime knobs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EngineOptions {
    /// Profile directory. Defaults to a per-process temp dir.
    pub profile_dir: Option<String>,
    /// Use the privacy-forward preset (DoH, HTTPS upgrades, starter lists).
    pub privacy_preset: bool,
    /// Override the DoH resolver URL (privacy preset only).
    pub doh_url: Option<String>,
    /// Seconds before background tabs are suspended.
    pub background_suspend_secs: u64,
    /// Maximum tabs before the memory governor urges suspension.
    pub max_active_tabs: u64,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            profile_dir: None,
            privacy_preset: false,
            doh_url: None,
            background_suspend_secs: 300,
            max_active_tabs: 16,
        }
    }
}

/// Commands the UI can issue. One command, one engine operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Open a new tab. → [`Event::TabOpened`] + reply `tab`.
    NewTab,
    /// Close a tab. → [`Event::TabClosed`].
    CloseTab {
        /// Tab id.
        tab: u64,
    },
    /// Navigate a tab. → [`Event::NavigationCompleted`].
    Navigate {
        /// Tab id.
        tab: u64,
        /// Absolute URL.
        url: String,
    },
    /// Go back. → [`Event::NavigationCompleted`] (or no-op event).
    GoBack {
        /// Tab id.
        tab: u64,
    },
    /// Go forward.
    GoForward {
        /// Tab id.
        tab: u64,
    },
    /// Mark a tab backgrounded (starts the suspension clock).
    BackgroundTab {
        /// Tab id.
        tab: u64,
    },
    /// Activate a tab (wakes it if suspended).
    ActivateTab {
        /// Tab id.
        tab: u64,
    },
    /// Suspend a tab immediately.
    SuspendTab {
        /// Tab id.
        tab: u64,
    },
    /// Run the idle sweeper now (normally periodic).
    SweepIdle,
    /// Save the session to the profile.
    SaveSession,
    /// Execute JavaScript in a site context (devtools / page scripting).
    ExecJs {
        /// Site origin, e.g. `https://example.com`.
        site: String,
        /// Script source.
        code: String,
    },
}

/// Events the engine emits. All payloads are plain data.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// A tab was opened.
    TabOpened {
        /// New tab id.
        tab: u64,
    },
    /// A tab was closed.
    TabClosed {
        /// Closed tab id.
        tab: u64,
    },
    /// A navigation finished (success, error, or policy block).
    NavigationCompleted {
        /// Tab id.
        tab: u64,
        /// Outcome summary (status, url, timings, blocked).
        outcome: NavigationOutcome,
    },
    /// A navigation failed with an engine error.
    NavigationFailed {
        /// Tab id.
        tab: u64,
        /// Human-readable error.
        error: String,
    },
    /// Tabs were suspended by the sweeper.
    TabsSuspended {
        /// Number of tabs suspended.
        count: usize,
    },
    /// Memory pressure changed tier.
    MemoryPressure {
        /// New tier.
        level: MemoryPressure,
    },
    /// Session was persisted.
    SessionSaved,
}

/// API-level errors (all serializable for IPC transports).
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiError {
    /// Bad command payload.
    #[error("invalid command: {0}")]
    Invalid(String),
    /// Engine failed to start.
    #[error("engine start: {0}")]
    EngineStart(String),
    /// The referenced tab does not exist.
    #[error("no such tab: {0}")]
    NoSuchTab(u64),
    /// Navigation failure.
    #[error("navigation: {0}")]
    Navigation(String),
    /// Script failure.
    #[error("js: {0}")]
    Js(String),
    /// Session failure.
    #[error("session: {0}")]
    Session(String),
}

/// The public browser API handle.
pub struct BrowserApi {
    engine: Arc<BrowserEngine>,
    events: broadcast::Sender<Event>,
    /// Last observed pressure tier (to emit on change only).
    pressure: Mutex<MemoryPressure>,
}

impl BrowserApi {
    /// Start the engine and the API layer. Must be called inside a tokio
    /// runtime.
    pub async fn start(options: EngineOptions) -> Result<Arc<BrowserApi>, ApiError> {
        let config = build_config(&options)?;
        let engine =
            BrowserEngine::new(config).await.map_err(|e| ApiError::EngineStart(e.to_string()))?;
        let (events, _) = broadcast::channel(1024);
        Ok(Arc::new(BrowserApi { engine, events, pressure: Mutex::new(MemoryPressure::Unknown) }))
    }

    /// Subscribe to the event stream (multiple subscribers allowed).
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// Execute one command. This is THE integration point for IPC/JSON
    /// transports: deserialize a [`Command`], call this, serialize the
    /// reply.
    pub async fn command(&self, cmd: Command) -> Result<serde_json::Value, ApiError> {
        match cmd {
            Command::NewTab => {
                let id = self.engine.new_tab().await;
                let _ = self.events.send(Event::TabOpened { tab: id.0 });
                Ok(serde_json::json!({ "tab": id.0 }))
            }
            Command::CloseTab { tab } => {
                let id = TabId(tab);
                if !self.engine.close_tab(id).await {
                    return Err(ApiError::NoSuchTab(tab));
                }
                let _ = self.events.send(Event::TabClosed { tab });
                Ok(serde_json::json!({ "closed": true }))
            }
            Command::Navigate { tab, url } => {
                let id = TabId(tab);
                match self.engine.navigate(id, &url).await {
                    Ok(outcome) => {
                        let _ = self.events.send(Event::NavigationCompleted { tab, outcome });
                        self.emit_pressure_if_changed().await;
                        Ok(serde_json::json!({ "navigated": true }))
                    }
                    Err(e) => {
                        let _ =
                            self.events.send(Event::NavigationFailed { tab, error: e.to_string() });
                        Err(ApiError::Navigation(e.to_string()))
                    }
                }
            }
            Command::GoBack { tab } => {
                let id = TabId(tab);
                self.engine.go_back(id).await.map_err(|e| ApiError::Navigation(e.to_string()))?;
                Ok(serde_json::json!({ "went_back": true }))
            }
            Command::GoForward { tab } => {
                let id = TabId(tab);
                self.engine
                    .go_forward(id)
                    .await
                    .map_err(|e| ApiError::Navigation(e.to_string()))?;
                Ok(serde_json::json!({ "went_forward": true }))
            }
            Command::BackgroundTab { tab } => {
                let id = TabId(tab);
                self.engine.background_tab(id).await.map_err(|_| ApiError::NoSuchTab(tab))?;
                Ok(serde_json::json!({ "backgrounded": true }))
            }
            Command::ActivateTab { tab } => {
                let id = TabId(tab);
                self.engine.activate_tab(id).await.map_err(|_| ApiError::NoSuchTab(tab))?;
                Ok(serde_json::json!({ "activated": true }))
            }
            Command::SuspendTab { tab } => {
                let id = TabId(tab);
                self.engine.suspend_tab(id).await.map_err(|_| ApiError::NoSuchTab(tab))?;
                Ok(serde_json::json!({ "suspended": true }))
            }
            Command::SweepIdle => {
                let count = self
                    .engine
                    .sweep_idle()
                    .await
                    .map_err(|e| ApiError::EngineStart(e.to_string()))?;
                if count > 0 {
                    let _ = self.events.send(Event::TabsSuspended { count });
                }
                self.emit_pressure_if_changed().await;
                Ok(serde_json::json!({ "suspended": count }))
            }
            Command::SaveSession => {
                self.engine.save_session().await.map_err(|e| ApiError::Session(e.to_string()))?;
                let _ = self.events.send(Event::SessionSaved);
                Ok(serde_json::json!({ "saved": true }))
            }
            Command::ExecJs { site, code } => {
                let value =
                    self.engine.exec_js(&site, &code).map_err(|e| ApiError::Js(e.to_string()))?;
                Ok(serde_json::to_value(value).unwrap_or(serde_json::Value::Null))
            }
        }
    }

    /// Full tab list (complete UI state in one call).
    pub async fn tabs(&self) -> Vec<TabEntry> {
        self.engine.tabs_snapshot().await
    }

    /// Engine statistics (diagnostics panel source).
    pub async fn stats(&self) -> bw_engine::EngineStats {
        self.engine.stats().await
    }

    /// Cold-start timings (for the about:startup page).
    pub fn startup(&self) -> &Startup {
        self.engine.startup()
    }

    /// The underlying engine (for UIs compiled against Rust directly that
    /// need operations not yet wrapped as commands).
    pub fn engine(&self) -> &Arc<BrowserEngine> {
        &self.engine
    }

    /// Start the periodic idle sweeper + pressure watcher. The returned
    /// join handle aborts when dropped.
    pub fn start_background_services(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let api = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let _ = api.command(Command::SweepIdle).await;
            }
        })
    }

    async fn emit_pressure_if_changed(&self) {
        let stats = self.engine.stats().await;
        let mut last = self.pressure.lock().await;
        if *last != stats.pressure {
            *last = stats.pressure;
            let _ = self.events.send(Event::MemoryPressure { level: stats.pressure });
        }
    }
}

/// Translate API options into the engine configuration.
fn build_config(options: &EngineOptions) -> Result<EngineConfig, ApiError> {
    let profile_dir =
        options.profile_dir.clone().map(std::path::PathBuf::from).unwrap_or_else(|| {
            std::env::temp_dir().join(format!("browse-wed-{}", std::process::id()))
        });

    let mut config = if options.privacy_preset {
        let mut cfg = EngineConfig::privacy_default(profile_dir);
        if let Some(doh) = &options.doh_url {
            cfg.network.dns = DnsMode::Doh { url: doh.clone() };
        }
        cfg
    } else {
        EngineConfig { profile_dir, ..EngineConfig::default() }
    };
    config.governor = GovernorPolicy {
        background_suspend_after: std::time::Duration::from_secs(options.background_suspend_secs),
        max_active_tabs: options.max_active_tabs as usize,
        ..GovernorPolicy::default()
    };
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> EngineOptions {
        EngineOptions {
            profile_dir: Some(tempfile::tempdir().unwrap().keep().to_string_lossy().into_owned()),
            background_suspend_secs: 1,
            ..EngineOptions::default()
        }
    }

    #[tokio::test]
    async fn starts_and_creates_tabs() {
        let api = BrowserApi::start(opts()).await.unwrap();
        let reply = api.command(Command::NewTab).await.unwrap();
        let tab = reply["tab"].as_u64().unwrap();
        assert!(tab >= 1);
        assert_eq!(api.tabs().await.len(), 1);
    }

    #[tokio::test]
    async fn events_flow_to_subscribers() {
        let api = BrowserApi::start(opts()).await.unwrap();
        let mut events = api.subscribe();
        api.command(Command::NewTab).await.unwrap();
        let event = events.recv().await.unwrap();
        match event {
            Event::TabOpened { tab } => assert!(tab >= 1),
            other => panic!("expected TabOpened, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_unknown_tab_errors() {
        let api = BrowserApi::start(opts()).await.unwrap();
        let err = api.command(Command::CloseTab { tab: 999 }).await;
        assert!(matches!(err, Err(ApiError::NoSuchTab(999))));
    }

    #[tokio::test]
    async fn navigate_invalid_url_fails_cleanly() {
        let api = BrowserApi::start(opts()).await.unwrap();
        let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
        let err = api.command(Command::Navigate { tab, url: "not a url".into() }).await;
        assert!(matches!(err, Err(ApiError::Navigation(_))));
    }

    #[tokio::test]
    async fn navigate_blocked_tracker_returns_outcome() {
        // The default preset carries the starter filter list; navigating
        // to a known tracker yields a synthetic 204 without any I/O.
        let opts = EngineOptions {
            profile_dir: Some(tempfile::tempdir().unwrap().keep().to_string_lossy().into_owned()),
            privacy_preset: true,
            doh_url: Some("https://dns.quad9.net/dns-query".into()),
            ..EngineOptions::default()
        };
        let api = BrowserApi::start(opts).await.unwrap();
        let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
        let mut events = api.subscribe();
        api.command(Command::Navigate { tab, url: "https://doubleclick.net/".into() })
            .await
            .unwrap();
        match events.recv().await.unwrap() {
            Event::NavigationCompleted { outcome, .. } => {
                assert_eq!(outcome.status, 204);
                assert_eq!(outcome.protocol, "synthetic");
                assert_eq!(outcome.blocked, 1);
            }
            other => panic!("expected NavigationCompleted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_js_round_trips() {
        let api = BrowserApi::start(opts()).await.unwrap();
        let reply = api
            .command(Command::ExecJs { site: "https://x.example".into(), code: "40 + 2".into() })
            .await
            .unwrap();
        assert_eq!(reply, serde_json::json!(42.0));
    }

    #[tokio::test]
    async fn commands_round_trip_through_json() {
        // The IPC contract: any Command serializes to JSON and back.
        let cmds = vec![
            Command::NewTab,
            Command::Navigate { tab: 3, url: "https://a.example/".into() },
            Command::CloseTab { tab: 3 },
            Command::SweepIdle,
            Command::SaveSession,
            Command::ExecJs { site: "s".into(), code: "1".into() },
        ];
        for cmd in cmds {
            let json = serde_json::to_string(&cmd).unwrap();
            let back: Command = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
    }

    #[tokio::test]
    async fn stats_and_startup_visible() {
        let api = BrowserApi::start(opts()).await.unwrap();
        let stats = api.stats().await;
        assert!(stats.memory.total_bytes > 0);
        assert!(api.startup().total > std::time::Duration::ZERO);
    }
}
