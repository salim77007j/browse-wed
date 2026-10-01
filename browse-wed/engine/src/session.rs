//! Session persistence and cold-start instrumentation.
//!
//! Sessions are a single JSON file per profile (`session.json`) holding
//! the open tabs and their histories — deliberately tiny, because a
//! session restore that costs 100 ms is a session restore nobody wants.
//! Suspended-tab state is *already* the on-disk representation: waking a
//! tab is a re-navigation, usually served from the HTTP cache.
//!
//! [`Startup`] records stage timings so the benchmark suite can prove
//! (or break) the cold-start promise with numbers, not adjectives.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::tab::{TabEntry, TabId};

/// Persisted session shape.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionFile {
    /// Version tag for forward migration.
    pub version: u32,
    /// Tabs in window order.
    pub tabs: Vec<TabEntry>,
    /// Next tab id counter (monotonic across sessions).
    pub next_tab_id: u64,
    /// Unix seconds when the session was written.
    pub saved_at_unix: u64,
}

/// Session persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Corrupt session file.
    #[error("corrupt session: {0}")]
    Corrupt(#[from] serde_json::Error),
}

/// Write a session snapshot to `profile/session.json` (atomic rename).
pub fn save_session(profile_dir: &Path, session: &SessionFile) -> Result<(), SessionError> {
    std::fs::create_dir_all(profile_dir)?;
    let tmp = profile_dir.join("session.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(session)?)?;
    std::fs::rename(&tmp, profile_dir.join("session.json"))?;
    Ok(())
}

/// Load the session from `profile/session.json` (None when absent).
pub fn load_session(profile_dir: &Path) -> Result<Option<SessionFile>, SessionError> {
    let path: PathBuf = profile_dir.join("session.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// Cold-start stage timings.
///
/// Stage granularity matches the subsystem constructors, so a regression
/// lands on the exact stage that caused it.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct Startup {
    /// Total engine bring-up time.
    pub total: Duration,
    /// Storage (profile DB) open.
    pub storage: Duration,
    /// Privacy lists compile.
    pub privacy: Duration,
    /// Network stack assembly (DNS, pools, TLS).
    pub network: Duration,
    /// JS worker spawn.
    pub javascript: Duration,
    /// Renderer (font scan) initialization.
    pub rendering: Duration,
}

impl Startup {
    /// Milliseconds per stage (for JSON-friendly reporting).
    pub fn as_millis_map(&self) -> serde_json::Value {
        serde_json::json!({
            "total": self.total.as_secs_f64() * 1000.0,
            "storage": self.storage.as_secs_f64() * 1000.0,
            "privacy": self.privacy.as_secs_f64() * 1000.0,
            "network": self.network.as_secs_f64() * 1000.0,
            "javascript": self.javascript.as_secs_f64() * 1000.0,
            "rendering": self.rendering.as_secs_f64() * 1000.0,
        })
    }
}

/// A stage-wise stopwatch used during engine bring-up.
#[derive(Debug)]
pub struct StartupTimer {
    started: std::time::Instant,
    last: std::time::Instant,
    startup: Startup,
}

impl Default for StartupTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupTimer {
    /// Start measuring.
    pub fn new() -> StartupTimer {
        let now = std::time::Instant::now();
        StartupTimer { started: now, last: now, startup: Startup::default() }
    }

    /// Close out the current stage into `record`.
    pub fn stage(&mut self, record: fn(&mut Startup, Duration)) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last);
        self.last = now;
        record(&mut self.startup, elapsed);
    }

    /// Finish and return the report.
    pub fn finish(mut self) -> Startup {
        self.startup.total = self.started.elapsed();
        self.startup
    }
}

/// Stage recorder: storage.
pub fn stage_storage(s: &mut Startup, d: Duration) {
    s.storage = d;
}
/// Stage recorder: privacy.
pub fn stage_privacy(s: &mut Startup, d: Duration) {
    s.privacy = d;
}
/// Stage recorder: network.
pub fn stage_network(s: &mut Startup, d: Duration) {
    s.network = d;
}
/// Stage recorder: javascript.
pub fn stage_javascript(s: &mut Startup, d: Duration) {
    s.javascript = d;
}
/// Stage recorder: rendering.
pub fn stage_rendering(s: &mut Startup, d: Duration) {
    s.rendering = d;
}

/// Convenience: the active tab selection policy — last-created wins on
/// restore (browsers disagree here; we pick the simplest predictable rule).
pub fn default_active_tab(session: &SessionFile) -> Option<TabId> {
    session.tabs.last().map(|t| t.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tab::TabRegistry;

    fn sample_session() -> SessionFile {
        let mut reg = TabRegistry::new();
        let a = reg.create();
        let b = reg.create();
        {
            let t = reg.get_mut(a).unwrap();
            t.push_history("https://news.example/".into(), "News".into());
            t.push_history("https://news.example/story".into(), "Story".into());
            t.state = crate::tab::TabState::Loaded;
            t.suspend();
        }
        reg.get_mut(b).unwrap().push_history("https://docs.example/".into(), "Docs".into());
        SessionFile {
            version: 1,
            tabs: reg.all().to_vec(),
            next_tab_id: 3,
            saved_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn session_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let session = sample_session();
        save_session(dir.path(), &session).unwrap();
        let loaded = load_session(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.tabs.len(), 2);
        assert_eq!(loaded.next_tab_id, 3);
        assert_eq!(loaded.tabs[0].current_url(), Some("https://news.example/story"));
        // Suspended state survives the round trip.
        assert_eq!(loaded.tabs[0].state, crate::tab::TabState::Suspended);
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn missing_session_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_session(dir.path()).unwrap().is_none());
    }

    #[test]
    fn corrupt_session_is_error_not_crash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("session.json"), b"{not json").unwrap();
        assert!(load_session(dir.path()).is_err());
    }

    #[test]
    fn restored_registry_navigates_history() {
        let session = sample_session();
        let mut reg = TabRegistry::new();
        reg.restore(session.tabs.clone(), session.next_tab_id);
        let a = reg.all()[0].id;
        let back = reg.get_mut(a).unwrap().go_back();
        assert_eq!(back, Some("https://news.example/".into()));
        // New ids continue past restored ones.
        let c = reg.create();
        assert_eq!(c, TabId(3));
    }

    #[test]
    fn startup_timer_records_stages() {
        let mut timer = StartupTimer::new();
        std::thread::sleep(Duration::from_millis(2));
        timer.stage(stage_storage);
        std::thread::sleep(Duration::from_millis(2));
        timer.stage(stage_privacy);
        let startup = timer.finish();
        assert!(startup.storage >= Duration::from_millis(2));
        assert!(startup.privacy >= Duration::from_millis(2));
        assert!(startup.total >= Duration::from_millis(4));
        assert!(startup.network.is_zero());
    }

    #[test]
    fn default_active_tab_is_last() {
        let session = sample_session();
        assert_eq!(default_active_tab(&session), Some(TabId(2)));
    }
}
