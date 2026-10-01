//! Tab registry: the tab lifecycle, per-tab history and suspension states.
//!
//! A tab is a small, explicit state machine:
//!
//! ```text
//!            navigate()                 background (N s)
//!  ┌──────┐ ──────────► ┌─────────┐ ──────────────► ┌───────────┐
//!  │ Blank │            │ Loading │                 │ Suspended │
//!  └──────┘ ◄────────── │  Loaded │ ◄────────────── │ (0 RAM)   │
//!            navigate() └─────────┘   activate()    └───────────┘
//! ```
//!
//! * **Suspended** tabs hold only their serialized session entry (URL +
//!   history): no DOM, no JS heap, no renderer state. Waking a suspended
//!   tab is a re-navigation (usually a cache hit).
//! * History is a flat cursor over a `Vec<HistoryEntry>` — the classic
//!   back/forward model, deduplicated against consecutive repeats.

#![forbid(unsafe_code)]

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Tab identifier (monotonic within the engine process).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TabId(pub u64);

/// Lifecycle state of a tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TabState {
    /// Created, never navigated.
    Blank,
    /// Navigation in flight.
    Loading,
    /// Content loaded, active in the foreground.
    Loaded,
    /// Content loaded, in the background (suspension candidate).
    Backgrounded,
    /// Suspended: no DOM, no JS runtime; session entry retained.
    Suspended,
}

/// One history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Final URL of the entry (post-redirect).
    pub url: String,
    /// Page title (may be empty until re-derived).
    pub title: String,
}

/// The mutable per-tab state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabEntry {
    /// Identifier.
    pub id: TabId,
    /// Current state.
    pub state: TabState,
    /// History stack (cursor at `history_cursor`).
    pub history: Vec<HistoryEntry>,
    /// Cursor into `history` (`usize` sentinel via Option).
    pub history_cursor: Option<usize>,
    /// When the tab went to background (suspension clock start).
    pub backgrounded_at: Option<u64>,
    /// Number of privacy blocks on the last load (diagnostics).
    pub blocked_count: u64,
    /// Site (origin) currently loaded.
    pub site: Option<String>,
}

impl TabEntry {
    /// New blank tab.
    pub fn new(id: TabId) -> TabEntry {
        TabEntry {
            id,
            state: TabState::Blank,
            history: Vec::new(),
            history_cursor: None,
            backgrounded_at: None,
            blocked_count: 0,
            site: None,
        }
    }

    /// The current URL, if any.
    pub fn current_url(&self) -> Option<&str> {
        self.history_cursor.and_then(|i| self.history.get(i)).map(|e| e.url.as_str())
    }

    /// The current title, if any.
    pub fn current_title(&self) -> Option<&str> {
        self.history_cursor.and_then(|i| self.history.get(i)).map(|e| e.title.as_str())
    }

    /// Push a new history entry (truncating any forward entries).
    pub fn push_history(&mut self, url: String, title: String) {
        // Deduplicate consecutive identical navigations.
        if let Some(cur) = self.history_cursor.and_then(|i| self.history.get(i)) {
            if cur.url == url {
                cur_title_patch(self, &title);
                return;
            }
        }
        if let Some(cur) = self.history_cursor {
            self.history.truncate(cur + 1);
        }
        self.history.push(HistoryEntry { url, title });
        self.history_cursor = Some(self.history.len() - 1);
    }

    /// Step back in history; returns the target URL if a step happened.
    pub fn go_back(&mut self) -> Option<String> {
        let cur = self.history_cursor?;
        if cur == 0 {
            return None;
        }
        self.history_cursor = Some(cur - 1);
        self.history.get(cur - 1).map(|e| e.url.clone())
    }

    /// Step forward in history; returns the target URL if a step happened.
    pub fn go_forward(&mut self) -> Option<String> {
        let cur = self.history_cursor?;
        let next = cur + 1;
        if next >= self.history.len() {
            return None;
        }
        self.history_cursor = Some(next);
        self.history.get(next).map(|e| e.url.clone())
    }

    /// Mark the tab as backgrounded (starts the suspension clock).
    pub fn background(&mut self) {
        if self.state == TabState::Loaded {
            self.state = TabState::Backgrounded;
            self.backgrounded_at = Some(unix_now_secs());
        }
    }

    /// Mark the tab as foreground-active.
    pub fn activate(&mut self) {
        self.state = match self.state {
            TabState::Suspended => TabState::Loading, // wake = reload
            TabState::Blank | TabState::Loading => self.state,
            _ => TabState::Loaded,
        };
        self.backgrounded_at = None;
    }

    /// Suspend: drop everything except the session entry.
    pub fn suspend(&mut self) -> bool {
        if matches!(self.state, TabState::Suspended | TabState::Blank) {
            return false;
        }
        self.state = TabState::Suspended;
        true
    }

    /// Suspend and report the site whose JS runtime should be dropped.
    pub(crate) fn suspend_and_site(&mut self) -> Option<String> {
        self.suspend();
        self.site.clone()
    }

    /// Seconds since backgrounding (0 when not backgrounded).
    pub fn backgrounded_secs(&self) -> u64 {
        self.backgrounded_at
            .and_then(|at| at.checked_sub(0))
            .map(|at| unix_now_secs().saturating_sub(at))
            .unwrap_or(0)
    }
}

fn cur_title_patch(tab: &mut TabEntry, title: &str) {
    if let Some(i) = tab.history_cursor {
        if let Some(entry) = tab.history.get_mut(i) {
            if entry.title.is_empty() {
                entry.title = title.to_string();
            }
        }
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The registry over all tabs.
#[derive(Default)]
pub struct TabRegistry {
    tabs: Vec<TabEntry>,
    next_id: u64,
}

impl TabRegistry {
    /// Create an empty registry.
    pub fn new() -> TabRegistry {
        TabRegistry { tabs: Vec::new(), next_id: 1 }
    }

    /// Open a new tab; returns its id.
    pub fn create(&mut self) -> TabId {
        let id = TabId(self.next_id);
        self.next_id += 1;
        self.tabs.push(TabEntry::new(id));
        id
    }

    /// Close a tab; returns true if it existed.
    pub fn close(&mut self, id: TabId) -> bool {
        let before = self.tabs.len();
        self.tabs.retain(|t| t.id != id);
        self.tabs.len() != before
    }

    /// Borrow a tab.
    pub fn get(&self, id: TabId) -> Option<&TabEntry> {
        self.tabs.iter().find(|t| t.id == id)
    }

    /// Mutably borrow a tab.
    pub fn get_mut(&mut self, id: TabId) -> Option<&mut TabEntry> {
        self.tabs.iter_mut().find(|t| t.id == id)
    }

    /// All tabs in creation order.
    pub fn all(&self) -> &[TabEntry] {
        &self.tabs
    }

    /// Count tabs by state.
    pub fn counts(&self) -> TabCounts {
        let mut counts = TabCounts::default();
        for t in &self.tabs {
            match t.state {
                TabState::Blank => counts.blank += 1,
                TabState::Loading => counts.loading += 1,
                TabState::Loaded => counts.loaded += 1,
                TabState::Backgrounded => counts.backgrounded += 1,
                TabState::Suspended => counts.suspended += 1,
            }
        }
        counts
    }

    /// Restore tabs from a session snapshot (ids preserved).
    pub fn restore(&mut self, tabs: Vec<TabEntry>, next_id: u64) {
        self.tabs = tabs;
        self.next_id = next_id;
    }
}

/// State counts for diagnostics.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct TabCounts {
    /// Blank tabs.
    pub blank: usize,
    /// Loading tabs.
    pub loading: usize,
    /// Loaded (active) tabs.
    pub loaded: usize,
    /// Backgrounded tabs (suspension candidates).
    pub backgrounded: usize,
    /// Suspended tabs (~zero RAM).
    pub suspended: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_create_navigate_background_suspend() {
        let mut reg = TabRegistry::new();
        let id = reg.create();
        assert_eq!(reg.get(id).unwrap().state, TabState::Blank);

        {
            let t = reg.get_mut(id).unwrap();
            t.push_history("https://a.example/".into(), "A".into());
            t.state = TabState::Loaded;
        }
        assert_eq!(reg.get(id).unwrap().current_url(), Some("https://a.example/"));

        reg.get_mut(id).unwrap().background();
        assert_eq!(reg.get(id).unwrap().state, TabState::Backgrounded);
        assert!(reg.get(id).unwrap().backgrounded_at.is_some());

        assert!(reg.get_mut(id).unwrap().suspend());
        assert_eq!(reg.get(id).unwrap().state, TabState::Suspended);
        // Session entry survives.
        assert_eq!(reg.get(id).unwrap().current_url(), Some("https://a.example/"));
    }

    #[test]
    fn history_back_forward() {
        let mut reg = TabRegistry::new();
        let id = reg.create();
        let t = reg.get_mut(id).unwrap();
        t.push_history("https://a/".into(), "a".into());
        t.push_history("https://b/".into(), "b".into());
        t.push_history("https://c/".into(), "c".into());
        assert_eq!(t.current_url(), Some("https://c/"));

        assert_eq!(t.go_back(), Some("https://b/".into()));
        assert_eq!(t.go_back(), Some("https://a/".into()));
        assert_eq!(t.go_back(), None); // at start

        assert_eq!(t.go_forward(), Some("https://b/".into()));
        // A new navigation truncates the forward entries.
        t.push_history("https://d/".into(), "d".into());
        assert_eq!(t.go_forward(), None);
        assert_eq!(t.current_url(), Some("https://d/"));
    }

    #[test]
    fn consecutive_duplicate_navigation_deduped() {
        let mut reg = TabRegistry::new();
        let id = reg.create();
        let t = reg.get_mut(id).unwrap();
        t.push_history("https://x/1".into(), "".into());
        t.push_history("https://x/1".into(), "Title".into());
        assert_eq!(t.history.len(), 1);
        assert_eq!(t.current_title(), Some("Title"));
    }

    #[test]
    fn close_removes_tab() {
        let mut reg = TabRegistry::new();
        let a = reg.create();
        let b = reg.create();
        assert!(reg.close(a));
        assert!(!reg.close(a));
        assert_eq!(reg.all().len(), 1);
        assert_eq!(reg.all()[0].id, b);
    }

    #[test]
    fn counts_partition_states() {
        let mut reg = TabRegistry::new();
        let _a = reg.create(); // stays blank
        let b = reg.create();
        {
            let t = reg.get_mut(b).unwrap();
            t.state = TabState::Loaded;
            t.suspend();
        }
        let c = reg.create();
        {
            let t = reg.get_mut(c).unwrap();
            t.state = TabState::Loaded;
            t.background();
        }
        let counts = reg.counts();
        assert_eq!(counts.blank, 1);
        assert_eq!(counts.suspended, 1);
        assert_eq!(counts.backgrounded, 1);
    }

    #[test]
    fn activate_wakes_suspended_to_loading() {
        let mut reg = TabRegistry::new();
        let id = reg.create();
        let t = reg.get_mut(id).unwrap();
        t.push_history("https://wake/".into(), "w".into());
        t.state = TabState::Loaded;
        t.suspend();
        t.activate();
        assert_eq!(t.state, TabState::Loading);
        assert!(t.backgrounded_at.is_none());
    }
}
