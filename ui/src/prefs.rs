//! User preferences: persisted settings profile (profile/prefs.json).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Search engines supported out of the box.
pub const SEARCH_ENGINES: &[(&str, &str)] = &[
    ("DuckDuckGo", "https://duckduckgo.com/?q="),
    ("Brave Search", "https://search.brave.com/search?q="),
    ("Startpage", "https://www.startpage.com/sp/search?query="),
    ("Mojeek", "https://www.mojeek.com/search?q="),
    ("Wikipedia", "https://en.wikipedia.org/w/index.php?search="),
];

/// Persisted UI preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "light" | "dark" | "system".
    pub theme_mode: String,
    /// Accent color, hex.
    pub accent: String,
    /// Show the bookmarks bar.
    pub bookmarks_bar: bool,
    /// Startup behavior: restore previous session.
    pub restore_session: bool,
    /// Homepage URL ("" = new tab page).
    pub homepage: String,
    /// Search engine name (key of SEARCH_ENGINES).
    pub search_engine: String,
    /// Privacy toggles.
    pub adblock: bool,
    pub trackerlist: bool,
    pub cosmetic: bool,
    pub fingerprint: bool,
    pub doh: bool,
    pub doh_url: String,
    pub https_only: bool,
    pub safebrowsing: bool,
    /// Cookie policy: "partitioned" | "block-3p" | "block-all".
    pub cookie_policy: String,
    /// Clear cookies on exit.
    pub clear_on_exit: bool,
    /// Background-tab suspension timeout (seconds).
    pub suspend_secs: u64,
    /// Last window size.
    pub window_width: f32,
    pub window_height: f32,
    /// Speed dial entries (url + title).
    pub speed_dial: Vec<(String, String)>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            theme_mode: "system".into(),
            accent: "#1a73e8".into(),
            bookmarks_bar: true,
            restore_session: true,
            homepage: String::new(),
            search_engine: "DuckDuckGo".into(),
            adblock: true,
            trackerlist: true,
            cosmetic: true,
            fingerprint: true,
            doh: true,
            doh_url: "https://dns.quad9.net/dns-query".into(),
            https_only: true,
            safebrowsing: true,
            cookie_policy: "partitioned".into(),
            clear_on_exit: false,
            suspend_secs: 300,
            window_width: 1360.0,
            window_height: 850.0,
            speed_dial: default_dial(),
        }
    }
}

fn default_dial() -> Vec<(String, String)> {
    [
        ("https://en.wikipedia.org", "Wikipedia"),
        ("https://github.com", "GitHub"),
        ("https://news.ycombinator.com", "Hacker News"),
        ("https://www.youtube.com", "YouTube"),
        ("https://example.com", "Example"),
        ("https://www.mozilla.org", "Mozilla"),
        ("https://www.rust-lang.org", "Rust"),
        ("https://duckduckgo.com", "DuckDuckGo"),
    ]
    .into_iter()
    .map(|(u, t)| (u.to_string(), t.to_string()))
    .collect()
}

impl Prefs {
    /// Load prefs from `<profile>/prefs.json` (defaults when missing).
    pub fn load(profile: &Path) -> Prefs {
        let path = profile.join("prefs.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist to `<profile>/prefs.json` atomically.
    pub fn save(&self, profile: &Path) -> std::io::Result<()> {
        let path: PathBuf = profile.join("prefs.json");
        let tmp = profile.join("prefs.json.tmp");
        let data = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, path)
    }

    /// The query template for the configured search engine.
    pub fn search_template(&self) -> &str {
        SEARCH_ENGINES
            .iter()
            .find(|(name, _)| *name == self.search_engine)
            .map(|(_, url)| *url)
            .unwrap_or("https://duckduckgo.com/?q=")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = Prefs::default();
        p.theme_mode = "dark".into();
        p.save(dir.path()).unwrap();
        let loaded = Prefs::load(dir.path());
        assert_eq!(loaded.theme_mode, "dark");
        assert_eq!(loaded.search_engine, "DuckDuckGo");
    }

    #[test]
    fn search_template_resolves() {
        let mut p = Prefs::default();
        p.search_engine = "Wikipedia".into();
        assert!(p.search_template().contains("wikipedia.org"));
    }
}
