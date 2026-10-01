//! Omnibox intelligence: URL detection, history/bookmark matches, search
//! suggestions (remote, through the engine pipeline — never a second
//! network stack).

use std::sync::Arc;

use bw_engine::BrowserEngine;
use bw_privacy::ResourceType;
use url::Url;

use crate::prefs::Prefs;
use crate::stores::{BookmarkStore, HistoryStore};

/// One omnibox suggestion row.
#[derive(Debug, Clone)]
pub struct Suggestion {
    pub kind: &'static str, // search | url | history | bookmark
    pub text: String,
    pub secondary: String,
    pub navigate: String,
}

/// Classify omnibox input: URL to open vs. query to search.
pub fn classify(input: &str) -> Suggestion {
    let t = input.trim();
    if t.is_empty() {
        return search_suggestion("", "");
    }
    if looks_like_url(t) {
        let url = if t.contains("://") { t.to_string() } else { format!("https://{t}") };
        return Suggestion {
            kind: "url",
            text: t.to_string(),
            secondary: "open website".into(),
            navigate: url,
        };
    }
    // Intrinsic schemes pass through.
    if t.starts_with("about:") || t.starts_with("file://") {
        return Suggestion {
            kind: "url",
            text: t.to_string(),
            secondary: "internal page".into(),
            navigate: t.to_string(),
        };
    }
    search_suggestion(t, "")
}

fn search_suggestion(query: &str, template_note: &str) -> Suggestion {
    let _ = template_note;
    Suggestion {
        kind: "search",
        text: if query.is_empty() {
            "Type to search or enter address".into()
        } else {
            query.to_string()
        },
        secondary: "search".into(),
        navigate: query.to_string(),
    }
}

pub fn looks_like_url(s: &str) -> bool {
    let t = s.trim();
    if t.contains(' ') {
        return false;
    }
    if t.starts_with("http://") || t.starts_with("https://") || t.starts_with("about:") {
        return true;
    }
    if t.starts_with("localhost") {
        return true;
    }
    // host.tld[/path]
    if let Some(rest) = t.split_once('.') {
        if !rest.0.is_empty() && rest.1.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            return true;
        }
    }
    false
}

/// Build the full suggestion list for omnibox input.
pub async fn build_suggestions(
    input: &str,
    history: &HistoryStore,
    bookmarks: &BookmarkStore,
    _prefs: &Prefs,
    engine: &Arc<BrowserEngine>,
) -> Vec<Suggestion> {
    let t = input.trim();
    let mut out = Vec::new();
    if t.is_empty() {
        return out;
    }

    // 1. The primary action (URL open or search).
    out.push(classify(t));

    // 2. Local matches — bookmarks then history.
    let tl = t.to_lowercase();
    for b in bookmarks.bookmarks.iter().filter(|b| b.url.to_lowercase().contains(&tl)).take(3) {
        out.push(Suggestion {
            kind: "bookmark",
            text: if b.title.is_empty() { b.url.clone() } else { b.title.clone() },
            secondary: b.url.clone(),
            navigate: b.url.clone(),
        });
    }
    let mut seen = 0;
    for h in history.entries.iter().rev().filter(|e| e.url.to_lowercase().contains(&tl)).take(4) {
        if seen >= 3 {
            break;
        }
        if out.iter().any(|s| s.navigate == h.url) {
            continue;
        }
        seen += 1;
        out.push(Suggestion {
            kind: "history",
            text: if h.title.is_empty() { h.url.clone() } else { h.title.clone() },
            secondary: h.url.clone(),
            navigate: h.url.clone(),
        });
    }

    // 3. Remote search suggestions via the engine (privacy: no second stack).
    if let Some(remote) = remote_suggest(engine, t).await {
        for phrase in remote.into_iter().take(5) {
            if phrase.eq_ignore_ascii_case(t) {
                continue;
            }
            let navigate = phrase.clone();
            out.push(Suggestion {
                kind: "search",
                text: phrase,
                secondary: "search suggestion".into(),
                navigate,
            });
        }
    }

    out.truncate(9);
    out
}

/// DuckDuckGo autocomplete endpoint, fetched through the engine.
async fn remote_suggest(engine: &Arc<BrowserEngine>, query: &str) -> Option<Vec<String>> {
    let url = Url::parse_with_params("https://duckduckgo.com/ac/", &[("q", query)]).ok()?;
    let host = "duckduckgo.com".to_string();
    let resp = engine.fetch_subresource(url, ResourceType::XHR, &host).await.ok()?;
    if !resp.status.is_success() {
        return None;
    }
    let body = std::str::from_utf8(&resp.body).ok()?;
    let parsed: Vec<serde_json::Value> = serde_json::from_str(body).ok()?;
    Some(
        parsed
            .into_iter()
            .filter_map(|v| v.get("phrase").and_then(|p| p.as_str()).map(str::to_string))
            .collect(),
    )
}

/// Turn a suggestion "navigate" value into the URL to load.
pub fn resolve_target(value: &str, prefs: &Prefs) -> String {
    let t = value.trim();
    if t.is_empty() {
        return "about:newtab".into();
    }
    if t.starts_with("http://") || t.starts_with("https://") || t.starts_with("about:") {
        return t.to_string();
    }
    if looks_like_url(t) {
        return format!("https://{t}");
    }
    format!("{}{}", prefs.search_template(), urlencoding_minimal(t))
}

/// Minimal %-encoding of the query component.
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b' ' | b'/' | b':' | b'@')
        {
            if b == b' ' {
                out.push('+');
            } else {
                out.push(b as char);
            }
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert_eq!(classify("example.com").kind, "url");
        assert_eq!(classify("https://a.example/x").kind, "url");
        assert_eq!(classify("rust programming language").kind, "search");
        assert_eq!(classify("localhost:8080").kind, "url");
        assert_eq!(classify("about:settings").kind, "url");
    }

    #[test]
    fn target_resolution() {
        let prefs = Prefs::default();
        assert_eq!(resolve_target("example.com", &prefs), "https://example.com");
        assert_eq!(resolve_target("hello world", &prefs), "https://duckduckgo.com/?q=hello+world");
        assert_eq!(resolve_target("https://x.example", &prefs), "https://x.example");
        assert_eq!(resolve_target("", &prefs), "about:newtab");
    }

    #[test]
    fn suggestions_include_local_matches() {
        let mut history = HistoryStore::default();
        history.record("Rust language", "https://rust-lang.org");
        let mut bookmarks = BookmarkStore::default();
        bookmarks.add("Rust docs", "https://doc.rust-lang.org", "bar");
        let prefs = Prefs::default();
        let sugg =
            tokio_block(build_suggestions("rust", &history, &bookmarks, &prefs, &test_engine()));
        assert!(sugg.iter().any(|s| s.kind == "search"));
        assert!(sugg.iter().any(|s| s.kind == "bookmark" && s.text == "Rust docs"));
    }

    fn tokio_block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    fn test_engine() -> Arc<BrowserEngine> {
        // A headless engine without network features: remote suggest will
        // simply fail and be skipped.
        tokio_block(async {
            let dir = tempfile::tempdir().unwrap();
            let cfg = bw_engine::EngineConfig {
                profile_dir: dir.keep(),
                ..bw_engine::EngineConfig::default()
            };
            BrowserEngine::new(cfg).await.unwrap()
        })
    }

    #[test]
    fn urlencoding_keeps_slashes() {
        assert_eq!(urlencoding_minimal("a b/c"), "a+b/c");
        assert_eq!(urlencoding_minimal("héllo"), "h%C3%A9llo");
    }
}
