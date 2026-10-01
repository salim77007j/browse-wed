//! Chrome-level stores: bookmarks and global history.
//!
//! Like real browsers, these live in the UI ("chrome") layer, persisted in
//! the profile directory — the engine owns page-level storage (cookies,
//! cache, partitioned LS/IDB) only.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ------------------------------------------------------------------ bookmarks

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bookmark {
    pub id: u64,
    pub title: String,
    pub url: String,
    pub folder: String,
    pub added_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BookmarkStore {
    pub next_id: u64,
    pub bookmarks: Vec<Bookmark>,
}

impl BookmarkStore {
    pub fn load(profile: &Path) -> BookmarkStore {
        std::fs::read_to_string(profile.join("bookmarks.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, profile: &Path) -> std::io::Result<()> {
        atomic_write(profile.join("bookmarks.json"), serde_json::to_vec_pretty(self).unwrap())
    }

    pub fn add(&mut self, title: &str, url: &str, folder: &str) -> u64 {
        if let Some(existing) = self.bookmarks.iter_mut().find(|b| b.url == url) {
            existing.title = title.to_string();
            return existing.id;
        }
        self.next_id += 1;
        let id = self.next_id;
        self.bookmarks.push(Bookmark {
            id,
            title: title.to_string(),
            url: url.to_string(),
            folder: folder.to_string(),
            added_unix: now(),
        });
        id
    }

    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.id != id);
        before != self.bookmarks.len()
    }

    pub fn remove_by_url(&mut self, url: &str) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.url != url);
        before != self.bookmarks.len()
    }

    pub fn contains(&self, url: &str) -> bool {
        self.bookmarks.iter().any(|b| b.url == url)
    }

    /// Netscape bookmark HTML export (the universal format every browser
    /// understands — including ours on import).
    pub fn export_html(&self) -> String {
        let mut out = String::from(
            "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n\
             <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n\
             <TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n",
        );
        for folder in ["bar", "other"] {
            let items: Vec<&Bookmark> =
                self.bookmarks.iter().filter(|b| b.folder == folder).collect();
            if items.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "    <DT><H3>{}</H3>\n    <DL><p>\n",
                if folder == "bar" { "Bookmarks bar" } else { "Other bookmarks" }
            ));
            for b in items {
                out.push_str(&format!(
                    "        <DT><A HREF=\"{}\">{}</A>\n",
                    html_escape(&b.url),
                    html_escape(&b.title)
                ));
            }
            out.push_str("    </DL><p>\n");
        }
        out.push_str("</DL><p>\n");
        out
    }

    /// Import from Netscape bookmark HTML (links + folder names).
    pub fn import_html(&mut self, html: &str) -> usize {
        let mut count = 0;
        let mut folder: String = "other".into();
        for line in html.lines() {
            let l = line.trim().to_ascii_lowercase();
            if l.contains("<h3") {
                folder = if l.contains("bookmarks bar") { "bar".into() } else { "other".into() };
            }
            if !l.contains("<a ") && !l.contains("<a\n") {
                continue;
            }
            let href = extract_attr(line, "href");
            let title = strip_tags(line);
            if let Some(url) = href {
                if url.starts_with("http") {
                    let t = if title.is_empty() { url.clone() } else { title };
                    self.add(&t, &url, &folder);
                    count += 1;
                }
            }
        }
        count
    }

    /// Import from a flat list of URLs (one per line).
    #[allow(dead_code)] // public store API
    pub fn import_urls(&mut self, text: &str) -> usize {
        let mut count = 0;
        for line in text.lines() {
            let u = line.trim();
            if u.starts_with("http://") || u.starts_with("https://") {
                self.add(u, u, "other");
                count += 1;
            }
        }
        count
    }
}

fn extract_attr(line: &str, attr: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let needle = format!("{attr}=\"");
    let i = lower.find(&needle)?;
    let rest = &line[i + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn strip_tags(line: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in line.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// -------------------------------------------------------------------- history

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: u64,
    pub title: String,
    pub url: String,
    pub visited_unix: u64,
    pub visits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HistoryStore {
    pub next_id: u64,
    pub entries: Vec<HistoryEntry>,
}

const MAX_ENTRIES: usize = 10_000;

impl HistoryStore {
    pub fn load(profile: &Path) -> HistoryStore {
        std::fs::read_to_string(profile.join("history.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, profile: &Path) -> std::io::Result<()> {
        atomic_write(profile.join("history.json"), serde_json::to_vec_pretty(self).unwrap())
    }

    /// Record a visit (dedupes consecutive, counts repeat visits).
    pub fn record(&mut self, title: &str, url: &str) {
        if !url.starts_with("http") {
            return;
        }
        if let Some(last) = self.entries.last_mut() {
            if last.url == url {
                last.visits += 1;
                last.visited_unix = now();
                last.title = title.to_string();
                return;
            }
        }
        if let Some(e) = self.entries.iter_mut().find(|e| e.url == url) {
            e.visits += 1;
            e.visited_unix = now();
            e.title = title.to_string();
            return;
        }
        self.next_id += 1;
        self.entries.push(HistoryEntry {
            id: self.next_id,
            title: title.to_string(),
            url: url.to_string(),
            visited_unix: now(),
            visits: 1,
        });
        if self.entries.len() > MAX_ENTRIES {
            self.entries.drain(0..self.entries.len() - MAX_ENTRIES);
        }
    }

    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        before != self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Top frecency sites for the speed dial.
    pub fn top_sites(&self, n: usize) -> Vec<(String, String)> {
        let mut scored: Vec<(u64, &str, &str)> = self
            .entries
            .iter()
            .map(|e| (e.visited_unix * e.visits as u64, e.url.as_str(), e.title.as_str()))
            .collect();
        scored.sort_by_key(|(score, _, _)| std::cmp::Reverse(*score));
        scored
            .into_iter()
            .take(n)
            .map(|(_, u, t)| {
                (u.to_string(), if t.is_empty() { u.to_string() } else { t.to_string() })
            })
            .collect()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn atomic_write(path: PathBuf, data: Vec<u8>) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

/// Human-friendly relative time ("just now", "12 min ago", "3 h ago",
/// "yesterday", "4 d ago", "12 Oct").
pub fn relative_time(unix: u64) -> String {
    let now = now();
    let delta = now.saturating_sub(unix);
    match delta {
        s if s < 45 => "just now".into(),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 86400 => format!("{} h ago", s / 3600),
        s if s < 2 * 86400 => "yesterday".into(),
        s if s < 7 * 86400 => format!("{} d ago", s / 86400),
        _ => {
            // day/month only — no strftime platform quirks.
            let days = unix / 86400;
            const SECS_PER_DAY: u64 = 86400;
            const CIVIL_1970_01_01: (u64, u64, u64) = (1970, 1, 1);
            let (y, m, d) = civil_from_days(days);
            let _ = (SECS_PER_DAY, CIVIL_1970_01_01);
            format!("{d:02} {} {y}", month_name(m))
        }
    }
}

fn civil_from_days(z: u64) -> (u64, u64, u64) {
    let z = z + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn month_name(m: u64) -> &'static str {
    const NAMES: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    NAMES.get((m as usize).saturating_sub(1)).copied().unwrap_or("Jan")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn bookmarks_add_remove_dedupe() {
        let mut b = BookmarkStore::default();
        let id = b.add("Example", "https://example.com", "bar");
        b.add("Example again", "https://example.com", "bar");
        assert_eq!(b.bookmarks.len(), 1);
        assert!(b.contains("https://example.com"));
        assert!(b.remove(id));
        assert!(!b.contains("https://example.com"));
    }

    #[test]
    fn bookmarks_html_round_trip() {
        let mut b = BookmarkStore::default();
        b.add("Example & <Test>", "https://example.com/x?a=1", "bar");
        b.add("Wiki", "https://wikipedia.org", "other");
        let html = b.export_html();
        let mut imported = BookmarkStore::default();
        let n = imported.import_html(&html);
        assert_eq!(n, 2);
        assert!(imported.contains("https://example.com/x?a=1"));
        assert!(imported.contains("https://wikipedia.org"));
    }

    #[test]
    fn bookmarks_import_urls() {
        let mut b = BookmarkStore::default();
        let n = b.import_urls("https://a.example\n  https://b.example\nnot-a-url\n");
        assert_eq!(n, 2);
    }

    #[test]
    fn history_records_and_dedupes() {
        let mut h = HistoryStore::default();
        h.record("A", "https://a.example/1");
        h.record("A2", "https://a.example/1");
        h.record("B", "https://b.example/1");
        assert_eq!(h.entries.len(), 2);
        assert_eq!(h.entries.iter().find(|e| e.url.contains("a.example")).unwrap().visits, 2);
        assert_eq!(h.entries.last().unwrap().title, "B");
    }

    #[test]
    fn history_top_sites_order() {
        let mut h = HistoryStore::default();
        h.record("A", "https://a.example");
        h.record("B", "https://b.example");
        h.record("B", "https://b.example");
        let top = h.top_sites(1);
        assert_eq!(top[0].0, "https://b.example");
    }

    #[test]
    fn stores_round_trip_disk() {
        let d = dir();
        let mut b = BookmarkStore::default();
        b.add("X", "https://x.example", "bar");
        b.save(d.path()).unwrap();
        assert_eq!(BookmarkStore::load(d.path()).bookmarks.len(), 1);

        let mut h = HistoryStore::default();
        h.record("Y", "https://y.example");
        h.save(d.path()).unwrap();
        assert_eq!(HistoryStore::load(d.path()).entries.len(), 1);
    }

    #[test]
    fn relative_time_buckets() {
        assert_eq!(relative_time(now() - 10), "just now");
        assert_eq!(relative_time(now() - 300), "5 min ago");
        assert_eq!(relative_time(now() - 7200), "2 h ago");
    }
}
