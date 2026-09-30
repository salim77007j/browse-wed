//! RFC 6265bis cookie jar with CHIPS (Cookies Having Independent Partitioned
//! State) partitioning.
//!
//! Semantics implemented:
//!
//! * `Set-Cookie` parsing: name/value, `Domain`, `Path`, `Expires`, `Max-Age`,
//!   `Secure`, `HttpOnly`, `SameSite=Lax|Strict|None`, `Partitioned`.
//! * Domain matching (host-only vs domain cookies, subdomain rules).
//! * Path matching (RFC 6265 §5.1.4).
//! * CHIPS: a cookie carrying `Partitioned` is stored under the *top-level
//!   site* partition and returned only inside that partition. Non-partitioned
//!   third-party cookies are dropped (2026 default posture).
//! * Cookie-date parsing per RFC 6265 §5.1.1.
//!
//! Persistence: the jar is kept in memory for O(1) request-path access and
//! snapshotted to the `cookies` redb table after mutations.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::keyspace;
use crate::{COOKIE_TABLE, Result};

/// SameSite attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SameSite {
    /// No SameSite attribute → Lax-by-default (2026 browser posture).
    #[default]
    Unspecified,
    /// `SameSite=Lax`
    Lax,
    /// `SameSite=Strict`
    Strict,
    /// `SameSite=None`
    None,
}

/// One stored cookie.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain (host-only cookies store the request host).
    pub domain: String,
    /// Path attribute.
    pub path: String,
    /// Absolute expiry instant (`None` = session cookie).
    pub expires: Option<SystemTime>,
    /// `Secure` attribute.
    pub secure: bool,
    /// `HttpOnly` attribute.
    pub http_only: bool,
    /// SameSite policy.
    pub same_site: SameSite,
    /// Host-only (no explicit `Domain=` attribute).
    pub host_only: bool,
    /// CHIPS partition key — the top-level site (scheme + registrable domain)
    /// that was present when the cookie was set.
    pub partition_key: Option<String>,
    /// Creation instant (tie-breaker for eviction ordering).
    pub creation_time: SystemTime,
}

impl Cookie {
    /// Serialized identity used as the storage key.
    fn storage_key(&self) -> String {
        keyspace::cookie_key(
            self.partition_key.as_deref().unwrap_or(""),
            &self.domain,
            &self.path,
            &self.name,
        )
    }

    /// True when the cookie has expired.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires.is_some_and(|e| now >= e)
    }

    /// Remaining lifetime in seconds (None = session cookie).
    pub fn max_age_remaining(&self, now: SystemTime) -> Option<u64> {
        self.expires.map(|e| {
            e.duration_since(now)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        })
    }
}

/// Cookie-jar statistics for the memory governor.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct JarStats {
    /// Total cookies in memory.
    pub total: usize,
    /// Partitioned (CHIPS) cookies.
    pub partitioned: usize,
    /// Session cookies (no expiry).
    pub session: usize,
}

/// The in-memory cookie jar.
#[derive(Default)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
    /// Whether non-partitioned third-party cookies are stored at all.
    allow_third_party: bool,
}

impl CookieJar {
    /// Create an empty jar with 2026 defaults (third-party cookies blocked
    /// unless partitioned).
    pub fn new() -> CookieJar {
        CookieJar {
            cookies: Vec::new(),
            allow_third_party: false,
        }
    }

    /// Toggle plain third-party cookie storage (user setting).
    pub fn set_allow_third_party(&mut self, allow: bool) {
        self.allow_third_party = allow;
    }

    /// Parse a `Set-Cookie` header value in the context of a response.
    ///
    /// * `request_host` — host of the URL the cookie was set from.
    /// * `top_level_site` — first-party site (e.g. `https://example.com`).
    /// * `is_secure_transport` — whether the connection used HTTPS.
    pub fn parse_set_cookie(
        &mut self,
        header: &str,
        request_host: &str,
        top_level_site: &str,
        is_secure_transport: bool,
    ) -> Option<Cookie> {
        let cookie =
            parse_set_cookie_header(header, request_host, top_level_site, is_secure_transport)?;
        // CHIPS gate: a third-party cookie (different registrable domain
        // than the top-level site) is only stored when it is Partitioned.
        let top_host = site_host(top_level_site).unwrap_or_default();
        if !top_host.is_empty()
            && !same_registrable_domain(&top_host, &cookie.domain)
            && cookie.partition_key.is_none()
            && !self.allow_third_party
        {
            tracing::debug!(
                domain = %cookie.domain,
                top = %top_host,
                "rejecting unpartitioned third-party cookie"
            );
            return None;
        }
        self.set(cookie)
    }

    /// Store a cookie (replacing any same-identity cookie). Returns the
    /// stored cookie, or `None` when the cookie was rejected.
    pub fn set(&mut self, cookie: Cookie) -> Option<Cookie> {
        // SameSite=None requires Secure.
        if cookie.same_site == SameSite::None && !cookie.secure {
            return None;
        }
        let key = cookie.storage_key();
        let now = SystemTime::now();
        let expired = cookie.is_expired(now);
        let existing_idx = self.cookies.iter().position(|c| c.storage_key() == key);
        if expired {
            if let Some(i) = existing_idx {
                self.cookies.remove(i);
            }
            return None;
        }
        match existing_idx {
            Some(i) => {
                // Keep original creation time per RFC 6265 §5.3 step 11.
                let mut merged = cookie.clone();
                merged.creation_time = self.cookies[i].creation_time;
                self.cookies[i] = merged;
            }
            None => self.cookies.push(cookie.clone()),
        }
        Some(cookie)
    }

    /// Compose a `Cookie:` request header value for a URL inside a
    /// partition. Returns `""` when no cookies apply.
    pub fn get_for(&self, url: &str, top_level_site: &str, is_secure_transport: bool) -> String {
        let Ok(parsed) = url::Url::parse(url) else {
            return String::new();
        };
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        let path = parsed.path();
        let now = SystemTime::now();
        let mut matches: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                !c.is_expired(now)
                    && domain_matches(&host, c)
                    && path_matches(path, &c.path)
                    && (!c.secure || is_secure_transport)
                    && partition_ok(c, top_level_site, &host)
            })
            .collect();
        // RFC 6265 §5.4: longer paths first, then earlier creation.
        matches.sort_by(|a, b| {
            b.path.len()
                .cmp(&a.path.len())
                .then(a.creation_time.cmp(&b.creation_time))
        });
        let mut out = String::new();
        for c in matches {
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(&c.name);
            out.push('=');
            out.push_str(&c.value);
        }
        out
    }

    /// Iterate live cookies (for devtools / export).
    pub fn iter(&self) -> impl Iterator<Item = &Cookie> {
        self.cookies.iter()
    }

    /// Statistics.
    pub fn stats(&self) -> JarStats {
        let now = SystemTime::now();
        JarStats {
            total: self.cookies.len(),
            partitioned: self.cookies.iter().filter(|c| c.partition_key.is_some()).count(),
            session: self.cookies.iter().filter(|c| c.expires.is_none()).count(),
        }
    }

    /// Drop expired cookies; returns the number removed.
    pub fn evict_expired(&mut self) -> usize {
        let now = SystemTime::now();
        let before = self.cookies.len();
        self.cookies.retain(|c| !c.is_expired(now));
        before - self.cookies.len()
    }

    /// Hard cap: keep at most `max` cookies, evicting oldest first.
    pub fn evict_to(&mut self, max: usize) -> usize {
        if self.cookies.len() <= max {
            return 0;
        }
        self.cookies.sort_by(|a, b| a.creation_time.cmp(&b.creation_time));
        let removed = self.cookies.len() - max;
        self.cookies.truncate(max);
        removed
    }

    /// Load from the database.
    pub fn load(db: &redb::Database) -> Result<CookieJar> {
        let mut jar = CookieJar::new();
        let tx = db.begin_read()?;
        match tx.open_table(COOKIE_TABLE) {
            Ok(t) => {
                for row in t.iter()? {
                    let (_, v) = row?;
                    if let Ok(c) = serde_json::from_str::<Cookie>(v.value()) {
                        jar.cookies.push(c);
                    }
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(jar)
    }

    /// Reload from the database (post-purge).
    pub fn reload(&mut self, db: &redb::Database) -> Result<()> {
        *self = CookieJar::load(db)?;
        Ok(())
    }

    /// Snapshot the jar into the database.
    pub fn persist(&self, db: &redb::Database) -> Result<()> {
        let tx = db.begin_write()?;
        {
            let mut t = tx.open_table(COOKIE_TABLE)?;
            let now = SystemTime::now();
            let live: Vec<&Cookie> = self.cookies.iter().filter(|c| !c.is_expired(now)).collect();
            // Clear stale entries: remove keys not in the live set.
            let live_keys: std::collections::HashSet<String> =
                live.iter().map(|c| c.storage_key()).collect();
            let mut stale: Vec<String> = Vec::new();
            for row in t.iter()? {
                let (k, _) = row?;
                let key = k.value().to_string();
                if !live_keys.contains(&key) {
                    stale.push(key);
                }
            }
            for key in stale {
                t.remove(key.as_str())?;
            }
            for c in live {
                let key = c.storage_key();
                let val = serde_json::to_string(c)?;
                t.insert(key.as_str(), val.as_str())?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn partition_ok(c: &Cookie, top_level_site: &str, request_host: &str) -> bool {
    match &c.partition_key {
        // First-party cookie: the request must be same-site with the
        // top-level context.
        None => same_registrable_domain(top_level_site, request_host),
        // CHIPS cookie: the current top-level site must match the partition.
        Some(partition) => same_registrable_domain(partition, top_level_site),
    }
}

fn parse_set_cookie_header(
    header: &str,
    request_host: &str,
    top_level_site: &str,
    is_secure_transport: bool,
) -> Option<Cookie> {
    let mut parts = header.split(';');
    let nv = parts.next()?;
    let (name, value) = nv.split_once('=')?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value = value.trim().to_string();

    let host = request_host.to_ascii_lowercase();
    let mut cookie = Cookie {
        name,
        value,
        domain: host.clone(),
        path: default_path(&format!("/{}", host)), // replaced below with real URL path
        expires: None,
        secure: false,
        http_only: false,
        same_site: SameSite::Unspecified,
        host_only: true,
        partition_key: None,
        creation_time: SystemTime::now(),
    };

    for attr in parts {
        let attr = attr.trim();
        let (an, av) = match attr.split_once('=') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (attr, ""),
        };
        match an.to_ascii_lowercase().as_str() {
            "domain" => {
                let d = av.trim_start_matches('.').to_ascii_lowercase();
                if !d.is_empty() && domain_allows(&host, &d) {
                    cookie.domain = d;
                    cookie.host_only = false;
                }
            }
            "path" => {
                cookie.path = if av.starts_with('/') {
                    av.to_string()
                } else {
                    // RFC 6265 §5.1.4 default-path (we only know the host
                    // here; the network layer passes the real path via
                    // `set_with_url` when precision matters).
                    "/".to_string()
                };
            }
            "expires" => {
                cookie.expires = parse_cookie_date(av);
            }
            "max-age" => {
                if let Ok(secs) = av.parse::<i64>() {
                    cookie.expires = if secs <= 0 {
                        Some(UNIX_EPOCH)
                    } else {
                        SystemTime::now().checked_add(Duration::from_secs(secs as u64))
                    };
                }
            }
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => {
                cookie.same_site = match av.to_ascii_lowercase().as_str() {
                    "strict" => SameSite::Strict,
                    "none" => SameSite::None,
                    _ => SameSite::Lax,
                };
            }
            "partitioned" => {
                cookie.partition_key = Some(top_level_site.to_string());
            }
            _ => {}
        }
    }
    // Secure cookies can only be set over secure transport.
    if cookie.secure && !is_secure_transport {
        return None;
    }
    Some(cookie)
}

/// Full-context variant used by the network layer: knows the document URL.
pub fn parse_set_cookie_for_url(
    header: &str,
    url: &url::Url,
    top_level_site: &str,
    is_secure_transport: bool,
) -> Option<Cookie> {
    let host = url.host_str()?.to_ascii_lowercase();
    let mut cookie =
        parse_set_cookie_header(header, &host, top_level_site, is_secure_transport)?;
    // Refine default path from the real URL (RFC 6265 §5.1.4).
    if !cookie.path_is_explicit() {
        cookie.path = default_path(url.path());
    }
    Some(cookie)
}

impl Cookie {
    /// Whether the Path attribute was explicit (internal bookkeeping).
    fn path_is_explicit(&self) -> bool {
        !self.path.is_empty() && self.path != "/"
    }
}

fn default_path(url_path: &str) -> String {
    // §5.1.4: path up to (not including) the rightmost '/'.
    if !url_path.starts_with('/') {
        return "/".to_string();
    }
    match url_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => url_path[..i].to_string(),
    }
}

fn domain_matches(host: &str, c: &Cookie) -> bool {
    if c.host_only {
        host == c.domain
    } else {
        host == c.domain || (host.ends_with(&c.domain) && host.as_bytes()[host.len() - c.domain.len() - 1] == b'.')
    }
}

fn domain_allows(request_host: &str, cookie_domain: &str) -> bool {
    // Public-suffix check (heuristic): single-label domains are rejected.
    if !cookie_domain.contains('.') {
        return false;
    }
    request_host == cookie_domain
        || (request_host.ends_with(cookie_domain)
            && request_host.as_bytes()[request_host.len() - cookie_domain.len() - 1] == b'.')
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if request_path.starts_with(cookie_path) {
        let tail = &request_path[cookie_path.len()..];
        if cookie_path.ends_with('/') || tail.starts_with('/') {
            return true;
        }
    }
    false
}

fn host_of(s: &str) -> &str {
    let s = s.trim_start_matches("https://").trim_start_matches("http://");
    s.split('/').next().unwrap_or(s)
}

/// Extract the registrable domain (last two labels; three for two-part
/// public suffixes like `co.uk`).
fn registrable(host: &str) -> &str {
    let host = host_of(host).trim_end_matches('.');
    let mut dots = host.rmatch_indices('.');
    if dots.next().is_none() {
        return host; // single label
    }
    let Some((i2, _)) = dots.next() else { return host };
    let last_two = &host[i2 + 1..];
    const TWO_PART_TLDS: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp", "co.kr", "com.au",
        "net.au", "org.au", "co.nz", "com.br", "com.mx", "com.cn", "com.tw", "co.in", "co.za",
    ];
    if TWO_PART_TLDS.contains(&last_two) {
        match dots.next() {
            Some((i3, _)) => &host[i3 + 1..],
            None => host,
        }
    } else {
        &host[i2 + 1..]
    }
}

fn same_registrable_domain(a: &str, b: &str) -> bool {
    registrable(a) == registrable(b)
}

fn site_host(site: &str) -> Option<String> {
    url::Url::parse(site)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}

/// RFC 6265 §5.1.1 cookie-date parsing: token soup — find time, day, month,
/// year in any order.
pub fn parse_cookie_date(s: &str) -> Option<SystemTime> {
    let mut time: Option<(u32, u32, u32)> = None;
    let mut day: Option<u32> = None;
    let mut month: Option<u32> = None;
    let mut year: Option<i64> = None;

    for tok in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == ':')) {
        if tok.is_empty() {
            continue;
        }
        // hh:mm:ss
        if time.is_none() && tok.contains(':') {
            let bits: Vec<&str> = tok.split(':').collect();
            if bits.len() == 3 {
                if let (Ok(h), Ok(m), Ok(sec)) =
                    (bits[0].parse::<u32>(), bits[1].parse::<u32>(), bits[2].parse::<u32>())
                {
                    time = Some((h, m, sec));
                    continue;
                }
            }
        }
        if tok.len() == 1 || tok.len() == 2 {
            if let Ok(d) = tok.parse::<u32>() {
                if day.is_none() && (1..=31).contains(&d) {
                    day = Some(d);
                    continue;
                }
                if year.is_none() && (70..=99).contains(&d) {
                    year = Some(1900 + d as i64);
                    continue;
                }
                if year.is_none() && (0..=69).contains(&d) {
                    year = Some(2000 + d as i64);
                    continue;
                }
            }
        }
        if tok.len() == 4 {
            if let Ok(y) = tok.parse::<i64>() {
                year = Some(y);
                continue;
            }
        }
        if month.is_none() {
            let m = match tok.to_ascii_lowercase().as_str() {
                "jan" => 1,
                "feb" => 2,
                "mar" => 3,
                "apr" => 4,
                "may" => 5,
                "jun" => 6,
                "jul" => 7,
                "aug" => 8,
                "sep" => 9,
                "oct" => 10,
                "nov" => 11,
                "dec" => 12,
                _ => continue,
            };
            month = Some(m);
        }
    }

    let (h, m, sec) = time?;
    let day = day?;
    let month = month?;
    let mut year = year?;
    if (70..=99).contains(&year) {
        year += 1900;
    } else if year <= 69 {
        year += 2000;
    }
    // Convert to epoch (UTC, ignoring leap seconds).
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86_400 + h as i64 * 3_600 + m as i64 * 60 + sec as i64;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jar() -> CookieJar {
        CookieJar::new()
    }

    #[test]
    fn set_and_get_first_party() {
        let mut j = jar();
        j.parse_set_cookie(
            "sid=abc; Path=/; HttpOnly",
            "example.com",
            "https://example.com",
            true,
        )
        .unwrap();
        let h = j.get_for("https://example.com/page", "https://example.com", true);
        assert_eq!(h, "sid=abc");
    }

    #[test]
    fn partitioned_third_party_cookie() {
        let mut j = jar();
        // third-party embeds a CHIPS cookie
        j.parse_set_cookie(
            "telemetry=1; Path=/; Secure; Partitioned",
            "cdn.embed.io",
            "https://news.com",
            true,
        )
        .unwrap();
        // same partition sees it
        let h = j.get_for("https://cdn.embed.io/t.gif", "https://news.com", true);
        assert_eq!(h, "telemetry=1");
        // different top-level site does NOT see it
        let h2 = j.get_for("https://cdn.embed.io/t.gif", "https://other.org", true);
        assert_eq!(h2, "");
    }

    #[test]
    fn unpartitioned_third_party_dropped() {
        let mut j = jar();
        assert!(j
            .parse_set_cookie(
                "tracker=x; Path=/; Secure",
                "cdn.embed.io",
                "https://news.com",
                true,
            )
            .is_none());
        assert!(j.get_for("https://cdn.embed.io/", "https://news.com", true).is_empty());
    }

    #[test]
    fn samesite_none_requires_secure() {
        let mut j = jar();
        assert!(j
            .parse_set_cookie(
                "a=1; SameSite=None",
                "example.com",
                "https://example.com",
                true,
            )
            .is_none());
    }

    #[test]
    fn debug_domain_cookie() {
        let mut j = jar();
        let stored = j.parse_set_cookie(
            "pref=dark; Domain=example.com; Path=/",
            "www.example.com",
            "https://www.example.com",
            true,
        );
        eprintln!("stored = {stored:?}");
        for c in j.iter() {
            eprintln!("jar cookie: domain={} host_only={} path={}", c.domain, c.host_only, c.path);
        }
        let got = j.get_for("https://api.example.com/x", "https://www.example.com", true);
        eprintln!("get_for = '{got}'");
    }

    #[test]
    fn domain_cookies_subdomain_match() {
        let mut j = jar();
        j.parse_set_cookie(
            "pref=dark; Domain=example.com; Path=/",
            "www.example.com",
            "https://www.example.com",
            true,
        )
        .unwrap();
        assert_eq!(
            j.get_for("https://api.example.com/x", "https://www.example.com", true),
            "pref=dark"
        );
    }

    #[test]
    fn host_only_no_subdomain_leak() {
        let mut j = jar();
        j.parse_set_cookie(
            "h=1; Path=/",
            "api.example.com",
            "https://api.example.com",
            true,
        )
        .unwrap();
        assert!(j.get_for("https://other.example.com/", "https://api.example.com", true).is_empty());
    }

    #[test]
    fn expiry_and_eviction() {
        let mut j = jar();
        j.parse_set_cookie(
            "sess=a; Max-Age=1",
            "example.com",
            "https://example.com",
            true,
        )
        .unwrap();
        assert!(
            j.parse_set_cookie(
                "perm=b; Max-Age=0",
                "example.com",
                "https://example.com",
                true,
            )
            .is_none(),
            "immediately-expired cookie must be dropped"
        );
        assert_eq!(j.stats().total, 1);
    }

    #[test]
    fn cookie_date_parsing() {
        let t = parse_cookie_date("Wed, 21 Oct 2015 07:28:00 GMT").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_445_412_480
        );
        let t2 = parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(
            t2.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            784_111_777
        );
    }

    #[test]
    fn path_matching_rules() {
        assert!(path_matches("/a/b", "/a"));
        assert!(path_matches("/a", "/a"));
        assert!(path_matches("/a/b/c", "/a/b"));
        assert!(!path_matches("/ab", "/a"));
        assert!(!path_matches("/a", "/a/b"));
        assert!(path_matches("/a/", "/a"));
    }

    #[test]
    fn persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("t.redb")).unwrap();
        let mut j = jar();
        j.parse_set_cookie(
            "sid=keep; Path=/; Max-Age=3600",
            "example.com",
            "https://example.com",
            true,
        )
        .unwrap();
        j.parse_set_cookie(
            "gone=x; Max-Age=1",
            "example.com",
            "https://example.com",
            true,
        )
        .unwrap();
        j.persist(&db).unwrap();
        let loaded = CookieJar::load(&db).unwrap();
        assert_eq!(loaded.stats().total, 2);
        assert_eq!(
            loaded.get_for("https://example.com/", "https://example.com", true),
            "sid=keep; gone=x"
        );
    }

    #[test]
    fn ordering_longer_paths_first() {
        let mut j = jar();
        j.parse_set_cookie("a=1; Path=/", "example.com", "https://example.com", true).unwrap();
        j.parse_set_cookie("b=2; Path=/app", "example.com", "https://example.com", true).unwrap();
        let h = j.get_for("https://example.com/app/x", "https://example.com", true);
        assert!(h.starts_with("b=2"), "longer path first: {h}");
    }
}
