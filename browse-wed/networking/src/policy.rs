//! Request policy: the privacy decision layer of the network stack.
//!
//! Every outgoing request passes through [`PolicyEngine`] *before* any
//! socket is opened:
//!
//! 1. **Network filters** (`bw_privacy::filter`) decide Allow / Block /
//!    Neuter from the compiled uBlock-syntax filter set.
//! 2. **Safe Browsing** (`bw_privacy::safebrowsing`) — the local
//!    Bloom-filter database is consulted; a hit escalates to the UI as a
//!    warning rather than a silent block (browsers must not
//!    silently kill navigations on Bloom false-positives).
//! 3. **CNAME uncloaking** — the DNS layer exposes the CNAME chain; when
//!    the chain crosses into a known tracker apex the *effective* host is
//!    re-run through the filter set.
//! 4. **HTTPS upgrade + HSTS** — plain navigations are upgraded where
//!    policy allows, and HSTS-known hosts are forced to https.
//!
//! All decisions are pure functions of (request, engine state) — no I/O,
//! no clock — which keeps them unit-testable and fuzzable.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use bw_privacy::cname::{CnameChain, Uncloaker};
use bw_privacy::filter::FilterSet;
use bw_privacy::safebrowsing::{SafeBrowsingDb, Verdict};
use bw_privacy::{Decision, RequestContext};
use url::Url;

use crate::config::NetworkConfig;

/// Why a request was blocked (surfaced to the UI / devtools).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum BlockReason {
    /// Matched a network filter rule.
    NetworkFilter,
    /// Effective host (after CNAME uncloaking) matched a filter rule.
    CnameCloaked,
    /// Safe Browsing database hit (UI must confirm before proceeding).
    SafeBrowsing,
}

/// The outcome of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Proceed unchanged.
    Allow,
    /// Block outright (network-level).
    Block(BlockReason),
    /// Neuter: answer locally with an empty body (tracker feeds).
    Neuter,
    /// Navigation-level warning: the UI decides.
    Warn(BlockReason),
}

/// HSTS record: host → expiry (unix seconds).
struct HstsEntry {
    #[allow(dead_code)]
    include_subdomains: bool,
    expires_unix: u64,
}

/// Alt-Svc record: origin → (alt authority, expiry).
struct AltSvcEntry {
    authority: String,
    expires_unix: u64,
}

/// The policy engine. Immutable filter sets + small mutable HSTS/Alt-Svc
/// maps guarded by an RwLock (writes happen only on response headers).
pub struct PolicyEngine {
    filters: Arc<FilterSet>,
    safe_browsing: Arc<SafeBrowsingDb>,
    uncloaker: RwLock<Uncloaker>,
    hsts: RwLock<HashMap<String, HstsEntry>>,
    alt_svc: RwLock<HashMap<String, AltSvcEntry>>,
    https_upgrade: bool,
    hsts_enabled: bool,
    stats: PolicyStatsInner,
}

#[derive(Default)]
struct PolicyStatsInner {
    checked: AtomicU64,
    blocked: AtomicU64,
    neutered: AtomicU64,
    upgraded: AtomicU64,
    warned: AtomicU64,
}

/// Policy statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyStats {
    /// Requests checked.
    pub checked: u64,
    /// Requests blocked.
    pub blocked: u64,
    /// Requests neutered.
    pub neutered: u64,
    /// URLs upgraded to https.
    pub upgraded: u64,
    /// Safe-browsing warnings raised.
    pub warned: u64,
}

impl PolicyEngine {
    /// Build the engine from a network config and compiled filter set.
    pub fn new(
        config: &NetworkConfig,
        filters: Arc<FilterSet>,
        safe_browsing: Arc<SafeBrowsingDb>,
    ) -> PolicyEngine {
        PolicyEngine {
            filters,
            safe_browsing,
            uncloaker: RwLock::new(Uncloaker::with_defaults()),
            hsts: RwLock::new(HashMap::new()),
            alt_svc: RwLock::new(HashMap::new()),
            https_upgrade: config.https_upgrade,
            hsts_enabled: config.hsts,
            stats: PolicyStatsInner::default(),
        }
    }

    /// Check a request. `is_top_level_navigation` escalates Safe Browsing
    /// hits to warnings instead of silent blocks.
    pub fn check(&self, ctx: &RequestContext, is_top_level_navigation: bool) -> PolicyVerdict {
        self.stats.checked.fetch_add(1, Ordering::Relaxed);
        match self.filters.decide(ctx) {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                return PolicyVerdict::Block(BlockReason::NetworkFilter);
            }
            Decision::Neuter => {
                self.stats.neutered.fetch_add(1, Ordering::Relaxed);
                return PolicyVerdict::Neuter;
            }
            Decision::Allow => {}
        }

        if let Verdict::Threat = self.safe_browsing.check(ctx.url.as_str()) {
            self.stats.warned.fetch_add(1, Ordering::Relaxed);
            if is_top_level_navigation {
                return PolicyVerdict::Warn(BlockReason::SafeBrowsing);
            }
            self.stats.blocked.fetch_add(1, Ordering::Relaxed);
            return PolicyVerdict::Block(BlockReason::SafeBrowsing);
        }
        PolicyVerdict::Allow
    }

    /// Re-check a request against its *effective* host after CNAME
    /// uncloaking. Returns the verdict if the uncloaked host changes the
    /// decision.
    pub fn check_uncloaked(&self, ctx: &RequestContext, chain: &CnameChain) -> PolicyVerdict {
        let report = {
            let uncloaker = self.uncloaker.read().expect("uncloaker lock poisoned");
            uncloaker.inspect(chain)
        };
        let Some(report) = report else {
            return PolicyVerdict::Allow;
        };
        // The chain crossed into a tracker's apex domain: re-run the
        // filter decision with the cloaked host as first-party context.
        let mut ctx2 = RequestContext {
            url: ctx.url.clone(),
            source_host: ctx.source_host.clone(),
            source_base: ctx.source_base.clone(),
            resource_type: ctx.resource_type,
        };
        // Point the target at the tracker's effective host by rewriting
        // the URL host — the filter patterns match on URL host anyway.
        if let Ok(mut u) = Url::parse(ctx.url.as_str()) {
            if u.set_host(Some(report.tracker_domain.as_str())).is_ok() {
                ctx2.url = u;
            }
        }
        match self.filters.decide(&ctx2) {
            Decision::Block => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                PolicyVerdict::Block(BlockReason::CnameCloaked)
            }
            Decision::Neuter => {
                self.stats.neutered.fetch_add(1, Ordering::Relaxed);
                PolicyVerdict::Neuter
            }
            Decision::Allow => PolicyVerdict::Allow,
        }
    }

    /// Upgrade a URL if policy says so: HSTS hosts, and (for navigations)
    /// opportunistic https upgrade.
    ///
    /// Loopback (`localhost`, `127.0.0.1`, `::1`) is never upgraded — the
    /// same exemption Chrome/Firefox apply, since dev servers are plain
    /// HTTP by design.
    pub fn upgrade_url(&self, url: &Url, is_navigation: bool) -> Option<Url> {
        if url.scheme() != "http" {
            return None;
        }
        let host = url.host_str()?;
        if is_loopback(host) {
            return None;
        }
        if self.hsts_enabled && self.is_hsts(host) {
            let mut u = url.clone();
            let _ = u.set_scheme("https");
            self.stats.upgraded.fetch_add(1, Ordering::Relaxed);
            return Some(u);
        }
        if self.https_upgrade && is_navigation {
            let mut u = url.clone();
            let _ = u.set_scheme("https");
            // Keep the default port semantics: strip explicit :80.
            let _ = u.set_port(None);
            self.stats.upgraded.fetch_add(1, Ordering::Relaxed);
            return Some(u);
        }
        None
    }

    /// Is this host HSTS-known?
    pub fn is_hsts(&self, host: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hsts = self.hsts.read().expect("hsts lock poisoned");
        if let Some(e) = hsts.get(host) {
            return e.expires_unix > now;
        }
        // includeSubdomains: any parent entry covers this host.
        let mut parent = host;
        while let Some(dot) = parent.find('.') {
            parent = &parent[dot + 1..];
            if let Some(e) = hsts.get(parent) {
                return e.include_subdomains && e.expires_unix > now;
            }
        }
        false
    }

    /// Learn HSTS from a `Strict-Transport-Security` header value.
    pub fn observe_hsts(&self, host: &str, header_value: &str) {
        let Some(max_age) = parse_max_age(header_value) else {
            return;
        };
        let include_subdomains = header_value.to_ascii_lowercase().contains("includesubdomains");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.hsts.write().expect("hsts lock poisoned").insert(
            host.to_string(),
            HstsEntry { include_subdomains, expires_unix: now.saturating_add(max_age) },
        );
    }

    /// The Alt-Svc authority advertising `h3` for an origin, if fresh.
    pub fn alt_svc_h3(&self, origin: &str) -> Option<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let map = self.alt_svc.read().expect("alt-svc lock poisoned");
        map.get(origin).filter(|e| e.expires_unix > now).map(|e| e.authority.clone())
    }

    /// Learn Alt-Svc from a response header value for `origin`.
    pub fn observe_alt_svc(&self, origin: &str, header_value: &str) {
        let Some((authority, max_age)) = parse_alt_svc(header_value) else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.alt_svc.write().expect("alt-svc lock poisoned").insert(
            origin.to_string(),
            AltSvcEntry { authority, expires_unix: now.saturating_add(max_age.unwrap_or(3600)) },
        );
    }

    /// Statistics snapshot.
    pub fn stats(&self) -> PolicyStats {
        PolicyStats {
            checked: self.stats.checked.load(Ordering::Relaxed),
            blocked: self.stats.blocked.load(Ordering::Relaxed),
            neutered: self.stats.neutered.load(Ordering::Relaxed),
            upgraded: self.stats.upgraded.load(Ordering::Relaxed),
            warned: self.stats.warned.load(Ordering::Relaxed),
        }
    }
}

/// Is this host loopback (never upgraded, never HSTS'd)?
pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

/// Parse `max-age=N` from an STS header.
pub fn parse_max_age(value: &str) -> Option<u64> {
    for part in value.split(';') {
        let part = part.trim();
        if let Some(num) = part.to_ascii_lowercase().strip_prefix("max-age=") {
            if let Ok(secs) = num.trim().parse::<u64>() {
                return Some(secs);
            }
        }
    }
    None
}

/// Parse an Alt-Svc header into the h3 authority and max-age.
///
/// Grammar (simplified): `h3=":443"; ma=86400, h3-29=":443"; ma=86400`.
/// We prefer the plain `h3` entry and default `ma` to 3600.
pub fn parse_alt_svc(value: &str) -> Option<(String, Option<u64>)> {
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(';');
        let proto_part = parts.next()?.trim();
        let proto = proto_part.split('=').next()?.trim();
        if proto != "h3" {
            continue;
        }
        let authority = proto_part
            .split_once('=')
            .map(|(_, a)| a.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        // Authority is either `:port`, `host` (default port) or `host:port`.
        let authority = if authority.is_empty() { ":443".to_string() } else { authority };
        let mut max_age = None;
        for attr in parts {
            let attr = attr.trim();
            if let Some(v) = attr.strip_prefix("ma=") {
                max_age = v.trim().parse::<u64>().ok();
            }
        }
        return Some((authority, max_age));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_privacy::filter::FilterSet;
    use bw_privacy::safebrowsing::SafeBrowsingDb;
    use bw_privacy::{RequestContext, ResourceType};

    fn engine() -> PolicyEngine {
        let config = NetworkConfig::default();
        let set = FilterSet::compile([
            "||tracker.example^",
            "||ads.example^$script",
            "@@||good.example^$script",
        ])
        .expect("valid test filters");
        PolicyEngine::new(&config, Arc::new(set), Arc::new(SafeBrowsingDb::new(0, 0.01)))
    }

    fn ctx(url: &str, source: &str, ty: ResourceType) -> RequestContext {
        RequestContext {
            url: url::Url::parse(url).unwrap(),
            source_host: source.to_string(),
            source_base: base_of(source),
            resource_type: ty,
        }
    }

    fn base_of(host: &str) -> String {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            host.to_string()
        }
    }

    #[test]
    fn blocks_tracker() {
        let e = engine();
        let c = ctx("https://tracker.example/pixel?id=1", "site.example", ResourceType::IMAGE);
        assert_eq!(e.check(&c, false), PolicyVerdict::Block(BlockReason::NetworkFilter));
    }

    #[test]
    fn neuter_vs_block_respected() {
        let e = engine();
        // `||tracker.example^` without $empty → Block.
        let c = ctx("https://tracker.example/x.js", "site.example", ResourceType::SCRIPT);
        assert_eq!(e.check(&c, false), PolicyVerdict::Block(BlockReason::NetworkFilter));
    }

    #[test]
    fn allows_first_party() {
        let e = engine();
        let c = ctx("https://site.example/app.js", "site.example", ResourceType::SCRIPT);
        assert_eq!(e.check(&c, false), PolicyVerdict::Allow);
    }

    #[test]
    fn script_option_honored() {
        let e = engine();
        // ads.example blocked only for scripts; image allowed.
        let img = ctx("https://ads.example/banner.png", "site.example", ResourceType::IMAGE);
        assert_eq!(e.check(&img, false), PolicyVerdict::Allow);
        let js = ctx("https://ads.example/banner.js", "site.example", ResourceType::SCRIPT);
        assert_eq!(e.check(&js, false), PolicyVerdict::Block(BlockReason::NetworkFilter));
    }

    #[test]
    fn safe_browsing_warns_on_navigation() {
        let mut db = SafeBrowsingDb::new(64, 0.01);
        let url = "https://phish.example/login";
        let full: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(canonical(url).as_bytes());
            h.finalize().into()
        };
        db.add_full_hash(full);
        let config = NetworkConfig::default();
        let e =
            PolicyEngine::new(&config, Arc::new(FilterSet::from_filters(Vec::new())), Arc::new(db));
        let c = ctx(url, "mail.example", ResourceType::DOCUMENT);
        assert_eq!(e.check(&c, true), PolicyVerdict::Warn(BlockReason::SafeBrowsing));
        assert_eq!(e.check(&c, false), PolicyVerdict::Block(BlockReason::SafeBrowsing));
    }

    fn canonical(url: &str) -> String {
        bw_privacy::safebrowsing::canonicalize(url)
    }

    #[test]
    fn hsts_persists_and_expires() {
        let e = engine();
        assert!(!e.is_hsts("secure.example"));
        e.observe_hsts("secure.example", "max-age=3600; includeSubdomains");
        assert!(e.is_hsts("secure.example"));
        assert!(e.is_hsts("sub.secure.example"));
        assert!(!e.is_hsts("other.example"));
        // max-age=0 clears (expiry in the past).
        e.observe_hsts("secure.example", "max-age=0");
        assert!(!e.is_hsts("secure.example"));
    }

    #[test]
    fn https_upgrade_for_navigations_only() {
        let config = NetworkConfig { hsts: false, ..NetworkConfig::default() };
        let e = PolicyEngine::new(
            &config,
            Arc::new(FilterSet::from_filters(Vec::new())),
            Arc::new(SafeBrowsingDb::new(0, 0.01)),
        );
        let http = url::Url::parse("http://plain.example/page").unwrap();
        let up = e.upgrade_url(&http, true).unwrap();
        assert_eq!(up.scheme(), "https");
        assert_eq!(e.upgrade_url(&http, false), None); // subresources untouched
    }

    #[test]
    fn alt_svc_parsed_and_fresh() {
        let e = engine();
        e.observe_alt_svc("https://fast.example", "h3=\":443\"; ma=86400");
        assert_eq!(e.alt_svc_h3("https://fast.example").as_deref(), Some(":443"));
        assert_eq!(e.alt_svc_h3("https://other.example"), None);
        // Expired entry disappears.
        e.observe_alt_svc("https://fast.example", "h3=\":443\"; ma=0");
        assert_eq!(e.alt_svc_h3("https://fast.example"), None);
    }

    #[test]
    fn max_age_parsing() {
        assert_eq!(parse_max_age("max-age=31536000; includeSubdomains"), Some(31536000));
        assert_eq!(parse_max_age("includeSubdomains; MAX-AGE=99"), Some(99));
        assert_eq!(parse_max_age("no directive"), None);
    }

    #[test]
    fn alt_svc_value_parsing() {
        assert_eq!(parse_alt_svc("h3=\":443\"; ma=86400"), Some((":443".into(), Some(86400))));
        assert_eq!(parse_alt_svc("h3-29=\":443\""), None);
        assert_eq!(
            parse_alt_svc("h3=\"alt.example:8443\""),
            Some(("alt.example:8443".into(), None))
        );
    }
}
