//! CNAME uncloaking protection.
//!
//! Attack: trackers hide first-party-looking hostnames behind benign CNAME
//! records (`metrics.shop.com CNAME xyz123.tracker.io`). Because the request
//! hostname is first-party, hostname-based blocking fails.
//!
//! Defence: at DNS-resolution time the engine walks the CNAME chain and
//! checks whether it crosses into a known tracker's apex domain. The
//! network layer supplies the chain ([`crate::cname`::CnameChain`]); this
//! module classifies it against a tracker-domain set.
//!
//! Bundled defaults are the well-known CNAME-cloaking endpoints published in
//! AdGuard's cname-cloaking list and NextDNS analytics lists.

use std::collections::HashSet;

/// A CNAME chain as observed by the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameChain {
    /// The hostname the page requested (leftmost).
    pub original: String,
    /// The CNAME records observed in resolution order (already lowercase).
    pub hops: Vec<String>,
}

impl CnameChain {
    /// Build from an original name plus hop list.
    pub fn new(original: impl Into<String>, hops: impl IntoIterator<Item = impl Into<String>>) -> Self {
        CnameChain {
            original: original.into().to_ascii_lowercase(),
            hops: hops.into_iter().map(|h| h.into().to_ascii_lowercase()).collect(),
        }
    }

    /// The final target (last hop, or the original when there are no hops).
    pub fn effective_host(&self) -> &str {
        self.hops.last().unwrap_or(&self.original)
    }

    /// True when resolution crosses registrable-domain boundaries at all.
    pub fn crosses_boundary(&self) -> bool {
        let orig_base = base_domain(&self.original);
        self.hops.iter().any(|h| base_domain(h) != orig_base)
    }
}

/// Known CNAME-cloaking endpoints (tracker apex domains).
///
/// Kept intentionally small + curated: the engine also supports loading the
/// full AdGuard list at runtime.
pub const DEFAULT_TRACKER_SUFFIXES: &[&str] = &[
    "adform.net",
    "adservice.google.com",
    "analytics.google.com",
    "atdns.net",
    "at-internet.com",
    "chartbeat.com",
    "clickiocdn.com",
    "criteo.com",
    "criteo.net",
    "dnsalias.com",
    "doubleclick.net",
    "edigitalsurvey.com",
    "etracker.com",
    "exponential.com",
    "factor73.com",
    "feedadsltd.com",
    "footprintdns.com",
    "google-analytics.com",
    "hostedsitemap.com",
    "iadsdk.apple.com",
    "keakr.com",
    "kingsoft.net",
    "liadm.com",
    "lightboxdns.com",
    "mathtag.com",
    "mdnsservice.com",
    "metric.gstatic.com",
    "mxpnl.com",
    "nuviz.com",
    "ogcommerce.net",
    "omtrdc.net",
    "p00lmarketing.com",
    "perfops.net",
    "pndsn.com",
    "polyfill.io",
    "qbox.cloud",
    "quantcount.com",
    "ravenjs.com",
    "recounsel.com",
    "redshell.io",
    "rimpqad.com",
    "sail-hub.com",
    "salesiq.net",
    "shb-cdn.com",
    "short-switch.com",
    "simpleanalyticscdn.com",
    "sitescout.com",
    "spdns.org",
    "storygize.net",
    "swarmfeed.com",
    "taboola.com",
    "tagsrvcs.com",
    "tiqcdn.com",
    "trakken.de",
    "turn.com",
    "uraniumledger.com",
    "vscdns.com",
    "w55c.net",
    "webtrekk.net",
    "yieldmo.com",
];

/// The uncloaking classifier.
#[derive(Default)]
pub struct Uncloaker {
    tracker_domains: HashSet<String>,
}

/// Result of uncloaking analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncloakReport {
    /// Hostname the page originally requested.
    pub requested: String,
    /// Tracker domain the chain crossed into.
    pub tracker_domain: String,
}

impl Uncloaker {
    /// Build with the bundled default tracker set.
    pub fn with_defaults() -> Uncloaker {
        let mut u = Uncloaker::default();
        for d in DEFAULT_TRACKER_SUFFIXES {
            u.tracker_domains.insert(d.to_string());
        }
        u
    }

    /// Add tracker domains at runtime (full AdGuard list, user additions...).
    pub fn add_domains(&mut self, domains: impl IntoIterator<Item = impl Into<String>>) {
        for d in domains {
            self.tracker_domains.insert(d.into().to_ascii_lowercase());
        }
    }

    /// Number of known tracker domains.
    pub fn len(&self) -> usize {
        self.tracker_domains.len()
    }

    /// True when no trackers are loaded.
    pub fn is_empty(&self) -> bool {
        self.tracker_domains.is_empty()
    }

    /// Analyse a CNAME chain. Returns a report when the chain crosses into a
    /// known tracker domain.
    pub fn inspect(&self, chain: &CnameChain) -> Option<UncloakReport> {
        for hop in &chain.hops {
            let base = base_domain(hop);
            if self.tracker_domains.contains(base) {
                return Some(UncloakReport {
                    requested: chain.original.clone(),
                    tracker_domain: base.to_string(),
                });
            }
        }
        None
    }

    /// True when the given hostname is itself a known tracker domain.
    pub fn is_tracker(&self, host: &str) -> bool {
        self.tracker_domains.contains(base_domain(host))
    }
}

/// Common two-label public suffixes we care about (co.uk, com.au, ...).
const TWO_PART_TLDS: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp", "co.kr", "com.au",
    "net.au", "org.au", "co.nz", "com.br", "com.mx", "com.cn", "com.tw", "co.in", "co.za",
];

fn is_two_part_tld(last_two: &str) -> bool {
    TWO_PART_TLDS.contains(&last_two)
}

/// Extract the registrable-ish domain: the last two labels, or three when the
/// last two form a known two-part public suffix (`shop.co.uk` stays whole).
/// Zero-allocation: the returned slice borrows from `host`.
pub fn base_domain(host: &str) -> &str {
    let host = host.trim_end_matches('.');
    let mut dots = host.rmatch_indices('.');
    if dots.next().is_none() {
        return host; // single label
    }
    let Some((i2, _)) = dots.next() else { return host }; // two labels
    let last_two = &host[i2 + 1..];
    if is_two_part_tld(last_two) {
        match dots.next() {
            Some((i3, _)) => &host[i3 + 1..],
            None => host,
        }
    } else {
        &host[i2 + 1..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_classic_cloaking() {
        let u = Uncloaker::with_defaults();
        let chain = CnameChain::new("metrics.shop.com", ["xyz123.p01.liadm.com"]);
        let report = u.inspect(&chain).expect("must detect liadm cloaking");
        assert_eq!(report.tracker_domain, "liadm.com");
        assert_eq!(report.requested, "metrics.shop.com");
    }

    #[test]
    fn clean_chains_pass() {
        let u = Uncloaker::with_defaults();
        let chain = CnameChain::new("cdn.shop.com", ["abc.cdn-provider.net"]);
        assert!(u.inspect(&chain).is_none());
        let no_hops = CnameChain::new("static.shop.com", Vec::<String>::new());
        assert!(u.inspect(&no_hops).is_none());
    }

    #[test]
    fn mid_chain_trackers_detected() {
        let u = Uncloaker::with_defaults();
        let chain = CnameChain::new(
            "e.example.com",
            ["alias.some-cdn.com", "tracker.criteo.net"],
        );
        assert_eq!(u.inspect(&chain).map(|r| r.tracker_domain), Some("criteo.net".into()));
    }

    #[test]
    fn boundary_detection() {
        let chain = CnameChain::new("a.example.com", ["b.other.net"]);
        assert!(chain.crosses_boundary());
        let same = CnameChain::new("a.example.com", ["b.example.com"]);
        assert!(!same.crosses_boundary());
    }

    #[test]
    fn two_part_tlds() {
        assert_eq!(base_domain("shop.co.uk"), "shop.co.uk");
        assert_eq!(base_domain("cdn.shop.co.uk"), "shop.co.uk");
        assert_eq!(base_domain("tracker.io"), "tracker.io");
        assert_eq!(base_domain("a.b.tracker.io"), "tracker.io");
    }
}
