//! Network filter list engine (uBlock Origin / EasyList syntax subset).
//!
//! Supported rule grammar (the subset that covers > 95% of EasyList /
//! EasyPrivacy lines in practice):
//!
//! ```text
//! rule      := pattern options?
//! pattern   := "||" host_anchor rest?
//!            | "|" url_prefix rest?
//!            | plain_substring
//! options   := "$" opt ("," opt)*
//! opt       := "third-party" | "~third-party" | "first-party"
//!            | "script" | "image" | ... | "~" type
//!            | "domain=" host ( "|" host )*
//!            | "empty" | "important"
//! exception := "@@" rule
//! ```
//!
//! Matching precedence (highest wins):
//! 1. `$important` blocking rules
//! 2. `@@` exceptions
//! 3. generic blocking rules
//!
//! The compiled [`FilterSet`] uses three dispatch structures so the request
//! hot path never degrades to a linear scan over substring rules:
//!
//! * one **Aho-Corasick automaton** shared by *all* substring patterns;
//! * a **host bucket map** for `||hostname` rules, consulted once per
//!   domain-suffix of the request host (O(labels), not O(rules));
//! * a small **always-scan list** for true regex / catch-all rules.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{Decision, RequestContext, ResourceType};

/// Error type for filter parsing.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    /// The rule could not be understood.
    #[error("unparsable rule: {0}")]
    BadRule(String),
}

/// One compiled network filter.
#[derive(Debug, Clone)]
pub struct NetworkFilter {
    /// Original rule text (for diagnostics and list round-tripping).
    pub raw: Arc<str>,
    /// Pattern semantics.
    pub pattern: Pattern,
    /// Resource type mask that must intersect the request's type.
    pub types: ResourceType,
    /// Party restriction.
    pub party: Party,
    /// Permitted / forbidden source domains (`domain=` option).
    pub domains: DomainRestriction,
    /// `@@` exception rule.
    pub exception: bool,
    /// `$important` — beats exceptions.
    pub important: bool,
    /// `$empty` — respond with an empty body instead of hard-blocking.
    pub empty: bool,
}

/// How the pattern is matched against the URL.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Plain substring, matched case-insensitively (Aho-Corasick automaton).
    Substring(String),
    /// Domain anchor `||example.org` — host is `example.org` or a subdomain.
    Hostname(String),
    /// Domain anchor with path remainder `||example.org/ads/`, compiled to a
    /// regex anchored at the domain boundary.
    HostPath(String, regex::Regex),
    /// Free-standing regex rule.
    Regex(regex::Regex),
    /// Matches every URL (`*`).
    Any,
}

/// Party restriction from `$third-party` / `$first-party`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    /// No restriction.
    Any,
    /// Only third-party requests.
    Third,
    /// Only first-party requests.
    First,
}

/// `domain=` option: lists of domains that permit or forbid the rule.
#[derive(Debug, Clone, Default)]
pub struct DomainRestriction {
    /// Rule applies only when the source base domain is in this list.
    pub include: Vec<String>,
    /// Rule never applies when the source base domain is in this list.
    pub exclude: Vec<String>,
}

impl DomainRestriction {
    fn matches(&self, ctx: &RequestContext) -> bool {
        let included = self.include.is_empty()
            || self.include.iter().any(|d| d.eq_ignore_ascii_case(&ctx.source_base));
        let excluded = self.exclude.iter().any(|d| d.eq_ignore_ascii_case(&ctx.source_base));
        included && !excluded
    }
}

impl NetworkFilter {
    /// Parse one rule. Returns `Ok(None)` for comments, blank lines and
    /// cosmetic rules (which belong to [`crate::cosmetic`]).
    pub fn parse(line: &str) -> Result<Option<NetworkFilter>, FilterError> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            return Ok(None);
        }
        if line.contains("##") || line.contains("#@#") || line.contains("#?#") {
            return Ok(None);
        }
        let (body, options) = match line.split_once('$') {
            Some((b, o)) => (b, Some(o)),
            None => (line, None),
        };
        let exception = body.starts_with("@@");
        let body = body.strip_prefix("@@").unwrap_or(body);

        let mut pattern = Pattern::Any;

        if let Some(rest) = body.strip_prefix("||") {
            let host: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
                .collect();
            if host.is_empty() {
                return Err(FilterError::BadRule(line.to_string()));
            }
            let host = host.to_ascii_lowercase();
            let tail = &rest[host.len()..];
            pattern = if tail.is_empty() {
                Pattern::Hostname(host)
            } else {
                let re = compile_host_path(&host, tail)?;
                Pattern::HostPath(host, re)
            };
        } else if let Some(rest) = body.strip_prefix('|') {
            if rest != "*" {
                pattern = if rest.contains('*') || rest.contains('^') {
                    Pattern::Regex(compile_wildcard(rest, true)?)
                } else {
                    Pattern::Substring(rest.to_ascii_lowercase())
                };
            }
        } else if body == "*" {
            // keep Pattern::Any
        } else if body.contains('*') || body.contains('^') {
            pattern = Pattern::Regex(compile_wildcard(body, false)?);
        } else {
            pattern = Pattern::Substring(body.to_ascii_lowercase());
        }

        let mut f = NetworkFilter {
            raw: Arc::from(line),
            pattern,
            types: ResourceType::ANY,
            party: Party::Any,
            domains: DomainRestriction::default(),
            exception,
            important: false,
            empty: false,
        };

        if let Some(opts) = options {
            for token in opts.split(',') {
                f.apply_option(token.trim())?;
            }
        }
        Ok(Some(f))
    }

    fn apply_option(&mut self, token: &str) -> Result<(), FilterError> {
        let lower = token.to_ascii_lowercase();
        match lower.as_str() {
            "important" => self.important = true,
            "empty" | "redirect=noop" | "redirect=none" => self.empty = true,
            "third-party" | "3p" => self.party = Party::Third,
            "first-party" | "1p" => self.party = Party::First,
            _ => {
                if let Some(rest) = lower.strip_prefix("domain=") {
                    for d in rest.split('|') {
                        if let Some(excluded) = d.strip_prefix('~') {
                            self.domains.exclude.push(excluded.to_string());
                        } else {
                            self.domains.include.push(d.to_string());
                        }
                    }
                    return Ok(());
                }
                if let Some((ty, neg)) = ResourceType::from_token(&lower) {
                    self.types = if self.types == ResourceType::ANY && !neg {
                        ty
                    } else if neg {
                        ResourceType(self.types.0 & !ty.0)
                    } else {
                        self.types.union(ty)
                    };
                    return Ok(());
                }
                // Unknown options are tolerated: EasyList carries options we
                // do not honour (`popup`, `webrtc`, `ghide`...). Ignoring
                // keeps the list loadable; the rule still applies generically.
            }
        }
        Ok(())
    }

    /// Full option-gated match against a request context.
    fn matches(&self, ctx: &RequestContext, url_lower: &str) -> bool {
        if self.types != ResourceType::ANY && !self.types.contains(ctx.resource_type) {
            return false;
        }
        match self.party {
            Party::Any => {}
            Party::Third if !ctx.is_third_party() => return false,
            Party::First if ctx.is_third_party() => return false,
            _ => {}
        }
        if !self.domains.matches(ctx) {
            return false;
        }
        match &self.pattern {
            Pattern::Any => true,
            Pattern::Substring(s) => url_lower.contains(s.as_str()),
            Pattern::Regex(re) => re.is_match(&ctx.url.as_str()),
            // Hostname / HostPath are gated by the bucket lookup in
            // FilterSet::decide; when reached directly we verify the tail.
            Pattern::Hostname(h) => host_matches(ctx.target_host(), h),
            Pattern::HostPath(h, re) => host_matches(ctx.target_host(), h) && re.is_match(&ctx.url.as_str()),
        }
    }
}

/// True when `host` is exactly `rule_host` or a subdomain of it.
fn host_matches(host: &str, rule_host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == rule_host
        || (host.len() > rule_host.len()
            && host.ends_with(rule_host)
            && host.as_bytes()[host.len() - rule_host.len() - 1] == b'.')
}

/// Compile `||host/path^query` into a regex anchored at the domain boundary.
fn compile_host_path(host: &str, tail: &str) -> Result<regex::Regex, FilterError> {
    let mut out = String::from("^(?:[a-z]+://)?(?:[a-z0-9-]+\\.)*");
    out.push_str(&regex::escape(host));
    push_escaped_tail(&mut out, tail);
    regex::Regex::new(&out).map_err(|_| FilterError::BadRule(format!("||{host}{tail}")))
}

/// Compile a wildcard pattern (`*`, `^`, leading `|`) into a regex.
fn compile_wildcard(pat: &str, anchored_start: bool) -> Result<regex::Regex, FilterError> {
    let mut out = String::new();
    if anchored_start {
        out.push('^');
    }
    push_escaped_tail(&mut out, pat);
    regex::Regex::new(&out).map_err(|_| FilterError::BadRule(pat.to_string()))
}

fn push_escaped_tail(out: &mut String, tail: &str) {
    for ch in tail.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '^' => out.push_str("[^a-zA-Z0-9_.%-]"),
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
}

/// A compiled set of network filters, ready for matching.
pub struct FilterSet {
    filters: Vec<Arc<NetworkFilter>>,
    /// Shared automaton over every substring pattern (blocking + exception).
    substring_index: aho_corasick::AhoCorasick,
    substring_map: HashMap<aho_corasick::PatternID, Vec<usize>>,
    /// `||host` and `||host/path` rules bucketed by host.
    host_buckets: HashMap<String, Vec<usize>>,
    /// Regex / Any rules always consulted.
    scan_filters: Vec<usize>,
}

impl FilterSet {
    /// Compile a list of rules (one rule per line).
    pub fn compile(
        rules: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<FilterSet, FilterError> {
        let mut filters = Vec::new();
        for line in rules {
            if let Some(f) = NetworkFilter::parse(line.as_ref())? {
                filters.push(Arc::new(f));
            }
        }
        Ok(Self::from_filters(filters))
    }

    /// Build from already-parsed filters.
    pub fn from_filters(filters: Vec<Arc<NetworkFilter>>) -> FilterSet {
        use aho_corasick::AhoCorasickBuilder;

        let mut substring_pats: Vec<String> = Vec::new();
        let mut substring_map: HashMap<aho_corasick::PatternID, Vec<usize>> = HashMap::new();
        let mut host_buckets: HashMap<String, Vec<usize>> = HashMap::new();
        let mut scan_filters = Vec::new();

        for (i, f) in filters.iter().enumerate() {
            match &f.pattern {
                Pattern::Substring(s) => {
                    let pid =
                        aho_corasick::PatternID::new(substring_pats.len()).expect("usize-bounded");
                    substring_pats.push(s.clone());
                    substring_map.entry(pid).or_default().push(i);
                }
                Pattern::Hostname(h) | Pattern::HostPath(h, _) => {
                    host_buckets.entry(h.clone()).or_default().push(i);
                }
                Pattern::Regex(_) | Pattern::Any => scan_filters.push(i),
            }
        }

        let substring_index = AhoCorasickBuilder::new()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(substring_pats)
            .expect("patterns are plain strings");

        FilterSet {
            filters,
            substring_index,
            substring_map,
            host_buckets,
            scan_filters,
        }
    }

    /// Number of loaded network rules.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// True when no rules are loaded.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Iterate all loaded filters (used by list diffing and diagnostics).
    pub fn iter(&self) -> impl Iterator<Item = &NetworkFilter> {
        self.filters.iter().map(|f| f.as_ref())
    }

    /// Decide the fate of a request.
    pub fn decide(&self, ctx: &RequestContext) -> Decision {
        let mut candidates: Vec<usize> = Vec::with_capacity(16);

        // 1) One automaton scan covers ALL substring patterns.
        for m in self.substring_index.find_iter(ctx.url.as_str()) {
            if let Some(ids) = self.substring_map.get(&m.pattern()) {
                candidates.extend(ids.iter().copied());
            }
        }

        // 2) Host buckets: consult one entry per domain suffix.
        let host = ctx.target_host().to_ascii_lowercase();
        if !host.is_empty() {
            let mut start = 0;
            loop {
                if let Some(bucket) = self.host_buckets.get(&host[start..]) {
                    candidates.extend(bucket.iter().copied());
                }
                match host[start..].find('.') {
                    Some(dot) => start += dot + 1,
                    None => break,
                }
            }
        }

        // 3) Regex / Any rules.
        for &i in &self.scan_filters {
            let f = &self.filters[i];
            let hit = match &f.pattern {
                Pattern::Any => true,
                Pattern::Regex(re) => re.is_match(ctx.url.as_str()),
                _ => false,
            };
            if hit {
                candidates.push(i);
            }
        }

        // Nothing matched at all — allow without touching per-rule gates.
        if candidates.is_empty() {
            return Decision::Allow;
        }

        let url_lower = ctx.url.as_str().to_ascii_lowercase();
        let matched = |i: usize| self.filters[i].matches(ctx, &url_lower);

        let empty_body = candidates.iter().any(|&i| self.filters[i].empty && matched(i));
        if candidates
            .iter()
            .any(|&i| self.filters[i].important && !self.filters[i].exception && matched(i))
        {
            return if empty_body { Decision::Neuter } else { Decision::Block };
        }
        if candidates.iter().any(|&i| self.filters[i].exception && matched(i)) {
            return Decision::Allow;
        }
        if candidates.iter().any(|&i| !self.filters[i].exception && matched(i)) {
            if empty_body {
                Decision::Neuter
            } else {
                Decision::Block
            }
        } else {
            Decision::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(url: &str, source: &str, ty: ResourceType) -> RequestContext {
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

    fn rules(list: &[&str]) -> FilterSet {
        FilterSet::compile(list.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn hostname_anchor_blocks_subdomains() {
        let fs = rules(&["||doubleclick.net^"]);
        assert_eq!(
            fs.decide(&make_ctx(
                "https://ad.doubleclick.net/dd?sz=1",
                "example.com",
                ResourceType::SCRIPT
            )),
            Decision::Block
        );
        assert_eq!(
            fs.decide(&make_ctx(
                "https://doubleclick.net/x",
                "example.com",
                ResourceType::SCRIPT
            )),
            Decision::Block
        );
        // not a subdomain boundary
        assert_eq!(
            fs.decide(&make_ctx(
                "https://notdoubleclick.net.example.org/x",
                "example.com",
                ResourceType::SCRIPT
            )),
            Decision::Allow
        );
    }

    #[test]
    fn host_path_rules_constrain_path() {
        let fs = rules(&["||cdn.example.com/ads/"]);
        assert_eq!(
            fs.decide(&make_ctx(
                "https://cdn.example.com/ads/banner.png",
                "example.com",
                ResourceType::IMAGE
            )),
            Decision::Block
        );
        assert_eq!(
            fs.decide(&make_ctx(
                "https://cdn.example.com/img/cat.png",
                "example.com",
                ResourceType::IMAGE
            )),
            Decision::Allow
        );
    }

    #[test]
    fn exceptions_beat_blocks() {
        let fs = rules(&["||ads.example.com^", "@@||ads.example.com^$script"]);
        assert_eq!(
            fs.decide(&make_ctx(
                "https://ads.example.com/t.js",
                "example.com",
                ResourceType::SCRIPT
            )),
            Decision::Allow
        );
        assert_eq!(
            fs.decide(&make_ctx(
                "https://ads.example.com/banner.png",
                "example.com",
                ResourceType::IMAGE
            )),
            Decision::Block
        );
    }

    #[test]
    fn important_beats_exceptions() {
        let fs = rules(&["||tracker.io^$important", "@@||tracker.io^"]);
        assert_eq!(
            fs.decide(&make_ctx("https://tracker.io/p", "x.com", ResourceType::XHR)),
            Decision::Block
        );
    }

    #[test]
    fn third_party_option() {
        let fs = rules(&["/analytics.js$third-party"]);
        assert_eq!(
            fs.decide(&make_ctx(
                "https://cdn.other.com/analytics.js",
                "example.com",
                ResourceType::SCRIPT
            )),
            Decision::Block
        );
        assert_eq!(
            fs.decide(&make_ctx(
                "https://example.com/analytics.js",
                "example.com",
                ResourceType::SCRIPT
            )),
            Decision::Allow
        );
    }

    #[test]
    fn domain_restriction() {
        let fs = rules(&["||adnet.io^$domain=news.com|blog.org"]);
        assert_eq!(
            fs.decide(&make_ctx("https://adnet.io/a", "news.com", ResourceType::IMAGE)),
            Decision::Block
        );
        assert_eq!(
            fs.decide(&make_ctx("https://adnet.io/a", "random.net", ResourceType::IMAGE)),
            Decision::Allow
        );
    }

    #[test]
    fn type_restriction() {
        let fs = rules(&["||imgtrack.net^$image"]);
        assert_eq!(
            fs.decide(&make_ctx("https://imgtrack.net/1.gif", "a.com", ResourceType::IMAGE)),
            Decision::Block
        );
        assert_eq!(
            fs.decide(&make_ctx("https://imgtrack.net/1.js", "a.com", ResourceType::SCRIPT)),
            Decision::Allow
        );
    }

    #[test]
    fn negated_type_restriction() {
        let fs = rules(&["||mixedmedia.net^$~script"]);
        assert_eq!(
            fs.decide(&make_ctx("https://mixedmedia.net/a.js", "a.com", ResourceType::SCRIPT)),
            Decision::Allow
        );
        assert_eq!(
            fs.decide(&make_ctx("https://mixedmedia.net/a.mp4", "a.com", ResourceType::MEDIA)),
            Decision::Block
        );
    }

    #[test]
    fn wildcard_regex_rules() {
        let fs = rules(&["||cnt.example.net^*/count*&id="]);
        assert_eq!(
            fs.decide(&make_ctx(
                "https://cnt.example.net/track/x/count?site=1&id=9",
                "first.com",
                ResourceType::XHR
            )),
            Decision::Block
        );
    }

    #[test]
    fn empty_neuters() {
        let fs = rules(&["||emptyads.io^$empty"]);
        assert_eq!(
            fs.decide(&make_ctx("https://emptyads.io/e.js", "a.com", ResourceType::SCRIPT)),
            Decision::Neuter
        );
    }

    #[test]
    fn unknown_options_tolerated() {
        let fs = rules(&["||popupads.net^$popup,ghide"]);
        assert_eq!(
            fs.decide(&make_ctx("https://popupads.net/x", "a.com", ResourceType::XHR)),
            Decision::Block
        );
    }

    #[test]
    fn comments_and_cosmetic_lines_skipped() {
        let fs = rules(&[
            "! comment",
            "example.com##.ad-banner",
            "",
            "||blockme.io^",
        ]);
        assert_eq!(fs.len(), 1);
    }
}
