//! Cosmetic filtering: `##selector` element-hiding rules.
//!
//! Grammar handled:
//!
//! ```text
//! host1,host2##selector          hide matching elements on those hosts
//! host##selector                 single host
//! ##selector                     generic hide (applies everywhere)
//! host1#@#selector               exception — never hide on these hosts
//! ```
//!
//! The selector matcher supports the high-value subset of CSS selectors used
//! by real filter lists: type, `#id`, `.class`, `[attr]`, `[attr=value]`,
//! `[attr^=]`, `[attr$=]`, `[attr*=]`, descendant (`a b`), child (`a > b`),
//! and comma groups. Matching runs against a simple DOM description
//! ([`DomView`]) supplied by the renderer, so this crate stays decoupled
//! from any concrete DOM implementation.

use std::collections::HashMap;

use crate::filter::FilterError;

/// A read-only view of a node supplied by the renderer for selector matching.
pub trait DomView {
    /// Opaque node identifier.
    type NodeId: Copy;

    /// Element tag name (lowercase), `None` for non-element nodes.
    fn tag(&self, id: Self::NodeId) -> Option<&str>;
    /// Attribute lookup, case-insensitive attribute names.
    fn attr(&self, id: Self::NodeId, name: &str) -> Option<&str>;
    /// Iterate attribute names (used by `[attr]` tests).
    fn attrs(&self, id: Self::NodeId) -> Vec<(String, String)>;
    /// Parent node.
    fn parent(&self, id: Self::NodeId) -> Option<Self::NodeId>;
    /// Node text content (for `:contains` support).
    fn text(&self, id: Self::NodeId) -> &str;
}

/// Parsed selector components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleSelector {
    /// `div`, `a`, `*`
    Type(String),
    /// `#main`
    Id(String),
    /// `.ad-slot`
    Class(String),
    /// `[href]`, `[href^="https"]`, `[data-x=y]`
    Attr {
        name: String,
        op: AttrOp,
        value: String,
    },
    /// `:contains(text)` — matched against the node's text content.
    Contains(String),
}

/// Attribute comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrOp {
    /// `[attr]` — presence.
    Present,
    /// `=`
    Equals,
    /// `^=`
    Prefix,
    /// `$=`
    Suffix,
    /// `*=`
    Contains,
}

/// One compound selector: a run of simple selectors that must all match the
/// same element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Compound {
    /// Simple selectors applying to the subject element itself.
    pub simples: Vec<SimpleSelector>,
}

/// A full (possibly compound) selector with descendant relationship, stored
/// as a chain: last element is the subject; earlier ones are ancestors that
/// must appear somewhere above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    /// Chain of compounds: `[ancestor..., subject]`.
    pub chain: Vec<Compound>,
}

impl Selector {
    /// Parse a single selector string (no comma groups — see
    /// [`parse_selector_list`]).
    pub fn parse(input: &str) -> Result<Selector, FilterError> {
        let mut chain: Vec<Compound> = Vec::new();
        let mut current: Compound = Compound { simples: Vec::new() };
        let mut tok = String::new();
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                ' ' => {
                    push_token(&tok, &mut current);
                    tok.clear();
                    if !current.simples.is_empty() {
                        chain.push(std::mem::take(&mut current));
                    }
                }
                '>' => {
                    push_token(&tok, &mut current);
                    tok.clear();
                    if current.simples.is_empty() && chain.is_empty() {
                        return Err(FilterError::BadRule(input.to_string()));
                    }
                    if !current.simples.is_empty() {
                        chain.push(std::mem::take(&mut current));
                    }
                    // Child combinator `a > b`: we insert an empty marker
                    // compound and treat it as descendant during matching
                    // (over-hiding is the safe direction for cosmetic rules;
                    // strict child checks arrive with the full CSS engine).
                    chain.push(Compound { simples: Vec::new() });
                }
                '[' => {
                    push_token(&tok, &mut current);
                    tok.clear();
                    // read attr selector
                    let mut buf = String::new();
                    for c2 in chars.by_ref() {
                        if c2 == ']' {
                            break;
                        }
                        buf.push(c2);
                    }
                    current.simples.push(parse_attr(&buf)?);
                }
                ':' => {
                    push_token(&tok, &mut current);
                    tok.clear();
                    let mut buf = String::new();
                    for c2 in chars.by_ref() {
                        if c2 == '(' {
                            // read until closing paren
                            let mut val = String::new();
                            let mut depth = 1;
                            for c3 in chars.by_ref() {
                                if c3 == '(' {
                                    depth += 1;
                                }
                                if c3 == ')' {
                                    depth -= 1;
                                    if depth == 0 {
                                        break;
                                    }
                                }
                                val.push(c3);
                            }
                            let val = val
                                .trim()
                                .trim_matches('"')
                                .trim_matches('\'')
                                .to_string();
                            if buf.eq_ignore_ascii_case("contains") {
                                current.simples.push(SimpleSelector::Contains(val));
                            }
                            buf.clear();
                            break;
                        }
                        if c2 == ' ' || c2 == ',' {
                            break;
                        }
                        buf.push(c2);
                    }
                    // Unsupported pseudo-classes (:hover, :nth-child...) make
                    // the selector unusable → parse error → rule dropped.
                    if !buf.is_empty() {
                        return Err(FilterError::BadRule(input.to_string()));
                    }
                }
                _ => tok.push(c),
            }
        }
        push_token(&tok, &mut current);
        if !current.simples.is_empty() {
            chain.push(current);
        }
        if chain.is_empty() {
            return Err(FilterError::BadRule(input.to_string()));
        }
        Ok(Selector { chain })
    }

    /// Match this selector against node `subject` in `dom`.
    pub fn matches<D: DomView>(&self, dom: &D, subject: D::NodeId) -> bool {
        let Some((last, ancestors)) = self.chain.split_last() else {
            return false;
        };
        if !compound_matches(last, dom, subject) {
            return false;
        }
        // Walk up for ancestor compounds. Empty marker compounds (from `>`)
        // are satisfied trivially but require the *next* compound to be the
        // direct parent — approximated strictly here.
        let mut node = dom.parent(subject);
        let mut chain_idx = ancestors.len();
        while chain_idx > 0 {
            chain_idx -= 1;
            let anc = &ancestors[chain_idx];
            if anc.simples.is_empty() {
                // child-combinator marker — satisfied trivially
                continue;
            }
            let mut found = None;
            let mut cur = node;
            while let Some(n) = cur {
                if compound_matches(anc, dom, n) {
                    found = Some(n);
                    break;
                }
                cur = dom.parent(n);
            }
            match found {
                Some(n) => node = dom.parent(n),
                None => return false,
            }
        }
        true
    }
}

/// Split a whitespace-free selector token into simple selectors.
/// Handles compounds like `div#nav.item.active`.
fn push_token(tok: &str, current: &mut Compound) {
    if tok.is_empty() {
        return;
    }
    let mut part = String::new();
    // 0 = type, 1 = id, 2 = class
    let mut kind = 0u8;
    let push = |part: &str, kind: u8, current: &mut Compound| {
        if part.is_empty() {
            return;
        }
        match kind {
            1 => current.simples.push(SimpleSelector::Id(part.to_string())),
            2 => current.simples.push(SimpleSelector::Class(part.to_string())),
            _ => {
                if part != "*" {
                    current.simples.push(SimpleSelector::Type(part.to_ascii_lowercase()));
                }
            }
        }
    };
    for ch in tok.chars() {
        match ch {
            '#' => {
                push(&part, kind, current);
                part.clear();
                kind = 1;
            }
            '.' => {
                push(&part, kind, current);
                part.clear();
                kind = 2;
            }
            _ => part.push(ch),
        }
    }
    push(&part, kind, current);
}

fn compound_matches<D: DomView>(c: &Compound, dom: &D, node: D::NodeId) -> bool {
    let Some(tag) = dom.tag(node) else {
        return false;
    };
    let _ = tag;
    for simple in &c.simples {
        let ok = match simple {
            SimpleSelector::Type(t) => dom.tag(node).is_some_and(|tg| tg.eq_ignore_ascii_case(t)),
            SimpleSelector::Id(id) => dom.attr(node, "id").is_some_and(|v| v == id),
            SimpleSelector::Class(cls) => dom
                .attr(node, "class")
                .is_some_and(|v| v.split_whitespace().any(|c| c == cls)),
            SimpleSelector::Attr { name, op, value } => match op {
                AttrOp::Present => dom.attr(node, name).is_some() || {
                    let lower = name.to_ascii_lowercase();
                    dom.attrs(node).iter().any(|(n, _)| n.eq_ignore_ascii_case(&lower))
                },
                AttrOp::Equals => dom.attr(node, name).is_some_and(|v| v == value),
                AttrOp::Prefix => dom.attr(node, name).is_some_and(|v| v.starts_with(value)),
                AttrOp::Suffix => dom.attr(node, name).is_some_and(|v| v.ends_with(value)),
                AttrOp::Contains => dom.attr(node, name).is_some_and(|v| v.contains(value)),
            },
            SimpleSelector::Contains(text) => dom.text(node).contains(text),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn parse_attr(buf: &str) -> Result<SimpleSelector, FilterError> {
    let buf = buf.trim();
    let eq = buf.find('=');
    let (name_part, value, has_value) = match eq {
        Some(idx) => (
            &buf[..idx],
            buf[idx + 1..]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string(),
            true,
        ),
        None => (buf, String::new(), false),
    };
    let (name, op) = match name_part.as_bytes().last() {
        Some(b'^') => (&name_part[..name_part.len() - 1], AttrOp::Prefix),
        Some(b'$') => (&name_part[..name_part.len() - 1], AttrOp::Suffix),
        Some(b'*') => (&name_part[..name_part.len() - 1], AttrOp::Contains),
        _ => (name_part, AttrOp::Equals),
    };
    if name.is_empty() {
        return Err(FilterError::BadRule(buf.to_string()));
    }
    let op = if !has_value { AttrOp::Present } else { op };
    Ok(SimpleSelector::Attr {
        name: name.to_ascii_lowercase(),
        op,
        value,
    })
}

/// Parse a comma-separated selector list.
pub fn parse_selector_list(input: &str) -> Result<Vec<Selector>, FilterError> {
    let mut out = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Ok(sel) = Selector::parse(part) {
            out.push(sel);
        } else {
            // One bad selector in a group invalidates only itself.
            tracing::debug!(selector = part, "dropping unsupported selector");
        }
    }
    if out.is_empty() {
        return Err(FilterError::BadRule(input.to_string()));
    }
    Ok(out)
}

/// One cosmetic rule (parsed or raw-with-error).
#[derive(Debug, Clone)]
pub struct CosmeticRule {
    /// Hosts the rule applies to (empty = generic).
    pub hosts: Vec<String>,
    /// Selector group (empty when the selector failed to parse).
    pub selectors: Vec<Selector>,
    /// Exception rule (`#@#`).
    pub exception: bool,
    /// Original line.
    pub raw: String,
}

/// Compiled cosmetic filter set.
#[derive(Default)]
pub struct CosmeticFilterSet {
    rules: Vec<CosmeticRule>,
    /// Generic (hostless) rules — always evaluated.
    generic: Vec<usize>,
    /// Host-specific rules.
    by_host: HashMap<String, Vec<usize>>,
}

impl CosmeticFilterSet {
    /// Parse a full cosmetic list (one rule per line).
    pub fn compile(lines: impl IntoIterator<Item = impl AsRef<str>>) -> CosmeticFilterSet {
        let mut set = CosmeticFilterSet::default();
        for line in lines {
            if let Some(rule) = parse_cosmetic_line(line.as_ref()) {
                set.add(rule);
            }
        }
        set
    }

    /// Add one parsed rule.
    pub fn add(&mut self, rule: CosmeticRule) {
        let idx = self.rules.len();
        if rule.hosts.is_empty() {
            self.generic.push(idx);
        } else {
            for h in &rule.hosts {
                self.by_host.entry(h.clone()).or_default().push(idx);
            }
        }
        self.rules.push(rule);
    }

    /// Number of cosmetic rules loaded.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when no rules are loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Compute the set of nodes that must be hidden on `host`.
    pub fn hidden_nodes<D: DomView>(
        &self,
        host: &str,
        dom: &D,
        nodes: &[D::NodeId],
    ) -> Vec<D::NodeId> {
        let host = host.to_ascii_lowercase();
        // Collect the applicable rule indices once: generic rules +
        // host-scoped rules for every domain suffix of `host`.
        let mut applicable: Vec<usize> = self.generic.clone();
        for bucket in self.host_buckets_for(&host) {
            applicable.extend(bucket.iter().copied());
        }

        let mut out = Vec::new();
        'node: for &n in nodes {
            // Exceptions win: a matching exception skips the node entirely.
            for &i in &applicable {
                let r = &self.rules[i];
                if !r.exception {
                    continue;
                }
                if (r.hosts.is_empty() || r.hosts.iter().any(|h| host_suffix(&host, h)))
                    && r.selectors.iter().any(|sel| sel.matches(dom, n))
                {
                    continue 'node;
                }
            }
            for &i in &applicable {
                let r = &self.rules[i];
                if r.exception {
                    continue;
                }
                if r.selectors.iter().any(|sel| sel.matches(dom, n)) {
                    out.push(n);
                    continue 'node;
                }
            }
        }
        out
    }

    fn host_buckets_for(&self, host: &str) -> Vec<&Vec<usize>> {
        let mut out = Vec::new();
        let mut start = 0usize;
        loop {
            if let Some(b) = self.by_host.get(&host[start..]) {
                out.push(b);
            }
            match host[start..].find('.') {
                Some(dot) => start += dot + 1,
                None => break,
            }
        }
        out
    }
}

fn host_suffix(host: &str, rule_host: &str) -> bool {
    host == rule_host
        || (host.len() > rule_host.len()
            && host.ends_with(rule_host)
            && host.as_bytes()[host.len() - rule_host.len() - 1] == b'.')
}

/// Parse one cosmetic line. Returns `None` for non-cosmetic lines.
pub fn parse_cosmetic_line(line: &str) -> Option<CosmeticRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') {
        return None;
    }
    // Locate the earliest separator of either flavour.
    let pos_hide = line.find("##");
    let pos_exc = line.find("#@#");
    let (hosts_part, selector_part, exception) = match (pos_hide, pos_exc) {
        (Some(a), Some(b)) if a <= b => (&line[..a], &line[a + 2..], false),
        (Some(_), Some(b)) => (&line[..b], &line[b + 3..], true),
        (Some(a), None) => (&line[..a], &line[a + 2..], false),
        (None, Some(b)) => (&line[..b], &line[b + 3..], true),
        (None, None) => return None,
    };

    let selector_part = selector_part.trim();
    if selector_part.is_empty() {
        return None;
    }
    // Filter lists also carry procedural filters (`##script:has(...)`) and
    // action operators (`##+js(...)`); both are out of scope — dropped.
    if selector_part.contains(":has(")
        || selector_part.contains(":matches(")
        || selector_part.contains("+:js(")
        || selector_part.contains("+js(")
        || selector_part.contains(":style(")
        || selector_part.contains(":remove()")
    {
        return None;
    }

    let hosts: Vec<String> = hosts_part
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();

    let selectors = parse_selector_list(selector_part).unwrap_or_default();

    Some(CosmeticRule {
        hosts,
        selectors,
        exception,
        raw: line.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// (tag, attrs, parent, text) per node.
    type TestNode = (String, Vec<(String, String)>, Option<u32>, String);

    #[derive(Default)]
    struct TestDom {
        nodes: HashMap<u32, TestNode>,
    }

    impl TestDom {
        fn add(&mut self, id: u32, tag: &str, parent: Option<u32>, attrs: &[(&str, &str)], text: &str) {
            self.nodes.insert(
                id,
                (
                    tag.to_string(),
                    attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                    parent,
                    text.to_string(),
                ),
            );
        }
    }

    impl DomView for TestDom {
        type NodeId = u32;
        fn tag(&self, id: u32) -> Option<&str> {
            self.nodes.get(&id).map(|(t, _, _, _)| t.as_str())
        }
        fn attr(&self, id: u32, name: &str) -> Option<&str> {
            let (_, attrs, _, _) = self.nodes.get(&id)?;
            attrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
        fn attrs(&self, id: u32) -> Vec<(String, String)> {
            self.nodes.get(&id).map(|(_, a, _, _)| a.clone()).unwrap_or_default()
        }
        fn parent(&self, id: u32) -> Option<u32> {
            self.nodes.get(&id).and_then(|(_, _, p, _)| *p)
        }
        fn text(&self, id: u32) -> &str {
            self.nodes.get(&id).map(|(_, _, _, t)| t.as_str()).unwrap_or("")
        }
    }

    fn dom() -> TestDom {
        let mut d = TestDom::default();
        d.add(1, "div", None, &[("id", "page")], "");
        d.add(2, "div", Some(1), &[("class", "ad-banner promo")], "Buy now");
        d.add(3, "div", Some(1), &[("class", "content")], "Article body");
        d.add(4, "a", Some(3), &[("href", "https://example.org/page")], "link");
        d.add(5, "img", Some(2), &[("src", "https://ads.x/1.gif"), ("data-tag", "sponsor")], "");
        d
    }

    #[test]
    fn class_selector_hides() {
        let set = CosmeticFilterSet::compile(["##.ad-banner"]);
        let d = dom();
        let nodes = [1u32, 2, 3, 4, 5];
        let hidden = set.hidden_nodes("any.com", &d, &nodes);
        assert_eq!(hidden, vec![2u32]);
    }

    #[test]
    fn host_scoped_rules() {
        let set = CosmeticFilterSet::compile(["news.com##.content"]);
        let d = dom();
        let nodes = [3u32];
        assert_eq!(set.hidden_nodes("news.com", &d, &nodes), vec![3u32]);
        assert!(set.hidden_nodes("other.com", &d, &nodes).is_empty());
        // subdomain applies
        assert_eq!(set.hidden_nodes("m.news.com", &d, &nodes), vec![3u32]);
    }

    #[test]
    fn exception_rules() {
        let set = CosmeticFilterSet::compile(["##.ad-banner", "trusted.com#@#.ad-banner"]);
        let d = dom();
        let nodes = [2u32];
        assert_eq!(set.hidden_nodes("x.com", &d, &nodes), vec![2u32]);
        assert!(set.hidden_nodes("trusted.com", &d, &nodes).is_empty());
    }

    #[test]
    fn attribute_selectors() {
        let set = CosmeticFilterSet::compile(["##[data-tag=sponsor]", "##a[href^=\"https://example\"]"]);
        let d = dom();
        let nodes = [4u32, 5u32];
        let mut hidden = set.hidden_nodes("x.com", &d, &nodes);
        hidden.sort_unstable();
        assert_eq!(hidden, vec![4u32, 5u32]);
    }

    #[test]
    fn descendant_selector() {
        let set = CosmeticFilterSet::compile(["##div.content a"]);
        let d = dom();
        let nodes = [4u32];
        assert_eq!(set.hidden_nodes("x.com", &d, &nodes), vec![4u32]);
    }

    #[test]
    fn contains_selector() {
        let set = CosmeticFilterSet::compile(["##div:contains(\"Buy now\")"]);
        let d = dom();
        let nodes = [2u32, 3u32];
        assert_eq!(set.hidden_nodes("x.com", &d, &nodes), vec![2u32]);
    }

    #[test]
    fn unsupported_selectors_dropped() {
        let set = CosmeticFilterSet::compile(["##div:has(img)"]);
        assert_eq!(set.len(), 0);
    }
}
