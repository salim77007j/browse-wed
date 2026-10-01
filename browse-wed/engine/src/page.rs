//! The page pipeline: fetched bytes → DOM → cosmetic filtering.
//!
//! One place turns an HTTP body into everything the engine and UI know
//! about a page:
//!
//! * the arena DOM ([`bw_render::Document`]),
//! * the **title** (from `<title>` text),
//! * **cosmetic filtering** — which elements the privacy layer would hide,
//!   so the renderer skips painting them entirely (cheaper than painting
//!   then covering up),
//! * basic page statistics (nodes, elements, scripts, stylesheets) for
//!   the UI's per-page info panel.
//!
//! The [`DomView`] implementation adapts our DOM to the privacy crate's
//! generic selector engine — no copies, no re-parse.

#![forbid(unsafe_code)]

use bw_privacy::cosmetic::{CosmeticFilterSet, DomView};
use bw_render::{Document, NodeId};

/// Everything the engine keeps about a loaded page.
#[derive(Debug)]
pub struct PageData {
    /// The parsed DOM (arena; cheap to drop wholesale on suspension).
    pub doc: Document,
    /// Derived title (may be empty).
    pub title: String,
    /// Node ids the cosmetic filter set hides for this page's host.
    pub hidden: Vec<NodeId>,
    /// Basic node statistics.
    pub stats: PageStats,
}

/// Node statistics for the UI.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct PageStats {
    /// Total nodes in the tree.
    pub nodes: usize,
    /// Element nodes.
    pub elements: usize,
    /// `<script>` elements.
    pub scripts: usize,
    /// `<link rel=stylesheet>` / `<style>` elements.
    pub stylesheets: usize,
    /// Images.
    pub images: usize,
}

/// Newtype over a borrowed render DOM: implements the privacy crate's
/// [`DomView`] (the orphan rule forbids implementing it directly on
/// `bw_render::Document`).
pub struct PageDom<'a>(pub &'a Document);

impl DomView for PageDom<'_> {
    type NodeId = NodeId;

    fn tag(&self, id: Self::NodeId) -> Option<&str> {
        self.0.tag_of(id)
    }

    fn attr(&self, id: Self::NodeId, name: &str) -> Option<&str> {
        // Attribute names are lowercased at tokenization; match likewise.
        self.0.element(id)?.attr(name.to_ascii_lowercase().as_str())
    }

    fn attrs(&self, id: Self::NodeId) -> Vec<(String, String)> {
        self.0
            .element(id)
            .map(|e| e.attrs.clone())
            .unwrap_or_default()
    }

    fn parent(&self, id: Self::NodeId) -> Option<Self::NodeId> {
        let p = self.0.get(id).parent;
        (p != NodeId::NONE).then_some(p)
    }

    fn text(&self, id: Self::NodeId) -> &str {
        // Text nodes report their own data; elements report their first
        // direct text child (what `:contains()` needs for label matching).
        if let Some(t) = self.0.text_of(id) {
            return t;
        }
        for child in self.0.children(id) {
            if let Some(t) = self.0.text_of(child) {
                return t;
            }
        }
        ""
    }
}

/// Build the page view from an HTML body.
pub fn build_page(html: &str, host: &str, cosmetics: &CosmeticFilterSet) -> PageData {
    let doc = bw_render::parse_html(html);
    let title = doc.title().unwrap_or_default();
    let all_elements = doc.all_elements();
    let dom = PageDom(&doc);
    let hidden = cosmetics.hidden_nodes(host, &dom, &all_elements);
    let mut stats = PageStats {
        nodes: doc.len(),
        elements: all_elements.len(),
        ..PageStats::default()
    };
    for &n in &all_elements {
        match doc.tag_of(n).unwrap_or_default() {
            "script" => stats.scripts += 1,
            "style" => stats.stylesheets += 1,
            "img" | "picture" | "source" => stats.images += 1,
            "link"
                if doc
                    .element(n)
                    .and_then(|e| e.attr("rel"))
                    .is_some_and(|r| r.contains("stylesheet")) =>
            {
                stats.stylesheets += 1;
            }
            _ => {}
        }
    }
    PageData { doc, title, hidden, stats }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cosmetics() -> CosmeticFilterSet {
        CosmeticFilterSet::compile([
            "##.ad-banner",
            "##iframe[src*=\"doubleclick\"]",
            "example.com##.site-specific-ad",
        ])
    }

    const PAGE: &str = r#"
        <!doctype html>
        <html><head><title>Test Page</title>
        <link rel="stylesheet" href="/s.css">
        </head><body>
        <h1>Heading</h1>
        <div class="ad-banner">BUY THINGS</div>
        <div class="site-specific-ad">MORE THINGS</div>
        <p>Real content <a href="/x">link</a></p>
        <iframe src="https://ad.doubleclick.net/x"></iframe>
        <img src="/pic.png">
        <script src="/app.js"></script>
        </body></html>
    "#;

    #[test]
    fn page_builds_with_title_and_stats() {
        let page = build_page(PAGE, "neutral.example", &cosmetics());
        assert_eq!(page.title, "Test Page");
        assert_eq!(page.stats.scripts, 1);
        assert_eq!(page.stats.stylesheets, 1);
        assert_eq!(page.stats.images, 1);
        assert!(page.stats.elements >= 10);
    }

    #[test]
    fn generic_cosmetic_rules_hide_ads() {
        let page = build_page(PAGE, "anything.example", &cosmetics());
        let hidden_tags: Vec<&str> = page
            .hidden
            .iter()
            .filter_map(|&n| page.doc.tag_of(n))
            .collect();
        // .ad-banner div and the doubleclick iframe are hidden.
        assert!(page.hidden.len() >= 2, "hidden: {:?}", hidden_tags);
    }

    #[test]
    fn host_scoped_rules_only_apply_to_host() {
        let on_host = build_page(PAGE, "example.com", &cosmetics());
        let off_host = build_page(PAGE, "other.example", &cosmetics());
        assert!(on_host.hidden.len() > off_host.hidden.len());
    }

    #[test]
    fn domview_adapter_reads_dom() {
        let doc = bw_render::parse_html("<div id=\"d\" class=\"c\">x</div>");
        let node = doc
            .all_elements()
            .into_iter()
            .find(|&n| doc.tag_of(n) == Some("div"))
            .unwrap();
        let dom = PageDom(&doc);
        assert_eq!(DomView::attr(&dom, node, "id"), Some("d"));
        assert_eq!(DomView::attr(&dom, node, "ID"), Some("d"));
        assert_eq!(DomView::text(&dom, node), "x");
        assert!(DomView::parent(&dom, node).is_some());
        assert_eq!(DomView::attrs(&dom, node).len(), 2);
    }
}
