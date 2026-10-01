//! DOM → renderable page model.
//!
//! The engine hands the UI *page data, not pixels* (see `docs/API.md`).
//! This module is that data: a walk of the arena [`Document`] that turns
//! HTML structure into a flat, layout-ready block list with inline styled
//! runs — the shape a text-centric renderer wants.
//!
//! Fidelity rules:
//!
//! * typography comes from the real CSS cascade (UA sheet + `<style>` author
//!   CSS + inline `style` attributes) — font size, weight, italic, color,
//!   text alignment are the page's own, not our guesses;
//! * whitespace collapses exactly like HTML inline flow: a run of spaces
//!   becomes one space that carries the *preceding* run's style, paragraph
//!   edges are stripped, and spaces survive across element boundaries;
//! * `<pre>` keeps its bytes verbatim;
//! * cosmetic-hidden nodes (the privacy layer's `hidden` set) are skipped
//!   entirely — cheaper than painting then covering up;
//! * every `href`/`src` resolves against the document base URL;
//! * replaced elements the engine cannot render (iframe, video, input…)
//!   become honest placeholder cards carrying their real attributes —
//!   no fake content.
//!
//! Everything is `serde`-serializable so the same model crosses an IPC
//! boundary unchanged (`bw_api::Command::PageSnapshot`).

use crate::css::{cascade, ComputedStyle, Display, TextAlign};
use crate::dom::{Document, NodeId};
use serde::{Deserialize, Serialize};

/// Upper bound on extracted blocks (pathological-page guard).
const MAX_BLOCKS: usize = 20_000;
/// Upper bound on author CSS text fed to the cascade.
const MAX_AUTHOR_CSS: usize = 262_144;
/// Maximum walk depth (deeply nested markup guard).
const MAX_DEPTH: usize = 96;

/// A complete, renderable page.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PageModel {
    /// Document title.
    pub title: String,
    /// Resolved base URL (document URL or `<base href>`).
    pub base_url: String,
    /// Content language hint (`<html lang>`), BCP-47-ish, may be empty.
    pub lang: String,
    /// Page background (body cascade), RGBA.
    pub background: [u8; 4],
    /// Page default text color (body cascade), RGBA.
    pub foreground: [u8; 4],
    /// Flow content, document order.
    pub blocks: Vec<Block>,
}

/// One flow-level block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Block {
    /// Heading, level 1..=6.
    Heading {
        /// 1 for `<h1>` … 6 for `<h6>`.
        level: u8,
        /// Inline content.
        runs: Vec<Run>,
    },
    /// Paragraph. `soft` marks a `<br>`-split line (no bottom margin).
    Paragraph {
        /// Inline content.
        runs: Vec<Run>,
        /// Alignment from the cascade.
        align: Align,
        /// True when produced by a `<br>` split inside a paragraph.
        soft: bool,
    },
    /// One list item (flattened; nesting becomes `indent`).
    ListItem {
        /// `•`/`–` or `1.` style marker text.
        marker: String,
        /// Nesting depth, 0 = top level.
        indent: u8,
        /// Inline content.
        runs: Vec<Run>,
    },
    /// Block quotation.
    Quote {
        /// Inline content.
        runs: Vec<Run>,
    },
    /// Preformatted text (`pre`); whitespace preserved, mono style.
    Code {
        /// Verbatim lines (split on `\n`).
        lines: Vec<String>,
    },
    /// Horizontal rule.
    Rule,
    /// Image with its real attributes.
    Image {
        /// Resolved absolute URL (None when `src` is absent/broken).
        url: Option<String>,
        /// Alt text (may be empty).
        alt: String,
        /// `width` attribute when parseable.
        width: Option<u32>,
        /// `height` attribute when parseable.
        height: Option<u32>,
    },
    /// Table with header row separation.
    Table {
        /// Header cells (`<th>` / header row), if any.
        head: Vec<TableCell>,
        /// Body rows.
        rows: Vec<Vec<TableCell>>,
    },
    /// Replaced element the engine v0.1 cannot render (iframe, video,
    /// form control…) — an honest placeholder carrying real attributes.
    Widget {
        /// Element tag (`iframe`, `input`, `select`, `video`…).
        kind: String,
        /// Resolved `src`/`data` when present.
        url: Option<String>,
        /// Label: value/placeholder/alt text for controls.
        label: String,
    },
}

/// One table cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableCell {
    /// Inline content.
    pub runs: Vec<Run>,
    /// Header cell?
    pub header: bool,
    /// `colspan` (>= 1).
    pub colspan: u32,
}

/// Text alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Align {
    /// Start (left in LTR).
    #[default]
    Start,
    /// Center.
    Center,
    /// End (right in LTR).
    End,
}

/// One styled inline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    /// Text (whitespace already normalized outside `pre`).
    pub text: String,
    /// Style for the whole run.
    pub style: RunStyle,
}

/// Inline style for a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunStyle {
    /// Font size in px (page's own cascade).
    pub size: f32,
    /// Font weight 100..900.
    pub weight: u16,
    /// Italic.
    pub italic: bool,
    /// Monospace family.
    pub mono: bool,
    /// RGBA text color.
    pub color: [u8; 4],
    /// Underline.
    pub underline: bool,
    /// Strikethrough.
    pub strike: bool,
    /// Resolved link target.
    pub link: Option<String>,
    /// Superscript (`sup`).
    pub sup: bool,
}

impl Default for RunStyle {
    fn default() -> Self {
        RunStyle {
            size: 16.0,
            weight: 400,
            italic: false,
            mono: false,
            color: [0x1a, 0x1a, 0x1a, 0xff],
            underline: false,
            strike: false,
            link: None,
            sup: false,
        }
    }
}

/// Extract the renderable model from a parsed document.
///
/// `hidden` is the cosmetic-filter hidden set (subtrees skipped); `doc_url`
/// is the document's own URL used as the base for relative references.
pub fn extract_page_model(doc: &Document, hidden: &[NodeId], doc_url: &str) -> PageModel {
    let styles = cascade(doc, &[], &author_css_of(doc));
    let hidden: std::collections::HashSet<NodeId> = hidden.iter().copied().collect();
    let (base_url, lang) = base_and_lang(doc, doc_url);

    let body = find_body(doc);
    let root_style = styles
        .get(&body.unwrap_or_else(|| doc.root()))
        .cloned()
        .unwrap_or_else(ComputedStyle::root);
    let (background, foreground) = (root_style.background, root_style.color);

    let root_style_copy = root_style.clone();
    let mut ctx = Extractor {
        doc,
        styles: &styles,
        hidden: &hidden,
        base: &base_url,
        blocks: Vec::new(),
        runs: Vec::new(),
        pending_space: false,
        deco: Vec::new(),
        list_stack: Vec::new(),
        in_li: 0,
        after_br: false,
        root_style: root_style_copy,
    };
    ctx.walk_children(body.unwrap_or_else(|| doc_first_meaningful(doc)), 0);
    ctx.flush(TextAlign::Left, false);
    let blocks = ctx.blocks;

    let mut model = PageModel {
        title: doc.title().unwrap_or_default(),
        base_url,
        lang,
        background,
        foreground,
        blocks,
    };
    model
        .blocks
        .retain(|b| !matches!(b, Block::Paragraph { runs, .. } | Block::Heading { runs, .. } if runs.is_empty()));
    model
}

/// Inline decoration context (text-decoration propagates to inline
/// descendants exactly like browsers do).
#[derive(Clone)]
struct Deco {
    underline: bool,
    strike: bool,
    sup: bool,
    mono: bool,
    size_scale: f32,
    link: Option<String>,
}

impl Default for Deco {
    fn default() -> Self {
        Deco {
            underline: false,
            strike: false,
            sup: false,
            mono: false,
            size_scale: 1.0,
            link: None,
        }
    }
}

/// Inline-accumulation state during the walk.
struct Extractor<'a> {
    doc: &'a Document,
    styles: &'a std::collections::HashMap<NodeId, ComputedStyle>,
    hidden: &'a std::collections::HashSet<NodeId>,
    base: &'a str,
    blocks: Vec<Block>,
    runs: Vec<Run>,
    /// A whitespace run is pending (to be glued to the next word, carrying
    /// the *previous* run's style — browser inline-flow semantics).
    pending_space: bool,
    /// Innermost-first decoration contexts.
    deco: Vec<Deco>,
    /// (ordered, next index) per open list nesting level.
    list_stack: Vec<(bool, usize)>,
    /// Depth of open list items (suppresses paragraph flushing inside li).
    in_li: usize,
    /// A `<br>` just closed a line: the next flush is a continuation.
    after_br: bool,
    root_style: ComputedStyle,
}

impl<'a> Extractor<'a> {
    /// Style for a node (fallback: document root style).
    fn style_of(&self, id: NodeId) -> &ComputedStyle {
        self.styles.get(&id).unwrap_or(&self.root_style)
    }

    /// Resolve a possibly-relative URL against the base.
    fn resolve(&self, href: &str) -> Option<String> {
        if href.is_empty() || href.starts_with("javascript:") || href.starts_with('#') {
            return None;
        }
        let base = url::Url::parse(self.base).ok()?;
        base.join(href).ok().map(|u| u.to_string())
    }

    fn push_block(&mut self, b: Block) {
        if self.blocks.len() < MAX_BLOCKS {
            self.blocks.push(b);
        }
    }

    /// Innermost decoration context (or the default).
    fn deco(&self) -> Deco {
        self.deco.last().cloned().unwrap_or_default()
    }

    /// Feed one text node through the inline accumulator.
    fn text(&mut self, raw: &str, style: &ComputedStyle) {
        let deco = self.deco();
        for ch in raw.chars() {
            if ch.is_whitespace() {
                self.pending_space = true;
                continue;
            }
            let word_start = ch;
            let rs = self.run_style_for(style, &deco);
            if self.pending_space {
                if !self.runs.is_empty() {
                    // Space glues to the *previous* run (its style).
                    if let Some(last) = self.runs.last_mut() {
                        last.text.push(' ');
                    }
                }
                self.pending_space = false;
            }
            match self.runs.last_mut() {
                Some(last) if last.style == rs => last.text.push(word_start),
                _ => self.runs.push(Run { text: word_start.to_string(), style: rs }),
            }
        }
    }

    /// Cascade style + decoration context → final run style.
    fn run_style_for(&self, style: &ComputedStyle, deco: &Deco) -> RunStyle {
        let mono = deco.mono
            || style.font_family.iter().any(|f| {
                let f = f.to_ascii_lowercase();
                f.contains("mono") || f == "courier" || f == "consolas"
            });
        RunStyle {
            size: style.font_size * deco.size_scale,
            weight: style.font_weight as u16,
            italic: style.font_style_italic,
            mono,
            color: style.color,
            underline: deco.underline,
            strike: deco.strike,
            link: deco.link.clone(),
            sup: deco.sup,
        }
    }

    /// Flush pending inline runs as a paragraph-like block.
    fn flush(&mut self, align: TextAlign, soft: bool) {
        self.pending_space = false;
        let soft = soft || self.after_br;
        self.after_br = false;
        if self.in_li > 0 {
            // Inside a list item: inline content stays with the item.
            return;
        }
        if self.runs.is_empty() {
            return;
        }
        let runs = std::mem::take(&mut self.runs);
        if runs.iter().all(|r| r.text.is_empty()) {
            return;
        }
        self.push_block(Block::Paragraph { runs, align: map_align(align), soft });
    }

    /// Walk the children of `node` at depth `d`.
    fn walk_children(&mut self, node: NodeId, d: usize) {
        for child in self.doc.children(node) {
            self.walk(child, d);
        }
    }

    fn walk(&mut self, id: NodeId, d: usize) {
        if self.hidden.contains(&id) || d > MAX_DEPTH {
            return;
        }
        let Some(el) = self.doc.element(id) else {
            if let Some(t) = self.doc.text_of(id) {
                let style = self.style_of(id).clone();
                self.text(t, &style);
            }
            return;
        };

        let tag = el.tag.as_str();
        let style = self.style_of(id).clone();

        if style.display == Display::None {
            return;
        }

        match tag {
            // --- never rendered --------------------------------------------------
            "script" | "style" | "noscript" | "template" | "head" | "title" | "meta" | "link"
            | "base" | "svg" | "path" | "circle" | "rect" | "defs" | "symbol" | "use" | "track"
            | "datalist" | "option" | "optgroup" | "rp" | "rt" | "ruby" => {}
            "source" | "picture" => {
                if tag == "picture" {
                    self.walk_children(id, d + 1);
                }
            }
            "br" => {
                self.flush(style.text_align, false);
                self.after_br = true;
            }
            "hr" => {
                self.flush(style.text_align, false);
                self.push_block(Block::Rule);
            }
            "img" => {
                let src = el.attr("src").or_else(|| el.attr("data-src")).unwrap_or_default();
                self.push_block(Block::Image {
                    url: self.resolve(src),
                    alt: el.attr("alt").unwrap_or_default().to_string(),
                    width: el.attr("width").and_then(parse_px),
                    height: el.attr("height").and_then(parse_px),
                });
            }
            // --- replaced elements → honest placeholder cards -------------------
            "iframe" | "embed" | "object" | "video" | "audio" | "canvas" => {
                self.flush(style.text_align, false);
                let src = el.attr("src").or_else(|| el.attr("data")).map(str::to_string);
                self.push_block(Block::Widget {
                    kind: tag.to_string(),
                    url: src.and_then(|s| self.resolve(&s)),
                    label: el.attr("title").unwrap_or_default().to_string(),
                });
            }
            "input" | "select" | "textarea" | "button" => {
                self.flush(style.text_align, false);
                let label = el
                    .attr("value")
                    .or_else(|| el.attr("placeholder"))
                    .or_else(|| el.attr("aria-label"))
                    .unwrap_or_default()
                    .to_string();
                self.push_block(Block::Widget {
                    kind: if tag == "input" {
                        el.attr("type").unwrap_or("text").to_string()
                    } else {
                        tag.to_string()
                    },
                    url: None,
                    label,
                });
            }
            // --- list structure --------------------------------------------------
            "ul" | "ol" | "menu" => {
                self.flush(style.text_align, false);
                self.list_stack.push((tag == "ol", 0));
                self.walk_children(id, d + 1);
                self.flush(style.text_align, false);
                self.list_stack.pop();
                self.after_br = false;
            }
            "li" => {
                let (marker, indent) = self.list_marker();
                let saved_runs = std::mem::take(&mut self.runs);
                let saved_space = self.pending_space;
                let saved_br = self.after_br;
                self.pending_space = false;
                self.after_br = false;
                // Reserve this item's slot BEFORE walking so nested lists
                // land after their parent (document order).
                let slot = self.blocks.len();
                self.push_block(Block::ListItem {
                    marker: marker.clone(),
                    indent,
                    runs: Vec::new(),
                });
                let reserved = slot < self.blocks.len();
                self.in_li += 1;
                self.walk_children(id, d + 1);
                self.in_li -= 1;
                let runs = std::mem::replace(&mut self.runs, saved_runs);
                self.pending_space = saved_space;
                self.after_br = saved_br;
                if reserved {
                    let empty = runs.is_empty();
                    if let Some(Block::ListItem { runs: r, .. }) = self.blocks.get_mut(slot) {
                        *r = runs;
                    }
                    if empty {
                        self.blocks.remove(slot);
                    }
                } else if !runs.is_empty() {
                    self.push_block(Block::ListItem { marker: marker.clone(), indent, runs });
                }
                if let Some(top) = self.list_stack.last_mut() {
                    top.1 += 1;
                }
            }
            "dl" => {
                self.flush(style.text_align, false);
                self.walk_children(id, d + 1);
                self.flush(style.text_align, false);
            }
            "dt" | "dd" => {
                let saved_runs = std::mem::take(&mut self.runs);
                let saved_space = self.pending_space;
                self.pending_space = false;
                self.in_li += 1;
                self.walk_children(id, d + 1);
                self.in_li -= 1;
                let runs = std::mem::replace(&mut self.runs, saved_runs);
                self.pending_space = saved_space;
                if !runs.is_empty() {
                    self.push_block(Block::ListItem {
                        marker: if tag == "dt" { String::new() } else { "–".into() },
                        indent: u8::from(tag == "dd"),
                        runs,
                    });
                }
            }
            // --- code ------------------------------------------------------------
            "pre" => {
                self.flush(style.text_align, false);
                let text = self.doc.inner_text(id);
                let lines: Vec<String> =
                    text.trim_end_matches('\n').split('\n').map(str::to_string).collect();
                if !lines.is_empty() {
                    self.push_block(Block::Code { lines });
                }
            }
            // --- tables ----------------------------------------------------------
            "table" => {
                self.flush(style.text_align, false);
                self.extract_table(id);
            }
            // --- headings --------------------------------------------------------
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.flush(style.text_align, false);
                self.walk_children(id, d + 1);
                let runs = std::mem::take(&mut self.runs);
                if !runs.is_empty() {
                    self.push_block(Block::Heading { level: tag.as_bytes()[1] - b'0', runs });
                }
            }
            // --- quotations ------------------------------------------------------
            "blockquote" | "q" | "cite" => {
                self.flush(style.text_align, false);
                self.walk_children(id, d + 1);
                let runs = std::mem::take(&mut self.runs);
                if !runs.is_empty() {
                    self.push_block(Block::Quote { runs });
                }
            }
            // --- generic ---------------------------------------------------------
            _ => {
                let blockish = is_blockish(tag) || style.display == Display::Block;
                if blockish {
                    self.flush(style.text_align, false);
                    self.walk_children(id, d + 1);
                    self.flush(style.text_align, false);
                } else {
                    // Inline element: push a decoration context for children.
                    let mut deco = Deco::default();
                    if let Some(d) = self.deco.last() {
                        deco = d.clone();
                    }
                    if tag == "a" || tag == "u" {
                        deco.underline = true;
                    }
                    if tag == "a" {
                        deco.link = el.attr("href").and_then(|h| self.resolve(h));
                    }
                    if matches!(tag, "s" | "del" | "strike") {
                        deco.strike = true;
                    }
                    if tag == "sup" {
                        deco.sup = true;
                        deco.size_scale *= 0.7;
                    }
                    if tag == "sub" {
                        deco.size_scale *= 0.75;
                    }
                    if tag == "small" {
                        deco.size_scale *= 0.85;
                    }
                    if matches!(tag, "code" | "kbd" | "samp" | "tt" | "var") {
                        deco.mono = true;
                    }
                    self.deco.push(deco);
                    self.walk_children(id, d + 1);
                    self.deco.pop();
                }
            }
        }
    }

    /// Marker + indent for the innermost open list.
    fn list_marker(&mut self) -> (String, u8) {
        let indent = self.list_stack.len().saturating_sub(1) as u8;
        match self.list_stack.last() {
            Some((true, idx)) => (format!("{}.", idx + 1), indent),
            Some((false, _)) => (indent_marker(indent), indent),
            None => (String::new(), 0),
        }
    }

    fn extract_table(&mut self, table: NodeId) {
        let mut head: Vec<TableCell> = Vec::new();
        let mut rows: Vec<Vec<TableCell>> = Vec::new();
        for section in self.doc.children(table) {
            let stag = self.doc.tag_of(section).unwrap_or_default();
            if !matches!(stag, "thead" | "tbody" | "tfoot" | "tr") {
                continue;
            }
            if stag == "tr" {
                self.table_row(section, &mut head, &mut rows);
                continue;
            }
            for tr in self.doc.children(section) {
                if self.doc.tag_of(tr) == Some("tr") {
                    self.table_row(tr, &mut head, &mut rows);
                }
            }
        }
        if head.is_empty() {
            if let Some(first) = rows.first() {
                if first.iter().any(|c| c.header) {
                    head = rows.remove(0);
                }
            }
        }
        if !rows.is_empty() || !head.is_empty() {
            self.push_block(Block::Table { head, rows });
        }
    }

    fn table_row(&mut self, tr: NodeId, head: &mut Vec<TableCell>, rows: &mut Vec<Vec<TableCell>>) {
        let mut cells = Vec::new();
        for cell in self.doc.children(tr) {
            let ctag = self.doc.tag_of(cell).unwrap_or_default();
            if !matches!(ctag, "td" | "th") {
                continue;
            }
            let header = ctag == "th";
            let colspan = self
                .doc
                .element(cell)
                .and_then(|e| e.attr("colspan"))
                .and_then(|v| v.trim().parse::<u32>().ok())
                .map(|n| n.max(1))
                .unwrap_or(1);
            self.runs.clear();
            self.pending_space = false;
            self.walk_children(cell, MAX_DEPTH - 8);
            let runs = std::mem::take(&mut self.runs);
            cells.push(TableCell { runs, header, colspan });
        }
        if cells.is_empty() {
            return;
        }
        if cells.iter().all(|c| c.header) {
            head.extend(cells);
        } else {
            rows.push(cells);
        }
    }
}

fn indent_marker(indent: u8) -> String {
    match indent % 3 {
        0 => "•".into(),
        1 => "◦".into(),
        _ => "▪".into(),
    }
}

fn map_align(a: TextAlign) -> Align {
    match a {
        TextAlign::Left => Align::Start,
        TextAlign::Center => Align::Center,
        TextAlign::Right => Align::End,
    }
}

/// Elements we treat as paragraph-sealing containers even when the cascade
/// didn't flag them block (covers raw HTML without CSS).
fn is_blockish(tag: &str) -> bool {
    matches!(
        tag,
        "p" | "div"
            | "section"
            | "article"
            | "header"
            | "footer"
            | "nav"
            | "main"
            | "aside"
            | "figure"
            | "figcaption"
            | "form"
            | "fieldset"
            | "address"
            | "details"
            | "summary"
            | "table"
            | "tr"
            | "td"
            | "th"
            | "thead"
            | "tbody"
            | "tfoot"
            | "ul"
            | "ol"
            | "li"
            | "dl"
            | "dt"
            | "dd"
            | "center"
            | "dialog"
            | "hgroup"
    )
}

fn parse_px(v: &str) -> Option<u32> {
    v.trim().trim_end_matches("px").parse::<u32>().ok()
}

/// Collect in-document `<style>` CSS (capped).
fn author_css_of(doc: &Document) -> String {
    let mut css = String::new();
    for el in doc.all_elements() {
        if doc.tag_of(el) == Some("style") {
            for child in doc.children(el) {
                if let Some(t) = doc.text_of(child) {
                    css.push_str(t);
                    css.push('\n');
                    if css.len() >= MAX_AUTHOR_CSS {
                        return css;
                    }
                }
            }
        }
    }
    css
}

/// `<base href>` (resolved) and `<html lang>`.
fn base_and_lang(doc: &Document, doc_url: &str) -> (String, String) {
    let mut base = doc_url.to_string();
    let mut lang = String::new();
    for el in doc.all_elements() {
        match doc.tag_of(el) {
            Some("base") => {
                if let Some(href) = doc.element(el).and_then(|e| e.attr("href")) {
                    if let Some(joined) =
                        url::Url::parse(doc_url).ok().and_then(|u| u.join(href).ok())
                    {
                        base = joined.to_string();
                    }
                }
            }
            Some("html") => {
                if let Some(l) = doc.element(el).and_then(|e| e.attr("lang")) {
                    lang = l.to_string();
                }
            }
            _ => {}
        }
    }
    (base, lang)
}

fn find_body(doc: &Document) -> Option<NodeId> {
    doc.all_elements().into_iter().find(|&n| doc.tag_of(n) == Some("body"))
}

fn doc_first_meaningful(doc: &Document) -> NodeId {
    for el in doc.all_elements() {
        if matches!(doc.tag_of(el), Some("html" | "body")) {
            return el;
        }
    }
    doc.root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_html;

    fn model(html: &str) -> PageModel {
        let doc = parse_html(html);
        extract_page_model(&doc, &[], "https://example.com/page")
    }

    #[test]
    fn basic_paragraph_with_inline_styles() {
        let m = model("<html><body><p>Hello <b>bold</b> and <i>italic</i> world</p></body></html>");
        assert_eq!(m.blocks.len(), 1);
        match &m.blocks[0] {
            Block::Paragraph { runs, .. } => {
                let joined: String = runs.iter().map(|r| r.text.as_str()).collect();
                assert_eq!(joined, "Hello bold and italic world");
                assert!(runs.iter().any(|r| r.style.weight >= 700 && r.text.contains("bold")));
                assert!(runs.iter().any(|r| r.style.italic && r.text.contains("italic")));
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn links_resolve_against_base() {
        let m = model(r#"<a href="/docs/x">docs</a> <a href="https://other.example/y">y</a>"#);
        let links: Vec<Option<&String>> = match &m.blocks[0] {
            Block::Paragraph { runs, .. } => runs.iter().map(|r| r.style.link.as_ref()).collect(),
            other => panic!("expected paragraph, got {other:?}"),
        };
        assert_eq!(links[0].map(|s| s.as_str()), Some("https://example.com/docs/x"));
        assert_eq!(links[1].map(|s| s.as_str()), Some("https://other.example/y"));
    }

    #[test]
    fn headings_lists_and_rules() {
        let m = model(
            "<h1>Title</h1><ul><li>one</li><li>two</li></ul><ol><li>first</li></ol><hr><p>end</p>",
        );
        assert!(matches!(m.blocks[0], Block::Heading { level: 1, .. }));
        let markers: Vec<String> = m
            .blocks
            .iter()
            .filter_map(|b| match b {
                Block::ListItem { marker, .. } => Some(marker.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(markers, vec!["•", "•", "1."]);
        assert!(matches!(m.blocks[4], Block::Rule));
    }

    #[test]
    fn pre_preserves_whitespace() {
        let m = model("<pre>line one\n  indented two\n</pre>");
        match &m.blocks[0] {
            Block::Code { lines } => {
                assert_eq!(lines, &vec!["line one".to_string(), "  indented two".to_string()]);
            }
            other => panic!("expected code, got {other:?}"),
        }
    }

    #[test]
    fn table_extraction_with_header_row() {
        let m = model(
            "<table><tr><th>Name</th><th>Age</th></tr><tr><td>Ada</td><td>36</td></tr></table>",
        );
        match &m.blocks[0] {
            Block::Table { head, rows } => {
                assert_eq!(head.len(), 2);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0][0].runs[0].text, "Ada");
            }
            other => panic!("expected table, got {other:?}"),
        }
    }

    #[test]
    fn hidden_nodes_are_skipped() {
        let doc = parse_html("<div><p>visible</p><p class=\"ad\">ad text</p></div>");
        let hidden: Vec<NodeId> = doc
            .all_elements()
            .into_iter()
            .filter(|&n| doc.element(n).map(|e| e.classes().contains(&"ad")).unwrap_or(false))
            .collect();
        let m = extract_page_model(&doc, &hidden, "https://x.example/");
        let text = format!("{:?}", m.blocks);
        assert!(text.contains("visible"));
        assert!(!text.contains("ad text"));
    }

    #[test]
    fn author_css_drives_typography() {
        let m =
            model("<style>p.x { color: #ff0000; font-size: 24px; }</style><p class=\"x\">red</p>");
        match &m.blocks[0] {
            Block::Paragraph { runs, .. } => {
                assert_eq!(runs[0].style.color, [0xff, 0, 0, 0xff]);
                assert!((runs[0].style.size - 24.0).abs() < 0.1);
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn images_carry_attributes() {
        let m = model(r#"<img src="/pic.png" alt="A pic" width="320" height="200">"#);
        match &m.blocks[0] {
            Block::Image { url, alt, width, height } => {
                assert_eq!(url.as_deref(), Some("https://example.com/pic.png"));
                assert_eq!(alt, "A pic");
                assert_eq!(*width, Some(320));
                assert_eq!(*height, Some(200));
            }
            other => panic!("expected image, got {other:?}"),
        }
    }

    #[test]
    fn widgets_are_honest_placeholders() {
        let m = model(r#"<iframe src="https://embed.example/v"></iframe><input value="query">"#);
        assert!(matches!(&m.blocks[0], Block::Widget { kind, url, .. } if kind == "iframe"
            && url.as_deref() == Some("https://embed.example/v")));
        assert!(
            matches!(&m.blocks[1], Block::Widget { kind, label, .. } if kind == "text" && label == "query")
        );
    }

    #[test]
    fn br_splits_soft_paragraphs() {
        let m = model("<p>line one<br>line two</p>");
        assert_eq!(m.blocks.len(), 2);
        match (&m.blocks[0], &m.blocks[1]) {
            (Block::Paragraph { soft, .. }, Block::Paragraph { soft: s2, .. }) => {
                assert!(!soft);
                assert!(*s2);
            }
            other => panic!("expected two paragraphs, got {other:?}"),
        }
    }

    #[test]
    fn base_href_overrides_resolution() {
        let m = model(
            "<head><base href=\"https://cdn.example/sub/\"></head><a href=\"file.html\">x</a>",
        );
        assert_eq!(m.base_url, "https://cdn.example/sub/");
        match &m.blocks[0] {
            Block::Paragraph { runs, .. } => {
                assert_eq!(
                    runs[0].style.link.as_deref(),
                    Some("https://cdn.example/sub/file.html")
                );
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn blockquote_and_nested_list_indent() {
        let m =
            model("<blockquote>quoted words</blockquote><ul><li>a<ul><li>b</li></ul></li></ul>");
        assert!(matches!(m.blocks[0], Block::Quote { .. }));
        match &m.blocks[1] {
            Block::ListItem { indent, .. } => assert_eq!(*indent, 0),
            o => panic!("{o:?}"),
        }
        match &m.blocks[2] {
            Block::ListItem { indent, .. } => assert_eq!(*indent, 1),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn whitespace_collapses_across_nodes() {
        let m = model("<p>Hello   <span>  world  </span>  again</p>");
        match &m.blocks[0] {
            Block::Paragraph { runs, .. } => {
                let joined: String = runs.iter().map(|r| r.text.as_str()).collect();
                assert_eq!(joined, "Hello world again");
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn space_takes_preceding_runs_style() {
        let m = model("<p><b>bold</b> <i>ital</i></p>");
        match &m.blocks[0] {
            Block::Paragraph { runs, .. } => {
                // The inter-word space belongs to the bold run.
                assert!(runs[0].text.ends_with(' ') && runs[0].style.weight >= 700);
                assert_eq!(runs[1].text, "ital");
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn link_decorates_nested_runs() {
        let m = model(r#"<a href="/x">outer <b>bold-in-link</b></a>"#);
        match &m.blocks[0] {
            Block::Paragraph { runs, .. } => {
                assert!(runs.iter().all(|r| r.style.link.is_some() && r.style.underline));
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn empty_paragraphs_are_dropped() {
        let m = model("<p></p><p>   </p><p>real</p>");
        let paras = m.blocks.iter().filter(|b| matches!(b, Block::Paragraph { .. })).count();
        assert_eq!(paras, 1);
    }

    #[test]
    fn model_serializes_for_ipc() {
        let m = model("<h1>t</h1><p>body <a href=\"/x\">link</a></p>");
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"blocks\""));
        let back: PageModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blocks.len(), m.blocks.len());
    }

    #[test]
    fn pathological_depth_is_bounded() {
        let deep = "<div>".repeat(80) + "text" + &"</div>".repeat(80);
        let m = model(&deep);
        assert!(m.blocks.len() <= MAX_BLOCKS);
        assert!(m.blocks.iter().any(
            |b| matches!(b, Block::Paragraph { runs, .. } if runs.iter().any(|r| r.text == "text"))
        ));
    }
}
