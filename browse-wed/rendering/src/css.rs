//! CSS engine: parsing, cascade, inheritance and computed styles.
//!
//! Supported selector grammar: type, `#id`, `.class`, compound (`div.a#b`),
//! attribute (`[x]`, `[x=v]`, `[x^=]`, `[x$=]`, `[x*=]`), descendant (`a b`)
//! and comma groups — the same subset the cosmetic engine supports, which
//! keeps one mental model across the codebase.
//!
//! Supported properties (the layout/paint pipeline's input):
//! `display`, `color`, `background-color`, `width`, `height`, `min-height`,
//! `margin` (+sides), `padding` (+sides), `border-width` (+sides),
//! `border-color`, `font-family`, `font-size`, `font-weight`, `font-style`,
//! `text-align`, `line-height`, `flex-direction`, `flex-wrap`,
//! `justify-content`, `align-items`, `flex-grow`, `flex-shrink`,
//! `flex-basis`, `gap`, `overflow`.

use std::collections::HashMap;

use crate::dom::{Document, ElementData, NodeId};

/// Color in RGBA8.
pub type Color = [u8; 4];

/// Display property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Display {
    /// Normal block flow.
    Block,
    /// Inline content.
    Inline,
    /// Flexbox container.
    Flex,
    /// Not rendered.
    None,
}

/// A parsed CSS declaration value (loosely typed).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Color literal.
    Color(Color),
    /// Length in px (CSS px units).
    Px(f32),
    /// Percentage (relative to containing block).
    Percent(f32),
    /// Keyword value.
    Keyword(String),
    /// Comma-separated list (font-family, margin shorthand elements).
    List(Vec<Value>),
}

impl Value {
    /// Resolve to pixels against a containing-block size.
    pub fn to_px(&self, containing: f32) -> f32 {
        match self {
            Value::Px(v) => *v,
            Value::Percent(p) => containing * p / 100.0,
            _ => 0.0,
        }
    }
}

/// Selector simple-part.
#[derive(Debug, Clone, PartialEq)]
enum Simple {
    Type(String),
    Id(String),
    Class(String),
    Attr { name: String, op: AttrOp, value: String },
}

/// Attribute operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttrOp {
    Present,
    Equals,
    Prefix,
    Suffix,
    Contains,
}

/// A single selector (compound chain: descendant relations).
#[derive(Debug, Clone, PartialEq)]
struct Selector {
    /// Chain of compounds: `[ancestor..., subject]`.
    chain: Vec<Vec<Simple>>,
}

/// Specificity tuple (inline styles count as highest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Specificity {
    /// id selectors
    pub ids: u32,
    /// class/attr selectors
    pub classes: u32,
    /// type selectors
    pub types: u32,
}

impl Default for Specificity {
    fn default() -> Self {
        Specificity { ids: 0, classes: 0, types: 0 }
    }
}

impl Specificity {
    fn bump(&mut self, s: &Simple) {
        match s {
            Simple::Id(_) => self.ids += 1,
            Simple::Class(_) | Simple::Attr { .. } => self.classes += 1,
            Simple::Type(_) => self.types += 1,
        }
    }
}

/// One parsed rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Selector group (any match applies).
    selectors: Vec<Selector>,
    /// Declarations.
    pub decls: Vec<(String, Vec<Value>)>,
    /// Max specificity across its selectors.
    pub specificity: Specificity,
    /// Source order (later wins at equal specificity).
    pub order: u32,
}

/// A parsed stylesheet.
#[derive(Debug, Clone, Default)]
pub struct Stylesheet {
    /// Rules in source order.
    pub rules: Vec<Rule>,
}

/// Computed style for one element (all layout inputs resolved).
#[derive(Debug, Clone, PartialEq)]
pub struct ComputedStyle {
    /// display
    pub display: Display,
    /// color
    pub color: Color,
    /// background-color
    pub background: Color,
    /// width (None = auto)
    pub width: Option<Value>,
    /// height (None = auto)
    pub height: Option<Value>,
    /// min-height
    pub min_height: Value,
    /// margins [top right bottom left]
    pub margin: [Value; 4],
    /// paddings [top right bottom left]
    pub padding: [Value; 4],
    /// border widths [top right bottom left]
    pub border: [f32; 4],
    /// border color
    pub border_color: Color,
    /// font families (first match wins)
    pub font_family: Vec<String>,
    /// font size in px
    pub font_size: f32,
    /// font weight (100..900)
    pub font_weight: u32,
    /// italic
    pub font_style_italic: bool,
    /// text alignment
    pub text_align: TextAlign,
    /// line height multiplier (None = font default)
    pub line_height: Option<f32>,
    /// flex properties
    pub flex: FlexStyle,
    /// overflow hidden flag
    pub overflow_hidden: bool,
}

/// Flex container/item properties.
#[derive(Debug, Clone, PartialEq)]
pub struct FlexStyle {
    /// direction: row/column
    pub direction: FlexDirection,
    /// justify-content
    pub justify: JustifyContent,
    /// align-items
    pub align: AlignItems,
    /// flex-grow
    pub grow: f32,
    /// flex-shrink
    pub shrink: f32,
    /// flex-basis
    pub basis: Option<Value>,
}

/// Flex direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlexDirection {
    /// Horizontal.
    Row,
    /// Vertical.
    Column,
}

/// Main-axis distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JustifyContent {
    /// start
    Start,
    /// center
    Center,
    /// end
    End,
    /// space-between
    Between,
}

/// Cross-axis alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignItems {
    /// stretch (default)
    Stretch,
    /// start
    Start,
    /// center
    Center,
    /// end
    End,
}

/// Text alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlign {
    /// left
    Left,
    /// center
    Center,
    /// right
    Right,
}

impl Default for ComputedStyle {
    fn default() -> Self {
        ComputedStyle {
            display: Display::Inline,
            color: [17, 17, 17, 255],
            background: [0, 0, 0, 0],
            width: None,
            height: None,
            min_height: Value::Px(0.0),
            margin: [Value::Px(0.0); 4],
            padding: [Value::Px(0.0); 4],
            border: [0.0; 4],
            border_color: [0, 0, 0, 255],
            font_family: vec!["sans-serif".to_string()],
            font_size: 16.0,
            font_weight: 400,
            font_style_italic: false,
            text_align: TextAlign::Left,
            line_height: None,
            flex: FlexStyle {
                direction: FlexDirection::Row,
                justify: JustifyContent::Start,
                align: AlignItems::Stretch,
                grow: 0.0,
                shrink: 1.0,
                basis: None,
            },
            overflow_hidden: false,
        }
    }
}

impl ComputedStyle {
    /// Style for `<body>`-ish defaults used at the root of layout.
    pub fn root() -> ComputedStyle {
        ComputedStyle {
            display: Display::Block,
            ..Default::default()
        }
    }

    /// Inheritable properties from parent.
    pub fn inherit_from(parent: &ComputedStyle) -> ComputedStyle {
        ComputedStyle {
            color: parent.color,
            font_family: parent.font_family.clone(),
            font_size: parent.font_size,
            font_weight: parent.font_weight,
            font_style_italic: parent.font_style_italic,
            text_align: parent.text_align,
            line_height: parent.line_height,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a stylesheet.
pub fn parse_stylesheet(css: &str) -> Stylesheet {
    let mut sheet = Stylesheet::default();
    let mut order = 0u32;
    for chunk in split_rules(css) {
        let (sels, body) = match chunk.split_once('{') {
            Some((s, rest)) => (s, rest.trim_end_matches('}')),
            None => continue,
        };
        let mut parsed_sels = Vec::new();
        for s in sels.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            if let Some(sel) = parse_selector(s) {
                parsed_sels.push(sel);
            }
        }
        if parsed_sels.is_empty() {
            continue;
        }
        let decls = parse_declarations(body);
        let mut specificity = Specificity::default();
        for sel in &parsed_sels {
            let s = sel.specificity();
            specificity = specificity.max(s);
        }
        sheet.rules.push(Rule {
            selectors: parsed_sels,
            decls,
            specificity,
            order,
        });
        order += 1;
    }
    sheet
}

/// Split top-level rules (brace-depth 0 chunks).
fn split_rules(css: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                depth += 1;
                cur.push(c);
            }
            '}' => {
                depth -= 1;
                if depth <= 0 {
                    cur.push(c);
                    out.push(std::mem::take(&mut cur));
                    depth = 0;
                } else {
                    cur.push(c);
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn parse_selector(input: &str) -> Option<Selector> {
    let input = input.trim();
    if input.is_empty() || input.starts_with('@') {
        return None; // at-rules unsupported
    }
    let mut chain: Vec<Vec<Simple>> = Vec::new();
    for compound in input.split_whitespace() {
        let mut simples = Vec::new();
        let mut part = String::new();
        let mut flush = |part: &mut String, simples: &mut Vec<Simple>| {
            if part.is_empty() {
                return;
            }
            let mut cur = String::new();
            let mut kind = 0u8; // 0 type, 1 id, 2 class
            let mut push = |cur: &str, kind: u8, out: &mut Vec<Simple>| {
                if cur.is_empty() {
                    return;
                }
                match kind {
                    1 => out.push(Simple::Id(cur.to_string())),
                    2 => out.push(Simple::Class(cur.to_string())),
                    _ => out.push(Simple::Type(cur.to_ascii_lowercase())),
                }
            };
            for ch in part.chars() {
                match ch {
                    '#' => {
                        push(&cur, kind, &mut *simples);
                        cur.clear();
                        kind = 1;
                    }
                    '.' => {
                        push(&cur, kind, &mut *simples);
                        cur.clear();
                        kind = 2;
                    }
                    _ => cur.push(ch),
                }
            }
            push(&cur, kind, simples);
            part.clear();
        };
        // handle attribute selectors inside compound
        let mut attr_buf = String::new();
        let mut in_attr = false;
        for ch in compound.chars() {
            if ch == '[' {
                flush(&mut part, &mut simples);
                in_attr = true;
                attr_buf.clear();
            } else if ch == ']' && in_attr {
                in_attr = false;
                if let Some(s) = parse_attr_selector(&attr_buf) {
                    simples.push(s);
                }
            } else if in_attr {
                attr_buf.push(ch);
            } else {
                part.push(ch);
            }
        }
        flush(&mut part, &mut simples);
        if !simples.is_empty() {
            chain.push(simples);
        }
    }
    if chain.is_empty() {
        None
    } else {
        Some(Selector { chain })
    }
}

fn parse_attr_selector(buf: &str) -> Option<Simple> {
    let buf = buf.trim();
    let eq = buf.find('=');
    let (name_part, value, has_value) = match eq {
        Some(i) => (&buf[..i], buf[i + 1..].trim().trim_matches('"').trim_matches('\''), true),
        None => (buf, "", false),
    };
    let (name, op) = match name_part.as_bytes().last() {
        Some(b'^') => (&name_part[..name_part.len() - 1], AttrOp::Prefix),
        Some(b'$') => (&name_part[..name_part.len() - 1], AttrOp::Suffix),
        Some(b'*') => (&name_part[..name_part.len() - 1], AttrOp::Contains),
        _ => (name_part, AttrOp::Equals),
    };
    if name.is_empty() {
        return None;
    }
    let op = if !has_value { AttrOp::Present } else { op };
    Some(Simple::Attr { name: name.to_ascii_lowercase(), op, value: value.to_string() })
}

impl Selector {
    /// Specificity of this selector.
    fn specificity(&self) -> Specificity {
        let mut s = Specificity::default();
        for compound in &self.chain {
            for simple in compound {
                s.bump(simple);
            }
        }
        s
    }

    /// Match against an element in a document.
    fn matches(&self, doc: &Document, node: NodeId) -> bool {
        let Some((last, ancestors)) = self.chain.split_last() else {
            return false;
        };
        if !compound_matches(last, doc, node) {
            return false;
        }
        let mut cur = doc.get(node).parent;
        for anc in ancestors.iter().rev() {
            let mut found = false;
            while let Some(n) = option_node(cur) {
                if compound_matches(anc, doc, n) {
                    found = true;
                    cur = doc.get(n).parent;
                    break;
                }
                cur = doc.get(n).parent;
            }
            if !found {
                return false;
            }
        }
        true
    }
}

fn option_node(id: NodeId) -> Option<NodeId> {
    if id == NodeId::NONE {
        None
    } else {
        Some(id)
    }
}

fn compound_matches(compound: &[Simple], doc: &Document, node: NodeId) -> bool {
    let Some(el) = doc.element(node) else {
        return false;
    };
    for simple in compound {
        let ok = match simple {
            Simple::Type(t) => el.tag == *t,
            Simple::Id(id) => el.id() == Some(id.as_str()),
            Simple::Class(cls) => el.classes().contains(&cls.as_str()),
            Simple::Attr { name, op, value } => match op {
                AttrOp::Present => el.attr(name).is_some(),
                AttrOp::Equals => el.attr(name) == Some(value.as_str()),
                AttrOp::Prefix => el.attr(name).is_some_and(|v| v.starts_with(value)),
                AttrOp::Suffix => el.attr(name).is_some_and(|v| v.ends_with(value)),
                AttrOp::Contains => el.attr(name).is_some_and(|v| v.contains(value)),
            },
        };
        if !ok {
            return false;
        }
    }
    true
}

fn parse_declarations(body: &str) -> Vec<(String, Vec<Value>)> {
    let mut out = Vec::new();
    for decl in body.split(';') {
        let Some((name, value)) = decl.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let values = parse_values(value.trim());
        if !values.is_empty() {
            out.push((name, values));
        }
    }
    out
}

fn parse_values(input: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for tok in input.split(',') {
        let tok = tok.trim();
        if let Some(c) = parse_color(tok) {
            out.push(Value::Color(c));
        } else if let Ok(px) = tok.trim_end_matches("px").trim().parse::<f32>() {
            if tok.ends_with("px") || (px != 0.0 && !tok.contains('%') && !tok.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-')) {
                out.push(Value::Px(px));
            } else if tok.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-') {
                out.push(Value::Px(px)); // unitless = px
            }
        } else if let Some(pct) = tok.strip_suffix('%') {
            if let Ok(p) = pct.trim().parse::<f32>() {
                out.push(Value::Percent(p));
            }
        } else if !tok.is_empty() {
            out.push(Value::Keyword(tok.to_string()));
        }
    }
    out
}

/// Parse CSS colors: `#rgb`, `#rrggbb`, `#rrggbbaa`, `rgb()`, `rgba()`,
/// and the 16 basic named colors.
pub fn parse_color(tok: &str) -> Option<Color> {
    let tok = tok.trim();
    if let Some(hex) = tok.strip_prefix('#') {
        let h = hex.as_bytes();
        return match h.len() {
            3 => Some([
                scale_hex(nibble(h[0])),
                scale_hex(nibble(h[1])),
                scale_hex(nibble(h[2])),
                255,
            ]),
            4 => Some([
                scale_hex(nibble(h[0])),
                scale_hex(nibble(h[1])),
                scale_hex(nibble(h[2])),
                scale_hex(nibble(h[3])),
            ]),
            6 => Some([
                byte(&hex[0..2])?,
                byte(&hex[2..4])?,
                byte(&hex[4..6])?,
                255,
            ]),
            8 => Some([
                byte(&hex[0..2])?,
                byte(&hex[2..4])?,
                byte(&hex[4..6])?,
                byte(&hex[6..8])?,
            ]),
            _ => None,
        };
    }
    let lower = tok.to_ascii_lowercase();
    let named = |name: &str, c: Color| {
        if lower == name {
            Some(c)
        } else {
            None
        }
    };
    if let Some(rest) = lower.strip_prefix("rgb(").or_else(|| lower.strip_prefix("rgba(")) {
        let rest = rest.trim_end_matches(')');
        let parts: Vec<&str> = rest.split(',').map(|p| p.trim()).collect();
        if parts.len() >= 3 {
            let r = parts[0].parse::<f32>().ok()?;
            let g = parts[1].parse::<f32>().ok()?;
            let b = parts[2].parse::<f32>().ok()?;
            let a = parts.get(3).and_then(|p| p.parse::<f32>().ok()).unwrap_or(1.0);
            return Some([
                r.clamp(0.0, 255.0) as u8,
                g.clamp(0.0, 255.0) as u8,
                b.clamp(0.0, 255.0) as u8,
                (a.clamp(0.0, 1.0) * 255.0) as u8,
            ]);
        }
        return None;
    }
    named("black", [0, 0, 0, 255])
        .or_else(|| named("white", [255, 255, 255, 255]))
        .or_else(|| named("red", [255, 0, 0, 255]))
        .or_else(|| named("green", [0, 128, 0, 255]))
        .or_else(|| named("blue", [0, 0, 255, 255]))
        .or_else(|| named("yellow", [255, 255, 0, 255]))
        .or_else(|| named("orange", [255, 165, 0, 255]))
        .or_else(|| named("purple", [128, 0, 128, 255]))
        .or_else(|| named("gray", [128, 128, 128, 255]))
        .or_else(|| named("grey", [128, 128, 128, 255]))
        .or_else(|| named("silver", [192, 192, 192, 255]))
        .or_else(|| named("transparent", [0, 0, 0, 0]))
}

fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn scale_hex(n: u8) -> u8 {
    n * 17
}

fn byte(hex: &str) -> Option<u8> {
    u8::from_str_radix(hex, 16).ok()
}

// ---------------------------------------------------------------------------
// Cascade
// ---------------------------------------------------------------------------

/// Compute styles for every element in the document.
pub fn cascade(doc: &Document, sheets: &[Stylesheet], author_style: &str) -> HashMap<NodeId, ComputedStyle> {
    let mut author = parse_stylesheet(author_style);
    for s in sheets {
        author.rules.extend(s.rules.clone());
    }
    let ua = user_agent_sheet();
    let mut out: HashMap<NodeId, ComputedStyle> = HashMap::new();
    compute_subtree(doc, doc.root(), &ComputedStyle::root(), &[ua, author], &mut out);
    out
}

fn compute_subtree(
    doc: &Document,
    node: NodeId,
    parent_style: &ComputedStyle,
    sheets: &[Stylesheet],
    out: &mut HashMap<NodeId, ComputedStyle>,
) {
    for child in doc.children(node) {
        let base = match doc.element(child) {
            Some(el) => {
                let mut style = ComputedStyle::inherit_from(parent_style);
                apply_tag_defaults(&mut style, el);
                // Gather matching declarations: UA sheet first, then author.
                let mut matched: Vec<(&Rule, u8)> = Vec::new();
                for (sheet_idx, sheet) in sheets.iter().enumerate() {
                    for rule in &sheet.rules {
                        if rule.selectors.iter().any(|s| s.matches(doc, child)) {
                            matched.push((rule, sheet_idx as u8));
                        }
                    }
                }
                // sort by (origin, specificity, order)
                matched.sort_by(|a, b| {
                    (a.1, a.0.specificity, a.0.order).cmp(&(b.1, b.0.specificity, b.0.order))
                });
                for (rule, _) in matched {
                    apply_declarations(&mut style, &rule.decls, parent_style);
                }
                // inline style attribute wins over everything
                if let Some(inline) = el.attr("style") {
                    let decls = parse_declarations(inline);
                    apply_declarations(&mut style, &decls, parent_style);
                }
                style
            }
            None => {
                // Text nodes inherit everything.
                ComputedStyle::inherit_from(parent_style)
            }
        };
        out.insert(child, base.clone());
        compute_subtree(doc, child, &base, sheets, out);
    }
}

fn apply_tag_defaults(style: &mut ComputedStyle, el: &ElementData) {
    match el.tag.as_str() {
        "html" | "body" => {
            style.display = Display::Block;
            style.margin = [Value::Px(8.0), Value::Px(8.0), Value::Px(8.0), Value::Px(8.0)];
        }
        "div" | "section" | "article" | "header" | "footer" | "nav" | "main" | "aside"
        | "figure" | "figcaption" | "blockquote" | "pre" | "form" | "fieldset" | "address"
        | "details" | "summary" | "dialog" => {
            style.display = Display::Block;
        }
        "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "ul" | "ol" | "li" | "dl" | "dt" | "dd"
        | "table" | "thead" | "tbody" | "tfoot" | "tr" | "td" | "th" | "caption" => {
            style.display = Display::Block;
        }
        "h1" => {
            style.font_size = 32.0;
            style.font_weight = 700;
            style.margin = [
                Value::Px(21.44),
                Value::Px(0.0),
                Value::Px(21.44),
                Value::Px(0.0),
            ];
        }
        "h2" => {
            style.font_size = 24.0;
            style.font_weight = 700;
            style.margin = [
                Value::Px(19.92),
                Value::Px(0.0),
                Value::Px(19.92),
                Value::Px(0.0),
            ];
        }
        "h3" => {
            style.font_size = 18.72;
            style.font_weight = 700;
            style.margin = [
                Value::Px(18.72),
                Value::Px(0.0),
                Value::Px(18.72),
                Value::Px(0.0),
            ];
        }
        "h4" => {
            style.font_size = 16.0;
            style.font_weight = 700;
        }
        "h5" | "h6" => {
            style.font_size = 13.28;
            style.font_weight = 700;
        }
        "b" | "strong" => style.font_weight = 700,
        "i" | "em" | "cite" | "var" => style.font_style_italic = true,
        "code" | "kbd" | "samp" | "pre" | "tt" => {
            style.font_family = vec!["monospace".to_string()];
        }
        "a" => {
            style.color = [0, 102, 204, 255];
        }
        "ul" | "ol" => {
            style.margin = [
                Value::Px(16.0),
                Value::Px(0.0),
                Value::Px(16.0),
                Value::Px(0.0),
            ];
            style.padding = [
                Value::Px(0.0),
                Value::Px(0.0),
                Value::Px(0.0),
                Value::Px(40.0),
            ];
        }
        "p" => {
            style.margin = [
                Value::Px(16.0),
                Value::Px(0.0),
                Value::Px(16.0),
                Value::Px(0.0),
            ];
        }
        "blockquote" => {
            style.margin = [
                Value::Px(16.0),
                Value::Px(0.0),
                Value::Px(16.0),
                Value::Px(40.0),
            ];
        }
        "button" | "input" | "select" | "textarea" => {
            style.display = Display::Inline;
            style.border = [1.0; 4];
            style.border_color = [118, 118, 118, 255];
            style.padding = [
                Value::Px(2.0),
                Value::Px(6.0),
                Value::Px(2.0),
                Value::Px(6.0),
            ];
        }
        "hr" => {
            style.display = Display::Block;
            style.border = [1.0, 0.0, 0.0, 0.0];
            style.border_color = [0, 0, 0, 255];
            style.margin = [
                Value::Px(8.0),
                Value::Px(0.0),
                Value::Px(8.0),
                Value::Px(0.0),
            ];
        }
        "img" | "video" | "canvas" | "svg" | "iframe" | "embed" | "object" => {
            style.display = Display::Inline;
        }
        "br" => {
            style.display = Display::Inline;
        }
        "script" | "style" | "meta" | "link" | "title" | "head" | "noscript" | "template" => {
            style.display = Display::None;
        }
        _ => {}
    }
}

fn apply_declarations(style: &mut ComputedStyle, decls: &[(String, Vec<Value>)], parent: &ComputedStyle) {
    for (name, values) in decls {
        let first = values.first().cloned();
        match name.as_str() {
            "display" => {
                if let Some(Value::Keyword(k)) = first {
                    style.display = match k.as_str() {
                        "block" => Display::Block,
                        "flex" => Display::Flex,
                        "none" => Display::None,
                        _ => Display::Inline,
                    };
                }
            }
            "color" => {
                if let Some(Value::Color(c)) = first {
                    style.color = c;
                }
            }
            "background-color" | "background" => {
                if let Some(Value::Color(c)) = first {
                    style.background = c;
                }
            }
            "width" => {
                style.width = match first {
                    Some(v @ (Value::Px(_) | Value::Percent(_))) => Some(v),
                    _ => None,
                };
            }
            "height" => {
                style.height = match first {
                    Some(v @ (Value::Px(_) | Value::Percent(_))) => Some(v),
                    _ => None,
                };
            }
            "min-height" => {
                if let Some(v @ (Value::Px(_) | Value::Percent(_))) = first {
                    style.min_height = v;
                }
            }
            "margin" => apply_box_shorthand(&mut style.margin, values, parent),
            "margin-top" => apply_one(&mut style.margin[0], first, parent),
            "margin-right" => apply_one(&mut style.margin[1], first, parent),
            "margin-bottom" => apply_one(&mut style.margin[2], first, parent),
            "margin-left" => apply_one(&mut style.margin[3], first, parent),
            "padding" => apply_box_shorthand(&mut style.padding, values, parent),
            "padding-top" => apply_one(&mut style.padding[0], first, parent),
            "padding-right" => apply_one(&mut style.padding[1], first, parent),
            "padding-bottom" => apply_one(&mut style.padding[2], first, parent),
            "padding-left" => apply_one(&mut style.padding[3], first, parent),
            "border-width" | "border" => {
                // `border: 1px solid black`
                for v in values {
                    if let Value::Px(p) = v {
                        style.border = [p; 4];
                    } else if let Value::Color(c) = v {
                        style.border_color = c;
                    }
                }
                if let Some(Value::Keyword(k)) = first {
                    if k == "none" {
                        style.border = [0.0; 4];
                    }
                }
            }
            "border-color" => {
                if let Some(Value::Color(c)) = first {
                    style.border_color = c;
                }
            }
            "font-family" => {
                let families: Vec<String> = values
                    .iter()
                    .flat_map(|v| match v {
                        Value::Keyword(k) => vec![k.clone()],
                        Value::List(l) => l
                            .iter()
                            .filter_map(|v| match v {
                                Value::Keyword(k) => Some(k.clone()),
                                _ => None,
                            })
                            .collect(),
                        _ => vec![],
                    })
                    .collect();
                if !families.is_empty() {
                    style.font_family = families;
                }
            }
            "font-size" => match first {
                Some(Value::Px(p)) => style.font_size = p.max(1.0),
                Some(Value::Percent(p)) => style.font_size = (parent.font_size * p / 100.0).max(1.0),
                Some(Value::Keyword(k)) => {
                    style.font_size = match k.as_str() {
                        "xx-small" => 9.0,
                        "x-small" => 10.0,
                        "small" => 13.0,
                        "medium" => 16.0,
                        "large" => 18.0,
                        "x-large" => 24.0,
                        "xx-large" => 32.0,
                        _ => style.font_size,
                    };
                }
                _ => {}
            },
            "font-weight" => {
                if let Some(Value::Keyword(k)) = first {
                    style.font_weight = match k.as_str() {
                        "bold" => 700,
                        "normal" => 400,
                        _ => style.font_weight,
                    };
                } else if let Some(Value::Px(w)) = first {
                    style.font_weight = (w as u32).clamp(100, 900);
                }
            }
            "font-style" => {
                if let Some(Value::Keyword(k)) = first {
                    style.font_style_italic = k == "italic" || k == "oblique";
                }
            }
            "text-align" => {
                if let Some(Value::Keyword(k)) = first {
                    style.text_align = match k.as_str() {
                        "center" => TextAlign::Center,
                        "right" => TextAlign::Right,
                        _ => TextAlign::Left,
                    };
                }
            }
            "line-height" => match first {
                Some(Value::Px(p)) => style.line_height = Some(p / 16.0),
                Some(Value::Percent(p)) => style.line_height = Some(p / 100.0),
                Some(Value::Keyword(k)) => {
                    if k == "normal" {
                        style.line_height = None;
                    }
                }
                _ => {}
            },
            "flex-direction" => {
                if let Some(Value::Keyword(k)) = first {
                    style.flex.direction = match k.as_str() {
                        "column" | "column-reverse" => FlexDirection::Column,
                        _ => FlexDirection::Row,
                    };
                }
            }
            "justify-content" => {
                if let Some(Value::Keyword(k)) = first {
                    style.flex.justify = match k.as_str() {
                        "center" => JustifyContent::Center,
                        "flex-end" | "end" => JustifyContent::End,
                        "space-between" => JustifyContent::Between,
                        _ => JustifyContent::Start,
                    };
                }
            }
            "align-items" => {
                if let Some(Value::Keyword(k)) = first {
                    style.flex.align = match k.as_str() {
                        "center" => AlignItems::Center,
                        "flex-start" | "start" => AlignItems::Start,
                        "flex-end" | "end" => AlignItems::End,
                        _ => AlignItems::Stretch,
                    };
                }
            }
            "flex-grow" => {
                if let Some(Value::Px(g)) = first {
                    style.flex.grow = g.max(0.0);
                }
            }
            "flex-shrink" => {
                if let Some(Value::Px(s)) = first {
                    style.flex.shrink = s.max(0.0);
                }
            }
            "flex-basis" => {
                style.flex.basis = match first {
                    Some(v @ (Value::Px(_) | Value::Percent(_))) => Some(v),
                    _ => None,
                };
            }
            "overflow" => {
                if let Some(Value::Keyword(k)) = first {
                    style.overflow_hidden = k == "hidden" || k == "clip";
                }
            }
            _ => {}
        }
    }
}

fn apply_one(slot: &mut Value, first: Option<Value>, _parent: &ComputedStyle) {
    if let Some(v @ (Value::Px(_) | Value::Percent(_))) = first {
        *slot = v;
    } else if let Some(Value::Keyword(k)) = first {
        if k == "auto" || k == "0" {
            *slot = Value::Px(0.0);
        }
    }
}

fn apply_box_shorthand(box4: &mut [Value; 4], values: &[Value], parent: &ComputedStyle) {
    match values.len() {
        1 => {
            let v = values[0].clone();
            *box4 = [v.clone(), v.clone(), v.clone(), v];
        }
        2 => {
            let (a, b) = (values[0].clone(), values[1].clone());
            *box4 = [a.clone(), b.clone(), a, b];
        }
        3 => {
            let (a, b, c) = (values[0].clone(), values[1].clone(), values[2].clone());
            *box4 = [a, b.clone(), c, b];
        }
        n if n >= 4 => {
            *box4 = [
                values[0].clone(),
                values[1].clone(),
                values[2].clone(),
                values[3].clone(),
            ];
        }
        _ => {}
    }
    let _ = parent;
}

/// The built-in user-agent stylesheet.
pub fn user_agent_sheet() -> Stylesheet {
    parse_stylesheet(
        r#"
        *, *::before, *::after { }
        body { display: block; }
        b, strong { font-weight: 700; }
        "#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_builder::parse_html;

    #[test]
    fn color_parsing() {
        assert_eq!(parse_color("#fff"), Some([255, 255, 255, 255]));
        assert_eq!(parse_color("#ff0000"), Some([255, 0, 0, 255]));
        assert_eq!(parse_color("#ff000080"), Some([255, 0, 0, 128]));
        assert_eq!(parse_color("rgb(1, 2, 3)"), Some([1, 2, 3, 255]));
        assert_eq!(parse_color("rgba(1,2,3,0.5)"), Some([1, 2, 3, 128]));
        assert_eq!(parse_color("red"), Some([255, 0, 0, 255]));
        assert_eq!(parse_color("nonsense-çölor"), None);
    }

    #[test]
    fn rule_parsing() {
        let sheet = parse_stylesheet("div.big, p#x { color: #abc; margin: 10px 5px; }");
        assert_eq!(sheet.rules.len(), 1);
        let r = &sheet.rules[0];
        assert_eq!(r.specificity, Specificity { ids: 1, classes: 1, types: 2 });
        assert!(r.decls.iter().any(|(k, _)| k == "color"));
    }

    #[test]
    fn cascade_specificity() {
        let html = "<html><body><p id=\"main\" class=\"note\">x</p></body></html>";
        let doc = parse_html(html);
        let sheet = parse_stylesheet("p { color: red; } .note { color: blue; } #main { color: #0f0; }");
        let styles = cascade(&doc, &[sheet], "");
        let p = doc
            .traverse()
            .find(|&n| doc.tag_of(n) == Some("p"))
            .unwrap();
        let s = &styles[&p];
        assert_eq!(s.color, [0, 255, 0, 255]);
    }

    #[test]
    fn inheritance_of_text_properties() {
        let html = "<html><body><div style=\"color: #f00; font-size: 20px\"><span>hi</span></div></body></html>";
        let doc = parse_html(html);
        let styles = cascade(&doc, &[], "");
        let span = doc.traverse().find(|&n| doc.tag_of(n) == Some("span")).unwrap();
        let s = &styles[&span];
        assert_eq!(s.color, [255, 0, 0, 255]);
        assert_eq!(s.font_size, 20.0);
    }

    #[test]
    fn inline_style_wins() {
        let html = "<html><body><p style=\"color: lime\" class=\"c\">x</p></body></html>";
        let doc = parse_html(html);
        let sheet = parse_stylesheet(".c { color: red; }");
        let styles = cascade(&doc, &[sheet], "");
        let p = doc.traverse().find(|&n| doc.tag_of(n) == Some("p")).unwrap();
        assert_eq!(styles[&p].color, parse_color("lime").unwrap());
    }

    #[test]
    fn display_none_for_head_elements() {
        let doc = parse_html("<title>t</title><p>x</p>");
        let styles = cascade(&doc, &[], "");
        let title = doc.traverse().find(|&n| doc.tag_of(n) == Some("title")).unwrap();
        assert_eq!(styles[&title].display, Display::None);
    }

    #[test]
    fn flex_parsing() {
        let sheet = parse_stylesheet(
            ".row { display: flex; flex-direction: row; justify-content: space-between; gap: 8px; }",
        );
        assert_eq!(sheet.rules.len(), 1);
        let html = "<html><body><div class=\"row\"></div></body></html>";
        let doc = parse_html(html);
        let styles = cascade(&doc, &[sheet], "");
        let div = doc.traverse().find(|&n| doc.tag_of(n) == Some("div")).unwrap();
        let s = &styles[&div];
        assert_eq!(s.display, Display::Flex);
        assert_eq!(s.flex.justify, JustifyContent::Between);
    }
}
