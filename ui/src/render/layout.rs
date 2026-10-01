//! Page layout: PageModel blocks → positioned glyph runs (cosmic-text).

use std::sync::Mutex;

use cosmic_text::{
    Attrs, AttrsList, Buffer, Color as CtColor, Family, FontSystem, Metrics, Shaping, Style,
    SwashCache, Weight,
};

use bw_render::page_model::{Align, Block, PageModel, Run, RunStyle, TableCell};

/// One positioned glyph (cache-key based, ready for swash rasterization).
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct LaidGlyph {
    pub x: f32,
    pub y: f32, // offset relative to the baseline
    pub cluster: usize,
    pub cache_key: cosmic_text::CacheKey,
    pub size: f32,
    pub color: [u8; 4],
}

/// One laid-out line of glyphs.
#[derive(Debug, Clone)]
pub struct LaidLine {
    pub y: f32,      // top of the line box
    pub height: f32, // line height
    pub baseline: f32,
    pub width: f32,
    pub x: f32,
    pub text: String,
    pub glyphs: Vec<LaidGlyph>,
    pub underline: bool,
    pub link: Option<String>,
    pub color: [u8; 4],
}

/// A laid image slot.
#[derive(Debug, Clone)]
pub struct LaidImage {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub url: Option<String>,
    pub alt: String,
}

/// A horizontal rule.
#[derive(Debug, Clone)]
pub struct LaidRule {
    pub y: f32,
    pub x: f32,
    pub w: f32,
}

/// A laid table.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct LaidTable {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub row_h: Vec<f32>,
    pub col_w: Vec<f32>,
    pub lines: Vec<LaidLine>,
    pub header_rows: usize,
}

/// A link hit rectangle (page coordinates).
#[derive(Debug, Clone)]
pub struct LinkRect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub url: String,
}

/// A widget placeholder (iframe / input / video …).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct LaidWidget {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub kind: String,
    pub label: String,
}

/// A find-in-page match (char range on a laid line).
#[derive(Debug, Clone)]
pub struct FindMatch {
    pub line: usize,
    pub start: usize,
    pub len: usize,
}

/// The laid-out page (all coordinates in page space, px).
#[derive(Debug, Clone, Default)]
pub struct LaidPage {
    pub width: f32,
    pub height: f32,
    pub background: [u8; 4],
    pub lines: Vec<LaidLine>,
    pub images: Vec<LaidImage>,
    pub rules: Vec<LaidRule>,
    pub tables: Vec<LaidTable>,
    pub widgets: Vec<LaidWidget>,
    pub links: Vec<LinkRect>,
}

/// Shared text shaping context (FontSystem is expensive; SwashCache caches
/// glyph rasters — one pair per process).
pub struct TextContext {
    pub fonts: FontSystem,
    pub swash: SwashCache,
}

static TEXT_CTX: Mutex<Option<TextContext>> = Mutex::new(None);

/// Access the shared shaping context (initializes on first use).
pub fn with_text_ctx<R>(f: impl FnOnce(&mut TextContext) -> R) -> R {
    let mut guard = TEXT_CTX.lock().unwrap();
    if guard.is_none() {
        *guard = Some(TextContext { fonts: FontSystem::new(), swash: SwashCache::new() });
    }
    f(guard.as_mut().unwrap())
}

/// Block spacing (em units of a 16px base — UA-margin flavor).
fn block_margins(block: &Block) -> (f32, f32) {
    match block {
        Block::Heading { level, .. } => match level {
            1 => (0.75, 0.35),
            2 => (0.7, 0.3),
            3 => (0.6, 0.28),
            _ => (0.5, 0.25),
        },
        Block::Paragraph { soft, .. } => {
            if *soft {
                (0.0, 0.0)
            } else {
                (0.15, 0.15)
            }
        }
        Block::ListItem { .. } => (0.02, 0.02),
        Block::Quote { .. } => (0.3, 0.3),
        Block::Code { .. } => (0.25, 0.25),
        Block::Rule => (0.4, 0.4),
        Block::Image { .. } => (0.3, 0.3),
        Block::Table { .. } => (0.3, 0.3),
        Block::Widget { .. } => (0.2, 0.2),
    }
}

fn heading_scale(level: u8) -> f32 {
    match level {
        1 => 1.9,
        2 => 1.5,
        3 => 1.25,
        4 => 1.1,
        _ => 1.0,
    }
}

/// Layout a full page model at `viewport_width` and `zoom` (1.0 = 100%).
pub fn layout_page(model: &PageModel, viewport_width: f32, zoom: f32) -> LaidPage {
    let content_w = ((viewport_width - 56.0).max(320.0) / zoom).min(860.0);
    let page_w = content_w * zoom;
    let x0 = ((viewport_width - page_w) / 2.0).max(28.0 * zoom);

    let mut page =
        LaidPage { width: viewport_width, background: model.background, ..Default::default() };
    let mut y = 28.0 * zoom;

    for block in &model.blocks {
        let (top_m, bottom_m) = block_margins(block);
        y += top_m * 16.0 * zoom;
        layout_block(block, &mut page, &mut y, x0, content_w, zoom);
        y += bottom_m * 16.0 * zoom;
    }

    page.height = (y + 28.0 * zoom).max(10.0);
    page
}

fn layout_block(
    block: &Block,
    page: &mut LaidPage,
    y: &mut f32,
    x0: f32,
    content_w: f32,
    zoom: f32,
) {
    match block {
        Block::Heading { level, runs } => {
            let base = 16.0 * heading_scale(*level) * zoom;
            let lh = base * 1.28;
            let (lines, _) = shape_runs(runs, x0, content_w, base, lh, zoom);
            for mut line in lines {
                line.y = *y;
                *y += lh;
                push_line(page, line);
            }
        }
        Block::Paragraph { runs, align, .. } => {
            let base = 16.0 * zoom;
            let lh = base * 1.45;
            let (lines, _) = shape_runs(runs, x0, content_w, base, lh, zoom);
            for mut line in lines {
                line.y = *y;
                line.x = match align {
                    Align::Center => x0 + (content_w * zoom - line.width) / 2.0,
                    Align::End => x0 + content_w * zoom - line.width,
                    Align::Start => x0,
                };
                *y += lh;
                push_line(page, line);
            }
        }
        Block::ListItem { marker, indent, runs } => {
            let base = 16.0 * zoom;
            let lh = base * 1.42;
            let indent_x = x0 + (*indent as f32) * 26.0 * zoom;
            let marker_w = (marker.chars().count().max(2) as f32) * 9.0 * zoom + 10.0 * zoom;
            let text_w = content_w - (*indent as f32) * 26.0 - marker_w / zoom;
            let marker_runs = vec![Run {
                text: marker.clone(),
                style: RunStyle { color: [0x5f, 0x63, 0x68, 0xff], ..Default::default() },
            }];
            let (marker_lines, _) =
                shape_runs(&marker_runs, indent_x, marker_w / zoom, base, lh, zoom);
            for mut ml in marker_lines {
                ml.y = *y;
                push_line(page, ml);
            }
            let (lines, _) = shape_runs(runs, indent_x + marker_w, text_w, base, lh, zoom);
            for mut line in lines {
                line.y = *y;
                *y += lh;
                push_line(page, line);
            }
        }
        Block::Quote { runs } => {
            let base = 16.0 * zoom;
            let lh = base * 1.45;
            let indent_x = x0 + 20.0 * zoom;
            let (lines, _) = shape_runs(runs, indent_x, content_w - 20.0, base, lh, zoom);
            for mut line in lines {
                line.y = *y;
                *y += lh;
                let bar_y = line.y + line.height - line.baseline - 3.0;
                push_line(page, line);
                page.rules.push(LaidRule { y: bar_y, x: x0, w: 3.0 * zoom });
            }
        }
        Block::Code { lines } => {
            let base = 13.5 * zoom;
            let lh = base * 1.5;
            for src in lines {
                let style = RunStyle {
                    size: 13.5,
                    mono: true,
                    color: [0xd0, 0x30, 0x4f, 0xff],
                    ..RunStyle::default()
                };
                let run = Run { text: src.clone(), style };
                let (laid, _) =
                    shape_runs(&[run], x0 + 14.0 * zoom, content_w - 28.0, base, lh, zoom);
                for mut line in laid {
                    line.y = *y;
                    *y += lh;
                    push_line(page, line);
                }
            }
        }
        Block::Rule => {
            page.rules.push(LaidRule { y: *y + 8.0 * zoom, x: x0, w: content_w * zoom });
            *y += 16.0 * zoom;
        }
        Block::Image { url, alt, width, height } => {
            let max_w = content_w * zoom;
            let (mut w, mut h) = match (width, height) {
                (Some(w), Some(h)) => (*w as f32, *h as f32),
                (Some(w), None) => (*w as f32, *w as f32 * 0.62),
                (None, Some(h)) => (*h as f32 / 0.62, *h as f32),
                _ => (320.0, 180.0),
            };
            let scale = (max_w / w).min(1.0);
            w *= scale;
            h *= scale;
            let ix = x0 + (content_w * zoom - w).max(0.0) / 2.0;
            page.images.push(LaidImage {
                x: ix,
                y: *y,
                w,
                h: h * zoom,
                url: url.clone(),
                alt: alt.clone(),
            });
            *y += h * zoom;
            if !alt.is_empty() {
                let base = 12.0 * zoom;
                let lh = base * 1.35;
                let caption = Run {
                    text: alt.clone(),
                    style: RunStyle {
                        size: 12.0,
                        italic: true,
                        color: [0x5f, 0x63, 0x68, 0xff],
                        ..Default::default()
                    },
                };
                let (lines, _) = shape_runs(&[caption], x0, content_w, base, lh, zoom);
                for mut line in lines {
                    line.y = *y + 4.0 * zoom;
                    *y += lh;
                    push_line(page, line);
                }
            }
        }
        Block::Table { head, rows } => {
            layout_table(head, rows, page, y, x0, content_w, zoom);
        }
        Block::Widget { kind, url, label } => {
            let w = content_w.min(560.0) * zoom;
            let h = 54.0 * zoom;
            page.widgets.push(LaidWidget {
                x: x0,
                y: *y,
                w,
                h,
                kind: kind.clone(),
                label: if label.is_empty() {
                    url.clone().unwrap_or_else(|| kind.clone())
                } else {
                    label.clone()
                },
            });
            *y += h;
        }
    }
}

/// Shape one block's runs into laid lines at fixed width.
fn shape_runs(
    runs: &[Run],
    x: f32,
    width: f32,
    base_size: f32,
    line_height: f32,
    zoom: f32,
) -> (Vec<LaidLine>, String) {
    let mut text = String::new();
    let mut spans: Vec<(std::ops::Range<usize>, Attrs)> = Vec::new();
    let mut link: Option<String> = None;
    let mut underline = false;

    for run in runs {
        let style = &run.style;
        let start = text.len();
        let attrs = Attrs::new()
            .family(if style.mono { Family::Monospace } else { Family::SansSerif })
            .weight(Weight(style.weight.clamp(100, 900)))
            .style(if style.italic { Style::Italic } else { Style::Normal })
            .color(CtColor::rgba(style.color[0], style.color[1], style.color[2], style.color[3]))
            .underline(if style.underline {
                cosmic_text::UnderlineStyle::Single
            } else {
                cosmic_text::UnderlineStyle::None
            })
            .metadata(if style.strike { 1 } else { 0 });
        text.push_str(&run.text);
        spans.push((start..text.len(), attrs));
        if style.link.is_some() {
            link = style.link.clone();
            underline = true;
        }
    }

    let mut lines_out: Vec<LaidLine> = Vec::new();
    if text.is_empty() {
        return (lines_out, text);
    }

    with_text_ctx(|ctx| {
        let mut attrs_list = AttrsList::new(&Attrs::new());
        for (range, attrs) in &spans {
            attrs_list.add_span(range.clone(), attrs);
        }

        let mut buffer = Buffer::new_empty(Metrics::new(base_size, line_height));
        buffer.set_size(Some(width), Some(f32::MAX));
        buffer.lines.clear();
        buffer.lines.push(cosmic_text::BufferLine::new(
            text.clone(),
            cosmic_text::LineEnding::None,
            attrs_list,
            Shaping::Advanced,
        ));
        buffer.shape_until_scroll(&mut ctx.fonts, false);

        for run in buffer.layout_runs() {
            let mut glyphs: Vec<LaidGlyph> = Vec::new();
            let default_color = [0x1a, 0x1a, 0x1a, 0xff];
            let mut line_color = default_color;
            for glyph in run.glyphs.iter() {
                let pg = glyph.physical((0.0, 0.0), 1.0);
                let color: [u8; 4] =
                    glyph.color_opt.map(|c| [c.r(), c.g(), c.b(), c.a()]).unwrap_or(default_color);
                line_color = color;
                glyphs.push(LaidGlyph {
                    x: pg.x as f32,
                    y: pg.y as f32,
                    cluster: glyph.start,
                    cache_key: pg.cache_key,
                    size: glyph.font_size,
                    color,
                });
            }
            // baseline relative to the line box top.
            let baseline = run.line_y - run.line_top;
            lines_out.push(LaidLine {
                y: 0.0,
                height: run.line_height,
                baseline,
                width: run.line_w,
                x,
                text: run.text.to_string(),
                glyphs,
                underline,
                link: link.clone(),
                color: line_color,
            });
        }
    });

    let _ = zoom;
    (lines_out, text)
}

fn push_line(page: &mut LaidPage, line: LaidLine) {
    if let Some(url) = &line.link {
        page.links.push(LinkRect {
            x: line.x,
            y: line.y,
            w: line.width.max(8.0),
            h: line.height,
            url: url.clone(),
        });
    }
    page.lines.push(line);
}

fn layout_table(
    head: &[TableCell],
    rows: &[Vec<TableCell>],
    page: &mut LaidPage,
    y: &mut f32,
    x0: f32,
    content_w: f32,
    zoom: f32,
) {
    let ncols = head.len().max(rows.first().map(|r| r.len()).unwrap_or(0)).max(1);
    let base = 14.0 * zoom;
    let lh = base * 1.4;

    // Column widths proportional to content weight.
    let mut weights = vec![4.0f32; ncols];
    for (i, c) in head.iter().enumerate() {
        let len: usize = c.runs.iter().map(|r| r.text.len()).sum();
        weights[i] = (len as f32).max(4.0);
    }
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i >= ncols {
                break;
            }
            let len: usize = c.runs.iter().map(|r| r.text.len()).sum();
            weights[i] = weights[i].max((len as f32).min(90.0));
        }
    }
    let total: f32 = weights.iter().sum::<f32>().max(1.0);
    let table_w = content_w * zoom;
    let col_w: Vec<f32> = weights.iter().map(|w| w / total * table_w).collect();

    let mut row_h: Vec<f32> = Vec::new();
    let mut lines: Vec<LaidLine> = Vec::new();
    let mut header_rows = 0usize;
    let mut cur_y = *y;

    let mut col_x = x0;
    let mut lay_row = |cells: &[TableCell], header: bool, cur_y: f32, row_h: &mut Vec<f32>| {
        let mut max_h = lh;
        col_x = x0;
        for (i, cell) in cells.iter().enumerate() {
            if i >= ncols {
                break;
            }
            let cw = (col_w[i].min(table_w - (col_x - x0)) - 12.0 * zoom).max(24.0);
            let style_runs: Vec<Run> = cell
                .runs
                .iter()
                .map(|r| {
                    let mut rr = r.clone();
                    if header {
                        rr.style.weight = 600;
                        rr.style.color = [0x20, 0x21, 0x24, 0xff];
                    }
                    rr.style.size = 14.0;
                    rr
                })
                .collect();
            let (cell_lines, _) =
                shape_runs(&style_runs, col_x + 6.0 * zoom, cw / zoom, base, lh, zoom);
            for mut line in cell_lines {
                line.y = cur_y;
                if line.height > max_h {
                    max_h = line.height;
                }
                lines.push(line);
            }
            col_x += col_w[i];
        }
        row_h.push(max_h);
    };

    if !head.is_empty() {
        header_rows = 1;
        lay_row(head, true, cur_y, &mut row_h);
        cur_y += row_h[0];
    }
    for r in rows {
        lay_row(r, false, cur_y, &mut row_h);
        cur_y += row_h.last().copied().unwrap_or(lh);
    }

    page.tables.push(LaidTable { x: x0, y: *y, w: table_w, row_h, col_w, lines, header_rows });
    *y = cur_y;
}

/// Find matches across laid lines (case-insensitive substring).
pub fn find_matches(page: &LaidPage, needle: &str) -> Vec<FindMatch> {
    if needle.is_empty() {
        return vec![];
    }
    let n = needle.to_lowercase();
    let mut out = Vec::new();
    for (i, line) in page.lines.iter().enumerate() {
        let hay = line.text.to_lowercase();
        let mut start = 0;
        while let Some(pos) = hay[start..].find(&n) {
            out.push(FindMatch { line: i, start: start + pos, len: n.len() });
            start += pos + n.len().max(1);
        }
    }
    out
}
