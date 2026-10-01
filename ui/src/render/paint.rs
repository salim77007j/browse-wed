//! Band painting: laid pages → RGBA pixels (tiny-skia + swash).

use tiny_skia::{Color as TsColor, FillRule, Paint, PathBuilder, Pixmap, Rect, Stroke, Transform};

use super::images::ImageCache;
use super::layout::{FindMatch, LaidPage, LaidTable};

/// Paint one horizontal band of the page into an RGBA buffer.
///
/// `find` carries the current matches; `active` is the index of the
/// highlighted one (rest get a softer fill).
/// Parameters for one band rasterization.
pub struct BandParams<'a> {
    pub band_y: f32,
    pub band_h: f32,
    pub width: u32,
    pub find: &'a [FindMatch],
    pub active: Option<usize>,
    pub dark: bool,
}

pub fn paint_band(page: &LaidPage, images: &mut ImageCache, p: BandParams<'_>) -> Vec<u8> {
    let band_y = p.band_y;
    let band_h = p.band_h;
    let width = p.width;
    let find = p.find;
    let active = p.active;
    let dark = p.dark;
    let mut pixmap =
        Pixmap::new(width, band_h.max(1.0) as u32).unwrap_or_else(|| Pixmap::new(1, 1).unwrap());

    // Page background (theme-aware for transparent pages).
    let bg = pick_bg(page.background, dark);
    pixmap.fill(bg);

    // --- images --------------------------------------------------------------
    for img in &page.images {
        let img_bottom = img.y + img.h;
        if img_bottom < band_y || img.y > band_y + band_h {
            continue;
        }
        if let Some(px) = images.get(img.url.as_deref().unwrap_or("")) {
            draw_pixmap(&mut pixmap, &px, img.x, img.y - band_y, img.w, img.h);
        } else {
            // Placeholder: subtle surface + corner glyph.
            let ph = surface_color(dark);
            fill_rect(&mut pixmap, img.x, img.y - band_y, img.w, img.h, ph);
            stroke_rect(&mut pixmap, img.x, img.y - band_y, img.w, img.h, divider_color(dark));
            if !img.alt.is_empty() {
                // alt text drawn as small caption line via glyph path in
                // the lines pass (layout added it) — nothing more here.
            }
        }
    }

    // --- widgets (honest placeholders) ----------------------------------------
    for w in &page.widgets {
        let bottom = w.y + w.h;
        if bottom < band_y || w.y > band_y + band_h {
            continue;
        }
        fill_rect(&mut pixmap, w.x, w.y - band_y, w.w, w.h, surface_color(dark));
        stroke_rect(&mut pixmap, w.x, w.y - band_y, w.w, w.h, divider_color(dark));
    }

    // --- tables ---------------------------------------------------------------
    for t in &page.tables {
        paint_table(&mut pixmap, t, band_y, dark);
    }

    // --- rules ------------------------------------------------------------------
    for r in &page.rules {
        let y = r.y - band_y;
        if y < 0.0 || y > band_h {
            continue;
        }
        fill_rect(&mut pixmap, r.x, y, r.w.max(1.0), 1.5, divider_color(dark));
    }

    // --- find highlights (under the text) ---------------------------------------
    if !find.is_empty() {
        for (idx, m) in find.iter().enumerate() {
            let line = match page.lines.get(m.line) {
                Some(l) => l,
                None => continue,
            };
            if line.y + line.height < band_y || line.y > band_y + band_h {
                continue;
            }
            let Some((x, w)) = match_range_width(line, m.start, m.len) else { continue };
            let color = if Some(idx) == active {
                TsColor::from_rgba8(0x1a, 0x73, 0xe8, 0xb8)
            } else {
                TsColor::from_rgba8(0xf9, 0xab, 0x00, 0x70)
            };
            fill_rect(
                &mut pixmap,
                line.x + x,
                line.y - band_y + line.height - line.baseline - 2.0,
                w,
                line.baseline + 4.0,
                color,
            );
        }
    }

    // --- glyphs -------------------------------------------------------------------
    for line in &page.lines {
        if line.y + line.height < band_y || line.y > band_y + band_h {
            continue;
        }
        let baseline = line.y - band_y + line.baseline;
        // underline for links
        if line.underline {
            let y = baseline + 1.5;
            fill_rect(
                &mut pixmap,
                line.x,
                y,
                line.width.max(2.0),
                1.2,
                TsColor::from_rgba8(line.color[0], line.color[1], line.color[2], 0xd0),
            );
        }
        for g in &line.glyphs {
            draw_glyph(&mut pixmap, g.cache_key, line.x + g.x, baseline + g.y, g.color);
        }
    }

    let data = pixmap.take();
    let _ = FillRule::Winding;
    data
}

/// Draw one glyph through the shared swash cache (cache-key based).
fn draw_glyph(
    pixmap: &mut Pixmap,
    cache_key: cosmic_text::CacheKey,
    x: f32,
    y: f32,
    color: [u8; 4],
) {
    super::layout::with_text_ctx(|ctx| {
        let image = ctx.swash.get_image(&mut ctx.fonts, cache_key);
        let Some(img) = image else { return };
        let left = img.placement.left as f32;
        let top = img.placement.top as f32;
        let (w, h) = (img.placement.width, img.placement.height);
        if w == 0 || h == 0 {
            return;
        }
        match img.content {
            cosmic_text::SwashContent::Mask => {
                for row in 0..h {
                    for col in 0..w {
                        let alpha = img.data[(row * w + col) as usize];
                        if alpha == 0 {
                            continue;
                        }
                        let px = x + left + col as f32;
                        let py = y + top + row as f32;
                        blend_pixel(pixmap, px, py, color, alpha);
                    }
                }
            }
            _ => {
                // Color / SubpixelMask bitmaps (emoji): RGBA bytes.
                for row in 0..h {
                    for col in 0..w {
                        let i = ((row * w + col) * 4) as usize;
                        let a = img.data[i + 3];
                        if a == 0 {
                            continue;
                        }
                        let c = [img.data[i], img.data[i + 1], img.data[i + 2], a];
                        let px = x + left + col as f32;
                        let py = y + top + row as f32;
                        blend_pixel(pixmap, px, py, c, a);
                    }
                }
            }
        }
    });
}

fn blend_pixel(pixmap: &mut Pixmap, x: f32, y: f32, color: [u8; 4], alpha: u8) {
    let xi = x as i32;
    let yi = y as i32;
    if xi < 0 || yi < 0 || xi >= pixmap.width() as i32 || yi >= pixmap.height() as i32 {
        return;
    }
    let a = (alpha as u32 * color[3] as u32) / 255;
    if a == 0 {
        return;
    }
    let idx = (yi as usize * pixmap.width() as usize + xi as usize) * 4;
    let data = pixmap.data_mut();
    let inv = 255 - a;
    // blend in straight-alpha over premultiplied destination
    data[idx] = ((color[0] as u32 * a + data[idx] as u32 * inv) / 255) as u8;
    data[idx + 1] = ((color[1] as u32 * a + data[idx + 1] as u32 * inv) / 255) as u8;
    data[idx + 2] = ((color[2] as u32 * a + data[idx + 2] as u32 * inv) / 255) as u8;
    data[idx + 3] = 255;
}

fn fill_rect(pixmap: &mut Pixmap, x: f32, y: f32, w: f32, h: f32, color: TsColor) {
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    let rect = match Rect::from_xywh(x, y, w, h) {
        Some(r) => r,
        None => return,
    };
    let mut paint = Paint::default();
    paint.set_color(color);
    paint.anti_alias = false;
    let path = PathBuilder::from_rect(rect);
    pixmap.fill_path(&path, &paint, FillRule::Winding, Transform::identity(), None);
}

fn stroke_rect(pixmap: &mut Pixmap, x: f32, y: f32, w: f32, h: f32, color: TsColor) {
    let mut pb = PathBuilder::new();
    pb.move_to(x, y);
    pb.line_to(x + w, y);
    pb.line_to(x + w, y + h);
    pb.line_to(x, y + h);
    pb.close();
    if let Some(path) = pb.finish() {
        let mut paint = Paint::default();
        paint.set_color(color);
        paint.anti_alias = true;
        pixmap.stroke_path(
            &path,
            &paint,
            &Stroke { width: 1.0, ..Default::default() },
            Transform::identity(),
            None,
        );
    }
}

fn draw_pixmap(dst: &mut Pixmap, src: &Pixmap, x: f32, y: f32, w: f32, h: f32) {
    if w <= 0.0 || h <= 0.0 || src.width() == 0 || src.height() == 0 {
        return;
    }
    let scale_x = w / src.width() as f32;
    let scale_y = h / src.height() as f32;
    let transform = Transform::from_scale(scale_x, scale_y).post_translate(x, y);
    let paint = tiny_skia::PixmapPaint {
        quality: tiny_skia::FilterQuality::Bilinear,
        ..Default::default()
    };
    dst.draw_pixmap(0, 0, src.as_ref(), &paint, transform, None);
}

fn paint_table(pixmap: &mut Pixmap, t: &LaidTable, band_y: f32, dark: bool) {
    let bottom = t.y + t.row_h.iter().sum::<f32>();
    if bottom < band_y || t.y > band_y + pixmap.height() as f32 {
        return;
    }
    // Header background + separators.
    let mut row_y = t.y;
    for (i, rh) in t.row_h.iter().enumerate() {
        if i < t.header_rows {
            fill_rect(
                pixmap,
                t.x,
                row_y - band_y,
                t.w,
                *rh,
                if dark {
                    TsColor::from_rgba8(0x3c, 0x40, 0x43, 0xff)
                } else {
                    TsColor::from_rgba8(0xf1, 0xf3, 0xf4, 0xff)
                },
            );
        }
        fill_rect(pixmap, t.x, row_y - band_y + rh - 1.0, t.w, 1.0, divider_color(dark));
        row_y += rh;
    }
    let mut col_x = t.x;
    for cw in &t.col_w {
        fill_rect(pixmap, col_x, t.y - band_y, 1.0, row_y - t.y, divider_color(dark));
        col_x += cw;
    }
    fill_rect(pixmap, col_x, t.y - band_y, 1.0, row_y - t.y, divider_color(dark));
}

/// Width (in px) of a char range on a line, from glyph clusters.
fn match_range_width(
    line: &super::layout::LaidLine,
    start: usize,
    len: usize,
) -> Option<(f32, f32)> {
    let mut x0: Option<f32> = None;
    let mut x1: Option<f32> = None;
    for g in &line.glyphs {
        if g.cluster >= start && g.cluster < start + len {
            x0 = x0.map_or(Some(g.x), |m: f32| Some(m.min(g.x)));
            x1 = x1.map_or(Some(g.x), |m: f32| Some(m.max(g.x)));
        }
    }
    // Add one glyph width of tolerance.
    match (x0, x1) {
        (Some(a), Some(b)) => Some((a, (b - a).max(6.0))),
        _ => {
            // Fallback: proportional estimate.
            let chars = line.text.chars().count().max(1) as f32;
            let w = line.width / chars;
            Some((start as f32 * w, len as f32 * w))
        }
    }
}

fn pick_bg(page_bg: [u8; 4], dark: bool) -> TsColor {
    // Alpha-carrying or near-white/black backgrounds are honored; otherwise
    // the theme page background wins (keeps dark mode pleasant).
    let [r, g, b, a] = page_bg;
    if a < 0x80 {
        return theme_bg(dark);
    }
    let lum = (r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000;
    if !(10..=245).contains(&lum) {
        theme_bg(dark)
    } else {
        TsColor::from_rgba8(r, g, b, 0xff)
    }
}

fn theme_bg(dark: bool) -> TsColor {
    if dark {
        TsColor::from_rgba8(0x1b, 0x1b, 0x1f, 0xff)
    } else {
        TsColor::from_rgba8(0xff, 0xff, 0xff, 0xff)
    }
}

fn surface_color(dark: bool) -> TsColor {
    if dark {
        TsColor::from_rgba8(0x23, 0x23, 0x26, 0xff)
    } else {
        TsColor::from_rgba8(0xf1, 0xf3, 0xf4, 0xff)
    }
}

fn divider_color(dark: bool) -> TsColor {
    if dark {
        TsColor::from_rgba8(0x3c, 0x40, 0x43, 0xff)
    } else {
        TsColor::from_rgba8(0xda, 0xdc, 0xe0, 0xff)
    }
}
