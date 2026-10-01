//! Font selection, metrics and glyph rasterization.
//!
//! * System font discovery via `fontdb`.
//! * Per-run font resolution from CSS `font-family` chains.
//! * Simple cmap-based shaping (char → glyph) with per-glyph advances.
//! * Glyph rasterization through `swash` into alpha masks, blitted by the
//!   painter.
//!
//! Advanced shaping (kerning, ligatures, bidi) is roadmap work — see
//! `docs/ROADMAP.md`. This module is deliberately synchronous: it runs on
//! the layout thread where a page owns its fonts.

use std::collections::HashMap;

use swash::proxy::MetricsProxy;
use swash::scale::{Render, ScaleContext, Source};
use swash::FontRef;

/// A font handle resolved from a family query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FontKey {
    /// fontdb face id.
    pub id: u32,
    /// Pixel size (px per em) this key was resolved for.
    pub size: u32,
}

/// Rasterized glyph: an alpha mask plus placement.
#[derive(Debug, Clone)]
pub struct RasterGlyph {
    /// Distance from the pen position to the left edge of the mask.
    pub left: i32,
    /// Distance from the baseline to the top edge of the mask.
    pub top: i32,
    /// Mask width.
    pub width: u32,
    /// Mask height.
    pub height: u32,
    /// 8-bit alpha coverage mask.
    pub mask: Vec<u8>,
}

/// Font manager: database + scaling context + metric cache.
pub struct FontSystem {
    db: fontdb::Database,
    cx: ScaleContext,
    /// (face, size) → scaled metrics.
    metrics_cache: HashMap<(fontdb::ID, u32), ScaledMetrics>,
}

/// Scaled font metrics for layout.
#[derive(Debug, Clone, Copy)]
pub struct ScaledMetrics {
    /// Ascent (px above baseline).
    pub ascent: f32,
    /// Descent (px below baseline, positive).
    pub descent: f32,
    /// Line gap.
    pub line_gap: f32,
}

impl ScaledMetrics {
    /// Line height: ascent + descent + line_gap.
    pub fn line_height(&self) -> f32 {
        self.ascent + self.descent + self.line_gap
    }
}

impl Default for FontSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl FontSystem {
    /// Load system fonts.
    pub fn new() -> FontSystem {
        let mut db = fontdb::Database::new();
        db.load_system_fonts();
        // Map generic CSS families to fonts that actually exist on this
        // machine. fontdb defaults to Windows names (Arial, ...); on Linux
        // containers those are absent and every sans-serif query would miss.
        map_generic_families(&mut db);
        // Guarantee a fallback even on bare containers.
        if db.is_empty() {
            tracing::warn!("no system fonts found; text rendering will be degraded");
        }
        FontSystem { db, cx: ScaleContext::new(), metrics_cache: HashMap::new() }
    }

    /// Number of loaded font faces.
    pub fn faces(&self) -> usize {
        self.db.len()
    }

    /// Resolve a family chain to a concrete face id.
    pub fn resolve(&self, families: &[String], weight: u32, italic: bool) -> Option<fontdb::ID> {
        let mut query_families: Vec<fontdb::Family> = families
            .iter()
            .map(|f| {
                if f.eq_ignore_ascii_case("serif") {
                    fontdb::Family::Serif
                } else if f.eq_ignore_ascii_case("sans-serif") || f.eq_ignore_ascii_case("sans") {
                    fontdb::Family::SansSerif
                } else if f.eq_ignore_ascii_case("monospace") {
                    fontdb::Family::Monospace
                } else if f.eq_ignore_ascii_case("cursive") {
                    fontdb::Family::Cursive
                } else if f.eq_ignore_ascii_case("fantasy") {
                    fontdb::Family::Fantasy
                } else {
                    fontdb::Family::Name(f)
                }
            })
            .collect();
        query_families.push(fontdb::Family::SansSerif);
        let query = fontdb::Query {
            families: &query_families,
            weight: fontdb::Weight(weight.clamp(100, 900) as u16),
            style: if italic { fontdb::Style::Italic } else { fontdb::Style::Normal },
            ..Default::default()
        };
        self.db.query(&query)
    }

    /// Scaled metrics for (face, size).
    pub fn metrics(&mut self, face: fontdb::ID, size: f32) -> ScaledMetrics {
        let cache_key = (face, size.to_bits());
        if let Some(m) = self.metrics_cache.get(&cache_key) {
            return *m;
        }
        let m = self
            .db
            .with_face_data(face, |data, index| {
                let font = FontRef::from_index(data, index as usize)?;
                let proxy = MetricsProxy::from_font(&font);
                let scaled = proxy.materialize_metrics(&font, &[]).scale(size);
                Some(ScaledMetrics {
                    ascent: scaled.ascent,
                    // swash reports descent as a positive below-baseline value.
                    descent: scaled.descent,
                    line_gap: scaled.leading,
                })
            })
            .flatten()
            .unwrap_or(ScaledMetrics { ascent: size * 0.8, descent: size * 0.2, line_gap: 0.0 });
        self.metrics_cache.insert(cache_key, m);
        m
    }

    /// A measured run of text.
    pub fn measure(&mut self, face: fontdb::ID, size: f32, text: &str) -> f32 {
        let cache_key = (face, size.to_bits());
        if !self.metrics_cache.contains_key(&cache_key) {
            let _ = self.metrics(face, size);
        }
        let mut width = 0.0f32;
        self.db.with_face_data(face, |data, index| {
            let Some(font) = FontRef::from_index(data, index as usize) else {
                return;
            };
            let proxy = MetricsProxy::from_font(&font);
            let metrics = proxy.materialize_metrics(&font, &[]).scale(size);
            let advances = proxy.materialize_glyph_metrics(&font, &[]).scale(size);
            let charmap = font.charmap();
            for ch in text.chars() {
                if ch.is_whitespace() {
                    // approximate space advance from average width
                    width += metrics.average_width;
                    continue;
                }
                let gid = charmap.map(ch);
                width += advances.advance_width(gid);
            }
        });
        width
    }

    /// Shape and rasterize a text run. Returns positioned glyphs.
    pub fn rasterize(
        &mut self,
        face: fontdb::ID,
        size: f32,
        text: &str,
    ) -> Vec<(f32, RasterGlyph)> {
        let mut out = Vec::new();
        self.db.with_face_data(face, |data, index| {
            let Some(font) = FontRef::from_index(data, index as usize) else {
                return;
            };
            let proxy = MetricsProxy::from_font(&font);
            let metrics = proxy.materialize_metrics(&font, &[]).scale(size);
            let advances = proxy.materialize_glyph_metrics(&font, &[]).scale(size);
            let charmap = font.charmap();
            let mut pen = 0.0f32;
            let mut scaler = self.cx.builder(font).size(size).build();
            let mut render = Render::new(&[Source::Outline]);
            render.format(swash::zeno::Format::Alpha);
            for ch in text.chars() {
                if ch.is_whitespace() {
                    pen += metrics.average_width;
                    continue;
                }
                let gid = charmap.map(ch);
                if let Some(image) = render.render(&mut scaler, gid) {
                    let p = image.placement;
                    out.push((
                        pen,
                        RasterGlyph {
                            left: p.left,
                            top: p.top,
                            width: p.width,
                            height: p.height,
                            mask: image.data.clone(),
                        },
                    ));
                }
                pen += advances.advance_width(gid);
            }
        });
        out
    }
}

/// Point generic CSS families at fonts that exist on this machine.
///
/// `fontdb` ships Windows-centric defaults (`Arial`, `Times New Roman`,
/// `Courier New`). On Linux/CI those faces are absent, so every
/// `sans-serif` query would return `None`. We probe a curated list of the
/// most common faces per platform and bind the first hit — the same job
/// fontconfig does for native Linux browsers.
fn map_generic_families(db: &mut fontdb::Database) {
    let has = |name: &str| {
        db.faces().any(|f| f.families.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)))
    };
    const SANS: &[&str] = &[
        "Arial",
        "DejaVu Sans",
        "Liberation Sans",
        "Noto Sans",
        "Segoe UI",
        "Helvetica",
        "Ubuntu",
        "Cantarell",
        "Roboto",
    ];
    const SERIF: &[&str] = &[
        "Times New Roman",
        "DejaVu Serif",
        "Liberation Serif",
        "Noto Serif",
        "Georgia",
        "FreeSerif",
    ];
    const MONO: &[&str] = &[
        "Courier New",
        "DejaVu Sans Mono",
        "Liberation Mono",
        "Noto Sans Mono",
        "Consolas",
        "Menlo",
        "FreeMono",
    ];
    // Resolve while `db` is immutably borrowed, then mutate.
    let sans = SANS.iter().find(|n| has(n)).copied();
    let serif = SERIF.iter().find(|n| has(n)).copied();
    let mono = MONO.iter().find(|n| has(n)).copied();
    if let Some(name) = sans {
        db.set_sans_serif_family(name);
        db.set_cursive_family(name);
        db.set_fantasy_family(name);
    }
    if let Some(name) = serif {
        db.set_serif_family(name);
    }
    if let Some(name) = mono {
        db.set_monospace_family(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_fonts_loaded() {
        let mut fs = FontSystem::new();
        // On CI containers there may be no fonts; the engine must not crash.
        if fs.faces() == 0 {
            return;
        }
        let face = fs.resolve(&["sans-serif".to_string()], 400, false);
        assert!(face.is_some());
        let m = fs.metrics(face.unwrap(), 16.0);
        assert!(m.ascent > 0.0);
        assert!(m.descent > 0.0);
        let w = fs.measure(face.unwrap(), 16.0, "hello");
        assert!(w > 0.0);
    }

    #[test]
    fn rasterize_produces_masks() {
        let mut fs = FontSystem::new();
        if fs.faces() == 0 {
            return;
        }
        let face = fs.resolve(&["sans-serif".to_string()], 400, false).unwrap();
        let glyphs = fs.rasterize(face, 16.0, "Hi!");
        assert!(!glyphs.is_empty());
        for (x, g) in &glyphs {
            assert!(*x >= 0.0);
            assert_eq!(g.mask.len(), (g.width as usize) * (g.height as usize));
        }
    }
}
