//! Page surface controller: layout + band cache + image pipeline.

pub mod images;
pub mod layout;
pub mod paint;

use std::sync::Arc;

use bw_engine::BrowserEngine;
use bw_render::page_model::PageModel;

use crate::imgdata::RgbaImage;

/// Band height (px) — the unit of rasterization and caching.
pub const BAND_H: f32 = 1024.0;

/// One band in the UI model: height + optional pixels (placeholders carry
/// height only).
#[derive(Clone)]
pub struct BandView {
    pub height: i32,
    pub rgba: Option<RgbaImage>,
}
/// Bands kept around the viewport.
const BAND_AROUND: i32 = 2;

/// Owns everything needed to paint a tab's page.
pub struct PageSurface {
    pub laid: layout::LaidPage,
    pub images: images::ImageCache,
    model: Option<PageModel>,
    zoom: f32,
    width: f32,
    bands: std::collections::HashMap<i32, RgbaImage>,
    find: Vec<layout::FindMatch>,
    find_active: Option<usize>,
    find_text_cached: String,
}

impl PageSurface {
    pub fn new(profile: &std::path::Path) -> Self {
        PageSurface {
            laid: layout::LaidPage::default(),
            images: images::ImageCache::new(profile),
            model: None,
            zoom: 1.0,
            width: 1200.0,
            bands: std::collections::HashMap::new(),
            find: vec![],
            find_active: None,
            find_text_cached: String::new(),
        }
    }

    /// Install a new page model and lay it out.
    pub fn set_page(&mut self, model: PageModel, width: f32, dark: bool) {
        self.model = Some(model);
        self.bands.clear();
        self.find.clear();
        self.find_active = None;
        self.laid = layout::layout_page(self.model.as_ref().unwrap(), width, self.zoom);
        let _ = dark;
    }

    /// Relayout (zoom or width change).
    pub fn relayout(&mut self, width: f32) {
        self.width = width;
        if let Some(model) = &self.model {
            self.bands.clear();
            let m = model.clone();
            self.laid = layout::layout_page(&m, width, self.zoom);
            if !self.find_text_cached.is_empty() {
                let t = self.find_text_cached.clone();
                self.find = layout::find_matches(&self.laid, &t);
            }
        }
    }

    /// Drop the page model + bands (tab suspended → DOM freed engine-side).
    pub fn clear_page(&mut self) {
        self.model = None;
        self.bands.clear();
        self.laid = layout::LaidPage::default();
        self.find.clear();
        self.find_active = None;
        self.find_text_cached.clear();
    }

    /// Current find status (total, 1-based current).
    pub fn find_status(&self) -> (i32, i32) {
        (self.find.len() as i32, self.find_active.map(|i| i as i32 + 1).unwrap_or(0))
    }

    /// Cosmetic-hidden count from the model (privacy stat).
    pub fn cosmetic_hidden(&self) -> i32 {
        self.model.as_ref().map(|m| m.blocks.len() as i32).unwrap_or(0)
    }

    /// Drop cached band pixels (theme change repaint).
    pub fn invalidate_bands(&mut self) {
        self.bands.clear();
    }

    /// Set zoom (0.25..=5.0) and relayout.
    pub fn set_zoom(&mut self, percent: i32, width: f32) {
        self.zoom = (percent as f32 / 100.0).clamp(0.25, 5.0);
        self.width = width;
        self.relayout(width);
    }

    #[allow(dead_code)]
    pub fn zoom(&self) -> i32 {
        (self.zoom * 100.0).round() as i32
    }

    pub fn page_height(&self) -> i32 {
        self.laid.height.ceil() as i32
    }

    /// Update find-in-page state. Returns (total, current).
    pub fn set_find(&mut self, needle: &str) -> (i32, i32) {
        self.find_text_cached = needle.to_string();
        self.find = layout::find_matches(&self.laid, needle);
        self.find_active = self.find.first().map(|_| 0);
        self.bands.clear();
        (self.find.len() as i32, self.find_active.map(|i| i as i32 + 1).unwrap_or(0))
    }

    pub fn find_step(&mut self, forward: bool) -> (i32, i32) {
        let total = self.find.len();
        if total == 0 {
            return (0, 0);
        }
        let cur = self.find_active.map(|i| i as i64).unwrap_or(-1);
        let next = if forward {
            (cur + 1) % total as i64
        } else {
            (cur - 1 + total as i64) % total as i64
        };
        self.find_active = Some(next as usize);
        (total as i32, next as i32 + 1)
    }

    /// Y offset of the active find match (to scroll to it).
    pub fn find_active_y(&self) -> Option<f32> {
        let idx = self.find_active?;
        let m = self.find.get(idx)?;
        let line = self.laid.lines.get(m.line)?;
        Some(line.y)
    }

    /// Fetch pending images; true when new pixels arrived (repaint needed).
    pub async fn pump_images(&mut self, engine: &Arc<BrowserEngine>) -> bool {
        let wanted: Vec<String> = self.laid.images.iter().filter_map(|i| i.url.clone()).collect();
        let loaded = self.images.fetch_pending(engine, &wanted).await;
        if loaded.is_empty() {
            false
        } else {
            // New pixels: re-layout (sizes may settle) and invalidate bands.
            self.bands.clear();
            true
        }
    }

    /// Link at a page-space point.
    pub fn link_at(&self, x: f32, y: f32) -> Option<String> {
        for l in &self.laid.links {
            if x >= l.x && x <= l.x + l.w && y >= l.y && y <= l.y + l.h {
                return Some(l.url.clone());
            }
        }
        None
    }

    /// Produce the band model for the current scroll position.
    pub fn bands_for_scroll(
        &mut self,
        scroll_y: i32,
        viewport_h: i32,
        dark: bool,
    ) -> Vec<BandView> {
        let total_bands = (self.laid.height / BAND_H).ceil().max(1.0) as i32;
        let center = (scroll_y as f32 / BAND_H).floor() as i32;
        let first = (center - BAND_AROUND).max(0);
        let last = (center + BAND_AROUND + (viewport_h as f32 / BAND_H).ceil() as i32)
            .min(total_bands - 1);

        // Demote far bands (keep memory flat).
        self.bands.retain(|k, _| *k >= first - 2 && *k <= last + 2);

        let mut out = Vec::new();
        for b in 0..total_bands {
            let h = (self.laid.height - b as f32 * BAND_H).clamp(1.0, BAND_H);
            let rgba = if (first..=last).contains(&b) {
                if !self.bands.contains_key(&b) {
                    let rendered = self.render_band(b, dark);
                    self.bands.insert(b, rendered);
                }
                self.bands.get(&b).cloned()
            } else {
                None // placeholder keeps geometry stable at negligible cost
            };
            out.push(BandView { height: h as i32, rgba });
        }
        out
    }

    fn render_band(&mut self, band: i32, dark: bool) -> RgbaImage {
        let band_y = band as f32 * BAND_H;
        let width = self.laid.width.max(1.0) as u32;
        let params = paint::BandParams {
            band_y,
            band_h: BAND_H,
            width,
            find: &self.find,
            active: self.find_active,
            dark,
        };
        let rgba = paint::paint_band(&self.laid, &mut self.images, params);
        let h = ((self.laid.height - band_y).clamp(1.0, BAND_H)) as u32;
        RgbaImage { width, height: h, data: rgba }
    }

    /// Full-page PDF-ready series of bands (print pipeline).
    pub fn render_all_bands(&mut self, dark: bool) -> Vec<(i32, RgbaImage)> {
        let total = (self.laid.height / BAND_H).ceil().max(1.0) as i32;
        (0..total).map(|b| (b, self.render_band(b, dark))).collect()
    }
}
