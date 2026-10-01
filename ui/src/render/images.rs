//! Page image pipeline: fetch via the engine, decode, cache as pixmaps.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bw_engine::BrowserEngine;
use bw_privacy::ResourceType;
use tiny_skia::Pixmap;
use url::Url;

/// In-memory decoded-image cache with a disk mirror.
pub struct ImageCache {
    dir: PathBuf,
    map: HashMap<String, Option<Arc<Pixmap>>>,
    pending: Vec<String>,
}

impl ImageCache {
    pub fn new(profile: &std::path::Path) -> Self {
        let dir = profile.join("http-cache-images");
        std::fs::create_dir_all(&dir).ok();
        ImageCache { dir, map: HashMap::new(), pending: Vec::new() }
    }

    /// Cached pixmap for a URL (None = not loaded yet).
    pub fn get(&mut self, url: &str) -> Option<Arc<Pixmap>> {
        if url.is_empty() {
            return None;
        }
        if let Some(hit) = self.map.get(url) {
            return hit.clone();
        }
        // Disk mirror?
        let path = self.dir.join(hash_name(url));
        if let Ok(bytes) = std::fs::read(&path) {
            if let Some(pm) = decode_pixmap(&bytes) {
                let arc = Arc::new(pm);
                self.map.insert(url.to_string(), Some(arc.clone()));
                return Some(arc);
            }
        }
        self.map.insert(url.to_string(), None);
        None
    }

    /// Fetch pending images for a page (bounded concurrency). Returns the
    /// URLs that became available this call.
    pub async fn fetch_pending(
        &mut self,
        engine: &Arc<BrowserEngine>,
        wanted: &[String],
    ) -> Vec<String> {
        let mut loaded = Vec::new();
        for url in wanted {
            if url.is_empty() || self.map.contains_key(url) || self.pending.contains(url) {
                continue;
            }
            self.pending.push(url.clone());
            let host = Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string));
            let Some(host) = host else {
                self.map.insert(url.clone(), None);
                continue;
            };
            let Ok(parsed) = Url::parse(url) else {
                continue;
            };
            match engine.fetch_subresource(parsed, ResourceType::IMAGE, &host).await {
                Ok(resp) if resp.status.is_success() && !resp.body.is_empty() => {
                    let path = self.dir.join(hash_name(url));
                    let _ = std::fs::write(&path, &resp.body);
                    if let Some(pm) = decode_pixmap(&resp.body) {
                        self.map.insert(url.clone(), Some(Arc::new(pm)));
                        loaded.push(url.clone());
                    } else {
                        self.map.insert(url.clone(), None);
                    }
                }
                _ => {
                    self.map.insert(url.clone(), None);
                }
            }
            self.pending.retain(|p| p != url);
            if loaded.len() >= 8 {
                break;
            }
        }
        loaded
    }
}

fn hash_name(url: &str) -> String {
    // FNV-1a 64 — no crypto needs, just a stable filename.
    let mut h: u64 = 1469598103934665603;
    for b in url.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("{h:016x}.img")
}

/// Decode PNG/JPEG into a tiny-skia pixmap.
pub fn decode_pixmap(bytes: &[u8]) -> Option<Pixmap> {
    let (w, h, rgba) = if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        decode_png(bytes)?
    } else if bytes.starts_with(&[0xFF, 0xD8][..]) {
        decode_jpeg(bytes)?
    } else {
        return None;
    };
    let mut pm = Pixmap::new(w, h)?;
    pm.pixels_mut().copy_from_slice(&rgba);
    Some(pm)
}

fn decode_png(bytes: &[u8]) -> Option<(u32, u32, Vec<tiny_skia::PremultipliedColorU8>)> {
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().ok()?;
    let size = reader.output_buffer_size()?;
    let mut buf = vec![0u8; size];
    let info = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (info.width, info.height);
    let mut out = Vec::with_capacity((w * h) as usize);
    match info.color_type {
        png::ColorType::Rgba => {
            for px in buf.chunks_exact(4) {
                out.push(tiny_skia::ColorU8::from_rgba(px[0], px[1], px[2], px[3]).premultiply());
            }
        }
        png::ColorType::Rgb => {
            for px in buf.chunks_exact(3) {
                out.push(tiny_skia::ColorU8::from_rgba(px[0], px[1], px[2], 255).premultiply());
            }
        }
        png::ColorType::Grayscale => {
            for px in buf {
                out.push(tiny_skia::ColorU8::from_rgba(px, px, px, 255).premultiply());
            }
        }
        png::ColorType::GrayscaleAlpha => {
            for px in buf.chunks_exact(2) {
                out.push(tiny_skia::ColorU8::from_rgba(px[0], px[0], px[0], px[1]).premultiply());
            }
        }
        png::ColorType::Indexed => return None,
    }
    Some((w, h, out))
}

fn decode_jpeg(bytes: &[u8]) -> Option<(u32, u32, Vec<tiny_skia::PremultipliedColorU8>)> {
    let mut zd = zune_jpeg::JpegDecoder::new(std::io::Cursor::new(bytes));
    let pixels = zd.decode().ok()?;
    let (w, h) = zd.dimensions()?;
    let mut out = Vec::with_capacity(w * h);
    match zd.output_colorspace().unwrap_or(zune_jpeg::zune_core::colorspace::ColorSpace::RGB) {
        zune_jpeg::zune_core::colorspace::ColorSpace::RGB => {
            for px in pixels.chunks_exact(3) {
                out.push(tiny_skia::ColorU8::from_rgba(px[0], px[1], px[2], 255).premultiply());
            }
        }
        zune_jpeg::zune_core::colorspace::ColorSpace::Luma => {
            for px in pixels {
                out.push(tiny_skia::ColorU8::from_rgba(px, px, px, 255).premultiply());
            }
        }
        _ => return None,
    }
    Some((w as u32, h as u32, out))
}
