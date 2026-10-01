//! Favicons: fetched through the engine pipeline, decoded (PNG/JPEG),
//! cached in the profile; letter avatars when a site has none. All image
//! data stays raw RGBA (Send-safe) — conversion to slint::Image happens
//! on the UI thread.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bw_engine::BrowserEngine;
use bw_privacy::ResourceType;
use url::Url;

use crate::imgdata::RgbaImage;

/// In-memory favicon cache (decoded RGBA).
pub struct FaviconCache {
    dir: PathBuf,
    map: HashMap<String, Option<RgbaImage>>,
}

impl FaviconCache {
    pub fn new(profile: &std::path::Path) -> Self {
        let dir = profile.join("favicons");
        std::fs::create_dir_all(&dir).ok();
        FaviconCache { dir, map: HashMap::new() }
    }

    /// Synchronous cached lookup.
    pub fn get(&mut self, url: &str) -> Option<RgbaImage> {
        let host = host_of(url)?;
        if let Some(hit) = self.map.get(&host) {
            return hit.clone();
        }
        // disk cache
        let path = self.dir.join(sanitize(&host));
        if let Ok(bytes) = std::fs::read(&path) {
            if let Some(img) = decode_image(&bytes) {
                self.map.insert(host, Some(img.clone()));
                return Some(img);
            }
        }
        None
    }

    /// Store a decoded favicon (disk + memory).
    pub fn store(&mut self, url: &str, bytes: &[u8], img: Option<RgbaImage>) {
        if let Some(host) = host_of(url) {
            let path = self.dir.join(sanitize(&host));
            std::fs::write(&path, bytes).ok();
            self.map.insert(host, img);
        }
    }
}

/// Fetch a site's favicon bytes through the engine (callers store them).
pub async fn fetch_bytes(engine: &Arc<BrowserEngine>, url: &str) -> Option<(Vec<u8>, String)> {
    let host = host_of(url)?;
    let origin = format!("https://{host}");
    let candidates = [format!("{origin}/favicon.ico"), format!("{origin}/favicon.png")];
    for cand in candidates {
        if let Ok(u) = Url::parse(&cand) {
            if let Ok(resp) = engine.fetch_subresource(u, ResourceType::IMAGE, &host).await {
                if resp.status.is_success()
                    && !resp.body.is_empty()
                    && decode_image(&resp.body).is_some()
                {
                    return Some((resp.body.to_vec(), host));
                }
            }
        }
    }
    None
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url).ok().and_then(|u| match u.host_str() {
        Some(h) if !h.is_empty() => Some(h.to_string()),
        _ => None,
    })
}

fn sanitize(host: &str) -> String {
    host.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

fn host_color(host: &str) -> (u8, u8, u8) {
    let mut h: u32 = 2166136261;
    for b in host.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(16777619);
    }
    let hue = (h % 360) as f32;
    hsl_to_rgb(hue, 0.55, 0.45)
}

fn hsl_to_rgb(h: f32, s: f32, l: f32) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let hp = h / 60.0;
    let x = c * (1.0 - (hp % 2.0 - 1.0).abs());
    let (r1, g1, b1) = match hp as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    (((r1 + m) * 255.0) as u8, ((g1 + m) * 255.0) as u8, ((b1 + m) * 255.0) as u8)
}

/// Deterministic letter avatar (initial on tinted background), 32×32 RGBA.
pub fn letter(url: &str) -> RgbaImage {
    let host = host_of(url).unwrap_or_else(|| "?".into());
    let initial = host.chars().next().unwrap_or('?').to_uppercase().next().unwrap_or('?');
    let (r, g, b) = host_color(&host);
    let mut img = RgbaImage::new(32, 32);
    for px in img.data.chunks_exact_mut(4) {
        px[0] = r;
        px[1] = g;
        px[2] = b;
        px[3] = 255;
    }
    let glyph = glyph_bitmap(initial);
    let (lw, lh) = (glyph.0.len() as i64, glyph.1 as i64);
    let ox = ((32 - lw) / 2).max(0) as usize;
    let oy = ((32 - lh) / 2).max(0) as usize;
    for (i, row) in glyph.0.iter().enumerate() {
        for (j, &on) in row.iter().enumerate() {
            if !on {
                continue;
            }
            let x = ox + j;
            let y = oy + i;
            if x < 32 && y < 32 {
                let idx = (y * 32 + x) * 4;
                let px = &mut img.data[idx..idx + 4];
                px[0] = 255;
                px[1] = 255;
                px[2] = 255;
                px[3] = 255;
            }
        }
    }
    img
}

/// Decode PNG or JPEG into raw RGBA.
pub fn decode_image(bytes: &[u8]) -> Option<RgbaImage> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
        let mut reader = decoder.read_info().ok()?;
        let size = reader.output_buffer_size()?;
        let mut buf = vec![0u8; size];
        let info = reader.next_frame(&mut buf).ok()?;
        let (w, h) = (info.width, info.height);
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        match info.color_type {
            png::ColorType::Rgba => rgba.extend_from_slice(&buf[..(w * h * 4) as usize]),
            png::ColorType::Rgb => {
                for px in buf.chunks_exact(3) {
                    rgba.extend_from_slice(&[px[0], px[1], px[2], 255]);
                }
            }
            png::ColorType::Grayscale => {
                for px in buf {
                    rgba.extend_from_slice(&[px, px, px, 255]);
                }
            }
            png::ColorType::GrayscaleAlpha => {
                for px in buf.chunks_exact(2) {
                    rgba.extend_from_slice(&[px[0], px[0], px[0], px[1]]);
                }
            }
            png::ColorType::Indexed => return None,
        }
        Some(RgbaImage { width: w, height: h, data: rgba })
    } else if bytes.starts_with(&[0xFF, 0xD8][..]) {
        let mut zd = zune_jpeg::JpegDecoder::new(std::io::Cursor::new(bytes));
        let pixels = zd.decode().ok()?;
        let (w, h) = zd.dimensions()?;
        let mut rgba = Vec::with_capacity(w * h * 4);
        match zd.output_colorspace().unwrap_or(zune_jpeg::zune_core::colorspace::ColorSpace::RGB) {
            zune_jpeg::zune_core::colorspace::ColorSpace::RGB => {
                for px in pixels.chunks_exact(3) {
                    rgba.extend_from_slice(&[px[0], px[1], px[2], 255]);
                }
            }
            zune_jpeg::zune_core::colorspace::ColorSpace::Luma => {
                for px in pixels {
                    rgba.extend_from_slice(&[px, px, px, 255]);
                }
            }
            _ => return None,
        }
        Some(RgbaImage { width: w as u32, height: h as u32, data: rgba })
    } else {
        None
    }
}

/// 5×7 bitmap font for letter avatars (uppercase + digits).
fn glyph_bitmap(c: char) -> (Vec<Vec<bool>>, usize) {
    const F: [&str; 26] = [
        "01110,10001,10001,10001,10001,10001,01110", // A
        "11110,10001,10001,11110,10001,10001,11110", // B
        "01110,10001,10000,10000,10000,10001,01110", // C
        "11110,10001,10001,10001,10001,10001,11110", // D
        "11111,10000,10000,11110,10000,10000,11111", // E
        "11111,10000,10000,11110,10000,10000,10000", // F
        "01110,10001,10000,10111,10001,10001,01111", // G
        "10001,10001,10001,11111,10001,10001,10001", // H
        "01110,00100,00100,00100,00100,00100,01110", // I
        "00111,00010,00010,00010,00010,10010,01100", // J
        "10001,10010,10100,11000,10100,10010,10001", // K
        "10000,10000,10000,10000,10000,10000,11111", // L
        "10001,11011,10101,10101,10001,10001,10001", // M
        "10001,11001,10101,10011,10001,10001,10001", // N
        "01110,10001,10001,10001,10001,10001,01110", // O
        "11110,10001,10001,11110,10000,10000,10000", // P
        "01110,10001,10001,10001,10101,10011,01111", // Q
        "11110,10001,10001,11110,10100,10010,10001", // R
        "01111,10000,10000,01110,00001,00001,11110", // S
        "11111,00100,00100,00100,00100,00100,00100", // T
        "10001,10001,10001,10001,10001,10001,01110", // U
        "10001,10001,10001,10001,10001,01010,00100", // V
        "10001,10001,10001,10101,10101,11011,10001", // W
        "10001,10001,01010,00100,01010,10001,10001", // X
        "10001,10001,01010,00100,00100,00100,00100", // Y
        "11111,00001,00010,00100,01000,10000,11111", // Z
    ];
    if c.is_ascii_digit() {
        const D: [&str; 10] = [
            "01110,10001,10011,10101,11001,10001,01110",
            "00100,01100,00100,00100,00100,00100,01110",
            "01110,10001,00001,00110,01000,10000,11111",
            "11110,00001,00001,01110,00001,00001,11110",
            "00010,00110,01010,10010,11111,00010,00010",
            "11111,10000,10000,11110,00001,00001,11110",
            "01110,10000,10000,11110,10001,10001,01110",
            "11111,00001,00010,00100,01000,01000,01000",
            "01110,10001,10001,01110,10001,10001,01110",
            "01110,10001,10001,01111,00001,00001,01110",
        ];
        let rows: Vec<Vec<bool>> = D[c as usize - '0' as usize]
            .split(',')
            .map(|r| r.chars().map(|ch| ch == '1').collect())
            .collect();
        return (rows, 5);
    }
    let upper = c.to_ascii_uppercase();
    let idx = (upper as u32).checked_sub('A' as u32).map(|i| i as usize);
    match idx {
        Some(i) if i < 26 => {
            let rows: Vec<Vec<bool>> =
                F[i].split(',').map(|r| r.chars().map(|ch| ch == '1').collect()).collect();
            (rows, 5)
        }
        _ => (vec![vec![true; 5]; 7], 5),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_avatar_is_32px() {
        let img = letter("https://example.com");
        assert_eq!(img.width, 32);
        assert_eq!(img.height, 32);
        assert_eq!(img.data.len(), 32 * 32 * 4);
    }

    #[test]
    fn host_colors_differ() {
        let a = host_color("wikipedia.org");
        let b = host_color("github.com");
        assert_ne!(a, b);
    }

    #[test]
    fn decodes_png() {
        // Encode a real 3×2 RGB PNG with the encoder.
        let mut buf = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut buf, 3, 2);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            let mut writer = enc.write_header().unwrap();
            writer
                .write_image_data(&[
                    200, 30, 40, 10, 20, 30, 1, 2, 3, 4, 5, 6, 7, 8, 9, 250, 251, 252,
                ])
                .unwrap();
        }
        let img = decode_image(&buf).unwrap();
        assert_eq!(img.width, 3);
        assert_eq!(img.height, 2);
        assert_eq!(img.data.len(), 3 * 2 * 4);
        assert_eq!(&img.data[..3], &[200, 30, 40]);
    }
}
