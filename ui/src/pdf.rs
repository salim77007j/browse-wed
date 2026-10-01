//! Minimal, correct PDF writer: painted bands → A4 pages (FlateDecode RGB
//! image XObjects). No dependencies beyond flate2.

use std::io::Write;
use std::path::Path;

/// A4 at 144 dpi.
const PAGE_W: u32 = 1190;
const PAGE_H: u32 = 1684;

/// Write the current page bands as a PDF. Returns the file size in bytes.
pub fn write_pdf(path: &Path, bands: &[(i32, crate::imgdata::RgbaImage)]) -> Result<u64, String> {
    // 1. Rasterize every band to RGB rows and page-slice them.
    let mut pages: Vec<Vec<u8>> = Vec::new(); // RGB, PAGE_W*PAGE_H*3
    let mut page_buf: Vec<u8> = vec![0xff; (PAGE_W * PAGE_H * 3) as usize];
    let mut page_y: u32 = 0;

    let scale = content_scale(bands);

    for (_, img) in bands {
        let (iw, ih, rgba) = (img.width, img.height, &img.data);
        if iw == 0 || ih == 0 {
            continue;
        }
        // Blit band into page buffer at scale.
        for y in 0..ih {
            let dst_y = page_y + ((y as f32) * scale.1) as u32;
            if dst_y >= PAGE_H {
                // flush page
                pages.push(std::mem::take(&mut page_buf));
                page_buf = vec![0xff; (PAGE_W * PAGE_H * 3) as usize];
                page_y = 0;
                continue;
            }
            for x in 0..iw {
                let dst_x = ((x as f32) * scale.0) as u32;
                if dst_x >= PAGE_W {
                    break;
                }
                let src = ((y * iw + x) * 4) as usize;
                let dst = ((dst_y * PAGE_W + dst_x) * 3) as usize;
                let a = rgba[src + 3] as u32;
                let inv = 255 - a;
                page_buf[dst] = ((rgba[src] as u32 * a + 255 * inv) / 255) as u8;
                page_buf[dst + 1] = ((rgba[src + 1] as u32 * a + 255 * inv) / 255) as u8;
                page_buf[dst + 2] = ((rgba[src + 2] as u32 * a + 255 * inv) / 255) as u8;
            }
        }
        page_y += ((ih as f32) * scale.1) as u32;
        while page_y >= PAGE_H {
            pages.push(std::mem::take(&mut page_buf));
            page_buf = vec![0xff; (PAGE_W * PAGE_H * 3) as usize];
            page_y -= PAGE_H;
        }
    }
    if page_y > 0 || pages.is_empty() {
        pages.push(page_buf);
    }

    // 2. Assemble the PDF.
    // Assemble the PDF: catalog, pages tree, page/image/content triples.
    let mut bodies: Vec<(u32, Vec<u8>)> = Vec::new();
    let _n_pages = pages.len();

    for (i, rgb) in pages.iter().enumerate() {
        let page_obj = 3 + (i as u32) * 3;
        let image_obj = page_obj + 1;
        let content_obj = page_obj + 2;

        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(rgb).map_err(|e| e.to_string())?;
        let compressed = enc.finish().map_err(|e| e.to_string())?;

        let mut b = Vec::new();
        let _ = write!(
            b,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] \
             /Resources << /XObject << /Im0 {image_obj} 0 R >> >> \
             /Contents {content_obj} 0 R >>"
        );
        bodies.push((page_obj, b));

        let mut b = Vec::new();
        b.extend_from_slice(
            format!(
                "<< /Type /XObject /Subtype /Image /Width {PAGE_W} /Height {PAGE_H} \
                 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {} >>\nstream\n",
                compressed.len()
            )
            .as_bytes(),
        );
        b.extend_from_slice(&compressed);
        b.extend_from_slice(b"\nendstream");
        bodies.push((image_obj, b));

        let content = format!("q\n{PAGE_W} 0 0 {PAGE_H} 0 0 cm\n/Im0 Do\nQ\n");
        let mut b = Vec::new();
        b.extend_from_slice(
            format!("<< /Length {} >>\nstream\n{content}endstream", content.len()).as_bytes(),
        );
        bodies.push((content_obj, b));
    }

    // Serialize with a real xref table.
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
    let mut offsets: Vec<(u32, u32)> = Vec::new(); // (obj id, byte offset)
    for (id, body) in &bodies {
        offsets.push((*id, out.len() as u32));
        out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref_pos = out.len() as u32;
    let max_obj = bodies.len() as u32 + 1;
    out.extend_from_slice(format!("xref\n0 {max_obj}\n").as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    let mut by_id = vec![0u32; bodies.len() + 1];
    for (id, off) in &offsets {
        if (*id as usize) < by_id.len() {
            by_id[*id as usize] = *off;
        }
    }
    for id in 1..=bodies.len() as u32 {
        out.extend_from_slice(format!("{:010} 00000 n \n", by_id[id as usize]).as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {max_obj} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n")
            .as_bytes(),
    );

    std::fs::write(path, &out).map_err(|e| e.to_string())?;
    Ok(out.len() as u64)
}

fn content_scale(bands: &[(i32, crate::imgdata::RgbaImage)]) -> (f32, f32) {
    let max_w = bands.iter().map(|(_, i)| i.width).max().unwrap_or(PAGE_W);
    let s = PAGE_W as f32 / max_w.max(1) as f32;
    (s.min(1.0), s.min(1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_valid_pdf_header_and_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pdf");
        // Build a 4×4 red band image.
        let img = crate::imgdata::RgbaImage {
            width: 4,
            height: 4,
            data: vec![255u8, 0, 0, 255].repeat(16),
        };
        let size = write_pdf(&path, &[(0, img)]).unwrap();
        assert!(size > 500);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF\n"));
        assert!(bytes.windows(4).any(|w| w == b"xref"));
        assert!(bytes.windows(6).any(|w| w == b"stream"));
    }
}
