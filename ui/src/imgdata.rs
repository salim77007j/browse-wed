//! Send-safe RGBA image payload (slint::Image is main-thread-only — the
//! engine/tokio side passes raw pixels, the UI thread converts).

#[derive(Debug, Clone)]
pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    /// RGBA8, premultiplied NOT required (straight alpha).
    pub data: Vec<u8>,
}

impl RgbaImage {
    pub fn new(width: u32, height: u32) -> Self {
        RgbaImage { width, height, data: vec![0; (width * height * 4) as usize] }
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0 || self.data.is_empty()
    }

    /// Convert to a slint image (main thread only).
    pub fn to_slint(&self) -> slint::Image {
        if self.is_empty() {
            return slint::Image::default();
        }
        let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(self.width, self.height);
        buf.make_mut_bytes().copy_from_slice(&self.data);
        slint::Image::from_rgba8(buf)
    }
}
