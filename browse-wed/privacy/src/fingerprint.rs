//! Anti-fingerprinting policy engine.
//!
//! Threat model: fingerprinting scripts aggregate dozens of high-entropy
//! signals (canvas pixels, audio buffers, WebGL strings, font lists, screen
//! geometry, navigator properties, timezone). Blocking values outright
//! breaks sites; returning *random* values every call breaks the site AND
//! creates a super-cookie. The state-of-the-art compromise — used here — is
//! **session-keyed per-site farbling**:
//!
//! * one 128-bit `session_key` is generated at browser start;
//! * every site receives `seed = SipHash13(session_key, site)`;
//! * the seed drives deterministic perturbation of canvas/audio pixels,
//!   and picks values from curated low-entropy sets (WebGL strings, screen
//!   sizes, hardware concurrency...);
//!
//! Consequences:
//! * a site sees a *stable* fingerprint within the session (sites work),
//! * different sites see *different* fingerprints (cross-site joins fail),
//! * next session the fingerprint changes (long-term linkability fails),
//! * the fingerprint is shared by every user of the engine
//!   (herd immunity — the Brave/Firefox-RFP strategy).
//!
//! The engine only computes *policies and values*. The JS/DOM bindings that
//! inject them live in `bw-js` / `bw-render`, keeping this crate pure and
//! unit-testable.

use std::hash::Hasher;

use siphasher::sip::SipHasher13;

/// Global fingerprinting protection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum FpMode {
    /// Every protection enabled. Maximum unlinkability.
    Strict,
    /// Canvas/audio farbling + navigator clamps (default).
    #[default]
    Balanced,
    /// Protections off (user explicitly allowed fingerprinting).
    Off,
}

/// WebRTC IP-leak policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum WebRtcPolicy {
    /// WebRTC fully disabled.
    Disable,
    /// mDNS candidates only — local IPs never exposed (default, 2026 norm).
    #[default]
    MaskLocal,
    /// Default browser behaviour.
    Allow,
}

/// What the engine reports to JS for `navigator`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NavigatorReport {
    /// Clamped `navigator.hardwareConcurrency`.
    pub hardware_concurrency: u32,
    /// Clamped `navigator.deviceMemory` (GiB).
    pub device_memory: u32,
    /// `navigator.platform`.
    pub platform: &'static str,
    /// Whether `navigator.getBattery` is exposed.
    pub battery_api: bool,
}

/// Curated low-entropy screen sizes (standard display buckets).
const SCREEN_SIZES: [(u32, u32); 12] = [
    (1280, 720),
    (1366, 768),
    (1440, 900),
    (1536, 864),
    (1600, 900),
    (1680, 1050),
    (1920, 1080),
    (1920, 1200),
    (2560, 1440),
    (2560, 1600),
    (2880, 1800),
    (3840, 2160),
];

/// Common WebGL vendor/renderer pairs (unified GPU class reporting).
const WEBGL_STRINGS: [(&str, &str); 4] = [
    ("Intel Inc.", "Intel Iris OpenGL Engine"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E92) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
];

/// Font allowlist — the ~40 fonts present on ≥ 95% of desktop systems.
pub const FONT_ALLOWLIST: &[&str] = &[
    "Arial", "Arial Black", "Arial Narrow", "Bahnschrift", "Calibri", "Cambria", "Candara",
    "Comic Sans MS", "Consolas", "Constantia", "Corbel", "Courier New", "Ebrima", "Franklin Gothic",
    "Gabriola", "Gadugi", "Georgia", "Impact", "Ink Free", "Javanese Text", "Leelawadee UI",
    "Lucida Console", "Lucida Sans Unicode", "Malgun Gothic", "Marlett", "Microsoft Himalaya",
    "Microsoft JhengHei", "Microsoft New Tai Lue", "Microsoft Sans Serif", "Microsoft YaHei",
    "MingLiU-ExtB", "Mongolian Baiti", "MS Gothic", "MV Boli", "Myanmar Text", "Nirmala UI",
    "Palatino Linotype", "Segoe Print", "Segoe Script", "Segoe UI", "SimSun", "Sitka",
    "Sylfaen", "Symbol", "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana", "Webdings",
    "Wingdings", "Yu Gothic",
];

/// The fingerprinting policy engine.
pub struct FpEngine {
    session_key: [u8; 16],
    mode: FpMode,
    webrtc: WebRtcPolicy,
    /// Real hardware concurrency (clamped at reporting time).
    real_cores: u32,
    /// Real installed memory in GiB (clamped at reporting time).
    real_memory_gib: u32,
}

impl Default for FpEngine {
    fn default() -> Self {
        let mut session_key = [0u8; 16];
        // Never fails on supported platforms; fall back to time+address mix.
        if getrandom::fill(&mut session_key).is_err() {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            session_key[..8].copy_from_slice(&t.to_le_bytes());
            let a = &session_key as *const _ as usize;
            session_key[8..].copy_from_slice(&(a as u64).to_le_bytes());
        }
        Self::from_key(session_key)
    }
}

impl FpEngine {
    /// Deterministic engine (for tests and reproducible sessions).
    pub fn from_key(session_key: [u8; 16]) -> FpEngine {
        FpEngine {
            session_key,
            mode: FpMode::Balanced,
            webrtc: WebRtcPolicy::MaskLocal,
            real_cores: 4,
            real_memory_gib: 8,
        }
    }

    /// Set the protection mode.
    pub fn set_mode(&mut self, mode: FpMode) {
        self.mode = mode;
    }

    /// Current protection mode.
    pub fn mode(&self) -> FpMode {
        self.mode
    }

    /// Set the WebRTC policy.
    pub fn set_webrtc_policy(&mut self, p: WebRtcPolicy) {
        self.webrtc = p;
    }

    /// Current WebRTC policy.
    pub fn webrtc_policy(&self) -> WebRtcPolicy {
        self.webrtc
    }

    /// Feed the engine real hardware facts (from the platform layer).
    pub fn set_hardware_facts(&mut self, cores: u32, memory_gib: u32) {
        self.real_cores = cores.max(1);
        self.real_memory_gib = memory_gib.max(1);
    }

    /// Per-site farbling seed.
    fn seed(&self, site: &str) -> u64 {
        let mut h = SipHasher13::new();
        h.write(&self.session_key);
        h.write(site.as_bytes());
        h.finish()
    }

    /// Farble raw canvas pixel data in place: perturb the low bits of every
    /// channel by ±1..3. Mirrors Brave's canvas farbling: visually
    /// imperceptible, breaks pixel-exact hashing.
    pub fn farble_canvas(&self, site: &str, pixels: &mut [u8]) {
        if self.mode == FpMode::Off {
            return;
        }
        let mut rng = SplitMix64::new(self.seed(site) ^ 0xCA04E5);
        for px in pixels.iter_mut() {
            // per-channel perturbation in [-3, 3]
            let delta = (rng.next_u64() % 7) as i8 - 3;
            let v = *px as i16 + delta as i16;
            *px = v.clamp(0, 255) as u8;
        }
    }

    /// Farble audio sample data in place: add tiny centred noise
    /// (~-80 dBFS) that defeats exact-buffer hashing while staying
    /// inaudible.
    pub fn farble_audio(&self, site: &str, samples: &mut [f32]) {
        if self.mode == FpMode::Off {
            return;
        }
        let mut rng = SplitMix64::new(self.seed(site) ^ 0xA0D10);
        for s in samples.iter_mut() {
            let noise = (rng.next_u64() % 1000) as f32 / 1000.0 - 0.5; // [-0.5, 0.5)
            *s += noise * 1e-4;
        }
    }

    /// WebGL UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL pair, stable per
    /// site, drawn from the curated hardware-class list.
    pub fn webgl_strings(&self, site: &str) -> (&'static str, &'static str) {
        if self.mode == FpMode::Off {
            return ("", "");
        }
        let idx = (self.seed(site) % WEBGL_STRINGS.len() as u64) as usize;
        WEBGL_STRINGS[idx]
    }

    /// Navigator report for the given site.
    pub fn navigator(&self, site: &str) -> NavigatorReport {
        if self.mode == FpMode::Off {
            return NavigatorReport {
                hardware_concurrency: self.real_cores,
                device_memory: self.real_memory_gib,
                platform: "Win32",
                battery_api: true,
            };
        }
        // Clamp to the mode-aware ceilings: Strict reports the herd value,
        // Balanced clamps to plausible ceilings.
        let (cores, mem) = match self.mode {
            FpMode::Strict => (2, 4),
            _ => (self.real_cores.min(8), self.real_memory_gib.min(8)),
        };
        let platform = if self.mode == FpMode::Strict {
            "Win32"
        } else {
            match self.seed(site) % 3 {
                0 => "Win32",
                1 => "MacIntel",
                _ => "Linux x86_64",
            }
        };
        NavigatorReport {
            hardware_concurrency: cores,
            device_memory: mem,
            platform,
            battery_api: false,
        }
    }

    /// Snap screen dimensions to the nearest curated bucket.
    pub fn screen(&self, w: u32, h: u32) -> (u32, u32) {
        if self.mode == FpMode::Off {
            return (w, h);
        }
        // nearest bucket by area
        SCREEN_SIZES
            .iter()
            .min_by_key(|&(bw, bh)| {
                let dw = bw.abs_diff(w);
                let dh = bh.abs_diff(h);
                (dw as u64) * (dw as u64) + (dh as u64) * (dh as u64)
            })
            .copied()
            .unwrap_or((1920, 1080))
    }

    /// Timezone policy: report a bucketed offset string rather than the
    /// precise local zone when in Strict mode.
    pub fn timezone(&self, local: &str) -> String {
        match self.mode {
            FpMode::Off => local.to_string(),
            FpMode::Strict => "UTC".to_string(),
            FpMode::Balanced => local.to_string(),
        }
    }

    /// Fonts visible to `queryLocalFonts` / measurement probes.
    pub fn fonts(&self) -> &'static [&'static str] {
        if self.mode == FpMode::Off {
            // Not truly "all fonts" — an exhaustive list is platform-specific;
            // Off mode is handled by the renderer not intercepting at all.
            FONT_ALLOWLIST
        } else {
            FONT_ALLOWLIST
        }
    }
}

/// SplitMix64 — tiny, high-quality deterministic PRNG for farbling streams.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn farbling_is_deterministic_per_site() {
        let eng = FpEngine::from_key([7u8; 16]);
        let mut a = vec![100u8; 256];
        let mut b = vec![100u8; 256];
        eng.farble_canvas("example.com", &mut a);
        eng.farble_canvas("example.com", &mut b);
        assert_eq!(a, b, "same site must see identical farbling");
    }

    #[test]
    fn farbling_differs_across_sites() {
        let eng = FpEngine::from_key([7u8; 16]);
        let mut a = vec![100u8; 256];
        let mut b = vec![100u8; 256];
        eng.farble_canvas("example.com", &mut a);
        eng.farble_canvas("tracker.io", &mut b);
        assert_ne!(a, b, "cross-site linkability must fail");
    }

    #[test]
    fn farbling_changes_across_sessions() {
        let e1 = FpEngine::from_key([1u8; 16]);
        let e2 = FpEngine::from_key([2u8; 16]);
        let mut a = vec![100u8; 256];
        let mut b = vec![100u8; 256];
        e1.farble_canvas("example.com", &mut a);
        e2.farble_canvas("example.com", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn farbling_stays_imperceptible() {
        let eng = FpEngine::from_key([9u8; 16]);
        let mut px = vec![128u8; 4096];
        eng.farble_canvas("example.com", &mut px);
        for v in px {
            assert!((v as i32 - 128).abs() <= 3, "perturbation must stay in LSBs");
        }
    }

    #[test]
    fn mode_off_is_transparent() {
        let mut eng = FpEngine::from_key([3u8; 16]);
        eng.set_mode(FpMode::Off);
        let mut px = vec![128u8; 64];
        eng.farble_canvas("example.com", &mut px);
        assert!(px.iter().all(|&v| v == 128));
    }

    #[test]
    fn audio_noise_is_tiny() {
        let eng = FpEngine::from_key([5u8; 16]);
        let mut s = vec![0.5f32; 512];
        eng.farble_audio("example.com", &mut s);
        for v in s {
            assert!((v - 0.5).abs() < 1e-4 + 1e-6);
        }
    }

    #[test]
    fn webgl_strings_stable_per_site() {
        let eng = FpEngine::from_key([4u8; 16]);
        let a = eng.webgl_strings("example.com");
        let b = eng.webgl_strings("example.com");
        assert_eq!(a, b);
        let c = eng.webgl_strings("other.org");
        // Different site *may* collide (small curated list) but the pair is
        // always one of the curated entries.
        assert!(WEBGL_STRINGS.contains(&c));
    }

    #[test]
    fn navigator_clamped() {
        let mut eng = FpEngine::from_key([6u8; 16]);
        eng.set_hardware_facts(32, 64);
        let nav = eng.navigator("x.com");
        assert!(nav.hardware_concurrency <= 8);
        assert!(nav.device_memory <= 8);
        eng.set_mode(FpMode::Strict);
        let nav = eng.navigator("x.com");
        assert_eq!(nav.hardware_concurrency, 2);
        assert_eq!(nav.device_memory, 4);
        assert!(!nav.battery_api);
    }

    #[test]
    fn screen_snaps_to_buckets() {
        let eng = FpEngine::from_key([8u8; 16]);
        let (w, h) = eng.screen(1927, 1081);
        assert_eq!((w, h), (1920, 1080));
        let (w, h) = eng.screen(2570, 1444);
        assert_eq!((w, h), (2560, 1440));
    }
}
