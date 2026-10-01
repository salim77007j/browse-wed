//! Privacy-preserving Safe Browsing.
//!
//! Design goals:
//! 1. **No URL egress.** The device never sends a full URL to any update
//!    server; only fixed-length SHA-256 *prefixes* (4 bytes) leave the
//!    device, and full-hash confirmation happens locally.
//! 2. **O(1) memory-bound checks.** A Bloom filter sized by the threat-list
//!    budget answers "possibly bad" in nanoseconds; a local full-hash set
//!    resolves false positives without any network round-trip.
//! 3. **Deterministic construction** so fuzzing can validate the filter.
//!
//! Update model (Safe Browsing v4-shaped, provider-agnostic): the caller
//! periodically downloads a prefix list (from any provider URL the user
//! configured — including a self-hosted mirror), calls
//! [`SafeBrowsingDb::apply_prefixes`], and stores the serialized database
//! on disk via [`SafeBrowsingDb::to_bytes`] / [`from_bytes`].

use std::collections::HashSet;
use std::hash::Hasher;

use sha2::{Digest, Sha256};
use siphasher::sip::SipHasher13;

/// Verdict for a URL check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not in any threat list.
    Safe,
    /// Prefix matched the Bloom filter AND the full hash is known-bad.
    Threat,
    /// Prefix matched the Bloom filter but no full hash confirms it
    /// (unknown threat, or Bloom false positive).
    Unverified,
}

/// A standard Bloom filter with SipHash-derived double hashing.
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
    key0: [u64; 2],
    key1: [u64; 2],
}

impl BloomFilter {
    /// Generate a random key pair for double hashing.
    fn random_pair() -> [u64; 2] {
        let mut b = [0u8; 16];
        if getrandom::fill(&mut b).is_err() {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x1234_5678);
            return [t, t.rotate_left(17) ^ 0x9E37_79B9];
        }
        let lo = u64::from_le_bytes(b[..8].try_into().unwrap());
        let hi = u64::from_le_bytes(b[8..].try_into().unwrap());
        [lo, hi]
    }
    /// Create a filter sized for `expected_items` with the given false
    /// positive probability.
    pub fn with_rate(expected_items: usize, fp_rate: f64) -> BloomFilter {
        let m = optimal_bits(expected_items, fp_rate);
        let k = optimal_hashes(m, expected_items);
        BloomFilter {
            bits: vec![0u64; m.div_ceil(64)],
            num_bits: m,
            num_hashes: k,
            key0: Self::random_pair(),
            key1: Self::random_pair(),
        }
    }

    fn indexes(&self, data: &[u8], out: &mut Vec<usize>) {
        let mut h0 = SipHasher13::new_with_keys(self.key0[0], self.key0[1]);
        h0.write(data);
        let h1v = {
            let mut h1 = SipHasher13::new_with_keys(self.key1[0], self.key1[1]);
            h1.write(data);
            h1.finish()
        };
        let h0v = h0.finish();
        for i in 0..self.num_hashes as u64 {
            let idx = (h0v.wrapping_add(i.wrapping_mul(h1v))) % self.num_bits as u64;
            out.push(idx as usize);
        }
    }

    /// Insert an item.
    pub fn insert(&mut self, data: &[u8]) {
        let mut idx = Vec::with_capacity(self.num_hashes as usize);
        self.indexes(data, &mut idx);
        for i in idx {
            self.bits[i / 64] |= 1u64 << (i % 64);
        }
    }

    /// Membership test.
    pub fn contains(&self, data: &[u8]) -> bool {
        let mut idx = Vec::with_capacity(self.num_hashes as usize);
        self.indexes(data, &mut idx);
        idx.iter().all(|&i| self.bits[i / 64] & (1u64 << (i % 64)) != 0)
    }

    /// Number of set bits (for diagnostics).
    pub fn bits_set(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Serialize: layout is `[num_bits u64][num_hashes u32][key0 2×u64][key1 2×u64][bits]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 * 5 + 4 + self.bits.len() * 8);
        out.extend_from_slice(&(self.num_bits as u64).to_le_bytes());
        out.extend_from_slice(&self.num_hashes.to_le_bytes());
        out.extend_from_slice(&self.key0[0].to_le_bytes());
        out.extend_from_slice(&self.key0[1].to_le_bytes());
        out.extend_from_slice(&self.key1[0].to_le_bytes());
        out.extend_from_slice(&self.key1[1].to_le_bytes());
        for w in &self.bits {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Deserialize a filter produced by [`BloomFilter::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Option<BloomFilter> {
        if bytes.len() < 44 {
            return None;
        }
        let num_bits = u64::from_le_bytes(bytes[..8].try_into().ok()?) as usize;
        let num_hashes = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let mut off = 12;
        let mut keys = [[0u64; 2]; 2];
        for key in &mut keys {
            key[0] = u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?);
            key[1] = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().ok()?);
            off += 16;
        }
        let n_words = num_bits.div_ceil(64);
        // Strict: the filter must consume the buffer exactly, otherwise the
        // trailing bytes belong to another section and this split is wrong.
        if bytes.len() != off + n_words * 8 {
            return None;
        }
        let mut bits = Vec::with_capacity(n_words);
        for i in 0..n_words {
            let s = off + i * 8;
            bits.push(u64::from_le_bytes(bytes[s..s + 8].try_into().ok()?));
        }
        Some(BloomFilter {
            bits,
            num_bits,
            num_hashes,
            key0: keys[0],
            key1: keys[1],
        })
    }
}

fn optimal_bits(n: usize, fp: f64) -> usize {
    let m = -(n as f64 * fp.ln()) / (2.0f64.ln().powi(2));
    m.max(64.0).ceil() as usize
}

fn optimal_hashes(m: usize, n: usize) -> u32 {
    if n == 0 {
        return 3;
    }
    let k = (m as f64 / n as f64) * 2.0f64.ln();
    k.clamp(1.0, 16.0).round() as u32
}

/// The local Safe Browsing database.
pub struct SafeBrowsingDb {
    bloom: BloomFilter,
    /// Sizing retained so `apply_prefixes` can rebuild the filter.
    prefix_count: usize,
    fp_rate: f64,
    /// Full 32-byte hashes confirming threats.
    full_hashes: HashSet<[u8; 32]>,
}

impl Default for SafeBrowsingDb {
    fn default() -> Self {
        Self::new(50_000, 0.01)
    }
}

impl SafeBrowsingDb {
    /// Create an empty database sized for `prefix_count` entries.
    pub fn new(prefix_count: usize, fp_rate: f64) -> SafeBrowsingDb {
        SafeBrowsingDb {
            bloom: BloomFilter::with_rate(prefix_count.max(1), fp_rate),
            prefix_count: prefix_count.max(1),
            fp_rate,
            full_hashes: HashSet::new(),
        }
    }

    /// Replace the threat prefix set (4-byte SHA-256 prefixes of canonical
    /// URL forms). This is what an update download delivers.
    pub fn apply_prefixes(&mut self, prefixes: impl IntoIterator<Item = [u8; 4]>) {
        let mut bloom = BloomFilter::with_rate(self.prefix_count, self.fp_rate);
        for p in prefixes {
            bloom.insert(&p);
        }
        self.bloom = bloom;
    }

    /// Add a confirmed full hash locally (from a threat feed or incident).
    pub fn add_full_hash(&mut self, full: [u8; 32]) {
        self.full_hashes.insert(full);
    }

    /// Check a URL. Prefixes use the canonicalized host+path form.
    pub fn check(&self, url: &str) -> Verdict {
        let canon = canonicalize(url);
        let mut hasher = Sha256::new();
        hasher.update(canon.as_bytes());
        let full: [u8; 32] = hasher.finalize().into();
        if self.full_hashes.contains(&full) {
            return Verdict::Threat;
        }
        let prefix: [u8; 4] = full[..4].try_into().expect("32-byte hash");
        if self.bloom.contains(&prefix) {
            Verdict::Unverified
        } else {
            Verdict::Safe
        }
    }

    /// Serialize the whole database.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.bloom.to_bytes();
        out.extend_from_slice(&(self.prefix_count as u64).to_le_bytes());
        out.extend_from_slice(&self.fp_rate.to_le_bytes());
        out.extend_from_slice(&(self.full_hashes.len() as u64).to_le_bytes());
        for h in &self.full_hashes {
            out.extend_from_slice(h);
        }
        out
    }

    /// Deserialize a database produced by [`SafeBrowsingDb::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Option<SafeBrowsingDb> {
        // Layout: [bloom (variable)][prefix_count u64][fp_rate u64][count u64][hashes].
        // Find the split where a valid Bloom prefix meets a consistent tail.
        for split in (0..bytes.len()).rev() {
            let tail = &bytes[split..];
            if tail.len() < 24 {
                continue;
            }
            let n64 = u64::from_le_bytes(tail[16..24].try_into().expect("8-byte slice"));
            let n = n64 as usize;
            let Some(expected_len) = 24usize.checked_add(32usize.saturating_mul(n)) else {
                continue;
            };
            if tail.len() != expected_len {
                continue;
            }
            let prefix_count = u64::from_le_bytes(tail[..8].try_into().ok()?);
            let fp_bits = u64::from_le_bytes(tail[8..16].try_into().ok()?);
            let fp_rate = f64::from_le_bytes(fp_bits.to_le_bytes());
            let Some(bloom) = BloomFilter::from_bytes(&bytes[..split]) else {
                continue;
            };
            let mut full_hashes = HashSet::new();
            let mut ok = true;
            for i in 0..n {
                let s = 24 + i * 32;
                match tail[s..s + 32].try_into() {
                    Ok(h) => full_hashes.insert(h),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                };
            }
            if ok {
                return Some(SafeBrowsingDb {
                    bloom,
                    prefix_count: prefix_count as usize,
                    fp_rate,
                    full_hashes,
                });
            }
        }
        None
    }
}

/// Safe-Browsing-style URL canonicalization: lowercase scheme+host, strip
/// fragment, drop common tracking params is *not* part of v4 (it matches
/// paths exactly) — we follow v4 semantics: lowercase host, remove trailing
/// dot, resolve `.`/`..` in path, strip fragment, percent-normalize escapes.
pub fn canonicalize(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase() + "://", r),
        None => ("http://".to_string(), url),
    };
    let (hostport, pathq) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (mut host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_ascii_lowercase(), Some(p.to_string()))
        }
        _ => (hostport.to_ascii_lowercase(), None),
    };
    if host.ends_with('.') {
        host.pop();
    }
    let path = normalize_path(pathq.split('#').next().unwrap_or(pathq));
    let port = port.filter(|p| !is_default_port(&scheme, p));
    let authority = match port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    format!("{scheme}{authority}{path}")
}

fn is_default_port(scheme: &str, port: &str) -> bool {
    (scheme == "http://" && port == "80") || (scheme == "https://" && port == "443")
}

fn normalize_path(pathq: &str) -> String {
    let (path, query) = match pathq.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (pathq, None),
    };
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = segments.join("/");
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    match query {
        Some(q) => format!("{out}?{q}"),
        None => out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloom_roundtrip() {
        let mut bf = BloomFilter::with_rate(1000, 0.01);
        for i in 0..1000u32 {
            bf.insert(&i.to_le_bytes());
        }
        let ser = bf.to_bytes();
        let bf2 = BloomFilter::from_bytes(&ser).expect("deserialize");
        for i in 0..1000u32 {
            assert!(bf2.contains(&i.to_le_bytes()), "item {i} lost in roundtrip");
        }
    }

    #[test]
    fn bloom_fp_rate_sane() {
        let mut bf = BloomFilter::with_rate(10_000, 0.01);
        for i in 0..10_000u64 {
            bf.insert(&i.to_le_bytes());
        }
        let fp = (0..10_000u64)
            .filter(|i| bf.contains(&(i + 1_000_000).to_le_bytes()))
            .count();
        assert!(fp < 300, "false positives too high: {fp}/10000");
    }

    #[test]
    fn db_flow() {
        let mut db = SafeBrowsingDb::new(1000, 0.01);
        let bad = "https://malware.example.net/payload";
        let prefix: [u8; 4] = {
            let mut h = Sha256::new();
            h.update(bad);
            let full: [u8; 32] = h.finalize().into();
            full[..4].try_into().unwrap()
        };
        db.apply_prefixes([prefix]);
        assert_eq!(db.check(bad), Verdict::Unverified);
        let mut h = Sha256::new();
        h.update(bad);
        let full: [u8; 32] = h.finalize().into();
        db.add_full_hash(full);
        assert_eq!(db.check(bad), Verdict::Threat);
        assert_eq!(db.check("https://good.example.org/"), Verdict::Safe);
    }

    #[test]
    fn db_serialization() {
        let mut db = SafeBrowsingDb::new(100, 0.05);
        let bad = "http://phish.example.com/login";
        let mut h = Sha256::new();
        h.update(bad);
        let full: [u8; 32] = h.finalize().into();
        db.apply_prefixes([full[..4].try_into().unwrap()]);
        db.add_full_hash(full);
        let bytes = db.to_bytes();
        let db2 = SafeBrowsingDb::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(db2.check(bad), Verdict::Threat);
    }

    #[test]
    fn canonicalization_rules() {
        assert_eq!(
            canonicalize("HTTPS://Example.COM./a/./b/../c"),
            "https://example.com/a/c"
        );
        assert_eq!(
            canonicalize("http://example.com:80/x#frag"),
            "http://example.com/x"
        );
        assert_eq!(
            canonicalize("https://example.com:8443/x"),
            "https://example.com:8443/x"
        );
        assert_eq!(canonicalize("example.com"), "http://example.com/");
    }
}
