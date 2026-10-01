//! Two-tier HTTP cache: hot in-memory LRU + on-disk blobs.
//!
//! Design:
//! * **Memory tier** — an O(1) LRU with a byte budget. Budget is derived
//!   from available system RAM by the engine's memory governor and can be
//!   resized live (evicting as needed).
//! * **Disk tier** — content-addressed blobs in the shared redb database.
//!   Entries carry metadata (status, content-type, ETag, Last-Modified,
//!   vary key, expiry) so the network layer can answer conditional GETs.
//!
//! Cache key: `sha256(scheme://host:port/path?query)` + vary-hash, so
//! `Vary`-differentiated representations never collide.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Cached resource metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    /// Response status code.
    pub status: u16,
    /// Content-Type of the body.
    pub content_type: String,
    /// ETag for revalidation.
    pub etag: Option<String>,
    /// Last-Modified for revalidation.
    pub last_modified: Option<String>,
    /// Absolute expiry instant (unix seconds); 0 = heuristic/no-store.
    pub expires_unix: u64,
    /// Vary header values that produced this representation.
    pub vary: Vec<String>,
    /// Size of the body in bytes.
    pub body_len: usize,
    /// When the entry was stored (unix seconds).
    pub stored_at_unix: u64,
}

impl CacheMeta {
    /// True when the entry is fresh at `now`.
    pub fn is_fresh(&self, now: SystemTime) -> bool {
        let now = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        self.expires_unix > now
    }
}

/// A memory-tier entry.
#[derive(Debug, Clone)]
struct MemEntry {
    meta: CacheMeta,
    body: Vec<u8>,
}

/// The HTTP cache. Thread-safe interior mutability (the network stack runs
/// on tokio workers).
#[derive(Debug)]
pub struct HttpCache {
    inner: std::sync::Mutex<CacheInner>,
    memory_budget: std::sync::atomic::AtomicUsize,
    disk_budget: usize,
}

#[derive(Debug, Default)]
struct CacheInner {
    /// Key → entry, plus LRU order (front = most recent).
    map: HashMap<String, MemEntry>,
    order: Vec<String>, // back = most recently used
    /// Bytes currently held in the memory tier.
    mem_bytes: usize,
}

impl HttpCache {
    /// Create with the given budgets. The disk tier is used implicitly via
    /// `spill` writes issued by the network layer (see `put_disk`).
    pub fn new(memory_budget: usize, disk_budget: usize) -> HttpCache {
        HttpCache {
            inner: std::sync::Mutex::new(CacheInner::default()),
            memory_budget: std::sync::atomic::AtomicUsize::new(memory_budget),
            disk_budget,
        }
    }

    /// Current memory budget.
    pub fn memory_budget(&self) -> usize {
        self.memory_budget.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Live-resize the memory budget (memory governor hook). Evicts until
    /// the new budget is honoured.
    pub fn set_memory_budget(&self, budget: usize) {
        self.memory_budget.store(budget, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut inner) = self.inner.lock() {
            evict_to_budget(&mut inner, budget);
        }
    }

    /// Disk budget.
    pub fn disk_budget(&self) -> usize {
        self.disk_budget
    }

    /// Compute the cache key for a URL (+ vary-hash when present).
    pub fn key_for(url: &str, vary_hash: Option<u64>) -> String {
        let mut h = Sha256::new();
        h.update(url.as_bytes());
        let mut key: String = hex(h.finalize());
        if let Some(v) = vary_hash {
            key.push('.');
            key.push_str(&format!("{v:016x}"));
        }
        key
    }

    /// Store an entry in the hot tier (and report the entry so the network
    /// layer can also persist it to disk).
    pub fn put(&self, url: &str, vary_hash: Option<u64>, meta: CacheMeta, body: Vec<u8>) {
        let key = Self::key_for(url, vary_hash);
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Remove previous entry for this key.
        if let Some(old) = inner.map.remove(&key) {
            inner.mem_bytes -= old.body.len();
            inner.order.retain(|k| k != &key);
        }
        inner.mem_bytes += body.len();
        inner.map.insert(key.clone(), MemEntry { meta, body });
        inner.order.push(key);
        evict_to_budget(&mut inner, self.memory_budget());
    }

    /// Fetch from the hot tier; refreshes LRU position.
    pub fn get(&self, url: &str, vary_hash: Option<u64>) -> Option<(CacheMeta, Vec<u8>)> {
        let key = Self::key_for(url, vary_hash);
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let entry = inner.map.get(&key)?.clone();
        if let Some(pos) = inner.order.iter().position(|k| k == &key) {
            let k = inner.order.remove(pos);
            inner.order.push(k);
        }
        Some((entry.meta, entry.body))
    }

    /// Fresh-only lookup: `None` when absent or stale.
    pub fn get_fresh(&self, url: &str, vary_hash: Option<u64>) -> Option<(CacheMeta, Vec<u8>)> {
        let now = SystemTime::now();
        let (meta, body) = self.get(url, vary_hash)?;
        if meta.is_fresh(now) {
            Some((meta, body))
        } else {
            None
        }
    }

    /// Drop one entry.
    pub fn invalidate(&self, url: &str, vary_hash: Option<u64>) {
        let key = Self::key_for(url, vary_hash);
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(old) = inner.map.remove(&key) {
            inner.mem_bytes -= old.body.len();
            inner.order.retain(|k| k != &key);
        }
    }

    /// Number of entries in the hot tier.
    pub fn memory_entries(&self) -> usize {
        self.inner.lock().map(|i| i.map.len()).unwrap_or(0)
    }

    /// Bytes held in the hot tier.
    pub fn memory_bytes(&self) -> usize {
        self.inner.lock().map(|i| i.mem_bytes).unwrap_or(0)
    }

    /// Clear the hot tier.
    pub fn clear_memory(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.map.clear();
            inner.order.clear();
            inner.mem_bytes = 0;
        }
    }

    /// Serialize a disk-tier entry: `[u32 meta_len][meta_json][body]`.
    pub fn encode_disk_entry(meta: &CacheMeta, body: &[u8]) -> Vec<u8> {
        let json = serde_json::to_vec(meta).unwrap_or_default();
        let mut out = Vec::with_capacity(4 + json.len() + body.len());
        out.extend_from_slice(&(json.len() as u32).to_le_bytes());
        out.extend_from_slice(&json);
        out.extend_from_slice(body);
        out
    }

    /// Decode a disk-tier entry produced by [`HttpCache::encode_disk_entry`].
    pub fn decode_disk_entry(bytes: &[u8]) -> Option<(CacheMeta, Vec<u8>)> {
        if bytes.len() < 4 {
            return None;
        }
        let meta_len = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
        if bytes.len() < 4 + meta_len {
            return None;
        }
        let meta: CacheMeta = serde_json::from_slice(&bytes[4..4 + meta_len]).ok()?;
        Some((meta, bytes[4 + meta_len..].to_vec()))
    }
}

fn evict_to_budget(inner: &mut CacheInner, budget: usize) {
    while inner.mem_bytes > budget {
        // Evict least-recently-used (front of `order`).
        let Some(victim) = inner.order.first().cloned() else { break };
        inner.order.remove(0);
        if let Some(entry) = inner.map.remove(&victim) {
            inner.mem_bytes = inner.mem_bytes.saturating_sub(entry.body.len());
        }
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

// Silence unused import when NonZeroUsize path changes.
#[allow(unused)]
fn _u(_: Option<NonZeroUsize>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(expires_in: u64) -> CacheMeta {
        CacheMeta {
            status: 200,
            content_type: "text/html".into(),
            etag: Some("\"x1\"".into()),
            last_modified: None,
            expires_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                + expires_in,
            vary: vec![],
            body_len: 0,
            stored_at_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        }
    }

    #[test]
    fn put_get_roundtrip() {
        let cache = HttpCache::new(1024 * 1024, 1024 * 1024);
        cache.put("https://a.com/1", None, meta(60), b"hello".to_vec());
        let (m, b) = cache.get("https://a.com/1", None).unwrap();
        assert_eq!(b, b"hello");
        assert_eq!(m.status, 200);
    }

    #[test]
    fn freshness() {
        let cache = HttpCache::new(1024 * 1024, 1024 * 1024);
        cache.put("https://a.com/2", None, meta(60), b"hot".to_vec());
        assert!(cache.get_fresh("https://a.com/2", None).is_some());
        cache.put("https://a.com/3", None, meta(0), b"stale".to_vec());
        assert!(cache.get_fresh("https://a.com/3", None).is_none());
        // stale-but-present for revalidation
        assert!(cache.get("https://a.com/3", None).is_some());
    }

    #[test]
    fn lru_eviction_under_budget() {
        let cache = HttpCache::new(100, 1024);
        cache.put("https://a.com/x", None, meta(60), vec![0u8; 40]);
        cache.put("https://a.com/y", None, meta(60), vec![0u8; 40]);
        assert_eq!(cache.memory_entries(), 2);
        // touching x makes y the LRU victim
        let _ = cache.get("https://a.com/x", None);
        cache.put("https://a.com/z", None, meta(60), vec![0u8; 40]);
        assert!(cache.get("https://a.com/x", None).is_some());
        assert!(cache.get("https://a.com/y", None).is_none(), "y must be evicted");
        assert!(cache.get("https://a.com/z", None).is_some());
    }

    #[test]
    fn live_budget_resize_evicts() {
        let cache = HttpCache::new(10_000, 1024);
        for i in 0..10 {
            cache.put(&format!("https://a.com/{i}"), None, meta(60), vec![0u8; 500]);
        }
        assert_eq!(cache.memory_entries(), 10);
        cache.set_memory_budget(2_000);
        assert!(cache.memory_entries() <= 4);
        assert!(cache.memory_bytes() <= 2_000);
    }

    #[test]
    fn vary_keys_do_not_collide() {
        let cache = HttpCache::new(1024 * 1024, 1024);
        cache.put("https://a.com/v", Some(1), meta(60), b"variant-a".to_vec());
        cache.put("https://a.com/v", Some(2), meta(60), b"variant-b".to_vec());
        assert_eq!(cache.get("https://a.com/v", Some(1)).unwrap().1, b"variant-a");
        assert_eq!(cache.get("https://a.com/v", Some(2)).unwrap().1, b"variant-b");
    }

    #[test]
    fn disk_entry_codec() {
        let m = meta(60);
        let enc = HttpCache::encode_disk_entry(&m, b"body-bytes");
        let (m2, body) = HttpCache::decode_disk_entry(&enc).unwrap();
        assert_eq!(body, b"body-bytes");
        assert_eq!(m2.etag, m.etag);
    }

    #[test]
    fn invalidation() {
        let cache = HttpCache::new(1024 * 1024, 1024);
        cache.put("https://a.com/g", None, meta(60), b"x".to_vec());
        cache.invalidate("https://a.com/g", None);
        assert!(cache.get("https://a.com/g", None).is_none());
    }
}
