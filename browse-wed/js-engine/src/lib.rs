//! The engine-level JS manager: per-origin runtime registry with LRU
//! eviction and suspension, owned by a dedicated worker thread.
//!
//! The registry enforces the memory promises of the engine:
//!
//! * **Bounded live runtimes** — an LRU (`max_live_runtimes`, default 8)
//!   drops the least-recently-used site runtime when a new one is needed;
//!   dropping a QuickJS runtime frees its entire heap in one call.
//! * **Explicit suspension** — the engine's tab suspender calls
//!   [`JsEngine::suspend_site`]; the next script for that site transparently
//!   spins up a fresh runtime (state loss is acceptable for suspended
//!   background tabs — the same trade every mainstream browser makes).
//! * **Aggregated heap stats** — the memory governor reads
//!   [`JsEngine::total_heap_bytes`] without stalling script execution.
//!
//! ## Threading model — the browser way
//!
//! QuickJS runtimes are not `Sync` (and rquickjs's `parallel` feature
//! solves that with a *global* lock, which would let one long script stall
//! every site). browse-wed instead runs **all JavaScript on a single
//! dedicated worker thread** that owns the registry, exactly like a
//! browser's main script thread:
//!
//! * every runtime stays on one thread — zero data races by construction,
//! * no locks exist on the execution path at all,
//! * [`JsEngine`] is a cheap `Clone` handle; calls are commands over a
//!   channel and block only their own caller while waiting for the reply.
//!
//! Site isolation is preserved (one heap per origin, per-runtime memory
//! caps and interrupt deadlines), and cross-site *parallelism* is the
//! engine's job to schedule — not the JS library's.

// Memory-safety policy: every module here is `#![forbid(unsafe_code)]`.

pub mod bridge;
pub mod runtime;
pub mod value;

pub use runtime::{HeapStats, JsError, RuntimeLimits, SiteRuntime};
pub use value::JsValue;

use std::collections::HashMap;
use std::sync::mpsc;

use std::time::Duration;

/// Errors from the JS manager.
#[derive(Debug, thiserror::Error)]
pub enum JsEngineError {
    /// Script failure (see [`crate::runtime::JsError`] for the taxonomy).
    #[error("{0}")]
    Script(#[from] crate::runtime::JsError),
    /// The worker thread is gone (engine shut down or panicked).
    #[error("js worker unavailable")]
    WorkerGone,
}

/// Registry statistics.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct JsEngineStats {
    /// Live site runtimes.
    pub live_runtimes: usize,
    /// Runtimes created since engine start.
    pub runtimes_created: u64,
    /// Runtimes dropped (LRU evictions + suspensions).
    pub runtimes_dropped: u64,
    /// Sum of heap bytes across live runtimes.
    pub total_heap_bytes: i64,
}

/// Commands sent to the JS worker thread.
enum Command {
    Exec {
        site: String,
        source: String,
        timeout: Duration,
        reply: mpsc::Sender<Result<JsValue, JsError>>,
    },
    Suspend {
        site: String,
        reply: mpsc::Sender<bool>,
    },
    GcAll {
        reply: mpsc::Sender<()>,
    },
    HeapStats {
        reply: mpsc::Sender<Vec<(String, HeapStats)>>,
    },
    Stats {
        reply: mpsc::Sender<JsEngineStats>,
    },
}

/// The JS engine facade: a handle to the dedicated worker thread.
///
/// Cloning the handle is cheap; every clone talks to the same worker.
#[derive(Clone)]
pub struct JsEngine {
    tx: mpsc::Sender<Command>,
}

impl JsEngine {
    /// Spawn the JS worker and return the engine handle.
    pub fn new(limits: RuntimeLimits) -> JsEngine {
        let (tx, rx) = mpsc::channel::<Command>();
        let max_live_runtimes = 8usize;
        std::thread::Builder::new()
            .name("bw-js-worker".into())
            .spawn(move || worker_loop(rx, limits, max_live_runtimes))
            .expect("spawning the js worker thread");
        JsEngine { tx }
    }

    /// Execute a script in the context of `site` (origin string).
    pub fn exec(&self, site: &str, source: &str) -> Result<JsValue, JsEngineError> {
        self.exec_with_timeout(site, source, Duration::from_secs(10))
    }

    /// Execute with an explicit timeout.
    pub fn exec_with_timeout(
        &self,
        site: &str,
        source: &str,
        timeout: Duration,
    ) -> Result<JsValue, JsEngineError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Command::Exec {
                site: site.to_string(),
                source: source.to_string(),
                timeout,
                reply: reply_tx,
            })
            .map_err(|_| JsEngineError::WorkerGone)?;
        reply_rx.recv().map_err(|_| JsEngineError::WorkerGone)?.map_err(JsEngineError::Script)
    }

    /// Drop a site's runtime (tab suspension path). Returns true when a
    /// runtime was actually dropped.
    pub fn suspend_site(&self, site: &str) -> Result<bool, JsEngineError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Command::Suspend { site: site.to_string(), reply: reply_tx })
            .map_err(|_| JsEngineError::WorkerGone)?;
        reply_rx.recv().map_err(|_| JsEngineError::WorkerGone)
    }

    /// Run GC on every live runtime.
    pub fn gc_all(&self) -> Result<(), JsEngineError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.send(Command::GcAll { reply: reply_tx }).map_err(|_| JsEngineError::WorkerGone)?;
        reply_rx.recv().map_err(|_| JsEngineError::WorkerGone)
    }

    /// Heap stats per live site.
    pub fn heap_stats(&self) -> Result<Vec<(String, HeapStats)>, JsEngineError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Command::HeapStats { reply: reply_tx })
            .map_err(|_| JsEngineError::WorkerGone)?;
        reply_rx.recv().map_err(|_| JsEngineError::WorkerGone)
    }

    /// Total heap bytes across live runtimes (for the memory governor).
    pub fn total_heap_bytes(&self) -> Result<i64, JsEngineError> {
        Ok(self.heap_stats()?.iter().map(|(_, s)| s.malloc_size).sum())
    }

    /// Engine-level statistics.
    pub fn stats(&self) -> Result<JsEngineStats, JsEngineError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.send(Command::Stats { reply: reply_tx }).map_err(|_| JsEngineError::WorkerGone)?;
        reply_rx.recv().map_err(|_| JsEngineError::WorkerGone)
    }
}

/// The worker thread state.
struct Worker {
    limits: RuntimeLimits,
    max_live: usize,
    runtimes: HashMap<String, SiteRuntime>,
    lru: Vec<String>,
    created: u64,
    dropped: u64,
}

fn worker_loop(rx: mpsc::Receiver<Command>, limits: RuntimeLimits, max_live: usize) {
    let mut worker = Worker {
        limits,
        max_live,
        runtimes: HashMap::new(),
        lru: Vec::new(),
        created: 0,
        dropped: 0,
    };
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::Exec { site, source, timeout, reply } => {
                let _ = reply.send(worker.exec(&site, &source, timeout));
            }
            Command::Suspend { site, reply } => {
                let _ = reply.send(worker.suspend(&site));
            }
            Command::GcAll { reply } => {
                worker.gc_all();
                let _ = reply.send(());
            }
            Command::HeapStats { reply } => {
                let _ = reply.send(worker.heap_stats());
            }
            Command::Stats { reply } => {
                let _ = reply.send(worker.stats());
            }
        }
    }
    // Channel closed: engine handles dropped — free every heap and exit.
}

impl Worker {
    fn exec(&mut self, site: &str, source: &str, timeout: Duration) -> Result<JsValue, JsError> {
        // Fast path: existing runtime.
        if !self.runtimes.contains_key(site) {
            self.ensure_capacity();
            let rt = SiteRuntime::new(site, self.limits)?;
            self.runtimes.insert(site.to_string(), rt);
            self.lru.push(site.to_string());
            self.created += 1;
        } else {
            touch_lru(&mut self.lru, site);
        }
        self.runtimes.get(site).expect("runtime just inserted").exec_with_timeout(source, timeout)
    }

    /// Evict LRU victims while at capacity (caller inserts after).
    fn ensure_capacity(&mut self) {
        while self.runtimes.len() >= self.max_live {
            let victim = self.lru.first().cloned();
            match victim {
                Some(v) => {
                    self.runtimes.remove(&v);
                    self.lru.remove(0);
                    self.dropped += 1;
                    tracing::debug!(site = %v, "evicted js runtime (lru)");
                }
                None => break,
            }
        }
    }

    fn suspend(&mut self, site: &str) -> bool {
        let removed = self.runtimes.remove(site).is_some();
        if removed {
            self.lru.retain(|s| s != site);
            self.dropped += 1;
            tracing::debug!(site, "suspended js runtime");
        }
        removed
    }

    fn gc_all(&mut self) {
        for rt in self.runtimes.values() {
            rt.gc();
        }
    }

    fn heap_stats(&self) -> Vec<(String, HeapStats)> {
        self.runtimes.iter().map(|(site, rt)| (site.clone(), rt.stats())).collect()
    }

    fn stats(&self) -> JsEngineStats {
        JsEngineStats {
            live_runtimes: self.runtimes.len(),
            runtimes_created: self.created,
            runtimes_dropped: self.dropped,
            total_heap_bytes: self.runtimes.values().map(|rt| rt.stats().malloc_size).sum(),
        }
    }
}

fn touch_lru(lru: &mut Vec<String>, site: &str) {
    if let Some(pos) = lru.iter().position(|s| s == site) {
        let s = lru.remove(pos);
        lru.push(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn executes_per_site() {
        let engine = JsEngine::new(RuntimeLimits::default());
        let v = engine.exec("https://a.example", "2 + 2").unwrap();
        assert_eq!(v, JsValue::Number(4.0));
    }

    #[test]
    fn lru_evicts_oldest() {
        let engine = JsEngine::new(RuntimeLimits {
            memory_limit: 8 * 1024 * 1024,
            ..RuntimeLimits::default()
        });
        for i in 0..8 {
            engine.exec(&format!("https://s{i}.example"), "1").unwrap();
        }
        assert_eq!(engine.stats().unwrap().live_runtimes, 8);
        engine.exec("https://new.example", "1").unwrap();
        let stats = engine.stats().unwrap();
        assert_eq!(stats.live_runtimes, 8);
        assert_eq!(stats.runtimes_dropped, 1);
        // s0's state is gone; re-exec spins a fresh runtime.
        let v = engine.exec("https://s0.example", "typeof globalThis").unwrap();
        assert!(matches!(v, JsValue::String(_)));
    }

    #[test]
    fn suspension_drops_heap() {
        let engine = JsEngine::new(RuntimeLimits::default());
        engine.exec("https://heavy.example", "globalThis.x = new Array(100000).fill(1);").unwrap();
        let before = engine.total_heap_bytes().unwrap();
        assert!(before > 0);
        assert!(engine.suspend_site("https://heavy.example").unwrap());
        let after = engine.total_heap_bytes().unwrap();
        assert_eq!(after, 0);
        assert!(!engine.suspend_site("https://heavy.example").unwrap());
    }

    #[test]
    fn heap_stats_aggregate() {
        let engine = JsEngine::new(RuntimeLimits::default());
        engine.exec("https://a.example", "globalThis.x = new Array(50000).fill(1);").unwrap();
        engine.exec("https://b.example", "globalThis.x = new Array(50000).fill(1);").unwrap();
        let stats = engine.stats().unwrap();
        assert_eq!(stats.live_runtimes, 2);
        assert!(stats.total_heap_bytes > 0);
    }

    #[test]
    fn handles_clone_share_worker() {
        let engine = JsEngine::new(RuntimeLimits::default());
        let engine2 = engine.clone();
        engine.exec("https://a.example", "globalThis.mark = 7").unwrap();
        let v = engine2.exec("https://a.example", "globalThis.mark").unwrap();
        assert_eq!(v, JsValue::Number(7.0));
        assert_eq!(engine.stats().unwrap().live_runtimes, 1);
    }

    #[test]
    fn concurrent_callers_serialize_through_worker() {
        let engine = Arc::new(JsEngine::new(RuntimeLimits::default()));
        let mut handles = Vec::new();
        for i in 0..4 {
            let engine = Arc::clone(&engine);
            handles.push(std::thread::spawn(move || {
                let site = format!("https://p{i}.example");
                for _ in 0..25 {
                    engine.exec(&site, "1 + 1").unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(engine.stats().unwrap().live_runtimes, 4);
    }
}
