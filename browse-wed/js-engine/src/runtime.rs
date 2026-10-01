//! Per-site QuickJS-ng runtimes.
//!
//! A [`SiteRuntime`] owns one `Runtime` + one `Context` — the isolation
//! unit for a web origin. Site isolation at the JS level means:
//!
//! * one heap per site → a leaky site cannot eat the whole engine,
//! * `set_memory_limit` per heap → hard cap (default 64 MiB),
//! * an interrupt handler armed per evaluation → hard wall-clock cap,
//! * dropping the runtime frees every byte of the site's heap instantly
//!   (the engine's tab suspender does exactly this).

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rquickjs::context::Context;
use rquickjs::runtime::Runtime;
use rquickjs::CatchResultExt;

use crate::bridge;
use crate::value::{value_to_js, JsValue};

/// Errors surfaced by script execution.
#[derive(Debug, thiserror::Error)]
pub enum JsError {
    /// Script syntax or runtime exception (message from QuickJS).
    #[error("js exception: {0}")]
    Exception(String),
    /// The script exceeded its wall-clock budget.
    #[error("script timed out after {0:?}")]
    Timeout(Duration),
    /// The script exceeded its heap budget.
    #[error("script exceeded its memory limit ({bytes} bytes used)")]
    MemoryLimit {
        /// Heap bytes at the point of failure.
        bytes: i64,
    },
    /// The runtime could not be created.
    #[error("runtime init failed: {0}")]
    Init(String),
}

/// Tuning knobs for a site runtime.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeLimits {
    /// Hard heap cap in bytes (QuickJS refuses allocations beyond it).
    pub memory_limit: usize,
    /// Stack cap in bytes (guards deep recursion DoS).
    pub stack_size: usize,
    /// Default per-evaluation wall-clock budget.
    pub default_timeout: Duration,
    /// GC threshold (bytes of allocation before a cycle run).
    pub gc_threshold: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        RuntimeLimits {
            memory_limit: 64 * 1024 * 1024,
            stack_size: 1024 * 1024,
            default_timeout: Duration::from_secs(10),
            gc_threshold: 256 * 1024,
        }
    }
}

/// Heap statistics of one runtime.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct HeapStats {
    /// Bytes allocated on the JS heap.
    pub malloc_size: i64,
    /// Bytes in QuickJS-owned objects/strings/arrays.
    pub memory_used: i64,
    /// Number of live JS objects.
    pub objects: i64,
    /// Number of live JS functions.
    pub functions: i64,
    /// Number of live atoms.
    pub atoms: i64,
}

/// The per-site execution state.
pub struct SiteRuntime {
    site: String,
    runtime: Runtime,
    context: Context,
    limits: RuntimeLimits,
    /// Monotonic deadline (microseconds since engine start) for the
    /// currently-armed evaluation; 0 = disarmed.
    deadline_us: Arc<AtomicI64>,
}

impl SiteRuntime {
    /// Create a fresh runtime for `site`.
    pub fn new(site: &str, limits: RuntimeLimits) -> Result<SiteRuntime, JsError> {
        let rt = Runtime::new().map_err(|e| JsError::Init(e.to_string()))?;
        rt.set_memory_limit(limits.memory_limit);
        rt.set_max_stack_size(limits.stack_size);
        rt.set_gc_threshold(limits.gc_threshold);

        let deadline_us: Arc<AtomicI64> = Arc::new(AtomicI64::new(0));
        {
            // The interrupt handler is polled by the interpreter loop;
            // returning true aborts execution with an InternalError.
            let deadline = Arc::clone(&deadline_us);
            rt.set_interrupt_handler(Some(Box::new(move || {
                let d = deadline.load(Ordering::Relaxed);
                if d <= 0 {
                    return false;
                }
                engine_now_us() >= d
            })));
        }

        let ctx = Context::full(&rt).map_err(|e| JsError::Init(e.to_string()))?;
        ctx.with(|ctx| bridge::install_basics(&ctx, site))
            .map_err(|e| JsError::Init(e.to_string()))?;

        Ok(SiteRuntime { site: site.to_string(), runtime: rt, context: ctx, limits, deadline_us })
    }

    /// The site this runtime belongs to.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// Execute a script; returns the last expression's value.
    ///
    /// Micro-tasks queued by the script (promise reactions) are drained
    /// after evaluation within the same timeout budget.
    pub fn exec(&self, source: &str) -> Result<JsValue, JsError> {
        self.exec_with_timeout(source, self.limits.default_timeout)
    }

    /// Execute with an explicit wall-clock budget.
    pub fn exec_with_timeout(&self, source: &str, timeout: Duration) -> Result<JsValue, JsError> {
        self.arm(timeout);
        // Phase 1: evaluate inside the context closure. While the closure
        // runs, the runtime's internal state is borrowed — we must not
        // touch any other runtime API (memory_usage, gc, jobs) here, so
        // errors are rendered to owned strings and classified afterwards.
        let outcome: Result<JsValue, String> = self.context.with(|ctx| {
            ctx.eval::<rquickjs::Value, _>(source)
                .catch(&ctx)
                .map_err(|caught| render_caught(&caught))
                .and_then(|v| value_to_js(&v).map_err(|e| format!("conversion error: {e}")))
        });
        // Snapshot whether the deadline fired BEFORE disarming (the
        // classifier needs it after the fact).
        let fired = {
            let d = self.deadline_us.load(Ordering::Relaxed);
            d > 0 && engine_now_us() >= d
        };
        self.disarm();
        match outcome {
            Ok(v) => {
                // Phase 2: drain the micro-task queue (promise callbacks)
                // under the same budget — outside the closure, so runtime
                // APIs are safe to call again.
                self.arm(timeout);
                loop {
                    match self.runtime.execute_pending_job() {
                        Ok(true) => continue,
                        Ok(false) => break,
                        Err(_job_err) => break, // failing job clears its own exception
                    }
                }
                self.disarm();
                Ok(v)
            }
            Err(msg) => Err(self.classify_after(fired, timeout, msg)),
        }
    }

    /// Classify a rendered error AFTER the context closure has finished,
    /// when runtime introspection is legal. `fired` is whether the
    /// interrupt deadline had been reached (snapshot before disarm).
    fn classify_after(&self, fired: bool, timeout: Duration, msg: String) -> JsError {
        // 1. Did our interrupt deadline fire?
        if fired {
            return JsError::Timeout(timeout);
        }
        // 2. Did we hit the heap cap?
        let used = self.runtime.memory_usage();
        if used.malloc_size as usize >= self.limits.memory_limit {
            return JsError::MemoryLimit { bytes: used.malloc_size };
        }
        // 3. Ordinary script exception.
        JsError::Exception(msg)
    }

    /// Run a full GC cycle; returns collected-heap stats.
    pub fn gc(&self) -> HeapStats {
        self.runtime.run_gc();
        self.stats()
    }

    /// Heap statistics snapshot.
    pub fn stats(&self) -> HeapStats {
        let usage = self.runtime.memory_usage();
        HeapStats {
            malloc_size: usage.malloc_size,
            memory_used: usage.memory_used_size,
            objects: usage.obj_count,
            functions: usage.js_func_count + usage.c_func_count,
            atoms: usage.atom_count,
        }
    }

    fn arm(&self, timeout: Duration) {
        let deadline = engine_now_us() + timeout.as_micros() as i64;
        self.deadline_us.store(deadline, Ordering::Relaxed);
    }

    fn disarm(&self) {
        self.deadline_us.store(0, Ordering::Relaxed);
    }
}

/// Engine-monotonic clock in microseconds (shared by all interrupt
/// handlers; starts at first use).
fn engine_now_us() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_micros() as i64
}

/// Render a caught QuickJS error into an owned string (must run inside
/// the context closure — exception values borrow the context).
fn render_caught(caught: &rquickjs::CaughtError<'_>) -> String {
    match caught {
        rquickjs::CaughtError::Error(e) => format!("internal error: {e}"),
        rquickjs::CaughtError::Exception(ex) => ex.message().unwrap_or_else(|| ex.to_string()),
        rquickjs::CaughtError::Value(v) => format!("{v:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::JsValue;

    fn rt() -> SiteRuntime {
        SiteRuntime::new("https://test.example", RuntimeLimits::default()).unwrap()
    }

    #[test]
    fn evals_expressions() {
        let rt = rt();
        let v = rt.exec("1 + 2 * 3").unwrap();
        assert_eq!(v, JsValue::Number(7.0));
    }

    #[test]
    fn strings_round_trip() {
        let rt = rt();
        let v = rt.exec("'hello' + ' ' + 'world'").unwrap();
        assert_eq!(v, JsValue::String("hello world".into()));
    }

    #[test]
    fn objects_and_arrays_convert() {
        let rt = rt();
        let v = rt.exec("({a: 1, b: [2, 3]})").unwrap();
        match v {
            JsValue::Object(map) => {
                assert_eq!(map.get("a"), Some(&JsValue::Number(1.0)));
                assert_eq!(
                    map.get("b"),
                    Some(&JsValue::Array(vec![JsValue::Number(2.0), JsValue::Number(3.0)]))
                );
            }
            other => panic!("expected object, got {other:?}"),
        }
    }

    #[test]
    fn undefined_and_null_map_correctly() {
        let rt = rt();
        assert_eq!(rt.exec("undefined").unwrap(), JsValue::Undefined);
        assert_eq!(rt.exec("null").unwrap(), JsValue::Null);
    }

    #[test]
    fn syntax_errors_are_exceptions() {
        let rt = rt();
        let err = rt.exec("function {").unwrap_err();
        assert!(matches!(err, JsError::Exception(_)));
    }

    #[test]
    fn runtime_errors_carry_messages() {
        let rt = rt();
        let err = rt.exec("throw new Error('boom')").unwrap_err();
        match err {
            JsError::Exception(msg) => assert!(msg.contains("boom")),
            other => panic!("expected exception, got {other:?}"),
        }
    }

    #[test]
    fn infinite_loop_times_out() {
        let rt = rt();
        let err = rt.exec_with_timeout("while(true) {}", Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, JsError::Timeout(_)));
    }

    #[test]
    fn deep_recursion_hits_stack_cap() {
        let limits = RuntimeLimits { stack_size: 128 * 1024, ..RuntimeLimits::default() };
        let rt = SiteRuntime::new("https://test.example", limits).unwrap();
        // Should terminate (stack overflow exception), never crash.
        let res = rt.exec("function f(){ return f(); } f()");
        assert!(res.is_err());
    }

    #[test]
    fn memory_limit_enforced() {
        let limits = RuntimeLimits { memory_limit: 4 * 1024 * 1024, ..RuntimeLimits::default() };
        let rt = SiteRuntime::new("https://test.example", limits).unwrap();
        let res = rt.exec("let a = []; for(;;) { a.push(new Array(10000).fill(0x41)); }");
        assert!(res.is_err());
    }

    #[test]
    fn promises_drain_after_eval() {
        let rt = rt();
        let v = rt
            .exec(
                r#"
                globalThis.result = 'pending';
                Promise.resolve(42).then(v => { globalThis.result = 'done:' + v; });
                globalThis.result;
            "#,
            )
            .unwrap();
        assert_eq!(v, JsValue::String("pending".into()));
        let after = rt.exec("globalThis.result").unwrap();
        assert_eq!(after, JsValue::String("done:42".into()));
    }

    #[test]
    fn console_basics_installed() {
        let rt = rt();
        let v = rt.exec("typeof console !== 'undefined' && typeof console.log").unwrap();
        assert_eq!(v, JsValue::String("function".into()));
    }

    #[test]
    fn performance_now_installed() {
        let rt = rt();
        let v = rt.exec("typeof performance.now === 'function' && performance.now() >= 0").unwrap();
        assert_eq!(v, JsValue::Bool(true));
    }

    #[test]
    fn heap_stats_track_allocations() {
        let rt = rt();
        let before = rt.stats();
        rt.exec("globalThis.keep = new Array(100000).fill(1.5);").unwrap();
        let after = rt.stats();
        assert!(after.memory_used > before.memory_used);
    }

    #[test]
    fn gc_frees_dropped_objects() {
        let rt = rt();
        // Real heap objects (not fast-array elements): auto-GC cannot free
        // them while the global reference holds, so the counts are stable.
        rt.exec("globalThis.keep = []; for (let i = 0; i < 10000; i++) keep.push({x: i});")
            .unwrap();
        let held = rt.stats().objects;
        rt.exec("globalThis.keep = null;").unwrap();
        let freed = rt.gc().objects;
        assert!(freed < held, "gc did not reclaim objects: {held} -> {freed}");
    }

    #[test]
    fn sites_have_isolated_heaps() {
        let a = SiteRuntime::new("https://a.example", RuntimeLimits::default()).unwrap();
        let b = SiteRuntime::new("https://b.example", RuntimeLimits::default()).unwrap();
        a.exec("globalThis.leak = new Array(50000).fill(0);").unwrap();
        assert_eq!(b.exec("typeof globalThis.leak").unwrap(), JsValue::String("undefined".into()));
        // b's heap must not carry a's objects.
        assert!(b.stats().memory_used < a.stats().memory_used);
    }
}
