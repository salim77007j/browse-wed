//! Basic web-platform globals injected into every site runtime.
//!
//! v0.1 surface (deliberately small and auditable):
//! * `console.log/info/warn/error/debug` → structured `tracing` events
//!   (never stdout — the UI subscribes to tracing).
//! * `performance.now()` / `performance.timeOrigin` — 5 µs resolution
//!   (coarsened below Chrome's 100 µs cross-origin default; enough for
//!   legitimate profiling, coarse enough to hurt timing side channels).
//! * `crypto.getRandomValues(typedArray)` — via `getrandom`, the same CSP
//!   the rest of the engine uses; the JS-level source is
//!   indistinguishable from the engine's own randomness.
//! * `Math.random` seeded per-runtime (QuickJS-ng already does this; we
//!   re-seed explicitly so two sites never share a sequence).
//!
//! Not installed (yet): `fetch`, `XMLHttpRequest`, DOM bindings — these
//! are installed by the engine layer once wired to the fetch pipeline.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use rquickjs::function::{Func, MutFn, Rest};
use rquickjs::{Ctx, Exception, FromJs, Object, Value};

/// Time origin of this engine process (ms since unix epoch).
fn time_origin_ms() -> f64 {
    static START: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *START.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0)
    })
}

/// Coarsened monotonic clock for `performance.now()`.
/// Resolution: 5 µs — see module docs for the rationale.
fn perf_now() -> f64 {
    use std::sync::OnceLock;
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    let us = start.elapsed().as_micros() as f64;
    (us / 5.0).floor() * 5.0 / 1000.0
}

/// Install the basic globals into a context.
pub(crate) fn install_basics<'js>(ctx: &Ctx<'js>, site: &str) -> rquickjs::Result<()> {
    let globals = ctx.globals();

    // --- console ---------------------------------------------------------
    let console = Object::new(ctx.clone())?;
    let levels: [&'static str; 5] = ["log", "info", "warn", "error", "debug"];
    for level in levels {
        let site = site.to_string();
        let lvl = level;
        // `Rest<T>` is the element type — varargs collect into Vec<Value>.
        let f = Func::from(move |args: Rest<Value>| {
            let Rest(items) = args;
            let mut parts: Vec<String> = Vec::with_capacity(items.len());
            for v in &items {
                parts.push(render_value(v));
            }
            site_log(&site, lvl, &parts.join(" "));
            rquickjs::Undefined
        });
        console.set(level, f)?;
    }
    globals.set("console", console)?;

    // --- performance -----------------------------------------------------
    let performance = Object::new(ctx.clone())?;
    performance.set("now", Func::from(perf_now))?;
    performance.set("timeOrigin", time_origin_ms())?;
    globals.set("performance", performance)?;

    // --- crypto.getRandomValues -----------------------------------------
    let crypto = Object::new(ctx.clone())?;
    let get_random_values = rquickjs::Function::new(ctx.clone(), |ta: Value<'js>| fill_random(ta))?;
    crypto.set("getRandomValues", get_random_values)?;
    globals.set("crypto", crypto)?;

    // --- re-seed Math.random per site ------------------------------------
    // QuickJS exposes Math.random as a plain function value we replace.
    let math = globals.get::<_, Object<'js>>("Math")?;
    let seed: [u8; 8] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(site.as_bytes());
        h.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                .to_le_bytes(),
        );
        let digest = h.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    };
    let mut state = u64::from_le_bytes(seed);
    let random = MutFn::new(move || {
        // xorshift64* — fast, good-enough distribution for Math.random's
        // documented non-cryptographic contract.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        ((state.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64) / (1u64 << 53) as f64
    });
    math.set("random", Func::from(random))?;
    globals.set("Math", math)?;

    Ok(())
}

/// Fill an integer TypedArray with CSP randomness; returns the array
/// (per spec). Implemented through JS-level element access so the whole
/// function stays in safe Rust.
fn fill_random<'js>(ta: Value<'js>) -> rquickjs::Result<Value<'js>> {
    let ctx = ta.ctx();
    let obj = rquickjs::Object::from_value(ta.clone())?;
    let length: usize = obj.get::<_, f64>("length")?.max(0.0) as usize;
    if length == 0 {
        return Ok(ta);
    }
    if length > 65536 {
        return Err(Exception::throw_message(
            ctx,
            "crypto.getRandomValues quota exceeded (65536 elements)",
        ));
    }
    // Element width from the constructor name (spec: integer arrays only).
    let name: String = obj.get::<_, rquickjs::Object<'js>>("constructor")?.get("name")?;
    let bits: u32 = match name.as_str() {
        "Int8Array" | "Uint8Array" | "Uint8ClampedArray" => 8,
        "Int16Array" | "Uint16Array" => 16,
        "Int32Array" | "Uint32Array" => 32,
        "BigInt64Array" | "BigUint64Array" => 64,
        _ => {
            return Err(Exception::throw_message(
                ctx,
                "crypto.getRandomValues requires an integer TypedArray",
            ));
        }
    };
    // One entropy draw for the whole request; XOR-mix per element.
    let mut pool = vec![0u8; (length + 1) * 8];
    if getrandom::fill(&mut pool).is_err() {
        return Err(Exception::throw_message(ctx, "entropy source unavailable"));
    }
    let mask: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    for i in 0..length {
        let chunk: [u8; 8] = pool[i * 8..i * 8 + 8].try_into().expect("8 bytes");
        let r = u64::from_le_bytes(chunk) & mask;
        if bits == 64 {
            // BigInt64/BigUint64 elements need BigInt values.
            let big = rquickjs::BigInt::from_u64(ctx.clone(), r);
            obj.set(i as u32, big)?;
        } else {
            let current: f64 = obj.get(i as u32)?;
            let mixed = ((current as i64 as u64) ^ r) & mask;
            obj.set(i as u32, mixed as f64)?;
        }
    }
    Ok(ta)
}

/// Render a JS value for console output (JSON-ish, single line).
fn render_value(v: &Value<'_>) -> String {
    match v.type_of() {
        rquickjs::Type::String => {
            String::from_js(v.ctx(), v.clone()).unwrap_or_default()
        }
        _ => match crate::value::value_to_js(v) {
            Ok(jv) => serde_json::to_string(&jv_to_display(&jv)).unwrap_or_else(|_| "?".into()),
            Err(_) => String::from("<value>"),
        },
    }
}

/// Convert JsValue into a serde_json-friendly mirror for display.
fn jv_to_display(v: &crate::value::JsValue) -> serde_json::Value {
    match v {
        crate::value::JsValue::Undefined | crate::value::JsValue::Null => serde_json::Value::Null,
        crate::value::JsValue::Bool(b) => serde_json::Value::Bool(*b),
        crate::value::JsValue::Number(n) => serde_json::json!(n),
        crate::value::JsValue::String(s) => serde_json::Value::String(s.clone()),
        crate::value::JsValue::Array(a) => {
            serde_json::Value::Array(a.iter().map(jv_to_display).collect())
        }
        crate::value::JsValue::Object(o) => serde_json::Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), jv_to_display(v)))
                .collect(),
        ),
        crate::value::JsValue::Function => serde_json::Value::String("[Function]".into()),
    }
}

/// Emit a structured console event for a site.
pub(crate) fn site_log(site: &str, level: &str, message: &str) {
    match level {
        "error" => tracing::warn!(site, "{message}"),
        "warn" => tracing::warn!(site, "{message}"),
        "info" => tracing::info!(site, "{message}"),
        _ => tracing::debug!(site, "{message}"),
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{RuntimeLimits, SiteRuntime};

    fn rt(site: &str) -> SiteRuntime {
        SiteRuntime::new(site, RuntimeLimits::default()).unwrap()
    }

    #[test]
    fn console_does_not_throw() {
        let rt = rt("https://t.example");
        assert!(rt.exec("console.log('a', 1, [2]); console.error('x');").is_ok());
    }

    #[test]
    fn crypto_fills_bytes() {
        let rt = rt("https://t.example");
        let v = rt
            .exec(
                r#"const a = new Uint8Array(16);
                   crypto.getRandomValues(a);
                   a.some(x => x !== 0);"#,
            )
            .unwrap();
        // Overwhelmingly true; a fixed zero-fill would be a CSP failure.
        assert_eq!(v, crate::value::JsValue::Bool(true));
    }

    #[test]
    fn crypto_rejects_non_typed_array() {
        let rt = rt("https://t.example");
        assert!(rt.exec("crypto.getRandomValues(42)").is_err());
    }

    #[test]
    fn math_random_is_deterministic_per_seed_sequence_but_not_constant() {
        let rt = rt("https://t.example");
        let v = rt
            .exec(
                "const xs = [Math.random(), Math.random(), Math.random()];
                 xs[0] !== xs[1] || xs[1] !== xs[2]",
            )
            .unwrap();
        assert_eq!(v, crate::value::JsValue::Bool(true));
    }

    #[test]
    fn math_random_sequences_differ_across_sites() {
        let a = rt("https://a.example");
        let b = rt("https://b.example");
        let va = a.exec("Math.random()").unwrap();
        let vb = b.exec("Math.random()").unwrap();
        // Two 53-bit draws colliding has probability ~1e-16; treat equal as
        // a seeding failure.
        assert_ne!(va, vb);
    }

    #[test]
    fn perf_now_is_monotonic() {
        let rt = rt("https://t.example");
        let v = rt
            .exec(
                "const a = performance.now();
                 let s = 0;
                 for (let i = 0; i < 1e6; i++) s += i;
                 performance.now() >= a",
            )
            .unwrap();
        assert_eq!(v, crate::value::JsValue::Bool(true));
    }
}
