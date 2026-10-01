//! Boundary value type: JS values as engine-side data.
//!
//! [`JsValue`] is the *only* shape script results cross the boundary in —
//! a plain enum, `Clone + Send + serde`, with no QuickJS lifetimes. The
//! engine, the API crate and the UI serialize it freely.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use rquickjs::{Array, FromJs, Object, Value};

/// A JS value mirrored on the engine side.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum JsValue {
    /// `undefined`
    Undefined,
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// Any JS number (QuickJS int/float unify here).
    Number(f64),
    /// String value.
    String(String),
    /// Array value.
    Array(Vec<JsValue>),
    /// Object value (string keys; insertion order lost, BTree for
    /// deterministic serialization).
    Object(BTreeMap<String, JsValue>),
    /// Any callable — we do not cross functions back over the boundary.
    #[serde(skip)]
    Function,
}

impl JsValue {
    /// JSON representation (best-effort; `undefined`/functions drop).
    ///
    /// Integral numbers render without a fractional part, matching
    /// `JSON.stringify` semantics (`1`, not `1.0`).
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.to_json_value()).unwrap_or_else(|_| "null".into())
    }

    /// serde_json mirror of this value.
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            JsValue::Undefined | JsValue::Null | JsValue::Function => serde_json::Value::Null,
            JsValue::Bool(b) => serde_json::Value::Bool(*b),
            JsValue::Number(n) => {
                if n.is_finite() && n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                    serde_json::Value::Number((*n as i64).into())
                } else if n.is_finite() {
                    serde_json::json!(n)
                } else {
                    // JSON has no NaN/Infinity.
                    serde_json::Value::Null
                }
            }
            JsValue::String(s) => serde_json::Value::String(s.clone()),
            JsValue::Array(a) => serde_json::Value::Array(a.iter().map(Self::to_json_value).collect()),
            JsValue::Object(o) => serde_json::Value::Object(
                o.iter().map(|(k, v)| (k.clone(), v.to_json_value())).collect(),
            ),
        }
    }
}

/// Convert a QuickJS value into a [`JsValue`].
///
/// Cycles are broken by depth cap: objects/arrays nested deeper than
/// `MAX_DEPTH` convert to a string marker instead of recursing. This is
/// both a stack-safety and a DoS guard (a 10k-deep structure must not
/// cost 10k stack frames on the engine thread).
pub(crate) fn value_to_js(v: &Value<'_>) -> rquickjs::Result<JsValue> {
    convert(v, 0)
}

const MAX_DEPTH: usize = 64;

fn convert(v: &Value<'_>, depth: usize) -> rquickjs::Result<JsValue> {
    if depth > MAX_DEPTH {
        return Ok(JsValue::String("<max depth exceeded>".into()));
    }
    match v.type_of() {
        rquickjs::Type::Uninitialized | rquickjs::Type::Undefined => Ok(JsValue::Undefined),
        rquickjs::Type::Null => Ok(JsValue::Null),
        rquickjs::Type::Bool => Ok(JsValue::Bool(v.as_bool().unwrap_or(false))),
        rquickjs::Type::Int => Ok(JsValue::Number(
            v.as_int().map(|i| i as f64).unwrap_or(0.0),
        )),
        rquickjs::Type::Float => Ok(JsValue::Number(v.as_float().unwrap_or(0.0))),
        rquickjs::Type::String => {
            let s: String = String::from_js(v.ctx(), v.clone()).unwrap_or_default();
            Ok(JsValue::String(s))
        }
        rquickjs::Type::Array => {
            let arr = Array::from_value(v.clone())?;
            let mut out = Vec::with_capacity(arr.len());
            for item in arr.iter::<Value>() {
                let item = item?;
                out.push(convert(&item, depth + 1)?);
            }
            Ok(JsValue::Array(out))
        }
        rquickjs::Type::Function | rquickjs::Type::Constructor => Ok(JsValue::Function),
        rquickjs::Type::Exception => {
            let obj = Object::from_value(v.clone())?;
            exception_to_js(&obj)
        }
        rquickjs::Type::BigInt => {
            let s = format!("{v:?}");
            Ok(JsValue::String(s))
        }
        // Plain objects (and Symbol/others rendered via toString-ish).
        _ => {
            let obj = Object::from_value(v.clone())?;
            let mut out = BTreeMap::new();
            for entry in obj.props::<String, Value>() {
                let (k, val) = entry?;
                out.insert(k, convert(&val, depth + 1)?);
            }
            Ok(JsValue::Object(out))
        }
    }
}

/// Exceptions convert to `{ name, message }` objects.
fn exception_to_js(obj: &Object<'_>) -> rquickjs::Result<JsValue> {
    let mut out = BTreeMap::new();
    let name: String = obj.get("name").unwrap_or_else(|_| "Error".into());
    let message: String = obj.get("message").unwrap_or_default();
    out.insert("name".into(), JsValue::String(name));
    out.insert("message".into(), JsValue::String(message));
    Ok(JsValue::Object(out))
}

#[cfg(test)]
mod tests {
    use super::JsValue;
    use crate::runtime::{RuntimeLimits, SiteRuntime};

    fn rt() -> SiteRuntime {
        SiteRuntime::new("https://t.example", RuntimeLimits::default()).unwrap()
    }

    #[test]
    fn primitives() {
        let rt = rt();
        assert_eq!(rt.exec("1").unwrap(), JsValue::Number(1.0));
        assert_eq!(rt.exec("-2.5").unwrap(), JsValue::Number(-2.5));
        assert_eq!(rt.exec("'x'").unwrap(), JsValue::String("x".into()));
        assert_eq!(rt.exec("true").unwrap(), JsValue::Bool(true));
    }

    #[test]
    fn nested_containers() {
        let rt = rt();
        let v = rt.exec("({list: [{n: 1}], flag: false})").unwrap();
        match v {
            JsValue::Object(map) => {
                assert_eq!(map.get("flag"), Some(&JsValue::Bool(false)));
                match map.get("list") {
                    Some(JsValue::Array(items)) => match &items[0] {
                        JsValue::Object(inner) => {
                            assert_eq!(inner.get("n"), Some(&JsValue::Number(1.0)))
                        }
                        other => panic!("expected inner object, got {other:?}"),
                    },
                    other => panic!("expected array, got {other:?}"),
                }
            }
            other => panic!("expected object, got {other:?}"),
        }
    }

    #[test]
    fn cycles_do_not_recurse_forever() {
        let rt = rt();
        // Self-referencing object must hit the depth cap, not blow the stack.
        let v = rt
            .exec("const a = {}; a.self = a; a")
            .unwrap();
        assert!(matches!(v, JsValue::Object(_)));
    }

    #[test]
    fn functions_marked() {
        let rt = rt();
        assert_eq!(rt.exec("(() => 1)").unwrap(), JsValue::Function);
        assert_eq!(rt.exec("Math.max").unwrap(), JsValue::Function);
    }

    #[test]
    fn json_rendering() {
        let rt = rt();
        let v = rt.exec("({a: 1})").unwrap();
        assert_eq!(v.to_json(), r#"{"a":1}"#);
    }
}
