//! Composite key encodings shared by the storage tables.
//!
//! All keys are `String`s with `\u{1F}` (unit separator) field joins. Fields
//! are length-independent because `\u{1F}` never appears in URLs, hostnames
//! or serde-JSON key encodings we emit (JSON string escaping converts
//! control characters to `\u001f` escape text).

/// Join fields into a table key.
pub fn join(fields: &[&str]) -> String {
    fields.join("\u{1f}")
}

/// Cookie key: `partition \x1f domain \x1f path \x1f name`.
pub fn cookie_key(partition: &str, domain: &str, path: &str, name: &str) -> String {
    join(&[partition, domain, path, name])
}

/// Range prefix for all cookies of one partition+origin: `partition \x1f domain \x1f`.
/// Note: prefix scans use `range(prefix..)` which is ordered, so a shared
/// prefix must be followed by the smallest separator-safe sentinel. We scan
/// `prefix..prefix_next` where `prefix_next` bumps the last byte.
pub fn cookie_key_prefix(partition: &str, domain: &str) -> String {
    let p = join(&[partition, domain]);
    // exclusive upper bound helper handled by callers via prefix_upper()
    p
}

/// Compute the exclusive upper bound for a prefix range (bump trailing byte).
pub fn prefix_upper(prefix: &str) -> String {
    let mut s = prefix.to_string();
    // Bump the final char; if it would overflow, append \u{1f}.
    if let Some(last) = s.chars().last() {
        if (last as u32) < u32::MAX - 1 {
            let mut chars: Vec<char> = s.chars().collect();
            let n = chars.len();
            chars[n - 1] = char::from_u32(last as u32 + 1).unwrap_or(last);
            return chars.into_iter().collect();
        }
    }
    s.push('\u{1f}');
    s
}

/// LocalStorage key: `partition \x1f origin \x1f key`.
pub fn ls_key(partition: &str, origin: &str, key: &str) -> String {
    join(&[partition, origin, key])
}

/// LocalStorage prefix: `partition \x1f origin \x1f`.
pub fn ls_key_prefix(partition: &str, origin: &str) -> String {
    join(&[partition, origin])
}

/// IndexedDB meta key: `p \x1f origin \x1f db_name`.
pub fn idb_meta_key(partition: &str, origin: &str, db_name: &str) -> String {
    join(&[partition, origin, db_name])
}

/// IndexedDB meta prefix.
pub fn idb_meta_prefix(partition: &str, origin: &str) -> String {
    join(&[partition, origin])
}

/// IndexedDB record key: `p \x1f origin \x1f db \x1f store \x1f primary-key`.
/// Primary keys are JSON-encoded so ordering matches IDB key order for
/// common types (numbers before strings in our encoding — good enough for
/// range scans over homogeneous stores).
pub fn idb_record_key(partition: &str, origin: &str, db: &str, store: &str, pk: &str) -> String {
    join(&[partition, origin, db, store, pk])
}

/// IndexedDB record prefix.
pub fn idb_record_prefix(partition: &str, origin: &str) -> String {
    join(&[partition, origin])
}

/// IndexedDB record prefix including database and store.
pub fn idb_store_prefix(partition: &str, origin: &str, db: &str, store: &str) -> String {
    join(&[partition, origin, db, store])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_upper_orders_after_prefix() {
        let p = cookie_key_prefix("a.com", "b.com");
        let upper = prefix_upper(&p);
        assert!(upper > p);
        assert!(cookie_key("a.com", "b.com", "/", "x").starts_with(&p));
        assert!(cookie_key("a.com", "b.com", "/", "x").as_str() < upper.as_str());
        assert!(cookie_key("a.com", "b.org", "/", "x").as_str() >= upper.as_str());
    }
}
