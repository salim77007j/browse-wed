//! # bw-privacy — the privacy core of the browse-wed engine
//!
//! This crate owns every privacy enforcement primitive that operates at or
//! below the resource-loading layer:
//!
//! * [`filter`] — a high-performance network filter engine speaking the
//!   uBlock Origin / EasyList rule syntax (network filters `||host^path`,
//!   exceptions `@@`, options `$script,image,third-party,...`).
//! * [`cosmetic`] — cosmetic filtering (element hiding via `##selector` and
//!   exception `#@#selector`), matched against a host DOM.
//! * [`cname`] — CNAME uncloaking: detects third-party hostnames whose DNS
//!   resolution crosses into a known tracker's apex domain.
//! * [`fingerprint`] — the anti-fingerprinting *policy engine*. It derives a
//!   stable per-(site, session) seed and computes the exact spoofed values
//!   for canvas, audio, WebGL, navigator, screen and font signals.
//! * [`safebrowsing`] — a purely local Bloom-filter backed URL checker with
//!   prefix-commit updates, designed so full URLs never leave the device
//!   except as fixed-length hashes.
//!
//! ## Design principles
//!
//! 1. **Zero blocking on the hot path.** Matching a request consults only
//!    precompiled automata (Aho-Corasick, domain tries, compiled regexes).
//! 2. **Deterministic decisions.** The same filter list + request always
//!    yields the same verdict, which makes the engine fuzzable and testable.
//! 3. **Privacy by construction.** Nothing in this crate performs network
//!    I/O. List updates and Safe Browsing updates are driven by the caller
//!    ([`bw_network`](https://docs.rs/bw-network)) so no hidden egress exists.

#![forbid(unsafe_code)]

pub mod cname;
pub mod cosmetic;
pub mod fingerprint;
pub mod filter;
pub mod safebrowsing;

/// The verdict a filter engine returns for a candidate request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Decision {
    /// Allow the request.
    Allow,
    /// Block the request (network filter matched).
    Block,
    /// Redirect to a neutered, empty body (used for `$empty`-style rules).
    Neuter,
}

impl Decision {
    /// True when the request must not proceed to the network.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Decision::Block | Decision::Neuter)
    }
}

/// The class of a request, used to honour `$script`, `$image`, ... options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ResourceType(pub u32);

impl ResourceType {
    /// No type specified — matches only untyped rules.
    pub const UNTYPED: ResourceType = ResourceType(0);
    /// External script.
    pub const SCRIPT: ResourceType = ResourceType(1 << 0);
    /// Image / favicon.
    pub const IMAGE: ResourceType = ResourceType(1 << 1);
    /// Stylesheet.
    pub const STYLESHEET: ResourceType = ResourceType(1 << 2);
    /// Top-level document navigation.
    pub const DOCUMENT: ResourceType = ResourceType(1 << 3);
    /// XHR / fetch.
    pub const XHR: ResourceType = ResourceType(1 << 4);
    /// Sub-frame document.
    pub const SUBDOCUMENT: ResourceType = ResourceType(1 << 5);
    /// Font.
    pub const FONT: ResourceType = ResourceType(1 << 6);
    /// Media (audio / video).
    pub const MEDIA: ResourceType = ResourceType(1 << 7);
    /// WebSocket.
    pub const WEBSOCKET: ResourceType = ResourceType(1 << 8);
    /// Ping / beacon.
    pub const PING: ResourceType = ResourceType(1 << 9);
    /// Anything else (data fetches, service workers...).
    pub const OTHER: ResourceType = ResourceType(1 << 10);

    /// The set of bits covering "any resource type".
    pub const ANY: ResourceType = ResourceType(0x7ff);

    /// Union of two type sets.
    pub fn union(self, other: ResourceType) -> ResourceType {
        ResourceType(self.0 | other.0)
    }

    /// True when `self` includes `other`.
    pub fn contains(&self, other: ResourceType) -> bool {
        self.0 & other.0 == other.0
    }

    /// Parse a single option token like `script` or `~image`.
    /// Returns `(mask, negated)`.
    pub(crate) fn from_token(token: &str) -> Option<(ResourceType, bool)> {
        let (neg, name) = match token.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, token),
        };
        let ty = match name {
            "script" => Self::SCRIPT,
            "image" => Self::IMAGE,
            "stylesheet" | "css" => Self::STYLESHEET,
            "document" | "doc" => Self::DOCUMENT,
            "xhr" | "xmlhttprequest" => Self::XHR,
            "subdocument" | "frame" => Self::SUBDOCUMENT,
            "font" => Self::FONT,
            "media" => Self::MEDIA,
            "websocket" => Self::WEBSOCKET,
            "ping" | "beacon" => Self::PING,
            "other" => Self::OTHER,
            _ => return None,
        };
        Some((ty, neg))
    }

    /// Map a MIME-ish hint to a resource type. Used by the network layer.
    pub fn from_hint(hint: &str) -> ResourceType {
        match hint {
            "script" => Self::SCRIPT,
            "image" => Self::IMAGE,
            "stylesheet" => Self::STYLESHEET,
            "document" => Self::DOCUMENT,
            "xhr" => Self::XHR,
            "subdocument" => Self::SUBDOCUMENT,
            "font" => Self::FONT,
            "media" => Self::MEDIA,
            "websocket" => Self::WEBSOCKET,
            "ping" => Self::PING,
            _ => Self::OTHER,
        }
    }
}

/// A candidate request handed to the filter engine.
///
/// The engine is intentionally fed *parsed* data (already a `Url`) so that
/// test cases never depend on ambient DNS or TLS state.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Fully-parsed target URL.
    pub url: url::Url,
    /// Hostname of the top-level document (first party).
    pub source_host: String,
    /// Registrable-ish domain of the first party (e.g. `example.org`).
    pub source_base: String,
    /// Resource type bits.
    pub resource_type: ResourceType,
}

impl RequestContext {
    /// Hostname of the request target, lowercased.
    pub fn target_host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    /// True when the request target belongs to a different site than the
    /// first party. A request is first-party when the target host equals the
    /// source host or is a subdomain of the source's registrable domain.
    pub fn is_third_party(&self) -> bool {
        let host = self.target_host();
        if host.is_empty() || self.source_base.is_empty() {
            return false;
        }
        let same_host = host.eq_ignore_ascii_case(&self.source_host);
        let subdomain = host.len() > self.source_base.len()
            && host[host.len() - self.source_base.len()..].eq_ignore_ascii_case(&self.source_base)
            && host.as_bytes()[host.len() - self.source_base.len() - 1] == b'.';
        !(same_host || subdomain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(host: &str, source: &str) -> RequestContext {
        RequestContext {
            url: url::Url::parse(&format!("https://{host}/x.js")).unwrap(),
            source_host: source.to_string(),
            source_base: base_of(source),
            resource_type: ResourceType::SCRIPT,
        }
    }

    fn base_of(host: &str) -> String {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            host.to_string()
        }
    }

    #[test]
    fn party_classification() {
        assert!(!ctx("cdn.example.com", "example.com").is_third_party());
        assert!(!ctx("example.com", "example.com").is_third_party());
        assert!(ctx("tracker.io", "example.com").is_third_party());
        assert!(ctx("tracker.example.org", "example.com").is_third_party());
    }
}
