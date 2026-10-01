//! # bw-network — the browse-wed network stack
//!
//! A complete, privacy-first browser networking layer:
//!
//! * **Protocols** — HTTP/1.1 and HTTP/2 over TCP+TLS 1.3 (rustls, pure
//!   Rust), HTTP/3 over QUIC (quinn + h3) with Alt-Svc discovery and
//!   automatic h3→h2 fallback.
//! * **DNS** — DoH (RFC 8484) / DoT (RFC 7858) / system, with CNAME chain
//!   exposure for uncloaking and happy-eyeballs v6/v4 interleaving.
//! * **Privacy at the network layer** — every request passes the compiled
//!   uBlock-syntax filter set (`bw-privacy`) *before* any socket opens;
//!   blocked requests never cost a DNS query or handshake.
//! * **Partitioned cookies (CHIPS)** — Set-Cookie processing goes through
//!   `bw-storage`'s partitioned jar; third-party cookies without a
//!   partition key are rejected at storage time.
//! * **HTTPS upgrade + HSTS + Alt-Svc** — learned from responses, enforced
//!   on subsequent requests.
//! * **Cache integration** — fresh hits short-circuit before transport.
//!
//! ## The one entry point that matters
//!
//! [`FetchService::fetch`] — one call, one [`FetchResponse`], everything
//! above applied in the right order. The UI layer never touches transports
//! directly.
//!
//! ## Crate layout
//!
//! | module | responsibility |
//! |---|---|
//! | [`config`] | tunables (protocols, DNS mode, timeouts) |
//! | [`dns`] | DoH/DoT resolver manager + CNAME chains |
//! | [`tls`] | rustls TLS 1.3 config + SNI helpers |
//! | [`connector`] | hostname → TCP/QUIC → TLS → stream (tower service) |
//! | [`http`] | pooled h1/h2 client (hyper-util legacy) |
//! | [`h3`] | HTTP/3 client (quinn + h3) |
//! | [`policy`] | filter/safe-browsing/upgrade decisions |
//! | [`fetch`] | the orchestration pipeline |
//!
//! ## Zero-I/O guarantee
//!
//! [`policy::PolicyEngine`] performs **no I/O**: decisions are pure
//! functions of the request and engine state. This makes the entire
//! privacy decision surface unit-testable and fuzzable without a network.

#![forbid(unsafe_code)]

pub mod config;
pub mod connector;
pub mod dns;
pub mod fetch;
pub mod h3;
pub mod http;
pub mod policy;
pub mod tls;

pub use config::{DnsMode, NetworkConfig, DEFAULT_DOH_SERVERS};
pub use dns::{DnsError, DnsManager, DnsStats};
pub use fetch::{
    CacheMode, FetchError, FetchRequest, FetchResponse, FetchService, FetchTiming, Protocol,
};
pub use policy::{BlockReason, PolicyEngine, PolicyStats, PolicyVerdict};

/// Top-level errors raised while assembling the network stack.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Invalid configuration.
    #[error("invalid network config: {0}")]
    InvalidConfig(String),
    /// DNS manager failed to initialize.
    #[error("dns init: {0}")]
    DnsInit(String),
    /// Transport failed to initialize (e.g. UDP bind for QUIC).
    #[error("transport init: {0}")]
    Transport(String),
}

/// The full assembled network stack handle (returned by
/// [`FetchService::new`], kept as a convenience for the engine layer).
#[derive(Clone)]
pub struct NetworkStack {
    /// The fetch pipeline.
    pub fetch: Arc<fetch::FetchService>,
}

impl NetworkStack {
    /// Build the whole stack from parts. Thin wrapper around
    /// [`FetchService::new`].
    pub async fn new(
        config: NetworkConfig,
        filters: Arc<bw_privacy::filter::FilterSet>,
        safe_browsing: Arc<bw_privacy::safebrowsing::SafeBrowsingDb>,
        cache: Arc<bw_storage::cache::HttpCache>,
        cookies: Arc<tokio::sync::Mutex<bw_storage::cookies::CookieJar>>,
    ) -> std::result::Result<NetworkStack, NetworkError> {
        let fetch = FetchService::new(config, filters, safe_browsing, cache, cookies).await?;
        Ok(NetworkStack { fetch })
    }
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_config_defaults_sane() {
        let c = NetworkConfig::default();
        assert!(c.enable_http2 && c.enable_http3 && c.https_upgrade && c.hsts);
        assert!(c.validate().is_ok());
    }
}
