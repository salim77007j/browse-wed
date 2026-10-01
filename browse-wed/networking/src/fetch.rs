//! The fetch pipeline — one function standing between a URL and the socket.
//!
//! ```text
//! FetchRequest
//!   │
//!   ├─① policy.check            → Block / Neuter / Warn / Allow
//!   ├─② policy.upgrade_url      → http→https, HSTS
//!   ├─③ cache.get_fresh         → 200-from-cache short-circuit
//!   ├─④ build request           → UA/Accept/Sec-Fetch headers + cookie line
//!   ├─⑤ transport               → h3 (Alt-Svc) or h1/h2 pool
//!   ├─⑥ redirects               → ≤ max_redirects, policy re-checked
//!   ├─⑦ Set-Cookie              → partitioned cookie jar (CHIPS)
//!   ├─⑧ HSTS / Alt-Svc learning → policy engine
//!   └─⑨ cache.put               → if cacheable
//!   ▼
//! FetchResponse { status, headers, body, from_cache, protocol, timing }
//! ```
//!
//! Design rules:
//! * **No I/O before policy.** A blocked tracker never costs a DNS query,
//!   let alone a TLS handshake — that is what makes content blocking here
//!   faster than extension-based blocking (Chrome's extension path blocks
//!   only after the request object exists).
//! * **Privacy-safe synthetic responses.** Blocked/neutered requests return
//!   synthetic `200 empty` / `204` responses with `X-bw-Blocked: <reason>`,
//!   so the loading page's promise machinery settles normally.
//! * **All timing captured.** Every fetch returns dns/connect/tls/ttfb/total
//!   timings — the data the UI performance panel and the benchmark suite
//!   consume.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use tokio::sync::Mutex;

use bw_privacy::{RequestContext, ResourceType};
use bw_storage::cache::{CacheMeta, HttpCache};
use bw_storage::cookies::CookieJar;
use url::Url;

use crate::config::NetworkConfig;
use crate::connector::BrowserConnector;
use crate::dns::DnsManager;
use crate::h3::{H3Client, H3Error};
use crate::http::HttpPool;
use crate::policy::{BlockReason, PolicyEngine, PolicyVerdict};

/// How the cache participates in a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheMode {
    /// Standard: serve fresh hits, revalidate stale, store cacheable.
    #[default]
    Default,
    /// Bypass cache read and write (reload button).
    NoStore,
    /// Only serve from cache; network is an error.
    OnlyIfCached,
}

/// A request to the fetch pipeline.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// Absolute target URL.
    pub url: Url,
    /// HTTP method.
    pub method: http::Method,
    /// Extra headers supplied by the caller (script `fetch()` headers etc.).
    pub headers: http::HeaderMap,
    /// Optional body (POST/PUT).
    pub body: Option<Bytes>,
    /// Resource classification for the filter engine.
    pub resource_type: ResourceType,
    /// Top-level site host (first-party context, CHIPS partition key).
    pub top_level_site: String,
    /// Registrable domain of the first party.
    pub source_base: String,
    /// True for top-level document navigations.
    pub is_top_level_navigation: bool,
    /// Cache participation.
    pub cache_mode: CacheMode,
}

impl FetchRequest {
    /// A plain GET navigation to `url`.
    pub fn navigation(url: Url) -> FetchRequest {
        let host = url.host_str().unwrap_or_default().to_string();
        let source_base = registrable(&host);
        FetchRequest {
            url,
            method: http::Method::GET,
            headers: http::HeaderMap::new(),
            body: None,
            resource_type: ResourceType::DOCUMENT,
            top_level_site: host,
            source_base,
            is_top_level_navigation: true,
            cache_mode: CacheMode::Default,
        }
    }

    /// A subresource request in the context of `top_level_site`.
    pub fn subresource(
        url: Url,
        top_level_site: &str,
        resource_type: ResourceType,
    ) -> FetchRequest {
        let source_base = registrable(top_level_site);
        FetchRequest {
            url,
            method: http::Method::GET,
            headers: http::HeaderMap::new(),
            body: None,
            resource_type,
            top_level_site: top_level_site.to_string(),
            source_base,
            is_top_level_navigation: false,
            cache_mode: CacheMode::Default,
        }
    }

    /// The filter-engine view of this request.
    pub fn request_context(&self) -> RequestContext {
        RequestContext {
            url: self.url.clone(),
            source_host: self.top_level_site.clone(),
            source_base: self.source_base.clone(),
            resource_type: self.resource_type,
        }
    }
}

/// Timing breakdown of one fetch.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct FetchTiming {
    /// Milliseconds spent in DNS (0 when cached / IP literal).
    pub dns_ms: f64,
    /// Milliseconds to establish the connection (TCP or QUIC).
    pub connect_ms: f64,
    /// Milliseconds for the TLS handshake (0 for plain http).
    pub tls_ms: f64,
    /// Milliseconds to the first response byte.
    pub ttfb_ms: f64,
    /// Total milliseconds.
    pub total_ms: f64,
}

/// Which wire protocol served the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP/1.1 over TCP (+TLS).
    Http1,
    /// HTTP/2 over TLS.
    Http2,
    /// HTTP/3 over QUIC.
    Http3,
    /// Synthetic: served from cache without transport.
    Cache,
    /// Synthetic: blocked/neutered by policy.
    Synthetic,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::Http1 => "http/1.1",
            Protocol::Http2 => "h2",
            Protocol::Http3 => "h3",
            Protocol::Cache => "cache",
            Protocol::Synthetic => "synthetic",
        };
        f.write_str(s)
    }
}

/// The outcome of a fetch.
#[derive(Debug)]
pub struct FetchResponse {
    /// Final status code.
    pub status: http::StatusCode,
    /// Final response headers (redirect chains not included).
    pub headers: http::HeaderMap,
    /// Body bytes.
    pub body: Bytes,
    /// Final URL after redirects.
    pub final_url: Url,
    /// Served from cache?
    pub from_cache: bool,
    /// Transport used.
    pub protocol: Protocol,
    /// Timings.
    pub timing: FetchTiming,
    /// Why a synthetic block happened, if it did.
    pub blocked_reason: Option<BlockReason>,
}

impl FetchResponse {
    /// A synthetic blocked response.
    fn synthetic_block(url: Url, reason: BlockReason) -> FetchResponse {
        let mut headers = http::HeaderMap::new();
        let why = match reason {
            BlockReason::NetworkFilter => "network-filter",
            BlockReason::CnameCloaked => "cname-cloaked",
            BlockReason::SafeBrowsing => "safe-browsing",
        };
        let _ = headers.insert("x-bw-blocked", why.parse().expect("static header value"));
        let _ = headers.insert("content-type", "text/plain".parse().unwrap());
        FetchResponse {
            status: http::StatusCode::NO_CONTENT,
            headers,
            body: Bytes::new(),
            final_url: url,
            from_cache: false,
            protocol: Protocol::Synthetic,
            timing: FetchTiming::default(),
            blocked_reason: Some(reason),
        }
    }

    /// A synthetic neutered response (empty 200 for script/img slots).
    fn synthetic_neuter(url: Url) -> FetchResponse {
        let mut headers = http::HeaderMap::new();
        let _ = headers.insert("x-bw-blocked", "network-filter".parse().unwrap());
        FetchResponse {
            status: http::StatusCode::OK,
            headers,
            body: Bytes::new(),
            final_url: url,
            from_cache: false,
            protocol: Protocol::Synthetic,
            timing: FetchTiming::default(),
            blocked_reason: Some(BlockReason::NetworkFilter),
        }
    }
}

/// Fetch errors.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Policy refused and the caller wanted an error (not a synthetic).
    #[error("blocked by policy: {0:?}")]
    Blocked(BlockReason),
    /// DNS resolution failure.
    #[error("dns: {0}")]
    Dns(String),
    /// Transport failure.
    #[error("transport: {0}")]
    Transport(String),
    /// Body read failure.
    #[error("body: {0}")]
    Body(String),
    /// Too many redirects.
    #[error("too many redirects (limit {0})")]
    TooManyRedirects(usize),
    /// Cache-miss in OnlyIfCached mode.
    #[error("cache miss in only-if-cached mode")]
    CacheMiss,
    /// Invalid URL / request shape.
    #[error("invalid request: {0}")]
    Invalid(String),
    /// Request exceeded its timeout.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

/// The fetch service: everything wired together.
pub struct FetchService {
    config: NetworkConfig,
    dns: Arc<DnsManager>,
    policy: Arc<PolicyEngine>,
    http_pool: HttpPool,
    h3: Option<Arc<H3Client>>,
    cache: Arc<HttpCache>,
    cookies: Arc<Mutex<CookieJar>>,
}

impl FetchService {
    /// Assemble the whole stack from a config and privacy primitives.
    pub async fn new(
        config: NetworkConfig,
        filters: Arc<bw_privacy::filter::FilterSet>,
        safe_browsing: Arc<bw_privacy::safebrowsing::SafeBrowsingDb>,
        cache: Arc<HttpCache>,
        cookies: Arc<Mutex<CookieJar>>,
    ) -> Result<Arc<FetchService>, crate::NetworkError> {
        config.validate().map_err(crate::NetworkError::InvalidConfig)?;
        let dns = DnsManager::new(config.dns.clone())
            .await
            .map_err(|e| crate::NetworkError::DnsInit(e.to_string()))?;
        let policy = Arc::new(PolicyEngine::new(&config, filters, safe_browsing));
        let connector = BrowserConnector::new(
            Arc::clone(&dns),
            config.connect_timeout,
            config.enable_http2,
            config.enable_ipv6,
        );
        let http_pool = HttpPool::new(connector);
        let h3 = if config.enable_http3 {
            Some(Arc::new(
                H3Client::new(Arc::clone(&dns), config.connect_timeout)
                    .map_err(|e| crate::NetworkError::Transport(e.to_string()))?,
            ))
        } else {
            None
        };
        Ok(Arc::new(FetchService { config, dns, policy, http_pool, h3, cache, cookies }))
    }

    /// The policy engine (for tests / UI diagnostics).
    pub fn policy(&self) -> &Arc<PolicyEngine> {
        &self.policy
    }

    /// The DNS manager (for CNAME inspection by the engine layer).
    pub fn dns(&self) -> &Arc<DnsManager> {
        &self.dns
    }

    /// Run one fetch through the whole pipeline.
    pub async fn fetch(&self, mut req: FetchRequest) -> Result<FetchResponse, FetchError> {
        let started = Instant::now();

        // ① Policy (before ANY I/O).
        let ctx = req.request_context();
        match self.policy.check(&ctx, req.is_top_level_navigation) {
            PolicyVerdict::Block(reason) => {
                return Ok(FetchResponse::synthetic_block(req.url, reason))
            }
            PolicyVerdict::Neuter => return Ok(FetchResponse::synthetic_neuter(req.url)),
            PolicyVerdict::Warn(reason) => {
                // Navigation warnings: the UI layer decides; until it
                // interposes, we return the warning as a synthetic page.
                return Ok(FetchResponse::synthetic_block(req.url, reason));
            }
            PolicyVerdict::Allow => {}
        }

        // ② HTTPS upgrade / HSTS.
        if let Some(upgraded) = self.policy.upgrade_url(&req.url, req.is_top_level_navigation) {
            req.url = upgraded;
        }

        // ③ Cache lookup.
        if req.method == http::Method::GET && req.cache_mode != CacheMode::NoStore {
            if let Some((meta, body)) = self.cache.get_fresh(req.url.as_str(), None) {
                if req.cache_mode == CacheMode::OnlyIfCached
                    || meta.is_fresh(std::time::SystemTime::now())
                {
                    return Ok(FetchResponse {
                        status: http::StatusCode::from_u16(meta.status)
                            .unwrap_or(http::StatusCode::OK),
                        headers: cache_meta_headers(&meta),
                        body: Bytes::from(body),
                        final_url: req.url,
                        from_cache: true,
                        protocol: Protocol::Cache,
                        timing: elapsed_timing(started),
                        blocked_reason: None,
                    });
                }
            }
        }
        if req.cache_mode == CacheMode::OnlyIfCached {
            return Err(FetchError::CacheMiss);
        }

        // ④-⑥ Send (with redirect following).
        let mut redirects_left = self.config.max_redirects;
        let mut current = req.clone();
        loop {
            let outcome = self.send_once(&current, started).await?;
            if let SendOutcome::Redirect { status, location } = outcome {
                if redirects_left == 0 {
                    return Err(FetchError::TooManyRedirects(self.config.max_redirects));
                }
                redirects_left -= 1;
                let next_url = resolve_url(&current.url, &location)
                    .ok_or_else(|| FetchError::Invalid("bad redirect location".into()))?;
                // Re-run policy for the new target.
                current.url = next_url;
                let ctx = current.request_context();
                match self.policy.check(&ctx, current.is_top_level_navigation) {
                    PolicyVerdict::Block(reason) => {
                        return Ok(FetchResponse::synthetic_block(current.url, reason))
                    }
                    PolicyVerdict::Neuter => {
                        return Ok(FetchResponse::synthetic_neuter(current.url))
                    }
                    PolicyVerdict::Warn(reason) => {
                        return Ok(FetchResponse::synthetic_block(current.url, reason))
                    }
                    PolicyVerdict::Allow => {}
                }
                // Redirects switch method per RFC 9110 (301/302/303 → GET).
                if matches!(status.as_u16(), 301..=303) {
                    current.method = http::Method::GET;
                    current.body = None;
                }
                continue;
            }
            let mut resp = match outcome {
                SendOutcome::Redirect { .. } => unreachable!(),
                SendOutcome::Complete(resp) => {
                    let mut resp = *resp;
                    // ⑦ Cookies from this response.
                    self.store_cookies(&current, &resp).await;
                    // ⑧ HSTS / Alt-Svc learning.
                    self.learn_from_response(&resp, &current.url).await;
                    // ⑨ Cache store.
                    if current.method == http::Method::GET
                        && current.cache_mode != CacheMode::NoStore
                    {
                        maybe_store_cache(&self.cache, &current.url, &mut resp);
                    }
                    resp
                }
            };
            resp.timing.total_ms = started.elapsed().as_secs_f64() * 1000.0;
            return Ok(resp);
        }
    }

    /// One transport round trip (no redirect handling).
    async fn send_once(
        &self,
        req: &FetchRequest,
        started: Instant,
    ) -> Result<SendOutcome, FetchError> {
        let is_https = req.url.scheme() == "https";

        // ④ Headers: UA, accepts, sec-fetch-*, cookies.
        let mut headers = http::HeaderMap::new();
        let _ = headers.insert("user-agent", self.config.user_agent.parse().unwrap());
        let _ = headers.insert("accept", accept_for(req.resource_type).parse().unwrap());
        let _ = headers.insert("accept-language", self.config.accept_language.parse().unwrap());
        let _ = headers.insert("accept-encoding", "gzip, deflate".parse().unwrap());
        let sec_fetch = match req.is_top_level_navigation {
            true => "navigate",
            false => match req.resource_type {
                r if r == ResourceType::SCRIPT => "script",
                r if r == ResourceType::IMAGE => "image",
                r if r == ResourceType::STYLESHEET => "style",
                _ => "empty",
            },
        };
        let _ = headers.insert("sec-fetch-dest", "empty".parse().unwrap());
        let _ = headers.insert("sec-fetch-mode", sec_fetch.parse().unwrap());
        let _ = headers.insert("sec-fetch-site", site_for(req).parse().unwrap());
        for (name, value) in &req.headers {
            headers.insert(name, value.clone());
        }
        let cookie_line = {
            let jar = self.cookies.lock().await;
            jar.get_for(req.url.as_str(), &req.top_level_site, is_https)
        };
        if !cookie_line.is_empty() {
            let _ = headers.insert("cookie", cookie_line.parse().unwrap());
        }

        // ⑤ Transport choice: Alt-Svc h3 → h3 client; else h1/h2 pool.
        let origin = origin_of(&req.url);
        let h3_authority = self.policy.alt_svc_h3(&origin);
        if is_https && h3_authority.is_some() && self.config.enable_http3 {
            if let Some(h3) = self.h3.as_ref() {
                let h3_url = rewrite_port(req.url.clone(), h3_authority.as_deref());
                match h3.request(&h3_url, &req.method, headers.clone(), req.body.clone()).await {
                    Ok(resp) => {
                        return Ok(SendOutcome::Complete(Box::new(FetchResponse {
                            status: resp.status,
                            headers: resp.headers,
                            body: resp.body,
                            final_url: req.url.clone(),
                            from_cache: false,
                            protocol: Protocol::Http3,
                            timing: elapsed_timing(started),
                            blocked_reason: None,
                        })));
                    }
                    Err(H3Error::ConnectionClosed | H3Error::ConnectionClosedFrom(_)) => {
                        h3.close_origin(&origin).await;
                        // fall through to h1/h2
                    }
                    Err(e) => {
                        // h3 attempted and failed hard: retry once over h1/h2
                        // (browsers must not fail the load just because QUIC
                        // is unreachable — RFC 9114 racing fallback).
                        tracing::debug!(error = %e, "h3 failed; falling back to h1/h2");
                    }
                }
            }
        }

        // h1/h2 path.
        let mut builder =
            http::Request::builder().method(req.method.clone()).uri(build_uri(&req.url));
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        let body = Full::new(req.body.clone().unwrap_or_default());
        let http_req = builder.body(body).map_err(|e| FetchError::Invalid(e.to_string()))?;

        let send_started = Instant::now();
        let fut = self.http_pool.request(http_req);
        let response = if self.config.request_timeout.is_zero() {
            fut.await.map_err(|e| FetchError::Transport(e.to_string()))?
        } else {
            tokio::time::timeout(self.config.request_timeout, fut)
                .await
                .map_err(|_| FetchError::Timeout(self.config.request_timeout))?
                .map_err(|e| FetchError::Transport(e.to_string()))?
        };
        let ttfb = send_started.elapsed().as_secs_f64() * 1000.0;

        let status = response.status();
        let resp_headers = response.headers().clone();
        if is_redirect(status) {
            let location = resp_headers
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            return Ok(SendOutcome::Redirect { status, location });
        }
        // Protocol truth: hyper sets the response version to the wire
        // protocol actually used (HTTP/2.0 / HTTP/3.0).
        let protocol = match response.version() {
            http::Version::HTTP_2 => Protocol::Http2,
            http::Version::HTTP_3 => Protocol::Http3,
            _ => Protocol::Http1,
        };
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .map_err(|e| FetchError::Body(e.to_string()))?
            .to_bytes();

        let timing = FetchTiming {
            dns_ms: 0.0, // connector-internal; exposed via DnsManager stats
            connect_ms: 0.0,
            tls_ms: 0.0,
            ttfb_ms: ttfb,
            total_ms: started.elapsed().as_secs_f64() * 1000.0,
        };
        Ok(SendOutcome::Complete(Box::new(FetchResponse {
            status,
            headers: resp_headers,
            body,
            final_url: req.url.clone(),
            from_cache: false,
            protocol,
            timing,
            blocked_reason: None,
        })))
    }

    /// ⑦ Store Set-Cookie responses into the partitioned jar.
    async fn store_cookies(&self, req: &FetchRequest, resp: &FetchResponse) {
        let host = req.url.host_str().unwrap_or_default().to_string();
        let is_secure = req.url.scheme() == "https";
        let values: Vec<String> = resp
            .headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();
        if values.is_empty() {
            return;
        }
        let mut jar = self.cookies.lock().await;
        for v in values {
            if let Some(stored) = jar.parse_set_cookie(&v, &host, &req.top_level_site, is_secure) {
                tracing::debug!(name = %stored.name, "cookie stored");
            }
        }
    }

    /// ⑧ Learn HSTS and Alt-Svc from response headers.
    async fn learn_from_response(&self, resp: &FetchResponse, url: &Url) {
        let host = url.host_str().unwrap_or_default().to_string();
        if url.scheme() != "https" {
            return;
        }
        if let Some(sts) =
            resp.headers.get(http::header::STRICT_TRANSPORT_SECURITY).and_then(|v| v.to_str().ok())
        {
            self.policy.observe_hsts(&host, sts);
        }
        if let Some(alt) = resp.headers.get(http::header::ALT_SVC).and_then(|v| v.to_str().ok()) {
            let origin = origin_of(url);
            self.policy.observe_alt_svc(&origin, alt);
        }
    }
}

enum SendOutcome {
    Redirect { status: http::StatusCode, location: String },
    Complete(Box<FetchResponse>),
}

/// Registrable-ish domain (last two labels; adequate for engine-internal
/// first-party classification — full PSL is roadmap).
pub(crate) fn registrable(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

fn is_redirect(status: http::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn resolve_url(base: &Url, location: &str) -> Option<Url> {
    if location.is_empty() {
        return None;
    }
    base.join(location).ok()
}

fn origin_of(url: &Url) -> String {
    match url.port() {
        Some(p) => format!("{}://{}:{}", url.scheme(), url.host_str().unwrap_or_default(), p),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
    }
}

fn rewrite_port(mut url: Url, authority: Option<&str>) -> Url {
    if let Some(auth) = authority {
        if let Some(port_str) = auth.rsplit(':').next() {
            if let Ok(port) = port_str.parse::<u16>() {
                let _ = url.set_port(Some(port));
            }
        }
    }
    url
}

fn build_uri(url: &Url) -> http::Uri {
    // Absolute-form URI: the legacy client derives the origin from it and
    // writes origin-form on plain (non-proxy) connections.
    http::Uri::try_from(url.as_str()).unwrap_or(http::Uri::from_static("/"))
}

fn site_for(req: &FetchRequest) -> &'static str {
    let target = req.url.host_str().unwrap_or_default();
    if target.eq_ignore_ascii_case(&req.top_level_site) {
        "same-origin"
    } else if registrable(target) == req.source_base {
        "same-site"
    } else {
        "cross-site"
    }
}

fn accept_for(ty: ResourceType) -> &'static str {
    if ty == ResourceType::DOCUMENT {
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    } else if ty == ResourceType::IMAGE {
        "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"
    } else if ty == ResourceType::STYLESHEET {
        "text/css,*/*;q=0.1"
    } else {
        "*/*"
    }
}

fn elapsed_timing(started: Instant) -> FetchTiming {
    FetchTiming { total_ms: started.elapsed().as_secs_f64() * 1000.0, ..FetchTiming::default() }
}

fn cache_meta_headers(meta: &CacheMeta) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    let _ = headers.insert(
        "content-type",
        meta.content_type.parse().unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    if let Some(etag) = &meta.etag {
        let _ = headers.insert(http::header::ETAG, etag.parse().unwrap());
    }
    if let Some(lm) = &meta.last_modified {
        let _ = headers.insert(http::header::LAST_MODIFIED, lm.parse().unwrap());
    }
    let _ = headers.insert("x-bw-cache", "hit".parse().unwrap());
    headers
}

fn maybe_store_cache(cache: &Arc<HttpCache>, url: &Url, resp: &mut FetchResponse) {
    if !resp.status.is_success() || resp.status != http::StatusCode::OK {
        return;
    }
    if resp.headers.contains_key("cache-control") {
        let cc = resp
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if cc.contains("no-store") || cc.contains("no-cache") {
            return;
        }
    }
    let content_type = resp
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let etag =
        resp.headers.get(http::header::ETAG).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let last_modified = resp
        .headers
        .get(http::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let max_age = resp
        .headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .and_then(|cc| {
            cc.split(',')
                .find_map(|p| p.trim().strip_prefix("max-age="))
                .and_then(|n| n.trim().parse::<u64>().ok())
        })
        .unwrap_or(600); // heuristic 10-minute floor for 200s without hints
    let expires_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + max_age)
        .unwrap_or(0);
    let body = std::mem::take(&mut resp.body);
    let meta = CacheMeta {
        status: resp.status.as_u16(),
        content_type,
        etag,
        last_modified,
        expires_unix,
        vary: Vec::new(),
        body_len: body.len(),
        stored_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    cache.put(url.as_str(), None, meta, body.to_vec());
    resp.body = body;
}
