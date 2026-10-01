//! HTTP/3 (RFC 9114) over QUIC.
//!
//! Uses `quinn` (pure-Rust QUIC) + the `h3` crate. The design:
//!
//! * One process-wide UDP [`quinn::Endpoint`] bound to an ephemeral port.
//! * TLS 1.3 config shared with the h1/h2 path, ALPN `h3` only.
//! * Per-origin connections, kept in a small LRU-style map; the h3
//!   connection driver is spawned on the runtime and the map entry is
//!   dropped (closing the connection) once idle-expired by the caller.
//!
//! HTTP/3 is only used when the origin advertises it via `Alt-Svc` (see
//! `fetch.rs`) or when the URL is explicitly `https://…:443` with a known
//! h3 capability — never guessed, because a failed QUIC handshake costs a
//! full round trip.
//!
//! Zero-RTT resumption is intentionally **disabled**: 0-RTT is replayable
//! and therefore a fingerprinting + integrity hazard for a privacy-first
//! engine.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use http::Request;
use tokio::sync::Mutex;

use crate::dns::DnsManager;
use crate::tls;

/// A live h3 connection to one origin.
struct H3Connection {
    send_request: SendRequest<h3_quinn::OpenStreams, Bytes>,
    _driver: tokio::task::JoinHandle<()>,
}

/// The HTTP/3 client.
pub struct H3Client {
    endpoint: quinn::Endpoint,
    dns: Arc<DnsManager>,
    connections: Mutex<HashMap<String, H3Connection>>,
    connect_timeout: Duration,
}

impl H3Client {
    /// Create the client (binds an ephemeral UDP port).
    pub fn new(dns: Arc<DnsManager>, connect_timeout: Duration) -> std::io::Result<H3Client> {
        let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let mut endpoint = quinn::Endpoint::client(any)?;
        let rustls_cfg = tls::client_config(&[tls::ALPN_H3]);
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| std::io::Error::other(format!("h3 tls init: {e:?}")))?;
        let mut quinn_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        {
            // Idle NAT-friendly keep-alives; browsers keep h3 warm at 30 s.
            let mut transport = quinn::TransportConfig::default();
            transport.keep_alive_interval(Some(Duration::from_secs(15)));
            transport.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(Duration::from_secs(60)).expect("valid timeout"),
            ));
            quinn_config.transport_config(Arc::new(transport));
        }
        endpoint.set_default_client_config(quinn_config);
        Ok(H3Client { endpoint, dns, connections: Mutex::new(HashMap::new()), connect_timeout })
    }

    /// Issue a full request/response round trip over HTTP/3.
    pub async fn request(
        &self,
        url: &url::Url,
        method: &http::Method,
        headers: http::HeaderMap,
        body: Option<Bytes>,
    ) -> std::result::Result<H3Response, H3Error> {
        let origin = origin_key(url);
        let mut guard = self.connections.lock().await;
        if let Some(conn) = guard.get_mut(&origin) {
            match round_trip(conn, url, method, headers.clone(), body.clone()).await {
                Ok(resp) => return Ok(resp),
                // Connection went stale (idle timeout, server restart) —
                // drop it and fall through to a fresh one.
                Err(H3Error::ConnectionClosed) => {
                    guard.remove(&origin);
                }
                Err(e) => return Err(e),
            }
        }
        let mut conn = self.open_connection(url).await?;
        let resp = round_trip(&mut conn, url, method, headers, body).await?;
        guard.insert(origin, conn);
        Ok(resp)
    }

    /// Number of live h3 connections (diagnostics).
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Close the connection to an origin (called when Alt-Svc expires).
    pub async fn close_origin(&self, origin: &str) {
        self.connections.lock().await.remove(origin);
    }

    async fn open_connection(&self, url: &url::Url) -> std::result::Result<H3Connection, H3Error> {
        let host = url.host_str().ok_or(H3Error::NoHost)?.to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs = self.dns.resolve(&host).await.map_err(|e| H3Error::Dns(e.to_string()))?;
        let addr = SocketAddr::new(addrs[0], port);

        let connecting =
            self.endpoint.connect(addr, &host).map_err(|e| H3Error::Quic(e.to_string()))?;
        let quinn_conn = tokio::time::timeout(self.connect_timeout, connecting)
            .await
            .map_err(|_| H3Error::Timeout)?
            .map_err(|e| H3Error::Quic(e.to_string()))?;

        let h3_conn = h3_quinn::Connection::new(quinn_conn);
        let (driver, send_request) =
            h3::client::new(h3_conn).await.map_err(|e| H3Error::H3(e.to_string()))?;
        // Drive the connection in the background until it idles out.
        let _driver = tokio::spawn(async move {
            let mut driver = driver;
            let _ = driver.wait_idle().await;
        });
        Ok(H3Connection { send_request, _driver })
    }
}

/// One round trip on an existing `SendRequest`.
async fn round_trip(
    conn: &mut H3Connection,
    url: &url::Url,
    method: &http::Method,
    headers: http::HeaderMap,
    body: Option<Bytes>,
) -> std::result::Result<H3Response, H3Error> {
    let mut builder = Request::builder().method(method).uri(build_h3_uri(url));
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    let req = builder.body(()).map_err(|e| H3Error::RequestBuild(e.to_string()))?;

    let mut stream = conn
        .send_request
        .send_request(req)
        .await
        .map_err(|e| H3Error::ConnectionClosedFrom(e.to_string()))?;

    if let Some(mut data) = body {
        stream
            .send_data(data.copy_to_bytes(data.remaining()))
            .await
            .map_err(|e| H3Error::Stream(e.to_string()))?;
    }
    stream.finish().await.map_err(|e| H3Error::Stream(e.to_string()))?;

    let response = stream.recv_response().await.map_err(|e| H3Error::Stream(e.to_string()))?;
    let status = response.status();
    let headers = response.headers().clone();

    let mut body_buf: Vec<u8> = Vec::new();
    while let Some(mut chunk) =
        stream.recv_data().await.map_err(|e| H3Error::Stream(e.to_string()))?
    {
        // Safety cap: 64 MiB bodies for h3 path (larger transfers should
        // stream through the h1/h2 path; this cap guards memory).
        if body_buf.len() + chunk.remaining() > 64 * 1024 * 1024 {
            return Err(H3Error::BodyTooLarge);
        }
        while chunk.has_remaining() {
            body_buf.push(chunk.get_u8());
        }
    }

    Ok(H3Response { status, headers, body: Bytes::from(body_buf) })
}

/// A complete h3 response.
pub struct H3Response {
    /// Status code.
    pub status: http::StatusCode,
    /// Response headers.
    pub headers: http::HeaderMap,
    /// Full body (bounded, see `round_trip`).
    pub body: Bytes,
}

/// Origin key for the connection map: `scheme://host:port`.
fn origin_key(url: &url::Url) -> String {
    match url.port() {
        Some(p) => format!("{}://{}:{}", url.scheme(), url.host_str().unwrap_or_default(), p),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
    }
}

/// h3 requests carry authority + path form; we build a minimal URI.
fn build_h3_uri(url: &url::Url) -> http::Uri {
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let pq = match url.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    http::Uri::builder()
        .path_and_query(pq)
        .authority(url.host_str().unwrap_or_default().to_string())
        .scheme(url.scheme())
        .build()
        .unwrap_or(http::Uri::from_static("/"))
}

/// HTTP/3 errors.
#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    /// URL had no host.
    #[error("no host in url")]
    NoHost,
    /// DNS failed.
    #[error("dns: {0}")]
    Dns(String),
    /// Connect timeout.
    #[error("quic connect timeout")]
    Timeout,
    /// QUIC-level error.
    #[error("quic: {0}")]
    Quic(String),
    /// h3 protocol error.
    #[error("h3: {0}")]
    H3(String),
    /// Connection closed (stale, retryable).
    #[error("connection closed")]
    ConnectionClosed,
    /// Send-request failed (connection closed; retryable).
    #[error("send_request failed: {0}")]
    ConnectionClosedFrom(String),
    /// Stream-level error.
    #[error("stream: {0}")]
    Stream(String),
    /// Request build failure.
    #[error("request build: {0}")]
    RequestBuild(String),
    /// Body exceeded the h3 path cap.
    #[error("h3 body exceeds 64 MiB cap")]
    BodyTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_keys() {
        let a = url::Url::parse("https://example.com/x").unwrap();
        let b = url::Url::parse("https://example.com:8443/y").unwrap();
        assert_eq!(origin_key(&a), "https://example.com");
        assert_eq!(origin_key(&b), "https://example.com:8443");
    }

    #[test]
    fn h3_uri_built_with_query() {
        let u = url::Url::parse("https://example.com/a/b?x=1&y=2").unwrap();
        let uri = build_h3_uri(&u);
        assert_eq!(uri.path(), "/a/b");
        // query is preserved on the path+query form
        assert!(uri.path_and_query().unwrap().as_str().contains("x=1"));
    }
}
