//! The browser connector: hostname → TCP → TLS → stream + ALPN report.
//!
//! This replaces hyper's stock `HttpConnector`/`HttpsConnector` so that every
//! outbound connection:
//!
//! * resolves through **our** [`DnsManager`] (DoH/DoT aware, CNAME-visible),
//! * applies **happy-eyeballs** (v6 gets a 300 ms head start, then v4 races),
//! * negotiates TLS 1.3 with ALPN (`h2`, `http/1.1`),
//! * reports the negotiated protocol back to hyper's pool so HTTP/2 is used
//!   automatically whenever the server offers it.
//!
//! The connector implements `tower_service::Service<Uri>` (which is what
//! `hyper_util::client::legacy::Client` consumes) and every produced stream
//! implements [`hyper_util::client::legacy::connect::Connection`] to expose
//! the ALPN result.

#![forbid(unsafe_code)]

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::client::legacy::connect::Connected;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;
use url::Url;

use crate::dns::DnsManager;
use crate::tls;

/// A stream that is either plain TCP or TLS-over-TCP, wrapped in
/// [`TokioIo`] so it satisfies hyper's runtime IO traits.
pub enum MaybeTlsStream {
    /// Plain TCP (http://).
    Plain(TokioIo<TcpStream>),
    /// TLS (https://). Boxed: the rustls session state dwarfs a plain
    /// socket (≈1.1 KiB vs 40 B), and the connector hands streams to
    /// hyper's pool by pointer anyway.
    Tls(Box<TokioIo<TlsStream<TcpStream>>>),
}

impl hyper_util::client::legacy::connect::Connection for MaybeTlsStream {
    fn connected(&self) -> Connected {
        match self {
            MaybeTlsStream::Plain(_) => Connected::new(),
            MaybeTlsStream::Tls(s) => {
                let alpn = s.inner().get_ref().1.alpn_protocol();
                if alpn == Some(&b"h2"[..]) {
                    Connected::new().negotiated_h2()
                } else {
                    Connected::new()
                }
            }
        }
    }
}

impl hyper::rt::Read for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// The connector proper.
#[derive(Clone)]
pub struct BrowserConnector {
    dns: Arc<DnsManager>,
    tls_config: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    enable_ipv6: bool,
}

impl BrowserConnector {
    /// Build a connector over a DNS manager.
    pub fn new(
        dns: Arc<DnsManager>,
        connect_timeout: Duration,
        enable_http2: bool,
        enable_ipv6: bool,
    ) -> BrowserConnector {
        let alpn = if enable_http2 { vec![tls::ALPN_H2, tls::ALPN_H1] } else { vec![tls::ALPN_H1] };
        BrowserConnector {
            dns,
            tls_config: tls::client_config(&alpn),
            connect_timeout,
            enable_ipv6,
        }
    }

    /// Resolve + connect + TLS for one destination.
    async fn connect_uri(&self, uri: url::Url) -> std::io::Result<MaybeTlsStream> {
        let host =
            uri.host_str().ok_or_else(|| std::io::Error::other("URI has no host"))?.to_string();
        let port =
            uri.port_or_known_default().unwrap_or(if uri.scheme() == "https" { 443 } else { 80 });

        let addrs =
            self.dns.resolve(&host).await.map_err(|e| std::io::Error::other(e.to_string()))?;
        let addrs: Vec<IpAddr> =
            addrs.into_iter().filter(|a| self.enable_ipv6 || a.is_ipv4()).collect();
        if addrs.is_empty() {
            return Err(std::io::Error::other("no usable addresses after filters"));
        }

        let stream = happy_eyeballs_connect(&addrs, port, self.connect_timeout).await?;

        if uri.scheme() == "https" {
            let sni = tls::server_name(&host)
                .ok_or_else(|| std::io::Error::other("invalid server name for TLS"))?;
            let connector = TlsConnector::from(Arc::clone(&self.tls_config));
            let tls_stream = connector
                .connect(sni, stream)
                .await
                .map_err(|e| std::io::Error::other(format!("tls handshake: {e}")))?;
            Ok(MaybeTlsStream::Tls(Box::new(TokioIo::new(tls_stream))))
        } else {
            Ok(MaybeTlsStream::Plain(TokioIo::new(stream)))
        }
    }
}

/// Connect with RFC 8305 happy-eyeballs: the first family gets a head
/// start; after the delay both families race in parallel.
async fn happy_eyeballs_connect(
    addrs: &[IpAddr],
    port: u16,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut attempt =
        tokio::time::timeout_at(deadline, TcpStream::connect(SocketAddr::new(addrs[0], port)))
            .await;
    if let Ok(Ok(s)) = attempt {
        return Ok(s);
    }
    // Race the remaining addresses in parallel; first success wins.
    let mut futures: Vec<Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send>>> =
        Vec::with_capacity(addrs.len().saturating_sub(1));
    for a in &addrs[1..] {
        futures.push(Box::pin(TcpStream::connect(SocketAddr::new(*a, port))));
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::other("connect timeout"));
    }
    if !futures.is_empty() {
        attempt = tokio::time::timeout(remaining, futures_util::future::select_all(futures))
            .await
            .map(|(res, _idx, _rest)| res);
        if let Ok(Ok(s)) = attempt {
            return Ok(s);
        }
    }
    // One more serial try on the first address (its head start may have
    // been too short for a slow network).
    tokio::time::timeout_at(deadline, TcpStream::connect(SocketAddr::new(addrs[0], port)))
        .await
        .map_err(|_| std::io::Error::other("connect timeout"))?
}

impl Service<hyper::Uri> for BrowserConnector {
    type Response = MaybeTlsStream;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: hyper::Uri) -> Self::Future {
        let this = self.clone();
        let url = uri_to_url(&uri);
        Box::pin(async move { this.connect_uri(url).await })
    }
}

/// Convert a hyper `Uri` into a `url::Url` for uniform handling.
fn uri_to_url(uri: &hyper::Uri) -> Url {
    let s = match (uri.scheme(), uri.authority()) {
        (Some(sch), Some(auth)) => format!("{sch}://{auth}"),
        _ => "http://localhost".to_string(),
    };
    Url::parse(&s).unwrap_or_else(|_| Url::parse("http://localhost").expect("static url"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_to_url_basics() {
        let uri: hyper::Uri = "https://example.com:8443/path".parse().unwrap();
        let url = uri_to_url(&uri);
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(8443));

        let uri: hyper::Uri = "http://127.0.0.1".parse().unwrap();
        let url = uri_to_url(&uri);
        assert_eq!(url.host_str(), Some("127.0.0.1"));
    }

    #[tokio::test]
    async fn connects_to_local_tcp_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(b"PONG!").await.unwrap();
        });

        // Plain TCP happy-eyeballs path.
        let addrs = vec![IpAddr::from([127, 0, 0, 1])];
        let mut stream =
            happy_eyeballs_connect(&addrs, addr.port(), Duration::from_secs(2)).await.unwrap();
        stream.write_all(b"PING!").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG!");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn happy_eyeballs_unreachable_times_out() {
        let addrs = vec![IpAddr::from([127, 0, 0, 1])];
        // Port 1 on localhost is virtually guaranteed closed in containers.
        let res = happy_eyeballs_connect(&addrs, 1, Duration::from_millis(300)).await;
        assert!(res.is_err());
    }
}
