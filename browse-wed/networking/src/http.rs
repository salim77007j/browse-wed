//! Pooled HTTP/1.1 + HTTP/2 client.
//!
//! `hyper_util`'s legacy client gives us, for free, exactly what a browser
//! network stack needs:
//!
//! * **connection pooling** keyed by origin, with idle timeouts,
//! * **protocol upgrade by ALPN** — when our connector reports `h2` was
//!   negotiated, hyper transparently speaks HTTP/2 on that connection,
//! * HTTP/1.1 keep-alive and pipelining-safe request framing.
//!
//! We deliberately cap the pool and set short idle timeouts: a browser that
//! holds hundreds of idle sockets open "just in case" is wasting kernel
//! memory (each socket costs buffers) — a core browse-wed no-no.

#![forbid(unsafe_code)]

use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::connector::BrowserConnector;

/// The pooled h1/h2 client handle.
pub struct HttpPool {
    client: Client<BrowserConnector, Full<Bytes>>,
}

impl HttpPool {
    /// Build the pool over a connector.
    pub fn new(connector: BrowserConnector) -> HttpPool {
        let mut builder = Client::builder(TokioExecutor::new());
        // Aggressive pool hygiene: idle sockets die quickly.
        builder
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(4);
        HttpPool {
            client: builder.build(connector),
        }
    }

    /// Issue a request; response body is streamed (`Incoming`).
    pub async fn request(
        &self,
        req: http::Request<Full<Bytes>>,
    ) -> std::result::Result<http::Response<Incoming>, hyper_util::client::legacy::Error> {
        self.client.request(req).await
    }

    /// The shared client handle (cheap clone through Arc internals).
    pub fn handle(&self) -> Client<BrowserConnector, Full<Bytes>> {
        self.client.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn serves_http1_from_local_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Minimal raw HTTP/1.1 responder: read headers, answer 200.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(buf.starts_with(b"GET /ping"));
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\npong!")
                .await
                .unwrap();
        });

        // Connector talking to the local server through System DNS.
        let dns = Arc::new(
            crate::dns::DnsManager::new(crate::config::DnsMode::System)
                .await
                .unwrap(),
        );
        let connector = BrowserConnector::new(
            Arc::clone(&dns),
            Duration::from_secs(3),
            true,
            true,
        );
        let pool = HttpPool::new(connector);

        let req = http::Request::builder()
            .method("GET")
            .uri(format!("http://{addr}/ping"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = pool.request(req).await.unwrap();
        assert_eq!(res.status(), 200);
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"pong!");
        server.await.unwrap();
    }
}
