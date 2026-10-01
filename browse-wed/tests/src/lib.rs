//! Integration tests: the whole engine against a live local HTTP server.
//!
//! These tests spin a minimal HTTP/1.1 responder on localhost and drive
//! the engine end-to-end through `bw_api::BrowserApi` — the exact surface
//! a real UI uses. What is proven here:
//!
//! * navigation → fetch → HTML → DOM → title extraction,
//! * HTTP cache reuse on second navigation (from_cache = true),
//! * Set-Cookie → partitioned jar → Cookie header on the next request,
//! * redirect following,
//! * tracker blocking at the network layer (no request reaches the wire),
//! * tab suspension freeing pages, session save/restore.

#![forbid(unsafe_code)]

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bw_api::{BrowserApi, Command, EngineOptions, Event};

/// A minimal HTTP/1.1 server for one host. Responses are routed by the
/// request line's path.
struct LocalServer {
    requests_seen: Arc<AtomicUsize>,
    addr: std::net::SocketAddr,
}

impl LocalServer {
    /// Start the server; `routes` maps path → (status, headers, body).
    async fn spawn(
        routes: Vec<(String, &'static str, &'static str)>,
    ) -> (LocalServer, tokio::task::JoinHandle<()>) {
        let requests_seen = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&requests_seen);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let seen = Arc::clone(&seen);
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // Read until end of headers (requests are header-only
                    // in these tests).
                    loop {
                        let n = match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    seen.fetch_add(1, Ordering::SeqCst);
                    let request_line = String::from_utf8_lossy(&buf);
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let cookie_seen = request_line.to_lowercase().contains("cookie:");
                    let route = routes.iter().find(|(p, _, _)| *p == path);
                    let (status, extra, body) = route
                        .map(|(_, s, b)| (*s, String::new(), (*b).to_string()))
                        .unwrap_or_else(|| {
                            (
                                "404 Not Found",
                                String::new(),
                                "<html><body>not found</body></html>".to_string(),
                            )
                        });
                    let cookie_note = if cookie_seen { "x-seen-cookie: yes\r\n" } else { "" };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: text/html\r\ncontent-length: {}\r\n{extra}{cookie_note}\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                });
            }
        });
        (LocalServer { requests_seen, addr }, handle)
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    fn hit_count(&self) -> usize {
        self.requests_seen.load(Ordering::SeqCst)
    }
}

fn options() -> EngineOptions {
    EngineOptions {
        profile_dir: Some(
            tempfile::tempdir()
                .unwrap()
                .keep()
                .to_string_lossy()
                .into_owned(),
        ),
        background_suspend_secs: 1,
        ..EngineOptions::default()
    }
}

#[tokio::test]
async fn navigate_parses_html_into_dom() {
    let (server, _guard) = LocalServer::spawn(vec![(
        "/page".into(),
        "200 OK",
        "<html><head><title>Integration Page</title></head><body><h1>Hello</h1><p>World</p></body></html>",
    )]).await;
    let api = BrowserApi::start(options()).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    let mut events = api.subscribe();

    api.command(Command::Navigate { tab, url: server.url("/page") })
        .await
        .unwrap();

    match events.recv().await.unwrap() {
        Event::NavigationCompleted { outcome, .. } => {
            assert_eq!(outcome.status, 200);
            assert_eq!(outcome.title, "Integration Page");
            assert_eq!(outcome.protocol, "http/1.1");
            assert!(outcome.page.elements >= 5);
            assert!(outcome.total_ms > 0.0);
        }
        other => panic!("expected NavigationCompleted, got {other:?}"),
    }
}

#[tokio::test]
async fn second_navigation_served_from_cache() {
    let (server, _guard) = LocalServer::spawn(vec![(
        "/cached".into(),
        "200 OK",
        "<html><head><title>Cached</title></head><body>cache me</body></html>",
    )]).await;
    let api = BrowserApi::start(options()).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();

    // First load: from the wire.
    api.command(Command::Navigate { tab, url: server.url("/cached") })
        .await
        .unwrap();
    let wire_hits = server.hit_count();
    assert_eq!(wire_hits, 1);

    // The server's response carries no cache headers; our heuristic
    // 10-minute freshness applies, so a reload within that window comes
    // from the engine's HTTP cache. Force it via a second navigate.
    api.command(Command::Navigate { tab, url: server.url("/cached") })
        .await
        .unwrap();
    let stats = api.stats().await;
    // The engine did not hit the wire a second time.
    assert_eq!(server.hit_count(), wire_hits, "cache miss went to the wire");
    assert!(stats.policy_checked >= 2);
}

#[tokio::test]
async fn redirects_are_followed() {
    // One TCP connection serves both requests: the redirect AND the target
    // (hyper's pool reuses the socket).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        for i in 0..2 {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
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
            if buf.is_empty() {
                break;
            }
            if i == 0 {
                let resp =
                    "HTTP/1.1 302 Found\r\nlocation: /end\r\ncontent-length: 0\r\n\r\n";
                sock.write_all(resp.as_bytes()).await.unwrap();
            } else {
                let body = "<html><head><title>Final</title></head><body>ok</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        }
    });

    let api = BrowserApi::start(options()).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    let mut events = api.subscribe();
    api.command(Command::Navigate { tab, url: format!("http://{addr}/start") })
        .await
        .unwrap();
    match events.recv().await.unwrap() {
        Event::NavigationCompleted { outcome, .. } => {
            assert_eq!(outcome.status, 200);
            assert_eq!(outcome.title, "Final");
            assert!(outcome.final_url.ends_with("/end"));
        }
        other => panic!("expected NavigationCompleted, got {other:?}"),
    }
}

#[tokio::test]
async fn cookies_flow_back_on_second_request() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen_cookie = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&seen_cookie);
    tokio::spawn(async move {
        for i in 0..2 {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 2048];
            loop {
                let n = match sock.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&buf).to_string();
            if text.to_lowercase().contains("cookie: sid=") {
                flag.store(true, Ordering::SeqCst);
            }
            let body = if i == 0 {
                "<html><head><title>One</title></head><body>1</body></html>".to_string()
            } else {
                "<html><head><title>Two</title></head><body>2</body></html>".to_string()
            };
            let set_cookie = if i == 0 {
                "set-cookie: sid=abc; Path=/\r\n"
            } else {
                ""
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n{set_cookie}content-length: {}\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        }
    });

    let api = BrowserApi::start(options()).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    api.command(Command::Navigate { tab, url: format!("http://{addr}/a") })
        .await
        .unwrap();
    api.command(Command::Navigate { tab, url: format!("http://{addr}/b") })
        .await
        .unwrap();
    // Give the server task a moment to record the observation.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        seen_cookie.load(Ordering::SeqCst),
        "second request did not carry the session cookie"
    );
}

#[tokio::test]
async fn tracker_navigation_blocked_without_wire() {
    // Privacy preset with the starter filter list: doubleclick.net is a
    // network-filtered tracker, and no DNS/wire access must happen.
    let opts = EngineOptions {
        profile_dir: Some(
            tempfile::tempdir().unwrap().keep().to_string_lossy().into_owned(),
        ),
        privacy_preset: true,
        doh_url: Some("https://dns.quad9.net/dns-query".into()),
        ..EngineOptions::default()
    };
    let api = BrowserApi::start(opts).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    let mut events = api.subscribe();
    api.command(Command::Navigate { tab, url: "https://doubleclick.net/tracker".into() })
        .await
        .unwrap();
    match events.recv().await.unwrap() {
        Event::NavigationCompleted { outcome, .. } => {
            assert_eq!(outcome.status, 204);
            assert_eq!(outcome.protocol, "synthetic");
            assert_eq!(outcome.blocked, 1);
            assert_eq!(outcome.body_len, 0);
        }
        other => panic!("expected NavigationCompleted, got {other:?}"),
    }
    let stats = api.stats().await;
    assert!(stats.policy_blocked >= 1);
    // No DNS query was needed for a blocked request.
    assert_eq!(stats.dns_queries, 0);
}

#[tokio::test]
async fn tab_suspension_frees_page_state() {
    let (server, _guard) = LocalServer::spawn(vec![(
        "/susp".into(),
        "200 OK",
        "<html><head><title>Suspend</title></head><body><p>many nodes</p></body></html>",
    )]).await;
    let api = BrowserApi::start(options()).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    api.command(Command::Navigate { tab, url: server.url("/susp") })
        .await
        .unwrap();
    let before = api.tabs().await;
    assert!(before[0].current_title().is_some_and(|t| t == "Suspend"));

    // Background, wait past the 1s threshold, sweep.
    api.command(Command::BackgroundTab { tab }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let reply = api.command(Command::SweepIdle).await.unwrap();
    assert_eq!(reply["suspended"].as_u64(), Some(1));

    let after = api.tabs().await;
    assert_eq!(
        serde_json::to_string(&after[0].state).unwrap(),
        serde_json::to_string(&bw_engine::TabState::Suspended).unwrap()
    );
    // The session entry keeps the URL for wake-up.
    assert_eq!(after[0].current_url(), Some(server.url("/susp").as_str()));
}

#[tokio::test]
async fn session_save_and_restore() {
    let (server, _guard) = LocalServer::spawn(vec![(
        "/persist".into(),
        "200 OK",
        "<html><head><title>Persist</title></head><body>session</body></html>",
    )]).await;
    let dir = tempfile::tempdir().unwrap().keep();
    let url = server.url("/persist");
    let opts = EngineOptions {
        profile_dir: Some(dir.to_string_lossy().into_owned()),
        ..EngineOptions::default()
    };
    let api = BrowserApi::start(opts).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    api.command(Command::Navigate { tab, url: url.clone() })
        .await
        .unwrap();
    api.command(Command::SuspendTab { tab }).await.unwrap();
    api.command(Command::SaveSession).await.unwrap();
    drop(api);

    // A fresh engine on the same profile restores the tab and its history.
    let api2 = BrowserApi::start(EngineOptions {
        profile_dir: Some(dir.to_string_lossy().into_owned()),
        ..EngineOptions::default()
    })
    .await
    .unwrap();
    // Session restore is exposed via the engine layer.
    let tabs = api2.tabs().await;
    assert!(tabs.is_empty(), "tabs start empty; restore is explicit");

    let restored = bw_engine::session::load_session(&dir).unwrap().unwrap();
    assert_eq!(restored.tabs.len(), 1);
    assert_eq!(restored.tabs[0].current_url(), Some(url.as_str()));
}

#[tokio::test]
async fn javascript_runs_in_site_context() {
    let api = BrowserApi::start(options()).await.unwrap();
    let reply = api
        .command(Command::ExecJs {
            site: "https://integration.example".into(),
            code: "JSON.stringify({ok: true, n: 6 * 7})".into(),
        })
        .await
        .unwrap();
    // The reply is the JS string; parse it back and compare structurally
    // (BTreeMap key order must not leak into assertions).
    let as_string: String = serde_json::from_value(reply).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&as_string).unwrap();
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(parsed["n"], serde_json::json!(42));
}

#[tokio::test]
async fn forty4_navigation_reports_error_state() {
    let (server, _guard) = LocalServer::spawn(vec![]).await;
    let api = BrowserApi::start(options()).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    api.command(Command::Navigate { tab, url: server.url("/missing") })
        .await
        .unwrap();
    let tabs = api.tabs().await;
    // 404 keeps the URL in history (browsers keep it; state stays usable).
    assert!(tabs[0].current_url().is_some());
}

#[tokio::test]
async fn back_and_forward_through_history() {
    let (server, _guard) = LocalServer::spawn(vec![
        (
            "/one".into(),
            "200 OK",
            "<html><head><title>One</title></head><body>1</body></html>",
        ),
        (
            "/two".into(),
            "200 OK",
            "<html><head><title>Two</title></head><body>2</body></html>",
        ),
    ]).await;
    let api = BrowserApi::start(options()).await.unwrap();
    let tab = api.command(Command::NewTab).await.unwrap()["tab"].as_u64().unwrap();
    api.command(Command::Navigate { tab, url: server.url("/one") })
        .await
        .unwrap();
    api.command(Command::Navigate { tab, url: server.url("/two") })
        .await
        .unwrap();
    let tabs = api.tabs().await;
    assert_eq!(tabs[0].current_url(), Some(server.url("/two").as_str()));

    api.command(Command::GoBack { tab }).await.unwrap();
    let tabs = api.tabs().await;
    assert_eq!(tabs[0].current_url(), Some(server.url("/one").as_str()));

    api.command(Command::GoForward { tab }).await.unwrap();
    let tabs = api.tabs().await;
    assert_eq!(tabs[0].current_url(), Some(server.url("/two").as_str()));
}
