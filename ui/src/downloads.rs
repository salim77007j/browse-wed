//! Download manager — every byte flows through the engine's fetch pipeline
//! (policy filters, cache, cookies, HTTPS upgrades). Pause/resume uses
//! HTTP range requests in bounded chunks so memory stays flat.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bw_engine::BrowserEngine;
use bw_network::fetch::FetchRequest;
use bw_privacy::ResourceType;
use http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE};
use url::Url;

/// Chunk size for ranged downloads (4 MiB).
const CHUNK: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlState {
    Active,
    Paused,
    Done,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct Download {
    pub id: u64,
    pub url: String,
    pub filename: String,
    pub path: PathBuf,
    pub received: u64,
    pub total: Option<u64>,
    pub state: DlState,
    pub supports_range: bool,
    pub bytes_per_sec: u64,
    pub mime: String,
}

pub struct DownloadManager {
    engine: Arc<BrowserEngine>,
    dir: PathBuf,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    downloads: Vec<Download>,
}

impl DownloadManager {
    pub fn new(engine: Arc<BrowserEngine>, dir: PathBuf) -> Arc<Self> {
        std::fs::create_dir_all(&dir).ok();
        Arc::new(DownloadManager { engine, dir, inner: Arc::new(Mutex::new(Inner::default())) })
    }

    /// Sync snapshot (cheap clone; safe from any thread).
    pub fn try_snapshot(&self) -> Vec<Download> {
        self.inner.lock().unwrap().downloads.clone()
    }

    /// Async snapshot (parity with the sync form).
    #[allow(dead_code)]
    pub async fn snapshot(&self) -> Vec<Download> {
        self.try_snapshot()
    }

    /// Start (or restart) a download. Returns the download id.
    pub async fn start(self: &Arc<Self>, url_str: &str) -> u64 {
        let url = match Url::parse(url_str) {
            Ok(u) => u,
            Err(_) => return 0,
        };
        let filename = unique_filename(&self.dir, url.as_str());
        let host = url.host_str().unwrap_or_default().to_string();

        let mut inner = self.inner.lock().unwrap();
        inner.next_id += 1;
        let id = inner.next_id;
        inner.downloads.insert(
            0,
            Download {
                id,
                url: url_str.to_string(),
                filename: filename.to_string_lossy().into_owned(),
                path: self.dir.join(&filename),
                received: 0,
                total: None,
                state: DlState::Active,
                supports_range: false,
                bytes_per_sec: 0,
                mime: String::new(),
            },
        );
        drop(inner);

        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            mgr.run(id, url, &host).await;
        });
        id
    }

    pub async fn pause(&self, id: u64) {
        if let Some(d) = self.inner.lock().unwrap().downloads.iter_mut().find(|d| d.id == id) {
            if d.state == DlState::Active {
                d.state = DlState::Paused;
            }
        }
    }

    pub async fn resume(self: &Arc<Self>, id: u64) {
        let url = {
            let mut inner = self.inner.lock().unwrap();
            match inner.downloads.iter_mut().find(|d| d.id == id) {
                Some(d) if d.state == DlState::Paused => {
                    d.state = DlState::Active;
                    d.url.clone()
                }
                _ => return,
            }
        };
        let parsed = match Url::parse(&url) {
            Ok(u) => u,
            Err(_) => return,
        };
        let host = parsed.host_str().unwrap_or_default().to_string();
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            mgr.run(id, parsed, &host).await;
        });
    }

    pub async fn cancel(&self, id: u64) {
        if let Some(d) = self.inner.lock().unwrap().downloads.iter_mut().find(|d| d.id == id) {
            if d.state == DlState::Active || d.state == DlState::Paused {
                d.state = DlState::Cancelled;
                let path = d.path.clone();
                drop(std::fs::remove_file(path));
            }
        }
    }

    pub async fn clear_finished(&self) {
        self.inner
            .lock()
            .unwrap()
            .downloads
            .retain(|d| d.state == DlState::Active || d.state == DlState::Paused);
    }

    /// The worker: chunked range requests through the engine pipeline.
    async fn run(self: Arc<Self>, id: u64, url: Url, host: &str) {
        let path = {
            let inner = self.inner.lock().unwrap();
            match inner.downloads.iter().find(|d| d.id == id) {
                Some(d) => d.path.clone(),
                None => return,
            }
        };

        // Resume: continue from the bytes already on disk.
        let mut offset: u64 = std::fs::metadata(&path).ok().map(|m| m.len()).unwrap_or(0);
        let mut first = true;

        loop {
            let should_run = {
                let inner = self.inner.lock().unwrap();
                match inner.downloads.iter().find(|d| d.id == id) {
                    Some(d) => matches!(d.state, DlState::Active),
                    None => false,
                }
            };
            if !should_run {
                return;
            }

            let started = std::time::Instant::now();
            let mut req = FetchRequest::subresource(url.clone(), host, ResourceType::OTHER);
            req.headers.insert(
                "range",
                format!("bytes={}-{}", offset, offset + CHUNK - 1).parse().unwrap(),
            );

            let resp = match self.engine.fetch_service().fetch(req).await {
                Ok(r) => r,
                Err(_) => {
                    self.finish(id, DlState::Failed).await;
                    return;
                }
            };

            let status = resp.status.as_u16();
            let body = resp.body;
            let ranged = status == 206 || resp.headers.contains_key(CONTENT_RANGE);

            // 200 in answer to a range request: server ignored it.
            if !ranged && !first {
                self.finish(id, DlState::Failed).await;
                return;
            }
            if !ranged && offset > 0 {
                // Can't resume mid-file: restart from zero.
                offset = 0;
                let _ = std::fs::remove_file(&path);
            }

            if first {
                let total = resp
                    .headers
                    .get(CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok());
                let supports_range = resp
                    .headers
                    .get(ACCEPT_RANGES)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.contains("bytes"));
                let mime = resp
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let total = total.or(Some(body.len() as u64));
                let mut inner = self.inner.lock().unwrap();
                if let Some(d) = inner.downloads.iter_mut().find(|d| d.id == id) {
                    d.total = total;
                    d.supports_range = supports_range || ranged;
                    d.mime = mime;
                }
            }

            if !body.is_empty() {
                use std::io::Write;
                let mut file =
                    match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                        Ok(f) => f,
                        Err(_) => {
                            self.finish(id, DlState::Failed).await;
                            return;
                        }
                    };
                if file.write_all(&body).is_err() {
                    self.finish(id, DlState::Failed).await;
                    return;
                }
                offset += body.len() as u64;
            }

            let elapsed = started.elapsed().as_millis().max(1) as u64;
            {
                let mut inner = self.inner.lock().unwrap();
                if let Some(d) = inner.downloads.iter_mut().find(|d| d.id == id) {
                    d.received = offset;
                    d.bytes_per_sec = body.len() as u64 * 1000 / elapsed;
                }
            }

            first = false;

            let done = {
                let inner = self.inner.lock().unwrap();
                match inner.downloads.iter().find(|d| d.id == id) {
                    Some(d) => d.total.map(|t| offset >= t).unwrap_or(true),
                    None => true,
                }
            };
            if done {
                self.finish(id, DlState::Done).await;
                return;
            }
            if body.is_empty() {
                self.finish(id, DlState::Failed).await;
                return;
            }
        }
    }

    /// Terminal state transition (frees the partial file on cancel).
    async fn finish(&self, id: u64, state: DlState) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(d) = inner.downloads.iter_mut().find(|d| d.id == id) {
            d.state = state;
            d.bytes_per_sec = 0;
            if state == DlState::Cancelled {
                drop(std::fs::remove_file(&d.path));
            }
        }
    }
}

fn unique_filename(dir: &Path, url: &str) -> PathBuf {
    let name = Url::parse(url)
        .ok()
        .and_then(|u| {
            u.path_segments().and_then(|mut segs| {
                while let Some(last) = segs.next_back() {
                    if !last.is_empty() {
                        return Some(percent_decode(last));
                    }
                }
                None
            })
        })
        .unwrap_or_else(|| "download".into());
    let clean = name
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect::<String>();
    let base = if clean.is_empty() { "download".to_string() } else { clean };
    let mut candidate = dir.join(&base);
    let mut n = 1;
    while candidate.exists() {
        let stem = Path::new(&base).file_stem().and_then(|s| s.to_str()).unwrap_or("download");
        let ext = Path::new(&base).extension().and_then(|s| s.to_str());
        candidate = match ext {
            Some(e) => dir.join(format!("{stem} ({n}).{e}")),
            None => dir.join(format!("{base} ({n})")),
        };
        n += 1;
    }
    candidate
}

/// Percent-decode a URL path segment (best-effort).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len() + 1
            && i + 2 < bytes.len() + 1
            && (i + 2 < bytes.len() || i + 2 == bytes.len())
        {
            let hex = &s[i + 1..(i + 3).min(s.len())];
            if hex.len() == 2 {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Open a path with the OS file manager / default app.
pub fn open_in_os(path: &Path) {
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("explorer").arg(path).spawn();
    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(path).spawn();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let result = std::process::Command::new("open").arg(path).spawn();
    let _ = result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_filename_sanitizes_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let a = unique_filename(dir.path(), "https://example.com/files/report q4.pdf");
        assert!(a.to_string_lossy().ends_with("report_q4.pdf"));
        std::fs::write(&a, b"x").unwrap();
        let b = unique_filename(dir.path(), "https://example.com/files/report q4.pdf");
        assert_ne!(a, b);
        assert!(b.to_string_lossy().contains("report_q4 (1).pdf"));
    }

    #[test]
    fn unique_filename_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let a = unique_filename(dir.path(), "https://example.com/");
        assert!(a.to_string_lossy().contains("download"));
    }
}
