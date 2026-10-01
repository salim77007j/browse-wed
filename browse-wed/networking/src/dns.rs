//! DNS resolution manager.
//!
//! Wraps `hickory-resolver` in whichever secure-transport mode the config
//! selects:
//!
//! * `System` — the OS resolver (read from `/etc/resolv.conf`).
//! * `DoH` — DNS-over-HTTPS (RFC 8484). The DoH server's own hostname is
//!   bootstrapped through the system resolver exactly once; afterwards all
//!   queries ride inside TLS to the DoH endpoint.
//! * `DoT` — DNS-over-TLS (RFC 7858), same bootstrap strategy.
//!
//! The manager also exposes the **CNAME chain** for a hostname, which the
//! privacy layer uses for CNAME-uncloaking (detecting `tracker.example`
//! hidden behind an innocuous first-party-looking subdomain).
//!
//! IPv4 and IPv6 are both resolved; results are returned in
//! happy-eyeballs-friendly interleaved order (v6, v4, v6, v4 …) so the
//! connector can race families, exactly like Chrome's `HostResolver`.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};

use bw_privacy::cname::CnameChain;

use crate::config::DnsMode;

/// Errors surfaced by the resolver manager.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// Underlying resolver failure.
    #[error("dns lookup failed: {0}")]
    Lookup(String),
    /// The configured DNS mode could not be initialized.
    #[error("dns init failed: {0}")]
    Init(String),
}

/// Resolution statistics (exported to the UI diagnostics panel).
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsStats {
    /// Total queries issued.
    pub queries: u64,
    /// Failed lookups.
    pub failures: u64,
    /// CNAME chains inspected for uncloaking.
    pub cname_inspected: u64,
    /// Bootstrapped secure resolver in use.
    pub secure_transport: bool,
}

/// The engine-wide DNS manager.
pub struct DnsManager {
    resolver: TokioResolver,
    mode: DnsMode,
    stats: DnsStatsInner,
}

#[derive(Default)]
struct DnsStatsInner {
    queries: AtomicU64,
    failures: AtomicU64,
    cname_inspected: AtomicU64,
}

impl DnsManager {
    /// Build the manager for a DNS mode. Must be called inside a tokio
    /// runtime (DoH/DoT bootstrap performs a system lookup).
    pub async fn new(mode: DnsMode) -> Result<Arc<DnsManager>, DnsError> {
        mode.validate().map_err(DnsError::Init)?;
        let resolver = match &mode {
            DnsMode::System => build_system_resolver().await?,
            DnsMode::Doh { url } => build_secure_resolver(url, true).await?,
            DnsMode::Dot { addr } => {
                let (host, port) = split_host_port(addr, 853);
                build_secure_resolver(&format!("https://{host}:{port}"), false).await?
            }
        };
        Ok(Arc::new(DnsManager {
            resolver,
            mode,
            stats: DnsStatsInner::default(),
        }))
    }

    /// The configured mode.
    pub fn mode(&self) -> &DnsMode {
        &self.mode
    }

    /// Resolve a hostname to ordered IP addresses (v6/v4 interleaved).
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        // IP literals skip DNS entirely.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| DnsError::Lookup(e.to_string()))?;
        let addrs: Vec<IpAddr> = lookup.iter().collect();
        if addrs.is_empty() {
            self.stats.failures.fetch_add(1, Ordering::Relaxed);
            return Err(DnsError::Lookup(format!("no addresses for {host}")));
        }
        Ok(interleave_families(addrs))
    }

    /// The CNAME chain for a hostname (empty when the name is canonical).
    pub async fn cname_chain(&self, host: &str) -> CnameChain {
        self.stats.cname_inspected.fetch_add(1, Ordering::Relaxed);
        let mut hops = Vec::new();
        let mut current = host.to_string();
        // Follow up to 8 links — beyond that the chain is pathological.
        for _ in 0..8 {
            let Ok(lookup) = self.resolver.lookup(current.clone(), RecordType::CNAME).await
            else {
                break;
            };
            let mut next: Option<String> = None;
            for record in lookup.answers() {
                if let RData::CNAME(cname) = &record.data {
                    next = Some(cname.0.to_string());
                    break;
                }
            }
            match next {
                Some(n) if !n.eq_ignore_ascii_case(&current) => {
                    hops.push(n.clone());
                    current = n;
                }
                _ => break,
            }
        }
        CnameChain::new(host, hops)
    }

    /// Snapshot of resolution statistics.
    pub fn stats(&self) -> DnsStats {
        DnsStats {
            queries: self.stats.queries.load(Ordering::Relaxed),
            failures: self.stats.failures.load(Ordering::Relaxed),
            cname_inspected: self.stats.cname_inspected.load(Ordering::Relaxed),
            secure_transport: !matches!(self.mode, DnsMode::System),
        }
    }
}

/// Order addresses for happy-eyeballs: alternate families, v6 first.
fn interleave_families(addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut v6: Vec<IpAddr> = Vec::new();
    let mut v4: Vec<IpAddr> = Vec::new();
    for a in addrs {
        match a {
            IpAddr::V4(_) => v4.push(a),
            IpAddr::V6(_) => v6.push(a),
        }
    }
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut i, mut j) = (0, 0);
    while i < v6.len() || j < v4.len() {
        if i < v6.len() {
            out.push(v6[i]);
            i += 1;
        }
        if j < v4.len() {
            out.push(v4[j]);
            j += 1;
        }
    }
    out
}

fn split_host_port(addr: &str, default_port: u16) -> (String, u16) {
    match addr.rsplit_once(':') {
        Some((host, p)) => (host.to_string(), p.parse().unwrap_or(default_port)),
        None => (addr.to_string(), default_port),
    }
}

/// System (OS) resolver.
async fn build_system_resolver() -> Result<TokioResolver, DnsError> {
    let builder = Resolver::builder(TokioRuntimeProvider::default())
        .map_err(|e| DnsError::Init(e.to_string()))?;
    builder.build().map_err(|e| DnsError::Init(e.to_string()))
}

/// DoH / DoT resolver with system bootstrap. `url` carries the host and
/// (possibly non-default) port; `is_doh` selects the transport.
async fn build_secure_resolver(url: &str, is_doh: bool) -> Result<TokioResolver, DnsError> {
    let parsed = url::Url::parse(url).map_err(|e| DnsError::Init(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| DnsError::Init("missing resolver host".into()))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    // Bootstrap: resolve the secure resolver's own hostname via the system.
    let bootstrap = build_system_resolver().await?;
    let ips: Vec<IpAddr> = bootstrap
        .lookup_ip(host.clone())
        .await
        .map_err(|e| DnsError::Init(format!("bootstrap lookup for {host} failed: {e}")))?
        .iter()
        .collect();
    let ip = ips
        .into_iter()
        .next()
        .ok_or_else(|| DnsError::Init("bootstrap produced no addresses".into()))?;

    let server_name: Arc<str> = Arc::from(host.as_str());

    let mut ns = if is_doh {
        NameServerConfig::https(ip, server_name, None)
    } else {
        NameServerConfig::tls(ip, server_name)
    };
    // Non-exhaustive struct: built via constructor, then port patched.
    if let Some(first) = ns.connections.first_mut() {
        first.port = port;
    }

    let mut config = ResolverConfig::default();
    config.add_name_server(ns);

    let builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.build().map_err(|e| DnsError::Init(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaves_families() {
        let addrs: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700::1111".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "2606:4700::1001".parse().unwrap(),
        ];
        let out = interleave_families(addrs);
        assert!(matches!(out[0], IpAddr::V6(_)));
        assert!(matches!(out[1], IpAddr::V4(_)));
        assert!(matches!(out[2], IpAddr::V6(_)));
        assert!(matches!(out[3], IpAddr::V4(_)));
    }

    #[test]
    fn splits_host_port() {
        assert_eq!(split_host_port("1.1.1.1:853", 53), ("1.1.1.1".into(), 853));
        assert_eq!(split_host_port("dns.example", 853), ("dns.example".into(), 853));
    }

    #[tokio::test]
    async fn system_resolver_resolves_localhost() {
        let dns = DnsManager::new(DnsMode::System).await.unwrap();
        let addrs = dns.resolve("localhost").await.unwrap();
        assert!(!addrs.is_empty());
    }

    #[tokio::test]
    async fn ip_literal_short_circuits() {
        let dns = DnsManager::new(DnsMode::System).await.unwrap();
        let addrs = dns.resolve("127.0.0.1").await.unwrap();
        assert_eq!(addrs.len(), 1);
    }

    #[tokio::test]
    async fn invalid_doh_url_rejected() {
        let err = DnsManager::new(DnsMode::Doh { url: "not-a-url".into() }).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn cname_chain_for_localhost_is_empty() {
        let dns = DnsManager::new(DnsMode::System).await.unwrap();
        let chain = dns.cname_chain("localhost").await;
        assert!(chain.effective_host() == "localhost");
    }
}
