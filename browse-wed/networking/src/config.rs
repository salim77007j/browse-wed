//! Configuration for the networking stack.
//!
//! Everything tunable lives here so the engine (and through it, the UI)
//! can adjust behaviour at runtime without touching internals: protocol
//! toggles, DNS strategy, timeouts and privacy transport settings.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// How hostnames are resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DnsMode {
    /// Ask the operating system resolver (`/etc/resolv.conf` on Unix).
    #[default]
    System,
    /// DNS-over-HTTPS (RFC 8484). The URL must be `https://…`.
    Doh { url: String },
    /// DNS-over-TLS (RFC 7858). `host:port`, e.g. `1.1.1.1:853`.
    Dot { addr: String },
}

impl DnsMode {
    /// Validate the mode's payload (URL / address shape).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            DnsMode::System => Ok(()),
            DnsMode::Doh { url } => {
                let parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
                if parsed.scheme() != "https" {
                    return Err("DoH URL must be https".into());
                }
                if parsed.path().is_empty() || parsed.path() == "/" {
                    // allow, path defaults to /dns-query server-side convention
                }
                Ok(())
            }
            DnsMode::Dot { addr } => {
                if addr.split(':').count() != 2 {
                    return Err("DoT address must be host:port".into());
                }
                Ok(())
            }
        }
    }
}

/// Default privacy-preserving DoH resolvers offered by the engine.
pub const DEFAULT_DOH_SERVERS: &[(&str, &str)] = &[
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Quad9", "https://dns.quad9.net/dns-query"),
    ("Google", "https://dns.google/dns-query"),
];

/// Networking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Enable HTTP/2 (ALPN `h2`).
    pub enable_http2: bool,
    /// Enable HTTP/3 over QUIC (ALPN `h3`), used via Alt-Svc discovery.
    pub enable_http3: bool,
    /// Upgrade plain `http://` navigations to `https://` where possible.
    pub https_upgrade: bool,
    /// Honour `Strict-Transport-Security` (in-memory list, no preload yet).
    pub hsts: bool,
    /// DNS strategy.
    pub dns: DnsMode,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Whole-request timeout (0 = none).
    pub request_timeout: Duration,
    /// User-Agent sent when the caller does not override it.
    pub user_agent: String,
    /// `Accept-Language` value.
    pub accept_language: String,
    /// Maximum redirects followed automatically.
    pub max_redirects: usize,
    /// Accept IPv6 connections (happy-eyeballs prefers IPv4 fallback).
    pub enable_ipv6: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            enable_http2: true,
            enable_http3: true,
            https_upgrade: true,
            hsts: true,
            dns: DnsMode::System,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            user_agent: concat!(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ",
                "(KHTML, like Gecko) browse-wed/0.1 Chrome/142.0.0.0 Safari/537.36"
            )
            .to_string(),
            accept_language: "en-US,en;q=0.9".into(),
            max_redirects: 10,
            enable_ipv6: true,
        }
    }
}

impl NetworkConfig {
    /// Privacy-hardened defaults: DoH to Quad9, HTTPS upgrades on.
    pub fn privacy_default() -> Self {
        NetworkConfig {
            dns: DnsMode::Doh { url: DEFAULT_DOH_SERVERS[1].1.into() },
            ..NetworkConfig::default()
        }
    }

    /// Validate the whole config.
    pub fn validate(&self) -> Result<(), String> {
        self.dns.validate()?;
        if self.connect_timeout.is_zero() {
            return Err("connect_timeout must be > 0".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_validates() {
        assert!(NetworkConfig::default().validate().is_ok());
    }

    #[test]
    fn doh_requires_https() {
        let cfg = NetworkConfig {
            dns: DnsMode::Doh { url: "http://dns.example/dns-query".into() },
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dot_requires_port() {
        let cfg = NetworkConfig {
            dns: DnsMode::Dot { addr: "1.1.1.1".into() },
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn privacy_default_uses_doh() {
        let cfg = NetworkConfig::privacy_default();
        assert!(matches!(cfg.dns, DnsMode::Doh { .. }));
        assert!(cfg.validate().is_ok());
    }
}
