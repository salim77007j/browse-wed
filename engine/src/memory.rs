//! System memory detection and the memory governor.
//!
//! The governor is what makes browse-wed's RAM promises real:
//!
//! * it reads **total** and **available** RAM portably (sysconf on Unix,
//!   `GlobalMemoryStatusEx` on Windows),
//! * it derives **cache budgets** from available RAM (unlike fixed budgets
//!   that ignore the machine the browser runs on),
//! * it owns the **background suspension policy**: tabs backgrounded for
//!   longer than the idle threshold are suspended — JS heap dropped, page
//!   tree dropped — which is where the "background tab costs ~0 RAM"
//!   promise comes from.
//!
//! All numbers are bytes. The governor never allocates; it only computes.

// The only `unsafe` in this module is the libc/Win32 FFI needed to read
// system memory (sysconf / GlobalMemoryStatusEx) — each block is audited
// and documented inline.
#![deny(unsafe_op_in_unsafe_fn)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A snapshot of system memory state.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct MemorySnapshot {
    /// Total physical RAM in bytes (0 if unknown).
    pub total_bytes: u64,
    /// RAM available to processes in bytes (0 if unknown).
    pub available_bytes: u64,
}

impl MemorySnapshot {
    /// Read the current system state.
    pub fn read() -> MemorySnapshot {
        MemorySnapshot { total_bytes: total_ram_bytes(), available_bytes: available_ram_bytes() }
    }

    /// Available RAM, falling back to a fraction of total (kernels lie).
    pub fn effective_available(&self) -> u64 {
        if self.available_bytes > 0 {
            self.available_bytes
        } else if self.total_bytes > 0 {
            self.total_bytes / 4
        } else {
            2 * 1024 * 1024 * 1024 // assume a 2 GiB floor
        }
    }
}

/// Total physical RAM.
pub fn total_ram_bytes() -> u64 {
    #[cfg(unix)]
    {
        // SAFETY: sysconf is thread-safe and takes a constant.
        let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if pages > 0 && page > 0 {
            return (pages as u64) * (page as u64);
        }
        0
    }
    #[cfg(windows)]
    {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        // SAFETY: `status` is a valid, correctly-sized struct.
        if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
            status.ullTotalPhys as u64
        } else {
            0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
}

/// Available RAM (Linux reads `/proc/meminfo` `MemAvailable`, which is the
/// kernel's honest estimate; other platforms approximate from free pages).
pub fn available_ram_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/proc/meminfo") {
            for line in info.lines() {
                if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
                    return kb * 1024;
                }
            }
        }
        0
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        // macOS/BSD: pages free + inactive is a decent availability proxy.
        // SAFETY: sysconf is thread-safe.
        let free = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if free > 0 && page > 0 {
            (free as u64) * (page as u64) * 4 // free is a floor; scale up conservatively
        } else {
            0
        }
    }
    #[cfg(windows)]
    {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        // SAFETY: `status` is a valid, correctly-sized struct.
        if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
            status.ullAvailPhys as u64
        } else {
            0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
}

#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

/// Governor policy knobs.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct GovernorPolicy {
    /// After this much idle time a background tab is suspended.
    pub background_suspend_after: Duration,
    /// Share of available RAM granted to the in-memory HTTP cache.
    pub cache_memory_fraction: f64,
    /// Cap for the in-memory HTTP cache (bytes).
    pub cache_memory_max: usize,
    /// JS heap limit per site runtime.
    pub js_heap_limit: usize,
    /// Keep at most this many non-suspended tabs when memory is tight.
    pub max_active_tabs: usize,
}

impl Default for GovernorPolicy {
    fn default() -> Self {
        GovernorPolicy {
            background_suspend_after: Duration::from_secs(300),
            cache_memory_fraction: 0.05,
            cache_memory_max: 192 * 1024 * 1024,
            js_heap_limit: 64 * 1024 * 1024,
            max_active_tabs: 16,
        }
    }
}

/// The memory governor: derives every budget from a live snapshot.
#[derive(Debug, Clone)]
pub struct MemoryGovernor {
    policy: GovernorPolicy,
    snapshot: MemorySnapshot,
}

impl MemoryGovernor {
    /// Measure the system and build the governor.
    pub fn new(policy: GovernorPolicy) -> MemoryGovernor {
        MemoryGovernor { policy, snapshot: MemorySnapshot::read() }
    }

    /// Re-measure the system (called by the periodic sweeper).
    pub fn refresh(&mut self) {
        self.snapshot = MemorySnapshot::read();
    }

    /// The last snapshot.
    pub fn snapshot(&self) -> MemorySnapshot {
        self.snapshot
    }

    /// In-memory HTTP cache budget (scaled to available RAM, capped).
    pub fn http_cache_memory_budget(&self) -> usize {
        let avail = self.snapshot.effective_available() as f64;
        let scaled = (avail * self.policy.cache_memory_fraction) as usize;
        scaled.min(self.policy.cache_memory_max)
    }

    /// On-disk HTTP cache budget: 4× the memory budget, capped at 1 GiB.
    pub fn http_cache_disk_budget(&self) -> usize {
        (self.http_cache_memory_budget() * 4).min(1024 * 1024 * 1024)
    }

    /// JS heap limit per site runtime.
    pub fn js_heap_limit(&self) -> usize {
        // On constrained machines (< 2 GiB available) halve the JS budget.
        let base = self.policy.js_heap_limit;
        if self.snapshot.effective_available() < 2 * 1024 * 1024 * 1024 {
            base / 2
        } else {
            base
        }
    }

    /// The configured idle threshold before background suspension.
    pub fn background_suspend_after(&self) -> Duration {
        self.policy.background_suspend_after
    }

    /// Is a tab backgrounded at `backgrounded_since` due for suspension?
    pub fn should_suspend(&self, backgrounded_since: SystemTime) -> bool {
        backgrounded_since
            .elapsed()
            .map(|e| e >= self.policy.background_suspend_after)
            .unwrap_or(false)
    }

    /// Memory pressure tier, for the UI to surface.
    pub fn pressure(&self) -> MemoryPressure {
        let avail = self.snapshot.effective_available();
        let total = if self.snapshot.total_bytes > 0 {
            self.snapshot.total_bytes
        } else {
            return MemoryPressure::Unknown;
        };
        let ratio = avail as f64 / total as f64;
        if ratio > 0.35 {
            MemoryPressure::Low
        } else if ratio > 0.15 {
            MemoryPressure::Moderate
        } else {
            MemoryPressure::High
        }
    }
}

/// Memory pressure tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryPressure {
    /// Plenty of headroom.
    Low,
    /// Consider proactive suspension.
    Moderate,
    /// Suspend aggressively.
    High,
    /// Could not be determined.
    Unknown,
}

/// Monotonic-ish "unix now" helper shared by the governor's callers.
pub fn unix_now() -> SystemTime {
    SystemTime::now()
}

/// Seconds since the epoch (for persistence formats).
pub fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reads_something() {
        let snap = MemorySnapshot::read();
        // On any CI/host we expect a nonzero total.
        assert!(snap.total_bytes > 0, "sysconf failed to report RAM");
        assert!(snap.effective_available() > 0);
    }

    #[test]
    fn budgets_scale_and_cap() {
        let gov = MemoryGovernor::new(GovernorPolicy {
            cache_memory_fraction: 1.0, // absurd fraction on purpose
            cache_memory_max: 1024,
            ..GovernorPolicy::default()
        });
        assert_eq!(gov.http_cache_memory_budget(), 1024);
        assert_eq!(gov.http_cache_disk_budget(), 4096);
    }

    #[test]
    fn fraction_scaling_is_sane() {
        let gov = MemoryGovernor::new(GovernorPolicy::default());
        let budget = gov.http_cache_memory_budget();
        let avail = gov.snapshot().effective_available();
        assert!(budget as u64 <= avail.max(1), "budget exceeds availability");
        assert!(budget <= 192 * 1024 * 1024);
    }

    #[test]
    fn suspension_deadline_works() {
        let gov = MemoryGovernor::new(GovernorPolicy {
            background_suspend_after: Duration::from_millis(10),
            ..GovernorPolicy::default()
        });
        let since = SystemTime::now() - Duration::from_millis(50);
        assert!(gov.should_suspend(since));
        let fresh = SystemTime::now();
        assert!(!gov.should_suspend(fresh));
    }

    #[test]
    fn pressure_is_classified() {
        let gov = MemoryGovernor::new(GovernorPolicy::default());
        // We can't force the host's memory, but the tier must be one of
        // the enum values and consistent with the ratio.
        let _ = gov.pressure();
        let snap = gov.snapshot();
        if snap.total_bytes > 0 {
            let ratio = snap.effective_available() as f64 / snap.total_bytes as f64;
            let expected = if ratio > 0.35 {
                MemoryPressure::Low
            } else if ratio > 0.15 {
                MemoryPressure::Moderate
            } else {
                MemoryPressure::High
            };
            assert_eq!(gov.pressure(), expected);
        }
    }
}
