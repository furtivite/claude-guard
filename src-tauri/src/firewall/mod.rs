//! Firewall abstraction.
//!
//! Each platform implements the `Firewall` trait. Rules target domain names so they
//! survive IP changes — platforms that support FQDN rules (PF, nftables) are preferred
//! over IP-based fallbacks.
//!
//! To add a platform: create a module, implement `Firewall`, add a branch to `platform()`.

use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

pub const BLOCKED_DOMAINS: &[&str] = &["api.anthropic.com", "claude.ai"];

/// Current addresses of every blocked domain, both families, deduplicated.
///
/// An empty result means DNS told us nothing: callers must treat that as a failure
/// rather than as "nothing to block", or they would report protection they are not
/// applying. Shared by all three backends so a resolver change cannot drift between
/// platforms.
pub fn resolve_blocked_ips() -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    for domain in BLOCKED_DOMAINS {
        match format!("{domain}:443").to_socket_addrs() {
            Ok(addrs) => seen.extend(addrs.map(|a| a.ip())),
            Err(e) => log::warn!("DNS resolve failed for {domain}: {e}"),
        }
    }
    seen.into_iter().collect()
}

/// Splits resolved addresses into (v4, v6) as display strings. The families are
/// configured through different mechanisms on every platform, so they never mix.
pub fn split_families(ips: &[IpAddr]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V4(a) => v4.push(a.to_string()),
            IpAddr::V6(a) => v6.push(a.to_string()),
        }
    }
    (v4, v6)
}

pub trait Firewall: Send + Sync {
    fn block(&self) -> Result<(), String>;
    fn unblock(&self) -> Result<(), String>;
    /// Reflects the last *successfully applied* state (the internal flag is only
    /// flipped after `block`/`unblock` returns `Ok`), so the fail-closed path can
    /// trust it. On process restart the flag starts `false`; `run_loop` reconciles
    /// this by (re-)applying `block()` on startup whenever the guard is enabled.
    fn is_blocked(&self) -> bool;
}

pub fn platform() -> Box<dyn Firewall> {
    #[cfg(target_os = "macos")]
    return Box::new(macos::MacosFirewall::new());

    #[cfg(target_os = "linux")]
    return Box::new(linux::LinuxFirewall::new());

    #[cfg(windows)]
    return Box::new(windows::WindowsFirewall::new());

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    compile_error!("Unsupported platform");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn families_are_split_and_never_mixed() {
        let ips = [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2607, 0x6bc0, 0, 0, 0, 0, 0, 0x10)),
        ];
        let (v4, v6) = split_families(&ips);
        assert_eq!(v4, ["1.2.3.4"]);
        assert_eq!(v6, ["2607:6bc0::10"]);
    }

    #[test]
    fn empty_input_yields_two_empty_families() {
        let (v4, v6) = split_families(&[]);
        assert!(v4.is_empty() && v6.is_empty());
    }
}
