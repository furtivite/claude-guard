//! Firewall abstraction.
//!
//! Each platform implements the `Firewall` trait. Rules target domain names so they
//! survive IP changes — platforms that support FQDN rules (PF, nftables) are preferred
//! over IP-based fallbacks.
//!
//! To add a platform: create a module, implement `Firewall`, add a branch to `platform()`.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

pub const BLOCKED_DOMAINS: &[&str] = &["api.anthropic.com", "claude.ai"];

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
