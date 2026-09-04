//! Windows firewall via netsh advfirewall.
//!
//! netsh does not support FQDN rules, so IPs are resolved on every `block()` call.
//! Rules are named `ClaudeGuard_<generation>_<n>`: a new generation is added before
//! the previous one is removed, so there is no window in which traffic is unfiltered.
//!
//! Adding firewall rules requires an elevated process. Every netsh failure — a
//! missing elevation above all — must surface as `Err`; reporting `Ok` here would
//! leave the UI showing "blocked" while traffic keeps flowing.

use super::{Firewall, BLOCKED_DOMAINS};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const RULE_PREFIX: &str = "ClaudeGuard_";

pub struct WindowsFirewall {
    blocked: AtomicBool,
}

impl WindowsFirewall {
    pub fn new() -> Self {
        Self { blocked: AtomicBool::new(false) }
    }
}

/// True when the current process holds an elevated token.
///
/// netsh silently refuses to add rules without one, so this is checked up front to
/// turn "protection is quietly absent" into a visible error.
fn is_elevated() -> bool {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: the token handle is closed on every path; GetTokenInformation is
    // given a correctly sized TOKEN_ELEVATION and its matching length.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size,
            &mut returned,
        );

        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// A monotonic-enough tag so a new rule set never collides with the one it replaces.
fn generation() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn netsh(args: &[&str]) -> Result<(), String> {
    let out = Command::new("netsh")
        .args(["advfirewall", "firewall"])
        .args(args)
        .output()
        .map_err(|e| format!("netsh: {e}"))?;

    if !out.status.success() {
        // netsh reports most failures on stdout, not stderr.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let detail = if stderr.trim().is_empty() { stdout } else { stderr };
        return Err(format!("netsh {args:?} failed: {}", detail.trim()));
    }
    Ok(())
}

/// Removes every `ClaudeGuard_*` rule except the given generation.
/// Pass `None` to remove all of them.
fn remove_rules(keep: Option<u128>) -> Result<(), String> {
    // netsh has no wildcard delete, so match by prefix through PowerShell.
    // SilentlyContinue keeps "no matching rules" from being an error — removing
    // nothing is the expected outcome on a first run or a repeated unblock.
    let filter = match keep {
        Some(id) => {
            format!(" | Where-Object {{ $_.DisplayName -notlike '{RULE_PREFIX}{id}_*' }}")
        }
        None => String::new(),
    };
    let script = format!(
        "Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue{filter} \
         | Remove-NetFirewallRule -ErrorAction Stop"
    );

    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("powershell: {e}"))?;

    if !out.status.success() {
        return Err(format!(
            "failed to remove {RULE_PREFIX}* rules: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn resolve_domains() -> Vec<String> {
    let mut seen = HashSet::new();
    for domain in BLOCKED_DOMAINS {
        match format!("{domain}:443").to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    seen.insert(addr.ip().to_string());
                }
            }
            Err(e) => log::warn!("DNS resolve failed for {domain}: {e}"),
        }
    }
    seen.into_iter().collect()
}

impl Firewall for WindowsFirewall {
    fn block(&self) -> Result<(), String> {
        if !is_elevated() {
            return Err(
                "Windows Firewall rules require elevation — restart Claude Guard as Administrator"
                    .into(),
            );
        }

        let ips = resolve_domains();
        if ips.is_empty() {
            return Err("DNS resolution returned no IPs — not blocking to avoid a false sense of protection".into());
        }

        // Add the new generation first, then drop the old one, so the previous
        // rules keep filtering until the replacements are in place.
        let generation_id = generation();
        for (i, ip) in ips.iter().enumerate() {
            netsh(&[
                "add",
                "rule",
                &format!("name={RULE_PREFIX}{generation_id}_{i}"),
                "dir=out",
                "action=block",
                &format!("remoteip={ip}"),
                "enable=yes",
                "profile=any",
            ])?;
        }

        // A stale generation left behind is over-blocking, never under-blocking,
        // so log it rather than failing a block that already succeeded.
        if let Err(e) = remove_rules(Some(generation_id)) {
            log::warn!("could not remove superseded rules: {e}");
        }

        self.blocked.store(true, Ordering::SeqCst);
        log::info!("Windows Firewall: blocked {} IPs (generation {generation_id})", ips.len());
        Ok(())
    }

    fn unblock(&self) -> Result<(), String> {
        remove_rules(None)?;
        self.blocked.store(false, Ordering::SeqCst);
        log::info!("Windows Firewall: removed {RULE_PREFIX}* rules");
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst)
    }
}
