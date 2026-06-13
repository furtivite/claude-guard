//! Linux firewall via nftables (preferred) or iptables fallback.
//!
//! IPs are re-resolved on every `block()` call so Anthropic IP changes are picked up
//! within one check cycle. DNS rebinding is a theoretical risk; the attack window is
//! bounded by the check interval.

use super::{Firewall, BLOCKED_DOMAINS};
use std::collections::HashSet;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

const TABLE: &str = "claude_guard";
const CHAIN: &str = "CLAUDE_GUARD";

#[derive(Debug, Clone, PartialEq)]
enum Backend { Nftables, Iptables }

pub struct LinuxFirewall {
    backend: Backend,
    blocked: AtomicBool,
}

impl LinuxFirewall {
    pub fn new() -> Self {
        Self {
            backend: detect_backend(),
            blocked: AtomicBool::new(false),
        }
    }
}

fn detect_backend() -> Backend {
    if Command::new("nft").arg("--version").output().is_ok() {
        log::info!("firewall backend: nftables");
        Backend::Nftables
    } else {
        log::info!("firewall backend: iptables");
        Backend::Iptables
    }
}

fn resolve_domains() -> Vec<String> {
    let mut seen = HashSet::new();
    for domain in BLOCKED_DOMAINS {
        if let Ok(addrs) = format!("{domain}:443").to_socket_addrs() {
            for addr in addrs {
                seen.insert(addr.ip().to_string());
            }
        } else {
            log::warn!("DNS resolve failed for {domain}");
        }
    }
    seen.into_iter().collect()
}

impl Firewall for LinuxFirewall {
    fn block(&self) -> Result<(), String> {
        let ips = resolve_domains();
        if ips.is_empty() {
            return Err("DNS resolution returned no IPs — not blocking to avoid false positives".into());
        }

        match self.backend {
            Backend::Nftables => block_nft(&ips),
            Backend::Iptables => block_ipt(&ips),
        }?;
        self.blocked.store(true, Ordering::SeqCst);
        log::info!("blocked {} IPs: {:?}", ips.len(), ips);
        Ok(())
    }

    fn unblock(&self) -> Result<(), String> {
        match self.backend {
            Backend::Nftables => unblock_nft(),
            Backend::Iptables => unblock_ipt(),
        }?;
        self.blocked.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst)
    }
}

fn block_nft(ips: &[String]) -> Result<(), String> {
    let ip_list = ips.join(", ");
    let ruleset = format!(
        r#"table inet {TABLE} {{
    set blocked_ips {{
        type ipv4_addr
        flags interval
        elements = {{ {ip_list} }}
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
        ip daddr @blocked_ips drop comment "claude-guard"
    }}
}}"#
    );

    // delete may fail on first run when the table does not yet exist
    let _ = Command::new("sudo").args(["nft", "delete", "table", "inet", TABLE]).output();

    let mut child = Command::new("sudo")
        .args(["nft", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft spawn: {e}"))?;

    child.stdin.take().unwrap()
        .write_all(ruleset.as_bytes())
        .map_err(|e| format!("nft stdin: {e}"))?;

    let status = child.wait().map_err(|e| format!("nft wait: {e}"))?;
    if !status.success() {
        return Err("nft: ruleset load failed".into());
    }
    Ok(())
}

fn unblock_nft() -> Result<(), String> {
    let _ = Command::new("sudo").args(["nft", "delete", "table", "inet", TABLE]).output();
    Ok(())
}

fn block_ipt(ips: &[String]) -> Result<(), String> {
    // Reset first to avoid accumulating duplicate rules
    unblock_ipt()?;

    let _ = Command::new("sudo").args(["iptables", "-N", CHAIN]).output();

    Command::new("sudo")
        .args(["iptables", "-I", "OUTPUT", "-j", CHAIN])
        .output()
        .map_err(|e| e.to_string())?;

    for ip in ips {
        Command::new("sudo")
            .args(["iptables", "-A", CHAIN, "-d", ip, "-j", "DROP",
                   "-m", "comment", "--comment", "claude-guard"])
            .output()
            .map_err(|e| format!("iptables add {ip}: {e}"))?;
    }
    Ok(())
}

fn unblock_ipt() -> Result<(), String> {
    let _ = Command::new("sudo").args(["iptables", "-D", "OUTPUT", "-j", CHAIN]).output();
    let _ = Command::new("sudo").args(["iptables", "-F", CHAIN]).output();
    let _ = Command::new("sudo").args(["iptables", "-X", CHAIN]).output();
    Ok(())
}
