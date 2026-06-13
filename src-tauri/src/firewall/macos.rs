//! macOS firewall via pfctl.
//!
//! Uses a dedicated PF anchor (`claude_guard`) that is isolated from system rules.
//! FQDN-based rules are resolved by pfctl at load time, protecting against DNS rebinding.

use super::{Firewall, BLOCKED_DOMAINS};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

const ANCHOR: &str = "claude_guard";

pub struct MacosFirewall {
    blocked: AtomicBool,
}

impl MacosFirewall {
    pub fn new() -> Self {
        Self { blocked: AtomicBool::new(false) }
    }

    fn pfctl(&self, args: &[&str]) -> Result<(), String> {
        let out = Command::new("sudo")
            .args([&["pfctl"], args].concat())
            .output()
            .map_err(|e| format!("pfctl: {e}"))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // pfctl -e returns exit 1 with "pf already enabled" — not an error for us
            if !stderr.contains("pf already enabled") && !stderr.is_empty() {
                log::warn!("pfctl stderr: {stderr}");
            }
        }
        Ok(())
    }

    fn write_rules(&self, rules: &str) -> Result<(), String> {
        let mut child = Command::new("sudo")
            .args(["pfctl", "-a", ANCHOR, "-f", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("pfctl spawn: {e}"))?;

        child
            .stdin
            .take()
            .unwrap()
            .write_all(rules.as_bytes())
            .map_err(|e| format!("pfctl stdin: {e}"))?;

        let status = child.wait().map_err(|e| format!("pfctl wait: {e}"))?;
        if !status.success() {
            return Err("pfctl: failed to load ruleset".into());
        }
        Ok(())
    }
}

impl Firewall for MacosFirewall {
    fn block(&self) -> Result<(), String> {
        let mut rules = String::new();
        for domain in BLOCKED_DOMAINS {
            rules += &format!("table <{domain}> persist {{{domain}}}\n");
        }
        for domain in BLOCKED_DOMAINS {
            // `quick` short-circuits further rule evaluation on match
            rules += &format!("block drop out quick proto {{ tcp udp }} to <{domain}>\n");
        }

        self.write_rules(&rules)?;
        self.pfctl(&["-e"])?; // ensure PF is enabled
        self.blocked.store(true, Ordering::SeqCst);
        log::info!("pfctl: blocked {BLOCKED_DOMAINS:?} via anchor {ANCHOR}");
        Ok(())
    }

    fn unblock(&self) -> Result<(), String> {
        self.pfctl(&["-a", ANCHOR, "-F", "all"])?;
        self.blocked.store(false, Ordering::SeqCst);
        log::info!("pfctl: unblocked anchor {ANCHOR}");
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst)
    }
}
