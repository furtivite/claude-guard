//! Linux firewall via nftables (preferred) or iptables fallback.
//!
//! IPs are re-resolved on every `block()` call so Anthropic IP changes are picked up
//! within one check cycle. DNS rebinding is a theoretical risk; the attack window is
//! bounded by the check interval.
//!
//! Both address families are handled. `claude.ai` publishes AAAA records, and a
//! v6-capable host will reach them over IPv6 — blocking only v4 would leave the
//! traffic flowing over the other family.

use super::{resolve_blocked_ips, split_families, Firewall};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

const TABLE: &str = "claude_guard";
const CHAIN: &str = "CLAUDE_GUARD";

#[derive(Debug, Clone, PartialEq)]
enum Backend {
    Nftables,
    Iptables,
}

pub struct LinuxFirewall {
    backend: Backend,
    blocked: AtomicBool,
}

impl LinuxFirewall {
    pub fn new() -> Self {
        Self { backend: detect_backend(), blocked: AtomicBool::new(false) }
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

/// Resolved addresses split by family — the two are configured through separate
/// nftables set types and separate iptables binaries, so they cannot be mixed.
#[derive(Default)]
struct Addresses {
    v4: Vec<String>,
    v6: Vec<String>,
}

impl Addresses {
    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

fn resolve_domains() -> Addresses {
    let (v4, v6) = split_families(&resolve_blocked_ips());
    Addresses { v4, v6 }
}

impl Firewall for LinuxFirewall {
    fn block(&self) -> Result<(), String> {
        let addrs = resolve_domains();
        if addrs.is_empty() {
            return Err(
                "DNS resolution returned no IPs — not blocking to avoid false positives".into()
            );
        }

        match self.backend {
            Backend::Nftables => block_nft(&addrs),
            Backend::Iptables => block_ipt(&addrs),
        }?;
        self.blocked.store(true, Ordering::SeqCst);
        log::info!("blocked {} IPs (v4: {:?}, v6: {:?})", addrs.len(), addrs.v4, addrs.v6);
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

/// `elements = { }` is a syntax error in nft, so the line is omitted for an empty
/// family. Declaring the set anyway keeps the chain rule referencing it valid.
fn elements_line(addrs: &[String]) -> String {
    if addrs.is_empty() {
        String::new()
    } else {
        format!("\n        elements = {{ {} }}", addrs.join(", "))
    }
}

fn block_nft(addrs: &Addresses) -> Result<(), String> {
    let v4 = elements_line(&addrs.v4);
    let v6 = elements_line(&addrs.v6);

    // The empty declaration + delete + redefinition run as one nft transaction, so
    // the old ruleset is replaced atomically — there is no moment where the table
    // is absent and traffic passes. The empty `table` line makes `delete` succeed
    // on the first run, when nothing exists yet.
    let ruleset = format!(
        r#"table inet {TABLE} {{}}
delete table inet {TABLE}
table inet {TABLE} {{
    set blocked_v4 {{
        type ipv4_addr
        flags interval{v4}
    }}
    set blocked_v6 {{
        type ipv6_addr
        flags interval{v6}
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
        ip daddr @blocked_v4 drop comment "claude-guard"
        ip6 daddr @blocked_v6 drop comment "claude-guard"
    }}
}}"#
    );

    let mut child = Command::new("sudo")
        .args(["nft", "-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft spawn: {e}"))?;

    child
        .stdin
        .take()
        .ok_or("nft: failed to capture stdin")?
        .write_all(ruleset.as_bytes())
        .map_err(|e| format!("nft stdin: {e}"))?;

    let out = child.wait_with_output().map_err(|e| format!("nft wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "nft: ruleset load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn unblock_nft() -> Result<(), String> {
    let out = Command::new("sudo")
        .args(["nft", "delete", "table", "inet", TABLE])
        .output()
        .map_err(|e| format!("nft: {e}"))?;

    // Deleting a table that was never created is the expected no-op on a first
    // unblock, so only a different failure is worth reporting.
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && !stderr.contains("No such file or directory") {
        return Err(format!("nft: delete table failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Runs one iptables/ip6tables invocation, failing loudly on a non-zero exit.
fn ipt(bin: &str, args: &[&str]) -> Result<(), String> {
    let out =
        Command::new("sudo").arg(bin).args(args).output().map_err(|e| format!("{bin}: {e}"))?;

    if !out.status.success() {
        return Err(format!(
            "{bin} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Best-effort teardown: every step is expected to fail when the chain is absent.
fn ipt_reset(bin: &str) {
    let _ = Command::new("sudo").args([bin, "-D", "OUTPUT", "-j", CHAIN]).output();
    let _ = Command::new("sudo").args([bin, "-F", CHAIN]).output();
    let _ = Command::new("sudo").args([bin, "-X", CHAIN]).output();
}

/// Number of rules currently in the chain. A missing chain counts as zero, which is
/// what a first run should see.
fn ipt_rule_count(bin: &str) -> usize {
    let Ok(out) = Command::new("sudo").args([bin, "-S", CHAIN]).output() else {
        return 0;
    };
    if !out.status.success() {
        return 0;
    }
    // `-S` echoes the chain declaration (`-N CLAUDE_GUARD`) before the rules.
    String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("-A")).count()
}

fn block_ipt(addrs: &Addresses) -> Result<(), String> {
    block_ipt_family("iptables", &addrs.v4)?;
    block_ipt_family("ip6tables", &addrs.v6)
}

fn block_ipt_family(bin: &str, ips: &[String]) -> Result<(), String> {
    // Nothing resolved for this family — drop any leftover rules so a stale address
    // is not blocked forever, then leave the family unconfigured.
    if ips.is_empty() {
        ipt_reset(bin);
        return Ok(());
    }

    // Fails when the chain already exists, which is the common case.
    let _ = Command::new("sudo").args([bin, "-N", CHAIN]).output();

    // The old rules stay in force while the new ones are appended, and the jump is
    // never removed. Both sets are briefly active, which over-blocks rather than
    // leaving a window where traffic passes unfiltered.
    let stale = ipt_rule_count(bin);

    for ip in ips {
        ipt(
            bin,
            &["-A", CHAIN, "-d", ip, "-j", "DROP", "-m", "comment", "--comment", "claude-guard"],
        )?;
    }

    // -C exits non-zero when the jump is absent; only then does it need inserting.
    let hooked = Command::new("sudo")
        .args([bin, "-C", "OUTPUT", "-j", CHAIN])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !hooked {
        ipt(bin, &["-I", "OUTPUT", "-j", CHAIN])?;
    }

    // Now that the replacements are live, retire the previous generation. Deleting
    // by index 1 repeatedly always removes the oldest remaining rule.
    for _ in 0..stale {
        if let Err(e) = ipt(bin, &["-D", CHAIN, "1"]) {
            log::warn!("could not retire a superseded {bin} rule: {e}");
            break;
        }
    }
    Ok(())
}

fn unblock_ipt() -> Result<(), String> {
    ipt_reset("iptables");
    ipt_reset("ip6tables");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_family_omits_the_elements_line() {
        assert_eq!(elements_line(&[]), "");
    }

    #[test]
    fn populated_family_renders_an_elements_line() {
        let line = elements_line(&["1.2.3.4".to_string(), "5.6.7.8".to_string()]);
        assert_eq!(line, "\n        elements = { 1.2.3.4, 5.6.7.8 }");
    }

    #[test]
    fn addresses_report_emptiness_across_both_families() {
        let mut a = Addresses::default();
        assert!(a.is_empty());
        a.v6.push("2607:6bc0::10".to_string());
        assert!(!a.is_empty());
        assert_eq!(a.len(), 1);
    }
}
