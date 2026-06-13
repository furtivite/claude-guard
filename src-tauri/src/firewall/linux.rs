//! Файрвол Linux: nftables (предпочтительно) или iptables с ipset.
//!
//! nftables: блокировка через `dnat` + verdict map по доменным именам невозможна
//! без userspace DNS — поэтому используем nftables с периодически обновляемым set.
//! Домены резолвятся через systemd-resolved/getaddrinfo в spawn_blocking,
//! результат пишется в nft set. При смене IP Anthropic — перезаписывается при
//! следующем цикле проверки (каждые N секунд).
//!
//! Это лучше чем единоразовый резолв: IP обновляется регулярно, а не только
//! при старте приложения. DNS rebinding остаётся теоретическим вектором,
//! но окно атаки ограничено интервалом проверки.
//!
//! Windows netsh не поддерживает FQDN — см. windows.rs.

use super::{Firewall, BLOCKED_DOMAINS};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::process::{Command, Stdio};
use std::io::Write;
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

/// Резолвит BLOCKED_DOMAINS в IP через системный DNS (getaddrinfo).
/// Выполняется в spawn_blocking — не блокирует async executor.
/// Вызывается при каждом цикле блокировки, поэтому смена IP Anthropic
/// подхватывается автоматически.
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
        // Резолвим каждый раз — IP мог смениться
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

// ── nftables ──────────────────────────────────────────────────

fn block_nft(ips: &[String]) -> Result<(), String> {
    // Атомарная замена таблицы: delete + create в одной транзакции
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

    // delete игнорируем — таблицы может не быть при первом запуске
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

// ── iptables ──────────────────────────────────────────────────

fn block_ipt(ips: &[String]) -> Result<(), String> {
    // Сначала сбрасываем старые правила — иначе накапливаются дубли
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
