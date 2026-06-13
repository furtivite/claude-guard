//! Файрвол Windows через Windows Filtering Platform (netsh advfirewall).
//!
//! Ограничение: netsh не поддерживает блокировку по FQDN — только по IP.
//! Это означает что при смене IP Anthropic правила устареют до следующего цикла.
//! Интервал проверки (default 30s) ограничивает окно уязвимости.
//!
//! При каждом вызове block() правила пересоздаются с актуальными IP —
//! это защищает от накопления устаревших записей.

use super::{Firewall, BLOCKED_DOMAINS};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

const RULE_PREFIX: &str = "ClaudeGuard_";

pub struct WindowsFirewall {
    blocked: AtomicBool,
}

impl WindowsFirewall {
    pub fn new() -> Self {
        Self { blocked: AtomicBool::new(false) }
    }

    fn netsh(&self, args: &[&str]) -> Result<(), String> {
        let out = Command::new("netsh")
            .args(["advfirewall", "firewall"])
            .args(args)
            .output()
            .map_err(|e| format!("netsh: {e}"))?;

        if !out.status.success() {
            log::warn!("netsh: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(())
    }

    fn delete_rules(&self) {
        // Удаляем все правила с нашим префиксом
        // netsh не поддерживает wildcard — удаляем по имени паттерна через PowerShell
        let _ = Command::new("powershell")
            .args([
                "-NoProfile", "-NonInteractive", "-Command",
                &format!(
                    "Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' 2>$null | Remove-NetFirewallRule"
                ),
            ])
            .output();
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

impl Firewall for WindowsFirewall {
    fn block(&self) -> Result<(), String> {
        let ips = resolve_domains();
        if ips.is_empty() {
            return Err("DNS resolution returned no IPs".into());
        }

        // Сначала удаляем старые — иначе накапливаются устаревшие правила
        self.delete_rules();

        for (i, ip) in ips.iter().enumerate() {
            let rule_name = format!("{RULE_PREFIX}{i}");
            self.netsh(&[
                "add", "rule",
                &format!("name={rule_name}"),
                "dir=out",
                "action=block",
                &format!("remoteip={ip}"),
                "enable=yes",
                "profile=any",
            ])?;
        }

        self.blocked.store(true, Ordering::SeqCst);
        log::info!("Windows Firewall: blocked {} IPs", ips.len());
        Ok(())
    }

    fn unblock(&self) -> Result<(), String> {
        self.delete_rules();
        self.blocked.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst)
    }
}
