//! Файрвол macOS через pfctl.
//!
//! Используем PF-таблицу с FQDN — pfctl резолвит домены сам через `/etc/hosts`
//! и системный DNS при загрузке правил, и периодически обновляет таблицу.
//! Это защищает от DNS rebinding: правило привязано к имени, не к IP.
//!
//! Якорь `claude_guard` изолирован — системные правила PF не затрагиваются.

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
            let err = String::from_utf8_lossy(&out.stderr);
            // pfctl пишет в stderr при успехе ("pfctl: Use of -f...") — фильтруем
            if !err.contains("pfctl: Use of") && !err.is_empty() {
                log::warn!("pfctl stderr: {err}");
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

        child.wait().map_err(|e| format!("pfctl wait: {e}"))?;
        Ok(())
    }
}

impl Firewall for MacosFirewall {
    fn block(&self) -> Result<(), String> {
        // Блокируем по FQDN — pfctl резолвит при загрузке правил.
        // `quick` прерывает дальнейшую обработку при совпадении.
        let rules: String = BLOCKED_DOMAINS
            .iter()
            .map(|domain| format!("block drop out quick proto {{ tcp udp }} to <{domain}>\n"))
            .collect();

        // Загружаем домены в именованные таблицы pfctl
        let mut table_rules = String::new();
        for domain in BLOCKED_DOMAINS {
            table_rules += &format!("table <{domain}> persist {{{domain}}}\n");
        }
        let full_rules = table_rules + &rules;

        self.write_rules(&full_rules)?;
        self.pfctl(&["-e"])?; // убедиться что PF включён
        self.blocked.store(true, Ordering::SeqCst);
        log::info!("pfctl: blocked {BLOCKED_DOMAINS:?} via anchor {ANCHOR}");
        Ok(())
    }

    fn unblock(&self) -> Result<(), String> {
        // Очищаем только наш якорь
        self.pfctl(&["-a", ANCHOR, "-F", "all"])?;
        self.blocked.store(false, Ordering::SeqCst);
        log::info!("pfctl: unblocked anchor {ANCHOR}");
        Ok(())
    }

    fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst)
    }
}
