//! Абстракция файрвола.
//!
//! Каждая платформа реализует трейт `Firewall`.
//! Блокировка идёт по доменным именам (не IP) — это защищает от DNS rebinding:
//! даже если Anthropic сменит IP или DNS будет скомпрометирован,
//! правила продолжат работать корректно.
//!
//! Добавить платформу: создай модуль, реализуй трейт, добавь ветку в `platform()`.

pub mod linux;
pub mod macos;
pub mod windows;

/// Домены блокируются на уровне файрвола напрямую — без DNS-резолва в приложении.
/// PF и nftables умеют работать с FQDN через таблицы/sets с периодическим резолвом.
/// Windows netsh не поддерживает FQDN — там оставляем IP-резолв как fallback,
/// но документируем ограничение.
pub const BLOCKED_DOMAINS: &[&str] = &["api.anthropic.com", "claude.ai"];

pub trait Firewall: Send + Sync {
    /// Заблокировать исходящий трафик к доменам из BLOCKED_DOMAINS.
    fn block(&self) -> Result<(), String>;
    /// Снять блокировку.
    fn unblock(&self) -> Result<(), String>;
    /// Текущее состояние.
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
