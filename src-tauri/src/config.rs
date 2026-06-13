//! Настройки приложения — единая точка чтения из store.
//!
//! Все дефолты живут здесь, guard.rs и main.rs не знают ключей store.

use crate::vpn_detector::VpnMode;
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;

pub const STORE_FILE: &str = "settings.json";

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub check_interval_secs: u64,
    pub show_tray: bool,
    pub vpn_mode: VpnMode,
    pub vpn_port: u16,
    pub vpn_process: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: 30,
            show_tray: true,
            vpn_mode: VpnMode::IpOnly,
            vpn_port: 10808,
            vpn_process: String::new(),
        }
    }
}

impl Config {
    pub fn load(app: &AppHandle) -> Self {
        let Ok(store) = app.store(STORE_FILE) else {
            return Self::default();
        };

        let vpn_mode = match store
            .get("vpn_mode")
            .and_then(|v| v.as_str().map(String::from))
            .as_deref()
        {
            Some("port") => VpnMode::Port,
            Some("process") => VpnMode::Process,
            _ => VpnMode::IpOnly,
        };

        Self {
            enabled: store.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
            check_interval_secs: store
                .get("check_interval")
                .and_then(|v| v.as_u64())
                .unwrap_or(30)
                .max(10),
            show_tray: store.get("show_tray").and_then(|v| v.as_bool()).unwrap_or(true),
            vpn_mode,
            vpn_port: store
                .get("vpn_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(10808) as u16,
            vpn_process: store
                .get("vpn_process")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
        }
    }

    /// Сериализует конфиг в JSON для команды get_settings.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "check_interval": self.check_interval_secs,
            "show_tray": self.show_tray,
            "vpn_mode": match self.vpn_mode {
                VpnMode::IpOnly  => "ip_only",
                VpnMode::Port    => "port",
                VpnMode::Process => "process",
            },
            "vpn_port": self.vpn_port,
            "vpn_process": self.vpn_process,
        })
    }
}
