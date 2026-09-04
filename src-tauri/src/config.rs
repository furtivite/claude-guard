//! Application settings — single source of truth for store keys and defaults.

use crate::vpn_detector::VpnMode;
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;

pub const STORE_FILE: &str = "settings.json";

/// Lower bound on the check interval — guards against hammering ipinfo.io.
pub const MIN_INTERVAL_SECS: u64 = 10;

/// Clamp a stored interval to the allowed minimum.
pub fn normalize_interval(secs: u64) -> u64 {
    secs.max(MIN_INTERVAL_SECS)
}

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub check_interval_secs: u64,
    pub show_tray: bool,
    pub autostart: bool,
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
            // Off by default: registering a login item changes state outside the app,
            // so it is the user's call rather than something installing itself.
            autostart: false,
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

        let vpn_mode =
            match store.get("vpn_mode").and_then(|v| v.as_str().map(String::from)).as_deref() {
                Some("port") => VpnMode::Port,
                Some("process") => VpnMode::Process,
                _ => VpnMode::IpOnly,
            };

        Self {
            enabled: store.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
            check_interval_secs: normalize_interval(
                store.get("check_interval").and_then(|v| v.as_u64()).unwrap_or(30),
            ),
            show_tray: store.get("show_tray").and_then(|v| v.as_bool()).unwrap_or(true),
            autostart: store.get("autostart").and_then(|v| v.as_bool()).unwrap_or(false),
            vpn_mode,
            vpn_port: store.get("vpn_port").and_then(|v| v.as_u64()).unwrap_or(10808) as u16,
            vpn_process: store
                .get("vpn_process")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "check_interval": self.check_interval_secs,
            "show_tray": self.show_tray,
            "autostart": self.autostart,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_is_clamped_to_minimum() {
        assert_eq!(normalize_interval(0), MIN_INTERVAL_SECS);
        assert_eq!(normalize_interval(5), MIN_INTERVAL_SECS);
        assert_eq!(normalize_interval(10), 10);
        assert_eq!(normalize_interval(30), 30);
    }

    #[test]
    fn default_config_is_disabled_and_ip_only() {
        let c = Config::default();
        assert!(!c.enabled);
        assert_eq!(c.vpn_mode, VpnMode::IpOnly);
        assert_eq!(c.check_interval_secs, 30);
    }

    #[test]
    fn autostart_is_off_until_asked_for() {
        assert!(!Config::default().autostart);
        assert_eq!(Config::default().to_json()["autostart"], false);
    }

    #[test]
    fn to_json_roundtrips_vpn_mode() {
        let c = Config { vpn_mode: VpnMode::Port, ..Config::default() };
        assert_eq!(c.to_json()["vpn_mode"], "port");
    }
}
