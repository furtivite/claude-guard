//! Определение активности VPN.
//!
//! `VpnDetector::is_active` используется как предусловие: если VPN не активен
//! в режимах Port/Process — блокируем сразу, без IP-запроса.
//! В режиме IpOnly решение принимается только по IP.
//!
//! `detect_interface` — отдельная индикация для UI, на логику блокировки не влияет.

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnMode {
    IpOnly,
    Port,
    Process,
}

impl Default for VpnMode {
    fn default() -> Self {
        Self::IpOnly
    }
}

pub struct VpnDetector {
    mode: VpnMode,
    port: u16,
    process: String,
}

impl VpnDetector {
    pub fn new(mode: VpnMode, port: u16, process: String) -> Self {
        Self { mode, port, process }
    }

    pub fn is_active(&self) -> bool {
        match self.mode {
            VpnMode::IpOnly => true,
            VpnMode::Port => self.port_open(),
            VpnMode::Process => self.process_running(),
        }
    }

    /// Ищет VPN-интерфейс в системе. Результат — только для отображения в UI.
    pub fn detect_interface() -> Option<String> {
        NetworkInterface::show()
            .unwrap_or_default()
            .into_iter()
            .find(|iface| {
                let n = &iface.name;
                !iface.addr.is_empty()
                    && (n.starts_with("utun")  // macOS: любой туннель
                        || n.starts_with("tun")
                        || n.starts_with("wg")
                        || n.starts_with("ppp"))
            })
            .map(|iface| iface.name)
    }

    fn port_open(&self) -> bool {
        use std::net::TcpStream;
        TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", self.port).parse().unwrap(),
            Duration::from_millis(300),
        )
        .is_ok()
    }

    fn process_running(&self) -> bool {
        if self.process.is_empty() {
            return false;
        }
        #[cfg(unix)]
        {
            std::process::Command::new("pgrep")
                .args(["-x", &self.process])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        #[cfg(windows)]
        {
            std::process::Command::new("tasklist")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains(self.process.as_str()))
                .unwrap_or(false)
        }
    }
}
