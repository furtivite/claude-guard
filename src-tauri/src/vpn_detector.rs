//! VPN activity detection.
//!
//! In Port/Process modes, an inactive VPN triggers an immediate block without
//! querying the IP API. In IpOnly mode, only the IP country is evaluated.

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnMode {
    #[default]
    IpOnly,
    Port,
    Process,
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

    /// Returns the name of the active VPN interface, for display in the UI only.
    pub fn detect_interface() -> Option<String> {
        NetworkInterface::show()
            .unwrap_or_default()
            .into_iter()
            .find(|iface| {
                let n = &iface.name;
                !iface.addr.is_empty()
                    && (n.starts_with("utun")
                        || n.starts_with("tun")
                        || n.starts_with("wg")
                        || n.starts_with("ppp"))
            })
            .map(|iface| iface.name)
    }

    fn port_open(&self) -> bool {
        use std::net::{SocketAddr, TcpStream};
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_only_is_always_active() {
        let d = VpnDetector::new(VpnMode::IpOnly, 0, String::new());
        assert!(d.is_active());
    }

    #[test]
    fn empty_process_name_is_never_running() {
        let d = VpnDetector::new(VpnMode::Process, 0, String::new());
        assert!(!d.is_active());
    }

    #[test]
    fn default_mode_is_ip_only() {
        assert_eq!(VpnMode::default(), VpnMode::IpOnly);
    }
}
