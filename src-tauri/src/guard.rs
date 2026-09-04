//! Core protection loop.
//!
//! Fail-closed error policy:
//! - On startup: block immediately, unblock only after a successful IP check.
//! - If ipinfo.io is unreachable: preserve existing firewall rules unchanged.
//! - If DNS resolution fails (Linux/Windows): preserve existing firewall rules unchanged.

use crate::config::Config;
use crate::firewall::{self, Firewall};
use crate::ip_checker::{self, IpInfo};
use crate::vpn_detector::{VpnDetector, VpnMode};
use crate::SharedState;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::Emitter;
use tauri_plugin_notification::NotificationExt;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    #[default]
    None,
    RussianIp,
    VpnInactive,
    CheckFailed,
    Initializing,
    /// A firewall command failed. Combined with `blocked` this distinguishes the
    /// two outcomes: `blocked == false` means the machine is NOT protected, while
    /// `blocked == true` means stale rules are still in force and could not be lifted.
    FirewallError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub blocked: bool,
    pub block_reason: BlockReason,
    pub ip_info: Option<IpInfo>,
    pub vpn_interface: Option<String>,
    pub vpn_active: bool,
    pub guard_enabled: bool,
    pub last_check: Option<String>,
    pub error: Option<String>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            blocked: false,
            block_reason: BlockReason::Initializing,
            ip_info: None,
            vpn_interface: None,
            vpn_active: false,
            guard_enabled: false,
            last_check: None,
            error: None,
        }
    }
}

pub struct GuardState {
    pub status: Status,
    pub firewall: Box<dyn Firewall>,
}

impl GuardState {
    pub fn new() -> Self {
        Self { status: Status::default(), firewall: firewall::platform() }
    }
}

pub async fn run_loop(app: tauri::AppHandle, state: SharedState) {
    let cfg = Config::load(&app);

    if cfg.enabled {
        let mut s = state.lock().await;
        s.status.guard_enabled = true;
        let result = s.firewall.block();
        match result {
            Ok(()) => {
                s.status.blocked = true;
                s.status.block_reason = BlockReason::Initializing;
            }
            // Nothing was applied, so reporting `blocked` here would be a lie in the
            // one direction that matters — the user would think they are protected.
            Err(e) => {
                log::error!("Initial block failed: {e}");
                s.status.blocked = false;
                s.status.block_reason = BlockReason::FirewallError;
                s.status.error = Some(e);
            }
        }
        emit(&app, &s.status);
    } else {
        let mut s = state.lock().await;
        s.status.guard_enabled = false;
        s.status.blocked = false;
        s.status.block_reason = BlockReason::None;
        emit(&app, &s.status);
    }

    loop {
        let interval = Config::load(&app).check_interval_secs;
        check(&app, &state).await;
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

pub async fn force_check(app: tauri::AppHandle, state: SharedState) {
    ip_checker::invalidate().await;
    check(&app, &state).await;
}

async fn check(app: &tauri::AppHandle, state: &SharedState) {
    let cfg = Config::load(app);

    if !cfg.enabled {
        let mut s = state.lock().await;
        if s.firewall.is_blocked() {
            let _ = s.firewall.unblock();
        }
        s.status.guard_enabled = false;
        s.status.blocked = false;
        s.status.block_reason = BlockReason::None;
        s.status.error = None;
        emit(app, &s.status);
        return;
    }

    let detector = VpnDetector::new(cfg.vpn_mode.clone(), cfg.vpn_port, cfg.vpn_process);
    let vpn_active = detector.is_active();
    let vpn_iface = VpnDetector::detect_interface();

    if cfg.vpn_mode != VpnMode::IpOnly && !vpn_active {
        let mut s = state.lock().await;
        transition(app, &mut s, None, vpn_iface, false, true, BlockReason::VpnInactive).await;
        return;
    }

    match ip_checker::get().await {
        Ok(info) => {
            let should_block = info.is_russian;
            let reason = if should_block { BlockReason::RussianIp } else { BlockReason::None };
            let mut s = state.lock().await;
            transition(app, &mut s, Some(info), vpn_iface, vpn_active, should_block, reason).await;
        }
        // Fail-closed: preserve current firewall state, update error in status only.
        Err(e) => {
            log::warn!("IP check failed (rules unchanged): {e}");
            let mut s = state.lock().await;
            let was_blocked = s.firewall.is_blocked();
            s.status.error = Some(e);
            s.status.last_check = Some(now());
            if was_blocked {
                s.status.block_reason = BlockReason::CheckFailed;
            }
            emit(app, &s.status);
        }
    }
}

async fn transition(
    app: &tauri::AppHandle,
    s: &mut GuardState,
    ip_info: Option<IpInfo>,
    vpn_interface: Option<String>,
    vpn_active: bool,
    should_block: bool,
    reason: BlockReason,
) {
    let was_blocked = s.firewall.is_blocked();
    let mut err = None;
    // What the firewall enforces once this cycle is done. It only tracks the intent
    // when the command succeeds; on failure the previous rules are what remains.
    let mut applied = should_block;
    let mut reason = reason;

    if should_block {
        // Re-apply on every cycle (not just on the false→true edge) so that
        // rotating Anthropic/Cloudflare IPs are re-resolved and the blocklist
        // stays current. block() is idempotent — it replaces the ruleset.
        match s.firewall.block() {
            // Old rules stay in place if this fails, so we remain fail-closed.
            Ok(()) if !was_blocked => {
                notify(app, "🔴 Blocked", "Russian IP detected. Anthropic traffic blocked.")
            }
            Ok(()) => {}
            Err(e) => {
                log::error!("firewall::block failed: {e}");
                err = Some(e);
                applied = was_blocked;
                reason = BlockReason::FirewallError;
                if !applied {
                    notify(
                        app,
                        "⚠️ NOT protected",
                        "Russian IP detected but the firewall rules could not be applied.",
                    );
                }
            }
        }
    } else if was_blocked {
        match s.firewall.unblock() {
            Ok(()) => notify(app, "🟢 Safe", "Non-Russian IP. Anthropic access restored."),
            // Failing to lift rules over-blocks, which is the safe direction, but the
            // UI must not claim traffic is flowing when it is not.
            Err(e) => {
                log::error!("firewall::unblock failed: {e}");
                err = Some(e);
                applied = true;
                reason = BlockReason::FirewallError;
            }
        }
    }

    let failed = reason == BlockReason::FirewallError;
    s.status = Status {
        blocked: applied,
        block_reason: reason,
        ip_info,
        vpn_interface,
        vpn_active,
        guard_enabled: true,
        last_check: Some(now()),
        error: err,
    };

    update_tray(app, applied, failed);
    emit(app, &s.status);
}

fn emit(app: &tauri::AppHandle, status: &Status) {
    let _ = app.emit("guard:status", status);
}

fn notify(app: &tauri::AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

fn update_tray(app: &tauri::AppHandle, blocked: bool, failed: bool) {
    if let Some(tray) = app.tray_by_id("main") {
        let tip = match (blocked, failed) {
            // Rules could not be applied — the tray must not read as "Protected".
            (false, true) => "Claude Guard — FIREWALL ERROR, NOT PROTECTED",
            (true, true) => "Claude Guard — BLOCKED (rules could not be lifted)",
            (true, false) => "Claude Guard — BLOCKED",
            (false, false) => "Claude Guard — Protected",
        };
        let _ = tray.set_tooltip(Some(tip));
    }
}

fn now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}
