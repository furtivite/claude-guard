#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod firewall;
mod guard;
mod ip_checker;
mod vpn_detector;

use std::sync::Arc;
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    Manager, Runtime, WebviewWindowBuilder,
};
use tauri_plugin_store::StoreExt;
use tokio::sync::Mutex;

use config::{Config, STORE_FILE};
use guard::GuardState;

pub type SharedState = Arc<Mutex<GuardState>>;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let cfg = Config::load(app.handle());
            let state: SharedState = Arc::new(Mutex::new(GuardState::new()));
            app.manage(state.clone());

            let handle = app.handle().clone();
            tokio::spawn(async move {
                guard::run_loop(handle, state).await;
            });

            if cfg.show_tray {
                setup_tray(app, cfg.enabled)?;
            }

            WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("/".into()))
                .title("Claude Guard")
                .inner_size(420.0, 580.0)
                .resizable(false)
                .visible(false)
                .build()?;

            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            cmd_get_status,
            cmd_get_settings,
            cmd_save_settings,
            cmd_force_check,
            cmd_toggle_enabled,
        ])
        .run(tauri::generate_context!())
        .expect("tauri failed to start");
}

/// Tooltip shown on hover, reflecting whether protection is on.
fn tray_tooltip(enabled: bool) -> &'static str {
    if enabled {
        "Claude Guard — Active"
    } else {
        "Claude Guard — Disabled"
    }
}

/// Builds the tray context menu for the given protection state.
///
/// Generic over the manager so it serves both `App` (at setup) and `AppHandle`
/// (on later rebuilds) — Tauri v2 has no API to relabel a single item, so the
/// whole menu is rebuilt whenever `enabled` changes.
fn build_tray_menu<R: Runtime, M: Manager<R>>(
    manager: &M,
    enabled: bool,
) -> tauri::Result<Menu<R>> {
    let toggle_label = if enabled { "Disable protection" } else { "Enable protection" };
    let toggle = MenuItem::with_id(manager, "toggle", toggle_label, true, None::<&str>)?;
    let show = MenuItem::with_id(manager, "show", "Open Status", true, None::<&str>)?;
    let quit = MenuItem::with_id(manager, "quit", "Quit", true, None::<&str>)?;
    Menu::with_items(manager, &[&toggle, &show, &quit])
}

fn setup_tray(app: &tauri::App, enabled: bool) -> tauri::Result<()> {
    let menu = build_tray_menu(app, enabled)?;

    // macOS menu bar expects a monochrome *template* image that the system
    // recolors for the light/dark bar. Windows and Linux have no such recoloring,
    // so use the full-color icon there — a black silhouette would vanish on dark
    // taskbars/panels.
    #[cfg(target_os = "macos")]
    let (icon_bytes, is_template): (&[u8], bool) = (&include_bytes!("../icons/tray.png")[..], true);
    #[cfg(not(target_os = "macos"))]
    let (icon_bytes, is_template): (&[u8], bool) =
        (&include_bytes!("../icons/icon.png")[..], false);

    let icon = Image::from_bytes(icon_bytes).expect("bundled tray icon is invalid");

    TrayIconBuilder::with_id("main")
        .icon(icon)
        .icon_as_template(is_template)
        .menu(&menu)
        .tooltip(tray_tooltip(enabled))
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                toggle_window(tray.app_handle());
            }
        })
        .on_menu_event(|app, event| match event.id.as_ref() {
            "toggle" => {
                let cfg = Config::load(app);
                let new_enabled = !cfg.enabled;
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = do_toggle_enabled(&app, new_enabled).await {
                        log::error!("tray toggle failed: {e}");
                    }
                });
            }
            "show" => toggle_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;

    Ok(())
}

/// Rebuilds the tray menu and tooltip to reflect the current `enabled` state.
pub fn update_tray_menu(app: &tauri::AppHandle, enabled: bool) {
    let Some(tray) = app.tray_by_id("main") else { return };

    if let Ok(menu) = build_tray_menu(app, enabled) {
        let _ = tray.set_menu(Some(menu));
    }
    let _ = tray.set_tooltip(Some(tray_tooltip(enabled)));
}

fn toggle_window(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("main") else { return };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
    } else {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
async fn cmd_get_status(state: tauri::State<'_, SharedState>) -> Result<guard::Status, String> {
    Ok(state.lock().await.status.clone())
}

#[tauri::command]
async fn cmd_get_settings(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    Ok(Config::load(&app).to_json())
}

#[tauri::command]
async fn cmd_save_settings(
    app: tauri::AppHandle,
    settings: serde_json::Value,
) -> Result<(), String> {
    // Whitelist known keys so the store can't be polluted with arbitrary entries.
    const ALLOWED_KEYS: &[&str] =
        &["enabled", "check_interval", "show_tray", "vpn_mode", "vpn_port", "vpn_process"];
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    if let Some(obj) = settings.as_object() {
        for (k, v) in obj {
            if ALLOWED_KEYS.contains(&k.as_str()) {
                store.set(k.clone(), v.clone());
            } else {
                log::warn!("cmd_save_settings: ignoring unknown key {k:?}");
            }
        }
    }
    store.save().map_err(|e| e.to_string())
}

#[tauri::command]
async fn cmd_force_check(
    app: tauri::AppHandle,
    state: tauri::State<'_, SharedState>,
) -> Result<(), String> {
    let state = state.inner().clone();
    tokio::spawn(async move {
        guard::force_check(app, state).await;
    });
    Ok(())
}

#[tauri::command]
async fn cmd_toggle_enabled(
    app: tauri::AppHandle,
    state: tauri::State<'_, SharedState>,
    enabled: bool,
) -> Result<(), String> {
    let state = state.inner().clone();
    do_toggle_enabled_with_state(&app, &state, enabled).await
}

async fn do_toggle_enabled(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let state = app.try_state::<SharedState>().ok_or("state not found")?.inner().clone();
    do_toggle_enabled_with_state(app, &state, enabled).await
}

async fn do_toggle_enabled_with_state(
    app: &tauri::AppHandle,
    state: &SharedState,
    enabled: bool,
) -> Result<(), String> {
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    store.set("enabled", serde_json::Value::Bool(enabled));
    store.save().map_err(|e| e.to_string())?;

    update_tray_menu(app, enabled);

    // Await the check (rather than spawning it detached) so the firewall state is
    // applied before this returns. That makes rapid enable/disable toggles resolve
    // in call order instead of racing several detached tasks for the state lock.
    guard::force_check(app.clone(), state.clone()).await;

    Ok(())
}

fn main() {
    env_logger::init();
    run();
}
