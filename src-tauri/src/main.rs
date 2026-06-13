#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod firewall;
mod guard;
mod ip_checker;
mod vpn_detector;

use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    Manager, WebviewWindowBuilder,
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

fn setup_tray(app: &tauri::App, enabled: bool) -> tauri::Result<()> {
    let toggle_label = if enabled { "Disable protection" } else { "Enable protection" };

    let toggle = MenuItem::with_id(app, "toggle", toggle_label, true, None::<&str>)?;
    let show   = MenuItem::with_id(app, "show",   "Open Status",       true, None::<&str>)?;
    let quit   = MenuItem::with_id(app, "quit",   "Quit",              true, None::<&str>)?;
    let menu   = Menu::with_items(app, &[&toggle, &show, &quit])?;

    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .tooltip(if enabled { "Claude Guard — Active" } else { "Claude Guard — Disabled" })
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
// Tauri v2 requires rebuilding the full menu to update a single item's label.
pub fn update_tray_menu(app: &tauri::AppHandle, enabled: bool) {
    let Some(tray) = app.tray_by_id("main") else { return };

    let label = if enabled { "Disable protection" } else { "Enable protection" };
    let tooltip = if enabled { "Claude Guard — Active" } else { "Claude Guard — Disabled" };

    if let (Ok(toggle), Ok(show), Ok(quit)) = (
        MenuItem::with_id(app, "toggle", label,         true, None::<&str>),
        MenuItem::with_id(app, "show",   "Open Status", true, None::<&str>),
        MenuItem::with_id(app, "quit",   "Quit",        true, None::<&str>),
    ) {
        if let Ok(menu) = Menu::with_items(app, &[&toggle, &show, &quit]) {
            let _ = tray.set_menu(Some(menu));
        }
    }
    let _ = tray.set_tooltip(Some(tooltip));
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
async fn cmd_get_status(
    state: tauri::State<'_, SharedState>,
) -> Result<guard::Status, String> {
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
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    if let Some(obj) = settings.as_object() {
        for (k, v) in obj {
            store.set(k.clone(), v.clone());
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
    let state = app
        .try_state::<SharedState>()
        .ok_or("state not found")?
        .inner()
        .clone();
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

    let app_clone = app.clone();
    let state_clone = state.clone();
    tokio::spawn(async move {
        guard::force_check(app_clone, state_clone).await;
    });

    Ok(())
}

fn main() {
    env_logger::init();
    run();
}
