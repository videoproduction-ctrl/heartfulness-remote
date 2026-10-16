//! Heartfulness Remote native client: a thin Tauri shell around the bundled
//! web client (`web/dist`). The webview gets exactly eight commands (see
//! capabilities/default.json); all logic lives in `hr-client-core`.

// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod keyring_store;

use std::sync::Arc;

use hr_client_core::client::Client;
use hr_client_core::{nav, KEYCHAIN_SERVICE};
use keyring_store::KeyringStore;
use tauri::webview::{DownloadEvent, NewWindowResponse};
use tauri::{AppHandle, Manager, State, WebviewWindowBuilder};
use tauri_plugin_opener::OpenerExt;

type AppClient = Client<Arc<KeyringStore>>;

// Commands run on the async runtime's worker threads (`async`), not the UI
// thread, because credential-store calls can block (e.g. a Keychain prompt).
// Errors are short, non-secret strings (the `invoke` rejection message).

#[tauri::command(async)]
fn device_key_public(client: State<'_, AppClient>) -> Result<String, String> {
    Ok(client.device_key_public()?)
}

#[tauri::command(async)]
fn device_key_sign(client: State<'_, AppClient>, data: String) -> Result<String, String> {
    Ok(client.device_key_sign(&data)?)
}

#[tauri::command(async)]
fn token_get(client: State<'_, AppClient>) -> Result<Option<String>, String> {
    Ok(client.token_get()?)
}

#[tauri::command(async)]
fn token_set(client: State<'_, AppClient>, token: String) -> Result<(), String> {
    Ok(client.token_set(&token)?)
}

#[tauri::command(async)]
fn token_clear(client: State<'_, AppClient>) -> Result<(), String> {
    Ok(client.token_clear()?)
}

#[tauri::command(async)]
fn config_get(client: State<'_, AppClient>) -> Result<Option<String>, String> {
    Ok(client.config_get())
}

/// Returns the canonical origin that was stored (callers may ignore it).
#[tauri::command(async)]
fn config_set(client: State<'_, AppClient>, origin: String) -> Result<String, String> {
    Ok(client.config_set(&origin)?)
}

#[tauri::command(async)]
fn open_url(app: AppHandle, client: State<'_, AppClient>, url: String) -> Result<(), String> {
    let target = client.open_url_target(&url)?;
    app.opener()
        .open_url(target.as_str(), None::<&str>)
        .map_err(|_| "could not open the system browser".to_string())
}

fn main() {
    tauri::Builder::default()
        // Used from Rust only (open_url); the webview is granted no opener
        // permissions, so it cannot call the plugin directly.
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let config_path = app.path().app_config_dir()?.join("config.json");
            let store = Arc::new(KeyringStore::new(KEYCHAIN_SERVICE));
            app.manage::<AppClient>(Client::new(store, config_path));

            // The main window is declared in tauri.conf.json with
            // `create: false` and built here so we can attach the guards.
            let window_config = app
                .config()
                .app
                .windows
                .iter()
                .find(|w| w.label == "main")
                .cloned()
                .ok_or("tauri.conf.json has no window labelled \"main\"")?;
            let downloads = app.path().download_dir().ok();

            WebviewWindowBuilder::from_config(app.handle(), &window_config)?
                // Only the bundled web client may ever be shown.
                .on_navigation(nav::is_app_url)
                // No popups (window.open / target=_blank).
                .on_new_window(|_, _| NewWindowResponse::Deny)
                // Files received from the Mac are saved by the web client via
                // `blob:` downloads; allow only those, into ~/Downloads.
                .on_download(move |_webview, event| match event {
                    DownloadEvent::Requested { url, destination } => {
                        let (Some(dir), true) = (&downloads, nav::is_app_blob_url(&url)) else {
                            return false;
                        };
                        if destination.parent() != Some(dir.as_path()) {
                            let name = destination
                                .file_name()
                                .map(|n| n.to_owned())
                                .unwrap_or_else(|| "download".into());
                            *destination = dir.join(name);
                        }
                        true
                    }
                    _ => true,
                })
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            device_key_public,
            device_key_sign,
            token_get,
            token_set,
            token_clear,
            config_get,
            config_set,
            open_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Heartfulness Remote");
}
