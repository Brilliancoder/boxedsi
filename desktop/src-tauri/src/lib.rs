pub mod commands;
pub mod framing;
pub mod manager;
pub mod navigation;
pub mod processes;

use std::io;
use std::path::PathBuf;

use serde_json::{json, Map, Value};
use tauri::{Manager, RunEvent, State, Wry};

use manager::{Config, Sidecar};

/// The sidecar sits next to the program: `Contents/MacOS/boxed` in a macOS app, beside `boxed-desktop.exe` on Windows.
fn sidecar_path() -> io::Result<PathBuf> {
    let program = std::env::current_exe()?;
    let name = if cfg!(windows) { "boxed.exe" } else { "boxed" };
    Ok(program.with_file_name(name))
}

/// The only thing the front end can ask of the shell (see capabilities/default.json): one request to the sidecar, one reply.
/// The request runs on a worker thread because it may take as long as the sidecar needs, up to the 120 s limit.
#[tauri::command]
async fn sidecar_request(sidecar: State<'_, Sidecar>, cmd: String, fields: Option<Map<String, Value>>) -> Result<Value, String> {
    let sidecar = sidecar.inner().clone();
    tauri::async_runtime::spawn_blocking(move || commands::dispatch(&sidecar, &cmd, fields.unwrap_or_default()))
        .await
        .or_else(|_| Ok(json!({"ok": false, "error": commands::INTERNAL_ERROR, "code": "internal"})))
}

pub fn run() {
    tauri::Builder::default()
        // The window never leaves the app's own pages, whatever the page tries.
        .plugin(tauri::plugin::Builder::<Wry, ()>::new("own-pages-only").on_navigation(|_webview, url| navigation::is_own_page(url)).build())
        // Registered so the updater settings in tauri.conf.json are read at start. Nothing calls it yet, and the front end
        // has no permission to.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let mut config = Config::new(sidecar_path()?, vec!["serve".into()]);
            // This sidecar carries the Russian name model (build-sidecar.py bundles the ner-ru extra and checks it). `ner` in
            // boxed.toml is shared with the command line and the browser host, which may not have the extra, so the shell
            // switches the model on for this process only, through the environment, and writes no file.
            config.env = vec![("BOXED_SERVE_NER".into(), "ru".into())];
            // A sidecar that a killed app left behind holds the vault: the next start looks for it by this folder's pid files.
            config.pid_dir = app.path().app_local_data_dir().ok();
            app.manage(Sidecar::start(config));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![sidecar_request])
        .build(tauri::generate_context!())
        .expect("boxed.si failed to start")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                // close the sidecar's input and let it finish the request it is on; it leaves by itself, or is killed
                app.state::<Sidecar>().shutdown();
            }
        });
}
