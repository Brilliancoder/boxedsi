use std::{fs, path::Path};

/// What a build made with plain cargo (not `cargo tauri build`) shows when the front end was not built.
const FRONT_END_MISSING: &str = "<!doctype html><meta charset=\"utf-8\"><title>boxed.si</title>\
<p>The front end is not built. Run <code>npm run build</code> in the desktop folder.</p>\n";

fn main() {
    // tauri::generate_context! reads frontendDist at compile time, so a clean checkout needs the folder before
    // `cargo test` can compile anything. `cargo tauri build` runs `npm run build` first and replaces this stub.
    let dist = Path::new("../dist");
    if !dist.exists() {
        fs::create_dir_all(dist).expect("cannot create ../dist");
        fs::write(dist.join("index.html"), FRONT_END_MISSING).expect("cannot write ../dist/index.html");
    }

    // The front end may call this one command and nothing else: it gets its own permission, `allow-sidecar-request`,
    // which capabilities/default.json grants to the main window.
    let app = tauri_build::AppManifest::new().commands(&["sidecar_request"]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(app)).expect("tauri-build failed");
}
