//! The security settings of the shell, kept as files and checked here: what the front end may call, where it may load from
//! and how updates are accepted. Weakening one of them is a decision that has to change one of these tests.

use std::collections::BTreeMap;
use std::fs;

use serde_json::{json, Value};

fn read(path: &str) -> String {
    fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn json_file(path: &str) -> Value {
    serde_json::from_str(&read(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn the_main_window_may_call_the_one_sidecar_command_and_nothing_else() {
    let capability = json_file("capabilities/default.json");
    assert_eq!(capability["windows"], json!(["main"]));
    assert_eq!(capability["permissions"], json!(["allow-sidecar-request"]), "no fs, shell, http, updater or core permission");
    for key in ["remote", "webviews", "platforms"] {
        assert!(capability.get(key).is_none(), "`{key}` widens who the capability applies to");
    }
    let files: Vec<_> = fs::read_dir(format!("{}/capabilities", env!("CARGO_MANIFEST_DIR"))).unwrap().collect();
    assert_eq!(files.len(), 1, "a second capability file would add permissions");
    let windows = json_file("tauri.conf.json")["app"]["windows"].clone();
    assert_eq!(windows.as_array().unwrap().len(), 1);
    assert_eq!(windows[0]["label"], "main");
}

/// The lines (keys) of one section of Cargo.toml.
fn manifest_keys(section: &str) -> Vec<String> {
    let manifest = read("Cargo.toml");
    let mut keys = Vec::new();
    let mut inside = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
        } else if inside && !line.is_empty() && !line.starts_with('#') {
            keys.push(line.split('=').next().unwrap().trim().to_string());
        }
    }
    keys
}

#[test]
fn no_plugin_for_files_shell_or_network_is_built_in() {
    assert_eq!(manifest_keys("dependencies"), ["tauri", "tauri-plugin-updater", "serde", "serde_json"]);
    assert_eq!(manifest_keys("build-dependencies"), ["tauri-build"]);
    // the one more: the sidecar's process group (killpg) and the look-up of a pid that may be a leftover; no network or file plugin
    assert_eq!(manifest_keys("target.'cfg(unix)'.dependencies"), ["libc"]);
    let manifest = read("Cargo.toml");
    let sections: Vec<_> = manifest.lines().filter(|l| l.starts_with('[') && l.contains("dependencies")).collect();
    assert_eq!(sections, ["[build-dependencies]", "[dependencies]", "[target.'cfg(unix)'.dependencies]"], "no dev dependencies");
    assert!(manifest.contains("tauri = { version = \"2.12\", features = [] }"), "tauri features change what the webview can do");
}

#[test]
fn the_content_security_policy_names_no_remote_source() {
    let conf = json_file("tauri.conf.json");
    let csp = conf["app"]["security"]["csp"].as_str().expect("a CSP string");
    let mut directives: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for part in csp.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let mut words = part.split_whitespace();
        directives.insert(words.next().unwrap(), words.collect());
    }
    // the app's own files, the IPC channel to the shell (its address differs between platforms), and nothing else
    let allowed = ["'self'", "'none'", "ipc:", "http://ipc.localhost"];
    for (name, sources) in &directives {
        for source in sources {
            assert!(allowed.contains(source), "{name} allows {source}");
        }
    }
    assert_eq!(directives["default-src"], ["'self'"]);
    assert_eq!(directives["connect-src"], ["ipc:", "http://ipc.localhost"]);
    assert_eq!(directives["object-src"], ["'none'"]);
    assert_eq!(directives["base-uri"], ["'none'"]);
    assert_eq!(directives["form-action"], ["'none'"]);
    assert!(!directives.contains_key("script-src") && !directives.contains_key("style-src"), "they follow default-src");
    assert_eq!(conf["app"]["security"]["freezePrototype"], true);
    let app = &conf["app"];
    assert!(app.get("withGlobalTauri").is_none_or(|v| v == false), "the IPC bridge stays out of the global scope");
    assert!(app["security"].get("assetProtocol").is_none(), "the front end cannot read files through asset URLs");
    assert!(app["security"].get("dangerousDisableAssetCspModification").is_none());
}

#[test]
fn updates_are_fetched_over_https_and_must_be_signed_for_the_version_they_announce() {
    let updater = json_file("tauri.conf.json")["plugins"]["updater"].clone();
    let config: tauri_plugin_updater::Config = serde_json::from_value(updater.clone()).expect("the plugin reads this config");
    assert!(config.require_signed_version, "an old signed artifact must not pass as a newer version");
    assert!(!config.allow_downgrades);
    assert!(!config.dangerous_insecure_transport_protocol);
    assert!(!config.dangerous_accept_invalid_certs);
    assert!(!config.dangerous_accept_invalid_hostnames);
    assert!(!config.endpoints.is_empty());
    for endpoint in &config.endpoints {
        assert_eq!(endpoint.scheme(), "https", "{endpoint}");
    }
    assert!(!config.pubkey.is_empty(), "a placeholder until a release key pair is generated");
    assert_eq!(updater["windows"]["installMode"], "passive");
}

#[test]
fn bundles_are_per_user_on_windows_and_the_sidecar_is_added_by_its_own_file() {
    let windows = json_file("tauri.windows.conf.json");
    assert_eq!(windows["bundle"]["targets"], json!(["nsis"]));
    assert_eq!(windows["bundle"]["windows"]["nsis"]["installMode"], "currentUser", "no admin rights, no prompt on update");
    let macos = json_file("tauri.macos.conf.json");
    assert_eq!(macos["bundle"]["targets"], json!(["app", "dmg"]));
    // the oldest macOS the frozen sidecar runs on, which build-sidecar.py prints after every build: numpy, which the Russian name
    // model needs, ships an arm64 build for macOS 14 (the program was 11.0 before that model went in)
    assert_eq!(macos["bundle"]["macOS"]["minimumSystemVersion"], "14.0");

    // not in tauri.conf.json: tauri-build wants the sidecar file to exist, which `cargo test` on a clean checkout cannot have
    assert!(json_file("tauri.conf.json")["bundle"].get("externalBin").is_none());
    let sidecar = json_file("tauri.sidecar.conf.json");
    assert_eq!(sidecar["bundle"]["externalBin"], json!(["binaries/boxed"]));
    // a folder build looks for its libraries in Contents/Frameworks inside a macOS app, not next to the program
    assert_eq!(sidecar["bundle"]["macOS"]["files"], json!({"Frameworks": "binaries/_internal"}));
}

#[test]
fn the_shell_the_build_and_its_check_all_mean_the_same_name_model() {
    // the shell switches the Russian model on for its sidecar, the build bundles it, and the check runs it as the shell does
    assert!(read("src/lib.rs").contains(r#"("BOXED_SERVE_NER".into(), "ru".into())"#));
    assert!(read("../scripts/build-sidecar.py").contains(r#"EXTRAS = ["formats", "ner-ru"]"#));
    assert!(read("../scripts/sidecar_check.py").contains(r#"env["BOXED_SERVE_NER"] = "ru""#));
}
