//! The window shows the app's own pages and nothing else. The content security policy keeps the page from loading anything
//! remote, but not from being replaced by a remote page (a link, `location.href`): this is the check for that.

use tauri::Url;

/// True for a page that belongs to the app: `tauri://localhost/...` on macOS, `http(s)://tauri.localhost/...` on Windows.
pub fn is_own_page(url: &Url) -> bool {
    // a port or a login means another server that merely has the same name
    if url.port().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost"),
        "http" | "https" => url.host_str() == Some("tauri.localhost"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own(url: &str) -> bool {
        is_own_page(&Url::parse(url).unwrap())
    }

    #[test]
    fn the_apps_own_pages_are_allowed() {
        assert!(own("tauri://localhost/"));
        assert!(own("tauri://localhost/index.html"));
        assert!(own("http://tauri.localhost/"));
        assert!(own("https://tauri.localhost/assets/index.js"));
    }

    #[test]
    fn nothing_else_is_allowed() {
        for url in [
            "https://example.com/",
            "http://example.com/tauri.localhost",
            "http://tauri.localhost.example.com/",
            "https://tauri.localhost@example.com/",
            "http://localhost:1420/",
            "http://tauri.localhost:8080/",
            "tauri://localhost:9/",
            "http://user:pass@tauri.localhost/",
            "http://127.0.0.1/",
            "tauri://example.com/",
            "tauri://localhost.example.com/",
            "file:///etc/passwd",
            "ftp://tauri.localhost/",
            "data:text/html,<p>hi</p>",
            "javascript:alert(1)",
            "ipc://localhost/sidecar_request",
            "about:blank",
        ] {
            assert!(!own(url), "{url}");
        }
    }
}
