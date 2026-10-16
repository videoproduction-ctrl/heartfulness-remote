//! Webview navigation policy: the window only ever shows the bundled web
//! client. Remote pages are never loaded in the webview (links to the server
//! go to the system browser through `open_url`).

use url::Url;

/// Is `url` a page of the bundled app?
///
/// Tauri serves bundled assets from `tauri://localhost` (macOS, Linux) and
/// `http://tauri.localhost` / `https://tauri.localhost` (Windows).
pub fn is_app_url(url: &Url) -> bool {
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost") && url.port().is_none(),
        "http" | "https" => url.host_str() == Some("tauri.localhost") && url.port().is_none(),
        _ => false,
    }
}

/// Is `url` a `blob:` URL created by the bundled app (used by the web client
/// to save files received from the Mac)?
pub fn is_app_blob_url(url: &Url) -> bool {
    url.scheme() == "blob"
        && Url::parse(url.path())
            .map(|inner| is_app_url(&inner))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn app_urls() {
        for s in [
            "tauri://localhost",
            "tauri://localhost/index.html",
            "tauri://localhost/#setup",
            "http://tauri.localhost/",
            "https://tauri.localhost/index.html?x=1",
        ] {
            assert!(is_app_url(&u(s)), "{s}");
        }
        for s in [
            "https://heartfulness-remote.dedyn.io/",
            "https://tauri.localhost.evil.com/",
            "http://tauri.localhost:8080/",
            "tauri://evil/",
            "http://localhost/",
            "file:///etc/passwd",
            "about:blank",
            "data:text/html,hi",
            "javascript:alert(1)",
        ] {
            assert!(!is_app_url(&u(s)), "{s}");
        }
    }

    #[test]
    fn blob_urls() {
        assert!(is_app_blob_url(&u("blob:tauri://localhost/5b2f0c1e-0000-4000-8000-000000000000")));
        assert!(is_app_blob_url(&u("blob:http://tauri.localhost/5b2f0c1e")));
        assert!(!is_app_blob_url(&u("blob:https://evil.com/5b2f0c1e")));
        assert!(!is_app_blob_url(&u("blob:null/5b2f0c1e")));
        assert!(!is_app_blob_url(&u("tauri://localhost/x")));
        assert!(!is_app_blob_url(&u("data:application/octet-stream,AAAA")));
    }
}
