//! Server origin configuration (stored as JSON in the app config directory)
//! and the URL policy for `open_url`.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::Error;

const MAX_ORIGIN_LEN: usize = 2048;
const MAX_OPEN_URL_LEN: usize = 8192;
const MAX_CONFIG_FILE: u64 = 64 * 1024;

fn has_forbidden_chars(s: &str) -> bool {
    // The WHATWG parser silently strips tabs/newlines and treats '\' like '/',
    // so reject them up front instead of accepting a surprising rewrite.
    s.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\')
}

/// Validate a server origin and return its canonical form
/// (`scheme://host[:port]`, lowercase host, no default port, no trailing
/// slash), e.g. `https://heartfulness-remote.dedyn.io`.
///
/// Accepted: `https://<host>[:port]` with an optional single trailing `/`,
/// or `http://localhost[:port]` / `http://127.0.0.1[:port]` for development.
/// Rejected: paths, queries, fragments, credentials, other schemes.
pub fn normalize_origin(input: &str) -> Result<String, Error> {
    let bad = |why: &str| Error::InvalidInput(format!("server address {why}"));
    if input.is_empty() || input.len() > MAX_ORIGIN_LEN {
        return Err(bad("must be 1-2048 characters"));
    }
    if has_forbidden_chars(input) {
        return Err(bad("contains spaces or control characters"));
    }
    let Some((_, rest)) = input.split_once("://") else {
        return Err(bad("must start with https://"));
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return Err(bad("must be https://host with no path, query or fragment"));
    }
    let url = Url::parse(input).map_err(|_| bad("is not a valid URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("must not contain credentials"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(bad("must be https://host with no path, query or fragment"));
    }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => {}
        ("http", Some(Host::Domain("localhost"))) => {}
        ("http", Some(Host::Ipv4(ip))) if ip.is_loopback() && ip.octets() == [127, 0, 0, 1] => {}
        ("http", _) => return Err(bad("must use https:// (http is only allowed for localhost)")),
        _ => return Err(bad("must start with https://")),
    }
    Ok(url.origin().ascii_serialization())
}

/// Policy for `open_url`: the URL must start with `origin + "/"` and parse to
/// exactly that origin. Returns the parsed URL to hand to the OS.
pub fn check_open_url(url: &str, origin: &str) -> Result<Url, Error> {
    let denied = || Error::NotAllowed("URL is not on the configured server".into());
    if url.len() > MAX_OPEN_URL_LEN || has_forbidden_chars(url) {
        return Err(Error::InvalidInput("URL is too long or contains spaces".into()));
    }
    if !url.starts_with(&format!("{origin}/")) {
        return Err(denied());
    }
    let parsed = Url::parse(url).map_err(|_| Error::InvalidInput("not a valid URL".into()))?;
    if parsed.origin().ascii_serialization() != origin
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(denied());
    }
    Ok(parsed)
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    version: u32,
    origin: Option<String>,
}

/// JSON config file in the app config directory. Only the canonical origin
/// is stored; nothing secret.
pub struct ConfigStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl ConfigStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The configured origin; `None` if unset, unreadable or invalid (the
    /// app then asks the user for the server address again).
    pub fn origin(&self) -> Option<String> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        self.read_unlocked()
    }

    fn read_unlocked(&self) -> Option<String> {
        let f = fs::File::open(&self.path).ok()?;
        let mut text = String::new();
        f.take(MAX_CONFIG_FILE).read_to_string(&mut text).ok()?;
        let cfg: ConfigFile = serde_json::from_str(&text).ok()?;
        let stored = cfg.origin?;
        // Only trust a value that is still valid and canonical.
        (normalize_origin(&stored).ok()? == stored).then_some(stored)
    }

    /// Store `origin` (already canonical). Returns the previous origin.
    pub fn store(&self, origin: &str) -> Result<Option<String>, Error> {
        debug_assert_eq!(normalize_origin(origin).as_deref(), Ok(origin));
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let previous = self.read_unlocked();
        let json = serde_json::to_vec_pretty(&ConfigFile {
            version: 1,
            origin: Some(origin.to_owned()),
        })
        .map_err(|_| Error::Io("could not encode config".into()))?;
        write_atomic(&self.path, &json).map_err(|e| Error::Io(format!("could not save ({})", e.kind())))?;
        Ok(previous)
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use std::path::PathBuf;

    /// A config path inside a fresh, unique temp directory.
    pub(crate) fn temp_config_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hr-client-test-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        dir.join("config.json")
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::temp_config_path;
    use super::*;

    #[test]
    fn accepts_and_canonicalises_origins() {
        let ok = [
            ("https://heartfulness-remote.dedyn.io", "https://heartfulness-remote.dedyn.io"),
            ("https://heartfulness-remote.dedyn.io/", "https://heartfulness-remote.dedyn.io"),
            ("HTTPS://Heartfulness-Remote.DEDYN.io", "https://heartfulness-remote.dedyn.io"),
            ("https://example.com:443", "https://example.com"),
            ("https://example.com:8443", "https://example.com:8443"),
            ("https://192.168.1.10:8443/", "https://192.168.1.10:8443"),
            ("https://bücher.example", "https://xn--bcher-kva.example"),
            ("http://localhost:8080", "http://localhost:8080"),
            ("http://localhost", "http://localhost"),
            ("http://127.0.0.1:8443/", "http://127.0.0.1:8443"),
        ];
        for (input, want) in ok {
            assert_eq!(normalize_origin(input).as_deref(), Ok(want), "{input}");
        }
    }

    #[test]
    fn rejects_bad_origins() {
        let bad = [
            "",
            "heartfulness-remote.dedyn.io",
            "https://",
            "https:///",
            "https://example.com/path",
            "https://example.com//",
            "https://example.com/?",
            "https://example.com?x=1",
            "https://example.com#frag",
            "https://example.com/#",
            "https://user:pw@example.com",
            "https://user@example.com",
            "https://example.com\\",
            "https://exa mple.com",
            " https://example.com",
            "https://example.com\n",
            "https://exam\tple.com",
            "http://example.com",
            "http://192.168.1.10",
            "http://127.0.0.2",
            "http://[::1]:8080",
            "http://localhost.evil.com",
            "ws://example.com",
            "wss://example.com",
            "file:///etc/passwd",
            "javascript://example.com",
            "tauri://localhost",
            "ftp://example.com",
        ];
        for input in bad {
            assert!(matches!(normalize_origin(input), Err(Error::InvalidInput(_))), "{input:?}");
        }
        assert!(normalize_origin(&format!("https://{}.com", "a".repeat(2050))).is_err());
    }

    #[test]
    fn open_url_policy() {
        let o = "https://heartfulness-remote.dedyn.io";
        let ok = [
            "https://heartfulness-remote.dedyn.io/",
            "https://heartfulness-remote.dedyn.io/link?code=ABCD-EFGH",
            "https://heartfulness-remote.dedyn.io/#link=ABCD-EFGH",
        ];
        for u in ok {
            assert_eq!(check_open_url(u, o).unwrap().as_str(), u);
        }
        let denied = [
            "https://heartfulness-remote.dedyn.io",                 // no slash
            "https://heartfulness-remote.dedyn.io.evil.com/",       // suffix trick
            "https://heartfulness-remote.dedyn.io@evil.com/",       // userinfo trick
            "https://heartfulness-remote.dedyn.io:444/",            // other port
            "http://heartfulness-remote.dedyn.io/",                 // downgrade
            "https://evil.com/?https://heartfulness-remote.dedyn.io/",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ];
        for u in denied {
            assert!(matches!(check_open_url(u, o), Err(Error::NotAllowed(_))), "{u}");
        }
        for u in [
            "https://heartfulness-remote.dedyn.io/a b",
            "https://heartfulness-remote.dedyn.io/\\evil.com",
            "https://heartfulness-remote.dedyn.io/\r\n",
        ] {
            assert!(matches!(check_open_url(u, o), Err(Error::InvalidInput(_))), "{u:?}");
        }
        assert!(check_open_url(&format!("{o}/{}", "a".repeat(9000)), o).is_err());
    }

    #[test]
    fn config_round_trip_and_corruption() {
        let path = temp_config_path("cfg");
        let c = ConfigStore::new(path.clone());
        assert_eq!(c.origin(), None);
        assert_eq!(c.store("https://a.example").unwrap(), None);
        assert_eq!(c.origin().as_deref(), Some("https://a.example"));
        assert_eq!(c.store("https://b.example").unwrap().as_deref(), Some("https://a.example"));
        assert_eq!(ConfigStore::new(path.clone()).origin().as_deref(), Some("https://b.example"));
        assert!(!path.with_extension("json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Tampered / invalid content is ignored, not trusted.
        fs::write(&path, br#"{"version":1,"origin":"http://evil.example"}"#).unwrap();
        assert_eq!(c.origin(), None);
        fs::write(&path, br#"{"version":1,"origin":"https://A.example/"}"#).unwrap();
        assert_eq!(c.origin(), None);
        fs::write(&path, b"not json").unwrap();
        assert_eq!(c.origin(), None);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
