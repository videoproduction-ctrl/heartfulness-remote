//! One method per Tauri command, so the app glue stays trivial and the
//! cross-cutting rules are unit-tested here.

use std::path::PathBuf;

use url::Url;

use crate::config::{check_open_url, normalize_origin, ConfigStore};
use crate::device_key::DeviceKey;
use crate::store::SecretStore;
use crate::token::TokenStore;
use crate::Error;

pub struct Client<S: SecretStore + Clone> {
    keys: DeviceKey<S>,
    tokens: TokenStore<S>,
    config: ConfigStore,
}

impl<S: SecretStore + Clone> Client<S> {
    pub fn new(store: S, config_path: PathBuf) -> Self {
        Self {
            keys: DeviceKey::new(store.clone()),
            tokens: TokenStore::new(store),
            config: ConfigStore::new(config_path),
        }
    }

    pub fn device_key_public(&self) -> Result<String, Error> {
        self.keys.public_key_b64()
    }

    pub fn device_key_sign(&self, data: &str) -> Result<String, Error> {
        self.keys.sign_b64(data)
    }

    pub fn token_get(&self) -> Result<Option<String>, Error> {
        self.tokens.get()
    }

    pub fn token_set(&self, token: &str) -> Result<(), Error> {
        self.tokens.set(token)
    }

    pub fn token_clear(&self) -> Result<(), Error> {
        self.tokens.clear()
    }

    pub fn config_get(&self) -> Option<String> {
        self.config.origin()
    }

    /// Validates and stores the origin; returns the canonical form.
    ///
    /// A session token belongs to one server: when the origin changes, the
    /// stored token is deleted *before* the new origin is saved, so it can
    /// never be sent to a different server.
    pub fn config_set(&self, origin: &str) -> Result<String, Error> {
        let origin = normalize_origin(origin)?;
        if self.config.origin().as_deref() != Some(origin.as_str()) {
            self.tokens.clear()?;
        }
        self.config.store(&origin)?;
        Ok(origin)
    }

    /// Returns the URL to hand to the system browser, or why it is refused.
    pub fn open_url_target(&self, url: &str) -> Result<Url, Error> {
        let origin = self.config.origin().ok_or(Error::NotConfigured)?;
        check_open_url(url, &origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::MemoryStore;
    use crate::token::TOKEN_ACCOUNT;
    use std::sync::Arc;

    fn client(tag: &str) -> (Client<Arc<MemoryStore>>, Arc<MemoryStore>, PathBuf) {
        let store = Arc::new(MemoryStore::default());
        let path = crate::config::tests_support::temp_config_path(tag);
        (Client::new(store.clone(), path.clone()), store, path)
    }

    #[test]
    fn origin_change_clears_token() {
        let (c, store, path) = client("origin-change");
        assert_eq!(c.config_get(), None);
        assert_eq!(c.config_set("https://A.example/").unwrap(), "https://a.example");
        c.token_set("tok-1").unwrap();
        // Same origin (any spelling): token kept.
        c.config_set("https://a.example").unwrap();
        assert_eq!(c.token_get().unwrap().as_deref(), Some("tok-1"));
        // Different origin: token gone.
        c.config_set("https://b.example").unwrap();
        assert_eq!(c.token_get().unwrap(), None);
        assert!(store.raw(TOKEN_ACCOUNT).is_none());
        assert_eq!(c.config_get().as_deref(), Some("https://b.example"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn origin_not_switched_if_token_cannot_be_cleared() {
        let (c, store, path) = client("clear-fail");
        c.config_set("https://a.example").unwrap();
        c.token_set("tok").unwrap();
        store.fail_writes.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(c.config_set("https://b.example").is_err());
        assert_eq!(c.config_get().as_deref(), Some("https://a.example"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn invalid_origin_leaves_state_untouched() {
        let (c, _store, path) = client("invalid");
        c.config_set("https://a.example").unwrap();
        c.token_set("tok").unwrap();
        assert!(c.config_set("http://evil.example").is_err());
        assert_eq!(c.config_get().as_deref(), Some("https://a.example"));
        assert_eq!(c.token_get().unwrap().as_deref(), Some("tok"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn open_url_requires_configured_origin() {
        let (c, _store, path) = client("open");
        assert_eq!(c.open_url_target("https://a.example/x"), Err(Error::NotConfigured));
        c.config_set("https://a.example").unwrap();
        assert_eq!(c.open_url_target("https://a.example/x").unwrap().as_str(), "https://a.example/x");
        assert!(matches!(c.open_url_target("https://b.example/x"), Err(Error::NotAllowed(_))));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn device_key_and_token_are_independent() {
        let (c, _store, _path) = client("indep");
        let pk = c.device_key_public().unwrap();
        c.token_set("abc").unwrap();
        c.token_clear().unwrap();
        assert_eq!(c.device_key_public().unwrap(), pk);
    }
}
