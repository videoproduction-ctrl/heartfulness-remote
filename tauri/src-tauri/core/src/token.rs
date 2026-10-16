//! Bearer session token (docs/PROTOCOL.md §2, §6), kept in the OS credential
//! store instead of a cookie.

use crate::store::SecretStore;
use crate::Error;

/// Credential-store account holding the session token.
pub const TOKEN_ACCOUNT: &str = "session-token-v1";

/// Upper bound on accepted token length (real tokens are 43 chars).
pub const MAX_TOKEN_LEN: usize = 1024;

/// RFC 6750 `b64token`: `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
/// Rejecting anything else keeps CR/LF and other header-breaking bytes out of
/// the `Authorization` header the web client builds from it.
pub fn validate_token(t: &str) -> Result<(), Error> {
    let bad = || Error::InvalidInput("token must be a non-empty base64url string".into());
    if t.is_empty() || t.len() > MAX_TOKEN_LEN {
        return Err(bad());
    }
    let body = t.trim_end_matches('=');
    if body.is_empty()
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
    {
        return Err(bad());
    }
    Ok(())
}

pub struct TokenStore<S: SecretStore> {
    store: S,
}

impl<S: SecretStore> TokenStore<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// `token_get`. A stored value that is not a valid token is removed and
    /// reported as absent (the user simply signs in again).
    pub fn get(&self) -> Result<Option<String>, Error> {
        let Some(raw) = self.store.get(TOKEN_ACCOUNT)? else {
            return Ok(None);
        };
        match std::str::from_utf8(&raw) {
            Ok(t) if validate_token(t).is_ok() => Ok(Some(t.to_owned())),
            _ => {
                self.store.delete(TOKEN_ACCOUNT)?;
                Ok(None)
            }
        }
    }

    /// `token_set`.
    pub fn set(&self, token: &str) -> Result<(), Error> {
        validate_token(token)?;
        self.store.set(TOKEN_ACCOUNT, token.as_bytes())
    }

    /// `token_clear`. Succeeds when no token is stored.
    pub fn clear(&self) -> Result<(), Error> {
        self.store.delete(TOKEN_ACCOUNT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::MemoryStore;
    use std::sync::Arc;

    const T: &str = "q1w2e3r4t5y6u7i8o9p0-_aSdFgHjKlZxCvBnMqWeRtY"; // 43+ chars

    #[test]
    fn set_get_clear() {
        let s = TokenStore::new(Arc::new(MemoryStore::default()));
        assert_eq!(s.get().unwrap(), None);
        s.set(T).unwrap();
        assert_eq!(s.get().unwrap().as_deref(), Some(T));
        s.clear().unwrap();
        assert_eq!(s.get().unwrap(), None);
        s.clear().unwrap(); // idempotent
    }

    #[test]
    fn rejects_malformed_tokens() {
        let s = TokenStore::new(Arc::new(MemoryStore::default()));
        for bad in ["", "=", "abc\r\nX-Evil: 1", "a b", "tök", "abc=def", &"a".repeat(1025)] {
            assert!(matches!(s.set(bad), Err(Error::InvalidInput(_))), "{bad:?}");
        }
        for good in ["abc", "abc==", "a.b~c+d/e_f-g"] {
            s.set(good).unwrap();
        }
    }

    #[test]
    fn corrupt_stored_token_is_dropped() {
        let store = Arc::new(MemoryStore::default());
        store.put_raw(TOKEN_ACCOUNT, b"bad\ntoken");
        let s = TokenStore::new(store.clone());
        assert_eq!(s.get().unwrap(), None);
        assert!(store.raw(TOKEN_ACCOUNT).is_none());
        store.put_raw(TOKEN_ACCOUNT, &[0xff, 0xfe]);
        assert_eq!(s.get().unwrap(), None);
    }

    #[test]
    fn store_errors_propagate() {
        let store = Arc::new(MemoryStore::default());
        store.fail_reads.store(true, std::sync::atomic::Ordering::SeqCst);
        let s = TokenStore::new(store);
        assert!(matches!(s.get(), Err(Error::Store(_))));
    }
}
