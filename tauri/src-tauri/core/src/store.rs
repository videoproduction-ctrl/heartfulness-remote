//! Abstraction over the OS credential store (macOS Keychain, Windows
//! Credential Manager). The app implements it with the `keyring` crate; tests
//! use the in-memory implementation below.

use zeroize::Zeroizing;

use crate::Error;

/// A secret read from the store; wiped from memory when dropped.
pub type Secret = Zeroizing<Vec<u8>>;

pub trait SecretStore: Send + Sync {
    /// Returns `Ok(None)` only when the entry definitely does not exist.
    /// Any other failure (locked keychain, access denied, …) is an `Err`, so
    /// callers never mistake "unreadable" for "absent".
    fn get(&self, account: &str) -> Result<Option<Secret>, Error>;
    /// Creates or replaces the entry.
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), Error>;
    /// Removes the entry; succeeds if it does not exist.
    fn delete(&self, account: &str) -> Result<(), Error>;
}

impl<T: SecretStore + ?Sized> SecretStore for std::sync::Arc<T> {
    fn get(&self, account: &str) -> Result<Option<Secret>, Error> {
        (**self).get(account)
    }
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), Error> {
        (**self).set(account, secret)
    }
    fn delete(&self, account: &str) -> Result<(), Error> {
        (**self).delete(account)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// In-memory store for tests. Values are zeroized when replaced/dropped.
    #[derive(Default)]
    pub struct MemoryStore {
        map: Mutex<HashMap<String, Secret>>,
        pub fail_reads: AtomicBool,
        pub fail_writes: AtomicBool,
        /// When set, `set` reports success but stores nothing (simulates a
        /// store that silently drops writes).
        pub drop_writes: AtomicBool,
        pub writes: AtomicUsize,
    }

    impl MemoryStore {
        pub fn raw(&self, account: &str) -> Option<Vec<u8>> {
            self.map.lock().unwrap().get(account).map(|s| s.to_vec())
        }
        pub fn put_raw(&self, account: &str, v: &[u8]) {
            self.map
                .lock()
                .unwrap()
                .insert(account.to_owned(), Zeroizing::new(v.to_vec()));
        }
    }

    impl SecretStore for MemoryStore {
        fn get(&self, account: &str) -> Result<Option<Secret>, Error> {
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err(Error::Store("access denied".into()));
            }
            Ok(self
                .map
                .lock()
                .unwrap()
                .get(account)
                .map(|s| Zeroizing::new(s.to_vec())))
        }
        fn set(&self, account: &str, secret: &[u8]) -> Result<(), Error> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(Error::Store("access denied".into()));
            }
            self.writes.fetch_add(1, Ordering::SeqCst);
            if !self.drop_writes.load(Ordering::SeqCst) {
                self.put_raw(account, secret);
            }
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), Error> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(Error::Store("access denied".into()));
            }
            self.map.lock().unwrap().remove(account);
            Ok(())
        }
    }
}
