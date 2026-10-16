//! `SecretStore` backed by the OS credential store via the `keyring` crate:
//! macOS Keychain, Windows Credential Manager (Linux: kernel keyutils, for
//! local development builds only).

use hr_client_core::store::{Secret, SecretStore};
use hr_client_core::Error;
use keyring::Entry;
use zeroize::Zeroizing;

pub struct KeyringStore {
    service: &'static str,
}

impl KeyringStore {
    pub fn new(service: &'static str) -> Self {
        Self { service }
    }

    fn entry(&self, account: &str) -> Result<Entry, Error> {
        Entry::new(self.service, account).map_err(map_err)
    }
}

/// Map keyring errors to short messages. Never include payload bytes
/// (`BadEncoding` carries the raw secret) or credential listings.
fn map_err(e: keyring::Error) -> Error {
    use keyring::Error as K;
    let os_reason = |inner: &dyn std::error::Error| {
        let mut s = inner.to_string();
        s.truncate(200);
        s
    };
    Error::Store(match &e {
        K::NoStorageAccess(inner) => format!(
            "access to the credential store was denied or it is locked ({})",
            os_reason(inner.as_ref())
        ),
        K::PlatformFailure(inner) => {
            format!("the credential store failed ({})", os_reason(inner.as_ref()))
        }
        K::NoEntry => "entry not found".into(),
        K::BadEncoding(_) => "unexpected value encoding".into(),
        K::TooLong(..) => "value too long for the credential store".into(),
        K::Invalid(..) => "invalid credential attributes".into(),
        K::Ambiguous(_) => "more than one matching credential exists".into(),
        _ => "credential store error".into(),
    })
}

impl SecretStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<Secret>, Error> {
        match self.entry(account)?.get_secret() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), Error> {
        self.entry(account)?.set_secret(secret).map_err(map_err)
    }

    fn delete(&self, account: &str) -> Result<(), Error> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}
