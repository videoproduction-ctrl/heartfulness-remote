//! Platform-independent logic of the Heartfulness Remote native client.
//!
//! Everything here is unit-testable without a GUI, a webview or an OS
//! keychain: secrets go through the [`store::SecretStore`] trait, which the
//! app implements with the OS credential store and the tests implement in
//! memory.

pub mod b64;
pub mod client;
pub mod config;
pub mod device_key;
pub mod error;
pub mod nav;
pub mod store;
pub mod token;

pub use error::Error;

/// Keychain / Credential Manager service name for every secret of the app.
pub const KEYCHAIN_SERVICE: &str = "org.heartfulness.remote.client";
