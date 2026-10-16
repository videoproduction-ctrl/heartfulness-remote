use std::fmt;

/// Errors surfaced to the web client (as the rejection message of `invoke`).
///
/// Messages are short, stable and never contain secret material (no seeds,
/// tokens, or raw keystore payloads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The OS credential store failed or refused access. The string is a
    /// short, non-secret reason.
    Store(String),
    /// The stored device key is unreadable (wrong length). It is never
    /// silently replaced, because that would change the device identity.
    CorruptKey,
    /// The OS random number generator failed.
    Rng,
    /// Caller supplied a malformed argument.
    InvalidInput(String),
    /// The request is well-formed but not permitted by policy.
    NotAllowed(String),
    /// No server origin has been configured yet.
    NotConfigured,
    /// Reading or writing the config file failed.
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Store(m) => write!(f, "keystore: {m}"),
            Error::CorruptKey => f.write_str(
                "keystore: the stored device key is corrupt; remove the \
                 'org.heartfulness.remote.client' keychain item to reset this device",
            ),
            Error::Rng => f.write_str("random number generator failure"),
            Error::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Error::NotAllowed(m) => write!(f, "not allowed: {m}"),
            Error::NotConfigured => f.write_str("no server configured"),
            Error::Io(m) => write!(f, "config: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}
