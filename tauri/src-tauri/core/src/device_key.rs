//! The device's Ed25519 identity key `D` (docs/PROTOCOL.md §2).
//!
//! * The 32-byte seed lives only in the OS credential store. It is loaded for
//!   each signature and wiped from memory right after (`Zeroizing`, and
//!   `SigningKey` zeroizes itself on drop).
//! * A missing key is created on first use. An *unreadable* key (store error,
//!   wrong length) is never replaced, because that would silently change the
//!   device identity and orphan its approval.
//! * Only protocol transcripts (`TBS`, §3) with a device-signed label can be
//!   signed, so the key cannot be used as a general-purpose signing oracle.

use std::sync::{Mutex, MutexGuard};

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::store::SecretStore;
use crate::{b64, Error};

/// Credential-store account holding the device seed.
pub const SEED_ACCOUNT: &str = "device-ed25519-seed-v1";

/// Largest transcript accepted for signing (offers carry only SDP hashes, so
/// real transcripts are a few hundred bytes).
pub const MAX_SIGN_INPUT: usize = 64 * 1024;

/// Transcript labels the *device* key signs (docs/PROTOCOL.md §3). Labels
/// signed by the host (`HR1/host-auth`, `HR1/cert`, …) are refused.
pub const DEVICE_LABELS: &[&str] = &[
    "HR1/client-auth",
    "HR1/pair-approve",
    "HR1/revoke-request",
    "HR1/kill-request",
    "HR1/offer",
];

pub struct DeviceKey<S: SecretStore> {
    store: S,
    /// Serialises load-or-create so two concurrent first calls cannot each
    /// create (and overwrite) a key.
    lock: Mutex<()>,
    /// Public key cache (not secret).
    public: Mutex<Option<[u8; 32]>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl<S: SecretStore> DeviceKey<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            lock: Mutex::new(()),
            public: Mutex::new(None),
        }
    }

    /// `device_key_public`: base64url (no padding) of the raw 32-byte public
    /// key. Creates the key on first use.
    pub fn public_key_b64(&self) -> Result<String, Error> {
        if let Some(pk) = *lock(&self.public) {
            return Ok(b64::encode(&pk));
        }
        let sk = self.load_or_create()?;
        Ok(b64::encode(sk.verifying_key().as_bytes()))
    }

    /// `device_key_sign`: `data_b64` is the base64url transcript; returns the
    /// base64url 64-byte Ed25519 signature.
    pub fn sign_b64(&self, data_b64: &str) -> Result<String, Error> {
        // 4 base64 chars per 3 bytes (+ possible padding).
        if data_b64.len() > MAX_SIGN_INPUT.div_ceil(3) * 4 {
            return Err(Error::InvalidInput("data too large".into()));
        }
        let data = b64::decode(data_b64, "data")?;
        check_transcript(&data)?;
        let sk = self.load_or_create()?;
        Ok(b64::encode(&sk.sign(&data).to_bytes()))
    }

    fn load_or_create(&self) -> Result<SigningKey, Error> {
        let _guard = lock(&self.lock);
        let sk = match self.store.get(SEED_ACCOUNT)? {
            Some(stored) => signing_key_from(&stored)?,
            None => self.create()?,
        };
        *lock(&self.public) = Some(sk.verifying_key().to_bytes());
        Ok(sk)
    }

    fn create(&self) -> Result<SigningKey, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(&mut seed[..]).map_err(|_| Error::Rng)?;
        self.store.set(SEED_ACCOUNT, &seed[..])?;
        // Read back: never hand out a key that the store did not persist,
        // or the device would get a new identity on the next launch.
        match self.store.get(SEED_ACCOUNT)? {
            Some(back) if back.as_slice() == &seed[..] => Ok(SigningKey::from_bytes(&seed)),
            _ => Err(Error::Store("the device key could not be saved".into())),
        }
    }
}

fn signing_key_from(stored: &[u8]) -> Result<SigningKey, Error> {
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(stored.try_into().map_err(|_| Error::CorruptKey)?);
    Ok(SigningKey::from_bytes(&seed))
}

/// Accept only a well-formed TBS transcript (docs/PROTOCOL.md §3):
/// `label || 0x00 || (u32be(len) || field)*` with an allowed device label.
pub fn check_transcript(data: &[u8]) -> Result<(), Error> {
    let not_tbs = || Error::NotAllowed("data is not a protocol transcript".into());
    let nul = data.iter().position(|&b| b == 0).ok_or_else(not_tbs)?;
    let label = std::str::from_utf8(&data[..nul]).map_err(|_| not_tbs())?;
    if !DEVICE_LABELS.contains(&label) {
        return Err(if label.len() <= 64 && label.starts_with("HR1/") {
            Error::NotAllowed(format!("label {label} is not signed by the device key"))
        } else {
            not_tbs()
        });
    }
    let mut rest = &data[nul + 1..];
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<4>().ok_or_else(not_tbs)?;
        let len = u32::from_be_bytes(*len) as usize;
        if tail.len() < len {
            return Err(not_tbs());
        }
        rest = &tail[len..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::MemoryStore;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    fn tbs(label: &str, fields: &[&[u8]]) -> Vec<u8> {
        let mut v = label.as_bytes().to_vec();
        v.push(0);
        for f in fields {
            v.extend_from_slice(&(f.len() as u32).to_be_bytes());
            v.extend_from_slice(f);
        }
        v
    }

    fn vectors() -> serde_json::Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../testdata/vectors.json");
        let text = std::fs::read_to_string(path).expect("testdata/vectors.json");
        serde_json::from_str(&text).unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn creates_key_once_and_persists_it() {
        let store = Arc::new(MemoryStore::default());
        let k = DeviceKey::new(store.clone());
        let p1 = k.public_key_b64().unwrap();
        assert_eq!(b64::decode(&p1, "p").unwrap().len(), 32);
        assert_eq!(store.raw(SEED_ACCOUNT).unwrap().len(), 32);
        assert_eq!(k.public_key_b64().unwrap(), p1);
        // A fresh instance (app restart) loads the same key.
        let k2 = DeviceKey::new(store.clone());
        assert_eq!(k2.public_key_b64().unwrap(), p1);
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn signature_verifies_with_public_key() {
        let store = Arc::new(MemoryStore::default());
        let k = DeviceKey::new(store);
        let msg = tbs("HR1/client-auth", &[b"https://remote.example.test", &[7u8; 32]]);
        let sig = b64::decode(&k.sign_b64(&b64::encode(&msg)).unwrap(), "s").unwrap();
        assert_eq!(sig.len(), 64);
        let pk: [u8; 32] = b64::decode(&k.public_key_b64().unwrap(), "p")
            .unwrap()
            .try_into()
            .unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        vk.verify(&msg, &Signature::from_slice(&sig).unwrap()).unwrap();
    }

    #[test]
    fn matches_cross_language_vectors() {
        let v = vectors();
        let store = Arc::new(MemoryStore::default());
        store.put_raw(SEED_ACCOUNT, &hex(v["deviceSeedHex"].as_str().unwrap()));
        let k = DeviceKey::new(store);
        assert_eq!(k.public_key_b64().unwrap(), v["devicePub"].as_str().unwrap());
        let mut device_vectors = 0;
        for t in v["tbs"].as_array().unwrap() {
            let data = b64::encode(&hex(t["tbsHex"].as_str().unwrap()));
            let label = t["label"].as_str().unwrap();
            if t["signer"] == "device" {
                assert!(DEVICE_LABELS.contains(&label), "{label}");
                assert_eq!(k.sign_b64(&data).unwrap(), t["sig"].as_str().unwrap(), "{label}");
                device_vectors += 1;
            } else {
                assert!(
                    matches!(k.sign_b64(&data), Err(Error::NotAllowed(_))),
                    "host label {label} must be refused"
                );
            }
        }
        assert_eq!(device_vectors, DEVICE_LABELS.len());
    }

    #[test]
    fn store_read_failure_never_creates_a_new_key() {
        let store = Arc::new(MemoryStore::default());
        store.fail_reads.store(true, Ordering::SeqCst);
        let k = DeviceKey::new(store.clone());
        assert!(matches!(k.public_key_b64(), Err(Error::Store(_))));
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn corrupt_key_is_reported_not_replaced() {
        let store = Arc::new(MemoryStore::default());
        store.put_raw(SEED_ACCOUNT, &[1u8; 31]);
        let k = DeviceKey::new(store.clone());
        assert_eq!(k.public_key_b64(), Err(Error::CorruptKey));
        assert_eq!(store.raw(SEED_ACCOUNT).unwrap(), vec![1u8; 31]);
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unpersisted_key_is_not_used() {
        let store = Arc::new(MemoryStore::default());
        store.drop_writes.store(true, Ordering::SeqCst);
        let k = DeviceKey::new(store.clone());
        assert!(matches!(k.public_key_b64(), Err(Error::Store(_))));
        store.fail_writes.store(true, Ordering::SeqCst);
        store.drop_writes.store(false, Ordering::SeqCst);
        assert!(matches!(k.public_key_b64(), Err(Error::Store(_))));
    }

    #[test]
    fn concurrent_first_use_creates_exactly_one_key() {
        let store = Arc::new(MemoryStore::default());
        let k = Arc::new(DeviceKey::new(store.clone()));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let k = k.clone();
                std::thread::spawn(move || k.public_key_b64().unwrap())
            })
            .collect();
        let keys: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(keys.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn refuses_non_transcripts() {
        let k = DeviceKey::new(Arc::new(MemoryStore::default()));
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"hello world".to_vec(),
            b"HR1/client-auth".to_vec(),                          // no separator
            tbs("HR1/host-auth", &[b"o", b"n"]),                  // host label
            tbs("HR1/cert", &[b"a"]),                             // host label
            tbs("SSH-2.0", &[b"x"]),                              // foreign
            [tbs("HR1/offer", &[b"abc"]), vec![0, 0, 0]].concat(), // trailing garbage
            {
                let mut v = tbs("HR1/offer", &[]);
                v.extend_from_slice(&10u32.to_be_bytes());
                v.extend_from_slice(b"short"); // length overruns
                v
            },
        ];
        for c in cases {
            assert!(
                matches!(k.sign_b64(&b64::encode(&c)), Err(Error::NotAllowed(_))),
                "{c:?}"
            );
        }
        assert!(matches!(k.sign_b64("***"), Err(Error::InvalidInput(_))));
        let huge = "A".repeat(MAX_SIGN_INPUT / 3 * 4 + 8);
        assert!(matches!(k.sign_b64(&huge), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn errors_never_contain_the_seed() {
        let store = Arc::new(MemoryStore::default());
        let k = DeviceKey::new(store.clone());
        k.public_key_b64().unwrap();
        let seed = store.raw(SEED_ACCOUNT).unwrap();
        let err = k.sign_b64(&b64::encode(b"nope")).unwrap_err().to_string();
        assert!(!err.contains(&b64::encode(&seed)));
        assert!(!format!("{:?}", Error::CorruptKey).is_empty());
    }
}
