//! Keyring for managing multiple verification keys
//!
//! A keyring holds multiple public keys and can verify signatures
//! against any of them.

use crate::error::{Error, Result};
use crate::verification::VerificationKey;
use jiff::Timestamp;
use sigstore_types::{KeyHint, Sha256Hash, SignatureBytes};
use std::collections::HashMap;

/// Optional validity window associated with a verification key.
///
/// The interval is closed and an absent end is unbounded, matching Sigstore's
/// `TimeRange` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyValidity {
    /// Inclusive start of the validity window.
    pub start: Timestamp,
    /// Inclusive end of the validity window, or no upper bound.
    pub end: Option<Timestamp>,
}

impl KeyValidity {
    /// Create a validity window.
    pub fn new(start: Timestamp, end: Option<Timestamp>) -> Self {
        Self { start, end }
    }

    /// Return whether `time` is within the closed validity window.
    pub fn contains(&self, time: Timestamp) -> bool {
        time >= self.start && self.end.map_or(true, |end| time <= end)
    }

    /// Return whether the validity window has started by `time`.
    pub fn has_started_by(&self, time: Timestamp) -> bool {
        time >= self.start
    }
}

struct KeyringEntry {
    key: VerificationKey,
    validity: Option<KeyValidity>,
}

/// A keyring containing multiple verification keys.
///
/// Keys are indexed by their SHA-256 key ID. A key may additionally carry a
/// validity window; callers can perform either an unrestricted historical
/// lookup or a lookup at a specific point in time.
#[derive(Default)]
pub struct Keyring {
    keys: HashMap<Sha256Hash, KeyringEntry>,
}

impl Keyring {
    /// Create a new empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key without a validity constraint.
    pub fn add_key(&mut self, key_id: Sha256Hash, key: VerificationKey) {
        self.add_key_with_validity(key_id, key, None);
    }

    /// Add a key with an optional validity constraint.
    pub fn add_key_with_validity(
        &mut self,
        key_id: Sha256Hash,
        key: VerificationKey,
        validity: Option<KeyValidity>,
    ) {
        self.keys.insert(key_id, KeyringEntry { key, validity });
    }

    /// Get a key by its full ID, without applying its validity window.
    pub fn get_key(&self, key_id: &Sha256Hash) -> Option<&VerificationKey> {
        self.keys.get(key_id).map(|entry| &entry.key)
    }

    /// Get a key by its full ID if it was valid at `time`.
    pub fn get_key_at(&self, key_id: &Sha256Hash, time: Timestamp) -> Option<&VerificationKey> {
        self.keys
            .get(key_id)
            .filter(|entry| {
                entry
                    .validity
                    .map_or(true, |validity| validity.contains(time))
            })
            .map(|entry| &entry.key)
    }

    /// Get a key by ID if its validity period has started by `time`.
    ///
    /// Unlike [`Self::get_key_at`], expired keys remain available for
    /// historical material whose exact production time is unavailable.
    pub fn get_key_started_by(
        &self,
        key_id: &Sha256Hash,
        time: Timestamp,
    ) -> Option<&VerificationKey> {
        self.keys
            .get(key_id)
            .filter(|entry| {
                entry
                    .validity
                    .map_or(true, |validity| validity.has_started_by(time))
            })
            .map(|entry| &entry.key)
    }

    /// Get all keys whose ID starts with the checkpoint's four-byte key hint.
    ///
    /// This returns all matches because hints are intentionally short and may
    /// collide. Keys whose validity period has not started by `time` are
    /// excluded, while expired keys remain available for historical material.
    pub fn keys_by_hint(
        &self,
        hint: &KeyHint,
        time: Timestamp,
    ) -> impl Iterator<Item = &VerificationKey> {
        let hint = *hint.as_bytes();
        self.keys.iter().filter_map(move |(id, entry)| {
            (id.as_bytes()[..4] == hint
                && entry
                    .validity
                    .map_or(true, |validity| validity.has_started_by(time)))
            .then_some(&entry.key)
        })
    }

    /// Verify a signature using a specific key ID.
    pub fn verify_with_key_id(
        &self,
        key_id: &Sha256Hash,
        data: impl AsRef<[u8]>,
        signature: &SignatureBytes,
    ) -> Result<()> {
        let key = self
            .get_key(key_id)
            .ok_or_else(|| Error::Verification(format!("key not found: {}", key_id.to_hex())))?;
        key.verify(data, signature)
    }

    /// Verify a signature using a key that was valid at `time`.
    pub fn verify_with_key_id_at(
        &self,
        key_id: &Sha256Hash,
        time: Timestamp,
        data: impl AsRef<[u8]>,
        signature: &SignatureBytes,
    ) -> Result<()> {
        let key = self.get_key_at(key_id, time).ok_or_else(|| {
            Error::Verification(format!(
                "key not found or not valid at {}: {}",
                time,
                key_id.to_hex()
            ))
        })?;
        key.verify(data, signature)
    }

    /// Try to verify a signature with any key in the keyring.
    ///
    /// Returns the key ID that successfully verified the signature.
    pub fn verify_any(
        &self,
        data: impl AsRef<[u8]>,
        signature: &SignatureBytes,
    ) -> Result<Sha256Hash> {
        let data = data.as_ref();
        for (key_id, entry) in &self.keys {
            if entry.key.verify(data, signature).is_ok() {
                return Ok(*key_id);
            }
        }
        Err(Error::Verification(
            "no key in keyring verified the signature".to_string(),
        ))
    }

    /// Get the number of keys in the keyring.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the keyring is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::signing::KeyPair;

    fn generated_key() -> (KeyPair, Sha256Hash, VerificationKey) {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let spki = kp.public_key_der().unwrap();
        let key_id = sha256(spki.as_bytes());
        let vk = VerificationKey::from_spki(&spki, kp.default_scheme()).unwrap();
        (kp, key_id, vk)
    }

    #[test]
    fn test_keyring_add_and_get() {
        let (_, key_id, vk) = generated_key();
        let mut keyring = Keyring::new();
        keyring.add_key(key_id, vk);
        assert_eq!(keyring.len(), 1);
        assert!(keyring.get_key(&key_id).is_some());
    }

    #[test]
    fn test_keyring_verify() {
        let (kp, key_id, vk) = generated_key();
        let mut keyring = Keyring::new();
        keyring.add_key(key_id, vk);
        let data = b"test data";
        let sig = kp.sign(data).unwrap();
        assert!(keyring.verify_with_key_id(&key_id, data, &sig).is_ok());
    }

    #[test]
    fn test_keyring_verify_any() {
        let mut keyring = Keyring::new();
        for _ in 0..3 {
            let (_, key_id, vk) = generated_key();
            keyring.add_key(key_id, vk);
        }
        let (kp, key_id, vk) = generated_key();
        keyring.add_key(key_id, vk);
        let data = b"test data";
        let sig = kp.sign(data).unwrap();
        assert_eq!(keyring.verify_any(data, &sig).unwrap(), key_id);
    }

    #[test]
    fn validity_and_hint_lookups() {
        let (_, key_id, vk) = generated_key();
        let hint = KeyHint::try_from_slice(&key_id.as_bytes()[..4]).unwrap();
        let start: Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
        let end: Timestamp = "2021-01-01T00:00:00Z".parse().unwrap();
        let mut keyring = Keyring::new();
        keyring.add_key_with_validity(key_id, vk, Some(KeyValidity::new(start, Some(end))));

        assert!(keyring.get_key_at(&key_id, start).is_some());
        assert!(keyring.get_key_at(&key_id, end).is_some());
        assert!(keyring
            .get_key_at(&key_id, "2022-01-01T00:00:00Z".parse().unwrap())
            .is_none());
        // Historical checkpoint lookup keeps an expired key once it has started.
        assert_eq!(
            keyring
                .keys_by_hint(&hint, "2022-01-01T00:00:00Z".parse().unwrap())
                .count(),
            1
        );
    }
}
