//! The crypto errors callers match on are typed.
#![cfg(feature = "aws-lc-rs")]

use sigstore_crypto::{Error, KeyPair, Keyring, SigningScheme, VerificationKey};
use sigstore_types::{Sha256Hash, TimeRange};

fn key() -> (KeyPair, VerificationKey) {
    let pair = KeyPair::generate_ecdsa_p256().unwrap();
    let key = VerificationKey::from_spki(&pair.public_key_der().unwrap()).unwrap();
    (pair, key)
}

#[test]
fn bad_signature_and_digest_length_are_typed() {
    let (pair, key) = key();
    let signature = pair.sign(b"message").unwrap();
    assert!(matches!(
        key.verify(b"other message", &signature),
        Err(Error::SignatureInvalid {
            scheme: SigningScheme::EcdsaP256Sha256
        })
    ));
    assert!(matches!(
        key.verify_prehashed(&[0u8; 20], &signature),
        Err(Error::DigestLength {
            expected: 32,
            actual: 20,
            ..
        })
    ));
}

#[test]
fn keyring_lookups_are_typed() {
    let (pair, key) = key();
    let signature = pair.sign(b"message").unwrap();
    let id = Sha256Hash::new([1; 32]);
    let missing = Sha256Hash::new([2; 32]);
    let start = jiff::Timestamp::from_second(1_700_000_000).unwrap();
    let mut keyring = Keyring::new();
    keyring.add_key_with_validity(id, key, Some(TimeRange::new(start, None)));

    assert!(matches!(
        keyring.verify_with_key_id(&missing, b"message", &signature),
        Err(Error::KeyNotFound { key_id }) if key_id == missing
    ));
    let before = start - jiff::SignedDuration::from_secs(1);
    assert!(matches!(
        keyring.verify_with_key_id_at(&id, before, b"message", &signature),
        Err(Error::KeyNotValidAt { key_id, time }) if key_id == id && time == before
    ));
    assert!(matches!(
        keyring.verify_any(b"other message", &signature),
        Err(Error::NoKeyVerified)
    ));
}
