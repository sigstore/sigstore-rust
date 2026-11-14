//! Interop tests for cosign's encrypted private key format.
#![cfg(all(feature = "cosign-key", feature = "aws-lc-rs"))]

use sigstore_crypto::{cosign_key, Error, KeyPair, VerificationKey};
use sigstore_types::DerPublicKey;

const KEY: &str = include_str!("fixtures/cosign-key/cosign.key");
const PUB: &str = include_str!("fixtures/cosign-key/cosign.pub");
const PASSWORD: &[u8] = b"sigstore-rust-test";
const EMPTY_KEY: &str = include_str!("fixtures/cosign-key/empty/cosign.key");
const EMPTY_PUB: &str = include_str!("fixtures/cosign-key/empty/cosign.pub");

/// The decrypted key's public half is cosign's `.pub`, and its signatures
/// verify under that public key.
fn assert_matches_public_key(keypair: &KeyPair, public_pem: &str) {
    let expected = DerPublicKey::from_pem(public_pem).unwrap();
    assert_eq!(keypair.public_key_der().unwrap(), expected);

    let signature = keypair.sign(b"hello cosign").unwrap();
    VerificationKey::from_spki(&expected)
        .unwrap()
        .verify(b"hello cosign", &signature)
        .unwrap();
}

#[test]
fn decrypts_a_cosign_generated_key() {
    let keypair = KeyPair::from_cosign_encrypted_pem(KEY, PASSWORD).unwrap();
    assert_matches_public_key(&keypair, PUB);
}

#[test]
fn decrypts_a_cosign_generated_key_with_an_empty_password() {
    let keypair = KeyPair::from_cosign_encrypted_pem(EMPTY_KEY, b"").unwrap();
    assert_matches_public_key(&keypair, EMPTY_PUB);
}

#[test]
fn wrong_password_is_an_error() {
    for password in [b"wrong".as_slice(), b""] {
        let err = KeyPair::from_cosign_encrypted_pem(KEY, password).unwrap_err();
        assert!(matches!(err, Error::KeyDecryption(_)), "{err}");
    }
}

#[test]
fn round_trips_with_an_empty_password() {
    let keypair = KeyPair::from_cosign_encrypted_pem(KEY, PASSWORD).unwrap();
    let pkcs8 = cosign_key::decrypt_pem(KEY, PASSWORD).unwrap();

    let pem = cosign_key::encrypt_pkcs8_der(&pkcs8, b"").unwrap();
    assert!(pem.starts_with("-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----"));
    assert_eq!(*cosign_key::decrypt_pem(&pem, b"").unwrap(), *pkcs8);
    let reloaded = KeyPair::from_cosign_encrypted_pem(&pem, b"").unwrap();
    assert_eq!(
        reloaded.public_key_der().unwrap(),
        keypair.public_key_der().unwrap()
    );
    assert!(matches!(
        cosign_key::decrypt_pem(&pem, b"x"),
        Err(Error::KeyDecryption(_))
    ));
}

/// The ocx golden key (cosign-generated, N = 2^16). The fixture lives in an
/// ocx checkout, so this test is ignored; run it with `--ignored`.
#[test]
#[ignore = "needs the ocx golden fixtures in ~/Programs/ocx"]
fn decrypts_the_ocx_golden_key() {
    let dir = std::path::PathBuf::from(std::env::var("HOME").unwrap())
        .join("Programs/ocx/test/tests/fixtures/golden/keys");
    let key = std::fs::read_to_string(dir.join("cosign.key")).unwrap();
    let public = std::fs::read_to_string(dir.join("cosign.pub")).unwrap();
    let keypair = KeyPair::from_cosign_encrypted_pem(&key, b"ocxtest").unwrap();
    assert_matches_public_key(&keypair, &public);
    assert!(KeyPair::from_cosign_encrypted_pem(&key, b"wrong").is_err());
}
