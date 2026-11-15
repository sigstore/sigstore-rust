//! ECDSA P-521 verification against an OpenSSL-made signature.
#![cfg(feature = "aws-lc-rs")]

use sigstore_crypto::{
    verify_signature, verify_signature_prehashed, KeyAlgorithm, SigningScheme, VerificationKey,
};
use sigstore_types::{DerPublicKey, HashAlgorithm, SignatureBytes};

/// `openssl ecparam -name secp521r1 -genkey`, public half as SPKI DER.
const SPKI: &str = "30819b301006072a8648ce3d020106052b81040023038186000401a01a439de59ace2ac65d33\
bbd770c53374b566a323c41612074d7daeebc83fa0963c0709a0b6a701672ac896c879e5f0b858a5898ca2c8fc4a5ecd\
e1bdd36a675700a8d463cae6d3b2898a5fb21bc21eef3a142b54181806a6084d6a4f4ba7c1d128d01d6026f1104c864a\
3aa1cb3cebb7c1a8872663047ddfcd3b1d3bf6b481521675";
/// `openssl dgst -sha512 -sign` over [`MESSAGE`].
const SIGNATURE: &str = "308188024200d5c09bd6d695e056aaf90385b0b4260419ffe30d210396702c1d12a2b0f4\
12e3222ef3585c537c43299cc582c40c189608e84edf2c5821ec6caa366678183017500242013869790c1d56fdf2d91a\
76a60f16a174092a97eddfc4e6a606184d9f4d2369f24e4e716c795acc8020ddd87c60856020cff075980becf0e19c8b\
9a15b195a425bf";
const MESSAGE: &[u8] = b"sigstore-rust P-521 test";

fn key() -> DerPublicKey {
    DerPublicKey::new(hex::decode(SPKI).unwrap())
}

fn signature() -> SignatureBytes {
    SignatureBytes::new(hex::decode(SIGNATURE).unwrap())
}

#[test]
fn p521_key_is_detected() {
    assert_eq!(
        KeyAlgorithm::from_spki(&key()).unwrap(),
        KeyAlgorithm::EcdsaP521
    );
    let vk = VerificationKey::from_spki(&key()).unwrap();
    assert_eq!(vk.scheme(), SigningScheme::EcdsaP521Sha512);
    assert_eq!(
        KeyAlgorithm::EcdsaP521
            .resolve_signing_scheme(HashAlgorithm::Sha2512)
            .unwrap(),
        SigningScheme::EcdsaP521Sha512
    );
    assert!(KeyAlgorithm::EcdsaP521
        .resolve_signing_scheme(HashAlgorithm::Sha2256)
        .is_err());
}

#[test]
fn p521_openssl_signature_verifies() {
    let scheme = SigningScheme::EcdsaP521Sha512;
    VerificationKey::from_spki(&key())
        .unwrap()
        .verify(MESSAGE, &signature())
        .unwrap();
    verify_signature(&key(), MESSAGE, &signature(), scheme).unwrap();
    let digest = sigstore_crypto::sha512(MESSAGE);
    verify_signature_prehashed(&key(), digest.as_slice(), &signature(), scheme).unwrap();

    assert!(verify_signature(&key(), b"another message", &signature(), scheme).is_err());
}
