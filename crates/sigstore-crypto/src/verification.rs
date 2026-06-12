//! Signature verification using aws-lc-rs

use crate::error::{Error, Result};
use crate::signing::SigningScheme;
use aws_lc_rs::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1, ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
};
use sigstore_types::{DerPublicKey, SignatureBytes};
use spki::SubjectPublicKeyInfoRef;

/// A public key for verification
pub struct VerificationKey {
    /// Raw public key bytes (format depends on scheme)
    bytes: Vec<u8>,
    /// The scheme to use for verification
    scheme: SigningScheme,
}

impl VerificationKey {
    /// Create a verification key from a DER-encoded SPKI public key
    ///
    /// This parses the SubjectPublicKeyInfo structure and extracts the raw
    /// public key bytes needed for verification.
    pub fn from_spki(key: &DerPublicKey, scheme: SigningScheme) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::try_from(key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SPKI: {e}")))?;

        // Extract raw public key bytes from the BIT STRING
        let raw_bytes = spki.subject_public_key.raw_bytes().to_vec();

        Ok(Self {
            bytes: raw_bytes,
            scheme,
        })
    }

    /// Get the raw public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signing scheme
    pub fn scheme(&self) -> SigningScheme {
        self.scheme
    }

    /// Verify a signature over data
    pub fn verify(&self, data: impl AsRef<[u8]>, signature: &SignatureBytes) -> Result<()> {
        self.verify_inner(data.as_ref(), signature.as_bytes())
    }

    fn verify_inner(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        match self.scheme {
            SigningScheme::EcdsaP256Sha256 => {
                let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-256 SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::EcdsaP256Sha384 => {
                let key = UnparsedPublicKey::new(&ECDSA_P256_SHA384_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-256 SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::EcdsaP384Sha256 => {
                let key = UnparsedPublicKey::new(&ECDSA_P384_SHA256_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-384 SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::EcdsaP384Sha384 => {
                let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("ECDSA P-384 SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::Ed25519 => {
                let key = UnparsedPublicKey::new(&ED25519, &self.bytes);
                key.verify(data, signature)
                    .map_err(|_| Error::Verification("Ed25519 signature invalid".to_string()))
            }
            SigningScheme::RsaPssSha256 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPssSha384 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPssSha512 => {
                let key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PSS SHA-512 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha256 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-256 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha384 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-384 signature invalid".to_string())
                })
            }
            SigningScheme::RsaPkcs1Sha512 => {
                let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &self.bytes);
                key.verify(data, signature).map_err(|_| {
                    Error::Verification("RSA PKCS#1 SHA-512 signature invalid".to_string())
                })
            }
        }
    }

    /// Verify a signature over prehashed data
    ///
    /// This is used for hashedrekord verification where the signature is over
    /// a pre-computed hash of the artifact, not the artifact itself.
    pub fn verify_prehashed(&self, digest: &[u8], signature: &SignatureBytes) -> Result<()> {
        use aws_lc_rs::digest::{Digest, SHA256, SHA384, SHA512};
        use aws_lc_rs::signature::VerificationAlgorithm;

        // Determine the expected hash algorithm and ASN.1 algorithm from the SigningScheme
        let (aws_algo, asn1_algo): (
            &aws_lc_rs::digest::Algorithm,
            &'static dyn VerificationAlgorithm,
        ) = match self.scheme {
            SigningScheme::EcdsaP256Sha256 => (&SHA256, &ECDSA_P256_SHA256_ASN1),
            SigningScheme::EcdsaP256Sha384 => (&SHA384, &ECDSA_P256_SHA384_ASN1),
            SigningScheme::EcdsaP384Sha256 => (&SHA256, &ECDSA_P384_SHA256_ASN1),
            SigningScheme::EcdsaP384Sha384 => (&SHA384, &ECDSA_P384_SHA384_ASN1),
            SigningScheme::RsaPssSha256 => (&SHA256, &RSA_PSS_2048_8192_SHA256),
            SigningScheme::RsaPssSha384 => (&SHA384, &RSA_PSS_2048_8192_SHA384),
            SigningScheme::RsaPssSha512 => (&SHA512, &RSA_PSS_2048_8192_SHA512),
            SigningScheme::RsaPkcs1Sha256 => (&SHA256, &RSA_PKCS1_2048_8192_SHA256),
            SigningScheme::RsaPkcs1Sha384 => (&SHA384, &RSA_PKCS1_2048_8192_SHA384),
            SigningScheme::RsaPkcs1Sha512 => (&SHA512, &RSA_PKCS1_2048_8192_SHA512),
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Scheme {:?} does not support prehashed mode",
                    self.scheme
                )));
            }
        };

        let aws_digest = Digest::import_less_safe(digest, aws_algo).map_err(|_| {
            Error::Verification(format!(
                "Failed to import digest: len={}, algo_expected_len={}",
                digest.len(),
                aws_algo.output_len
            ))
        })?;

        let key = UnparsedPublicKey::new(asn1_algo, &self.bytes);
        key.verify_digest(&aws_digest, signature.as_bytes())
            .map_err(|e| Error::Verification(format!("Signature invalid: {}", e)))
    }
}

/// Verify a signature using the specified scheme
///
/// This is a convenience function that creates a temporary `VerificationKey`.
/// For repeated verifications with the same key, prefer using `VerificationKey` directly.
///
/// # Arguments
/// * `public_key` - DER-encoded SPKI public key
/// * `data` - Data that was signed
/// * `signature` - The signature to verify
/// * `scheme` - The signing scheme used
pub fn verify_signature(
    public_key: &DerPublicKey,
    data: &[u8],
    signature: &SignatureBytes,
    scheme: SigningScheme,
) -> Result<()> {
    VerificationKey::from_spki(public_key, scheme)?.verify(data, signature)
}

/// Verify a signature over prehashed data using the specified scheme
///
/// This is used for hashedrekord verification where the signature is over
/// a pre-computed hash of the artifact, not the artifact itself.
///
/// # Arguments
/// * `public_key` - DER-encoded SPKI public key
/// * `digest` - Pre-computed hash of the artifact
/// * `signature` - The signature to verify
/// * `scheme` - The signing scheme used
pub fn verify_signature_prehashed(
    public_key: &DerPublicKey,
    digest: &[u8],
    signature: &SignatureBytes,
    scheme: SigningScheme,
) -> Result<()> {
    VerificationKey::from_spki(public_key, scheme)?.verify_prehashed(digest, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyPair;

    #[test]
    fn test_verify_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify(data, &sig).is_ok());
    }

    #[test]
    fn test_verify_bad_signature() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data";
        let bad_sig = SignatureBytes::new(vec![0u8; 64]);

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify(data, &bad_sig).is_err());
    }

    #[test]
    fn test_verify_wrong_data() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify(b"wrong data", &sig).is_err());
    }

    #[test]
    fn test_verify_prehashed_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data to prehash";
        let sig = kp.sign(data).unwrap();
        let digest = crate::hash::sha256(data);

        let pubkey = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pubkey, kp.default_scheme()).unwrap();
        assert!(vk.verify_prehashed(digest.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn test_verify_prehashed_unsupported() {
        // Construct a VerificationKey directly with Ed25519 which doesn't support prehashed
        let vk = VerificationKey {
            bytes: vec![0u8; 32],
            scheme: SigningScheme::Ed25519,
        };
        let dummy_digest = vec![0u8; 32];
        let dummy_sig = SignatureBytes::new(vec![0u8; 64]);

        let result = vk.verify_prehashed(&dummy_digest, &dummy_sig);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::UnsupportedAlgorithm(_)
        ));
    }

    /// A standard P-384/SHA-384 signature verifies via `EcdsaP384Sha384` (raw and
    /// prehashed), while the mismatched `EcdsaP384Sha256` scheme fails closed.
    #[test]
    fn test_verify_p384_sha384_roundtrip_and_mismatch_fails_closed() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{
            EcdsaKeyPair, KeyPair as AwsKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING,
        };

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref()).unwrap();

        let data = b"artifact signed with a P-384 key";
        let sig = SignatureBytes::new(kp.sign(&rng, data).unwrap().as_ref().to_vec());

        // Raw uncompressed point, as `from_spki` would extract from an SPKI key.
        let raw_pubkey = kp.public_key().as_ref().to_vec();

        // Standard pairing: verifies over raw artifact and SHA-384 prehash.
        let vk384 = VerificationKey {
            bytes: raw_pubkey.clone(),
            scheme: SigningScheme::EcdsaP384Sha384,
        };
        assert!(vk384.verify(data, &sig).is_ok());
        let sha384 = crate::hash::sha384(data);
        assert!(vk384.verify_prehashed(&sha384, &sig).is_ok());

        // Mismatched hash must fail closed.
        let vk256 = VerificationKey {
            bytes: raw_pubkey,
            scheme: SigningScheme::EcdsaP384Sha256,
        };
        let sha256 = crate::hash::sha256(data);
        assert!(vk256.verify(data, &sig).is_err());
        assert!(vk256.verify_prehashed(sha256.as_bytes(), &sig).is_err());
    }
}
