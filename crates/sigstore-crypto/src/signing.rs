//! Key generation and signing using aws-lc-rs

use crate::error::{Error, Result};
use crate::hash::Sha256Hasher;
use aws_lc_rs::{
    digest::{Digest, SHA256},
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair as AwsKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1};
use der::{asn1::BitString, Encode as _};
use sigstore_types::{DerPublicKey, HashAlgorithm, Sha256Hash, SignatureBytes};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Supported signing schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningScheme {
    /// ECDSA P-256 with SHA-256
    EcdsaP256Sha256,
    /// ECDSA P-256 with SHA-384 (non-standard but valid)
    EcdsaP256Sha384,
    /// ECDSA P-384 with SHA-256
    EcdsaP384Sha256,
    /// ECDSA P-384 with SHA-384
    EcdsaP384Sha384,
    /// Ed25519
    Ed25519,
    /// RSA PSS with SHA-256
    RsaPssSha256,
    /// RSA PSS with SHA-384
    RsaPssSha384,
    /// RSA PSS with SHA-512
    RsaPssSha512,
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512
    RsaPkcs1Sha512,
    /// ML-DSA-44
    MlDsa44,
    /// ML-DSA-65
    MlDsa65,
    /// ML-DSA-87
    MlDsa87,
}

impl SigningScheme {
    /// Get the name of this scheme
    pub fn name(&self) -> &'static str {
        match self {
            SigningScheme::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
            SigningScheme::EcdsaP256Sha384 => "ECDSA_P256_SHA384",
            SigningScheme::EcdsaP384Sha256 => "ECDSA_P384_SHA256",
            SigningScheme::EcdsaP384Sha384 => "ECDSA_P384_SHA384",
            SigningScheme::Ed25519 => "ED25519",
            SigningScheme::RsaPssSha256 => "RSA_PSS_SHA256",
            SigningScheme::RsaPssSha384 => "RSA_PSS_SHA384",
            SigningScheme::RsaPssSha512 => "RSA_PSS_SHA512",
            SigningScheme::RsaPkcs1Sha256 => "RSA_PKCS1_SHA256",
            SigningScheme::RsaPkcs1Sha384 => "RSA_PKCS1_SHA384",
            SigningScheme::RsaPkcs1Sha512 => "RSA_PKCS1_SHA512",
            SigningScheme::MlDsa44 => "ML_DSA_44",
            SigningScheme::MlDsa65 => "ML_DSA_65",
            SigningScheme::MlDsa87 => "ML_DSA_87",
        }
    }

    /// Check if this scheme supports prehashed verification.
    ///
    /// Ed25519 doesn't support prehashed verification (it signs the full message).
    /// ECDSA and RSA schemes support prehashed verification.
    pub fn supports_prehashed(&self) -> bool {
        !matches!(
            self,
            SigningScheme::Ed25519
                | SigningScheme::MlDsa44
                | SigningScheme::MlDsa65
                | SigningScheme::MlDsa87
        )
    }

    /// Hash algorithm used by prehashed variants of this scheme.
    pub fn hash_algorithm(&self) -> Option<HashAlgorithm> {
        match self {
            Self::EcdsaP256Sha256
            | Self::EcdsaP384Sha256
            | Self::RsaPssSha256
            | Self::RsaPkcs1Sha256 => Some(HashAlgorithm::Sha2256),
            Self::EcdsaP256Sha384
            | Self::EcdsaP384Sha384
            | Self::RsaPssSha384
            | Self::RsaPkcs1Sha384 => Some(HashAlgorithm::Sha2384),
            Self::RsaPssSha512 | Self::RsaPkcs1Sha512 => Some(HashAlgorithm::Sha2512),
            Self::Ed25519 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => None,
        }
    }
}

/// Key algorithm derived from the certificate/public key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA P-256
    EcdsaP256,
    /// ECDSA P-384
    EcdsaP384,
    /// Ed25519
    Ed25519,
    /// RSA
    Rsa,
}

impl KeyAlgorithm {
    /// Get the default signing scheme for this key algorithm
    pub fn default_signing_scheme(&self) -> SigningScheme {
        match self {
            KeyAlgorithm::EcdsaP256 => SigningScheme::EcdsaP256Sha256,
            KeyAlgorithm::EcdsaP384 => SigningScheme::EcdsaP384Sha384,
            KeyAlgorithm::Ed25519 => SigningScheme::Ed25519,
            KeyAlgorithm::Rsa => SigningScheme::RsaPkcs1Sha256,
        }
    }

    /// Resolve the signing scheme using the key algorithm and a specific hash algorithm
    pub fn resolve_signing_scheme(
        &self,
        hash_algo: sigstore_types::HashAlgorithm,
    ) -> Result<SigningScheme> {
        match self {
            KeyAlgorithm::EcdsaP256 => match hash_algo {
                sigstore_types::HashAlgorithm::Sha2256 => Ok(SigningScheme::EcdsaP256Sha256),
                sigstore_types::HashAlgorithm::Sha2384 => Ok(SigningScheme::EcdsaP256Sha384),
                _ => Err(Error::UnsupportedAlgorithm(format!(
                    "ECDSA P-256 does not support hash algorithm {:?}",
                    hash_algo
                ))),
            },
            KeyAlgorithm::EcdsaP384 => match hash_algo {
                sigstore_types::HashAlgorithm::Sha2256 => Ok(SigningScheme::EcdsaP384Sha256),
                sigstore_types::HashAlgorithm::Sha2384 => Ok(SigningScheme::EcdsaP384Sha384),
                _ => Err(Error::UnsupportedAlgorithm(format!(
                    "ECDSA P-384 does not support hash algorithm {:?}",
                    hash_algo
                ))),
            },
            KeyAlgorithm::Ed25519 => Ok(SigningScheme::Ed25519),
            KeyAlgorithm::Rsa => match hash_algo {
                sigstore_types::HashAlgorithm::Sha2256 => Ok(SigningScheme::RsaPkcs1Sha256),
                sigstore_types::HashAlgorithm::Sha2384 => Ok(SigningScheme::RsaPkcs1Sha384),
                sigstore_types::HashAlgorithm::Sha2512 => Ok(SigningScheme::RsaPkcs1Sha512),
            },
        }
    }
}

/// A key pair for signing
pub enum KeyPair {
    /// ECDSA P-256 key pair
    EcdsaP256(EcdsaKeyPair),
}

impl KeyPair {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate_ecdsa_p256() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string()))?;
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())?;
        Ok(KeyPair::EcdsaP256(key_pair))
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        match self {
            KeyPair::EcdsaP256(kp) => kp.public_key().as_ref(),
        }
    }

    /// Sign data with this key pair
    pub fn sign(&self, data: &[u8]) -> Result<SignatureBytes> {
        let rng = SystemRandom::new();
        match self {
            KeyPair::EcdsaP256(kp) => {
                let sig = kp.sign(&rng, data)?;
                Ok(SignatureBytes::new(sig.as_ref().to_vec()))
            }
        }
    }

    /// Sign a message from its incrementally computed SHA-256 digest.
    ///
    /// This produces a signature that verifies identically to [`KeyPair::sign`]
    /// over the full message (ECDSA P-256 hashes the message with SHA-256 before signing),
    /// but operates on the already-computed digest, so the signing cost is
    /// independent of the message size. This lets callers hash large inputs
    /// incrementally — and, in async contexts, yield to the executor between
    /// chunks — without re-hashing the whole message during signing.
    ///
    /// Returns the message digest along with the signature.
    pub fn sign_prehashed(&self, hasher: Sha256Hasher) -> Result<(Sha256Hash, SignatureBytes)> {
        let digest = hasher.finish_digest();
        match self {
            KeyPair::EcdsaP256(kp) => {
                let sig = kp.sign_digest(&digest)?;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(digest.as_ref());
                Ok((
                    Sha256Hash::from_bytes(hash),
                    SignatureBytes::new(sig.as_ref().to_vec()),
                ))
            }
        }
    }

    /// Sign a caller-supplied SHA-256 digest.
    ///
    /// This attests to the digest supplied by the caller; the original message
    /// is not available for the library to hash or otherwise inspect.
    pub fn sign_digest(&self, digest: &Sha256Hash) -> Result<SignatureBytes> {
        let digest = Digest::import_less_safe(digest.as_bytes(), &SHA256)
            .map_err(|_| Error::Signing("invalid SHA-256 digest".to_string()))?;
        match self {
            KeyPair::EcdsaP256(kp) => {
                let sig = kp.sign_digest(&digest)?;
                Ok(SignatureBytes::new(sig.as_ref().to_vec()))
            }
        }
    }

    /// Get the signing scheme for this key pair
    pub fn default_scheme(&self) -> SigningScheme {
        match self {
            KeyPair::EcdsaP256(_) => SigningScheme::EcdsaP256Sha256,
        }
    }

    /// Get the public key as a type-safe DerPublicKey
    ///
    /// Returns the public key in DER-encoded SubjectPublicKeyInfo format.
    /// Use `.to_pem()` on the result if you need PEM format.
    pub fn public_key_der(&self) -> Result<DerPublicKey> {
        match self {
            KeyPair::EcdsaP256(kp) => {
                let alg_id = AlgorithmIdentifier {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(
                        der::Any::encode_from(&SECP_256_R_1)
                            .map_err(|e| Error::Der(e.to_string()))?,
                    ),
                };

                let pub_key_bytes = kp.public_key().as_ref();

                let spki = SubjectPublicKeyInfo {
                    algorithm: alg_id,
                    subject_public_key: BitString::from_bytes(pub_key_bytes)
                        .map_err(|e| Error::Der(e.to_string()))?,
                };

                let der_bytes = spki.to_der().map_err(|e| Error::Der(e.to_string()))?;
                Ok(DerPublicKey::new(der_bytes))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        assert!(!kp.public_key_bytes().is_empty());
    }

    #[test]
    fn test_sign_ecdsa_p256() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let data = b"test data to sign";
        let sig = kp.sign(data).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_sign_digest_verifies_as_signature_over_message() {
        use crate::verification::VerificationKey;

        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let message = b"caller supplied digest";
        let digest = crate::hash::sha256(message);
        let sig = kp.sign_digest(&digest).unwrap();
        let vk = VerificationKey::from_spki(
            &kp.public_key_der().unwrap(),
            SigningScheme::EcdsaP256Sha256,
        )
        .unwrap();
        vk.verify(message, &sig).unwrap();
    }

    #[test]
    fn test_sign_prehashed_verifies_as_signature_over_message() {
        use crate::verification::VerificationKey;

        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let message = b"prehashed signing test message";

        let mut hasher = Sha256Hasher::new();
        hasher.update(&message[..10]);
        hasher.update(&message[10..]);
        let (digest, sig) = kp.sign_prehashed(hasher).unwrap();

        // The returned digest matches one-shot hashing.
        assert_eq!(digest, crate::hash::sha256(message));

        // The signature verifies as ECDSA-SHA256 over the full message.
        let key = VerificationKey::from_spki_with_scheme(
            &kp.public_key_der().unwrap(),
            SigningScheme::EcdsaP256Sha256,
        )
        .unwrap();
        key.verify(message.as_slice(), &sig).unwrap();
    }

    #[test]
    fn test_ecdsa_p256_public_key_len() {
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let bytes = kp.public_key_bytes();
        println!("Public key len: {}", bytes.len());
        // Uncompressed P-256 key should be 65 bytes (0x04 + 32 bytes X + 32 bytes Y)
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
    }
}
