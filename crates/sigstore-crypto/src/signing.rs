//! Key generation and signing

use crate::error::{Error, Result};
use crate::hash::Sha256Hasher;
use crate::provider::{default_provider, SigningKeyPair};
use crate::verification::{ID_ED25519, ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1};
use der::{asn1::BitString, Encode as _};
use sigstore_types::{DerPublicKey, HashAlgorithm, Sha256Hash, SignatureBytes};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Supported signing schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    /// Public-key algorithm required by this signing scheme.
    pub fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::EcdsaP256Sha256 | Self::EcdsaP256Sha384 => KeyAlgorithm::EcdsaP256,
            Self::EcdsaP384Sha256 | Self::EcdsaP384Sha384 => KeyAlgorithm::EcdsaP384,
            Self::Ed25519 => KeyAlgorithm::Ed25519,
            Self::RsaPssSha256
            | Self::RsaPssSha384
            | Self::RsaPssSha512
            | Self::RsaPkcs1Sha256
            | Self::RsaPkcs1Sha384
            | Self::RsaPkcs1Sha512 => KeyAlgorithm::Rsa,
            Self::MlDsa44 => KeyAlgorithm::MlDsa44,
            Self::MlDsa65 => KeyAlgorithm::MlDsa65,
            Self::MlDsa87 => KeyAlgorithm::MlDsa87,
        }
    }

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// ECDSA P-256
    EcdsaP256,
    /// ECDSA P-384
    EcdsaP384,
    /// Ed25519
    Ed25519,
    /// RSA
    Rsa,
    /// ML-DSA-44
    MlDsa44,
    /// ML-DSA-65
    MlDsa65,
    /// ML-DSA-87
    MlDsa87,
}

impl KeyAlgorithm {
    /// Get the default signing scheme for this key algorithm
    pub fn default_signing_scheme(&self) -> SigningScheme {
        match self {
            KeyAlgorithm::EcdsaP256 => SigningScheme::EcdsaP256Sha256,
            KeyAlgorithm::EcdsaP384 => SigningScheme::EcdsaP384Sha384,
            KeyAlgorithm::Ed25519 => SigningScheme::Ed25519,
            KeyAlgorithm::Rsa => SigningScheme::RsaPkcs1Sha256,
            KeyAlgorithm::MlDsa44 => SigningScheme::MlDsa44,
            KeyAlgorithm::MlDsa65 => SigningScheme::MlDsa65,
            KeyAlgorithm::MlDsa87 => SigningScheme::MlDsa87,
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
            KeyAlgorithm::Ed25519
            | KeyAlgorithm::MlDsa44
            | KeyAlgorithm::MlDsa65
            | KeyAlgorithm::MlDsa87 => Ok(self.default_signing_scheme()),
            KeyAlgorithm::Rsa => match hash_algo {
                sigstore_types::HashAlgorithm::Sha2256 => Ok(SigningScheme::RsaPkcs1Sha256),
                sigstore_types::HashAlgorithm::Sha2384 => Ok(SigningScheme::RsaPkcs1Sha384),
                sigstore_types::HashAlgorithm::Sha2512 => Ok(SigningScheme::RsaPkcs1Sha512),
                _ => Err(Error::UnsupportedAlgorithm(format!(
                    "RSA does not support hash algorithm {:?}",
                    hash_algo
                ))),
            },
        }
    }
}

/// A key pair for signing
///
/// The key material and the cryptographic backend are private, so new key
/// types can be supported without changing this type.
pub struct KeyPair(Box<dyn SigningKeyPair>);

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Generate a new key pair for `algorithm`.
    ///
    /// Only [`KeyAlgorithm::EcdsaP256`] is supported by the built-in provider today.
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self> {
        Ok(Self(default_provider().generate_key_pair(algorithm)?))
    }

    /// Generate a new ECDSA P-256 key pair
    pub fn generate_ecdsa_p256() -> Result<Self> {
        Self::generate(KeyAlgorithm::EcdsaP256)
    }

    /// Load a key pair from a DER-encoded PKCS#8 private key.
    ///
    /// Only ECDSA P-256 keys are supported by the built-in provider today.
    pub fn from_pkcs8_der(pkcs8: &[u8]) -> Result<Self> {
        use der::Decode as _;
        // Ensure outer DER has no trailing bytes before passing to the provider.
        der::asn1::AnyRef::from_der(pkcs8).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Ok(Self(default_provider().key_pair_from_pkcs8_der(pkcs8)?))
    }

    /// The key algorithm of this key pair.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.0.algorithm()
    }

    /// Get the raw public key bytes (for ECDSA, the uncompressed SEC1 point)
    pub fn public_key_bytes(&self) -> &[u8] {
        self.0.public_key_bytes()
    }

    /// Sign data with this key pair
    pub fn sign(&self, data: &[u8]) -> Result<SignatureBytes> {
        let sig = self.0.sign_raw(data)?;
        Ok(SignatureBytes::new(sig))
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
        let digest = hasher.finalize();
        let sig = self.sign_digest(&digest)?;
        Ok((digest, sig))
    }

    /// Sign a caller-supplied SHA-256 digest.
    ///
    /// This attests to the digest supplied by the caller; the original message
    /// is not available for the library to hash or otherwise inspect.
    pub fn sign_digest(&self, digest: &Sha256Hash) -> Result<SignatureBytes> {
        let sig = self.0.sign_prehashed(digest.as_bytes())?;
        Ok(SignatureBytes::new(sig))
    }

    /// Get the signing scheme for this key pair
    pub fn default_scheme(&self) -> SigningScheme {
        self.algorithm().default_signing_scheme()
    }

    /// Get the public key as a type-safe DerPublicKey
    ///
    /// Returns the public key in DER-encoded SubjectPublicKeyInfo format.
    /// Use `.to_pem()` on the result if you need PEM format.
    pub fn public_key_der(&self) -> Result<DerPublicKey> {
        let algorithm = match self.algorithm() {
            KeyAlgorithm::EcdsaP256 => AlgorithmIdentifier {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(
                    der::Any::encode_from(&SECP_256_R_1).map_err(|e| Error::Der(e.to_string()))?,
                ),
            },
            KeyAlgorithm::EcdsaP384 => AlgorithmIdentifier {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(
                    der::Any::encode_from(&SECP_384_R_1).map_err(|e| Error::Der(e.to_string()))?,
                ),
            },
            KeyAlgorithm::Rsa => AlgorithmIdentifier {
                oid: RSA_ENCRYPTION,
                parameters: Some(der::Any::null()),
            },
            KeyAlgorithm::Ed25519 => AlgorithmIdentifier {
                oid: ID_ED25519,
                parameters: None,
            },
            KeyAlgorithm::MlDsa44 => AlgorithmIdentifier {
                oid: ID_ML_DSA_44,
                parameters: None,
            },
            KeyAlgorithm::MlDsa65 => AlgorithmIdentifier {
                oid: ID_ML_DSA_65,
                parameters: None,
            },
            KeyAlgorithm::MlDsa87 => AlgorithmIdentifier {
                oid: ID_ML_DSA_87,
                parameters: None,
            },
        };

        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::from_bytes(self.public_key_bytes())
                .map_err(|e| Error::Der(e.to_string()))?,
        };

        let der_bytes = spki.to_der().map_err(|e| Error::Der(e.to_string()))?;
        Ok(DerPublicKey::new(der_bytes))
    }
}

#[cfg(test)]
mod spki_tests {
    use super::*;

    struct DummySigningKeyPair {
        algorithm: KeyAlgorithm,
        pubkey: Vec<u8>,
    }

    impl SigningKeyPair for DummySigningKeyPair {
        fn algorithm(&self) -> KeyAlgorithm {
            self.algorithm
        }

        fn public_key_bytes(&self) -> &[u8] {
            &self.pubkey
        }

        fn sign_raw(&self, _data: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![])
        }

        fn sign_prehashed(&self, _digest: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    #[test]
    fn public_key_der_round_trips_all_key_algorithms() {
        let rsa_der = vec![0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x03];
        for (algorithm, pubkey) in [
            (KeyAlgorithm::EcdsaP256, vec![0x04; 65]),
            (KeyAlgorithm::EcdsaP384, vec![0x04; 97]),
            (KeyAlgorithm::Rsa, rsa_der),
            (KeyAlgorithm::Ed25519, vec![0x11; 32]),
            (KeyAlgorithm::MlDsa44, vec![0x22; 1312]),
            (KeyAlgorithm::MlDsa65, vec![0x33; 1952]),
            (KeyAlgorithm::MlDsa87, vec![0x44; 2592]),
        ] {
            let kp = KeyPair(Box::new(DummySigningKeyPair { algorithm, pubkey }));
            let spki = kp.public_key_der().unwrap();
            assert_eq!(KeyAlgorithm::from_spki(&spki).unwrap(), algorithm);
        }
    }
}

#[cfg(all(test, feature = "aws-lc-rs"))]
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
        let vk = VerificationKey::from_spki_with_scheme(
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

    #[test]
    fn key_pair_is_opaque_and_round_trips_pkcs8() {
        let pkcs8 = crate::aws_lc::test_support::generate_p256_pkcs8();
        let key = KeyPair::from_pkcs8_der(&pkcs8).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::EcdsaP256);
        assert_eq!(key.default_scheme(), SigningScheme::EcdsaP256Sha256);
        assert_eq!(format!("{key:?}"), "KeyPair { algorithm: EcdsaP256, .. }");

        // Trailing bytes after the PKCS#8 DER element must be rejected.
        let mut with_trailing = pkcs8;
        with_trailing.push(0x00);
        assert!(matches!(
            KeyPair::from_pkcs8_der(&with_trailing),
            Err(Error::InvalidKeyFormat(_))
        ));

        assert!(KeyPair::from_pkcs8_der(b"not a key").is_err());
        assert!(matches!(
            KeyPair::generate(KeyAlgorithm::Ed25519),
            Err(Error::UnsupportedAlgorithm(_))
        ));
    }
}
