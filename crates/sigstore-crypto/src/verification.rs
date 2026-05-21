//! Signature verification

use crate::error::{Error, Result};
use crate::signing::SigningScheme;
#[cfg(feature = "rustls")]
use aws_lc_rs::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1, ECDSA_P384_SHA384_ASN1,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
};
#[cfg(feature = "native-tls")]
use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1, ECDSA_P384_SHA384_ASN1,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
};
use sigstore_types::{DerPublicKey, Sha256Hash, SignatureBytes};
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

    /// Verify a signature over prehashed data (SHA-256)
    ///
    /// This is used for hashedrekord verification where the signature is over
    /// the SHA-256 hash of the artifact, not the artifact itself.
    pub fn verify_prehashed(&self, digest: &Sha256Hash, signature: &SignatureBytes) -> Result<()> {
        #[cfg(feature = "rustls")]
        if self.scheme == SigningScheme::EcdsaP256Sha256 {
            use aws_lc_rs::digest::{Digest, SHA256};

            let aws_digest = Digest::import_less_safe(digest.as_slice(), &SHA256)
                .map_err(|_| Error::Verification("Failed to import digest".to_string()))?;

            let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.bytes);
            return key
                .verify_digest(&aws_digest, signature.as_bytes())
                .map_err(|_| Error::Verification("ECDSA P-256 signature invalid".to_string()));
        }

        // For Ed25519 and other schemes (or ring backend), verify directly over digest bytes
        self.verify_inner(digest.as_slice(), signature.as_bytes())
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
/// the SHA-256 hash of the artifact, not the artifact itself.
///
/// # Arguments
/// * `public_key` - DER-encoded SPKI public key
/// * `digest` - SHA-256 hash of the artifact
/// * `signature` - The signature to verify
/// * `scheme` - The signing scheme used
pub fn verify_signature_prehashed(
    public_key: &DerPublicKey,
    digest: &Sha256Hash,
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
}
