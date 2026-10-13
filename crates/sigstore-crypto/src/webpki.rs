//! `rustls-webpki` signature verification algorithms backed by `sigstore-crypto`.
//!
//! This module bridges `sigstore-crypto`'s active cryptographic backend to
//! [`rustls_pki_types::SignatureVerificationAlgorithm`], allowing `rustls-webpki`
//! to verify X.509 certificate chains without depending on `aws-lc-rs` directly.

use crate::provider::default_provider;
use crate::signing::SigningScheme;
use crate::verification::validate_raw_public_key;
use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};

#[derive(Debug)]
struct WebpkiVerificationAlg {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    scheme: SigningScheme,
}

impl SignatureVerificationAlgorithm for WebpkiVerificationAlg {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        validate_raw_public_key(self.scheme, public_key).map_err(|_| InvalidSignature)?;
        default_provider()
            .verify_raw(self.scheme, public_key, message, signature)
            .map_err(|_| InvalidSignature)
    }
}

/// ECDSA P-256 with SHA-256 verification algorithm for `webpki`.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    scheme: SigningScheme::EcdsaP256Sha256,
};

/// ECDSA P-256 with SHA-384 verification algorithm for `webpki`.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    scheme: SigningScheme::EcdsaP256Sha384,
};

/// ECDSA P-384 with SHA-256 verification algorithm for `webpki`.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    scheme: SigningScheme::EcdsaP384Sha256,
};

/// ECDSA P-384 with SHA-384 verification algorithm for `webpki`.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    scheme: SigningScheme::EcdsaP384Sha384,
};

/// Ed25519 verification algorithm for `webpki`.
pub static ED25519: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    scheme: SigningScheme::Ed25519,
};

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-256 verification algorithm for `webpki`.
pub static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA256,
        scheme: SigningScheme::RsaPkcs1Sha256,
    };

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-384 verification algorithm for `webpki`.
pub static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA384,
        scheme: SigningScheme::RsaPkcs1Sha384,
    };

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-512 verification algorithm for `webpki`.
pub static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PKCS1_SHA512,
        scheme: SigningScheme::RsaPkcs1Sha512,
    };

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-256 and absent `AlgorithmIdentifier` parameters (RFC 4055 §5).
pub static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: AlgorithmIdentifier::from_slice(&[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        ]),
        scheme: SigningScheme::RsaPkcs1Sha256,
    };

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-384 and absent `AlgorithmIdentifier` parameters (RFC 4055 §5).
pub static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: AlgorithmIdentifier::from_slice(&[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
        ]),
        scheme: SigningScheme::RsaPkcs1Sha384,
    };

/// RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-512 and absent `AlgorithmIdentifier` parameters (RFC 4055 §5).
pub static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &WebpkiVerificationAlg {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: AlgorithmIdentifier::from_slice(&[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
        ]),
        scheme: SigningScheme::RsaPkcs1Sha512,
    };

/// RSA-PSS (2048–8192 bits) with SHA-256 verification algorithm for `webpki`.
pub static RSA_PSS_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    scheme: SigningScheme::RsaPssSha256,
};

/// RSA-PSS (2048–8192 bits) with SHA-384 verification algorithm for `webpki`.
pub static RSA_PSS_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    scheme: SigningScheme::RsaPssSha384,
};

/// RSA-PSS (2048–8192 bits) with SHA-512 verification algorithm for `webpki`.
pub static RSA_PSS_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    scheme: SigningScheme::RsaPssSha512,
};

/// ML-DSA-44 verification algorithm for `webpki`.
pub static ML_DSA_44: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ML_DSA_44,
    signature_alg_id: alg_id::ML_DSA_44,
    scheme: SigningScheme::MlDsa44,
};

/// ML-DSA-65 verification algorithm for `webpki`.
pub static ML_DSA_65: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ML_DSA_65,
    signature_alg_id: alg_id::ML_DSA_65,
    scheme: SigningScheme::MlDsa65,
};

/// ML-DSA-87 verification algorithm for `webpki`.
pub static ML_DSA_87: &dyn SignatureVerificationAlgorithm = &WebpkiVerificationAlg {
    public_key_alg_id: alg_id::ML_DSA_87,
    signature_alg_id: alg_id::ML_DSA_87,
    scheme: SigningScheme::MlDsa87,
};

/// All X.509 signature verification algorithms supported by `sigstore-crypto` for `rustls-webpki`.
pub static WEBPKI_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
];

#[cfg(all(test, feature = "aws-lc-rs"))]
mod tests {
    use super::*;
    use crate::signing::KeyPair;
    use sigstore_types::HashAlgorithm;

    #[test]
    fn webpki_algorithms_verify_and_reject_invalid_signatures() {
        let msg = b"webpki tbsCertificate test payload";

        // 1. ECDSA P-256
        let kp = KeyPair::generate_ecdsa_p256().unwrap();
        let sig = kp.sign(msg).unwrap();
        assert!(ECDSA_P256_SHA256
            .verify_signature(kp.public_key_bytes(), msg, sig.as_bytes())
            .is_ok());
        assert!(ECDSA_P256_SHA256
            .verify_signature(kp.public_key_bytes(), b"wrong", sig.as_bytes())
            .is_err());

        // 2. ECDSA P-384
        let (p384_pk, p384_sig) = crate::aws_lc::test_support::sign_p384_sha384(msg);
        assert!(ECDSA_P384_SHA384
            .verify_signature(&p384_pk, msg, p384_sig.as_bytes())
            .is_ok());
        assert!(ECDSA_P384_SHA256
            .verify_signature(&p384_pk, msg, p384_sig.as_bytes())
            .is_err());

        // 3. Ed25519
        let (ed_pk, ed_sig) = crate::aws_lc::test_support::sign_ed25519(msg);
        assert!(ED25519
            .verify_signature(&ed_pk, msg, ed_sig.as_bytes())
            .is_ok());

        // 4. RSA PKCS#1 (with and without NULL params) and RSA-PSS
        let (rsa_pk, pkcs1_sig, pss_sig) =
            crate::aws_lc::test_support::sign_rsa(msg, HashAlgorithm::Sha2256);
        for alg in [
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        ] {
            assert!(alg
                .verify_signature(rsa_pk.as_bytes(), msg, pkcs1_sig.as_bytes())
                .is_ok());
            assert!(alg
                .verify_signature(rsa_pk.as_bytes(), msg, pss_sig.as_bytes())
                .is_err());
        }
        assert!(RSA_PSS_2048_8192_SHA256
            .verify_signature(rsa_pk.as_bytes(), msg, pss_sig.as_bytes())
            .is_ok());

        // 5. ML-DSA-44/65/87
        let seed = [0x33u8; 32];
        for (scheme, alg) in [
            (SigningScheme::MlDsa44, ML_DSA_44),
            (SigningScheme::MlDsa65, ML_DSA_65),
            (SigningScheme::MlDsa87, ML_DSA_87),
        ] {
            let (mldsa_pk, mldsa_sig) = crate::aws_lc::test_support::sign_mldsa(scheme, &seed, msg);
            assert!(alg
                .verify_signature(&mldsa_pk, msg, mldsa_sig.as_bytes())
                .is_ok());
        }

        assert_eq!(WEBPKI_VERIFICATION_ALGS.len(), 17);
    }
}
