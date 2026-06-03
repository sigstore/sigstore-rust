//! Cryptographic primitives for Sigstore
//!
//! This crate provides key generation, signing, and verification functionality
//! using aws-lc-rs as the cryptographic backend.

pub mod checkpoint;
pub mod error;
pub mod hash;
pub mod keyring;
pub mod signing;
pub mod verification;
pub mod x509;

pub use checkpoint::{
    compute_key_hint, detect_key_type, extract_raw_key, verify_ecdsa_p256, verify_ed25519,
    verify_signature_auto, Checkpoint, CheckpointSignature, CheckpointVerifyExt, KeyType,
};
pub use error::{Error, Result};
pub use hash::{sha256, sha256_reader, sha384, sha512, Sha256Hasher};
pub use keyring::Keyring;
pub use signing::{KeyAlgorithm, KeyPair, SigningScheme};
pub use verification::{verify_signature, verify_signature_prehashed, VerificationKey};
pub use x509::{parse_certificate_info, CertificateInfo};
