//! Cryptographic primitives for Sigstore
//!
//! This crate provides key generation, signing, and verification functionality
//! using aws-lc-rs as the cryptographic backend.

pub mod error;
pub mod hash;
pub mod keyring;
pub mod signing;
pub mod verification;
pub mod x509;

pub use error::{Error, Result};
pub use hash::{sha256, sha256_reader, sha384, sha512, Sha256Hasher};
pub use keyring::Keyring;
pub use signing::{KeyAlgorithm, KeyPair, SigningScheme};
pub use sigstore_types::{Checkpoint, CheckpointSignature};
pub use verification::{
    detect_key_type, verify_signature, verify_signature_prehashed, KeyType, VerificationKey,
};
pub use x509::{parse_certificate_info, CertificateInfo};
