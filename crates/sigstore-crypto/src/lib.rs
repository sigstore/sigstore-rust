//! Cryptographic primitives for Sigstore
//!
//! This crate provides key generation, signing, and verification functionality
//! using `aws-lc-rs` (default) or a custom [`CryptoProvider`].

#![warn(missing_docs)]

#[cfg(feature = "aws-lc-rs")]
mod aws_lc;

pub mod checkpoint;
pub mod error;
pub mod hash;
pub mod keyring;
pub mod provider;
pub mod signing;
pub mod verification;
pub mod webpki;
pub mod x509;

pub use checkpoint::{compute_key_hint, Checkpoint, CheckpointSignature, CheckpointVerifyExt};
pub use error::{Error, Result};
pub use hash::{
    hash_async_reader, hash_reader, hash_reader_yielding, hash_yielding, sha256, sha256_reader,
    sha384, sha512, ArtifactHasher, HashUpdate, Sha256Hasher,
};
pub use keyring::Keyring;
#[cfg(feature = "aws-lc-rs")]
pub use provider::aws_lc_provider;
pub use provider::{
    default_provider, install_default_provider, try_default_provider, CryptoProvider, HashContext,
    SigningKeyPair,
};
pub use signing::{KeyAlgorithm, KeyPair, SigningScheme};
pub use verification::{
    validate_raw_public_key, verify_signature, verify_signature_prehashed, VerificationKey,
};
pub use webpki::WEBPKI_VERIFICATION_ALGS;
pub use x509::{
    parse_certificate_info, CertificateInfo, DeprecatedGitHubClaims, FulcioCiClaims, SubjectAltName,
};
