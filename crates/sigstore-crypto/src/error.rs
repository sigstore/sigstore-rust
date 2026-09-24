//! Error types for sigstore-crypto

use thiserror::Error;

/// Errors that can occur in cryptographic operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Key generation error
    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    /// Signing error
    #[error("Signing error: {0}")]
    Signing(String),

    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// PEM encoding/decoding error
    #[error("PEM error: {0}")]
    Pem(String),

    /// DER encoding/decoding error
    #[error("DER error: {0}")]
    Der(String),

    /// Checkpoint parsing/verification error
    #[error("Checkpoint error: {0}")]
    Checkpoint(String),

    /// Certificate parsing/validation error
    #[error("Certificate error: {0}")]
    InvalidCertificate(String),

    /// Invalid key error
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, Error>;
