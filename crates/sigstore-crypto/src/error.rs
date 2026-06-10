//! Error types for sigstore-crypto

use thiserror::Error;

/// Errors that can occur in cryptographic operations
#[derive(Error, Debug)]
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

    /// Base64 error
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Crypto backend error
    #[error("Crypto error: {0}")]
    AwsLc(String),

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

#[cfg(feature = "rustls")]
impl From<aws_lc_rs::error::Unspecified> for Error {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        Error::AwsLc("unspecified error".to_string())
    }
}

#[cfg(feature = "rustls")]
impl From<aws_lc_rs::error::KeyRejected> for Error {
    fn from(e: aws_lc_rs::error::KeyRejected) -> Self {
        Error::InvalidKeyFormat(e.to_string())
    }
}

#[cfg(feature = "native-tls")]
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::AwsLc("unspecified error".to_string())
    }
}

#[cfg(feature = "native-tls")]
impl From<ring::error::KeyRejected> for Error {
    fn from(e: ring::error::KeyRejected) -> Self {
        Error::InvalidKeyFormat(e.to_string())
    }
}

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, Error>;
