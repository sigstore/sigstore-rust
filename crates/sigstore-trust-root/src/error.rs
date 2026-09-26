//! Error types for trusted root operations

use thiserror::Error;

/// Errors that can occur during trusted root operations
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// JSON parsing error
    #[error("failed to parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Reading trust material from a file failed
    #[error("failed to read trust material: {0}")]
    Io(#[from] std::io::Error),

    /// Trust material contained an invalid encoding, key or checkpoint
    #[error(transparent)]
    Types(#[from] sigstore_types::Error),

    /// Certificate parsing error
    #[error("failed to parse certificate: {0}")]
    Certificate(String),

    /// Invalid key format
    #[error("invalid key format: {0}")]
    InvalidKey(String),

    /// Unsupported media type
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    /// No matching key found
    #[error("no matching key found for ID: {0}")]
    KeyNotFound(String),

    /// No matching certificate found
    #[error("no matching certificate found")]
    CertificateNotFound,

    /// TUF error (only available with "tuf" feature)
    #[error("TUF error: {0}")]
    Tuf(String),
}

/// Result type for trusted root operations
pub type Result<T> = std::result::Result<T, Error>;
