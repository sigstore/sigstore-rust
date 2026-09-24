//! Error types for sigstore-types

use thiserror::Error;

/// Errors that can occur in sigstore-types
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid media type
    #[error("Invalid media type: {0}")]
    InvalidMediaType(String),

    /// Invalid checkpoint format
    #[error("Invalid checkpoint format: {0}")]
    InvalidCheckpoint(String),

    /// Invalid hash algorithm
    #[error("Invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Invalid encoding (hex, base64, etc.)
    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),
}

/// Result type for sigstore-types operations
pub type Result<T> = std::result::Result<T, Error>;
