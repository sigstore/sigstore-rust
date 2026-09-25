//! Error types for sigstore-rekor

use thiserror::Error;

/// Errors that can occur in Rekor operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The request could not be sent or the response could not be read
    #[error("HTTP error: {0}")]
    Http(String),

    /// Rekor answered with a non-success HTTP status (for example 409 when
    /// the entry already exists)
    #[error("Rekor returned HTTP {status}: {message}")]
    Status {
        /// The HTTP status code
        status: u16,
        /// What was requested, and the response body if any
        message: String,
    },

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Merkle proof error
    #[error("Merkle proof error: {0}")]
    Merkle(#[from] sigstore_merkle::Error),

    /// The response did not have the expected shape
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

/// Result type for Rekor operations
pub type Result<T> = std::result::Result<T, Error>;
