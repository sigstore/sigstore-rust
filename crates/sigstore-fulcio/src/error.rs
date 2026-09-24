//! Error types for sigstore-fulcio

use thiserror::Error;

/// Errors that can occur in Fulcio operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The request could not be sent or the response could not be read
    #[error("HTTP error: {0}")]
    Http(String),

    /// Fulcio answered with a non-success HTTP status
    #[error("Fulcio returned HTTP {status}: {message}")]
    Status {
        /// The HTTP status code
        status: u16,
        /// What was requested, and the response body if any
        message: String,
    },

    /// The response did not have the expected shape
    #[error("invalid Fulcio response: {0}")]
    InvalidResponse(String),

    /// The key pair could not produce the request (public key export or
    /// proof of possession)
    #[error("failed to prepare the certificate request: {0}")]
    Signing(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type for Fulcio operations
pub type Result<T> = std::result::Result<T, Error>;
