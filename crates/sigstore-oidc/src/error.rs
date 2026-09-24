//! Error types for sigstore-oidc

use thiserror::Error;

/// Errors that can occur in OIDC operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(String),

    /// Token error
    #[error("Token error: {0}")]
    Token(String),

    /// OAuth error
    #[error("OAuth error: {0}")]
    OAuth(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type for OIDC operations
pub type Result<T> = std::result::Result<T, Error>;
