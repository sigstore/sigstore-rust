//! Error types for sigstore-bundle

use thiserror::Error;

/// Errors that can occur in bundle operations
#[derive(Error, Debug)]
pub enum Error {
    /// Bundle validation error
    #[error("Bundle validation error: {0}")]
    Validation(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type for bundle operations
pub type Result<T> = std::result::Result<T, Error>;
