//! Error types for sigstore-verify

use thiserror::Error;

/// Errors that can occur during verification
#[derive(Error, Debug)]
pub enum Error {
    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),

    /// Types error
    #[error("Types error: {0}")]
    Types(#[from] sigstore_types::Error),

    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(#[from] sigstore_crypto::Error),

    /// Bundle error
    #[error("Bundle error: {0}")]
    Bundle(#[from] sigstore_bundle::Error),

    /// Failed to read artifact input.
    #[error("failed to read artifact: {0}")]
    ArtifactRead(#[source] std::io::Error),
}

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, Error>;
