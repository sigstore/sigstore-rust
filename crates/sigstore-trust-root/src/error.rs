//! Error types for trusted root operations

use thiserror::Error;

/// Errors that can occur during trusted root operations
#[derive(Debug, Error)]
pub enum Error {
    /// JSON parsing error
    #[error("failed to parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error
    #[error("failed to decode base64: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Certificate parsing error
    #[error("failed to parse certificate: {0}")]
    Certificate(String),

    /// Invalid key format
    #[error("invalid key format: {0}")]
    InvalidKey(String),

    /// Missing required field
    #[error("missing required field: {0}")]
    MissingField(String),

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

/// Convert from sigstore_types::Error to our Error type
impl From<sigstore_types::Error> for Error {
    fn from(err: sigstore_types::Error) -> Self {
        match err {
            sigstore_types::Error::Base64(e) => Error::Base64(e),
            sigstore_types::Error::Json(e) => Error::Json(e),
            sigstore_types::Error::InvalidEncoding(s) => Error::InvalidKey(s),
            sigstore_types::Error::InvalidCertificate(s) => Error::Certificate(s),
            sigstore_types::Error::MissingField(s) => Error::MissingField(s),
            // For other variants, convert to string error
            _ => Error::InvalidKey(err.to_string()),
        }
    }
}
