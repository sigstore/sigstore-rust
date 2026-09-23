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

    /// Invalid trust-root configuration.
    #[error("Trust root error: {0}")]
    TrustRoot(#[from] sigstore_trust_root::Error),

    /// A configured authority certificate could not be parsed.
    #[error("invalid trusted certificate: {0}")]
    TrustedCertificate(#[source] webpki::Error),

    /// Failed to read artifact input.
    #[error("failed to read artifact: {0}")]
    ArtifactRead(#[source] std::io::Error),
}

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, Error>;
