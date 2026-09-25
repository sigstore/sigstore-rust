//! Error types for sigstore-verify

use sigstore_crypto::SubjectAltName;
use thiserror::Error;

use crate::IdentityMatcher;

/// Errors that can occur during verification
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The certificate identity does not satisfy the policy
    #[error("identity mismatch: expected {expected}, got {}", display_opt(actual))]
    IdentityMismatch {
        /// What the policy requires
        expected: IdentityMatcher,
        /// The certificate's SAN identity, if it has one
        actual: Option<SubjectAltName>,
    },

    /// The certificate's OIDC issuer does not satisfy the policy
    #[error("issuer mismatch: expected {expected}, got {}", display_opt(actual))]
    IssuerMismatch {
        /// The issuer the policy requires
        expected: String,
        /// The certificate's issuer claim, if it has one
        actual: Option<String>,
    },

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
    TrustedCertificate(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Failed to read artifact input.
    #[error("failed to read artifact: {0}")]
    ArtifactRead(#[source] std::io::Error),
}

fn display_opt(value: &Option<impl std::fmt::Display>) -> String {
    value
        .as_ref()
        .map_or_else(|| "none".to_string(), ToString::to_string)
}

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, Error>;
