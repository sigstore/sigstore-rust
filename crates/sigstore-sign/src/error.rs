//! Error types for sigstore-sign
//!
//! [`Error`](enum@Error) says which step of signing failed. Service failures
//! keep the service client's own error ([`Error::Fulcio`], [`Error::Rekor`],
//! [`Error::Tsa`], [`Error::Oidc`]) so callers can tell, for example, an HTTP
//! 409 from Rekor apart from a network failure. Configuration problems are
//! detected before any request is made and are described by
//! [`ConfigError`].

use std::fmt;

use sigstore_crypto::SigningScheme;
use sigstore_rekor::RekorApiVersion;
use sigstore_trust_root::ServiceSelector;
use thiserror::Error;

/// Errors that can occur during signing
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The signing services cannot produce a verifiable bundle. Nothing was
    /// sent to any service.
    #[error("invalid signing configuration: {0}")]
    Config(#[from] ConfigError),

    /// The artifact was supplied in a form this signer cannot sign, such as
    /// a digest that is not SHA-256.
    #[error("unsupported artifact: {0}")]
    UnsupportedArtifact(String),

    /// The statement to sign is not a valid in-toto statement.
    #[error("invalid in-toto statement: {0}")]
    InvalidStatement(#[source] serde_json::Error),

    /// Types error
    #[error("types error: {0}")]
    Types(#[from] sigstore_types::Error),

    /// Key generation or signing failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] sigstore_crypto::Error),

    /// Bundle error
    #[error("bundle error: {0}")]
    Bundle(#[from] sigstore_bundle::Error),

    /// The transparency log rejected the entry or returned an invalid
    /// response.
    #[error("Rekor error: {0}")]
    Rekor(#[from] sigstore_rekor::Error),

    /// The certificate authority did not issue a signing certificate.
    #[error("Fulcio error: {0}")]
    Fulcio(#[from] sigstore_fulcio::Error),

    /// The timestamp authority did not issue a timestamp.
    #[error("TSA error: {0}")]
    Tsa(#[from] sigstore_tsa::Error),

    /// Obtaining an identity token failed.
    #[error("OIDC error: {0}")]
    Oidc(#[from] sigstore_oidc::Error),

    /// Loading the instance's signing config failed
    #[error("trust root error: {0}")]
    TrustRoot(#[from] sigstore_trust_root::Error),

    /// Failed to read artifact input.
    #[error("failed to read artifact: {0}")]
    ArtifactRead(#[source] std::io::Error),
}

/// Why a set of signing services cannot be used.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The signing config lists no endpoint for this service that is
    /// currently valid and speaks a supported API version.
    #[error("no eligible {0} endpoint in the signing config")]
    MissingService(Service),

    /// A specific Rekor API version was requested but the signing config
    /// lists no eligible log for it.
    #[error("no eligible Rekor {0:?} endpoint in the signing config")]
    MissingRekorVersion(RekorApiVersion),

    /// The Rekor log speaks an API version this signer does not support.
    #[error("unsupported Rekor API version {0}")]
    UnsupportedRekorVersion(u32),

    /// The signing config requires submitting to more than one instance of
    /// this service, or leaves the requirement undefined. This signer
    /// submits to exactly one.
    #[error("{service} selector {selector:?} (count {count:?}) cannot be satisfied by submitting to one service")]
    UnsatisfiableSelector {
        /// The service the requirement applies to
        service: Service,
        /// The selector from the signing config
        selector: ServiceSelector,
        /// The count from the signing config, if any
        count: Option<u32>,
    },

    /// The signing scheme is not supported for keyless signing.
    #[error("signing scheme {} is not supported", .0.name())]
    UnsupportedScheme(SigningScheme),

    /// Bundles need an RFC 3161 timestamp because neither a Rekor v2 entry
    /// nor a bundle without a transparency log entry carries an integrated
    /// time, but no timestamp authority is configured.
    #[error(
        "an RFC 3161 timestamp authority is required with Rekor v2 or without a transparency log"
    )]
    TimestampAuthorityRequired,
}

/// A service used while signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Service {
    /// The certificate authority (Fulcio)
    Fulcio,
    /// The transparency log (Rekor)
    Rekor,
    /// The RFC 3161 timestamp authority
    Tsa,
    /// The OIDC identity provider
    Oidc,
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fulcio => "Fulcio",
            Self::Rekor => "Rekor",
            Self::Tsa => "TSA",
            Self::Oidc => "OIDC",
        })
    }
}

/// Result type for signing operations
pub type Result<T> = std::result::Result<T, Error>;
