//! Error types for sigstore-bundle

use sigstore_types::MediaType;
use thiserror::Error;

/// Reasons a bundle fails structural validation
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bundle's media type is not supported by this version
    #[error("unsupported bundle media type: {0}")]
    UnsupportedMediaType(MediaType),

    /// The bundle's verification material is not supported by this version
    #[error("unsupported verification material")]
    UnsupportedVerificationMaterial,

    /// A v0.3 bundle carries a certificate chain instead of a single certificate
    #[error("{0} bundles must use a single certificate, not a chain")]
    CertificateChainNotAllowed(MediaType),

    /// The bundle version requires an inclusion promise (SET)
    #[error("{0} bundles must have an inclusion promise")]
    MissingInclusionPromise(MediaType),

    /// An inclusion proof is required but absent
    #[error("{0} bundle must have an inclusion proof")]
    MissingInclusionProof(MediaType),

    /// The bundle has neither usable transparency log entries nor timestamps
    #[error("bundle must have at least one tlog entry or timestamp verification data")]
    MissingSigningTimeEvidence,

    /// RFC 3161 timestamps are required but absent
    #[error("bundle must have timestamp verification data")]
    MissingTimestamp,

    /// An inclusion proof has no checkpoint
    #[error("inclusion proof has no checkpoint")]
    MissingCheckpoint,

    /// A log index does not fall inside the tree it claims to be in
    #[error("log index {log_index} out of range for tree size {tree_size}")]
    LogIndexOutOfRange {
        /// The claimed log index
        log_index: u64,
        /// The tree size the index was checked against
        tree_size: u64,
    },

    /// A Rekor v1 inclusion proof's root hash differs from its checkpoint's
    #[error("inclusion proof root hash does not match checkpoint root hash")]
    CheckpointRootMismatch,
}

/// Result type for bundle operations
pub type Result<T> = std::result::Result<T, Error>;
