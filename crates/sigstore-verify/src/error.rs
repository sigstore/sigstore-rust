//! Error types for sigstore-verify
//!
//! [`Error`] says *why* verification failed in a form callers can match on:
//! a policy mismatch, an invalid signature, a certificate, transparency-log or
//! timestamp problem, or a bundle that does not describe the artifact. The
//! nested enums narrow the category further; their string payloads are
//! human-readable detail, not something to match on.

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

    /// The signature does not verify over the artifact (or DSSE payload)
    /// with the signing key.
    #[error("invalid signature: {0}")]
    SignatureInvalid(String),

    /// The bundle does not describe the supplied artifact: a digest or
    /// attestation subject does not match it.
    #[error("artifact mismatch: {0}")]
    ArtifactMismatch(String),

    /// The artifact was supplied in a form this verification cannot use, for
    /// example a digest of the wrong algorithm or a reader for a signing
    /// scheme that needs the whole message.
    #[error("unsupported artifact input: {0}")]
    UnsupportedArtifact(String),

    /// The signing certificate was rejected.
    #[error(transparent)]
    Certificate(#[from] CertificateError),

    /// The transparency log evidence was rejected.
    #[error(transparent)]
    TransparencyLog(#[from] TransparencyLogError),

    /// An RFC 3161 timestamp was rejected, or no trusted signing time exists.
    #[error(transparent)]
    Timestamp(#[from] TimestampError),

    /// The bundle is malformed or internally inconsistent.
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),

    /// The bundle is well formed but uses content, key types or entry kinds
    /// this version cannot verify.
    #[error("unsupported bundle: {0}")]
    UnsupportedBundle(String),

    /// The trusted root cannot be used for verification.
    #[error("invalid trusted root: {0}")]
    InvalidTrustRoot(String),

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

/// Why the signing certificate was rejected.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateError {
    /// The certificate (or its chain) could not be parsed.
    #[error("malformed certificate: {0}")]
    Malformed(String),

    /// The certificate does not chain to a trusted Fulcio authority, or lacks
    /// the code-signing usage.
    #[error("certificate chain is invalid: {0}")]
    ChainInvalid(String),

    /// No Fulcio authority in the trusted root was valid at the signing time.
    #[error("no trusted certificate authority is valid at {time}")]
    NoValidAuthority {
        /// The authenticated signing time
        time: jiff::Timestamp,
    },

    /// The signing time is before the certificate's `notBefore`.
    #[error("certificate is not yet valid at {time} (not before {not_before})")]
    NotYetValid {
        /// The authenticated signing time
        time: jiff::Timestamp,
        /// The certificate's `notBefore`
        not_before: jiff::Timestamp,
    },

    /// The signing time is after the certificate's `notAfter`.
    #[error("certificate had expired at {time} (not after {not_after})")]
    Expired {
        /// The authenticated signing time
        time: jiff::Timestamp,
        /// The certificate's `notAfter`
        not_after: jiff::Timestamp,
    },

    /// The certificate's Signed Certificate Timestamp is missing or invalid.
    #[error("invalid signed certificate timestamp: {0}")]
    Sct(String),
}

/// Why the transparency log evidence was rejected.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransparencyLogError {
    /// The entry names a log that is not in the trusted root.
    #[error("unknown transparency log {log_id}")]
    UnknownLog {
        /// The log ID from the entry
        log_id: String,
    },

    /// The inclusion proof does not prove the entry is in the log.
    #[error("invalid inclusion proof: {0}")]
    InclusionProof(String),

    /// The checkpoint (signed tree head) is missing, malformed or not signed
    /// by a trusted log key.
    #[error("invalid checkpoint: {0}")]
    Checkpoint(String),

    /// The inclusion promise (Signed Entry Timestamp) is missing or invalid.
    #[error("invalid inclusion promise: {0}")]
    InclusionPromise(String),

    /// The log entry does not describe this bundle's signature, key or
    /// artifact.
    #[error("log entry does not match the bundle: {0}")]
    EntryMismatch(String),

    /// The entry's integrated time is in the future or outside the signing
    /// certificate's validity.
    #[error("invalid integrated time: {0}")]
    IntegratedTime(String),

    /// The log entry body could not be parsed or has an unsupported kind.
    #[error("malformed log entry: {0}")]
    MalformedEntry(String),
}

/// Why a timestamp was rejected.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampError {
    /// An RFC 3161 timestamp did not verify against any trusted authority.
    #[error("invalid RFC 3161 timestamp: {0}")]
    Invalid(String),

    /// An RFC 3161 timestamp is authentic, but its time is outside the
    /// validity window of the authority that signed it.
    #[error(
        "RFC 3161 timestamp {time} is outside the validity period of the authority that signed it"
    )]
    OutsideAuthorityValidity {
        /// The authenticated signed time
        time: jiff::Timestamp,
    },

    /// No trusted signing time could be established.
    #[error("no verified timestamp: {0}")]
    NoVerifiedTimestamp(String),
}

/// Constructors for the categorized errors, so call sites stay short.
impl Error {
    pub(crate) fn cert_malformed(detail: String) -> Self {
        CertificateError::Malformed(detail).into()
    }
    pub(crate) fn cert_chain_invalid(detail: String) -> Self {
        CertificateError::ChainInvalid(detail).into()
    }
    pub(crate) fn sct(detail: String) -> Self {
        CertificateError::Sct(detail).into()
    }
    pub(crate) fn unknown_log(log_id: String) -> Self {
        TransparencyLogError::UnknownLog { log_id }.into()
    }
    pub(crate) fn inclusion_proof(detail: String) -> Self {
        TransparencyLogError::InclusionProof(detail).into()
    }
    pub(crate) fn checkpoint(detail: String) -> Self {
        TransparencyLogError::Checkpoint(detail).into()
    }
    pub(crate) fn inclusion_promise(detail: String) -> Self {
        TransparencyLogError::InclusionPromise(detail).into()
    }
    pub(crate) fn entry_mismatch(detail: String) -> Self {
        TransparencyLogError::EntryMismatch(detail).into()
    }
    pub(crate) fn integrated_time(detail: String) -> Self {
        TransparencyLogError::IntegratedTime(detail).into()
    }
    pub(crate) fn malformed_entry(detail: String) -> Self {
        TransparencyLogError::MalformedEntry(detail).into()
    }
    pub(crate) fn timestamp_invalid(detail: String) -> Self {
        TimestampError::Invalid(detail).into()
    }
    pub(crate) fn no_verified_timestamp(detail: String) -> Self {
        TimestampError::NoVerifiedTimestamp(detail).into()
    }
}

fn display_opt(value: &Option<impl std::fmt::Display>) -> String {
    value
        .as_ref()
        .map_or_else(|| "none".to_string(), ToString::to_string)
}

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, Error>;
