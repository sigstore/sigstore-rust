//! Error types for sigstore-tsa

use thiserror::Error;

/// Errors that can occur in TSA operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The TSA answered with a non-success HTTP status.
    #[error("TSA returned HTTP {status}: {message}")]
    Status {
        /// The HTTP status code
        status: u16,
        /// The status reason or response detail
        message: String,
    },

    /// The request could not be sent or the response could not be read
    /// (connection, TLS, timeout). Retrying may succeed.
    #[error("TSA request failed: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The TSA's response does not answer the request: this field differs.
    #[error("TSA response does not match the request: {field} differs")]
    ResponseMismatch {
        /// The mismatching field
        field: ResponseField,
    },

    /// The timestamp request was not granted; `status` is the RFC 3161
    /// `PKIStatus`.
    #[error("timestamp request not granted (status {status})")]
    NotGranted {
        /// The `PKIStatus` value
        status: u8,
    },

    /// The timestamp response carries no timestamp token.
    #[error("no timestamp token in response")]
    NoToken,

    /// The timestamp token carries no TSTInfo.
    #[error("no TSTInfo in timestamp token")]
    NoTstInfo,

    /// The message imprint in the token does not match the timestamped data.
    #[error("timestamp message hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The hex-encoded digest the token commits to
        expected: String,
        /// The hex-encoded digest computed locally
        actual: String,
    },

    /// The token's signature does not verify, or its signer cannot be
    /// determined.
    #[error("invalid timestamp signature: {0}")]
    SignatureInvalid(String),

    /// The TSA certificate does not chain to a trusted authority or is
    /// otherwise unacceptable.
    #[error("TSA certificate is invalid: {0}")]
    CertificateInvalid(String),

    /// The leaf certificate lacks the timeStamping extended key usage.
    #[error("leaf certificate does not have the timeStamping extended key usage")]
    MissingTimestampingEku,

    /// The hash algorithm has no RFC 3161 encoding here, or the token uses
    /// one this crate does not support.
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(String),

    /// The timestamp response or token could not be parsed.
    #[error("failed to parse timestamp response: {0}")]
    Parse(String),

    /// The token is authentic, but its signed time falls outside the
    /// validity window of the timestamp authority that signed it
    #[error(
        "timestamp {time} is outside the validity period of the timestamp authority that signed it"
    )]
    TimestampOutsideValidity {
        /// The authenticated signed time of the token
        time: jiff::Timestamp,
    },

    /// Any other failure, such as an internal encoding error.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// A field of a timestamp response that must echo the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResponseField {
    /// The message imprint's hash algorithm
    HashAlgorithm,
    /// The message imprint's digest
    MessageImprint,
    /// The request nonce
    Nonce,
}

impl std::fmt::Display for ResponseField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::HashAlgorithm => "hash algorithm",
            Self::MessageImprint => "message imprint",
            Self::Nonce => "nonce",
        })
    }
}

/// Result type for TSA operations
pub type Result<T> = std::result::Result<T, Error>;
