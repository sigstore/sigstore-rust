//! Error types for sigstore-types

use thiserror::Error;

/// Errors that can occur in sigstore-types
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The value is not a known bundle media type.
    #[error("invalid media type: {0}")]
    InvalidMediaType(String),

    /// The checkpoint (signed note) is malformed; the payload says how.
    #[error("invalid checkpoint format: {0}")]
    InvalidCheckpoint(String),

    /// The value is not a known hash algorithm name.
    #[error("invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),

    /// A value has the wrong length in bytes.
    #[error("{what} must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// What was being built, e.g. `"SHA-256 hash"`
        what: &'static str,
        /// The required length
        expected: usize,
        /// The supplied length
        actual: usize,
    },

    /// A log index is negative, does not fit a protobuf `int64`, or is not a
    /// number. The payload is the offending value.
    #[error("invalid log index {0}: must be an integer in 0..=9223372036854775807")]
    InvalidLogIndex(String),

    /// Text could not be decoded from the given encoding.
    #[error("invalid {encoding}: {source}")]
    InvalidEncoding {
        /// The encoding that failed to decode
        encoding: Encoding,
        /// The decoder's error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A PEM block has a different label than required.
    #[error("expected a {expected} PEM block, got {actual}")]
    UnexpectedPemLabel {
        /// The required label, e.g. `"CERTIFICATE"`
        expected: &'static str,
        /// The label found
        actual: String,
    },
}

/// A text encoding of binary data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Encoding {
    /// Hexadecimal
    Hex,
    /// Base64 (standard or URL-safe alphabet)
    Base64,
    /// PEM
    Pem,
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Hex => "hex",
            Self::Base64 => "base64",
            Self::Pem => "PEM",
        })
    }
}

impl Error {
    /// An [`Error::InvalidEncoding`] for `encoding` caused by `source`.
    pub(crate) fn encoding(
        encoding: Encoding,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::InvalidEncoding {
            encoding,
            source: Box::new(source),
        }
    }
}

/// Result type for sigstore-types operations
pub type Result<T> = std::result::Result<T, Error>;
