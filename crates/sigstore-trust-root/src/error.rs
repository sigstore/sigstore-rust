//! Error types for trusted root operations

use sigstore_types::LogKeyId;
use thiserror::Error;

/// Errors that can occur during trusted root operations
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// JSON parsing error
    #[error("failed to parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Reading trust material from a file failed
    #[error("failed to read trust material: {0}")]
    Io(#[from] std::io::Error),

    /// Trust material contained an invalid encoding, key or checkpoint
    #[error(transparent)]
    Types(#[from] sigstore_types::Error),

    /// The document's media type is not one this crate reads.
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    /// The trusted root lists two transparency logs with the same log ID.
    #[error("duplicate transparency log ID: {log_id}")]
    DuplicateLogId {
        /// The repeated log ID
        log_id: LogKeyId,
    },

    /// No usable key for this log ID is in the trusted root.
    #[error("no matching key found for log ID {log_id}")]
    KeyNotFound {
        /// The requested log ID
        log_id: LogKeyId,
    },

    /// Fetching TUF metadata or a target failed at the transport level (for
    /// example a network error). Retrying may succeed.
    #[error("TUF transport error: {context}")]
    TufTransport {
        /// What was being fetched
        context: String,
        /// The underlying error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// TUF metadata or a target failed verification, or the TUF client
    /// configuration or cache cannot be used.
    #[error("TUF error: {context}")]
    Tuf {
        /// What failed
        context: String,
        /// The underlying error, if there is one
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl Error {
    /// A [`Error::Tuf`] without an underlying error.
    #[cfg(feature = "tuf")]
    pub(crate) fn tuf(context: impl Into<String>) -> Self {
        Self::Tuf {
            context: context.into(),
            source: None,
        }
    }

    /// A [`Error::Tuf`] caused by `source`.
    #[cfg(feature = "tuf")]
    pub(crate) fn tuf_caused_by(
        context: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Tuf {
            context: context.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Classify a `sigstore-tuf` error, keeping transport failures apart so
    /// callers can retry them.
    #[cfg(feature = "tuf")]
    pub(crate) fn from_tuf(context: impl Into<String>, error: sigstore_tuf::Error) -> Self {
        let context = context.into();
        match error {
            transport @ sigstore_tuf::Error::Transport { .. } => Self::TufTransport {
                context,
                source: Box::new(transport),
            },
            other => Self::tuf_caused_by(context, other),
        }
    }
}

/// Result type for trusted root operations
pub type Result<T> = std::result::Result<T, Error>;
