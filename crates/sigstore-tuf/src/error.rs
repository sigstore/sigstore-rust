//! Error types for the `sigstore-tuf` crate.

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while parsing or verifying TUF metadata.
///
/// An error's [`Display`](std::fmt::Display) output describes only that error;
/// an underlying cause is never repeated there and is available through
/// [`Error::source`](std::error::Error::source) instead. Walk the source chain
/// to render the full story.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The metadata could not be parsed as JSON.
    #[error("failed to parse JSON")]
    Json(#[from] serde_json::Error),

    /// The JSON did not have the structure expected for a signed metadata file.
    #[error("malformed metadata: {0}")]
    Malformed(String),

    /// A value that must be an integer (per TUF canonical JSON rules) was a
    /// float or otherwise out of range.
    #[error("canonical JSON only supports integers, found a non-integer number")]
    NonIntegerNumber,

    /// A key declared in the metadata could not be turned into a usable
    /// verification key.
    #[error("unusable key {key_id}: {reason}")]
    UnusableKey {
        /// The declared key ID.
        key_id: String,
        /// Why the key could not be used.
        reason: String,
    },

    /// A key referenced a `keytype`/`scheme` combination we do not support yet.
    #[error("unsupported key scheme: keytype={keytype:?} scheme={scheme:?}")]
    UnsupportedScheme {
        /// The TUF `keytype`.
        keytype: String,
        /// The TUF `scheme`.
        scheme: String,
    },

    /// The metadata referenced a role that is not present in the trusted root.
    #[error("unknown role: {0}")]
    UnknownRole(String),

    /// A role's signatures referenced the same key ID more than once. Per the
    /// TUF spec this is invalid regardless of threshold (matching python-tuf).
    #[error("duplicate signature key id {key_id} for role {role}")]
    DuplicateSignature {
        /// The role being verified.
        role: String,
        /// The key ID that appeared more than once.
        key_id: String,
    },

    /// Fewer valid signatures than the role's threshold were found.
    #[error("signature threshold not met for role {role}: {found}/{threshold} valid signatures")]
    ThresholdNotMet {
        /// The role being verified.
        role: String,
        /// How many distinct, valid signatures were found.
        found: usize,
        /// The required threshold.
        threshold: usize,
    },

    /// The metadata's version number went backwards (rollback attack).
    #[error("rollback detected for {role}: trusted version {trusted} > new version {new}")]
    Rollback {
        /// The role being updated.
        role: String,
        /// The currently trusted version.
        trusted: u64,
        /// The (lower) version that was offered.
        new: u64,
    },

    /// A candidate's version equals the trusted version, so it carries no
    /// update. Not a fault — callers discard the candidate and keep what they
    /// have (used for the timestamp role per the TUF workflow).
    #[error("{role} version {version} equals the trusted version; no update")]
    EqualVersion {
        /// The role being updated.
        role: String,
        /// The (equal) version.
        version: u64,
    },

    /// A new root's version was not exactly one greater than the trusted root.
    #[error("root version must increment by one: trusted {trusted}, got {new}")]
    BadRootVersion {
        /// The currently trusted root version.
        trusted: u64,
        /// The offered root version.
        new: u64,
    },

    /// The metadata has expired.
    #[error("{role} metadata expired at {expires}")]
    Expired {
        /// The role whose metadata expired.
        role: String,
        /// The declared expiry timestamp.
        expires: jiff::Timestamp,
    },

    /// A length or hash recorded in a parent role did not match the child.
    #[error("integrity check failed: {0}")]
    IntegrityMismatch(String),

    /// An error originating from `sigstore-crypto`.
    #[error("crypto error")]
    Crypto(#[from] sigstore_crypto::Error),

    /// [`Updater::refresh`](crate::Updater::refresh) has not completed, so
    /// there is no trusted targets metadata to resolve targets against.
    #[error("no trusted targets metadata; refresh() must succeed first")]
    NotRefreshed,

    /// No trusted targets role lists the requested target.
    #[error("target {0:?} is not listed by any trusted targets role")]
    TargetNotFound(String),

    /// Reading or writing a [`MetadataStore`](crate::MetadataStore) failed.
    #[error("{context}")]
    Io {
        /// What was being done, e.g. which file was written.
        context: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A transport-level error occurred while fetching metadata or targets.
    #[error("transport error: {message}")]
    Transport {
        /// What failed.
        message: String,
        /// The underlying error, if there is one.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl Error {
    /// A [`Error::Transport`] with no underlying error, for use by
    /// [`Repository`](crate::Repository) implementations.
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
            source: None,
        }
    }

    /// A [`Error::Transport`] caused by `source`, for use by
    /// [`Repository`](crate::Repository) implementations.
    pub fn transport_with_source(
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Transport {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// A [`Error::Io`] caused by `source`, for use by
    /// [`MetadataStore`](crate::MetadataStore) implementations.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

/// Displays an error followed by each of its [sources](std::error::Error::source),
/// separated by `": "`.
pub(crate) struct DisplayChain<'a>(pub(crate) &'a dyn std::error::Error);

impl std::fmt::Display for DisplayChain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(cause) = source {
            write!(f, ": {cause}")?;
            source = cause.source();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_chain_renders_each_cause_once() {
        let err = Error::io(
            "reading /tmp/timestamp.json",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
        );
        assert_eq!(err.to_string(), "reading /tmp/timestamp.json");
        assert_eq!(
            DisplayChain(&err).to_string(),
            "reading /tmp/timestamp.json: permission denied"
        );

        let err = Error::transport_with_source("fetching root.json", "connection refused");
        assert_eq!(
            DisplayChain(&err).to_string(),
            "transport error: fetching root.json: connection refused"
        );
    }
}
