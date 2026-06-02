//! Error types for the `sigstore-tuf` crate.

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while parsing or verifying TUF metadata.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The metadata could not be parsed as JSON.
    #[error("failed to parse JSON: {0}")]
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
        expires: String,
    },

    /// A length or hash recorded in a parent role did not match the child.
    #[error("integrity check failed for {0}: length or hash mismatch")]
    IntegrityMismatch(String),

    /// An expiry timestamp could not be parsed.
    #[error("invalid timestamp {value:?}: {source}")]
    InvalidTimestamp {
        /// The offending value.
        value: String,
        /// The underlying parse error.
        source: jiff::Error,
    },

    /// A signature blob was not valid hex.
    #[error("signature for key {key_id} is not valid hex: {source}")]
    InvalidSignatureEncoding {
        /// The key ID the signature was attributed to.
        key_id: String,
        /// The underlying decode error.
        source: hex::FromHexError,
    },

    /// An error originating from `sigstore-crypto`.
    #[error("crypto error: {0}")]
    Crypto(#[from] sigstore_crypto::Error),

    /// A transport-level error occurred while fetching metadata or targets.
    #[error("transport error: {0}")]
    Transport(String),
}
