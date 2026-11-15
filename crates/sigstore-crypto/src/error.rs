//! Error types for sigstore-crypto

use crate::signing::SigningScheme;
use sigstore_types::Sha256Hash;
use thiserror::Error;

/// Errors that can occur in cryptographic operations
///
/// Custom [`CryptoProvider`](crate::CryptoProvider)s construct these too, so
/// the variants keep public fields.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Key generation failed in the cryptographic backend.
    #[error("key generation error: {0}")]
    KeyGeneration(String),

    /// Signing failed in the cryptographic backend.
    #[error("signing error: {0}")]
    Signing(String),

    /// The signature does not verify with the key under this scheme.
    #[error("{} signature invalid", scheme.name())]
    SignatureInvalid {
        /// The scheme the signature was checked under
        scheme: SigningScheme,
    },

    /// A prehashed digest has the wrong length for the scheme's hash.
    #[error("{} needs a {expected}-byte digest, got {actual} bytes", scheme.name())]
    DigestLength {
        /// The scheme the digest was supplied for
        scheme: SigningScheme,
        /// The length of the scheme's hash output
        expected: usize,
        /// The length supplied
        actual: usize,
    },

    /// No key with this ID is in the keyring.
    #[error("key not found: {}", key_id.to_hex())]
    KeyNotFound {
        /// The requested key ID
        key_id: Sha256Hash,
    },

    /// The keyring holds a key with this ID, but it was not valid at `time`.
    #[error("key {} is not valid at {time}", key_id.to_hex())]
    KeyNotValidAt {
        /// The requested key ID
        key_id: Sha256Hash,
        /// The time the key had to be valid at
        time: jiff::Timestamp,
    },

    /// No key in the keyring verified the signature.
    #[error("no key in the keyring verified the signature")]
    NoKeyVerified,

    /// No signature on the checkpoint carries the key's hint.
    #[error("no checkpoint signature matches the key")]
    CheckpointKeyNotFound,

    /// A private key is not in the expected format.
    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// The algorithm, curve or scheme is well formed but not supported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// A certificate could not be parsed.
    #[error("certificate error: {0}")]
    InvalidCertificate(String),

    /// A public key is malformed.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Any other failure, such as an internal encoding error.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    /// An [`Error::Other`] wrapping `source`.
    pub(crate) fn other(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Other(Box::new(source))
    }
}

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, Error>;
