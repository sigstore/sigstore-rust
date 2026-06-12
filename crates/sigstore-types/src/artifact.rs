//! Artifact types for signing and verification
//!
//! This module provides types for representing artifacts to be signed or verified.
//! Artifacts can be provided as raw bytes or as pre-computed digests, allowing
//! for efficient handling of large files without loading them entirely into memory.

use crate::{DigestBytes, Sha256Hash};
use std::borrow::Cow;

/// An artifact to be signed or verified
///
/// This enum allows flexible input for signing and verification operations:
/// - `Bytes`: Raw artifact bytes (hash will be computed internally)
/// - `Digest`: Pre-computed digest (no raw bytes needed)
///
/// The digest is stored as a [`Cow`] so it can either borrow from the caller
/// (zero-copy, the common case) or own its bytes when an owned value is
/// converted into an `Artifact` (e.g. `Artifact::from(some_sha256_hash)`).
///
/// # Example
///
/// ```
/// use sigstore_types::{Artifact, Sha256Hash};
///
/// // From raw bytes
/// let artifact = Artifact::from(b"hello world".as_slice());
///
/// // From a pre-computed digest (borrowed, zero-copy)
/// let digest = Sha256Hash::from_hex(
///     "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
/// ).unwrap();
/// let artifact = Artifact::from(&digest);
/// ```
#[derive(Debug, Clone)]
pub enum Artifact<'a> {
    /// Raw artifact bytes (hash will be computed)
    Bytes(&'a [u8]),
    /// Pre-computed digest bytes
    Digest(Cow<'a, [u8]>),
}

impl<'a> Artifact<'a> {
    /// Create an artifact from raw bytes
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Artifact::Bytes(bytes)
    }

    /// Create an artifact from a pre-computed digest (borrowed, zero-copy)
    pub fn from_digest(digest: &'a [u8]) -> Self {
        Artifact::Digest(Cow::Borrowed(digest))
    }

    /// Check if this artifact has raw bytes available
    pub fn has_bytes(&self) -> bool {
        matches!(self, Artifact::Bytes(_))
    }

    /// Get the raw bytes if available
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Artifact::Bytes(bytes) => Some(bytes),
            Artifact::Digest(_) => None,
        }
    }

    /// Get the pre-computed digest bytes if available
    pub fn pre_computed_digest(&self) -> Option<&[u8]> {
        match self {
            Artifact::Bytes(_) => None,
            Artifact::Digest(hash) => Some(hash.as_ref()),
        }
    }
}

impl<'a> From<&'a [u8]> for Artifact<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Artifact::Bytes(bytes)
    }
}

impl<'a> From<&'a Vec<u8>> for Artifact<'a> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        Artifact::Bytes(bytes.as_slice())
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Artifact<'a> {
    fn from(bytes: &'a [u8; N]) -> Self {
        Artifact::Bytes(bytes.as_slice())
    }
}

impl<'a> From<&'a Sha256Hash> for Artifact<'a> {
    fn from(hash: &'a Sha256Hash) -> Self {
        Artifact::Digest(Cow::Borrowed(hash.as_bytes()))
    }
}

impl<'a> From<&'a DigestBytes> for Artifact<'a> {
    fn from(digest: &'a DigestBytes) -> Self {
        Artifact::Digest(Cow::Borrowed(digest.as_bytes()))
    }
}

impl From<Sha256Hash> for Artifact<'static> {
    fn from(hash: Sha256Hash) -> Self {
        // Owned digest: copies the 32 bytes into the `Cow`. Prefer the
        // borrowing `From<&Sha256Hash>` when the hash outlives the `Artifact`.
        Artifact::Digest(Cow::Owned(hash.as_bytes().to_vec()))
    }
}

impl From<DigestBytes> for Artifact<'static> {
    fn from(digest: DigestBytes) -> Self {
        Artifact::Digest(Cow::Owned(digest.as_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_from_bytes() {
        let bytes = b"hello world";
        let artifact = Artifact::from(bytes.as_slice());
        assert!(artifact.has_bytes());
        assert_eq!(artifact.bytes(), Some(bytes.as_slice()));
    }

    #[test]
    fn test_artifact_from_digest() {
        let digest = Sha256Hash::from_hex(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .unwrap();
        let artifact = Artifact::from(digest);
        assert!(!artifact.has_bytes());
        assert_eq!(artifact.bytes(), None);
        assert_eq!(
            artifact.pre_computed_digest(),
            Some(digest.as_bytes().as_slice())
        );
    }

    #[test]
    fn test_artifact_from_digest_bytes() {
        let raw_bytes = vec![5u8; 32];
        let digest = DigestBytes::from_bytes(raw_bytes.clone());
        let artifact = Artifact::from(&digest);
        assert!(!artifact.has_bytes());
        assert_eq!(artifact.bytes(), None);
        assert_eq!(artifact.pre_computed_digest(), Some(raw_bytes.as_slice()));
    }
}
