//! Artifact inputs for signing and verification.

use crate::{DigestBytes, Error, HashAlgorithm, Sha256Hash};

/// A typed, pre-computed artifact digest.
///
/// Carrying the algorithm with the bytes prevents a SHA-384 or SHA-512 value
/// from being silently interpreted as SHA-256 (or vice versa).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDigest {
    algorithm: HashAlgorithm,
    value: DigestBytes,
}

impl ArtifactDigest {
    /// Construct a digest and validate that its length matches `algorithm`.
    pub fn new(algorithm: HashAlgorithm, value: impl Into<DigestBytes>) -> Result<Self, Error> {
        let value = value.into();
        if value.as_bytes().len() != algorithm.digest_size() {
            return Err(Error::Validation(format!(
                "{} digest must be {} bytes, got {}",
                algorithm,
                algorithm.digest_size(),
                value.as_bytes().len()
            )));
        }
        Ok(Self { algorithm, value })
    }

    /// Construct a SHA-256 artifact digest.
    pub fn sha256(value: Sha256Hash) -> Self {
        Self {
            algorithm: HashAlgorithm::Sha2256,
            value: value.into(),
        }
    }

    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn value(&self) -> &DigestBytes {
        &self.value
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

impl From<Sha256Hash> for ArtifactDigest {
    fn from(value: Sha256Hash) -> Self {
        Self::sha256(value)
    }
}

impl From<&Sha256Hash> for ArtifactDigest {
    fn from(value: &Sha256Hash) -> Self {
        Self::sha256(*value)
    }
}

/// Material supplied as the subject of signing or verification.
#[derive(Debug, Clone)]
pub enum Artifact<'a> {
    /// Complete artifact bytes.
    Blob(&'a [u8]),
    /// A typed pre-computed digest. The original bytes are unavailable.
    Digest(ArtifactDigest),
}

impl<'a> Artifact<'a> {
    pub fn from_blob(blob: &'a [u8]) -> Self {
        Self::Blob(blob)
    }

    pub fn from_digest(digest: impl Into<ArtifactDigest>) -> Self {
        Self::Digest(digest.into())
    }

    pub fn blob(&self) -> Option<&[u8]> {
        match self {
            Self::Blob(blob) => Some(blob),
            Self::Digest(_) => None,
        }
    }

    pub fn digest(&self) -> Option<&ArtifactDigest> {
        match self {
            Self::Blob(_) => None,
            Self::Digest(digest) => Some(digest),
        }
    }
}

impl<'a> From<&'a [u8]> for Artifact<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Blob(value)
    }
}

impl<'a> From<&'a Vec<u8>> for Artifact<'a> {
    fn from(value: &'a Vec<u8>) -> Self {
        Self::Blob(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Artifact<'a> {
    fn from(value: &'a [u8; N]) -> Self {
        Self::Blob(value)
    }
}

impl From<ArtifactDigest> for Artifact<'static> {
    fn from(value: ArtifactDigest) -> Self {
        Self::Digest(value)
    }
}

impl From<Sha256Hash> for Artifact<'static> {
    fn from(value: Sha256Hash) -> Self {
        Self::Digest(value.into())
    }
}

impl From<&Sha256Hash> for Artifact<'static> {
    fn from(value: &Sha256Hash) -> Self {
        Self::Digest(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_rejects_wrong_length() {
        assert!(ArtifactDigest::new(HashAlgorithm::Sha2384, &[0_u8; 32][..]).is_err());
    }

    #[test]
    fn sha256_conversion_is_typed() {
        let hash = Sha256Hash::from_bytes([7; 32]);
        let artifact = Artifact::from(hash);
        let digest = artifact.digest().unwrap();
        assert_eq!(digest.algorithm(), HashAlgorithm::Sha2256);
        assert_eq!(digest.as_bytes(), hash.as_bytes());
    }
}
