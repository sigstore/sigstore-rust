//! Hash algorithm types and utilities

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Supported hash algorithms
///
/// This enum supports multiple serialization formats for compatibility:
/// - Sigstore bundle format: "SHA2_256", "SHA2_384", "SHA2_512"
/// - Rekor API format: "sha256", "sha384", "sha512"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA2-256
    Sha2256,
    /// SHA2-384
    Sha2384,
    /// SHA2-512
    Sha2512,
}

impl HashAlgorithm {
    /// Get the digest size in bytes for this algorithm
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha2256 => 32,
            HashAlgorithm::Sha2384 => 48,
            HashAlgorithm::Sha2512 => 64,
        }
    }

    /// The name used by the Rekor API (`sha256`, `sha384`, `sha512`)
    pub fn as_rekor_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha2256 => "sha256",
            HashAlgorithm::Sha2384 => "sha384",
            HashAlgorithm::Sha2512 => "sha512",
        }
    }
}

impl std::str::FromStr for HashAlgorithm {
    type Err = crate::Error;

    /// Parse the protobuf-specs (`SHA2_256`), Rekor (`sha256`) or
    /// hyphenated (`sha-256`) spelling, case-insensitively.
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "sha256" | "sha2_256" | "sha-256" => Ok(HashAlgorithm::Sha2256),
            "sha384" | "sha2_384" | "sha-384" => Ok(HashAlgorithm::Sha2384),
            "sha512" | "sha2_512" | "sha-512" => Ok(HashAlgorithm::Sha2512),
            _ => Err(crate::Error::InvalidHashAlgorithm(s.to_string())),
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha2256 => write!(f, "SHA2_256"),
            HashAlgorithm::Sha2384 => write!(f, "SHA2_384"),
            HashAlgorithm::Sha2512 => write!(f, "SHA2_512"),
        }
    }
}

impl Serialize for HashAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize to the canonical Sigstore format
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<HashAlgorithm>().map_err(serde::de::Error::custom)
    }
}
