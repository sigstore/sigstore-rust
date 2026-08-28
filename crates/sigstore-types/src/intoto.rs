//! In-toto attestation types
//!
//! In-toto provides a framework for securing software supply chain integrity.
//! This module defines types for in-toto attestation statements, commonly used
//! with DSSE envelopes in Sigstore.
//!
//! Specification: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>

use crate::{Sha256Hash, Sha512Hash};
use serde::{Deserialize, Serialize};

/// In-toto Statement v1
///
/// An in-toto statement is a generic attestation format that binds a predicate
/// to a set of subjects (artifacts). It's commonly used for SLSA provenance,
/// vulnerability scans, and other supply chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statement {
    /// Type identifier for the statement (typically "<https://in-toto.io/Statement/v1>")
    #[serde(rename = "_type")]
    pub type_: String,
    /// Subjects (artifacts) being attested about
    pub subject: Vec<Subject>,
    /// Type of the predicate (e.g., "<https://slsa.dev/provenance/v1>")
    pub predicate_type: String,
    /// The actual attestation content (format depends on predicate_type)
    pub predicate: serde_json::Value,
}

/// Subject of an in-toto statement
///
/// A subject represents an artifact being attested about, identified by
/// its name and cryptographic digest(s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Name of the artifact (e.g., file name, package name).
    /// Defaults to empty string when omitted (cosign v3 omits this for container signing).
    #[serde(default)]
    pub name: String,
    /// Cryptographic digest(s) of the artifact
    pub digest: Digest,
}

/// Digest for a subject
///
/// Contains one or more cryptographic hashes of the artifact.
/// At minimum, sha256 should be provided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Digest {
    /// SHA-256 hash (hex-encoded)
    #[serde(
        default,
        with = "option_hex_sha256",
        skip_serializing_if = "Option::is_none"
    )]
    pub sha256: Option<Sha256Hash>,
    /// SHA-512 hash (hex-encoded)
    #[serde(
        default,
        with = "option_hex_sha512",
        skip_serializing_if = "Option::is_none"
    )]
    pub sha512: Option<Sha512Hash>,
    /// Additional in-toto digest algorithms, preserved without interpretation.
    ///
    /// The in-toto digest map is extensible. Algorithms understood by this
    /// crate are parsed into fixed-size semantic values above; other entries
    /// remain available for lossless round trips.
    #[serde(flatten)]
    pub other: std::collections::BTreeMap<String, String>,
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireDigest {
            #[serde(default, with = "option_hex_sha256")]
            sha256: Option<Sha256Hash>,
            #[serde(default, with = "option_hex_sha512")]
            sha512: Option<Sha512Hash>,
            #[serde(flatten)]
            other: std::collections::BTreeMap<String, String>,
        }

        let wire = WireDigest::deserialize(deserializer)?;
        if wire.sha256.is_none() && wire.sha512.is_none() && wire.other.is_empty() {
            return Err(serde::de::Error::custom(
                "subject digest must contain at least one algorithm",
            ));
        }
        Ok(Self {
            sha256: wire.sha256,
            sha512: wire.sha512,
            other: wire.other,
        })
    }
}

impl Statement {
    /// Check if any subject in the statement matches the given SHA-256 hash
    pub fn matches_sha256(&self, hash: &Sha256Hash) -> bool {
        self.subject
            .iter()
            .any(|subject| subject.digest.sha256.as_ref() == Some(hash))
    }

    /// Check if any subject in the statement matches the given SHA-512 hash
    pub fn matches_sha512(&self, hash: &Sha512Hash) -> bool {
        self.subject
            .iter()
            .any(|subject| subject.digest.sha512.as_ref() == Some(hash))
    }
}

macro_rules! option_hex_digest {
    ($module:ident, $type:ty) => {
        mod $module {
            use super::*;
            use serde::{Deserializer, Serializer};

            pub fn serialize<S>(value: &Option<$type>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                value.as_ref().map(<$type>::to_hex).serialize(serializer)
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<$type>, D::Error>
            where
                D: Deserializer<'de>,
            {
                Option::<String>::deserialize(deserializer)?
                    .map(|value| <$type>::from_hex(&value).map_err(serde::de::Error::custom))
                    .transpose()
            }
        }
    };
}

option_hex_digest!(option_hex_sha256, Sha256Hash);
option_hex_digest!(option_hex_sha512, Sha512Hash);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statement_deserialization() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": "example.txt",
                "digest": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }"#;

        let statement: Statement = serde_json::from_str(json).unwrap();
        assert_eq!(statement.type_, "https://in-toto.io/Statement/v1");
        assert_eq!(statement.subject[0].name, "example.txt");
        assert_eq!(
            statement.subject[0].digest.sha256,
            Some(Sha256Hash::from_bytes([0; 32]))
        );
    }

    #[test]
    fn test_matches_typed_digests() {
        let sha256_1 = Sha256Hash::from_bytes([1; 32]);
        let sha256_2 = Sha256Hash::from_bytes([2; 32]);
        let sha256_3 = Sha256Hash::from_bytes([3; 32]);
        let sha512_1 = Sha512Hash::from_bytes([1; 64]);
        let sha512_2 = Sha512Hash::from_bytes([2; 64]);
        let statement = Statement {
            type_: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![
                Subject {
                    name: "file1.txt".to_string(),
                    digest: Digest {
                        sha256: Some(sha256_1),
                        sha512: Some(sha512_1),
                        other: Default::default(),
                    },
                },
                Subject {
                    name: "file2.txt".to_string(),
                    digest: Digest {
                        sha256: Some(sha256_2),
                        sha512: None,
                        other: Default::default(),
                    },
                },
            ],
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate: serde_json::json!({}),
        };

        assert!(statement.matches_sha256(&sha256_1));
        assert!(statement.matches_sha256(&sha256_2));
        assert!(!statement.matches_sha256(&sha256_3));
        assert!(statement.matches_sha512(&sha512_1));
        assert!(!statement.matches_sha512(&sha512_2));
    }

    #[test]
    fn test_subject_missing_name() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"digest": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}}],
            "predicateType": "https://sigstore.dev/cosign/sign/v1",
            "predicate": {}
        }"#;
        let statement: Statement = serde_json::from_str(json).unwrap();
        assert_eq!(statement.subject[0].name, "");
        assert_eq!(
            statement.subject[0].digest.sha256,
            Some(Sha256Hash::from_bytes([0; 32]))
        );
    }

    #[test]
    fn malformed_subject_digest_is_rejected() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"digest": {"sha256": "abc123"}}],
            "predicateType": "https://sigstore.dev/cosign/sign/v1",
            "predicate": {}
        }"#;
        assert!(serde_json::from_str::<Statement>(json).is_err());
    }

    #[test]
    fn additional_subject_digest_is_preserved_instead_of_discarded() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"digest": {"sha384": "00"}}],
            "predicateType": "https://sigstore.dev/cosign/sign/v1",
            "predicate": {}
        }"#;
        let statement = serde_json::from_str::<Statement>(json).unwrap();
        assert_eq!(statement.subject[0].digest.other["sha384"], "00");
        let serialized = serde_json::to_value(statement).unwrap();
        assert_eq!(serialized["subject"][0]["digest"]["sha384"], "00");
    }

    #[test]
    fn empty_subject_digest_is_rejected() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"digest": {}}],
            "predicateType": "https://sigstore.dev/cosign/sign/v1",
            "predicate": {}
        }"#;
        assert!(serde_json::from_str::<Statement>(json).is_err());
    }
}
