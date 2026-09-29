//! Rekor log entry types

use crate::hex_encoded::HexLogId;
use serde::{Deserialize, Serialize};
use sigstore_types::{
    CanonicalizedBody, DerCertificate, DerPublicKey, EntryUuid, HashAlgorithm, LogIndex,
    PemContent, Sha256Hash, SignatureBytes, SignedTimestamp,
};

/// Rekor API version
///
/// The version determines the entry formats and the API, not the log URL:
/// v1 and v2 logs are separate services, and a Sigstore instance publishes
/// the URLs of its logs in its signing config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum RekorApiVersion {
    /// V1 API - uses hashedrekord 0.0.1 and dsse 0.0.1
    #[default]
    V1,
    /// V2 API - uses hashedrekord 0.0.2 for both artifacts and DSSE envelopes.
    /// Returns inclusion proofs with checkpoints and requires RFC 3161 timestamps.
    V2,
}

impl RekorApiVersion {
    /// The major API version number, as used in signing configs.
    pub fn major(self) -> u32 {
        match self {
            RekorApiVersion::V1 => 1,
            RekorApiVersion::V2 => 2,
        }
    }

    /// The API version for a major version number, if supported.
    pub fn from_major(major: u32) -> Option<Self> {
        match major {
            1 => Some(RekorApiVersion::V1),
            2 => Some(RekorApiVersion::V2),
            _ => None,
        }
    }
}

/// A log entry from Rekor
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LogEntry {
    /// UUID of the entry (the key in the response map)
    #[serde(skip)]
    pub uuid: EntryUuid,
    /// Canonicalized JSON body of the entry.
    pub body: CanonicalizedBody,
    /// Integrated time reported by the Rekor v1 API. `None` if the response
    /// omits it.
    #[serde(
        default,
        with = "jiff::fmt::serde::timestamp::second::optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub integrated_time: Option<jiff::Timestamp>,
    /// Log ID (hex-encoded SHA-256 of the log's public key)
    #[serde(rename = "logID")]
    pub log_id: HexLogId,
    /// Log index (rejected while parsing if it does not fit a protobuf `int64`)
    pub log_index: LogIndex,
    /// Verification data
    #[serde(default)]
    pub verification: Option<Verification>,
}

impl LogEntry {
    /// Convert a Rekor response into bundle verification material.
    ///
    /// Checks that the checkpoint parses; log indices are already range-checked
    /// by their type. This is format conversion, not cryptographic
    /// verification of the log entry.
    pub fn to_bundle_entry(
        &self,
        kind_version: sigstore_types::KindVersion,
    ) -> sigstore_types::Result<sigstore_types::TransparencyLogEntry> {
        use sigstore_types::{
            bundle::CheckpointData, InclusionPromise, InclusionProof, LogId, TransparencyLogEntry,
        };
        let mut entry = TransparencyLogEntry::new(
            self.log_index,
            LogId::new(self.log_id.to_log_key_id()?),
            kind_version,
            self.body.clone(),
        );
        entry.integrated_time = self.integrated_time;
        if let Some(verification) = &self.verification {
            entry.inclusion_promise = verification
                .signed_entry_timestamp
                .as_ref()
                .map(|set| InclusionPromise::new(set.clone()));
            if let Some(proof) = &verification.inclusion_proof {
                entry.inclusion_proof = Some(InclusionProof::new(
                    proof.log_index,
                    proof.root_hash,
                    proof.tree_size,
                    proof.hashes.clone(),
                    CheckpointData::new(proof.checkpoint.clone())?,
                ));
            }
        }
        Ok(entry)
    }
}

/// Verification data for a log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Verification {
    /// Inclusion proof
    #[serde(default)]
    pub inclusion_proof: Option<RekorInclusionProof>,
    /// Signed entry timestamp (SET)
    #[serde(default)]
    pub signed_entry_timestamp: Option<SignedTimestamp>,
}

/// Inclusion proof from the Rekor V1 API.
///
/// This mirrors the V1 response, where hashes are hex-encoded and the
/// checkpoint is unparsed text. [`LogEntry::to_bundle_entry`] converts it to
/// the bundle's `sigstore_types::InclusionProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RekorInclusionProof {
    /// Checkpoint (signed tree head)
    pub checkpoint: String,
    /// Hashes in the proof path (hex-encoded in V1 API)
    #[serde(with = "hex_sha256_vec")]
    pub hashes: Vec<Sha256Hash>,
    /// Log index
    pub log_index: LogIndex,
    /// Root hash (hex-encoded in V1 API)
    #[serde(with = "hex_sha256")]
    pub root_hash: Sha256Hash,
    /// Tree size
    pub tree_size: u64,
}

mod hex_sha256 {
    use serde::{Deserialize, Deserializer, Serializer};
    use sigstore_types::Sha256Hash;

    pub fn serialize<S>(value: &Sha256Hash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_hex())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Sha256Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Sha256Hash::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

mod hex_sha256_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use sigstore_types::Sha256Hash;

    pub fn serialize<S>(values: &[Sha256Hash], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        values
            .iter()
            .map(Sha256Hash::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Sha256Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| Sha256Hash::from_hex(&value).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// A query against the Rekor v1 search index.
///
/// Build one with [`SearchIndex::sha256`] or [`SearchIndex::email`] and pass
/// it to `RekorClient::search_index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchIndex {
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
}

impl SearchIndex {
    /// Find entries of an artifact by its SHA-256 digest.
    pub fn sha256(hash: &Sha256Hash) -> Self {
        Self {
            email: None,
            hash: Some(format!("sha256:{}", hash.to_hex())),
        }
    }

    /// Find entries whose signing certificate carries this email identity.
    pub fn email(email: impl Into<String>) -> Self {
        Self {
            email: Some(email.into()),
            hash: None,
        }
    }
}

/// DSSE entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEntry {
    pub(crate) api_version: String,
    pub(crate) kind: String,
    pub(crate) spec: DsseEntrySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DsseEntrySpec {
    /// Proposed content - when present, signatures should NOT be included
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proposed_content: Option<DsseProposedContent>,
    /// Signatures - only used when proposedContent is NOT present
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) signatures: Vec<DsseEntrySignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DsseProposedContent {
    pub(crate) envelope: String,
    pub(crate) verifiers: Vec<String>,
}

/// Signature entry in a Rekor DSSE entry.
///
/// Note: This is different from `sigstore_types::DsseSignature` which represents
/// signatures in the DSSE envelope format itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DsseEntrySignature {
    pub(crate) signature: String,
    pub(crate) verifier: String,
}

impl DsseEntry {
    /// Create a new DSSE entry from an envelope and certificate
    ///
    /// Uses the `proposedContent` mode where the envelope contains the signatures.
    /// The Rekor server will extract and verify the signatures from the envelope.
    ///
    /// # Arguments
    /// * `envelope` - The DSSE envelope containing signatures
    /// * `certificate` - DER-encoded X.509 certificate from Fulcio
    ///
    /// # Errors
    /// Returns [`Error::Json`](crate::Error::Json) if the envelope cannot be
    /// serialized.
    pub fn new(
        envelope: &sigstore_types::DsseEnvelope,
        certificate: &DerCertificate,
    ) -> crate::Result<Self> {
        use base64::Engine;

        // Serialize envelope to JSON (Rekor expects JSON string, not base64)
        let envelope_json = serde_json::to_string(envelope)?;

        // Rekor API expects the PEM to be base64-encoded
        let cert_pem = certificate.to_pem();
        let cert_base64 = base64::engine::general_purpose::STANDARD.encode(&cert_pem);

        // When using proposedContent, do NOT include signatures separately -
        // they are extracted from the envelope by the Rekor server
        Ok(Self {
            api_version: "0.0.1".to_string(),
            kind: "dsse".to_string(),
            spec: DsseEntrySpec {
                proposed_content: Some(DsseProposedContent {
                    envelope: envelope_json,
                    verifiers: vec![cert_base64],
                }),
                signatures: vec![],
            },
        })
    }
}

/// HashedRekord entry for creating new log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekord {
    /// API version
    #[serde(rename = "apiVersion")]
    pub(crate) api_version: String,
    /// Entry kind
    pub(crate) kind: String,
    /// Spec containing the actual data
    pub(crate) spec: HashedRekordSpec,
}

/// HashedRekord specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordSpec {
    /// Data containing the hash
    pub(crate) data: HashedRekordData,
    /// Signature
    pub(crate) signature: HashedRekordSignature,
}

/// Data portion of HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordData {
    /// Hash of the artifact
    pub(crate) hash: HashedRekordHash,
}

/// Serde helper for lowercase hash algorithm serialization (for Rekor API)
///
/// Use this with `#[serde(with = "rekor_hash_algorithm")]` on `HashAlgorithm`
/// fields that need to serialize as "sha256" instead of "SHA2_256".
mod rekor_hash_algorithm {
    use serde::{Deserialize, Deserializer, Serializer};
    use sigstore_types::HashAlgorithm;

    pub fn serialize<S>(algo: &HashAlgorithm, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(algo.as_rekor_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashAlgorithm, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<HashAlgorithm>().map_err(serde::de::Error::custom)
    }
}

/// Hash in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordHash {
    /// Hash algorithm (serializes as lowercase for Rekor API)
    #[serde(with = "rekor_hash_algorithm")]
    pub(crate) algorithm: HashAlgorithm,
    /// Hash value (hex encoded)
    pub(crate) value: String,
}

/// Signature in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordSignature {
    /// Signature content (base64 encoded)
    pub(crate) content: SignatureBytes,
    /// Public key
    #[serde(rename = "publicKey")]
    pub(crate) public_key: HashedRekordPublicKey,
}

/// Public key in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordPublicKey {
    /// PEM-encoded public key or certificate (base64-encoded PEM)
    pub(crate) content: PemContent,
}

impl HashedRekord {
    /// Create a new HashedRekord entry with a certificate
    ///
    /// The certificate (obtained from Fulcio) contains the identity binding that
    /// verifiers need to validate.
    ///
    /// # Arguments
    /// * `artifact_hash` - SHA256 hash of the artifact
    /// * `signature` - Signature bytes
    /// * `certificate` - DER-encoded X.509 certificate from Fulcio
    pub fn new(
        artifact_hash: &Sha256Hash,
        signature: &SignatureBytes,
        certificate: &DerCertificate,
    ) -> Self {
        // Convert DER to PEM for Rekor V1 API
        let cert_pem = certificate.to_pem();

        Self {
            api_version: "0.0.1".to_string(),
            kind: "hashedrekord".to_string(),
            spec: HashedRekordSpec {
                data: HashedRekordData {
                    hash: HashedRekordHash {
                        algorithm: HashAlgorithm::Sha2256,
                        value: artifact_hash.to_hex(),
                    },
                },
                signature: HashedRekordSignature {
                    content: signature.clone(),
                    public_key: HashedRekordPublicKey {
                        content: PemContent::new(cert_pem.into_bytes()),
                    },
                },
            },
        }
    }
}

/// HashedRekord entry for creating new log entries (V2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV2 {
    #[serde(rename = "hashedRekordRequestV002")]
    pub(crate) request: HashedRekordRequestV002,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordRequestV002 {
    pub(crate) digest: Sha256Hash,
    pub(crate) signature: HashedRekordSignatureV2,
}

/// Signature in HashedRekord V2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordSignatureV2 {
    /// Signature content
    pub(crate) content: SignatureBytes,
    /// Verifier
    pub(crate) verifier: HashedRekordVerifierV2,
}

/// Signature algorithms accepted by the Rekor v2 hashedrekord service.
///
/// The current request API accepts a SHA-256 digest, so it exposes only the
/// matching algorithm. Supporting additional algorithms requires carrying
/// their SHA-384 or SHA-512 digests instead of merely changing this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RekorV2KeyDetails {
    #[serde(rename = "PKIX_ECDSA_P256_SHA_256")]
    PkixEcdsaP256Sha256,
}

/// Verifier in a Rekor v2 hashedrekord request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HashedRekordVerifierV2 {
    pub(crate) key_details: RekorV2KeyDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<HashedRekordCertificateV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_key: Option<HashedRekordPublicKeyV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordCertificateV2 {
    #[serde(rename = "rawBytes")]
    pub(crate) content: DerCertificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HashedRekordPublicKeyV2 {
    #[serde(rename = "rawBytes")]
    pub(crate) content: DerPublicKey,
}

impl HashedRekordV2 {
    /// Create a request authenticated by an X.509 certificate.
    pub fn new_with_certificate(
        artifact_hash: &Sha256Hash,
        signature: &SignatureBytes,
        certificate: &DerCertificate,
        key_details: RekorV2KeyDetails,
    ) -> Self {
        Self::new(
            artifact_hash,
            signature,
            HashedRekordVerifierV2 {
                key_details,
                x509_certificate: Some(HashedRekordCertificateV2 {
                    content: certificate.clone(),
                }),
                public_key: None,
            },
        )
    }

    /// Create a request authenticated by a self-managed public key.
    pub fn new_with_public_key(
        artifact_hash: &Sha256Hash,
        signature: &SignatureBytes,
        public_key: &DerPublicKey,
        key_details: RekorV2KeyDetails,
    ) -> Self {
        Self::new(
            artifact_hash,
            signature,
            HashedRekordVerifierV2 {
                key_details,
                x509_certificate: None,
                public_key: Some(HashedRekordPublicKeyV2 {
                    content: public_key.clone(),
                }),
            },
        )
    }

    fn new(
        artifact_hash: &Sha256Hash,
        signature: &SignatureBytes,
        verifier: HashedRekordVerifierV2,
    ) -> Self {
        Self {
            request: HashedRekordRequestV002 {
                digest: *artifact_hash,
                signature: HashedRekordSignatureV2 {
                    content: signature.clone(),
                    verifier,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_bundle_conversion_preserves_fields() {
        let json = r#"{"body":"e30=","integratedTime":0,"logID":"0000000000000000000000000000000000000000000000000000000000000000","logIndex":18446744073709551615}"#;
        // Indices outside the protobuf int64 range are rejected while parsing.
        assert!(serde_json::from_str::<LogEntry>(json).is_err());
        let mut entry: LogEntry =
            serde_json::from_str(&json.replace("18446744073709551615", "123")).unwrap();
        let converted = entry
            .to_bundle_entry(sigstore_types::KindVersion::HashedRekordV001)
            .unwrap();
        assert_eq!(converted.log_index.get(), 123);
        assert_eq!(converted.canonicalized_body, entry.body);
        assert_eq!(converted.integrated_time, entry.integrated_time);
        entry.verification = Some(Verification {
            signed_entry_timestamp: None,
            inclusion_proof: Some(RekorInclusionProof {
                log_index: sigstore_types::LogIndex::new(0).unwrap(),
                checkpoint: "not a checkpoint".to_string(),
                hashes: vec![],
                root_hash: Sha256Hash::new([0; 32]),
                tree_size: 1,
            }),
        });
        // A malformed checkpoint fails the conversion.
        assert!(entry
            .to_bundle_entry(sigstore_types::KindVersion::HashedRekordV001)
            .is_err());
    }

    #[test]
    fn test_hashed_rekord_creation() {
        let entry = HashedRekord::new(
            &Sha256Hash::new([0u8; 32]),
            &SignatureBytes::from_bytes(b"signature"),
            &DerCertificate::new(vec![0x30, 0x00]), // Minimal DER sequence
        );
        assert_eq!(entry.kind, "hashedrekord");
        assert_eq!(entry.api_version, "0.0.1");
        assert_eq!(entry.spec.data.hash.algorithm, HashAlgorithm::Sha2256);
        assert_eq!(
            entry.spec.data.hash.value,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        // SignatureBytes serializes as base64
        assert_eq!(
            entry.spec.signature.content,
            SignatureBytes::from_bytes(b"signature")
        );
    }

    #[test]
    fn v2_serializes_typed_certificate_and_public_key_verifiers() {
        let digest = Sha256Hash::new([0; 32]);
        let signature = SignatureBytes::from_bytes(b"signature");
        let certificate = HashedRekordV2::new_with_certificate(
            &digest,
            &signature,
            &DerCertificate::new(vec![1, 2]),
            RekorV2KeyDetails::PkixEcdsaP256Sha256,
        );
        let certificate_json = serde_json::to_value(certificate).unwrap();
        let verifier = &certificate_json["hashedRekordRequestV002"]["signature"]["verifier"];
        assert_eq!(verifier["keyDetails"], "PKIX_ECDSA_P256_SHA_256");
        assert_eq!(verifier["x509Certificate"]["rawBytes"], "AQI=");
        assert!(verifier.get("publicKey").is_none());

        let public_key = HashedRekordV2::new_with_public_key(
            &digest,
            &signature,
            &DerPublicKey::new(vec![3, 4]),
            RekorV2KeyDetails::PkixEcdsaP256Sha256,
        );
        let public_key_json = serde_json::to_value(public_key).unwrap();
        let verifier = &public_key_json["hashedRekordRequestV002"]["signature"]["verifier"];
        assert_eq!(verifier["keyDetails"], "PKIX_ECDSA_P256_SHA_256");
        assert_eq!(verifier["publicKey"]["rawBytes"], "AwQ=");
        assert!(verifier.get("x509Certificate").is_none());
    }

    #[test]
    fn test_hashed_rekord_serializes_lowercase_algorithm() {
        let entry = HashedRekord::new(
            &Sha256Hash::new([0u8; 32]),
            &SignatureBytes::from_bytes(b"signature"),
            &DerCertificate::new(vec![0x30, 0x00]), // Minimal DER sequence
        );
        let json = serde_json::to_string(&entry).unwrap();
        // Verify the algorithm is serialized as lowercase "sha256" for Rekor API
        assert!(json.contains("\"algorithm\":\"sha256\""));
        assert!(!json.contains("SHA2_256"));
    }
}
