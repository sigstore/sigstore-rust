//! Bundle builder for creating Sigstore bundles

use sigstore_rekor::entry::LogEntry;
use sigstore_types::{
    bundle::{
        CertificateContent, CheckpointData, InclusionPromise, InclusionProof, KindVersion, LogId,
        MessageSignature, Rfc3161Timestamp, SignatureContent, TimestampVerificationData,
        TransparencyLogEntry, VerificationMaterial, VerificationMaterialContent,
    },
    Bundle, CanonicalizedBody, DerCertificate, DsseEnvelope, LogIndex, LogKeyId, MediaType,
    Result as TypesResult, Sha256Hash, SignatureBytes, SignedTimestamp, TimestampToken,
};

/// Verification material for v0.3 bundles.
///
/// In v0.3 bundles, only a single certificate or a public key hint is allowed.
/// Certificate chains are NOT permitted in v0.3 format.
#[derive(Debug, Clone)]
pub enum VerificationMaterialV03 {
    /// Single certificate (the common case for Fulcio-issued certs)
    Certificate(DerCertificate),
    /// Public key hint (for pre-existing keys)
    PublicKey { hint: String },
}

/// A Sigstore bundle in v0.3 format.
///
/// The v0.3 format requires:
/// - A single certificate (not a chain) or public key hint
/// - Either a message signature or DSSE envelope
/// - Optional transparency log entries and RFC 3161 timestamps
///
/// # Example
///
/// ```ignore
/// use sigstore_bundle::BundleV03;
///
/// let bundle = BundleV03::with_certificate_and_signature(cert_der, signature, artifact_hash)
///     .with_tlog_entry(tlog_entry)
///     .into_bundle();
/// ```
#[derive(Debug, Clone)]
pub struct BundleV03 {
    /// Verification material - either a certificate or public key
    pub verification: VerificationMaterialV03,
    /// The signature content (message signature or DSSE envelope)
    pub content: SignatureContent,
    /// Transparency log entries
    pub tlog_entries: Vec<TransparencyLogEntry>,
    /// RFC 3161 timestamps
    pub rfc3161_timestamps: Vec<Rfc3161Timestamp>,
}

impl BundleV03 {
    /// Create a new v0.3 bundle with the required fields.
    pub fn new(verification: VerificationMaterialV03, content: SignatureContent) -> Self {
        Self {
            verification,
            content,
            tlog_entries: Vec::new(),
            rfc3161_timestamps: Vec::new(),
        }
    }

    /// Create a new v0.3 bundle with a certificate and message signature.
    ///
    /// This is the most common case for Sigstore signing with Fulcio certificates.
    pub fn with_certificate_and_signature(
        certificate: DerCertificate,
        signature: SignatureBytes,
        artifact_digest: Sha256Hash,
    ) -> Self {
        Self::new(
            VerificationMaterialV03::Certificate(certificate),
            SignatureContent::MessageSignature(MessageSignature {
                message_digest: Some(sigstore_types::bundle::MessageDigest {
                    algorithm: sigstore_types::HashAlgorithm::Sha2256,
                    digest: artifact_digest.into(),
                }),
                signature,
            }),
        )
    }

    /// Create a new v0.3 bundle with a certificate and DSSE envelope.
    ///
    /// Used for attestations (in-toto statements).
    pub fn with_certificate_and_dsse(certificate: DerCertificate, envelope: DsseEnvelope) -> Self {
        Self::new(
            VerificationMaterialV03::Certificate(certificate),
            SignatureContent::DsseEnvelope(envelope),
        )
    }

    /// Add a transparency log entry.
    pub fn with_tlog_entry(mut self, entry: TransparencyLogEntry) -> Self {
        self.tlog_entries.push(entry);
        self
    }

    /// Add an RFC 3161 timestamp.
    pub fn with_rfc3161_timestamp(mut self, timestamp: TimestampToken) -> Self {
        self.rfc3161_timestamps.push(Rfc3161Timestamp {
            signed_timestamp: timestamp,
        });
        self
    }

    /// Convert to a serializable Bundle.
    pub fn into_bundle(self) -> Bundle {
        let verification_content = match self.verification {
            VerificationMaterialV03::Certificate(cert) => {
                VerificationMaterialContent::Certificate(CertificateContent { raw_bytes: cert })
            }
            VerificationMaterialV03::PublicKey { hint } => {
                VerificationMaterialContent::PublicKey { hint }
            }
        };

        Bundle {
            media_type: MediaType::Bundle0_3,
            verification_material: VerificationMaterial {
                content: verification_content,
                tlog_entries: self.tlog_entries,
                timestamp_verification_data: TimestampVerificationData {
                    rfc3161_timestamps: self.rfc3161_timestamps,
                },
            },
            content: self.content,
        }
    }
}

/// Helper to create a transparency log entry.
pub struct TlogEntryBuilder {
    log_index: LogIndex,
    log_id: String,
    kind_version: KindVersion,
    integrated_time: Option<jiff::Timestamp>,
    canonicalized_body: Vec<u8>,
    inclusion_promise: Option<InclusionPromise>,
    inclusion_proof: Option<InclusionProof>,
}

impl TlogEntryBuilder {
    /// Create a builder with the required entry fields.
    pub fn new(
        log_index: LogIndex,
        log_id: LogKeyId,
        kind_version: KindVersion,
        body: CanonicalizedBody,
    ) -> Self {
        Self {
            log_index,
            log_id: log_id.as_str().to_owned(),
            kind_version,
            integrated_time: None,
            canonicalized_body: body.as_bytes().to_vec(),
            inclusion_promise: None,
            inclusion_proof: None,
        }
    }

    /// Create a tlog entry builder from a Rekor LogEntry response.
    ///
    /// This method extracts all relevant fields from a Rekor API response
    /// and populates the builder automatically.
    ///
    /// # Arguments
    /// * `entry` - The LogEntry returned from the Rekor API
    /// * `kind_version` - The typed Rekor entry format
    pub fn from_log_entry(entry: &LogEntry, kind_version: KindVersion) -> TypesResult<Self> {
        // Convert hex log_id to base64 using the type-safe method
        let log_id_base64 = entry.log_id.to_base64()?;

        let mut builder = Self {
            log_index: LogIndex::new(entry.log_index)?,
            log_id: log_id_base64,
            kind_version,
            integrated_time: entry.integrated_time,
            canonicalized_body: entry.body.as_bytes().to_vec(),
            inclusion_promise: None,
            inclusion_proof: None,
        };

        // Add verification data if present
        if let Some(verification) = &entry.verification {
            if let Some(set) = &verification.signed_entry_timestamp {
                builder.inclusion_promise = Some(InclusionPromise {
                    signed_entry_timestamp: set.clone(),
                });
            }

            if let Some(proof) = &verification.inclusion_proof {
                builder.inclusion_proof = Some(InclusionProof {
                    log_index: LogIndex::new(proof.log_index)?,
                    root_hash: proof.root_hash,
                    tree_size: proof.tree_size,
                    hashes: proof.hashes.clone(),
                    checkpoint: CheckpointData::new(proof.checkpoint.clone())?,
                });
            }
        }

        Ok(builder)
    }

    /// Set the log index.
    pub fn log_index(mut self, index: LogIndex) -> Self {
        self.log_index = index;
        self
    }

    /// Set the integrated time.
    pub fn integrated_time(mut self, time: jiff::Timestamp) -> Self {
        self.integrated_time = Some(time);
        self
    }

    /// Set the inclusion promise (Signed Entry Timestamp).
    pub fn inclusion_promise(mut self, signed_entry_timestamp: SignedTimestamp) -> Self {
        self.inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp,
        });
        self
    }

    /// Set the inclusion proof.
    ///
    /// # Arguments
    /// * `log_index` - The log index
    /// * `root_hash` - The root hash
    /// * `tree_size` - The tree size
    /// * `hashes` - The proof hashes
    /// * `checkpoint` - The checkpoint envelope
    pub fn inclusion_proof(
        mut self,
        log_index: u64,
        root_hash: Sha256Hash,
        tree_size: u64,
        hashes: Vec<Sha256Hash>,
        checkpoint: String,
    ) -> TypesResult<Self> {
        self.inclusion_proof = Some(InclusionProof {
            log_index: LogIndex::new(log_index)?,
            root_hash,
            tree_size,
            hashes,
            checkpoint: CheckpointData::new(checkpoint)?,
        });
        Ok(self)
    }

    /// Build the transparency log entry.
    pub fn build(self) -> TransparencyLogEntry {
        TransparencyLogEntry {
            log_index: self.log_index,
            log_id: LogId {
                key_id: LogKeyId::new(self.log_id),
            },
            kind_version: self.kind_version,
            integrated_time: self.integrated_time,
            inclusion_promise: self.inclusion_promise,
            inclusion_proof: self.inclusion_proof,
            canonicalized_body: CanonicalizedBody::new(self.canonicalized_body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rekor_index_overflow_returns_an_error() {
        let entry: LogEntry = serde_json::from_str(r#"{"body":"e30=","integratedTime":0,"logID":"0000000000000000000000000000000000000000000000000000000000000000","logIndex":18446744073709551615}"#).unwrap();
        assert!(TlogEntryBuilder::from_log_entry(&entry, KindVersion::HashedRekordV001).is_err());
    }
}
