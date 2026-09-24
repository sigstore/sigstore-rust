//! Bundle builder for creating Sigstore bundles

use sigstore_types::{
    bundle::{
        CertificateContent, CheckpointData, InclusionPromise, InclusionProof, KindVersion, LogId,
        MessageSignature, PublicKeyIdentifier, Rfc3161Timestamp, SignatureContent,
        TimestampVerificationData, TransparencyLogEntry, VerificationMaterial,
        VerificationMaterialContent,
    },
    Bundle, CanonicalizedBody, DerCertificate, DsseEnvelope, LogIndex, LogKeyId, MediaType,
    Sha256Hash, SignatureBytes, SignedTimestamp, TimestampToken,
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
            SignatureContent::MessageSignature(
                MessageSignature::new(signature).with_message_digest(
                    sigstore_types::bundle::MessageDigest::new(
                        sigstore_types::HashAlgorithm::Sha2256,
                        artifact_digest.into(),
                    ),
                ),
            ),
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
        self.rfc3161_timestamps
            .push(Rfc3161Timestamp::new(timestamp));
        self
    }

    /// Convert to a serializable Bundle.
    pub fn into_bundle(self) -> Bundle {
        let verification_content = match self.verification {
            VerificationMaterialV03::Certificate(cert) => {
                VerificationMaterialContent::Certificate(CertificateContent::new(cert))
            }
            VerificationMaterialV03::PublicKey { hint } => {
                VerificationMaterialContent::PublicKey(PublicKeyIdentifier::new(hint))
            }
        };

        Bundle::new(
            MediaType::Bundle0_3,
            VerificationMaterial::new(verification_content)
                .with_tlog_entries(self.tlog_entries)
                .with_timestamp_verification_data(TimestampVerificationData::new(
                    self.rfc3161_timestamps,
                )),
            self.content,
        )
    }
}

/// Helper to create a transparency log entry.
#[derive(Debug, Clone)]
pub struct TlogEntryBuilder {
    log_index: LogIndex,
    log_id: LogKeyId,
    kind_version: KindVersion,
    integrated_time: Option<jiff::Timestamp>,
    canonicalized_body: CanonicalizedBody,
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
            log_id,
            kind_version,
            integrated_time: None,
            canonicalized_body: body,
            inclusion_promise: None,
            inclusion_proof: None,
        }
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
        self.inclusion_promise = Some(InclusionPromise::new(signed_entry_timestamp));
        self
    }

    /// Set the inclusion proof.
    ///
    /// # Arguments
    /// * `log_index` - The log index the proof is for
    /// * `root_hash` - The root hash
    /// * `tree_size` - The tree size
    /// * `hashes` - The proof hashes
    /// * `checkpoint` - The parsed checkpoint (see [`CheckpointData::new`])
    pub fn inclusion_proof(
        mut self,
        log_index: LogIndex,
        root_hash: Sha256Hash,
        tree_size: u64,
        hashes: Vec<Sha256Hash>,
        checkpoint: CheckpointData,
    ) -> Self {
        self.inclusion_proof = Some(InclusionProof::new(
            log_index, root_hash, tree_size, hashes, checkpoint,
        ));
        self
    }

    /// Build the transparency log entry.
    pub fn build(self) -> TransparencyLogEntry {
        // Destructure so that a new builder field cannot be silently dropped.
        let Self {
            log_index,
            log_id,
            kind_version,
            integrated_time,
            canonicalized_body,
            inclusion_promise,
            inclusion_proof,
        } = self;
        let mut entry = TransparencyLogEntry::new(
            log_index,
            LogId::new(log_id),
            kind_version,
            canonicalized_body,
        );
        // The optional fields are assigned directly: the `with_*` setters take
        // present values, while the builder holds `Option`s.
        entry.integrated_time = integrated_time;
        entry.inclusion_promise = inclusion_promise;
        entry.inclusion_proof = inclusion_proof;
        entry
    }
}
