//! Trusted root types and parsing

use crate::{time_range::TimeRange, Error, Result};
use jiff::Timestamp;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sigstore_crypto::{SigningScheme, VerificationKey};
use sigstore_types::{
    DerCertificate, DerPublicKey, HashAlgorithm, KeyDetails, KeyHint, LogId, LogKeyId, Sha256Hash,
};

/// TSA certificate with its optional validity period
pub type TsaCertWithValidity = (CertificateDer<'static>, Option<TimeRange>);

/// A trusted root bundle containing all trust anchors
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRoot {
    /// Media type of the trusted root
    pub media_type: String,

    /// Transparency logs (Rekor)
    #[serde(default)]
    pub tlogs: Vec<TransparencyLog>,

    /// Certificate authorities (Fulcio)
    #[serde(default)]
    pub certificate_authorities: Vec<CertificateAuthority>,

    /// Certificate Transparency logs
    #[serde(default)]
    pub ctlogs: Vec<CertificateTransparencyLog>,

    /// Timestamp authorities (RFC 3161 TSAs)
    #[serde(default)]
    pub timestamp_authorities: Vec<TimestampAuthority>,
}

/// A transparency log entry (Rekor)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLog {
    /// Base URL of the transparency log
    pub base_url: String,

    /// Hash algorithm used
    pub hash_algorithm: HashAlgorithm,

    /// Public key for verification
    pub public_key: PublicKey,

    /// Log ID
    pub log_id: LogId,
}

/// A certificate authority entry (Fulcio)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthority {
    /// Subject information
    #[serde(default)]
    pub subject: CertificateSubject,

    /// URI of the CA
    pub uri: String,

    /// Certificate chain
    pub cert_chain: CertChain,

    /// Validity period
    #[serde(default)]
    pub valid_for: Option<ValidityPeriod>,
}

/// A Certificate Transparency log entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateTransparencyLog {
    /// Base URL of the CT log
    pub base_url: String,

    /// Hash algorithm used
    pub hash_algorithm: HashAlgorithm,

    /// Public key for verification
    pub public_key: PublicKey,

    /// Log ID
    pub log_id: LogId,
}

/// A timestamp authority entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimestampAuthority {
    /// Subject information
    #[serde(default)]
    pub subject: CertificateSubject,

    /// URI of the TSA
    #[serde(default)]
    pub uri: Option<String>,

    /// Certificate chain
    pub cert_chain: CertChain,

    /// Validity period
    #[serde(default)]
    pub valid_for: Option<ValidityPeriod>,
}

/// Public key information
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    /// Raw bytes of the public key (DER-encoded)
    pub raw_bytes: DerPublicKey,

    /// The signature algorithm declared for this key
    pub key_details: KeyDetails,

    /// Validity period for this key
    #[serde(default)]
    pub valid_for: Option<ValidityPeriod>,
}

/// Subject information for a certificate.
///
/// Note: This is different from `sigstore_types::Subject` which represents
/// an in-toto Statement subject (artifact name + digest).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSubject {
    /// Organization name
    #[serde(default)]
    pub organization: Option<String>,

    /// Common name
    #[serde(default)]
    pub common_name: Option<String>,
}

/// Certificate chain
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertChain {
    /// Certificates in the chain
    pub certificates: Vec<CertificateEntry>,
}

/// A certificate entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateEntry {
    /// Raw bytes of the certificate (DER-encoded)
    pub raw_bytes: DerCertificate,
}

/// Validity period for a key or certificate.
///
/// The trusted root's `validFor` fields are instances of the protobuf-specs
/// `TimeRange` message, so this is an alias for [`TimeRange`] — the same type
/// the signing config uses for its service validity periods.
pub type ValidityPeriod = TimeRange;

/// A transparency log key (Rekor or CTFE) from the trusted root, parsed and
/// ready to verify with.
///
/// The verification scheme comes from the trusted root's declared
/// `keyDetails`, not from inspecting the key material, and the key/scheme
/// consistency is checked when the key is parsed. The identifier forms needed
/// by specific verification flows are precomputed ([`LogKey::key_hint`]) or
/// derived ([`LogKey::computed_log_id`]).
#[derive(Debug, Clone)]
pub struct LogKey {
    /// The log's key ID as declared in the trusted root (the base64-encoded
    /// SHA-256 hash of the DER-encoded public key).
    pub log_id: LogKeyId,
    /// The DER (SPKI)-encoded public key.
    pub public_key: DerPublicKey,
    /// The verification key, using the scheme declared by `keyDetails`.
    pub key: VerificationKey,
    /// The checkpoint key hint: the first 4 bytes of the decoded log ID.
    ///
    /// Checkpoint (signed note) signatures identify their signing key by this
    /// hint. `None` when the declared log ID cannot yield one (not decodable,
    /// or shorter than 4 bytes) — such an entry can never match a checkpoint
    /// signature.
    pub key_hint: Option<KeyHint>,
}

impl LogKey {
    /// The log ID recomputed from the public key: the SHA-256 hash of the
    /// DER-encoded key.
    ///
    /// SCT verification matches a certificate SCT's `LogID` against this
    /// computed value rather than the declared [`Self::log_id`], so a trusted
    /// root whose declared ID disagrees with its key material cannot redirect
    /// the lookup.
    pub fn computed_log_id(&self) -> Sha256Hash {
        sigstore_crypto::sha256(self.public_key.as_bytes())
    }
}

/// A transparency log key this implementation cannot verify with.
///
/// Trusted roots legitimately carry such keys (e.g. staging's CT log key,
/// whose deprecated `PKCS1_RSA_PKCS1V5` key details name no fixed hash and
/// whose material is not an SPKI structure). They are reported alongside the
/// usable keys so that a lookup which lands on one can say why it failed
/// instead of pretending the key does not exist.
#[derive(Debug, Clone)]
pub struct UnusableLogKey {
    /// The log's key ID as declared in the trusted root.
    pub log_id: LogKeyId,
    /// The DER-encoded public key as declared in the trusted root.
    pub public_key: DerPublicKey,
    /// Why the key cannot be used for verification.
    pub reason: String,
}

impl UnusableLogKey {
    /// The log ID recomputed from the declared key bytes, matching
    /// [`LogKey::computed_log_id`].
    pub fn computed_log_id(&self) -> Sha256Hash {
        sigstore_crypto::sha256(self.public_key.as_bytes())
    }
}

/// The transparency log keys of one kind (Rekor or CTFE) from a trusted root.
#[derive(Debug, Clone, Default)]
pub struct LogKeys {
    /// Keys this implementation can verify with.
    pub usable: Vec<LogKey>,
    /// Keys it cannot, with the reason.
    pub unusable: Vec<UnusableLogKey>,
}

impl LogKeys {
    /// Whether the trusted root declared no keys of this kind at all.
    pub fn is_empty(&self) -> bool {
        self.usable.is_empty() && self.unusable.is_empty()
    }
}

/// Parse a trusted-root public key into a verification key using the scheme
/// its `keyDetails` declares.
fn parsed_verification_key(
    public_key: &PublicKey,
) -> std::result::Result<VerificationKey, String> {
    let scheme = SigningScheme::try_from(&public_key.key_details).map_err(|e| e.to_string())?;
    VerificationKey::from_spki(&public_key.raw_bytes, scheme).map_err(|e| e.to_string())
}

/// The checkpoint key hint for a declared log ID: the first 4 bytes of the
/// decoded ID, or `None` when the ID cannot yield one.
fn derive_key_hint(log_id: &LogKeyId) -> Option<KeyHint> {
    let bytes = log_id.decode().ok()?;
    KeyHint::try_from_slice(bytes.get(..4)?).ok()
}

/// Whether an instance with the given `valid_for` may be used as verification
/// material at `now`.
///
/// Instances without a `valid_for` constraint are always usable. Instances
/// whose window has not started yet are excluded; expired instances are kept
/// because historical entries/certificates were created while they were valid.
fn usable_for_verification(valid_for: Option<&ValidityPeriod>, now: Timestamp) -> bool {
    valid_for.map_or(true, |period| period.has_started_by(now))
}

impl TrustedRoot {
    /// Parse a trusted root from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load a trusted root from a file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let json =
            std::fs::read_to_string(path).map_err(|e| Error::Json(serde_json::Error::io(e)))?;
        Self::from_json(&json)
    }

    /// Get all Fulcio certificate authority certificates
    ///
    /// Certificate authorities whose `valid_for` window has not started yet
    /// are excluded. Expired certificate authorities are included because
    /// they are needed to verify certificates issued while they were valid.
    pub fn fulcio_certs(&self) -> Vec<CertificateDer<'static>> {
        let now = Timestamp::now();
        let mut certs = Vec::new();
        for ca in &self.certificate_authorities {
            if !usable_for_verification(ca.valid_for.as_ref(), now) {
                continue;
            }
            for cert_entry in &ca.cert_chain.certificates {
                certs.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        certs
    }

    /// Get all Rekor transparency log keys
    ///
    /// Keys whose `valid_for` window has not started yet are excluded.
    /// Expired keys are included because they are needed to verify log
    /// entries that were integrated while the key was valid. Keys this
    /// implementation cannot verify with are reported in
    /// [`LogKeys::unusable`].
    pub fn rekor_keys(&self) -> LogKeys {
        Self::collect_log_keys(self.tlogs.iter().map(|t| (&t.log_id, &t.public_key)))
    }

    /// Get all Certificate Transparency log keys
    ///
    /// Keys whose `valid_for` window has not started yet are excluded.
    /// Expired keys are included because they are needed to verify SCTs
    /// issued while the key was valid. Keys this implementation cannot
    /// verify with are reported in [`LogKeys::unusable`].
    pub fn ctfe_keys(&self) -> LogKeys {
        Self::collect_log_keys(self.ctlogs.iter().map(|c| (&c.log_id, &c.public_key)))
    }

    fn collect_log_keys<'a>(entries: impl Iterator<Item = (&'a LogId, &'a PublicKey)>) -> LogKeys {
        let now = Timestamp::now();
        let mut keys = LogKeys::default();
        for (log_id, public_key) in entries {
            if !usable_for_verification(public_key.valid_for.as_ref(), now) {
                continue;
            }
            match parsed_verification_key(public_key) {
                Ok(key) => keys.usable.push(LogKey {
                    log_id: log_id.key_id.clone(),
                    public_key: public_key.raw_bytes.clone(),
                    key,
                    key_hint: derive_key_hint(&log_id.key_id),
                }),
                Err(reason) => keys.unusable.push(UnusableLogKey {
                    log_id: log_id.key_id.clone(),
                    public_key: public_key.raw_bytes.clone(),
                    reason,
                }),
            }
        }
        keys
    }

    /// Get a specific Rekor verification key by log ID
    ///
    /// Keys whose `valid_for` window has not started yet are not returned.
    /// Expired keys are returned because they are needed to verify log
    /// entries that were integrated while the key was valid.
    pub fn rekor_key_for_log(&self, log_id: &LogKeyId) -> Result<VerificationKey> {
        let now = Timestamp::now();
        self.rekor_key_matching(log_id, |public_key| {
            usable_for_verification(public_key.valid_for.as_ref(), now)
        })
    }

    /// Get a specific Rekor verification key by log ID, valid at the given time
    ///
    /// Unlike [`Self::rekor_key_for_log`] this requires the key's `valid_for`
    /// window (if present) to fully contain `time`, which is suitable when
    /// the relevant timestamp of the material being verified is known (e.g.
    /// a log entry's integrated time).
    pub fn rekor_key_for_log_at(
        &self,
        log_id: &LogKeyId,
        time: Timestamp,
    ) -> Result<VerificationKey> {
        self.rekor_key_matching(log_id, |public_key| {
            public_key
                .valid_for
                .map_or(true, |period| period.contains(time))
        })
    }

    /// Find the first tlog entry with the declared `log_id` whose validity
    /// window passes `window_ok`, and parse its key. An entry that matches
    /// but cannot be parsed is remembered so the error can say why, while the
    /// search continues in case another entry with the same ID is usable.
    fn rekor_key_matching(
        &self,
        log_id: &LogKeyId,
        window_ok: impl Fn(&PublicKey) -> bool,
    ) -> Result<VerificationKey> {
        let mut unusable_reason = None;
        for tlog in &self.tlogs {
            if &tlog.log_id.key_id != log_id || !window_ok(&tlog.public_key) {
                continue;
            }
            match parsed_verification_key(&tlog.public_key) {
                Ok(key) => return Ok(key),
                Err(reason) => unusable_reason = Some(reason),
            }
        }
        match unusable_reason {
            Some(reason) => Err(Error::InvalidKey(format!(
                "log key {log_id} cannot be used for verification: {reason}"
            ))),
            None => Err(Error::KeyNotFound(log_id.to_string())),
        }
    }

    /// Get all TSA certificates with their validity periods
    pub fn tsa_certs_with_validity(&self) -> Vec<TsaCertWithValidity> {
        let mut result = Vec::new();

        for tsa in &self.timestamp_authorities {
            let validity = tsa.valid_for;

            for cert_entry in &tsa.cert_chain.certificates {
                let cert_der = cert_entry.raw_bytes.as_bytes().to_vec();
                result.push((CertificateDer::from(&cert_der[..]).into_owned(), validity));
            }
        }

        result
    }

    /// Get TSA root certificates (for chain validation)
    ///
    /// Timestamp authorities whose `valid_for` window has not started yet are
    /// excluded. Expired authorities are included because they are needed to
    /// verify timestamps issued while they were valid.
    pub fn tsa_root_certs(&self) -> Vec<CertificateDer<'static>> {
        let now = Timestamp::now();
        let mut roots = Vec::new();
        for tsa in &self.timestamp_authorities {
            if !usable_for_verification(tsa.valid_for.as_ref(), now) {
                continue;
            }
            // The last certificate in the chain is typically the root
            if let Some(cert_entry) = tsa.cert_chain.certificates.last() {
                roots.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        roots
    }

    /// Get TSA intermediate certificates (for chain validation)
    ///
    /// Timestamp authorities whose `valid_for` window has not started yet are
    /// excluded. Expired authorities are included because they are needed to
    /// verify timestamps issued while they were valid.
    pub fn tsa_intermediate_certs(&self) -> Vec<CertificateDer<'static>> {
        let now = Timestamp::now();
        let mut intermediates = Vec::new();
        for tsa in &self.timestamp_authorities {
            if !usable_for_verification(tsa.valid_for.as_ref(), now) {
                continue;
            }
            // All certificates except the first (leaf) and last (root) are intermediates
            let chain_len = tsa.cert_chain.certificates.len();
            if chain_len > 2 {
                for cert_entry in &tsa.cert_chain.certificates[1..chain_len - 1] {
                    intermediates
                        .push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
                }
            }
        }
        intermediates
    }

    /// Get TSA leaf certificates (the first certificate in each chain)
    /// These are the actual TSA signing certificates
    ///
    /// Timestamp authorities whose `valid_for` window has not started yet are
    /// excluded. Expired authorities are included because they are needed to
    /// verify timestamps issued while they were valid.
    pub fn tsa_leaf_certs(&self) -> Vec<CertificateDer<'static>> {
        let now = Timestamp::now();
        let mut leaves = Vec::new();
        for tsa in &self.timestamp_authorities {
            if !usable_for_verification(tsa.valid_for.as_ref(), now) {
                continue;
            }
            // The first certificate in the chain is the leaf (TSA signing cert)
            if let Some(cert_entry) = tsa.cert_chain.certificates.first() {
                leaves.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        leaves
    }

    /// Check if a timestamp is within any TSA's validity period from the trust root
    ///
    /// Returns `true` if:
    /// - There are no timestamp authorities configured (no TSA verification)
    /// - Any TSA has no `valid_for` field (open-ended validity)
    /// - The timestamp falls within at least one TSA's `valid_for` period
    ///
    /// Returns `false` only if there are TSAs with validity constraints and
    /// the timestamp doesn't fall within any of them.
    pub fn is_timestamp_within_tsa_validity(&self, timestamp: Timestamp) -> bool {
        // If no TSAs are configured, no validity check needed
        if self.timestamp_authorities.is_empty() {
            return true;
        }

        self.timestamp_authorities.iter().any(|tsa| {
            // A TSA without a valid_for constraint is valid for all time
            tsa.valid_for
                .map_or(true, |valid_for| valid_for.contains(timestamp))
        })
    }
}

/// Embedded production trusted root from <https://tuf-repo-cdn.sigstore.dev/>
/// This is the default trusted root for Sigstore's public production instance.
pub const SIGSTORE_PRODUCTION_TRUSTED_ROOT: &str = include_str!("trusted_root.json");

/// Embedded staging trusted root from <https://tuf-repo-cdn.sigstage.dev/>
/// This is the trusted root for Sigstore's staging/testing instance.
pub const SIGSTORE_STAGING_TRUSTED_ROOT: &str = include_str!("trusted_root_staging.json");

/// Embedded GitHub trusted root from <https://tuf-repo.github.com/>
///
/// This is GitHub's separate Sigstore instance for artifact attestations whose
/// leaf certificates are issued by `O=GitHub, Inc.`.
pub const SIGSTORE_GITHUB_TRUSTED_ROOT: &str = include_str!("trusted_root_github.json");

/// Well-known Sigstore trust instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigstoreInstance {
    /// Sigstore's public-good production instance.
    PublicGood,
    /// Sigstore's public-good staging instance.
    Staging,
    /// GitHub's artifact attestation instance.
    GitHub,
}

impl SigstoreInstance {
    /// Return the embedded `trusted_root.json` snapshot for this instance.
    pub fn embedded_trusted_root_json(self) -> &'static str {
        match self {
            Self::PublicGood => SIGSTORE_PRODUCTION_TRUSTED_ROOT,
            Self::Staging => SIGSTORE_STAGING_TRUSTED_ROOT,
            Self::GitHub => SIGSTORE_GITHUB_TRUSTED_ROOT,
        }
    }

    /// Load this instance's embedded trusted root snapshot.
    pub fn embedded_trusted_root(self) -> Result<TrustedRoot> {
        TrustedRoot::from_json(self.embedded_trusted_root_json())
    }
}

impl TrustedRoot {
    /// Load an embedded trusted root snapshot for a well-known instance.
    pub fn from_embedded(instance: SigstoreInstance) -> Result<Self> {
        instance.embedded_trusted_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TRUSTED_ROOT: &str = r#"{
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [{
            "baseUrl": "https://rekor.sigstore.dev",
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYI4heOTrNrZO27elFE8ynfrdPMikttRkbe+vJKQ50G6bfwQ3WyhLpRwwwohelDAm8xRzJ56nYsIa3VHivVvpmA==",
                "keyDetails": "PKIX_ECDSA_P256_SHA_256"
            },
            "logId": {
                "keyId": "test-key-id"
            }
        }],
        "certificateAuthorities": [],
        "ctlogs": [],
        "timestampAuthorities": []
    }"#;

    #[test]
    fn test_parse_trusted_root() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        assert_eq!(root.tlogs.len(), 1);
        assert_eq!(
            root.tlogs[0].log_id.key_id,
            LogKeyId::new("test-key-id".to_string())
        );
    }

    fn has_log(keys: &LogKeys, log_id: &str) -> bool {
        keys.usable
            .iter()
            .any(|key| key.log_id == LogKeyId::new(log_id.to_string()))
    }

    #[test]
    fn test_rekor_keys() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        let keys = root.rekor_keys();
        assert_eq!(keys.usable.len(), 1);
        assert!(keys.unusable.is_empty());
        assert!(has_log(&keys, "test-key-id"));
    }

    #[test]
    fn test_from_json_production() {
        let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
        assert!(!root.tlogs.is_empty());
        assert!(!root.certificate_authorities.is_empty());
        assert!(!root.ctlogs.is_empty());
    }

    #[test]
    fn test_from_json_staging() {
        let root = TrustedRoot::from_json(SIGSTORE_STAGING_TRUSTED_ROOT).unwrap();
        assert!(!root.tlogs.is_empty());
        assert!(!root.certificate_authorities.is_empty());
        assert!(!root.ctlogs.is_empty());
        // Staging should have different URLs from production
        assert!(root.tlogs[0].base_url.contains("sigstage.dev"));
    }

    #[test]
    fn test_from_embedded_github() {
        let root = TrustedRoot::from_embedded(SigstoreInstance::GitHub).unwrap();
        assert!(root
            .certificate_authorities
            .iter()
            .any(|ca| ca.uri == "fulcio.githubapp.com"));
    }

    // A dummy DER-encoded P-256 public key (base64), reused across instances.
    const TEST_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYI4heOTrNrZO27elFE8ynfrdPMikttRkbe+vJKQ50G6bfwQ3WyhLpRwwwohelDAm8xRzJ56nYsIa3VHivVvpmA==";

    fn trusted_root_json_with_tlog_validity(valid_for: &[(&str, &str)]) -> String {
        let tlogs: Vec<String> = valid_for
            .iter()
            .enumerate()
            .map(|(i, (key_id, validity))| {
                format!(
                    r#"{{
                        "baseUrl": "https://rekor-{i}.example.com",
                        "hashAlgorithm": "SHA2_256",
                        "publicKey": {{
                            "rawBytes": "{TEST_KEY}",
                            "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                            "validFor": {validity}
                        }},
                        "logId": {{ "keyId": "{key_id}" }}
                    }}"#
                )
            })
            .collect();
        format!(
            r#"{{
                "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                "tlogs": [{}]
            }}"#,
            tlogs.join(",")
        )
    }

    fn trusted_root_with_tlog_validity(valid_for: &[(&str, &str)]) -> TrustedRoot {
        TrustedRoot::from_json(&trusted_root_json_with_tlog_validity(valid_for)).unwrap()
    }

    #[test]
    fn test_rekor_keys_excludes_not_yet_valid() {
        let root = trusted_root_with_tlog_validity(&[
            // Expired key: usable for verifying historical entries
            (
                "expired-key",
                r#"{"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}"#,
            ),
            // Currently valid key
            ("current-key", r#"{"start": "2021-01-01T00:00:00Z"}"#),
            // Key whose validity window has not started yet
            ("future-key", r#"{"start": "2999-01-01T00:00:00Z"}"#),
        ]);

        let keys = root.rekor_keys();
        assert_eq!(keys.usable.len(), 2);
        assert!(has_log(&keys, "expired-key"));
        assert!(has_log(&keys, "current-key"));
        assert!(!has_log(&keys, "future-key"));

        // rekor_key_for_log honors the same rule
        assert!(root
            .rekor_key_for_log(&LogKeyId::new("expired-key".to_string()))
            .is_ok());
        assert!(root
            .rekor_key_for_log(&LogKeyId::new("current-key".to_string()))
            .is_ok());
        assert!(matches!(
            root.rekor_key_for_log(&LogKeyId::new("future-key".to_string())),
            Err(Error::KeyNotFound(_))
        ));
    }

    #[test]
    fn test_rekor_key_for_log_at_checks_full_window() {
        let root = trusted_root_with_tlog_validity(&[(
            "windowed-key",
            r#"{"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}"#,
        )]);
        let key_id = LogKeyId::new("windowed-key".to_string());

        // Inside the window
        let inside: Timestamp = "2020-06-01T00:00:00Z".parse().unwrap();
        assert!(root.rekor_key_for_log_at(&key_id, inside).is_ok());

        // Before the window
        let before: Timestamp = "2019-06-01T00:00:00Z".parse().unwrap();
        assert!(root.rekor_key_for_log_at(&key_id, before).is_err());

        // After the window
        let after: Timestamp = "2022-06-01T00:00:00Z".parse().unwrap();
        assert!(root.rekor_key_for_log_at(&key_id, after).is_err());
    }

    #[test]
    fn test_malformed_validity_timestamp_is_a_parse_error() {
        // `validFor` is a protobuf-specs `TimeRange`, so its timestamps are
        // parsed (and rejected) when the trusted root itself is parsed.
        let json =
            trusted_root_json_with_tlog_validity(&[("bad-key", r#"{"start": "not-a-timestamp"}"#)]);
        assert!(matches!(TrustedRoot::from_json(&json), Err(Error::Json(_))));
    }

    #[test]
    fn test_missing_validity_start_is_a_parse_error() {
        // The spec requires `TimeRange.start`.
        let json = trusted_root_json_with_tlog_validity(&[(
            "no-start-key",
            r#"{"end": "2021-01-01T00:00:00Z"}"#,
        )]);
        assert!(matches!(TrustedRoot::from_json(&json), Err(Error::Json(_))));
    }

    #[test]
    fn test_ctfe_keys_exclude_not_yet_valid() {
        let json = format!(
            r#"{{
                "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                "ctlogs": [
                    {{
                        "baseUrl": "https://ctfe-current.example.com",
                        "hashAlgorithm": "SHA2_256",
                        "publicKey": {{
                            "rawBytes": "{TEST_KEY}",
                            "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                            "validFor": {{"start": "2021-01-01T00:00:00Z"}}
                        }},
                        "logId": {{ "keyId": "current-ctlog" }}
                    }},
                    {{
                        "baseUrl": "https://ctfe-future.example.com",
                        "hashAlgorithm": "SHA2_256",
                        "publicKey": {{
                            "rawBytes": "{TEST_KEY}",
                            "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                            "validFor": {{"start": "2999-01-01T00:00:00Z"}}
                        }},
                        "logId": {{ "keyId": "future-ctlog" }}
                    }}
                ]
            }}"#
        );
        let root = TrustedRoot::from_json(&json).unwrap();

        let keys = root.ctfe_keys();
        assert_eq!(keys.usable.len(), 1);
        assert!(has_log(&keys, "current-ctlog"));

        // Malformed timestamp is rejected when the trusted root is parsed
        let bad_json = json.replace("2999-01-01T00:00:00Z", "garbage");
        assert!(matches!(
            TrustedRoot::from_json(&bad_json),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn test_log_key_derived_identifiers() {
        use base64::Engine;

        // Log ID matching the spec: base64(SHA-256(DER public key))
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(TEST_KEY)
            .unwrap();
        let computed = sigstore_crypto::sha256(&key_bytes);
        let log_id = LogKeyId::from_bytes(computed.as_bytes());

        let root = trusted_root_with_tlog_validity(&[(
            log_id.as_str(),
            r#"{"start": "2021-01-01T00:00:00Z"}"#,
        )]);
        let keys = root.rekor_keys();
        let key = &keys.usable[0];

        assert_eq!(key.computed_log_id(), computed);
        assert_eq!(
            key.key_hint.unwrap().as_ref(),
            &computed.as_bytes()[..4],
            "key hint is the first 4 bytes of the decoded log ID"
        );
    }

    #[test]
    fn test_short_log_id_yields_no_key_hint() {
        // "AQID" decodes to [1, 2, 3]: too short for a 4-byte key hint. The
        // key stays usable (e.g. for SET verification by full log ID); it
        // just can never match a checkpoint signature.
        let root =
            trusted_root_with_tlog_validity(&[("AQID", r#"{"start": "2021-01-01T00:00:00Z"}"#)]);
        let keys = root.rekor_keys();
        assert_eq!(keys.usable.len(), 1);
        assert!(keys.usable[0].key_hint.is_none());
    }

    #[test]
    fn test_unsupported_key_details_is_reported_unusable() {
        // A deprecated key details value that names no fixed hash algorithm
        // cannot be mapped to a verification scheme.
        let json = trusted_root_json_with_tlog_validity(&[(
            "deprecated-key",
            r#"{"start": "2021-01-01T00:00:00Z"}"#,
        )])
        .replace("PKIX_ECDSA_P256_SHA_256", "PKCS1_RSA_PKCS1V5");
        let root = TrustedRoot::from_json(&json).unwrap();

        let keys = root.rekor_keys();
        assert!(keys.usable.is_empty());
        assert_eq!(keys.unusable.len(), 1);
        assert!(keys.unusable[0].reason.contains("PKCS1_RSA_PKCS1V5"));

        // A by-ID lookup that lands on the unusable key says why
        assert!(matches!(
            root.rekor_key_for_log(&LogKeyId::new("deprecated-key".to_string())),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn test_key_details_mismatching_key_material_is_unusable() {
        // The key material is an ECDSA P-256 SPKI, but the trusted root
        // declares Ed25519: the declaration is checked against the key.
        let json = trusted_root_json_with_tlog_validity(&[(
            "lying-key",
            r#"{"start": "2021-01-01T00:00:00Z"}"#,
        )])
        .replace("PKIX_ECDSA_P256_SHA_256", "PKIX_ED25519");
        let root = TrustedRoot::from_json(&json).unwrap();

        let keys = root.rekor_keys();
        assert!(keys.usable.is_empty());
        assert_eq!(keys.unusable.len(), 1);
    }

    #[test]
    fn test_staging_ct_keys_report_the_rsa_key_unusable() {
        // Staging's CT log key is a raw PKCS#1 RSA key with deprecated key
        // details; it must be reported, not silently dropped or fatal.
        let root = TrustedRoot::from_json(SIGSTORE_STAGING_TRUSTED_ROOT).unwrap();
        let keys = root.ctfe_keys();
        assert!(!keys.usable.is_empty());
        assert_eq!(keys.unusable.len(), 1);
    }

    #[test]
    fn test_fulcio_certs_exclude_not_yet_valid() {
        // raw cert bytes are not parsed by fulcio_certs, so dummy DER is fine here
        let json = r#"{
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities": [
                {
                    "uri": "https://fulcio-expired.example.com",
                    "certChain": { "certificates": [{ "rawBytes": "AAAA" }] },
                    "validFor": {"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}
                },
                {
                    "uri": "https://fulcio-current.example.com",
                    "certChain": { "certificates": [{ "rawBytes": "AAAA" }] },
                    "validFor": {"start": "2021-01-01T00:00:00Z"}
                },
                {
                    "uri": "https://fulcio-future.example.com",
                    "certChain": { "certificates": [{ "rawBytes": "AAAA" }] },
                    "validFor": {"start": "2999-01-01T00:00:00Z"}
                }
            ]
        }"#;
        let root = TrustedRoot::from_json(json).unwrap();

        // Expired CA is kept (verifies historical certificates), future CA is excluded
        let certs = root.fulcio_certs();
        assert_eq!(certs.len(), 2);
    }

    const TSA_TRUSTED_ROOT: &str = r#"{
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "timestampAuthorities": [{
            "uri": "https://tsa.example.com",
            "certChain": { "certificates": [{ "rawBytes": "AAAA" }] },
            "validFor": {"start": "2020-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"}
        }]
    }"#;

    #[test]
    fn test_tsa_validity_window() {
        let root = TrustedRoot::from_json(TSA_TRUSTED_ROOT).unwrap();

        let certs = root.tsa_certs_with_validity();
        assert_eq!(certs.len(), 1);
        assert_eq!(
            certs[0].1,
            Some(TimeRange::new(
                "2020-01-01T00:00:00Z".parse().unwrap(),
                Some("2030-01-01T00:00:00Z".parse().unwrap()),
            ))
        );

        assert!(root.is_timestamp_within_tsa_validity("2025-01-01T00:00:00Z".parse().unwrap()));
        assert!(!root.is_timestamp_within_tsa_validity("2019-01-01T00:00:00Z".parse().unwrap()));
        // Closed interval: the end bound is inside the window
        assert!(root.is_timestamp_within_tsa_validity("2030-01-01T00:00:00Z".parse().unwrap()));
        assert!(!root.is_timestamp_within_tsa_validity("2030-01-01T00:00:01Z".parse().unwrap()));

        assert_eq!(root.tsa_root_certs().len(), 1);
        assert_eq!(root.tsa_leaf_certs().len(), 1);
    }

    #[test]
    fn test_tsa_malformed_timestamp_is_a_parse_error() {
        let bad = TSA_TRUSTED_ROOT.replace("2020-01-01T00:00:00Z", "BAD-TIMESTAMP");
        assert!(matches!(TrustedRoot::from_json(&bad), Err(Error::Json(_))));
    }

    #[test]
    fn test_validity_period_is_a_time_range() {
        // `ValidityPeriod` is the protobuf-specs `TimeRange`; the containment
        // semantics themselves are covered in `crate::time_range`.
        let root = trusted_root_with_tlog_validity(&[(
            "key",
            r#"{"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}"#,
        )]);
        let period: ValidityPeriod = root.tlogs[0].public_key.valid_for.unwrap();

        assert_eq!(
            period,
            TimeRange::new(
                "2020-01-01T00:00:00Z".parse().unwrap(),
                Some("2021-01-01T00:00:00Z".parse().unwrap()),
            )
        );
        assert!(period.contains("2020-06-01T00:00:00Z".parse().unwrap()));
        assert!(!period.contains("2019-06-01T00:00:00Z".parse().unwrap()));
        assert!(period.has_started_by("2022-06-01T00:00:00Z".parse().unwrap()));
    }
}
