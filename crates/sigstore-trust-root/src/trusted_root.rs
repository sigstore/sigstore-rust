//! Trusted root types and parsing

use crate::{Error, Result};
use jiff::Timestamp;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sigstore_types::{DerCertificate, DerPublicKey, HashAlgorithm, KeyHint, LogId, LogKeyId};
use std::collections::HashMap;

/// TSA certificate with optional validity period (start, end)
pub type TsaCertWithValidity = (
    CertificateDer<'static>,
    Option<Timestamp>,
    Option<Timestamp>,
);

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

    /// Key details/type
    pub key_details: String,

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

/// Validity period for a key or certificate
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityPeriod {
    /// Start time (ISO 8601)
    #[serde(default)]
    pub start: Option<String>,

    /// End time (ISO 8601)
    #[serde(default)]
    pub end: Option<String>,
}

fn parse_validity_timestamp(value: Option<&str>, field: &str) -> Result<Option<Timestamp>> {
    value
        .map(|s| {
            s.parse::<Timestamp>().map_err(|e| {
                Error::TimeParse(format!("invalid validFor.{field} timestamp {s:?}: {e}"))
            })
        })
        .transpose()
}

impl ValidityPeriod {
    /// Parsed start of the validity window.
    ///
    /// Returns an error if the timestamp is present but malformed.
    pub fn start(&self) -> Result<Option<Timestamp>> {
        parse_validity_timestamp(self.start.as_deref(), "start")
    }

    /// Parsed end of the validity window.
    ///
    /// Returns an error if the timestamp is present but malformed.
    pub fn end(&self) -> Result<Option<Timestamp>> {
        parse_validity_timestamp(self.end.as_deref(), "end")
    }

    /// Whether `time` falls within this validity window.
    ///
    /// A missing `start` or `end` bound is treated as unbounded on that side.
    /// Returns an error if a timestamp is present but malformed.
    pub fn contains(&self, time: Timestamp) -> Result<bool> {
        let after_start = self.start()?.map_or(true, |s| time >= s);
        let before_end = self.end()?.map_or(true, |e| time <= e);
        Ok(after_start && before_end)
    }

    /// Whether this validity window has started by `time` (i.e. `start` is
    /// unset or `start <= time`).
    ///
    /// Instances that have started — including ones whose window has since
    /// expired — are still required to verify historical material that was
    /// produced while they were valid.
    pub fn has_started_by(&self, time: Timestamp) -> Result<bool> {
        Ok(self.start()?.map_or(true, |s| time >= s))
    }
}

/// Whether an instance with the given `valid_for` may be used as verification
/// material at `now`.
///
/// Instances without a `valid_for` constraint are always usable. Instances
/// whose window has not started yet are excluded; expired instances are kept
/// because historical entries/certificates were created while they were valid.
fn usable_for_verification(valid_for: Option<&ValidityPeriod>, now: Timestamp) -> Result<bool> {
    match valid_for {
        None => Ok(true),
        Some(period) => period.has_started_by(now),
    }
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
    pub fn fulcio_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let now = Timestamp::now();
        let mut certs = Vec::new();
        for ca in &self.certificate_authorities {
            if !usable_for_verification(ca.valid_for.as_ref(), now)? {
                continue;
            }
            for cert_entry in &ca.cert_chain.certificates {
                certs.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        Ok(certs)
    }

    /// Get all Rekor public keys mapped by key ID
    ///
    /// Keys whose `valid_for` window has not started yet are excluded.
    /// Expired keys are included because they are needed to verify log
    /// entries that were integrated while the key was valid.
    pub fn rekor_keys(&self) -> Result<HashMap<String, Vec<u8>>> {
        let now = Timestamp::now();
        let mut keys = HashMap::new();
        for tlog in &self.tlogs {
            if !usable_for_verification(tlog.public_key.valid_for.as_ref(), now)? {
                continue;
            }
            keys.insert(
                tlog.log_id.key_id.to_string(),
                tlog.public_key.raw_bytes.as_bytes().to_vec(),
            );
        }
        Ok(keys)
    }

    /// Get all Rekor public keys with their key hints (4-byte identifiers)
    ///
    /// Returns a vector of (key_hint, public_key) tuples where key_hint is
    /// the first 4 bytes of the keyId from the log_id field.
    ///
    /// Keys whose `valid_for` window has not started yet are excluded.
    /// Expired keys are included because they are needed to verify log
    /// entries that were integrated while the key was valid.
    pub fn rekor_keys_with_hints(&self) -> Result<Vec<(KeyHint, DerPublicKey)>> {
        let now = Timestamp::now();
        let mut keys = Vec::new();
        for tlog in &self.tlogs {
            if !usable_for_verification(tlog.public_key.valid_for.as_ref(), now)? {
                continue;
            }
            // Decode the key_id to get the key hint (first 4 bytes)
            let key_id_bytes = tlog.log_id.key_id.decode()?;

            if key_id_bytes.len() >= 4 {
                let key_hint = KeyHint::new([
                    key_id_bytes[0],
                    key_id_bytes[1],
                    key_id_bytes[2],
                    key_id_bytes[3],
                ]);
                keys.push((key_hint, tlog.public_key.raw_bytes.clone()));
            }
        }
        Ok(keys)
    }

    /// Get a specific Rekor public key by log ID
    ///
    /// Keys whose `valid_for` window has not started yet are not returned.
    /// Expired keys are returned because they are needed to verify log
    /// entries that were integrated while the key was valid.
    pub fn rekor_key_for_log(&self, log_id: &LogKeyId) -> Result<DerPublicKey> {
        let now = Timestamp::now();
        for tlog in &self.tlogs {
            if &tlog.log_id.key_id == log_id {
                if !usable_for_verification(tlog.public_key.valid_for.as_ref(), now)? {
                    continue;
                }
                return Ok(tlog.public_key.raw_bytes.clone());
            }
        }
        Err(Error::KeyNotFound(log_id.to_string()))
    }

    /// Get a specific Rekor public key by log ID, valid at the given time
    ///
    /// Unlike [`Self::rekor_key_for_log`] this requires the key's `valid_for`
    /// window (if present) to fully contain `time`, which is suitable when
    /// the relevant timestamp of the material being verified is known (e.g.
    /// a log entry's integrated time).
    pub fn rekor_key_for_log_at(&self, log_id: &LogKeyId, time: Timestamp) -> Result<DerPublicKey> {
        for tlog in &self.tlogs {
            if &tlog.log_id.key_id == log_id {
                let valid = match &tlog.public_key.valid_for {
                    None => true,
                    Some(period) => period.contains(time)?,
                };
                if valid {
                    return Ok(tlog.public_key.raw_bytes.clone());
                }
            }
        }
        Err(Error::KeyNotFound(log_id.to_string()))
    }

    /// Get all Certificate Transparency log public keys mapped by key ID
    ///
    /// Keys whose `valid_for` window has not started yet are excluded.
    /// Expired keys are included because they are needed to verify SCTs
    /// issued while the key was valid.
    pub fn ctfe_keys(&self) -> Result<HashMap<LogKeyId, DerPublicKey>> {
        let now = Timestamp::now();
        let mut keys = HashMap::new();
        for ctlog in &self.ctlogs {
            if !usable_for_verification(ctlog.public_key.valid_for.as_ref(), now)? {
                continue;
            }
            keys.insert(
                ctlog.log_id.key_id.clone(),
                ctlog.public_key.raw_bytes.clone(),
            );
        }
        Ok(keys)
    }

    /// Get all Certificate Transparency log public keys with their SHA-256 log IDs
    /// Returns a list of (log_id, public_key) pairs where log_id is the SHA-256 hash
    /// of the public key (used for matching against SCTs)
    ///
    /// Keys whose `valid_for` window has not started yet are excluded.
    /// Expired keys are included because they are needed to verify SCTs
    /// issued while the key was valid.
    pub fn ctfe_keys_with_ids(&self) -> Result<Vec<(Vec<u8>, DerPublicKey)>> {
        let now = Timestamp::now();
        let mut result = Vec::new();
        for ctlog in &self.ctlogs {
            if !usable_for_verification(ctlog.public_key.valid_for.as_ref(), now)? {
                continue;
            }
            let key_bytes = ctlog.public_key.raw_bytes.as_bytes();
            // Compute SHA-256 hash of the public key to get the log ID
            let log_id = sigstore_crypto::sha256(key_bytes).as_bytes().to_vec();
            result.push((log_id, ctlog.public_key.raw_bytes.clone()));
        }
        Ok(result)
    }

    /// Get all TSA certificates with their validity periods
    ///
    /// Returns an error if a `valid_for` timestamp is present but malformed.
    pub fn tsa_certs_with_validity(&self) -> Result<Vec<TsaCertWithValidity>> {
        let mut result = Vec::new();

        for tsa in &self.timestamp_authorities {
            // Parse validity period, propagating malformed timestamps as errors
            let (start, end) = match &tsa.valid_for {
                Some(valid_for) => (valid_for.start()?, valid_for.end()?),
                None => (None, None),
            };

            for cert_entry in &tsa.cert_chain.certificates {
                let cert_der = cert_entry.raw_bytes.as_bytes().to_vec();
                result.push((CertificateDer::from(&cert_der[..]).into_owned(), start, end));
            }
        }

        Ok(result)
    }

    /// Get TSA root certificates (for chain validation)
    ///
    /// Timestamp authorities whose `valid_for` window has not started yet are
    /// excluded. Expired authorities are included because they are needed to
    /// verify timestamps issued while they were valid.
    pub fn tsa_root_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let now = Timestamp::now();
        let mut roots = Vec::new();
        for tsa in &self.timestamp_authorities {
            if !usable_for_verification(tsa.valid_for.as_ref(), now)? {
                continue;
            }
            // The last certificate in the chain is typically the root
            if let Some(cert_entry) = tsa.cert_chain.certificates.last() {
                roots.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        Ok(roots)
    }

    /// Get TSA intermediate certificates (for chain validation)
    ///
    /// Timestamp authorities whose `valid_for` window has not started yet are
    /// excluded. Expired authorities are included because they are needed to
    /// verify timestamps issued while they were valid.
    pub fn tsa_intermediate_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let now = Timestamp::now();
        let mut intermediates = Vec::new();
        for tsa in &self.timestamp_authorities {
            if !usable_for_verification(tsa.valid_for.as_ref(), now)? {
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
        Ok(intermediates)
    }

    /// Get TSA leaf certificates (the first certificate in each chain)
    /// These are the actual TSA signing certificates
    ///
    /// Timestamp authorities whose `valid_for` window has not started yet are
    /// excluded. Expired authorities are included because they are needed to
    /// verify timestamps issued while they were valid.
    pub fn tsa_leaf_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let now = Timestamp::now();
        let mut leaves = Vec::new();
        for tsa in &self.timestamp_authorities {
            if !usable_for_verification(tsa.valid_for.as_ref(), now)? {
                continue;
            }
            // The first certificate in the chain is the leaf (TSA signing cert)
            if let Some(cert_entry) = tsa.cert_chain.certificates.first() {
                leaves.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        Ok(leaves)
    }

    /// Check if a Rekor key ID exists in the trusted root
    ///
    /// Note: this is a pure presence check and does not consider `valid_for`.
    pub fn has_rekor_key(&self, key_id: &LogKeyId) -> bool {
        self.tlogs.iter().any(|tlog| &tlog.log_id.key_id == key_id)
    }

    /// Get the validity period for a TSA at a given time
    ///
    /// Returns an error if a `valid_for` timestamp is present but malformed.
    pub fn tsa_validity_for_time(
        &self,
        timestamp: Timestamp,
    ) -> Result<Option<(Timestamp, Timestamp)>> {
        for tsa in &self.timestamp_authorities {
            if let Some(valid_for) = &tsa.valid_for {
                let start = valid_for.start()?;
                let end = valid_for.end()?;

                // Check if timestamp falls within this TSA's validity
                if let (Some(start_time), Some(end_time)) = (start, end) {
                    if timestamp >= start_time && timestamp <= end_time {
                        return Ok(Some((start_time, end_time)));
                    }
                } else if let Some(start_time) = start {
                    // Only start time specified, check if after start
                    if timestamp >= start_time {
                        return Ok(start.zip(end));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Check if a timestamp is within any TSA's validity period from the trust root
    ///
    /// Returns `Ok(true)` if:
    /// - There are no timestamp authorities configured (no TSA verification)
    /// - Any TSA has no `valid_for` field (open-ended validity)
    /// - The timestamp falls within at least one TSA's `valid_for` period
    ///
    /// Returns `Ok(false)` only if there are TSAs with validity constraints and
    /// the timestamp doesn't fall within any of them.
    ///
    /// Returns an error if a `valid_for` timestamp is present but malformed.
    pub fn is_timestamp_within_tsa_validity(&self, timestamp: Timestamp) -> Result<bool> {
        // If no TSAs are configured, no validity check needed
        if self.timestamp_authorities.is_empty() {
            return Ok(true);
        }

        for tsa in &self.timestamp_authorities {
            // If a TSA has no valid_for constraint, it's valid for all time
            let Some(valid_for) = &tsa.valid_for else {
                return Ok(true);
            };

            // Check if timestamp falls within this TSA's validity period
            if valid_for.contains(timestamp)? {
                return Ok(true);
            }
        }

        // No TSA's validity period matched
        Ok(false)
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

    #[test]
    fn test_rekor_keys() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        let keys = root.rekor_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("test-key-id"));
    }

    #[test]
    fn test_has_rekor_key() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        assert!(root.has_rekor_key(&LogKeyId::new("test-key-id".to_string())));
        assert!(!root.has_rekor_key(&LogKeyId::new("non-existent".to_string())));
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

    fn trusted_root_with_tlog_validity(valid_for: &[(&str, &str)]) -> TrustedRoot {
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
        let json = format!(
            r#"{{
                "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                "tlogs": [{}]
            }}"#,
            tlogs.join(",")
        );
        TrustedRoot::from_json(&json).unwrap()
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

        let keys = root.rekor_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("expired-key"));
        assert!(keys.contains_key("current-key"));
        assert!(!keys.contains_key("future-key"));

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
    fn test_rekor_keys_malformed_timestamp_is_error() {
        let root =
            trusted_root_with_tlog_validity(&[("bad-key", r#"{"start": "not-a-timestamp"}"#)]);

        assert!(matches!(root.rekor_keys(), Err(Error::TimeParse(_))));
        assert!(matches!(
            root.rekor_keys_with_hints(),
            Err(Error::TimeParse(_))
        ));
        assert!(matches!(
            root.rekor_key_for_log(&LogKeyId::new("bad-key".to_string())),
            Err(Error::TimeParse(_))
        ));
    }

    #[test]
    fn test_ctfe_keys_exclude_not_yet_valid_and_error_on_malformed() {
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

        let keys = root.ctfe_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key(&LogKeyId::new("current-ctlog".to_string())));

        assert_eq!(root.ctfe_keys_with_ids().unwrap().len(), 1);

        // Malformed timestamp produces an error
        let bad_json = json.replace("2999-01-01T00:00:00Z", "garbage");
        let bad_root = TrustedRoot::from_json(&bad_json).unwrap();
        assert!(matches!(bad_root.ctfe_keys(), Err(Error::TimeParse(_))));
        assert!(matches!(
            bad_root.ctfe_keys_with_ids(),
            Err(Error::TimeParse(_))
        ));
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
        let certs = root.fulcio_certs().unwrap();
        assert_eq!(certs.len(), 2);
    }

    const TSA_TRUSTED_ROOT: &str = r#"{
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "timestampAuthorities": [{
            "uri": "https://tsa.example.com",
            "certChain": { "certificates": [{ "rawBytes": "AAAA" }] },
            "validFor": {"start": "BAD-TIMESTAMP", "end": "2030-01-01T00:00:00Z"}
        }]
    }"#;

    #[test]
    fn test_tsa_malformed_timestamp_is_error() {
        let root = TrustedRoot::from_json(TSA_TRUSTED_ROOT).unwrap();
        let now = Timestamp::now();

        assert!(matches!(
            root.tsa_certs_with_validity(),
            Err(Error::TimeParse(_))
        ));
        assert!(matches!(
            root.is_timestamp_within_tsa_validity(now),
            Err(Error::TimeParse(_))
        ));
        assert!(matches!(
            root.tsa_validity_for_time(now),
            Err(Error::TimeParse(_))
        ));
        assert!(matches!(root.tsa_root_certs(), Err(Error::TimeParse(_))));
        assert!(matches!(root.tsa_leaf_certs(), Err(Error::TimeParse(_))));
    }

    #[test]
    fn test_validity_period_contains() {
        let period = ValidityPeriod {
            start: Some("2020-01-01T00:00:00Z".to_string()),
            end: Some("2021-01-01T00:00:00Z".to_string()),
        };
        let inside: Timestamp = "2020-06-01T00:00:00Z".parse().unwrap();
        let before: Timestamp = "2019-06-01T00:00:00Z".parse().unwrap();
        let after: Timestamp = "2022-06-01T00:00:00Z".parse().unwrap();

        assert!(period.contains(inside).unwrap());
        assert!(!period.contains(before).unwrap());
        assert!(!period.contains(after).unwrap());

        assert!(period.has_started_by(inside).unwrap());
        assert!(period.has_started_by(after).unwrap());
        assert!(!period.has_started_by(before).unwrap());

        // Open-ended period
        let open = ValidityPeriod {
            start: Some("2020-01-01T00:00:00Z".to_string()),
            end: None,
        };
        assert!(open.contains(after).unwrap());

        // Malformed timestamps surface as errors
        let bad = ValidityPeriod {
            start: Some("garbage".to_string()),
            end: None,
        };
        assert!(matches!(bad.contains(inside), Err(Error::TimeParse(_))));
        assert!(matches!(bad.start(), Err(Error::TimeParse(_))));
    }
}
