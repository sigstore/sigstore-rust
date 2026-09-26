//! Trusted root types and parsing

use crate::{Error, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sigstore_crypto::{Keyring, SigningScheme, VerificationKey};
use sigstore_types::{
    DerCertificate, DerPublicKey, HashAlgorithm, LogId, LogKeyId, Sha256Hash, TimeRange,
    TsaAuthority,
};

/// A trusted root bundle containing all trust anchors
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
    pub valid_for: Option<TimeRange>,
}

/// A Certificate Transparency log entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
#[non_exhaustive]
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
    pub valid_for: Option<TimeRange>,
}

/// The protobuf-specs `PublicKeyDetails` name of a key's algorithm and
/// encoding, such as `PKIX_ECDSA_P256_SHA_256` or `PKIX_ED25519`.
///
/// Kept as the specification's string, so trust roots listing algorithms this
/// crate does not know still parse.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct PublicKeyDetails(String);

impl PublicKeyDetails {
    /// Wrap a `PublicKeyDetails` name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The `PublicKeyDetails` name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PublicKeyDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Public key information
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PublicKey {
    /// Raw bytes of the public key (DER-encoded)
    pub raw_bytes: DerPublicKey,

    /// Key details/type
    pub key_details: PublicKeyDetails,

    /// Validity period for this key
    #[serde(default)]
    pub valid_for: Option<TimeRange>,
}

/// Subject information for a certificate.
///
/// Note: This is different from `sigstore_types::Subject` which represents
/// an in-toto Statement subject (artifact name + digest).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct CertChain {
    /// Certificates in the chain
    pub certificates: Vec<CertificateEntry>,
}

/// A certificate entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CertificateEntry {
    /// Raw bytes of the certificate (DER-encoded)
    pub raw_bytes: DerCertificate,
}

/// Whether an instance with the given `valid_for` may be used as verification
/// material at `now`.
///
/// Instances without a `valid_for` constraint are always usable. Instances
/// whose window has not started yet are excluded; expired instances are kept
/// because historical entries/certificates were created while they were valid.
fn usable_for_verification(valid_for: Option<&TimeRange>, now: Timestamp) -> bool {
    valid_for.is_none_or(|period| period.has_started_by(now))
}

fn key_id(log_id: &LogKeyId) -> Result<Sha256Hash> {
    Ok(Sha256Hash::try_from(log_id.as_bytes())?)
}

impl TrustedRoot {
    /// Parse a trusted root from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load a trusted root from a file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }

    /// Get all Fulcio certificate authority certificates
    ///
    /// Certificate authorities whose `valid_for` window has not started yet
    /// are excluded. Expired certificate authorities are included because
    /// they are needed to verify certificates issued while they were valid.
    pub fn fulcio_certs(&self) -> Vec<DerCertificate> {
        let now = Timestamp::now();
        let mut certs = Vec::new();
        for ca in &self.certificate_authorities {
            if !usable_for_verification(ca.valid_for.as_ref(), now) {
                continue;
            }
            for cert_entry in &ca.cert_chain.certificates {
                certs.push(cert_entry.raw_bytes.clone());
            }
        }
        certs
    }

    /// Build a keyring containing all supported Rekor transparency log keys.
    ///
    /// Key IDs and validity windows come directly from the trusted root. The
    /// keyring applies those windows when callers perform time-aware lookups.
    /// Unsupported key material is skipped so adding a key for a newer
    /// algorithm does not make otherwise usable trust material fail on older
    /// clients. Malformed or duplicate IDs are rejected deterministically
    /// rather than making the result depend on array order.
    pub fn rekor_keys(&self) -> Result<Keyring> {
        let mut keyring = Keyring::new();
        for tlog in &self.tlogs {
            let Ok(key) = VerificationKey::from_spki(&tlog.public_key.raw_bytes) else {
                continue;
            };
            let key_id = key_id(&tlog.log_id.key_id)?;
            if keyring.get_key(&key_id).is_some() {
                return Err(Error::InvalidKey(format!(
                    "duplicate Rekor log ID: {}",
                    tlog.log_id.key_id
                )));
            }
            keyring.add_key_with_validity(key_id, key, tlog.public_key.valid_for);
        }
        Ok(keyring)
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
                if !usable_for_verification(tlog.public_key.valid_for.as_ref(), now) {
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
                let valid = tlog
                    .public_key
                    .valid_for
                    .is_none_or(|period| period.contains(time));
                if valid {
                    return Ok(tlog.public_key.raw_bytes.clone());
                }
            }
        }
        Err(Error::KeyNotFound(log_id.to_string()))
    }

    /// Build a keyring containing all Certificate Transparency log keys.
    ///
    /// The SCT supplies the signature scheme, while key IDs and validity
    /// windows come directly from the trusted root.
    pub fn ctfe_keys(&self, scheme: SigningScheme) -> Result<Keyring> {
        let mut keyring = Keyring::new();
        for ctlog in &self.ctlogs {
            // A trusted root can contain keys for a different algorithm than
            // this SCT uses. They are not candidates for this keyring.
            let Ok(key) = VerificationKey::from_der(&ctlog.public_key.raw_bytes, scheme) else {
                continue;
            };
            keyring.add_key_with_validity(
                key_id(&ctlog.log_id.key_id)?,
                key,
                ctlog.public_key.valid_for,
            );
        }
        Ok(keyring)
    }

    /// Get each timestamp authority usable for verification.
    ///
    /// Each authority's chain is kept separate so cryptographic verification
    /// and temporal authorization always use the same authority (verify a
    /// timestamp against one via
    /// `sigstore_tsa::verify_timestamp_for_authority`). Authorities with
    /// empty chains or validity windows that have not started are skipped;
    /// expired authorities remain available for historical verification.
    pub fn tsa_authorities(&self) -> Vec<TsaAuthority> {
        let now = Timestamp::now();
        let mut authorities = Vec::new();
        for tsa in &self.timestamp_authorities {
            if !usable_for_verification(tsa.valid_for.as_ref(), now) {
                continue;
            }
            let (leaf, intermediates, root) = match tsa.cert_chain.certificates.as_slice() {
                [] => continue,
                [root] => (root, &[][..], root),
                [leaf, intermediates @ .., root] => (leaf, intermediates, root),
            };
            let intermediates = intermediates
                .iter()
                .map(|cert| cert.raw_bytes.clone())
                .collect();
            authorities.push(TsaAuthority::new(
                leaf.raw_bytes.clone(),
                intermediates,
                root.raw_bytes.clone(),
                tsa.valid_for,
            ));
        }
        authorities
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
#[non_exhaustive]
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

    /// Return the embedded `signing_config.json` snapshot, if this instance
    /// publishes one (GitHub's instance does not).
    pub fn embedded_signing_config_json(self) -> Option<&'static str> {
        match self {
            Self::PublicGood => Some(crate::SIGSTORE_PRODUCTION_SIGNING_CONFIG),
            Self::Staging => Some(crate::SIGSTORE_STAGING_SIGNING_CONFIG),
            Self::GitHub => None,
        }
    }

    /// Load this instance's embedded signing config snapshot, if it has one.
    ///
    /// Snapshots go stale; prefer fetching the signing config through TUF.
    pub fn embedded_signing_config(self) -> Result<Option<crate::SigningConfig>> {
        self.embedded_signing_config_json()
            .map(crate::SigningConfig::from_json)
            .transpose()
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
                "keyId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
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
        assert_eq!(root.tlogs[0].log_id.key_id, LogKeyId::from_bytes(&[0; 32]));
    }

    fn test_key_id(label: &str) -> Sha256Hash {
        sigstore_crypto::sha256(label.as_bytes())
    }

    #[test]
    fn test_rekor_keys() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        let keys = root.rekor_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.get_key(&Sha256Hash::new([0; 32])).is_some());
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
                let key_id = test_key_id(key_id).to_base64();
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

        let keys = root.rekor_keys().unwrap();
        assert_eq!(keys.len(), 3);
        let now = Timestamp::now();
        assert!(keys
            .get_key_started_by(&test_key_id("expired-key"), now)
            .is_some());
        assert!(keys
            .get_key_started_by(&test_key_id("current-key"), now)
            .is_some());
        assert!(keys
            .get_key_started_by(&test_key_id("future-key"), now)
            .is_none());

        // The compatibility lookup honors the same rule.
        assert!(root
            .rekor_key_for_log(&LogKeyId::from_bytes(test_key_id("expired-key").as_bytes()))
            .is_ok());
        assert!(root
            .rekor_key_for_log(&LogKeyId::from_bytes(test_key_id("current-key").as_bytes()))
            .is_ok());
        assert!(matches!(
            root.rekor_key_for_log(&LogKeyId::from_bytes(test_key_id("future-key").as_bytes())),
            Err(Error::KeyNotFound(_))
        ));
    }

    #[test]
    fn test_rekor_key_for_log_at_checks_full_window() {
        let root = trusted_root_with_tlog_validity(&[(
            "windowed-key",
            r#"{"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}"#,
        )]);
        let key_id = LogKeyId::from_bytes(test_key_id("windowed-key").as_bytes());

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
        let current_id = test_key_id("current-ctlog").to_base64();
        let future_id = test_key_id("future-ctlog").to_base64();
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
                        "logId": {{ "keyId": "{current_id}" }}
                    }},
                    {{
                        "baseUrl": "https://ctfe-future.example.com",
                        "hashAlgorithm": "SHA2_256",
                        "publicKey": {{
                            "rawBytes": "{TEST_KEY}",
                            "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                            "validFor": {{"start": "2999-01-01T00:00:00Z"}}
                        }},
                        "logId": {{ "keyId": "{future_id}" }}
                    }}
                ]
            }}"#
        );
        let root = TrustedRoot::from_json(&json).unwrap();

        let keys = root.ctfe_keys(SigningScheme::EcdsaP256Sha256).unwrap();
        assert_eq!(keys.len(), 2);
        let now = Timestamp::now();
        assert!(keys
            .get_key_started_by(&test_key_id("current-ctlog"), now)
            .is_some());
        assert!(keys
            .get_key_started_by(&test_key_id("future-ctlog"), now)
            .is_none());

        // Malformed timestamp is rejected when the trusted root is parsed
        let bad_json = json.replace("2999-01-01T00:00:00Z", "garbage");
        assert!(matches!(
            TrustedRoot::from_json(&bad_json),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn unsupported_rekor_entries_do_not_poison_keyring() {
        let mut value: serde_json::Value = serde_json::from_str(SAMPLE_TRUSTED_ROOT).unwrap();
        let unsupported = serde_json::json!({
            "baseUrl": "https://future-rekor.example.com",
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": "AQID",
                "keyDetails": "FUTURE_KEY_TYPE"
            },
            "logId": {
                "keyId": sigstore_crypto::sha256(b"future-key").to_base64()
            }
        });
        value["tlogs"].as_array_mut().unwrap().push(unsupported);
        let root = TrustedRoot::from_json(&value.to_string()).unwrap();
        assert_eq!(root.rekor_keys().unwrap().len(), 1);
    }

    #[test]
    fn malformed_rekor_log_ids_are_rejected() {
        let json =
            SAMPLE_TRUSTED_ROOT.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQID");
        let root = TrustedRoot::from_json(&json).unwrap();
        assert!(root.rekor_keys().is_err());
    }

    #[test]
    fn duplicate_rekor_log_ids_are_rejected_deterministically() {
        let mut value: serde_json::Value = serde_json::from_str(SAMPLE_TRUSTED_ROOT).unwrap();
        let duplicate = value["tlogs"][0].clone();
        value["tlogs"].as_array_mut().unwrap().push(duplicate);
        let root = TrustedRoot::from_json(&value.to_string()).unwrap();
        assert!(matches!(root.rekor_keys(), Err(Error::InvalidKey(_))));
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
    fn test_tsa_authorities_split_per_authority() {
        let root = TrustedRoot::from_json(TSA_TRUSTED_ROOT).unwrap();
        let authorities = root.tsa_authorities();
        assert_eq!(authorities.len(), 1);

        let authority = &authorities[0];
        assert_eq!(authority.leaf.as_bytes(), &[0, 0, 0]);
        assert!(authority.intermediates.is_empty());
        assert_eq!(authority.root.as_bytes(), &[0, 0, 0]);
        // The window is carried through verbatim; enforcement lives in
        // `sigstore_tsa::verify_timestamp_for_authority`.
        assert_eq!(
            authority.valid_for,
            Some(TimeRange::new(
                "2020-01-01T00:00:00Z".parse().unwrap(),
                Some("2030-01-01T00:00:00Z".parse().unwrap()),
            ))
        );
    }

    #[test]
    fn test_tsa_malformed_timestamp_is_a_parse_error() {
        let bad = TSA_TRUSTED_ROOT.replace("2020-01-01T00:00:00Z", "BAD-TIMESTAMP");
        assert!(matches!(TrustedRoot::from_json(&bad), Err(Error::Json(_))));
    }

    #[test]
    fn test_validity_period_is_a_time_range() {
        // `TimeRange` is the protobuf-specs `TimeRange`; the containment
        // semantics themselves are covered by `sigstore_types::TimeRange`.
        let root = trusted_root_with_tlog_validity(&[(
            "key",
            r#"{"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"}"#,
        )]);
        let period: TimeRange = root.tlogs[0].public_key.valid_for.unwrap();

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

    #[test]
    fn instances_expose_their_embedded_material() {
        for instance in [
            SigstoreInstance::PublicGood,
            SigstoreInstance::Staging,
            SigstoreInstance::GitHub,
        ] {
            instance.embedded_trusted_root().unwrap();
            let signing_config = instance.embedded_signing_config().unwrap();
            assert_eq!(
                signing_config.is_some(),
                instance != SigstoreInstance::GitHub
            );
        }
    }
}
