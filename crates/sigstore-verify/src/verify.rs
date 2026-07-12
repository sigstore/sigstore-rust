//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

use crate::error::{Error, Result};
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::{parse_certificate_info, SigningScheme};
use sigstore_trust_root::TrustedRoot;

use sigstore_types::{Artifact, Bundle, HashAlgorithm, SignatureContent, Statement};

/// Default clock skew tolerance in seconds (60 seconds = 1 minute)
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;

/// How the signing certificate is verified.
///
/// SCT verification depends on the issuer identified while verifying the
/// certificate chain, so it cannot be requested independently. Nesting the
/// `verify_sct` flag inside the [`CertificatePolicy::Verify`] variant makes the
/// invalid "verify SCT but not the chain" combination unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificatePolicy {
    /// Skip certificate chain verification (and, necessarily, SCT verification).
    ///
    /// WARNING: This is unsafe for production use. Only use for testing with
    /// bundles that don't chain to the trusted root.
    Skip,
    /// Verify the certificate chains to the trusted root, is valid at the time
    /// of signing, and has the CODE_SIGNING EKU.
    Verify {
        /// Also verify the certificate's embedded Signed Certificate Timestamp.
        verify_sct: bool,
    },
}

/// Policy for verifying signatures
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Expected identity (email or URI)
    pub identity: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Verify transparency log inclusion
    pub verify_tlog: bool,
    /// How the signing certificate (and its SCT) is verified
    pub certificate: CertificatePolicy,
    /// Clock skew tolerance in seconds for time validation
    ///
    /// This allows for a tolerance when checking that integrated times
    /// are not in the future. Default is 60 seconds.
    pub clock_skew_seconds: i64,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            identity: None,
            issuer: None,
            verify_tlog: true,
            certificate: CertificatePolicy::Verify { verify_sct: true },
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }
}

impl VerificationPolicy {
    /// Create a policy that requires a specific identity
    pub fn with_identity(identity: impl Into<String>) -> Self {
        Self {
            identity: Some(identity.into()),
            ..Default::default()
        }
    }

    /// Create a policy that requires a specific issuer
    pub fn with_issuer(issuer: impl Into<String>) -> Self {
        Self {
            issuer: Some(issuer.into()),
            ..Default::default()
        }
    }

    /// Require a specific identity
    pub fn require_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Require a specific issuer
    pub fn require_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Skip transparency log verification
    pub fn skip_tlog(mut self) -> Self {
        self.verify_tlog = false;
        self
    }

    /// Skip certificate chain verification
    ///
    /// WARNING: This is unsafe for production use. Only use for testing
    /// with bundles that don't chain to the trusted root. This also skips SCT
    /// verification, which depends on the verified certificate chain.
    pub fn skip_certificate_chain(mut self) -> Self {
        self.certificate = CertificatePolicy::Skip;
        self
    }

    /// Skip Signed Certificate Timestamp verification
    ///
    /// This is needed for trust domains, such as GitHub's artifact attestation
    /// instance, whose certificates do not carry public Sigstore CT SCTs. The
    /// certificate chain is still verified unless `skip_certificate_chain()` is
    /// also used.
    pub fn skip_sct(mut self) -> Self {
        if let CertificatePolicy::Verify { verify_sct } = &mut self.certificate {
            *verify_sct = false;
        }
        self
    }

    /// Set the clock skew tolerance in seconds
    ///
    /// This allows for a tolerance when checking that integrated times
    /// are not in the future. Default is 60 seconds.
    pub fn with_clock_skew_seconds(mut self, seconds: i64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }
}

/// Result of verification
///
/// This is returned only when verification *succeeds* — any failure is reported
/// as an [`Err`]. It carries metadata extracted during verification (identity,
/// issuer, integrated time) plus any non-fatal warnings.
#[derive(Debug)]
pub struct VerificationResult {
    /// Identity from the certificate
    pub identity: Option<String>,
    /// Issuer from the certificate
    pub issuer: Option<String>,
    /// Integrated time from transparency log
    pub integrated_time: Option<i64>,
    /// Any warnings during verification
    pub warnings: Vec<String>,
}

impl VerificationResult {
    /// Create an empty result to be populated as verification proceeds.
    pub fn new() -> Self {
        Self {
            identity: None,
            issuer: None,
            integrated_time: None,
            warnings: Vec::new(),
        }
    }
}

impl Default for VerificationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// A verifier for Sigstore signatures
pub struct Verifier {
    /// Trusted root containing verification material
    trusted_root: TrustedRoot,
}

impl Verifier {
    /// Create a new verifier with a trusted root
    ///
    /// The trusted root is required and contains all cryptographic material
    /// needed for verification (Fulcio CA certs, Rekor keys, TSA certs, etc.)
    pub fn new(trusted_root: &TrustedRoot) -> Self {
        Self {
            trusted_root: trusted_root.clone(),
        }
    }

    /// Verify an artifact against a bundle
    ///
    /// The artifact can be provided as raw bytes or as a pre-computed SHA-256 digest.
    /// When using a pre-computed digest, the raw bytes are not needed, which is useful
    /// for large files or when the digest is already known (e.g., from a registry).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_verify::{Verifier, VerificationPolicy};
    /// use sigstore_trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
    /// use sigstore_types::{Artifact, Bundle, Sha256Hash};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)?;
    /// let verifier = Verifier::new(&trusted_root);
    /// let bundle: Bundle = todo!();
    /// let policy = VerificationPolicy::default();
    ///
    /// // Option 1: Verify with raw bytes
    /// let artifact_bytes = b"hello world";
    /// verifier.verify(artifact_bytes.as_slice(), &bundle, &policy)?;
    ///
    /// // Option 2: Verify with pre-computed digest (no raw bytes needed!)
    /// let digest = Sha256Hash::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")?;
    /// verifier.verify(digest, &bundle, &policy)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// In order to verify an artifact, we need to achieve the following:
    ///
    /// 0. Establish the verified times for the signature.
    /// 1. Verify that the signing certificate chains to the root of trust
    ///    and is valid at every verified signing time.
    /// 2. Verify the signing certificate's SCT.
    /// 3. Verify that the signing certificate conforms to the Sigstore
    ///    X.509 profile as well as the passed-in `VerificationPolicy`.
    /// 4. Verify the inclusion proof and signed checkpoint for the log
    ///    entry.
    /// 5. Verify the inclusion promise for the log entry, if present.
    /// 6. Verify the timely insertion of the log entry against the validity
    ///    period for the signing certificate.
    /// 7. Verify the signature and input against the signing certificate's
    ///    public key.
    /// 8. Verify the transparency log entry's consistency against the other
    ///    materials, to prevent variants of CVE-2022-36056.
    pub fn verify<'a>(
        &self,
        artifact: impl Into<Artifact<'a>>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let artifact = artifact.into();
        let mut result = VerificationResult::new();

        // Validate bundle structure first. This is a purely structural
        // (shape/required-fields) check; all cryptographic verification of
        // the bundle's contents happens in the steps below.
        let options = ValidationOptions {
            require_inclusion_proof: policy.verify_tlog,
            require_timestamp: false, // Don't require timestamps, but verify if present
        };
        validate_bundle_with_options(bundle, &options)
            .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

        // Extract certificate for verification
        let cert = crate::verify_impl::helpers::extract_certificate(
            &bundle.verification_material.content,
        )?;
        let cert_info = parse_certificate_info(cert.as_bytes())
            .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

        // Store identity and issuer in result
        result.identity = cert_info.identity.clone();
        result.issuer = cert_info.issuer.clone();

        // (0): Establish the times for the signature
        // First, establish verified times for the signature. This is required to
        // validate the certificate chain, so this step comes first.
        // These include TSA timestamps and (in the case of rekor v1 entries)
        // rekor log integrated time.
        let signature = crate::verify_impl::helpers::extract_signature(&bundle.content)?;
        let validation_times = crate::verify_impl::helpers::determine_validation_times(
            bundle,
            &signature,
            &self.trusted_root,
        )?;

        // (1): Verify that the signing certificate chains to the root of trust,
        //      is valid at EVERY verified signing time, and has CODE_SIGNING EKU.
        //      Checking each timestamp (rather than only the earliest) prevents a
        //      single backdated timestamp - e.g. from one compromised TSA in a
        //      multi-TSA deployment - from vouching for expired key material.
        //      The verified path yields the leaf's direct issuer, which SCT
        //      verification needs to reconstruct the RFC 6962 signed data.
        //
        // (2): Verify the signing certificate's SCT. This is nested here because
        //      it consumes the issuer produced by chain verification; the type
        //      system therefore guarantees the issuer is available whenever SCT
        //      verification runs.
        if let CertificatePolicy::Verify { verify_sct } = policy.certificate {
            let mut issuer_spki = None;
            for &validation_time in &validation_times {
                issuer_spki = Some(crate::verify_impl::helpers::verify_certificate_chain(
                    &bundle.verification_material.content,
                    validation_time,
                    &self.trusted_root,
                )?);

                // Also verify the certificate is within its validity period
                crate::verify_impl::helpers::validate_certificate_time(
                    validation_time,
                    &cert_info,
                )?;
            }
            let issuer_spki =
                issuer_spki.expect("determine_validation_times returns at least one timestamp");

            if verify_sct {
                crate::verify_impl::sct::verify_sct(
                    cert.as_bytes(),
                    issuer_spki.as_bytes(),
                    &self.trusted_root,
                )?;
            }
        }

        // (3): Verify against the given `VerificationPolicy`.

        // Verify against policy constraints
        if let Some(ref expected_identity) = policy.identity {
            match &result.identity {
                Some(actual_identity) if actual_identity == expected_identity => {}
                Some(actual_identity) => {
                    return Err(Error::Verification(format!(
                        "identity mismatch: expected {}, got {}",
                        expected_identity, actual_identity
                    )));
                }
                None => {
                    return Err(Error::Verification(format!(
                        "certificate is missing identity (SAN), but policy requires: {}",
                        expected_identity
                    )));
                }
            }
        }

        if let Some(ref expected_issuer) = policy.issuer {
            match &result.issuer {
                Some(actual_issuer) if actual_issuer == expected_issuer => {}
                Some(actual_issuer) => {
                    return Err(Error::Verification(format!(
                        "issuer mismatch: expected {}, got {}",
                        expected_issuer, actual_issuer
                    )));
                }
                None => {
                    return Err(Error::Verification(format!(
                        "certificate is missing issuer (Fulcio OID extension), but policy requires: {}",
                        expected_issuer
                    )));
                }
            }
        }

        // (4): Verify the inclusion proof and signed checkpoint for the log entry.
        // (5): Verify the inclusion promise for the log entry, if present.
        // (6): Verify the timely insertion of the log entry against the validity
        //      period for the signing certificate.
        if policy.verify_tlog {
            let integrated_time = crate::verify_impl::tlog::verify_tlog_entries(
                bundle,
                &self.trusted_root,
                cert_info.not_before,
                cert_info.not_after,
                policy.clock_skew_seconds,
            )?;

            if let Some(time) = integrated_time {
                result.integrated_time = Some(time);
            }
        }

        // (7): Verify the signature and input against the signing certificate's
        //      public key.
        // For DSSE envelopes, verify using PAE (Pre-Authentication Encoding)
        if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
            let payload_bytes = envelope.decode_payload();

            // Compute the PAE that was signed
            let pae = sigstore_types::pae(&envelope.payload_type, &payload_bytes);

            // Verify at least one signature is cryptographically valid
            let mut any_sig_valid = false;
            for sig in &envelope.signatures {
                if sigstore_crypto::verify_signature(
                    &cert_info.public_key,
                    &pae,
                    &sig.sig,
                    cert_info.key_algorithm.default_signing_scheme(),
                )
                .is_ok()
                {
                    any_sig_valid = true;
                    break;
                }
            }

            if !any_sig_valid {
                return Err(Error::Verification(
                    "DSSE signature verification failed: no valid signatures found".to_string(),
                ));
            }

            // Verify the payload binds the artifact
            verify_dsse_artifact_binding(envelope, &artifact)?;
        }

        // For MessageSignature bundles, verify the messageDigest matches the artifact
        if let SignatureContent::MessageSignature(msg_sig) = &bundle.content {
            if let Some(ref digest) = msg_sig.message_digest {
                let artifact_hash = compute_artifact_digest_algo(&artifact, digest.algorithm)?;

                // Compare the digest in the bundle with the computed artifact hash
                if digest.digest != artifact_hash {
                    return Err(Error::Verification(
                        "message digest in bundle does not match artifact hash".to_string(),
                    ));
                }
            }

            // Cryptographically verify the signature over the artifact. This runs
            // regardless of `policy.verify_tlog` so the signature is always checked;
            // the transparency-log path (step 8) performs an equivalent check when
            // enabled, but must not be the only place verification happens.
            verify_message_signature_crypto(&cert_info, msg_sig, &artifact)?;
        }

        // (8): Verify the transparency log entry's consistency against the other
        //      materials, to prevent variants of CVE-2022-36056.
        if policy.verify_tlog {
            crate::verify_impl::verify_tlog_consistency(bundle, &artifact)?;
        }

        Ok(result)
    }
}

fn compute_artifact_digest_algo(artifact: &Artifact<'_>, algo: HashAlgorithm) -> Result<Vec<u8>> {
    match artifact {
        Artifact::Bytes(bytes) => match algo {
            HashAlgorithm::Sha2256 => Ok(sigstore_crypto::sha256(bytes).as_bytes().to_vec()),
            HashAlgorithm::Sha2384 => Ok(sigstore_crypto::sha384(bytes)),
            HashAlgorithm::Sha2512 => Ok(sigstore_crypto::sha512(bytes)),
        },
        Artifact::Digest(hash) => {
            let expected_len = algo.digest_size();
            if hash.len() != expected_len {
                return Err(Error::Verification(format!(
                    "expected digest length {} for {:?}, got {}",
                    expected_len,
                    algo,
                    hash.len()
                )));
            }
            Ok(hash.to_vec())
        }
    }
}

/// Verify that a DSSE envelope's payload binds the artifact being verified.
///
/// Only in-toto statements are supported: any other payload type has no
/// defined relationship to the artifact, so verification fails closed rather
/// than accepting an arbitrary artifact alongside a validly-signed envelope.
/// The artifact's SHA-256 digest must match at least one subject of the
/// statement, and the statement must have at least one subject.
///
/// Note: in-toto supports multiple digest algorithms (e.g. sha512), but
/// Sigstore currently mandates SHA-256 for attestation subjects.
fn verify_dsse_artifact_binding(
    envelope: &sigstore_types::DsseEnvelope,
    artifact: &Artifact<'_>,
) -> Result<()> {
    if envelope.payload_type != "application/vnd.in-toto+json" {
        return Err(Error::Verification(format!(
            "unsupported DSSE payload type {:?}: cannot bind artifact to attestation",
            envelope.payload_type
        )));
    }

    let artifact_hash = compute_artifact_digest_algo(artifact, HashAlgorithm::Sha2256)?;
    let artifact_hash_hex = sigstore_types::Sha256Hash::try_from_slice(&artifact_hash)
        .map_err(|_| Error::Verification("invalid SHA-256 hash length".to_string()))?
        .to_hex();

    let payload_str = std::str::from_utf8(envelope.payload.as_bytes())
        .map_err(|e| Error::Verification(format!("payload is not valid UTF-8: {}", e)))?;
    let statement: Statement = serde_json::from_str(payload_str)
        .map_err(|e| Error::Verification(format!("failed to parse in-toto statement: {}", e)))?;

    if statement.subject.is_empty() {
        return Err(Error::Verification(
            "in-toto statement has no subjects: cannot bind artifact to attestation".to_string(),
        ));
    }
    if !statement.matches_sha256(&artifact_hash_hex) {
        return Err(Error::Verification(
            "artifact hash does not match any subject in attestation".to_string(),
        ));
    }

    Ok(())
}

/// Verify `signature` over `artifact` with an already-resolved signing scheme.
///
/// Raw bytes are verified directly; a pre-computed digest uses prehashed
/// verification and fails closed if the scheme can't be prehashed (e.g. Ed25519),
/// since the original bytes aren't available to verify over.
fn verify_signature_over_artifact(
    public_key: &sigstore_types::DerPublicKey,
    scheme: SigningScheme,
    signature: &sigstore_types::SignatureBytes,
    artifact: &Artifact<'_>,
) -> Result<()> {
    let result = match artifact {
        Artifact::Bytes(bytes) => {
            sigstore_crypto::verify_signature(public_key, bytes, signature, scheme)
        }
        Artifact::Digest(hash) => {
            if !scheme.supports_prehashed() {
                return Err(Error::Verification(format!(
                    "cannot verify signature with digest-only - scheme {} does not support prehashed mode",
                    scheme.name()
                )));
            }
            sigstore_crypto::verify_signature_prehashed(public_key, hash, signature, scheme)
        }
    };
    result.map_err(|e| Error::Verification(format!("signature verification failed: {}", e)))
}

/// Cryptographically verify a `MessageSignature`'s signature over the artifact
/// using the signing certificate's public key.
///
/// This is intentionally independent of transparency-log verification. Without
/// it, a `MessageSignature` bundle verified with `policy.verify_tlog == false`
/// would only have its `messageDigest` compared against the artifact and its
/// signature would never be cryptographically checked. The signature hash is
/// resolved from the certificate's key algorithm plus the bundle's declared
/// `messageDigest.algorithm` (falling back to the key's default scheme).
fn verify_message_signature_crypto(
    cert_info: &sigstore_crypto::CertificateInfo,
    msg_sig: &sigstore_types::bundle::MessageSignature,
    artifact: &Artifact<'_>,
) -> Result<()> {
    let scheme = match &msg_sig.message_digest {
        Some(digest) => cert_info
            .key_algorithm
            .resolve_signing_scheme(digest.algorithm)?,
        None => cert_info.key_algorithm.default_signing_scheme(),
    };
    verify_signature_over_artifact(&cert_info.public_key, scheme, &msg_sig.signature, artifact)
}

/// Convenience function to verify an artifact against a bundle
///
/// This uses the trusted root for all cryptographic material
/// (Rekor keys, Fulcio certs, TSA certs).
///
/// The artifact can be provided as raw bytes or as a pre-computed SHA-256 digest:
/// - `verify(artifact_bytes, ...)` - pass raw bytes
/// - `verify(digest, ...)` - pass pre-computed digest
///
/// # Example
///
/// ```no_run
/// use sigstore_verify::verify;
/// use sigstore_trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
/// use sigstore_types::{Bundle, Sha256Hash};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)?;
/// let bundle_json = std::fs::read_to_string("artifact.sigstore.json")?;
/// let bundle = Bundle::from_json(&bundle_json)?;
/// let artifact = std::fs::read("artifact.txt")?;
///
/// verify(&artifact, &bundle, &sigstore_verify::VerificationPolicy::default(), &trusted_root)?;
/// # Ok(())
/// # }
/// ```
pub fn verify<'a>(
    artifact: impl Into<Artifact<'a>>,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let verifier = Verifier::new(trusted_root);
    verifier.verify(artifact, bundle, policy)
}

/// Verify an artifact against a bundle using a provided public key
///
/// This is used for managed key verification where the bundle contains a public key
/// hint instead of a certificate. The actual public key is provided separately.
///
/// This verification:
/// - Verifies the signature using the provided public key
/// - Verifies transparency log entries (Merkle inclusion proofs, checkpoints, SETs)
/// - Skips certificate chain verification (no certificate present)
/// - Skips identity/issuer verification
///
/// # Example
///
/// ```no_run
/// use sigstore_verify::verify_with_key;
/// use sigstore_trust_root::TrustedRoot;
/// use sigstore_types::{Bundle, DerPublicKey};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let trusted_root = TrustedRoot::from_file("trusted_root.json")?;
/// let bundle_json = std::fs::read_to_string("artifact.sigstore.json")?;
/// let bundle = Bundle::from_json(&bundle_json)?;
/// let artifact = std::fs::read("artifact.txt")?;
/// let key_pem = std::fs::read_to_string("key.pub")?;
/// let public_key = DerPublicKey::from_pem(&key_pem)?;
///
/// verify_with_key(&artifact, &bundle, &public_key, &trusted_root)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_with_key<'a>(
    artifact: impl Into<Artifact<'a>>,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    use sigstore_bundle::{validate_bundle_with_options, ValidationOptions};
    use sigstore_crypto::{detect_key_type, KeyType, SigningScheme};

    let artifact = artifact.into();
    let result = VerificationResult::new();

    // Validate bundle structure (structural only; the cryptographic checks
    // follow below)
    let options = ValidationOptions {
        require_inclusion_proof: true,
        require_timestamp: false,
    };
    validate_bundle_with_options(bundle, &options)
        .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

    // Determine signing scheme from public key
    let signing_scheme = match detect_key_type(public_key) {
        KeyType::Ed25519 => SigningScheme::Ed25519,
        KeyType::EcdsaP256 => SigningScheme::EcdsaP256Sha256,
        KeyType::Unknown => {
            return Err(Error::Verification(
                "unsupported or unrecognized public key type".to_string(),
            ));
        }
    };

    // Verify transparency log entries (Merkle inclusion proofs, checkpoints,
    // SETs) without certificate time validation
    for entry in &bundle.verification_material.tlog_entries {
        crate::verify_impl::tlog::verify_entry_inclusion(entry, trusted_root)?;
    }

    // Verify the signature
    match &bundle.content {
        SignatureContent::MessageSignature(msg_sig) => {
            // Verify message digest matches artifact
            if let Some(ref digest) = msg_sig.message_digest {
                let artifact_hash = compute_artifact_digest_algo(&artifact, digest.algorithm)?;
                if digest.digest != artifact_hash {
                    return Err(Error::Verification(
                        "message digest in bundle does not match artifact hash".to_string(),
                    ));
                }
            }

            // Verify signature over the artifact
            verify_signature_over_artifact(
                public_key,
                signing_scheme,
                &msg_sig.signature,
                &artifact,
            )?;
        }
        SignatureContent::DsseEnvelope(envelope) => {
            let payload_bytes = envelope.decode_payload();
            let pae = sigstore_types::pae(&envelope.payload_type, &payload_bytes);

            // Verify at least one signature is valid
            let mut any_sig_valid = false;
            for sig in &envelope.signatures {
                if sigstore_crypto::verify_signature(public_key, &pae, &sig.sig, signing_scheme)
                    .is_ok()
                {
                    any_sig_valid = true;
                    break;
                }
            }

            if !any_sig_valid {
                return Err(Error::Verification(
                    "DSSE signature verification failed: no valid signatures found".to_string(),
                ));
            }

            // Verify the payload binds the artifact
            verify_dsse_artifact_binding(envelope, &artifact)?;
        }
    }

    // Verify the transparency log entries' consistency against the bundle's
    // other materials and the artifact (CVE-2022-36056 class), mirroring
    // step 8 of `Verifier::verify`. Without this, a log entry whose body
    // (hash, signature, verifier) disagrees with the bundle passes silently.
    crate::verify_impl::verify_tlog_consistency(bundle, &artifact)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_policy_default() {
        let policy = VerificationPolicy::default();
        assert!(policy.verify_tlog);
        assert_eq!(
            policy.certificate,
            CertificatePolicy::Verify { verify_sct: true }
        );
    }

    #[test]
    fn test_verification_policy_builder() {
        let policy = VerificationPolicy::default()
            .require_identity("test@example.com")
            .require_issuer("https://accounts.google.com")
            .skip_tlog();

        assert_eq!(policy.identity, Some("test@example.com".to_string()));
        assert_eq!(
            policy.issuer,
            Some("https://accounts.google.com".to_string())
        );
        assert!(!policy.verify_tlog);
    }

    #[test]
    fn test_skip_sct_keeps_certificate_chain_verification() {
        let policy = VerificationPolicy::default().skip_sct();

        assert_eq!(
            policy.certificate,
            CertificatePolicy::Verify { verify_sct: false }
        );
    }

    #[test]
    fn test_skip_certificate_chain_preserves_legacy_sct_skip() {
        let policy = VerificationPolicy::default().skip_certificate_chain();

        assert_eq!(policy.certificate, CertificatePolicy::Skip);
    }

    fn in_toto_envelope(payload: &str) -> sigstore_types::DsseEnvelope {
        sigstore_types::DsseEnvelope::new(
            "application/vnd.in-toto+json".to_string(),
            sigstore_types::PayloadBytes::from_bytes(payload.as_bytes()),
            vec![],
        )
    }

    fn statement_with_subject_sha256(hash_hex: &str) -> String {
        format!(
            r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{{"name":"artifact","digest":{{"sha256":"{}"}}}}],"predicateType":"https://example.com/predicate/v1","predicate":{{}}}}"#,
            hash_hex
        )
    }

    #[test]
    fn test_dsse_binding_matching_subject_ok() {
        let artifact_bytes = b"hello world";
        let hash_hex = sigstore_crypto::sha256(artifact_bytes).to_hex();
        let envelope = in_toto_envelope(&statement_with_subject_sha256(&hash_hex));

        let artifact = Artifact::from(artifact_bytes.as_slice());
        assert!(verify_dsse_artifact_binding(&envelope, &artifact).is_ok());
    }

    #[test]
    fn test_dsse_binding_mismatched_subject_fails() {
        let hash_hex = sigstore_crypto::sha256(b"some other artifact").to_hex();
        let envelope = in_toto_envelope(&statement_with_subject_sha256(&hash_hex));

        let artifact = Artifact::from(b"hello world".as_slice());
        let err = verify_dsse_artifact_binding(&envelope, &artifact).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match any subject in attestation"));
    }

    #[test]
    fn test_dsse_binding_empty_subjects_fails_closed() {
        let payload = r#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://example.com/predicate/v1","predicate":{}}"#;
        let envelope = in_toto_envelope(payload);

        let artifact = Artifact::from(b"hello world".as_slice());
        let err = verify_dsse_artifact_binding(&envelope, &artifact).unwrap_err();
        assert!(err.to_string().contains("no subjects"));
    }

    #[test]
    fn test_dsse_binding_unknown_payload_type_fails_closed() {
        let envelope = sigstore_types::DsseEnvelope::new(
            "application/vnd.example+json".to_string(),
            sigstore_types::PayloadBytes::from_bytes(b"{}"),
            vec![],
        );

        let artifact = Artifact::from(b"hello world".as_slice());
        let err = verify_dsse_artifact_binding(&envelope, &artifact).unwrap_err();
        assert!(err.to_string().contains("unsupported DSSE payload type"));
    }
}
