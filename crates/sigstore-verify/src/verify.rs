//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

use crate::error::{Error, Result};
use base64::Engine;
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::{
    detect_key_type, parse_certificate_info, KeyAlgorithm, KeyType, SigningScheme,
};
use sigstore_trust_root::TrustedRoot;

use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Artifact, Bundle, DerPublicKey, HashAlgorithm, SignatureContent, Statement};

/// Default clock skew tolerance in seconds (60 seconds = 1 minute)
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;

/// Verification mode and the policy that applies to that mode.
#[derive(Debug, Clone, Copy)]
pub enum VerificationMode<'a> {
    /// Bundle carries a signing certificate or certificate chain.
    Certificate(&'a VerificationPolicy),
    /// Bundle carries only a public-key hint; caller supplies the key.
    PublicKey {
        public_key: &'a DerPublicKey,
        policy: &'a PublicKeyVerificationPolicy,
    },
}

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

/// Policy for verifying key-based signatures.
#[derive(Debug, Clone)]
pub struct PublicKeyVerificationPolicy {
    /// Verify transparency log inclusion
    pub verify_tlog: bool,
}

impl Default for PublicKeyVerificationPolicy {
    fn default() -> Self {
        Self { verify_tlog: true }
    }
}

impl PublicKeyVerificationPolicy {
    /// Skip transparency log verification
    pub fn skip_tlog(mut self) -> Self {
        self.verify_tlog = false;
        self
    }
}

/// Policy for verifying certificate-based signatures
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
    /// use sigstore_verify::{VerificationMode, Verifier, VerificationPolicy};
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
    /// verifier.verify(artifact_bytes.as_slice(), &bundle, VerificationMode::Certificate(&policy))?;
    ///
    /// // Option 2: Verify with pre-computed digest (no raw bytes needed!)
    /// let digest = Sha256Hash::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")?;
    /// verifier.verify(digest, &bundle, VerificationMode::Certificate(&policy))?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// In order to verify an artifact, we need to achieve the following:
    ///
    /// 0. Establish a time for the signature.
    /// 1. Verify that the signing certificate chains to the root of trust
    ///    and is valid at the time of signing.
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
        mode: VerificationMode<'_>,
    ) -> Result<VerificationResult> {
        verify_with_trusted_root(artifact.into(), bundle, mode, &self.trusted_root)
    }
}

fn verify_with_trusted_root(
    artifact: Artifact<'_>,
    bundle: &Bundle,
    mode: VerificationMode<'_>,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    match (&bundle.verification_material.content, mode) {
        (
            VerificationMaterialContent::Certificate(_)
            | VerificationMaterialContent::X509CertificateChain { .. },
            VerificationMode::Certificate(policy),
        ) => verify_certificate_bundle(artifact, bundle, policy, trusted_root),
        (
            VerificationMaterialContent::PublicKey { hint },
            VerificationMode::PublicKey { public_key, policy },
        ) => {
            verify_public_key_hint(hint, public_key)?;
            verify_public_key_bundle(artifact, bundle, public_key, policy, trusted_root)
        }
        (VerificationMaterialContent::PublicKey { .. }, VerificationMode::Certificate(_)) => {
            Err(Error::Verification(
                "bundle contains a public key but certificate verification was requested"
                    .to_string(),
            ))
        }
        (_, VerificationMode::PublicKey { .. }) => Err(Error::Verification(
            "bundle contains a certificate but a public key was supplied".to_string(),
        )),
    }
}

fn validate_bundle_shape(bundle: &Bundle, verify_tlog: bool) -> Result<()> {
    let options = ValidationOptions {
        require_inclusion_proof: verify_tlog,
        require_timestamp: false,
    };
    validate_bundle_with_options(bundle, &options)
        .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))
}

fn verify_certificate_bundle(
    artifact: Artifact<'_>,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let mut result = VerificationResult::new();
    validate_bundle_shape(bundle, policy.verify_tlog)?;

    let cert =
        crate::verify_impl::helpers::extract_certificate(&bundle.verification_material.content)?;
    let cert_info = parse_certificate_info(cert.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    result.identity = cert_info.identity.clone();
    result.issuer = cert_info.issuer.clone();

    let signature = crate::verify_impl::helpers::extract_signature(&bundle.content)?;
    let validation_time =
        crate::verify_impl::helpers::determine_validation_time(bundle, &signature, trusted_root)?;

    if let CertificatePolicy::Verify { verify_sct } = policy.certificate {
        let issuer_spki = crate::verify_impl::helpers::verify_certificate_chain(
            &bundle.verification_material.content,
            validation_time,
            trusted_root,
        )?;
        crate::verify_impl::helpers::validate_certificate_time(validation_time, &cert_info)?;

        if verify_sct {
            crate::verify_impl::sct::verify_sct(
                cert.as_bytes(),
                issuer_spki.as_bytes(),
                trusted_root,
            )?;
        }
    }

    verify_identity_policy(&result, policy)?;

    if policy.verify_tlog {
        if let Some(time) = crate::verify_impl::tlog::verify_tlog_entries(
            bundle,
            trusted_root,
            cert_info.not_before,
            cert_info.not_after,
            policy.clock_skew_seconds,
        )? {
            result.integrated_time = Some(time);
        }
    }

    verify_signed_content(
        bundle,
        &artifact,
        &cert_info.public_key,
        signing_scheme_for_content(cert_info.key_algorithm, &bundle.content)?,
    )?;
    verify_tlog_consistency_if_enabled(bundle, &artifact, policy)?;

    Ok(result)
}

fn verify_public_key_bundle(
    artifact: Artifact<'_>,
    bundle: &Bundle,
    public_key: &DerPublicKey,
    policy: &PublicKeyVerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    validate_bundle_shape(bundle, policy.verify_tlog)?;

    if policy.verify_tlog {
        for entry in &bundle.verification_material.tlog_entries {
            crate::verify_impl::tlog::verify_entry_inclusion(entry, trusted_root)?;
        }
    }

    verify_signed_content(
        bundle,
        &artifact,
        public_key,
        signing_scheme_for_content(public_key_algorithm(public_key)?, &bundle.content)?,
    )?;
    if policy.verify_tlog {
        crate::verify_impl::verify_tlog_consistency(bundle, &artifact)?;
    }

    Ok(VerificationResult::new())
}

fn verify_identity_policy(result: &VerificationResult, policy: &VerificationPolicy) -> Result<()> {
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

    Ok(())
}

fn verify_tlog_consistency_if_enabled(
    bundle: &Bundle,
    artifact: &Artifact<'_>,
    policy: &VerificationPolicy,
) -> Result<()> {
    if policy.verify_tlog {
        crate::verify_impl::verify_tlog_consistency(bundle, artifact)?;
    }
    Ok(())
}

fn verify_signed_content(
    bundle: &Bundle,
    artifact: &Artifact<'_>,
    public_key: &DerPublicKey,
    signing_scheme: SigningScheme,
) -> Result<()> {
    match &bundle.content {
        SignatureContent::MessageSignature(msg_sig) => {
            if let Some(ref digest) = msg_sig.message_digest {
                let artifact_hash = compute_artifact_digest_algo(artifact, digest.algorithm)?;
                if digest.digest != artifact_hash {
                    return Err(Error::Verification(
                        "message digest in bundle does not match artifact hash".to_string(),
                    ));
                }
            }
            verify_signature_over_artifact(public_key, signing_scheme, &msg_sig.signature, artifact)
        }
        SignatureContent::DsseEnvelope(envelope) => {
            let payload_bytes = envelope.decode_payload();
            let pae = sigstore_types::pae(&envelope.payload_type, &payload_bytes);
            let any_sig_valid = envelope.signatures.iter().any(|sig| {
                sigstore_crypto::verify_signature(public_key, &pae, &sig.sig, signing_scheme)
                    .is_ok()
            });

            if !any_sig_valid {
                return Err(Error::Verification(
                    "DSSE signature verification failed: no valid signatures found".to_string(),
                ));
            }

            verify_dsse_artifact_binding(envelope, artifact)
        }
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
fn signing_scheme_for_message_signature(
    key_algorithm: KeyAlgorithm,
    msg_sig: &sigstore_types::bundle::MessageSignature,
) -> Result<SigningScheme> {
    match &msg_sig.message_digest {
        Some(digest) => Ok(key_algorithm.resolve_signing_scheme(digest.algorithm)?),
        None => Ok(key_algorithm.default_signing_scheme()),
    }
}

fn signing_scheme_for_content(
    key_algorithm: KeyAlgorithm,
    content: &SignatureContent,
) -> Result<SigningScheme> {
    match content {
        SignatureContent::MessageSignature(msg_sig) => {
            signing_scheme_for_message_signature(key_algorithm, msg_sig)
        }
        SignatureContent::DsseEnvelope(_) => Ok(key_algorithm.default_signing_scheme()),
    }
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
/// use sigstore_verify::{verify, VerificationMode, VerificationPolicy};
/// use sigstore_trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
/// use sigstore_types::{Bundle, Sha256Hash};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)?;
/// let bundle_json = std::fs::read_to_string("artifact.sigstore.json")?;
/// let bundle = Bundle::from_json(&bundle_json)?;
/// let artifact = std::fs::read("artifact.txt")?;
///
/// let policy = VerificationPolicy::default();
/// verify(&artifact, &bundle, VerificationMode::Certificate(&policy), &trusted_root)?;
/// # Ok(())
/// # }
/// ```
pub fn verify<'a>(
    artifact: impl Into<Artifact<'a>>,
    bundle: &Bundle,
    mode: VerificationMode<'_>,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    verify_with_trusted_root(artifact.into(), bundle, mode, trusted_root)
}

fn public_key_algorithm(public_key: &sigstore_types::DerPublicKey) -> Result<KeyAlgorithm> {
    match detect_key_type(public_key) {
        KeyType::Ed25519 => Ok(KeyAlgorithm::Ed25519),
        KeyType::EcdsaP256 => Ok(KeyAlgorithm::EcdsaP256),
        KeyType::Unknown => Err(Error::Verification(
            "unsupported or unrecognized public key type".to_string(),
        )),
    }
}

fn verify_public_key_hint(hint: &str, public_key: &sigstore_types::DerPublicKey) -> Result<()> {
    let expected = sigstore_crypto::sha256(public_key.as_bytes());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(hint)
        .map_err(|_| Error::Verification("public key hint is not base64 SHA-256".to_string()))?;

    if decoded != expected.as_bytes() {
        return Err(Error::Verification(
            "public key hint does not match supplied public key".to_string(),
        ));
    }

    Ok(())
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

    #[test]
    fn test_signing_scheme_follows_message_digest_algorithm() {
        let msg_sig = sigstore_types::bundle::MessageSignature {
            message_digest: Some(sigstore_types::bundle::MessageDigest {
                algorithm: HashAlgorithm::Sha2384,
                digest: sigstore_types::DigestBytes::from_bytes(vec![0; 48]),
            }),
            signature: sigstore_types::SignatureBytes::from_bytes(b"sig"),
        };

        assert_eq!(
            signing_scheme_for_message_signature(KeyAlgorithm::EcdsaP256, &msg_sig).unwrap(),
            SigningScheme::EcdsaP256Sha384
        );
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
