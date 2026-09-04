//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

use crate::artifact::PreparedArtifact;
use crate::error::{Error, Result};
use base64::Engine;
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::{parse_certificate_info, KeyAlgorithm, SigningScheme, VerificationKey};
use sigstore_trust_root::TrustedRoot;

use sigstore_types::{
    Artifact, Bundle, HashAlgorithm, Sha256Hash, Sha512Hash, SignatureContent, Statement,
};

/// Artifact input for verification.
#[derive(Debug)]
pub enum ArtifactSource<'a, R = std::io::Empty> {
    /// Raw artifact bytes or a pre-computed digest.
    Artifact(Artifact<'a>),
    /// Artifact bytes streamed from a reader.
    Reader(R),
}

/// Reader input for [`ArtifactSource`].
#[derive(Debug)]
pub struct Reader<R>(R);

/// Wrap a reader so it can be passed to `verify(...).`
pub fn reader<R>(reader: R) -> Reader<R> {
    Reader(reader)
}

impl<'a, A> From<A> for ArtifactSource<'a>
where
    A: Into<Artifact<'a>>,
{
    fn from(artifact: A) -> Self {
        Self::Artifact(artifact.into())
    }
}

impl<'a, R> From<Reader<R>> for ArtifactSource<'a, R> {
    fn from(reader: Reader<R>) -> Self {
        Self::Reader(reader.0)
    }
}

/// Artifact input for async verification.
#[derive(Debug)]
pub enum AsyncArtifactSource<'a, R = futures::io::Empty> {
    /// Raw artifact bytes or a pre-computed digest.
    Artifact(Artifact<'a>),
    /// Artifact bytes streamed from an async reader.
    Reader(R),
}

/// Async reader input for [`AsyncArtifactSource`].
#[derive(Debug)]
pub struct AsyncReader<R>(R);

/// Wrap an async reader so it can be passed to `verify_async(...).`
pub fn async_reader<R>(reader: R) -> AsyncReader<R> {
    AsyncReader(reader)
}

impl<'a, A> From<A> for AsyncArtifactSource<'a>
where
    A: Into<Artifact<'a>>,
{
    fn from(artifact: A) -> Self {
        Self::Artifact(artifact.into())
    }
}

impl<'a, R> From<AsyncReader<R>> for AsyncArtifactSource<'a, R> {
    fn from(reader: AsyncReader<R>) -> Self {
        Self::Reader(reader.0)
    }
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

/// Policy for verifying signatures
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Expected identity (email or URI)
    pub identity: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Verify transparency log inclusion
    ///
    /// WARNING: Disabling this is unsafe for production use against the
    /// Sigstore public-good instance: it accepts bundles whose signature
    /// event was never logged. Signed timestamps (TSA timestamps and Rekor
    /// SETs) are authenticated regardless of this flag, as is each log
    /// entry's consistency with the rest of the bundle, but inclusion
    /// proofs and checkpoints are skipped when it is disabled.
    /// See [`VerificationPolicy::skip_tlog_unsafe`].
    pub verify_tlog: bool,
    /// How the signing certificate (and its SCT) is verified
    pub certificate: CertificatePolicy,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            identity: None,
            issuer: None,
            verify_tlog: true,
            certificate: CertificatePolicy::Verify { verify_sct: true },
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
    ///
    /// WARNING: This is unsafe for production use against the Sigstore
    /// public-good instance: bundles are accepted without proof that the
    /// signature event was ever logged, because the inclusion proof and
    /// checkpoint are not checked.
    ///
    /// What does still hold: TSA timestamps and Rekor SETs are verified
    /// before a timestamp is used as the certificate validation time, and
    /// every log entry is checked for consistency with the bundle it
    /// travels in. Together these reject a tampered `integratedTime` (the
    /// SET signature covers it) and an `integratedTime` borrowed from an
    /// unrelated log entry (its body would not describe this bundle).
    ///
    /// What this does NOT give you: any evidence that the entry was
    /// actually incorporated into the log. A well-formed entry that Rekor
    /// never accepted is indistinguishable from one it did.
    ///
    /// Only use this for trust domains without an accessible transparency
    /// log, such as bundles for GitHub's private-repository artifact
    /// attestations, or for testing.
    pub fn skip_tlog_unsafe(mut self) -> Self {
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
    pub integrated_time: Option<jiff::Timestamp>,
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
    pub fn verify<'a, R: std::io::Read>(
        &self,
        artifact: impl Into<ArtifactSource<'a, R>>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let artifact = match artifact.into() {
            ArtifactSource::Artifact(artifact) => PreparedArtifact::from_artifact(artifact),
            ArtifactSource::Reader(reader) => PreparedArtifact::from_reader(reader, bundle)?,
        };
        self.verify_prepared(artifact, bundle, policy)
    }

    /// Verify an artifact read synchronously to EOF in constant memory.
    ///
    /// Reads happen on the calling thread. Async applications should use
    /// [`Verifier::verify_async_reader`] to avoid blocking an executor.
    pub fn verify_reader(
        &self,
        reader: impl std::io::Read,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        self.verify(crate::verify::reader(reader), bundle, policy)
    }

    /// Verify an artifact read asynchronously to EOF in constant memory.
    pub async fn verify_async_reader(
        &self,
        reader: impl futures::io::AsyncRead + Unpin,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        self.verify_async(crate::verify::async_reader(reader), bundle, policy)
            .await
    }

    /// Verify an artifact or async reader against a bundle.
    pub async fn verify_async<'a, R: futures::io::AsyncRead + Unpin>(
        &self,
        artifact: impl Into<AsyncArtifactSource<'a, R>>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let artifact = match artifact.into() {
            AsyncArtifactSource::Artifact(artifact) => PreparedArtifact::from_artifact(artifact),
            AsyncArtifactSource::Reader(reader) => {
                PreparedArtifact::from_async_reader(reader, bundle).await?
            }
        };
        self.verify_prepared(artifact, bundle, policy)
    }

    fn verify_prepared(
        &self,
        artifact: PreparedArtifact<'_>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
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
        let signature = crate::verify_impl::helpers::extract_signature(&bundle.content);
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
            // determine_validation_times never yields an empty list, but fail
            // closed rather than panic if that ever stops holding: reaching
            // here with no issuer means no timestamp was actually checked.
            let Some(issuer_spki) = issuer_spki else {
                return Err(Error::Verification(
                    "no verified timestamp to validate the signing certificate against".to_string(),
                ));
            };

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
            )?;

            if let Some(time) = integrated_time {
                result.integrated_time = Some(time);
            }
        }

        // (7): Verify the signature and input against the signing certificate's
        //      public key.
        // For DSSE envelopes, verify using PAE (Pre-Authentication Encoding)
        if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
            verify_dsse_envelope_signature(
                envelope,
                &cert_info.public_key,
                cert_info.key_algorithm.default_signing_scheme(),
            )?;

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
        //
        //      This runs regardless of `policy.verify_tlog`. It needs no trusted
        //      root and performs no log cryptography - it only checks that each
        //      entry's body describes *this* bundle. Skipping it would let an
        //      entry belonging to an unrelated signature ride along in the
        //      bundle, and step (0) would accept that entry's SET-authenticated
        //      integratedTime as a verified signing time.
        crate::verify_impl::verify_tlog_consistency(bundle, &artifact)?;

        Ok(result)
    }
}

fn compute_artifact_digest_algo(
    artifact: &PreparedArtifact<'_>,
    algo: HashAlgorithm,
) -> Result<Vec<u8>> {
    artifact.digest(algo)
}

/// Verify the DSSE envelope's signature over its PAE with the given key.
fn verify_dsse_envelope_signature(
    envelope: &sigstore_types::DsseEnvelope,
    public_key: &sigstore_types::DerPublicKey,
    scheme: SigningScheme,
) -> Result<()> {
    // Compute the PAE that was signed
    let payload_bytes = envelope.decode_payload();
    let pae = sigstore_types::pae(&envelope.payload_type, &payload_bytes);

    sigstore_crypto::verify_signature(public_key, &pae, &envelope.signature.sig, scheme)
        .map_err(|e| Error::Verification(format!("DSSE signature verification failed: {}", e)))
}

/// Verify that a DSSE envelope's payload binds the artifact being verified.
///
/// Only in-toto statements are supported: any other payload type has no
/// defined relationship to the artifact, so verification fails closed rather
/// than accepting an arbitrary artifact alongside a validly-signed envelope.
/// A supported artifact digest (SHA-256 or SHA-512) must match at least one
/// subject of the statement, and the statement must have at least one subject.
fn verify_dsse_artifact_binding(
    envelope: &sigstore_types::DsseEnvelope,
    artifact: &PreparedArtifact<'_>,
) -> Result<()> {
    if envelope.payload_type != "application/vnd.in-toto+json" {
        return Err(Error::Verification(format!(
            "unsupported DSSE payload type {:?}: cannot bind artifact to attestation",
            envelope.payload_type
        )));
    }

    let payload_str = std::str::from_utf8(envelope.payload.as_bytes())
        .map_err(|e| Error::Verification(format!("payload is not valid UTF-8: {}", e)))?;
    let statement: Statement = serde_json::from_str(payload_str)
        .map_err(|e| Error::Verification(format!("failed to parse in-toto statement: {}", e)))?;

    if statement.subject.is_empty() {
        return Err(Error::Verification(
            "in-toto statement has no subjects: cannot bind artifact to attestation".to_string(),
        ));
    }
    let sha256_matches = artifact
        .digest(HashAlgorithm::Sha2256)
        .ok()
        .and_then(|digest| Sha256Hash::try_from_slice(&digest).ok())
        .is_some_and(|digest| statement.matches_sha256(&digest));
    let sha512_matches = artifact
        .digest(HashAlgorithm::Sha2512)
        .ok()
        .and_then(|digest| Sha512Hash::try_from_slice(&digest).ok())
        .is_some_and(|digest| statement.matches_sha512(&digest));
    let matches = sha256_matches || sha512_matches;

    if !matches {
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
    artifact: &PreparedArtifact<'_>,
) -> Result<()> {
    let result = if let Some(blob) = artifact.blob() {
        sigstore_crypto::verify_signature(public_key, blob, signature, scheme)
    } else {
        if !scheme.supports_prehashed() {
            return Err(Error::Verification(format!(
                "cannot verify signature from a digest or reader - scheme {} does not support prehashed mode",
                scheme.name()
            )));
        }
        let expected = scheme.hash_algorithm().ok_or_else(|| {
            Error::Verification(format!(
                "scheme {} has no external digest algorithm",
                scheme.name()
            ))
        })?;
        let digest = artifact.digest(expected)?;
        sigstore_crypto::verify_signature_prehashed(public_key, &digest, signature, scheme)
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

fn verify_message_signature_crypto(
    cert_info: &sigstore_crypto::CertificateInfo,
    msg_sig: &sigstore_types::bundle::MessageSignature,
    artifact: &PreparedArtifact<'_>,
) -> Result<()> {
    verify_signature_over_artifact(
        &cert_info.public_key,
        signing_scheme_for_message_signature(cert_info.key_algorithm, msg_sig)?,
        &msg_sig.signature,
        artifact,
    )
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
pub fn verify<'a, R: std::io::Read>(
    artifact: impl Into<ArtifactSource<'a, R>>,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let verifier = Verifier::new(trusted_root);
    verifier.verify(artifact, bundle, policy)
}

/// Verify an artifact from a synchronous reader.
pub fn verify_reader(
    reader: impl std::io::Read,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    verify(crate::verify::reader(reader), bundle, policy, trusted_root)
}

/// Verify an artifact from a runtime-independent asynchronous reader.
pub async fn verify_async_reader(
    reader: impl futures::io::AsyncRead + Unpin,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    verify_async(
        crate::verify::async_reader(reader),
        bundle,
        policy,
        trusted_root,
    )
    .await
}

/// Verify an artifact or async reader against a bundle.
pub async fn verify_async<'a, R: futures::io::AsyncRead + Unpin>(
    artifact: impl Into<AsyncArtifactSource<'a, R>>,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    Verifier::new(trusted_root)
        .verify_async(artifact, bundle, policy)
        .await
}

/// Derive the key algorithm from the public key's SPKI algorithm identifier.
///
/// Parsing goes through [`VerificationKey::from_spki`], so malformed
/// SPKI structures, unknown algorithm OIDs, and unsupported EC curves are
/// rejected eagerly with precise errors (TOB-SIGSTORE-6). The scheme itself
/// is still resolved from the bundle content afterwards, so a declared
/// SHA-384 message digest keeps selecting ECDSA-P256-SHA384.
fn public_key_algorithm(public_key: &sigstore_types::DerPublicKey) -> Result<KeyAlgorithm> {
    let key = VerificationKey::from_spki(public_key)
        .map_err(|e| Error::Verification(format!("invalid public key: {e}")))?;
    match key.scheme() {
        SigningScheme::Ed25519 => Ok(KeyAlgorithm::Ed25519),
        SigningScheme::EcdsaP256Sha256 | SigningScheme::EcdsaP256Sha384 => {
            Ok(KeyAlgorithm::EcdsaP256)
        }
        other => Err(Error::Verification(format!(
            "unsupported public key scheme: {}",
            other.name()
        ))),
    }
}

fn verify_public_key_hint(hint: &str, public_key: &sigstore_types::DerPublicKey) -> Result<()> {
    let expected = sigstore_crypto::sha256(public_key.as_bytes());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(hint)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(hint))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(hint))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(hint))
        .map_err(|_| {
            Error::Verification("public key hint is not a supported SHA-256 key hint".to_string())
        })?;

    if decoded != expected.as_bytes() {
        return Err(Error::Verification(
            "public key hint does not match supplied public key".to_string(),
        ));
    }

    Ok(())
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
pub fn verify_with_key<'a, R: std::io::Read>(
    artifact: impl Into<ArtifactSource<'a, R>>,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let artifact = match artifact.into() {
        ArtifactSource::Artifact(artifact) => PreparedArtifact::from_artifact(artifact),
        ArtifactSource::Reader(reader) => PreparedArtifact::from_reader(reader, bundle)?,
    };
    verify_with_key_prepared(artifact, bundle, public_key, trusted_root)
}

/// Verify a managed-key bundle from a synchronous artifact reader.
pub fn verify_with_key_reader(
    reader: impl std::io::Read,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    verify_with_key(
        crate::verify::reader(reader),
        bundle,
        public_key,
        trusted_root,
    )
}

/// Verify a managed-key bundle from an asynchronous artifact reader.
pub async fn verify_with_key_async_reader(
    reader: impl futures::io::AsyncRead + Unpin,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    verify_with_key_async(
        crate::verify::async_reader(reader),
        bundle,
        public_key,
        trusted_root,
    )
    .await
}

/// Verify a managed-key bundle from an artifact or async reader.
pub async fn verify_with_key_async<'a, R: futures::io::AsyncRead + Unpin>(
    artifact: impl Into<AsyncArtifactSource<'a, R>>,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let artifact = match artifact.into() {
        AsyncArtifactSource::Artifact(artifact) => PreparedArtifact::from_artifact(artifact),
        AsyncArtifactSource::Reader(reader) => {
            PreparedArtifact::from_async_reader(reader, bundle).await?
        }
    };
    verify_with_key_prepared(artifact, bundle, public_key, trusted_root)
}

fn verify_with_key_prepared(
    artifact: PreparedArtifact<'_>,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let result = VerificationResult::new();

    if let sigstore_types::bundle::VerificationMaterialContent::PublicKey { hint } =
        &bundle.verification_material.content
    {
        verify_public_key_hint(hint, public_key)?;
    }

    // Validate bundle structure (structural only; the cryptographic checks
    // follow below)
    let options = ValidationOptions {
        require_inclusion_proof: true,
        require_timestamp: false,
    };
    validate_bundle_with_options(bundle, &options)
        .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

    let key_algorithm = public_key_algorithm(public_key)?;
    let signing_scheme = signing_scheme_for_content(key_algorithm, &bundle.content)?;

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
            verify_dsse_envelope_signature(envelope, public_key, signing_scheme)?;

            // Verify the payload binds the artifact
            verify_dsse_artifact_binding(envelope, &artifact)?;
        }
    }

    // Verify the transparency log entries' consistency against the bundle's
    // other materials and the artifact (CVE-2022-36056 class), mirroring
    // step 8 of `Verifier::verify`. Pass the caller-supplied key so legacy
    // intoto entries can bind their logged verifier in managed-key bundles.
    crate::verify_impl::rekor::verify_tlog_consistency_with_key(
        bundle,
        &artifact,
        Some(public_key),
    )?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_hint_accepts_all_protojson_base64_variants() {
        let key = sigstore_types::DerPublicKey::from_bytes(b"test public key");
        let digest = sigstore_crypto::sha256(key.as_bytes());
        for hint in [
            base64::engine::general_purpose::STANDARD.encode(digest),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest),
            base64::engine::general_purpose::URL_SAFE.encode(digest),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
        ] {
            verify_public_key_hint(&hint, &key).unwrap();
        }

        // Prefixes are not part of the protobuf field's encoding.
        let prefixed = format!(
            "sha256:{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        assert!(verify_public_key_hint(&prefixed, &key).is_err());
    }

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
            .skip_tlog_unsafe();

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

    fn unused_signature() -> sigstore_types::DsseSignature {
        sigstore_types::DsseSignature {
            sig: sigstore_types::SignatureBytes::from_bytes(b"unused"),
            keyid: sigstore_types::KeyId::default(),
        }
    }

    fn in_toto_envelope(payload: &str) -> sigstore_types::DsseEnvelope {
        sigstore_types::DsseEnvelope::new(
            "application/vnd.in-toto+json".to_string(),
            sigstore_types::PayloadBytes::from_bytes(payload.as_bytes()),
            unused_signature(),
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

        let artifact = PreparedArtifact::from_artifact(Artifact::from(artifact_bytes.as_slice()));
        assert!(verify_dsse_artifact_binding(&envelope, &artifact).is_ok());
    }

    #[test]
    fn test_dsse_binding_mismatched_subject_fails() {
        let hash_hex = sigstore_crypto::sha256(b"some other artifact").to_hex();
        let envelope = in_toto_envelope(&statement_with_subject_sha256(&hash_hex));

        let artifact = PreparedArtifact::from_artifact(Artifact::from(b"hello world".as_slice()));
        let err = verify_dsse_artifact_binding(&envelope, &artifact).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match any subject in attestation"));
    }

    #[test]
    fn test_dsse_binding_empty_subjects_fails_closed() {
        let payload = r#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://example.com/predicate/v1","predicate":{}}"#;
        let envelope = in_toto_envelope(payload);

        let artifact = PreparedArtifact::from_artifact(Artifact::from(b"hello world".as_slice()));
        let err = verify_dsse_artifact_binding(&envelope, &artifact).unwrap_err();
        assert!(err.to_string().contains("no subjects"));
    }

    #[test]
    fn test_dsse_binding_unknown_payload_type_fails_closed() {
        let envelope = sigstore_types::DsseEnvelope::new(
            "application/vnd.example+json".to_string(),
            sigstore_types::PayloadBytes::from_bytes(b"{}"),
            unused_signature(),
        );

        let artifact = PreparedArtifact::from_artifact(Artifact::from(b"hello world".as_slice()));
        let err = verify_dsse_artifact_binding(&envelope, &artifact).unwrap_err();
        assert!(err.to_string().contains("unsupported DSSE payload type"));
    }

    const DSSE_TEST_PAYLOAD: &[u8] = br#"{"hello":"world"}"#;

    fn dsse_envelope_signed_over(
        keypair: &sigstore_crypto::KeyPair,
        data: &[u8],
    ) -> sigstore_types::DsseEnvelope {
        sigstore_types::DsseEnvelope::new(
            "application/vnd.in-toto+json".to_string(),
            sigstore_types::PayloadBytes::from_bytes(DSSE_TEST_PAYLOAD),
            sigstore_types::DsseSignature {
                sig: keypair.sign(data).unwrap(),
                keyid: sigstore_types::KeyId::default(),
            },
        )
    }

    #[test]
    fn test_dsse_envelope_valid_signature_verifies() {
        let keypair = sigstore_crypto::KeyPair::generate_ecdsa_p256().unwrap();
        let pae = sigstore_types::pae("application/vnd.in-toto+json", DSSE_TEST_PAYLOAD);
        let envelope = dsse_envelope_signed_over(&keypair, &pae);

        let public_key = keypair.public_key_der().unwrap();
        verify_dsse_envelope_signature(&envelope, &public_key, keypair.default_scheme())
            .expect("an envelope with a valid signature must verify");
    }

    #[test]
    fn test_dsse_envelope_invalid_signature_is_hard_error() {
        let keypair = sigstore_crypto::KeyPair::generate_ecdsa_p256().unwrap();
        // Signature over something other than the PAE: must fail.
        let envelope = dsse_envelope_signed_over(&keypair, b"not the PAE");

        let public_key = keypair.public_key_der().unwrap();
        let err = verify_dsse_envelope_signature(&envelope, &public_key, keypair.default_scheme())
            .expect_err("an invalid signature must fail verification");
        assert!(
            err.to_string()
                .contains("DSSE signature verification failed"),
            "unexpected error: {err}"
        );
    }
}
