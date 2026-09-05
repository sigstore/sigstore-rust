//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

use crate::artifact::{ArtifactRequirements, PreparedArtifact};
use crate::error::{Error, Result};
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::{parse_certificate_info, KeyAlgorithm, SigningScheme, VerificationKey};
use sigstore_trust_root::TrustedRoot;

use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Artifact, Bundle, KindVersion, SignatureContent};

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

/// Policy for verifying signatures made with a caller-supplied public key.
#[derive(Debug, Clone)]
pub struct PublicKeyVerificationPolicy {
    /// Verify transparency log inclusion.
    pub verify_tlog: bool,
}

impl Default for PublicKeyVerificationPolicy {
    fn default() -> Self {
        Self { verify_tlog: true }
    }
}

impl PublicKeyVerificationPolicy {
    /// Skip transparency log inclusion verification.
    ///
    /// WARNING: This accepts bundles without proof that the signature event
    /// was incorporated into the log. Log-entry consistency is still checked.
    pub fn skip_tlog_unsafe(mut self) -> Self {
        self.verify_tlog = false;
        self
    }
}

/// Policy for verifying certificate-based signatures.
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
    pub fn verify<'a>(
        &self,
        artifact: impl Into<Artifact<'a>>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let cert_info = prepare_certificate(bundle, policy)?;
        let requirements = ArtifactRequirements::new(
            &bundle.content,
            signing_scheme_for_content(cert_info.key_algorithm, &bundle.content)?,
        )?;
        self.verify_prepared(
            PreparedArtifact::from_artifact(artifact.into(), &requirements),
            bundle,
            policy,
            &cert_info,
            &requirements,
        )
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
        let cert_info = prepare_certificate(bundle, policy)?;
        let requirements = ArtifactRequirements::new(
            &bundle.content,
            signing_scheme_for_content(cert_info.key_algorithm, &bundle.content)?,
        )?;
        self.verify_prepared(
            PreparedArtifact::from_reader(reader, &requirements)?,
            bundle,
            policy,
            &cert_info,
            &requirements,
        )
    }

    /// Verify an artifact read asynchronously to EOF in constant memory.
    pub async fn verify_async_reader(
        &self,
        reader: impl futures_io::AsyncRead + Unpin,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let cert_info = prepare_certificate(bundle, policy)?;
        let requirements = ArtifactRequirements::new(
            &bundle.content,
            signing_scheme_for_content(cert_info.key_algorithm, &bundle.content)?,
        )?;
        self.verify_prepared(
            PreparedArtifact::from_async_reader(reader, &requirements).await?,
            bundle,
            policy,
            &cert_info,
            &requirements,
        )
    }

    fn verify_prepared(
        &self,
        artifact: PreparedArtifact<'_>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
        cert_info: &sigstore_crypto::CertificateInfo,
        requirements: &ArtifactRequirements,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::new();
        let cert = bundle
            .signing_certificate()
            .ok_or_else(|| Error::Verification("bundle has no signing certificate".into()))?;

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
                crate::verify_impl::helpers::validate_certificate_time(validation_time, cert_info)?;
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
            requirements.verify_binding(&artifact)?;
        }

        // For MessageSignature bundles, verify the messageDigest matches the artifact
        if let SignatureContent::MessageSignature(msg_sig) = &bundle.content {
            verify_message_digest_binding(msg_sig, &artifact)?;

            // Cryptographically verify the signature over the artifact. This runs
            // regardless of `policy.verify_tlog` so the signature is always checked;
            // the transparency-log path (step 8) performs an equivalent check when
            // enabled, but must not be the only place verification happens.
            verify_message_signature_crypto(cert_info, msg_sig, &artifact)?;
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

    /// Verify a managed-key bundle using a caller-supplied public key.
    ///
    /// Managed-key bundles carry a public key hint instead of a signing
    /// certificate, so the key itself must be supplied by the caller. This
    /// verifies the signature with that key and the transparency log entries
    /// against the trusted root, and skips certificate chain and
    /// identity checks because no certificate is present.
    ///
    /// The artifact can be provided as raw bytes or as a pre-computed digest,
    /// exactly as for [`Verifier::verify`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_verify::{PublicKeyVerificationPolicy, Verifier};
    /// use sigstore_trust_root::TrustedRoot;
    /// use sigstore_types::{Bundle, DerPublicKey};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let trusted_root = TrustedRoot::from_file("trusted_root.json")?;
    /// let verifier = Verifier::new(&trusted_root);
    /// let bundle = Bundle::from_json(&std::fs::read_to_string("artifact.sigstore.json")?)?;
    /// let public_key = DerPublicKey::from_pem(&std::fs::read_to_string("key.pub")?)?;
    /// let artifact = std::fs::read("artifact.txt")?;
    ///
    /// verifier.verify_with_key(
    ///     &artifact,
    ///     &bundle,
    ///     &public_key,
    ///     &PublicKeyVerificationPolicy::default(),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_with_key<'a>(
        &self,
        artifact: impl Into<Artifact<'a>>,
        bundle: &Bundle,
        public_key: &sigstore_types::DerPublicKey,
        policy: &PublicKeyVerificationPolicy,
    ) -> Result<VerificationResult> {
        let scheme = prepare_public_key(bundle, public_key, policy)?;
        let requirements = ArtifactRequirements::new(&bundle.content, scheme)?;
        self.verify_with_key_prepared(
            PreparedArtifact::from_artifact(artifact.into(), &requirements),
            bundle,
            public_key,
            policy,
            scheme,
            &requirements,
        )
    }

    /// Verify a managed-key bundle against an artifact read synchronously to
    /// EOF in constant memory.
    ///
    /// Reads happen on the calling thread. Async applications should use
    /// [`Verifier::verify_with_key_async_reader`] to avoid blocking an
    /// executor.
    pub fn verify_with_key_reader(
        &self,
        reader: impl std::io::Read,
        bundle: &Bundle,
        public_key: &sigstore_types::DerPublicKey,
        policy: &PublicKeyVerificationPolicy,
    ) -> Result<VerificationResult> {
        let scheme = prepare_public_key(bundle, public_key, policy)?;
        let requirements = ArtifactRequirements::new(&bundle.content, scheme)?;
        self.verify_with_key_prepared(
            PreparedArtifact::from_reader(reader, &requirements)?,
            bundle,
            public_key,
            policy,
            scheme,
            &requirements,
        )
    }

    /// Verify a managed-key bundle against an artifact read asynchronously to
    /// EOF in constant memory.
    pub async fn verify_with_key_async_reader(
        &self,
        reader: impl futures_io::AsyncRead + Unpin,
        bundle: &Bundle,
        public_key: &sigstore_types::DerPublicKey,
        policy: &PublicKeyVerificationPolicy,
    ) -> Result<VerificationResult> {
        let scheme = prepare_public_key(bundle, public_key, policy)?;
        let requirements = ArtifactRequirements::new(&bundle.content, scheme)?;
        self.verify_with_key_prepared(
            PreparedArtifact::from_async_reader(reader, &requirements).await?,
            bundle,
            public_key,
            policy,
            scheme,
            &requirements,
        )
    }

    fn verify_with_key_prepared(
        &self,
        artifact: PreparedArtifact<'_>,
        bundle: &Bundle,
        public_key: &sigstore_types::DerPublicKey,
        policy: &PublicKeyVerificationPolicy,
        signing_scheme: SigningScheme,
        requirements: &ArtifactRequirements,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::new();

        // Verify transparency log entries (Merkle inclusion proofs, checkpoints,
        // SETs) without certificate time validation.
        if policy.verify_tlog {
            for entry in &bundle.verification_material.tlog_entries {
                crate::verify_impl::tlog::verify_entry_inclusion(entry, &self.trusted_root)?;

                let is_rekor_v1 = matches!(
                    entry.kind_version,
                    KindVersion::HashedRekordV001 | KindVersion::DsseV001 | KindVersion::IntotoV002
                );
                if is_rekor_v1 && entry.inclusion_promise.is_some() {
                    if let Some(time) = entry.integrated_time {
                        crate::verify_impl::tlog::validate_integrated_time_not_in_future(
                            time,
                            jiff::Timestamp::now(),
                        )?;
                        result.integrated_time = Some(time);
                    }
                }
            }
        }

        // Verify the signature
        match &bundle.content {
            SignatureContent::MessageSignature(msg_sig) => {
                verify_message_digest_binding(msg_sig, &artifact)?;

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
                requirements.verify_binding(&artifact)?;
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
}

/// Check that a `MessageSignature`'s declared `messageDigest`, if any, matches
/// the artifact.
fn verify_message_digest_binding(
    msg_sig: &sigstore_types::bundle::MessageSignature,
    artifact: &PreparedArtifact<'_>,
) -> Result<()> {
    if let Some(digest) = &msg_sig.message_digest {
        let artifact_digest = artifact.digest(digest.algorithm)?;
        if digest.digest != artifact_digest.as_bytes() {
            return Err(Error::Verification(
                "message digest in bundle does not match artifact hash".to_string(),
            ));
        }
    }
    Ok(())
}

/// Verify the DSSE envelope's signature over its PAE with the given key.
fn verify_dsse_envelope_signature(
    envelope: &sigstore_types::DsseEnvelope,
    public_key: &sigstore_types::DerPublicKey,
    scheme: SigningScheme,
) -> Result<()> {
    // Compute the PAE that was signed
    let pae = envelope.pae();

    sigstore_crypto::verify_signature(public_key, &pae, &envelope.signature.sig, scheme)
        .map_err(|e| Error::Verification(format!("DSSE signature verification failed: {}", e)))
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
    let result = if let Some(algorithm) = scheme.hash_algorithm() {
        let digest = artifact.digest(algorithm)?;
        sigstore_crypto::verify_signature_prehashed(
            public_key,
            digest.as_bytes(),
            signature,
            scheme,
        )
    } else if let Some(blob) = artifact.blob() {
        sigstore_crypto::verify_signature(public_key, blob, signature, scheme)
    } else {
        return Err(Error::Verification(format!("cannot verify signature from a digest or reader - scheme {} does not support prehashed mode", scheme.name())));
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

fn validate_structure(bundle: &Bundle, verify_tlog: bool) -> Result<()> {
    validate_bundle_with_options(
        bundle,
        &ValidationOptions {
            require_inclusion_proof: verify_tlog,
            require_timestamp: false,
        },
    )
    .map_err(|e| Error::Verification(format!("bundle validation failed: {e}")))
}

fn prepare_certificate(
    bundle: &Bundle,
    policy: &VerificationPolicy,
) -> Result<sigstore_crypto::CertificateInfo> {
    validate_structure(bundle, policy.verify_tlog)?;
    let cert = bundle
        .signing_certificate()
        .ok_or_else(|| Error::Verification("bundle has no signing certificate".into()))?;
    parse_certificate_info(cert.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {e}")))
}

fn prepare_public_key(
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    policy: &PublicKeyVerificationPolicy,
) -> Result<SigningScheme> {
    if !matches!(
        bundle.verification_material.content,
        VerificationMaterialContent::PublicKey { .. }
    ) {
        return Err(Error::Verification(
            "bundle contains a certificate but public-key verification was requested".into(),
        ));
    }
    validate_structure(bundle, policy.verify_tlog)?;
    signing_scheme_for_content(public_key_algorithm(public_key)?, &bundle.content)
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
/// This is a thin wrapper over [`Verifier::verify`]. The artifact can be
/// provided as raw bytes or as a pre-computed digest. Use a [`Verifier`]
/// directly to stream the artifact from a reader with
/// [`Verifier::verify_reader`] or [`Verifier::verify_async_reader`].
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
    Verifier::new(trusted_root).verify(artifact, bundle, policy)
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

/// Convenience function to verify a managed-key bundle with a caller-supplied
/// public key
///
/// This is a thin wrapper over [`Verifier::verify_with_key`]. Use a
/// [`Verifier`] directly to stream the artifact from a reader with
/// [`Verifier::verify_with_key_reader`] or
/// [`Verifier::verify_with_key_async_reader`].
///
/// # Example
///
/// ```no_run
/// use sigstore_verify::{verify_with_key, PublicKeyVerificationPolicy};
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
/// verify_with_key(
///     &artifact,
///     &bundle,
///     &public_key,
///     &PublicKeyVerificationPolicy::default(),
///     &trusted_root,
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn verify_with_key<'a>(
    artifact: impl Into<Artifact<'a>>,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    policy: &PublicKeyVerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    Verifier::new(trusted_root).verify_with_key(artifact, bundle, public_key, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::HashAlgorithm;

    #[test]
    fn public_key_policy_defaults_to_tlog_verification() {
        assert!(PublicKeyVerificationPolicy::default().verify_tlog);
        assert!(
            !PublicKeyVerificationPolicy::default()
                .skip_tlog_unsafe()
                .verify_tlog
        );
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
    fn statement_requirements_fail_closed_and_bind_blob() {
        let content = SignatureContent::DsseEnvelope(in_toto_envelope(
            &statement_with_subject_sha256(&sigstore_crypto::sha256(b"hello").to_hex()),
        ));
        let requirements =
            ArtifactRequirements::new(&content, SigningScheme::EcdsaP256Sha256).unwrap();
        for (bytes, matches) in [(b"hello".as_slice(), true), (b"wrong".as_slice(), false)] {
            let artifact = PreparedArtifact::from_artifact(bytes.into(), &requirements);
            assert_eq!(requirements.verify_binding(&artifact).is_ok(), matches);
        }
        for payload in [
            "not json",
            r#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"p","predicate":{}}"#,
        ] {
            let content = SignatureContent::DsseEnvelope(in_toto_envelope(payload));
            assert!(ArtifactRequirements::new(&content, SigningScheme::EcdsaP256Sha256).is_err());
        }
        let mut envelope = in_toto_envelope("{}");
        envelope.payload_type = "unknown".into();
        assert!(ArtifactRequirements::new(
            &SignatureContent::DsseEnvelope(envelope),
            SigningScheme::EcdsaP256Sha256
        )
        .is_err());
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
