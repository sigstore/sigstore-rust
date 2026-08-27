//! High-level signing API
//!
//! This module provides the main entry point for signing artifacts with Sigstore.

use crate::error::{Error, Result};
use futures::io::{AsyncRead, AsyncReadExt};
use sigstore_bundle::{BundleV03, TlogEntryBuilder};
use sigstore_crypto::{KeyPair, Sha256Hasher, SigningScheme};
use sigstore_fulcio::FulcioClient;
use sigstore_oidc::IdentityToken;
use sigstore_rekor::{DsseEntry, HashedRekord, HashedRekordV2, RekorApiVersion, RekorClient};
use sigstore_trust_root::{
    SigningConfig as TufSigningConfig, SIGSTORE_PRODUCTION_SIGNING_CONFIG,
    SIGSTORE_STAGING_SIGNING_CONFIG,
};
use sigstore_tsa::TimestampClient;
use sigstore_types::{
    Artifact, Bundle, DerCertificate, DsseEnvelope, DsseSignature, HashAlgorithm, KeyId,
    PayloadBytes, Sha256Hash, SignatureBytes, Statement, Subject, TimestampToken,
};

/// Artifact input for signing.
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

/// Wrap a reader so it can be passed to `sign(...).`
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

/// Artifact input for async signing.
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

/// Wrap an async reader so it can be passed to `sign_async(...).`
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

/// Number of bytes hashed between yields to the async executor.
const HASH_YIELD_CHUNK_SIZE: usize = 64 * 1024;

/// Yield control back to the async executor once.
///
/// Runtime-agnostic equivalent of `tokio::task::yield_now()`: the future
/// wakes its own waker and returns `Pending` on the first poll, then `Ready`.
fn yield_now() -> impl std::future::Future<Output = ()> {
    struct YieldNow {
        yielded: bool,
    }

    impl std::future::Future for YieldNow {
        type Output = ();

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.yielded {
                std::task::Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }

    YieldNow { yielded: false }
}

async fn update_sha256_yielding(hasher: &mut Sha256Hasher, data: &[u8]) {
    for chunk in data.chunks(HASH_YIELD_CHUNK_SIZE) {
        hasher.update(chunk);
        yield_now().await;
    }
}

/// Compute a SHA-256 digest over `data` in chunks, yielding to the async
/// executor between chunks.
///
/// Hashing is CPU-bound: doing it in one shot over unbounded caller input
/// would occupy the executor thread for the whole duration and starve other
/// tasks (TOB-SIGSTORE-8). Hashing in [`HASH_YIELD_CHUNK_SIZE`] chunks keeps
/// each non-yielding stretch short so other tasks can make progress.
///
/// Returns the hasher so callers can either [`Sha256Hasher::finalize`] it or
/// sign the digest directly via [`KeyPair::sign_prehashed`].
async fn sha256_yielding(data: &[u8]) -> Sha256Hasher {
    let mut hasher = Sha256Hasher::new();
    update_sha256_yielding(&mut hasher, data).await;
    hasher
}

async fn sha256_reader_yielding(mut reader: impl std::io::Read) -> Result<Sha256Hash> {
    let mut hasher = Sha256Hasher::new();
    let mut buffer = [0_u8; HASH_YIELD_CHUNK_SIZE];
    loop {
        let read = std::io::Read::read(&mut reader, &mut buffer).map_err(Error::ArtifactRead)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        yield_now().await;
    }
    Ok(hasher.finalize())
}

async fn sha256_async_reader(mut reader: impl AsyncRead + Unpin) -> Result<Sha256Hash> {
    let mut hasher = Sha256Hasher::new();
    let mut buffer = [0_u8; HASH_YIELD_CHUNK_SIZE];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(Error::ArtifactRead)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        // AsyncRead is allowed to remain ready indefinitely (for example,
        // futures::io::Cursor), so the read itself is not necessarily a
        // scheduling point. Yield explicitly to keep large inputs from
        // monopolizing the executor thread.
        yield_now().await;
    }
    Ok(hasher.finalize())
}

/// Start hashing a DSSE PAE without materializing the PAE in memory.
fn dsse_pae_hasher(payload_type: &str, payload_len: usize) -> Sha256Hasher {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"DSSEv1 ");
    hasher.update(payload_type.len().to_string().as_bytes());
    hasher.update(b" ");
    hasher.update(payload_type.as_bytes());
    hasher.update(b" ");
    hasher.update(payload_len.to_string().as_bytes());
    hasher.update(b" ");
    hasher
}

/// Hash a DSSE PAE in chunks without first allocating a full PAE copy.
async fn sha256_pae_yielding(payload_type: &str, payload: &[u8]) -> Sha256Hasher {
    let mut hasher = dsse_pae_hasher(payload_type, payload.len());
    update_sha256_yielding(&mut hasher, payload).await;
    hasher
}

/// Copy a DSSE payload into its owned envelope representation while hashing
/// its PAE in the same yielding pass.
async fn prepare_dsse_payload_yielding(
    payload_type: &str,
    data: &[u8],
) -> (PayloadBytes, Sha256Hasher) {
    let mut payload = Vec::with_capacity(data.len());
    let mut hasher = dsse_pae_hasher(payload_type, data.len());
    for chunk in data.chunks(HASH_YIELD_CHUNK_SIZE) {
        payload.extend_from_slice(chunk);
        hasher.update(chunk);
        yield_now().await;
    }
    (PayloadBytes::new(payload), hasher)
}

/// Configuration for signing operations
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Fulcio URL
    pub fulcio_url: String,
    /// Rekor URL
    pub rekor_url: String,
    /// TSA URL (optional)
    pub tsa_url: Option<String>,
    /// Signing scheme to use
    pub signing_scheme: SigningScheme,
    /// Rekor API version to use (defaults to V2)
    pub rekor_api_version: RekorApiVersion,
    /// OIDC provider URL (optional)
    pub oidc_url: Option<String>,
}

impl Default for SigningConfig {
    fn default() -> Self {
        let rekor_api_version = RekorApiVersion::default();
        Self {
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: rekor_api_version.default_url().to_string(),
            tsa_url: Some("https://timestamp.sigstore.dev/api/v1/timestamp".to_string()),
            signing_scheme: SigningScheme::EcdsaP256Sha256,
            rekor_api_version,
            oidc_url: Some("https://oauth2.sigstore.dev/auth".to_string()),
        }
    }
}

impl SigningConfig {
    /// Create configuration for Sigstore public-good instance
    ///
    /// This uses the embedded signing config to get the best available endpoints.
    /// For the most up-to-date endpoints, use `from_tuf_config()` with a TUF-fetched config.
    pub fn production() -> Self {
        Self::from_tuf_config(
            &TufSigningConfig::from_json(SIGSTORE_PRODUCTION_SIGNING_CONFIG)
                .expect("Failed to parse embedded production config"),
        )
        .expect("Failed to find required endpoints in embedded production config")
    }

    /// Create configuration for Sigstore staging instance
    ///
    /// This uses the embedded signing config to get the best available endpoints.
    /// For the most up-to-date endpoints, use `from_tuf_config()` with a TUF-fetched config.
    pub fn staging() -> Self {
        Self::from_tuf_config(
            &TufSigningConfig::from_json(SIGSTORE_STAGING_SIGNING_CONFIG)
                .expect("Failed to parse embedded staging config"),
        )
        .expect("Failed to find required endpoints in embedded staging config")
    }

    /// Create configuration from a TUF signing config
    ///
    /// This extracts the best available endpoints from the signing config,
    /// preferring higher API versions when available.
    ///
    /// # Arguments
    ///
    /// * `tuf_config` - The signing config from TUF
    pub fn from_tuf_config(tuf_config: &TufSigningConfig) -> Result<Self> {
        Self::from_tuf_config_with_rekor_version(tuf_config, None)
    }

    /// Create configuration from a TUF signing config with optional forced Rekor version
    ///
    /// # Arguments
    ///
    /// * `tuf_config` - The signing config from TUF
    /// * `force_rekor_version` - If Some, force a specific Rekor API version
    pub fn from_tuf_config_with_rekor_version(
        tuf_config: &TufSigningConfig,
        force_rekor_version: Option<u32>,
    ) -> Result<Self> {
        let fulcio_url = tuf_config
            .get_fulcio_url()
            .map(|e| e.url.clone())
            .ok_or_else(|| Error::Config("Missing Fulcio URL in TUF config".to_string()))?;

        let (rekor_url, rekor_api_version) =
            if let Some(rekor) = tuf_config.get_rekor_url(force_rekor_version) {
                let version = if rekor.major_api_version == 2 {
                    RekorApiVersion::V2
                } else {
                    RekorApiVersion::V1
                };
                (rekor.url.clone(), version)
            } else {
                return Err(Error::Config("Missing Rekor URL in TUF config".to_string()));
            };

        let tsa_url = tuf_config.get_tsa_url().map(|e| e.url.clone());
        let oidc_url = tuf_config.get_oidc_url().map(|e| e.url.clone());

        Ok(Self {
            fulcio_url,
            rekor_url,
            tsa_url,
            signing_scheme: SigningScheme::EcdsaP256Sha256,
            rekor_api_version,
            oidc_url,
        })
    }

    /// Set the Rekor API version and automatically update the URL
    pub fn with_rekor_version(mut self, version: RekorApiVersion) -> Self {
        self.rekor_api_version = version;
        self.rekor_url = version.default_url().to_string();
        self
    }
}

/// Context for signing operations
pub struct SigningContext {
    /// Configuration
    config: SigningConfig,
}

impl SigningContext {
    /// Create a new signing context with default configuration
    pub fn new() -> Self {
        Self::with_config(SigningConfig::default())
    }

    /// Create a new signing context with custom configuration
    pub fn with_config(config: SigningConfig) -> Self {
        Self { config }
    }

    /// Create a signing context for the public-good instance
    pub fn production() -> Self {
        Self::with_config(SigningConfig::production())
    }

    /// Create a signing context for the staging instance
    pub fn staging() -> Self {
        Self::with_config(SigningConfig::staging())
    }

    /// Get the configuration
    pub fn config(&self) -> &SigningConfig {
        &self.config
    }

    /// Create a signer with the given identity token
    pub fn signer(&self, identity_token: IdentityToken) -> Signer {
        Signer {
            identity_token,
            signing_scheme: self.config.signing_scheme,
            fulcio_url: self.config.fulcio_url.clone(),
            rekor_url: self.config.rekor_url.clone(),
            tsa_url: self.config.tsa_url.clone(),
            rekor_api_version: self.config.rekor_api_version,
        }
    }
}

impl Default for SigningContext {
    fn default() -> Self {
        Self::new()
    }
}

/// A signer for creating Sigstore signatures
pub struct Signer {
    identity_token: IdentityToken,
    signing_scheme: SigningScheme,
    fulcio_url: String,
    rekor_url: String,
    tsa_url: Option<String>,
    rekor_api_version: RekorApiVersion,
}

impl Signer {
    /// Sign an artifact and return a Sigstore bundle (hashedrekord format)
    ///
    /// This creates a hashedrekord bundle that includes a signature over the artifact.
    /// The artifact can be provided as raw bytes or as an `Artifact` enum.
    ///
    /// A pre-computed digest is trusted as the identity of the artifact and
    /// signed directly in prehashed mode; the library cannot check it against
    /// bytes it was not given.
    ///
    /// # Executor behavior
    ///
    /// Hashing the artifact is CPU-bound work that runs on the current task.
    /// To keep a large artifact from monopolizing the async executor thread,
    /// the SHA-256 digest is computed incrementally in 64 KiB chunks with a
    /// yield to the executor between chunks. The ECDSA signature is then
    /// produced over the precomputed digest and verifies identically to a
    /// signature over the raw artifact, so signing cost does not scale with
    /// the artifact size.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_sign::{SigningContext, Signer};
    /// use sigstore_oidc::IdentityToken;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let context = SigningContext::production();
    /// let token = IdentityToken::from_jwt("header.payload.signature")?;
    /// let signer = context.signer(token);
    /// let artifact = b"hello world";
    /// let bundle = signer.sign(artifact.as_slice()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign<'a, R: std::io::Read>(
        &self,
        artifact: impl Into<ArtifactSource<'a, R>>,
    ) -> Result<Bundle> {
        let artifact_hash = match artifact.into() {
            ArtifactSource::Artifact(artifact) => self.sha256_artifact(artifact).await?,
            ArtifactSource::Reader(reader) => sha256_reader_yielding(reader).await?,
        };
        self.sign_sha256(artifact_hash).await
    }

    /// Sign an artifact read synchronously to EOF in constant memory.
    ///
    /// Reads happen while this future is polled and may block its executor
    /// thread. Async applications should prefer [`Signer::sign_async_reader`].
    pub async fn sign_reader(&self, reader: impl std::io::Read) -> Result<Bundle> {
        self.sign(crate::sign::reader(reader)).await
    }

    /// Sign an artifact read asynchronously to EOF in constant memory.
    pub async fn sign_async_reader(&self, reader: impl AsyncRead + Unpin) -> Result<Bundle> {
        self.sign_async(crate::sign::async_reader(reader)).await
    }

    /// Sign an artifact or async reader.
    pub async fn sign_async<'a, R: AsyncRead + Unpin>(
        &self,
        artifact: impl Into<AsyncArtifactSource<'a, R>>,
    ) -> Result<Bundle> {
        let artifact_hash = match artifact.into() {
            AsyncArtifactSource::Artifact(artifact) => self.sha256_artifact(artifact).await?,
            AsyncArtifactSource::Reader(reader) => sha256_async_reader(reader).await?,
        };
        self.sign_sha256(artifact_hash).await
    }

    async fn sha256_artifact(&self, artifact: Artifact<'_>) -> Result<Sha256Hash> {
        match artifact {
            Artifact::Blob(blob) => Ok(sha256_yielding(blob).await.finalize()),
            Artifact::Digest(digest) => {
                if digest.algorithm() != HashAlgorithm::Sha2256 {
                    return Err(Error::Signing(format!(
                        "hashedrekord signing requires a SHA-256 artifact digest, got {}",
                        digest.algorithm()
                    )));
                }
                Sha256Hash::try_from_slice(digest.as_bytes())
                    .map_err(|e| Error::Signing(e.to_string()))
            }
        }
    }

    async fn sign_sha256(&self, artifact_hash: Sha256Hash) -> Result<Bundle> {
        // 1. Generate ephemeral key pair
        let key_pair = self.generate_ephemeral_keypair()?;

        // 2. Get signing certificate from Fulcio
        let leaf_cert_der = self.request_certificate(&key_pair).await?;

        // 3. Sign the already prepared digest.
        let signature = key_pair.sign_digest(&artifact_hash)?;

        // 4. Create Rekor entry (with certificate, not just public key)
        let tlog_entry = self
            .create_rekor_entry(&artifact_hash, &signature, &leaf_cert_der)
            .await?;

        // 6. Get timestamp from TSA (optional)
        let timestamp = if let Some(tsa_url) = &self.tsa_url {
            Some(self.request_timestamp(tsa_url, &signature).await?)
        } else {
            None
        };

        // 7. Build bundle
        let mut bundle =
            BundleV03::with_certificate_and_signature(leaf_cert_der, signature, artifact_hash)
                .with_tlog_entry(tlog_entry.build());

        if let Some(ts) = timestamp {
            bundle = bundle.with_rfc3161_timestamp(ts);
        }

        Ok(bundle.into_bundle())
    }

    /// Generate an ephemeral key pair based on the configured signing scheme
    fn generate_ephemeral_keypair(&self) -> Result<KeyPair> {
        match self.signing_scheme {
            SigningScheme::EcdsaP256Sha256 => KeyPair::generate_ecdsa_p256().map_err(|e| {
                Error::Signing(format!("Failed to generate ECDSA P-256 key pair: {}", e))
            }),
            _ => Err(Error::Signing(format!(
                "Signing scheme {:?} not yet supported",
                self.signing_scheme
            ))),
        }
    }

    /// Request a signing certificate from Fulcio
    ///
    /// Returns the leaf certificate as DerCertificate.
    async fn request_certificate(&self, key_pair: &KeyPair) -> Result<DerCertificate> {
        // Create Fulcio client and request certificate
        let fulcio = FulcioClient::new(&self.fulcio_url);
        let cert_response = fulcio
            .create_signing_certificate(&self.identity_token, key_pair)
            .await
            .map_err(|e| Error::Signing(format!("Failed to get certificate from Fulcio: {}", e)))?;

        // Get the leaf certificate (v0.3 bundles use single cert, not chain)
        cert_response
            .leaf_certificate()
            .map_err(|e| Error::Signing(format!("Failed to get certificate: {}", e)))
    }

    /// Create a Rekor entry for the signed artifact
    async fn create_rekor_entry(
        &self,
        artifact_hash: &Sha256Hash,
        signature: &SignatureBytes,
        certificate: &DerCertificate,
    ) -> Result<TlogEntryBuilder> {
        // Create Rekor client
        let rekor = RekorClient::new(&self.rekor_url);

        // Use V1 or V2 API based on configuration
        let (log_entry, version) =
            match self.rekor_api_version {
                RekorApiVersion::V1 => {
                    let hashed_rekord = HashedRekord::new(artifact_hash, signature, certificate);
                    let entry = rekor.create_entry(hashed_rekord).await.map_err(|e| {
                        Error::Signing(format!("Failed to create Rekor entry: {}", e))
                    })?;
                    (entry, "0.0.1")
                }
                RekorApiVersion::V2 => {
                    let hashed_rekord = HashedRekordV2::new(artifact_hash, signature, certificate);
                    let entry = rekor.create_entry_v2(hashed_rekord).await.map_err(|e| {
                        Error::Signing(format!("Failed to create Rekor entry: {}", e))
                    })?;
                    (entry, "0.0.2")
                }
            };

        // Build TlogEntry from the log entry response
        let tlog_builder = TlogEntryBuilder::from_log_entry(&log_entry, "hashedrekord", version);

        Ok(tlog_builder)
    }

    /// Request a timestamp from the Timestamp Authority
    async fn request_timestamp(
        &self,
        tsa_url: &str,
        signature: &SignatureBytes,
    ) -> Result<TimestampToken> {
        let tsa = TimestampClient::new(tsa_url.to_string());
        tsa.timestamp_signature(signature)
            .await
            .map_err(|e| Error::Signing(format!("Failed to get timestamp: {}", e)))
    }

    /// Sign an attestation (DSSE envelope with in-toto statement)
    ///
    /// This creates a GitHub-style attestation bundle with a DSSE envelope containing
    /// an in-toto statement. Unlike `sign()`, this method doesn't need the raw artifact
    /// bytes - only the artifact name and digest.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_sign::{SigningContext, Attestation};
    /// use sigstore_oidc::IdentityToken;
    /// use sigstore_types::Sha256Hash;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let context = SigningContext::production();
    /// let token = IdentityToken::from_jwt("header.payload.signature")?;
    /// let signer = context.signer(token);
    ///
    /// // Create attestation with pre-computed digest (no raw bytes needed!)
    /// let digest = Sha256Hash::from_hex("54303491a8418fbed24344b51354618c29b43bf282ceb433af65e2299f9271f")?;
    /// let attestation = Attestation::new(
    ///     "https://example.com/attestation-type/v1",
    ///     serde_json::json!({"key": "value"})
    /// )
    /// .add_subject("my-package-1.0.0.tar.gz", digest);
    ///
    /// let bundle = signer.sign_attestation(attestation).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign_attestation(&self, attestation: Attestation) -> Result<Bundle> {
        let statement = attestation.build_statement();
        let statement_json = serde_json::to_vec(&statement)
            .map_err(|e| Error::Signing(format!("Failed to serialize statement: {}", e)))?;

        self.sign_raw_statement(&statement_json).await
    }

    /// Sign a pre-existing raw in-toto statement
    ///
    /// This creates a DSSE bundle with the given statement bytes.
    /// The given bytes are used as-is as the in-toto statement: caller is responsible
    /// for the content of the statement.
    ///
    /// # Executor behavior
    ///
    /// The DSSE pre-authentication encoding (PAE) of the statement is hashed
    /// incrementally with yields to the executor between chunks, and the
    /// signature is produced over the precomputed digest, as in
    /// [`sign`](Self::sign). Validating the statement JSON still runs
    /// synchronously on the current task; statements are expected to be small
    /// (metadata, not artifact contents).
    pub async fn sign_raw_statement(&self, statement_bytes: &[u8]) -> Result<Bundle> {
        // Generate ephemeral key, get a signing certificate for it
        let key_pair = self.generate_ephemeral_keypair()?;
        let leaf_cert_der = self.request_certificate(&key_pair).await?;

        // validate that input is a valid statement
        if serde_json::from_slice::<Statement>(statement_bytes).is_err() {
            return Err(Error::Signing(
                "Provided statement is not a valid in-toto Statement".to_string(),
            ));
        }

        // Copy the payload and hash its PAE in one cooperative pass, without
        // allocating a second, full-size PAE buffer.
        let payload_type = "application/vnd.in-toto+json".to_string();
        let (payload, hasher) = prepare_dsse_payload_yielding(&payload_type, statement_bytes).await;
        let (_pae_hash, signature) = key_pair.sign_prehashed(hasher)?;

        let dsse_envelope = DsseEnvelope::new(
            payload_type,
            payload,
            DsseSignature {
                sig: signature.clone(),
                keyid: KeyId::default(),
            },
        );

        // Create and submit DSSE Rekor entry
        let tlog_entry = self
            .create_dsse_rekor_entry(&dsse_envelope, &leaf_cert_der)
            .await?;

        // Get timestamp from TSA (optional)
        let timestamp = if let Some(tsa_url) = &self.tsa_url {
            Some(self.request_timestamp(tsa_url, &signature).await?)
        } else {
            None
        };

        // Build bundle with DSSE envelope
        let mut bundle = BundleV03::with_certificate_and_dsse(leaf_cert_der, dsse_envelope)
            .with_tlog_entry(tlog_entry.build());

        if let Some(ts) = timestamp {
            bundle = bundle.with_rfc3161_timestamp(ts);
        }

        Ok(bundle.into_bundle())
    }

    /// Create a DSSE Rekor entry
    async fn create_dsse_rekor_entry(
        &self,
        envelope: &DsseEnvelope,
        certificate: &DerCertificate,
    ) -> Result<TlogEntryBuilder> {
        // Create Rekor client
        let rekor = RekorClient::new(&self.rekor_url);

        // Use V1 or V2 API based on configuration
        let (log_entry, kind, version) = match self.rekor_api_version {
            RekorApiVersion::V1 => {
                let dsse_entry = DsseEntry::new(envelope, certificate);
                let entry = rekor.create_dsse_entry(dsse_entry).await.map_err(|e| {
                    Error::Signing(format!("Failed to create DSSE Rekor entry: {}", e))
                })?;
                (entry, "dsse", "0.0.1")
            }
            RekorApiVersion::V2 => {
                let hash = sha256_pae_yielding(&envelope.payload_type, envelope.payload.as_bytes())
                    .await
                    .finalize();

                let signature = &envelope.signature.sig;

                let hashed_rekord = HashedRekordV2::new(&hash, signature, certificate);
                let entry = rekor.create_entry_v2(hashed_rekord).await.map_err(|e| {
                    Error::Signing(format!("Failed to create Rekor entry for DSSE: {}", e))
                })?;
                (entry, "hashedrekord", "0.0.2")
            }
        };

        // Build TlogEntry from the log entry response
        let tlog_builder = TlogEntryBuilder::from_log_entry(&log_entry, kind, version);

        Ok(tlog_builder)
    }
}

/// An attestation to be signed (in-toto statement)
///
/// Attestations are used to make claims about artifacts without needing the raw
/// artifact bytes. Each attestation contains:
/// - One or more subjects (artifacts) identified by name and digest
/// - A predicate type URI identifying the attestation format
/// - The predicate content (attestation-specific data)
///
/// # Example
///
/// ```
/// use sigstore_sign::Attestation;
/// use sigstore_types::Sha256Hash;
///
/// let digest = Sha256Hash::from_hex(
///     "54303491a8418fbed24344b51354618c29b43bf282ceb433af65e2299f9271ff"
/// ).unwrap();
///
/// let attestation = Attestation::new(
///     "https://slsa.dev/provenance/v1",
///     serde_json::json!({
///         "buildType": "https://example.com/build/v1",
///         "builder": {"id": "https://github.com/actions/runner"}
///     })
/// )
/// .add_subject("my-package-1.0.0.tar.gz", digest);
/// ```
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Subjects (artifacts being attested about)
    subjects: Vec<AttestationSubject>,
    /// Predicate type URI
    predicate_type: String,
    /// Predicate content
    predicate: serde_json::Value,
}

/// A subject in an attestation
#[derive(Debug, Clone)]
pub struct AttestationSubject {
    /// Name of the artifact
    pub name: String,
    /// SHA-256 digest of the artifact
    pub digest: Sha256Hash,
}

impl Attestation {
    /// Create a new attestation with the given predicate type and content
    pub fn new(predicate_type: impl Into<String>, predicate: serde_json::Value) -> Self {
        Self {
            subjects: Vec::new(),
            predicate_type: predicate_type.into(),
            predicate,
        }
    }

    /// Add a subject to the attestation
    pub fn add_subject(mut self, name: impl Into<String>, digest: Sha256Hash) -> Self {
        self.subjects.push(AttestationSubject {
            name: name.into(),
            digest,
        });
        self
    }

    /// Add multiple subjects at once
    pub fn with_subjects(mut self, subjects: Vec<(String, Sha256Hash)>) -> Self {
        for (name, digest) in subjects {
            self.subjects.push(AttestationSubject { name, digest });
        }
        self
    }

    /// Build the in-toto statement
    fn build_statement(&self) -> sigstore_types::Statement {
        use sigstore_types::Digest;

        sigstore_types::Statement {
            type_: "https://in-toto.io/Statement/v1".to_string(),
            subject: self
                .subjects
                .iter()
                .map(|s| Subject {
                    name: s.name.clone(),
                    digest: Digest {
                        sha256: Some(s.digest.to_hex()),
                        sha512: None,
                    },
                })
                .collect(),
            predicate_type: self.predicate_type.clone(),
            predicate: self.predicate.clone(),
        }
    }
}

/// Convenience function to create a signing context
pub fn sign_context() -> SigningContext {
    SigningContext::production()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_config_default() {
        let config = SigningConfig::default();
        assert!(config.fulcio_url.contains("sigstore.dev"));
        assert!(config.rekor_url.contains("sigstore.dev"));
    }

    #[test]
    fn test_signing_context_creation() {
        let _context = SigningContext::new();
        let _prod = SigningContext::production();
        let _staging = SigningContext::staging();
    }

    #[tokio::test]
    async fn test_sha256_yielding_matches_one_shot() {
        for size in [
            0,
            1,
            HASH_YIELD_CHUNK_SIZE - 1,
            HASH_YIELD_CHUNK_SIZE,
            HASH_YIELD_CHUNK_SIZE + 1,
            3 * HASH_YIELD_CHUNK_SIZE + 17,
        ] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let chunked = sha256_yielding(&data).await.finalize();
            assert_eq!(chunked, sigstore_crypto::sha256(&data), "size {size}");
        }
    }

    #[tokio::test]
    async fn reader_hashing_matches_blob_hashing() {
        let data = vec![42_u8; HASH_YIELD_CHUNK_SIZE * 2 + 7];
        let expected = sigstore_crypto::sha256(&data);
        assert_eq!(
            sha256_reader_yielding(std::io::Cursor::new(&data))
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            sha256_async_reader(futures::io::Cursor::new(&data))
                .await
                .unwrap(),
            expected
        );
    }

    #[test]
    fn async_reader_hashing_yields_even_when_reads_are_ready() {
        let mut future = Box::pin(sha256_async_reader(futures::io::Cursor::new(vec![42_u8])));
        let waker = futures::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(future.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
    }

    #[tokio::test]
    async fn test_dsse_pae_yielding_matches_materialized_pae() {
        let payload_type = "application/vnd.in-toto+json";
        for size in [0, 1, HASH_YIELD_CHUNK_SIZE, HASH_YIELD_CHUNK_SIZE + 1] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (payload, hasher) = prepare_dsse_payload_yielding(payload_type, &data).await;
            assert_eq!(payload.as_bytes(), data);
            assert_eq!(
                hasher.finalize(),
                sigstore_crypto::sha256(&sigstore_types::pae(payload_type, &data))
            );
        }
    }
}
