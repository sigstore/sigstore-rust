//! Pluggable cryptographic provider interface for `sigstore-crypto`.
//!
//! By default (when the `aws-lc-rs` Cargo feature is enabled), `sigstore-crypto`
//! uses [`aws_lc_provider()`] automatically without any setup.
//!
//! Downstream consumers that cannot build or link `aws-lc-sys` (for example,
//! bindings that already link BoringSSL, OpenSSL, or a custom FFI table) can
//! disable the default `aws-lc-rs` feature, implement [`CryptoProvider`], and
//! register their implementation once at startup via [`install_default_provider`].

use crate::error::{Error, Result};
use crate::signing::{KeyAlgorithm, SigningScheme};
use sigstore_types::HashAlgorithm;
use std::sync::OnceLock;

/// Incremental hash state created by a [`CryptoProvider`].
pub trait HashContext: Send {
    /// Absorb additional input bytes into the hash state.
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash computation and return the raw digest bytes.
    fn finalize(self: Box<Self>) -> Vec<u8>;
}

/// A signing key pair backed by a [`CryptoProvider`].
pub trait SigningKeyPair: Send + Sync {
    /// Key algorithm of this key pair.
    fn algorithm(&self) -> KeyAlgorithm;

    /// Raw public key bytes (`subjectPublicKey` bit-string content, e.g. uncompressed
    /// SEC1 point `0x04 || X || Y` for ECDSA, 32-byte key for Ed25519).
    fn public_key_bytes(&self) -> &[u8];

    /// Sign raw message `data` using this key pair's default signing scheme.
    fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Sign a precomputed message `digest` (for schemes that support prehashed signing,
    /// such as ECDSA P-256 with a 32-byte SHA-256 digest).
    fn sign_prehashed(&self, digest: &[u8]) -> Result<Vec<u8>>;
}

/// Pluggable cryptographic backend for `sigstore-crypto`.
///
/// Implementations provide hashing, signature verification (both over raw messages
/// and over prehashed digests), and optionally key generation and signing.
pub trait CryptoProvider: Send + Sync + std::fmt::Debug + 'static {
    /// Create a streaming [`HashContext`] for `algorithm` (`Sha2256`, `Sha2384`, or `Sha2512`).
    fn hash(&self, algorithm: HashAlgorithm) -> Result<Box<dyn HashContext>>;

    /// Compute a one-shot SHA-256 digest.
    ///
    /// Providers may override this to avoid boxing a [`HashContext`].
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut ctx = self
            .hash(HashAlgorithm::Sha2256)
            .expect("CryptoProvider must support SHA-256");
        ctx.update(data);
        ctx.finalize()
            .try_into()
            .expect("CryptoProvider SHA-256 digest must be 32 bytes")
    }

    /// Compute a one-shot SHA-384 digest.
    ///
    /// Providers may override this to avoid boxing a [`HashContext`].
    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        let mut ctx = self
            .hash(HashAlgorithm::Sha2384)
            .expect("CryptoProvider must support SHA-384");
        ctx.update(data);
        ctx.finalize()
            .try_into()
            .expect("CryptoProvider SHA-384 digest must be 48 bytes")
    }

    /// Compute a one-shot SHA-512 digest.
    ///
    /// Providers may override this to avoid boxing a [`HashContext`].
    fn sha512(&self, data: &[u8]) -> [u8; 64] {
        let mut ctx = self
            .hash(HashAlgorithm::Sha2512)
            .expect("CryptoProvider must support SHA-512");
        ctx.update(data);
        ctx.finalize()
            .try_into()
            .expect("CryptoProvider SHA-512 digest must be 64 bytes")
    }

    /// Verify a signature over raw message `data`.
    ///
    /// When called via [`VerificationKey`](crate::VerificationKey) or
    /// [`WEBPKI_VERIFICATION_ALGS`](crate::WEBPKI_VERIFICATION_ALGS),
    /// `spki_pubkey_bytes` has already been validated by
    /// [`validate_raw_public_key`](crate::validate_raw_public_key) and contains
    /// the raw `subjectPublicKey` bit-string bytes extracted from the X.509
    /// certificate or SPKI key:
    /// - 65-byte or 97-byte uncompressed SEC1 point (`0x04 || X || Y`) for ECDSA P-256 and P-384
    /// - 32-byte raw public key for Ed25519
    /// - PKCS#1 `RSAPublicKey` DER (`SEQUENCE { modulus, publicExponent }`, 2048–8192 bits) for RSA
    /// - Raw FIPS 204 public key bytes for ML-DSA-44 (1312B), ML-DSA-65 (1952B), and ML-DSA-87 (2592B)
    fn verify_raw(
        &self,
        scheme: SigningScheme,
        spki_pubkey_bytes: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<()>;

    /// Verify a signature over a precomputed `digest`.
    ///
    /// When called via [`VerificationKey::verify_prehashed`](crate::VerificationKey::verify_prehashed),
    /// only schemes where [`SigningScheme::supports_prehashed`] is `true` (ECDSA and RSA)
    /// are passed to this method, `spki_pubkey_bytes` has been validated by
    /// [`validate_raw_public_key`](crate::validate_raw_public_key), and `digest` is
    /// guaranteed to match the byte length of [`SigningScheme::hash_algorithm`].
    fn verify_prehashed(
        &self,
        scheme: SigningScheme,
        spki_pubkey_bytes: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()>;

    /// Generate a new ephemeral key pair for `algorithm`.
    ///
    /// Verification-only providers may leave the default implementation, which returns
    /// [`Error::UnsupportedAlgorithm`].
    fn generate_key_pair(&self, algorithm: KeyAlgorithm) -> Result<Box<dyn SigningKeyPair>> {
        Err(Error::UnsupportedAlgorithm(format!(
            "key generation for {algorithm:?} is not supported by the active CryptoProvider"
        )))
    }

    /// Load a signing key pair from DER-encoded PKCS#8 private key bytes.
    ///
    /// Verification-only providers may leave the default implementation, which returns
    /// [`Error::UnsupportedAlgorithm`].
    fn key_pair_from_pkcs8_der(&self, _pkcs8: &[u8]) -> Result<Box<dyn SigningKeyPair>> {
        Err(Error::UnsupportedAlgorithm(
            "PKCS#8 key loading is not supported by the active CryptoProvider".into(),
        ))
    }
}

static DEFAULT_PROVIDER: OnceLock<&'static dyn CryptoProvider> = OnceLock::new();

/// Install a process-wide default [`CryptoProvider`].
///
/// Returns `Err(provider)` if a default provider has already been installed.
/// When installed before any cryptographic operations run, this provider takes
/// precedence even if the default `aws-lc-rs` feature is also enabled.
pub fn install_default_provider(
    provider: &'static dyn CryptoProvider,
) -> std::result::Result<(), &'static dyn CryptoProvider> {
    DEFAULT_PROVIDER.set(provider)
}

/// Return the active [`CryptoProvider`], or `None` if no provider has been
/// installed and the `aws-lc-rs` feature is disabled.
pub fn try_default_provider() -> Option<&'static dyn CryptoProvider> {
    if let Some(&provider) = DEFAULT_PROVIDER.get() {
        return Some(provider);
    }
    #[cfg(feature = "aws-lc-rs")]
    {
        Some(aws_lc_provider())
    }
    #[cfg(not(feature = "aws-lc-rs"))]
    {
        None
    }
}

/// Return the active [`CryptoProvider`].
///
/// Checks the provider installed via [`install_default_provider`] first, then
/// falls back to [`aws_lc_provider()`] when the `aws-lc-rs` feature is enabled.
///
/// # Panics
///
/// Panics if the `aws-lc-rs` feature is disabled and no provider has been
/// installed via [`install_default_provider`].
pub fn default_provider() -> &'static dyn CryptoProvider {
    try_default_provider().expect(
        "no sigstore-crypto CryptoProvider installed; call \
         sigstore_crypto::install_default_provider() or enable the `aws-lc-rs` feature",
    )
}

/// Return the built-in `aws-lc-rs` [`CryptoProvider`].
#[cfg(feature = "aws-lc-rs")]
pub fn aws_lc_provider() -> &'static dyn CryptoProvider {
    &crate::aws_lc::AWS_LC_PROVIDER
}
