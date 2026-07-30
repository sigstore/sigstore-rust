//! TUF client for fetching Sigstore trusted roots and signing configuration
//!
//! This module provides functionality to securely fetch trusted root configuration
//! and signing configuration from Sigstore's TUF repository using The Update Framework protocol.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_trust_root::{TrustedRoot, SigningConfig};
//!
//! # async fn example() -> Result<(), sigstore_trust_root::Error> {
//! // Fetch trusted root via TUF from production Sigstore (recommended)
//! let root = TrustedRoot::production().await?;
//!
//! // Fetch signing config via TUF
//! let config = SigningConfig::production().await?;
//!
//! // Or from staging
//! let staging_root = TrustedRoot::staging().await?;
//! let staging_config = SigningConfig::staging().await?;
//! # Ok(())
//! # }
//! ```
//!
//! For custom TUF repositories:
//!
//! ```ignore
//! use sigstore_trust_root::{TrustedRoot, TufConfig};
//!
//! # async fn example() -> Result<(), sigstore_trust_root::Error> {
//! let config = TufConfig::custom(
//!     "https://sigstore.github.io/root-signing/",
//!     include_bytes!("path/to/root.json"),
//! );
//! let root = TrustedRoot::from_tuf(config).await?;
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};

use sigstore_tuf::{FileStore, HttpRepository, StoreRepository, Updater};

use crate::{Error, Result, SigningConfig, SigstoreInstance, TrustedRoot};

/// Default Sigstore production TUF repository URL
pub const DEFAULT_TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// Sigstore staging TUF repository URL
pub const STAGING_TUF_URL: &str = "https://tuf-repo-cdn.sigstage.dev";

/// GitHub artifact attestation TUF repository URL
///
/// This is GitHub's separate Sigstore instance, used for GitHub-hosted artifact
/// attestations whose leaf certificates are issued by `O=GitHub, Inc.`.
pub const GITHUB_TUF_URL: &str = "https://tuf-repo.github.com";

/// Embedded root.json for production TUF instance
pub const PRODUCTION_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_root.json");

/// Embedded root.json for staging TUF instance
pub const STAGING_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_staging_root.json");

/// Embedded root.json for GitHub's artifact attestation TUF instance
pub const GITHUB_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_github_root.json");

/// TUF target name for trusted root
pub const TRUSTED_ROOT_TARGET: &str = "trusted_root.json";

/// TUF target name for signing configuration
pub const SIGNING_CONFIG_TARGET: &str = "signing_config.v0.2.json";

/// Convert a URL to a safe directory name for caching
///
/// This encodes special characters to create a filesystem-safe name while
/// remaining human-readable. URLs are expected to be ASCII.
fn url_to_dirname(url: &str) -> String {
    // Normalize trailing slashes so that `https://example.com` and
    // `https://example.com/` resolve to the same cache directory.
    let trimmed = url.trim_end_matches('/');
    let mut result = String::with_capacity(trimmed.len() * 3);
    for &byte in trimmed.as_bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                result.push(byte as char)
            }
            _ => {
                result.push('%');
                result.push(char::from(HEX_CHARS[(byte >> 4) as usize]));
                result.push(char::from(HEX_CHARS[(byte & 0xf) as usize]));
            }
        }
    }
    result
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

/// How offline mode responds when the local TUF cache cannot be served.
///
/// In offline mode ([`TufConfig::offline`]) no network requests are made and
/// the local cache is only served after re-running the full TUF verification
/// workflow against the pinned root of trust (see [`TufConfig::offline`] for
/// details). This enum decides what happens when that is not possible —
/// because the cache is absent, or because it fails any verification step
/// (missing metadata, bad signatures, rollback, hash/length mismatch, or
/// expired metadata):
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineMode {
    /// Serve the verified cache or fail: any cache that is absent or fails
    /// verification is an error surfaced to the caller.
    ///
    /// The error message states why the cache was rejected (e.g. expired
    /// metadata vs. a hash mismatch), so the caller can decide whether to
    /// refresh online or to explicitly fall back to the embedded snapshot via
    /// [`TrustedRoot::from_embedded`](crate::TrustedRoot::from_embedded).
    Strict,
    /// Fall back to the embedded compile-time data whenever the cache is
    /// absent or fails verification (a `tracing::warn!` records the reason).
    ///
    /// Only known Sigstore instances (production, staging, GitHub) have
    /// embedded data; for custom TUF URLs the fallback itself fails and this
    /// behaves like [`OfflineMode::Strict`].
    ///
    /// Note the embedded snapshot is frozen at compile time of this crate: it
    /// is authentic but may be *older* than the cache that just failed
    /// verification (e.g. because it merely expired). Choose
    /// [`OfflineMode::Strict`] if silently downgrading to older trust
    /// material is not acceptable.
    EmbeddedFallback,
}

/// Configuration for TUF client
#[derive(Debug, Clone)]
pub struct TufConfig {
    /// Base URL for the TUF repository
    pub url: String,
    /// Path to local cache directory (optional, derived from URL if not set)
    pub cache_dir: Option<PathBuf>,
    /// Whether to disable local caching
    pub disable_cache: bool,
    /// Offline mode: `Some(mode)` means no network requests are made and the
    /// (verified) cache is served per `mode`; `None` means online.
    pub offline: Option<OfflineMode>,
    /// Custom TUF root.json for bootstrapping trust (None = use embedded for known URLs)
    root_json: Option<Vec<u8>>,
}

impl Default for TufConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_TUF_URL.to_string(),
            cache_dir: None,
            disable_cache: false,
            offline: None,
            root_json: None,
        }
    }
}

impl TufConfig {
    /// Create configuration for production Sigstore instance
    pub fn production() -> Self {
        Self::default()
    }

    /// Create configuration for staging Sigstore instance
    pub fn staging() -> Self {
        Self {
            url: STAGING_TUF_URL.to_string(),
            ..Default::default()
        }
    }

    /// Create configuration for GitHub's artifact attestation Sigstore instance
    pub fn github() -> Self {
        Self {
            url: GITHUB_TUF_URL.to_string(),
            ..Default::default()
        }
    }

    /// Create configuration for a custom TUF repository
    ///
    /// # Arguments
    ///
    /// * `url` - Base URL of the TUF repository
    /// * `root_json` - Contents of root.json for bootstrapping trust
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // For the root-signing test repository
    /// let config = TufConfig::custom(
    ///     "https://sigstore.github.io/root-signing/",
    ///     include_bytes!("path/to/root.json"),
    /// );
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cache_dir: None,
            disable_cache: false,
            offline: None,
            root_json: None,
        }
    }

    /// Provide a custom root.json for bootstrapping trust
    pub fn with_root(mut self, root_json: impl AsRef<[u8]>) -> Self {
        self.root_json = Some(root_json.as_ref().to_vec());
        self
    }

    /// Create configuration for a custom TUF repository, loading root.json from a file
    ///
    /// # Arguments
    ///
    /// * `url` - Base URL of the TUF repository
    /// * `root_path` - Path to the root.json file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = TufConfig::custom_from_file(
    ///     "https://sigstore.github.io/root-signing/",
    ///     "path/to/root.json",
    /// )?;
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom_from_file(
        url: impl Into<String>,
        root_path: impl AsRef<Path>,
    ) -> std::io::Result<Self> {
        let root_json = std::fs::read(root_path)?;
        Ok(Self::custom(url).with_root(root_json))
    }

    /// Set the cache directory
    pub fn with_cache_dir(mut self, path: PathBuf) -> Self {
        self.cache_dir = Some(path);
        self
    }

    /// Disable local caching
    pub fn without_cache(mut self) -> Self {
        self.disable_cache = true;
        self
    }

    /// Enable offline mode (no network; verified cache only, with an explicit
    /// fallback policy)
    ///
    /// In offline mode no network requests are made. The local TUF cache is
    /// served, but **only** after re-running the full TUF verification
    /// workflow (root → timestamp → snapshot → targets) against the pinned
    /// root of trust — an explicitly configured [`with_root`](Self::with_root)
    /// root or the embedded root for known Sigstore instances — and checking
    /// each target against the length and hashes pinned in the verified
    /// metadata. The cache directory is writable and therefore untrusted
    /// input; raw cached bytes are never returned (TOB-SIGSTORE-10).
    ///
    /// TUF metadata expiry is enforced during offline verification: a cache
    /// whose `timestamp.json` has expired (for Sigstore production this
    /// happens within days of the last online refresh) fails verification.
    /// This is the fail-secure choice — stale cached key material is not kept
    /// alive indefinitely. Run without `offline()` periodically to keep the
    /// cache fresh.
    ///
    /// `mode` decides what happens when the cache is absent or fails any
    /// verification step: [`OfflineMode::Strict`] surfaces an error saying
    /// why, [`OfflineMode::EmbeddedFallback`] serves the embedded
    /// compile-time data for known Sigstore instances (which may be *older*
    /// than the rejected cache).
    pub fn offline(mut self, mode: OfflineMode) -> Self {
        self.offline = Some(mode);
        self
    }
}

/// Embedded production trusted root (same as SIGSTORE_PRODUCTION_TRUSTED_ROOT but as bytes)
const EMBEDDED_PRODUCTION_TRUSTED_ROOT: &[u8] = include_bytes!("trusted_root.json");

/// Embedded production signing config
const EMBEDDED_PRODUCTION_SIGNING_CONFIG: &[u8] =
    include_bytes!("../repository/signing_config.json");

/// Embedded staging trusted root (same as SIGSTORE_STAGING_TRUSTED_ROOT but as bytes)
const EMBEDDED_STAGING_TRUSTED_ROOT: &[u8] = include_bytes!("trusted_root_staging.json");

/// Embedded staging signing config
const EMBEDDED_STAGING_SIGNING_CONFIG: &[u8] =
    include_bytes!("../repository/signing_config_staging.json");

/// Embedded GitHub trusted root (same as SIGSTORE_GITHUB_TRUSTED_ROOT but as bytes)
const EMBEDDED_GITHUB_TRUSTED_ROOT: &[u8] = include_bytes!("trusted_root_github.json");

/// Internal TUF client for fetching targets
struct TufClient {
    config: TufConfig,
    /// Embedded targets for offline fallback (target_name -> bytes)
    embedded_targets: &'static [(&'static str, &'static [u8])],
}

impl TufClient {
    /// Create a new TUF client with the given configuration
    ///
    /// Embedded fallback targets are automatically configured for known URLs
    /// (production, staging, and GitHub).
    fn new(config: TufConfig) -> Self {
        // Determine embedded targets based on URL for offline fallback
        let normalized_url = config.url.trim_end_matches('/');
        let embedded_targets: &'static [(&'static str, &'static [u8])] =
            if normalized_url == DEFAULT_TUF_URL {
                &[
                    (TRUSTED_ROOT_TARGET, EMBEDDED_PRODUCTION_TRUSTED_ROOT),
                    (SIGNING_CONFIG_TARGET, EMBEDDED_PRODUCTION_SIGNING_CONFIG),
                ]
            } else if normalized_url == STAGING_TUF_URL {
                &[
                    (TRUSTED_ROOT_TARGET, EMBEDDED_STAGING_TRUSTED_ROOT),
                    (SIGNING_CONFIG_TARGET, EMBEDDED_STAGING_SIGNING_CONFIG),
                ]
            } else if normalized_url == GITHUB_TUF_URL {
                &[(TRUSTED_ROOT_TARGET, EMBEDDED_GITHUB_TRUSTED_ROOT)]
            } else {
                // Custom URLs have no embedded fallback
                &[]
            };

        Self {
            config,
            embedded_targets,
        }
    }

    /// Fetch a target file from the TUF repository
    ///
    /// In online mode: fetches via TUF protocol with verification
    /// In offline mode: serves the cache after re-verifying it via the TUF
    /// protocol, per the configured [`OfflineMode`]
    async fn fetch_target(&self, target_name: &str) -> Result<Vec<u8>> {
        if let Some(mode) = self.config.offline {
            let mut results = self.fetch_targets_offline(&[target_name], mode).await?;
            return Ok(results.remove(0));
        }
        let mut updater = self.build_updater().await?;
        updater
            .get_target(target_name, jiff::Timestamp::now())
            .await
            .map_err(|e| Error::Tuf(format!("Failed to fetch target {target_name}: {e}")))
    }

    /// Fetch multiple targets in a single TUF session
    ///
    /// This avoids the overhead of re-fetching and re-verifying TUF metadata
    /// for each target (root.json, timestamp.json, snapshot.json, targets.json).
    async fn fetch_targets(&self, target_names: &[&str]) -> Result<Vec<Vec<u8>>> {
        if let Some(mode) = self.config.offline {
            return self.fetch_targets_offline(target_names, mode).await;
        }
        let mut updater = self.build_updater().await?;
        let now = jiff::Timestamp::now();
        let mut results = Vec::with_capacity(target_names.len());
        for name in target_names {
            let bytes = updater
                .get_target(name, now)
                .await
                .map_err(|e| Error::Tuf(format!("Failed to fetch target {name}: {e}")))?;
            results.push(bytes);
        }
        Ok(results)
    }

    /// Get the *pinned* TUF root.json for this configuration: an explicitly
    /// configured root ([`TufConfig::with_root`]) or the embedded root for a
    /// known Sigstore URL.
    ///
    /// Unlike [`Self::get_root_json`], this never reads from the cache
    /// directory, so the result is trustworthy even when the cache is
    /// attacker-writable — it is the only acceptable trust anchor for offline
    /// verification of cached metadata.
    fn pinned_root_json(&self) -> Option<Vec<u8>> {
        if let Some(ref root) = self.config.root_json {
            return Some(root.clone());
        }

        // Fall back to embedded roots for known URLs
        let normalized_url = self.config.url.trim_end_matches('/');
        if normalized_url == DEFAULT_TUF_URL {
            Some(PRODUCTION_TUF_ROOT.to_vec())
        } else if normalized_url == STAGING_TUF_URL {
            Some(STAGING_TUF_ROOT.to_vec())
        } else if normalized_url == GITHUB_TUF_URL {
            Some(GITHUB_TUF_ROOT.to_vec())
        } else {
            None
        }
    }

    /// Get the TUF root.json bytes for this configuration
    fn get_root_json(&self) -> Result<Vec<u8>> {
        if let Some(root) = self.pinned_root_json() {
            return Ok(root);
        }

        // A TUF root was not provided or embedded: Use a cached one if found
        if !self.config.disable_cache {
            if let Ok(cache_dir) = self.get_cache_dir() {
                let cached_path = cache_dir.join("root.json");
                if let Ok(bytes) = std::fs::read(&cached_path) {
                    return Ok(bytes);
                }
            }
        }

        Err(Error::Tuf(format!(
            "No root.json provided for custom URL: {}. Use .with_root() or initialize trust first.",
            self.config.url
        )))
    }

    /// Build a `sigstore-tuf` updater and run the TUF refresh workflow
    /// (root → timestamp → snapshot → targets), verifying all metadata against
    /// the configured bootstrap root.
    ///
    /// When caching is enabled, verified metadata and downloaded targets are
    /// written through to the per-URL cache directory so a later `offline()`
    /// run can serve them.
    async fn build_updater(&self) -> Result<Updater> {
        let repo = HttpRepository::new(&self.config.url).map_err(|e| Error::Tuf(e.to_string()))?;
        let root_bytes = self.get_root_json()?;
        let mut updater = Updater::new(repo, &root_bytes).map_err(|e| Error::Tuf(e.to_string()))?;

        if !self.config.disable_cache {
            let cache_dir = self.get_cache_dir()?;
            tokio::fs::create_dir_all(&cache_dir)
                .await
                .map_err(|e| Error::Tuf(format!("Failed to create cache directory: {e}")))?;
            updater = updater.with_store(FileStore::new(cache_dir));
        }

        updater
            .refresh(jiff::Timestamp::now())
            .await
            .map_err(|e| Error::Tuf(format!("TUF repository load failed: {e}")))?;
        Ok(updater)
    }

    /// Build an updater that re-runs the full TUF verification workflow
    /// (root → timestamp → snapshot → targets) entirely from the local cache,
    /// with no network access, anchored to the pinned root of trust.
    ///
    /// The cache is treated as untrusted input: every cached metadata file is
    /// re-verified against the pinned root — signature thresholds, version
    /// anti-rollback, and expiry — and targets served through the returned
    /// updater are checked against the length and hashes pinned in the
    /// verified targets metadata.
    async fn build_offline_updater(&self) -> Result<Updater> {
        let root_bytes = self.pinned_root_json().ok_or_else(|| {
            Error::Tuf(format!(
                "no pinned TUF root for {}; refusing to verify the cache against \
                 a root taken from the (writable) cache itself",
                self.config.url
            ))
        })?;
        let cache_dir = self.get_cache_dir()?;
        let store = FileStore::new(&cache_dir);
        let mut updater = Updater::new(StoreRepository::new(store.clone()), &root_bytes)
            .map_err(|e| Error::Tuf(e.to_string()))?
            .with_store(store);
        updater
            .refresh(jiff::Timestamp::now())
            .await
            .map_err(|e| Error::Tuf(format!("offline verification of cached metadata: {e}")))?;
        Ok(updater)
    }

    /// Look up a target in the embedded compile-time data.
    fn embedded_target(&self, target_name: &str) -> Option<&'static [u8]> {
        self.embedded_targets
            .iter()
            .find(|(name, _)| *name == target_name)
            .map(|(_, data)| *data)
    }

    /// Fetch targets in offline mode (no network)
    ///
    /// The local TUF cache is only served after the full TUF verification
    /// workflow has been re-run from it against the pinned root (signatures,
    /// versions, expiry) and each target matched its pinned length and
    /// hashes. Raw cache bytes are never returned: the cache directory is
    /// writable and therefore untrusted — a shared CI cache or
    /// attacker-supplied directory could otherwise swap in different service
    /// URLs or keys (TOB-SIGSTORE-10).
    ///
    /// When the cache is absent or fails verification, `mode` decides between
    /// erroring ([`OfflineMode::Strict`]) and serving the embedded
    /// compile-time snapshot ([`OfflineMode::EmbeddedFallback`]).
    async fn fetch_targets_offline(
        &self,
        target_names: &[&str],
        mode: OfflineMode,
    ) -> Result<Vec<Vec<u8>>> {
        match mode {
            OfflineMode::Strict => self.fetch_targets_offline_strict(target_names).await,
            OfflineMode::EmbeddedFallback => {
                self.fetch_targets_offline_with_fallback(target_names).await
            }
        }
    }

    /// [`OfflineMode::Strict`]: verified cache or error — every failure
    /// (absent cache, caching disabled, or any verification step) is
    /// surfaced to the caller with the reason.
    async fn fetch_targets_offline_strict(&self, target_names: &[&str]) -> Result<Vec<Vec<u8>>> {
        if self.config.disable_cache {
            return Err(Error::Tuf(
                "offline strict mode needs the local TUF cache, but caching is disabled; \
                 enable caching or use OfflineMode::EmbeddedFallback"
                    .into(),
            ));
        }
        let mut updater = self.build_offline_updater().await?;
        let now = jiff::Timestamp::now();
        let mut results = Vec::with_capacity(target_names.len());
        for name in target_names {
            let bytes = updater.get_target(name, now).await.map_err(|e| {
                Error::Tuf(format!(
                    "offline verification of cached target '{name}': {e}"
                ))
            })?;
            results.push(bytes);
        }
        Ok(results)
    }

    /// [`OfflineMode::EmbeddedFallback`]: prefer the verified cache, fall
    /// back to the embedded compile-time snapshot (known Sigstore instances
    /// only) whenever the cache is absent or fails verification.
    async fn fetch_targets_offline_with_fallback(
        &self,
        target_names: &[&str],
    ) -> Result<Vec<Vec<u8>>> {
        if !self.config.disable_cache {
            // Only attempt cache verification when cached metadata exists at
            // all, so a first offline run doesn't warn about an empty cache.
            let has_cached_metadata = self
                .get_cache_dir()
                .map(|dir| dir.join("timestamp.json").is_file())
                .unwrap_or(false);
            if has_cached_metadata {
                match self.build_offline_updater().await {
                    Ok(mut updater) => {
                        let now = jiff::Timestamp::now();
                        let mut results = Vec::with_capacity(target_names.len());
                        for name in target_names {
                            match updater.get_target(name, now).await {
                                Ok(bytes) => results.push(bytes),
                                Err(e) => {
                                    tracing::warn!(
                                        target = %name,
                                        error = %e,
                                        "offline mode: cached target failed verification; \
                                         falling back to the embedded target set"
                                    );
                                    results.clear();
                                    break;
                                }
                            }
                        }
                        if results.len() == target_names.len() {
                            return Ok(results);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "offline mode: cached TUF metadata failed verification; \
                             falling back to embedded targets"
                        );
                    }
                }
            } else {
                tracing::debug!("offline mode: no cached TUF metadata; using embedded targets");
            }
        }

        target_names
            .iter()
            .map(|name| {
                self.embedded_target(name)
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| {
                        Error::Tuf(format!(
                            "Target '{name}' not found in verified cache or embedded data (offline mode)"
                        ))
                    })
            })
            .collect()
    }

    /// Get the cache directory path
    ///
    /// Returns URL-namespaced cache directory to prevent collisions between
    /// different TUF repositories.
    fn get_cache_dir(&self) -> Result<PathBuf> {
        if let Some(ref dir) = self.config.cache_dir {
            return Ok(dir.clone());
        }

        // Use platform-specific cache directory with URL namespace
        let project_dirs = directories::ProjectDirs::from("dev", "sigstore", "sigstore-rust")
            .ok_or_else(|| Error::Tuf("Could not determine cache directory".into()))?;

        // Create URL-namespaced subdirectory
        let namespace = url_to_dirname(&self.config.url);
        Ok(project_dirs.cache_dir().join("tuf").join(namespace))
    }
}

impl TrustedRoot {
    /// Fetch the trusted root from Sigstore's production TUF repository
    ///
    /// This is the **recommended** way to get the trusted root for production use.
    /// It securely fetches the latest `trusted_root.json` using the TUF protocol,
    /// verifying all metadata signatures against the embedded root of trust.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::TrustedRoot;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let root = TrustedRoot::production().await?;
    /// println!("Loaded {} Rekor logs", root.tlogs.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn production() -> Result<Self> {
        Self::from_tuf(TufConfig::production()).await
    }

    /// Fetch the trusted root from Sigstore's staging TUF repository
    ///
    /// This is useful for testing against the staging Sigstore infrastructure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::TrustedRoot;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let root = TrustedRoot::staging().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn staging() -> Result<Self> {
        Self::from_tuf(TufConfig::staging()).await
    }

    /// Fetch the trusted root from a TUF repository with custom configuration
    ///
    /// This method allows fetching from custom TUF repositories or configuring
    /// advanced options like cache directory, offline mode, etc.
    ///
    /// # Example: Custom TUF Repository
    ///
    /// ```ignore
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // For the root-signing test repository
    /// let config = TufConfig::custom(
    ///     "https://sigstore.github.io/root-signing/",
    ///     include_bytes!("path/to/root.json"),
    /// );
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Example: Offline Mode
    ///
    /// ```no_run
    /// use sigstore_trust_root::{OfflineMode, TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // No network: serve the verified local cache, or error explaining why
    /// // it could not be verified (use OfflineMode::EmbeddedFallback to fall
    /// // back to the embedded compile-time data instead).
    /// let config = TufConfig::production().offline(OfflineMode::Strict);
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf(config: TufConfig) -> Result<Self> {
        let client = TufClient::new(config);
        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in {}: {}", TRUSTED_ROOT_TARGET, e)))?;
        Self::from_json(&json)
    }
}

impl SigstoreInstance {
    /// Return the TUF configuration for this well-known Sigstore instance.
    pub fn tuf_config(self) -> TufConfig {
        match self {
            Self::PublicGood => TufConfig::production(),
            Self::Staging => TufConfig::staging(),
            Self::GitHub => TufConfig::github(),
        }
    }
}

impl SigningConfig {
    /// Fetch the signing configuration from Sigstore's production TUF repository
    ///
    /// This is the **recommended** way to get the signing config for production use.
    /// It securely fetches the latest `signing_config.v0.2.json` using the TUF protocol,
    /// verifying all metadata signatures against the embedded root of trust.
    ///
    /// The signing config contains service endpoints for signing operations:
    /// - Fulcio CA URLs for certificate issuance
    /// - Rekor transparency log URLs (V1 and V2 endpoints)
    /// - TSA URLs for RFC 3161 timestamp requests
    /// - OIDC provider URLs for authentication
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::SigningConfig;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let config = SigningConfig::production().await?;
    /// if let Some(rekor) = config.get_rekor_url(None) {
    ///     println!("Rekor URL: {} (v{})", rekor.url, rekor.major_api_version);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn production() -> Result<Self> {
        Self::from_tuf(TufConfig::production()).await
    }

    /// Fetch the signing configuration from Sigstore's staging TUF repository
    ///
    /// This is useful for testing against the staging Sigstore infrastructure,
    /// which may have newer API versions (e.g., Rekor V2) available.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::SigningConfig;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let config = SigningConfig::staging().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn staging() -> Result<Self> {
        Self::from_tuf(TufConfig::staging()).await
    }

    /// Fetch the signing configuration from a TUF repository with custom configuration
    ///
    /// This method allows fetching from custom TUF repositories or configuring
    /// advanced options like cache directory, offline mode, etc.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::{OfflineMode, SigningConfig, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // Use offline mode: verified cache only, error otherwise
    /// let config = TufConfig::production().offline(OfflineMode::Strict);
    /// let signing_config = SigningConfig::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf(config: TufConfig) -> Result<Self> {
        let client = TufClient::new(config);
        let bytes = client.fetch_target(SIGNING_CONFIG_TARGET).await?;
        let json = String::from_utf8(bytes).map_err(|e| {
            Error::Tuf(format!("Invalid UTF-8 in {}: {}", SIGNING_CONFIG_TARGET, e))
        })?;
        Self::from_json(&json)
    }
}

/// Fetch both the trusted root and signing config in a single TUF session.
///
/// This is more efficient than calling `TrustedRoot::from_tuf()` and
/// `SigningConfig::from_tuf()` separately, as it only performs the TUF
/// metadata exchange (root → timestamp → snapshot → targets) once.
///
/// # Example
///
/// ```no_run
/// use sigstore_trust_root::tuf::{fetch_trust_material, TufConfig};
///
/// # async fn example() -> Result<(), sigstore_trust_root::Error> {
/// let (root, config) = fetch_trust_material(TufConfig::production()).await?;
/// # Ok(())
/// # }
/// ```
pub async fn fetch_trust_material(config: TufConfig) -> Result<(TrustedRoot, SigningConfig)> {
    let client = TufClient::new(config);
    let results = client
        .fetch_targets(&[TRUSTED_ROOT_TARGET, SIGNING_CONFIG_TARGET])
        .await?;

    let root_json = String::from_utf8(results[0].clone())
        .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in {}: {}", TRUSTED_ROOT_TARGET, e)))?;
    let config_json = String::from_utf8(results[1].clone())
        .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in {}: {}", SIGNING_CONFIG_TARGET, e)))?;

    let root = TrustedRoot::from_json(&root_json)?;
    let config = SigningConfig::from_json(&config_json)?;

    Ok((root, config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_to_dirname() {
        assert_eq!(
            url_to_dirname("https://tuf-repo-cdn.sigstore.dev"),
            "https%3A%2F%2Ftuf-repo-cdn.sigstore.dev"
        );
        // Alphanumeric and safe chars should pass through
        assert_eq!(url_to_dirname("abc-123_test.json"), "abc-123_test.json");
    }

    #[test]
    fn test_url_to_dirname_normalizes_trailing_slash() {
        // URLs that differ only in trailing slash(es) should map to the same dir.
        let no_slash = url_to_dirname("https://tuf-repo-cdn.sigstore.dev");
        let one_slash = url_to_dirname("https://tuf-repo-cdn.sigstore.dev/");
        let many_slashes = url_to_dirname("https://tuf-repo-cdn.sigstore.dev///");
        assert_eq!(no_slash, one_slash);
        assert_eq!(no_slash, many_slashes);

        assert_eq!(
            url_to_dirname("https://sigstore.github.io/root-signing/"),
            url_to_dirname("https://sigstore.github.io/root-signing"),
        );
    }

    #[test]
    fn test_tuf_config_default() {
        let config = TufConfig::default();
        assert_eq!(config.url, DEFAULT_TUF_URL);
        assert!(config.cache_dir.is_none());
        assert!(!config.disable_cache);
        assert!(config.offline.is_none());
        assert!(config.root_json.is_none());
    }

    #[test]
    fn test_tuf_config_staging() {
        let config = TufConfig::staging();
        assert_eq!(config.url, STAGING_TUF_URL);
    }

    #[test]
    fn test_tuf_config_github() {
        let config = TufConfig::github();
        assert_eq!(config.url, GITHUB_TUF_URL);
    }

    #[test]
    fn test_tuf_config_custom() {
        let root_json = b"test root json";
        let config = TufConfig::custom("https://custom.tuf/").with_root(root_json);
        assert_eq!(config.url, "https://custom.tuf/");
        assert_eq!(config.root_json, Some(root_json.to_vec()));
    }

    #[test]
    fn test_tuf_config_builder() {
        let config = TufConfig::production()
            .with_cache_dir(PathBuf::from("/tmp/test"))
            .without_cache()
            .offline(OfflineMode::Strict);
        assert!(config.disable_cache);
        assert_eq!(config.offline, Some(OfflineMode::Strict));
        assert_eq!(config.cache_dir, Some(PathBuf::from("/tmp/test")));
    }

    #[test]
    fn test_tuf_config_get_root_json_production() {
        let config = TufConfig::production();
        assert_eq!(
            TufClient::new(config).get_root_json().unwrap(),
            PRODUCTION_TUF_ROOT
        );
    }

    #[test]
    fn test_tuf_config_get_root_json_staging() {
        let config = TufConfig::staging();
        assert_eq!(
            TufClient::new(config).get_root_json().unwrap(),
            STAGING_TUF_ROOT
        );
    }

    #[test]
    fn test_tuf_config_get_root_json_github() {
        let config = TufConfig::github();
        assert_eq!(
            TufClient::new(config).get_root_json().unwrap(),
            GITHUB_TUF_ROOT
        );
    }

    #[test]
    fn test_tuf_config_get_root_json_custom() {
        let root_json = b"custom root";
        let config = TufConfig::custom("https://custom.tuf/").with_root(root_json);
        assert_eq!(TufClient::new(config).get_root_json().unwrap(), root_json);
    }

    #[test]
    fn test_tuf_config_get_root_json_unknown_url_errors() {
        let config = TufConfig {
            url: "https://unknown.tuf/".to_string(),
            cache_dir: None,
            disable_cache: false,
            offline: None,
            root_json: None,
        };
        let err = TufClient::new(config).get_root_json().unwrap_err();
        assert!(err
            .to_string()
            .contains("No root.json provided for custom URL"));
    }

    #[test]
    fn test_embedded_tuf_roots_are_valid_json() {
        // Verify the embedded TUF roots are valid JSON
        let _: serde_json::Value =
            serde_json::from_slice(PRODUCTION_TUF_ROOT).expect("Invalid production TUF root");
        let _: serde_json::Value =
            serde_json::from_slice(STAGING_TUF_ROOT).expect("Invalid staging TUF root");
        let _: serde_json::Value =
            serde_json::from_slice(GITHUB_TUF_ROOT).expect("Invalid GitHub TUF root");
    }

    #[test]
    fn test_embedded_targets_are_valid() {
        // Verify embedded trusted roots can be parsed
        let _root: crate::TrustedRoot = serde_json::from_slice(EMBEDDED_PRODUCTION_TRUSTED_ROOT)
            .expect("Invalid production trusted root");
        let _root: crate::TrustedRoot = serde_json::from_slice(EMBEDDED_STAGING_TRUSTED_ROOT)
            .expect("Invalid staging trusted root");
        let _root: crate::TrustedRoot =
            crate::TrustedRoot::from_embedded(crate::SigstoreInstance::GitHub)
                .expect("Invalid GitHub trusted root");

        // Verify embedded signing configs can be parsed
        let _config: crate::SigningConfig =
            serde_json::from_slice(EMBEDDED_PRODUCTION_SIGNING_CONFIG)
                .expect("Invalid production signing config");
        let _config: crate::SigningConfig = serde_json::from_slice(EMBEDDED_STAGING_SIGNING_CONFIG)
            .expect("Invalid staging signing config");
    }

    #[tokio::test]
    async fn test_offline_mode_uses_embedded_data() {
        // Use offline mode with cache disabled - should fall back to embedded data
        let config = TufConfig::production()
            .offline(OfflineMode::EmbeddedFallback)
            .without_cache();
        let client = TufClient::new(config);

        // Should successfully return embedded trusted root
        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap();
        assert!(!bytes.is_empty());
        let _root: crate::TrustedRoot = serde_json::from_slice(&bytes).unwrap();

        // Should successfully return embedded signing config
        let bytes = client.fetch_target(SIGNING_CONFIG_TARGET).await.unwrap();
        assert!(!bytes.is_empty());
        let _config: crate::SigningConfig = serde_json::from_slice(&bytes).unwrap();
    }

    #[tokio::test]
    async fn test_offline_mode_fails_for_unknown_target() {
        let config = TufConfig::production()
            .offline(OfflineMode::EmbeddedFallback)
            .without_cache();
        let client = TufClient::new(config);

        // Should fail for unknown target
        let result = client.fetch_target("unknown.json").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_github_trusted_root_uses_explicit_embedded_data() {
        let root = crate::TrustedRoot::from_embedded(crate::SigstoreInstance::GitHub).unwrap();

        assert!(root
            .certificate_authorities
            .iter()
            .any(|ca| ca.uri == "fulcio.githubapp.com"));
    }

    #[tokio::test]
    async fn test_github_offline_mode_uses_embedded_data() {
        let config = TufConfig::github()
            .offline(OfflineMode::EmbeddedFallback)
            .without_cache();
        let client = TufClient::new(config);

        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap();
        assert!(!bytes.is_empty());
        let root: crate::TrustedRoot = serde_json::from_slice(&bytes).unwrap();

        assert!(root
            .certificate_authorities
            .iter()
            .any(|ca| ca.uri == "fulcio.githubapp.com"));
    }

    #[tokio::test]
    async fn test_custom_url_offline_fails_without_cache() {
        // Custom URLs have no embedded fallback
        let config = TufConfig::custom("https://custom.tuf/")
            .with_root(b"root")
            .offline(OfflineMode::EmbeddedFallback)
            .without_cache();
        let client = TufClient::new(config);

        // Should fail since there's no embedded data for custom URLs
        let result = client.fetch_target(TRUSTED_ROOT_TARGET).await;
        assert!(result.is_err());
    }

    /// Helpers to write a fully signed, single-key TUF repository into a
    /// directory using the same layout as `FileStore`, so offline-mode tests
    /// can exercise a cache that passes full TUF verification — and tampered
    /// or expired variants of it.
    mod signed_cache {
        use std::path::Path;

        use serde_json::{json, Value};
        use sha2::{Digest, Sha256};
        use sigstore_crypto::KeyPair;

        pub const FAR_FUTURE: &str = "2999-01-01T00:00:00Z";
        pub const IN_THE_PAST: &str = "2001-01-01T00:00:00Z";

        fn signature(signed: &Value, keyid: &str, kp: &KeyPair) -> Value {
            let canonical = sigstore_tuf::canonical_json::to_canonical_bytes(signed).unwrap();
            let sig = kp.sign(&canonical).unwrap();
            json!({ "keyid": keyid, "sig": hex::encode(sig.as_bytes()) })
        }

        fn envelope(signed: Value, sigs: Vec<Value>) -> Vec<u8> {
            serde_json::to_vec(&json!({ "signed": signed, "signatures": sigs })).unwrap()
        }

        /// A `meta` entry pinning length + sha256 + version of a metadata file.
        fn metafile(bytes: &[u8], version: u64) -> Value {
            json!({
                "version": version,
                "length": bytes.len(),
                "hashes": { "sha256": hex::encode(Sha256::digest(bytes)) },
            })
        }

        /// Write signed TUF metadata pinning `target_content` as
        /// `trusted_root.json` into `cache_dir`, returning the matching
        /// root.json to pin as the bootstrap root of trust.
        pub fn write(cache_dir: &Path, target_content: &[u8], timestamp_expires: &str) -> Vec<u8> {
            let kp = KeyPair::generate_ecdsa_p256().unwrap();
            let pem = kp.public_key_der().unwrap().to_pem();
            let key_obj = json!({
                "keytype": "ecdsa",
                "scheme": "ecdsa-sha2-nistp256",
                "keyval": { "public": pem },
            });
            let key: sigstore_tuf::Key = serde_json::from_value(key_obj.clone()).unwrap();
            let kid = key.key_id().unwrap();

            let target_path = super::TRUSTED_ROOT_TARGET;
            let targets_signed = json!({
                "_type": "targets",
                "spec_version": "1.0.0",
                "version": 1,
                "expires": FAR_FUTURE,
                "targets": {
                    target_path: {
                        "length": target_content.len(),
                        "hashes": { "sha256": hex::encode(Sha256::digest(target_content)) },
                    }
                },
            });
            let targets_bytes = envelope(
                targets_signed.clone(),
                vec![signature(&targets_signed, &kid, &kp)],
            );

            let snapshot_signed = json!({
                "_type": "snapshot",
                "spec_version": "1.0.0",
                "version": 1,
                "expires": FAR_FUTURE,
                "meta": { "targets.json": metafile(&targets_bytes, 1) },
            });
            let snapshot_bytes = envelope(
                snapshot_signed.clone(),
                vec![signature(&snapshot_signed, &kid, &kp)],
            );

            let timestamp_signed = json!({
                "_type": "timestamp",
                "spec_version": "1.0.0",
                "version": 1,
                "expires": timestamp_expires,
                "meta": { "snapshot.json": metafile(&snapshot_bytes, 1) },
            });
            let timestamp_bytes = envelope(
                timestamp_signed.clone(),
                vec![signature(&timestamp_signed, &kid, &kp)],
            );

            let role = json!({ "keyids": [kid.clone()], "threshold": 1 });
            let root_signed = json!({
                "_type": "root",
                "spec_version": "1.0.0",
                "version": 1,
                "expires": FAR_FUTURE,
                "consistent_snapshot": false,
                "keys": { kid.clone(): key_obj },
                "roles": {
                    "root": role, "timestamp": role,
                    "snapshot": role, "targets": role,
                },
            });
            let root_bytes = envelope(
                root_signed.clone(),
                vec![signature(&root_signed, &kid, &kp)],
            );

            std::fs::create_dir_all(cache_dir.join("targets")).unwrap();
            std::fs::write(cache_dir.join("timestamp.json"), &timestamp_bytes).unwrap();
            std::fs::write(cache_dir.join("snapshot.json"), &snapshot_bytes).unwrap();
            std::fs::write(cache_dir.join("targets.json"), &targets_bytes).unwrap();
            std::fs::write(cache_dir.join("targets").join(target_path), target_content).unwrap();

            root_bytes
        }
    }

    #[tokio::test]
    async fn test_offline_mode_serves_fully_verified_cache() {
        // A cache whose metadata chain verifies against the pinned root and
        // whose target matches the pinned hash/length is served offline —
        // in strict mode, so success proves the bytes came from the verified
        // cache with no fallback involved.
        let tmp = tempfile::tempdir().unwrap();
        let content = b"verified offline target content";
        let root = signed_cache::write(tmp.path(), content, signed_cache::FAR_FUTURE);

        let config = TufConfig::custom("https://offline.example/")
            .with_root(&root)
            .offline(OfflineMode::Strict)
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap();
        assert_eq!(bytes, content);
    }

    #[tokio::test]
    async fn test_offline_mode_rejects_tampered_cached_target() {
        // Valid signed metadata, but the cached target bytes were swapped
        // after the fact: the hash check must reject them, and strict mode
        // must surface the failure — the attacker bytes are never returned.
        let tmp = tempfile::tempdir().unwrap();
        let root = signed_cache::write(tmp.path(), b"legitimate", signed_cache::FAR_FUTURE);
        std::fs::write(
            tmp.path().join("targets").join(TRUSTED_ROOT_TARGET),
            b"attacker-controlled bytes",
        )
        .unwrap();

        let config = TufConfig::custom("https://offline.example/")
            .with_root(&root)
            .offline(OfflineMode::Strict)
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("offline verification of cached target"));
    }

    #[tokio::test]
    async fn test_offline_mode_rejects_expired_cached_metadata() {
        // Expired timestamp metadata must fail offline verification
        // (fail-secure): strict mode errors — with a reason naming the
        // expiry — instead of serving a cache whose freshness can no longer
        // be established.
        let tmp = tempfile::tempdir().unwrap();
        let root = signed_cache::write(tmp.path(), b"stale", signed_cache::IN_THE_PAST);

        let config = TufConfig::custom("https://offline.example/")
            .with_root(&root)
            .offline(OfflineMode::Strict)
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("offline verification of cached metadata"));
        assert!(msg.contains("expired"));
    }

    #[tokio::test]
    async fn test_offline_mode_ignores_bare_cached_target_without_metadata() {
        // A bare file dropped into `targets/` without any signed metadata
        // must not be served; offline mode falls back to the embedded data.
        let tmp = tempfile::tempdir().unwrap();
        let targets_dir = tmp.path().join("targets");
        tokio::fs::create_dir_all(&targets_dir).await.unwrap();
        tokio::fs::write(targets_dir.join(TRUSTED_ROOT_TARGET), b"unauthenticated")
            .await
            .unwrap();

        let config = TufConfig::production()
            .offline(OfflineMode::EmbeddedFallback)
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap();
        assert_eq!(bytes, EMBEDDED_PRODUCTION_TRUSTED_ROOT);
    }

    #[tokio::test]
    async fn test_offline_strict_mode_errors_without_cache() {
        // Strict mode never falls back: an absent cache is an error the
        // caller must handle, even for known instances with embedded data.
        let tmp = tempfile::tempdir().unwrap();
        let config = TufConfig::production()
            .offline(OfflineMode::Strict)
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("offline verification of cached metadata"));
    }

    #[tokio::test]
    async fn test_offline_strict_mode_errors_when_caching_disabled() {
        let config = TufConfig::production()
            .offline(OfflineMode::Strict)
            .without_cache();
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        assert!(err.to_string().contains("caching is disabled"));
    }

    #[tokio::test]
    async fn test_offline_embedded_fallback_on_unverifiable_cache() {
        // A cache whose metadata does not verify against the pinned
        // production root (here: signed by an unrelated test key) is
        // rejected, and EmbeddedFallback serves the embedded snapshot.
        let tmp = tempfile::tempdir().unwrap();
        let _unrelated_root = signed_cache::write(tmp.path(), b"evil", signed_cache::FAR_FUTURE);

        let config = TufConfig::production()
            .offline(OfflineMode::EmbeddedFallback)
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap();
        assert_eq!(bytes, EMBEDDED_PRODUCTION_TRUSTED_ROOT);
    }

    #[tokio::test]
    async fn test_offline_fallback_does_not_mix_cached_and_embedded_target_sets() {
        // The cache is valid but only contains trusted_root.json. Falling back
        // per target would combine that cached root with the older embedded
        // signing config, breaking TUF snapshot consistency. One failed target
        // must discard the entire cached set.
        let tmp = tempfile::tempdir().unwrap();
        let cached_root = b"verified but deliberately different root target";
        let root = signed_cache::write(tmp.path(), cached_root, signed_cache::FAR_FUTURE);

        let config = TufConfig::production()
            .with_root(&root)
            .offline(OfflineMode::EmbeddedFallback)
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let targets = client
            .fetch_targets(&[TRUSTED_ROOT_TARGET, SIGNING_CONFIG_TARGET])
            .await
            .unwrap();
        assert_eq!(targets[0], EMBEDDED_PRODUCTION_TRUSTED_ROOT);
        assert_eq!(targets[1], EMBEDDED_PRODUCTION_SIGNING_CONFIG);
        assert_ne!(targets[0], cached_root);
    }

    #[tokio::test]
    async fn test_offline_mode_does_not_trust_unauthenticated_cache_tob_sigstore_10() {
        // Regression test for TOB-SIGSTORE-10: an attacker who can write to
        // the cache directory (shared CI cache, restored cache artifact)
        // swaps the Rekor URL in `targets/trusted_root.json`. Offline mode
        // must not hand that data to `TrustedRoot::from_tuf`.
        let tmp = tempfile::tempdir().unwrap();
        let targets_dir = tmp.path().join("targets");
        tokio::fs::create_dir_all(&targets_dir).await.unwrap();

        let mut doctored: serde_json::Value =
            serde_json::from_slice(EMBEDDED_PRODUCTION_TRUSTED_ROOT).unwrap();
        doctored["tlogs"][0]["baseUrl"] = "https://attacker.invalid/rekor".into();
        tokio::fs::write(
            targets_dir.join(TRUSTED_ROOT_TARGET),
            serde_json::to_vec(&doctored).unwrap(),
        )
        .await
        .unwrap();

        let config = TufConfig::production()
            .offline(OfflineMode::EmbeddedFallback)
            .with_cache_dir(tmp.path().to_path_buf());
        let root = crate::TrustedRoot::from_tuf(config).await.unwrap();

        assert!(
            root.tlogs
                .iter()
                .all(|t| !t.base_url.contains("attacker.invalid")),
            "attacker-controlled cache content must never be served in offline mode"
        );
        let embedded: crate::TrustedRoot =
            serde_json::from_slice(EMBEDDED_PRODUCTION_TRUSTED_ROOT).unwrap();
        assert_eq!(root.tlogs[0].base_url, embedded.tlogs[0].base_url);
    }
}
