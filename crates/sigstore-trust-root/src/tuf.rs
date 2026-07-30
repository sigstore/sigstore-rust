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

/// Configuration for TUF client
#[derive(Debug, Clone)]
pub struct TufConfig {
    /// Base URL for the TUF repository
    pub url: String,
    /// Path to local cache directory (optional, derived from URL if not set)
    pub cache_dir: Option<PathBuf>,
    /// Whether to disable local caching
    pub disable_cache: bool,
    /// Whether to prohibit network requests and use only the verified cache.
    pub offline: bool,
    /// Custom TUF root.json for bootstrapping trust (None = use embedded for known URLs)
    root_json: Option<Vec<u8>>,
}

impl Default for TufConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_TUF_URL.to_string(),
            cache_dir: None,
            disable_cache: false,
            offline: false,
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
            offline: false,
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

    /// Enable offline mode (no network; verified cache only).
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
    /// Metadata expiry is evaluated at the validation time passed to the load
    /// operation. The default APIs use the current time; the `*_at` APIs let
    /// applications deliberately validate at another time.
    ///
    /// A missing or invalid cache is always an error. Embedded trust material
    /// is a separate, explicit source available through
    /// [`TrustedRoot::from_embedded`](crate::TrustedRoot::from_embedded).
    pub fn offline(mut self) -> Self {
        self.offline = true;
        self
    }
}

/// Internal TUF client for fetching targets.
struct TufClient {
    config: TufConfig,
}

impl TufClient {
    fn new(config: TufConfig) -> Self {
        Self { config }
    }

    #[cfg(test)]
    async fn fetch_target(&self, target_name: &str) -> Result<Vec<u8>> {
        self.fetch_target_at(target_name, jiff::Timestamp::now())
            .await
    }

    /// Fetch one target, evaluating all metadata expiry at `validation_time`.
    async fn fetch_target_at(
        &self,
        target_name: &str,
        validation_time: jiff::Timestamp,
    ) -> Result<Vec<u8>> {
        let mut results = self
            .fetch_targets_at(&[target_name], validation_time)
            .await?;
        Ok(results.remove(0))
    }

    /// Fetch multiple targets in one TUF session, using one validation time for
    /// the complete metadata refresh and every target lookup.
    async fn fetch_targets_at(
        &self,
        target_names: &[&str],
        validation_time: jiff::Timestamp,
    ) -> Result<Vec<Vec<u8>>> {
        let mut updater = if self.config.offline {
            self.build_offline_updater(validation_time).await?
        } else {
            self.build_updater(validation_time).await?
        };
        let mut results = Vec::with_capacity(target_names.len());
        for name in target_names {
            let bytes = updater
                .get_target(name, validation_time)
                .await
                .map_err(|e| {
                    let context = if self.config.offline {
                        "offline verification of cached target"
                    } else {
                        "failed to fetch target"
                    };
                    Error::Tuf(format!("{context} '{name}': {e}"))
                })?;
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
    async fn build_updater(&self, validation_time: jiff::Timestamp) -> Result<Updater> {
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
            .refresh(validation_time)
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
    async fn build_offline_updater(&self, validation_time: jiff::Timestamp) -> Result<Updater> {
        if self.config.disable_cache {
            return Err(Error::Tuf(
                "offline mode requires a local TUF cache, but caching is disabled".into(),
            ));
        }
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
            .refresh(validation_time)
            .await
            .map_err(|e| Error::Tuf(format!("offline verification of cached metadata: {e}")))?;
        Ok(updater)
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
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // No network: serve the fully verified local TUF repository.
    /// let config = TufConfig::production().offline();
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf(config: TufConfig) -> Result<Self> {
        Self::from_tuf_at(config, jiff::Timestamp::now()).await
    }

    /// Fetch the trusted root while evaluating TUF metadata expiry at
    /// `validation_time`.
    ///
    /// Supplying an earlier time lets an application deliberately use a cache
    /// that was valid at its last successful refresh. This weakens TUF's
    /// freeze-attack protection and the time must come from application-owned
    /// state, not cache metadata or filesystem timestamps.
    pub async fn from_tuf_at(config: TufConfig, validation_time: jiff::Timestamp) -> Result<Self> {
        let client = TufClient::new(config);
        let bytes = client
            .fetch_target_at(TRUSTED_ROOT_TARGET, validation_time)
            .await?;
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
    /// use sigstore_trust_root::{SigningConfig, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // Use offline mode: verified cache only, error otherwise
    /// let config = TufConfig::production().offline();
    /// let signing_config = SigningConfig::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf(config: TufConfig) -> Result<Self> {
        Self::from_tuf_at(config, jiff::Timestamp::now()).await
    }

    /// Fetch the signing configuration while evaluating TUF metadata expiry
    /// at `validation_time`. See [`TrustedRoot::from_tuf_at`] for the security
    /// implications of supplying a historical time.
    pub async fn from_tuf_at(config: TufConfig, validation_time: jiff::Timestamp) -> Result<Self> {
        let client = TufClient::new(config);
        let bytes = client
            .fetch_target_at(SIGNING_CONFIG_TARGET, validation_time)
            .await?;
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
    fetch_trust_material_at(config, jiff::Timestamp::now()).await
}

/// Fetch both trust-material targets while evaluating TUF metadata expiry at
/// `validation_time`. See [`TrustedRoot::from_tuf_at`] for the security
/// implications of supplying a historical time.
pub async fn fetch_trust_material_at(
    config: TufConfig,
    validation_time: jiff::Timestamp,
) -> Result<(TrustedRoot, SigningConfig)> {
    let client = TufClient::new(config);
    let results = client
        .fetch_targets_at(
            &[TRUSTED_ROOT_TARGET, SIGNING_CONFIG_TARGET],
            validation_time,
        )
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
        assert!(!config.offline);
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
            .offline();
        assert!(config.disable_cache);
        assert!(config.offline);
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
            offline: false,
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

    #[tokio::test]
    async fn test_offline_mode_fails_for_unknown_target() {
        let config = TufConfig::production().offline().without_cache();
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
    async fn test_custom_url_offline_fails_without_cache() {
        // Offline mode requires a cache for every repository.
        let config = TufConfig::custom("https://custom.tuf/")
            .with_root(b"root")
            .offline()
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
        // Success proves the bytes came from the verified cache.
        let tmp = tempfile::tempdir().unwrap();
        let content = b"verified offline target content";
        let root = signed_cache::write(tmp.path(), content, signed_cache::FAR_FUTURE);

        let config = TufConfig::custom("https://offline.example/")
            .with_root(&root)
            .offline()
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap();
        assert_eq!(bytes, content);
    }

    #[tokio::test]
    async fn test_offline_mode_rejects_tampered_cached_target() {
        // Valid signed metadata, but the cached target bytes were swapped
        // after the fact: the hash check must reject them and the attacker
        // bytes must never be returned.
        let tmp = tempfile::tempdir().unwrap();
        let root = signed_cache::write(tmp.path(), b"legitimate", signed_cache::FAR_FUTURE);
        std::fs::write(
            tmp.path().join("targets").join(TRUSTED_ROOT_TARGET),
            b"attacker-controlled bytes",
        )
        .unwrap();

        let config = TufConfig::custom("https://offline.example/")
            .with_root(&root)
            .offline()
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
        // (fail-secure): offline mode errors — with a reason naming the
        // expiry — instead of serving a cache whose freshness can no longer
        // be established.
        let tmp = tempfile::tempdir().unwrap();
        let root = signed_cache::write(tmp.path(), b"stale", signed_cache::IN_THE_PAST);

        let config = TufConfig::custom("https://offline.example/")
            .with_root(&root)
            .offline()
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("offline verification of cached metadata"));
        assert!(msg.contains("expired"));
    }

    #[tokio::test]
    async fn test_offline_mode_can_validate_at_an_application_selected_time() {
        let tmp = tempfile::tempdir().unwrap();
        let content = b"valid at the application's last refresh";
        let root = signed_cache::write(tmp.path(), content, signed_cache::IN_THE_PAST);
        let validation_time: jiff::Timestamp = "2000-01-01T00:00:00Z".parse().unwrap();

        let config = TufConfig::custom("https://offline.example/")
            .with_root(&root)
            .offline()
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let bytes = client
            .fetch_target_at(TRUSTED_ROOT_TARGET, validation_time)
            .await
            .unwrap();
        assert_eq!(bytes, content);
    }

    #[tokio::test]
    async fn test_offline_mode_ignores_bare_cached_target_without_metadata() {
        // A bare file dropped into `targets/` without any signed metadata
        // must not be served.
        let tmp = tempfile::tempdir().unwrap();
        let targets_dir = tmp.path().join("targets");
        tokio::fs::create_dir_all(&targets_dir).await.unwrap();
        tokio::fs::write(targets_dir.join(TRUSTED_ROOT_TARGET), b"unauthenticated")
            .await
            .unwrap();

        let config = TufConfig::production()
            .offline()
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("offline verification of cached metadata"));
    }

    #[tokio::test]
    async fn test_offline_mode_errors_without_cache() {
        // An absent cache is an error even for known instances that also
        // provide separately accessible embedded trust material.
        let tmp = tempfile::tempdir().unwrap();
        let config = TufConfig::production()
            .offline()
            .with_cache_dir(tmp.path().to_path_buf());
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("offline verification of cached metadata"));
    }

    #[tokio::test]
    async fn test_offline_mode_errors_when_caching_disabled() {
        let config = TufConfig::production().offline().without_cache();
        let client = TufClient::new(config);

        let err = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap_err();
        assert!(err.to_string().contains("caching is disabled"));
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
            serde_json::from_str(crate::SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
        doctored["tlogs"][0]["baseUrl"] = "https://attacker.invalid/rekor".into();
        tokio::fs::write(
            targets_dir.join(TRUSTED_ROOT_TARGET),
            serde_json::to_vec(&doctored).unwrap(),
        )
        .await
        .unwrap();

        let config = TufConfig::production()
            .offline()
            .with_cache_dir(tmp.path().to_path_buf());
        let err = crate::TrustedRoot::from_tuf(config).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("offline verification of cached metadata"));
    }
}
