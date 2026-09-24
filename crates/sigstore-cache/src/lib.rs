//! Flexible caching support for Sigstore clients
//!
//! This crate provides a pluggable caching mechanism for Sigstore operations.
//! It allows users to choose between different caching strategies:
//!
//! - [`FileSystemCache`]: Persistent cache stored on disk (default location or custom)
//! - [`InMemoryCache`]: Fast in-process cache with TTL support
//! - [`NoCache`]: Disabled caching (for testing or when caching is not desired)
//!
//! # Example
//!
//! ```no_run
//! use sigstore_cache::{CacheAdapter, CacheKey, CacheResource, FileSystemCache};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), sigstore_cache::Error> {
//! // Use default cache location (~/.cache/sigstore-rust/)
//! let cache = FileSystemCache::default_location()?;
//!
//! // Or specify a custom directory
//! let cache = FileSystemCache::new("/tmp/my-cache")?;
//!
//! // Keys are scoped to the service they belong to
//! let key = CacheKey::new(CacheResource::RekorPublicKey, "https://rekor.sigstore.dev");
//!
//! // Store a value with TTL
//! cache.set(&key, b"public-key-data", Duration::from_secs(86400)).await?;
//!
//! // Retrieve the value
//! if let Some(data) = cache.get(&key).await? {
//!     println!("Got cached data: {} bytes", data.len());
//! }
//! # Ok(())
//! # }
//! ```

mod error;
mod filesystem;
mod memory;
mod noop;

pub use error::{Error, Result};
pub use filesystem::{FileSystemCache, SIGSTORE_PRODUCTION_URL, SIGSTORE_STAGING_URL};
pub use memory::InMemoryCache;
pub use noop::NoCache;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Future type for cache get operations
pub type CacheGetFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + 'a>>;

/// Future type for cache set/remove/clear operations
pub type CacheOpFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// The kind of Sigstore resource being cached
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CacheResource {
    /// Rekor transparency log public key
    RekorPublicKey,
    /// Rekor log info (tree size, root hash)
    RekorLogInfo,
    /// Fulcio trust bundle (CA certificates)
    FulcioTrustBundle,
    /// Fulcio OIDC configuration
    FulcioConfiguration,
    /// Trusted root from TUF
    TrustedRoot,
}

impl CacheResource {
    /// Get the string representation used for file names
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheResource::RekorPublicKey => "rekor_public_key",
            CacheResource::RekorLogInfo => "rekor_log_info",
            CacheResource::FulcioTrustBundle => "fulcio_trust_bundle",
            CacheResource::FulcioConfiguration => "fulcio_configuration",
            CacheResource::TrustedRoot => "trusted_root",
        }
    }

    /// Get the recommended TTL for this resource
    pub fn default_ttl(&self) -> Duration {
        match self {
            // Keys/certs rotate infrequently
            CacheResource::RekorPublicKey => Duration::from_secs(24 * 60 * 60), // 24 hours
            CacheResource::FulcioTrustBundle => Duration::from_secs(24 * 60 * 60), // 24 hours
            CacheResource::TrustedRoot => Duration::from_secs(24 * 60 * 60),    // 24 hours
            // OIDC config is very stable
            CacheResource::FulcioConfiguration => Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            // Log info changes more frequently
            CacheResource::RekorLogInfo => Duration::from_secs(60 * 60), // 1 hour
        }
    }
}

/// Identifies one cached resource of one service.
///
/// The service URL is part of the key, so a cache shared by clients of
/// different Rekor logs or Fulcio instances never returns one service's key
/// material to a client of another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    resource: CacheResource,
    service: String,
}

impl CacheKey {
    /// Key `resource` for the service at `service_url`.
    ///
    /// Trailing slashes are ignored so that equivalent base URLs share entries.
    pub fn new(resource: CacheResource, service_url: &str) -> Self {
        Self {
            resource,
            service: service_url.trim_end_matches('/').to_string(),
        }
    }

    /// The kind of resource.
    pub fn resource(&self) -> CacheResource {
        self.resource
    }

    /// The service URL the resource belongs to.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The recommended TTL for this key's resource.
    pub fn default_ttl(&self) -> Duration {
        self.resource.default_ttl()
    }

    /// A file-system-safe name that is unique per resource and service.
    pub fn file_stem(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.service.as_bytes());
        let service: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        format!("{}-{service}", self.resource.as_str())
    }
}

/// Trait for cache adapters
///
/// This trait defines the interface for caching operations. Implementations
/// can provide different storage backends (filesystem, memory, etc.) while
/// maintaining the same API.
pub trait CacheAdapter: Send + Sync {
    /// Get a cached value by key
    ///
    /// Returns `Ok(Some(data))` if the key exists and hasn't expired,
    /// `Ok(None)` if the key doesn't exist or has expired,
    /// or `Err(...)` on I/O or other errors.
    fn get(&self, key: &CacheKey) -> CacheGetFuture<'_>;

    /// Set a cached value with a TTL
    ///
    /// The value will be considered expired after `ttl` has elapsed.
    fn set(&self, key: &CacheKey, value: &[u8], ttl: Duration) -> CacheOpFuture<'_>;

    /// Remove a cached value
    fn remove(&self, key: &CacheKey) -> CacheOpFuture<'_>;

    /// Clear all cached values
    fn clear(&self) -> CacheOpFuture<'_>;
}

/// Extension trait providing convenience methods for caching
pub trait CacheAdapterExt: CacheAdapter {
    /// Get a cached value, or compute and cache it if not present
    fn get_or_set<'a, F, Fut>(
        &'a self,
        key: CacheKey,
        ttl: Duration,
        compute: F,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>
    where
        F: FnOnce() -> Fut + Send + 'a,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'a,
    {
        Box::pin(async move {
            // Try to get from cache first
            if let Some(cached) = self.get(&key).await? {
                return Ok(cached);
            }

            // Compute the value
            let value = compute().await?;

            // Store in cache (ignore errors - caching is best-effort)
            let _ = self.set(&key, &value, ttl).await;

            Ok(value)
        })
    }

    /// Get a cached value using the key's default TTL for caching
    fn get_or_set_default<'a, F, Fut>(
        &'a self,
        key: CacheKey,
        compute: F,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>
    where
        F: FnOnce() -> Fut + Send + 'a,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'a,
    {
        let ttl = key.default_ttl();
        self.get_or_set(key, ttl, compute)
    }
}

// Implement CacheAdapterExt for all CacheAdapter implementations
impl<T: CacheAdapter + ?Sized> CacheAdapterExt for T {}

// Also implement CacheAdapter for Arc<T> where T: CacheAdapter
impl<T: CacheAdapter + ?Sized> CacheAdapter for Arc<T> {
    fn get(&self, key: &CacheKey) -> CacheGetFuture<'_> {
        (**self).get(key)
    }

    fn set(&self, key: &CacheKey, value: &[u8], ttl: Duration) -> CacheOpFuture<'_> {
        (**self).set(key, value, ttl)
    }

    fn remove(&self, key: &CacheKey) -> CacheOpFuture<'_> {
        (**self).remove(key)
    }

    fn clear(&self) -> CacheOpFuture<'_> {
        (**self).clear()
    }
}

// Implement CacheAdapter for Box<dyn CacheAdapter>
impl CacheAdapter for Box<dyn CacheAdapter> {
    fn get(&self, key: &CacheKey) -> CacheGetFuture<'_> {
        (**self).get(key)
    }

    fn set(&self, key: &CacheKey, value: &[u8], ttl: Duration) -> CacheOpFuture<'_> {
        (**self).set(key, value, ttl)
    }

    fn remove(&self, key: &CacheKey) -> CacheOpFuture<'_> {
        (**self).remove(key)
    }

    fn clear(&self) -> CacheOpFuture<'_> {
        (**self).clear()
    }
}

/// Get the default cache directory for sigstore-rust
///
/// This returns the platform-specific cache directory:
/// - Linux: `~/.cache/sigstore-rust/`
/// - macOS: `~/Library/Caches/dev.sigstore.sigstore-rust/`
/// - Windows: `C:\Users\<User>\AppData\Local\sigstore\sigstore-rust\cache\`
pub fn default_cache_dir() -> Result<std::path::PathBuf> {
    let project_dirs = directories::ProjectDirs::from("dev", "sigstore", "sigstore-rust")
        .ok_or_else(|| Error::Io("Could not determine cache directory".into()))?;
    Ok(project_dirs.cache_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_as_str() {
        assert_eq!(CacheResource::RekorPublicKey.as_str(), "rekor_public_key");
        assert_eq!(
            CacheResource::FulcioTrustBundle.as_str(),
            "fulcio_trust_bundle"
        );
    }

    #[test]
    fn test_cache_key_default_ttl() {
        // Just verify they return reasonable values
        assert!(CacheResource::RekorPublicKey.default_ttl().as_secs() > 0);
        assert!(CacheResource::FulcioConfiguration.default_ttl().as_secs() > 0);
    }
}
