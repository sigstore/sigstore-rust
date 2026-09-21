//! In-memory cache implementation with TTL support

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::{CacheAdapter, CacheKey};

/// A cached entry with expiration time
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached data
    data: Vec<u8>,
    /// When this entry expires
    expires_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// In-memory cache with TTL support
///
/// This cache stores values in memory with automatic expiration.
/// It's fast but not persistent across process restarts.
///
/// Thread-safe and suitable for use across async tasks.
///
/// # Example
///
/// ```
/// use sigstore_cache::{InMemoryCache, CacheAdapter, CacheKey};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), sigstore_cache::Error> {
/// let cache = InMemoryCache::new();
///
/// // Cache a value for 1 hour
/// cache.set(
///     CacheKey::RekorPublicKey,
///     b"public-key-data",
///     Duration::from_secs(3600)
/// ).await?;
///
/// // Retrieve it
/// if let Some(data) = cache.get(CacheKey::RekorPublicKey).await? {
///     println!("Got {} bytes", data.len());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct InMemoryCache {
    /// The actual cache storage
    entries: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCache {
    /// Create a new empty in-memory cache
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Remove expired entries from the cache
    ///
    /// This is called automatically on `get` operations, but can be
    /// called manually to proactively clean up memory.
    pub async fn cleanup_expired(&self) {
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| !entry.is_expired());
    }

    /// Get the number of entries in the cache (including expired ones)
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if the cache is empty
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

impl CacheAdapter for InMemoryCache {
    fn get(&self, key: CacheKey) -> crate::CacheGetFuture<'_> {
        Box::pin(async move {
            // Check expiration and remove the entry under the same lock.
            let mut entries = self.entries.write().await;

            match entries.get(&key) {
                Some(entry) if !entry.is_expired() => Ok(Some(entry.data.clone())),
                Some(_) => {
                    // Entry exists but is expired - clean it up
                    entries.remove(&key);
                    Ok(None)
                }
                None => Ok(None),
            }
        })
    }

    fn set(&self, key: CacheKey, value: &[u8], ttl: Duration) -> crate::CacheOpFuture<'_> {
        let value = value.to_vec();
        Box::pin(async move {
            let entry = CacheEntry {
                data: value,
                expires_at: Instant::now()
                    .checked_add(ttl)
                    .ok_or_else(|| crate::Error::Io("cache TTL exceeds supported range".into()))?,
            };

            let mut entries = self.entries.write().await;
            entries.insert(key, entry);

            Ok(())
        })
    }

    fn remove(&self, key: CacheKey) -> crate::CacheOpFuture<'_> {
        Box::pin(async move {
            let mut entries = self.entries.write().await;
            entries.remove(&key);
            Ok(())
        })
    }

    fn clear(&self) -> crate::CacheOpFuture<'_> {
        Box::pin(async move {
            let mut entries = self.entries.write().await;
            entries.clear();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_cache_roundtrip() {
        let cache = InMemoryCache::new();
        let key = CacheKey::RekorPublicKey;
        let value = b"test-data";

        // Initially empty
        assert!(cache.get(key).await.unwrap().is_none());

        // Set and get
        cache
            .set(key, value, Duration::from_secs(3600))
            .await
            .unwrap();
        let retrieved = cache.get(key).await.unwrap().unwrap();
        assert_eq!(retrieved, value);

        // Remove
        cache.remove(key).await.unwrap();
        assert!(cache.get(key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_cache_expiration() {
        let cache = InMemoryCache::new();
        let key = CacheKey::FulcioConfiguration;
        let value = b"test-config";

        // Set with very short TTL
        cache
            .set(key, value, Duration::from_millis(10))
            .await
            .unwrap();

        // Should exist immediately
        assert!(cache.get(key).await.unwrap().is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Should be expired now
        assert!(cache.get(key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_cache_clear() {
        let cache = InMemoryCache::new();

        cache
            .set(CacheKey::RekorPublicKey, b"a", Duration::from_secs(3600))
            .await
            .unwrap();
        cache
            .set(CacheKey::FulcioTrustBundle, b"b", Duration::from_secs(3600))
            .await
            .unwrap();

        assert_eq!(cache.len().await, 2);

        cache.clear().await.unwrap();

        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_memory_cache_cleanup_expired() {
        let cache = InMemoryCache::new();

        // Add some entries with different TTLs
        cache
            .set(
                CacheKey::RekorPublicKey,
                b"long-lived",
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        cache
            .set(
                CacheKey::FulcioTrustBundle,
                b"short-lived",
                Duration::from_millis(10),
            )
            .await
            .unwrap();

        assert_eq!(cache.len().await, 2);

        // Wait for short-lived to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Cleanup
        cache.cleanup_expired().await;

        // Only long-lived should remain
        assert_eq!(cache.len().await, 1);
        assert!(cache.get(CacheKey::RekorPublicKey).await.unwrap().is_some());
        assert!(cache
            .get(CacheKey::FulcioTrustBundle)
            .await
            .unwrap()
            .is_none());
    }
}
