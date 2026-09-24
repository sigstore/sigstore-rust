//! No-op cache implementation (caching disabled)

use std::time::Duration;

#[cfg(test)]
use crate::CacheResource;
use crate::{CacheAdapter, CacheKey};

/// A no-op cache that doesn't store anything
///
/// This is useful when caching needs to be disabled, for testing,
/// or for environments where caching is not desired.
///
/// # Example
///
/// ```
/// use sigstore_cache::{NoCache, CacheAdapter, CacheKey, CacheResource};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), sigstore_cache::Error> {
/// let cache = NoCache;
///
/// // Set does nothing
/// cache.set(&CacheKey::new(CacheResource::RekorPublicKey, "https://service.example"), b"data", Duration::from_secs(3600)).await?;
///
/// // Get always returns None
/// assert!(cache.get(&CacheKey::new(CacheResource::RekorPublicKey, "https://service.example")).await?.is_none());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCache;

impl CacheAdapter for NoCache {
    fn get(&self, _key: &CacheKey) -> crate::CacheGetFuture<'_> {
        Box::pin(async { Ok(None) })
    }

    fn set(&self, _key: &CacheKey, _value: &[u8], _ttl: Duration) -> crate::CacheOpFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn remove(&self, _key: &CacheKey) -> crate::CacheOpFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn clear(&self) -> crate::CacheOpFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_cache() {
        let cache = NoCache;

        // Set does nothing
        cache
            .set(
                &CacheKey::new(CacheResource::RekorPublicKey, "https://service.example"),
                b"data",
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Get always returns None
        assert!(cache
            .get(&CacheKey::new(
                CacheResource::RekorPublicKey,
                "https://service.example"
            ))
            .await
            .unwrap()
            .is_none());

        // Remove and clear are no-ops
        cache
            .remove(&CacheKey::new(
                CacheResource::RekorPublicKey,
                "https://service.example",
            ))
            .await
            .unwrap();
        cache.clear().await.unwrap();
    }
}
