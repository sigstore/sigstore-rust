//! File system cache: expiration and payload are published as one atomic record.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{default_cache_dir, CacheAdapter, CacheKey, Result};

fn url_to_dirname(url: &str) -> String {
    let mut result = String::new();
    for byte in url.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                result.push(byte as char)
            }
            _ => result.push_str(&format!("%{byte:02X}")),
        }
    }
    result
}

#[derive(Serialize, Deserialize)]
struct CacheRecord {
    expires_at: Timestamp,
    data: Vec<u8>,
}

/// File system cache with atomic replacement of expiration and payload.
///
/// Each key maps to a single `.entry` JSON record. Legacy `.cache`/`.meta`
/// pairs are ignored, since they cannot guarantee matching generations.
/// Expired records remain on disk until replaced or explicitly cleared: a
/// reader must not unlink a concurrent writer's replacement.
#[derive(Debug, Clone)]
pub struct FileSystemCache {
    cache_dir: PathBuf,
}

pub const SIGSTORE_PRODUCTION_URL: &str = "https://sigstore.dev";
pub const SIGSTORE_STAGING_URL: &str = "https://sigstage.dev";

impl FileSystemCache {
    /// Use a directory dedicated to one Sigstore instance.
    pub fn new(cache_dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
        })
    }

    /// Use the default cache directory for the production instance.
    pub fn default_location() -> Result<Self> {
        Self::production()
    }

    /// Namespace cache records by instance URL.
    pub fn for_instance(base_url: &str) -> Result<Self> {
        // The prefix also keeps values like ".." from becoming parent paths.
        Self::new(default_cache_dir()?.join(format!("instance-{}", url_to_dirname(base_url))))
    }

    pub fn production() -> Result<Self> {
        Self::for_instance(SIGSTORE_PRODUCTION_URL)
    }

    pub fn staging() -> Result<Self> {
        Self::for_instance(SIGSTORE_STAGING_URL)
    }

    fn cache_path(&self, key: CacheKey) -> PathBuf {
        self.cache_dir.join(format!("{}.entry", key.as_str()))
    }
}

impl CacheAdapter for FileSystemCache {
    fn get(&self, key: CacheKey) -> crate::CacheGetFuture<'_> {
        Box::pin(async move {
            match fs::read(self.cache_path(key)).await {
                Ok(bytes) => {
                    let record: CacheRecord = serde_json::from_slice(&bytes)?;
                    Ok((Timestamp::now() < record.expires_at).then_some(record.data))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn set(&self, key: CacheKey, value: &[u8], ttl: Duration) -> crate::CacheOpFuture<'_> {
        let data = value.to_vec();
        Box::pin(async move {
            let ttl = SignedDuration::try_from(ttl).map_err(|e| crate::Error::Io(e.to_string()))?;
            let expires_at = Timestamp::now()
                .checked_add(ttl)
                .map_err(|e| crate::Error::Io(e.to_string()))?;
            let bytes = serde_json::to_vec(&CacheRecord { expires_at, data })?;
            let dir = self.cache_dir.clone();
            let path = self.cache_path(key);
            tokio::task::spawn_blocking(move || -> Result<()> {
                std::fs::create_dir_all(&dir)?;
                let mut temp = tempfile::NamedTempFile::new_in(dir)?;
                temp.write_all(&bytes)?;
                let mut retries = 0;
                loop {
                    match temp.persist(&path) {
                        Ok(_) => break,
                        // Windows can temporarily deny replacement while a reader
                        // holds the previous generation open. Keep the old record
                        // intact and retry; never delete it before publishing.
                        Err(error)
                            if cfg!(windows)
                                && matches!(error.error.raw_os_error(), Some(5 | 32))
                                && retries < 10 =>
                        {
                            temp = error.file;
                            retries += 1;
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => return Err(error.error.into()),
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| crate::Error::Io(e.to_string()))?
        })
    }

    fn remove(&self, key: CacheKey) -> crate::CacheOpFuture<'_> {
        Box::pin(async move {
            match fs::remove_file(self.cache_path(key)).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn clear(&self) -> crate::CacheOpFuture<'_> {
        Box::pin(async move {
            let mut entries = match fs::read_dir(&self.cache_dir).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("entry" | "cache" | "meta")
                ) {
                    match fs::remove_file(path).await {
                        Ok(()) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn atomic_records_do_not_mix_payloads_and_expiration() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FileSystemCache::new(dir.path()).unwrap();
        let key = CacheKey::RekorPublicKey;
        assert!(cache.get(key).await.unwrap().is_none());
        cache
            .set(key, b"fresh", Duration::from_secs(3600))
            .await
            .unwrap();
        assert_eq!(cache.get(key).await.unwrap().unwrap(), b"fresh");
        cache.set(key, b"expired", Duration::ZERO).await.unwrap();
        assert!(cache.get(key).await.unwrap().is_none());
        // An uncommitted replacement cannot renew the expired generation.
        fs::write(dir.path().join("unfinished.tmp"), b"partial new record")
            .await
            .unwrap();
        assert!(cache.get(key).await.unwrap().is_none());
        let writer = async {
            for _ in 0..30 {
                cache
                    .set(key, b"fresh", Duration::from_secs(3600))
                    .await
                    .unwrap();
                cache.set(key, b"expired", Duration::ZERO).await.unwrap();
            }
        };
        let reader = async {
            for _ in 0..100 {
                if let Some(bytes) = cache.get(key).await.unwrap() {
                    assert_eq!(bytes, b"fresh");
                }
            }
        };
        tokio::join!(writer, reader);
        cache.remove(key).await.unwrap();
        assert!(cache.get(key).await.unwrap().is_none());
        cache.clear().await.unwrap();
    }

    #[test]
    fn instances_are_namespaced() {
        assert_ne!(
            FileSystemCache::production().unwrap().cache_dir,
            FileSystemCache::staging().unwrap().cache_dir
        );
        assert_eq!(
            FileSystemCache::default_location().unwrap().cache_dir,
            FileSystemCache::production().unwrap().cache_dir
        );
        assert_eq!(
            url_to_dirname("https://example.com"),
            "https%3A%2F%2Fexample.com"
        );
        assert_eq!(
            FileSystemCache::for_instance("..")
                .unwrap()
                .cache_dir
                .file_name()
                .unwrap(),
            "instance-.."
        );
    }
}
