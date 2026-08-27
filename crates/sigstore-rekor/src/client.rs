//! Rekor client for transparency log operations

use crate::body::RekorEntryBody;
use crate::entry::{
    DsseEntry, HashedRekord, HashedRekordV2, LogEntry, LogEntryResponse, LogInfo, RekorApiVersion,
    SearchIndex,
};
use crate::error::{Error, Result};
use sigstore_types::{Checkpoint, TransparencyLogEntry};
use std::num::NonZeroU8;
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Raw hash tile returned by Rekor v2's C2SP tile endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorV2Tile {
    pub level: u32,
    pub index: u64,
    pub width: Option<NonZeroU8>,
    pub bytes: Vec<u8>,
}

/// Raw entry bundle returned by Rekor v2's C2SP tile endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorV2EntryBundle {
    pub index: u64,
    pub width: Option<NonZeroU8>,
    pub bytes: Vec<u8>,
}

#[cfg(feature = "cache")]
use sigstore_cache::{CacheAdapter, CacheKey};
#[cfg(feature = "cache")]
use std::sync::Arc;

fn build_http_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("HTTP client configuration is valid")
}

/// A client for the Rekor v1 REST API.
///
/// For tile-based Rekor v2 logs, use [`RekorV2Client`].
pub struct RekorClient {
    /// Base URL of the Rekor instance
    url: String,
    /// HTTP client
    client: reqwest::Client,
    /// Optional cache adapter
    #[cfg(feature = "cache")]
    cache: Option<Arc<dyn CacheAdapter>>,
}

impl RekorClient {
    /// Create a new Rekor v1 client
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_string(),
            client: build_http_client(DEFAULT_TIMEOUT),
            #[cfg(feature = "cache")]
            cache: None,
        }
    }

    /// Create a client for the public Sigstore Rekor v1 instance.
    pub fn public() -> Self {
        Self::new(RekorApiVersion::V1.default_url())
    }

    /// Create a client for the Sigstore staging Rekor v1 instance.
    pub fn staging() -> Self {
        Self::new(RekorApiVersion::V1.default_staging_url())
    }

    /// Create a builder for configuring the client
    pub fn builder(url: impl Into<String>) -> RekorClientBuilder {
        RekorClientBuilder::new(url)
    }

    /// Get log info (tree size, root hash, etc.)
    ///
    /// With the `cache` feature enabled and a cache configured, this will
    /// cache the log info with the default TTL (1 hour).
    pub async fn get_log_info(&self) -> Result<LogInfo> {
        #[cfg(feature = "cache")]
        if let Some(ref cache) = self.cache {
            if let Ok(Some(cached)) = cache.get(CacheKey::RekorLogInfo).await {
                if let Ok(info) = serde_json::from_slice(&cached) {
                    return Ok(info);
                }
            }
        }

        let info = self.fetch_log_info().await?;

        #[cfg(feature = "cache")]
        if let Some(ref cache) = self.cache {
            if let Ok(json) = serde_json::to_vec(&info) {
                let _ = cache
                    .set(
                        CacheKey::RekorLogInfo,
                        &json,
                        CacheKey::RekorLogInfo.default_ttl(),
                    )
                    .await;
            }
        }

        Ok(info)
    }

    /// Fetch log info from the API (bypassing cache)
    async fn fetch_log_info(&self) -> Result<LogInfo> {
        let url = format!("{}/api/v1/log", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get log info: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Get a log entry by UUID
    pub async fn get_entry_by_uuid(&self, uuid: &str) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries/{}", self.url, uuid);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get entry {}: {}",
                uuid,
                response.status()
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        // Extract the single entry from the response
        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Get a log entry by index
    pub async fn get_entry_by_index(&self, index: i64) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries?logIndex={}", self.url, index);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get entry at index {}: {}",
                index,
                response.status()
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Create a new log entry (V1)
    pub async fn create_entry(&self, entry: HashedRekord) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries", self.url);
        let response = self
            .client
            .post(&url)
            .json(&entry)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create entry: {} - {}",
                status, body
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Create a new DSSE log entry (V1)
    pub async fn create_dsse_entry(&self, entry: DsseEntry) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries", self.url);
        let response = self
            .client
            .post(&url)
            .json(&entry)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create DSSE entry: {} - {}",
                status, body
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Search the index for entries
    pub async fn search_index(&self, query: SearchIndex) -> Result<Vec<String>> {
        let url = format!("{}/api/v1/index/retrieve", self.url);
        let response = self
            .client
            .post(&url)
            .json(&query)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!("search failed: {}", response.status())));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Search by hash (hex encoded)
    pub async fn search_by_hash(&self, hash: &str) -> Result<Vec<String>> {
        self.search_index(SearchIndex {
            hash: Some(format!("sha256:{}", hash)),
            email: None,
            public_key: None,
        })
        .await
    }

    /// Get the public key of the log
    ///
    /// With the `cache` feature enabled and a cache configured, this will
    /// cache the public key with the default TTL (24 hours).
    pub async fn get_public_key(&self) -> Result<String> {
        #[cfg(feature = "cache")]
        if let Some(ref cache) = self.cache {
            if let Ok(Some(cached)) = cache.get(CacheKey::RekorPublicKey).await {
                if let Ok(key) = String::from_utf8(cached) {
                    return Ok(key);
                }
            }
        }

        let key = self.fetch_public_key().await?;

        #[cfg(feature = "cache")]
        if let Some(ref cache) = self.cache {
            let _ = cache
                .set(
                    CacheKey::RekorPublicKey,
                    key.as_bytes(),
                    CacheKey::RekorPublicKey.default_ttl(),
                )
                .await;
        }

        Ok(key)
    }

    /// Fetch public key from the API (bypassing cache)
    async fn fetch_public_key(&self) -> Result<String> {
        let url = format!("{}/api/v1/log/publicKey", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get public key: {}",
                response.status()
            )));
        }

        response
            .text()
            .await
            .map_err(|e| Error::Http(e.to_string()))
    }
}

/// A client for tile-based Rekor v2 logs.
///
/// Rekor v2 shares no endpoints with the v1 REST API: writes go through
/// `/api/v2/log/entries` and reads use the C2SP tlog-tiles endpoints
/// (checkpoint, hash tiles, and entry bundles). Use [`RekorClient`] for
/// Rekor v1 instances.
pub struct RekorV2Client {
    /// Base URL of the Rekor v2 log
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl RekorV2Client {
    /// Create a new Rekor v2 client with the default request timeout.
    pub fn new(url: impl Into<String>) -> Self {
        Self::new_with_timeout(url, DEFAULT_TIMEOUT)
    }

    /// Create a new Rekor v2 client with a custom HTTP request timeout.
    ///
    /// Rekor v2 writes wait for log inclusion; use at least 20 seconds.
    pub fn new_with_timeout(url: impl Into<String>, timeout: Duration) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_string(),
            client: build_http_client(timeout),
        }
    }

    /// Create a client for the public Sigstore Rekor v2 instance.
    pub fn public() -> Self {
        Self::new(RekorApiVersion::V2.default_url())
    }

    /// Create a client for the Sigstore staging Rekor v2 instance.
    pub fn staging() -> Self {
        Self::new(RekorApiVersion::V2.default_staging_url())
    }

    /// Create a Rekor v2 hashedrekord entry.
    ///
    /// Rekor v2 returns the protobuf `TransparencyLogEntry` JSON representation
    /// used directly by Sigstore bundles. No v1 compatibility conversion is
    /// performed.
    pub async fn create_entry(
        &self,
        entry_request: HashedRekordV2,
    ) -> Result<TransparencyLogEntry> {
        let url = format!("{}/api/v2/log/entries", self.url);
        let response = self
            .client
            .post(&url)
            .json(&entry_request)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create entry: {} - {}",
                status, body
            )));
        }

        let response_text = response
            .text()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let entry: TransparencyLogEntry = serde_json::from_str(&response_text)
            .map_err(|e| Error::InvalidResponse(format!("invalid v2 log entry JSON: {e}")))?;
        validate_v2_entry(&entry, &entry_request)?;
        Ok(entry)
    }

    /// Fetch and parse the latest C2SP signed checkpoint from a Rekor v2 log.
    ///
    /// Parsing does not authenticate the checkpoint signature. Consumers must
    /// verify it with a key from their trusted root before trusting its contents.
    pub async fn get_checkpoint(&self) -> Result<Checkpoint> {
        let bytes = self.get_bytes("checkpoint").await?;
        let text = String::from_utf8(bytes)
            .map_err(|e| Error::InvalidResponse(format!("checkpoint is not UTF-8: {e}")))?;
        Checkpoint::from_text(&text)
            .map_err(|e| Error::InvalidResponse(format!("invalid checkpoint: {e}")))
    }

    /// Fetch a full or partial Rekor v2 hash tile.
    pub async fn get_tile(
        &self,
        level: u32,
        index: u64,
        width: Option<NonZeroU8>,
    ) -> Result<RekorV2Tile> {
        let path = tile_path(index, width);
        let bytes = self.get_bytes(&format!("tile/{level}/{path}")).await?;
        Ok(RekorV2Tile {
            level,
            index,
            width,
            bytes,
        })
    }

    /// Fetch a full or partial Rekor v2 entry bundle.
    pub async fn get_entry_bundle(
        &self,
        index: u64,
        width: Option<NonZeroU8>,
    ) -> Result<RekorV2EntryBundle> {
        let path = tile_path(index, width);
        let bytes = self.get_bytes(&format!("tile/entries/{path}")).await?;
        Ok(RekorV2EntryBundle {
            index,
            width,
            bytes,
        })
    }

    async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}/api/v2/{path}", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to fetch Rekor v2 {path}: {}",
                response.status()
            )));
        }
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|e| Error::Http(e.to_string()))
    }
}

/// Builder for configuring a [`RekorClient`]
///
/// # Example
///
/// ```no_run
/// use sigstore_rekor::RekorClient;
///
/// // Without caching
/// let client = RekorClient::builder("https://rekor.sigstore.dev")
///     .build();
/// ```
///
/// With the `cache` feature enabled:
///
/// ```ignore
/// use sigstore_rekor::RekorClient;
/// use sigstore_cache::FileSystemCache;
///
/// let cache = FileSystemCache::default_location()?;
/// let client = RekorClient::builder("https://rekor.sigstore.dev")
///     .with_cache(cache)
///     .build();
/// ```
pub struct RekorClientBuilder {
    url: String,
    timeout: Duration,
    #[cfg(feature = "cache")]
    cache: Option<Arc<dyn CacheAdapter>>,
}

impl RekorClientBuilder {
    /// Create a new builder with the given URL
    pub fn new(url: impl Into<String>) -> Self {
        let url = url.into();
        Self {
            url: url.trim_end_matches('/').to_string(),
            timeout: DEFAULT_TIMEOUT,
            #[cfg(feature = "cache")]
            cache: None,
        }
    }

    /// Set the HTTP request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the cache adapter
    #[cfg(feature = "cache")]
    pub fn with_cache(mut self, cache: impl CacheAdapter + 'static) -> Self {
        self.cache = Some(Arc::new(cache));
        self
    }

    /// Set a shared cache adapter
    #[cfg(feature = "cache")]
    pub fn with_shared_cache(mut self, cache: Arc<dyn CacheAdapter>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Build the client
    pub fn build(self) -> RekorClient {
        RekorClient {
            url: self.url,
            client: build_http_client(self.timeout),
            #[cfg(feature = "cache")]
            cache: self.cache,
        }
    }
}

fn validate_v2_entry(entry: &TransparencyLogEntry, request: &HashedRekordV2) -> Result<()> {
    if entry.kind_version.kind != "hashedrekord" || entry.kind_version.version != "0.0.2" {
        return Err(Error::InvalidResponse(format!(
            "expected hashedrekord/0.0.2, received {}/{}",
            entry.kind_version.kind, entry.kind_version.version
        )));
    }
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )?;
    let RekorEntryBody::HashedRekordV002(body) = body else {
        return Err(Error::InvalidResponse(
            "Rekor v2 response body is not hashedrekord/0.0.2".to_string(),
        ));
    };
    let logged = body.spec.hashed_rekord_v002;
    let requested = &request.request;
    let verifier_matches = match (
        &logged.signature.verifier.x509_certificate,
        &logged.signature.verifier.public_key,
        &requested.signature.verifier.x509_certificate,
        &requested.signature.verifier.public_key,
    ) {
        (Some(logged), None, Some(requested), None) => logged.raw_bytes == requested.content,
        (None, Some(logged), None, Some(requested)) => logged.raw_bytes == requested.content,
        _ => false,
    };
    if logged.data.algorithm != sigstore_types::HashAlgorithm::Sha2256
        || logged.data.digest.as_slice() != requested.digest.as_bytes()
        || logged.signature.content != requested.signature.content
        || logged.signature.verifier.key_details != requested.signature.verifier.key_details
        || !verifier_matches
    {
        return Err(Error::InvalidResponse(
            "Rekor v2 response body does not match the submitted entry".to_string(),
        ));
    }

    if entry.integrated_time.is_some() {
        return Err(Error::InvalidResponse(
            "Rekor v2 response contains a nonzero integrated time".to_string(),
        ));
    }
    if entry.inclusion_promise.is_some() {
        return Err(Error::InvalidResponse(
            "Rekor v2 response contains an inclusion promise".to_string(),
        ));
    }
    let proof = entry.inclusion_proof.as_ref().ok_or_else(|| {
        Error::InvalidResponse("Rekor v2 response has no inclusion proof".to_string())
    })?;
    // proof.log_index, proof.tree_size, and proof.root_hash are unauthenticated
    // duplicates in Rekor v2. Consumers use the top-level index and signed
    // checkpoint values instead.
    if proof.checkpoint.is_empty() {
        return Err(Error::InvalidResponse(
            "Rekor v2 response has an empty checkpoint".to_string(),
        ));
    }
    Ok(())
}

/// Encode a tile index per C2SP tlog-tiles: base-1000 groups, each
/// zero-padded to 3 digits, all but the last prefixed with `x`
/// (e.g. 1234067 -> `x001/x234/067`).
fn tile_path(index: u64, width: Option<NonZeroU8>) -> String {
    let mut groups = vec![format!("{:03}", index % 1000)];
    let mut remaining = index / 1000;
    while remaining > 0 {
        groups.insert(0, format!("x{:03}", remaining % 1000));
        remaining /= 1000;
    }
    let mut path = groups.join("/");
    if let Some(width) = width {
        path.push_str(&format!(".p/{width}"));
    }
    path
}

/// Convenience function to get log info from the public Rekor instance
pub async fn get_public_log_info() -> Result<LogInfo> {
    RekorClient::public().get_log_info().await
}

#[cfg(test)]
mod tests {
    use super::tile_path;
    use std::num::NonZeroU8;

    #[test]
    fn tile_path_zero_pads_every_group() {
        // Groups with fewer than 3 significant digits must still be
        // zero-padded; 1234067 -> x001/x234/067 is the C2SP spec example.
        for (index, expected) in [
            (0, "000"),
            (1, "001"),
            (999, "999"),
            (1_000, "x001/000"),
            (1_234, "x001/234"),
            (12_345, "x012/345"),
            (123_456, "x123/456"),
            (999_999, "x999/999"),
            (1_000_000, "x001/x000/000"),
            (1_234_067, "x001/x234/067"),
            (u64::MAX, "x018/x446/x744/x073/x709/x551/615"),
        ] {
            assert_eq!(tile_path(index, None), expected, "index {index}");
        }
    }

    #[test]
    fn tile_path_appends_partial_tile_width() {
        assert_eq!(tile_path(1_234, NonZeroU8::new(7)), "x001/234.p/7");
        assert_eq!(tile_path(5, NonZeroU8::new(255)), "005.p/255");
    }
}
