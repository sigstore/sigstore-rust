//! Rekor client for transparency log operations

use crate::body::RekorEntryBody;
use crate::entry::{
    DsseEntry, HashedRekord, HashedRekordV2, LogEntry, LogEntryResponse, LogInfo, SearchIndex,
};
use crate::error::{Error, Result};
use serde::de::DeserializeOwned;
use sigstore_types::{
    Checkpoint, DerPublicKey, EntryUuid, KindVersion, LogIndex, Sha256Hash, TransparencyLogEntry,
    USER_AGENT,
};
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
use sigstore_cache::{CacheAdapter, CacheKey, CacheResource};
#[cfg(feature = "cache")]
use std::sync::Arc;

/// The client used when the caller does not supply one.
fn default_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| Error::Http(format!("failed to build HTTP client: {e}")))
}

/// Send a request and turn a non-success status into [`Error::Status`].
async fn send(request: reqwest::RequestBuilder, what: &str) -> Result<reqwest::Response> {
    let response = request
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    Err(Error::Status {
        status: status.as_u16(),
        message: if body.is_empty() {
            what.to_string()
        } else {
            format!("{what}: {body}")
        },
    })
}

/// Read a JSON response body, reporting malformed bodies as
/// [`Error::InvalidResponse`].
async fn read_json<T: DeserializeOwned>(response: reqwest::Response, what: &str) -> Result<T> {
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    serde_json::from_slice(&body).map_err(|e| Error::InvalidResponse(format!("{what}: {e}")))
}

/// Extract the single entry from a Rekor v1 `{uuid: entry}` response.
fn single_entry(entries: LogEntryResponse) -> Result<LogEntry> {
    let (uuid, mut entry) = entries
        .into_iter()
        .next()
        .ok_or_else(|| Error::InvalidResponse("empty log entry response".to_string()))?;
    entry.uuid = EntryUuid::new(uuid);
    Ok(entry)
}

/// A client for the Rekor v1 REST API.
///
/// For tile-based Rekor v2 logs, use [`RekorV2Client`].
#[derive(Clone)]
pub struct RekorClient {
    /// Base URL of the Rekor instance
    url: String,
    /// HTTP client
    client: reqwest::Client,
    /// Optional cache adapter
    #[cfg(feature = "cache")]
    cache: Option<Arc<dyn CacheAdapter>>,
}

impl std::fmt::Debug for RekorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekorClient")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl RekorClient {
    /// Create a Rekor v1 client with a default HTTP client (30-second
    /// timeout, `sigstore-rust/<version>` user agent).
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Self::builder(url).build()
    }

    /// The Rekor base URL this client talks to.
    pub fn url(&self) -> &str {
        &self.url
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
            if let Ok(Some(cached)) = cache
                .get(&CacheKey::new(CacheResource::RekorLogInfo, &self.url))
                .await
            {
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
                        &CacheKey::new(CacheResource::RekorLogInfo, &self.url),
                        &json,
                        CacheResource::RekorLogInfo.default_ttl(),
                    )
                    .await;
            }
        }

        Ok(info)
    }

    /// Fetch log info from the API (bypassing cache)
    async fn fetch_log_info(&self) -> Result<LogInfo> {
        let url = format!("{}/api/v1/log", self.url);
        let response = send(self.client.get(&url), "failed to get log info").await?;
        read_json(response, "log info").await
    }

    /// Get a log entry by UUID
    pub async fn get_entry_by_uuid(&self, uuid: &EntryUuid) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries/{}", self.url, uuid);
        let response = send(
            self.client.get(&url),
            &format!("failed to get entry {uuid}"),
        )
        .await?;
        single_entry(read_json(response, "log entry").await?)
    }

    /// Get a log entry by index
    pub async fn get_entry_by_index(&self, index: LogIndex) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries?logIndex={}", self.url, index);
        let response = send(
            self.client.get(&url),
            &format!("failed to get entry at index {index}"),
        )
        .await?;
        single_entry(read_json(response, "log entry").await?)
    }

    /// Create a new log entry (V1)
    pub async fn create_entry(&self, entry: HashedRekord) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries", self.url);
        let response = send(
            self.client.post(&url).json(&entry),
            "failed to create entry",
        )
        .await?;
        single_entry(read_json(response, "log entry").await?)
    }

    /// Create a new DSSE log entry (V1)
    pub async fn create_dsse_entry(&self, entry: DsseEntry) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries", self.url);
        let response = send(
            self.client.post(&url).json(&entry),
            "failed to create DSSE entry",
        )
        .await?;
        single_entry(read_json(response, "log entry").await?)
    }

    /// Search the index for entries
    pub async fn search_index(&self, query: SearchIndex) -> Result<Vec<EntryUuid>> {
        let url = format!("{}/api/v1/index/retrieve", self.url);
        let response = send(self.client.post(&url).json(&query), "search failed").await?;
        read_json(response, "search results").await
    }

    /// Search for entries of an artifact by its SHA-256 digest
    pub async fn search_by_hash(&self, hash: &Sha256Hash) -> Result<Vec<EntryUuid>> {
        self.search_index(SearchIndex {
            hash: Some(format!("sha256:{}", hash.to_hex())),
            email: None,
            public_key: None,
        })
        .await
    }

    /// Get the public key of the log
    ///
    /// With the `cache` feature enabled and a cache configured, this will
    /// cache the public key with the default TTL (24 hours).
    pub async fn get_public_key(&self) -> Result<DerPublicKey> {
        #[cfg(feature = "cache")]
        if let Some(ref cache) = self.cache {
            if let Ok(Some(cached)) = cache
                .get(&CacheKey::new(CacheResource::RekorPublicKey, &self.url))
                .await
            {
                if let Some(key) = String::from_utf8(cached)
                    .ok()
                    .and_then(|pem| DerPublicKey::from_pem(&pem).ok())
                {
                    return Ok(key);
                }
            }
        }

        let pem = self.fetch_public_key().await?;
        let key = DerPublicKey::from_pem(&pem)
            .map_err(|e| Error::InvalidResponse(format!("log public key: {e}")))?;

        #[cfg(feature = "cache")]
        if let Some(ref cache) = self.cache {
            let _ = cache
                .set(
                    &CacheKey::new(CacheResource::RekorPublicKey, &self.url),
                    pem.as_bytes(),
                    CacheResource::RekorPublicKey.default_ttl(),
                )
                .await;
        }

        Ok(key)
    }

    /// Fetch public key from the API (bypassing cache)
    async fn fetch_public_key(&self) -> Result<String> {
        let url = format!("{}/api/v1/log/publicKey", self.url);
        let response = send(self.client.get(&url), "failed to get public key").await?;
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
#[derive(Debug, Clone)]
pub struct RekorV2Client {
    /// Base URL of the Rekor v2 log
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl RekorV2Client {
    /// Create a Rekor v2 client with a default HTTP client (30-second
    /// timeout, `sigstore-rust/<version>` user agent).
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Ok(Self::with_http_client(url, default_http_client()?))
    }

    /// Create a Rekor v2 client that uses a caller-configured HTTP client.
    ///
    /// Rekor v2 writes wait for log inclusion; allow at least 20 seconds.
    pub fn with_http_client(url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_string(),
            client,
        }
    }

    /// The Rekor v2 log URL this client talks to.
    pub fn url(&self) -> &str {
        &self.url
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
        let response = send(
            self.client.post(&url).json(&entry_request),
            "failed to create entry",
        )
        .await?;
        let entry: TransparencyLogEntry = read_json(response, "v2 log entry").await?;
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
        let response = send(
            self.client.get(&url),
            &format!("failed to fetch Rekor v2 {path}"),
        )
        .await?;
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
/// use sigstore_rekor::{reqwest, RekorClient};
/// use std::time::Duration;
///
/// let http = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .build()?;
/// let client = RekorClient::builder("https://rekor.sigstore.dev")
///     .with_http_client(http)
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
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
///     .build()?;
/// ```
#[must_use]
pub struct RekorClientBuilder {
    url: String,
    http_client: Option<reqwest::Client>,
    #[cfg(feature = "cache")]
    cache: Option<Arc<dyn CacheAdapter>>,
}

impl RekorClientBuilder {
    /// Create a new builder with the given URL
    pub fn new(url: impl Into<String>) -> Self {
        let url = url.into();
        Self {
            url: url.trim_end_matches('/').to_string(),
            http_client: None,
            #[cfg(feature = "cache")]
            cache: None,
        }
    }

    /// Use a caller-configured HTTP client (timeouts, proxies, TLS roots,
    /// user agent).
    ///
    /// Without one, a client with a 30-second request timeout and a
    /// `sigstore-rust/<version>` user agent is used.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
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
    pub fn build(self) -> Result<RekorClient> {
        let client = match self.http_client {
            Some(client) => client,
            None => default_http_client()?,
        };
        Ok(RekorClient {
            url: self.url,
            client,
            #[cfg(feature = "cache")]
            cache: self.cache,
        })
    }
}

fn validate_v2_entry(entry: &TransparencyLogEntry, request: &HashedRekordV2) -> Result<()> {
    if entry.kind_version != KindVersion::HashedRekordV002 {
        return Err(Error::InvalidResponse(format!(
            "expected hashedrekord/0.0.2, received {}/{}",
            entry.kind_version.kind(),
            entry.kind_version.version()
        )));
    }
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        entry.kind_version.kind(),
        entry.kind_version.version(),
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
        || logged.data.digest.as_bytes() != requested.digest.as_bytes()
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
