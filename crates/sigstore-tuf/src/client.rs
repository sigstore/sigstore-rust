//! The network TUF client: [`Updater`] and the HTTP transport.
//!
//! [`Updater`] drives the full TUF client workflow over a pluggable
//! [`Repository`]: walk the root chain to the latest root, then refresh
//! timestamp → snapshot → top-level targets, feeding every downloaded file
//! through [`TrustedMetadataSet`] so all verification happens in one audited
//! place. It then resolves and downloads individual targets, walking the
//! delegation tree as needed.
//!
//! Cross-cutting concerns are handled here rather than in the verifier:
//! * **Download bounds** — every fetch carries a per-role `max_length` from
//!   [`UpdaterConfig`].
//! * **Caching** — an optional [`MetadataStore`] receives every *verified*
//!   metadata file (write-through) and is re-verified from the pinned root on
//!   the next run, so a tampered cache can never bypass verification.

use std::collections::BTreeSet;

use crate::cache::MetadataStore;
use crate::error::{Error, Result};
use crate::metadata::TargetFile;
use crate::transport::{Repository, UpdaterConfig};
use crate::trusted::TrustedMetadataSet;

/// A TUF client that refreshes and verifies metadata from a [`Repository`] and
/// downloads verified targets.
pub struct Updater {
    repo: Box<dyn Repository>,
    trusted: TrustedMetadataSet,
    config: UpdaterConfig,
    store: Option<Box<dyn MetadataStore>>,
}

impl std::fmt::Debug for Updater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Updater")
            .field("root_version", &self.trusted.root().version)
            .field("config", &self.config)
            .field("has_store", &self.store.is_some())
            .finish()
    }
}

impl Updater {
    /// Create an updater bootstrapped from a pinned root, with default limits.
    ///
    /// The root is verified (self-signed to threshold) immediately.
    pub fn new(repo: impl Repository + 'static, root_bytes: &[u8]) -> Result<Self> {
        let trusted = TrustedMetadataSet::from_root(root_bytes)?;
        Ok(Self {
            repo: Box::new(repo),
            trusted,
            config: UpdaterConfig::default(),
            store: None,
        })
    }

    /// Override the download limits / rotation bounds.
    pub fn with_config(mut self, config: UpdaterConfig) -> Self {
        self.config = config;
        self
    }

    /// Attach a metadata store for write-through caching.
    ///
    /// Any cached root chain is re-verified forward from the pinned bootstrap
    /// root immediately, so we start from the freshest *securely reachable*
    /// root. A cached root that doesn't chain from the bootstrap is ignored.
    pub fn with_store(mut self, store: impl MetadataStore + 'static) -> Self {
        let store: Box<dyn MetadataStore> = Box::new(store);
        loop {
            let next = self.trusted.root().version + 1;
            match store.load(&format!("{next}.root.json")) {
                Some(bytes) if self.trusted.update_root(&bytes).is_ok() => {
                    tracing::debug!(version = next, "adopted cached root");
                }
                _ => break,
            }
        }
        self.store = Some(store);
        self
    }

    /// The verified trusted-metadata set.
    pub fn trusted(&self) -> &TrustedMetadataSet {
        &self.trusted
    }

    /// Run the full TUF refresh workflow: root chain → timestamp → snapshot →
    /// top-level targets. `now` is used for expiry checks (typically
    /// [`jiff::Timestamp::now`]).
    pub async fn refresh(&mut self, now: jiff::Timestamp) -> Result<()> {
        self.refresh_root().await?;
        self.trusted.check_root_expired(now)?;
        self.seed_lower_from_store(now);
        self.refresh_timestamp(now).await?;
        self.refresh_snapshot(now).await?;
        self.refresh_targets(now).await?;
        Ok(())
    }

    /// Seed the trusted timestamp/snapshot/targets from previously persisted
    /// metadata in the store, so anti-rollback protection spans process runs:
    /// a fresh `Updater` started against a populated cache treats the cached
    /// versions as the floor that the network must meet or exceed.
    ///
    /// Best-effort — a cached file that is missing, stale, expired, or no longer
    /// consistent with the trusted root is simply skipped; the subsequent
    /// network refresh will replace it. (This mirrors how `python-tuf`'s
    /// `ngclient` loads its local trusted metadata at startup.)
    fn seed_lower_from_store(&mut self, now: jiff::Timestamp) {
        let Some((ts, snap, tgt)) = self.store.as_ref().map(|s| {
            (
                s.load("timestamp.json"),
                s.load("snapshot.json"),
                s.load("targets.json"),
            )
        }) else {
            return;
        };
        if let Some(bytes) = ts {
            let _ = self.trusted.update_timestamp(&bytes, now);
        }
        if let Some(bytes) = snap {
            let _ = self.trusted.update_snapshot(&bytes, now);
        }
        if let Some(bytes) = tgt {
            let _ = self.trusted.update_targets(&bytes, now);
        }
    }

    fn cache_put(&self, name: &str, bytes: &[u8]) {
        if let Some(store) = &self.store {
            if let Err(e) = store.store(name, bytes) {
                tracing::warn!(%name, error = %e, "failed to cache metadata");
            }
        }
    }

    async fn refresh_root(&mut self) -> Result<()> {
        let start = self.trusted.root().version;
        for next in (start + 1)..=(start + self.config.max_root_rotations) {
            let name = format!("{next}.root.json");
            match self
                .repo
                .fetch_metadata(&name, self.config.root_max_length)
                .await?
            {
                Some(bytes) => {
                    self.trusted.update_root(&bytes)?;
                    self.cache_put(&name, &bytes);
                    self.cache_put("root.json", &bytes);
                    tracing::debug!(version = next, "updated root");
                }
                None => return Ok(()),
            }
        }
        Err(Error::Transport(format!(
            "exceeded {} root rotations without reaching the latest root",
            self.config.max_root_rotations
        )))
    }

    async fn refresh_timestamp(&mut self, now: jiff::Timestamp) -> Result<()> {
        // timestamp.json is never version-prefixed, even with consistent snapshots.
        let bytes = self
            .repo
            .fetch_metadata("timestamp.json", self.config.timestamp_max_length)
            .await?
            .ok_or_else(|| Error::Transport("timestamp.json not found".to_string()))?;
        self.trusted.update_timestamp(&bytes, now)?;
        self.cache_put("timestamp.json", &bytes);
        Ok(())
    }

    async fn refresh_snapshot(&mut self, now: jiff::Timestamp) -> Result<()> {
        let consistent = self.trusted.root().consistent_snapshot;
        let version = self
            .trusted
            .timestamp()
            .and_then(|t| t.snapshot_meta())
            .map(|m| m.version)
            .ok_or_else(|| Error::Malformed("timestamp does not pin snapshot".to_string()))?;
        let name = if consistent {
            format!("{version}.snapshot.json")
        } else {
            "snapshot.json".to_string()
        };
        let bytes = self
            .repo
            .fetch_metadata(&name, self.config.snapshot_max_length)
            .await?
            .ok_or_else(|| Error::Transport(format!("{name} not found")))?;
        self.trusted.update_snapshot(&bytes, now)?;
        self.cache_put(&name, &bytes);
        self.cache_put("snapshot.json", &bytes);
        Ok(())
    }

    async fn refresh_targets(&mut self, now: jiff::Timestamp) -> Result<()> {
        let bytes = self.fetch_targets_metadata("targets").await?;
        self.trusted.update_targets(&bytes, now)?;
        self.cache_put("targets.json", &bytes);
        Ok(())
    }

    /// Fetch the (version-prefixed, when consistent) metadata file for a targets
    /// role, using its snapshot pin to choose the file name.
    async fn fetch_targets_metadata(&self, role_name: &str) -> Result<Vec<u8>> {
        let consistent = self.trusted.root().consistent_snapshot;
        let meta_name = format!("{role_name}.json");
        let version = self
            .trusted
            .snapshot()
            .and_then(|s| s.meta.get(&meta_name))
            .map(|m| m.version)
            .ok_or_else(|| Error::Malformed(format!("snapshot does not pin {meta_name}")))?;
        let name = if consistent {
            format!("{version}.{role_name}.json")
        } else {
            meta_name
        };
        self.repo
            .fetch_metadata(&name, self.config.targets_max_length)
            .await?
            .ok_or_else(|| Error::Transport(format!("{name} not found")))
    }

    /// Resolve a target's metadata by walking the delegation tree, fetching and
    /// verifying delegated targets roles on demand. Requires a prior
    /// [`Updater::refresh`]. Returns `None` if no role authorizes the target.
    ///
    /// Implements TUF's pre-order, depth-first delegation search with
    /// `terminating` handling and a configurable depth bound
    /// ([`UpdaterConfig::max_delegations`]).
    pub async fn get_targetinfo(
        &mut self,
        target_path: &str,
        now: jiff::Timestamp,
    ) -> Result<Option<TargetFile>> {
        if self.trusted.targets_role("targets").is_none() {
            return Err(Error::Malformed(
                "refresh() must be called before resolving targets".to_string(),
            ));
        }

        // Queue of (role_name, delegator_name) to visit, front = next.
        let mut to_visit: Vec<(String, String)> = vec![("targets".to_string(), "root".to_string())];
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut steps = 0u32;

        while !to_visit.is_empty() {
            let (role, delegator) = to_visit.remove(0);
            if visited.contains(&role) {
                continue;
            }
            if steps >= self.config.max_delegations {
                tracing::warn!(
                    max = self.config.max_delegations,
                    "delegation search hit depth bound; target may be unresolved"
                );
                break;
            }
            steps += 1;

            // Ensure the role is loaded & verified (top-level already is).
            if role != "targets" {
                let bytes = self.fetch_targets_metadata(&role).await?;
                self.trusted
                    .update_delegated_targets(&bytes, &role, &delegator, now)?;
                self.cache_put(&format!("{role}.json"), &bytes);
            }
            visited.insert(role.clone());

            let targets = self.trusted.targets_role(&role).expect("role just loaded");

            if let Some(found) = targets.target(target_path) {
                return Ok(Some(found.clone()));
            }

            // Enqueue matching child delegations in pre-order (DFS): collect
            // them, honoring `terminating`, then prepend to the work list.
            let mut children: Vec<(String, String)> = Vec::new();
            if let Some(delegations) = &targets.delegations {
                for child in &delegations.roles {
                    if child.matches_path(target_path)? {
                        children.push((child.name.clone(), role.clone()));
                        if child.terminating {
                            // Stop considering any further delegations entirely.
                            to_visit.clear();
                            break;
                        }
                    }
                }
            }
            children.extend(std::mem::take(&mut to_visit));
            to_visit = children;
        }

        Ok(None)
    }

    /// Look up a target by path in the trusted **top-level** targets metadata
    /// only (no delegation walk). Use [`Updater::get_targetinfo`] to search
    /// delegated roles.
    pub fn find_target(&self, target_path: &str) -> Option<&TargetFile> {
        self.trusted.targets_role("targets")?.target(target_path)
    }

    /// Download a target file and verify its length and hash against the trusted
    /// targets metadata (searching delegations). Requires a prior
    /// [`Updater::refresh`].
    pub async fn download_target(
        &mut self,
        target_path: &str,
        now: jiff::Timestamp,
    ) -> Result<Vec<u8>> {
        let target = self
            .get_targetinfo(target_path, now)
            .await?
            .ok_or_else(|| Error::Malformed(format!("unknown target {target_path:?}")))?;

        if target.length > self.config.target_max_length {
            return Err(Error::IntegrityMismatch(format!(
                "{target_path}: pinned length {} exceeds configured max {}",
                target.length, self.config.target_max_length
            )));
        }

        let consistent = self.trusted.root().consistent_snapshot;
        // With consistent snapshots the hash prefixes the *file name* only, not
        // the whole path: `dir/sub/<hash>.name`, never `<hash>.dir/sub/name`.
        let relative = if consistent {
            let (_, hash) = preferred_hash(&target.hashes).ok_or_else(|| {
                Error::IntegrityMismatch(format!(
                    "{target_path}: no hash to locate consistent target"
                ))
            })?;
            match target_path.rsplit_once('/') {
                Some((dir, name)) => format!("{dir}/{hash}.{name}"),
                None => format!("{hash}.{target_path}"),
            }
        } else {
            target_path.to_string()
        };

        let bytes = self
            .repo
            .fetch_target(&relative, target.length)
            .await?
            .ok_or_else(|| Error::Transport(format!("target {relative} not found")))?;

        verify_target_bytes(&bytes, &target, target_path)?;
        if self.store.is_some() {
            self.cache_put(&format!("targets/{target_path}"), &bytes);
        }
        Ok(bytes)
    }
}

/// Pick the hash to use for a target, preferring `sha256`, then `sha512`, then
/// whatever is listed. Returns `(algorithm, hex-digest)`.
fn preferred_hash(hashes: &std::collections::BTreeMap<String, String>) -> Option<(&str, &str)> {
    for algo in ["sha256", "sha512"] {
        if let Some(hex) = hashes.get(algo) {
            return Some((algo, hex.as_str()));
        }
    }
    hashes.iter().next().map(|(a, h)| (a.as_str(), h.as_str()))
}

/// Verify downloaded target bytes against the pinned length and hashes.
///
/// The length must match, and every hash whose algorithm we support (`sha256`,
/// `sha512`) must match; at least one supported hash must be present so a target
/// is never accepted without an integrity check.
fn verify_target_bytes(bytes: &[u8], target: &TargetFile, path: &str) -> Result<()> {
    use sha2::{Digest, Sha256, Sha512};
    if bytes.len() as u64 != target.length {
        return Err(Error::IntegrityMismatch(format!(
            "{path}: length {} != pinned {}",
            bytes.len(),
            target.length
        )));
    }

    let mut verified_any = false;
    for (algo, expected) in &target.hashes {
        let actual = match algo.as_str() {
            "sha256" => hex::encode(Sha256::digest(bytes)),
            "sha512" => hex::encode(Sha512::digest(bytes)),
            _ => continue,
        };
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(Error::IntegrityMismatch(format!("{path}: {algo} mismatch")));
        }
        verified_any = true;
    }

    if !verified_any {
        return Err(Error::IntegrityMismatch(format!(
            "{path}: no supported hash to verify ({:?})",
            target.hashes.keys().collect::<Vec<_>>()
        )));
    }
    Ok(())
}

#[cfg(feature = "fetch")]
mod http {
    use url::Url;

    use crate::error::{Error, Result};
    use crate::transport::{FetchFuture, Repository};

    /// An HTTP-backed TUF repository.
    #[derive(Debug, Clone)]
    pub struct HttpRepository {
        metadata_base: Url,
        targets_base: Url,
        client: reqwest::Client,
    }

    impl HttpRepository {
        /// Create a repository rooted at `base_url`.
        ///
        /// Metadata is fetched from `<base_url>/` and targets from
        /// `<base_url>/targets/`, matching the common Sigstore/TUF layout.
        pub fn new(base_url: &str) -> Result<Self> {
            let base = normalize_base(base_url)?;
            let targets_base = base
                .join("targets/")
                .map_err(|e| Error::Transport(format!("invalid targets base: {e}")))?;
            Ok(Self {
                metadata_base: base,
                targets_base,
                client: reqwest::Client::new(),
            })
        }

        /// Override where target files are fetched from.
        pub fn with_targets_base(mut self, targets_base_url: &str) -> Result<Self> {
            self.targets_base = normalize_base(targets_base_url)?;
            Ok(self)
        }

        async fn bounded_get(&self, url: Url, max_length: u64) -> Result<Option<Vec<u8>>> {
            let mut resp = self
                .client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| Error::Transport(format!("GET {url} failed: {e}")))?;

            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !resp.status().is_success() {
                return Err(Error::Transport(format!(
                    "GET {url} returned status {}",
                    resp.status()
                )));
            }
            // Reject early if the advertised size already exceeds the bound.
            if let Some(len) = resp.content_length() {
                if len > max_length {
                    return Err(Error::Transport(format!(
                        "{url}: content-length {len} exceeds max {max_length}"
                    )));
                }
            }
            // Bound memory while reading, in case the size was not advertised.
            let mut buf = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| Error::Transport(format!("reading {url} failed: {e}")))?
            {
                if buf.len() as u64 + chunk.len() as u64 > max_length {
                    return Err(Error::Transport(format!(
                        "{url}: response exceeds max length {max_length}"
                    )));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(Some(buf))
        }
    }

    fn normalize_base(base_url: &str) -> Result<Url> {
        // A base URL must end in `/` for `Url::join` to treat it as a directory.
        let with_slash = if base_url.ends_with('/') {
            base_url.to_string()
        } else {
            format!("{base_url}/")
        };
        Url::parse(&with_slash).map_err(|e| Error::Transport(format!("invalid base URL: {e}")))
    }

    impl Repository for HttpRepository {
        fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
            Box::pin(async move {
                let url = self
                    .metadata_base
                    .join(name)
                    .map_err(|e| Error::Transport(format!("invalid URL {name:?}: {e}")))?;
                self.bounded_get(url, max_length).await
            })
        }

        fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
            Box::pin(async move {
                let url = self
                    .targets_base
                    .join(path)
                    .map_err(|e| Error::Transport(format!("invalid URL {path:?}: {e}")))?;
                self.bounded_get(url, max_length).await
            })
        }
    }
}

#[cfg(feature = "fetch")]
pub use http::HttpRepository;
