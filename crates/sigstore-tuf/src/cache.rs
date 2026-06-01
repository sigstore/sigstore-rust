//! Local persistence for trusted metadata.
//!
//! [`MetadataStore`] is a small blob store keyed by file name. The
//! [`Updater`](crate::client::Updater) writes every metadata file through to a
//! store *after* it has been verified, so a later run can bootstrap its trusted
//! root from the freshest local copy (standard TUF behavior) and an offline run
//! can re-verify entirely from cache via [`StoreRepository`].
//!
//! Stored bytes are still untrusted on read: the [`Updater`] re-runs every
//! signature/version/expiry check against them, so a tampered cache cannot
//! bypass verification — at worst it fails the refresh.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::transport::{FetchFuture, Repository};

/// A blob store for verified TUF metadata (and optionally cached targets),
/// keyed by file name.
pub trait MetadataStore: Send + Sync {
    /// Load a previously stored blob, or `None` if absent.
    fn load(&self, name: &str) -> Option<Vec<u8>>;

    /// Persist a blob under `name`. Best-effort callers may ignore the error.
    fn store(&self, name: &str, bytes: &[u8]) -> Result<()>;
}

/// A filesystem-backed [`MetadataStore`] rooted at a directory.
///
/// File names may contain `/`; intermediate directories are created. Names
/// containing `..` or absolute components are rejected to prevent escaping the
/// store root.
#[derive(Debug, Clone)]
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// Create a store rooted at `dir` (created on first write).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn safe_path(&self, name: &str) -> Result<PathBuf> {
        let rel = Path::new(name);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Error::Malformed(format!("unsafe cache name {name:?}")));
        }
        Ok(self.dir.join(rel))
    }
}

impl MetadataStore for FileStore {
    fn load(&self, name: &str) -> Option<Vec<u8>> {
        let path = self.safe_path(name).ok()?;
        std::fs::read(path).ok()
    }

    fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.safe_path(name)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Transport(format!("cache mkdir failed: {e}")))?;
        }
        std::fs::write(&path, bytes)
            .map_err(|e| Error::Transport(format!("cache write failed: {e}")))
    }
}

/// An in-memory [`MetadataStore`], useful for tests and ephemeral runs.
#[derive(Debug, Default)]
pub struct MemoryStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl MetadataStore for MemoryStore {
    fn load(&self, name: &str) -> Option<Vec<u8>> {
        self.map.lock().unwrap().get(name).cloned()
    }

    fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.map
            .lock()
            .unwrap()
            .insert(name.to_string(), bytes.to_vec());
        Ok(())
    }
}

impl<S: MetadataStore + ?Sized> MetadataStore for std::sync::Arc<S> {
    fn load(&self, name: &str) -> Option<Vec<u8>> {
        (**self).load(name)
    }

    fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
        (**self).store(name, bytes)
    }
}

/// Adapts a [`MetadataStore`] into a read-only [`Repository`], so a refresh can
/// run entirely from local cache with no network — and still re-verify every
/// signature. Honors `max_length` exactly like a network transport.
#[derive(Debug)]
pub struct StoreRepository<S> {
    store: S,
}

impl<S: MetadataStore> StoreRepository<S> {
    /// Wrap a store as an offline repository.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    fn read(&self, name: &str, max_length: u64) -> Result<Option<Vec<u8>>> {
        match self.store.load(name) {
            Some(bytes) if bytes.len() as u64 > max_length => Err(Error::Transport(format!(
                "cached {name} exceeds max length {max_length}"
            ))),
            other => Ok(other),
        }
    }
}

impl<S: MetadataStore> Repository for StoreRepository<S> {
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        let res = self.read(name, max_length);
        Box::pin(async move { res })
    }

    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
        let res = self.read(&format!("targets/{path}"), max_length);
        Box::pin(async move { res })
    }
}
