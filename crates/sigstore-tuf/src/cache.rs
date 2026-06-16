//! Local persistence for trusted metadata.
//!
//! [`MetadataStore`] is a small blob store keyed by file name. The
//! [`Updater`](crate::client::Updater) writes every metadata file through to a
//! store *after* it has been verified, so a later run can bootstrap its trusted
//! root from the freshest local copy (standard TUF behavior) and an offline run
//! can re-verify entirely from cache via [`StoreRepository`].
//!
//! Stored bytes are still untrusted on read: the [`Updater`](crate::client::Updater) re-runs every
//! signature/version/expiry check against them, so a tampered cache cannot
//! bypass verification — at worst it fails the refresh.

use std::collections::HashMap;
use std::io::Write;
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
///
/// # Durability and concurrency
///
/// Writes are **atomic**: bytes are written to a uniquely-named temp file in
/// the destination directory and then `rename`d over the final name. A reader
/// therefore never observes a half-written file, and a crash mid-write leaves
/// either the old file or the new one — never a truncated or interleaved blob.
///
/// As a consequence the store is **safe to share across concurrent processes**:
/// two writers racing on the same name resolve to a clean last-writer-wins,
/// not a corrupted file. The store deliberately does *not* provide *cross-file*
/// atomicity (e.g. `timestamp.json` and `snapshot.json` updated as a unit) and
/// takes no lock spanning a refresh. It does not need to: the
/// [`Updater`](crate::client::Updater) re-verifies every cached file from the
/// pinned root and enforces version floors on read, so a concurrently-written,
/// internally-inconsistent set of cache files can at worst trigger a re-fetch —
/// it can never bypass verification.
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
        write_atomic(&path, bytes)
    }
}

/// Write `bytes` to `path` atomically via a [`tempfile::NamedTempFile`] in the
/// same directory followed by `persist` (an atomic rename). The temp lives in
/// the destination directory (not `$TMPDIR`) so the rename stays within one
/// filesystem and is therefore atomic; it carries a random name, so concurrent
/// writers never collide, and `NamedTempFile` removes it on any error path so a
/// crashed or losing writer leaks nothing.
///
/// On Windows, `persist` over a file another process currently has open can
/// transiently fail, so the rename is retried a few times with brief backoff.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| Error::Transport(format!("cache temp create failed: {e}")))?;
    tmp.write_all(bytes)
        .map_err(|e| Error::Transport(format!("cache write failed: {e}")))?;

    let mut to_persist = tmp;
    for attempt in 0..5 {
        match to_persist.persist(path) {
            Ok(_) => return Ok(()),
            // `persist` returns the temp file back inside the error so a retry
            // can reuse it without rewriting the bytes.
            Err(e) => {
                to_persist = e.file;
                if attempt == 4 {
                    return Err(Error::Transport(format!(
                        "cache rename failed: {}",
                        e.error
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(10 * (attempt + 1)));
            }
        }
    }
    unreachable!("loop returns on the final attempt")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Count leftover temp files (tempfile names them `.tmpXXXXXX`) in `dir`.
    fn temp_residue(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .count()
    }

    #[test]
    fn store_round_trips_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());

        store.store("timestamp.json", b"v1").unwrap();
        assert_eq!(store.load("timestamp.json").as_deref(), Some(&b"v1"[..]));

        // Last-writer-wins, in place.
        store.store("timestamp.json", b"v2-longer").unwrap();
        assert_eq!(
            store.load("timestamp.json").as_deref(),
            Some(&b"v2-longer"[..])
        );

        assert_eq!(store.load("absent.json"), None);
    }

    #[test]
    fn writes_leave_no_temp_residue() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());

        // Including a nested name to exercise the create_dir_all path.
        store.store("root_history/2.root.json", b"root").unwrap();
        store.store("snapshot.json", b"snap").unwrap();
        store.store("snapshot.json", b"snap-again").unwrap();

        assert_eq!(
            temp_residue(dir.path()),
            0,
            "no temp files should remain in the store root"
        );
        assert_eq!(
            temp_residue(&dir.path().join("root_history")),
            0,
            "no temp files should remain in nested dirs"
        );
    }

    #[test]
    fn rejects_paths_escaping_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        assert!(store.store("../escape.json", b"x").is_err());
        assert!(store.load("../escape.json").is_none());
    }
}
