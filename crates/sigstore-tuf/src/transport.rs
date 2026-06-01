//! Transport abstraction for fetching TUF metadata and targets.
//!
//! [`Repository`] is the pluggable I/O boundary: the verification core
//! ([`crate::trusted::TrustedMetadataSet`]) never touches the network, and the
//! [`Updater`](crate::client::Updater) drives a `Repository` to fetch bytes.
//! This makes offline, in-memory, and caching transports first-class — they are
//! just other `Repository` implementations.
//!
//! Every fetch carries a `max_length`: the transport MUST refuse to return more
//! than that many bytes (ideally bounding memory while reading, not just after).
//! This caps the work an attacker controlling the mirror can induce — an
//! endless-data attack on metadata.

use std::future::Future;
use std::pin::Pin;

use crate::error::Result;

/// The future returned by [`Repository`] methods.
///
/// Boxed so the trait is object-safe (usable as `dyn Repository`) and compatible
/// with the crate's MSRV without relying on `async fn` in traits.
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + 'a>>;

/// A source of TUF metadata and target bytes.
///
/// Returning `Ok(None)` signals "not found" (e.g. HTTP 404) — used by root
/// chaining to detect the end of the root chain. Any other failure is `Err`.
pub trait Repository: Send + Sync {
    /// Fetch a metadata file by name (e.g. `"1.root.json"`, `"timestamp.json"`),
    /// returning at most `max_length` bytes.
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a>;

    /// Fetch a target file by repository-relative path, returning at most
    /// `max_length` bytes.
    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a>;
}

impl Repository for Box<dyn Repository> {
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        (**self).fetch_metadata(name, max_length)
    }

    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
        (**self).fetch_target(path, max_length)
    }
}

/// Per-role byte limits and root-rotation bound for the refresh workflow.
///
/// Defaults match `python-tuf`'s `UpdaterConfig`, which in turn follows the TUF
/// specification's guidance on bounding download sizes.
#[derive(Debug, Clone, Copy)]
pub struct UpdaterConfig {
    /// Maximum bytes for a single `root` metadata file.
    pub root_max_length: u64,
    /// Maximum bytes for `timestamp` metadata.
    pub timestamp_max_length: u64,
    /// Maximum bytes for `snapshot` metadata.
    pub snapshot_max_length: u64,
    /// Maximum bytes for a `targets` metadata file (top-level or delegated).
    pub targets_max_length: u64,
    /// Default maximum bytes for a target whose length is not pinned in
    /// metadata. (When a length is pinned, it is used instead.)
    pub target_max_length: u64,
    /// Maximum number of root rotations to walk in one refresh.
    pub max_root_rotations: u64,
    /// Maximum depth of the delegation tree to traverse.
    pub max_delegations: u32,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            root_max_length: 512_000,
            timestamp_max_length: 16_384,
            snapshot_max_length: 2_000_000,
            targets_max_length: 5_000_000,
            target_max_length: 50_000_000,
            max_root_rotations: 32,
            max_delegations: 32,
        }
    }
}
