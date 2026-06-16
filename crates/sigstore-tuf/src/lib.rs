//! `sigstore-tuf` — a pure-Rust implementation of [The Update Framework (TUF)].
//!
//! This crate is a focused TUF client built for Sigstore's needs, aligned with
//! the work of `python-tuf` (sigstore-python) and `go-tuf` (sigstore-go), and
//! inspired by `tough` — but deliberately interoperable with **all** the
//! ecosystem's repositories, including those produced by `tuf-on-ci` /
//! `securesystemslib` such as GitHub's (`https://tuf-repo.github.com`).
//!
//! # Why not just use `tough`?
//!
//! `tough` recomputes each key's TUF key ID over the entire key object
//! (including non-standard fields like `x-tuf-on-ci-keyowner`) and *rejects*
//! metadata whose declared key IDs don't match. That makes it unable to load
//! GitHub's TUF root at all, even though `python-tuf`, `go-tuf`, and
//! `gh attestation` all consume it fine. Per the TUF spec a key ID is an opaque,
//! producer-chosen identifier — there is no requirement that `keyid ==
//! hash(key)`. This crate therefore treats **declared key IDs as authoritative**
//! and never recomputes-and-rejects (see [`key`]).
//!
//! A second, subtler interop requirement: TUF signs over **securesystemslib /
//! OLPC canonical JSON**, not RFC 8785 JCS. The two differ in string escaping
//! (notably newlines inside embedded PEM keys) and number handling, so this
//! crate ships its own canonical encoder ([`canonical_json`]) rather than reuse
//! a JCS implementation.
//!
//! # Architecture
//!
//! * [`canonical_json`] — TUF-compatible canonical JSON (the bytes signatures
//!   cover).
//! * [`key`] — TUF keys → [`sigstore_crypto::VerificationKey`]; declared key IDs
//!   are authoritative.
//! * [`metadata`] — the signed envelope and the four roles (`root`,
//!   `timestamp`, `snapshot`, `targets`).
//! * [`trusted::TrustedMetadataSet`] — the transport-free verification state
//!   machine: signature thresholds, anti-rollback, expiry, and length/hash
//!   pinning. This is where the security lives, and it is fully unit-testable.
//! * [`client`] (feature `fetch`) — an HTTP [`client::Updater`] that drives the
//!   refresh workflow and downloads/verifies targets.
//!
//! # Status
//!
//! Implemented: metadata parsing, canonical JSON, key handling, root chaining,
//! timestamp/snapshot/targets verification, **delegated-targets discovery**
//! (pre-order DFS with `terminating` and path/hash-prefix matching), **per-file
//! download size limits** ([`transport::UpdaterConfig`]), a **pluggable
//! transport** ([`transport::Repository`]) with **offline** support
//! ([`cache::StoreRepository`]), and **write-through on-disk caching**
//! ([`cache::FileStore`]) that re-verifies from the pinned root on each run.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "fetch")]
//! # async fn run() -> Result<(), sigstore_tuf::Error> {
//! use sigstore_tuf::{client::Updater, client::HttpRepository, cache::FileStore};
//!
//! let repo = HttpRepository::new("https://tuf-repo.github.com")?;
//! let root = std::fs::read("github-root.json").unwrap();
//! let mut updater = Updater::new(repo, &root)?
//!     .with_store(FileStore::new("/var/cache/sigstore/github"));
//! updater.refresh(jiff::Timestamp::now()).await?;
//!
//! let trusted_root = updater
//!     .get_target("trusted_root.json", jiff::Timestamp::now())
//!     .await?;
//! # let _ = trusted_root;
//! # Ok(())
//! # }
//! ```
//!
//! [The Update Framework (TUF)]: https://theupdateframework.io/

#![warn(missing_docs)]

pub mod cache;
pub mod canonical_json;
pub mod client;
pub mod error;
pub mod key;
pub mod metadata;
pub mod transport;
pub mod trusted;

pub use error::{Error, Result};
pub use key::{Key, KeyVal};
pub use metadata::{
    DelegatedRole, Delegations, MetaFile, Metadata, Role, RoleKeys, Root, Signature, Snapshot,
    TargetFile, Targets, Timestamp,
};
pub use transport::{Repository, UpdaterConfig};
pub use trusted::TrustedMetadataSet;

pub use cache::{FileStore, MemoryStore, MetadataStore, StoreRepository};
pub use client::Updater;

#[cfg(feature = "fetch")]
pub use client::HttpRepository;
