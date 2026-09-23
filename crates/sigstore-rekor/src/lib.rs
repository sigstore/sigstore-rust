//! Rekor transparency log client for Sigstore
//!
//! This crate provides a client for interacting with Rekor, the Sigstore
//! transparency log service.
//!
//! # Features
//!
//! - `client` - HTTP clients. Enabled by the default `rustls` feature.
//! - `cache` - HTTP response caching via `RekorClientBuilder::with_cache`.
//! - Disable default features for offline entry types and bundle conversion.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "client")]
//! # async fn example() -> Result<(), sigstore_rekor::Error> {
//! use sigstore_rekor::RekorClient;
//! let client = RekorClient::public();
//! let log_info = client.get_log_info().await?;
//! println!("Tree size: {}", log_info.tree_size);
//! # Ok(())
//! # }
//! ```
//!
//! With caching enabled:
//!
//! ```ignore
//! use sigstore_rekor::RekorClient;
//! use sigstore_cache::FileSystemCache;
//!
//! let cache = FileSystemCache::default_location()?;
//! let client = RekorClient::builder("https://rekor.sigstore.dev")
//!     .with_cache(cache)
//!     .build();
//! ```

pub mod body;
#[cfg(feature = "client")]
pub mod client;
pub mod entry;
pub mod error;

pub use body::RekorEntryBody;
#[cfg(feature = "client")]
pub use client::{
    get_public_log_info, RekorClient, RekorClientBuilder, RekorV2Client, RekorV2EntryBundle,
    RekorV2Tile,
};
pub use entry::{
    DsseEntry, HashedRekord, HashedRekordV2, LogEntry, LogInfo, RekorApiVersion, RekorV2KeyDetails,
    SearchIndex,
};
pub use error::{Error, Result};
