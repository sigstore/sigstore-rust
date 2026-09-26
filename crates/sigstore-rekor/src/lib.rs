//! Rekor transparency log client for Sigstore
//!
//! This crate provides a client for interacting with Rekor, the Sigstore
//! transparency log service.
//!
//! # Features
//!
//! - `client` - HTTP clients. Enabled by the default `rustls` feature.
//! - Disable default features for offline entry types and bundle conversion.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "client")]
//! # async fn example() -> Result<(), sigstore_rekor::Error> {
//! use sigstore_rekor::RekorClient;
//! let client = RekorClient::new("https://rekor.sigstore.dev")?;
//! let log_info = client.get_log_info().await?;
//! println!("Tree size: {}", log_info.tree_size);
//! # Ok(())
//! # }
//! ```

pub mod body;
#[cfg(feature = "client")]
pub mod client;
pub mod entry;
pub mod error;
pub mod hex_encoded;

pub use body::RekorEntryBody;
#[cfg(feature = "client")]
pub use client::{RekorClient, RekorClientBuilder, RekorV2Client, RekorV2EntryBundle, RekorV2Tile};
pub use entry::{
    DsseEntry, HashedRekord, HashedRekordV2, LogEntry, LogInfo, RekorApiVersion, RekorV2KeyDetails,
    SearchIndex,
};
pub use error::{Error, Result};
pub use hex_encoded::{HexHash, HexLogId};
/// The HTTP client crate used by [`RekorClientBuilder::with_http_client`] and
/// [`RekorV2Client::with_http_client`].
#[cfg(feature = "client")]
pub use reqwest;
