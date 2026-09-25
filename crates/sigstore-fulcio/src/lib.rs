//! Fulcio certificate authority client for Sigstore
//!
//! This crate provides a client for interacting with Fulcio, the Sigstore
//! certificate authority service.
//!
//! # Features
//!
//! - `cache` - Enable caching support for configuration and trust bundle responses.
//!   When enabled, use [`FulcioClientBuilder::with_cache`] to configure a cache adapter.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_fulcio::FulcioClient;
//!
//! # async fn example() -> Result<(), sigstore_fulcio::Error> {
//! let client = FulcioClient::new("https://fulcio.sigstore.dev")?;
//! let config = client.get_configuration().await?;
//! println!("Supported issuers: {:?}", config.issuers);
//! # Ok(())
//! # }
//! ```
//!
//! With caching enabled:
//!
//! ```ignore
//! use sigstore_fulcio::FulcioClient;
//! use sigstore_cache::FileSystemCache;
//!
//! let cache = FileSystemCache::default_location()?;
//! let client = FulcioClient::builder("https://fulcio.sigstore.dev")
//!     .with_cache(cache)
//!     .build()?;
//! ```

pub mod client;
pub mod error;

pub use client::{
    Configuration, FulcioClient, FulcioClientBuilder, IssuerUrl, OidcIssuer, SigningCertificate,
    TrustBundle,
};
pub use error::{Error, Result};
/// The HTTP client crate used by [`FulcioClientBuilder::with_http_client`].
pub use reqwest;
