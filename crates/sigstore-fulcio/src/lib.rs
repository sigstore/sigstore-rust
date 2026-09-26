//! Fulcio certificate authority client for Sigstore
//!
//! This crate provides a client for interacting with Fulcio, the Sigstore
//! certificate authority service.
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

pub mod client;
pub mod error;

pub use client::{
    Configuration, FulcioClient, FulcioClientBuilder, IssuerUrl, OidcIssuer, SigningCertificate,
    TrustBundle,
};
pub use error::{Error, Result};
/// The HTTP client crate used by [`FulcioClientBuilder::with_http_client`].
pub use reqwest;
