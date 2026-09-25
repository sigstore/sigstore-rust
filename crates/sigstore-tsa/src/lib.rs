//! RFC 3161 Time-Stamp Protocol client for Sigstore
//!
//! This crate implements the Time-Stamp Protocol as specified in RFC 3161,
//! including request creation, response parsing, and timestamp verification.

mod asn1;
#[cfg(feature = "client")]
mod client;
pub mod error;
mod verify;

#[cfg(feature = "client")]
pub use client::{TimestampClient, TimestampClientBuilder};
pub use error::{Error, Result};
/// The HTTP client crate used by [`TimestampClientBuilder::with_http_client`].
#[cfg(feature = "client")]
pub use reqwest;
pub use sigstore_types::TsaAuthority;
pub use verify::verify_timestamp_for_authority;
