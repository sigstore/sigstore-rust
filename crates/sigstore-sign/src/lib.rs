//! Sigstore signature creation
//!
//! This crate provides the main entry point for signing artifacts with Sigstore.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_sign::{SigningContext, SigstoreInstance};
//! use sigstore_oidc::IdentityToken;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // `SigningContext::production().await?` fetches the current signing config
//! // through TUF instead of using the embedded snapshot.
//! let context = SigningContext::from_embedded(SigstoreInstance::PublicGood)?;
//! let token = IdentityToken::from_jwt("header.payload.signature")?;
//! let signer = context.signer(token);
//!
//! let artifact = b"hello world";
//! let bundle = signer.sign(artifact).await?;
//!
//! // Write bundle to file
//! std::fs::write("artifact.sigstore.json", bundle.to_json_pretty()?)?;
//! # Ok(())
//! # }
//! ```

pub mod error;
mod sign;

// Re-export core crates that users need
pub use sigstore_bundle as bundle;
pub use sigstore_crypto as crypto;
pub use sigstore_fulcio as fulcio;
/// The HTTP client crate used by [`SigningContext::with_http_client`].
pub use sigstore_fulcio::reqwest;
pub use sigstore_oidc as oidc;
pub use sigstore_rekor as rekor;
pub use sigstore_trust_root as trust_root;
pub use sigstore_tsa as tsa;
pub use sigstore_types as types;

pub use error::{Error, Result};
pub use sign::{Attestation, Signer, SigningContext, SigningServices};
pub use sigstore_trust_root::SigstoreInstance;
