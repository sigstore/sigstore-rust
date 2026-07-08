//! Sigstore signature verification
//!
//! This crate provides the main entry point for verifying Sigstore signatures.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_verify::{verify, VerificationMode, VerificationPolicy};
//! use sigstore_trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
//! use sigstore_types::Bundle;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)?;
//! let bundle_json = std::fs::read_to_string("artifact.sigstore.json")?;
//! let bundle = Bundle::from_json(&bundle_json)?;
//! let artifact = std::fs::read("artifact.txt")?;
//!
//! let policy = VerificationPolicy::default()
//!     .require_identity("user@example.com")
//!     .require_issuer("https://accounts.google.com");
//!
//! verify(&artifact, &bundle, VerificationMode::Certificate(&policy), &trusted_root)?;
//! # Ok(())
//! # }
//! ```

pub mod error;
mod verify;

// Private submodules for verification logic
mod verify_impl;

// Re-export core types that users need
pub use sigstore_bundle as bundle;
pub use sigstore_crypto as crypto;
pub use sigstore_rekor as rekor;
pub use sigstore_trust_root as trust_root;
pub use sigstore_tsa as tsa;
pub use sigstore_types as types;

pub use error::{Error, Result};
pub use verify::{
    verify, CertificatePolicy, PublicKeyVerificationPolicy, VerificationMode, VerificationPolicy,
    VerificationResult, Verifier, DEFAULT_CLOCK_SKEW_SECONDS,
};
