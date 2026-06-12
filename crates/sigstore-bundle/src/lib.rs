//! Bundle format handling for Sigstore
//!
//! This crate handles creation, parsing, and *structural* validation of
//! Sigstore bundles (versions 0.1, 0.2, and 0.3).
//!
//! Note that [`validate_bundle`] and [`validate_bundle_with_options`] only
//! check bundle shape and version conformance; they perform no cryptographic
//! verification. Use the `sigstore-verify` crate to cryptographically verify
//! a bundle (signatures, inclusion proofs, checkpoints, SETs, timestamps and
//! certificates).

pub mod builder;
pub mod error;
pub mod validation;

pub use builder::{BundleV03, TlogEntryBuilder, VerificationMaterialV03};
pub use error::{Error, Result};
pub use validation::{validate_bundle, validate_bundle_with_options, ValidationOptions};
