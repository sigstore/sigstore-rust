//! A timestamp authority as a single unit of trust.
//!
//! The certificate chain and the `valid_for` window travel together so a
//! timestamp's temporal authorization always comes from the same authority
//! that cryptographically signed it (TOB-SIGSTORE-11).

use crate::{DerCertificate, TimeRange};

/// A single timestamp authority usable for RFC 3161 verification: its
/// certificate chain split into leaf, intermediates and root, together with
/// the authority's `valid_for` window.
///
/// An authority is consumed as one unit by
/// `sigstore_tsa::verify_timestamp_for_authority`, which both authenticates a
/// token against the chain and checks the signed time against `valid_for` —
/// the window of an authority that did not sign a token can never authorize
/// it.
#[derive(Debug, Clone)]
pub struct TsaAuthority {
    /// The TSA signing certificate (the first certificate in the chain).
    pub leaf: DerCertificate,
    /// Certificates between the leaf and the root, if any.
    pub intermediates: Vec<DerCertificate>,
    /// The trust anchor (the last certificate in the chain).
    pub root: DerCertificate,
    /// The authority's validity window; `None` means unrestricted.
    pub valid_for: Option<TimeRange>,
}
