//! Live TUF bootstrap tests against the real Sigstore and GitHub repositories.
//!
//! These hit the network, so they are `#[ignore]`d by default; run with
//! `cargo test -p sigstore-trust-root --test tuf_bootstrap -- --ignored`.
//!
//! The GitHub case is the original motivation for the `sigstore-tuf` client:
//! `tough` cannot load GitHub's `tuf-on-ci` root at all.

#![cfg(feature = "tuf")]

use sigstore_trust_root::{TrustedRoot, TufConfig};

#[tokio::test]
#[ignore = "network"]
async fn bootstrap_production_trusted_root() {
    let root = TrustedRoot::from_tuf(TufConfig::production().without_cache())
        .await
        .expect("production trusted root should bootstrap over TUF");
    assert!(
        !root.tlogs.is_empty(),
        "expected at least one transparency log in the trusted root"
    );
}

#[tokio::test]
#[ignore = "network"]
async fn bootstrap_github_trusted_root() {
    // This is the case `tough` rejects (tuf-on-ci key IDs).
    let root = TrustedRoot::from_tuf(TufConfig::github().without_cache())
        .await
        .expect("GitHub trusted root should bootstrap over TUF");
    assert!(
        !root.certificate_authorities.is_empty(),
        "expected GitHub trusted root to carry certificate authorities"
    );
}
