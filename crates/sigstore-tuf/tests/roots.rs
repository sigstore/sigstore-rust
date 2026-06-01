//! Integration tests that load real-world TUF roots.
//!
//! These roots are reused from the `sigstore-trust-root` crate's embedded
//! repository so we exercise the exact bytes shipped elsewhere in the workspace.
//! The GitHub root in particular is the one `tough` cannot load (it
//! recompute-and-rejects the `tuf-on-ci` key IDs); loading and self-verifying it
//! here is the whole point of this crate.

use sigstore_tuf::{Metadata, Root, TrustedMetadataSet};

const GITHUB_ROOT: &[u8] =
    include_bytes!("../../sigstore-trust-root/repository/tuf_github_root.json");
const PRODUCTION_ROOT: &[u8] =
    include_bytes!("../../sigstore-trust-root/repository/tuf_root.json");
const STAGING_ROOT: &[u8] =
    include_bytes!("../../sigstore-trust-root/repository/tuf_staging_root.json");

#[test]
fn parses_and_self_verifies_github_root() {
    // This is the case that fails with `tough`.
    let trusted = TrustedMetadataSet::from_root(GITHUB_ROOT)
        .expect("GitHub TUF root should parse and self-verify");
    assert_eq!(trusted.root().type_, "root");
    assert!(trusted.root().consistent_snapshot);
    assert!(!trusted.root().keys.is_empty());
}

#[test]
fn parses_and_self_verifies_sigstore_production_root() {
    let trusted = TrustedMetadataSet::from_root(PRODUCTION_ROOT)
        .expect("Sigstore production root should parse and self-verify");
    assert_eq!(trusted.root().type_, "root");
}

#[test]
fn parses_and_self_verifies_sigstore_staging_root() {
    TrustedMetadataSet::from_root(STAGING_ROOT)
        .expect("Sigstore staging root should parse and self-verify");
}

#[test]
fn github_declared_key_ids_are_used_verbatim() {
    // The metadata must be indexed by the declared IDs, including the one
    // (`1b8fa2…`) whose recomputed ID `tough` complains about.
    let md = Metadata::<Root>::from_slice(GITHUB_ROOT).unwrap();
    let declared = "1b8fa2a77525b38ef24804d3d907ca96f76d178a49520333626ba36d319c5790";
    assert!(
        md.signed.keys.contains_key(declared),
        "declared key ID must be preserved as the map key"
    );

    // And that same key's *recomputed* ID (over {keytype, scheme, keyval}) is
    // the declared one — confirming the divergence is purely about which fields
    // enter the hash, not the key material.
    let key = &md.signed.keys[declared];
    assert_eq!(
        key.key_id().unwrap(),
        declared,
        "recomputed key ID over canonical {{keytype,scheme,keyval}} should match the declared ID"
    );
}

#[test]
fn tampering_with_signed_content_breaks_self_verification() {
    // Flip the consistent_snapshot flag in the signed body; signatures must then
    // fail to meet threshold.
    let text = std::str::from_utf8(GITHUB_ROOT).unwrap();
    let tampered = text.replace(
        "\"consistent_snapshot\": true",
        "\"consistent_snapshot\": false",
    );
    assert_ne!(tampered, text, "test setup: expected to mutate the root");
    let err = TrustedMetadataSet::from_root(tampered.as_bytes())
        .expect_err("tampered root must fail verification");
    let msg = err.to_string();
    assert!(
        msg.contains("threshold not met"),
        "expected threshold failure, got: {msg}"
    );
}
