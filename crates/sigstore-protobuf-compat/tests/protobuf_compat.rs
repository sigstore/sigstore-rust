//! Wire-format compatibility with the canonical Sigstore protobuf definitions.
//!
//! For every fixture, four properties are checked against the generated
//! `sigstore_protobuf_specs` types (prost + pbjson, i.e. spec-faithful
//! protobuf JSON):
//!
//! 1. The fixture parses with the generated types (fixture sanity).
//! 2. Our type parses the fixture and its re-serialization is *accepted* by
//!    the generated types — pbjson rejects unknown fields, so misnamed or
//!    invented fields fail here.
//! 3. Parsing our re-serialization with the generated types yields a value
//!    structurally equal to parsing the fixture directly — we drop or
//!    corrupt nothing the protobuf schema considers meaningful. Using the
//!    prost types as the equality oracle makes proto3 default-elision
//!    (omitted vs. zero-valued fields) a non-issue.
//! 4. Our type parses the *canonical* protobuf JSON emitted by the generated
//!    types — we tolerate default-field elision and canonical encodings.

use serde::de::DeserializeOwned;
use serde::Serialize;

use sigstore_protobuf_specs::dev::sigstore::bundle::v1::Bundle as PbBundle;
use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::SigningConfig as PbSigningConfig;
use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::TrustedRoot as PbTrustedRoot;

use sigstore_trust_root::{SigningConfig, TrustedRoot};
use sigstore_types::Bundle;

/// See module docs for the four properties this enforces.
///
/// `normalize` runs on both parsed protobuf values before comparison, to
/// collapse encodings that differ in representation but not in meaning
/// (proto3 message-field presence vs. an all-defaults message).
fn check<Ours, Pb>(name: &str, fixture: &str, normalize: impl Fn(&mut Pb))
where
    Ours: Serialize + DeserializeOwned,
    Pb: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    // (1) the fixture itself is valid protobuf JSON
    let mut canonical: Pb = serde_json::from_str(fixture)
        .unwrap_or_else(|e| panic!("{name}: fixture rejected by protobuf-specs types: {e}"));

    // (2) our roundtrip is valid protobuf JSON
    let ours: Ours = serde_json::from_str(fixture)
        .unwrap_or_else(|e| panic!("{name}: fixture rejected by our types: {e}"));
    let reserialized = serde_json::to_string(&ours)
        .unwrap_or_else(|e| panic!("{name}: serialization failed: {e}"));
    let mut via_ours: Pb = serde_json::from_str(&reserialized).unwrap_or_else(|e| {
        panic!("{name}: our serialization rejected by protobuf-specs types: {e}\n{reserialized}")
    });

    // (3) no data lost or corrupted by our roundtrip
    normalize(&mut canonical);
    normalize(&mut via_ours);
    if canonical != via_ours {
        let expected = serde_json::to_value(&canonical).unwrap();
        let actual = serde_json::to_value(&via_ours).unwrap();
        let mut diffs = Vec::new();
        json_diff("$", &expected, &actual, &mut diffs);
        panic!(
            "{name}: data differs after roundtrip through our types:\n{}",
            diffs.join("\n")
        );
    }

    // (4) we accept canonical protobuf JSON (with default fields elided)
    let canonical_json = serde_json::to_string(&canonical)
        .unwrap_or_else(|e| panic!("{name}: protobuf-specs serialization failed: {e}"));
    let _: Ours = serde_json::from_str(&canonical_json).unwrap_or_else(|e| {
        panic!("{name}: canonical protobuf JSON rejected by our types: {e}\n{canonical_json}")
    });
}

/// Collect human-readable paths where two JSON values differ.
fn json_diff(
    path: &str,
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    out: &mut Vec<String>,
) {
    use serde_json::Value;
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for key in e.keys().chain(a.keys().filter(|k| !e.contains_key(*k))) {
                let sub = format!("{path}.{key}");
                match (e.get(key), a.get(key)) {
                    (Some(ev), Some(av)) => json_diff(&sub, ev, av, out),
                    (Some(ev), None) => out.push(format!("{sub}: missing (expected {ev})")),
                    (None, Some(av)) => out.push(format!("{sub}: unexpected (got {av})")),
                    (None, None) => unreachable!(),
                }
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                out.push(format!("{path}: length {} != {}", e.len(), a.len()));
            }
            for (i, (ev, av)) in e.iter().zip(a.iter()).enumerate() {
                json_diff(&format!("{path}[{i}]"), ev, av, out);
            }
        }
        (e, a) if e != a => {
            let (mut es, mut as_) = (e.to_string(), a.to_string());
            es.truncate(120);
            as_.truncate(120);
            out.push(format!("{path}: expected {es} != actual {as_}"));
        }
        _ => {}
    }
}

fn check_bundle(name: &str, fixture: &str) {
    check::<Bundle, PbBundle>(name, fixture, |bundle| {
        // An absent timestampVerificationData and a present-but-empty one are
        // semantically identical (no timestamps either way); our types always
        // materialize the field while protojson elides it when absent.
        // Collapse both spellings to None before comparing.
        if let Some(vm) = &mut bundle.verification_material {
            if vm
                .timestamp_verification_data
                .as_ref()
                .is_some_and(|t| t.rfc3161_timestamps.is_empty())
            {
                vm.timestamp_verification_data = None;
            }
        }
    });
}

fn check_exact<Ours, Pb>(name: &str, fixture: &str)
where
    Ours: Serialize + DeserializeOwned,
    Pb: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    check::<Ours, Pb>(name, fixture, |_| {});
}

// ==== Trusted roots (all embedded snapshots) ====

#[test]
fn trusted_root_production() {
    check_exact::<TrustedRoot, PbTrustedRoot>(
        "trusted_root.json",
        sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT,
    );
}

#[test]
fn trusted_root_staging() {
    check_exact::<TrustedRoot, PbTrustedRoot>(
        "trusted_root_staging.json",
        sigstore_trust_root::SIGSTORE_STAGING_TRUSTED_ROOT,
    );
}

#[test]
fn trusted_root_github() {
    check_exact::<TrustedRoot, PbTrustedRoot>(
        "trusted_root_github.json",
        sigstore_trust_root::SIGSTORE_GITHUB_TRUSTED_ROOT,
    );
}

// ==== Signing configs (all embedded snapshots) ====

#[test]
fn signing_config_production() {
    check_exact::<SigningConfig, PbSigningConfig>(
        "signing_config.json",
        sigstore_trust_root::SIGSTORE_PRODUCTION_SIGNING_CONFIG,
    );
}

#[test]
fn signing_config_staging() {
    check_exact::<SigningConfig, PbSigningConfig>(
        "signing_config_staging.json",
        sigstore_trust_root::SIGSTORE_STAGING_SIGNING_CONFIG,
    );
}

// ==== Bundles across versions, content types and verification materials ====

#[test]
fn bundle_v03_dsse_inclusion_proof() {
    check_bundle(
        "happy-path.json",
        include_str!("../../sigstore-bundle/tests/fixtures/happy-path.json"),
    );
}

#[test]
fn bundle_v03_message_signature() {
    check_bundle(
        "bundle_v3.json",
        include_str!("../../sigstore-bundle/tests/fixtures/bundle_v3.json"),
    );
}

#[test]
fn bundle_v03_dsse_github_attestation() {
    check_bundle(
        "conda-attestation.sigstore.json",
        include_str!("../../sigstore-verify/test_data/bundles/conda-attestation.sigstore.json"),
    );
}

#[test]
fn bundle_v03_hashedrekord_with_tsa() {
    check_bundle(
        "cosign-v3-blob.sigstore.json",
        include_str!("../../sigstore-verify/test_data/bundles/cosign-v3-blob.sigstore.json"),
    );
}

#[test]
fn bundle_v03_hashedrekord_v002_rekor2() {
    check_bundle(
        "conda-attestation-rekor2.sigstore.json",
        include_str!(
            "../../sigstore-verify/test_data/bundles/conda-attestation-rekor2.sigstore.json"
        ),
    );
}

#[test]
fn bundle_v01_x509_chain_dsse() {
    check_bundle(
        "dsse.sigstore.json",
        include_str!("../../sigstore-verify/test_data/bundles/dsse.sigstore.json"),
    );
}

#[test]
fn bundle_v02_github_whl() {
    check_bundle(
        "bundle_v3_github.whl.sigstore",
        include_str!("../../sigstore-verify/test_data/bundles/bundle_v3_github.whl.sigstore"),
    );
}
