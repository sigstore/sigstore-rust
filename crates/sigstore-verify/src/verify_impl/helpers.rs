//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;
use rustls_pki_types::{CertificateDer, UnixTime};
use sigstore_crypto::CertificateInfo;
use sigstore_trust_root::{TrustedRoot, TsaAuthority};
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, DerCertificate, DerPublicKey, SignatureBytes, SignatureContent};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};

/// Extract and decode the signing certificate from verification material
pub fn extract_certificate(
    verification_material: &VerificationMaterialContent,
) -> Result<DerCertificate> {
    match verification_material {
        VerificationMaterialContent::Certificate(cert) => Ok(cert.raw_bytes.clone()),
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            Ok(certificates[0].raw_bytes.clone())
        }
        VerificationMaterialContent::PublicKey { .. } => Err(Error::Verification(
            "public key verification not yet supported".to_string(),
        )),
    }
}

/// Extract signature from bundle content (needed for TSA verification).
///
/// `DsseEnvelope` holds exactly one signature by construction, so timestamp
/// verification necessarily authenticates the signature used by the bundle.
pub fn extract_signature(content: &SignatureContent) -> SignatureBytes {
    match content {
        SignatureContent::MessageSignature(msg_sig) => msg_sig.signature.clone(),
        SignatureContent::DsseEnvelope(envelope) => envelope.signature.sig.clone(),
    }
}

/// Extract and verify TSA RFC 3161 timestamps
///
/// Every timestamp present in the bundle must be cryptographically
/// authenticated by one of the configured timestamp authorities, and its
/// signed time must fall within *that* authority's `valid_for` window (see
/// [`verify_timestamp_against_authorities`]). Returns every verified
/// timestamp; any timestamp that fails verification is an error.
pub fn extract_tsa_timestamps(
    bundle: &Bundle,
    signature_bytes: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<Vec<jiff::Timestamp>> {
    let rfc3161_timestamps = &bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps;

    if rfc3161_timestamps.is_empty() {
        return Ok(Vec::new());
    }

    let authorities = trusted_root.tsa_authorities();

    let mut timestamps = Vec::new();

    for ts in rfc3161_timestamps {
        timestamps.push(verify_timestamp_against_authorities(
            ts.signed_timestamp.as_bytes(),
            signature_bytes,
            &authorities,
        )?);
    }

    Ok(timestamps)
}

/// Verify a single RFC 3161 timestamp token against the configured timestamp
/// authorities, binding temporal authorization to the authority that signed it
/// (TOB-SIGSTORE-11).
///
/// Each authority is tried in isolation: the CMS signer certificate must be
/// that authority's leaf and the chain must terminate at that authority's
/// root. On success, ONLY that authority's window is consulted (via
/// [`TsaAuthority::authorizes`]; an absent window is unrestricted). A token
/// whose signing authority's window excludes the signed time is NOT rescued
/// by another authority's window: it is only accepted if some authority both
/// cryptographically verified it and temporally authorizes it.
fn verify_timestamp_against_authorities(
    ts_bytes: &[u8],
    signature_bytes: &[u8],
    authorities: &[TsaAuthority],
) -> Result<jiff::Timestamp> {
    use sigstore_tsa::{verify_timestamp_response, VerifyOpts as TsaVerifyOpts};

    // Signed time of a token that some authority authenticated but whose
    // window excludes it, kept for error reporting.
    let mut rejected_time = None;
    let mut last_error: Option<String> = None;

    for authority in authorities {
        let opts = TsaVerifyOpts::new()
            .with_root(authority.root.clone())
            .with_intermediates(authority.intermediates.clone())
            .with_tsa_certificates(vec![authority.leaf.clone()]);

        let result = match verify_timestamp_response(ts_bytes, signature_bytes, opts) {
            Ok(result) => result,
            Err(e) => {
                last_error = Some(e.to_string());
                continue;
            }
        };

        // The token is cryptographically bound to this authority: consult
        // only this authority's validity window.
        if authority.authorizes(result.time) {
            return Ok(result.time);
        }
        rejected_time = Some(result.time);
    }

    if let Some(time) = rejected_time {
        return Err(Error::Verification(format!(
            "TSA timestamp {} is outside the validity period of the timestamp authority that signed it",
            time
        )));
    }

    Err(Error::Verification(format!(
        "TSA timestamp verification failed: {}",
        last_error
            .unwrap_or_else(|| "no timestamp authorities configured in trusted root".to_string())
    )))
}

/// Check if bundle contains V2 tlog entries (hashedrekord/dsse v0.0.2)
/// V2 entries have no integrated time and require RFC3161 timestamps
pub fn has_v2_tlog_entries(bundle: &Bundle) -> bool {
    bundle
        .verification_material
        .tlog_entries
        .iter()
        .any(|entry| entry.kind_version.version == "0.0.2")
}

/// Extract integrated time from V1 tlog entries that have inclusion promises.
///
/// Per sigstore-python, integrated_time is only valid as a timestamp source when:
/// 1. The entry has an inclusion_promise (SET) that cryptographically binds it
/// 2. The entry is a V1 type (hashedrekord/dsse v0.0.1)
/// 3. The entry carries an integrated time
///
/// The SET is verified here, before the integrated time is trusted: the SET
/// signature covers `integratedTime`, so this is what authenticates the
/// timestamp. Without it a tampered (e.g. backdated) `integratedTime` would
/// become the validation time whenever transparency log verification is
/// disabled or reordered. An entry that qualifies as a timestamp source but
/// whose SET does not verify is a hard error, not a skipped candidate.
///
/// Returns every authenticated integrated time.
fn extract_v1_integrated_times_with_promise(
    bundle: &Bundle,
    trusted_root: &TrustedRoot,
) -> Result<Vec<jiff::Timestamp>> {
    let mut times = Vec::new();

    for entry in &bundle.verification_material.tlog_entries {
        // Only V1 entries (0.0.1) with inclusion promises are valid timestamp sources
        let is_v1 = entry.kind_version.version == "0.0.1"
            && (entry.kind_version.kind == "hashedrekord" || entry.kind_version.kind == "dsse");

        if !is_v1 || entry.inclusion_promise.is_none() {
            continue;
        }

        if let Some(time) = entry.integrated_time {
            crate::verify_impl::tlog::verify_set(entry, trusted_root)?;
            times.push(time);
        }
    }

    Ok(times)
}

/// Collect every verified timestamp for the signature.
///
/// At least one verified timestamp source is REQUIRED. This matches sigstore-python's
/// behavior which enforces `VERIFIED_TIME_THRESHOLD = 1`.
///
/// Timestamp sources:
/// - TSA timestamps (RFC 3161), verified against the trusted root's TSA certificates
/// - Integrated times from V1 tlog entries with inclusion promises, authenticated
///   via their SET
///
/// All verified timestamps are returned (never an empty vector), and the caller
/// must validate the signing certificate against **each** of them: checking only
/// one (e.g. the earliest) would let a single backdated-but-verifiable timestamp
/// mask another timestamp that falls outside the certificate's validity.
///
/// Note: There is NO fallback to current time. If no verified timestamp is found,
/// verification fails.
///
/// Both sources are always collected; there is no TSA-else-Rekor short circuit.
/// A timestamp source that is present but does not verify is a hard error, so a
/// bundle is rejected even when its *other* source would have been sufficient on
/// its own - an unverifiable SET is fatal despite a valid TSA timestamp, and vice
/// versa. This is deliberately stricter than sigstore-python, which discards
/// sources that fail to verify and then applies `VERIFIED_TIME_THRESHOLD = 1`.
/// It also applies when the caller passed
/// [`skip_tlog_unsafe`](crate::VerificationPolicy::skip_tlog_unsafe): that flag
/// skips inclusion proofs and checkpoints, not SET authentication.
pub fn determine_validation_times(
    bundle: &Bundle,
    signature: &SignatureBytes,
    trusted_root: &TrustedRoot,
) -> Result<Vec<jiff::Timestamp>> {
    let mut times = extract_tsa_timestamps(bundle, signature.as_bytes(), trusted_root)?;
    times.extend(extract_v1_integrated_times_with_promise(
        bundle,
        trusted_root,
    )?);

    if !times.is_empty() {
        return Ok(times);
    }

    // No verified timestamp found - fail verification
    // This matches sigstore-python's behavior: "not enough sources of verified time"
    let is_v2 = has_v2_tlog_entries(bundle);
    if is_v2 {
        Err(Error::Verification(
            "V2 bundle requires RFC3161 timestamp but none could be verified. \
             V2 tlog entries have no integrated time by design. \
             Ensure TSA certificates are present in the trusted root."
                .to_string(),
        ))
    } else {
        Err(Error::Verification(
            "No verified timestamp found. V1 bundles require either an RFC3161 timestamp \
             or a tlog entry with both an integrated time and an inclusion_promise (SET)."
                .to_string(),
        ))
    }
}

/// Validate certificate is within validity period
pub fn validate_certificate_time(
    validation_time: jiff::Timestamp,
    cert_info: &CertificateInfo,
) -> Result<()> {
    if validation_time < cert_info.not_before {
        return Err(Error::Verification(format!(
            "certificate not yet valid: validation time {} is before not_before {}",
            validation_time, cert_info.not_before
        )));
    }

    if validation_time > cert_info.not_after {
        return Err(Error::Verification(format!(
            "certificate has expired: validation time {} is after not_after {}",
            validation_time, cert_info.not_after
        )));
    }

    Ok(())
}

/// Verify the certificate chain to the Fulcio root of trust
///
/// This function verifies that the signing certificate chains to a trusted
/// Fulcio root certificate at the given verification time. It also verifies
/// that the certificate has the CODE_SIGNING extended key usage.
///
/// On success, returns the SubjectPublicKeyInfo of the leaf's direct issuer
/// taken from the *verified* path. This is the canonical source for the issuer
/// used by SCT verification: it is the certificate webpki proved signed the
/// leaf, so it disambiguates Fulcio intermediates that share a subject name but
/// have different keys (as in Sigstore staging's multi-region deployment).
pub fn verify_certificate_chain(
    verification_material: &VerificationMaterialContent,
    validation_time: jiff::Timestamp,
    trusted_root: &TrustedRoot,
) -> Result<DerPublicKey> {
    // Extract the end-entity certificate and any intermediates from the bundle
    let (ee_cert_der, intermediate_ders) = match verification_material {
        VerificationMaterialContent::Certificate(cert) => {
            (cert.raw_bytes.as_bytes().to_vec(), Vec::new())
        }
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            let ee = certificates[0].raw_bytes.as_bytes().to_vec();
            let intermediates: Vec<Vec<u8>> = certificates[1..]
                .iter()
                .map(|c| c.raw_bytes.as_bytes().to_vec())
                .collect();
            (ee, intermediates)
        }
        VerificationMaterialContent::PublicKey { .. } => {
            return Err(Error::Verification(
                "public key verification not yet supported".to_string(),
            ));
        }
    };

    // Get Fulcio certificates from trusted root to use as trust anchors
    let fulcio_certs = trusted_root.fulcio_certs();

    if fulcio_certs.is_empty() {
        return Err(Error::Verification(
            "no Fulcio certificates in trusted root".to_string(),
        ));
    }

    // Build trust anchors from Fulcio root certificates
    let trust_anchors: Vec<_> = fulcio_certs
        .iter()
        .filter_map(|cert_der| {
            let cert = CertificateDer::from(&cert_der[..]);
            anchor_from_trusted_cert(&cert)
                .map(|anchor| anchor.to_owned())
                .ok()
        })
        .collect();

    if trust_anchors.is_empty() {
        return Err(Error::Verification(
            "failed to create trust anchors from Fulcio certificates".to_string(),
        ));
    }

    // Convert intermediate certificates to CertificateDer
    let intermediate_certs: Vec<CertificateDer<'static>> = intermediate_ders
        .into_iter()
        .map(|der| CertificateDer::from(der).into_owned())
        .collect();

    // Parse the end-entity certificate for webpki
    let ee_cert_der_ref = CertificateDer::from(ee_cert_der.as_slice());
    let end_entity_cert = EndEntityCert::try_from(&ee_cert_der_ref).map_err(|e| {
        Error::Verification(format!("failed to parse end-entity certificate: {}", e))
    })?;

    // Convert validation time to webpki UnixTime
    let verification_time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        validation_time.as_second() as u64,
    ));

    // Verify the certificate chain with CODE_SIGNING EKU
    // This performs:
    // - Chain building from end-entity to trust anchor
    // - Signature verification at each step
    // - Time validity checking
    // - Extended Key Usage validation (CODE_SIGNING)
    let path = end_entity_cert
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediate_certs,
            verification_time,
            KeyUsage::required(ID_KP_CODE_SIGNING.as_bytes()),
            None, // No CRL/OCSP revocation checking (matches sigstore-python)
            None, // No custom path validation callback needed
        )
        .map_err(|e| Error::Verification(format!("certificate chain validation failed: {}", e)))?;

    tracing::debug!("Certificate chain validated successfully with CODE_SIGNING EKU");

    issuer_spki_from_path(&path)
}

/// Extract the leaf's direct-issuer SubjectPublicKeyInfo (full DER) from a
/// webpki-verified path.
///
/// The direct issuer is the leaf-proximal intermediate, or the trust anchor
/// itself when the leaf was signed directly by an anchor — which is the common
/// case for Sigstore, since Fulcio intermediates are shipped as trust anchors.
fn issuer_spki_from_path(path: &webpki::VerifiedPath) -> Result<DerPublicKey> {
    let der = match path.intermediate_certificates().next() {
        // `Cert::subject_public_key_info()` already returns the full SPKI SEQUENCE.
        Some(issuer) => issuer.subject_public_key_info().as_ref().to_vec(),
        None => {
            // webpki exposes the anchor SPKI as the SEQUENCE *contents* only, so
            // wrap it back into a SEQUENCE to get the full SubjectPublicKeyInfo.
            use x509_cert::der::{Any, Encode, Tag};
            let spki = path.anchor().subject_public_key_info.as_ref();
            Any::new(Tag::Sequence, spki)
                .and_then(|any| any.to_der())
                .map_err(|e| Error::Verification(format!("failed to encode issuer SPKI: {e}")))?
        }
    };
    Ok(DerPublicKey::new(der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::Bundle;

    /// The certificate must be validated against *every* verified timestamp
    /// in the bundle, so the timestamp collector must not collapse multiple
    /// sources into one. This bundle carries both a TSA timestamp and a
    /// SET-authenticated v1 integratedTime.
    #[test]
    fn determine_validation_times_returns_all_verified_sources() {
        let trusted_root =
            TrustedRoot::from_json(sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
        let bundle = Bundle::from_json(include_str!(
            "../../test_data/bundles/cosign-v3-blob.sigstore.json"
        ))
        .unwrap();
        let signature = extract_signature(&bundle.content);

        let times = determine_validation_times(&bundle, &signature, &trusted_root).unwrap();

        assert_eq!(
            times.len(),
            2,
            "expected one TSA timestamp and one integratedTime, got {times:?}"
        );
        let integrated_time = bundle.verification_material.tlog_entries[0]
            .integrated_time
            .unwrap();
        assert!(times.contains(&integrated_time));
    }

    /// Regression test for the Sigstore staging multi-region rollout (July 2026).
    ///
    /// Staging began issuing certificates from a second Fulcio intermediate that
    /// shares the subject `CN=sigstore-intermediate` with the pre-existing 2022
    /// intermediate but has a different key. SCT verification used to resolve the
    /// issuer from the trusted root by subject *name* and picked the first (wrong)
    /// intermediate, so the reconstructed `issuer_key_hash` was wrong and SCT
    /// verification failed with a spurious "ECDSA P-256 SHA-256 signature invalid"
    /// error. Sourcing the issuer from the webpki-verified chain fixes it, because
    /// the verified path identifies the certificate that actually signed the leaf.
    ///
    /// The trusted root and bundle fixtures are the real staging artifacts from
    /// the failing tuf-on-ci smoke test run.
    #[test]
    fn sct_verifies_with_multiple_same_named_intermediates() {
        // The leaf's SCT timestamp / notBefore; used as the chain validation time.
        let validation_time = jiff::Timestamp::from_second(1_783_488_311).unwrap();

        let trusted_root = TrustedRoot::from_json(include_str!(
            "../../test_data/sct-multi-intermediate/staging_trusted_root.json"
        ))
        .expect("failed to load staging trusted root");
        let bundle = Bundle::from_json(include_str!(
            "../../test_data/sct-multi-intermediate/staging_bundle.sigstore.json"
        ))
        .expect("failed to parse staging bundle");
        let material = &bundle.verification_material.content;

        // Sanity check: the trusted root really does contain two Fulcio
        // intermediates that share the same subject name, which is the
        // condition that triggered the bug.
        use x509_cert::der::Decode;
        use x509_cert::Certificate;
        let same_named_intermediates = trusted_root
            .fulcio_certs()
            .iter()
            .filter_map(|der| Certificate::from_der(der).ok())
            .filter(|c| {
                c.tbs_certificate
                    .subject
                    .to_string()
                    .contains("sigstore-intermediate")
            })
            .count();
        assert!(
            same_named_intermediates >= 2,
            "fixture must contain multiple sigstore-intermediate CAs to exercise the bug, found {same_named_intermediates}"
        );

        // The canonical flow: the issuer comes from the verified chain, then SCT
        // verification uses it. Before the fix, SCT verification returned
        // Err("SCT signature verification failed: ... signature invalid").
        let issuer_spki = verify_certificate_chain(material, validation_time, &trusted_root)
            .expect("certificate chain should verify against the staging root");
        let cert = extract_certificate(material).unwrap();
        super::super::sct::verify_sct(cert.as_bytes(), issuer_spki.as_bytes(), &trusted_root)
            .expect("SCT verification should succeed once the correct issuer is selected");
    }

    /// Tests for TOB-SIGSTORE-11: an RFC 3161 timestamp must be temporally
    /// authorized by the `valid_for` window of the exact timestamp authority
    /// that signed it — never by an unrelated authority's window.
    mod tsa_authority_binding {
        use super::*;
        use serde_json::{json, Value};

        // Conformance fixtures shared with `sigstore-tsa`: a bundle carrying a
        // single RFC 3161 timestamp and the trusted root of the TSA that
        // issued it (leaf + self-signed root, `validFor.start` only).
        const TSA_BUNDLE: &str = include_str!("../../test_data/timestamps/valid_bundle.json");
        const TSA_TRUSTED_ROOT: &str =
            include_str!("../../test_data/timestamps/valid_trusted_root.json");
        // GitHub's TSA trust root (five authorities with overlapping windows)
        // and a real GitHub-issued attestation bundle.
        const GITHUB_TSA_BUNDLE: &str =
            include_str!("../../test_data/timestamps/github_sha384_bundle.json");
        const GITHUB_TRUSTED_ROOT: &str =
            include_str!("../../test_data/timestamps/github_trusted_root.json");

        fn verify_bundle_timestamp(root: &TrustedRoot) -> Result<Option<i64>> {
            let bundle = Bundle::from_json(TSA_BUNDLE).unwrap();
            let signature = extract_signature(&bundle.content);
            let timestamps = extract_tsa_timestamps(&bundle, signature.as_bytes(), root)?;
            Ok(timestamps.first().map(|t| t.as_second()))
        }

        /// The token's signed time (whole seconds; the fixture's genTime has
        /// no fractional part), derived by verifying against the pristine
        /// trusted root.
        fn token_time() -> i64 {
            let root = TrustedRoot::from_json(TSA_TRUSTED_ROOT).unwrap();
            verify_bundle_timestamp(&root)
                .expect("fixture bundle should verify against its own trusted root")
                .expect("fixture bundle carries a timestamp")
        }

        fn iso(seconds: i64) -> String {
            jiff::Timestamp::from_second(seconds).unwrap().to_string()
        }

        /// Rebuild the fixture trusted root with the signing authority's
        /// `validFor` window replaced (or removed), optionally appending
        /// extra timestamp authorities.
        fn root_with(valid_for: Option<Value>, extra_authorities: Vec<Value>) -> TrustedRoot {
            let mut root: Value = serde_json::from_str(TSA_TRUSTED_ROOT).unwrap();
            let tsas = root["timestampAuthorities"].as_array_mut().unwrap();
            match valid_for {
                Some(window) => tsas[0]["validFor"] = window,
                None => {
                    tsas[0].as_object_mut().unwrap().remove("validFor");
                }
            }
            tsas.extend(extra_authorities);
            TrustedRoot::from_json(&root.to_string()).unwrap()
        }

        /// A real but unrelated timestamp authority (GitHub's TSA) with the
        /// given `validFor` window. Its chain verifies nothing signed by the
        /// fixture TSA.
        fn unrelated_authority(valid_for: Value) -> Value {
            let github: Value = serde_json::from_str(GITHUB_TRUSTED_ROOT).unwrap();
            let mut tsa = github["timestampAuthorities"][0].clone();
            tsa["validFor"] = valid_for;
            tsa
        }

        #[test]
        fn accepts_token_within_signing_authoritys_window() {
            let time = token_time();
            let covering = json!({ "start": iso(time - 3600), "end": iso(time + 3600) });
            // The unrelated authority's presence must not disturb acceptance.
            let root = root_with(Some(covering.clone()), vec![unrelated_authority(covering)]);
            assert_eq!(verify_bundle_timestamp(&root).unwrap(), Some(time));
        }

        #[test]
        fn accepts_token_from_authority_without_validity_window() {
            // An absent `valid_for` window means the authority is unrestricted.
            let root = root_with(None, vec![]);
            assert_eq!(verify_bundle_timestamp(&root).unwrap(), Some(token_time()));
        }

        #[test]
        fn accepts_token_exactly_at_window_boundaries() {
            // `ValidityPeriod::contains` is inclusive on both ends.
            let time = token_time();
            let root = root_with(
                Some(json!({ "start": iso(time), "end": iso(time) })),
                vec![],
            );
            assert_eq!(verify_bundle_timestamp(&root).unwrap(), Some(time));
        }

        #[test]
        fn rejects_token_just_outside_window_boundary() {
            let time = token_time();
            let root = root_with(
                Some(json!({ "start": iso(time - 3600), "end": iso(time - 1) })),
                vec![],
            );
            let err = verify_bundle_timestamp(&root).unwrap_err();
            assert!(
                err.to_string().contains("outside the validity period"),
                "unexpected error: {err}"
            );
        }

        /// The finding's core scenario: the signing authority's window
        /// excludes the token, and an unrelated authority's covering window
        /// must NOT lend it temporal authorization.
        #[test]
        fn rejects_token_outside_its_authoritys_window_despite_unrelated_covering_authority() {
            let time = token_time();
            let excluding = json!({ "start": iso(time - 7200), "end": iso(time - 3600) });
            let covering = json!({ "start": iso(time - 3600), "end": iso(time + 3600) });
            let root = root_with(Some(excluding), vec![unrelated_authority(covering)]);
            let err = verify_bundle_timestamp(&root).unwrap_err();
            assert!(
                err.to_string().contains("outside the validity period"),
                "unexpected error: {err}"
            );
        }

        /// Trail of Bits' exact reproducer: an authority entry with an EMPTY
        /// certificate chain and a covering window used to authorize a token
        /// that was rejected under its actual signer's window.
        #[test]
        fn rejects_empty_chain_authority_lending_its_window() {
            let time = token_time();
            let excluding = json!({ "start": iso(time - 7200), "end": iso(time - 3600) });
            let empty_chain_authority = json!({
                "certChain": { "certificates": [] },
                "validFor": { "start": iso(time - 3600), "end": iso(time + 3600) },
            });
            let root = root_with(Some(excluding), vec![empty_chain_authority]);
            let err = verify_bundle_timestamp(&root).unwrap_err();
            assert!(
                err.to_string().contains("outside the validity period"),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn rejects_token_signed_by_no_configured_authority() {
            let time = token_time();
            let covering = json!({ "start": iso(time - 3600), "end": iso(time + 3600) });
            // Replace the signing authority entirely with an unrelated one
            // whose window covers the token.
            let mut root: Value = serde_json::from_str(TSA_TRUSTED_ROOT).unwrap();
            root["timestampAuthorities"] = json!([unrelated_authority(covering)]);
            let root = TrustedRoot::from_json(&root.to_string()).unwrap();
            let err = verify_bundle_timestamp(&root).unwrap_err();
            assert!(
                err.to_string()
                    .contains("TSA timestamp verification failed"),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn rejects_token_when_no_authorities_configured() {
            let mut root: Value = serde_json::from_str(TSA_TRUSTED_ROOT).unwrap();
            root["timestampAuthorities"] = json!([]);
            let root = TrustedRoot::from_json(&root.to_string()).unwrap();
            let err = verify_bundle_timestamp(&root).unwrap_err();
            assert!(
                err.to_string()
                    .contains("no timestamp authorities configured"),
                "unexpected error: {err}"
            );
        }

        /// Multi-authority selection against real data: GitHub's trust root
        /// configures five TSA entries with overlapping epochs, and the token
        /// must be matched to (and authorized by) the one that signed it.
        #[test]
        fn selects_signing_authority_among_many_real_authorities() {
            let bundle = Bundle::from_json(GITHUB_TSA_BUNDLE).unwrap();
            let signature = extract_signature(&bundle.content);
            let root = TrustedRoot::from_json(GITHUB_TRUSTED_ROOT).unwrap();
            let timestamps = extract_tsa_timestamps(&bundle, signature.as_bytes(), &root)
                .expect("GitHub bundle timestamp should verify");
            let time = timestamps
                .first()
                .expect("GitHub bundle carries a timestamp");
            assert!(time.as_second() > 0);
        }
    }
}
