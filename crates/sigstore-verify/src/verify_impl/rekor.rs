//! Rekor transparency log entry validation
//!
//! This module handles validation of different Rekor entry types against
//! bundle content to ensure consistency.

use crate::error::{Error, Result};
use base64::Engine;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, SignatureContent, TransparencyLogEntry};

/// Verify that all log entries are consistent with the bundle's content and artifact
pub fn verify_tlog_consistency(
    bundle: &Bundle,
    artifact: &sigstore_types::Artifact<'_>,
) -> Result<()> {
    for entry in &bundle.verification_material.tlog_entries {
        match &bundle.content {
            // DSSE envelope handling depends on Rekor version:
            // * Rekor 1 gives us a "dsse 0.0.1" entry (or "intoto 0.0.2")
            // * Rekor 2 gives us a "hashedrekord 0.0.2" entry
            SignatureContent::DsseEnvelope(envelope) => match entry.kind_version.kind.as_str() {
                "hashedrekord" => match entry.kind_version.version.as_str() {
                    "0.0.2" => {
                        super::hashedrekord::verify_hashedrekord_entry(entry, bundle, artifact)?;
                    }
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported hashedrekord entry version for DSSE envelope: {}",
                            version
                        )))
                    }
                },
                "dsse" => match entry.kind_version.version.as_str() {
                    "0.0.1" => verify_dsse_v001(entry, envelope, bundle)?,
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported dsse entry version: {}",
                            version
                        )))
                    }
                },
                "intoto" => match entry.kind_version.version.as_str() {
                    "0.0.2" => verify_intoto_v002(entry, envelope)?,
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported intoto entry version: {}",
                            version
                        )))
                    }
                },
                kind => {
                    return Err(Error::Verification(format!(
                        "unsupported log entry kind for DSSE envelope: {}",
                        kind
                    )))
                }
            },
            SignatureContent::MessageSignature(_) => match entry.kind_version.kind.as_str() {
                "hashedrekord" => match entry.kind_version.version.as_str() {
                    "0.0.1" | "0.0.2" => {
                        super::hashedrekord::verify_hashedrekord_entry(entry, bundle, artifact)?;
                    }
                    version => {
                        return Err(Error::Verification(format!(
                            "unsupported hashedrekord entry version: {}",
                            version
                        )))
                    }
                },
                kind => {
                    return Err(Error::Verification(format!(
                        "unsupported log entry kind for MessageSignature: {}",
                        kind
                    )))
                }
            },
        }
    }

    Ok(())
}

/// Verify DSSE v0.0.1 entry
///
/// NOTE: This does NOT verify the envelope hash.
/// The envelope hash in DSSE v0.0.1 entries cannot be reliably verified because:
/// 1. The hash is computed over uncanonicalized JSON during submission to Rekor
/// 2. JSON serialization can vary (field ordering, whitespace) between implementations
/// 3. We cannot reproduce the exact JSON representation that was originally submitted
///
/// Instead, we verify:
/// - Payload hash (hash of envelope.payload bytes)
/// - Signatures list matches between entry and envelope (both signature and verifier)
fn verify_dsse_v001(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
    bundle: &Bundle,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV001(dsse_body) => (
            &dsse_body.spec.payload_hash.value,
            &dsse_body.spec.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.1 body, got different type".to_string(),
            ))
        }
    };

    // Verify payload hash (v0.0.1 uses hex encoding)
    let payload_bytes = envelope.payload.as_bytes();
    let payload_hash = sigstore_crypto::sha256(payload_bytes);
    let payload_hash_hex = hex::encode(payload_hash);

    if &payload_hash_hex != expected_hash {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            payload_hash_hex, expected_hash
        )));
    }

    // Extract the signing certificate from the bundle. Key-based bundles
    // carry no certificate (the Rekor verifier is a public key), so only the
    // signature bytes can be compared for them.
    let bundle_cert = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            certificates.first().map(|c| c.raw_bytes.clone())
        }
        VerificationMaterialContent::Certificate(cert) => Some(cert.raw_bytes.clone()),
        VerificationMaterialContent::PublicKey { .. } => None,
    };

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    // IMPORTANT: We must verify BOTH the signature bytes AND the verifier (certificate)
    if envelope.signatures.len() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures.len(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    // We must match both the signature AND the verifier to prevent signature substitution
    for bundle_sig in &envelope.signatures {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            if bundle_sig.sig.as_bytes() != rekor_sig.signature.as_bytes() {
                continue;
            }
            match &bundle_cert {
                Some(cert) => {
                    // Convert Rekor's PEM verifier to DER for canonical comparison
                    let rekor_cert_der = rekor_sig
                        .to_certificate()
                        .map_err(|e| Error::Verification(format!("{}", e)))?;
                    if cert.as_bytes() == rekor_cert_der.as_bytes() {
                        found = true;
                        break;
                    }
                }
                None => {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry (signature or verifier mismatch)".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify intoto v0.0.2 entry
fn verify_intoto_v002(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (rekor_payload_b64, rekor_signatures) = match &body {
        RekorEntryBody::IntotoV002(intoto_body) => (
            &intoto_body.spec.content.envelope.payload,
            &intoto_body.spec.content.envelope.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected Intoto v0.0.2 body, got different type".to_string(),
            ))
        }
    };

    // The Rekor entry has the payload double-base64-encoded, decode it once
    let rekor_payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(rekor_payload_b64.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to decode Rekor payload: {}", e)))?;

    // Compare with bundle payload bytes
    if envelope.payload.as_bytes() != rekor_payload_bytes.as_slice() {
        return Err(Error::Verification(
            "DSSE payload in bundle does not match intoto Rekor entry".to_string(),
        ));
    }

    // Validate that the signatures match
    let mut found_match = false;
    for bundle_sig in &envelope.signatures {
        for rekor_sig in rekor_signatures {
            // The Rekor signature is also double-base64-encoded, decode it once
            let rekor_sig_decoded = base64::engine::general_purpose::STANDARD
                .decode(rekor_sig.sig.as_bytes())
                .map_err(|e| {
                    Error::Verification(format!("failed to decode Rekor signature: {}", e))
                })?;

            if bundle_sig.sig.as_bytes() == rekor_sig_decoded.as_slice() {
                found_match = true;
                break;
            }
        }
        if found_match {
            break;
        }
    }

    if !found_match {
        return Err(Error::Verification(
            "DSSE signature in bundle does not match intoto Rekor entry".to_string(),
        ));
    }

    Ok(())
}
