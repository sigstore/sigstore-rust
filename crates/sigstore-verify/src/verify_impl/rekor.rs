//! Rekor transparency log entry validation
//!
//! This module handles validation of different Rekor entry types against
//! bundle content to ensure consistency.

use crate::artifact::PreparedArtifact;
use crate::error::{Error, Result};
use base64::Engine;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{
    Bundle, DerCertificate, DerPublicKey, HashAlgorithm, SignatureContent, TransparencyLogEntry,
};
use x509_cert::der::{Decode, Encode};

/// Verify that all log entries are consistent with the bundle's content and artifact
pub fn verify_tlog_consistency(bundle: &Bundle, artifact: &PreparedArtifact<'_>) -> Result<()> {
    verify_tlog_consistency_with_key(bundle, artifact, None)
}

/// Verify log-entry consistency when managed-key verification supplies the
/// public key that the bundle references only by hint.
pub(crate) fn verify_tlog_consistency_with_key(
    bundle: &Bundle,
    artifact: &PreparedArtifact<'_>,
    managed_key: Option<&DerPublicKey>,
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
                    "0.0.2" => verify_intoto_v002(entry, envelope, bundle, managed_key)?,
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

    // Verify that the signature in the bundle matches what's in Rekor
    // This prevents signature substitution attacks
    // IMPORTANT: We must verify BOTH the signature bytes AND the verifier (certificate)
    // The bundle's envelope holds exactly one signature by construction.
    if rekor_signatures.len() != 1 {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has 1, Rekor entry has {}",
            rekor_signatures.len()
        )));
    }
    let rekor_sig = &rekor_signatures[0];

    if envelope.signature.sig.as_bytes() != rekor_sig.signature.as_bytes() {
        return Err(Error::Verification(
            "DSSE signature in bundle does not match any signature in Rekor entry (signature or verifier mismatch)".to_string(),
        ));
    }
    if let Some(cert) = &bundle_cert {
        // Convert Rekor's PEM verifier to DER for canonical comparison
        let rekor_cert_der = rekor_sig
            .to_certificate()
            .map_err(|e| Error::Verification(format!("{}", e)))?;
        if cert.as_bytes() != rekor_cert_der.as_bytes() {
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
    bundle: &Bundle,
    managed_key: Option<&DerPublicKey>,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (rekor_envelope, payload_hash) = match &body {
        RekorEntryBody::IntotoV002(intoto_body) => (
            &intoto_body.spec.content.envelope,
            &intoto_body.spec.content.payload_hash,
        ),
        _ => {
            return Err(Error::Verification(
                "expected Intoto v0.0.2 body, got different type".to_string(),
            ))
        }
    };

    if payload_hash.algorithm != HashAlgorithm::Sha2256 {
        return Err(Error::Verification(format!(
            "unsupported intoto payload hash algorithm: {}",
            payload_hash.algorithm
        )));
    }
    let expected_payload_hash = payload_hash
        .value
        .decode()
        .map_err(|e| Error::Verification(format!("invalid intoto payload hash: {}", e)))?;
    let actual_payload_hash = sigstore_crypto::sha256(envelope.payload.as_bytes());
    if actual_payload_hash.as_bytes() != expected_payload_hash.as_slice() {
        return Err(Error::Verification(
            "DSSE payload hash does not match intoto Rekor entry".to_string(),
        ));
    }

    if envelope.payload_type != rekor_envelope.payload_type {
        return Err(Error::Verification(format!(
            "DSSE payload type mismatch: bundle has {:?}, Rekor entry has {:?}",
            envelope.payload_type, rekor_envelope.payload_type
        )));
    }

    let expected_public_key = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            let certificate = certificates.first().ok_or_else(|| {
                Error::Verification("bundle certificate chain is empty".to_string())
            })?;
            certificate_public_key(&certificate.raw_bytes)?
        }
        VerificationMaterialContent::Certificate(cert) => certificate_public_key(&cert.raw_bytes)?,
        VerificationMaterialContent::PublicKey { .. } => managed_key.cloned().ok_or_else(|| {
            Error::Verification(
                "intoto Rekor signature cannot be bound without the managed public key".to_string(),
            )
        })?,
    };

    let [rekor_sig] = rekor_envelope.signatures.as_slice() else {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has 1, Rekor entry has {}",
            rekor_envelope.signatures.len()
        )));
    };

    // Rekor's signature field contains an additional base64 layer in canonical
    // intoto/0.0.2 entries.
    let rekor_sig_decoded = base64::engine::general_purpose::STANDARD
        .decode(rekor_sig.sig.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to decode Rekor signature: {e}")))?;
    if envelope.signature.sig.as_bytes() != rekor_sig_decoded.as_slice() {
        return Err(Error::Verification(
            "DSSE signature in bundle does not match the intoto Rekor signature".to_string(),
        ));
    }

    let rekor_public_key = match rekor_sig.to_certificate() {
        Ok(certificate) => certificate_public_key(&certificate)?,
        Err(_) => rekor_sig
            .to_public_key()
            .map_err(|e| Error::Verification(e.to_string()))?,
    };
    if rekor_public_key.as_bytes() != expected_public_key.as_bytes() {
        return Err(Error::Verification(
            "DSSE signing certificate does not match the intoto Rekor verifier".to_string(),
        ));
    }

    Ok(())
}

fn certificate_public_key(certificate: &DerCertificate) -> Result<DerPublicKey> {
    let certificate = x509_cert::Certificate::from_der(certificate.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to parse signing certificate: {e}")))?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| {
            Error::Verification(format!(
                "failed to encode signing certificate public key: {e}"
            ))
        })?;
    Ok(DerPublicKey::new(spki))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::{Artifact, Bundle, CanonicalizedBody, Sha256Hash};

    const CANONICAL_INTOTO_BUNDLE: &str =
        include_str!("../../test_data/bundles/sigstore.js@2.0.0-provenance.sigstore.json");

    fn bundle() -> Bundle {
        Bundle::from_json(CANONICAL_INTOTO_BUNDLE).unwrap()
    }

    fn mutate_body(bundle: &mut Bundle, mutation: impl FnOnce(&mut serde_json::Value)) {
        let entry = &mut bundle.verification_material.tlog_entries[0];
        let mut body: serde_json::Value =
            serde_json::from_slice(entry.canonicalized_body.as_bytes()).unwrap();
        mutation(&mut body);
        entry.canonicalized_body = CanonicalizedBody::new(serde_json::to_vec(&body).unwrap());
    }

    fn verify_consistency(bundle: &Bundle) -> Result<()> {
        let digest = [0u8; 32];
        let artifact =
            PreparedArtifact::from_artifact(Artifact::from(Sha256Hash::from_bytes(digest)));
        verify_tlog_consistency(bundle, &artifact)
    }

    #[test]
    fn canonical_intoto_entry_matches_bundle() {
        verify_consistency(&bundle()).unwrap();
    }

    #[test]
    fn canonical_intoto_entry_binds_managed_public_key() {
        let mut bundle = bundle();
        let certificate = match &bundle.verification_material.content {
            VerificationMaterialContent::Certificate(cert) => cert.raw_bytes.clone(),
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                certificates[0].raw_bytes.clone()
            }
            VerificationMaterialContent::PublicKey { .. } => {
                panic!("fixture must use a certificate")
            }
        };
        let public_key = certificate_public_key(&certificate).unwrap();
        bundle.verification_material.content = VerificationMaterialContent::PublicKey {
            hint: sigstore_crypto::sha256(public_key.as_bytes()).to_base64(),
        };
        let digest = [0u8; 32];
        let artifact =
            PreparedArtifact::from_artifact(Artifact::from(Sha256Hash::from_bytes(digest)));
        verify_tlog_consistency_with_key(&bundle, &artifact, Some(&public_key)).unwrap();

        let wrong_key = DerPublicKey::new(vec![1, 2, 3]);
        assert!(verify_tlog_consistency_with_key(&bundle, &artifact, Some(&wrong_key)).is_err());
    }

    #[test]
    fn canonical_intoto_entry_binds_payload_hash() {
        let mut bundle = bundle();
        mutate_body(&mut bundle, |body| {
            body["spec"]["content"]["payloadHash"]["value"] = "00".repeat(32).into();
        });
        assert!(verify_consistency(&bundle).is_err());
    }

    #[test]
    fn canonical_intoto_entry_binds_payload_type() {
        let mut bundle = bundle();
        mutate_body(&mut bundle, |body| {
            body["spec"]["content"]["envelope"]["payloadType"] =
                "application/vnd.example+json".into();
        });
        assert!(verify_consistency(&bundle).is_err());
    }

    #[test]
    fn canonical_intoto_entry_binds_signature() {
        let mut bundle = bundle();
        mutate_body(&mut bundle, |body| {
            body["spec"]["content"]["envelope"]["signatures"][0]["sig"] = "YmFk".into();
        });
        assert!(verify_consistency(&bundle).is_err());
    }

    #[test]
    fn canonical_intoto_entry_binds_signing_certificate() {
        let mut bundle = bundle();
        mutate_body(&mut bundle, |body| {
            body["spec"]["content"]["envelope"]["signatures"][0]["publicKey"] = "YmFk".into();
        });
        assert!(verify_consistency(&bundle).is_err());
    }
}
