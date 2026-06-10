//! HashedRekord entry validation
//!
//! This module handles validation of hashedrekord entries, including
//! artifact hash verification and certificate/signature matching.

use crate::error::{Error, Result};
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Artifact, Bundle, Sha256Hash, SignatureContent, TransparencyLogEntry};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Verify artifact/dsse hash matches what's in Rekor (for hashedrekord entries)
/// Verify a single hashedrekord entry
pub(crate) fn verify_hashedrekord_entry(
    entry: &TransparencyLogEntry,
    bundle: &Bundle,
    artifact: &Artifact<'_>,
) -> Result<()> {
    // Parse the Rekor entry body (convert canonicalized body to base64 string)
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    // Compute hash from artifact (bytes or pre-computed digest) or DSSE envelope
    let hash = match &bundle.content {
        SignatureContent::MessageSignature(_) => compute_artifact_digest(artifact)?,
        SignatureContent::DsseEnvelope(envelope) => sigstore_crypto::sha256(&envelope.pae()),
    };

    // Validate artifact hash matches what's in Rekor
    match &body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: spec.data.hash.value (hex-encoded)
            let expected = Sha256Hash::from_hex(rekord.spec.data.hash.value.as_str())
                .map_err(|e| Error::Verification(format!("invalid hash in Rekor entry: {}", e)))?;
            validate_artifact_hash(&hash, &expected)?;
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.data.digest (Vec<u8>)
            let expected = Sha256Hash::try_from_slice(&rekord.spec.hashed_rekord_v002.data.digest)
                .map_err(|e| {
                    Error::Verification(format!("invalid digest in Rekor entry: {}", e))
                })?;
            validate_artifact_hash(&hash, &expected)?;
        }
        _ => {
            return Err(Error::Verification(format!(
                "expected HashedRekord body, got different type for version {}",
                entry.kind_version.version
            )));
        }
    };

    // Validate certificate matches
    validate_certificate_match(entry, &body, bundle)?;

    // Validate signature matches (for MessageSignature only)
    validate_signature_match(entry, &body, bundle)?;

    // Validate integrated time is within certificate validity (for v0.0.1)
    validate_integrated_time(entry, bundle)?;

    // Perform cryptographic signature verification
    verify_signature_cryptographically(bundle, artifact)?;

    Ok(())
}

/// Compute the SHA-256 digest from an artifact for Rekor inclusion proof
fn compute_artifact_digest(artifact: &Artifact<'_>) -> Result<Sha256Hash> {
    match artifact {
        Artifact::Bytes(bytes) => Ok(sigstore_crypto::sha256(bytes)),
        Artifact::Digest(hash) => Sha256Hash::try_from_slice(hash).map_err(|_| {
            Error::Verification(
                "Rekor entry verification requires a 32-byte SHA-256 digest".to_string(),
            )
        }),
    }
}

/// Validate artifact hash matches expected hash
fn validate_artifact_hash(artifact_hash: &Sha256Hash, expected_hash: &Sha256Hash) -> Result<()> {
    if artifact_hash != expected_hash {
        return Err(Error::Verification(
            "artifact hash mismatch for hashedrekord entry".to_string(),
        ));
    }

    Ok(())
}

/// Validate that the certificate in Rekor matches the certificate in the bundle
fn validate_certificate_match(
    _entry: &TransparencyLogEntry,
    body: &RekorEntryBody,
    bundle: &Bundle,
) -> Result<()> {
    // Extract certificate DER from Rekor entry
    let rekor_cert_der_opt = match body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: parse PEM certificate from publicKey content
            let cert = rekord
                .spec
                .signature
                .public_key
                .to_certificate()
                .map_err(|e| Error::Verification(format!("{}", e)))?;
            Some(cert.as_bytes().to_vec())
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes (DerCertificate)
            rekord
                .spec
                .hashed_rekord_v002
                .signature
                .verifier
                .x509_certificate
                .as_ref()
                .map(|cert| cert.raw_bytes.as_bytes().to_vec())
        }
        _ => None,
    };

    if let Some(rekor_cert_der) = rekor_cert_der_opt {
        // Get the certificate from the bundle
        let bundle_cert = match &bundle.verification_material.content {
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                certificates.first().map(|c| &c.raw_bytes)
            }
            VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
            _ => None,
        };

        if let Some(bundle_cert) = bundle_cert {
            // Bundle certificate is DerCertificate, get raw bytes
            let bundle_cert_der = bundle_cert.as_bytes();

            // Compare certificates
            if bundle_cert_der != rekor_cert_der {
                return Err(Error::Verification(
                    "certificate in bundle does not match certificate in Rekor entry".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate that the signature in the bundle matches the signature in Rekor
fn validate_signature_match(
    _entry: &TransparencyLogEntry,
    body: &RekorEntryBody,
    bundle: &Bundle,
) -> Result<()> {
    // Extract signature from Rekor entry (SignatureBytes)
    let rekor_sig = match body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: spec.signature.content (SignatureBytes)
            Some(&rekord.spec.signature.content)
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.signature.content (SignatureBytes)
            Some(&rekord.spec.hashed_rekord_v002.signature.content)
        }
        _ => None,
    };

    if let Some(rekor_sig) = rekor_sig {
        // Get the signature from the bundle
        match &bundle.content {
            SignatureContent::MessageSignature(sig) => {
                let bundle_sig = &sig.signature;

                // Compare signatures (both are SignatureBytes)
                if bundle_sig != rekor_sig {
                    return Err(Error::Verification(
                        "signature in bundle does not match signature in Rekor entry".to_string(),
                    ));
                }
            }
            SignatureContent::DsseEnvelope(envelope) => {
                // Compare against the first DSSE envelope signature
                if let Some(first_sig) = envelope.signatures.first() {
                    if &first_sig.sig != rekor_sig {
                        return Err(Error::Verification(
                            "DSSE signature in bundle does not match signature in Rekor entry"
                                .to_string(),
                        ));
                    }
                } else {
                    return Err(Error::Verification(
                        "No signatures found in DSSE envelope".to_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Perform cryptographic verification of the signature over the artifact.
///
/// In Sigstore's hashedrekord format, the signature is created over the **artifact
/// itself**, not over the artifact's hash. The hash in the Rekor entry is used for
/// lookup/deduplication. The bundle and Rekor signatures are already checked to be
/// equal by [`validate_signature_match`], so verifying the bundle's signature here
/// (via the shared helper) is equivalent to verifying the Rekor one.
fn verify_signature_cryptographically(bundle: &Bundle, artifact: &Artifact<'_>) -> Result<()> {
    // Only verify for MessageSignature (not DSSE envelopes)
    let SignatureContent::MessageSignature(msg_sig) = &bundle.content else {
        return Ok(());
    };

    // Get the signing certificate from the bundle
    let bundle_cert = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            certificates.first().map(|c| &c.raw_bytes)
        }
        VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
        _ => None,
    };

    let Some(bundle_cert) = bundle_cert else {
        return Ok(());
    };

    let cert_info = sigstore_crypto::x509::parse_certificate_info(bundle_cert.as_bytes())?;
    crate::verify::verify_message_signature_crypto(&cert_info, msg_sig, artifact)
}

/// Validate that integrated time is within certificate validity period
fn validate_integrated_time(entry: &TransparencyLogEntry, bundle: &Bundle) -> Result<()> {
    let bundle_cert = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            certificates.first().map(|c| &c.raw_bytes)
        }
        VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
        _ => None,
    };

    if let Some(bundle_cert) = bundle_cert {
        let bundle_cert_der = bundle_cert.as_bytes();

        // Only validate integrated time for hashedrekord 0.0.1
        // For 0.0.2 (Rekor v2), integrated_time is not present (0)
        if entry.kind_version.version == "0.0.1" && entry.integrated_time != 0 {
            let cert = Certificate::from_der(bundle_cert_der).map_err(|e| {
                Error::Verification(format!(
                    "failed to parse certificate for time validation: {}",
                    e
                ))
            })?;

            // Convert certificate validity times to Unix timestamps
            use std::time::UNIX_EPOCH;
            let not_before_system = cert.tbs_certificate.validity.not_before.to_system_time();
            let not_after_system = cert.tbs_certificate.validity.not_after.to_system_time();

            let not_before = not_before_system
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    Error::Verification(format!("failed to convert notBefore to Unix time: {}", e))
                })?
                .as_secs() as i64;
            let not_after = not_after_system
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    Error::Verification(format!("failed to convert notAfter to Unix time: {}", e))
                })?
                .as_secs() as i64;

            let integrated_time = entry.integrated_time;

            if integrated_time < not_before || integrated_time > not_after {
                return Err(Error::Verification(format!(
                    "integrated time {} is outside certificate validity period ({} to {})",
                    integrated_time, not_before, not_after
                )));
            }
        }
    }

    Ok(())
}
