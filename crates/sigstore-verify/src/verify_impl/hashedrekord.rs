//! HashedRekord entry validation
//!
//! This module handles validation of hashedrekord entries, including
//! artifact hash verification and certificate/signature matching.

use crate::artifact::PreparedArtifact;
use crate::error::{Error, Result};
use sigstore_crypto::{parse_certificate_info, ArtifactHasher, KeyAlgorithm};
use sigstore_rekor::body::{HashedRekordV002Data, HashedRekordV002Verifier, RekorEntryBody};
use sigstore_rekor::RekorV2KeyDetails;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{
    Bundle, DerPublicKey, HashAlgorithm, KindVersion, Sha256Hash, SignatureContent,
    TransparencyLogEntry,
};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Verify a single hashedrekord entry's consistency against the bundle and
/// artifact: the artifact/DSSE hash, certificate, and signature recorded in
/// Rekor must match the bundle's materials.
///
/// This does NOT cryptographically verify the signature itself; that happens
/// unconditionally in `Verifier::verify` (step 7). Since the Rekor entry's
/// signature is checked for equality with the bundle's signature here, that
/// single verification covers both.
pub(crate) fn verify_hashedrekord_entry(
    entry: &TransparencyLogEntry,
    bundle: &Bundle,
    artifact: &PreparedArtifact<'_>,
    managed_key: Option<&DerPublicKey>,
) -> Result<()> {
    // Parse the Rekor entry body (convert canonicalized body to base64 string)
    let body = RekorEntryBody::parse(&entry.canonicalized_body, entry.kind_version)
        .map_err(|e| Error::malformed_entry(format!("failed to parse Rekor body: {}", e)))?;

    // Validate that the logged digest is the digest of this artifact or DSSE
    // envelope
    match &body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: spec.data.hash.value (hex-encoded SHA-256)
            let hash = match &bundle.content {
                SignatureContent::MessageSignature(_) => artifact.sha256()?,
                SignatureContent::DsseEnvelope(envelope) => {
                    sigstore_crypto::sha256(&envelope.pae())
                }
                _ => {
                    return Err(Error::UnsupportedBundle(
                        "unsupported bundle signature content".to_string(),
                    ))
                }
            };
            let expected =
                Sha256Hash::from_hex(rekord.spec.data.hash.value.as_str()).map_err(|e| {
                    Error::malformed_entry(format!("invalid hash in Rekor entry: {}", e))
                })?;
            validate_artifact_hash(hash.as_bytes(), expected.as_bytes())?;
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: the key details fix the digest algorithm. The logged key,
            // digest algorithm and digest length must all agree with them
            // before the digest itself is compared.
            let logged = &rekord.spec.hashed_rekord_v002;
            let algorithm = v002_digest_algorithm(logged)?;
            let hash = match &bundle.content {
                SignatureContent::MessageSignature(_) => artifact.digest(algorithm)?,
                SignatureContent::DsseEnvelope(envelope) => {
                    // The DSSE pre-authentication encoding is hashed with the
                    // signature's hash algorithm, e.g. SHA-384 for P-384.
                    let mut hasher = ArtifactHasher::new(algorithm)?;
                    hasher.update(&envelope.pae());
                    hasher.finalize()
                }
                _ => {
                    return Err(Error::UnsupportedBundle(
                        "unsupported bundle signature content".to_string(),
                    ))
                }
            };
            validate_artifact_hash(hash.as_bytes(), logged.data.digest.as_bytes())?;
        }
        _ => {
            return Err(Error::malformed_entry(format!(
                "expected HashedRekord body, got different type for version {}",
                entry.kind_version.version()
            )));
        }
    };

    // Validate certificate matches
    validate_verifier_match(entry, &body, bundle, managed_key)?;

    // Validate signature matches (for MessageSignature only)
    validate_signature_match(entry, &body, bundle)?;

    // Validate integrated time is within certificate validity (for v0.0.1)
    validate_integrated_time(entry, bundle)?;

    Ok(())
}

/// Validate artifact hash matches expected hash
fn validate_artifact_hash(artifact_hash: &[u8], expected_hash: &[u8]) -> Result<()> {
    if artifact_hash != expected_hash {
        return Err(Error::ArtifactMismatch(
            "artifact hash mismatch for hashedrekord entry".to_string(),
        ));
    }

    Ok(())
}

/// Check that a Rekor v2 entry's key details agree with the key it logs, its
/// digest algorithm and its digest length, and return the digest algorithm.
///
/// A Rekor v2 log derives the digest algorithm from the key details, so an
/// entry whose fields disagree was not produced by a conforming log for this
/// signature.
fn v002_digest_algorithm(logged: &HashedRekordV002Data) -> Result<HashAlgorithm> {
    let verifier = &logged.signature.verifier;
    let key_details = verifier.key_details;
    let expected_key = match key_details {
        RekorV2KeyDetails::PkixEcdsaP256Sha256 => KeyAlgorithm::EcdsaP256,
        RekorV2KeyDetails::PkixEcdsaP384Sha384 => KeyAlgorithm::EcdsaP384,
        other => {
            return Err(Error::UnsupportedBundle(format!(
                "unsupported Rekor v2 key details: {other}"
            )))
        }
    };

    let logged_key = logged_key_algorithm(verifier)?;
    if logged_key != expected_key {
        return Err(Error::entry_mismatch(format!(
            "Rekor entry key details {key_details} do not match its {logged_key:?} key"
        )));
    }

    let algorithm = key_details.hash_algorithm();
    if logged.data.algorithm != algorithm {
        return Err(Error::entry_mismatch(format!(
            "Rekor entry digest algorithm {} does not match key details {key_details} ({algorithm})",
            logged.data.algorithm
        )));
    }

    let length = logged.data.digest.as_bytes().len();
    if length != algorithm.digest_size() {
        return Err(Error::malformed_entry(format!(
            "Rekor entry {algorithm} digest is {length} bytes, expected {}",
            algorithm.digest_size()
        )));
    }

    Ok(algorithm)
}

/// Read the algorithm of the entry's sole public-key or certificate verifier.
fn logged_key_algorithm(verifier: &HashedRekordV002Verifier) -> Result<KeyAlgorithm> {
    Ok(match (&verifier.public_key, &verifier.x509_certificate) {
        (Some(key), None) => KeyAlgorithm::from_spki(&key.raw_bytes).map_err(|e| {
            Error::malformed_entry(format!("invalid public key in Rekor entry: {e}"))
        })?,
        (None, Some(cert)) => {
            parse_certificate_info(&cert.raw_bytes)
                .map_err(|e| {
                    Error::malformed_entry(format!("invalid certificate in Rekor entry: {e}"))
                })?
                .key_algorithm
        }
        (Some(_), Some(_)) => {
            return Err(Error::malformed_entry(
                "Rekor entry verifier has both a public key and a certificate".to_string(),
            ))
        }
        (None, None) => {
            return Err(Error::malformed_entry(
                "Rekor entry verifier has neither a public key nor a certificate".to_string(),
            ))
        }
    })
}

/// Validate that the certificate in Rekor matches the certificate in the bundle
fn validate_verifier_match(
    _entry: &TransparencyLogEntry,
    body: &RekorEntryBody,
    bundle: &Bundle,
    managed_key: Option<&DerPublicKey>,
) -> Result<()> {
    // Get the certificate from the bundle. Key-based bundles carry no
    // certificate (the Rekor verifier is a public key, not a certificate),
    // so there is nothing to compare; the signature bytes are still matched
    // by `validate_signature_match`.
    let bundle_cert = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            certificates.first().map(|c| &c.raw_bytes)
        }
        VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
        VerificationMaterialContent::PublicKey(_) => None,
        _ => {
            return Err(Error::UnsupportedBundle(
                "unsupported bundle verification material".to_string(),
            ))
        }
    };
    if bundle_cert.is_none() {
        let managed_key = managed_key.ok_or_else(|| {
            Error::entry_mismatch(
                "Rekor verifier cannot be bound without the managed public key".to_string(),
            )
        })?;
        let rekor_key = match body {
            RekorEntryBody::HashedRekordV001(rekord) => rekord
                .spec
                .signature
                .public_key
                .parse_public_key()
                .map_err(|e| Error::malformed_entry(e.to_string()))?,
            RekorEntryBody::HashedRekordV002(rekord) => rekord
                .spec
                .hashed_rekord_v002
                .signature
                .verifier
                .public_key
                .as_ref()
                .map(|key| key.raw_bytes.clone())
                .ok_or_else(|| {
                    Error::entry_mismatch(
                        "managed-key Rekor entry contains no public-key verifier".to_string(),
                    )
                })?,
            _ => {
                return Err(Error::UnsupportedBundle(
                    "unsupported Rekor verifier type".to_string(),
                ))
            }
        };
        if rekor_key.as_bytes() != managed_key.as_bytes() {
            return Err(Error::entry_mismatch(
                "public key in Rekor entry does not match managed key".to_string(),
            ));
        }
        return Ok(());
    }
    let bundle_cert = bundle_cert.expect("checked above");

    // Extract certificate DER from Rekor entry
    let rekor_cert_der_opt = match body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: parse PEM certificate from publicKey content
            let cert = rekord
                .spec
                .signature
                .public_key
                .parse_certificate()
                .map_err(|e| Error::malformed_entry(format!("{}", e)))?;
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

    let rekor_cert_der = rekor_cert_der_opt.ok_or_else(|| {
        Error::entry_mismatch("certificate-backed Rekor entry contains no certificate".to_string())
    })?;
    if bundle_cert.as_bytes() != rekor_cert_der {
        return Err(Error::entry_mismatch(
            "certificate in bundle does not match certificate in Rekor entry".to_string(),
        ));
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
                    return Err(Error::entry_mismatch(
                        "signature in bundle does not match signature in Rekor entry".to_string(),
                    ));
                }
            }
            SignatureContent::DsseEnvelope(envelope) => {
                if &envelope.signature.sig != rekor_sig {
                    return Err(Error::entry_mismatch(
                        "DSSE signature in bundle does not match signature in Rekor entry"
                            .to_string(),
                    ));
                }
            }
            _ => {
                return Err(Error::UnsupportedBundle(
                    "unsupported bundle signature content".to_string(),
                ))
            }
        }
    }

    Ok(())
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
        // For 0.0.2 (Rekor v2), integrated_time is not present
        let v1_integrated_time = entry
            .integrated_time
            .filter(|_| entry.kind_version == KindVersion::HashedRekordV001);
        if let Some(integrated_time) = v1_integrated_time {
            let cert = Certificate::from_der(bundle_cert_der).map_err(|e| {
                Error::cert_malformed(format!(
                    "failed to parse certificate for time validation: {}",
                    e
                ))
            })?;

            let not_before = jiff::Timestamp::try_from(
                cert.tbs_certificate.validity.not_before.to_system_time(),
            )
            .map_err(|e| Error::cert_malformed(format!("invalid notBefore time: {}", e)))?;
            let not_after =
                jiff::Timestamp::try_from(cert.tbs_certificate.validity.not_after.to_system_time())
                    .map_err(|e| Error::cert_malformed(format!("invalid notAfter time: {}", e)))?;

            if integrated_time < not_before || integrated_time > not_after {
                return Err(Error::integrated_time(format!(
                    "integrated time {} is outside certificate validity period ({} to {})",
                    integrated_time, not_before, not_after
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactRequirements;
    use crate::error::TransparencyLogError;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::{json, Value};
    use sigstore_crypto::SigningScheme;
    use sigstore_types::Artifact;

    /// Test public keys used for curve detection and exact key binding.
    const P384_KEY: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPjUQjqathWUZXpBdDJWDjVyyt2YdKshU+5yRnQu+LoY/+s+ASLZMFAscoSnyNhtJqIanYUWKH3bcnJvjUhYX8PsLZ4U28uOSh++vOqacWHVOK3CRJGmw47AudN9oHsO6";
    const P256_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd1cZefkJQlXtMUcBsptiJ8HfpRyHwukZWXVCjrRIMK8U1k3lOw8CXdzE/iLy5DEiqa4oA8td++rmxiPlJlZUAg==";
    const OTHER_P384_KEY: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEg9Umw8SVCTf5swPswBu3b1qXDPc4+Uj4T/h/F6bm2I6xkA4O1bXzTy4nnmGXxevyrRlJeUIRrHd/aJLs4p084odVdyJAvgYMmzfiSpib1N2SmCTLKRXOyS45o6N4w40m";
    const SIGNATURE: &str = "c2lnbmF0dXJl";

    fn statement() -> Vec<u8> {
        let subject = sigstore_crypto::sha256(b"artifact").to_hex();
        json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "a", "digest": {"sha256": subject}}],
            "predicateType": "https://example.com/predicate/v1",
            "predicate": {},
        })
        .to_string()
        .into_bytes()
    }

    // Independent PAE encoding: do not use the production envelope.pae() oracle.
    fn pae() -> Vec<u8> {
        let payload = statement();
        let payload_type = "application/vnd.in-toto+json";
        let mut pae = format!(
            "DSSEv1 {} {} {} ",
            payload_type.len(),
            payload_type,
            payload.len()
        )
        .into_bytes();
        pae.extend_from_slice(&payload);
        pae
    }

    struct Entry {
        key_details: &'static str,
        key: &'static str,
        algorithm: &'static str,
        digest: Vec<u8>,
    }

    impl Entry {
        fn conforming_p384() -> Self {
            Self {
                key_details: "PKIX_ECDSA_P384_SHA_384",
                key: P384_KEY,
                algorithm: "SHA2_384",
                digest: sigstore_crypto::sha384(&pae()).as_bytes().to_vec(),
            }
        }

        fn conforming_p256() -> Self {
            Self {
                key_details: "PKIX_ECDSA_P256_SHA_256",
                key: P256_KEY,
                algorithm: "SHA2_256",
                digest: sigstore_crypto::sha256(&pae()).as_bytes().to_vec(),
            }
        }

        fn bundle(&self, content: Value) -> Bundle {
            let body = json!({
                "apiVersion": "0.0.2",
                "kind": "hashedrekord",
                "spec": {
                    "hashedRekordV002": {
                        "data": {"algorithm": self.algorithm, "digest": STANDARD.encode(&self.digest)},
                        "signature": {
                            "content": SIGNATURE,
                            "verifier": {
                                "keyDetails": self.key_details,
                                "publicKey": {"rawBytes": self.key},
                            },
                        },
                    },
                },
            });
            let mut bundle = json!({
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "publicKey": {"hint": "hint"},
                    "tlogEntries": [{
                        "logIndex": "1",
                        "logId": {"keyId": STANDARD.encode([0u8; 32])},
                        "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
                        "canonicalizedBody": STANDARD.encode(body.to_string()),
                    }],
                },
            });
            bundle
                .as_object_mut()
                .unwrap()
                .extend(content.as_object().unwrap().clone());
            Bundle::from_json(&bundle.to_string()).unwrap()
        }

        /// Verify a DSSE bundle carrying this entry with `managed_key`.
        fn verify(&self, managed_key: &str) -> Result<()> {
            let bundle = self.bundle(json!({
                "dsseEnvelope": {
                    "payload": STANDARD.encode(statement()),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"sig": SIGNATURE, "keyid": ""}],
                },
            }));
            verify_entry_bundle(&bundle, Artifact::Blob(b"artifact"), managed_key)
        }
    }

    fn verify_entry_bundle(
        bundle: &Bundle,
        artifact: Artifact<'_>,
        managed_key: &str,
    ) -> Result<()> {
        let managed_key = DerPublicKey::new(STANDARD.decode(managed_key).unwrap());
        // These tests inspect Rekor binding directly; the signing scheme only
        // prepares artifact digests and does not verify the placeholder signature.
        let requirements =
            ArtifactRequirements::new(&bundle.content, SigningScheme::EcdsaP384Sha384).unwrap();
        let artifact = PreparedArtifact::from_artifact(artifact, &requirements).unwrap();
        let entry = &bundle.verification_material.tlog_entries[0];
        verify_hashedrekord_entry(entry, bundle, &artifact, Some(&managed_key))
    }

    fn assert_entry_mismatch(result: Result<()>, expected: &str) {
        match result {
            Err(Error::TransparencyLog(TransparencyLogError::EntryMismatch(m)))
                if m.contains(expected) => {}
            other => panic!("expected entry mismatch containing {expected:?}, got {other:?}"),
        }
    }

    fn assert_malformed_entry(result: Result<()>) -> String {
        match result {
            Err(Error::TransparencyLog(TransparencyLogError::MalformedEntry(message))) => message,
            other => panic!("expected malformed entry, got {other:?}"),
        }
    }

    #[test]
    fn test_p384_dsse_entry_binds_sha384_of_pae() {
        Entry::conforming_p384().verify(P384_KEY).unwrap();
    }

    #[test]
    fn test_p256_dsse_entry_binds_sha256_of_pae() {
        Entry::conforming_p256().verify(P256_KEY).unwrap();
    }

    #[test]
    fn test_p384_entry_with_sha256_of_pae_is_rejected() {
        // A P-256-shaped digest under P-384 key details: the algorithm label
        // disagrees with the key details.
        let entry = Entry {
            algorithm: "SHA2_256",
            digest: sigstore_crypto::sha256(&pae()).as_bytes().to_vec(),
            ..Entry::conforming_p384()
        };
        assert_entry_mismatch(
            entry.verify(P384_KEY),
            "digest algorithm SHA2_256 does not match key details PKIX_ECDSA_P384_SHA_384",
        );
    }

    #[test]
    fn test_key_details_must_match_the_logged_key() {
        // P-384 key labeled as P-256.
        let entry = Entry {
            key_details: "PKIX_ECDSA_P256_SHA_256",
            ..Entry::conforming_p384()
        };
        assert_entry_mismatch(
            entry.verify(P384_KEY),
            "key details PKIX_ECDSA_P256_SHA_256 do not match its EcdsaP384 key",
        );

        // P-256 key labeled as P-384, with an otherwise consistent SHA-384
        // digest.
        let entry = Entry {
            key_details: "PKIX_ECDSA_P384_SHA_384",
            algorithm: "SHA2_384",
            digest: sigstore_crypto::sha384(&pae()).as_bytes().to_vec(),
            ..Entry::conforming_p256()
        };
        assert_entry_mismatch(
            entry.verify(P256_KEY),
            "key details PKIX_ECDSA_P384_SHA_384 do not match its EcdsaP256 key",
        );
    }

    #[test]
    fn test_digest_length_must_match_the_algorithm() {
        let mut entry = Entry::conforming_p384();
        entry.digest.truncate(32);
        let message = assert_malformed_entry(entry.verify(P384_KEY));
        assert!(message.contains("SHA2_384 digest is 32 bytes, expected 48"));
    }

    #[test]
    fn test_digest_value_must_match_the_pae() {
        let mut entry = Entry::conforming_p384();
        entry.digest[0] ^= 1;
        assert!(matches!(
            entry.verify(P384_KEY),
            Err(Error::ArtifactMismatch(_))
        ));

        // SHA-384 of the payload alone is not the logged digest.
        let entry = Entry {
            digest: sigstore_crypto::sha384(&statement()).as_bytes().to_vec(),
            ..Entry::conforming_p384()
        };
        assert!(matches!(
            entry.verify(P384_KEY),
            Err(Error::ArtifactMismatch(_))
        ));
    }

    #[test]
    fn test_logged_key_must_match_the_managed_key() {
        let entry = Entry::conforming_p384();

        assert_entry_mismatch(
            entry.verify(OTHER_P384_KEY),
            "public key in Rekor entry does not match managed key",
        );
    }

    #[test]
    fn test_p384_message_signature_entry_binds_sha384_of_artifact() {
        let verify = |logged: &[u8], supplied: Artifact<'_>| {
            let entry = Entry {
                digest: logged.to_vec(),
                ..Entry::conforming_p384()
            };
            let bundle = entry.bundle(json!({"messageSignature": {"signature": SIGNATURE}}));
            verify_entry_bundle(&bundle, supplied, P384_KEY)
        };
        let digest = sigstore_crypto::sha384(b"artifact");
        verify(digest.as_bytes(), Artifact::Blob(b"artifact")).unwrap();
        assert!(matches!(
            verify(digest.as_bytes(), Artifact::Blob(b"other")),
            Err(Error::ArtifactMismatch(_))
        ));
        // A SHA-256 digest of the artifact cannot be checked against a
        // SHA-384 entry, so verification fails closed.
        let sha256 = sigstore_crypto::sha256(b"artifact");
        assert!(matches!(
            verify(
                digest.as_bytes(),
                Artifact::Digest(
                    sigstore_types::ArtifactDigest::new(
                        HashAlgorithm::Sha2256,
                        sha256.as_bytes().to_vec()
                    )
                    .unwrap()
                )
            ),
            Err(Error::UnsupportedArtifact(_))
        ));
    }

    #[test]
    fn test_unknown_key_details_fail_to_parse() {
        let entry = Entry {
            key_details: "PKIX_ECDSA_P384_SHA_256",
            ..Entry::conforming_p384()
        };
        assert_malformed_entry(entry.verify(P384_KEY));
    }
}
