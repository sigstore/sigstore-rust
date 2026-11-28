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
    let (expected_key, expected_rsa_bits) = match key_details {
        RekorV2KeyDetails::PkixEcdsaP256Sha256 => (KeyAlgorithm::EcdsaP256, None),
        RekorV2KeyDetails::PkixEcdsaP384Sha384 => (KeyAlgorithm::EcdsaP384, None),
        RekorV2KeyDetails::PkixEcdsaP521Sha512 => (KeyAlgorithm::EcdsaP521, None),
        RekorV2KeyDetails::PkixRsaPkcs1v152048Sha256 => (KeyAlgorithm::Rsa, Some(2048)),
        RekorV2KeyDetails::PkixRsaPkcs1v153072Sha256 => (KeyAlgorithm::Rsa, Some(3072)),
        RekorV2KeyDetails::PkixRsaPkcs1v154096Sha256 => (KeyAlgorithm::Rsa, Some(4096)),
        RekorV2KeyDetails::PkixEd25519Ph => (KeyAlgorithm::Ed25519, None),
        other => {
            return Err(Error::UnsupportedBundle(format!(
                "unsupported Rekor v2 key details: {other}"
            )))
        }
    };

    let (logged_spki, logged_key) = logged_verifier_key(verifier)?;
    if logged_key != expected_key {
        return Err(Error::entry_mismatch(format!(
            "Rekor entry key details {key_details} do not match its {logged_key:?} key"
        )));
    }
    if let Some(expected_bits) = expected_rsa_bits {
        let actual_bits = rsa_modulus_bits(&logged_spki)?;
        if actual_bits != expected_bits {
            return Err(Error::entry_mismatch(format!(
                "Rekor entry key details {key_details} require a {expected_bits}-bit RSA key, got {actual_bits} bits"
            )));
        }
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

/// Read the SPKI public key and algorithm of the entry's sole public-key or
/// certificate verifier.
fn logged_verifier_key(
    verifier: &HashedRekordV002Verifier,
) -> Result<(DerPublicKey, KeyAlgorithm)> {
    match (&verifier.public_key, &verifier.x509_certificate) {
        (Some(key), None) => {
            let algorithm = KeyAlgorithm::from_spki(&key.raw_bytes).map_err(|e| {
                Error::malformed_entry(format!("invalid public key in Rekor entry: {e}"))
            })?;
            Ok((key.raw_bytes.clone(), algorithm))
        }
        (None, Some(cert)) => {
            let info = parse_certificate_info(&cert.raw_bytes).map_err(|e| {
                Error::malformed_entry(format!("invalid certificate in Rekor entry: {e}"))
            })?;
            Ok((info.public_key, info.key_algorithm))
        }
        (Some(_), Some(_)) => Err(Error::malformed_entry(
            "Rekor entry verifier has both a public key and a certificate".to_string(),
        )),
        (None, None) => Err(Error::malformed_entry(
            "Rekor entry verifier has neither a public key nor a certificate".to_string(),
        )),
    }
}

/// Return the modulus size in bits of an RSA SPKI public key.
fn rsa_modulus_bits(spki_der: &DerPublicKey) -> Result<usize> {
    use x509_cert::der::{asn1::UintRef, Reader as _, SliceReader};

    let spki = x509_cert::spki::SubjectPublicKeyInfoRef::try_from(spki_der.as_bytes())
        .map_err(|e| Error::malformed_entry(format!("invalid public key in Rekor entry: {e}")))?;
    let mut reader = SliceReader::new(spki.subject_public_key.raw_bytes()).map_err(|e| {
        Error::malformed_entry(format!("invalid RSA public key in Rekor entry: {e}"))
    })?;
    let modulus = reader
        .sequence(|r| {
            let modulus: UintRef<'_> = r.decode()?;
            let _public_exponent: UintRef<'_> = r.decode()?;
            Ok(modulus)
        })
        .and_then(|modulus| {
            reader.finish(modulus)?;
            Ok(modulus)
        })
        .map_err(|e| {
            Error::malformed_entry(format!("invalid RSA public key in Rekor entry: {e}"))
        })?;
    let mod_bytes = modulus.as_bytes();
    let bits = match mod_bytes.first() {
        Some(&first) => (mod_bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
        None => 0,
    };
    Ok(bits)
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

    /// Test public keys used for algorithm/key-size detection and exact key binding.
    const P384_KEY: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPjUQjqathWUZXpBdDJWDjVyyt2YdKshU+5yRnQu+LoY/+s+ASLZMFAscoSnyNhtJqIanYUWKH3bcnJvjUhYX8PsLZ4U28uOSh++vOqacWHVOK3CRJGmw47AudN9oHsO6";
    const P256_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd1cZefkJQlXtMUcBsptiJ8HfpRyHwukZWXVCjrRIMK8U1k3lOw8CXdzE/iLy5DEiqa4oA8td++rmxiPlJlZUAg==";
    const P521_KEY: &str = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAZEF9WGS0QHBx6alJ8zR5/hGIQgsuuuPxWreALuawfc5AD2hfLJoyLvBcwVcjiAmSOo0gkYM2r+QnEbWuVLoqcQkAfwvNVoSTEhTG7gwVrA6V8AAw92KCLhoU+wOiah1J3uXYyb22F7VKBuV055i+TSN3Vc+++yCnasowCp0n564+vyw=";
    const RSA2048_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0XTRQ9s+hbdbNghC52qxjAQjuxUHZKbD3sWlcg3STVxIGjX/m1yHMJz2GRhZVPUFe6BDUeJRTaSxBOtcFvWuYlbJTS8SM/5MmtlWkb5PALa+lBg2HqtJrNkLT6D+eWOneHfh/7Inf2N7E9CAslR3WW0ViKqWUoK60ygD7bAtFr5PpkXaqEw3R4RIoO7wEtzjvp1q6pt+0GLafUyJBKYXXCN2QIpwkGLdMdHkBc6DcJxu1wvt1AVOYYmUjLCdigCqJ+qugk5ayx3ftX6ujXxwvuFM4RKx5hsndwB//M9BW1cd6u1DaTFuZ5lI8qqUkJla9DheoiXArm/4cKRW13GDwIDAQAB";
    const RSA3072_KEY: &str = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAij3GJZQoruUKd/NR3byrEor3a5pE7j1lNZNCe9rbu9oATE3tC0r0ckx/FE0N04r9JtY8yEDdA/1VYxjkha0hQLxa0nfykqGddQn7D19zt2sya2m+r0T5ztJroEu6qft5XcJu47ntmIgVMWhFHCJl2s8sXyfE2Ts+x0kXPtqDPOYufNjMDWYC5eG0sOZxcvmkk+tcioGS+z1OF1nTeI4wGs8q53HwpZQH9fyn8HpN8iCCgmR2u0KPRr5hYnALL59vz2asD/wDJN5QwGzP184/VAp8cWbWBLobZG03j8GuKLB86pWYfbdgV6z65K5IbgkH27dh5SM54qrjfO1EeJFRryD0bk9YmEaeTshPiFN0emHm+zqOMNypeWcWnMP11DkZpCkcZJseuGfc9Bn0KfYDgL38aCB3VkNhAiyE01fIbrQnINc3jpPYp58b8oNEk5JFKjQRFUa4Ebd3b9R15E7ZpHKru+z8JVpe2xFWBlEZe57G8aRVw+hBvS6bj1ejYD8BAgMBAAE=";
    const RSA4096_KEY: &str = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwzT/IH1bbRa3LVdDVTatIx2E3dUFVDfY4rkCl6obqV37+e/pWq9LZxcL/sBKLORD2l67xaZSIlvxVAcsX+xkQMqHChVc4jvVUuAWI1sYIgC8Ym+oAHkvOGaQKdZKNWbZI9NtEbjEB82VKrv+Otk0fvgOgc16XU5aCVkt8O/zTZppEWDSidLs+vd3LbQiFf3k27+mP1MsNm4UkqFNxMkp257gnz63MMwJLDEAhDov82+XGYEYiACpwoY2Y9I0p82lu9mCO9sERPNG2UQ47fI1qk0GdV1bme6sgCDufJHRHXWD2MPITrRJnyzg6YYn7tX7g32xKZqAA7jJyCpcjTHHsXwP8U03XAiU4U22D1necgXYuIa+rCRQpPjUMI0MX+JfL+npkgefk2ygTOprI+dqclD9WBJiSYevln24cOJlORjG7mg13TuxVJQq0YsKDsan0FZpovLyBuj9LrgzeJpaiBmuznhoVFVOBImrgROVRSHQxFNCYCCf5gqEFaNcbXaUrcPOA/5EuSrhvY+xBaYhnb7bR9u7znR2J9BI7VC2lxlRNu1LnmjholreI9GcLhS3+5aAHgsrG09BmHn4YMgCXWP1J+JVy+VYtfGe3tspwuSLhBEnNP9XXQr4ii30WH5hpyXHzkJOHqIwickDUqhdptkhfNoe/ttlRByLl7EVpk0CAwEAAQ==";
    const ED25519_KEY: &str = "MCowBQYDK2VwAyEAB31fpkySzG9cBMZ8NGA26DmcuIHJ4x7K9gqRNNssOss=";
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

        fn conforming_p521() -> Self {
            Self {
                key_details: "PKIX_ECDSA_P521_SHA_512",
                key: P521_KEY,
                algorithm: "SHA2_512",
                digest: sigstore_crypto::sha512(&pae()).as_bytes().to_vec(),
            }
        }

        fn conforming_rsa(key_details: &'static str, key: &'static str) -> Self {
            Self {
                key_details,
                key,
                algorithm: "SHA2_256",
                digest: sigstore_crypto::sha256(&pae()).as_bytes().to_vec(),
            }
        }

        fn conforming_ed25519ph() -> Self {
            Self {
                key_details: "PKIX_ED25519_PH",
                key: ED25519_KEY,
                algorithm: "SHA2_512",
                digest: sigstore_crypto::sha512(&pae()).as_bytes().to_vec(),
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
    fn test_p521_dsse_entry_binds_sha512_of_pae() {
        Entry::conforming_p521().verify(P521_KEY).unwrap();
    }

    #[test]
    fn test_rsa_dsse_entries_bind_sha256_of_pae() {
        for (details, key) in [
            ("PKIX_RSA_PKCS1V15_2048_SHA256", RSA2048_KEY),
            ("PKIX_RSA_PKCS1V15_3072_SHA256", RSA3072_KEY),
            ("PKIX_RSA_PKCS1V15_4096_SHA256", RSA4096_KEY),
        ] {
            Entry::conforming_rsa(details, key).verify(key).unwrap();
        }
    }

    #[test]
    fn test_ed25519ph_dsse_entry_binds_sha512_of_pae() {
        Entry::conforming_ed25519ph().verify(ED25519_KEY).unwrap();
    }

    #[test]
    fn test_rsa_key_size_must_match_key_details() {
        for (details, wrong_key, expected_bits, actual_bits) in [
            ("PKIX_RSA_PKCS1V15_2048_SHA256", RSA3072_KEY, 2048, 3072),
            ("PKIX_RSA_PKCS1V15_2048_SHA256", RSA4096_KEY, 2048, 4096),
            ("PKIX_RSA_PKCS1V15_3072_SHA256", RSA2048_KEY, 3072, 2048),
            ("PKIX_RSA_PKCS1V15_4096_SHA256", RSA2048_KEY, 4096, 2048),
        ] {
            let entry = Entry::conforming_rsa(details, wrong_key);
            assert_entry_mismatch(
                entry.verify(wrong_key),
                &format!(
                    "key details {details} require a {expected_bits}-bit RSA key, got {actual_bits} bits"
                ),
            );
        }
    }

    #[test]
    fn test_p521_and_ed25519ph_message_signature_entries_bind_sha512() {
        let digest = sigstore_crypto::sha512(b"artifact");
        for (entry, key, scheme) in [
            (
                Entry {
                    digest: digest.as_bytes().to_vec(),
                    ..Entry::conforming_p521()
                },
                P521_KEY,
                SigningScheme::EcdsaP521Sha512,
            ),
            (
                Entry {
                    digest: digest.as_bytes().to_vec(),
                    ..Entry::conforming_ed25519ph()
                },
                ED25519_KEY,
                SigningScheme::Ed25519Ph,
            ),
        ] {
            let bundle = entry.bundle(json!({"messageSignature": {"signature": SIGNATURE}}));
            let managed_key = DerPublicKey::new(STANDARD.decode(key).unwrap());
            let requirements = ArtifactRequirements::new(&bundle.content, scheme).unwrap();
            let artifact =
                PreparedArtifact::from_artifact(Artifact::Blob(b"artifact"), &requirements)
                    .unwrap();
            let tlog = &bundle.verification_material.tlog_entries[0];
            verify_hashedrekord_entry(tlog, &bundle, &artifact, Some(&managed_key)).unwrap();

            let wrong =
                PreparedArtifact::from_artifact(Artifact::Blob(b"other"), &requirements).unwrap();
            assert!(matches!(
                verify_hashedrekord_entry(tlog, &bundle, &wrong, Some(&managed_key)),
                Err(Error::ArtifactMismatch(_))
            ));
        }
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
