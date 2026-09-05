//! RFC 3161 timestamp verification
//!
//! This module provides full verification of RFC 3161 timestamps including:
//! - CMS signature verification
//! - Certificate chain validation
//! - Message imprint validation
//! - TSA Extended Key Usage validation

use crate::asn1::{self, PkiStatus, TimeStampResp, TstInfo};
use crate::error::{Error, Result};
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use jiff::Timestamp;
use rustls_pki_types::CertificateDer;
use sigstore_crypto::{verify_signature, KeyAlgorithm};
use sigstore_types::{DerPublicKey, SignatureBytes, TsaAuthority};
use x509_cert::Certificate;

// Re-export webpki from rustls-webpki
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};

// Define OIDs as constants using const_oid::db
const ID_KP_TIME_STAMPING: ObjectIdentifier = const_oid::db::rfc5280::ID_KP_TIME_STAMPING;
const ID_SIGNED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_SIGNED_DATA;
const OID_MESSAGE_DIGEST: ObjectIdentifier = const_oid::db::rfc6268::ID_MESSAGE_DIGEST;
const OID_SHA256: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_256;
const OID_SHA384: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_384;
const OID_SHA512: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_512;

/// Verification options for RFC 3161 timestamps.
///
/// Crate-private on purpose: an opts bag lets certificates and validity
/// windows be mixed across authorities, which is exactly the misuse behind
/// TOB-SIGSTORE-11. The public entry point is
/// [`verify_timestamp_for_authority`], which consumes a [`TsaAuthority`] as
/// one unsplittable unit.
#[derive(Debug, Clone)]
pub(crate) struct VerifyOpts<'a> {
    /// Root certificates for chain verification
    pub roots: Vec<CertificateDer<'a>>,

    /// Intermediate certificates for chain building
    pub intermediates: Vec<CertificateDer<'a>>,

    /// TSA certificates (optional if embedded in timestamp)
    /// Multiple certificates can be provided to support multiple TSAs
    ///
    /// When non-empty, the CMS signer certificate MUST match one of these
    /// certificates. This pins the timestamp to a known TSA identity: a
    /// token whose signer merely chains to a trusted root via embedded
    /// certificates is rejected unless the signer itself is listed here.
    pub tsa_certificates: Vec<CertificateDer<'a>>,
}

impl<'a> VerifyOpts<'a> {
    /// Create new verification options
    pub fn new() -> Self {
        Self {
            roots: Vec::new(),
            intermediates: Vec::new(),
            tsa_certificates: Vec::new(),
        }
    }

    /// Add a root certificate
    pub fn with_root(mut self, root: CertificateDer<'a>) -> Self {
        self.roots.push(root);
        self
    }

    /// Add multiple intermediate certificates
    pub fn with_intermediates(mut self, intermediates: Vec<CertificateDer<'a>>) -> Self {
        self.intermediates = intermediates;
        self
    }

    /// Add multiple TSA certificates
    pub fn with_tsa_certificates(mut self, certs: Vec<CertificateDer<'a>>) -> Self {
        self.tsa_certificates = certs;
        self
    }
}

impl Default for VerifyOpts<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of raw timestamp verification: cryptographically authenticated,
/// but not yet temporally authorized by any authority's `valid_for` window.
#[derive(Debug, Clone)]
pub(crate) struct TimestampResult {
    /// The timestamp from the TSA
    pub time: Timestamp,
}

/// Parse a timestamp token and return the extracted TstInfo and SignedData.
///
/// This function supports both `TimeStampResp` and direct `ContentInfo` (TimeStampToken) formats.
pub fn parse_timestamp_token(timestamp_token_bytes: &[u8]) -> Result<(TstInfo, SignedData)> {
    use cms::content_info::ContentInfo;
    use x509_cert::der::{Decode, Encode};

    // Try to parse as TimeStampResp first, if that fails, try as ContentInfo
    let content_info = match TimeStampResp::from_der(timestamp_token_bytes) {
        Ok(resp) => {
            // Check status
            if resp.status.status != PkiStatus::Granted as u8
                && resp.status.status != PkiStatus::GrantedWithMods as u8
            {
                return Err(Error::ParseError(format!(
                    "Timestamp request not granted: {}",
                    resp.status.status
                )));
            }

            let token_any = resp.time_stamp_token.ok_or(Error::ParseError(
                "TimeStampResp missing timeStampToken".to_string(),
            ))?;
            // We need the DER bytes of the token for ContentInfo parsing
            let bytes = token_any
                .to_der()
                .map_err(|e| Error::ParseError(format!("failed to re-encode token: {}", e)))?;

            // Parse ContentInfo from bytes
            ContentInfo::from_der(&bytes).map_err(|e| {
                Error::ParseError(format!("failed to decode ContentInfo from token: {}", e))
            })?
        }
        Err(_) => {
            // Try as ContentInfo directly
            ContentInfo::from_der(timestamp_token_bytes)
                .map_err(|e| Error::ParseError(format!("failed to decode TimeStampToken: {}", e)))?
        }
    };

    // Verify content type is SignedData
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(Error::ParseError(
            "ContentInfo content type is not SignedData".to_string(),
        ));
    }

    // We can encode the content to DER, which gives us the bytes of the SignedData structure
    let signed_data_der = content_info
        .content
        .to_der()
        .map_err(|e| Error::ParseError(format!("failed to encode SignedData content: {}", e)))?;

    let signed_data = SignedData::from_der(&signed_data_der)
        .map_err(|e| Error::ParseError(format!("failed to decode SignedData: {}", e)))?;

    // Verify the content type inside SignedData is TSTInfo
    if signed_data.encap_content_info.econtent_type != asn1::OID_TST_INFO {
        return Err(Error::ParseError(
            "encap content type is not TSTInfo".to_string(),
        ));
    }

    // Extract the TSTInfo
    let tst_info = if let Some(content) = &signed_data.encap_content_info.econtent {
        // The content is an Any wrapping an OCTET STRING that contains the TSTInfo
        let tst_info_bytes = content.value();

        TstInfo::from_der(tst_info_bytes)
            .map_err(|e| Error::ParseError(format!("failed to decode TSTInfo: {}", e)))?
    } else {
        return Err(Error::NoTstInfo);
    };

    Ok((tst_info, signed_data))
}

/// Verify an RFC 3161 timestamp token (ContentInfo).
///
/// This function:
/// 1. Parses the timestamp token (DER encoded ContentInfo)
/// 2. Extracts the TSTInfo to get the timestamp
/// 3. Verifies the message imprint (hash) matches the signature bytes
/// 4. Verifies the CMS signature using the embedded or provided TSA certificate
/// 5. Validates the TSA certificate chain to a trusted root
///
/// # Arguments
///
/// * `timestamp_token_bytes` - The RFC 3161 timestamp token bytes (DER encoded ContentInfo)
/// * `signature_bytes` - The signature that was timestamped
/// * `opts` - Verification options including trusted roots and validity period
///
/// # Returns
///
/// Returns `Ok(TimestampResult)` if verification succeeds, otherwise returns an error.
///
/// Note: the returned time is NOT temporally authorized. Public consumers go
/// through [`verify_timestamp_for_authority`], which cannot skip that step.
pub(crate) fn verify_timestamp_response(
    timestamp_token_bytes: &[u8],
    signature_bytes: &[u8],
    opts: VerifyOpts<'_>,
) -> Result<TimestampResult> {
    tracing::debug!("Starting RFC 3161 timestamp verification");

    let (tst_info, signed_data) = parse_timestamp_token(timestamp_token_bytes)?;

    // Verify the message imprint (hash of the signature) matches
    verify_message_imprint(&tst_info, signature_bytes)?;

    // Extract the timestamp from TSTInfo
    let timestamp = Timestamp::try_from(tst_info.gen_time.to_system_time())
        .map_err(|_| Error::ParseError("invalid timestamp in TSTInfo".to_string()))?;
    if timestamp < Timestamp::UNIX_EPOCH {
        return Err(Error::ParseError("timestamp before epoch".to_string()));
    }

    tracing::debug!("Extracted timestamp: {}", timestamp);

    // Verify the CMS signature
    let tst_info_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(Error::NoTstInfo)?
        .value();

    tracing::debug!("Starting CMS signature verification");
    let signer_cert = verify_cms_signature(&signed_data, tst_info_der, &opts)?;
    tracing::debug!("CMS signature verification completed successfully");

    // Validate the signer using only the configured authority's chain.
    tracing::debug!("Starting TSA certificate chain validation");
    validate_tsa_certificate_chain(&signer_cert, timestamp, &opts)?;
    tracing::debug!("TSA certificate chain validation completed successfully");

    Ok(TimestampResult { time: timestamp })
}

/// Verify an RFC 3161 timestamp token against a single timestamp authority.
///
/// An `Ok` time is simultaneously:
///
/// 1. **cryptographically authenticated** by `authority`: the CMS signer
///    certificate must be the authority's leaf, and the chain must terminate
///    at the authority's root, using only the authority's own intermediates;
/// 2. **temporally authorized** by the same authority: the signed time must
///    fall within its `valid_for` window (an absent window is unrestricted).
///
/// The two checks are inseparable by construction, so temporal authorization
/// can never come from an authority other than the one that signed the token
/// (TOB-SIGSTORE-11). A token whose signing authority's window excludes its
/// signed time fails with [`Error::TimestampOutsideValidity`]; callers
/// trying several authorities can use that variant to distinguish "wrong
/// authority" from "right authority, wrong time".
pub fn verify_timestamp_for_authority(
    timestamp_token_bytes: &[u8],
    signature_bytes: &[u8],
    authority: &TsaAuthority,
) -> Result<Timestamp> {
    let opts = VerifyOpts::new()
        .with_root(CertificateDer::from(authority.root.as_bytes()))
        .with_intermediates(
            authority
                .intermediates
                .iter()
                .map(|cert| CertificateDer::from(cert.as_bytes()))
                .collect(),
        )
        .with_tsa_certificates(vec![CertificateDer::from(authority.leaf.as_bytes())]);

    let result = verify_timestamp_response(timestamp_token_bytes, signature_bytes, opts)?;

    let authorized = authority
        .valid_for
        .as_ref()
        .is_none_or(|window| window.contains(result.time));
    if !authorized {
        return Err(Error::TimestampOutsideValidity { time: result.time });
    }

    Ok(result.time)
}

/// Verify the message imprint matches the signature bytes
fn verify_message_imprint(tst_info: &TstInfo, signature_bytes: &[u8]) -> Result<()> {
    use aws_lc_rs::digest::{digest, SHA256, SHA384, SHA512};

    let message_imprint = &tst_info.message_imprint;
    let hash_alg_oid = &message_imprint.hash_algorithm.algorithm;

    // Hash the signature bytes using the algorithm specified in the message imprint
    let computed_hash = if hash_alg_oid == &OID_SHA256 {
        digest(&SHA256, signature_bytes)
    } else if hash_alg_oid == &OID_SHA384 {
        digest(&SHA384, signature_bytes)
    } else if hash_alg_oid == &OID_SHA512 {
        digest(&SHA512, signature_bytes)
    } else {
        return Err(Error::ParseError(format!(
            "unsupported hash algorithm: {}",
            hash_alg_oid
        )));
    };

    let expected_hash = message_imprint.hashed_message.as_bytes();

    if computed_hash.as_ref() != expected_hash {
        return Err(Error::HashMismatch {
            expected: hex::encode(expected_hash),
            actual: hex::encode(computed_hash),
        });
    }

    Ok(())
}

/// Re-encode signed attributes for signature verification.
///
/// RFC 5652: The signed attributes are stored with [0] IMPLICIT tag in SignerInfo,
/// but for signature verification they must be re-encoded as a generic SET OF.
/// This strips the [0] tag and applies the default SET (0x31) tag.
fn get_signed_attrs_for_verification(attrs: &x509_cert::attr::Attributes) -> Result<Vec<u8>> {
    use x509_cert::der::{asn1::SetOfVec, Encode};

    // Convert the attributes into a Vec first, then construct SetOfVec
    let attrs_vec: Vec<x509_cert::attr::Attribute> = attrs.iter().cloned().collect();
    let generic_set = SetOfVec::try_from(attrs_vec).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to create SetOfVec: {}", e))
    })?;

    generic_set.to_der().map_err(|e| {
        Error::SignatureVerificationError(format!("failed to re-encode attributes: {}", e))
    })
}

/// Verify the CMS signature and return the signer certificate
fn verify_cms_signature(
    signed_data: &SignedData,
    tst_info_der: &[u8],
    opts: &VerifyOpts,
) -> Result<Certificate> {
    // Get the first (and should be only) signer info
    let signer_info = signed_data
        .signer_infos
        .0
        .get(0)
        .ok_or_else(|| Error::SignatureVerificationError("no signer info found".to_string()))?;

    // Resolve the signer exclusively among the authority's trusted leaves.
    // Certificates embedded in the CMS envelope are untrusted input.
    use x509_cert::der::Decode;
    let trusted_signers = opts
        .tsa_certificates
        .iter()
        .map(|certificate| {
            Certificate::from_der(certificate.as_ref()).map_err(|e| {
                Error::SignatureVerificationError(format!(
                    "failed to parse trusted TSA certificate: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let signer_cert = find_signer_certificate(&signer_info.sid, &trusted_signers)?;

    // Get signed attributes and verify the message-digest attribute
    let signed_attrs = signer_info.signed_attrs.as_ref().ok_or_else(|| {
        Error::SignatureVerificationError("no signed attributes found".to_string())
    })?;

    // Get the digest algorithm OID from signer_info
    let digest_alg_oid = &signer_info.digest_alg.oid;

    // Verify the message-digest attribute matches the TSTInfo
    verify_message_digest_attribute(signed_attrs, tst_info_der, digest_alg_oid)?;

    // Re-encode attributes for signature verification
    let signed_attrs_bytes = get_signed_attrs_for_verification(signed_attrs)?;

    // Verify the signature using the signer certificate's public key
    let signature_bytes = signer_info.signature.as_bytes();

    // Verify the signature
    verify_ecdsa_signature(
        signature_bytes,
        &signed_attrs_bytes,
        &signer_cert,
        digest_alg_oid,
    )?;

    Ok(signer_cert)
}

/// Find the signer certificate that matches the SignerIdentifier
fn find_signer_certificate(
    signer_id: &SignerIdentifier,
    certificates: &[Certificate],
) -> Result<Certificate> {
    match signer_id {
        SignerIdentifier::IssuerAndSerialNumber(issuer_serial) => {
            // Match by issuer and serial number
            for cert in certificates {
                if cert.tbs_certificate.issuer == issuer_serial.issuer
                    && cert.tbs_certificate.serial_number == issuer_serial.serial_number
                {
                    return Ok(cert.clone());
                }
            }
            Err(Error::SignatureVerificationError(
                "CMS signer does not match any trusted TSA certificate".to_string(),
            ))
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // Match by subject key identifier extension
            for cert in certificates {
                if let Some(extensions) = &cert.tbs_certificate.extensions {
                    for ext in extensions.iter() {
                        use x509_cert::der::Decode;
                        // OID for SubjectKeyIdentifier: 2.5.29.14
                        if ext.extn_id.to_string() == "2.5.29.14" {
                            if let Ok(cert_ski) =
                                x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                                    ext.extn_value.as_bytes(),
                                )
                            {
                                if &cert_ski == ski {
                                    return Ok(cert.clone());
                                }
                            }
                        }
                    }
                }
            }
            Err(Error::SignatureVerificationError(
                "CMS signer does not match any trusted TSA certificate".to_string(),
            ))
        }
    }
}

/// Verify the message-digest attribute in signed_attrs matches the TSTInfo content.
///
/// The digest algorithm is taken from the `SignerInfo.digestAlgorithm` field (RFC 5652
/// §5.3) rather than assumed to be SHA-256, so signers that use SHA-384 or SHA-512 —
/// notably GitHub Actions's internal TSA, which uses SHA-384 — can still be verified.
fn verify_message_digest_attribute(
    signed_attrs: &x509_cert::attr::Attributes,
    tst_info_der: &[u8],
    digest_alg_oid: &ObjectIdentifier,
) -> Result<()> {
    use aws_lc_rs::digest::{digest, SHA256, SHA384, SHA512};
    use x509_cert::der::asn1::OctetStringRef;
    use x509_cert::der::{Decode, Encode};

    // Find the message-digest attribute
    let message_digest_attr = signed_attrs
        .iter()
        .find(|attr| attr.oid == OID_MESSAGE_DIGEST)
        .ok_or_else(|| {
            Error::SignatureVerificationError(
                "message-digest attribute not found in signed_attrs".to_string(),
            )
        })?;

    // The attribute values should contain exactly one OCTET STRING
    if message_digest_attr.values.len() != 1 {
        return Err(Error::SignatureVerificationError(
            "message-digest attribute should have exactly one value".to_string(),
        ));
    }

    // Decode the attribute value as OCTET STRING
    let message_digest_any = message_digest_attr.values.get(0).ok_or_else(|| {
        Error::SignatureVerificationError(
            "failed to get message-digest attribute value".to_string(),
        )
    })?;
    let message_digest_der = message_digest_any.to_der().map_err(|e| {
        Error::SignatureVerificationError(format!(
            "failed to encode message-digest attribute value: {}",
            e
        ))
    })?;
    let message_digest_octets = OctetStringRef::from_der(&message_digest_der).map_err(|e| {
        Error::SignatureVerificationError(format!(
            "failed to decode message-digest as OCTET STRING: {}",
            e
        ))
    })?;

    let message_digest = message_digest_octets.as_bytes();

    // Hash the TSTInfo content using the algorithm declared by the signer.
    let content_hash = if digest_alg_oid == &OID_SHA256 {
        digest(&SHA256, tst_info_der)
    } else if digest_alg_oid == &OID_SHA384 {
        digest(&SHA384, tst_info_der)
    } else if digest_alg_oid == &OID_SHA512 {
        digest(&SHA512, tst_info_der)
    } else {
        return Err(Error::ParseError(format!(
            "unsupported signer digest algorithm: {}",
            digest_alg_oid
        )));
    };

    // Compare the hashes
    if content_hash.as_ref() != message_digest {
        return Err(Error::HashMismatch {
            expected: hex::encode(message_digest),
            actual: hex::encode(content_hash),
        });
    }

    Ok(())
}

/// Verify the CMS signature with the shared crypto verification API.
fn verify_ecdsa_signature(
    signature: &[u8],
    message: &[u8],
    certificate: &Certificate,
    digest_alg_oid: &ObjectIdentifier,
) -> Result<()> {
    use x509_cert::der::Encode;

    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let public_key = DerPublicKey::new(spki.to_der().map_err(|e| {
        Error::SignatureVerificationError(format!("failed to encode signer public key: {e}"))
    })?);

    let algorithm = KeyAlgorithm::from_spki(&public_key)
        .map_err(|e| Error::SignatureVerificationError(e.to_string()))?;
    if !matches!(algorithm, KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384) {
        return Err(Error::SignatureVerificationError("not an EC key".into()));
    }
    let hash = match *digest_alg_oid {
        OID_SHA256 => sigstore_types::HashAlgorithm::Sha2256,
        OID_SHA384 => sigstore_types::HashAlgorithm::Sha2384,
        OID_SHA512 => sigstore_types::HashAlgorithm::Sha2512,
        _ => {
            return Err(Error::SignatureVerificationError(format!(
                "unsupported digest algorithm: {digest_alg_oid}"
            )))
        }
    };
    let scheme = algorithm
        .resolve_signing_scheme(hash)
        .map_err(|e| Error::SignatureVerificationError(e.to_string()))?;
    verify_signature(
        &public_key,
        message,
        &SignatureBytes::from_bytes(signature),
        scheme,
    )
    .map_err(|e| Error::SignatureVerificationError(e.to_string()))
}

/// Validate the TSA certificate chain
fn validate_tsa_certificate_chain(
    signer_cert: &Certificate,
    timestamp: Timestamp,
    opts: &VerifyOpts,
) -> Result<()> {
    use rustls_pki_types::{CertificateDer, UnixTime};
    use x509_cert::der::Encode;

    // If no roots are provided, fail certificate chain validation
    if opts.roots.is_empty() {
        return Err(Error::CertificateValidationError(
            "No trusted roots provided for TSA certificate validation".to_string(),
        ));
    }

    // Convert the signer certificate to DER format for webpki
    let signer_cert_der = signer_cert.to_der().map_err(|e| {
        Error::CertificateValidationError(format!(
            "failed to encode signer certificate to DER: {}",
            e
        ))
    })?;

    let signer_cert_der = CertificateDer::from(signer_cert_der);
    let end_entity_cert = EndEntityCert::try_from(&signer_cert_der).map_err(|e| {
        Error::CertificateValidationError(format!("failed to parse end-entity certificate: {}", e))
    })?;

    // Build trust anchors from the provided roots
    let trust_anchors: Vec<_> = opts
        .roots
        .iter()
        .map(|cert| {
            anchor_from_trusted_cert(cert)
                .map(|anchor| anchor.to_owned())
                .map_err(|e| {
                    Error::CertificateValidationError(format!(
                        "failed to create trust anchor: {}",
                        e
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let intermediate_ders: Vec<CertificateDer<'static>> = opts
        .intermediates
        .iter()
        .map(|certificate| certificate.clone().into_owned())
        .collect();

    tracing::debug!(
        "Using {} trusted intermediate cert(s)",
        intermediate_ders.len()
    );

    // Convert timestamp to UnixTime for webpki
    let verification_time =
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(timestamp.as_second() as u64));

    tracing::debug!(
        "Verifying certificate chain at timestamp: {} (unix: {})",
        timestamp,
        timestamp.as_second()
    );

    // Verify the certificate chain with TimeStamping EKU
    end_entity_cert
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediate_ders,
            verification_time,
            KeyUsage::required(ID_KP_TIME_STAMPING.as_bytes()),
            None, // No CRL/OCSP revocation checking (matches sigstore-python)
            None, // No custom path validation callback needed
        )
        .map_err(|e| {
            Error::CertificateValidationError(format!(
                "TSA certificate chain validation failed: {}",
                e
            ))
        })?;

    tracing::debug!("TSA certificate chain validated successfully");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // Test data from sigstore-conformance
    const VALID_BUNDLE: &str = include_str!("../test_data/timestamps/valid_bundle.json");
    const VALID_TRUSTED_ROOT: &str =
        include_str!("../test_data/timestamps/valid_trusted_root.json");
    const PAYLOAD_MISMATCH_BUNDLE: &str =
        include_str!("../test_data/timestamps/payload_mismatch_bundle.json");

    /// Helper to extract timestamp token from bundle JSON
    fn extract_timestamp_token(bundle_json: &str) -> Vec<u8> {
        let bundle: serde_json::Value = serde_json::from_str(bundle_json).unwrap();
        let timestamps =
            &bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"];
        let signed_ts = timestamps[0]["signedTimestamp"].as_str().unwrap();
        STANDARD.decode(signed_ts).unwrap()
    }

    /// Helper to extract signature from bundle JSON
    fn extract_signature(bundle_json: &str) -> Vec<u8> {
        let bundle: serde_json::Value = serde_json::from_str(bundle_json).unwrap();
        let sig = bundle["messageSignature"]["signature"].as_str().unwrap();
        STANDARD.decode(sig).unwrap()
    }

    /// Helper to extract TSA certificates from trusted root JSON
    fn extract_tsa_certs(trusted_root_json: &str) -> Vec<CertificateDer<'static>> {
        let root: serde_json::Value = serde_json::from_str(trusted_root_json).unwrap();
        let tsas = root["timestampAuthorities"].as_array().unwrap();

        let mut certs = Vec::new();
        for tsa in tsas {
            let cert_chain = tsa["certChain"]["certificates"].as_array().unwrap();
            for cert in cert_chain {
                let raw_bytes = cert["rawBytes"].as_str().unwrap();
                let der = STANDARD.decode(raw_bytes).unwrap();
                certs.push(CertificateDer::from(der));
            }
        }
        certs
    }

    #[test]
    fn test_verify_valid_timestamp() {
        // Extract timestamp token and signature from the bundle
        let timestamp_token = extract_timestamp_token(VALID_BUNDLE);
        let signature = extract_signature(VALID_BUNDLE);

        // Extract TSA certificates from trusted root
        let tsa_certs = extract_tsa_certs(VALID_TRUSTED_ROOT);

        // The chain is leaf-first and root-last.
        let leaf = tsa_certs.first().unwrap().clone();
        let root = tsa_certs.last().unwrap().clone();
        let intermediates: Vec<_> = tsa_certs[1..tsa_certs.len() - 1].to_vec();

        let opts = VerifyOpts::new()
            .with_root(root)
            .with_intermediates(intermediates)
            .with_tsa_certificates(vec![leaf]);

        // Verify the timestamp
        let result = verify_timestamp_response(&timestamp_token, &signature, opts);
        assert!(
            result.is_ok(),
            "Timestamp verification should succeed: {:?}",
            result
        );

        let timestamp_result = result.unwrap();
        // The timestamp should be a valid datetime
        assert!(
            timestamp_result.time.as_second() > 0,
            "Timestamp should be positive"
        );
    }

    #[test]
    fn test_verify_timestamp_without_roots_fails() {
        // When no roots are provided, verification should fail
        let timestamp_token = extract_timestamp_token(VALID_BUNDLE);
        let signature = extract_signature(VALID_BUNDLE);

        let tsa_certs = extract_tsa_certs(VALID_TRUSTED_ROOT);
        let leaf = tsa_certs.first().unwrap().clone();
        let opts = VerifyOpts::new().with_tsa_certificates(vec![leaf]);

        // Should fail with CertificateValidationError
        let result = verify_timestamp_response(&timestamp_token, &signature, opts);
        assert!(
            result.is_err(),
            "Timestamp verification without roots should fail"
        );
        match result.unwrap_err() {
            Error::CertificateValidationError(msg) => {
                assert!(msg.contains("No trusted roots provided"));
            }
            other => panic!(
                "Expected CertificateValidationError error, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_verify_timestamp_accepts_pinned_signer_certificate() {
        let timestamp_token = extract_timestamp_token(VALID_BUNDLE);
        let signature = extract_signature(VALID_BUNDLE);

        let tsa_certs = extract_tsa_certs(VALID_TRUSTED_ROOT);
        // The chain is leaf-first: pin the CMS signer to the leaf.
        let leaf = tsa_certs.first().unwrap().clone();
        let root = tsa_certs.last().unwrap().clone();
        let intermediates: Vec<_> = tsa_certs[1..tsa_certs.len() - 1].to_vec();

        let opts = VerifyOpts::new()
            .with_root(root)
            .with_intermediates(intermediates)
            .with_tsa_certificates(vec![leaf]);

        let result = verify_timestamp_response(&timestamp_token, &signature, opts);
        assert!(
            result.is_ok(),
            "Timestamp signed by the pinned certificate should verify: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_timestamp_rejects_signer_not_in_pinned_certificates() {
        let timestamp_token = extract_timestamp_token(VALID_BUNDLE);
        let signature = extract_signature(VALID_BUNDLE);

        let tsa_certs = extract_tsa_certs(VALID_TRUSTED_ROOT);
        let root = tsa_certs.last().unwrap().clone();
        let intermediates: Vec<_> = tsa_certs[1..tsa_certs.len() - 1].to_vec();

        // Trusting the root as the leaf must reject the actual CMS signer.
        let opts = VerifyOpts::new()
            .with_root(root.clone())
            .with_intermediates(intermediates)
            .with_tsa_certificates(vec![root]);

        let result = verify_timestamp_response(&timestamp_token, &signature, opts);
        match result.unwrap_err() {
            Error::SignatureVerificationError(msg) => {
                assert!(
                    msg.contains("does not match any trusted TSA certificate"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!(
                "Expected SignatureVerificationError error, got: {:?}",
                other
            ),
        }
    }

    /// Build a [`TsaAuthority`] from the fixture trusted root's single TSA
    /// entry (chain is leaf-first, root last), with the given window.
    fn fixture_authority(valid_for: Option<sigstore_types::TimeRange>) -> TsaAuthority {
        use sigstore_types::DerCertificate;

        let root: serde_json::Value = serde_json::from_str(VALID_TRUSTED_ROOT).unwrap();
        let chain = root["timestampAuthorities"][0]["certChain"]["certificates"]
            .as_array()
            .unwrap();
        let der = |index: usize| {
            let raw = chain[index]["rawBytes"].as_str().unwrap();
            DerCertificate::new(STANDARD.decode(raw).unwrap())
        };
        TsaAuthority {
            leaf: der(0),
            intermediates: (1..chain.len() - 1).map(der).collect(),
            root: der(chain.len() - 1),
            valid_for,
        }
    }

    /// The fixture token's signed time, obtained through an unrestricted
    /// authority (absent `valid_for` window).
    fn authority_token_time() -> Timestamp {
        verify_timestamp_for_authority(
            &extract_timestamp_token(VALID_BUNDLE),
            &extract_signature(VALID_BUNDLE),
            &fixture_authority(None),
        )
        .expect("fixture token should verify under an unrestricted authority")
    }

    fn window_around(
        time: Timestamp,
        start_offset: i64,
        end_offset: i64,
    ) -> sigstore_types::TimeRange {
        let at = |offset: i64| Timestamp::from_second(time.as_second() + offset).unwrap();
        sigstore_types::TimeRange::new(at(start_offset), Some(at(end_offset)))
    }

    #[test]
    fn test_authority_verification_accepts_token_within_window() {
        let time = authority_token_time();
        let authority = fixture_authority(Some(window_around(time, -3600, 3600)));

        let result = verify_timestamp_for_authority(
            &extract_timestamp_token(VALID_BUNDLE),
            &extract_signature(VALID_BUNDLE),
            &authority,
        );
        assert_eq!(result.unwrap(), time);
    }

    #[test]
    fn test_authority_verification_rejects_token_outside_window() {
        // The window check cannot be skipped: an authenticated token whose
        // signing authority's window excludes it is a typed error carrying
        // the authenticated time.
        let time = authority_token_time();
        let authority = fixture_authority(Some(window_around(time, -7200, -3600)));

        let result = verify_timestamp_for_authority(
            &extract_timestamp_token(VALID_BUNDLE),
            &extract_signature(VALID_BUNDLE),
            &authority,
        );
        match result.unwrap_err() {
            Error::TimestampOutsideValidity { time: rejected } => assert_eq!(rejected, time),
            other => panic!("Expected TimestampOutsideValidity, got: {:?}", other),
        }
    }

    #[test]
    fn test_authority_verification_rejects_token_signed_by_other_leaf() {
        // An authority whose leaf is not the CMS signer must fail closed even
        // though the token chains to the same root: its window is never
        // consulted (a covering window cannot rescue the token).
        let time = authority_token_time();
        let mut authority = fixture_authority(Some(window_around(time, -3600, 3600)));
        authority.leaf = authority.root.clone();

        let result = verify_timestamp_for_authority(
            &extract_timestamp_token(VALID_BUNDLE),
            &extract_signature(VALID_BUNDLE),
            &authority,
        );
        match result.unwrap_err() {
            Error::SignatureVerificationError(msg) => {
                assert!(
                    msg.contains("does not match any trusted TSA certificate"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("Expected SignatureVerificationError, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_timestamp_payload_mismatch() {
        // This bundle has a valid timestamp but it doesn't match the signature
        let timestamp_token = extract_timestamp_token(PAYLOAD_MISMATCH_BUNDLE);
        let signature = extract_signature(PAYLOAD_MISMATCH_BUNDLE);

        let opts = VerifyOpts::new();

        // Should fail because the timestamp was created for a different signature
        let result = verify_timestamp_response(&timestamp_token, &signature, opts);
        assert!(result.is_err(), "Payload mismatch should be detected");

        // Check that it's a hash mismatch error
        let err = result.unwrap_err();
        match err {
            Error::HashMismatch { .. } => (),
            other => panic!("Expected HashMismatch error, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_timestamp_invalid_token() {
        // Try to verify with invalid/garbage timestamp token
        let invalid_token = b"this is not a valid timestamp token";
        let signature = extract_signature(VALID_BUNDLE);

        let opts = VerifyOpts::new();

        let result = verify_timestamp_response(invalid_token, &signature, opts);
        assert!(
            result.is_err(),
            "Invalid token should fail verification: {:?}",
            result
        );

        // Check that it's a parse error
        let err = result.unwrap_err();
        match err {
            Error::ParseError(_) => (),
            other => panic!("Expected ParseError, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_timestamp_empty_signature() {
        // Try to verify with empty signature bytes
        let timestamp_token = extract_timestamp_token(VALID_BUNDLE);
        let empty_signature: &[u8] = &[];

        let opts = VerifyOpts::new();

        let result = verify_timestamp_response(&timestamp_token, empty_signature, opts);
        assert!(
            result.is_err(),
            "Empty signature should fail verification: {:?}",
            result
        );

        // Should be a hash mismatch since hash of empty bytes != expected hash
        let err = result.unwrap_err();
        match err {
            Error::HashMismatch { .. } => (),
            other => panic!("Expected HashMismatch error, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_timestamp_wrong_signature() {
        // Try to verify with wrong signature bytes (but valid length)
        let timestamp_token = extract_timestamp_token(VALID_BUNDLE);
        let wrong_signature = vec![0u8; 64]; // Wrong signature content

        let opts = VerifyOpts::new();

        let result = verify_timestamp_response(&timestamp_token, &wrong_signature, opts);
        assert!(
            result.is_err(),
            "Wrong signature should fail verification: {:?}",
            result
        );

        // Should be a hash mismatch
        let err = result.unwrap_err();
        match err {
            Error::HashMismatch { .. } => (),
            other => panic!("Expected HashMismatch error, got: {:?}", other),
        }
    }

    /// Regression test for the SHA-256 hardcode in `verify_message_digest_attribute`.
    ///
    /// GitHub Actions's internal TSA signs CMS `SignedData` with SHA-384, declared in
    /// `SignerInfo.digestAlgorithm`. Before this fix the verifier assumed SHA-256 and
    /// rejected every GitHub-issued attestation with `HashMismatch { expected: <48 hex
    /// bytes>, actual: <32 hex bytes> }`. The bundle in
    /// `test_data/timestamps/github_sha384_bundle.json` is a real attestation from
    /// `jdx/communique@v0.1.9` and the trust root is GitHub's published TSA chain
    /// from <https://tuf-repo.github.com/>, narrowed to just `timestampAuthorities`.
    const GITHUB_SHA384_BUNDLE: &str =
        include_str!("../test_data/timestamps/github_sha384_bundle.json");
    const GITHUB_TRUSTED_ROOT: &str =
        include_str!("../test_data/timestamps/github_trusted_root.json");

    /// Helper to extract a DSSE envelope signature, matching how `sigstore-verify`'s
    /// `extract_signature` feeds DSSE bundles into `verify_timestamp_response`.
    fn extract_dsse_signature(bundle_json: &str) -> Vec<u8> {
        let bundle: serde_json::Value = serde_json::from_str(bundle_json).unwrap();
        let sig = bundle["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap();
        STANDARD.decode(sig).unwrap()
    }

    #[test]
    fn test_verify_github_sha384_timestamp() {
        let timestamp_token = extract_timestamp_token(GITHUB_SHA384_BUNDLE);
        let signature = extract_dsse_signature(GITHUB_SHA384_BUNDLE);

        // GitHub's TSA chain is not embedded in the CMS `SignedData.certificates`,
        // so `find_signer_certificate` needs the chain provided out-of-band.
        let tsa_certs = extract_tsa_certs(GITHUB_TRUSTED_ROOT);

        // The last cert is the root, others are intermediates/leaf
        let root = tsa_certs.last().unwrap().clone();
        let intermediates = tsa_certs[..tsa_certs.len() - 1].to_vec();

        let opts = VerifyOpts::new()
            .with_root(root)
            .with_intermediates(intermediates)
            .with_tsa_certificates(tsa_certs);

        let result = verify_timestamp_response(&timestamp_token, &signature, opts);
        assert!(
            result.is_ok(),
            "GitHub SHA-384 timestamp should verify: {:?}",
            result
        );
    }

    #[test]
    fn test_parse_timestamp_token_extracts_nonce() {
        let timestamp_token = extract_timestamp_token(VALID_BUNDLE);
        let (tst_info, _) = parse_timestamp_token(&timestamp_token).unwrap();

        // Verify that the nonce is correctly extracted
        assert!(tst_info.nonce.is_some());
    }
}
