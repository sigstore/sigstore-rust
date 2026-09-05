//! X.509 certificate utilities for Sigstore
//!
//! This module provides utilities for parsing and extracting information
//! from X.509 certificates used in Sigstore bundles.

use crate::error::{Error, Result};
use crate::KeyAlgorithm;
use sigstore_types::DerPublicKey;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

// OID constants for algorithm identification
use const_oid::ObjectIdentifier;

/// Fulcio issuer OID: 1.3.6.1.4.1.57264.1.1
/// This extension contains the OIDC issuer URL
const FULCIO_ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");

/// Information extracted from a certificate
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Identity from SAN extension (email or URI)
    pub identity: Option<String>,
    /// Issuer from certificate (OIDC issuer URL from Fulcio extension)
    pub issuer: Option<String>,
    /// Not valid before
    pub not_before: jiff::Timestamp,
    /// Not valid after
    pub not_after: jiff::Timestamp,
    /// Public key in DER-encoded SPKI format
    pub public_key: DerPublicKey,
    /// Key algorithm derived from the public key algorithm
    pub key_algorithm: KeyAlgorithm,
}

/// Parse certificate information from DER-encoded certificate
pub fn parse_certificate_info(cert_der: &[u8]) -> Result<CertificateInfo> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::InvalidCertificate(format!("failed to parse certificate: {}", e)))?;

    // Extract validity times
    let not_before =
        jiff::Timestamp::try_from(cert.tbs_certificate.validity.not_before.to_system_time())
            .map_err(|e| Error::InvalidCertificate(format!("invalid notBefore time: {}", e)))?;
    let not_after =
        jiff::Timestamp::try_from(cert.tbs_certificate.validity.not_after.to_system_time())
            .map_err(|e| Error::InvalidCertificate(format!("invalid notAfter time: {}", e)))?;

    // Extract public key in SPKI (SubjectPublicKeyInfo) DER format
    // This is required by aws-lc-rs UnparsedPublicKey, which expects the full SPKI,
    // not just the raw key bytes
    let public_key_info = &cert.tbs_certificate.subject_public_key_info;
    let public_key_der = public_key_info
        .to_der()
        .map_err(|e| Error::InvalidCertificate(format!("failed to encode SPKI: {}", e)))?;
    let public_key = DerPublicKey::new(public_key_der);

    // Determine key algorithm from algorithm OID and parameters
    let key_algorithm = KeyAlgorithm::from_spki(&public_key)?;

    // Extract identity from SAN extension
    let identity = extract_san_identity(&cert)?;

    // Extract issuer from Fulcio extension
    let issuer = extract_fulcio_issuer(&cert)?;

    Ok(CertificateInfo {
        identity,
        issuer,
        not_before,
        not_after,
        public_key,
        key_algorithm,
    })
}

/// Extract identity from Subject Alternative Name (SAN) extension
///
/// This extracts the email address or URI from the SAN extension using
/// x509-cert's proper ASN.1 parsing (handles all length encodings correctly).
pub fn extract_san_identity(cert: &Certificate) -> Result<Option<String>> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    // Try to get the SAN extension using the typed getter
    // Returns Option<(critical: bool, extension: T)>
    let san_opt: Option<(bool, SubjectAltName)> = cert
        .tbs_certificate
        .get()
        .map_err(|e| Error::InvalidCertificate(format!("failed to get SAN extension: {}", e)))?;

    let Some((_critical, san)) = san_opt else {
        return Ok(None);
    };

    // Iterate through GeneralNames and extract email or URI
    for name in san.0.iter() {
        match name {
            GeneralName::Rfc822Name(email) => {
                return Ok(Some(email.to_string()));
            }
            GeneralName::UniformResourceIdentifier(uri) => {
                return Ok(Some(uri.to_string()));
            }
            _ => continue,
        }
    }

    Ok(None)
}

/// Extract the OIDC issuer from Fulcio certificate extension
///
/// Fulcio certificates contain the OIDC issuer URL in extension OID 1.3.6.1.4.1.57264.1.1
pub fn extract_fulcio_issuer(cert: &Certificate) -> Result<Option<String>> {
    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None => return Ok(None),
    };

    for ext in extensions.iter() {
        if ext.extn_id == FULCIO_ISSUER_OID {
            // The extension value is a UTF8String wrapped in OCTET STRING
            let value_bytes = ext.extn_value.as_bytes();

            // Try to decode as UTF8String (the value is DER-encoded)
            if let Ok(utf8_str) = der::asn1::Utf8StringRef::from_der(value_bytes) {
                return Ok(Some(utf8_str.to_string()));
            }

            // Fallback: try to interpret the raw bytes as UTF-8
            if let Ok(s) = std::str::from_utf8(value_bytes) {
                return Ok(Some(s.to_string()));
            }

            return Err(Error::InvalidCertificate(
                "malformed Fulcio issuer extension".to_string(),
            ));
        }
    }

    Ok(None)
}
