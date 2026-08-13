//! Certificate Transparency SCT (Signed Certificate Timestamp) verification
//!
//! This module provides types and functions for verifying SCTs embedded in certificates,
//! as defined by RFC 6962. SCTs provide proof that a certificate has been submitted to
//! a Certificate Transparency log.

use crate::error::{Error, Result};
use const_oid::db::rfc6962::CT_PRECERT_SCTS;
use sigstore_crypto::SigningScheme;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Sha256Hash, SignatureBytes};
use tls_codec::{SerializeBytes, TlsByteVecU16, TlsByteVecU24, TlsSerializeBytes, TlsSize};
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix::{sct::Version, SignedCertificateTimestamp, SignedCertificateTimestampList},
    Certificate,
};

// TLS SignatureAndHashAlgorithm constants (RFC 5246)
const ECDSA_SHA256: u16 = 0x0403;
const ECDSA_SHA384: u16 = 0x0503;
const RSA_PKCS1_SHA256: u16 = 0x0401;
const RSA_PKCS1_SHA384: u16 = 0x0501;
const RSA_PKCS1_SHA512: u16 = 0x0601;

/// SignatureType as defined in RFC 6962
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum SignatureType {
    CertificateTimestamp = 0,
    TreeHash = 1,
}

/// LogEntryType as defined in RFC 6962
#[derive(PartialEq, Debug)]
#[repr(u16)]
enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

/// PreCert structure for precertificate entries
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
struct PreCert {
    /// SHA-256 hash of the issuer's SubjectPublicKeyInfo
    issuer_key_hash: [u8; 32],
    /// The TBSCertificate with SCT extension removed
    tbs_certificate: TlsByteVecU24,
}

/// SignedEntry enum for different log entry types
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u16)]
enum SignedEntry {
    #[allow(unused)]
    #[tls_codec(discriminant = "LogEntryType::X509Entry")]
    X509Entry(TlsByteVecU24),
    #[tls_codec(discriminant = "LogEntryType::PrecertEntry")]
    PrecertEntry(PreCert),
}

/// The digitally-signed structure that is verified against the CT log's signature
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
pub struct DigitallySigned {
    version: Version,
    signature_type: SignatureType,
    timestamp: u64,
    signed_entry: SignedEntry,
    extensions: TlsByteVecU16,

    // These fields are not encoded in the TLS blob, but needed for verification
    #[tls_codec(skip)]
    log_id: [u8; 32],
    #[tls_codec(skip)]
    signature: Vec<u8>,
}

impl DigitallySigned {
    /// Create a DigitallySigned from an embedded SCT in a certificate
    pub fn from_embedded_sct(
        cert: &Certificate,
        sct: &SignedCertificateTimestamp,
        issuer_key_hash: [u8; 32],
    ) -> Result<Self> {
        // Reconstruct the precertificate TBS by removing the SCT extension
        let mut tbs_precert = cert.tbs_certificate.clone();
        tbs_precert.extensions = tbs_precert.extensions.map(|exts| {
            exts.iter()
                .filter(|ext| ext.extn_id != CT_PRECERT_SCTS)
                .cloned()
                .collect()
        });

        let mut tbs_precert_der = Vec::new();
        tbs_precert
            .encode_to_vec(&mut tbs_precert_der)
            .map_err(|e| Error::Verification(format!("failed to encode precert TBS: {}", e)))?;

        Ok(DigitallySigned {
            version: match sct.version {
                Version::V1 => Version::V1,
            },
            signature_type: SignatureType::CertificateTimestamp,
            timestamp: sct.timestamp,
            signed_entry: SignedEntry::PrecertEntry(PreCert {
                issuer_key_hash,
                tbs_certificate: tbs_precert_der.as_slice().into(),
            }),
            extensions: sct.extensions.clone(),
            log_id: sct.log_id.key_id,
            signature: sct.signature.signature.clone().into(),
        })
    }

    /// The bytes the CT log signed, serialized according to RFC 6962
    pub fn signed_data(&self) -> Result<Vec<u8>> {
        self.tls_serialize()
            .map_err(|e| Error::Verification(format!("failed to serialize SCT data: {}", e)))
    }

    /// The log ID this SCT claims to come from: RFC 6962 §3.2's key ID, i.e.
    /// the SHA-256 hash of the log's public key.
    pub fn log_id(&self) -> Sha256Hash {
        Sha256Hash::from_bytes(self.log_id)
    }
}

/// Map an RFC 5246 `SignatureAndHashAlgorithm` to a [`SigningScheme`]
fn sct_signing_scheme(sig_alg: u16) -> Result<SigningScheme> {
    match sig_alg {
        ECDSA_SHA256 => Ok(SigningScheme::EcdsaP256Sha256),
        ECDSA_SHA384 => Ok(SigningScheme::EcdsaP384Sha384),
        RSA_PKCS1_SHA256 => Ok(SigningScheme::RsaPkcs1Sha256),
        RSA_PKCS1_SHA384 => Ok(SigningScheme::RsaPkcs1Sha384),
        RSA_PKCS1_SHA512 => Ok(SigningScheme::RsaPkcs1Sha512),
        _ => Err(Error::Verification(format!(
            "unsupported SCT signature algorithm: 0x{:04x}",
            sig_alg
        ))),
    }
}

/// Extract the SCT from a certificate and prepare it for verification
pub fn extract_sct(
    cert: &Certificate,
    issuer_spki_der: &[u8],
) -> Result<(SignedCertificateTimestamp, [u8; 32])> {
    // Extract the SCT list extension from the certificate
    let scts: SignedCertificateTimestampList = match cert.tbs_certificate.get() {
        Ok(Some((_, ext))) => ext,
        _ => {
            return Err(Error::Verification(
                "certificate is missing SCT extension (Signed Certificate Timestamp)".to_string(),
            ))
        }
    };

    // Parse the SCT structures
    let timestamps = scts
        .parse_timestamps()
        .map_err(|e| Error::Verification(format!("failed to parse SCT list: {:?}", e)))?;

    // We expect exactly one SCT
    let sct = match timestamps.as_slice() {
        [single] => single
            .parse_timestamp()
            .map_err(|e| Error::Verification(format!("failed to parse SCT: {:?}", e)))?,
        [] => {
            return Err(Error::Verification(
                "no SCTs found in certificate".to_string(),
            ))
        }
        _ => {
            return Err(Error::Verification(
                "certificate contains multiple SCTs, expected exactly one".to_string(),
            ))
        }
    };

    // Calculate the issuer key hash (SHA-256 of issuer's SPKI)
    let issuer_key_hash = *sigstore_crypto::sha256(issuer_spki_der).as_bytes();

    Ok((sct, issuer_key_hash))
}

/// Verify the Signed Certificate Timestamp (SCT) embedded in the certificate
///
/// This is the main entry point for SCT verification. It extracts the SCT from the
/// certificate, reconstructs the signed data, and verifies it against the trusted
/// CT log keys.
pub fn verify_sct(
    cert_der: &[u8],
    issuer_spki_der: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<()> {
    // Parse the certificate
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    // Extract the SCT and calculate issuer key hash
    let (sct, issuer_key_hash) = extract_sct(&cert, issuer_spki_der)?;

    // Extract signature algorithm and signature bytes for verification
    // Convert the SignatureAndHashAlgorithm to u16
    let sig_alg_bytes = sct.signature.algorithm.tls_serialize().map_err(|e| {
        Error::Verification(format!("failed to serialize signature algorithm: {}", e))
    })?;
    let sig_alg = u16::from_be_bytes([sig_alg_bytes[0], sig_alg_bytes[1]]);
    let scheme = sct_signing_scheme(sig_alg)?;
    let signature = SignatureBytes::new(sct.signature.signature.clone().into_vec());

    // TrustedRoot constructs the keyring and preserves each CT log's declared
    // key ID and validity window. RFC 6962 timestamps are milliseconds since
    // the Unix epoch, so select the key that was valid when the SCT was issued.
    let keyring = trusted_root
        .ctfe_keys(scheme)
        .map_err(|e| Error::Verification(format!("failed to build CT keyring: {e}")))?;
    if keyring.is_empty() {
        return Err(Error::Verification(
            "no CT log keys in trusted root".to_string(),
        ));
    }

    let digitally_signed = DigitallySigned::from_embedded_sct(&cert, &sct, issuer_key_hash)?;
    let log_id = digitally_signed.log_id();
    let issued_at = jiff::Timestamp::from_millisecond(
        i64::try_from(sct.timestamp)
            .map_err(|_| Error::Verification("SCT timestamp is out of range".to_string()))?,
    )
    .map_err(|e| Error::Verification(format!("invalid SCT timestamp: {e}")))?;

    keyring
        .verify_with_key_id_at(
            &log_id,
            issued_at,
            &digitally_signed.signed_data()?,
            &signature,
        )
        .map_err(|e| Error::Verification(format!("SCT signature verification failed: {e}")))
}
