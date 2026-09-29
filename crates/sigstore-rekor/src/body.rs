//! Strongly-typed Rekor entry body structures
//!
//! This module provides typed representations of the canonicalized body
//! content for different Rekor entry types and versions.

use crate::entry::RekorV2KeyDetails;
use crate::hex_encoded::HexHash;
use serde::{Deserialize, Serialize};
use sigstore_types::{
    CanonicalizedBody, DerCertificate, DerPublicKey, DigestBytes, HashAlgorithm, KindVersion,
    PemContent, SignatureBytes,
};

/// Parsed Rekor entry body
///
/// Parse with [`RekorEntryBody::parse`] (for bundle entries) or
/// [`RekorEntryBody::from_json`], which select the body type from the entry's
/// kind and version rather than guessing from its shape.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum RekorEntryBody {
    /// HashedRekord v0.0.1
    HashedRekordV001(HashedRekordV001Body),
    /// HashedRekord v0.0.2
    HashedRekordV002(HashedRekordV002Body),
    /// DSSE v0.0.1
    DsseV001(DsseV001Body),
    /// DSSE v0.0.2
    DsseV002(DsseV002Body),
    /// Intoto v0.0.2
    IntotoV002(IntotoV002Body),
}

// ============================================================================
// HashedRekord v0.0.1
// ============================================================================

/// Body of a `hashedrekord` v0.0.1 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashedRekordV001Body {
    /// The entry-kind specific content.
    pub spec: HashedRekordV001Spec,
}

/// The `spec` of a `hashedrekord` v0.0.1 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashedRekordV001Spec {
    /// The signed artifact.
    pub data: HashedRekordV001Data,
    /// The signature and the material to verify it.
    pub signature: HashedRekordV001Signature,
}

/// The artifact a `hashedrekord` v0.0.1 entry was made for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashedRekordV001Data {
    /// Digest of the signed artifact.
    pub hash: HashValue,
}

/// A hash algorithm and hex-encoded digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashValue {
    /// The hash algorithm.
    pub algorithm: HashAlgorithm,
    /// Hex-encoded hash value (used in v0.0.1)
    pub value: HexHash,
}

/// Signature and verification material of a `hashedrekord` v0.0.1 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HashedRekordV001Signature {
    /// Base64-encoded signature
    pub content: SignatureBytes,
    /// The key or certificate that verifies the signature.
    pub public_key: PublicKeyContent,
}

/// PEM verification material: a certificate or a public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PublicKeyContent {
    /// Base64-encoded PEM public key (double-encoded: base64 of PEM text)
    pub content: PemContent,
}

impl PublicKeyContent {
    /// Parse the PEM content and return a DER certificate.
    pub fn parse_certificate(&self) -> Result<DerCertificate, crate::error::Error> {
        let pem_bytes = self.content.as_bytes();
        let pem_str = String::from_utf8(pem_bytes.to_vec()).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("PEM not valid UTF-8: {}", e))
        })?;
        DerCertificate::from_pem(&pem_str).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("failed to parse certificate PEM: {}", e))
        })
    }

    /// Parse the PEM content and return a DER SubjectPublicKeyInfo public key.
    pub fn parse_public_key(&self) -> Result<DerPublicKey, crate::error::Error> {
        let pem_bytes = self.content.as_bytes();
        let pem_str = String::from_utf8(pem_bytes.to_vec()).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("PEM not valid UTF-8: {}", e))
        })?;
        DerPublicKey::from_pem(&pem_str).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("failed to parse public key PEM: {}", e))
        })
    }
}

// ============================================================================
// HashedRekord v0.0.2
// ============================================================================

/// Body of a `hashedrekord` v0.0.2 (Rekor v2) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashedRekordV002Body {
    /// The entry-kind specific content.
    pub spec: HashedRekordV002Spec,
}

/// The `spec` of a `hashedrekord` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HashedRekordV002Spec {
    /// The `hashedRekordV002` content.
    pub hashed_rekord_v002: HashedRekordV002Data,
}

/// The artifact digest and signature of a `hashedrekord` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashedRekordV002Data {
    /// The signed artifact.
    pub data: HashedRekordV002DataInner,
    /// The signature and the material to verify it.
    pub signature: HashedRekordV002Signature,
}

/// The artifact digest of a `hashedrekord` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashedRekordV002DataInner {
    /// Algorithm used for the logged digest.
    pub algorithm: HashAlgorithm,
    /// Hash digest (base64 on the wire)
    pub digest: DigestBytes,
}

/// Signature and verifier of a `hashedrekord` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HashedRekordV002Signature {
    /// Base64-encoded signature
    pub content: SignatureBytes,
    /// The key that verifies the signature.
    pub verifier: HashedRekordV002Verifier,
}

/// The key that made a Rekor v2 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HashedRekordV002Verifier {
    /// Signature algorithm and key encoding authenticated by the log entry.
    pub key_details: RekorV2KeyDetails,
    /// The signing certificate, for keyless signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<X509CertificateRaw>,
    /// The key or certificate that verifies the signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyRaw>,
}

/// A DER-encoded X.509 certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct X509CertificateRaw {
    /// DER-encoded certificate
    pub raw_bytes: DerCertificate,
}

/// A DER-encoded SubjectPublicKeyInfo public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PublicKeyRaw {
    /// DER-encoded public key
    pub raw_bytes: DerPublicKey,
}

// ============================================================================
// DSSE v0.0.1
// ============================================================================

/// Body of a `dsse` v0.0.1 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DsseV001Body {
    /// The entry-kind specific content.
    pub spec: DsseV001Spec,
}

/// The `spec` of a `dsse` v0.0.1 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DsseV001Spec {
    /// Hash of the complete DSSE envelope.
    pub envelope_hash: EnvelopeHash,
    /// Hash of the DSSE payload.
    pub payload_hash: PayloadHashV001,
    /// The envelope signatures.
    pub signatures: Vec<DsseV001Signature>,
}

/// Hash of a complete DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EnvelopeHash {
    /// The hash algorithm.
    pub algorithm: HashAlgorithm,
    /// The digest value.
    pub value: String,
}

/// Hash of a DSSE payload in a `dsse` v0.0.1 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PayloadHashV001 {
    /// The hash algorithm.
    pub algorithm: HashAlgorithm,
    /// Hash value (hex or base64-encoded depending on algorithm)
    pub value: String,
}

/// A signature over a DSSE envelope, with its verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DsseV001Signature {
    /// Signature bytes
    pub signature: SignatureBytes,
    /// PEM-encoded certificate (base64-encoded)
    pub verifier: PemContent,
}

impl DsseV001Signature {
    /// Parse the PEM verifier and return a DER certificate.
    pub fn parse_certificate(&self) -> Result<DerCertificate, crate::error::Error> {
        let pem_bytes = self.verifier.as_bytes();
        let pem_str = String::from_utf8(pem_bytes.to_vec()).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("PEM not valid UTF-8: {}", e))
        })?;
        DerCertificate::from_pem(&pem_str).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("failed to parse certificate PEM: {}", e))
        })
    }
}

// ============================================================================
// DSSE v0.0.2
// ============================================================================

/// Body of a `dsse` v0.0.2 (Rekor v2) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DsseV002Body {
    /// The entry-kind specific content.
    pub spec: DsseV002Spec,
}

/// The `spec` of a `dsse` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DsseV002Spec {
    /// The `dsseV002` content.
    pub dsse_v002: DsseV002Data,
}

/// Payload hash and signatures of a `dsse` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DsseV002Data {
    /// Hash of the DSSE payload.
    pub payload_hash: PayloadHash,
    /// The envelope signatures.
    pub signatures: Vec<DsseV002Signature>,
}

/// Hash of a DSSE payload in a `dsse` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PayloadHash {
    /// The hash algorithm.
    pub algorithm: HashAlgorithm,
    /// Hash digest (base64 on the wire)
    pub digest: DigestBytes,
}

/// A signature over a DSSE envelope in a `dsse` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DsseV002Signature {
    /// Signature bytes
    pub content: SignatureBytes,
    /// Verifier information (certificate and key details)
    pub verifier: DsseV002Verifier,
}

/// The key that made a `dsse` v0.0.2 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DsseV002Verifier {
    /// Key algorithm details (e.g., "PKIX_ECDSA_P256_SHA_256")
    pub key_details: String,
    /// X.509 certificate, when the signature was made by a certificate's key.
    ///
    /// Exactly one of `x509_certificate` and `public_key` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<X509CertificateRaw>,
    /// Public key, when the signature was made by a managed key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyRaw>,
}

// ============================================================================
// Intoto v0.0.2
// ============================================================================

/// Body of an `intoto` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntotoV002Body {
    /// The entry-kind specific content.
    pub spec: IntotoV002Spec,
}

/// The `spec` of an `intoto` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IntotoV002Spec {
    /// The logged content.
    pub content: IntotoV002Content,
}

/// The logged envelope and its hashes in an `intoto` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IntotoV002Content {
    /// The logged DSSE envelope.
    pub envelope: IntotoEnvelope,
    /// Hash of the complete submitted DSSE envelope.
    pub hash: HashValue,
    /// Hash of the decoded DSSE payload.
    pub payload_hash: HashValue,
}

/// The DSSE envelope recorded by an `intoto` v0.0.2 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IntotoEnvelope {
    /// DSSE payload type. Canonical log entries omit the proposed payload.
    pub payload_type: String,
    /// The envelope signatures.
    pub signatures: Vec<IntotoSignature>,
}

/// A signature in an `intoto` v0.0.2 envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IntotoSignature {
    /// Optional key identifier hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Signature bytes (double-encoded in Rekor).
    pub sig: SignatureBytes,
    /// PEM certificate or public key associated with the signature.
    pub public_key: PemContent,
}

impl IntotoSignature {
    /// Parse the PEM verifier as an X.509 certificate.
    pub fn parse_certificate(&self) -> Result<DerCertificate, crate::error::Error> {
        let pem_str = self.verifier_pem()?;
        DerCertificate::from_pem(&pem_str).map_err(|e| {
            crate::error::Error::InvalidResponse(format!(
                "failed to parse intoto signature certificate PEM: {}",
                e
            ))
        })
    }

    /// Parse the PEM verifier as a SubjectPublicKeyInfo public key.
    pub fn parse_public_key(&self) -> Result<DerPublicKey, crate::error::Error> {
        let pem_str = self.verifier_pem()?;
        DerPublicKey::from_pem(&pem_str).map_err(|e| {
            crate::error::Error::InvalidResponse(format!(
                "failed to parse intoto signature public key PEM: {}",
                e
            ))
        })
    }

    fn verifier_pem(&self) -> Result<String, crate::error::Error> {
        String::from_utf8(self.public_key.as_bytes().to_vec()).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("PEM not valid UTF-8: {}", e))
        })
    }
}

// ============================================================================
// Helper functions
// ============================================================================

impl RekorEntryBody {
    /// Parse the canonicalized body of a bundle's transparency log entry.
    pub fn parse(
        body: &CanonicalizedBody,
        kind_version: KindVersion,
    ) -> Result<Self, crate::error::Error> {
        Self::from_json(body.as_bytes(), kind_version.kind(), kind_version.version())
    }

    /// Parse a JSON entry body of the given Rekor `kind` and `version`.
    ///
    /// Use this for entry types that bundles cannot carry, such as
    /// `dsse`/`0.0.2`.
    pub fn from_json(body: &[u8], kind: &str, version: &str) -> Result<Self, crate::error::Error> {
        let body_str = std::str::from_utf8(body).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("body is not valid UTF-8: {}", e))
        })?;

        // Parse based on kind and version
        match (kind, version) {
            ("hashedrekord", "0.0.1") => {
                let body: HashedRekordV001Body = serde_json::from_str(body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse hashedrekord v0.0.1 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::HashedRekordV001(body))
            }
            ("hashedrekord", "0.0.2") => {
                let body: HashedRekordV002Body = serde_json::from_str(body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse hashedrekord v0.0.2 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::HashedRekordV002(body))
            }
            ("dsse", "0.0.1") => {
                let body: DsseV001Body = serde_json::from_str(body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse dsse v0.0.1 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::DsseV001(body))
            }
            ("dsse", "0.0.2") => {
                let body: DsseV002Body = serde_json::from_str(body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse dsse v0.0.2 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::DsseV002(body))
            }
            ("intoto", "0.0.2") => {
                let body: IntotoV002Body = serde_json::from_str(body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse intoto v0.0.2 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::IntotoV002(body))
            }
            _ => Err(crate::error::Error::InvalidResponse(format!(
                "unsupported entry kind/version: {}/{}",
                kind, version
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hashedrekord_v001() {
        let body_json = r#"{
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": "abcd1234"
                    }
                },
                "signature": {
                    "content": "c2lnbmF0dXJl",
                    "publicKey": {
                        "content": "cHVibGlja2V5"
                    }
                }
            }
        }"#;

        let body = RekorEntryBody::from_json(body_json.as_bytes(), "hashedrekord", "0.0.1");
        assert!(body.is_ok());
    }

    fn parse_dsse_v002(verifier: &str) -> DsseV002Body {
        let body_json = format!(
            r#"{{"apiVersion": "0.0.2", "kind": "dsse", "spec": {{"dsseV002": {{
                "payloadHash": {{"algorithm": "SHA2_256",
                    "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
                "signatures": [{{"content": "c2lnbmF0dXJl", "verifier": {verifier}}}]
            }}}}}}"#
        );
        match RekorEntryBody::from_json(body_json.as_bytes(), "dsse", "0.0.2").unwrap() {
            RekorEntryBody::DsseV002(body) => body,
            other => panic!("expected dsse v0.0.2 body, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_dsse_v002_with_public_key_verifier() {
        let body = parse_dsse_v002(
            r#"{"publicKey": {"rawBytes": "cHVibGlja2V5"}, "keyDetails": "PKIX_ED25519"}"#,
        );
        let verifier = &body.spec.dsse_v002.signatures[0].verifier;
        assert_eq!(verifier.key_details, "PKIX_ED25519");
        assert!(verifier.x509_certificate.is_none());
        assert_eq!(
            verifier.public_key.as_ref().unwrap().raw_bytes.as_bytes(),
            b"publickey"
        );
    }

    #[test]
    fn test_parse_dsse_v002_with_certificate_verifier() {
        let body = parse_dsse_v002(
            r#"{"x509Certificate": {"rawBytes": "Y2VydA=="}, "keyDetails": "PKIX_ECDSA_P256_SHA_256"}"#,
        );
        let verifier = &body.spec.dsse_v002.signatures[0].verifier;
        assert!(verifier.public_key.is_none());
        assert!(verifier.x509_certificate.is_some());
    }
}
