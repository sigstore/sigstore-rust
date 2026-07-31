//! Public key details from the protobuf-specs `PublicKeyDetails` enum
//!
//! The trusted root and other protobuf-specs messages declare, for every
//! public key, the exact signature algorithm it is used with. This module
//! parses that declaration into a typed value at deserialization time so
//! consumers never have to interpret raw strings.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The signature algorithm declared for a public key.
///
/// This mirrors the protobuf-specs `PublicKeyDetails` enum, including its
/// deprecated variants (which still appear in real trusted roots, e.g. the
/// staging CT log key) and variants this implementation cannot verify with
/// (post-quantum and stateful hash-based schemes). Values not known to this
/// implementation are preserved verbatim in [`KeyDetails::Unrecognized`] so
/// that a trusted root round-trips unchanged and a newer spec revision does
/// not fail parsing outright; whether an unrecognized key is an error is
/// decided where the key is used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyDetails {
    /// PKCS#1 v1.5-encoded RSA key, PKCS#1 v1.5 signatures (deprecated in the spec)
    Pkcs1RsaPkcs1v5,
    /// PKCS#1 v1.5-encoded RSA key, RSA-PSS signatures (deprecated in the spec)
    Pkcs1RsaPss,
    /// SPKI-encoded RSA key, PKCS#1 v1.5 signatures, unspecified size/hash (deprecated in the spec)
    PkixRsaPkcs1v5,
    /// SPKI-encoded RSA key, RSA-PSS signatures, unspecified size/hash (deprecated in the spec)
    PkixRsaPss,
    /// RSA-2048, PKCS#1 v1.5 signatures over SHA-256
    PkixRsaPkcs1v15_2048Sha256,
    /// RSA-3072, PKCS#1 v1.5 signatures over SHA-256
    PkixRsaPkcs1v15_3072Sha256,
    /// RSA-4096, PKCS#1 v1.5 signatures over SHA-256
    PkixRsaPkcs1v15_4096Sha256,
    /// RSA-2048, RSA-PSS signatures over SHA-256
    PkixRsaPss2048Sha256,
    /// RSA-3072, RSA-PSS signatures over SHA-256
    PkixRsaPss3072Sha256,
    /// RSA-4096, RSA-PSS signatures over SHA-256
    PkixRsaPss4096Sha256,
    /// ECDSA P-256 with HMAC-SHA-256 (deprecated in the spec)
    PkixEcdsaP256HmacSha256,
    /// ECDSA P-256 over SHA-256
    PkixEcdsaP256Sha256,
    /// ECDSA P-384 over SHA-384
    PkixEcdsaP384Sha384,
    /// ECDSA P-521 over SHA-512
    PkixEcdsaP521Sha512,
    /// Ed25519 (PureEdDSA)
    PkixEd25519,
    /// Ed25519ph (HashEdDSA)
    PkixEd25519Ph,
    /// LMS with SHA-256 (stateful hash-based)
    LmsSha256,
    /// LM-OTS with SHA-256 (one-time hash-based)
    LmotsSha256,
    /// ML-DSA-65 (post-quantum)
    MlDsa65,
    /// ML-DSA-87 (post-quantum)
    MlDsa87,
    /// A value this implementation does not know, preserved verbatim
    Unrecognized(String),
}

impl KeyDetails {
    /// The protojson wire name for this value.
    pub fn as_str(&self) -> &str {
        match self {
            KeyDetails::Pkcs1RsaPkcs1v5 => "PKCS1_RSA_PKCS1V5",
            KeyDetails::Pkcs1RsaPss => "PKCS1_RSA_PSS",
            KeyDetails::PkixRsaPkcs1v5 => "PKIX_RSA_PKCS1V5",
            KeyDetails::PkixRsaPss => "PKIX_RSA_PSS",
            KeyDetails::PkixRsaPkcs1v15_2048Sha256 => "PKIX_RSA_PKCS1V15_2048_SHA256",
            KeyDetails::PkixRsaPkcs1v15_3072Sha256 => "PKIX_RSA_PKCS1V15_3072_SHA256",
            KeyDetails::PkixRsaPkcs1v15_4096Sha256 => "PKIX_RSA_PKCS1V15_4096_SHA256",
            KeyDetails::PkixRsaPss2048Sha256 => "PKIX_RSA_PSS_2048_SHA256",
            KeyDetails::PkixRsaPss3072Sha256 => "PKIX_RSA_PSS_3072_SHA256",
            KeyDetails::PkixRsaPss4096Sha256 => "PKIX_RSA_PSS_4096_SHA256",
            KeyDetails::PkixEcdsaP256HmacSha256 => "PKIX_ECDSA_P256_HMAC_SHA_256",
            KeyDetails::PkixEcdsaP256Sha256 => "PKIX_ECDSA_P256_SHA_256",
            KeyDetails::PkixEcdsaP384Sha384 => "PKIX_ECDSA_P384_SHA_384",
            KeyDetails::PkixEcdsaP521Sha512 => "PKIX_ECDSA_P521_SHA_512",
            KeyDetails::PkixEd25519 => "PKIX_ED25519",
            KeyDetails::PkixEd25519Ph => "PKIX_ED25519_PH",
            KeyDetails::LmsSha256 => "LMS_SHA256",
            KeyDetails::LmotsSha256 => "LMOTS_SHA256",
            KeyDetails::MlDsa65 => "ML_DSA_65",
            KeyDetails::MlDsa87 => "ML_DSA_87",
            KeyDetails::Unrecognized(s) => s,
        }
    }
}

impl From<&str> for KeyDetails {
    fn from(s: &str) -> Self {
        match s {
            "PKCS1_RSA_PKCS1V5" => KeyDetails::Pkcs1RsaPkcs1v5,
            "PKCS1_RSA_PSS" => KeyDetails::Pkcs1RsaPss,
            "PKIX_RSA_PKCS1V5" => KeyDetails::PkixRsaPkcs1v5,
            "PKIX_RSA_PSS" => KeyDetails::PkixRsaPss,
            "PKIX_RSA_PKCS1V15_2048_SHA256" => KeyDetails::PkixRsaPkcs1v15_2048Sha256,
            "PKIX_RSA_PKCS1V15_3072_SHA256" => KeyDetails::PkixRsaPkcs1v15_3072Sha256,
            "PKIX_RSA_PKCS1V15_4096_SHA256" => KeyDetails::PkixRsaPkcs1v15_4096Sha256,
            "PKIX_RSA_PSS_2048_SHA256" => KeyDetails::PkixRsaPss2048Sha256,
            "PKIX_RSA_PSS_3072_SHA256" => KeyDetails::PkixRsaPss3072Sha256,
            "PKIX_RSA_PSS_4096_SHA256" => KeyDetails::PkixRsaPss4096Sha256,
            "PKIX_ECDSA_P256_HMAC_SHA_256" => KeyDetails::PkixEcdsaP256HmacSha256,
            "PKIX_ECDSA_P256_SHA_256" => KeyDetails::PkixEcdsaP256Sha256,
            "PKIX_ECDSA_P384_SHA_384" => KeyDetails::PkixEcdsaP384Sha384,
            "PKIX_ECDSA_P521_SHA_512" => KeyDetails::PkixEcdsaP521Sha512,
            "PKIX_ED25519" => KeyDetails::PkixEd25519,
            "PKIX_ED25519_PH" => KeyDetails::PkixEd25519Ph,
            "LMS_SHA256" => KeyDetails::LmsSha256,
            "LMOTS_SHA256" => KeyDetails::LmotsSha256,
            "ML_DSA_65" => KeyDetails::MlDsa65,
            "ML_DSA_87" => KeyDetails::MlDsa87,
            other => KeyDetails::Unrecognized(other.to_string()),
        }
    }
}

impl std::fmt::Display for KeyDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for KeyDetails {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyDetails {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(KeyDetails::from(s.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values_round_trip() {
        for name in [
            "PKCS1_RSA_PKCS1V5",
            "PKIX_RSA_PKCS1V15_2048_SHA256",
            "PKIX_RSA_PSS_4096_SHA256",
            "PKIX_ECDSA_P256_SHA_256",
            "PKIX_ECDSA_P384_SHA_384",
            "PKIX_ECDSA_P521_SHA_512",
            "PKIX_ED25519",
            "PKIX_ED25519_PH",
            "ML_DSA_87",
        ] {
            let parsed: KeyDetails = serde_json::from_str(&format!("\"{name}\"")).unwrap();
            assert!(!matches!(parsed, KeyDetails::Unrecognized(_)), "{name}");
            assert_eq!(serde_json::to_string(&parsed).unwrap(), format!("\"{name}\""));
        }
    }

    #[test]
    fn unrecognized_value_is_preserved() {
        let parsed: KeyDetails = serde_json::from_str("\"FUTURE_ALGORITHM\"").unwrap();
        assert_eq!(
            parsed,
            KeyDetails::Unrecognized("FUTURE_ALGORITHM".to_string())
        );
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            "\"FUTURE_ALGORITHM\""
        );
    }
}
