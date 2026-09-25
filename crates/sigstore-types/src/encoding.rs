//! Encoding helpers and concrete types for sigstore
//!
//! This module provides concrete types with semantic meaning that handle
//! encoding/decoding internally. Each type represents a specific kind of data
//! and serializes appropriately (usually as base64).
//!
//! The design philosophy is:
//! - Use concrete newtype wrappers with semantic meaning
//! - Types handle their own encoding/decoding via serde
//! - Clear type names prevent mixing up different kinds of data

use crate::error::{Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

// ProtoJSON bytes permit standard/URL-safe alphabets, with or without padding.
fn decode_protojson_base64(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::{
        alphabet,
        engine::{
            general_purpose::{GeneralPurpose, GeneralPurposeConfig},
            DecodePaddingMode,
        },
    };
    let alphabet = if value.contains(['-', '_']) {
        &alphabet::URL_SAFE
    } else {
        &alphabet::STANDARD
    };
    GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
    .decode(value)
}

fn deserialize_proto_int64<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Visitor};

    struct ProtoInt64Visitor;

    impl Visitor<'_> for ProtoInt64Visitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a protobuf int64 as an integer or string")
        }

        fn visit_i64<E: Error>(self, value: i64) -> std::result::Result<i64, E> {
            Ok(value)
        }

        fn visit_u64<E: Error>(self, value: u64) -> std::result::Result<i64, E> {
            i64::try_from(value).map_err(Error::custom)
        }

        fn visit_str<E: Error>(self, value: &str) -> std::result::Result<i64, E> {
            value.parse().map_err(Error::custom)
        }
    }

    deserializer.deserialize_any(ProtoInt64Visitor)
}

// ============================================================================
// Serde helper modules (for use with raw Vec<u8> when needed)
// ============================================================================

/// Serde helper for u64 fields serialized as strings.
pub(crate) mod string_u64 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_proto_int64(deserializer).and_then(|value| {
            u64::try_from(value)
                .map_err(|_| serde::de::Error::custom(format!("invalid unsigned integer: {value}")))
        })
    }
}

/// Serde helper for optional timestamps serialized as string-encoded Unix
/// seconds (protobuf JSON `int64`).
///
/// Proto3 semantics make `0` and "absent" indistinguishable, so both map to
/// `None`. Any other value must be representable as a `jiff::Timestamp`, or
/// deserialization fails: an unrepresentable timestamp is rejected at parse
/// time instead of being carried around as a raw integer.
pub(crate) mod string_timestamp_opt {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<jiff::Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let seconds = value.map_or(0, |ts| ts.as_second());
        serializer.serialize_str(&seconds.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<jiff::Timestamp>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seconds = super::deserialize_proto_int64(deserializer)?;
        if seconds == 0 {
            return Ok(None);
        }
        jiff::Timestamp::from_second(seconds)
            .map(Some)
            .map_err(|e| serde::de::Error::custom(format!("invalid timestamp {}: {}", seconds, e)))
    }
}

// ============================================================================
// Macro for creating base64-encoded newtype wrappers
// ============================================================================

macro_rules! base64_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Create from raw bytes
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            /// Create from a byte slice
            pub fn from_bytes(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }

            /// Create from base64-encoded string
            pub fn from_base64(s: &str) -> Result<Self> {
                let bytes = decode_protojson_base64(s)
                    .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {}", e)))?;
                Ok(Self(bytes))
            }

            /// Encode as base64 string
            pub fn to_base64(&self) -> String {
                base64::engine::general_purpose::STANDARD.encode(&self.0)
            }

            /// Get the raw bytes
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Consume and return the inner bytes
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }

            /// Get the length in bytes
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Check if empty
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8]> for $name {
            fn from(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.to_base64())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.to_base64())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::from_base64(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

// ============================================================================
// Concrete Types for Different Kinds of Binary Data
// ============================================================================

base64_newtype!(
    /// DER-encoded X.509 certificate bytes
    ///
    /// This type represents a certificate in DER format (binary ASN.1).
    /// Serializes as base64 in JSON.
    ///
    /// # Example
    /// ```
    /// use sigstore_types::DerCertificate;
    ///
    /// // Parse from PEM (validates CERTIFICATE header)
    /// let pem = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----";
    /// let cert = DerCertificate::from_pem(pem).unwrap();
    ///
    /// // Convert back to PEM
    /// let pem_out = cert.to_pem();
    /// ```
    DerCertificate
);

impl DerCertificate {
    /// Parse from PEM-encoded certificate string.
    ///
    /// Validates that the PEM block has a `CERTIFICATE` header.
    /// Returns an error if the PEM is invalid or has the wrong type.
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let parsed = pem::parse(pem_str)
            .map_err(|e| Error::InvalidEncoding(format!("failed to parse PEM: {}", e)))?;

        if parsed.tag() != "CERTIFICATE" {
            return Err(Error::InvalidEncoding(format!(
                "expected CERTIFICATE PEM block, got {}",
                parsed.tag()
            )));
        }

        Ok(Self::new(parsed.contents().to_vec()))
    }

    /// Encode as PEM string with CERTIFICATE header.
    pub fn to_pem(&self) -> String {
        let pem_block = pem::Pem::new("CERTIFICATE", self.as_bytes());
        pem::encode(&pem_block)
    }
}

base64_newtype!(
    /// DER-encoded public key bytes (SubjectPublicKeyInfo format)
    ///
    /// This type represents a public key in DER format.
    /// Serializes as base64 in JSON.
    ///
    /// # Example
    /// ```
    /// use sigstore_types::DerPublicKey;
    ///
    /// // Parse from PEM (validates PUBLIC KEY header)
    /// let pem = "-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----";
    /// let key = DerPublicKey::from_pem(pem).unwrap();
    ///
    /// // Convert back to PEM
    /// let pem_out = key.to_pem();
    /// ```
    DerPublicKey
);

impl DerPublicKey {
    /// Parse from PEM-encoded public key string.
    ///
    /// Validates that the PEM block has a `PUBLIC KEY` header.
    /// Returns an error if the PEM is invalid or has the wrong type.
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let parsed = pem::parse(pem_str)
            .map_err(|e| Error::InvalidEncoding(format!("failed to parse PEM: {}", e)))?;

        if parsed.tag() != "PUBLIC KEY" {
            return Err(Error::InvalidEncoding(format!(
                "expected PUBLIC KEY PEM block, got {}",
                parsed.tag()
            )));
        }

        Ok(Self::new(parsed.contents().to_vec()))
    }

    /// Encode as PEM string with PUBLIC KEY header.
    pub fn to_pem(&self) -> String {
        let pem_block = pem::Pem::new("PUBLIC KEY", self.as_bytes());
        pem::encode(&pem_block)
    }
}

base64_newtype!(
    /// Cryptographic signature bytes
    ///
    /// This type represents raw signature bytes (format depends on algorithm).
    /// Serializes as base64 in JSON.
    SignatureBytes
);

base64_newtype!(
    /// DSSE payload bytes
    ///
    /// This type represents the payload content of a DSSE envelope.
    /// Serializes as base64 in JSON.
    PayloadBytes
);

base64_newtype!(
    /// Canonicalized Rekor entry body
    ///
    /// This type represents the canonicalized JSON body of a Rekor log entry.
    /// Serializes as base64 in JSON.
    CanonicalizedBody
);

base64_newtype!(
    /// Signed Entry Timestamp (SET) bytes
    ///
    /// This type represents a signed timestamp from the transparency log.
    /// Serializes as base64 in JSON.
    SignedTimestamp
);

base64_newtype!(
    /// RFC 3161 timestamp token bytes
    ///
    /// This type represents a DER-encoded RFC 3161 timestamp response.
    /// Serializes as base64 in JSON.
    TimestampToken
);

base64_newtype!(
    /// PEM-encoded content (double-encoded in base64)
    ///
    /// This type represents PEM text that gets base64-encoded for JSON.
    /// Used when APIs expect base64-encoded PEM strings.
    PemContent
);

// ============================================================================
// Identifier Types (String Wrappers for Semantic Clarity)
// ============================================================================

/// UUID for a Rekor log entry
///
/// This is the unique identifier for an entry in the transparency log. It is
/// treated as an opaque string: no format is enforced, because Rekor has
/// used both bare entry hashes and tree-ID-prefixed UUIDs.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryUuid(String);

impl EntryUuid {
    /// Wrap a string.
    pub fn new(s: impl Into<String>) -> Self {
        EntryUuid(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for EntryUuid {
    fn from(s: String) -> Self {
        EntryUuid::new(s)
    }
}

impl AsRef<str> for EntryUuid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntryUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A non-negative transparency-log index representable by protobuf `int64`.
///
/// Negative and overflowing values are rejected during deserialization, so
/// consumers never need to validate the sign before using an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LogIndex(u64);

impl LogIndex {
    /// Create a log index; fails if it does not fit a protobuf `int64`.
    pub fn new(index: u64) -> Result<Self> {
        if index > i64::MAX as u64 {
            return Err(Error::Validation("log index exceeds protobuf int64".into()));
        }
        Ok(Self(index))
    }

    /// The index.
    pub fn get(self) -> u64 {
        self.0
    }

    /// The index as a protobuf `int64`; never negative.
    pub fn as_i64(self) -> i64 {
        self.0 as i64
    }
}

impl TryFrom<u64> for LogIndex {
    type Error = Error;
    fn try_from(index: u64) -> Result<Self> {
        Self::new(index)
    }
}

impl TryFrom<i64> for LogIndex {
    type Error = Error;
    fn try_from(index: i64) -> Result<Self> {
        u64::try_from(index)
            .map(Self)
            .map_err(|_| Error::Validation("log index must not be negative".into()))
    }
}

impl From<LogIndex> for u64 {
    fn from(index: LogIndex) -> Self {
        index.0
    }
}

impl std::str::FromStr for LogIndex {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let index = s
            .parse::<u64>()
            .map_err(|e| Error::Validation(format!("invalid log index {s:?}: {e}")))?;
        Self::new(index)
    }
}

impl std::fmt::Display for LogIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for LogIndex {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as string to match existing bundle format
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for LogIndex {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = deserialize_proto_int64(deserializer)?;
        let value = u64::try_from(value)
            .map_err(|_| serde::de::Error::custom(format!("negative log index: {value}")))?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

base64_newtype!(
    /// Transparency log key ID (typically SHA-256 of the public key).
    LogKeyId
);

/// Key ID for signature key identification
///
/// Optional hint used in DSSE to identify which key was used for signing.
/// DSSE leaves its format to the signer, so it is treated as an opaque,
/// unauthenticated string.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Wrap a string.
    pub fn new(s: impl Into<String>) -> Self {
        KeyId(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        KeyId::new(s)
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================
// Key Hint Type (Fixed 4-byte Size)
// ============================================================================

/// Key hint for checkpoint signature identification (4 bytes)
///
/// The key hint is the first 4 bytes of SHA-256(public_key_der).
/// It is used in signed notes/checkpoints to match signatures to public keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyHint(#[serde(with = "base64_bytes_array4")] [u8; 4]);

impl KeyHint {
    /// Create a new key hint from a 4-byte array
    pub fn new(bytes: [u8; 4]) -> Self {
        KeyHint(bytes)
    }

    /// Get the key hint as a byte slice
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Get the key hint as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for KeyHint {
    type Error = Error;

    /// The slice must be exactly 4 bytes.
    fn try_from(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; 4] = slice.try_into().map_err(|_| {
            Error::Validation(format!(
                "key hint must be exactly 4 bytes, got {}",
                slice.len()
            ))
        })?;
        Ok(KeyHint(bytes))
    }
}

impl std::fmt::Display for KeyHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl From<[u8; 4]> for KeyHint {
    fn from(bytes: [u8; 4]) -> Self {
        KeyHint::new(bytes)
    }
}

impl AsRef<[u8]> for KeyHint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Serde helper for base64-encoded 4-byte arrays
mod base64_bytes_array4 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(&s)
            .map_err(|e| serde::de::Error::custom(format!("invalid base64: {}", e)))?;
        if bytes.len() != 4 {
            return Err(serde::de::Error::custom(format!(
                "expected 4 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ============================================================================
// Fixed-size hash types
// ============================================================================

/// Define a fixed-size hash type. Every hash type gets the same constructors,
/// encodings and conversions, so SHA-256 and SHA-512 stay interchangeable.
macro_rules! fixed_hash {
    ($(#[$meta:meta])* $name:ident, $len:literal, $label:literal) => {
        $(#[$meta])*
        ///
        /// Serializes as base64 and deserializes from hex or (ProtoJSON) base64.
        /// `Display` and `FromStr` use lowercase hex.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            #[doc = concat!("Wrap a ", $label, " digest.")]
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Parse a hex-encoded digest.
            pub fn from_hex(hex_str: &str) -> Result<Self> {
                let bytes = hex::decode(hex_str)
                    .map_err(|e| Error::InvalidEncoding(format!("invalid hex: {e}")))?;
                Self::try_from(bytes.as_slice())
            }

            /// Parse a base64-encoded digest (standard or URL-safe, padded or not).
            pub fn from_base64(s: &str) -> Result<Self> {
                let bytes = decode_protojson_base64(s)
                    .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {e}")))?;
                Self::try_from(bytes.as_slice())
            }

            /// Parse a hex or base64 digest, detecting the encoding by its shape.
            pub fn from_hex_or_base64(s: &str) -> Result<Self> {
                if s.len() == 2 * $len && s.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Self::from_hex(s);
                }
                Self::from_base64(s)
            }

            /// Lowercase hex encoding.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Standard, padded base64 encoding.
            pub fn to_base64(&self) -> String {
                base64::engine::general_purpose::STANDARD.encode(self.0)
            }

            /// The digest bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// The digest bytes as a slice.
            pub fn as_slice(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self> {
                let bytes: [u8; $len] = bytes.try_into().map_err(|_| {
                    Error::InvalidEncoding(format!(
                        concat!($label, " hash must be ", $len, " bytes, got {}"),
                        bytes.len()
                    ))
                })?;
                Ok(Self(bytes))
            }
        }

        impl TryFrom<DigestBytes> for $name {
            type Error = Error;

            fn try_from(digest: DigestBytes) -> Result<Self> {
                Self::try_from(digest.as_bytes())
            }
        }

        impl TryFrom<&DigestBytes> for $name {
            type Error = Error;

            fn try_from(digest: &DigestBytes) -> Result<Self> {
                Self::try_from(digest.as_bytes())
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(hash: $name) -> Self {
                hash.0
            }
        }

        impl From<$name> for DigestBytes {
            fn from(hash: $name) -> Self {
                DigestBytes(hash.0.to_vec())
            }
        }

        impl From<&$name> for DigestBytes {
            fn from(hash: &$name) -> Self {
                DigestBytes(hash.0.to_vec())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl std::str::FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                Self::from_hex(s)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.to_base64())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::from_hex_or_base64(&s).map_err(serde::de::Error::custom)
            }
        }

        impl PartialEq<DigestBytes> for $name {
            fn eq(&self, other: &DigestBytes) -> bool {
                self.as_slice() == other.as_bytes()
            }
        }

        impl PartialEq<$name> for DigestBytes {
            fn eq(&self, other: &$name) -> bool {
                self.as_bytes() == other.as_slice()
            }
        }

        impl PartialEq<[u8; $len]> for $name {
            fn eq(&self, other: &[u8; $len]) -> bool {
                &self.0 == other
            }
        }

        impl PartialEq<$name> for [u8; $len] {
            fn eq(&self, other: &$name) -> bool {
                self == &other.0
            }
        }

        impl<'a> PartialEq<&'a [u8]> for $name {
            fn eq(&self, other: &&'a [u8]) -> bool {
                self.as_slice() == *other
            }
        }

        impl PartialEq<$name> for &[u8] {
            fn eq(&self, other: &$name) -> bool {
                *self == other.as_slice()
            }
        }

        impl PartialEq<Vec<u8>> for $name {
            fn eq(&self, other: &Vec<u8>) -> bool {
                self.as_slice() == other.as_slice()
            }
        }

        impl PartialEq<$name> for Vec<u8> {
            fn eq(&self, other: &$name) -> bool {
                self.as_slice() == other.as_slice()
            }
        }
    };
}

fixed_hash!(
    /// SHA-256 hash digest (32 bytes)
    Sha256Hash,
    32,
    "SHA-256"
);

fixed_hash!(
    /// SHA-512 hash digest (64 bytes)
    Sha512Hash,
    64,
    "SHA-512"
);

// ============================================================================
// Arbitrary Digest Type (Flexible Size)
// ============================================================================

/// Arbitrary length hash digest
///
/// Flexible-size hash. Serializes as base64, deserializes from base64.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DigestBytes(Vec<u8>);

impl DigestBytes {
    /// Wrap digest bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        DigestBytes(bytes)
    }

    /// The digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Take ownership of the digest bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Length of the digest in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the digest is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Decode an explicitly hex-encoded digest (wire JSON uses base64 instead).
    pub fn from_hex(value: &str) -> Result<Self> {
        hex::decode(value)
            .map(Self)
            .map_err(|e| Error::InvalidEncoding(e.to_string()))
    }

    /// Lowercase hex encoding.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl AsRef<[u8]> for DigestBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for DigestBytes {
    fn from(bytes: &[u8]) -> Self {
        DigestBytes(bytes.to_vec())
    }
}

impl From<Vec<u8>> for DigestBytes {
    fn from(bytes: Vec<u8>) -> Self {
        DigestBytes(bytes)
    }
}

impl std::fmt::Display for DigestBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for DigestBytes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for DigestBytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = decode_protojson_base64(&s).map_err(serde::de::Error::custom)?;
        Ok(DigestBytes(bytes))
    }
}

impl<'a> PartialEq<&'a [u8]> for DigestBytes {
    fn eq(&self, other: &&'a [u8]) -> bool {
        self.as_bytes() == *other
    }
}

impl PartialEq<DigestBytes> for &[u8] {
    fn eq(&self, other: &DigestBytes) -> bool {
        *self == other.as_bytes()
    }
}

impl PartialEq<Vec<u8>> for DigestBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl PartialEq<DigestBytes> for Vec<u8> {
    fn eq(&self, other: &DigestBytes) -> bool {
        self.as_slice() == other.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_index_and_digest_wire_roundtrips() {
        assert!(LogIndex::new(u64::MAX).is_err());
        assert!(serde_json::from_str::<LogIndex>(&u64::MAX.to_string()).is_err());
        for bytes in [vec![0; 48], vec![0xff; 32], vec![0xfb; 64]] {
            let digest = DigestBytes::new(bytes.clone());
            assert_eq!(
                serde_json::from_str::<DigestBytes>(&serde_json::to_string(&digest).unwrap())
                    .unwrap(),
                digest
            );
            for engine in [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::STANDARD_NO_PAD,
                base64::engine::general_purpose::URL_SAFE,
                base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ] {
                let json = serde_json::to_string(&engine.encode(&bytes)).unwrap();
                assert_eq!(serde_json::from_str::<DigestBytes>(&json).unwrap(), digest);
            }
        }
    }

    #[test]
    fn test_der_certificate_roundtrip() {
        let cert = DerCertificate::from_bytes(b"fake cert data");
        let json = serde_json::to_string(&cert).unwrap();
        let decoded: DerCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, decoded);
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let sig = SignatureBytes::from_bytes(b"fake signature");
        let json = serde_json::to_string(&sig).unwrap();
        let decoded: SignatureBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn test_sha256_hash() {
        let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash = Sha256Hash::from_hex(hash_hex).unwrap();
        assert_eq!(hash.to_hex(), hash_hex);

        // Can also deserialize from hex
        let json_hex = format!("\"{}\"", hash_hex);
        let from_hex: Sha256Hash = serde_json::from_str(&json_hex).unwrap();
        assert_eq!(hash, from_hex);
    }

    #[test]
    fn log_index_deserializes_only_non_negative_protobuf_int64_values() {
        assert_eq!(
            serde_json::from_str::<LogIndex>("\"42\"").unwrap().get(),
            42
        );
        assert_eq!(serde_json::from_str::<LogIndex>("42").unwrap().get(), 42);
        assert!(serde_json::from_str::<LogIndex>("-1").is_err());
        assert!(serde_json::from_str::<LogIndex>("\"-1\"").is_err());
        assert!(serde_json::from_str::<LogIndex>("9223372036854775808").is_err());
    }

    #[test]
    fn log_key_id_accepts_protojson_base64_variants() {
        let bytes = [0xfb, 0xff, 0xef, 0xfa];
        for engine in [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            let json = serde_json::to_string(&engine.encode(bytes)).unwrap();
            assert_eq!(
                serde_json::from_str::<LogKeyId>(&json).unwrap().as_bytes(),
                bytes
            );
        }
        assert!(serde_json::from_str::<LogKeyId>(r#""not base64!""#).is_err());
    }

    #[test]
    fn test_certificate_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----";
        let cert = DerCertificate::from_pem(pem).unwrap();
        assert_eq!(cert.as_bytes(), b"abcd");
    }

    #[test]
    fn test_certificate_from_pem_wrong_type() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----";
        let result = DerCertificate::from_pem(pem);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected CERTIFICATE"));
    }

    #[test]
    fn test_certificate_to_pem() {
        let cert = DerCertificate::from_bytes(b"abcd");
        let pem = cert.to_pem();
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));

        // Round-trip
        let cert2 = DerCertificate::from_pem(&pem).unwrap();
        assert_eq!(cert, cert2);
    }

    #[test]
    fn test_public_key_from_pem() {
        let pem = "-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----";
        let key = DerPublicKey::from_pem(pem).unwrap();
        assert_eq!(key.as_bytes(), b"abcd");
    }

    #[test]
    fn test_public_key_from_pem_wrong_type() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----";
        let result = DerPublicKey::from_pem(pem);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected PUBLIC KEY"));
    }

    #[test]
    fn test_public_key_to_pem() {
        let key = DerPublicKey::from_bytes(b"abcd");
        let pem = key.to_pem();
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));

        // Round-trip
        let key2 = DerPublicKey::from_pem(&pem).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_digest_interoperability() {
        let raw_bytes = [5u8; 32];
        let sha_hash = Sha256Hash::new(raw_bytes);
        let digest_bytes = DigestBytes::new(raw_bytes.to_vec());

        // From/TryFrom conversions
        let converted_digest: DigestBytes = sha_hash.into();
        assert_eq!(converted_digest, digest_bytes);

        let converted_sha1: Sha256Hash = digest_bytes.clone().try_into().unwrap();
        assert_eq!(converted_sha1, sha_hash);

        let converted_sha2: Sha256Hash = (&digest_bytes).try_into().unwrap();
        assert_eq!(converted_sha2, sha_hash);

        let array: [u8; 32] = sha_hash.into();
        assert_eq!(array, raw_bytes);

        // Invalid length TryFrom
        let bad_digest = DigestBytes::new(vec![1u8; 16]);
        let bad_sha_result = Sha256Hash::try_from(bad_digest);
        assert!(bad_sha_result.is_err());

        // PartialEq comparisons
        assert_eq!(sha_hash, digest_bytes);
        assert_eq!(digest_bytes, sha_hash);

        assert_eq!(sha_hash, raw_bytes);
        assert_eq!(raw_bytes, sha_hash);

        assert_eq!(sha_hash, raw_bytes.as_slice());
        assert_eq!(raw_bytes.as_slice(), sha_hash);

        let vec_bytes = raw_bytes.to_vec();
        assert_eq!(sha_hash, vec_bytes);
        assert_eq!(vec_bytes, sha_hash);

        assert_eq!(digest_bytes, raw_bytes.as_slice());
        assert_eq!(raw_bytes.as_slice(), digest_bytes);

        assert_eq!(digest_bytes, vec_bytes);
        assert_eq!(vec_bytes, digest_bytes);
    }

    #[test]
    fn test_sha512_hash_matches_sha256_hash_api() {
        let hash = Sha512Hash::new([7u8; 64]);
        let hex = hash.to_hex();
        assert_eq!(hash.to_string(), hex);
        assert_eq!(hex.parse::<Sha512Hash>().unwrap(), hash);
        assert_eq!(Sha512Hash::from_base64(&hash.to_base64()).unwrap(), hash);
        assert_eq!(Sha512Hash::from_hex_or_base64(&hex).unwrap(), hash);

        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{}\"", hash.to_base64()));
        assert_eq!(serde_json::from_str::<Sha512Hash>(&json).unwrap(), hash);

        let digest = DigestBytes::from(hash);
        assert_eq!(Sha512Hash::try_from(&digest).unwrap(), hash);
        assert_eq!(hash, digest);
        assert!(Sha512Hash::try_from(&[0u8; 32][..]).is_err());

        let sha256 = Sha256Hash::new([1u8; 32]);
        assert_eq!(sha256.to_string().parse::<Sha256Hash>().unwrap(), sha256);
        assert_eq!(
            KeyHint::try_from(&[1u8, 2, 3, 4][..]).unwrap().to_string(),
            "01020304"
        );
    }

    #[test]
    fn test_log_index_conversions() {
        let index: LogIndex = "42".parse().unwrap();
        assert_eq!(index.get(), 42);
        assert_eq!(u64::from(index), 42);
        assert_eq!(LogIndex::try_from(42i64).unwrap(), index);
        assert!(LogIndex::try_from(-1i64).is_err());
        assert!(LogIndex::try_from(u64::MAX).is_err());
        assert!("-1".parse::<LogIndex>().is_err());
    }
}
