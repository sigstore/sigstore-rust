//! Core types and data structures for Sigstore
//!
//! This crate provides the fundamental data structures used throughout the Sigstore
//! ecosystem, including bundle formats, transparency log entries, and trust roots.

pub mod artifact;
pub mod bundle;
pub mod checkpoint;
pub mod dsse;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod intoto;
pub mod time_range;
pub mod tsa_authority;

pub use artifact::{Artifact, ArtifactDigest};
pub use bundle::{
    Bundle, CertificateContent, CheckpointData, InclusionPromise, InclusionProof, KindVersion,
    LogId, MediaType, MessageDigest, MessageSignature, PublicKeyIdentifier, Rfc3161Timestamp,
    SignatureContent, TimestampVerificationData, TransparencyLogEntry, VerificationMaterial,
    VerificationMaterialContent, X509Certificate,
};
pub use checkpoint::{Checkpoint, CheckpointSignature};
pub use dsse::{pae, DsseEnvelope, DsseSignature};
pub use encoding::{
    CanonicalizedBody, DerCertificate, DerPublicKey, DigestBytes, EntryUuid, KeyHint, KeyId,
    LogIndex, LogKeyId, PayloadBytes, PemContent, Sha256Hash, Sha512Hash, SignatureBytes,
    SignedTimestamp, TimestampToken,
};
pub use error::{Error, Result};
pub use hash::HashAlgorithm;
pub use intoto::{Digest, Statement, Subject};
pub use time_range::TimeRange;
pub use tsa_authority::TsaAuthority;
