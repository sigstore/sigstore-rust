use crate::error::{Error, Result};
use futures_io::AsyncRead;
use sigstore_crypto::{hash_async_reader, hash_reader, ArtifactHasher, SigningScheme};
use sigstore_types::{
    Artifact, ArtifactDigest, HashAlgorithm, Sha256Hash, Sha512Hash, SignatureContent, Statement,
};
use std::io::Read;

/// Parse binding requirements before consuming caller input. The statement is
/// retained for the binding check, rather than parsed a second time after I/O.
pub(crate) struct ArtifactRequirements {
    algorithms: Vec<HashAlgorithm>,
    statement: Option<Statement>,
    message_scheme: Option<SigningScheme>,
}

impl ArtifactRequirements {
    pub(crate) fn new(content: &SignatureContent, scheme: SigningScheme) -> Result<Self> {
        match content {
            SignatureContent::MessageSignature(signature) => {
                let mut algorithms = vec![HashAlgorithm::Sha2256]; // hashedrekord
                for algorithm in signature
                    .message_digest
                    .as_ref()
                    .map(|d| d.algorithm)
                    .into_iter()
                    .chain(scheme.hash_algorithm())
                {
                    if !algorithms.contains(&algorithm) {
                        algorithms.push(algorithm);
                    }
                }
                Ok(Self {
                    algorithms,
                    statement: None,
                    message_scheme: Some(scheme),
                })
            }
            SignatureContent::DsseEnvelope(envelope) => {
                if envelope.payload_type != "application/vnd.in-toto+json" {
                    return Err(Error::Verification(format!(
                        "unsupported DSSE payload type {:?}: cannot bind artifact to attestation",
                        envelope.payload_type
                    )));
                }
                let statement: Statement = serde_json::from_slice(envelope.payload.as_bytes())
                    .map_err(|e| {
                        Error::Verification(format!("failed to parse in-toto statement: {e}"))
                    })?;
                if statement.subject.is_empty() {
                    return Err(Error::Verification(
                        "in-toto statement has no subjects: cannot bind artifact to attestation"
                            .into(),
                    ));
                }
                let algorithms = statement.subject_algorithms();
                if algorithms.is_empty() {
                    return Err(Error::Verification(
                        "in-toto statement has no supported subject digest algorithms".into(),
                    ));
                }
                Ok(Self {
                    algorithms,
                    statement: Some(statement),
                    message_scheme: None,
                })
            }
        }
    }

    fn hashers(&self) -> Vec<ArtifactHasher> {
        self.algorithms
            .iter()
            .copied()
            .map(ArtifactHasher::new)
            .collect()
    }

    fn check_reader(&self) -> Result<()> {
        if let Some(scheme) = self.message_scheme {
            if !scheme.supports_prehashed() {
                return Err(Error::Verification(format!("cannot verify signature from a digest or reader - scheme {} does not support prehashed mode", scheme.name())));
            }
        }
        Ok(())
    }

    pub(crate) fn verify_binding(&self, artifact: &PreparedArtifact<'_>) -> Result<()> {
        if let Some(statement) = &self.statement {
            let matches = artifact
                .sha256()
                .is_ok_and(|digest| statement.matches_sha256(&digest))
                || artifact
                    .sha512()
                    .is_ok_and(|digest| statement.matches_sha512(&digest));
            if !matches {
                return Err(Error::Verification(
                    "artifact hash does not match any subject in attestation".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Digests computed in one pass. Bytes are retained only for schemes such as
/// Ed25519 that cannot verify a prehashed message.
pub(crate) struct PreparedArtifact<'a> {
    blob: Option<&'a [u8]>,
    digests: Vec<ArtifactDigest>,
}

impl<'a> PreparedArtifact<'a> {
    pub(crate) fn from_artifact(
        artifact: Artifact<'a>,
        requirements: &ArtifactRequirements,
    ) -> Self {
        match artifact {
            Artifact::Blob(blob) => {
                let mut hashers = requirements.hashers();
                for hasher in &mut hashers {
                    hasher.update(blob);
                }
                Self {
                    blob: Some(blob),
                    digests: Self::finalize(hashers),
                }
            }
            Artifact::Digest(digest) => Self {
                blob: None,
                digests: vec![digest],
            },
        }
    }

    pub(crate) fn from_reader(
        reader: impl Read,
        requirements: &ArtifactRequirements,
    ) -> Result<PreparedArtifact<'static>> {
        requirements.check_reader()?;
        let mut hashers = requirements.hashers();
        hash_reader(reader, &mut hashers).map_err(Error::ArtifactRead)?;
        Ok(Self::from_digests(Self::finalize(hashers)))
    }

    pub(crate) async fn from_async_reader(
        reader: impl AsyncRead + Unpin,
        requirements: &ArtifactRequirements,
    ) -> Result<PreparedArtifact<'static>> {
        requirements.check_reader()?;
        let mut hashers = requirements.hashers();
        hash_async_reader(reader, &mut hashers)
            .await
            .map_err(Error::ArtifactRead)?;
        Ok(Self::from_digests(Self::finalize(hashers)))
    }

    fn finalize(hashers: Vec<ArtifactHasher>) -> Vec<ArtifactDigest> {
        hashers.into_iter().map(ArtifactHasher::finalize).collect()
    }

    fn from_digests(digests: Vec<ArtifactDigest>) -> PreparedArtifact<'static> {
        PreparedArtifact {
            blob: None,
            digests,
        }
    }

    pub(crate) fn blob(&self) -> Option<&[u8]> {
        self.blob
    }

    pub(crate) fn digest(&self, algorithm: HashAlgorithm) -> Result<ArtifactDigest> {
        self.digests
            .iter()
            .find(|digest| digest.algorithm() == algorithm)
            .cloned()
            .ok_or_else(|| {
                let supplied = self
                    .digests
                    .iter()
                    .map(|digest| digest.algorithm().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                Error::Verification(format!(
                    "verification requires an {algorithm} artifact digest; supplied: {supplied}"
                ))
            })
    }

    pub(crate) fn sha256(&self) -> Result<Sha256Hash> {
        Sha256Hash::try_from_slice(self.digest(HashAlgorithm::Sha2256)?.as_bytes())
            .map_err(|e| Error::Verification(e.to_string()))
    }

    pub(crate) fn sha512(&self) -> Result<Sha512Hash> {
        Sha512Hash::try_from_slice(self.digest(HashAlgorithm::Sha2512)?.as_bytes())
            .map_err(|e| Error::Verification(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::{DsseEnvelope, DsseSignature, PayloadBytes, SignatureBytes};

    #[test]
    fn scheme_and_subjects_select_the_required_digests() {
        let message = SignatureContent::MessageSignature(sigstore_types::MessageSignature {
            message_digest: None,
            signature: SignatureBytes::from_bytes(b"unused"),
        });
        let requirements =
            ArtifactRequirements::new(&message, SigningScheme::EcdsaP384Sha384).unwrap();
        let artifact = PreparedArtifact::from_reader(&b"hello"[..], &requirements).unwrap();
        assert!(artifact.digest(HashAlgorithm::Sha2256).is_ok());
        assert!(artifact.digest(HashAlgorithm::Sha2384).is_ok());
        assert!(artifact.digest(HashAlgorithm::Sha2512).is_err());
        let requirements = ArtifactRequirements::new(&message, SigningScheme::Ed25519).unwrap();
        let mut reader = std::io::Cursor::new(b"do not read");
        assert!(PreparedArtifact::from_reader(&mut reader, &requirements).is_err());
        assert_eq!(reader.position(), 0);

        let hash = sigstore_crypto::sha512(b"hello").to_hex();
        let content = SignatureContent::DsseEnvelope(DsseEnvelope::new("application/vnd.in-toto+json".into(), PayloadBytes::new(format!(r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{{"digest":{{"sha512":"{hash}"}}}}],"predicateType":"p","predicate":{{}}}}"#).into_bytes()), DsseSignature { sig: SignatureBytes::from_bytes(b"unused"), keyid: Default::default() }));
        let requirements = ArtifactRequirements::new(&content, SigningScheme::Ed25519).unwrap();
        assert_eq!(requirements.algorithms, vec![HashAlgorithm::Sha2512]);
        let artifact = PreparedArtifact::from_reader(&b"hello"[..], &requirements).unwrap();
        requirements.verify_binding(&artifact).unwrap();
        let wrong = PreparedArtifact::from_reader(&b"other"[..], &requirements).unwrap();
        assert!(requirements.verify_binding(&wrong).is_err());
    }
}
