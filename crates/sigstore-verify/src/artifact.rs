use crate::error::{Error, Result};
use futures_io::AsyncRead;
use sigstore_crypto::{hash_async_reader, hash_reader, ArtifactHasher, SigningScheme};
use sigstore_types::{
    Artifact, ArtifactDigest, HashAlgorithm, Sha256Hash, Sha512Hash, SignatureContent, Statement,
};
use std::io::Read;

/// Artifact data normalized for the verification core.
///
/// Every input is hashed at most once. Blob and reader input are run through
/// all the digest algorithms the bundle content can ask for in a single pass;
/// digest input supplies exactly one digest. Blob callers additionally retain
/// their bytes for schemes that cannot verify prehashed input.
pub(crate) struct PreparedArtifact<'a> {
    blob: Option<&'a [u8]>,
    digests: Vec<ArtifactDigest>,
}

/// How the signature over a `MessageSignature` artifact will be checked.
///
/// Blob input keeps its bytes, so the signature is verified over them directly
/// and only the digests that bind the artifact to the bundle are needed.
/// Streamed input keeps nothing but digests, so the signature must be verified
/// prehashed and the single pass over the reader has to produce the digest the
/// signing scheme consumes.
#[derive(Clone, Copy)]
enum SignatureInput {
    Bytes,
    Prehashed(Option<SigningScheme>),
}

fn require(algorithms: &mut Vec<HashAlgorithm>, algorithm: HashAlgorithm) {
    if !algorithms.contains(&algorithm) {
        algorithms.push(algorithm);
    }
}

/// The digest algorithms verification can request for this bundle content.
fn required_algorithms(content: &SignatureContent, input: SignatureInput) -> Vec<HashAlgorithm> {
    match content {
        SignatureContent::MessageSignature(signature) => {
            // hashedrekord binds SHA-256; the declared messageDigest may use
            // another algorithm and is compared against the artifact as well.
            let mut algorithms = vec![HashAlgorithm::Sha2256];
            if let Some(digest) = &signature.message_digest {
                require(&mut algorithms, digest.algorithm);
            }
            match input {
                SignatureInput::Bytes => {}
                // Schemes without an external digest (Ed25519) cannot be
                // verified prehashed at all; verification reports that later.
                SignatureInput::Prehashed(Some(scheme)) => {
                    if let Some(algorithm) = scheme.hash_algorithm() {
                        require(&mut algorithms, algorithm);
                    }
                }
                // The key could not be read before the artifact, so the
                // scheme's digest is unknown. Hash with every algorithm so
                // verification can still proceed and report the real problem.
                SignatureInput::Prehashed(None) => {
                    for algorithm in [
                        HashAlgorithm::Sha2256,
                        HashAlgorithm::Sha2384,
                        HashAlgorithm::Sha2512,
                    ] {
                        require(&mut algorithms, algorithm);
                    }
                }
            }
            algorithms
        }
        // Only the in-toto subjects bind the artifact, so hash with the
        // algorithms they use. If the payload is not a readable statement,
        // hash both so the binding check later reports the real problem.
        SignatureContent::DsseEnvelope(envelope) => {
            std::str::from_utf8(envelope.payload.as_bytes())
                .ok()
                .and_then(|payload| serde_json::from_str::<Statement>(payload).ok())
                .map(|statement| statement.subject_algorithms())
                .filter(|algorithms| !algorithms.is_empty())
                .unwrap_or_else(|| vec![HashAlgorithm::Sha2256, HashAlgorithm::Sha2512])
        }
    }
}

fn required_hashers(content: &SignatureContent, input: SignatureInput) -> Vec<ArtifactHasher> {
    required_algorithms(content, input)
        .into_iter()
        .map(ArtifactHasher::new)
        .collect()
}

impl<'a> PreparedArtifact<'a> {
    pub(crate) fn from_artifact(artifact: Artifact<'a>, content: &SignatureContent) -> Self {
        match artifact {
            Artifact::Blob(blob) => {
                let mut hashers = required_hashers(content, SignatureInput::Bytes);
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

    /// Hash a blocking reader to EOF.
    ///
    /// `scheme` is the signing scheme the signature will be verified with, if
    /// it could be determined from the bundle's key material up front. It only
    /// matters for `MessageSignature` bundles: streamed input can only be
    /// verified prehashed, so this pass must produce the scheme's digest.
    pub(crate) fn from_reader(
        reader: impl Read,
        content: &SignatureContent,
        scheme: Option<SigningScheme>,
    ) -> Result<PreparedArtifact<'static>> {
        let mut hashers = required_hashers(content, SignatureInput::Prehashed(scheme));
        hash_reader(reader, &mut hashers).map_err(Error::ArtifactRead)?;
        Ok(Self::from_digests(Self::finalize(hashers)))
    }

    /// Hash an async reader to EOF. See [`PreparedArtifact::from_reader`] for
    /// the role of `scheme`.
    pub(crate) async fn from_async_reader(
        reader: impl AsyncRead + Unpin,
        content: &SignatureContent,
        scheme: Option<SigningScheme>,
    ) -> Result<PreparedArtifact<'static>> {
        let mut hashers = required_hashers(content, SignatureInput::Prehashed(scheme));
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

    /// The artifact digest for `algorithm`.
    ///
    /// Blob and reader input were hashed once with every algorithm the bundle
    /// content can request; digest input supplies a single algorithm. Anything
    /// else is an error naming what was supplied.
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
        let digest = self.digest(HashAlgorithm::Sha2256)?;
        Sha256Hash::try_from_slice(digest.as_bytes())
            .map_err(|e| Error::Verification(e.to_string()))
    }

    pub(crate) fn sha512(&self) -> Result<Sha512Hash> {
        let digest = self.digest(HashAlgorithm::Sha2512)?;
        Sha512Hash::try_from_slice(digest.as_bytes())
            .map_err(|e| Error::Verification(e.to_string()))
    }
}
