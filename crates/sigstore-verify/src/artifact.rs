use crate::error::{Error, Result};
use futures::io::{AsyncRead, AsyncReadExt};
use sigstore_crypto::ArtifactHasher;
use sigstore_types::{Artifact, ArtifactDigest, Bundle, HashAlgorithm, SignatureContent};
use std::io::Read;

/// Artifact data normalized for the verification core.
///
/// Blob callers retain their bytes for schemes that cannot verify prehashed
/// input. Reader callers provide every digest computed during their single
/// pass and never need to retain the artifact in memory.
pub(crate) struct PreparedArtifact<'a> {
    blob: Option<&'a [u8]>,
    digests: Vec<ArtifactDigest>,
}

fn required_hashers(bundle: &Bundle) -> Vec<ArtifactHasher> {
    // SHA-256 binds DSSE subjects and hashedrekord entries. MessageSignature
    // may additionally select SHA-384 or SHA-512 for signature verification.
    let mut algorithms = vec![HashAlgorithm::Sha2256];
    if let SignatureContent::MessageSignature(signature) = &bundle.content {
        if let Some(digest) = &signature.message_digest {
            if !algorithms.contains(&digest.algorithm) {
                algorithms.push(digest.algorithm);
            }
        }
    }
    algorithms.into_iter().map(ArtifactHasher::new).collect()
}

impl<'a> PreparedArtifact<'a> {
    pub(crate) fn from_artifact(artifact: Artifact<'a>) -> Self {
        match artifact {
            Artifact::Blob(blob) => Self {
                blob: Some(blob),
                digests: Vec::new(),
            },
            Artifact::Digest(digest) => Self {
                blob: None,
                digests: vec![digest],
            },
        }
    }

    pub(crate) fn from_reader(
        mut reader: impl Read,
        bundle: &Bundle,
    ) -> Result<PreparedArtifact<'static>> {
        let mut hashers = required_hashers(bundle);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(Error::ArtifactRead)?;
            if read == 0 {
                break;
            }
            for hasher in &mut hashers {
                hasher.update(&buffer[..read]);
            }
        }
        Ok(Self::from_hashers(hashers))
    }

    pub(crate) async fn from_async_reader(
        mut reader: impl AsyncRead + Unpin,
        bundle: &Bundle,
    ) -> Result<PreparedArtifact<'static>> {
        let mut hashers = required_hashers(bundle);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .await
                .map_err(Error::ArtifactRead)?;
            if read == 0 {
                break;
            }
            for hasher in &mut hashers {
                hasher.update(&buffer[..read]);
            }
        }
        Ok(Self::from_hashers(hashers))
    }

    fn from_hashers(hashers: Vec<ArtifactHasher>) -> PreparedArtifact<'static> {
        PreparedArtifact {
            blob: None,
            digests: hashers.into_iter().map(ArtifactHasher::finalize).collect(),
        }
    }

    pub(crate) fn blob(&self) -> Option<&[u8]> {
        self.blob
    }

    pub(crate) fn digest(&self, algorithm: HashAlgorithm) -> Result<Vec<u8>> {
        if let Some(blob) = self.blob {
            return Ok(match algorithm {
                HashAlgorithm::Sha2256 => sigstore_crypto::sha256(blob).as_bytes().to_vec(),
                HashAlgorithm::Sha2384 => sigstore_crypto::sha384(blob),
                HashAlgorithm::Sha2512 => sigstore_crypto::sha512(blob),
            });
        }

        self.digests
            .iter()
            .find(|digest| digest.algorithm() == algorithm)
            .map(|digest| digest.as_bytes().to_vec())
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
}
