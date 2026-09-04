use crate::error::{Error, Result};
use futures::io::{AsyncRead, AsyncReadExt};
use sigstore_crypto::ArtifactHasher;
use sigstore_types::{
    Artifact, ArtifactDigest, HashAlgorithm, Sha256Hash, Sha512Hash, SignatureContent,
};
use std::io::Read;

/// Yield control back to the async executor once.
///
/// `AsyncRead` implementations may return `Ready` indefinitely, so awaiting a
/// read is not by itself a reliable scheduling point.
fn yield_now() -> impl std::future::Future<Output = ()> {
    struct YieldNow(bool);

    impl std::future::Future for YieldNow {
        type Output = ();

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                std::task::Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }

    YieldNow(false)
}

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

/// The digest algorithms verification can request for this bundle content.
fn required_hashers(content: &SignatureContent) -> Vec<ArtifactHasher> {
    let mut algorithms = vec![HashAlgorithm::Sha2256];
    match content {
        // hashedrekord binds SHA-256; the signature itself may be over the
        // declared messageDigest algorithm (SHA-384 for ECDSA-P256-SHA384).
        SignatureContent::MessageSignature(signature) => {
            if let Some(digest) = &signature.message_digest {
                if !algorithms.contains(&digest.algorithm) {
                    algorithms.push(digest.algorithm);
                }
            }
        }
        // in-toto subjects may be bound by SHA-256 or SHA-512.
        SignatureContent::DsseEnvelope(_) => algorithms.push(HashAlgorithm::Sha2512),
    }
    algorithms.into_iter().map(ArtifactHasher::new).collect()
}

impl<'a> PreparedArtifact<'a> {
    pub(crate) fn from_artifact(artifact: Artifact<'a>, content: &SignatureContent) -> Self {
        match artifact {
            Artifact::Blob(blob) => {
                let mut hashers = required_hashers(content);
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
        mut reader: impl Read,
        content: &SignatureContent,
    ) -> Result<PreparedArtifact<'static>> {
        let mut hashers = required_hashers(content);
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
        Ok(Self::from_digests(Self::finalize(hashers)))
    }

    pub(crate) async fn from_async_reader(
        mut reader: impl AsyncRead + Unpin,
        content: &SignatureContent,
    ) -> Result<PreparedArtifact<'static>> {
        let mut hashers = required_hashers(content);
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
            // Always-ready readers (including in-memory cursors) do not yield
            // when awaited. Cooperate explicitly after each hashing chunk.
            yield_now().await;
        }
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
