use crate::error::{Error, Result};
use futures::io::{AsyncRead, AsyncReadExt};
use sigstore_crypto::ArtifactHasher;
use sigstore_types::{
    Artifact, ArtifactDigest, Bundle, HashAlgorithm, Sha256Hash, Sha512Hash, SignatureContent,
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
/// Blob callers retain their bytes for schemes that cannot verify prehashed
/// input. Reader callers provide every digest computed during their single
/// pass and never need to retain the artifact in memory.
pub(crate) struct PreparedArtifact<'a> {
    blob: Option<&'a [u8]>,
    digests: Vec<ArtifactDigest>,
}

fn required_hashers(bundle: &Bundle) -> Vec<ArtifactHasher> {
    // SHA-256 binds hashedrekord entries, while in-toto subjects can use
    // SHA-256 or SHA-512. MessageSignature may additionally select SHA-384.
    let mut algorithms = vec![HashAlgorithm::Sha2256, HashAlgorithm::Sha2512];
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
            // Always-ready readers (including in-memory cursors) do not yield
            // when awaited. Cooperate explicitly after each hashing chunk.
            yield_now().await;
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

    /// The artifact digest for `algorithm`.
    ///
    /// Blob input is hashed on demand. Digest and reader input can only
    /// supply the algorithms they were prepared with, so any other request is
    /// an error that names what was supplied.
    pub(crate) fn digest(&self, algorithm: HashAlgorithm) -> Result<ArtifactDigest> {
        if let Some(blob) = self.blob {
            let mut hasher = ArtifactHasher::new(algorithm);
            hasher.update(blob);
            return Ok(hasher.finalize());
        }

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
