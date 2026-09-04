//! Hashing utilities using aws-lc-rs

use aws_lc_rs::digest::{self, Context, SHA256, SHA384, SHA512};
use futures_io::AsyncRead;
use sigstore_types::{ArtifactDigest, HashAlgorithm, Sha256Hash, Sha512Hash};
use std::future::Future;
use std::io::{self, Read};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

/// Bytes read and hashed between yields to the async executor.
const HASH_CHUNK_SIZE: usize = 64 * 1024;

/// Hash data using SHA-256, returning a typed hash
pub fn sha256(data: &[u8]) -> Sha256Hash {
    let digest = digest::digest(&SHA256, data);
    let mut result = [0u8; 32];
    result.copy_from_slice(digest.as_ref());
    Sha256Hash::from_bytes(result)
}

/// Hash data using SHA-384, returning raw bytes
pub fn sha384(data: &[u8]) -> Vec<u8> {
    let digest = digest::digest(&SHA384, data);
    digest.as_ref().to_vec()
}

/// Hash data using SHA-512, returning a typed hash
pub fn sha512(data: &[u8]) -> Sha512Hash {
    let digest = digest::digest(&SHA512, data);
    let mut result = [0u8; 64];
    result.copy_from_slice(digest.as_ref());
    Sha512Hash::from_bytes(result)
}

/// Incremental hasher for a typed artifact digest.
pub struct ArtifactHasher {
    algorithm: HashAlgorithm,
    context: Context,
}

impl ArtifactHasher {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let backend = match algorithm {
            HashAlgorithm::Sha2256 => &SHA256,
            HashAlgorithm::Sha2384 => &SHA384,
            HashAlgorithm::Sha2512 => &SHA512,
        };
        Self {
            algorithm,
            context: Context::new(backend),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    pub fn finalize(self) -> ArtifactDigest {
        ArtifactDigest::new(self.algorithm, self.context.finish().as_ref())
            .expect("backend digest length does not match the algorithm's documented length")
    }
}

/// An incremental hasher that can absorb more input.
///
/// Implemented by every hasher in this module so the reader helpers below can
/// feed one pass over the input into any combination of them.
pub trait HashUpdate {
    /// Absorb `data`.
    fn update(&mut self, data: &[u8]);
}

impl HashUpdate for ArtifactHasher {
    fn update(&mut self, data: &[u8]) {
        ArtifactHasher::update(self, data);
    }
}

impl HashUpdate for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        Sha256Hasher::update(self, data);
    }
}

/// Incremental SHA-256 hasher
pub struct Sha256Hasher {
    context: Context,
}

impl Sha256Hasher {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self {
            context: Context::new(&SHA256),
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Finalize and get the digest as a typed hash
    pub fn finalize(self) -> Sha256Hash {
        let digest = self.finish_digest();
        let mut result = [0u8; 32];
        result.copy_from_slice(digest.as_ref());
        Sha256Hash::from_bytes(result)
    }

    /// Finalize and return the raw aws-lc-rs digest.
    ///
    /// Crate-internal so that [`crate::KeyPair::sign_prehashed`] can sign the
    /// digest directly without leaking aws-lc-rs types into the public API.
    pub(crate) fn finish_digest(self) -> digest::Digest {
        self.context.finish()
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-256 hash by reading from a reader (streaming, constant memory)
///
/// This is useful for hashing large files without loading them entirely into memory.
///
/// # Example
/// ```no_run
/// use std::fs::File;
/// use sigstore_crypto::sha256_reader;
///
/// let file = File::open("large-file.tar.gz").unwrap();
/// let hash = sha256_reader(file).unwrap();
/// ```
pub fn sha256_reader(reader: impl Read) -> io::Result<Sha256Hash> {
    let mut hasher = Sha256Hasher::new();
    hash_reader(reader, std::slice::from_mut(&mut hasher))?;
    Ok(hasher.finalize())
}

/// Feed `reader` to EOF into every hasher in constant memory.
///
/// Reads block the calling thread. Inside an async task use
/// [`hash_reader_yielding`] or [`hash_async_reader`] instead.
pub fn hash_reader<H: HashUpdate>(mut reader: impl Read, hashers: &mut [H]) -> io::Result<()> {
    let mut buffer = [0_u8; HASH_CHUNK_SIZE];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        for hasher in hashers.iter_mut() {
            hasher.update(&buffer[..read]);
        }
    }
}

/// Feed a blocking `reader` to EOF into every hasher, yielding to the async
/// executor after each chunk.
///
/// Hashing is CPU-bound: doing it in one shot over unbounded caller input
/// would occupy the executor thread for the whole duration and starve other
/// tasks (TOB-SIGSTORE-8). Reading and hashing in 64 KiB chunks
/// keeps each non-yielding stretch short. In-memory input works too, since
/// `&[u8]` implements [`Read`].
///
/// The reads themselves still block the executor thread; prefer
/// [`hash_async_reader`] when the input has an async source.
pub async fn hash_reader_yielding<H: HashUpdate>(
    reader: impl Read,
    hashers: &mut [H],
) -> io::Result<()> {
    hash_async_reader(BlockingReader(reader), hashers).await
}

/// Feed an async `reader` to EOF into every hasher, yielding to the executor
/// after each chunk.
///
/// `AsyncRead` implementations may return `Ready` indefinitely (an in-memory
/// cursor, for example), so awaiting a read is not by itself a scheduling
/// point. Yielding explicitly after each hashed chunk keeps large inputs from
/// monopolizing the executor thread (TOB-SIGSTORE-8).
pub async fn hash_async_reader<H: HashUpdate>(
    mut reader: impl AsyncRead + Unpin,
    hashers: &mut [H],
) -> io::Result<()> {
    let mut buffer = [0_u8; HASH_CHUNK_SIZE];
    loop {
        let read =
            std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read(cx, &mut buffer)).await?;
        if read == 0 {
            return Ok(());
        }
        for hasher in hashers.iter_mut() {
            hasher.update(&buffer[..read]);
        }
        yield_now().await;
    }
}

/// Adapter presenting a blocking [`Read`] as an always-ready [`AsyncRead`].
struct BlockingReader<R>(R);

// The wrapped reader is only ever used through `&mut`, never pinned, so the
// adapter can move freely regardless of `R`.
impl<R> Unpin for BlockingReader<R> {}

impl<R: Read> AsyncRead for BlockingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.0.read(buf))
    }
}

/// Yield control back to the async executor once.
///
/// Runtime-agnostic equivalent of `tokio::task::yield_now()`: the future
/// wakes its own waker and returns `Pending` on the first poll, then `Ready`.
fn yield_now() -> impl Future<Output = ()> {
    struct YieldNow {
        yielded: bool,
    }

    impl Future for YieldNow {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    YieldNow { yielded: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.as_bytes().len(), 32);

        // Known SHA-256 hash of "hello"
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(hash.as_bytes(), expected.as_slice());
    }

    #[test]
    fn test_sha512() {
        let hash = sha512(b"hello");
        assert_eq!(hash.as_bytes().len(), 64);

        let expected = hex::decode(concat!(
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
            "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
        ))
        .unwrap();
        assert_eq!(hash.as_bytes(), expected.as_slice());
    }

    #[test]
    fn test_sha256_incremental() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"hel");
        hasher.update(b"lo");
        let hash = hasher.finalize();

        let direct = sha256(b"hello");
        assert_eq!(hash, direct);
    }

    #[test]
    fn test_sha256_reader() {
        use std::io::Cursor;

        let data = b"hello world, this is a test of streaming hash";
        let cursor = Cursor::new(data);
        let hash = sha256_reader(cursor).unwrap();

        let direct = sha256(data);
        assert_eq!(hash, direct);
    }

    fn chunk_boundary_sizes() -> [usize; 6] {
        [
            0,
            1,
            HASH_CHUNK_SIZE - 1,
            HASH_CHUNK_SIZE,
            HASH_CHUNK_SIZE + 1,
            3 * HASH_CHUNK_SIZE + 17,
        ]
    }

    fn patterned(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        // Every future here only ever yields once per chunk and re-wakes
        // itself, so a spin loop with a no-op waker is a sufficient executor.
        let waker = futures_task_noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    fn futures_task_noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: the vtable functions ignore the data pointer entirely.
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    #[test]
    fn reader_helpers_match_one_shot_hashing_across_chunk_boundaries() {
        for size in chunk_boundary_sizes() {
            let data = patterned(size);
            let expected = sha256(&data);

            let mut hashers = [
                ArtifactHasher::new(HashAlgorithm::Sha2256),
                ArtifactHasher::new(HashAlgorithm::Sha2512),
            ];
            hash_reader(data.as_slice(), &mut hashers).unwrap();
            let [h256, h512] = hashers;
            assert_eq!(
                h256.finalize().as_bytes(),
                expected.as_bytes(),
                "size {size}"
            );
            assert_eq!(
                h512.finalize().as_bytes(),
                sha512(&data).as_bytes(),
                "size {size}"
            );

            let mut hasher = Sha256Hasher::new();
            block_on(hash_reader_yielding(
                data.as_slice(),
                std::slice::from_mut(&mut hasher),
            ))
            .unwrap();
            assert_eq!(hasher.finalize(), expected, "size {size}");

            let mut hasher = Sha256Hasher::new();
            block_on(hash_async_reader(
                BlockingReader(data.as_slice()),
                std::slice::from_mut(&mut hasher),
            ))
            .unwrap();
            assert_eq!(hasher.finalize(), expected, "size {size}");
        }
    }

    #[test]
    fn async_hashing_yields_even_when_reads_are_ready() {
        let mut hasher = Sha256Hasher::new();
        let mut future = Box::pin(hash_async_reader(
            BlockingReader(&[42_u8][..]),
            std::slice::from_mut(&mut hasher),
        ));
        let waker = futures_task_noop_waker();
        let mut cx = TaskContext::from_waker(&waker);
        assert!(future.as_mut().poll(&mut cx).is_pending());
    }

    #[test]
    fn reader_errors_are_propagated() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::Other, "disk on fire"))
            }
        }
        let mut hasher = Sha256Hasher::new();
        let err = hash_reader(Failing, std::slice::from_mut(&mut hasher)).unwrap_err();
        assert_eq!(err.to_string(), "disk on fire");
    }
}
