//! Hashing utilities

#[cfg(feature = "rustls")]
use aws_lc_rs::digest::{self, Context, SHA256};
#[cfg(feature = "native-tls")]
use ring::digest::{self, Context, SHA256};

use sigstore_types::Sha256Hash;
use std::io::{self, Read};

/// Hash data using SHA-256, returning a typed hash
pub fn sha256(data: &[u8]) -> Sha256Hash {
    let digest = digest::digest(&SHA256, data);
    let mut result = [0u8; 32];
    result.copy_from_slice(digest.as_ref());
    Sha256Hash::from_bytes(result)
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
        let digest = self.context.finish();
        let mut result = [0u8; 32];
        result.copy_from_slice(digest.as_ref());
        Sha256Hash::from_bytes(result)
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
pub fn sha256_reader(mut reader: impl Read) -> io::Result<Sha256Hash> {
    let mut hasher = Sha256Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
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
}
