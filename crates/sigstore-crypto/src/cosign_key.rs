//! Cosign's encrypted private key format.
//!
//! `cosign generate-key-pair` writes the private key as a PEM block labelled
//! `ENCRYPTED SIGSTORE PRIVATE KEY` (older releases used
//! `ENCRYPTED COSIGN PRIVATE KEY`). The PEM body is a JSON document:
//!
//! ```json
//! {
//!   "kdf": {"name": "scrypt", "params": {"N": 65536, "r": 8, "p": 1}, "salt": "<base64>"},
//!   "cipher": {"name": "nacl/secretbox", "nonce": "<base64>"},
//!   "ciphertext": "<base64>"
//! }
//! ```
//!
//! The password is stretched with scrypt into a 32-byte key, which opens the
//! XSalsa20-Poly1305 secretbox. The plaintext is the PKCS#8 DER private key.
//! This is the go-tuf `encrypted` package format.
//!
//! Requires the `cosign-key` feature.

use crate::error::{Error, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The PEM label cosign writes today.
pub const PEM_LABEL: &str = "ENCRYPTED SIGSTORE PRIVATE KEY";
/// The PEM label older cosign releases wrote; still accepted when reading.
pub const LEGACY_PEM_LABEL: &str = "ENCRYPTED COSIGN PRIVATE KEY";

const KDF_SCRYPT: &str = "scrypt";
const CIPHER_SECRETBOX: &str = "nacl/secretbox";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 32;

/// scrypt parameters used when encrypting: cosign's current defaults.
const ENCRYPT_LOG_N: u8 = 16;
const ENCRYPT_R: u32 = 8;
const ENCRYPT_P: u32 = 1;

/// Upper bounds on the scrypt parameters accepted when decrypting. With
/// these, deriving the key needs at most 128 MiB (`128 * r * N` bytes) and
/// two passes, so a hostile key file cannot make decryption arbitrarily slow.
/// Cosign writes `N` = 2^15 or 2^16, `r` = 8, `p` = 1.
const MAX_LOG_N: u32 = 17;
const MAX_R: u32 = 8;
const MAX_P: u32 = 2;

#[derive(Serialize, Deserialize)]
struct EncryptedKey {
    kdf: Kdf,
    cipher: Cipher,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Kdf {
    name: String,
    params: ScryptParams,
    #[serde(with = "b64")]
    salt: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ScryptParams {
    #[serde(rename = "N")]
    n: u64,
    r: u32,
    p: u32,
}

#[derive(Serialize, Deserialize)]
struct Cipher {
    name: String,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
}

mod b64 {
    use super::BASE64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        BASE64.decode(s).map_err(serde::de::Error::custom)
    }
}

impl ScryptParams {
    /// Validate the parameters and convert them, before any work is done.
    fn to_scrypt(&self) -> Result<scrypt::Params> {
        if !self.n.is_power_of_two() || self.n < 2 {
            return Err(Error::InvalidKeyFormat(format!(
                "scrypt N must be a power of two greater than 1, got {}",
                self.n
            )));
        }
        let log_n = self.n.trailing_zeros();
        if log_n > MAX_LOG_N || !(1..=MAX_R).contains(&self.r) || !(1..=MAX_P).contains(&self.p) {
            return Err(Error::UnsupportedAlgorithm(format!(
                "scrypt parameters N={}, r={}, p={} exceed the accepted bounds \
                 (N <= 2^{MAX_LOG_N}, r <= {MAX_R}, p <= {MAX_P})",
                self.n, self.r, self.p
            )));
        }
        // `log_n <= MAX_LOG_N` fits in a u8.
        scrypt::Params::new(log_n as u8, self.r, self.p)
            .map_err(|e| Error::InvalidKeyFormat(format!("invalid scrypt parameters: {e}")))
    }
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &scrypt::Params,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    scrypt::scrypt(password, salt, params, key.as_mut())
        .map_err(|e| Error::KeyDecryption(format!("scrypt failed: {e}")))?;
    Ok(key)
}

/// Decrypt a cosign encrypted private key and return its PKCS#8 DER.
///
/// `password` may be empty: cosign allows encrypting a key with an empty
/// password. A wrong password, like a corrupted ciphertext, fails with
/// [`Error::KeyDecryption`]. A malformed document fails with
/// [`Error::InvalidKeyFormat`] (as does a PEM block of another kind), and an unknown KDF or cipher, or scrypt
/// parameters beyond the accepted bounds, with
/// [`Error::UnsupportedAlgorithm`].
///
/// The returned buffer holds secret key material and is zeroed when dropped.
pub fn decrypt_pem(pem: &str, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let block =
        pem::parse(pem).map_err(|e| Error::InvalidKeyFormat(format!("invalid PEM: {e}")))?;
    if block.tag() != PEM_LABEL && block.tag() != LEGACY_PEM_LABEL {
        return Err(Error::InvalidKeyFormat(format!(
            "expected a `{PEM_LABEL}` PEM block, got `{}`",
            block.tag()
        )));
    }
    decrypt_json(block.contents(), password)
}

fn decrypt_json(json: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let doc: EncryptedKey = serde_json::from_slice(json)
        .map_err(|e| Error::InvalidKeyFormat(format!("malformed encrypted key: {e}")))?;
    if doc.kdf.name != KDF_SCRYPT {
        return Err(Error::UnsupportedAlgorithm(format!(
            "unsupported key derivation function `{}`",
            doc.kdf.name
        )));
    }
    if doc.cipher.name != CIPHER_SECRETBOX {
        return Err(Error::UnsupportedAlgorithm(format!(
            "unsupported cipher `{}`",
            doc.cipher.name
        )));
    }
    if doc.cipher.nonce.len() != NONCE_LEN {
        return Err(Error::InvalidKeyFormat(format!(
            "secretbox nonce must be {NONCE_LEN} bytes, got {}",
            doc.cipher.nonce.len()
        )));
    }
    if doc.kdf.salt.is_empty() {
        return Err(Error::InvalidKeyFormat("scrypt salt is empty".into()));
    }
    let params = doc.kdf.params.to_scrypt()?;

    let key = derive_key(password, &doc.kdf.salt, &params)?;
    let cipher = XSalsa20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(
            doc.cipher.nonce.as_slice().into(),
            doc.ciphertext.as_slice(),
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::KeyDecryption("wrong password or corrupted key".into()))
}

/// Encrypt a PKCS#8 DER private key in cosign's format, as a PEM block
/// labelled [`PEM_LABEL`].
///
/// Uses cosign's current parameters: scrypt with `N` = 2^16, `r` = 8,
/// `p` = 1, a random 32-byte salt, and a random 24-byte nonce. `password`
/// may be empty. The key itself is not validated; pass a key that
/// [`KeyPair::from_pkcs8_der`](crate::KeyPair::from_pkcs8_der) accepts.
pub fn encrypt_pkcs8_der(pkcs8: &[u8], password: &[u8]) -> Result<String> {
    let mut salt = vec![0u8; SALT_LEN];
    rand::fill(salt.as_mut_slice());
    let mut nonce = vec![0u8; NONCE_LEN];
    rand::fill(nonce.as_mut_slice());

    let params = ScryptParams {
        n: 1 << ENCRYPT_LOG_N,
        r: ENCRYPT_R,
        p: ENCRYPT_P,
    };
    let key = derive_key(password, &salt, &params.to_scrypt()?)?;
    let ciphertext = XSalsa20Poly1305::new(key.as_ref().into())
        .encrypt(nonce.as_slice().into(), pkcs8)
        .map_err(|_| Error::KeyDecryption("secretbox encryption failed".into()))?;

    let doc = EncryptedKey {
        kdf: Kdf {
            name: KDF_SCRYPT.into(),
            params,
            salt,
        },
        cipher: Cipher {
            name: CIPHER_SECRETBOX.into(),
            nonce,
        },
        ciphertext,
    };
    let json = serde_json::to_vec(&doc)
        .map_err(|e| Error::InvalidKeyFormat(format!("failed to encode encrypted key: {e}")))?;
    Ok(pem::encode(&pem::Pem::new(PEM_LABEL, json)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(n: u64, r: u32, p: u32, kdf: &str, cipher: &str, nonce_len: usize) -> Vec<u8> {
        serde_json::to_vec(&EncryptedKey {
            kdf: Kdf {
                name: kdf.into(),
                params: ScryptParams { n, r, p },
                salt: vec![1; 32],
            },
            cipher: Cipher {
                name: cipher.into(),
                nonce: vec![2; nonce_len],
            },
            ciphertext: vec![3; 64],
        })
        .unwrap()
    }

    #[test]
    fn rejects_unknown_kdf_and_cipher() {
        for (kdf, cipher) in [("argon2", CIPHER_SECRETBOX), (KDF_SCRYPT, "aes-gcm")] {
            let err = decrypt_json(&document(1 << 15, 8, 1, kdf, cipher, 24), b"").unwrap_err();
            assert!(matches!(err, Error::UnsupportedAlgorithm(_)), "{err}");
        }
    }

    #[test]
    fn rejects_expensive_or_malformed_scrypt_parameters_before_deriving() {
        // Each of these would take far too long or too much memory if scrypt
        // ran; they must fail immediately.
        for (n, r, p) in [(1 << 30, 8, 1), (1 << 15, 1024, 1), (1 << 15, 8, 64)] {
            let err = decrypt_json(&document(n, r, p, KDF_SCRYPT, CIPHER_SECRETBOX, 24), b"")
                .unwrap_err();
            assert!(matches!(err, Error::UnsupportedAlgorithm(_)), "{err}");
        }
        for (n, r, p) in [(0, 8, 1), (1, 8, 1), (3000, 8, 1), (1 << 15, 0, 1)] {
            let err = decrypt_json(&document(n, r, p, KDF_SCRYPT, CIPHER_SECRETBOX, 24), b"")
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::InvalidKeyFormat(_) | Error::UnsupportedAlgorithm(_)
                ),
                "{err}"
            );
        }
    }

    #[test]
    fn rejects_bad_nonce_and_malformed_json() {
        let err = decrypt_json(
            &document(1 << 10, 8, 1, KDF_SCRYPT, CIPHER_SECRETBOX, 12),
            b"",
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidKeyFormat(_)), "{err}");
        let err = decrypt_json(b"{\"kdf\":1}", b"").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyFormat(_)), "{err}");
    }

    #[test]
    fn rejects_other_pem_labels() {
        let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", vec![0u8; 4]));
        assert!(matches!(
            decrypt_pem(&pem, b""),
            Err(Error::InvalidKeyFormat(_))
        ));
    }

    #[test]
    fn wrong_password_fails_without_panicking() {
        let doc = document(1 << 10, 8, 1, KDF_SCRYPT, CIPHER_SECRETBOX, 24);
        assert!(matches!(
            decrypt_json(&doc, b"nope"),
            Err(Error::KeyDecryption(_))
        ));
    }
}
