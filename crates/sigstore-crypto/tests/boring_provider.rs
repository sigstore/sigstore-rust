//! Reference [`CryptoProvider`] implementation using `boring` (BoringSSL) and
//! end-to-end regression tests for `sigstore-crypto`'s provider abstraction.
//!
//! This integration test serves two purposes:
//! 1. **Reference implementation**: Demonstrates how downstream consumers can
//!    implement [`CryptoProvider`], [`HashContext`], and [`SigningKeyPair`] for
//!    an external cryptographic library (such as `boring`, `bssl-crypto`,
//!    `openssl`, or a custom FFI function table) without depending on `aws-lc-rs`.
//! 2. **Anti-bitrot regression test**: Installed as the process-wide default
//!    provider in this test binary via [`install_default_provider`] and exercised
//!    with `RUSTFLAGS="--cfg sigstore_boring_test"` under both
//!    `cargo test --test boring_provider -p sigstore-crypto --no-default-features`
//!    and `cargo test --test boring_provider -p sigstore-crypto` (including
//!    cross-provider interoperability against [`sigstore_crypto::aws_lc_provider()`]
//!    when `aws-lc-rs` is enabled).

#![cfg(sigstore_boring_test)]

use boring::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::{hash, Hasher, MessageDigest},
    mldsa::{Algorithm as MlDsaAlgorithm, MlDsaPrivateKey, MlDsaPublicKey},
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer, Verifier},
};
use const_oid::{
    db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1},
    ObjectIdentifier,
};
use sigstore_crypto::{
    compute_key_hint, default_provider, install_default_provider, sha256, sha256_reader, sha384,
    sha512, try_default_provider, ArtifactHasher, Checkpoint, CheckpointVerifyExt, CryptoProvider,
    Error, HashContext, KeyAlgorithm, KeyPair, Keyring, Result, Sha256Hasher, SigningKeyPair,
    SigningScheme, VerificationKey, WEBPKI_VERIFICATION_ALGS,
};
use sigstore_types::{DerPublicKey, HashAlgorithm, SignatureBytes};

static BORING_PROVIDER: BoringProvider = BoringProvider;

fn ensure_boring_installed() {
    let _ = install_default_provider(&BORING_PROVIDER);
}

#[derive(Debug)]
struct BoringProvider;

struct BoringHashContext(Hasher);

impl HashContext for BoringHashContext {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("BoringSSL hasher update failed");
    }

    fn finalize(mut self: Box<Self>) -> Vec<u8> {
        self.0
            .finish()
            .expect("BoringSSL hasher finish failed")
            .to_vec()
    }
}

struct BoringP256KeyPair {
    ec_key: EcKey<Private>,
    public_key_bytes: Vec<u8>,
}

impl BoringP256KeyPair {
    fn generate() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string()))?;
        let ec_key = EcKey::generate(&group)
            .map_err(|_| Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string()))?;
        Self::from_ec_key(ec_key)
    }

    fn from_pkcs8_der(pkcs8: &[u8]) -> Result<Self> {
        let pkey = PKey::private_key_from_pkcs8(pkcs8)
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        let ec_key = pkey
            .ec_key()
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        if ec_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(Error::InvalidKeyFormat(
                "expected ECDSA P-256 private key".to_string(),
            ));
        }
        ec_key
            .check_key()
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Self::from_ec_key(ec_key)
    }

    fn from_ec_key(ec_key: EcKey<Private>) -> Result<Self> {
        let mut ctx = BigNumContext::new().map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        let public_key_bytes = ec_key
            .public_key()
            .to_bytes(ec_key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Ok(Self {
            ec_key,
            public_key_bytes,
        })
    }
}

impl SigningKeyPair for BoringP256KeyPair {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EcdsaP256
    }

    fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign_prehashed(&BORING_PROVIDER.sha256(data))
    }

    fn sign_prehashed(&self, digest: &[u8]) -> Result<Vec<u8>> {
        if digest.len() != 32 {
            return Err(Error::Signing("invalid SHA-256 digest".to_string()));
        }
        let sig = EcdsaSig::sign(digest, &self.ec_key)
            .map_err(|_| Error::Signing("the cryptographic backend failed to sign".to_string()))?;
        sig.to_der()
            .map_err(|_| Error::Signing("the cryptographic backend failed to sign".to_string()))
    }
}

fn message_digest(algorithm: HashAlgorithm) -> Result<MessageDigest> {
    match algorithm {
        HashAlgorithm::Sha2256 => Ok(MessageDigest::sha256()),
        HashAlgorithm::Sha2384 => Ok(MessageDigest::sha384()),
        HashAlgorithm::Sha2512 => Ok(MessageDigest::sha512()),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "cannot compute {algorithm} digests"
        ))),
    }
}

impl CryptoProvider for BoringProvider {
    fn hash(&self, algorithm: HashAlgorithm) -> Result<Box<dyn HashContext>> {
        let md = message_digest(algorithm)?;
        let hasher = Hasher::new(md).map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        Ok(Box::new(BoringHashContext(hasher)))
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let digest = hash(MessageDigest::sha256(), data).expect("SHA-256 hashing failed");
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        result
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        let digest = hash(MessageDigest::sha384(), data).expect("SHA-384 hashing failed");
        let mut result = [0u8; 48];
        result.copy_from_slice(&digest);
        result
    }

    fn sha512(&self, data: &[u8]) -> [u8; 64] {
        let digest = hash(MessageDigest::sha512(), data).expect("SHA-512 hashing failed");
        let mut result = [0u8; 64];
        result.copy_from_slice(&digest);
        result
    }

    fn verify_raw(
        &self,
        scheme: SigningScheme,
        spki_pubkey_bytes: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let res = match scheme {
            SigningScheme::EcdsaP256Sha256 | SigningScheme::EcdsaP384Sha256 => self
                .verify_prehashed(scheme, spki_pubkey_bytes, &self.sha256(data), signature)
                .map_err(|_| ()),
            SigningScheme::EcdsaP256Sha384 | SigningScheme::EcdsaP384Sha384 => self
                .verify_prehashed(scheme, spki_pubkey_bytes, &self.sha384(data), signature)
                .map_err(|_| ()),
            SigningScheme::Ed25519 => verify_ed25519(spki_pubkey_bytes, data, signature),
            SigningScheme::RsaPssSha256 => verify_rsa(
                spki_pubkey_bytes,
                MessageDigest::sha256(),
                true,
                data,
                signature,
            ),
            SigningScheme::RsaPssSha384 => verify_rsa(
                spki_pubkey_bytes,
                MessageDigest::sha384(),
                true,
                data,
                signature,
            ),
            SigningScheme::RsaPssSha512 => verify_rsa(
                spki_pubkey_bytes,
                MessageDigest::sha512(),
                true,
                data,
                signature,
            ),
            SigningScheme::RsaPkcs1Sha256 => verify_rsa(
                spki_pubkey_bytes,
                MessageDigest::sha256(),
                false,
                data,
                signature,
            ),
            SigningScheme::RsaPkcs1Sha384 => verify_rsa(
                spki_pubkey_bytes,
                MessageDigest::sha384(),
                false,
                data,
                signature,
            ),
            SigningScheme::RsaPkcs1Sha512 => verify_rsa(
                spki_pubkey_bytes,
                MessageDigest::sha512(),
                false,
                data,
                signature,
            ),
            SigningScheme::MlDsa44 => {
                MlDsaPublicKey::from_slice(MlDsaAlgorithm::MlDsa44, spki_pubkey_bytes)
                    .and_then(|key| key.verify(data, signature))
                    .map_err(|_| ())
            }
            SigningScheme::MlDsa65 => {
                MlDsaPublicKey::from_slice(MlDsaAlgorithm::MlDsa65, spki_pubkey_bytes)
                    .and_then(|key| key.verify(data, signature))
                    .map_err(|_| ())
            }
            SigningScheme::MlDsa87 => {
                MlDsaPublicKey::from_slice(MlDsaAlgorithm::MlDsa87, spki_pubkey_bytes)
                    .and_then(|key| key.verify(data, signature))
                    .map_err(|_| ())
            }
            _ => Err(()),
        };
        res.map_err(|()| Error::Verification(format!("{} signature invalid", scheme.name())))
    }

    fn verify_prehashed(
        &self,
        scheme: SigningScheme,
        spki_pubkey_bytes: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let hash_alg = scheme.hash_algorithm().ok_or_else(|| {
            Error::UnsupportedAlgorithm(format!(
                "Scheme {scheme:?} does not support prehashed mode"
            ))
        })?;
        let res = match scheme {
            SigningScheme::EcdsaP256Sha256 | SigningScheme::EcdsaP256Sha384 => {
                verify_ecdsa_digest(Nid::X9_62_PRIME256V1, spki_pubkey_bytes, digest, signature)
            }
            SigningScheme::EcdsaP384Sha256 | SigningScheme::EcdsaP384Sha384 => {
                verify_ecdsa_digest(Nid::SECP384R1, spki_pubkey_bytes, digest, signature)
            }
            SigningScheme::RsaPkcs1Sha256
            | SigningScheme::RsaPkcs1Sha384
            | SigningScheme::RsaPkcs1Sha512 => {
                verify_rsa_pkcs1_prehashed(spki_pubkey_bytes, hash_alg, digest, signature)
            }
            SigningScheme::RsaPssSha256
            | SigningScheme::RsaPssSha384
            | SigningScheme::RsaPssSha512 => {
                let md = message_digest(hash_alg).map_err(|_| {
                    Error::Verification(format!("{} signature invalid", scheme.name()))
                })?;
                verify_rsa_pss_prehashed(spki_pubkey_bytes, md, digest, signature)
            }
            _ => Err(()),
        };
        res.map_err(|()| Error::Verification(format!("{} signature invalid", scheme.name())))
    }

    fn generate_key_pair(&self, algorithm: KeyAlgorithm) -> Result<Box<dyn SigningKeyPair>> {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => Ok(Box::new(BoringP256KeyPair::generate()?)),
            other => Err(Error::UnsupportedAlgorithm(format!(
                "key generation is not supported for {other:?}"
            ))),
        }
    }

    fn key_pair_from_pkcs8_der(&self, pkcs8: &[u8]) -> Result<Box<dyn SigningKeyPair>> {
        Ok(Box::new(BoringP256KeyPair::from_pkcs8_der(pkcs8)?))
    }
}

fn verify_ecdsa_digest(
    curve: Nid,
    pubkey_bytes: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let group = EcGroup::from_curve_name(curve).map_err(|_| ())?;
    let mut ctx = BigNumContext::new().map_err(|_| ())?;
    let point = EcPoint::from_bytes(&group, pubkey_bytes, &mut ctx).map_err(|_| ())?;
    let ec_key = EcKey::from_public_key(&group, &point).map_err(|_| ())?;
    ec_key.check_key().map_err(|_| ())?;

    let sig = EcdsaSig::from_der(signature).map_err(|_| ())?;
    // Require canonical ASN.1 DER with no trailing bytes.
    if sig.to_der().map_err(|_| ())? != signature {
        return Err(());
    }
    if sig.verify(digest, &ec_key).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

fn verify_ed25519(
    pubkey_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    if pubkey_bytes.len() != 32 || signature.len() != 64 {
        return Err(());
    }
    // RFC 8410 SubjectPublicKeyInfo prefix for a 32-byte Ed25519 public key.
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(pubkey_bytes);

    let pkey = PKey::public_key_from_der(&spki).map_err(|_| ())?;
    let mut verifier = Verifier::new_without_digest(&pkey).map_err(|_| ())?;
    if verifier.verify_oneshot(signature, data).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

fn parse_rsa_public_key(pubkey_bytes: &[u8]) -> std::result::Result<Rsa<Public>, ()> {
    Rsa::public_key_from_der_pkcs1(pubkey_bytes).map_err(|_| ())
}

fn verify_rsa(
    pubkey_bytes: &[u8],
    md: MessageDigest,
    pss: bool,
    data: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = parse_rsa_public_key(pubkey_bytes)?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| ())?;
    let mut verifier = Verifier::new(md, &pkey).map_err(|_| ())?;
    if pss {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|_| ())?;
        verifier.set_rsa_mgf1_md(md).map_err(|_| ())?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|_| ())?;
    }
    verifier.update(data).map_err(|_| ())?;
    if verifier.verify(signature).map_err(|_| ())? {
        Ok(())
    } else {
        Err(())
    }
}

/// Prehashed RSA PKCS#1 v1.5 verification.
///
/// SECURITY NOTE: Production `CryptoProvider` implementations should prefer
/// their cryptographic library's native one-shot digest verification API
/// (e.g. `EVP_PKEY_verify` / `openssl::pkey_ctx::PkeyCtx::verify` / `RSA_verify`)
/// rather than `Rsa::public_decrypt` + manual padding verification.
///
/// The safe `boring` crate (v5) only wraps streaming `EVP_DigestVerify*`
/// (`boring::sign::Verifier`) and does not expose a safe wrapper around
/// `EVP_PKEY_verify` or `RSA_verify` for precomputed digests. To keep this
/// test implementation free of `unsafe` FFI and `boring-sys` dependencies, we
/// use BoringSSL's `Rsa::public_decrypt(..., Padding::PKCS1)` and verify the
/// RFC 8017 §9.2 `DigestInfo` encoding in [`verify_emsa_pkcs1_digest_info`].
fn verify_rsa_pkcs1_prehashed(
    pubkey_bytes: &[u8],
    hash_alg: HashAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = parse_rsa_public_key(pubkey_bytes)?;
    if signature.len() != rsa.size() as usize {
        return Err(());
    }
    let mut decrypted = vec![0u8; rsa.size() as usize];
    let len = rsa
        .public_decrypt(signature, &mut decrypted, Padding::PKCS1)
        .map_err(|_| ())?;
    verify_emsa_pkcs1_digest_info(&decrypted[..len], hash_alg, digest)
}

/// Check that the PKCS#1 v1.5 unpadded `DigestInfo` matches the expected hash
/// algorithm OID prefix (RFC 8017 §9.2) and `digest`.
fn verify_emsa_pkcs1_digest_info(
    digest_info: &[u8],
    hash_alg: HashAlgorithm,
    digest: &[u8],
) -> std::result::Result<(), ()> {
    // RFC 8017 §9.2 DER DigestInfo prefixes (with NULL parameters and with absent parameters).
    let (expected_len, prefix_with_null, prefix_without_null): (usize, &[u8], &[u8]) =
        match hash_alg {
            HashAlgorithm::Sha2256 => (
                32,
                &[
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                ],
                &[
                    0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x04, 0x20,
                ],
            ),
            HashAlgorithm::Sha2384 => (
                48,
                &[
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
                ],
                &[
                    0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x02, 0x04, 0x30,
                ],
            ),
            HashAlgorithm::Sha2512 => (
                64,
                &[
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
                ],
                &[
                    0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x03, 0x04, 0x40,
                ],
            ),
            _ => return Err(()),
        };

    if digest.len() != expected_len {
        return Err(());
    }

    let matches_prefix = |prefix: &[u8]| {
        digest_info.len() == prefix.len() + digest.len()
            && boring::memcmp::eq(&digest_info[..prefix.len()], prefix)
            && boring::memcmp::eq(&digest_info[prefix.len()..], digest)
    };

    if matches_prefix(prefix_with_null) || matches_prefix(prefix_without_null) {
        Ok(())
    } else {
        Err(())
    }
}

/// Prehashed RSA-PSS verification.
///
/// SECURITY NOTE: Production `CryptoProvider` implementations should prefer
/// their cryptographic library's native one-shot digest verification API
/// (e.g. `EVP_PKEY_verify` / `openssl::pkey_ctx::PkeyCtx::verify` / `RSA_verify_pss_mgf1`)
/// rather than `Rsa::public_decrypt` + manual EMSA-PSS verification.
///
/// The safe `boring` crate (v5) only wraps streaming `EVP_DigestVerify*`
/// (`boring::sign::Verifier`) and does not expose a safe wrapper around
/// `EVP_PKEY_verify` or `RSA_verify_pss_mgf1` for precomputed digests. To keep
/// this test implementation free of `unsafe` FFI and `boring-sys` dependencies,
/// we recover the encoded message via BoringSSL's `Rsa::public_decrypt(..., Padding::NONE)`
/// and verify RFC 8017 §9.1.2 `EMSA-PSS-VERIFY` in [`verify_emsa_pss`].
fn verify_rsa_pss_prehashed(
    pubkey_bytes: &[u8],
    md: MessageDigest,
    digest: &[u8],
    signature: &[u8],
) -> std::result::Result<(), ()> {
    let rsa = parse_rsa_public_key(pubkey_bytes)?;
    let mod_len = rsa.size() as usize;
    if signature.len() != mod_len {
        return Err(());
    }
    let mut em_buf = vec![0u8; mod_len];
    let len = rsa
        .public_decrypt(signature, &mut em_buf, Padding::NONE)
        .map_err(|_| ())?;
    if len != mod_len {
        return Err(());
    }
    let mod_bits = rsa.n().num_bits() as usize;
    verify_emsa_pss(&em_buf, mod_bits, md, digest)
}

/// Verify RFC 8017 §9.1.2 `EMSA-PSS-VERIFY` with `sLen = hLen` and `MGF1(md)`.
fn verify_emsa_pss(
    em_buf: &[u8],
    mod_bits: usize,
    md: MessageDigest,
    digest: &[u8],
) -> std::result::Result<(), ()> {
    let mod_len = em_buf.len();
    let em_bits = mod_bits.checked_sub(1).ok_or(())?;
    let em_len = em_bits.div_ceil(8);
    if em_len > mod_len {
        return Err(());
    }
    let em = if em_len < mod_len {
        if em_buf[..mod_len - em_len].iter().any(|&b| b != 0) {
            return Err(());
        }
        &em_buf[mod_len - em_len..]
    } else {
        em_buf
    };

    let h_len = md.size();
    if digest.len() != h_len {
        return Err(());
    }
    let s_len = h_len;
    if em_len < h_len + s_len + 2 || em[em_len - 1] != 0xbc {
        return Err(());
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..em_len - 1];

    let top_zero_bits = 8 * em_len - em_bits;
    let top_mask = 0xffu8 >> top_zero_bits;
    if masked_db[0] & !top_mask != 0 {
        return Err(());
    }

    // MGF1 (RFC 8017 §B.2.1)
    let mut db = Vec::with_capacity(db_len);
    let mut counter: u32 = 0;
    while db.len() < db_len {
        let mut hasher = Hasher::new(md).map_err(|_| ())?;
        hasher.update(h).map_err(|_| ())?;
        hasher.update(&counter.to_be_bytes()).map_err(|_| ())?;
        let mask_chunk = hasher.finish().map_err(|_| ())?;
        for &b in mask_chunk.as_ref() {
            if db.len() < db_len {
                db.push(masked_db[db.len()] ^ b);
            }
        }
        counter += 1;
    }
    db[0] &= top_mask;

    let zero_pad_len = em_len - h_len - s_len - 2;
    if db[..zero_pad_len].iter().any(|&b| b != 0) || db[zero_pad_len] != 0x01 {
        return Err(());
    }

    let salt = &db[zero_pad_len + 1..];
    let mut h_prime_hasher = Hasher::new(md).map_err(|_| ())?;
    h_prime_hasher.update(&[0u8; 8]).map_err(|_| ())?;
    h_prime_hasher.update(digest).map_err(|_| ())?;
    h_prime_hasher.update(salt).map_err(|_| ())?;
    let h_prime = h_prime_hasher.finish().map_err(|_| ())?;

    if boring::memcmp::eq(h_prime.as_ref(), h) {
        Ok(())
    } else {
        Err(())
    }
}

// ============================================================================
// Test helpers
// ============================================================================

const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const ID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const ID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const ID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

fn spki_der(
    oid: ObjectIdentifier,
    curve: Option<ObjectIdentifier>,
    key_bytes: &[u8],
) -> DerPublicKey {
    use der::{asn1::BitString, Encode as _};
    use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid,
            parameters: curve.map(|c| der::Any::encode_from(&c).unwrap()),
        },
        subject_public_key: BitString::from_bytes(key_bytes).unwrap(),
    };
    DerPublicKey::new(spki.to_der().unwrap())
}

fn generate_p256_pkcs8() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    pkey.private_key_to_der_pkcs8().unwrap()
}

fn sign_p384_sha384(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let raw_pubkey = ec_key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
    signer.update(data).unwrap();
    let sig = SignatureBytes::new(signer.sign_to_vec().unwrap());
    (raw_pubkey, sig)
}

fn sign_ed25519(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
    let pkey = PKey::generate(Id::ED25519).unwrap();
    let mut signer = Signer::new_without_digest(&pkey).unwrap();
    let sig = SignatureBytes::new(signer.sign_oneshot_to_vec(data).unwrap());
    let spki = pkey.public_key_to_der().unwrap();
    // Last 32 bytes of RFC 8410 Ed25519 SPKI are the raw public key.
    let raw_pubkey = spki[spki.len() - 32..].to_vec();
    (raw_pubkey, sig)
}

fn sign_mldsa(scheme: SigningScheme, seed: &[u8; 32], data: &[u8]) -> (Vec<u8>, SignatureBytes) {
    let alg = match scheme {
        SigningScheme::MlDsa44 => MlDsaAlgorithm::MlDsa44,
        SigningScheme::MlDsa65 => MlDsaAlgorithm::MlDsa65,
        SigningScheme::MlDsa87 => MlDsaAlgorithm::MlDsa87,
        _ => panic!("unsupported ML-DSA signing scheme"),
    };
    let sk = MlDsaPrivateKey::from_seed(alg, seed).unwrap();
    let pk = sk.public_key().unwrap().to_bytes().unwrap();
    let sig = sk.sign(data).unwrap();
    (pk, SignatureBytes::new(sig))
}

fn sign_rsa(
    data: &[u8],
    hash_alg: HashAlgorithm,
) -> (DerPublicKey, SignatureBytes, SignatureBytes) {
    let rsa = Rsa::generate(2048).unwrap();
    let bare = DerPublicKey::new(rsa.public_key_to_der_pkcs1().unwrap());
    let pkey = PKey::from_rsa(rsa).unwrap();
    let md = message_digest(hash_alg).unwrap();

    let mut pkcs1_signer = Signer::new(md, &pkey).unwrap();
    pkcs1_signer.update(data).unwrap();
    let pkcs1_sig = SignatureBytes::new(pkcs1_signer.sign_to_vec().unwrap());

    let mut pss_signer = Signer::new(md, &pkey).unwrap();
    pss_signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    pss_signer.set_rsa_mgf1_md(md).unwrap();
    pss_signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .unwrap();
    pss_signer.update(data).unwrap();
    let pss_sig = SignatureBytes::new(pss_signer.sign_to_vec().unwrap());

    (bare, pkcs1_sig, pss_sig)
}

// ============================================================================
// Tests exercising sigstore-crypto through BoringProvider
// ============================================================================

#[test]
fn provider_registration_and_hashing() {
    ensure_boring_installed();
    assert!(try_default_provider().is_some());
    assert!(install_default_provider(&BORING_PROVIDER).is_err());
    assert_eq!(format!("{:?}", default_provider()), "BoringProvider");

    let expected_256 =
        hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").unwrap();
    assert_eq!(sha256(b"hello").as_bytes(), expected_256.as_slice());

    let expected_512 = hex::decode(concat!(
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
        "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
    ))
    .unwrap();
    assert_eq!(sha512(b"hello").as_bytes(), expected_512.as_slice());

    let mut hasher = Sha256Hasher::new();
    hasher.update(b"hel");
    hasher.update(b"lo");
    assert_eq!(hasher.finalize(), sha256(b"hello"));

    let mut artifact_hasher = ArtifactHasher::new(HashAlgorithm::Sha2384).unwrap();
    artifact_hasher.update(b"hello");
    assert_eq!(
        artifact_hasher.finalize().as_bytes(),
        sha384(b"hello").as_slice()
    );

    let reader_hash = sha256_reader(std::io::Cursor::new(b"hello")).unwrap();
    assert_eq!(reader_hash, sha256(b"hello"));
}

#[test]
fn ecdsa_p256_signing_pkcs8_keyring_and_checkpoint() {
    ensure_boring_installed();

    let kp = KeyPair::generate_ecdsa_p256().unwrap();
    assert_eq!(kp.public_key_bytes().len(), 65);
    assert_eq!(kp.public_key_bytes()[0], 0x04);

    let message = b"test message signed via BoringProvider";
    let sig = kp.sign(message).unwrap();
    let pubkey_der = kp.public_key_der().unwrap();
    let vk = VerificationKey::from_spki(&pubkey_der).unwrap();
    vk.verify(message, &sig).unwrap();
    assert!(vk.verify(b"tampered", &sig).is_err());

    let digest = sha256(message);
    vk.verify_prehashed(digest.as_bytes(), &sig).unwrap();

    // PKCS#8 round-trip and trailing-byte rejection
    let pkcs8 = generate_p256_pkcs8();
    let loaded = KeyPair::from_pkcs8_der(&pkcs8).unwrap();
    assert_eq!(loaded.algorithm(), KeyAlgorithm::EcdsaP256);
    let mut with_trailing = pkcs8;
    with_trailing.push(0x00);
    assert!(matches!(
        KeyPair::from_pkcs8_der(&with_trailing),
        Err(Error::InvalidKeyFormat(_))
    ));

    // Keyring verification
    let mut keyring = Keyring::new();
    let key_id = sha256(pubkey_der.as_bytes());
    keyring.add_key(key_id, vk);
    assert_eq!(keyring.verify_any(message, &sig).unwrap(), key_id);

    // Checkpoint verification
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let hint = compute_key_hint(&pubkey_der);
    let body = "example.com/log\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
    let cp_sig = kp.sign(body.as_bytes()).unwrap();
    let mut raw_note_sig = hint.as_bytes().to_vec();
    raw_note_sig.extend_from_slice(cp_sig.as_bytes());
    let text = format!(
        "{body}\n\u{2014} test-log {}\n",
        engine.encode(raw_note_sig)
    );
    let checkpoint = Checkpoint::from_text(&text).unwrap();
    checkpoint.verify_signature(&pubkey_der).unwrap();
}

#[test]
fn p384_ed25519_rsa_mldsa_and_webpki_verification() {
    ensure_boring_installed();
    let data = b"multi-algorithm verification payload";

    // 1. ECDSA P-384
    let (p384_pk, p384_sig) = sign_p384_sha384(data);
    let p384_spki = spki_der(ID_EC_PUBLIC_KEY, Some(SECP_384_R_1), &p384_pk);
    let vk_p384 = VerificationKey::from_spki(&p384_spki).unwrap();
    vk_p384.verify(data, &p384_sig).unwrap();
    vk_p384.verify_prehashed(&sha384(data), &p384_sig).unwrap();
    let vk_p384_256 =
        VerificationKey::from_spki_with_scheme(&p384_spki, SigningScheme::EcdsaP384Sha256).unwrap();
    assert!(vk_p384_256.verify(data, &p384_sig).is_err());

    // Compressed SEC1 point must be rejected
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    let compressed_spki = spki_der(ID_EC_PUBLIC_KEY, Some(SECP_256_R_1), &compressed);
    let vk_comp = VerificationKey::from_spki(&compressed_spki).unwrap();
    let dummy_sig = SignatureBytes::new(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    assert!(vk_comp.verify(data, &dummy_sig).is_err());

    // 2. Ed25519 (dynamic + RFC 8032 static vector)
    let (ed_pk, ed_sig) = sign_ed25519(data);
    let ed_spki = spki_der(ID_ED25519, None, &ed_pk);
    let vk_ed = VerificationKey::from_spki(&ed_spki).unwrap();
    vk_ed.verify(data, &ed_sig).unwrap();

    let rfc8032_pk: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];
    let rfc8032_sig: [u8; 64] = [
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00,
    ];
    let vk_rfc8032 = VerificationKey::from_spki(&spki_der(ID_ED25519, None, &rfc8032_pk)).unwrap();
    vk_rfc8032
        .verify([0x72], &SignatureBytes::new(rfc8032_sig.to_vec()))
        .unwrap();

    // 3. RSA PKCS#1 v1.5 and PSS (SHA-256, SHA-384, SHA-512)
    let digest256 = sha256(data);
    let digest384 = sha384(data);
    let digest512 = sha512(data);
    for (hash_alg, digest, pkcs1_scheme, pss_scheme) in [
        (
            HashAlgorithm::Sha2256,
            &digest256.as_bytes()[..],
            SigningScheme::RsaPkcs1Sha256,
            SigningScheme::RsaPssSha256,
        ),
        (
            HashAlgorithm::Sha2384,
            digest384.as_slice(),
            SigningScheme::RsaPkcs1Sha384,
            SigningScheme::RsaPssSha384,
        ),
        (
            HashAlgorithm::Sha2512,
            &digest512.as_bytes()[..],
            SigningScheme::RsaPkcs1Sha512,
            SigningScheme::RsaPssSha512,
        ),
    ] {
        let (bare, pkcs1_sig, pss_sig) = sign_rsa(data, hash_alg);
        let spki = spki_der(RSA_ENCRYPTION, None, bare.as_bytes());

        let vk_pkcs1 = VerificationKey::from_spki_with_scheme(&spki, pkcs1_scheme).unwrap();
        vk_pkcs1.verify(data, &pkcs1_sig).unwrap();
        vk_pkcs1.verify_prehashed(digest, &pkcs1_sig).unwrap();
        assert!(vk_pkcs1.verify(data, &pss_sig).is_err());

        let vk_pss = VerificationKey::from_der(&bare, pss_scheme).unwrap();
        vk_pss.verify(data, &pss_sig).unwrap();
        vk_pss.verify_prehashed(digest, &pss_sig).unwrap();
        assert!(vk_pss.verify(data, &pkcs1_sig).is_err());
    }

    // 4. ML-DSA-44/65/87
    let seed = [0x5au8; 32];
    for (oid, scheme) in [
        (ID_ML_DSA_44, SigningScheme::MlDsa44),
        (ID_ML_DSA_65, SigningScheme::MlDsa65),
        (ID_ML_DSA_87, SigningScheme::MlDsa87),
    ] {
        let (raw_pk, sig) = sign_mldsa(scheme, &seed, data);
        let spki = spki_der(oid, None, &raw_pk);
        let vk = VerificationKey::from_spki(&spki).unwrap();
        vk.verify(data, &sig).unwrap();
        assert!(vk.verify(b"wrong", &sig).is_err());
    }

    // 5. WEBPKI_VERIFICATION_ALGS
    assert_eq!(WEBPKI_VERIFICATION_ALGS.len(), 17);
    let (rsa_pk, pkcs1_sig, pss_sig) = sign_rsa(data, HashAlgorithm::Sha2256);
    for alg in [
        sigstore_crypto::webpki::RSA_PKCS1_2048_8192_SHA256,
        sigstore_crypto::webpki::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    ] {
        alg.verify_signature(rsa_pk.as_bytes(), data, pkcs1_sig.as_bytes())
            .unwrap();
    }
    sigstore_crypto::webpki::RSA_PSS_2048_8192_SHA256
        .verify_signature(rsa_pk.as_bytes(), data, pss_sig.as_bytes())
        .unwrap();
}

#[test]
fn emsa_pkcs1_and_pss_prehashed_boundary_cases() {
    ensure_boring_installed();

    // 1. EMSA-PKCS1-v1_5 DigestInfo boundaries
    let digest256 = [0x42u8; 32];
    let prefix_with_null: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let prefix_without_null: &[u8] = &[
        0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x04, 0x20,
    ];

    let mut di_null = prefix_with_null.to_vec();
    di_null.extend_from_slice(&digest256);
    assert!(verify_emsa_pkcs1_digest_info(&di_null, HashAlgorithm::Sha2256, &digest256).is_ok());

    let mut di_no_null = prefix_without_null.to_vec();
    di_no_null.extend_from_slice(&digest256);
    assert!(verify_emsa_pkcs1_digest_info(&di_no_null, HashAlgorithm::Sha2256, &digest256).is_ok());

    assert!(verify_emsa_pkcs1_digest_info(&di_null, HashAlgorithm::Sha2384, &digest256).is_err());
    assert!(
        verify_emsa_pkcs1_digest_info(&di_null, HashAlgorithm::Sha2384, &[0x42u8; 48]).is_err()
    );
    assert!(
        verify_emsa_pkcs1_digest_info(&di_null, HashAlgorithm::Sha2256, &[0x42u8; 31]).is_err()
    );

    let mut di_trailing = di_null.clone();
    di_trailing.push(0x00);
    assert!(
        verify_emsa_pkcs1_digest_info(&di_trailing, HashAlgorithm::Sha2256, &digest256).is_err()
    );

    let mut di_bad_oid = di_null.clone();
    di_bad_oid[14] ^= 0x01;
    assert!(
        verify_emsa_pkcs1_digest_info(&di_bad_oid, HashAlgorithm::Sha2256, &digest256).is_err()
    );

    let mut di_bad_digest = di_null;
    *di_bad_digest.last_mut().unwrap() ^= 0x01;
    assert!(
        verify_emsa_pkcs1_digest_info(&di_bad_digest, HashAlgorithm::Sha2256, &digest256).is_err()
    );

    // 2. EMSA-PSS boundaries
    let data = b"pss boundary test payload";
    let digest = sha256(data);
    let (bare, _pkcs1_sig, pss_sig) = sign_rsa(data, HashAlgorithm::Sha2256);
    let rsa = parse_rsa_public_key(bare.as_bytes()).unwrap();
    let mod_len = rsa.size() as usize;
    let mod_bits = rsa.n().num_bits() as usize;
    let md = MessageDigest::sha256();

    let mut valid_em = vec![0u8; mod_len];
    let len = rsa
        .public_decrypt(pss_sig.as_bytes(), &mut valid_em, Padding::NONE)
        .unwrap();
    assert_eq!(len, mod_len);
    assert!(verify_emsa_pss(&valid_em, mod_bits, md, digest.as_bytes()).is_ok());

    assert!(verify_emsa_pss(&valid_em, 0, md, digest.as_bytes()).is_err());
    assert!(verify_emsa_pss(&valid_em, mod_bits + 16, md, digest.as_bytes()).is_err());
    assert!(verify_emsa_pss(&valid_em, mod_bits, md, &[0u8; 31]).is_err());
    assert!(verify_emsa_pss(&valid_em[..65], 65 * 8, md, digest.as_bytes()).is_err());

    let mut bad_trailer = valid_em.clone();
    *bad_trailer.last_mut().unwrap() = 0xbd;
    assert!(verify_emsa_pss(&bad_trailer, mod_bits, md, digest.as_bytes()).is_err());

    let mut bad_top_bit = valid_em.clone();
    bad_top_bit[0] |= 0x80;
    assert!(verify_emsa_pss(&bad_top_bit, mod_bits, md, digest.as_bytes()).is_err());

    let mut bad_ps = valid_em.clone();
    bad_ps[10] ^= 0x01;
    assert!(verify_emsa_pss(&bad_ps, mod_bits, md, digest.as_bytes()).is_err());

    let zero_pad_len = mod_len - 32 - 32 - 2;
    let mut bad_sep = valid_em.clone();
    bad_sep[zero_pad_len] ^= 0x02;
    assert!(verify_emsa_pss(&bad_sep, mod_bits, md, digest.as_bytes()).is_err());

    let mut wrong_digest = *digest.as_bytes();
    wrong_digest[0] ^= 0x01;
    assert!(verify_emsa_pss(&valid_em, mod_bits, md, &wrong_digest).is_err());

    let mut prefixed_em = vec![0x01];
    prefixed_em.extend_from_slice(&valid_em);
    assert!(verify_emsa_pss(&prefixed_em, mod_bits, md, digest.as_bytes()).is_err());
    prefixed_em[0] = 0x00;
    assert!(verify_emsa_pss(&prefixed_em, mod_bits, md, digest.as_bytes()).is_ok());
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn cross_provider_interoperability_with_aws_lc() {
    ensure_boring_installed();
    let aws = sigstore_crypto::aws_lc_provider();
    let bor: &dyn CryptoProvider = &BORING_PROVIDER;

    let data = b"cross-provider interoperability test payload";
    let digest256 = aws.sha256(data);
    assert_eq!(digest256, bor.sha256(data));
    let digest384 = aws.sha384(data);
    assert_eq!(digest384, bor.sha384(data));
    let digest512 = aws.sha512(data);
    assert_eq!(digest512, bor.sha512(data));

    // 1. ECDSA P-256 PKCS#8 + signing cross-verification
    let pkcs8 = generate_p256_pkcs8();
    let aws_kp = aws.key_pair_from_pkcs8_der(&pkcs8).unwrap();
    let bor_kp = bor.key_pair_from_pkcs8_der(&pkcs8).unwrap();
    assert_eq!(aws_kp.algorithm(), KeyAlgorithm::EcdsaP256);
    assert_eq!(bor_kp.algorithm(), KeyAlgorithm::EcdsaP256);
    assert_eq!(aws_kp.public_key_bytes(), bor_kp.public_key_bytes());

    let aws_sig = aws_kp.sign_prehashed(&digest256).unwrap();
    let bor_sig = bor_kp.sign_raw(data).unwrap();
    bor.verify_raw(
        SigningScheme::EcdsaP256Sha256,
        aws_kp.public_key_bytes(),
        data,
        &aws_sig,
    )
    .unwrap();
    aws.verify_raw(
        SigningScheme::EcdsaP256Sha256,
        bor_kp.public_key_bytes(),
        data,
        &bor_sig,
    )
    .unwrap();

    // 2. ECDSA P-384, Ed25519, RSA, and ML-DSA signed by BoringSSL and verified by AwsLcProvider
    let (p384_pk, p384_sig) = sign_p384_sha384(data);
    aws.verify_raw(
        SigningScheme::EcdsaP384Sha384,
        &p384_pk,
        data,
        p384_sig.as_bytes(),
    )
    .unwrap();

    let (ed_pk, ed_sig) = sign_ed25519(data);
    aws.verify_raw(SigningScheme::Ed25519, &ed_pk, data, ed_sig.as_bytes())
        .unwrap();

    for (hash_alg, digest, pkcs1_scheme, pss_scheme) in [
        (
            HashAlgorithm::Sha2256,
            &digest256[..],
            SigningScheme::RsaPkcs1Sha256,
            SigningScheme::RsaPssSha256,
        ),
        (
            HashAlgorithm::Sha2384,
            &digest384[..],
            SigningScheme::RsaPkcs1Sha384,
            SigningScheme::RsaPssSha384,
        ),
        (
            HashAlgorithm::Sha2512,
            &digest512[..],
            SigningScheme::RsaPkcs1Sha512,
            SigningScheme::RsaPssSha512,
        ),
    ] {
        let (rsa_pk, pkcs1_sig, pss_sig) = sign_rsa(data, hash_alg);
        aws.verify_raw(pkcs1_scheme, rsa_pk.as_bytes(), data, pkcs1_sig.as_bytes())
            .unwrap();
        aws.verify_prehashed(
            pkcs1_scheme,
            rsa_pk.as_bytes(),
            digest,
            pkcs1_sig.as_bytes(),
        )
        .unwrap();
        aws.verify_raw(pss_scheme, rsa_pk.as_bytes(), data, pss_sig.as_bytes())
            .unwrap();
        aws.verify_prehashed(pss_scheme, rsa_pk.as_bytes(), digest, pss_sig.as_bytes())
            .unwrap();
    }

    let seed = [0x7bu8; 32];
    for scheme in [
        SigningScheme::MlDsa44,
        SigningScheme::MlDsa65,
        SigningScheme::MlDsa87,
    ] {
        let (bor_pk, bor_sig) = sign_mldsa(scheme, &seed, data);
        aws.verify_raw(scheme, &bor_pk, data, bor_sig.as_bytes())
            .unwrap();
    }
}
