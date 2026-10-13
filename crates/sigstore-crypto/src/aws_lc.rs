//! Default [`CryptoProvider`](crate::provider::CryptoProvider) implementation backed by `aws-lc-rs`.

use crate::error::{Error, Result};
use crate::provider::{CryptoProvider, HashContext, SigningKeyPair};
use crate::signing::{KeyAlgorithm, SigningScheme};
use aws_lc_rs::{
    digest::{self, Context, Digest, SHA256, SHA384, SHA512},
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair as AwsKeyPair, UnparsedPublicKey, VerificationAlgorithm,
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA384_ASN1,
        ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, ML_DSA_44, ML_DSA_65, ML_DSA_87,
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
    },
};
use sigstore_types::HashAlgorithm;

pub(crate) static AWS_LC_PROVIDER: AwsLcProvider = AwsLcProvider;

#[derive(Debug)]
pub(crate) struct AwsLcProvider;

struct AwsLcHashContext(Context);

impl HashContext for AwsLcHashContext {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }
}

struct AwsLcP256KeyPair(EcdsaKeyPair);

impl AwsLcP256KeyPair {
    fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Ok(Self(kp))
    }
}

impl SigningKeyPair for AwsLcP256KeyPair {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EcdsaP256
    }

    fn public_key_bytes(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .0
            .sign(&rng, data)
            .map_err(|_| Error::Signing("the cryptographic backend failed to sign".to_string()))?;
        Ok(sig.as_ref().to_vec())
    }

    fn sign_prehashed(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let digest = Digest::import_less_safe(digest, &SHA256)
            .map_err(|_| Error::Signing("invalid SHA-256 digest".to_string()))?;
        let sig = self
            .0
            .sign_digest(&digest)
            .map_err(|_| Error::Signing("the cryptographic backend failed to sign".to_string()))?;
        Ok(sig.as_ref().to_vec())
    }
}

fn verification_algorithm(scheme: SigningScheme) -> &'static dyn VerificationAlgorithm {
    match scheme {
        SigningScheme::EcdsaP256Sha256 => &ECDSA_P256_SHA256_ASN1,
        SigningScheme::EcdsaP256Sha384 => &ECDSA_P256_SHA384_ASN1,
        SigningScheme::EcdsaP384Sha256 => &ECDSA_P384_SHA256_ASN1,
        SigningScheme::EcdsaP384Sha384 => &ECDSA_P384_SHA384_ASN1,
        SigningScheme::Ed25519 => &ED25519,
        SigningScheme::RsaPssSha256 => &RSA_PSS_2048_8192_SHA256,
        SigningScheme::RsaPssSha384 => &RSA_PSS_2048_8192_SHA384,
        SigningScheme::RsaPssSha512 => &RSA_PSS_2048_8192_SHA512,
        SigningScheme::RsaPkcs1Sha256 => &RSA_PKCS1_2048_8192_SHA256,
        SigningScheme::RsaPkcs1Sha384 => &RSA_PKCS1_2048_8192_SHA384,
        SigningScheme::RsaPkcs1Sha512 => &RSA_PKCS1_2048_8192_SHA512,
        SigningScheme::MlDsa44 => &ML_DSA_44,
        SigningScheme::MlDsa65 => &ML_DSA_65,
        SigningScheme::MlDsa87 => &ML_DSA_87,
    }
}

impl CryptoProvider for AwsLcProvider {
    fn hash(&self, algorithm: HashAlgorithm) -> Result<Box<dyn HashContext>> {
        let backend = match algorithm {
            HashAlgorithm::Sha2256 => &SHA256,
            HashAlgorithm::Sha2384 => &SHA384,
            HashAlgorithm::Sha2512 => &SHA512,
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "cannot compute {algorithm} digests"
                )))
            }
        };
        Ok(Box::new(AwsLcHashContext(Context::new(backend))))
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let digest = digest::digest(&SHA256, data);
        let mut result = [0u8; 32];
        result.copy_from_slice(digest.as_ref());
        result
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        let digest = digest::digest(&SHA384, data);
        let mut result = [0u8; 48];
        result.copy_from_slice(digest.as_ref());
        result
    }

    fn sha512(&self, data: &[u8]) -> [u8; 64] {
        let digest = digest::digest(&SHA512, data);
        let mut result = [0u8; 64];
        result.copy_from_slice(digest.as_ref());
        result
    }

    fn verify_raw(
        &self,
        scheme: SigningScheme,
        spki_pubkey_bytes: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let key = UnparsedPublicKey::new(verification_algorithm(scheme), spki_pubkey_bytes);
        key.verify(data, signature)
            .map_err(|_| Error::Verification(format!("{} signature invalid", scheme.name())))
    }

    fn verify_prehashed(
        &self,
        scheme: SigningScheme,
        spki_pubkey_bytes: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let aws_algo = match scheme.hash_algorithm() {
            Some(HashAlgorithm::Sha2256) => &SHA256,
            Some(HashAlgorithm::Sha2384) => &SHA384,
            Some(HashAlgorithm::Sha2512) => &SHA512,
            _ => {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "Scheme {scheme:?} does not support prehashed mode"
                )))
            }
        };
        let aws_digest = Digest::import_less_safe(digest, aws_algo).map_err(|_| {
            Error::Verification(format!(
                "Failed to import digest: len={}, algo_expected_len={}",
                digest.len(),
                aws_algo.output_len()
            ))
        })?;
        let key = UnparsedPublicKey::new(verification_algorithm(scheme), spki_pubkey_bytes);
        key.verify_digest(&aws_digest, signature)
            .map_err(|_| Error::Verification(format!("{} signature invalid", scheme.name())))
    }

    fn generate_key_pair(&self, algorithm: KeyAlgorithm) -> Result<Box<dyn SigningKeyPair>> {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => {
                let rng = SystemRandom::new();
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .map_err(|_| {
                        Error::KeyGeneration("failed to generate ECDSA P-256 key".to_string())
                    })?;
                Ok(Box::new(AwsLcP256KeyPair::from_pkcs8(pkcs8.as_ref())?))
            }
            other => Err(Error::UnsupportedAlgorithm(format!(
                "key generation is not supported for {other:?}"
            ))),
        }
    }

    fn key_pair_from_pkcs8_der(&self, pkcs8: &[u8]) -> Result<Box<dyn SigningKeyPair>> {
        Ok(Box::new(AwsLcP256KeyPair::from_pkcs8(pkcs8)?))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use aws_lc_rs::{
        rsa::KeySize,
        signature::{
            Ed25519KeyPair, PqdsaKeyPair, RsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING,
            ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
        },
    };
    use sigstore_types::{DerPublicKey, SignatureBytes};

    pub(crate) fn generate_p256_pkcs8() -> Vec<u8> {
        let rng = SystemRandom::new();
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    pub(crate) fn sign_p384_sha384(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let sig = SignatureBytes::new(kp.sign(&rng, data).unwrap().as_ref().to_vec());
        (kp.public_key().as_ref().to_vec(), sig)
    }

    pub(crate) fn sign_ed25519(data: &[u8]) -> (Vec<u8>, SignatureBytes) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let sig = SignatureBytes::new(kp.sign(data).as_ref().to_vec());
        (kp.public_key().as_ref().to_vec(), sig)
    }

    pub(crate) fn sign_mldsa(
        scheme: SigningScheme,
        seed: &[u8; 32],
        data: &[u8],
    ) -> (Vec<u8>, SignatureBytes) {
        let alg = match scheme {
            SigningScheme::MlDsa44 => &ML_DSA_44_SIGNING,
            SigningScheme::MlDsa65 => &ML_DSA_65_SIGNING,
            SigningScheme::MlDsa87 => &ML_DSA_87_SIGNING,
            _ => panic!("unsupported ML-DSA signing scheme"),
        };
        let kp = PqdsaKeyPair::from_seed(alg, seed).unwrap();
        let mut sig = vec![0u8; alg.signature_len()];
        let sig_len = kp.sign(data, &mut sig).unwrap();
        sig.truncate(sig_len);
        (kp.public_key().as_ref().to_vec(), SignatureBytes::new(sig))
    }

    pub(crate) fn sign_rsa(
        data: &[u8],
        hash_alg: HashAlgorithm,
    ) -> (DerPublicKey, SignatureBytes, SignatureBytes) {
        let rng = SystemRandom::new();
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let bare = DerPublicKey::new(key.public_key().as_ref().to_vec());
        let (pkcs1_enc, pss_enc) = match hash_alg {
            HashAlgorithm::Sha2256 => (&RSA_PKCS1_SHA256, &RSA_PSS_SHA256),
            HashAlgorithm::Sha2384 => (&RSA_PKCS1_SHA384, &RSA_PSS_SHA384),
            HashAlgorithm::Sha2512 => (&RSA_PKCS1_SHA512, &RSA_PSS_SHA512),
            _ => panic!("unsupported RSA hash algorithm"),
        };
        let mut pkcs1_buf = vec![0u8; key.public_modulus_len()];
        key.sign(pkcs1_enc, &rng, data, &mut pkcs1_buf).unwrap();
        let mut pss_buf = vec![0u8; key.public_modulus_len()];
        key.sign(pss_enc, &rng, data, &mut pss_buf).unwrap();
        (
            bare,
            SignatureBytes::new(pkcs1_buf),
            SignatureBytes::new(pss_buf),
        )
    }
}
