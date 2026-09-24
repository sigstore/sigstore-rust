//! X.509 certificate utilities for Sigstore
//!
//! This module provides utilities for parsing and extracting information
//! from X.509 certificates used in Sigstore bundles.

use crate::error::{Error, Result};
use crate::KeyAlgorithm;
use sigstore_types::DerPublicKey;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

// OID constants for algorithm identification
use const_oid::ObjectIdentifier;

/// Legacy Fulcio issuer extension (raw UTF-8).
const FULCIO_ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
/// Current Fulcio issuer extension (DER UTF8String).
const FULCIO_ISSUER_V2_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
/// The arc all Fulcio extensions live under.
const FULCIO_ARC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1");

/// Information extracted from a certificate
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CertificateInfo {
    /// Identity from SAN extension (email or URI)
    pub identity: Option<String>,
    /// Issuer from certificate (OIDC issuer URL from Fulcio extension)
    pub issuer: Option<String>,
    /// Not valid before
    pub not_before: jiff::Timestamp,
    /// Not valid after
    pub not_after: jiff::Timestamp,
    /// Public key in DER-encoded SPKI format
    pub public_key: DerPublicKey,
    /// Key algorithm derived from the public key algorithm
    pub key_algorithm: KeyAlgorithm,
    /// Claims about the CI workload the certificate was issued to
    pub ci_claims: FulcioCiClaims,
}

/// The claims a Fulcio certificate makes about the CI workload it was issued
/// to, from the extensions under the arc `1.3.6.1.4.1.57264.1`.
///
/// Fulcio copies these from the workload identity token, so together they
/// describe where a signed artifact came from: the repository, the commit, the
/// build configuration that ran and the CI run that invoked the signer. They
/// are the values a relying party needs to decide whether a signature it has
/// verified was produced by the build it expects, which the SAN identity and
/// the OIDC issuer alone do not answer.
///
/// Every claim is optional. Fulcio only sets them for a certificate issued to a
/// CI workload, and which ones it sets depends on the identity provider: a
/// certificate issued to a human identity through an interactive OIDC flow
/// carries none of them. The names are provider-neutral by design, so a relying
/// party should render or match whichever claims are present instead of
/// branching on the issuer.
///
/// The deprecated extensions `1.3.6.1.4.1.57264.1.2` to `.1.6` are not read.
/// The claims below supersede them, and unlike them are DER encoded rather than
/// bare strings. See
/// <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md>.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FulcioCiClaims {
    /// `.1.9` — the build configuration that requested the signature,
    /// including its ref. This is the value the SAN identity is derived from.
    pub build_signer_uri: Option<String>,
    /// `.1.10` — the commit the signing configuration was taken from.
    pub build_signer_digest: Option<String>,
    /// `.1.11` — the kind of runner the workload ran on, e.g. `github-hosted`
    /// or `self-hosted`.
    ///
    /// A self-hosted runner is a weaker guarantee than a provider-hosted one,
    /// because its environment is controlled by the repository owner.
    pub runner_environment: Option<String>,
    /// `.1.12` — the repository the artifact was built from.
    pub source_repository_uri: Option<String>,
    /// `.1.13` — the commit the artifact was built from.
    pub source_repository_digest: Option<String>,
    /// `.1.14` — the ref the artifact was built from, e.g. `refs/heads/main`.
    pub source_repository_ref: Option<String>,
    /// `.1.15` — the provider's immutable identifier for the repository.
    ///
    /// Unlike [`Self::source_repository_uri`] this does not change when the
    /// repository is renamed or transferred, which makes it the more robust
    /// value for a policy to pin to.
    pub source_repository_identifier: Option<String>,
    /// `.1.16` — the owner of the source repository.
    pub source_repository_owner_uri: Option<String>,
    /// `.1.17` — the provider's immutable identifier for the owner.
    pub source_repository_owner_identifier: Option<String>,
    /// `.1.18` — the build configuration that ran, e.g. a workflow file.
    pub build_config_uri: Option<String>,
    /// `.1.19` — the commit the build configuration was taken from.
    pub build_config_digest: Option<String>,
    /// `.1.20` — the event that triggered the build, e.g. `push` or `release`.
    pub build_trigger: Option<String>,
    /// `.1.21` — the specific run that produced the signature. For GitHub
    /// Actions this is a URL under which the build logs can be inspected.
    pub run_invocation_uri: Option<String>,
    /// `.1.22` — whether the source repository was `public`, `private` or
    /// `internal` when the certificate was issued.
    ///
    /// A signature from a private repository cannot be audited by a third
    /// party, because neither the source nor the build logs are reachable.
    pub source_repository_visibility_at_signing: Option<String>,
    /// `.1.23` — the deployment environment the build targeted, e.g.
    /// `production`. Absent when the build declared no environment.
    ///
    /// An environment is what a provider attaches deployment protection rules
    /// to — required reviewers, a wait timer, a branch allowlist — so a policy
    /// that pins this claim asks for more than a build from the expected ref:
    /// it asks for one that passed those gates.
    pub deployment_environment: Option<String>,
    /// `.1.24` — the raw `sub` claim of the identity token the certificate was
    /// requested with, e.g. `repo:sigstore/fulcio:ref:refs/heads/main`.
    ///
    /// Providers translate `sub` into the SAN identity and the claims above,
    /// each in their own way; this is what the token itself said, unchanged.
    pub token_subject: Option<String>,
}

impl FulcioCiClaims {
    /// Whether the certificate carried no CI claims at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Parse certificate information from DER-encoded certificate
pub fn parse_certificate_info(cert_der: &[u8]) -> Result<CertificateInfo> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::InvalidCertificate(format!("failed to parse certificate: {}", e)))?;

    // Extract validity times
    let not_before =
        jiff::Timestamp::try_from(cert.tbs_certificate.validity.not_before.to_system_time())
            .map_err(|e| Error::InvalidCertificate(format!("invalid notBefore time: {}", e)))?;
    let not_after =
        jiff::Timestamp::try_from(cert.tbs_certificate.validity.not_after.to_system_time())
            .map_err(|e| Error::InvalidCertificate(format!("invalid notAfter time: {}", e)))?;

    // Extract public key in SPKI (SubjectPublicKeyInfo) DER format
    // This is required by aws-lc-rs UnparsedPublicKey, which expects the full SPKI,
    // not just the raw key bytes
    let public_key_info = &cert.tbs_certificate.subject_public_key_info;
    let public_key_der = public_key_info
        .to_der()
        .map_err(|e| Error::InvalidCertificate(format!("failed to encode SPKI: {}", e)))?;
    let public_key = DerPublicKey::new(public_key_der);

    // Determine key algorithm from algorithm OID and parameters
    let key_algorithm = KeyAlgorithm::from_spki(&public_key)?;

    // Extract identity from SAN extension
    let identity = extract_san_identity(&cert)?;

    // Extract issuer from Fulcio extension
    let issuer = extract_fulcio_issuer(&cert)?;

    Ok(CertificateInfo {
        identity,
        issuer,
        not_before,
        not_after,
        public_key,
        key_algorithm,
        ci_claims: extract_fulcio_ci_claims(&cert),
    })
}

/// Extract identity from Subject Alternative Name (SAN) extension
///
/// This extracts the email address or URI from the SAN extension using
/// x509-cert's proper ASN.1 parsing (handles all length encodings correctly).
pub fn extract_san_identity(cert: &Certificate) -> Result<Option<String>> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    // Try to get the SAN extension using the typed getter
    // Returns Option<(critical: bool, extension: T)>
    let san_opt: Option<(bool, SubjectAltName)> = cert
        .tbs_certificate
        .get()
        .map_err(|e| Error::InvalidCertificate(format!("failed to get SAN extension: {}", e)))?;

    let Some((_critical, san)) = san_opt else {
        return Ok(None);
    };

    // Iterate through GeneralNames and extract email or URI
    for name in san.0.iter() {
        match name {
            GeneralName::Rfc822Name(email) => {
                return Ok(Some(email.to_string()));
            }
            GeneralName::UniformResourceIdentifier(uri) => {
                return Ok(Some(uri.to_string()));
            }
            _ => continue,
        }
    }

    Ok(None)
}

/// Extract the OIDC issuer from Fulcio certificate extension
///
/// Prefer the DER UTF8String in OID 1.3.6.1.4.1.57264.1.8. Fall back to the
/// legacy OID 1.3.6.1.4.1.57264.1.1 only when the current extension is absent;
/// a malformed current extension is an error, regardless of the legacy value.
pub fn extract_fulcio_issuer(cert: &Certificate) -> Result<Option<String>> {
    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None => return Ok(None),
    };

    if let Some(ext) = extensions
        .iter()
        .find(|ext| ext.extn_id == FULCIO_ISSUER_V2_OID)
    {
        return der::asn1::Utf8StringRef::from_der(ext.extn_value.as_bytes())
            .map(|issuer| Some(issuer.to_string()))
            .map_err(|e| {
                Error::InvalidCertificate(format!("malformed Fulcio issuer v2 extension: {e}"))
            });
    }

    for ext in extensions.iter() {
        if ext.extn_id == FULCIO_ISSUER_OID {
            // The extension value is a UTF8String wrapped in OCTET STRING
            let value_bytes = ext.extn_value.as_bytes();

            // Try to decode as UTF8String (the value is DER-encoded)
            if let Ok(utf8_str) = der::asn1::Utf8StringRef::from_der(value_bytes) {
                return Ok(Some(utf8_str.to_string()));
            }

            // Fallback: try to interpret the raw bytes as UTF-8
            if let Ok(s) = std::str::from_utf8(value_bytes) {
                return Ok(Some(s.to_string()));
            }

            return Err(Error::InvalidCertificate(
                "malformed Fulcio issuer extension".to_string(),
            ));
        }
    }

    Ok(None)
}

/// Extract the CI claims from the Fulcio extensions of a certificate.
///
/// A claim that is absent or malformed is left unset instead of reported, so a
/// certificate from a provider that populates only part of the arc still yields
/// the claims it does carry. None of these claims is used to decide whether a
/// signature is valid, so a value that cannot be read costs nothing beyond the
/// claim itself; the OIDC issuer, which policies do match on, is read by
/// [`extract_fulcio_issuer`] and is an error when malformed.
pub fn extract_fulcio_ci_claims(cert: &Certificate) -> FulcioCiClaims {
    let mut claims = FulcioCiClaims::default();
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return claims;
    };

    for ext in extensions.iter() {
        let claim = match fulcio_claim_number(&ext.extn_id) {
            // `.1.1` and `.1.8` are the OIDC issuer and `.1.2` to `.1.6` are
            // the deprecated claims the fields below supersede.
            Some(9) => &mut claims.build_signer_uri,
            Some(10) => &mut claims.build_signer_digest,
            Some(11) => &mut claims.runner_environment,
            Some(12) => &mut claims.source_repository_uri,
            Some(13) => &mut claims.source_repository_digest,
            Some(14) => &mut claims.source_repository_ref,
            Some(15) => &mut claims.source_repository_identifier,
            Some(16) => &mut claims.source_repository_owner_uri,
            Some(17) => &mut claims.source_repository_owner_identifier,
            Some(18) => &mut claims.build_config_uri,
            Some(19) => &mut claims.build_config_digest,
            Some(20) => &mut claims.build_trigger,
            Some(21) => &mut claims.run_invocation_uri,
            Some(22) => &mut claims.source_repository_visibility_at_signing,
            Some(23) => &mut claims.deployment_environment,
            Some(24) => &mut claims.token_subject,
            _ => continue,
        };

        // Every claim in this arc is a DER UTF8String inside the extension's
        // OCTET STRING.
        if let Ok(value) = der::asn1::Utf8StringRef::from_der(ext.extn_value.as_bytes()) {
            *claim = Some(value.as_str().to_owned());
        }
    }

    claims
}

/// The number identifying a Fulcio extension, if `oid` is a direct child of the
/// Fulcio arc.
fn fulcio_claim_number(oid: &ObjectIdentifier) -> Option<u32> {
    if oid.parent()? != FULCIO_ARC {
        return None;
    }
    oid.arc(FULCIO_ARC.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::DerCertificate;

    /// A Fulcio certificate issued to a GitHub Actions workflow, which populates
    /// the claim arc up to `.1.22`. It is the signing certificate of the bundle
    /// in `sigstore-verify/test_data/bundles/conda-attestation.sigstore.json`.
    const GITHUB_ACTIONS_CERT: &str = include_str!("../test_data/fulcio_github_actions_cert.pem");

    /// A Fulcio certificate issued to a GitHub Actions job that ran in a
    /// deployment environment, so it carries `.1.23` and `.1.24` as well.
    const ENVIRONMENT_CERT: &str =
        include_str!("../test_data/fulcio_github_actions_environment_cert.pem");

    /// One of the certificates of the public good instance's chain, which is not
    /// issued to a workload and therefore carries no claims.
    const INTERMEDIATE_CERT: &str = include_str!("../test_data/sigstore_intermediate_cert.pem");

    fn parse(pem: &str) -> CertificateInfo {
        let der = DerCertificate::from_pem(pem).expect("the fixture is a PEM certificate");
        parse_certificate_info(der.as_bytes()).expect("the fixture is a valid certificate")
    }

    #[test]
    fn test_parse_github_actions_claims() {
        let info = parse(GITHUB_ACTIONS_CERT);
        let workflow =
            "https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main";
        let commit = "193b5bd7d3985809503963ae400594ea16df31cf";

        assert_eq!(info.identity.as_deref(), Some(workflow));
        assert_eq!(
            info.issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );

        let claims = &info.ci_claims;
        assert!(!claims.is_empty());
        assert_eq!(claims.build_signer_uri.as_deref(), Some(workflow));
        assert_eq!(claims.build_signer_digest.as_deref(), Some(commit));
        assert_eq!(claims.runner_environment.as_deref(), Some("github-hosted"));
        assert_eq!(
            claims.source_repository_uri.as_deref(),
            Some("https://github.com/prefix-dev/sigstore-example")
        );
        assert_eq!(claims.source_repository_digest.as_deref(), Some(commit));
        assert_eq!(
            claims.source_repository_ref.as_deref(),
            Some("refs/heads/main")
        );
        assert_eq!(
            claims.source_repository_identifier.as_deref(),
            Some("1048392115")
        );
        assert_eq!(
            claims.source_repository_owner_uri.as_deref(),
            Some("https://github.com/prefix-dev")
        );
        assert_eq!(
            claims.source_repository_owner_identifier.as_deref(),
            Some("111356225")
        );
        assert_eq!(claims.build_config_uri.as_deref(), Some(workflow));
        assert_eq!(claims.build_config_digest.as_deref(), Some(commit));
        assert_eq!(claims.build_trigger.as_deref(), Some("push"));
        assert_eq!(
            claims.run_invocation_uri.as_deref(),
            Some("https://github.com/prefix-dev/sigstore-example/actions/runs/17377272645/attempts/1")
        );
        assert_eq!(
            claims.source_repository_visibility_at_signing.as_deref(),
            Some("public")
        );

        // The job declared no environment, and the certificate predates `.1.24`.
        assert_eq!(claims.deployment_environment, None);
        assert_eq!(claims.token_subject, None);
    }

    /// A job that runs in a deployment environment adds `.1.23`, and `.1.24`
    /// records the `sub` the certificate was requested with, which for GitHub
    /// Actions is the only place the environment appears verbatim — the SAN
    /// identity is the workflow ref and says nothing about it.
    #[test]
    fn test_parse_deployment_environment_claims() {
        let claims = parse(ENVIRONMENT_CERT).ci_claims;

        assert_eq!(claims.deployment_environment.as_deref(), Some("upload"));
        assert_eq!(
            claims.token_subject.as_deref(),
            Some("repo:pavelzw/skill-forge:environment:upload")
        );
        // The claims shared with the fixture above are parsed the same way, so
        // one of them is enough to show this certificate is read as a whole.
        assert_eq!(
            claims.source_repository_uri.as_deref(),
            Some("https://github.com/pavelzw/skill-forge")
        );
    }

    /// The fixture also carries the deprecated extensions `.1.2` to `.1.6`, so
    /// the claims asserted above are the ones the parser took from `.1.9`
    /// onwards rather than from their predecessors. Guards the fixture: were
    /// those extensions to disappear from it, the test above would no longer
    /// show that the deprecated arc is skipped.
    #[test]
    fn test_fixture_carries_the_deprecated_extensions() {
        let der = DerCertificate::from_pem(GITHUB_ACTIONS_CERT).expect("the fixture is a PEM");
        let cert = Certificate::from_der(der.as_bytes()).expect("the fixture is a certificate");
        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .expect("the fixture has extensions");

        for number in 2..=6 {
            let oid = format!("1.3.6.1.4.1.57264.1.{number}");
            assert!(
                extensions.iter().any(|ext| ext.extn_id.to_string() == oid),
                "the fixture is expected to carry the deprecated extension {oid}"
            );
        }
    }

    /// A certificate that was not issued to a CI workload yields no claims rather
    /// than an error, so a caller can render whatever a certificate carries
    /// without knowing how it was issued.
    #[test]
    fn test_certificate_without_claims() {
        let info = parse(INTERMEDIATE_CERT);
        assert!(info.ci_claims.is_empty());
        assert_eq!(info.ci_claims, FulcioCiClaims::default());
    }

    #[test]
    fn test_fulcio_claim_number() {
        let claim = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.9");
        assert_eq!(fulcio_claim_number(&claim), Some(9));

        // Not a child of the arc, and a grandchild of it.
        let other = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.2.9");
        assert_eq!(fulcio_claim_number(&other), None);
        let nested = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.9.1");
        assert_eq!(fulcio_claim_number(&nested), None);
    }
}
