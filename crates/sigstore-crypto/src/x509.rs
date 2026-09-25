//! X.509 certificate utilities for Sigstore
//!
//! This module provides utilities for parsing and extracting information
//! from X.509 certificates used in Sigstore bundles.

use crate::error::{Error, Result};
use crate::KeyAlgorithm;
use sigstore_types::{DerCertificate, DerPublicKey};
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

/// The identity a certificate's Subject Alternative Name asserts.
///
/// Fulcio issues certificates with an email address (for human identities)
/// or a URI (for workloads such as CI jobs).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubjectAltName {
    /// An `rfc822Name` (email address)
    Email(String),
    /// A `uniformResourceIdentifier`
    Uri(String),
}

impl SubjectAltName {
    /// The identity value, regardless of its kind.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Email(value) | Self::Uri(value) => value,
        }
    }
}

impl std::fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Information extracted from a certificate
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CertificateInfo {
    /// Identity from the SAN extension (the first email or URI)
    pub identity: Option<SubjectAltName>,
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
/// The extensions Fulcio has deprecated are read too, into
/// [`Self::deprecated_github`]. See
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
    /// The GitHub Actions specific claims Fulcio deprecated in favour of the
    /// provider-neutral ones above.
    pub deprecated_github: DeprecatedGitHubClaims,
}

impl FulcioCiClaims {
    /// Whether the certificate carried no CI claims at all, deprecated ones
    /// included.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The GitHub Actions specific claims from the extensions
/// `1.3.6.1.4.1.57264.1.2` to `.1.6`, which Fulcio deprecated in favour of the
/// provider-neutral claims in [`FulcioCiClaims`].
///
/// Prefer the successor each field below points at. All but
/// [`Self::workflow_name`] have one, and a certificate Fulcio issues to a GitHub
/// Actions workflow today carries both. These are read for the certificates that
/// predate the provider-neutral arc: such a certificate carries the deprecated
/// extensions alone, so for that signature they are the only claims there are.
///
/// They are kept apart from their successors rather than folded into them
/// because the values are not interchangeable — [`Self::workflow_repository`] is
/// `owner/repository` where [`FulcioCiClaims::source_repository_uri`] is a full
/// URL — and because [`Self::workflow_name`] has no successor at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeprecatedGitHubClaims {
    /// `.1.2` — the event that triggered the workflow run, e.g. `push`.
    /// Superseded by [`FulcioCiClaims::build_trigger`], which holds the same
    /// value.
    pub workflow_trigger: Option<String>,
    /// `.1.3` — the commit the workflow run was based on. Superseded by
    /// [`FulcioCiClaims::source_repository_digest`], which holds the same value.
    pub workflow_sha: Option<String>,
    /// `.1.4` — the name of the workflow that ran, e.g. `Package and sign`.
    ///
    /// This one has no successor in the provider-neutral arc: it is the
    /// workflow's display name, whereas
    /// [`FulcioCiClaims::build_config_uri`] identifies the file the workflow was
    /// defined in.
    pub workflow_name: Option<String>,
    /// `.1.5` — the repository the workflow run was based on, as
    /// `owner/repository`.
    ///
    /// Superseded by [`FulcioCiClaims::source_repository_uri`], which is the
    /// fully qualified URL of the same repository rather than this short form.
    pub workflow_repository: Option<String>,
    /// `.1.6` — the ref the workflow run was based on, e.g. `refs/heads/main`.
    /// Superseded by [`FulcioCiClaims::source_repository_ref`], which holds the
    /// same value.
    pub workflow_ref: Option<String>,
}

impl DeprecatedGitHubClaims {
    /// Whether the certificate carried none of the deprecated claims, which is
    /// the case for any certificate not issued to a GitHub Actions workflow.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Parse certificate information from DER-encoded certificate
pub fn parse_certificate_info(cert_der: &DerCertificate) -> Result<CertificateInfo> {
    let cert = Certificate::from_der(cert_der.as_bytes())
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
pub(crate) fn extract_san_identity(cert: &Certificate) -> Result<Option<SubjectAltName>> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName as SanExtension;

    // Try to get the SAN extension using the typed getter
    // Returns Option<(critical: bool, extension: T)>
    let san_opt: Option<(bool, SanExtension)> = cert
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
                return Ok(Some(SubjectAltName::Email(email.to_string())));
            }
            GeneralName::UniformResourceIdentifier(uri) => {
                return Ok(Some(SubjectAltName::Uri(uri.to_string())));
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
pub(crate) fn extract_fulcio_issuer(cert: &Certificate) -> Result<Option<String>> {
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
pub(crate) fn extract_fulcio_ci_claims(cert: &Certificate) -> FulcioCiClaims {
    let mut claims = FulcioCiClaims::default();
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return claims;
    };

    for ext in extensions.iter() {
        let bytes = ext.extn_value.as_bytes();

        // `.1.1` and `.1.8` are the OIDC issuer, which `extract_fulcio_issuer`
        // reads. The deprecated `.1.2` to `.1.6` hold a bare string, everything
        // from `.1.9` onwards a DER UTF8String.
        let (claim, value) = match fulcio_claim_number(&ext.extn_id) {
            Some(2) => (
                &mut claims.deprecated_github.workflow_trigger,
                bare_string(bytes),
            ),
            Some(3) => (
                &mut claims.deprecated_github.workflow_sha,
                bare_string(bytes),
            ),
            Some(4) => (
                &mut claims.deprecated_github.workflow_name,
                bare_string(bytes),
            ),
            Some(5) => (
                &mut claims.deprecated_github.workflow_repository,
                bare_string(bytes),
            ),
            Some(6) => (
                &mut claims.deprecated_github.workflow_ref,
                bare_string(bytes),
            ),
            Some(9) => (&mut claims.build_signer_uri, der_string(bytes)),
            Some(10) => (&mut claims.build_signer_digest, der_string(bytes)),
            Some(11) => (&mut claims.runner_environment, der_string(bytes)),
            Some(12) => (&mut claims.source_repository_uri, der_string(bytes)),
            Some(13) => (&mut claims.source_repository_digest, der_string(bytes)),
            Some(14) => (&mut claims.source_repository_ref, der_string(bytes)),
            Some(15) => (&mut claims.source_repository_identifier, der_string(bytes)),
            Some(16) => (&mut claims.source_repository_owner_uri, der_string(bytes)),
            Some(17) => (
                &mut claims.source_repository_owner_identifier,
                der_string(bytes),
            ),
            Some(18) => (&mut claims.build_config_uri, der_string(bytes)),
            Some(19) => (&mut claims.build_config_digest, der_string(bytes)),
            Some(20) => (&mut claims.build_trigger, der_string(bytes)),
            Some(21) => (&mut claims.run_invocation_uri, der_string(bytes)),
            Some(22) => (
                &mut claims.source_repository_visibility_at_signing,
                der_string(bytes),
            ),
            Some(23) => (&mut claims.deployment_environment, der_string(bytes)),
            Some(24) => (&mut claims.token_subject, der_string(bytes)),
            _ => continue,
        };

        if value.is_some() {
            *claim = value;
        }
    }

    claims
}

/// A claim held as a DER `UTF8String` inside the extension's OCTET STRING, which
/// is how Fulcio encodes everything from `1.3.6.1.4.1.57264.1.8` onwards.
fn der_string(bytes: &[u8]) -> Option<String> {
    der::asn1::Utf8StringRef::from_der(bytes)
        .ok()
        .map(|value| value.as_str().to_owned())
}

/// A claim held as a bare string, which is how Fulcio encodes the deprecated
/// extensions `1.3.6.1.4.1.57264.1.2` to `.1.6`.
///
/// A DER `UTF8String` is accepted too, as it is for the legacy issuer in
/// [`extract_fulcio_issuer`]: none of these values can begin with the tag byte
/// that would make the bare form decode as one, so trying it first cannot
/// misread a claim.
fn bare_string(bytes: &[u8]) -> Option<String> {
    der_string(bytes).or_else(|| std::str::from_utf8(bytes).ok().map(str::to_owned))
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
        parse_certificate_info(&der).expect("the fixture is a valid certificate")
    }

    /// Every claim the GitHub Actions fixture carries, as a snapshot so that a
    /// claim added to [`FulcioCiClaims`] later shows up here instead of going
    /// untested until someone remembers to assert it. The individual claims a
    /// reader has to reason about are asserted by name in the tests below; the
    /// identity and the issuer are, because a policy matches on them.
    #[test]
    fn test_parse_github_actions_claims() {
        let info = parse(GITHUB_ACTIONS_CERT);

        assert_eq!(
            info.identity,
            Some(SubjectAltName::Uri(
                "https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main"
                    .to_string()
            ))
        );
        assert_eq!(
            info.issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );

        assert!(!info.ci_claims.is_empty());
        // The job declared no environment and the certificate predates `.1.24`,
        // so `deployment_environment` and `token_subject` are absent below.
        insta::assert_debug_snapshot!(info.ci_claims);
    }

    /// A job that runs in a deployment environment adds `.1.23`, and `.1.24`
    /// records the `sub` the certificate was requested with. This fixture is the
    /// one that covers the arc in full, `.1.2` to `.1.24`, so it is snapshotted
    /// as well.
    ///
    /// The assertion below is the point of the fixture: the SAN identity is the
    /// workflow ref and says nothing about the environment the job ran in, which
    /// for GitHub Actions makes the two claims in the snapshot the only place
    /// `upload` appears at all.
    #[test]
    fn test_parse_deployment_environment_claims() {
        let info = parse(ENVIRONMENT_CERT);

        assert_eq!(
            info.identity.as_ref().map(SubjectAltName::as_str),
            Some("https://github.com/pavelzw/skill-forge/.github/workflows/package.yml@refs/heads/main")
        );
        insta::assert_debug_snapshot!(info.ci_claims);
    }

    /// The deprecated `.1.2` to `.1.6`, which the fixture carries alongside the
    /// extensions that superseded them, are read from their own extensions and
    /// not confused with those: `.1.5` holds `owner/repository` where `.1.12`
    /// holds the full URL, and the deprecated extensions are bare strings where
    /// the arc from `.1.8` is DER. Reading both back verbatim shows neither the
    /// values nor the encodings are mixed up.
    #[test]
    fn test_parse_deprecated_github_claims() {
        let claims = parse(GITHUB_ACTIONS_CERT).ci_claims;

        assert!(!claims.deprecated_github.is_empty());
        assert_eq!(
            claims.deprecated_github.workflow_repository.as_deref(),
            Some("prefix-dev/sigstore-example")
        );
        assert_eq!(
            claims.source_repository_uri.as_deref(),
            Some("https://github.com/prefix-dev/sigstore-example")
        );
    }

    /// A certificate issued before Fulcio grew the provider-neutral arc carries
    /// only the deprecated extensions, and is the case they are read for: its
    /// claims are still reachable, under [`DeprecatedGitHubClaims`].
    ///
    /// Stands in for such a certificate by dropping everything from `.1.8`
    /// onwards from the fixture, since the fixtures here are all recent enough
    /// to carry both.
    #[test]
    fn test_parse_certificate_with_only_deprecated_claims() {
        let der = DerCertificate::from_pem(GITHUB_ACTIONS_CERT).expect("the fixture is a PEM");
        let mut cert = Certificate::from_der(der.as_bytes()).expect("the fixture is a certificate");
        let extensions = cert
            .tbs_certificate
            .extensions
            .take()
            .expect("the fixture has extensions");
        cert.tbs_certificate.extensions = Some(
            extensions
                .into_iter()
                .filter(|ext| fulcio_claim_number(&ext.extn_id).is_none_or(|number| number <= 6))
                .collect(),
        );

        let claims = extract_fulcio_ci_claims(&cert);
        assert!(!claims.is_empty());
        assert_eq!(
            claims.deprecated_github.workflow_trigger.as_deref(),
            Some("push")
        );
        assert_eq!(
            claims.deprecated_github.workflow_repository.as_deref(),
            Some("prefix-dev/sigstore-example")
        );
        // Nothing was read from the arc that is no longer there.
        assert_eq!(claims.build_signer_uri, None);
        assert_eq!(claims.source_repository_uri, None);
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
