//! Parsing of Fulcio's `/api/v2/configuration` response.

use sigstore_fulcio::{Configuration, IssuerUrl};

/// Trimmed copy of <https://fulcio.sigstore.dev/api/v2/configuration>.
const FIXTURE: &str = include_str!("fixtures/configuration.json");

#[test]
fn deserializes_exact_and_wildcard_issuers() {
    let config: Configuration = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(config.issuers.len(), 5);

    let github = &config.issuers[2];
    assert_eq!(
        github.issuer,
        IssuerUrl::Exact("https://token.actions.githubusercontent.com".into())
    );
    assert_eq!(github.audience, "sigstore");
    assert_eq!(github.challenge_claim.as_deref(), Some("sub"));
    assert_eq!(github.issuer_type.as_deref(), Some("ci-provider"));
    // Fulcio sends unset optional strings as "".
    assert_eq!(github.spiffe_trust_domain, None);
    assert_eq!(github.subject_domain, None);
    assert!(!github.skip_email_verification);

    let aks = &config.issuers[3];
    assert_eq!(
        aks.issuer,
        IssuerUrl::Wildcard("https://*.oic.prod-aks.azure.com/*/*".into())
    );
    assert_eq!(aks.issuer_type.as_deref(), Some("kubernetes"));
}

#[test]
fn tolerates_omitted_proto3_defaults() {
    let config: Configuration =
        serde_json::from_str(r#"{"issuers": [{"issuerUrl": "https://issuer.example"}]}"#).unwrap();
    let issuer = &config.issuers[0];
    assert_eq!(
        issuer.issuer,
        IssuerUrl::Exact("https://issuer.example".into())
    );
    assert_eq!(issuer.audience, "");
    assert_eq!(issuer.challenge_claim, None);
    assert!(!issuer.skip_email_verification);

    let empty: Configuration = serde_json::from_str("{}").unwrap();
    assert!(empty.issuers.is_empty());
}

#[test]
fn rejects_issuer_without_url() {
    let result =
        serde_json::from_str::<Configuration>(r#"{"issuers": [{"audience": "sigstore"}]}"#);
    assert!(result.is_err());
}

#[test]
fn serializes_the_issuer_oneof_as_its_json_field() {
    let config: Configuration = serde_json::from_str(FIXTURE).unwrap();
    let json = serde_json::to_value(&config.issuers[4]).unwrap();
    assert_eq!(json["wildcardIssuerUrl"], "https://oidc.circleci.com/org/*");
    assert!(json.get("issuerUrl").is_none());
}
