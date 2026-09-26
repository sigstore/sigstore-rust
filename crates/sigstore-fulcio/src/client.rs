//! Fulcio client for certificate operations

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sigstore_crypto::KeyPair;
use sigstore_oidc::IdentityToken;
use sigstore_types::{DerCertificate, SignatureBytes, USER_AGENT};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A client for interacting with Fulcio
#[derive(Clone)]
pub struct FulcioClient {
    /// Base URL of the Fulcio instance
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl std::fmt::Debug for FulcioClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FulcioClient")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl FulcioClient {
    /// Create a Fulcio client with default settings.
    ///
    /// `url` is the Fulcio base URL, for example the CA URL from a Sigstore
    /// instance's signing config.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Self::builder(url).build()
    }

    /// The Fulcio base URL this client talks to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Create a builder for configuring the client
    pub fn builder(url: impl Into<String>) -> FulcioClientBuilder {
        FulcioClientBuilder::new(url)
    }

    /// Get the OIDC configuration (supported issuers)
    pub async fn get_configuration(&self) -> Result<Configuration> {
        let url = format!("{}/api/v2/configuration", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Status {
                status: response.status().as_u16(),
                message: "failed to get configuration".to_string(),
            });
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        serde_json::from_slice(&body)
            .map_err(|e| Error::InvalidResponse(format!("configuration: {e}")))
    }

    /// Request a signing certificate
    ///
    /// This method handles the complete certificate request flow:
    /// 1. Extracts the public key from the key pair
    /// 2. Creates a proof of possession by signing the identity
    /// 3. Sends the request to Fulcio
    ///
    /// # Arguments
    /// * `identity_token` - The OIDC identity token
    /// * `key_pair` - The key pair (public key will be extracted, private key used for proof)
    pub async fn create_signing_certificate(
        &self,
        identity_token: &IdentityToken,
        key_pair: &KeyPair,
    ) -> Result<SigningCertificate> {
        let url = format!("{}/api/v2/signingCert", self.url);

        // Extract public key and convert to PEM for the API
        let public_key_pem = key_pair
            .public_key_der()
            .map_err(|e| Error::Signing(format!("failed to export public key: {}", e)))?
            .to_pem();

        // Create proof of possession by signing the identity (email or subject)
        let proof_of_possession = key_pair
            .sign(identity_token.identity().as_bytes())
            .map_err(|e| Error::Signing(format!("failed to create proof of possession: {}", e)))?;

        let request = CreateSigningCertificateRequest {
            credentials: Credentials {
                oidc_identity_token: identity_token.expose_secret().to_string(),
            },
            public_key_request: PublicKeyRequest {
                public_key: PublicKeyData {
                    algorithm: String::new(), // Not needed for PEM (contains algorithm info)
                    content: public_key_pem,
                },
                proof_of_possession,
            },
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Status {
                status,
                message: format!("failed to create signing certificate: {body}"),
            });
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let wire: SigningCertificateWire = serde_json::from_slice(&body)
            .map_err(|e| Error::InvalidResponse(format!("signing certificate: {e}")))?;
        SigningCertificate::try_from(wire)
    }

    /// Get the trust bundle (CA certificates)
    ///
    /// This is Fulcio's unauthenticated view of its CAs; verification uses the
    /// CAs from a TUF-verified trusted root instead.
    pub async fn get_trust_bundle(&self) -> Result<TrustBundle> {
        let url = format!("{}/api/v2/trustBundle", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Status {
                status: response.status().as_u16(),
                message: "failed to get trust bundle".to_string(),
            });
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        TrustBundle::from_json(&body)
    }
}

/// Builder for configuring a [`FulcioClient`]
///
/// # Example
///
/// ```no_run
/// use sigstore_fulcio::{reqwest, FulcioClient};
/// use std::time::Duration;
///
/// // Proxies, timeouts, TLS roots and the user agent are configured on the
/// // HTTP client itself.
/// let http = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .build()?;
/// let client = FulcioClient::builder("https://fulcio.sigstore.dev")
///     .with_http_client(http)
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub struct FulcioClientBuilder {
    url: String,
    http_client: Option<reqwest::Client>,
}

impl FulcioClientBuilder {
    /// Create a new builder with the given URL
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_string(),
            http_client: None,
        }
    }

    /// Use a caller-configured HTTP client (timeouts, proxies, TLS roots,
    /// user agent).
    ///
    /// Without one, a client with a 30-second request timeout and a
    /// `sigstore-rust/<version>` user agent is used.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Build the client
    pub fn build(self) -> Result<FulcioClient> {
        let client = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .timeout(DEFAULT_TIMEOUT)
                .user_agent(USER_AGENT)
                .build()
                .map_err(|e| Error::Http(format!("failed to build HTTP client: {e}")))?,
        };
        Ok(FulcioClient {
            url: self.url,
            client,
        })
    }
}

/// OIDC configuration response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Configuration {
    /// List of supported OIDC issuers
    #[serde(default)]
    pub issuers: Vec<OidcIssuer>,
}

/// How an OIDC issuer is identified (the `issuer` oneof in Fulcio's API)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IssuerUrl {
    /// An exact issuer URL
    #[serde(rename = "issuerUrl")]
    Exact(String),
    /// An issuer URL pattern, e.g. `https://oidc.eks.*.amazonaws.com/id/*`.
    ///
    /// Fulcio replaces each `*` with `[-_a-zA-Z0-9]+` when matching.
    #[serde(rename = "wildcardIssuerUrl")]
    Wildcard(String),
}

/// OIDC issuer configuration
///
/// Optional string fields that Fulcio sends as empty strings are exposed as `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct OidcIssuer {
    /// Issuer URL, either exact or a wildcard pattern
    #[serde(flatten)]
    pub issuer: IssuerUrl,
    /// Audience
    #[serde(default)]
    pub audience: String,
    /// Challenge claim
    #[serde(default, deserialize_with = "empty_as_none")]
    pub challenge_claim: Option<String>,
    /// SPIFFE trust domain
    #[serde(default, deserialize_with = "empty_as_none")]
    pub spiffe_trust_domain: Option<String>,
    /// Identity provider type (e.g. `email`, `ci-provider`, `kubernetes`)
    #[serde(default, deserialize_with = "empty_as_none")]
    pub issuer_type: Option<String>,
    /// Expected subject domain for URI or username identities
    #[serde(default, deserialize_with = "empty_as_none")]
    pub subject_domain: Option<String>,
    /// Whether Fulcio skips email verification for this issuer
    #[serde(default)]
    pub skip_email_verification: bool,
}

fn empty_as_none<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.filter(|value| !value.is_empty()))
}

/// Request to create a signing certificate
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSigningCertificateRequest {
    credentials: Credentials,
    public_key_request: PublicKeyRequest,
}

/// OIDC credentials. Deliberately not `Debug`: it holds the raw token.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Credentials {
    oidc_identity_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyRequest {
    public_key: PublicKeyData,
    proof_of_possession: SignatureBytes,
}

#[derive(Serialize)]
struct PublicKeyData {
    /// Empty: the PEM content identifies the algorithm.
    algorithm: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningCertificateWire {
    #[serde(default)]
    signed_certificate_embedded_sct: Option<ChainWire>,
    #[serde(default)]
    signed_certificate_detached_sct: Option<DetachedSctWire>,
}

#[derive(Deserialize)]
struct ChainWire {
    chain: ChainContentWire,
}

#[derive(Deserialize)]
struct ChainContentWire {
    certificates: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DetachedSctWire {
    chain: ChainContentWire,
    signed_certificate_timestamp: String,
}

#[derive(Deserialize)]
struct TrustBundleWire {
    #[serde(default)]
    chains: Vec<ChainWire>,
}

/// Parse a PEM chain; a chain must contain at least one certificate.
fn parse_chain(chain: ChainContentWire) -> Result<Vec<DerCertificate>> {
    if chain.certificates.is_empty() {
        return Err(Error::InvalidResponse(
            "certificate chain is empty".to_string(),
        ));
    }
    chain
        .certificates
        .iter()
        .map(|pem| {
            DerCertificate::from_pem(pem)
                .map_err(|e| Error::InvalidResponse(format!("invalid certificate PEM: {e}")))
        })
        .collect()
}

/// A certificate issued by Fulcio, leaf first.
///
/// Fulcio either embeds the Signed Certificate Timestamp in the leaf
/// certificate or returns it alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningCertificate {
    /// The SCT is embedded in the leaf certificate.
    EmbeddedSct {
        /// The certificate chain, leaf first; never empty.
        chain: Vec<DerCertificate>,
    },
    /// The SCT is returned separately.
    DetachedSct {
        /// The certificate chain, leaf first; never empty.
        chain: Vec<DerCertificate>,
        /// The base64-encoded Signed Certificate Timestamp.
        signed_certificate_timestamp: String,
    },
}

impl TryFrom<SigningCertificateWire> for SigningCertificate {
    type Error = Error;

    fn try_from(wire: SigningCertificateWire) -> Result<Self> {
        match (
            wire.signed_certificate_embedded_sct,
            wire.signed_certificate_detached_sct,
        ) {
            (Some(embedded), None) => Ok(Self::EmbeddedSct {
                chain: parse_chain(embedded.chain)?,
            }),
            (None, Some(detached)) => Ok(Self::DetachedSct {
                chain: parse_chain(detached.chain)?,
                signed_certificate_timestamp: detached.signed_certificate_timestamp,
            }),
            (None, None) => Err(Error::InvalidResponse(
                "response contains no certificate".to_string(),
            )),
            (Some(_), Some(_)) => Err(Error::InvalidResponse(
                "response contains both an embedded and a detached SCT".to_string(),
            )),
        }
    }
}

impl SigningCertificate {
    /// The certificate chain, leaf first.
    pub fn certificate_chain(&self) -> &[DerCertificate] {
        match self {
            Self::EmbeddedSct { chain } | Self::DetachedSct { chain, .. } => chain,
        }
    }

    /// The leaf (signing) certificate.
    pub fn leaf_certificate(&self) -> &DerCertificate {
        // Chains are non-empty by construction.
        &self.certificate_chain()[0]
    }
}

/// Fulcio's CA certificate chains.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustBundle {
    /// Certificate chains, each leaf (intermediate) first.
    pub chains: Vec<Vec<DerCertificate>>,
}

impl TrustBundle {
    /// Parse Fulcio's `/api/v2/trustBundle` response.
    pub fn from_json(json: &[u8]) -> Result<Self> {
        let wire: TrustBundleWire = serde_json::from_slice(json)
            .map_err(|e| Error::InvalidResponse(format!("trust bundle: {e}")))?;
        let chains = wire
            .chains
            .into_iter()
            .map(|chain| parse_chain(chain.chain))
            .collect::<Result<_>>()?;
        Ok(Self { chains })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = include_str!("../tests/fixtures/root.pem");

    fn parse(json: serde_json::Value) -> Result<SigningCertificate> {
        let wire: SigningCertificateWire = serde_json::from_value(json).unwrap();
        SigningCertificate::try_from(wire)
    }

    #[test]
    fn signing_certificate_models_the_sct_oneof() {
        let chain = serde_json::json!({ "chain": { "certificates": [PEM] } });
        let embedded = parse(serde_json::json!({ "signedCertificateEmbeddedSct": chain })).unwrap();
        assert!(matches!(embedded, SigningCertificate::EmbeddedSct { .. }));
        assert_eq!(embedded.certificate_chain().len(), 1);
        assert_eq!(
            embedded.leaf_certificate(),
            &embedded.certificate_chain()[0]
        );

        let detached = parse(serde_json::json!({
            "signedCertificateDetachedSct": {
                "chain": { "certificates": [PEM] },
                "signedCertificateTimestamp": "c2N0",
            }
        }))
        .unwrap();
        assert!(matches!(
            detached,
            SigningCertificate::DetachedSct { ref signed_certificate_timestamp, .. }
                if signed_certificate_timestamp == "c2N0"
        ));

        for invalid in [
            serde_json::json!({}),
            serde_json::json!({ "signedCertificateEmbeddedSct": { "chain": { "certificates": [] } } }),
            serde_json::json!({
                "signedCertificateEmbeddedSct": chain,
                "signedCertificateDetachedSct": {
                    "chain": { "certificates": [PEM] },
                    "signedCertificateTimestamp": "c2N0",
                },
            }),
        ] {
            assert!(matches!(parse(invalid), Err(Error::InvalidResponse(_))));
        }
    }
}
