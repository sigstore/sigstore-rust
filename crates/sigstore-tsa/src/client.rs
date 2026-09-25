//! TSA client for RFC 3161 Time-Stamp Protocol

use crate::asn1::{AlgorithmIdentifier, Asn1MessageImprint, TimeStampReq};
use crate::error::{Error, Result};
use sigstore_types::{ArtifactDigest, SignatureBytes, TimestampToken, USER_AGENT};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A client for interacting with a Time-Stamp Authority
#[derive(Debug, Clone)]
pub struct TimestampClient {
    /// Timestamp endpoint URL
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

/// Builder for [`TimestampClient`]
#[derive(Debug, Clone)]
#[must_use]
pub struct TimestampClientBuilder {
    url: String,
    http_client: Option<reqwest::Client>,
}

impl TimestampClientBuilder {
    /// Use a caller-configured HTTP client (timeouts, proxies, TLS roots,
    /// user agent).
    ///
    /// Without one, a client with a 30-second request timeout and a
    /// `sigstore-rust/<version>` user agent is used.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<TimestampClient> {
        let client = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .timeout(DEFAULT_TIMEOUT)
                .user_agent(USER_AGENT)
                .build()
                .map_err(|e| Error::Http(format!("failed to build HTTP client: {e}")))?,
        };
        Ok(TimestampClient {
            url: self.url,
            client,
        })
    }
}

impl TimestampClient {
    /// Create a TSA client with default settings.
    ///
    /// `url` is the full timestamp endpoint, for example the TSA URL from a
    /// Sigstore instance's signing config.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Self::builder(url).build()
    }

    /// Configure a TSA client for the timestamp endpoint at `url`.
    pub fn builder(url: impl Into<String>) -> TimestampClientBuilder {
        TimestampClientBuilder {
            url: url.into(),
            http_client: None,
        }
    }

    /// Request a timestamp for the given digest
    ///
    /// # Arguments
    /// * `digest` - The hash digest to timestamp
    /// * `algorithm` - The hash algorithm used
    ///
    /// # Returns
    /// The timestamp token (DER-encoded RFC 3161 response)
    async fn timestamp(
        &self,
        digest: &[u8],
        algorithm: AlgorithmIdentifier,
    ) -> Result<TimestampToken> {
        // Build the timestamp request
        let imprint = Asn1MessageImprint::new(algorithm, digest.to_vec());
        let request = TimeStampReq::new(imprint);

        // Encode to DER
        let request_der = request
            .to_der()
            .map_err(|e| Error::Asn1(format!("failed to encode request: {}", e)))?;

        // Send HTTP request
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .body(request_der)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Http(format!(
                "TSA returned status {}",
                response.status()
            )));
        }

        // Get response bytes
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        // Parse the response and extract TstInfo
        let (tst_info, _) = crate::verify::parse_timestamp_token(&response_bytes)?;

        // Verify the nonce matches the request nonce
        if let Some(req_nonce) = &request.nonce {
            if tst_info.nonce.as_ref() != Some(req_nonce) {
                return Err(Error::InvalidResponse(format!(
                    "TSA response nonce mismatch: expected {:?}, got {:?}",
                    req_nonce, tst_info.nonce
                )));
            }
        }

        // Return the timestamp token
        Ok(TimestampToken::new(response_bytes.to_vec()))
    }

    /// Request a timestamp over a precomputed digest.
    pub async fn timestamp_digest(&self, digest: &ArtifactDigest) -> Result<TimestampToken> {
        let algorithm = AlgorithmIdentifier::try_from(digest.algorithm())?;
        self.timestamp(digest.as_bytes(), algorithm).await
    }

    /// Request a timestamp for a signature
    ///
    /// This is the most common use case - timestamps the SHA-256 hash of the signature bytes.
    pub async fn timestamp_signature(&self, signature: &SignatureBytes) -> Result<TimestampToken> {
        let digest = sigstore_crypto::sha256(signature.as_bytes());
        self.timestamp(digest.as_bytes(), AlgorithmIdentifier::sha256())
            .await
    }
}
