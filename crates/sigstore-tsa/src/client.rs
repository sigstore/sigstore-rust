//! TSA client for RFC 3161 Time-Stamp Protocol

use crate::asn1::{AlgorithmIdentifier, Asn1MessageImprint, TimeStampReq};
use crate::error::{Error, ResponseField, Result};
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
                .map_err(|e| Error::Transport(Box::new(e)))?,
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
        let request_der = request.to_der().map_err(|e| Error::Other(Box::new(e)))?;

        // Send HTTP request
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .body(request_der)
            .send()
            .await
            .map_err(|e| Error::Transport(Box::new(e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Status {
                status: status.as_u16(),
                message: status
                    .canonical_reason()
                    .unwrap_or("unknown status")
                    .to_string(),
            });
        }

        // Get response bytes
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Transport(Box::new(e)))?;

        validate_response(&request, &response_bytes)
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

fn validate_response(request: &TimeStampReq, response_bytes: &[u8]) -> Result<TimestampToken> {
    // Parse the response and extract TstInfo
    let (tst_info, _) = crate::verify::parse_timestamp_token(response_bytes)?;

    // Verify the message imprint matches the request (RFC 3161 §2.4.2).
    if tst_info.message_imprint.hash_algorithm.algorithm
        != request.message_imprint.hash_algorithm.algorithm
    {
        return Err(Error::ResponseMismatch {
            field: ResponseField::HashAlgorithm,
        });
    }
    if tst_info.message_imprint.hashed_message != request.message_imprint.hashed_message {
        return Err(Error::ResponseMismatch {
            field: ResponseField::MessageImprint,
        });
    }

    // Verify the nonce matches the request nonce
    if let Some(req_nonce) = &request.nonce {
        if tst_info.nonce.as_ref() != Some(req_nonce) {
            return Err(Error::ResponseMismatch {
                field: ResponseField::Nonce,
            });
        }
    }

    // Return the timestamp token
    Ok(TimestampToken::new(response_bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    const VALID_BUNDLE: &str = include_str!("../test_data/timestamps/valid_bundle.json");

    fn fixture_token_and_request() -> (Vec<u8>, TimeStampReq) {
        let bundle: serde_json::Value = serde_json::from_str(VALID_BUNDLE).unwrap();
        let signed_ts = bundle["verificationMaterial"]["timestampVerificationData"]
            ["rfc3161Timestamps"][0]["signedTimestamp"]
            .as_str()
            .unwrap();
        let token = STANDARD.decode(signed_ts).unwrap();
        let (tst_info, _) = crate::verify::parse_timestamp_token(&token).unwrap();

        let imprint = Asn1MessageImprint::new(
            AlgorithmIdentifier::sha256(),
            tst_info.message_imprint.hashed_message.as_bytes().to_vec(),
        );
        let mut req = TimeStampReq::new(imprint);
        req.nonce = tst_info.nonce;
        (token, req)
    }

    #[test]
    fn validate_response_accepts_matching_imprint_and_nonce() {
        let (token, req) = fixture_token_and_request();
        let validated = validate_response(&req, &token).unwrap();
        assert_eq!(validated.as_bytes(), token.as_slice());
    }

    #[test]
    fn validate_response_rejects_hash_algorithm_mismatch() {
        let (token, mut req) = fixture_token_and_request();
        req.message_imprint.hash_algorithm = AlgorithmIdentifier::sha384();

        let err = validate_response(&req, &token).unwrap_err();
        assert!(
            matches!(
                &err,
                Error::ResponseMismatch {
                    field: ResponseField::HashAlgorithm
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn validate_response_rejects_message_imprint_digest_mismatch() {
        let (token, mut req) = fixture_token_and_request();
        req.message_imprint = Asn1MessageImprint::new(AlgorithmIdentifier::sha256(), vec![0u8; 32]);

        let err = validate_response(&req, &token).unwrap_err();
        assert!(
            matches!(
                &err,
                Error::ResponseMismatch {
                    field: ResponseField::MessageImprint
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn validate_response_rejects_nonce_mismatch() {
        let (token, mut req) = fixture_token_and_request();
        req.nonce = Some(crate::asn1::generate_nonce());

        let err = validate_response(&req, &token).unwrap_err();
        assert!(
            matches!(
                &err,
                Error::ResponseMismatch {
                    field: ResponseField::Nonce
                }
            ),
            "unexpected error: {err:?}"
        );
    }
}
