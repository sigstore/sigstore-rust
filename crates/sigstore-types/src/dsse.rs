//! Dead Simple Signing Envelope (DSSE) types
//!
//! DSSE is a signature envelope format used for signing arbitrary payloads.
//! Specification: <https://github.com/secure-systems-lab/dsse>

use crate::encoding::{KeyId, PayloadBytes, SignatureBytes};
use serde::{Deserialize, Serialize};

/// A DSSE envelope containing a signed payload
///
/// The DSSE wire format carries a `signatures` list, but a DSSE envelope in a
/// Sigstore bundle must contain exactly one signature: the bundle's
/// verification material (certificate, timestamps, log entries) vouches for a
/// single signature, so every verification step must consume the same
/// signature bytes. This type enforces that invariant at deserialization,
/// making multi-signature envelopes unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DsseEnvelopeWire", into = "DsseEnvelopeWire")]
pub struct DsseEnvelope {
    /// Type URI of the payload
    pub payload_type: String,
    /// Payload bytes
    pub payload: PayloadBytes,
    /// The signature over the PAE (Pre-Authentication Encoding)
    pub signature: DsseSignature,
}

/// A signature in a DSSE envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    /// Signature bytes
    pub sig: SignatureBytes,
    /// Key ID (optional hint for key lookup)
    #[serde(default, skip_serializing_if = "KeyId::is_empty")]
    pub keyid: KeyId,
}

/// The DSSE wire format, where `signatures` is a list
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseEnvelopeWire {
    payload_type: String,
    payload: PayloadBytes,
    signatures: Vec<DsseSignature>,
}

impl TryFrom<DsseEnvelopeWire> for DsseEnvelope {
    type Error = String;

    fn try_from(wire: DsseEnvelopeWire) -> Result<Self, Self::Error> {
        match <[DsseSignature; 1]>::try_from(wire.signatures) {
            Ok([signature]) => Ok(Self {
                payload_type: wire.payload_type,
                payload: wire.payload,
                signature,
            }),
            Err(signatures) => Err(format!(
                "DSSE envelope must contain exactly one signature, found {}",
                signatures.len()
            )),
        }
    }
}

impl From<DsseEnvelope> for DsseEnvelopeWire {
    fn from(envelope: DsseEnvelope) -> Self {
        Self {
            payload_type: envelope.payload_type,
            payload: envelope.payload,
            signatures: vec![envelope.signature],
        }
    }
}

impl DsseEnvelope {
    /// Create a new DSSE envelope
    pub fn new(payload_type: String, payload: PayloadBytes, signature: DsseSignature) -> Self {
        Self {
            payload_type,
            payload,
            signature,
        }
    }

    /// Get the Pre-Authentication Encoding (PAE) string
    ///
    /// PAE is the string that gets signed in DSSE:
    /// `DSSEv1 <payload_type_len> <payload_type> <payload_len> <payload>`
    pub fn pae(&self) -> Vec<u8> {
        pae(&self.payload_type, self.payload.as_bytes())
    }

    /// Decode the payload bytes
    pub fn decode_payload(&self) -> Vec<u8> {
        self.payload.as_bytes().to_vec()
    }
}

/// Compute the Pre-Authentication Encoding (PAE)
///
/// Format: `DSSEv1 <len(type)> <type> <len(body)> <body>`
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // "DSSEv1" + space
    result.extend_from_slice(b"DSSEv1 ");

    // payload_type length + space
    result.extend_from_slice(format!("{} ", payload_type.len()).as_bytes());

    // payload_type + space
    result.extend_from_slice(payload_type.as_bytes());
    result.push(b' ');

    // payload length + space
    result.extend_from_slice(format!("{} ", payload.len()).as_bytes());

    // payload
    result.extend_from_slice(payload);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pae() {
        // Test vector from DSSE spec
        let pae_result = pae("application/example", b"hello world");
        let expected = b"DSSEv1 19 application/example 11 hello world";
        assert_eq!(pae_result, expected);
    }

    #[test]
    fn test_dsse_envelope_serde() {
        let envelope = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: PayloadBytes::from_bytes(b"{\"_type\":\"https://in-toto.io/Statement/v1\"}"),
            signature: DsseSignature {
                sig: SignatureBytes::from_bytes(b"\x30\x44\x02\x20"),
                keyid: KeyId::default(),
            },
        };

        let json = serde_json::to_string(&envelope).unwrap();
        // The wire format carries the signature as a one-element list
        assert!(
            json.contains(r#""signatures":[{"#),
            "unexpected wire format: {json}"
        );
        let parsed: DsseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, parsed);
    }

    /// Envelopes with any signature count other than one are rejected at
    /// parse time.
    #[test]
    fn test_dsse_envelope_rejects_non_single_signatures() {
        let no_signatures = r#"{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[]}"#;
        let err = serde_json::from_str::<DsseEnvelope>(no_signatures).unwrap_err();
        assert!(
            err.to_string().contains("exactly one signature, found 0"),
            "unexpected error: {err}"
        );

        let two_signatures = r#"{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[{"sig":"c2ln"},{"sig":"c2ln"}]}"#;
        let err = serde_json::from_str::<DsseEnvelope>(two_signatures).unwrap_err();
        assert!(
            err.to_string().contains("exactly one signature, found 2"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_dsse_envelope_keyid_handling() {
        // Test that empty keyid is omitted (matches GitHub/cosign behavior)
        let json_with_empty_keyid = r#"{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[{"sig":"c2ln","keyid":""}]}"#;

        let envelope: DsseEnvelope = serde_json::from_str(json_with_empty_keyid).unwrap();
        assert_eq!(envelope.signature.keyid, KeyId::default());

        let reserialized = serde_json::to_string(&envelope).unwrap();
        assert!(
            !reserialized.contains("keyid"),
            "Empty keyid should be omitted from output"
        );

        // Test that missing keyid deserializes to default
        let json_without_keyid = r#"{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[{"sig":"c2ln"}]}"#;
        let envelope_no_keyid: DsseEnvelope = serde_json::from_str(json_without_keyid).unwrap();
        assert_eq!(envelope_no_keyid.signature.keyid, KeyId::default());

        // Test with non-empty keyid - should be preserved
        let json_with_keyid = r#"{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[{"sig":"c2ln","keyid":"test-key"}]}"#;
        let envelope_with_keyid: DsseEnvelope = serde_json::from_str(json_with_keyid).unwrap();
        let json_out = serde_json::to_string(&envelope_with_keyid).unwrap();
        assert!(
            json_out.contains(r#""keyid":"test-key""#),
            "Non-empty keyid should be included in output"
        );
    }
}
