//! Checkpoint (signed tree head) types
//!
//! A checkpoint represents a signed commitment to the state of a transparency log.
//! Format specified in: <https://github.com/transparency-dev/formats/blob/main/log/README.md>
//!
//! # Format
//!
//! A checkpoint (also known as a "signed note") consists of a text header and signature lines,
//! separated by a blank line:
//!
//! ```text
//! <origin>
//! <tree_size>
//! <root_hash_base64>
//! <optional_metadata>
//!
//! — <signer_name> <signature_base64>
//! ```
//!
//! The signature lines begin with the Unicode em dash (U+2014, "—"), not an ASCII hyphen.
//! Each base64-decoded signature consists of a 4-byte key ID followed by the signature bytes.

use crate::encoding::{KeyHint, Sha256Hash, SignatureBytes};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// A checkpoint (signed tree head) from a transparency log.
///
/// Also known as a "signed note" in the Go ecosystem. Contains the log state
/// (origin, tree size, root hash) plus one or more cryptographic signatures.
///
/// A `Checkpoint` can only be constructed by parsing its text representation
/// with [`Checkpoint::from_text`]. Its fields are private so that the parsed
/// semantic fields always agree with the exact signed bytes returned by
/// [`Checkpoint::signed_data`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The origin string identifying the log (e.g., "rekor.sigstore.dev - 2605736670972794746")
    origin: String,
    /// Tree size (number of leaves/entries in the log)
    tree_size: u64,
    /// Root hash of the Merkle tree (32 bytes SHA-256)
    root_hash: Sha256Hash,
    /// Other data lines (optional extension data, e.g., "Timestamp: 1689177396617352539")
    other_content: Vec<String>,
    /// Signatures over the checkpoint
    signatures: Vec<CheckpointSignature>,
    /// Raw text of the checkpoint body (used for signature verification).
    /// This is the text before the blank line separator, with trailing newline.
    signed_note_text: String,
}

/// A signature on a checkpoint.
///
/// Each signature consists of:
/// - A name identifying the signer (e.g., "rekor.sigstore.dev")
/// - A 4-byte key ID (key hint) used to match the signature to a public key
/// - The signature bytes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CheckpointSignature {
    /// The name of the signer (appears after the em dash in the signature line)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Key identifier (first 4 bytes of SHA-256 of the public key)
    pub key_id: KeyHint,
    /// Signature bytes
    pub signature: SignatureBytes,
}

impl Checkpoint {
    /// Parse a checkpoint from its text representation
    ///
    /// Format:
    /// ```text
    /// <origin>
    /// <tree_size>
    /// <root_hash_base64>
    /// [other_content...]
    ///
    /// — <key_id_base64> <sig_base64>
    /// [additional signatures...]
    /// ```
    pub fn from_text(text: &str) -> Result<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        if text.is_empty() {
            return Err(Error::InvalidCheckpoint("empty checkpoint".to_string()));
        }

        // Split into checkpoint body and signatures at the blank line
        let parts: Vec<&str> = text.split("\n\n").collect();
        if parts.len() < 2 {
            return Err(Error::InvalidCheckpoint(
                "missing blank line separator".to_string(),
            ));
        }

        let checkpoint_body = parts[0];
        let signatures_text = parts[1];

        // Store the signed note text (checkpoint body with trailing newline)
        let signed_note_text = format!("{}\n", checkpoint_body);

        let mut lines = checkpoint_body.lines();

        // Parse origin
        let origin = lines
            .next()
            .ok_or_else(|| Error::InvalidCheckpoint("missing origin".to_string()))?
            .trim()
            .to_string();

        if origin.is_empty() {
            return Err(Error::InvalidCheckpoint("empty origin".to_string()));
        }

        // Parse tree size
        let tree_size_str = lines
            .next()
            .ok_or_else(|| Error::InvalidCheckpoint("missing tree size".to_string()))?
            .trim();
        let tree_size = tree_size_str
            .parse()
            .map_err(|_| Error::InvalidCheckpoint("invalid tree size".to_string()))?;

        // Parse root hash
        let root_hash_b64 = lines
            .next()
            .ok_or_else(|| Error::InvalidCheckpoint("missing root hash".to_string()))?
            .trim();
        let root_hash_bytes = STANDARD
            .decode(root_hash_b64)
            .map_err(|_| Error::InvalidCheckpoint("invalid root hash base64".to_string()))?;
        let root_hash = Sha256Hash::try_from_slice(&root_hash_bytes)
            .map_err(|e| Error::InvalidCheckpoint(format!("invalid root hash: {}", e)))?;

        // Remaining lines are other content (metadata)
        let other_content: Vec<String> = lines
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        // Parse signatures
        let mut signatures = Vec::new();
        for line in signatures_text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Signature line format: — <name> <base64_signature>
            // The em dash (U+2014) is required at the start
            if !line.starts_with('—') {
                return Err(Error::InvalidCheckpoint(
                    "signature line must start with em dash (U+2014)".to_string(),
                ));
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                return Err(Error::InvalidCheckpoint(
                    "signature line must have format: — <name> <base64_signature>".to_string(),
                ));
            }

            let name = parts[1].to_string();
            let key_and_sig_b64 = parts[2];

            let decoded = STANDARD
                .decode(key_and_sig_b64)
                .map_err(|_| Error::InvalidCheckpoint("invalid signature base64".to_string()))?;

            if decoded.len() < 5 {
                return Err(Error::InvalidCheckpoint(
                    "signature too short (must be at least 5 bytes for key_id + signature)"
                        .to_string(),
                ));
            }

            let key_id = KeyHint::try_from_slice(&decoded[..4])?;
            let signature = SignatureBytes::new(decoded[4..].to_vec());

            signatures.push(CheckpointSignature {
                name,
                key_id,
                signature,
            });
        }

        if signatures.is_empty() {
            return Err(Error::InvalidCheckpoint("no signatures found".to_string()));
        }

        Ok(Checkpoint {
            origin,
            tree_size,
            root_hash,
            other_content,
            signatures,
            signed_note_text,
        })
    }

    /// The origin string identifying the log.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Tree size (number of leaves/entries in the log).
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Root hash of the Merkle tree.
    pub fn root_hash(&self) -> &Sha256Hash {
        &self.root_hash
    }

    /// Other (extension) data lines in the checkpoint body.
    pub fn other_content(&self) -> &[String] {
        &self.other_content
    }

    /// Signatures over the checkpoint body.
    pub fn signatures(&self) -> &[CheckpointSignature] {
        &self.signatures
    }

    /// Iterate over all signatures matching the given key hint (key ID).
    ///
    /// Key hints are only 4 bytes and may collide, so verifiers must try every
    /// matching signature rather than just the first one.
    pub fn signatures_by_key_hint<'a>(
        &'a self,
        key_hint: &'a KeyHint,
    ) -> impl Iterator<Item = &'a CheckpointSignature> + 'a {
        self.signatures
            .iter()
            .filter(move |sig| &sig.key_id == key_hint)
    }

    /// Encode the checkpoint to its text representation (without signatures).
    ///
    /// This returns the signed note body that can be used for signature verification.
    pub fn to_signed_note_body(&self) -> String {
        let mut result = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.tree_size,
            self.root_hash.to_base64()
        );

        for line in &self.other_content {
            result.push_str(line);
            result.push('\n');
        }

        result
    }

    /// Find a signature matching the given key hint (key ID).
    ///
    /// The key hint is the first 4 bytes of SHA-256(public_key_der).
    /// Returns the first signature if found, or None if no matching signature exists.
    ///
    /// Key hints may collide; signature verification should use
    /// [`Checkpoint::signatures_by_key_hint`] and try every match.
    pub fn find_signature_by_key_hint(&self, key_hint: &KeyHint) -> Option<&CheckpointSignature> {
        self.signatures.iter().find(|sig| &sig.key_id == key_hint)
    }

    /// Get the raw signed note text for signature verification.
    ///
    /// This is the checkpoint body (before the blank line) with trailing newline,
    /// which is what gets signed.
    pub fn signed_data(&self) -> &[u8] {
        self.signed_note_text.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checkpoint() {
        let checkpoint_text = "rekor.sigstore.dev - 1193050959916656506
42591958
npv1T/m9N8zX0jPlbh4rB51zL6GpnV9bQaXSOdzAV+s=

— rekor.sigstore.dev wNI9ajBFAiEA0OP4Pv5ks5MoTTwcM0kS6HMn8gZ5fFPjT9s6vVqXgHkCIDCe5qWSdM4OXpCQ1YNP2KpLo1r/2dRfFHXkPR5h3ywe
";

        let checkpoint = Checkpoint::from_text(checkpoint_text).unwrap();
        assert_eq!(
            checkpoint.origin,
            "rekor.sigstore.dev - 1193050959916656506"
        );
        assert_eq!(checkpoint.tree_size, 42591958);
        assert_eq!(checkpoint.root_hash.as_bytes().len(), 32);
        assert_eq!(checkpoint.signatures.len(), 1);
        assert_eq!(checkpoint.signatures[0].name, "rekor.sigstore.dev");
        assert_eq!(checkpoint.signatures[0].key_id.as_bytes().len(), 4);

        // Check that signed_note_text is preserved for verification
        assert!(!checkpoint.signed_note_text.is_empty());
        assert!(checkpoint
            .signed_note_text
            .starts_with("rekor.sigstore.dev"));
    }

    #[test]
    fn test_parse_checkpoint_with_metadata() {
        let checkpoint_text = "rekor.sigstore.dev - 2605736670972794746
23083062
dauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=
Timestamp: 1689177396617352539

— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs
";

        let checkpoint = Checkpoint::from_text(checkpoint_text).unwrap();
        assert_eq!(checkpoint.tree_size, 23083062);
        assert_eq!(checkpoint.other_content.len(), 1);
        assert_eq!(
            checkpoint.other_content[0],
            "Timestamp: 1689177396617352539"
        );
    }

    #[test]
    fn test_find_signature_by_key_hint() {
        let checkpoint_text = "rekor.sigstore.dev - 1193050959916656506
42591958
npv1T/m9N8zX0jPlbh4rB51zL6GpnV9bQaXSOdzAV+s=

— rekor.sigstore.dev wNI9ajBFAiEA0OP4Pv5ks5MoTTwcM0kS6HMn8gZ5fFPjT9s6vVqXgHkCIDCe5qWSdM4OXpCQ1YNP2KpLo1r/2dRfFHXkPR5h3ywe
";

        let checkpoint = Checkpoint::from_text(checkpoint_text).unwrap();
        let key_hint = &checkpoint.signatures[0].key_id;

        let found = checkpoint.find_signature_by_key_hint(key_hint);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "rekor.sigstore.dev");

        // Non-existent key hint
        let not_found = checkpoint.find_signature_by_key_hint(&KeyHint::new([0, 0, 0, 0]));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_accessors_and_signed_data_match_parsed_text() {
        // Trailing whitespace on body lines is trimmed for the semantic fields
        // but must be preserved in the exact signed bytes.
        let body = "rekor.sigstore.dev - 1193050959916656506 \n42591958\nnpv1T/m9N8zX0jPlbh4rB51zL6GpnV9bQaXSOdzAV+s=\nTimestamp: 1\n";
        let text = format!(
            "{body}\n— rekor.sigstore.dev wNI9ajBFAiEA0OP4Pv5ks5MoTTwcM0kS6HMn8gZ5fFPjT9s6vVqXgHkCIDCe5qWSdM4OXpCQ1YNP2KpLo1r/2dRfFHXkPR5h3ywe\n"
        );
        let checkpoint = Checkpoint::from_text(&text).unwrap();
        assert_eq!(
            checkpoint.origin(),
            "rekor.sigstore.dev - 1193050959916656506"
        );
        assert_eq!(checkpoint.tree_size(), 42591958);
        assert_eq!(
            checkpoint.root_hash().to_base64(),
            "npv1T/m9N8zX0jPlbh4rB51zL6GpnV9bQaXSOdzAV+s="
        );
        assert_eq!(checkpoint.other_content(), ["Timestamp: 1".to_string()]);
        assert_eq!(checkpoint.signatures().len(), 1);
        assert_eq!(checkpoint.signed_data(), body.as_bytes());
    }

    #[test]
    fn test_signatures_by_key_hint_returns_all_collisions() {
        // Two signatures sharing the same 4-byte key hint (AAAAAA==) plus one other.
        let text = "example.com/log
1
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— a AAAAAAE=
— b AAAAAAI=
— c AQIDBAM=
";
        let checkpoint = Checkpoint::from_text(text).unwrap();
        let hint = KeyHint::new([0, 0, 0, 0]);
        let names: Vec<_> = checkpoint
            .signatures_by_key_hint(&hint)
            .map(|sig| sig.name.as_str())
            .collect();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(
            checkpoint
                .signatures_by_key_hint(&KeyHint::new([9, 9, 9, 9]))
                .count(),
            0
        );
    }
}
