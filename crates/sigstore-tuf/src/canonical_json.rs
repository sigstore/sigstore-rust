//! TUF-compatible canonical JSON.
//!
//! TUF signatures are computed over a *canonical* serialization of the `signed`
//! object. The canonical form TUF uses is the one implemented by
//! [`securesystemslib`] (historically OLPC canonical JSON), **not** RFC 8785
//! JSON Canonicalization Scheme (JCS). The two differ in ways that matter for
//! signature verification:
//!
//! * Only `\` and `"` are escaped in strings. Every other character — including
//!   control characters such as newline (`0x0A`) — is emitted verbatim as its
//!   UTF-8 bytes. JCS, by contrast, would escape a newline as `\n`. This matters
//!   because TUF root keys embed PEM blobs whose values contain real newlines.
//! * Numbers must be integers; floats are rejected outright (TUF metadata never
//!   contains floats). JCS has elaborate float-formatting rules we must not use.
//! * Object keys are sorted by Unicode code point (equivalently, by UTF-8 bytes
//!   for the ASCII keys TUF uses) and emitted with no insignificant whitespace.
//!
//! Using JCS here would produce different bytes and every signature check would
//! fail against real-world repositories, so this module implements the
//! securesystemslib rules directly.
//!
//! [`securesystemslib`]: https://github.com/secure-systems-lab/securesystemslib

use serde_json::Value;

use crate::error::{Error, Result};

/// Serialize a [`serde_json::Value`] into TUF canonical JSON bytes.
///
/// Returns [`Error::NonIntegerNumber`] if the value contains a non-integer
/// number anywhere in the tree.
pub fn to_canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode(value, &mut out)?;
    Ok(out)
}

fn encode(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            // Only integers are permitted. `serde_json` parses integers as
            // i64/u64 and only falls back to f64 for values with a fraction or
            // exponent, so a value that is neither i64 nor u64 is a float.
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(itoa(i).as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(Error::NonIntegerNumber);
            }
        }
        Value::String(s) => encode_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sort keys by code point. For `&str`, Rust's `Ord` compares UTF-8
            // bytes, which agrees with code-point order for valid UTF-8.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_string(key, out);
                out.push(b':');
                encode(&map[key.as_str()], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Encode a string with securesystemslib's minimal escaping: only backslash and
/// double-quote are escaped; everything else is passed through as raw UTF-8.
fn encode_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for &byte in s.as_bytes() {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            other => out.push(other),
        }
    }
    out.push(b'"');
}

/// Small helper so we can format an `i64` without an extra dependency.
fn itoa(value: i64) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let value = json!({ "b": 1, "a": 2 });
        assert_eq!(to_canonical_bytes(&value).unwrap(), b"{\"a\":2,\"b\":1}");
    }

    #[test]
    fn newlines_are_emitted_raw_not_escaped() {
        // This is the crucial difference from RFC 8785 JCS: a real newline in a
        // string value (as found in embedded PEM keys) stays a raw 0x0A byte.
        let value = json!({ "public": "line1\nline2" });
        let bytes = to_canonical_bytes(&value).unwrap();
        assert_eq!(bytes, b"{\"public\":\"line1\nline2\"}");
        assert!(bytes.contains(&b'\n'));
        // It must NOT contain the two-character escape sequence "\n".
        assert!(!bytes.windows(2).any(|w| w == b"\\n"));
    }

    #[test]
    fn only_backslash_and_quote_are_escaped() {
        let value = json!("a\\b\"c");
        assert_eq!(to_canonical_bytes(&value).unwrap(), b"\"a\\\\b\\\"c\"");
    }

    #[test]
    fn rejects_floats() {
        let value = json!({ "x": 1.5 });
        assert!(matches!(
            to_canonical_bytes(&value),
            Err(Error::NonIntegerNumber)
        ));
    }

    #[test]
    fn handles_nested_structures() {
        let value = json!({ "z": [3, 2, 1], "a": { "n": -5, "b": true } });
        assert_eq!(
            to_canonical_bytes(&value).unwrap(),
            b"{\"a\":{\"b\":true,\"n\":-5},\"z\":[3,2,1]}"
        );
    }
}
