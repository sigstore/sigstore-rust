//! Parsing of Fulcio's certificate and trust bundle responses.

use sigstore_fulcio::{Error, TrustBundle};

const PEM: &str = include_str!("fixtures/root.pem");

fn chain_json(certificates: &[&str]) -> String {
    serde_json::json!({ "chains": [{ "chain": { "certificates": certificates } }] }).to_string()
}

#[test]
fn trust_bundle_parses_pem_chains() {
    let bundle = TrustBundle::from_json(chain_json(&[PEM, PEM]).as_bytes()).unwrap();
    assert_eq!(bundle.chains.len(), 1);
    assert_eq!(bundle.chains[0].len(), 2);
    assert_eq!(bundle.chains[0][0], bundle.chains[0][1]);
}

#[test]
fn trust_bundle_rejects_empty_and_malformed_chains() {
    for json in [chain_json(&[]), chain_json(&["not a certificate"])] {
        assert!(matches!(
            TrustBundle::from_json(json.as_bytes()),
            Err(Error::InvalidResponse(_))
        ));
    }
}
