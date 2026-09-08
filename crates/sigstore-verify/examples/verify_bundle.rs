//! Example: Verify a Sigstore bundle
//!
//! This example demonstrates how to verify a Sigstore bundle against an artifact.
//! Files are streamed unless the message-signature scheme requires the original
//! bytes (e.g. Ed25519), in which case the file is loaded into memory.
//!
//! # Usage
//!
//! Verify a local bundle:
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- artifact.txt artifact.sigstore.json
//! ```
//!
//! Verify with identity requirements:
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- \
//!     --certificate-identity "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0" \
//!     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
//!     artifact.txt artifact.sigstore.json
//! ```
//!
//! Verify with regex matching (cosign-compatible):
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- \
//!     --certificate-identity-regexp ".*" \
//!     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
//!     artifact.txt artifact.sigstore.json
//! ```
//!
//! Verify using digest instead of file:
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- \
//!     --certificate-identity-regexp ".*" \
//!     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
//!     sha256:abc123... bundle.sigstore.json
//! ```
//!
//! # Getting a bundle from GitHub
//!
//! You can download attestation bundles from GitHub releases using the GitHub CLI:
//! ```sh
//! # Download attestation for a release artifact
//! gh attestation download <artifact-url> -o bundle.sigstore.json
//!
//! # Or verify directly with gh (uses sigstore under the hood)
//! gh attestation verify <artifact> --owner <owner>
//! ```

use regex::Regex;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, Sha256Hash, SignatureContent};
use sigstore_verify::{Error, VerificationPolicy, VerificationResult, Verifier};

use std::env;
use std::fs;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut identity: Option<String> = None;
    let mut identity_regexp: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut instance: Option<String> = None;
    let mut trusted_root_path: Option<String> = None;
    let mut tuf_root_path: Option<String> = None;
    let mut staging = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--identity" | "-i" | "--certificate-identity" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --certificate-identity requires a value");
                    process::exit(1);
                }
                identity = Some(args[i].clone());
            }
            "--certificate-identity-regexp" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --certificate-identity-regexp requires a value");
                    process::exit(1);
                }
                identity_regexp = Some(args[i].clone());
            }
            "--issuer" | "-o" | "--certificate-oidc-issuer" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --certificate-oidc-issuer requires a value");
                    process::exit(1);
                }
                issuer = Some(args[i].clone());
            }
            "--instance" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --instance requires a value");
                    process::exit(1);
                }
                instance = Some(args[i].clone());
            }
            "--trusted-root" | "--tuf-root" => {
                let option = args[i].clone();
                i += 1;
                let value = args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("Error: {option} requires a file path");
                    process::exit(2);
                });
                if option == "--trusted-root" {
                    trusted_root_path = Some(value);
                } else {
                    tuf_root_path = Some(value);
                }
            }
            "--staging" => {
                staging = true;
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                process::exit(0);
            }
            arg if !arg.starts_with('-') => {
                positional.push(arg.to_string());
            }
            unknown => {
                eprintln!("Error: Unknown option: {}", unknown);
                print_usage(&args[0]);
                process::exit(1);
            }
        }
        i += 1;
    }

    if positional.len() != 2 {
        eprintln!("Error: Expected exactly 2 positional arguments (artifact/digest and bundle)");
        print_usage(&args[0]);
        process::exit(1);
    }

    if usize::from(instance.is_some())
        + usize::from(trusted_root_path.is_some())
        + usize::from(staging)
        > 1
        || (instance.is_some() != tuf_root_path.is_some())
    {
        eprintln!(
            "Error: select only one of --trusted-root, --staging, or --instance with --tuf-root"
        );
        process::exit(2);
    }

    let artifact_or_digest = &positional[0];
    let bundle_path = &positional[1];

    // Check if artifact is a digest (sha256:...)
    let is_digest = artifact_or_digest.starts_with("sha256:");

    // Read bundle
    let bundle_json = match fs::read_to_string(bundle_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading bundle '{}': {}", bundle_path, e);
            process::exit(1);
        }
    };

    // Parse bundle
    let bundle = match Bundle::from_json(&bundle_json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error parsing bundle: {}", e);
            process::exit(1);
        }
    };

    // Load trusted root (staging or production Sigstore instance)
    let trusted_root = if let Some(path) = trusted_root_path {
        let root = fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|json| TrustedRoot::from_json(&json).map_err(|e| e.to_string()));
        root.unwrap_or_else(|e| {
            eprintln!("Error loading trusted root: {e}");
            process::exit(2);
        })
    } else if let Some(url) = instance {
        println!("  Using: custom instance ({})", url);
        let bootstrap = fs::read(tuf_root_path.unwrap()).unwrap_or_else(|e| {
            eprintln!("Error reading trusted TUF bootstrap: {e}");
            process::exit(2);
        });
        let config = sigstore_trust_root::tuf::TufConfig::custom(
            &url,
            sigstore_trust_root::tuf::TufBootstrap::trusted(bootstrap),
        );
        match TrustedRoot::from_tuf(config).await {
            Ok(root) => root,
            Err(e) => {
                eprintln!("Error fetching custom trusted root via TUF: {}", e);
                process::exit(1);
            }
        }
    } else if staging {
        println!("  Using: staging instance");
        match TrustedRoot::staging().await {
            Ok(root) => root,
            Err(e) => {
                eprintln!("Error fetching staging trusted root via TUF: {}", e);
                process::exit(1);
            }
        }
    } else {
        println!("  Using: production instance");
        match TrustedRoot::production().await {
            Ok(root) => root,
            Err(e) => {
                eprintln!("Error fetching production trusted root via TUF: {}", e);
                process::exit(1);
            }
        }
    };

    // Build verification policy
    let mut policy = VerificationPolicy::default();
    if let Some(id) = &identity {
        policy = policy.require_identity(id);
    }
    if let Some(iss) = &issuer {
        policy = policy.require_issuer(iss);
    }

    // Print bundle info
    println!("Verifying bundle...");
    if is_digest {
        println!("  Digest: {}", artifact_or_digest);
    } else {
        println!("  Artifact: {}", artifact_or_digest);
    }
    println!("  Bundle: {}", bundle_path);
    println!("  Media Type: {}", bundle.media_type);
    println!("  Version: {:?}", bundle.version());
    if let Some(id) = &identity {
        println!("  Required Identity: {}", id);
    }
    if let Some(re) = &identity_regexp {
        println!("  Required Identity Regexp: {}", re);
    }
    if let Some(iss) = &issuer {
        println!("  Required Issuer: {}", iss);
    }

    // Verify
    let verifier = Verifier::new(&trusted_root);
    let result = if is_digest {
        // Parse digest (sha256:hex...)
        let hex_digest = artifact_or_digest.strip_prefix("sha256:").unwrap();
        let digest = match Sha256Hash::from_hex(hex_digest) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error parsing digest: {}", e);
                process::exit(1);
            }
        };
        verifier.verify(digest, &bundle, &policy)
    } else {
        verify_file(artifact_or_digest, &verifier, &bundle, &policy)
    };

    match result {
        Ok(result) => {
            // Check identity regexp if provided
            if let Some(re_str) = &identity_regexp {
                let re = match Regex::new(re_str) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error compiling identity regexp: {}", e);
                        process::exit(1);
                    }
                };
                if let Some(id) = &result.identity {
                    if !re.is_match(id) {
                        eprintln!("\nVerification: FAILED");
                        eprintln!("  Identity '{}' does not match regexp '{}'", id, re_str);
                        process::exit(1);
                    }
                } else {
                    eprintln!("\nVerification: FAILED");
                    eprintln!("  No identity found in certificate");
                    process::exit(1);
                }
            }

            println!("\nVerification: SUCCESS");
            if let Some(id) = &result.identity {
                println!("  Identity: {}", id);
            }
            if let Some(iss) = &result.issuer {
                println!("  Issuer: {}", iss);
            }
            if let Some(time) = result.integrated_time {
                println!("  Signed at: {}", time);
            }
            for warning in &result.warnings {
                println!("  Warning: {}", warning);
            }
            process::exit(0);
        }
        Err(e) => {
            eprintln!("\nVerification error: {}", e);
            process::exit(1);
        }
    }
}

fn requires_blob(bundle: &Bundle) -> Result<bool, Error> {
    if !matches!(bundle.content, SignatureContent::MessageSignature(_)) {
        // DSSE signatures cover the envelope, not the streamed artifact.
        return Ok(false);
    }
    let cert = bundle
        .signing_certificate()
        .ok_or_else(|| Error::Verification("bundle has no signing certificate".into()))?;
    Ok(!sigstore_crypto::parse_certificate_info(cert.as_bytes())?
        .key_algorithm
        .default_signing_scheme()
        .supports_prehashed())
}

fn verify_file(
    path: &str,
    verifier: &Verifier,
    bundle: &Bundle,
    policy: &VerificationPolicy,
) -> Result<VerificationResult, Error> {
    if requires_blob(bundle)? {
        let artifact = fs::read(path).map_err(Error::ArtifactRead)?;
        verifier.verify(&artifact, bundle, policy)
    } else {
        let artifact = fs::File::open(path).map_err(Error::ArtifactRead)?;
        verifier.verify_reader(artifact, bundle, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::{bundle::VerificationMaterialContent, DerCertificate};
    use x509_cert::der::{asn1::BitString, Decode, Encode};

    #[test]
    fn only_non_prehashed_message_signatures_require_blob_input() {
        let mut bundle = Bundle::from_json(include_str!(
            "../../sigstore-bundle/tests/fixtures/bundle_v3.json"
        ))
        .unwrap();
        assert!(!requires_blob(&bundle).unwrap());

        // Synthetic Ed25519 certificate: only key parsing is exercised here,
        // not certificate-chain or signature verification.
        let mut cert =
            x509_cert::Certificate::from_der(bundle.signing_certificate().unwrap().as_bytes())
                .unwrap();
        let spki = &mut cert.tbs_certificate.subject_public_key_info;
        spki.algorithm.oid = "1.3.101.112".parse().unwrap();
        spki.algorithm.parameters = None;
        spki.subject_public_key = BitString::from_bytes(&[0; 32]).unwrap();
        bundle.verification_material.content =
            VerificationMaterialContent::Certificate(sigstore_types::bundle::CertificateContent {
                raw_bytes: DerCertificate::new(cert.to_der().unwrap()),
            });
        assert!(requires_blob(&bundle).unwrap());

        let dsse = Bundle::from_json(include_str!(
            "../../sigstore-bundle/tests/fixtures/happy-path.json"
        ))
        .unwrap();
        bundle.content = dsse.content;
        assert!(!requires_blob(&bundle).unwrap());
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [OPTIONS] <ARTIFACT|DIGEST> <BUNDLE>", program);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <ARTIFACT|DIGEST>  Path to artifact file OR sha256:hex digest");
    eprintln!("  <BUNDLE>           Path to the Sigstore bundle (.sigstore.json)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --certificate-identity <ID>        Required certificate identity (exact match)");
    eprintln!("  --certificate-identity-regexp <RE> Required certificate identity (regex)");
    eprintln!("  --certificate-oidc-issuer <ISSUER> Required OIDC issuer");
    eprintln!("  --trusted-root <FILE>              Use a local Sigstore trusted root (offline)");
    eprintln!("  --instance <URL> --tuf-root <FILE>  Custom instance with trusted TUF bootstrap");
    eprintln!("  --staging                          Use Sigstore staging instance");
    eprintln!("  -h, --help                         Print this help message");
    eprintln!();
    eprintln!("Aliases (for backwards compatibility):");
    eprintln!("  -i, --identity  Same as --certificate-identity");
    eprintln!("  -o, --issuer    Same as --certificate-oidc-issuer");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Verify a bundle");
    eprintln!("  {} artifact.txt artifact.sigstore.json", program);
    eprintln!();
    eprintln!("  # Verify with identity regex (cosign-compatible)");
    eprintln!("  {} --certificate-identity-regexp \".*\" \\", program);
    eprintln!("      --certificate-oidc-issuer https://token.actions.githubusercontent.com \\");
    eprintln!("      artifact.txt artifact.sigstore.json");
    eprintln!();
    eprintln!("  # Verify using digest instead of file");
    eprintln!("  {} --certificate-identity-regexp \".*\" \\", program);
    eprintln!("      --certificate-oidc-issuer https://token.actions.githubusercontent.com \\");
    eprintln!("      sha256:abc123def456... bundle.sigstore.json");
    eprintln!();
    eprintln!("Getting bundles from GitHub:");
    eprintln!("  gh attestation download <artifact-url> -o bundle.sigstore.json");
}
