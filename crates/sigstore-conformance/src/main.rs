//! Sigstore Conformance Client
//!
//! CLI implementation following the specification:
//! <https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md>
//!
//! This binary implements the conformance test protocol for Sigstore clients.

use sigstore_oidc::IdentityToken;
use sigstore_sign::{SigningContext, SigningServices};
use sigstore_trust_root::{SigningConfig as TufSigningConfig, SigstoreInstance, TrustedRoot};
use sigstore_types::{Artifact, Bundle, DerPublicKey, Sha256Hash};
use sigstore_verify::{verify, Policy, PublicKeyVerificationPolicy, VerificationPolicy};

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }

    let command = &args[1];
    let result = match command.as_str() {
        "sign-bundle" => sign_bundle(&args[2..]),
        "verify-bundle" => verify_bundle(&args[2..]),
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage(&args[0]);
            process::exit(1);
        }
    };

    match result {
        Ok(()) => {
            eprintln!("Operation succeeded!");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Operation failed:\n{}", e);
            process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {} sign-bundle --identity-token TOKEN --bundle FILE [--in-toto] [--staging] [--trusted-root FILE] [--signing-config FILE] ARTIFACT", program);
    eprintln!("  {} verify-bundle --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--staging] [--trusted-root FILE] ARTIFACT_OR_DIGEST", program);
    eprintln!("  {} verify-bundle --bundle FILE --key KEY_FILE [--staging] [--trusted-root FILE] ARTIFACT_OR_DIGEST", program);
}

#[tokio::main]
async fn sign_bundle(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let mut identity_token: Option<String> = None;
    let mut bundle_path: Option<String> = None;
    let mut artifact_path: Option<String> = None;
    let mut staging = false;
    let mut _trusted_root: Option<String> = None;
    let mut _signing_config: Option<String> = None;
    let mut in_toto = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--identity-token" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --identity-token".into());
                }
                identity_token = Some(args[i].clone());
            }
            "--bundle" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --bundle".into());
                }
                bundle_path = Some(args[i].clone());
            }
            "--in-toto" => {
                in_toto = true;
            }
            "--staging" => {
                staging = true;
            }
            "--trusted-root" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --trusted-root".into());
                }
                _trusted_root = Some(args[i].clone());
            }
            "--signing-config" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --signing-config".into());
                }
                _signing_config = Some(args[i].clone());
            }
            arg if !arg.starts_with("--") => {
                artifact_path = Some(arg.to_string());
            }
            unknown => {
                return Err(format!("Unknown option: {}", unknown).into());
            }
        }
        i += 1;
    }

    let identity_token_str = identity_token.ok_or("Missing required --identity-token")?;
    let bundle_path = bundle_path.ok_or("Missing required --bundle")?;
    let artifact_path = artifact_path.ok_or("Missing artifact path")?;

    let signing_services = if let Some(config_path) = &_signing_config {
        let tuf_config = TufSigningConfig::from_file(config_path)?;
        SigningServices::from_tuf_config(&tuf_config)?
    } else if staging {
        SigningServices::embedded(SigstoreInstance::Staging)?
    } else {
        SigningServices::embedded(SigstoreInstance::PublicGood)?
    };

    let context = SigningContext::new(signing_services);
    let identity_token = IdentityToken::from_jwt(&identity_token_str)?;
    let signer = context.signer(identity_token);

    // Read artifact
    let artifact_data = fs::read(&artifact_path)?;

    // Sign and get bundle
    let bundle = if in_toto {
        signer.sign_raw_statement(&artifact_data).await?
    } else {
        signer.sign(artifact_data.as_slice()).await?
    };

    // Write bundle
    let bundle_json = bundle.to_json_pretty()?;
    fs::write(&bundle_path, bundle_json)?;

    Ok(())
}

fn verify_bundle(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let mut bundle_path: Option<String> = None;
    let mut certificate_identity: Option<String> = None;
    let mut certificate_oidc_issuer: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut artifact_or_digest: Option<String> = None;
    let mut staging = false;
    let mut trusted_root_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --bundle".into());
                }
                bundle_path = Some(args[i].clone());
            }
            "--certificate-identity" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --certificate-identity".into());
                }
                certificate_identity = Some(args[i].clone());
            }
            "--certificate-oidc-issuer" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --certificate-oidc-issuer".into());
                }
                certificate_oidc_issuer = Some(args[i].clone());
            }
            "--key" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --key".into());
                }
                key_path = Some(args[i].clone());
            }
            "--staging" => {
                staging = true;
            }
            "--trusted-root" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --trusted-root".into());
                }
                trusted_root_path = Some(args[i].clone());
            }
            arg if !arg.starts_with("--") => {
                artifact_or_digest = Some(arg.to_string());
            }
            unknown => {
                return Err(format!("Unknown option: {}", unknown).into());
            }
        }
        i += 1;
    }

    let bundle_path = bundle_path.ok_or("Missing required --bundle")?;
    let artifact_or_digest = artifact_or_digest.ok_or("Missing artifact or digest")?;

    // An explicit root takes precedence over the selected instance.
    let trusted_root = if let Some(root_path) = trusted_root_path {
        TrustedRoot::from_file(&root_path)?
    } else {
        TrustedRoot::from_embedded(if staging {
            SigstoreInstance::Staging
        } else {
            SigstoreInstance::PublicGood
        })?
    };

    // Load bundle
    let bundle_json = fs::read_to_string(&bundle_path)?;
    let bundle = Bundle::from_json(&bundle_json)?;

    // A managed-key bundle is verified against the supplied key, a keyless
    // one against the expected certificate identity.
    let policy: Box<dyn Policy> = match key_path {
        Some(key_path) => {
            let key_pem = fs::read_to_string(&key_path)?;
            let public_key = DerPublicKey::from_pem(&key_pem)
                .map_err(|e| format!("Failed to parse public key: {}", e))?;
            Box::new(PublicKeyVerificationPolicy::new(public_key))
        }
        None => {
            let (Some(identity), Some(issuer)) = (certificate_identity, certificate_oidc_issuer)
            else {
                return Err("Either --key or both --certificate-identity and --certificate-oidc-issuer must be provided".into());
            };
            Box::new(VerificationPolicy::new(identity, issuer))
        }
    };

    // The artifact is either a `sha256:<hex>` digest or a file path.
    let artifact_data;
    let artifact: Artifact<'_> = match artifact_or_digest.strip_prefix("sha256:") {
        Some(digest_hex) => {
            let digest_bytes =
                hex::decode(digest_hex).map_err(|e| format!("Invalid hex digest: {}", e))?;
            if digest_bytes.len() != 32 {
                return Err(format!(
                    "Invalid SHA256 digest length: expected 32 bytes, got {}",
                    digest_bytes.len()
                )
                .into());
            }
            Sha256Hash::try_from(digest_bytes.as_slice())
                .map_err(|e| format!("Invalid digest: {}", e))?
                .into()
        }
        None => {
            artifact_data = fs::read(&artifact_or_digest)?;
            Artifact::from_blob(&artifact_data)
        }
    };

    verify(artifact, &bundle, policy.as_ref(), &trusted_root)?;
    Ok(())
}
