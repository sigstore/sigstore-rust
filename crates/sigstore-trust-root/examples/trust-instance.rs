//! Example: Trust a custom Sigstore instance
//!
//! This example demonstrates how to establish trust for a custom Sigstore instance
//! (like a root-signing test environment) by downloading its trusted root and
//! caching it locally.
//!
//! # Usage
//!
//! ```sh
//! cargo run -p sigstore-trust-root --example trust-instance -- --instance <URL> <ROOT_JSON>
//! ```

use sigstore_trust_root::tuf::{fetch_trust_material, TufConfig};
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let mut instance_url: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--instance" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --instance requires a value");
                    process::exit(1);
                }
                instance_url = Some(args[i].clone());
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

    if positional.len() != 1 {
        eprintln!("Error: Expected exactly 1 positional argument (path to root.json)");
        print_usage(&args[0]);
        process::exit(1);
    }

    let url = match instance_url {
        Some(u) => u,
        None => {
            eprintln!("Error: --instance is required");
            print_usage(&args[0]);
            process::exit(1);
        }
    };

    let root_path = &positional[0];

    println!("Trusting instance: {}", url);
    println!("Using bootstrap root: {}", root_path);

    let config = match TufConfig::custom_from_file(&url, root_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading root.json from {}: {}", root_path, e);
            process::exit(1);
        }
    };

    println!("\nFetching and verifying TUF metadata...");
    match fetch_trust_material(config).await {
        Ok((_root, _signing_config)) => {
            println!("This instance is now trusted and can be used in sign and verify examples:");
            println!(
                "  cargo run -p sigstore-sign --example sign_blob -- --instance {} README.md",
                url
            );
        }
        Err(e) => {
            eprintln!("Error initializing trust: {}", e);
            process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} --instance <URL> <ROOT_JSON>", program);
    eprintln!();
    eprintln!("Initialize trust for a custom Sigstore instance by verifying");
    eprintln!("and caching its TUF repository using the provided bootstrap root.");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <ROOT_JSON>        Path to a trusted TUF root.json");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --instance <URL>   Base URL of the custom TUF repository");
    eprintln!("  -h, --help         Print this help message");
}
