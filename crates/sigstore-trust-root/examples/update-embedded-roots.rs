//! Update the TUF data embedded in the `sigstore-trust-root` crate.
//!
//! This crate embeds a snapshot of trust material for the production,
//! staging, and GitHub Sigstore instances so that offline mode works and
//! TUF clients can bootstrap from a recent root:
//!
//! * `repository/tuf_root.json`            - production TUF `root.json`
//! * `repository/tuf_staging_root.json`    - staging TUF `root.json`
//! * `repository/tuf_github_root.json`     - GitHub TUF `root.json`
//! * `src/trusted_root.json`               - production `trusted_root.json` target
//! * `src/trusted_root_staging.json`       - staging `trusted_root.json` target
//! * `src/trusted_root_github.json`        - GitHub `trusted_root.json` target
//! * `repository/signing_config.json`      - production `signing_config.v0.2.json` target
//! * `repository/signing_config_staging.json` - staging `signing_config.v0.2.json` target
//!
//! Run this example to refresh all of them using the TUF client itself
//! (so the files are fetched and verified the same way the library does
//! at runtime):
//!
//! ```sh
//! cargo run -p sigstore-trust-root --example update-embedded-roots
//! ```
//!
//! The fetched bytes are written verbatim (no JSON reformatting), so a
//! `git diff` after running this shows exactly what changed upstream.
//! The scheduled `.github/workflows/check-embedded-root.yml` workflow runs
//! this example and files an issue when the embedded data is out of date.

use std::path::Path;

use tough::{ExpirationEnforcement, IntoVec, RepositoryLoader, TargetName};
use url::Url;

use sigstore_trust_root::{
    DEFAULT_TUF_URL, GITHUB_TUF_ROOT, GITHUB_TUF_URL, PRODUCTION_TUF_ROOT, SIGNING_CONFIG_TARGET,
    STAGING_TUF_ROOT, STAGING_TUF_URL, TRUSTED_ROOT_TARGET,
};

/// One Sigstore TUF instance whose embedded data we keep up to date.
struct Instance {
    name: &'static str,
    /// Base URL of the TUF repository.
    url: &'static str,
    /// Currently embedded `root.json`, used as the trust anchor.
    embedded_root: &'static [u8],
    /// Where the (possibly updated) `root.json` is embedded, relative to the
    /// crate root.
    root_path: &'static str,
    /// TUF targets to refresh: (target name, embedded path relative to the
    /// crate root).
    targets: &'static [(&'static str, &'static str)],
}

const INSTANCES: &[Instance] = &[
    Instance {
        name: "production",
        url: DEFAULT_TUF_URL,
        embedded_root: PRODUCTION_TUF_ROOT,
        root_path: "repository/tuf_root.json",
        targets: &[
            (TRUSTED_ROOT_TARGET, "src/trusted_root.json"),
            (SIGNING_CONFIG_TARGET, "repository/signing_config.json"),
        ],
    },
    Instance {
        name: "staging",
        url: STAGING_TUF_URL,
        embedded_root: STAGING_TUF_ROOT,
        root_path: "repository/tuf_staging_root.json",
        targets: &[
            (TRUSTED_ROOT_TARGET, "src/trusted_root_staging.json"),
            (
                SIGNING_CONFIG_TARGET,
                "repository/signing_config_staging.json",
            ),
        ],
    },
    Instance {
        name: "github",
        url: GITHUB_TUF_URL,
        embedded_root: GITHUB_TUF_ROOT,
        root_path: "repository/tuf_github_root.json",
        // GitHub's Sigstore instance does not publish a signing config.
        targets: &[(TRUSTED_ROOT_TARGET, "src/trusted_root_github.json")],
    },
];

/// Load a TUF repository, trusting `root` as the initial root of trust.
async fn load_repository(
    url: &str,
    root: &[u8],
) -> Result<tough::Repository, Box<dyn std::error::Error>> {
    let base_url = Url::parse(url)?;
    let targets_url = base_url.join("targets/")?;
    let repo = RepositoryLoader::new(&root, base_url, targets_url)
        // Refuse stale metadata: this tool exists to fetch *current* data.
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .load()
        .await?;
    Ok(repo)
}

/// Write `bytes` to `path` only if the contents differ, reporting the result.
fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        println!("  unchanged: {}", path.display());
        return Ok(false);
    }
    std::fs::write(path, bytes)?;
    println!("  UPDATED:   {}", path.display());
    Ok(true)
}

async fn update_instance(instance: &Instance) -> Result<bool, Box<dyn std::error::Error>> {
    println!("{} ({})", instance.name, instance.url);
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Walk the TUF root chain from the embedded root.json; this verifies
    // every intermediate root signature, exactly like the library does.
    let repo = load_repository(instance.url, instance.embedded_root).await?;

    // Fetch the latest root.json (as raw bytes, to keep the file byte-for-byte
    // identical to what the repository serves). `cache_metadata` re-downloads
    // the root chain, so verify the result by loading the repository again
    // with the downloaded root.json as the sole trust anchor.
    let latest_root_version = repo.root().signed.version.get();
    let metadata_dir = tempfile::tempdir()?;
    repo.cache_metadata(metadata_dir.path(), true).await?;
    let latest_root = std::fs::read(
        metadata_dir
            .path()
            .join(format!("{latest_root_version}.root.json")),
    )?;
    load_repository(instance.url, &latest_root)
        .await
        .map_err(|e| format!("downloaded root.json failed verification: {e}"))?;

    let mut changed = write_if_changed(&crate_dir.join(instance.root_path), &latest_root)?;

    // Fetch each embedded target through the TUF client (hash/length checked
    // against the verified targets metadata) and write the bytes verbatim.
    for (target_name, embedded_path) in instance.targets {
        let target = TargetName::new(*target_name)?;
        let bytes = repo
            .read_target(&target)
            .await?
            .ok_or_else(|| format!("target not found: {target_name}"))?
            .into_vec()
            .await?;
        changed |= write_if_changed(&crate_dir.join(embedded_path), &bytes)?;
    }

    Ok(changed)
}

#[tokio::main]
async fn main() {
    // Keep going if one instance fails so that the others still get
    // refreshed, but exit non-zero so failures are visible in CI.
    let mut changed = false;
    let mut failed = false;
    for instance in INSTANCES {
        match update_instance(instance).await {
            Ok(c) => changed |= c,
            Err(e) => {
                eprintln!("  ERROR: failed to update '{}': {e}", instance.name);
                failed = true;
            }
        }
    }
    if changed {
        println!("\nEmbedded TUF data was updated; review the diff and commit it.");
    } else {
        println!("\nEmbedded TUF data is up to date.");
    }
    if failed {
        std::process::exit(1);
    }
}
