//! `tuf-conformance` client-under-test adapter.
//!
//! Implements the CLI protocol that the
//! [tuf-conformance](https://github.com/theupdateframework/tuf-conformance)
//! suite drives, so `sigstore-tuf` can be tested for cross-implementation
//! conformance alongside `python-tuf` and `go-tuf`:
//!
//! ```text
//! conformance_client --metadata-dir <DIR> init <TRUSTED_ROOT>
//! conformance_client --metadata-dir <DIR> --metadata-url <URL> refresh
//! conformance_client --metadata-dir <DIR> --metadata-url <URL> \
//!     --target-name <PATH> --target-base-url <URL> --target-dir <DIR> download
//! ```
//!
//! Exit code 0 on success, 1 on any failure. The harness wraps invocations in
//! `faketime`, so we use the real system clock (`jiff::Timestamp::now`) for
//! expiry — letting the harness drive time forward for expiration tests.

use std::path::{Path, PathBuf};

use sigstore_tuf::cache::MetadataStore;
use sigstore_tuf::client::{HttpRepository, Updater};
use sigstore_tuf::{Error, Result};

/// A metadata store that persists trusted metadata under the canonical,
/// non-versioned file names (`root.json`, `timestamp.json`, ...) the
/// conformance harness inspects. Versioned files (`2.root.json`) and cached
/// targets (`targets/...`) are intentionally not persisted into the trusted
/// metadata dir so the harness's role enumeration sees exactly the trusted set.
struct ConformanceStore {
    dir: PathBuf,
}

impl MetadataStore for ConformanceStore {
    fn load(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join(name)).ok()
    }

    fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
        // Skip cached target artifacts.
        if name.contains('/') {
            return Ok(());
        }
        // Skip version-prefixed file names like "2.root.json".
        let stem = name.split('.').next().unwrap_or("");
        if !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(());
        }
        std::fs::write(self.dir.join(name), bytes)
            .map_err(|e| Error::Transport(format!("cache write {name}: {e}")))
    }
}

#[derive(Default)]
struct Args {
    metadata_dir: Option<String>,
    metadata_url: Option<String>,
    target_name: Option<String>,
    target_dir: Option<String>,
    target_base_url: Option<String>,
    positionals: Vec<String>,
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(tok) = it.next() {
        let mut take = |a: &mut Option<String>| -> std::result::Result<(), String> {
            *a = Some(
                it.next()
                    .ok_or_else(|| format!("missing value for {tok}"))?,
            );
            Ok(())
        };
        match tok.as_str() {
            "--metadata-dir" => take(&mut args.metadata_dir)?,
            "--metadata-url" => take(&mut args.metadata_url)?,
            "--target-name" => take(&mut args.target_name)?,
            "--target-dir" => take(&mut args.target_dir)?,
            "--target-base-url" => take(&mut args.target_base_url)?,
            "-v" | "--verbose" => {}
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            _ => args.positionals.push(tok),
        }
    }
    Ok(args)
}

fn metadata_dir(args: &Args) -> Result<PathBuf> {
    args.metadata_dir
        .as_ref()
        .map(PathBuf::from)
        .ok_or_else(|| Error::Transport("--metadata-dir is required".into()))
}

/// `init`: copy the given trusted root into the metadata dir as `root.json`.
fn cmd_init(args: &Args) -> Result<()> {
    let dir = metadata_dir(args)?;
    let trusted_root = args
        .positionals
        .get(1)
        .ok_or_else(|| Error::Transport("init requires a trusted root path".into()))?;
    let bytes = std::fs::read(trusted_root)
        .map_err(|e| Error::Transport(format!("reading trusted root: {e}")))?;
    // Validate it parses & self-verifies before trusting it on first use.
    sigstore_tuf::TrustedMetadataSet::from_root(&bytes)?;
    std::fs::write(dir.join("root.json"), &bytes)
        .map_err(|e| Error::Transport(format!("writing root.json: {e}")))?;
    Ok(())
}

fn build_updater(args: &Args) -> Result<Updater> {
    let dir = metadata_dir(args)?;
    let url = args
        .metadata_url
        .as_ref()
        .ok_or_else(|| Error::Transport("--metadata-url is required".into()))?;
    let root = std::fs::read(dir.join("root.json"))
        .map_err(|e| Error::Transport(format!("no trusted root in metadata dir: {e}")))?;
    let mut repo = HttpRepository::new(url)?;
    if let Some(target_base) = &args.target_base_url {
        repo = repo.with_targets_base(target_base)?;
    }
    Ok(Updater::new(repo, &root)?.with_store(ConformanceStore { dir }))
}

/// `refresh`: run the TUF refresh workflow, persisting trusted metadata.
async fn cmd_refresh(args: &Args) -> Result<()> {
    let mut updater = build_updater(args)?;
    updater.refresh(jiff::Timestamp::now()).await
}

/// `download`: refresh, resolve the target (walking delegations), verify and
/// write it into the target dir.
async fn cmd_download(args: &Args) -> Result<()> {
    let target_name = args
        .target_name
        .as_ref()
        .ok_or_else(|| Error::Transport("--target-name is required".into()))?;
    let target_dir = args
        .target_dir
        .as_ref()
        .map(PathBuf::from)
        .ok_or_else(|| Error::Transport("--target-dir is required".into()))?;

    let mut updater = build_updater(args)?;
    let now = jiff::Timestamp::now();
    updater.refresh(now).await?;

    // Resolve the target (walking delegations) so we can check the cache before
    // fetching the artifact itself.
    let info = updater
        .get_targetinfo(target_name, now)
        .await?
        .ok_or_else(|| Error::Malformed(format!("unknown target {target_name:?}")))?;
    let out = target_dir.join(safe_target_filename(target_name));

    // Artifact cache: if we already have a byte-identical copy, don't download
    // it again (tuf-conformance's test_artifact_cache checks this).
    if let Ok(existing) = std::fs::read(&out) {
        if target_bytes_match(&existing, &info) {
            return Ok(());
        }
    }

    let bytes = updater.download_target(target_name, now).await?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Transport(format!("creating target dir: {e}")))?;
    }
    std::fs::write(&out, &bytes).map_err(|e| Error::Transport(format!("writing target: {e}")))?;
    Ok(())
}

/// Whether `bytes` already satisfies a target's pinned length and hash.
fn target_bytes_match(bytes: &[u8], info: &sigstore_tuf::TargetFile) -> bool {
    use sha2::{Digest, Sha256, Sha512};
    if bytes.len() as u64 != info.length {
        return false;
    }
    info.hashes.iter().any(|(algo, expected)| {
        let actual = match algo.as_str() {
            "sha256" => hex::encode(Sha256::digest(bytes)),
            "sha512" => hex::encode(Sha512::digest(bytes)),
            _ => return false,
        };
        actual.eq_ignore_ascii_case(expected)
    })
}

/// Map a TUF target path to a safe relative path under the target dir.
fn safe_target_filename(target_name: &str) -> PathBuf {
    let rel = Path::new(target_name.trim_start_matches('/'));
    if rel
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        // Fall back to the basename if the path tries to escape.
        return PathBuf::from(rel.file_name().unwrap_or(rel.as_os_str()));
    }
    rel.to_path_buf()
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("conformance_client: {e}");
            std::process::exit(1);
        }
    };

    let result = match args.positionals.first().map(String::as_str) {
        Some("init") => cmd_init(&args),
        Some("refresh") => cmd_refresh(&args).await,
        Some("download") => cmd_download(&args).await,
        other => Err(Error::Transport(format!(
            "expected subcommand init|refresh|download, got {other:?}"
        ))),
    };

    if let Err(e) = result {
        eprintln!("conformance_client: {e}");
        std::process::exit(1);
    }
}
