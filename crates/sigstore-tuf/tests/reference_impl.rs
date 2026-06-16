//! Interop tests against `python-tuf`-generated metadata.
//!
//! The `tuf-reference-impl` fixture under `tests/data/` is a complete repository
//! produced by the TUF reference implementation (`python-tuf`), vendored from
//! `tough` (see `tests/data/ATTRIBUTION.md`). Driving our `Updater` over it with
//! a filesystem transport proves we interoperate byte-for-byte with metadata
//! signed by `securesystemslib` canonical JSON — independent of any network.
//!
//! It also exercises a two-level targets delegation (`role1` → `role2`) and a
//! few malformed roots that must fail bootstrap closed.

use std::path::{Path, PathBuf};

use sigstore_tuf::transport::{FetchFuture, Repository};
use sigstore_tuf::{Error, TrustedMetadataSet, Updater};

/// A filesystem-backed [`Repository`]: metadata from one dir, targets from
/// another. Mirrors `tough`'s `FilesystemTransport`-style fixtures.
struct FsRepo {
    metadata_dir: PathBuf,
    targets_dir: PathBuf,
}

impl FsRepo {
    fn read(dir: &Path, name: &str, max_length: u64) -> sigstore_tuf::Result<Option<Vec<u8>>> {
        match std::fs::read(dir.join(name)) {
            Ok(bytes) if bytes.len() as u64 > max_length => {
                Err(Error::Transport(format!("{name} exceeds {max_length}")))
            }
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Transport(e.to_string())),
        }
    }
}

impl Repository for FsRepo {
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        let res = Self::read(&self.metadata_dir, name, max_length);
        Box::pin(async move { res })
    }

    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
        let res = Self::read(&self.targets_dir, path, max_length);
        Box::pin(async move { res })
    }
}

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn reference_impl_repo() -> (FsRepo, Vec<u8>) {
    let base = data_dir().join("tuf-reference-impl");
    let root = std::fs::read(base.join("metadata/1.root.json")).unwrap();
    let repo = FsRepo {
        metadata_dir: base.join("metadata"),
        targets_dir: base.join("targets"),
    };
    (repo, root)
}

/// The fixtures expire 2030-01-01, so "now" just needs to be before then.
fn now() -> jiff::Timestamp {
    "2026-06-01T00:00:00Z".parse().unwrap()
}

#[test]
fn reference_impl_root_self_verifies() {
    // ed25519 + rsassa-pss-sha256 keys, signed with securesystemslib canonical
    // JSON. This passing means our canonical encoder and key handling agree with
    // python-tuf for both key types.
    let (_, root) = reference_impl_repo();
    TrustedMetadataSet::from_root(&root).expect("python-tuf reference root should self-verify");
}

#[tokio::test]
async fn full_refresh_and_read_targets() {
    let (repo, root) = reference_impl_repo();
    let mut updater = Updater::new(repo, &root).unwrap();
    updater
        .refresh(now())
        .await
        .expect("refresh over python-tuf repo should verify end to end");

    // Top-level targets.
    let f1 = updater.get_target("file1.txt", now()).await.unwrap();
    assert_eq!(f1, b"This is an example target file.");
    let f2 = updater.get_target("file2.txt", now()).await.unwrap();
    assert_eq!(f2, b"This is an another example target file.");

    // `custom` metadata round-trips.
    let info = updater.find_target("file1.txt").unwrap();
    assert_eq!(
        info.custom.as_ref().unwrap()["file_permissions"],
        serde_json::json!("0644")
    );
}

#[tokio::test]
async fn resolves_target_through_delegation() {
    // `file3.txt` is not in top-level targets; it is delegated to `role1`
    // (paths = ["file3.txt"]), which `role2` further extends. The walk must
    // verify role1 against the delegating keys and find the target there.
    let (repo, root) = reference_impl_repo();
    let mut updater = Updater::new(repo, &root).unwrap();
    updater.refresh(now()).await.unwrap();

    assert!(
        updater.find_target("file3.txt").is_none(),
        "file3.txt should not be in top-level targets"
    );
    let info = updater
        .get_targetinfo("file3.txt", now())
        .await
        .unwrap()
        .expect("delegation walk should resolve file3.txt via role1");
    assert!(info.length > 0);

    let bytes = updater.download_target(&info, "file3.txt").await.unwrap();
    assert_eq!(bytes, b"This is role1's target file.");
}

#[test]
fn malformed_roots_fail_closed() {
    let neg = data_dir().join("negative");
    for (file, why) in [
        ("no-root-json-signatures.root.json", "zero signatures"),
        ("invalid-root-json-signature.root.json", "corrupt signature"),
        (
            "duplicate-sigs.root.json",
            "duplicate sigs from one key vs threshold 2",
        ),
    ] {
        let bytes = std::fs::read(neg.join(file)).unwrap();
        let err = TrustedMetadataSet::from_root(&bytes)
            .expect_err(&format!("{file} must fail bootstrap ({why})"));
        // All must fail closed; the exact variant (threshold not met vs.
        // duplicate signature) depends on the fixture.
        assert!(
            matches!(
                err,
                Error::ThresholdNotMet { .. } | Error::DuplicateSignature { .. }
            ),
            "{file}: expected a verification failure, got {err:?}"
        );
    }
}
