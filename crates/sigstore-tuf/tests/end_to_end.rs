//! End-to-end exercise of the full client over a self-built, signed TUF repo.
//!
//! This both *produces* metadata (signing canonical JSON with ECDSA P-256) and
//! *consumes* it through the [`Updater`], closing the loop on canonical JSON and
//! signature verification. It covers: root → timestamp → snapshot → top-level
//! targets, a real delegation hand-off (a delegated role signed by a *different*
//! key), target download with hash verification, per-file size limits, and an
//! offline re-verification purely from the write-through cache.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sigstore_crypto::KeyPair;
use sigstore_tuf::transport::{FetchFuture, Repository};
use sigstore_tuf::{Key, MemoryStore, MetadataStore, StoreRepository, Updater, UpdaterConfig};

const FAR_FUTURE: &str = "2999-01-01T00:00:00Z";

fn now() -> jiff::Timestamp {
    "2026-06-01T00:00:00Z".parse().unwrap()
}

/// A trivial in-memory repository.
#[derive(Default)]
struct MemRepo {
    metadata: HashMap<String, Vec<u8>>,
    targets: HashMap<String, Vec<u8>>,
}

impl Repository for MemRepo {
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        let res = match self.metadata.get(name) {
            Some(b) if b.len() as u64 > max_length => Err(sigstore_tuf::Error::Transport(format!(
                "{name} exceeds {max_length}"
            ))),
            other => Ok(other.cloned()),
        };
        Box::pin(async move { res })
    }

    fn fetch_target<'a>(&'a self, path: &'a str, _max_length: u64) -> FetchFuture<'a> {
        let res = Ok(self.targets.get(path).cloned());
        Box::pin(async move { res })
    }
}

/// Build a `Key` JSON object and its declared key ID from a keypair.
fn key_entry(kp: &KeyPair) -> (String, Value) {
    let pem = kp.public_key_der().unwrap().to_pem();
    let obj = json!({
        "keytype": "ecdsa",
        "scheme": "ecdsa-sha2-nistp256",
        "keyval": { "public": pem },
    });
    let key: Key = serde_json::from_value(obj.clone()).unwrap();
    (key.key_id().unwrap(), obj)
}

/// Sign `signed` with `kp` under `keyid`, producing a signature entry.
fn signature(signed: &Value, keyid: &str, kp: &KeyPair) -> Value {
    let canonical = sigstore_tuf::canonical_json::to_canonical_bytes(signed).unwrap();
    let sig = kp.sign(&canonical).unwrap();
    json!({ "keyid": keyid, "sig": hex::encode(sig.as_bytes()) })
}

fn envelope(signed: Value, sigs: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({ "signed": signed, "signatures": sigs })).unwrap()
}

/// A `meta` entry pinning length + sha256 + version of a metadata file.
fn metafile(bytes: &[u8], version: u64) -> Value {
    json!({
        "version": version,
        "length": bytes.len(),
        "hashes": { "sha256": hex::encode(Sha256::digest(bytes)) },
    })
}

/// Assemble a complete, signed, non-consistent-snapshot repo with one
/// delegation. Returns the repo and the pinned bootstrap root bytes.
fn build_repo() -> (MemRepo, Vec<u8>) {
    let root_kp = KeyPair::generate_ecdsa_p256().unwrap();
    let deleg_kp = KeyPair::generate_ecdsa_p256().unwrap();
    let (root_kid, root_key) = key_entry(&root_kp);
    let (deleg_kid, deleg_key) = key_entry(&deleg_kp);

    // --- the actual target file, only listed in the delegated role ---
    let target_content = b"hello from the delegated role".to_vec();
    let target_path = "delegated/file.txt";

    // --- delegated targets metadata (signed by the delegation key) ---
    let delegated_signed = json!({
        "_type": "targets",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": FAR_FUTURE,
        "targets": {
            target_path: {
                "length": target_content.len(),
                "hashes": { "sha256": hex::encode(Sha256::digest(&target_content)) },
            }
        },
    });
    let delegated_bytes = envelope(
        delegated_signed.clone(),
        vec![signature(&delegated_signed, &deleg_kid, &deleg_kp)],
    );

    // --- top-level targets: empty, but delegates `delegated/*` to deleg_kp ---
    let targets_signed = json!({
        "_type": "targets",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": FAR_FUTURE,
        "targets": {},
        "delegations": {
            "keys": { deleg_kid.clone(): deleg_key },
            "roles": [{
                "name": "delegated",
                "keyids": [deleg_kid],
                "threshold": 1,
                "paths": ["delegated/*"],
                "terminating": false,
            }],
        },
    });
    let targets_bytes = envelope(
        targets_signed.clone(),
        vec![signature(&targets_signed, &root_kid, &root_kp)],
    );

    // --- snapshot pins both targets files ---
    let snapshot_signed = json!({
        "_type": "snapshot",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": FAR_FUTURE,
        "meta": {
            "targets.json": metafile(&targets_bytes, 1),
            "delegated.json": metafile(&delegated_bytes, 1),
        },
    });
    let snapshot_bytes = envelope(
        snapshot_signed.clone(),
        vec![signature(&snapshot_signed, &root_kid, &root_kp)],
    );

    // --- timestamp pins snapshot ---
    let timestamp_signed = json!({
        "_type": "timestamp",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": FAR_FUTURE,
        "meta": { "snapshot.json": metafile(&snapshot_bytes, 1) },
    });
    let timestamp_bytes = envelope(
        timestamp_signed.clone(),
        vec![signature(&timestamp_signed, &root_kid, &root_kp)],
    );

    // --- root: one key authorizes all top-level roles ---
    let role = json!({ "keyids": [root_kid.clone()], "threshold": 1 });
    let root_signed = json!({
        "_type": "root",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": FAR_FUTURE,
        "consistent_snapshot": false,
        "keys": { root_kid.clone(): root_key },
        "roles": {
            "root": role, "timestamp": role,
            "snapshot": role, "targets": role,
        },
    });
    let root_bytes = envelope(
        root_signed.clone(),
        vec![signature(&root_signed, &root_kid, &root_kp)],
    );

    let mut repo = MemRepo::default();
    repo.metadata
        .insert("timestamp.json".into(), timestamp_bytes);
    repo.metadata.insert("snapshot.json".into(), snapshot_bytes);
    repo.metadata.insert("targets.json".into(), targets_bytes);
    repo.metadata
        .insert("delegated.json".into(), delegated_bytes);
    repo.targets.insert(target_path.into(), target_content);

    (repo, root_bytes)
}

#[tokio::test]
async fn full_refresh_resolves_delegated_target_and_caches() {
    let (repo, root_bytes) = build_repo();
    let store = Arc::new(MemoryStore::new());

    let mut updater = Updater::new(repo, &root_bytes)
        .unwrap()
        .with_store(Arc::clone(&store));
    updater
        .refresh(now())
        .await
        .expect("refresh should succeed");

    // The target lives only in the delegated role, so the top-level lookup
    // misses but the delegation walk finds it.
    assert!(updater.find_target("delegated/file.txt").is_none());
    let info = updater
        .get_targetinfo("delegated/file.txt", now())
        .await
        .unwrap()
        .expect("delegation walk should resolve the target");
    assert_eq!(info.length, b"hello from the delegated role".len() as u64);

    let bytes = updater
        .download_target("delegated/file.txt", now())
        .await
        .expect("download + verify should succeed");
    assert_eq!(bytes, b"hello from the delegated role");

    // Write-through cache populated.
    assert!(store.load("timestamp.json").is_some());
    assert!(store.load("delegated.json").is_some());
    assert!(store.load("targets/delegated/file.txt").is_some());

    // --- offline: re-verify entirely from the cache, no network ---
    let offline_repo = StoreRepository::new(Arc::clone(&store));
    let mut offline = Updater::new(offline_repo, &root_bytes).unwrap();
    offline
        .refresh(now())
        .await
        .expect("offline refresh from cache should re-verify");
    let offline_bytes = offline
        .download_target("delegated/file.txt", now())
        .await
        .expect("offline download from cache");
    assert_eq!(offline_bytes, b"hello from the delegated role");
}

#[tokio::test]
async fn size_limit_is_enforced() {
    let (repo, root_bytes) = build_repo();
    let config = UpdaterConfig {
        timestamp_max_length: 4, // far too small
        ..UpdaterConfig::default()
    };
    let mut updater = Updater::new(repo, &root_bytes).unwrap().with_config(config);
    let err = updater
        .refresh(now())
        .await
        .expect_err("oversized timestamp must be rejected");
    assert!(err.to_string().contains("exceeds"), "got: {err}");
}

#[tokio::test]
async fn expired_metadata_is_rejected() {
    let (repo, root_bytes) = build_repo();
    let mut updater = Updater::new(repo, &root_bytes).unwrap();
    // A `now` far past FAR_FUTURE makes every role expired.
    let future = "3999-01-01T00:00:00Z".parse().unwrap();
    let err = updater
        .refresh(future)
        .await
        .expect_err("expired metadata must be rejected");
    assert!(err.to_string().contains("expired"), "got: {err}");
}
