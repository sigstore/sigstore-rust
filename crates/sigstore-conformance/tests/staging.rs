use std::path::Path;
use std::process::Command;

#[test]
fn verify_bundle_selects_instance_unless_a_root_is_explicit() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (bundle, identity, issuer, artifact, bundle_is_staging) in [
        (
            "crates/sigstore-verify/test_data/bundles/cosign-v3-blob.sigstore.json",
            "w.vollprecht@gmail.com",
            "https://github.com/login/oauth",
            "crates/sigstore-verify/test_data/bundles/cosign-v3-blob.txt",
            false,
        ),
        (
            "crates/sigstore-verify/test_data/sct-multi-intermediate/staging_bundle.sigstore.json",
            "https://github.com/sigstore/root-signing-staging/.github/workflows/custom-test.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            true,
        ),
    ] {
        for (staging, custom_root, root_is_staging) in [
            (false, None, false),
            (true, None, true),
            (false, Some("crates/sigstore-trust-root/src/trusted_root_staging.json"), true),
            (true, Some("crates/sigstore-trust-root/src/trusted_root.json"), false),
        ] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_conformance"));
            command.current_dir(&workspace).args([
                "verify-bundle",
                "--bundle", bundle,
                "--certificate-identity", identity,
                "--certificate-oidc-issuer", issuer,
                artifact,
            ]);
            if staging {
                command.arg("--staging");
            }
            if let Some(root) = custom_root {
                command.args(["--trusted-root", root]);
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.success(),
                bundle_is_staging == root_is_staging,
                "bundle={bundle}, staging={staging}, root={custom_root:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
