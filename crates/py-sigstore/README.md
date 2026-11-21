# py-sigstore

Python bindings for [sigstore-rust](https://github.com/prefix-dev/sigstore-rust) — fast Sigstore artifact signing and verification backed by a native Rust implementation.

> **Status: alpha.** The API may change before 1.0.
>
> **Naming:** the import name `sigstore` is the same as the PyPI package
> [`sigstore`](https://pypi.org/project/sigstore/) (sigstore-python). The two
> cannot be installed in the same environment. This package is a separate,
> Rust-backed implementation with its own (not drop-in compatible) API.

## Installation

```bash
pip install py-sigstore
```

## Usage

### Verification

```python
import sigstore as sr

bundle = sr.Bundle.from_json(open("artifact.sigstore.json").read())
policy = sr.Identity(
    identity="user@example.com",
    issuer="https://accounts.google.com",
)

verifier = sr.Verifier.production()
result = verifier.verify_artifact(open("artifact.bin", "rb").read(), bundle, policy)
print(result.identity, result.issuer, result.integrated_time)
```

Verification raises on failure and returns a `VerificationResult` on success.
Large files can be verified (or signed) from a precomputed digest with
`sr.Hashed`:

```python
import hashlib
digest = sr.Hashed(hashlib.sha256(data).digest())   # sha256 / sha384 / sha512
verifier.verify_artifact(digest, bundle, policy)
```

`Identity` also accepts `skip_sct=True` (trust domains without public CT SCTs,
such as GitHub's attestation instance) and the **unsafe** `skip_tlog_unsafe` /
`skip_certificate_chain` options.

### Signing (CI / ambient OIDC)

```python
import sigstore as sr

token = sr.IdentityToken.detect_ambient()
signer = sr.Signer.production(token)
bundle = signer.sign_artifact(open("artifact.bin", "rb").read())

with open("artifact.sigstore.json", "w") as f:
    f.write(bundle.to_json())
```

### Attestations

```python
bundle = signer.sign_attestation(
    "https://slsa.dev/provenance/v1",
    {"buildDefinition": {}},                       # predicate (dict or JSON text)
    [("artifact.bin", {"sha256": sha256_hex})],    # subjects
)
payload_type, payload = verifier.verify_dsse(artifact_bytes, bundle, policy)
```

### Errors

All exceptions derive from `sigstore.SigstoreError`:

| Exception | Raised for |
|---|---|
| `VerificationError` | any verification failure; subclasses `IdentityMismatchError`, `SignatureInvalidError`, `ArtifactMismatchError`, `CertificateError`, `TransparencyLogError`, `TimestampError`, `UnsupportedAlgorithmError` |
| `SigningError` | any signing failure; subclasses `SigningConfigError`, `RekorError` / `FulcioError` (with `.status`), `TsaError` |
| `BundleError` | unparseable or invalid bundle |
| `TrustedRootError` | trust root problems; subclass `TufError` |
| `IdentityTokenError` | invalid, expired or undetectable OIDC token |

The underlying Rust error chain is available as `__cause__`.

### One-shot convenience API

```python
import sigstore as sr

# Verify
sr.verify(artifact_bytes, bundle_json_str, identity="user@example.com",
          issuer="https://accounts.google.com")

# Sign (detects ambient OIDC token automatically)
bundle = sr.sign(artifact_bytes)
```

## License

Apache-2.0
