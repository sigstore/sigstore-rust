# py-sigstore-rust

Python bindings for [sigstore-rust](https://github.com/prefix-dev/sigstore-rust) — fast Sigstore artifact signing and verification backed by a native Rust implementation.

## Installation

```bash
pip install py-sigstore-rust
```

## Usage

### Verification

```python
import py_sigstore_rust as sr

bundle = sr.Bundle.from_json(open("artifact.sigstore.json").read())
policy = sr.Identity(
    identity="user@example.com",
    issuer="https://accounts.google.com",
)

verifier = sr.Verifier.production()
verifier.verify_artifact(open("artifact.bin", "rb").read(), bundle, policy)
```

### Signing (CI / ambient OIDC)

```python
import py_sigstore_rust as sr

token = sr.IdentityToken.detect_ambient()
signer = sr.Signer.production(token)
bundle = signer.sign_artifact(open("artifact.bin", "rb").read())

with open("artifact.sigstore.json", "w") as f:
    f.write(bundle.to_json())
```

### One-shot convenience API

```python
import py_sigstore_rust as sr

# Verify
sr.verify(artifact_bytes, bundle_json_str, identity="user@example.com",
          issuer="https://accounts.google.com")

# Sign (detects ambient OIDC token automatically)
bundle = sr.sign(artifact_bytes)
```

## License

Apache-2.0
