# `sigstore-crypto` test data

All certificates are real and public, and only reproduced here as PEM so
`x509.rs` can decode them without depending on another crate's fixtures.

## `fulcio_github_actions_cert.pem`

The signing certificate of
`crates/sigstore-verify/test_data/bundles/conda-attestation.sigstore.json`,
issued by Fulcio to a GitHub Actions workflow in the `prefix-dev/sigstore-example`
repository. It populates the CI claim arc `1.3.6.1.4.1.57264.1` up to `.1.22`,
including the deprecated extensions `.1.2` to `.1.6`, so it exercises both the
claims that are parsed and the ones that are skipped.

To regenerate it from the bundle:

```console
jq -r '.verificationMaterial.certificate.rawBytes' \
  crates/sigstore-verify/test_data/bundles/conda-attestation.sigstore.json \
  | base64 -d | openssl x509 -inform der -out fulcio_github_actions_cert.pem
```

## `fulcio_github_actions_environment_cert.pem`

A signing certificate from a conda publish attestation of the public
[`pavelzw/skill-forge`](https://github.com/pavelzw/skill-forge) repository,
issued to a job that ran in the `upload` deployment environment. Unlike the
fixture above it therefore carries `.1.23` (the environment) and `.1.24` (the
raw token `sub`), which are the two most recent claims of the arc and the only
place the environment appears — the SAN identity is the workflow ref.

To regenerate it from the published attestation:

```console
curl -sL https://prefix.dev/skill-forge/noarch/agent-skill-conda-forge-0.0.21-h4616a5c_0.conda.sigs.f2ca226e600751167a29953233ff121c4dcf6e391da9ce0ec8fb621379fe73a5 \
  | jq -r '.[0].verificationMaterial.certificate.rawBytes' \
  | base64 -d \
  | openssl x509 -inform der -out fulcio_github_actions_environment_cert.pem
```

## `sigstore_intermediate_cert.pem`

The `sigstore-intermediate` certificate of the public good instance, taken from
the embedded trusted root in `crates/sigstore-trust-root/src/trusted_root.json`.
It was not issued to a workload and therefore carries no CI claims, which is the
case a relying party sees for any certificate outside a CI flow.

To regenerate it from the trusted root:

```console
jq -r '.certificateAuthorities[1].certChain.certificates[0].rawBytes' \
  crates/sigstore-trust-root/src/trusted_root.json \
  | base64 -d | openssl x509 -inform der -out sigstore_intermediate_cert.pem
```
