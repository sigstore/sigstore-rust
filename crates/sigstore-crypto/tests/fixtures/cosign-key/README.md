# cosign key fixtures (test only)

Key pairs written by `cosign generate-key-pair` (cosign v2.6.0), used to test
`sigstore_crypto::cosign_key` against cosign's real output. They protect
nothing and sign nothing outside these tests.

- `cosign.key` / `cosign.pub`: password `sigstore-rust-test`
- `empty/cosign.key` / `empty/cosign.pub`: empty password

Regenerate with `COSIGN_PASSWORD=<password> cosign generate-key-pair`.
