# sigstore-python Rekor v2 fixtures

These fixtures are copied from `sigstore/sigstore-python` commit
[`71b63df1aea910fbfe5ba0fb1dc1199a27f56b25`](https://github.com/sigstore/sigstore-python/tree/71b63df1aea910fbfe5ba0fb1dc1199a27f56b25/test/assets):

- [`staging-rekor-v2.txt`](https://github.com/sigstore/sigstore-python/blob/71b63df1aea910fbfe5ba0fb1dc1199a27f56b25/test/assets/staging-rekor-v2.txt)
- [`staging-rekor-v2.txt.sigstore.json`](https://github.com/sigstore/sigstore-python/blob/71b63df1aea910fbfe5ba0fb1dc1199a27f56b25/test/assets/staging-rekor-v2.txt.sigstore.json)
- [`a.dsse.staging-rekor-v2.txt.sigstore.json`](https://github.com/sigstore/sigstore-python/blob/71b63df1aea910fbfe5ba0fb1dc1199a27f56b25/test/assets/a.dsse.staging-rekor-v2.txt.sigstore.json)

They are distributed under sigstore-python's Apache-2.0 license. They exercise
both message-signature and DSSE-as-hashedrekord Rekor v2 verification. The DSSE
fixture is verified by its subject digest because the original artifact is not
part of the upstream fixture set.
