"""
Type stubs for sigstore public API.

Classes and functions come from the compiled _internal extension;
exceptions are defined here because pyo3::create_exception! cannot
be auto-stubbed with dotted module paths.
"""

from sigstore._internal import (
    Bundle as Bundle,
    TrustedRoot as TrustedRoot,
    Identity as Identity,
    Verifier as Verifier,
    IdentityToken as IdentityToken,
    Signer as Signer,
    py_verify as verify,
    py_sign as sign,
)
from sigstore._exceptions import (
    SigstoreError as SigstoreError,
    VerificationError as VerificationError,
    SigningError as SigningError,
    BundleError as BundleError,
    TrustedRootError as TrustedRootError,
    IdentityTokenError as IdentityTokenError,
)

__all__ = [
    "SigstoreError",
    "VerificationError",
    "SigningError",
    "BundleError",
    "TrustedRootError",
    "IdentityTokenError",
    "Bundle",
    "TrustedRoot",
    "Identity",
    "Verifier",
    "IdentityToken",
    "Signer",
    "verify",
    "sign",
]
