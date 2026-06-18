"""
Type stubs for py_sigstore_rust public API.

Classes and functions come from the compiled _internal extension;
exceptions are defined here because pyo3::create_exception! cannot
be auto-stubbed with dotted module paths.
"""

from py_sigstore_rust._internal import (
    Bundle as Bundle,
    TrustedRoot as TrustedRoot,
    Identity as Identity,
    Verifier as Verifier,
    IdentityToken as IdentityToken,
    Signer as Signer,
    verify as verify,
    sign as sign,
)
from py_sigstore_rust._exceptions import (
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
