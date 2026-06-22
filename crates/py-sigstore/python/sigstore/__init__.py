"""
py-sigstore: Python bindings for the sigstore-rust library.

Provides fast Sigstore artifact signing and verification backed by a
native Rust implementation.
"""

from sigstore._internal import (
    # Exceptions
    SigstoreError,
    VerificationError,
    SigningError,
    BundleError,
    TrustedRootError,
    IdentityTokenError,
    # Core types
    Bundle,
    TrustedRoot,
    Identity,
    Verifier,
    # Signing + OIDC
    IdentityToken,
    Signer,
    # Convenience functions (exported under cleaner public names)
    py_verify as verify,
    py_sign as sign,
)

__all__ = [
    # Exceptions
    "SigstoreError",
    "VerificationError",
    "SigningError",
    "BundleError",
    "TrustedRootError",
    "IdentityTokenError",
    # Core types
    "Bundle",
    "TrustedRoot",
    "Identity",
    "Verifier",
    # Signing + OIDC
    "IdentityToken",
    "Signer",
    # Convenience functions
    "verify",
    "sign",
]
