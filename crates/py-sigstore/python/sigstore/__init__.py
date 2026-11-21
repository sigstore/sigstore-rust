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
    IdentityMismatchError,
    SignatureInvalidError,
    ArtifactMismatchError,
    CertificateError,
    TransparencyLogError,
    TimestampError,
    UnsupportedAlgorithmError,
    SigningConfigError,
    RekorError,
    FulcioError,
    TsaError,
    TufError,
    # Core types
    Bundle,
    TrustedRoot,
    Identity,
    Verifier,
    VerificationResult,
    Hashed,
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
    "IdentityMismatchError",
    "SignatureInvalidError",
    "ArtifactMismatchError",
    "CertificateError",
    "TransparencyLogError",
    "TimestampError",
    "UnsupportedAlgorithmError",
    "SigningConfigError",
    "RekorError",
    "FulcioError",
    "TsaError",
    "TufError",
    # Core types
    "Bundle",
    "TrustedRoot",
    "Identity",
    "Verifier",
    "VerificationResult",
    "Hashed",
    # Signing + OIDC
    "IdentityToken",
    "Signer",
    # Convenience functions
    "verify",
    "sign",
]
