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
    IdentityMismatchError as IdentityMismatchError,
    SignatureInvalidError as SignatureInvalidError,
    ArtifactMismatchError as ArtifactMismatchError,
    CertificateError as CertificateError,
    TransparencyLogError as TransparencyLogError,
    TimestampError as TimestampError,
    UnsupportedAlgorithmError as UnsupportedAlgorithmError,
    SigningConfigError as SigningConfigError,
    RekorError as RekorError,
    FulcioError as FulcioError,
    TsaError as TsaError,
    TufError as TufError,
)

__all__ = [
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
    "Bundle",
    "TrustedRoot",
    "Identity",
    "Verifier",
    "IdentityToken",
    "Signer",
    "verify",
    "sign",
]
