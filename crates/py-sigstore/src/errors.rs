//! Python exception hierarchy and mapping from the Rust error types.
//!
//! Hierarchy (all derive from `SigstoreError`)::
//!
//!     SigstoreError
//!     ├── VerificationError
//!     │   ├── IdentityMismatchError        identity or issuer policy not met
//!     │   ├── SignatureInvalidError
//!     │   ├── ArtifactMismatchError        bundle does not describe the artifact
//!     │   ├── CertificateError             chain, validity period, SCT
//!     │   ├── TransparencyLogError         inclusion proof, checkpoint, SET, ...
//!     │   ├── TimestampError               RFC 3161 timestamps
//!     │   └── UnsupportedAlgorithmError
//!     ├── SigningError
//!     │   ├── SigningConfigError           invalid / unsatisfiable configuration
//!     │   ├── RekorError                   has `.status` (HTTP status or None)
//!     │   ├── FulcioError                  has `.status` (HTTP status or None)
//!     │   └── TsaError
//!     ├── BundleError
//!     ├── TrustedRootError
//!     │   └── TufError
//!     └── IdentityTokenError
//!
//! Mapped errors keep the Rust `Error::source()` chain as Python
//! `__cause__`.

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use std::error::Error as StdError;

macro_rules! exceptions {
    ($($name:ident : $base:ident = $doc:literal;)+) => {
        $(
            pyo3::create_exception!(sigstore, $name, $base, $doc);
        )+

        /// Register every exception class on the extension module.
        pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
            m.add("SigstoreError", m.py().get_type::<SigstoreError>())?;
            $(
                m.add(stringify!($name), m.py().get_type::<$name>())?;
            )+
            Ok(())
        }
    };
}

pyo3::create_exception!(
    sigstore,
    SigstoreError,
    PyException,
    "Base exception for all py-sigstore errors."
);

exceptions! {
    VerificationError: SigstoreError = "Raised when artifact or bundle verification fails.";
    SigningError: SigstoreError = "Raised when artifact signing fails.";
    BundleError: SigstoreError = "Raised when a Sigstore bundle cannot be parsed or is structurally invalid.";
    TrustedRootError: SigstoreError = "Raised when a TrustedRoot cannot be loaded, fetched, or parsed.";
    IdentityTokenError: SigstoreError = "Raised when an OIDC identity token is invalid, expired, or cannot be detected.";

    IdentityMismatchError: VerificationError = "Raised when the signer identity or OIDC issuer does not match the policy.";
    SignatureInvalidError: VerificationError = "Raised when a signature does not verify.";
    ArtifactMismatchError: VerificationError = "Raised when the bundle does not describe the supplied artifact.";
    CertificateError: VerificationError = "Raised when the signing certificate, its chain or its SCT is invalid.";
    TransparencyLogError: VerificationError = "Raised when transparency log evidence (inclusion proof, checkpoint, promise) is invalid.";
    TimestampError: VerificationError = "Raised when an RFC 3161 timestamp is invalid or missing.";
    UnsupportedAlgorithmError: VerificationError = "Raised when a key or signature algorithm is not supported.";

    SigningConfigError: SigningError = "Raised when the signing configuration is invalid or cannot be satisfied.";
    RekorError: SigningError = "Raised when Rekor rejects or fails a request. ``status`` holds the HTTP status, if any.";
    FulcioError: SigningError = "Raised when Fulcio rejects or fails a request. ``status`` holds the HTTP status, if any.";
    TsaError: SigningError = "Raised when the timestamp authority request fails.";

    TufError: TrustedRootError = "Raised when fetching or validating trust material through TUF fails.";
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Turn an error's `source()` chain into a chain of Python exceptions.
fn cause_chain(err: &(dyn StdError + 'static)) -> PyErr {
    let py_err = PyException::new_err(err.to_string());
    if let Some(src) = err.source() {
        let cause = cause_chain(src);
        Python::attach(|py| py_err.set_cause(py, Some(cause)));
    }
    py_err
}

/// Attach the Rust error's source chain as `__cause__`.
fn with_cause(py_err: PyErr, err: &(dyn StdError + 'static)) -> PyErr {
    if let Some(src) = err.source() {
        let cause = cause_chain(src);
        Python::attach(|py| py_err.set_cause(py, Some(cause)));
    }
    py_err
}

/// Set a `status` attribute (HTTP status code or `None`) on the exception.
fn with_status(py_err: PyErr, status: Option<u16>) -> PyErr {
    Python::attach(|py| {
        // Setting an attribute on a freshly-created exception cannot
        // reasonably fail; ignore the result rather than mask the real error.
        let _ = py_err.value(py).setattr("status", status);
    });
    py_err
}

// ---------------------------------------------------------------------------
// Rust → Python mappings
// ---------------------------------------------------------------------------

/// Map a `sigstore_verify` error to the most specific Python exception.
pub fn verify_error(e: sigstore_verify::Error) -> PyErr {
    use sigstore_verify::Error as E;
    let msg = e.to_string();
    let py_err = match &e {
        E::IdentityMismatch { .. } | E::IssuerMismatch { .. } => IdentityMismatchError::new_err(msg),
        E::SignatureInvalid(_) => SignatureInvalidError::new_err(msg),
        E::ArtifactMismatch(_) => ArtifactMismatchError::new_err(msg),
        E::Certificate(_) => CertificateError::new_err(msg),
        E::TransparencyLog(_) => TransparencyLogError::new_err(msg),
        E::Timestamp(_) => TimestampError::new_err(msg),
        E::Crypto(sigstore_verify::crypto::Error::UnsupportedAlgorithm(_)) => {
            UnsupportedAlgorithmError::new_err(msg)
        }
        E::InvalidTrustRoot(_) | E::TrustRoot(_) | E::TrustedCertificate(_) => {
            TrustedRootError::new_err(msg)
        }
        _ => VerificationError::new_err(msg),
    };
    with_cause(py_err, &e)
}

/// Map a `sigstore_sign` error to the most specific Python exception.
pub fn sign_error(e: sigstore_sign::Error) -> PyErr {
    use sigstore_sign::Error as E;
    let msg = e.to_string();
    let py_err = match &e {
        E::Config(_) => SigningConfigError::new_err(msg),
        E::Rekor(r) => {
            let status = match r {
                sigstore_sign::rekor::Error::Status { status, .. } => Some(*status),
                _ => None,
            };
            with_status(RekorError::new_err(msg), status)
        }
        E::Fulcio(f) => {
            let status = match f {
                sigstore_sign::fulcio::Error::Status { status, .. } => Some(*status),
                _ => None,
            };
            with_status(FulcioError::new_err(msg), status)
        }
        E::Tsa(_) => TsaError::new_err(msg),
        E::Oidc(_) => IdentityTokenError::new_err(msg),
        E::TrustRoot(t) => return trust_root_error_ref(t, msg, &e),
        _ => SigningError::new_err(msg),
    };
    with_cause(py_err, &e)
}

fn trust_root_error_ref(
    t: &sigstore_trust_root::Error,
    msg: String,
    outer: &(dyn StdError + 'static),
) -> PyErr {
    let py_err = match t {
        sigstore_trust_root::Error::Tuf(_) => TufError::new_err(msg),
        _ => TrustedRootError::new_err(msg),
    };
    with_cause(py_err, outer)
}

/// Map a `sigstore_trust_root` error to `TufError` or `TrustedRootError`.
pub fn trust_root_error(e: sigstore_trust_root::Error) -> PyErr {
    let msg = e.to_string();
    trust_root_error_ref(&e, msg, &e)
}

/// Map a `sigstore_types` error (bundle / JSON parsing) to `BundleError`.
pub fn bundle_error(e: sigstore_types::Error) -> PyErr {
    with_cause(BundleError::new_err(e.to_string()), &e)
}

/// Map a `sigstore_oidc` error to `IdentityTokenError`.
pub fn token_error(e: sigstore_oidc::Error) -> PyErr {
    with_cause(IdentityTokenError::new_err(e.to_string()), &e)
}
