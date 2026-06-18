//! Python exception hierarchy for py-sigstore-rust.
//!
//! All exceptions derive from `SigstoreError` so callers can catch the base
//! class or a specific subclass.
//!
//! ```python
//! import py_sigstore_rust as sr
//!
//! try:
//!     sr.verify(artifact, bundle, identity="...", issuer="...")
//! except sr.VerificationError as e:
//!     print(f"Verification failed: {e}")
//! except sr.SigstoreError as e:
//!     print(f"Sigstore error: {e}")
//! ```

use pyo3::exceptions::PyException;
use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// Exception class declarations
//
// Using plain pyo3::create_exception! (not the stub-gen wrapper) because
// pyo3_stub_gen::create_exception! uses `stringify!($module)` internally,
// which cannot handle dotted module paths like "py_sigstore_rust._internal".
// The exceptions are documented in the hand-written _internal.pyi stub instead.
// ---------------------------------------------------------------------------

pyo3::create_exception!(
    py_sigstore_rust,
    SigstoreError,
    PyException,
    "Base exception for all py-sigstore-rust errors."
);

pyo3::create_exception!(
    py_sigstore_rust,
    VerificationError,
    SigstoreError,
    "Raised when artifact or bundle verification fails."
);

pyo3::create_exception!(
    py_sigstore_rust,
    SigningError,
    SigstoreError,
    "Raised when artifact signing fails."
);

pyo3::create_exception!(
    py_sigstore_rust,
    BundleError,
    SigstoreError,
    "Raised when a Sigstore bundle cannot be parsed or is structurally invalid."
);

pyo3::create_exception!(
    py_sigstore_rust,
    TrustedRootError,
    SigstoreError,
    "Raised when a TrustedRoot cannot be loaded, fetched, or parsed."
);

pyo3::create_exception!(
    py_sigstore_rust,
    IdentityTokenError,
    SigstoreError,
    "Raised when an OIDC identity token is invalid, expired, or cannot be detected."
);

// ---------------------------------------------------------------------------
// Register all exceptions into a module
// ---------------------------------------------------------------------------

/// Add all exception classes to the given Python module.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SigstoreError", m.py().get_type::<SigstoreError>())?;
    m.add("VerificationError", m.py().get_type::<VerificationError>())?;
    m.add("SigningError", m.py().get_type::<SigningError>())?;
    m.add("BundleError", m.py().get_type::<BundleError>())?;
    m.add("TrustedRootError", m.py().get_type::<TrustedRootError>())?;
    m.add(
        "IdentityTokenError",
        m.py().get_type::<IdentityTokenError>(),
    )?;
    Ok(())
}
