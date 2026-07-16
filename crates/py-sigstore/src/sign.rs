//! Python bindings for signing: `PySigner` and the module-level `sign()`
//! convenience function.

use crate::bundle::PyBundle;
use crate::errors::{IdentityTokenError, SigningError};
use crate::oidc::PyIdentityToken;
use crate::runtime::get_runtime;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods, gen_stub_pyfunction};
use sigstore_sign::{Signer, SigningContext};

// ---------------------------------------------------------------------------
// PySigner
// ---------------------------------------------------------------------------

/// Signs artifacts using the Sigstore infrastructure.
///
/// Construct via :meth:`production` or :meth:`staging`, providing an
/// :class:`IdentityToken`. The token is used to obtain a short-lived Fulcio
/// signing certificate; the resulting :class:`Bundle` includes the
/// signature, certificate, and a Rekor transparency log entry.
///
/// Example::
///
///     token = IdentityToken.detect_ambient()
///     signer = Signer.production(token)
///
///     # Sign raw artifact bytes:
///     bundle = signer.sign_artifact(open("artifact.bin", "rb").read())
///
///     # Sign an in-toto DSSE statement:
///     bundle = signer.sign_dsse(statement_json_bytes,
///                               "application/vnd.in-toto+json")
#[gen_stub_pyclass]
#[pyclass(name = "Signer", module = "sigstore._internal")]
pub struct PySigner {
    /// The inner Rust signer. Wrapped in a Box so PySigner is `Send`.
    inner: Box<Signer>,
}

#[gen_stub_pymethods]
#[pymethods]
impl PySigner {
    /// Create a signer using the Sigstore public-good infrastructure.
    ///
    /// Args:
    ///     token: An :class:`IdentityToken` for authentication with Fulcio.
    ///
    /// Raises :exc:`IdentityTokenError` if the token is expired.
    #[classmethod]
    fn production(_cls: &Bound<'_, pyo3::types::PyType>, token: &PyIdentityToken) -> PyResult<Self> {
        if token.inner.is_expired() {
            return Err(IdentityTokenError::new_err(
                "Identity token is expired. Obtain a fresh token before signing.",
            ));
        }
        let ctx = SigningContext::production();
        let signer = ctx.signer(token.inner.clone());
        Ok(PySigner {
            inner: Box::new(signer),
        })
    }

    /// Create a signer using the Sigstore staging infrastructure.
    ///
    /// For testing only. Bundles produced with the staging signer cannot be
    /// verified against the production trusted root.
    ///
    /// Args:
    ///     token: An :class:`IdentityToken` for authentication.
    ///
    /// Raises :exc:`IdentityTokenError` if the token is expired.
    #[classmethod]
    fn staging(_cls: &Bound<'_, pyo3::types::PyType>, token: &PyIdentityToken) -> PyResult<Self> {
        if token.inner.is_expired() {
            return Err(IdentityTokenError::new_err(
                "Identity token is expired. Obtain a fresh token before signing.",
            ));
        }
        let ctx = SigningContext::staging();
        let signer = ctx.signer(token.inner.clone());
        Ok(PySigner {
            inner: Box::new(signer),
        })
    }

    /// Sign raw artifact bytes and return a Sigstore bundle.
    ///
    /// Contacts Fulcio (for a signing certificate) and Rekor (to record the
    /// signature in the transparency log). Releases the GIL during network
    /// I/O.
    ///
    /// Args:
    ///     input: The raw artifact bytes to sign.
    ///
    /// Returns:
    ///     A :class:`Bundle` containing the signature and verification material.
    ///
    /// Raises :exc:`SigningError` on any failure.
    fn sign_artifact(&self, py: Python<'_>, input: &Bound<'_, pyo3::types::PyBytes>) -> PyResult<PyBundle> {
        // Extract the slice before detach() — Bound<'_, PyBytes> is !Send and
        // cannot be captured by the Ungil closure.
        let data = input.as_bytes().to_vec();
        py.detach(|| get_runtime().block_on(self.inner.sign(&data)))
            .map(|inner| PyBundle { inner })
            .map_err(|e| SigningError::new_err(e.to_string()))
    }

    /// Sign an in-toto DSSE statement and return a Sigstore bundle.
    ///
    /// The ``payload`` must be a valid JSON-serialized in-toto statement.
    /// ``payload_type`` **must** be ``"application/vnd.in-toto+json"`` — this
    /// is the only value currently supported. Passing any other string raises
    /// :exc:`ValueError`.
    ///
    /// Args:
    ///     payload:      The raw statement bytes (JSON-encoded in-toto statement).
    ///     payload_type: The DSSE payload type URI. Currently only
    ///                   ``"application/vnd.in-toto+json"`` is accepted.
    ///
    /// Returns:
    ///     A :class:`Bundle` containing the DSSE envelope and verification material.
    ///
    /// Raises :exc:`SigningError` on any failure.
    fn sign_dsse(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, pyo3::types::PyBytes>,
        payload_type: &str,
    ) -> PyResult<PyBundle> {
        // sign_raw_statement validates that it's a valid in-toto statement
        // and wraps it in a DSSE envelope with the standard payload type.
        // For custom payload types we'd need to build a lower-level API;
        // for now this accepts only "application/vnd.in-toto+json".
        if payload_type != "application/vnd.in-toto+json" {
            // Wrong argument value is a programming error, not a signing failure.
            // Use ValueError rather than SigningError to match Python conventions.
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unsupported payload_type {payload_type:?}. \
                 Only \"application/vnd.in-toto+json\" is supported in this release."
            )));
        }
        // Extract before detach() — Bound is !Send.
        let payload_data = payload.as_bytes().to_vec();
        py.detach(|| get_runtime().block_on(self.inner.sign_raw_statement(&payload_data)))
            .map(|inner| PyBundle { inner })
            .map_err(|e| SigningError::new_err(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Module-level sign() convenience function
// ---------------------------------------------------------------------------

/// One-shot artifact signing.
///
/// A convenience wrapper that handles token detection and signer construction
/// automatically. For multiple signing operations, prefer constructing a
/// :class:`Signer` once and reusing it.
///
/// Args:
///     input:   The raw artifact bytes to sign.
///     token:   An :class:`IdentityToken` or a raw JWT string. If ``None``,
///              ambient OIDC detection is attempted (suitable for CI).
///     staging: If ``True``, use the Sigstore staging infrastructure instead
///              of production. Default: ``False``.
///
/// Returns:
///     A :class:`Bundle` containing the signature and verification material.
///
/// Raises:
///     :exc:`SigningError`:        If signing fails.
///     :exc:`IdentityTokenError`:  If no token is provided and ambient
///                                 detection fails, or if the token is expired.
#[gen_stub_pyfunction(module = "sigstore._internal")]
#[pyfunction]
#[pyo3(signature = (input, token=None, *, staging=false))]
pub fn py_sign(
    py: Python<'_>,
    input: &Bound<'_, pyo3::types::PyBytes>,
    token: Option<&Bound<'_, PyAny>>,
    staging: bool,
) -> PyResult<PyBundle> {
    use sigstore_oidc::IdentityToken;

    // Resolve token: IdentityToken object | JWT string | ambient detection
    let identity_token: IdentityToken = if let Some(t) = token {
        if let Ok(py_token) = t.extract::<PyRef<PyIdentityToken>>() {
            py_token.inner.clone()
        } else if let Ok(jwt_str) = t.extract::<String>() {
            IdentityToken::from_jwt(&jwt_str)
                .map_err(|e| IdentityTokenError::new_err(e.to_string()))?
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "token must be an IdentityToken object or a JWT string",
            ));
        }
    } else {
        // Attempt ambient detection
        let maybe = py
            .detach(|| get_runtime().block_on(IdentityToken::detect_ambient()))
            .map_err(|e| IdentityTokenError::new_err(e.to_string()))?;
        maybe.ok_or_else(|| {
            IdentityTokenError::new_err(
                "No ambient OIDC credential found and no token provided. \
                 Pass token= or run in a supported CI environment.",
            )
        })?
    };

    if identity_token.is_expired() {
        return Err(IdentityTokenError::new_err(
            "Identity token is expired. Obtain a fresh token before signing.",
        ));
    }

    let ctx = if staging {
        SigningContext::staging()
    } else {
        SigningContext::production()
    };
    let signer = ctx.signer(identity_token);

    // Extract before detach() — Bound is !Send.
    let input_data = input.as_bytes().to_vec();
    py.detach(|| get_runtime().block_on(signer.sign(&input_data)))
        .map(|inner| PyBundle { inner })
        .map_err(|e| SigningError::new_err(e.to_string()))
}
