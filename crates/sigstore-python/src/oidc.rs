//! Python binding for `sigstore_oidc::IdentityToken`.

use crate::errors::IdentityTokenError;
use crate::runtime::get_runtime;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};
use sigstore_oidc::IdentityToken;

/// An OIDC identity token used to authenticate with Fulcio during signing.
///
/// Obtain a token via :meth:`detect_ambient` (for CI environments like
/// GitHub Actions) or :meth:`from_jwt` (if you already have a raw JWT).
///
/// Example (GitHub Actions)::
///
///     token = IdentityToken.detect_ambient()
///     signer = Signer.production(token)
///     bundle = signer.sign_artifact(open("artifact.bin", "rb").read())
///
/// Example (raw JWT)::
///
///     token = IdentityToken.from_jwt(os.environ["SIGSTORE_TOKEN"])
#[gen_stub_pyclass]
#[pyclass(name = "IdentityToken", module = "py_sigstore_rust._internal")]
pub struct PyIdentityToken {
    pub inner: IdentityToken,
}

#[gen_stub_pymethods]
#[pymethods]
impl PyIdentityToken {
    /// Parse an OIDC identity token from a raw JWT string.
    ///
    /// Args:
    ///     token: A JWT string in ``header.payload.signature`` format.
    ///
    /// Raises :exc:`IdentityTokenError` if the JWT is malformed.
    #[classmethod]
    fn from_jwt(_cls: &Bound<'_, pyo3::types::PyType>, token: &str) -> PyResult<Self> {
        IdentityToken::from_jwt(token)
            .map(|inner| PyIdentityToken { inner })
            .map_err(|e| IdentityTokenError::new_err(e.to_string()))
    }

    /// Detect an ambient OIDC credential from the current environment.
    ///
    /// Checks for well-known CI/CD environment variables (GitHub Actions
    /// ``ACTIONS_ID_TOKEN_REQUEST_*``, GitLab CI, Buildkite, etc.).
    ///
    /// Raises :exc:`IdentityTokenError` if no ambient credential is available
    /// or if detection fails.
    #[classmethod]
    fn detect_ambient(cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        let py = cls.py();
        let maybe_token = py
            .detach(|| get_runtime().block_on(IdentityToken::detect_ambient()))
            .map_err(|e| IdentityTokenError::new_err(e.to_string()))?;

        maybe_token
            .map(|inner| PyIdentityToken { inner })
            .ok_or_else(|| {
                IdentityTokenError::new_err(
                    "No ambient OIDC credential found. \
                     Set ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN \
                     (GitHub Actions), or provide a token via IdentityToken.from_jwt().",
                )
            })
    }

    /// The OIDC issuer URL (e.g. ``"https://token.actions.githubusercontent.com"``).
    #[getter]
    fn issuer(&self) -> &str {
        self.inner.issuer()
    }

    /// The token subject (user ID or workflow identifier).
    #[getter]
    fn subject(&self) -> &str {
        self.inner.subject()
    }

    /// The signer identity string.
    ///
    /// Returns the email address if present in the token, otherwise the
    /// subject. This is the value matched against :class:`Identity`.
    #[getter]
    fn identity(&self) -> &str {
        self.inner.identity()
    }

    /// Whether the token is expired.
    #[getter]
    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    fn __repr__(&self) -> String {
        format!(
            "IdentityToken(identity={:?}, issuer={:?}, expired={})",
            self.inner.identity(),
            self.inner.issuer(),
            self.inner.is_expired(),
        )
    }
}
