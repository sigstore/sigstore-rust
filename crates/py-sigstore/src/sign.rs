//! Python bindings for signing: `PySigner` and the module-level `sign()`
//! convenience function.

use crate::artifact::extract_artifact;
use crate::bundle::PyBundle;
use crate::errors::{sign_error, token_error, IdentityTokenError};
use crate::oidc::PyIdentityToken;
use crate::runtime::get_runtime;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods, gen_stub_pyfunction};
use sigstore_sign::{Attestation, Signer, SigningContext};

/// Build a signer for the given instance, fetching the signing config via TUF.
///
/// Releases the GIL during the network fetch.
fn build_signer(
    py: Python<'_>,
    token: sigstore_oidc::IdentityToken,
    staging: bool,
) -> PyResult<Signer> {
    if token.is_expired() {
        return Err(IdentityTokenError::new_err(
            "identity token is expired; obtain a fresh token before signing",
        ));
    }
    let ctx = py
        .detach(|| {
            get_runtime().block_on(async {
                if staging {
                    SigningContext::staging().await
                } else {
                    SigningContext::production().await
                }
            })
        })
        .map_err(sign_error)?;
    Ok(ctx.signer(token))
}


/// Convert a Python predicate (JSON text or a JSON-serializable object) to JSON.
fn predicate_to_json(py: Python<'_>, predicate: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    let text: String = if let Ok(s) = predicate.extract::<String>() {
        s
    } else if let Ok(b) = predicate.cast::<pyo3::types::PyBytes>() {
        String::from_utf8(b.as_bytes().to_vec())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("predicate is not UTF-8: {e}")))?
    } else {
        py.import("json")?.call_method1("dumps", (predicate,))?.extract()?
    };
    serde_json::from_str(&text)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid predicate JSON: {e}")))
}

/// Build an in-toto subject digest from an `{"sha256": hex, ...}` mapping.
fn subject_digest(
    digests: &std::collections::HashMap<String, String>,
) -> PyResult<sigstore_types::Digest> {
    use pyo3::exceptions::PyValueError;
    use sigstore_types::{Digest, Sha256Hash, Sha512Hash};

    let mut out: Option<Digest> = None;
    for (alg, hex) in digests {
        match alg.as_str() {
            "sha256" => {
                let h = Sha256Hash::from_hex(hex).map_err(|e| PyValueError::new_err(e.to_string()))?;
                match out.as_mut() {
                    Some(d) => d.sha256 = Some(h),
                    None => out = Some(Digest::sha256(h)),
                }
            }
            "sha512" => {
                let h = Sha512Hash::from_hex(hex).map_err(|e| PyValueError::new_err(e.to_string()))?;
                match out.as_mut() {
                    Some(d) => d.sha512 = Some(h),
                    None => out = Some(Digest::sha512(h)),
                }
            }
            other => {
                return Err(PyValueError::new_err(format!(
                    "unsupported subject digest algorithm {other:?}; expected sha256 or sha512"
                )))
            }
        }
    }
    out.ok_or_else(|| PyValueError::new_err("subject digest mapping is empty"))
}

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
#[pyclass(name = "Signer", module = "py_sigstore._internal")]
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
    /// Fetches the signing config via TUF (network request).
    ///
    /// Raises :exc:`IdentityTokenError` if the token is expired and
    /// :exc:`SigningError` if the signing config cannot be loaded.
    #[classmethod]
    fn production(cls: &Bound<'_, pyo3::types::PyType>, token: &PyIdentityToken) -> PyResult<Self> {
        let signer = build_signer(cls.py(), token.inner.clone(), false)?;
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
    fn staging(cls: &Bound<'_, pyo3::types::PyType>, token: &PyIdentityToken) -> PyResult<Self> {
        let signer = build_signer(cls.py(), token.inner.clone(), true)?;
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
    ///     input: The artifact to sign: raw ``bytes`` or a pre-computed
    ///            :class:`Hashed` digest.
    ///
    /// Returns:
    ///     A :class:`Bundle` containing the signature and verification material.
    ///
    /// Raises :exc:`SigningError` on any failure.
    fn sign_artifact(&self, py: Python<'_>, input: &Bound<'_, PyAny>) -> PyResult<PyBundle> {
        // Extract before detach() — Bound is !Send and cannot be captured by
        // the Ungil closure.
        let data = extract_artifact(input)?;
        py.detach(|| get_runtime().block_on(self.inner.sign(data.as_artifact())))
            .map(|inner| PyBundle { inner })
            .map_err(sign_error)
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
            .map_err(sign_error)
    }

    /// Sign an in-toto attestation and return a Sigstore bundle.
    ///
    /// Builds the in-toto statement from the arguments, wraps it in a DSSE
    /// envelope and signs it.
    ///
    /// Args:
    ///     predicate_type: The predicate type URI, e.g.
    ///         ``"https://slsa.dev/provenance/v1"``.
    ///     predicate:      The predicate: a JSON ``str``/``bytes`` document, or
    ///         any JSON-serializable Python object (``dict``, ``list``, ...).
    ///     subjects:       A list of ``(name, digest)`` pairs, where ``digest``
    ///         is a mapping of algorithm to hex digest
    ///         (``{"sha256": "..."}``; ``sha512`` is also accepted).
    ///
    /// Raises:
    ///     ValueError:   If a subject digest or the predicate is malformed.
    ///     SigningError: On any signing failure.
    fn sign_attestation(
        &self,
        py: Python<'_>,
        predicate_type: &str,
        predicate: &Bound<'_, PyAny>,
        subjects: Vec<(String, std::collections::HashMap<String, String>)>,
    ) -> PyResult<PyBundle> {
        let predicate_value = predicate_to_json(py, predicate)?;
        let mut attestation = Attestation::new(predicate_type, predicate_value);
        for (name, digests) in subjects {
            attestation = attestation.add_subject(name, subject_digest(&digests)?);
        }
        py.detach(|| get_runtime().block_on(self.inner.sign_attestation(attestation)))
            .map(|inner| PyBundle { inner })
            .map_err(sign_error)
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
///     input:   The artifact: raw ``bytes`` or a :class:`Hashed` digest.
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
#[gen_stub_pyfunction(module = "py_sigstore._internal")]
#[pyfunction]
#[pyo3(signature = (input, token=None, *, staging=false))]
pub fn py_sign(
    py: Python<'_>,
    input: &Bound<'_, PyAny>,
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
                .map_err(token_error)?
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "token must be an IdentityToken object or a JWT string",
            ));
        }
    } else {
        // Attempt ambient detection
        let maybe = py
            .detach(|| get_runtime().block_on(IdentityToken::detect_ambient()))
            .map_err(token_error)?;
        maybe.ok_or_else(|| {
            IdentityTokenError::new_err(
                "No ambient OIDC credential found and no token provided. \
                 Pass token= or run in a supported CI environment.",
            )
        })?
    };

    let signer = build_signer(py, identity_token, staging)?;

    // Extract before detach() — Bound is !Send.
    let input_data = extract_artifact(input)?;
    py.detach(|| get_runtime().block_on(signer.sign(input_data.as_artifact())))
        .map(|inner| PyBundle { inner })
        .map_err(sign_error)
}
