//! Python bindings for verification: `PyIdentity`, `PyVerifier`, and the
//! module-level `verify()` convenience function.

use crate::bundle::PyBundle;
use crate::errors::{BundleError, TrustedRootError, VerificationError};
use crate::runtime::get_runtime;
use crate::trust_root::PyTrustedRoot;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods, gen_stub_pyfunction};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::Artifact;
use sigstore_verify::{VerificationPolicy, Verifier};

// ---------------------------------------------------------------------------
// PyIdentity — wraps VerificationPolicy
// ---------------------------------------------------------------------------

/// Identity policy specifying the expected signer for verification.
///
/// Pass an ``Identity`` to :meth:`Verifier.verify_artifact` or
/// :meth:`Verifier.verify_dsse` to assert who signed the artifact.
///
/// Args:
///     identity: The expected signer identity. For email-based OIDC
///         providers this is an email address (e.g.
///         ``"user@example.com"``). For GitHub Actions this is a
///         workflow URI (e.g.
///         ``"https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"``).
///     issuer:   The expected OIDC issuer URL. Strongly recommended;
///         if omitted any issuer is accepted.
///
/// Example::
///
///     policy = Identity(
///         identity="https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main",
///         issuer="https://token.actions.githubusercontent.com",
///     )
#[gen_stub_pyclass]
#[pyclass(name = "Identity", module = "sigstore._internal")]
pub struct PyIdentity {
    pub inner: VerificationPolicy,
}

#[gen_stub_pymethods]
#[pymethods]
impl PyIdentity {
    #[new]
    #[pyo3(signature = (identity, issuer=None))]
    fn new(identity: &str, issuer: Option<&str>) -> Self {
        let mut policy = VerificationPolicy::with_identity(identity);
        if let Some(iss) = issuer {
            policy = policy.require_issuer(iss);
        }
        PyIdentity { inner: policy }
    }

    /// The required identity string, if set.
    #[getter]
    fn identity(&self) -> Option<&str> {
        self.inner.identity.as_deref()
    }

    /// The required issuer URL, if set.
    #[getter]
    fn issuer(&self) -> Option<&str> {
        self.inner.issuer.as_deref()
    }

    fn __repr__(&self) -> String {
        match (&self.inner.identity, &self.inner.issuer) {
            (Some(id), Some(iss)) => format!("Identity(identity={id:?}, issuer={iss:?})"),
            (Some(id), None) => format!("Identity(identity={id:?})"),
            _ => "Identity()".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// PyVerifier — wraps Verifier
// ---------------------------------------------------------------------------

/// Verifies Sigstore bundles against a trusted root.
///
/// Construct via one of the class methods, then call
/// :meth:`verify_artifact` or :meth:`verify_dsse`.
///
/// Example::
///
///     verifier = Verifier.production()
///     bundle = Bundle.from_json(open("artifact.sigstore.json").read())
///     policy = Identity(identity="user@example.com",
///                       issuer="https://accounts.google.com")
///
///     verifier.verify_artifact(open("artifact.bin", "rb").read(), bundle, policy)
///     # raises VerificationError on failure, returns None on success
#[gen_stub_pyclass]
#[pyclass(name = "Verifier", module = "sigstore._internal")]
pub struct PyVerifier {
    inner: Verifier,
}

#[gen_stub_pymethods]
#[pymethods]
impl PyVerifier {
    /// Create a verifier using the Sigstore public-good trusted root.
    ///
    /// Fetches the latest trust material via TUF. Makes a network request.
    ///
    /// Raises :exc:`TrustedRootError` if the TUF fetch fails.
    #[classmethod]
    fn production(cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        let py = cls.py();
        let root = py
            .detach(|| get_runtime().block_on(TrustedRoot::production()))
            .map_err(|e| TrustedRootError::new_err(e.to_string()))?;
        Ok(PyVerifier {
            inner: Verifier::new(&root),
        })
    }

    /// Create a verifier using the Sigstore staging trusted root.
    ///
    /// Fetches the latest staging trust material via TUF. For testing only.
    ///
    /// Raises :exc:`TrustedRootError` if the TUF fetch fails.
    #[classmethod]
    fn staging(cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        let py = cls.py();
        let root = py
            .detach(|| get_runtime().block_on(TrustedRoot::staging()))
            .map_err(|e| TrustedRootError::new_err(e.to_string()))?;
        Ok(PyVerifier {
            inner: Verifier::new(&root),
        })
    }

    /// Create a verifier using the embedded GitHub Actions trusted root.
    ///
    /// No network request is made. Use this for verifying GitHub artifact
    /// attestations in offline or air-gapped environments.
    ///
    /// Raises :exc:`TrustedRootError` if the embedded root data is invalid.
    #[classmethod]
    fn github(_cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        use sigstore_trust_root::SIGSTORE_GITHUB_TRUSTED_ROOT;
        let root = TrustedRoot::from_json(SIGSTORE_GITHUB_TRUSTED_ROOT)
            .map_err(|e| TrustedRootError::new_err(e.to_string()))?;
        Ok(PyVerifier {
            inner: Verifier::new(&root),
        })
    }

    /// Create a verifier from a pre-loaded :class:`TrustedRoot`.
    ///
    /// Use this when you have already loaded or cached the trusted root and
    /// want to avoid a repeated network fetch.
    #[classmethod]
    fn from_root(_cls: &Bound<'_, pyo3::types::PyType>, root: &PyTrustedRoot) -> PyResult<Self> {
        Ok(PyVerifier {
            inner: Verifier::new(&root.inner),
        })
    }

    /// Verify a raw artifact against a Sigstore bundle.
    ///
    /// Returns ``None`` on success. Raises :exc:`VerificationError` if
    /// verification fails for any reason (invalid signature, identity
    /// mismatch, expired certificate, etc.).
    ///
    /// Args:
    ///     input:   The raw artifact bytes to verify.
    ///     bundle:  The :class:`Bundle` produced during signing.
    ///     policy:  The :class:`Identity` asserting the expected signer.
    fn verify_artifact(
        &self,
        input: &Bound<'_, pyo3::types::PyBytes>,
        bundle: &PyBundle,
        policy: &PyIdentity,
    ) -> PyResult<()> {
        // Construct Artifact<'_> transiently — lifetime is scoped to this call
        let artifact = Artifact::from(input.as_bytes());
        self.inner
            .verify(artifact, &bundle.inner, &policy.inner)
            .map(|_| ())
            .map_err(|e| VerificationError::new_err(e.to_string()))
    }

    /// Verify a DSSE envelope bundle against an artifact and return the payload.
    ///
    /// The ``artifact`` bytes are required because the in-toto statement inside
    /// the DSSE envelope must reference the artifact's SHA-256 digest as one of
    /// its subjects. This ensures the attestation is bound to the artifact.
    ///
    /// Returns a ``(payload_type, payload_bytes)`` tuple on success.
    /// Raises :exc:`VerificationError` if verification fails.
    ///
    /// Args:
    ///     artifact: The raw artifact bytes whose digest is claimed by the
    ///               in-toto statement.
    ///     bundle:   The DSSE :class:`Bundle` produced during signing.
    ///     policy:   The :class:`Identity` asserting the expected signer.
    ///
    /// Returns:
    ///     A ``(str, bytes)`` tuple of ``(payload_type, payload_bytes)``.
    fn verify_dsse<'py>(
        &self,
        py: Python<'py>,
        artifact: &Bound<'_, pyo3::types::PyBytes>,
        bundle: &PyBundle,
        policy: &PyIdentity,
    ) -> PyResult<(String, pyo3::Py<pyo3::types::PyBytes>)> {
        use sigstore_types::SignatureContent;

        let art = Artifact::from(artifact.as_bytes());
        self.inner
            .verify(art, &bundle.inner, &policy.inner)
            .map_err(|e| VerificationError::new_err(e.to_string()))?;

        // Extract (payload_type, payload_bytes) from the DSSE envelope
        match &bundle.inner.content {
            SignatureContent::DsseEnvelope(env) => {
                let payload_type = env.payload_type.clone();
                let payload_bytes = env.decode_payload().to_vec();
                Ok((payload_type, pyo3::types::PyBytes::new(py, &payload_bytes).into()))
            }
            SignatureContent::MessageSignature(_) => Err(VerificationError::new_err(
                "verify_dsse called on a MessageSignature bundle; use verify_artifact instead",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Module-level verify() convenience function
// ---------------------------------------------------------------------------

/// One-shot artifact verification.
///
/// A convenience wrapper around :class:`Verifier` that handles trust root
/// loading automatically. For repeated verifications, prefer constructing a
/// :class:`Verifier` once and reusing it.
///
/// Args:
///     input:        The raw artifact bytes to verify.
///     bundle:       A :class:`Bundle` object or a JSON string.
///     identity:     The expected signer identity string.
///     issuer:       The expected OIDC issuer URL. Strongly recommended.
///     trusted_root: Optional pre-loaded :class:`TrustedRoot`. If not
///                   provided, the Sigstore public-good root is fetched via
///                   TUF.
///
/// Raises:
///     :exc:`VerificationError`: If verification fails.
///     :exc:`BundleError`:       If ``bundle`` is a string that cannot be parsed.
///     :exc:`TrustedRootError`:  If the trusted root cannot be fetched.
#[gen_stub_pyfunction(module = "sigstore._internal")]
#[pyfunction]
#[pyo3(signature = (input, bundle, identity, issuer=None, *, trusted_root=None))]
pub fn py_verify(
    py: Python<'_>,
    input: &Bound<'_, pyo3::types::PyBytes>,
    bundle: &Bound<'_, PyAny>,
    identity: &str,
    issuer: Option<&str>,
    trusted_root: Option<&PyTrustedRoot>,
) -> PyResult<()> {
    // Accept Bundle object or JSON string.
    let owned_bundle: sigstore_types::Bundle =
        if let Ok(b) = bundle.extract::<PyRef<PyBundle>>() {
            b.inner.clone()
        } else if let Ok(s) = bundle.extract::<String>() {
            use sigstore_types::Bundle;
            Bundle::from_json(&s).map_err(|e| BundleError::new_err(e.to_string()))?
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "bundle must be a Bundle object or a JSON string",
            ));
        };

    let mut policy = VerificationPolicy::with_identity(identity);
    if let Some(iss) = issuer {
        policy = policy.require_issuer(iss);
    }

    // Load or reuse trusted root
    let owned_root: TrustedRoot;
    let root_ref: &TrustedRoot = if let Some(r) = trusted_root {
        &r.inner
    } else {
        owned_root = py
            .detach(|| get_runtime().block_on(TrustedRoot::production()))
            .map_err(|e| TrustedRootError::new_err(e.to_string()))?;
        &owned_root
    };

    let artifact = Artifact::from(input.as_bytes());
    sigstore_verify::verify(artifact, &owned_bundle, &policy, root_ref)
        .map(|_| ())
        .map_err(|e| VerificationError::new_err(e.to_string()))
}
