//! Python bindings for verification: `PyIdentity`, `PyVerifier`, and the
//! module-level `verify()` convenience function.

use crate::artifact::extract_artifact;
use crate::bundle::PyBundle;
use crate::errors::{bundle_error, trust_root_error, verify_error, VerificationError};
use crate::runtime::get_runtime;
use crate::trust_root::PyTrustedRoot;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods, gen_stub_pyfunction};
use sigstore_trust_root::TrustedRoot;
use sigstore_verify::{VerificationPolicy, VerificationResult, Verifier};

// ---------------------------------------------------------------------------
// PyVerificationResult
// ---------------------------------------------------------------------------

/// Convert a Unix timestamp (seconds) to an aware UTC ``datetime``.
fn utc_datetime<'py>(py: Python<'py>, seconds: i64) -> PyResult<Bound<'py, PyAny>> {
    let datetime = py.import("datetime")?;
    let utc = datetime.getattr("timezone")?.getattr("utc")?;
    datetime
        .getattr("datetime")?
        .call_method1("fromtimestamp", (seconds, utc))
}

/// Details of a successful verification.
///
/// Returned by :meth:`Verifier.verify_artifact`, :meth:`Verifier.verify_dsse`
/// and :func:`verify`. Failures raise a :exc:`VerificationError` instead.
#[gen_stub_pyclass]
#[pyclass(name = "VerificationResult", module = "py_sigstore._internal", frozen)]
pub struct PyVerificationResult {
    identity: Option<String>,
    issuer: Option<String>,
    integrated_time: Option<i64>,
    verified_timestamps: Vec<i64>,
    certificate_verified: bool,
    sct_verified: bool,
    tlog_verified: bool,
    identity_policy_checked: bool,
}

impl From<&VerificationResult> for PyVerificationResult {
    fn from(r: &VerificationResult) -> Self {
        PyVerificationResult {
            identity: r.identity().map(|i| i.as_str().to_string()),
            issuer: r.issuer().map(str::to_string),
            integrated_time: r.integrated_time().map(|t| t.as_second()),
            verified_timestamps: r.verified_timestamps().iter().map(|t| t.as_second()).collect(),
            certificate_verified: r.certificate_verified(),
            sct_verified: r.sct_verified(),
            tlog_verified: r.tlog_verified(),
            identity_policy_checked: r.identity_policy_checked(),
        }
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl PyVerificationResult {
    /// The signer identity from the certificate (email or URI), if any.
    #[getter]
    fn identity(&self) -> Option<&str> {
        self.identity.as_deref()
    }

    /// The OIDC issuer recorded in the certificate, if any.
    #[getter]
    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// The transparency log integrated time as an aware UTC ``datetime``.
    #[getter]
    fn integrated_time<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.integrated_time.map(|t| utc_datetime(py, t)).transpose()
    }

    /// Verified RFC 3161 timestamps as aware UTC ``datetime`` objects.
    #[getter]
    fn verified_timestamps<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        self.verified_timestamps.iter().map(|t| utc_datetime(py, *t)).collect()
    }

    /// Whether the certificate chain was verified.
    #[getter]
    fn certificate_verified(&self) -> bool {
        self.certificate_verified
    }

    /// Whether the signed certificate timestamp (SCT) was verified.
    #[getter]
    fn sct_verified(&self) -> bool {
        self.sct_verified
    }

    /// Whether transparency log inclusion was verified.
    #[getter]
    fn tlog_verified(&self) -> bool {
        self.tlog_verified
    }

    /// Whether an identity policy was checked against the signer.
    #[getter]
    fn identity_policy_checked(&self) -> bool {
        self.identity_policy_checked
    }

    fn __repr__(&self) -> String {
        let opt = |v: &Option<String>| match v {
            Some(s) => format!("{s:?}"),
            None => "None".to_string(),
        };
        format!(
            "VerificationResult(identity={}, issuer={}, tlog_verified={}, certificate_verified={})",
            opt(&self.identity),
            opt(&self.issuer),
            if self.tlog_verified { "True" } else { "False" },
            if self.certificate_verified { "True" } else { "False" },
        )
    }
}

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
///         if omitted, any issuer is accepted for the given identity.
///     skip_tlog_unsafe: **Unsafe.** Do not require transparency log
///         inclusion. Only for trust domains without an accessible log
///         (e.g. GitHub private-repository attestations) or testing.
///     skip_sct: Do not require a signed certificate timestamp. Needed for
///         trust domains whose certificates carry no public CT SCT (e.g.
///         GitHub's attestation instance).
///     skip_certificate_chain: **Unsafe.** Do not verify the certificate
///         chain (also skips the SCT). Testing only.
///
/// Example::
///
///     policy = Identity(
///         identity="https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main",
///         issuer="https://token.actions.githubusercontent.com",
///     )
#[gen_stub_pyclass]
#[pyclass(name = "Identity", module = "py_sigstore._internal")]
pub struct PyIdentity {
    pub inner: VerificationPolicy,
    identity: String,
    issuer: Option<String>,
}

/// Build a certificate-identity policy.
///
/// With an issuer this is `VerificationPolicy::new`. Without one, only the
/// identity is required (any issuer is accepted).
fn build_policy(identity: &str, issuer: Option<&str>) -> VerificationPolicy {
    match issuer {
        Some(iss) => VerificationPolicy::new(identity, iss),
        None => VerificationPolicy::any_identity().require_identity(identity),
    }
}

/// Apply the opt-out flags to a policy.
fn apply_flags(
    mut policy: VerificationPolicy,
    skip_tlog_unsafe: bool,
    skip_sct: bool,
    skip_certificate_chain: bool,
) -> VerificationPolicy {
    if skip_tlog_unsafe {
        policy = policy.skip_tlog_unsafe();
    }
    if skip_sct {
        policy = policy.skip_sct();
    }
    if skip_certificate_chain {
        policy = policy.skip_certificate_chain();
    }
    policy
}

fn verifier_from_root(root: &TrustedRoot) -> PyResult<Verifier> {
    Verifier::new(root).map_err(verify_error)
}

#[gen_stub_pymethods]
#[pymethods]
impl PyIdentity {
    #[new]
    #[pyo3(signature = (identity, issuer=None, *, skip_tlog_unsafe=false, skip_sct=false, skip_certificate_chain=false))]
    fn new(
        identity: &str,
        issuer: Option<&str>,
        skip_tlog_unsafe: bool,
        skip_sct: bool,
        skip_certificate_chain: bool,
    ) -> Self {
        PyIdentity {
            inner: apply_flags(
                build_policy(identity, issuer),
                skip_tlog_unsafe,
                skip_sct,
                skip_certificate_chain,
            ),
            identity: identity.to_string(),
            issuer: issuer.map(str::to_string),
        }
    }

    /// The required identity string.
    #[getter]
    fn identity(&self) -> &str {
        &self.identity
    }

    /// The required issuer URL, if set.
    #[getter]
    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn __repr__(&self) -> String {
        match &self.issuer {
            Some(iss) => format!("Identity(identity={:?}, issuer={iss:?})", self.identity),
            None => format!("Identity(identity={:?})", self.identity),
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
///     result = verifier.verify_artifact(data, bundle, policy)
///     # raises VerificationError on failure; returns a VerificationResult
#[gen_stub_pyclass]
#[pyclass(name = "Verifier", module = "py_sigstore._internal")]
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
            .map_err(trust_root_error)?;
        Ok(PyVerifier {
            inner: verifier_from_root(&root)?,
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
            .map_err(trust_root_error)?;
        Ok(PyVerifier {
            inner: verifier_from_root(&root)?,
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
            .map_err(trust_root_error)?;
        Ok(PyVerifier {
            inner: verifier_from_root(&root)?,
        })
    }

    /// Create a verifier from a pre-loaded :class:`TrustedRoot`.
    ///
    /// Use this when you have already loaded or cached the trusted root and
    /// want to avoid a repeated network fetch.
    #[classmethod]
    fn from_root(_cls: &Bound<'_, pyo3::types::PyType>, root: &PyTrustedRoot) -> PyResult<Self> {
        Ok(PyVerifier {
            inner: verifier_from_root(&root.inner)?,
        })
    }

    /// Verify an artifact against a Sigstore bundle.
    ///
    /// Returns a :class:`VerificationResult` on success. Raises
    /// :exc:`VerificationError` (or a more specific subclass such as
    /// :exc:`IdentityMismatchError`) if verification fails.
    ///
    /// Args:
    ///     input:   The artifact: raw ``bytes`` or a pre-computed :class:`Hashed`.
    ///     bundle:  The :class:`Bundle` produced during signing.
    ///     policy:  The :class:`Identity` asserting the expected signer.
    fn verify_artifact(
        &self,
        input: &Bound<'_, PyAny>,
        bundle: &PyBundle,
        policy: &PyIdentity,
    ) -> PyResult<PyVerificationResult> {
        let artifact = extract_artifact(input)?;
        self.inner
            .verify(artifact.as_artifact(), &bundle.inner, &policy.inner)
            .map(|r| PyVerificationResult::from(&r))
            .map_err(verify_error)
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
    ///     artifact: The artifact (``bytes`` or :class:`Hashed`) whose digest is
    ///               claimed by the in-toto statement.
    ///     bundle:   The DSSE :class:`Bundle` produced during signing.
    ///     policy:   The :class:`Identity` asserting the expected signer.
    ///
    /// Returns:
    ///     A ``(str, bytes)`` tuple of ``(payload_type, payload_bytes)``.
    fn verify_dsse<'py>(
        &self,
        py: Python<'py>,
        artifact: &Bound<'_, PyAny>,
        bundle: &PyBundle,
        policy: &PyIdentity,
    ) -> PyResult<(String, pyo3::Py<pyo3::types::PyBytes>)> {
        use sigstore_types::SignatureContent;

        let art = extract_artifact(artifact)?;
        self.inner
            .verify(art.as_artifact(), &bundle.inner, &policy.inner)
            .map_err(verify_error)?;

        // Extract (payload_type, payload_bytes) from the DSSE envelope
        match &bundle.inner.content {
            SignatureContent::DsseEnvelope(env) => {
                let payload_type = env.payload_type.clone();
                let payload_bytes: &[u8] = env.payload.as_ref();
                Ok((payload_type, pyo3::types::PyBytes::new(py, payload_bytes).into()))
            }
            SignatureContent::MessageSignature(_) => Err(VerificationError::new_err(
                "verify_dsse called on a MessageSignature bundle; use verify_artifact instead",
            )),
            // `SignatureContent` is `#[non_exhaustive]`.
            _ => Err(VerificationError::new_err(
                "unsupported bundle content type for verify_dsse",
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
///     input:        The artifact: raw ``bytes`` or a :class:`Hashed` digest.
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
#[gen_stub_pyfunction(module = "py_sigstore._internal")]
#[pyfunction]
#[pyo3(signature = (input, bundle, identity, issuer=None, *, trusted_root=None))]
pub fn py_verify(
    py: Python<'_>,
    input: &Bound<'_, PyAny>,
    bundle: &Bound<'_, PyAny>,
    identity: &str,
    issuer: Option<&str>,
    trusted_root: Option<&PyTrustedRoot>,
) -> PyResult<PyVerificationResult> {
    // Accept Bundle object or JSON string.
    let owned_bundle: sigstore_types::Bundle =
        if let Ok(b) = bundle.extract::<PyRef<PyBundle>>() {
            b.inner.clone()
        } else if let Ok(s) = bundle.extract::<String>() {
            use sigstore_types::Bundle;
            Bundle::from_json(&s).map_err(bundle_error)?
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "bundle must be a Bundle object or a JSON string",
            ));
        };

    let policy = build_policy(identity, issuer);

    // Load or reuse trusted root
    let owned_root: TrustedRoot;
    let root_ref: &TrustedRoot = if let Some(r) = trusted_root {
        &r.inner
    } else {
        owned_root = py
            .detach(|| get_runtime().block_on(TrustedRoot::production()))
            .map_err(trust_root_error)?;
        &owned_root
    };

    let artifact = extract_artifact(input)?;
    sigstore_verify::verify(artifact.as_artifact(), &owned_bundle, &policy, root_ref)
        .map(|r| PyVerificationResult::from(&r))
        .map_err(verify_error)
}
