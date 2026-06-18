//! Python binding for `sigstore_trust_root::TrustedRoot`.

use crate::errors::TrustedRootError;
use crate::runtime::get_runtime;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};
use sigstore_trust_root::{TrustedRoot, SIGSTORE_GITHUB_TRUSTED_ROOT};

/// Trust anchors for Sigstore verification.
///
/// The ``TrustedRoot`` contains all cryptographic material required to verify
/// Sigstore bundles: Fulcio CA certificates, Rekor public keys, CT log keys,
/// and TSA certificates.
///
/// For most users, :meth:`production` or :meth:`github` is the right choice.
///
/// Example::
///
///     # Fetch latest trust material via TUF (recommended for production):
///     root = TrustedRoot.production()
///
///     # Use embedded GitHub Actions root (no network needed):
///     root = TrustedRoot.github()
///
///     # Load from a local file:
///     root = TrustedRoot.from_file("/path/to/trusted_root.json")
#[gen_stub_pyclass]
#[pyclass(name = "TrustedRoot", module = "py_sigstore_rust._internal")]
pub struct PyTrustedRoot {
    pub inner: TrustedRoot,
}

#[gen_stub_pymethods]
#[pymethods]
impl PyTrustedRoot {
    /// Fetch the Sigstore public-good trusted root via TUF.
    ///
    /// Makes a network request to download and verify the latest trust
    /// material from Sigstore's TUF repository. This is the recommended
    /// method for production use.
    ///
    /// Raises :exc:`TrustedRootError` if the fetch or verification fails.
    #[classmethod]
    fn production(cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        let py = cls.py();
        py.detach(|| get_runtime().block_on(TrustedRoot::production()))
            .map(|inner| PyTrustedRoot { inner })
            .map_err(|e| TrustedRootError::new_err(e.to_string()))
    }

    /// Fetch the Sigstore staging trusted root via TUF.
    ///
    /// Use this for testing against the Sigstore staging infrastructure.
    /// Not for production use.
    ///
    /// Raises :exc:`TrustedRootError` if the fetch or verification fails.
    #[classmethod]
    fn staging(cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        let py = cls.py();
        py.detach(|| get_runtime().block_on(TrustedRoot::staging()))
            .map(|inner| PyTrustedRoot { inner })
            .map_err(|e| TrustedRootError::new_err(e.to_string()))
    }

    /// Load the GitHub Actions trusted root (embedded, no network required).
    ///
    /// Use this when verifying GitHub artifact attestations. The embedded
    /// root is kept up to date with library releases.
    ///
    /// Raises :exc:`TrustedRootError` if the embedded data is invalid
    /// (should not happen in normal use).
    #[classmethod]
    fn github(_cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        TrustedRoot::from_json(SIGSTORE_GITHUB_TRUSTED_ROOT)
            .map(|inner| PyTrustedRoot { inner })
            .map_err(|e| TrustedRootError::new_err(e.to_string()))
    }

    /// Parse a trusted root from a JSON string.
    ///
    /// Raises :exc:`TrustedRootError` if the JSON is invalid.
    #[classmethod]
    fn from_json(_cls: &Bound<'_, pyo3::types::PyType>, data: &str) -> PyResult<Self> {
        TrustedRoot::from_json(data)
            .map(|inner| PyTrustedRoot { inner })
            .map_err(|e| TrustedRootError::new_err(e.to_string()))
    }

    /// Load a trusted root from a JSON file on disk.
    ///
    /// Args:
    ///     path: Filesystem path to the trusted root JSON file.
    ///
    /// Raises :exc:`TrustedRootError` if the file cannot be read or parsed.
    #[classmethod]
    fn from_file(_cls: &Bound<'_, pyo3::types::PyType>, path: &str) -> PyResult<Self> {
        TrustedRoot::from_file(path)
            .map(|inner| PyTrustedRoot { inner })
            .map_err(|e| TrustedRootError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "TrustedRoot(tlogs={}, cas={})",
            self.inner.tlogs.len(),
            self.inner.certificate_authorities.len(),
        )
    }
}
