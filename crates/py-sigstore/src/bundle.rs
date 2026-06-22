//! Python binding for `sigstore_types::Bundle`.

use crate::errors::BundleError;
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};
use sigstore_types::Bundle;

/// A Sigstore bundle containing a signature, verification material, and
/// transparency log entries.
///
/// Bundles are the primary artifact exchanged between signers and verifiers.
/// They can be serialized to JSON (`.sigstore.json` files) and parsed back.
///
/// Example::
///
///     bundle = Bundle.from_json(open("artifact.sigstore.json").read())
///     print(bundle.media_type)
#[gen_stub_pyclass]
#[pyclass(name = "Bundle", module = "sigstore._internal")]
pub struct PyBundle {
    pub inner: Bundle,
}

#[gen_stub_pymethods]
#[pymethods]
impl PyBundle {
    /// Parse a Sigstore bundle from a JSON string or bytes.
    ///
    /// Raises :exc:`BundleError` if the input is not valid bundle JSON.
    #[classmethod]
    fn from_json(_cls: &Bound<'_, pyo3::types::PyType>, data: &str) -> PyResult<Self> {
        Bundle::from_json(data)
            .map(|inner| PyBundle { inner })
            .map_err(|e| BundleError::new_err(e.to_string()))
    }

    /// Serialize the bundle to a JSON string.
    ///
    /// Raises :exc:`BundleError` on serialization failure (extremely rare).
    fn to_json(&self) -> PyResult<String> {
        self.inner
            .to_json()
            .map_err(|e| BundleError::new_err(e.to_string()))
    }

    /// The bundle media type string.
    ///
    /// For example:
    /// ``"application/vnd.dev.sigstore.bundle.v0.3+json"``
    #[getter]
    fn media_type(&self) -> &str {
        self.inner.media_type.as_str()
    }

    fn __repr__(&self) -> String {
        format!("Bundle(media_type={:?})", self.inner.media_type.as_str())
    }
}
