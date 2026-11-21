//! Python binding for `sigstore_types::Bundle`.

use crate::errors::bundle_error;
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
#[pyclass(name = "Bundle", module = "py_sigstore._internal")]
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
            .map_err(bundle_error)
    }

    /// Serialize the bundle to a JSON string.
    ///
    /// Raises :exc:`BundleError` on serialization failure (extremely rare).
    fn to_json(&self) -> PyResult<String> {
        self.inner
            .to_json()
            .map_err(bundle_error)
    }

    /// The bundle media type string.
    ///
    /// For example:
    /// ``"application/vnd.dev.sigstore.bundle.v0.3+json"``
    #[getter]
    fn media_type(&self) -> &str {
        self.inner.media_type.as_str()
    }

    /// Serialize the bundle to indented JSON.
    fn to_json_pretty(&self) -> PyResult<String> {
        self.inner
            .to_json_pretty()
            .map_err(bundle_error)
    }

    /// The signing certificate as a PEM string, if the bundle carries one.
    #[getter]
    fn signing_certificate_pem(&self) -> Option<String> {
        self.inner.signing_certificate().map(|c| c.to_pem())
    }

    /// Whether the bundle contains a transparency log inclusion proof.
    #[getter]
    fn has_inclusion_proof(&self) -> bool {
        self.inner.has_inclusion_proof()
    }

    /// Whether the bundle contains a transparency log inclusion promise (SET).
    #[getter]
    fn has_inclusion_promise(&self) -> bool {
        self.inner.has_inclusion_promise()
    }

    /// Whether the bundle wraps a DSSE envelope (as opposed to a plain signature).
    #[getter]
    fn is_dsse(&self) -> bool {
        matches!(
            self.inner.content,
            sigstore_types::SignatureContent::DsseEnvelope(_)
        )
    }

    fn __repr__(&self) -> String {
        format!("Bundle(media_type={:?})", self.inner.media_type.as_str())
    }
}
