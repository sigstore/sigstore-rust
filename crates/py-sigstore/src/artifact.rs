//! Artifact inputs: raw bytes or a pre-computed digest (`Hashed`).

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};
use sigstore_types::{Artifact, ArtifactDigest, HashAlgorithm};

/// A pre-computed artifact digest.
///
/// Pass a ``Hashed`` wherever an artifact is expected (``Verifier.verify_artifact``,
/// ``Signer.sign_artifact``) to avoid loading or re-hashing a large file.
///
/// Args:
///     digest:    The raw digest bytes.
///     algorithm: ``"sha256"`` (default), ``"sha384"`` or ``"sha512"``.
///
/// Raises:
///     ValueError: If the algorithm is unknown or the digest has the wrong length.
///
/// Example::
///
///     import hashlib
///     h = Hashed(hashlib.sha256(data).digest())
///     verifier.verify_artifact(h, bundle, policy)
#[gen_stub_pyclass]
#[pyclass(name = "Hashed", module = "py_sigstore._internal", frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyHashed {
    pub inner: ArtifactDigest,
}

fn parse_algorithm(name: &str) -> PyResult<HashAlgorithm> {
    match name.to_ascii_lowercase().replace('-', "").as_str() {
        "sha256" | "sha2256" => Ok(HashAlgorithm::Sha2256),
        "sha384" | "sha2384" => Ok(HashAlgorithm::Sha2384),
        "sha512" | "sha2512" => Ok(HashAlgorithm::Sha2512),
        other => Err(PyValueError::new_err(format!(
            "unsupported hash algorithm {other:?}; expected sha256, sha384 or sha512"
        ))),
    }
}

fn algorithm_name(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha2256 => "sha256",
        HashAlgorithm::Sha2384 => "sha384",
        HashAlgorithm::Sha2512 => "sha512",
        // `HashAlgorithm` may grow variants.
        _ => "unknown",
    }
}

impl PyHashed {
    fn from_slice(digest: &[u8], algorithm: &str) -> PyResult<Self> {
        let algorithm = parse_algorithm(algorithm)?;
        let inner =
            ArtifactDigest::new(algorithm, digest).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyHashed { inner })
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl PyHashed {
    #[new]
    #[pyo3(signature = (digest, algorithm="sha256"))]
    fn new(digest: &Bound<'_, PyBytes>, algorithm: &str) -> PyResult<Self> {
        Self::from_slice(digest.as_bytes(), algorithm)
    }

    /// Build a ``Hashed`` from a hex-encoded digest.
    #[classmethod]
    #[pyo3(signature = (digest, algorithm="sha256"))]
    fn from_hex(
        _cls: &Bound<'_, pyo3::types::PyType>,
        digest: &str,
        algorithm: &str,
    ) -> PyResult<Self> {
        let bytes = sigstore_types::DigestBytes::from_hex(digest)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Self::from_slice(bytes.as_bytes(), algorithm)
    }

    /// The hash algorithm name (``"sha256"``, ``"sha384"`` or ``"sha512"``).
    #[getter]
    fn algorithm(&self) -> &'static str {
        algorithm_name(self.inner.algorithm())
    }

    /// The raw digest bytes.
    #[getter]
    fn digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }

    fn __repr__(&self) -> String {
        format!(
            "Hashed(algorithm={:?}, digest={})",
            self.algorithm(),
            self.inner.value().to_hex()
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

/// An owned artifact input extracted from Python (`bytes` or `Hashed`).
pub enum OwnedArtifact {
    Blob(Vec<u8>),
    Digest(ArtifactDigest),
}

impl OwnedArtifact {
    /// Borrow as the Rust `Artifact` accepted by `Signer::sign` / `Verifier::verify`.
    pub fn as_artifact(&self) -> Artifact<'_> {
        match self {
            OwnedArtifact::Blob(b) => Artifact::Blob(b),
            OwnedArtifact::Digest(d) => Artifact::Digest(d.clone()),
        }
    }
}

/// Extract an artifact from a Python `bytes` or :class:`Hashed` object.
pub fn extract_artifact(obj: &Bound<'_, PyAny>) -> PyResult<OwnedArtifact> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(OwnedArtifact::Blob(b.as_bytes().to_vec()));
    }
    if let Ok(h) = obj.extract::<PyRef<PyHashed>>() {
        return Ok(OwnedArtifact::Digest(h.inner.clone()));
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "artifact must be bytes or a Hashed digest",
    ))
}
