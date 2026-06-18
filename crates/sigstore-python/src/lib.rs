//! Python bindings for sigstore-rust.
//!
//! This crate exposes a Pythonic facade over the sigstore-rust workspace
//! crates. It is built as a Python extension module (`_internal`) and
//! re-exported through the `py_sigstore_rust` Python package.

use pyo3::prelude::*;
use pyo3_stub_gen::define_stub_info_gatherer;

mod bundle;
mod errors;
mod oidc;
mod runtime;
mod sign;
mod trust_root;
mod verify;

// Register all stub metadata collected by pyo3-stub-gen macros.
// The `stub_gen` binary calls `stub_info()` to write the `.pyi` file.
define_stub_info_gatherer!(stub_info);

/// Python module entry point.
///
/// The module is named `_internal`; the public `py_sigstore_rust` package
/// re-exports everything from here via `__init__.py`.
#[pymodule]
fn _internal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register exception hierarchy first (other items may reference them)
    errors::register_exceptions(m)?;

    // Core types
    m.add_class::<bundle::PyBundle>()?;
    m.add_class::<trust_root::PyTrustedRoot>()?;
    m.add_class::<verify::PyIdentity>()?;
    m.add_class::<verify::PyVerifier>()?;

    // Signing + OIDC
    m.add_class::<oidc::PyIdentityToken>()?;
    m.add_class::<sign::PySigner>()?;

    // Module-level convenience functions
    m.add_function(wrap_pyfunction!(verify::py_verify, m)?)?;
    m.add_function(wrap_pyfunction!(sign::py_sign, m)?)?;

    Ok(())
}
