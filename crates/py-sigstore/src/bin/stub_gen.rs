//! Stub generation binary.
//!
//! Run with:
//!   cargo run --bin stub_gen
//!
//! This generates `python/sigstore/_internal.pyi` from the
//! `#[gen_stub_*]` annotations throughout the crate.
//!
//! The generated file is committed to source control and validated in CI
//! by running this binary and checking `git diff --exit-code`.

fn main() -> pyo3_stub_gen::Result<()> {
    // The library crate is named `_internal` (matching `[lib] name` in Cargo.toml).
    let stub = _internal::stub_info()?;
    stub.generate()?;
    Ok(())
}
