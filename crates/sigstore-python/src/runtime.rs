//! Embedded Tokio runtime for async→sync bridging.
//!
//! All async Rust operations (TUF fetch, signing, OIDC token detection) are
//! executed on this runtime. It is initialized once and reused for the lifetime
//! of the Python process.
//!
//! Python callers release the GIL before entering `block_on` so that other
//! Python threads remain unblocked during network I/O.

use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Return the process-wide Tokio runtime, initializing it on first call.
///
/// Panics at startup if the runtime cannot be built (extremely unlikely —
/// would require OS-level resource exhaustion).
pub fn get_runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build embedded Tokio runtime for py-sigstore-rust")
    })
}
