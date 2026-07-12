//! Wire-format compatibility tests against the canonical Sigstore protobuf
//! definitions.
//!
//! This crate is test-only and never published. sigstore-rust deliberately
//! builds its public API on hand-written serde types instead of the
//! protobuf-generated ones, but it must stay compatible with the protobuf
//! JSON wire format those definitions specify. The tests in `tests/` enforce
//! that against `sigstore_protobuf_specs`, the crate generated from
//! <https://github.com/sigstore/protobuf-specs>.
