//! Toolchain binary locations (`cargo`, `rustc`, `rustdoc`).

use std::env;
use std::path::PathBuf;

/// Path to the `cargo` binary.
pub fn cargo() -> PathBuf {
    env::var_os("CARGO")
        .map(Into::into)
        .unwrap_or_else(|| PathBuf::from("cargo"))
}

/// Path to `rustc` as selected by Cargo.
pub fn rustc() -> PathBuf {
    env::var_os("RUSTC")
        .expect("RUSTC env var is not set")
        .into()
}

/// Path to `rustdoc` as selected by Cargo.
pub fn rustdoc() -> PathBuf {
    env::var_os("RUSTDOC")
        .expect("RUSTDOC env var is not set")
        .into()
}
