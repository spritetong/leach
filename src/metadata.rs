//! Inter-dependency metadata communication between build scripts.

use std::env;

/// Emits a metadata field for dependents of this package.
pub fn emit_raw(key: &str, value: &str) {
    println!("cargo:{key}={value}");
}

/// Reads a metadata field from the specified dependency.
pub fn get_raw(dep: &str, key: &str) -> Option<String> {
    let name = format!("DEP_{}_{}", dep.to_uppercase(), key.to_uppercase());
    env::var(&name).ok()
}
