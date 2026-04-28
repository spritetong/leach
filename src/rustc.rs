//! Functions for emitting `rustc` instruction metadata back to Cargo.

use crate::{LibKind, SearchKind};
use std::path::Path;

/// Links a library into the output.
pub fn link_lib<P: AsRef<Path>>(link_kind: Option<LibKind>, name: P) {
    let prefix = link_kind.map(|k| format!("{k}=")).unwrap_or_default();
    println!("cargo:rustc-link-lib={prefix}{}", name.as_ref().display());
}

/// Adds a library search directory.
pub fn link_search<P: AsRef<Path>>(link_kind: Option<SearchKind>, path: P) {
    let prefix = link_kind.map(|k| format!("{k}=")).unwrap_or_default();
    println!(
        "cargo:rustc-link-search={prefix}{}",
        path.as_ref().display()
    );
}

/// Passes a raw flag to `rustc`. See Cargo docs for permitted flags.
pub fn flags(flags: &str) {
    println!("cargo:rustc-flags={flags}");
}

/// Defines a conditional compilation flag (`cfg`).
pub fn cfg(cfg: &str) {
    println!("cargo:rustc-cfg={cfg}");
}

/// Convenience: links multiple libraries with the same kind.
pub fn link_libs<I>(kind: Option<LibKind>, names: I)
where
    I: IntoIterator,
    I::Item: AsRef<Path>,
{
    names.into_iter().for_each(|x| link_lib(kind, x))
}

/// Convenience: registers multiple search paths with the same kind.
pub fn link_search_paths<I>(kind: Option<SearchKind>, paths: I)
where
    I: IntoIterator,
    I::Item: AsRef<Path>,
{
    paths.into_iter().for_each(|x| link_search(kind, x))
}

/// Sets an environment variable in `rustc`.
pub fn env_var<K: AsRef<str>, V: AsRef<str>>(key: K, val: V) {
    println!("cargo:rustc-env={}={}", key.as_ref(), val.as_ref());
}

/// Sets multiple environment variables in `rustc`.
pub fn env_vars<I, K, V>(vars: I)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    vars.into_iter().for_each(|(k, v)| env_var(k, v))
}

/// Passes a linker argument via `rustc`.
pub fn link_arg<A: AsRef<str>>(arg: A) {
    println!("cargo:rustc-link-arg={}", arg.as_ref());
}

/// Passes multiple linker arguments via `rustc`.
pub fn link_args<I, A>(args: I)
where
    I: IntoIterator<Item = A>,
    A: AsRef<str>,
{
    args.into_iter().for_each(|a| link_arg(a))
}

/// Defines a conditional compilation check-cfg.
pub fn check_cfg<C: AsRef<str>>(cfg: C) {
    println!("cargo:rustc-check-cfg={}", cfg.as_ref());
}

/// Defines multiple conditional compilation check-cfgs.
pub fn check_cfgs<I, C>(cfgs: I)
where
    I: IntoIterator<Item = C>,
    C: AsRef<str>,
{
    cfgs.into_iter().for_each(|c| check_cfg(c))
}
