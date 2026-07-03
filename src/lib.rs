// Copyright (c) 2022-2026 Sprite Tong (<spritetong@gmail.com>)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Build script utilities for CMake FFI and cross-compilation.
//!
//! This crate provides convenience wrappers over Cargo build script
//! environment variables, plus CMake integration for C/C++ FFI bindings.

pub mod bgx;
pub mod bin;
pub mod cargo;
pub mod cmkabe;
pub mod metadata;
pub mod rustc;
pub mod target;

pub use ::bindgen;
pub use ::std::{
    cell::RefCell,
    collections::HashSet,
    env, fs,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};
pub use filetime::{self, FileTime};
pub use regex::{self, Regex, RegexSet};
pub use semver;
pub use walkdir::{self, DirEntry, WalkDir};

/// Instructs Cargo to display a warning.
///
/// `warning!(..)` is shorthand for `warning(&format!(..))`.
#[macro_export]
macro_rules! warning {
    ($($args:tt)*) => {
        $crate::warning(format!($($args)*))
    };
}

/// Error type indicating a string parse failed due to invalid input.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct InvalidInput(String);

impl InvalidInput {
    /// Returns the input which caused the error.
    pub fn input(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid input: {:?}", self.0)
    }
}

impl std::error::Error for InvalidInput {
    fn description(&self) -> &str {
        "invalid input"
    }
}

/// Represents an atomic type supported by a target.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Atomic {
    /// Integers with the given number of `bits` are atomic.
    Integer { bits: u8 },
    /// Pointers are atomic.
    Pointer,
}

impl std::fmt::Display for Atomic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Atomic::Integer { bits } => write!(f, "{bits}"),
            Atomic::Pointer => write!(f, "ptr"),
        }
    }
}

impl std::str::FromStr for Atomic {
    type Err = InvalidInput;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "ptr" {
            Ok(Atomic::Pointer)
        } else if let Ok(bits) = s.parse::<u8>() {
            Ok(Atomic::Integer { bits })
        } else {
            Err(InvalidInput(s.to_owned()))
        }
    }
}

/// Represents the target platform's endianness.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Endianness {
    Big,
    Little,
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endianness::Big => write!(f, "big"),
            Endianness::Little => write!(f, "little"),
        }
    }
}

impl std::str::FromStr for Endianness {
    type Err = InvalidInput;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "big" => Ok(Endianness::Big),
            "little" => Ok(Endianness::Little),
            _ => Err(InvalidInput(s.to_owned())),
        }
    }
}

/// Library linkage kind.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum LibKind {
    /// Link a static library.
    Static,
    /// Link a dynamic library.
    DyLib,
    /// Link an Objective-C framework (macOS/iOS).
    Framework,
}

impl std::fmt::Display for LibKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LibKind::Static => write!(f, "static"),
            LibKind::DyLib => write!(f, "dylib"),
            LibKind::Framework => write!(f, "framework"),
        }
    }
}

impl std::str::FromStr for LibKind {
    type Err = InvalidInput;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "static" => Ok(LibKind::Static),
            "dylib" => Ok(LibKind::DyLib),
            "framework" => Ok(LibKind::Framework),
            _ => Err(InvalidInput(s.to_owned())),
        }
    }
}

/// A build profile.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Profile {
    Debug,
    Release,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Profile::Debug => write!(f, "debug"),
            Profile::Release => write!(f, "release"),
        }
    }
}

impl std::str::FromStr for Profile {
    type Err = InvalidInput;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "debug" => Ok(Profile::Debug),
            "release" => Ok(Profile::Release),
            _ => Err(InvalidInput(s.to_owned())),
        }
    }
}

/// Library search path kind.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SearchKind {
    Dependency,
    Crate,
    Native,
    Framework,
    All,
}

impl std::fmt::Display for SearchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchKind::Dependency => write!(f, "dependency"),
            SearchKind::Crate => write!(f, "crate"),
            SearchKind::Native => write!(f, "native"),
            SearchKind::Framework => write!(f, "framework"),
            SearchKind::All => write!(f, "all"),
        }
    }
}

impl std::str::FromStr for SearchKind {
    type Err = InvalidInput;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dependency" => Ok(SearchKind::Dependency),
            "crate" => Ok(SearchKind::Crate),
            "native" => Ok(SearchKind::Native),
            "framework" => Ok(SearchKind::Framework),
            "all" => Ok(SearchKind::All),
            _ => Err(InvalidInput(s.to_owned())),
        }
    }
}

/// Platform triple (e.g. `x86_64-unknown-linux-gnu`).
///
/// Parsed into architecture, vendor/family, OS, and optional environment fields.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Triple {
    raw: String,
    arch: String,
    vendor: String,
    os: String,
    env: Option<String>,
}

impl Triple {
    /// Creates a `Triple` from its string representation.
    pub fn new(triple: String) -> Triple {
        let segments: Vec<&str> = triple.splitn(4, '-').collect();
        let arch = segments.first().map(|&s| s.to_owned()).unwrap_or_default();
        let vendor = segments.get(1).map(|&s| s.to_owned()).unwrap_or_default();
        let os = segments.get(2).map(|&s| s.to_owned()).unwrap_or_default();
        let env = segments
            .get(3)
            .filter(|&s| !s.is_empty())
            .map(|&s| s.to_owned());
        Triple {
            raw: triple,
            arch,
            vendor,
            os,
            env,
        }
    }

    /// Returns the full triple string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Processor architecture (e.g. `x86_64`, `aarch64`, `arm`).
    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// Toolchain environment (e.g. `gnu`, `msvc`, `musl`).
    /// Returns `None` if unspecified.
    pub fn env(&self) -> Option<&str> {
        self.env.as_deref()
    }

    /// Vendor/family (e.g. `pc`, `apple`, `unknown`).
    pub fn family(&self) -> &str {
        &self.vendor
    }

    /// Operating system (e.g. `linux`, `windows`, `darwin`).
    pub fn os(&self) -> &str {
        &self.os
    }
}

impl std::fmt::Display for Triple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.raw.fmt(f)
    }
}

impl std::str::FromStr for Triple {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Triple::new(s.to_owned()))
    }
}

/// Whether this is a debug build.
pub fn debug() -> bool {
    std::env::var("DEBUG").expect("DEBUG env var is not set") == "true"
}

/// Host platform triple.
pub fn host() -> Triple {
    Triple::new(std::env::var("HOST").expect("HOST env var is not set"))
}

/// Number of top-level parallel jobs.
pub fn num_jobs() -> u32 {
    let raw = std::env::var("NUM_JOBS").expect("NUM_JOBS env var is not set");
    raw.parse().expect("NUM_JOBS is not a valid integer")
}

/// Optimisation level (e.g. `0`, `1`, `2`, `3`, `s`, `z`).
pub fn opt_level() -> String {
    std::env::var("OPT_LEVEL").expect("OPT_LEVEL env var is not set")
}

/// Output directory for build script artifacts (`OUT_DIR`).
pub fn out_dir() -> PathBuf {
    std::env::var_os("OUT_DIR")
        .expect("OUT_DIR env var is not set")
        .into()
}

/// Build profile (`Debug` or `Release`).
pub fn profile() -> Profile {
    let raw = std::env::var("PROFILE").expect("PROFILE env var is not set");
    match raw.as_str() {
        "debug" => Profile::Debug,
        "release" => Profile::Release,
        other => panic!("PROFILE {other:?} is not a valid profile"),
    }
}

/// Instructs Cargo to rerun the build script if the given file/directory changes.
pub fn rerun_if_changed<P: AsRef<Path>>(path: P) {
    println!("cargo:rerun-if-changed={}", path.as_ref().display());
}

/// Instructs Cargo to rerun the build script if the given environment variable changes.
pub fn rerun_if_env_changed<N: AsRef<str>>(name: N) {
    println!("cargo:rerun-if-env-changed={}", name.as_ref());
}

/// Temporary directory for the current build target (`CARGO_TARGET_TMPDIR`).
pub fn target_tmpdir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_TMPDIR")
        .expect("CARGO_TARGET_TMPDIR env var is not set")
        .into()
}

/// Whether the current package is the primary target being compiled.
pub fn is_primary_package() -> bool {
    std::env::var("CARGO_PRIMARY_PACKAGE").is_ok()
}

/// Whether the target platform is Windows.
pub fn windows() -> bool {
    std::env::var("CARGO_CFG_WINDOWS").is_ok()
}

/// Whether the target platform is UNIX.
pub fn unix() -> bool {
    std::env::var("CARGO_CFG_UNIX").is_ok()
}

/// Instructs Cargo to display a warning message.
pub fn warning<S: AsRef<str>>(msg: S) {
    println!("cargo:warning={}", msg.as_ref());
}

/// Instructs Cargo to display an error and fail the build.
pub fn error<S: AsRef<str>>(msg: S) {
    println!("cargo:error={}", msg.as_ref());
}

////////////////////////////////////////////////////////////////////////////////

/// Converts a name to the canonical environment-variable format:
/// upper-case, with hyphens replaced by underscores.
pub fn canon_feature_name<T: AsRef<str>>(name: T) -> String {
    name.as_ref().to_ascii_uppercase().replace('-', "_")
}

/// Resolves a path to its canonical (real) form if it exists,
/// stripping the `\\?\` prefix on Windows. Returns the original
/// path if canonicalization fails.
pub fn realpath<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    match path.canonicalize() {
        Ok(v) => {
            let s = v.to_string_lossy();
            match s.strip_prefix(r"\\?\") {
                Some(v) => v.into(),
                _ => s.into_owned().into(),
            }
        }
        _ => path.to_owned(),
    }
}

/// Watch file changes in the specified directory and triggers rebuilds when matching files change.
///
/// # Arguments
/// * `root` - The root directory to watch
/// * `patterns` - Regular expression patterns to match filenames against
///
/// # Returns
/// * `io::Result<()>` - Success or error status
pub fn watch_file_changes<R, P>(root: R, patterns: P) -> io::Result<()>
where
    R: AsRef<Path>,
    P: IntoIterator,
    P::Item: AsRef<str>,
{
    let re = RegexSet::new(patterns).map_err(io::Error::other)?;
    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                // Ignore hidden directories and the "target" directory.
                .map(|s| s.starts_with('.') || s == "target")
                .unwrap_or(false)
        })
    {
        if let Ok(entry) = entry.as_ref() {
            if entry.file_type().is_file()
                && re.is_match(entry.file_name().to_string_lossy().as_ref())
            {
                rerun_if_changed(entry.path());
            }
        }
    }
    Ok(())
}

/// Updates the timestamps of the specified files.
///
/// # Arguments
/// * `files` - Iterator of file paths to touch
///
/// # Returns
/// * `io::Result<()>` - Success or error status
pub fn touch<P>(files: P) -> io::Result<()>
where
    P: IntoIterator,
    P::Item: AsRef<Path>,
{
    for file in files.into_iter() {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(file)?;
        filetime::set_file_handle_times(&f, None, Some(FileTime::now()))?;
    }
    Ok(())
}
