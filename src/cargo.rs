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

//! Cargo package environment info: features, manifest, package metadata,
//! and leach-specific build-directory helpers.

use crate::{canon_feature_name, realpath, target};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Enabled Cargo features.
pub mod features {
    use std::env;

    /// Iterator over all enabled Cargo features.
    ///
    /// Features are returned lower-cased, with underscores replaced by hyphens.
    pub struct Iter {
        cursor: env::Vars,
    }

    impl Iterator for Iter {
        type Item = String;

        fn next(&mut self) -> Option<Self::Item> {
            for (key, _) in self.cursor.by_ref() {
                if let Some(suffix) = key.strip_prefix("CARGO_FEATURE_") {
                    return Some(decode(suffix));
                }
            }
            None
        }
    }

    /// Returns an iterator over all enabled Cargo features.
    pub fn all() -> Iter {
        Iter {
            cursor: env::vars(),
        }
    }

    /// Whether a specific Cargo feature is enabled.
    pub fn enabled(name: &str) -> bool {
        let key = format!("CARGO_FEATURE_{}", encode(name));
        env::var(&key).is_ok()
    }

    /// Converts env-var-style feature name to display form.
    /// `CARGO_FEATURE_FOO_BAR` → `foo-bar`
    fn decode(name: &str) -> String {
        name.chars()
            .map(|c| match c {
                'A'..='Z' => c.to_ascii_lowercase(),
                '_' => '-',
                other => other,
            })
            .collect()
    }

    /// Converts display-form feature name to env-var style.
    /// `foo-bar` → `FOO_BAR`
    fn encode(name: &str) -> String {
        name.chars()
            .map(|c| match c {
                'a'..='z' => c.to_ascii_uppercase(),
                '-' => '_',
                other => other,
            })
            .collect()
    }
}

/// Name of the crate being built (`CARGO_CRATE_NAME`).
pub fn crate_name() -> String {
    env::var("CARGO_CRATE_NAME").expect("CARGO_CRATE_NAME env var is not set")
}

/// Package manifest information.
pub mod manifest {
    use std::env;
    use std::path::PathBuf;

    /// Path to the directory containing `Cargo.toml`.
    pub fn dir() -> PathBuf {
        let raw = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var is not set");
        PathBuf::from(raw)
    }

    /// The `package.links` field, if set.
    pub fn links() -> Option<String> {
        env::var("CARGO_MANIFEST_LINKS").ok()
    }

    /// Absolute path to the `Cargo.toml` file.
    pub fn path() -> PathBuf {
        let raw =
            env::var("CARGO_MANIFEST_PATH").expect("CARGO_MANIFEST_PATH env var is not set");
        PathBuf::from(raw)
    }
}

/// Package metadata (name, version, authors, etc.).
pub mod pkg {
    use std::env;

    /// Colon-separated list of package authors.
    pub fn authors() -> Vec<String> {
        let raw = env::var("CARGO_PKG_AUTHORS").expect("CARGO_PKG_AUTHORS env var is not set");
        raw.split(':').map(ToOwned::to_owned).collect()
    }

    /// Package description, or `None` if empty.
    pub fn description() -> Option<String> {
        let raw =
            env::var("CARGO_PKG_DESCRIPTION").expect("CARGO_PKG_DESCRIPTION env var is not set");
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    }

    /// Package homepage URL, or `None` if empty.
    pub fn homepage() -> Option<String> {
        let raw = env::var("CARGO_PKG_HOMEPAGE").expect("CARGO_PKG_HOMEPAGE env var is not set");
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    }

    /// Package name.
    pub fn name() -> String {
        env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME env var is not set")
    }

    /// Package repository URL, or `None` if empty.
    pub fn repository() -> Option<String> {
        let raw = env::var("CARGO_PKG_REPOSITORY").expect("CARGO_PKG_REPOSITORY env var is not set");
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    }

    /// Package license expression, or `None` if not specified.
    pub fn license() -> Option<String> {
        let raw = env::var("CARGO_PKG_LICENSE").ok()?;
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    }

    /// Minimum Rust version specified in `package.rust-version`, or `None`.
    pub fn rust_version() -> Option<String> {
        let raw = env::var("CARGO_PKG_RUST_VERSION").ok()?;
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    }

    /// Package version major number.
    pub fn version_major() -> u64 {
        let raw =
            env::var("CARGO_PKG_VERSION_MAJOR").expect("CARGO_PKG_VERSION_MAJOR env var is not set");
        raw.parse().expect("CARGO_PKG_VERSION_MAJOR is not a valid integer")
    }

    /// Package version minor number.
    pub fn version_minor() -> u64 {
        let raw =
            env::var("CARGO_PKG_VERSION_MINOR").expect("CARGO_PKG_VERSION_MINOR env var is not set");
        raw.parse().expect("CARGO_PKG_VERSION_MINOR is not a valid integer")
    }

    /// Package version patch number.
    pub fn version_patch() -> u64 {
        let raw =
            env::var("CARGO_PKG_VERSION_PATCH").expect("CARGO_PKG_VERSION_PATCH env var is not set");
        raw.parse().expect("CARGO_PKG_VERSION_PATCH is not a valid integer")
    }

    /// Package version pre-release tag (e.g. `"alpha.1"` or empty).
    pub fn version_pre() -> String {
        env::var("CARGO_PKG_VERSION_PRE").expect("CARGO_PKG_VERSION_PRE env var is not set")
    }
}

/// Resolves `(<target-triple>, Option<cross-linker-name>)` from the
/// cross-compile linker env var, or the target triple otherwise.
///
/// Strips trailing `-gcc`/`-cc` suffixes from the linker name when
/// the prefix contains at least two hyphens.
pub fn triple_with_linker() -> (String, Option<String>) {
    let triple = target::triple().to_string();
    if let Ok(linker_path) = env::var(format!(
        "CARGO_TARGET_{}_LINKER",
        canon_feature_name(&triple)
    ))
    .or_else(|_| env::var("RUSTC_LINKER"))
    {
        let linker = Path::new(&linker_path)
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if let Some(prefix) = linker
            .strip_suffix("-gcc")
            .or_else(|| linker.strip_suffix("-cc"))
            .filter(|p| p.chars().filter(|&x| x == '-').count() >= 2)
        {
            return (prefix.to_owned(), Some(linker));
        }
        (triple, Some(linker))
    } else {
        (triple, None)
    }
}

struct BuildDirs {
    workspace_dir: PathBuf,
    target_dir: PathBuf,
    output_dir: PathBuf,
}

static BUILD_DIRS: LazyLock<BuildDirs> = LazyLock::new(|| {
    // Typical OUT_DIR: <workspace>/target/<profile>/build/<pkg>/out
    // Walk up 3 levels to get the output dir, then find Cargo.toml.
    let out_path = realpath(env::var("OUT_DIR").unwrap());
    let mut it = out_path.ancestors().skip(3);
    let output_dir = it.next().unwrap().to_owned();
    let mut t = it.next().unwrap().to_owned();
    let mut w = it.next().unwrap().to_owned();
    while !w.join("Cargo.toml").is_file() {
        t = w.clone();
        w = it.next().unwrap().to_owned();
    }
    BuildDirs {
        workspace_dir: w,
        target_dir: t,
        output_dir,
    }
});

/// Returns the workspace root directory.
pub fn workspace_dir() -> PathBuf {
    BUILD_DIRS.workspace_dir.clone()
}

/// Returns `<workspace>/target`.
pub fn build_target_dir() -> PathBuf {
    BUILD_DIRS.target_dir.clone()
}

/// Returns `<workspace>/target/<debug|release>`.
pub fn build_output_dir() -> PathBuf {
    BUILD_DIRS.output_dir.clone()
}
