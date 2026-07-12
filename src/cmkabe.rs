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

//! CMake build integration helpers.
//! Provides CMake configuration, compilation, and installation utilities.

use super::*;

/// Get the CMake build type configured for `cmkabe`.
/// Possible values are: Debug, Release, RelWithDebInfo, or MinSizeRel.
pub fn cmake_build_type() -> Option<String> {
    env::var("CMKABE_CMAKE_BUILD_TYPE").ok()
}

/// Get the CMake build directory path.
pub fn cmake_build_dir() -> Option<String> {
    env::var("CMKABE_CMAKE_BUILD_DIR").ok()
}

/// Get sub-directories in the target prefix directories of `cmkabe`.
pub fn cmake_prefix_subdirs() -> Vec<PathBuf> {
    _cmake_env_dirs("CMKABE_PREFIX_SUBDIRS")
}

/// Get the `bin` directories of `cmkabe`.
pub fn cmake_bin_dirs() -> Vec<PathBuf> {
    _cmake_env_dirs("CMKABE_BIN_DIRS")
}

/// Get the `lib` directories of `cmkabe`.
pub fn cmake_lib_dirs() -> Vec<PathBuf> {
    _cmake_env_dirs("CMKABE_LIB_DIRS")
}

/// Get the `include` directories of `cmkabe`.
pub fn cmake_include_dirs() -> Vec<PathBuf> {
    _cmake_env_dirs("CMKABE_INCLUDE_DIRS")
}

/// Configures the link search paths for `cmkabe`.
///
/// # Arguments
/// * `link_kind` - Optional search kind configuration for the linker
pub fn set_link_search(link_kind: Option<SearchKind>) {
    for dir in cmake_lib_dirs() {
        rustc::link_search(link_kind, dir);
    }
}

fn _cmake_env_dirs(key: &str) -> Vec<PathBuf> {
    if let Ok(dirs) = env::var(key) {
        env::split_paths(&dirs)
            .filter_map(|dir| {
                dir.to_str().and_then(|dir| {
                    let dir = dir.trim();
                    if !dir.is_empty() {
                        Some(PathBuf::from(dir))
                    } else {
                        None
                    }
                })
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// Builder for configuring and executing CMake builds.
#[derive(Clone, Default)]
pub struct MakeBuilder {
    target: String,
    args: Vec<String>,
    skipped: bool,
}

impl MakeBuilder {
    const SPLIT_CHARS: &'static [char] = &[' ', '\t', ';', ','];

    /// Creates a new MakeBuilder configured with the specified CMake targets.
    ///
    /// # Arguments
    /// * `cmake_targets` - Iterator of CMake target names to build
    pub fn with_cmake_targets<I>(cmake_targets: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut builder = Self::default();

        let mut filter_out = Vec::<&str>::new();
        let completed_projects = env::var("CMKABE_COMPLETED_PROJECTS").ok();
        if let Some(ref s) = completed_projects {
            s.split(Self::SPLIT_CHARS)
                .filter(|&s| !s.is_empty())
                .for_each(|x| filter_out.push(x));
        }

        let mut arg = "CMAKE_TARGETS=".to_owned();
        builder.skipped = true;
        cmake_targets.into_iter().for_each(|x| {
            let s = x.as_ref();
            if !filter_out.contains(&s) {
                if builder.skipped {
                    builder.skipped = false;
                } else {
                    arg.push(' ');
                }
                arg.push_str(s);
            }
        });

        builder.arg("cmake".to_owned());
        builder.arg(arg);
        builder
    }

    /// Adds a single argument to the CMake build command.
    ///
    /// # Arguments
    /// * `arg` - Argument to add
    pub fn arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    /// Adds multiple arguments to the CMake build command.
    ///
    /// # Arguments
    /// * `args` - Iterator of arguments to add
    pub fn args<A>(&mut self, args: A) -> &mut Self
    where
        A: IntoIterator,

        A::Item: Into<String>,
    {
        self.args.extend(args.into_iter().map(|x| x.into()));
        self
    }

    /// Executes the CMake build with the configured settings.
    ///
    /// # Returns
    /// * `io::Result<()>` - Success or error status
    pub fn build(&self) -> io::Result<()> {
        if self.skipped {
            return Ok(());
        }

        let root = cargo::workspace_dir();
        let target = if self.target.is_empty() {
            "cmake-build".to_owned()
        } else if self.target.starts_with("cmake-") {
            self.target.clone()
        } else {
            format!("cmake-{}", &self.target)
        };

        let mut args = vec![target];
        args.extend(self.args.iter().cloned());
        if let Ok(vars) = env::var("CMKABE_MAKE_BUILD_VARS") {
            let mut key = String::new();
            for name in vars.split(Self::SPLIT_CHARS).filter(|&s| !s.is_empty()) {
                key.clear();
                key.push_str("CMKABE_");
                key.push_str(name);
                args.push(format!("{}={}", name, env::var(&key).unwrap_or_default()));
            }
        } else {
            let (triple, _linker) = cargo::triple_with_linker();
            args.push(format!("TARGET={}", triple));
        }

        rerun_if_changed(root.join("CMakeLists.txt"));
        match duct::cmd("make", args)
            .stdout_to_stderr()
            .unchecked()
            .dir(root)
            .run()?
            .status
            .code()
            .unwrap_or(1)
        {
            0 => Ok(()),
            status => Err(io::Error::other(format!(
                "CMake build failed with error code: {status}"
            ))),
        }
    }
}
