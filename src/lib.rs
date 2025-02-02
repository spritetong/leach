pub use ::bindgen;
pub use ::build_helper::{self, *};
pub use ::std::{
    cell::RefCell,
    collections::HashSet,
    env, fs,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};
pub use filetime::{self, FileTime};
pub use regex::{self, Regex, RegexSet};
pub use walkdir::{self, DirEntry, WalkDir};

pub mod cmake;

pub mod bin {
    pub use ::build_helper::bin::*;
}

pub mod cargo {
    use super::*;
    pub use ::build_helper::cargo::*;

    /// Get `(<target-triple>, Option<cross-linker-name>)` from
    /// the cross compile linker if it's present, or the target triple otherwize.
    pub fn triple_linker() -> (String, Option<String>) {
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
            // Remove the tailing "-gcc".
            if let Some(prefix) = linker
                .strip_suffix("-gcc")
                .or_else(|| linker.strip_suffix("-cc"))
            {
                if prefix.chars().filter(|&x| x == '-').count() >= 2 {
                    return (prefix.to_owned(), Some(linker));
                }
            }
            (triple, Some(linker))
        } else {
            (triple, None)
        }
    }

    // Get the workspace directory.
    pub fn workspace_dir() -> PathBuf {
        initialize();
        env::var("CARGO_WORKSPACE_DIR").unwrap().into()
    }

    /// `<workspace>/target`
    pub fn build_target_dir() -> PathBuf {
        initialize();
        env::var("CARGO_BUILD_TARGET_DIR").unwrap().into()
    }

    /// `<workspace>/target/<debug|release>`
    pub fn build_output_dir() -> PathBuf {
        initialize();
        env::var("CARGO_BUILD_OUTPUT_DIR").unwrap().into()
    }

    /// Initialize environment of cargo build.
    pub fn initialize() {
        use ::std::sync::atomic::{AtomicBool, Ordering};
        static IS_INITED: AtomicBool = AtomicBool::new(false);
        if IS_INITED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        // TARGET: triple
        // CARGO_WORKSPACE_DIR, CARGO_BUILD_TARGET_DIR, CARGO_BUILD_OUTPUT_DIR

        let out_path = realpath(env::var("OUT_DIR").unwrap());
        let mut it = out_path.ancestors().skip(3);
        // <workspace>/target/<debug|release>
        let output_dir = it.next().unwrap().to_string_lossy();
        let mut t = it.next().unwrap();
        let mut w = it.next().unwrap();
        while !w.join("Cargo.toml").is_file() {
            t = w;
            w = it.next().unwrap()
        }
        // <workspace>/target
        let target_dir = t.to_string_lossy();
        // <workspace>
        let workspace_dir = w.to_string_lossy();
        for (name, value) in [
            ("CARGO_WORKSPACE_DIR", workspace_dir.as_ref()),
            ("CARGO_BUILD_TARGET_DIR", target_dir.as_ref()),
            ("CARGO_BUILD_OUTPUT_DIR", output_dir.as_ref()),
        ] {
            env::set_var(name, value);
            println!("cargo:rustc-env={name}={value}");
        }
    }
}

pub mod metadata {
    pub use ::build_helper::metadata::*;
}

pub mod rustc {
    use super::*;
    pub use ::build_helper::rustc::*;

    /// Links a library to the Rust build.
    ///
    /// # Arguments
    /// * `kind` - The kind of library to link
    /// * `names` - Iterator of library paths to link
    pub fn link_libs<I>(kind: Option<LibKind>, names: I)
    where
        I: IntoIterator,

        I::Item: AsRef<Path>,
    {
        names.into_iter().for_each(|x| link_lib(kind, x))
    }

    /// Links search paths to the Rust build.
    ///
    /// # Arguments
    /// * `kind` - The kind of search path to link
    /// * `paths` - Iterator of paths to link
    pub fn link_search_paths<I>(kind: Option<SearchKind>, paths: I)
    where
        I: IntoIterator,

        I::Item: AsRef<Path>,
    {
        paths.into_iter().for_each(|x| link_search(kind, x))
    }
}

pub mod target {
    pub use ::build_helper::target::*;
}

/// Upper-case seperated with '_'
///
/// # Arguments
/// * `name` - The name to convert
///
/// # Returns
/// * `String` - The converted name
pub fn canon_feature_name<T: AsRef<str>>(name: T) -> String {
    name.as_ref().to_ascii_uppercase().replace('-', "_")
}

/// Get the real path, or the original value if the path is not existent.
///
/// # Arguments
/// * `path` - The path to get the real path of
///
/// # Returns
/// * `PathBuf` - The real path of the given path
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
