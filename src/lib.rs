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

    /// Get triple from the cross compile linker if it's present,
    /// or the target triple otherwize.
    pub fn linker_triple() -> String {
        let triple = target::triple().to_string();
        match env::var(format!(
            "CARGO_TARGET_{}_LINKER",
            canon_feature_name(&triple)
        ))
        .or_else(|_| env::var("RUSTC_LINKER"))
        {
            // Remove the tailer "-gcc".
            Ok(v) => v
                .split('-')
                .rev()
                .skip(1)
                .collect::<Vec<&str>>()
                .into_iter()
                .rev()
                .collect::<Vec<&str>>()
                .join("-"),
            _ => triple,
        }
    }

    // Get the workspace directory.
    pub fn workspace_dir() -> PathBuf {
        initialize();
        env::var("CARGO_WORKSPACE_DIR").unwrap().into()
    }

    /// <workspace>/target
    pub fn build_target_dir() -> PathBuf {
        initialize();
        env::var("CARGO_BUILD_TARGET_DIR").unwrap().into()
    }

    /// <workspace>/target/<debug|release>
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

    pub fn link_libs<I>(kind: Option<LibKind>, names: I)
    where
        I: IntoIterator,
        I::Item: AsRef<Path>,
    {
        names.into_iter().for_each(|x| link_lib(kind, x))
    }

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
pub fn canon_feature_name<T: AsRef<str>>(name: T) -> String {
    name.as_ref().to_ascii_uppercase().replace('-', "_")
}

/// Get the real path, or the original value if the path is not existent.
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
