use super::*;
use std::{
    borrow::Cow,
    collections::{hash_map::DefaultHasher, BTreeMap, VecDeque},
    hash::{Hash, Hasher},
    io::Read,
};

pub fn is_under_rust_analyzer(set_rebuild_tag: bool) -> bool {
    let result = env::var("VSCODE_PID").is_ok();
    if result && set_rebuild_tag {
        use ::std::sync::atomic::{AtomicBool, Ordering};
        static IS_INITED: AtomicBool = AtomicBool::new(false);
        if IS_INITED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let path = out_dir().with_file_name(".leach.timestamp");
            if cmake::touch([&path]).is_ok() {
                rerun_if_changed(path);
            }
        }
    }
    result
}

pub fn monitor_file_changes<R, P>(root: R, patterns: P) -> io::Result<()>
where
    R: AsRef<Path>,
    P: IntoIterator,
    P::Item: AsRef<str>,
{
    let re =
        RegexSet::new(patterns.into_iter()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name()
                .to_str()
                // Ingore hidden directories and the "target" directory.
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

/// Returns the target output prefix directory of `cmake-abe`,
/// excluding the tailing `/<target-triple>`.
pub fn target_prefix_dir() -> Option<String> {
    env::var("CMKABE_TARGET_PREFIX").ok()
}

/// Returns the target output prefix directory of `cmake-abe`,
/// including the tailing `/<target-triple>`.
pub fn prefix_triple_dir() -> Option<String> {
    if let Some((target, _, target_prefix_dir)) = cmkabe_target_prefix() {
        Some(format!("{}/{}", target_prefix_dir, target))
    } else {
        None
    }
}

/// Set the link search paths of `cmake-abe`.
pub fn set_link_search(link_kind: Option<SearchKind>) {
    if let Ok(dirs) = env::var("CMKABE_LINK_DIRS") {
        env::split_paths(&dirs).for_each(|dir| {
            if let Some(dir) = dir.to_str() {
                let dir = dir.trim();
                if !dir.is_empty() {
                    rustc::link_search(link_kind, dir);
                }
            }
        });
    }
}

fn cmkabe_target_prefix() -> Option<(String, String, String)> {
    if let (Ok(mut target), Ok(cargo_target), Ok(target_prefix_dir)) = (
        env::var("CMKABE_TARGET"),
        env::var("CMKABE_CARGO_TARGET"),
        env::var("CMKABE_TARGET_PREFIX"),
    ) {
        if target.is_empty() || target == "native" {
            target.clone_from(&cargo_target);
        }
        Some((target, cargo_target, target_prefix_dir))
    } else {
        None
    }
}

/// Build helper for cmake.
#[derive(Clone, Default)]
pub struct Builder {
    target: String,
    args: Vec<String>,
}

impl Builder {
    pub fn target(&mut self, target: impl Into<String>) -> &mut Self {
        self.target = target.into();
        self
    }

    pub fn arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<A>(&mut self, args: A) -> &mut Self
    where
        A: IntoIterator,
        A::Item: Into<String>,
    {
        self.args.extend(args.into_iter().map(|x| x.into()));
        self
    }

    pub fn build(&self) -> io::Result<()> {
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
        if env::var("CMKABE_TARGET").is_ok() {
            fn opt(name: &str, key: &str) -> String {
                format!("{}={}", name, env::var(key).unwrap_or_default())
            }
            args.push(opt("TARGET", "CMKABE_TARGET"));
            args.push(opt("TARGET_DIR", "CMKABE_TARGET_DIR"));
            args.push(opt("TARGET_CMAKE_DIR", "CMKABE_TARGET_CMAKE_DIR"));
            args.push(opt("CMAKE_TARGET_PREFIX", "CMKABE_TARGET_PREFIX"));
            args.push(opt("TARGET_CC", "CMKABE_TARGET_CC"));
            args.push(opt("CARGO_TARGET", "CMKABE_CARGO_TARGET"));
            args.push(opt("ZIG_TARGET", "CMKABE_ZIG_TARGET"));
            args.push(opt("DEBUG", "CMKABE_DEBUG"));
            args.push(opt("MINSIZE", "CMKABE_MINSIZE"));
            args.push(opt("DBGINFO", "CMKABE_DBGINFO"));
        } else {
            let (triple, _linker) = cargo::triple_linker();
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
            status => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("CMake build failed with error code: {status}"),
            )),
        }
    }
}

#[derive(Clone, Default, Hash)]
pub struct Bindgen {
    rs_file: Option<PathBuf>,
    allow_bad_code_styles: bool,
    headers: Vec<String>,
    includes: Vec<String>,
    definitions: Vec<(String, String)>,
    allowlist: Vec<String>,
    blocklist: Vec<String>,
    header_codes: Vec<String>,
    footer_codes: Vec<String>,
    derive: BTreeMap<String, Vec<String>>,
}

pub type BeforeBindgenCb =
    dyn FnOnce(&mut Bindgen, bindgen::Builder) -> io::Result<bindgen::Builder>;

impl Bindgen {
    pub fn rs_file<T: Into<PathBuf>>(&mut self, rs_file: T) -> &mut Self {
        self.rs_file = Some(rs_file.into());
        self
    }

    pub fn allow_bad_code_styles(&mut self) -> &mut Self {
        self.allow_bad_code_styles = true;
        self
    }

    pub fn deny_bad_code_styles(&mut self) -> &mut Self {
        self.allow_bad_code_styles = false;
        self
    }

    pub fn header<T: AsRef<Path>>(&mut self, header: T) -> &mut Self {
        self.headers.push(Self::norm_path(realpath(header)));
        self
    }

    pub fn headers<T>(&mut self, headers: T) -> &mut Self
    where
        T: IntoIterator,
        T::Item: AsRef<Path>,
    {
        self.headers
            .extend(headers.into_iter().map(|x| Self::norm_path(realpath(x))));
        self
    }

    pub fn include<T: AsRef<Path>>(&mut self, include: T) -> &mut Self {
        self.includes.push(Self::norm_path(include));
        self
    }

    pub fn includes<T>(&mut self, includes: T) -> &mut Self
    where
        T: IntoIterator,
        T::Item: AsRef<Path>,
    {
        self.includes
            .extend(includes.into_iter().map(Self::norm_path));
        self
    }

    /// Set the C/C++ includes of `cmake-abe`.
    pub fn cmake_includes(&mut self) -> &mut Self {
        if let Ok(dirs) = env::var("CMKABE_INCLUDE_DIRS") {
            env::split_paths(&dirs).for_each(|dir| {
                if let Some(dir) = dir.to_str() {
                    let dir = dir.trim();
                    if !dir.is_empty() {
                        self.includes.push(dir.to_owned());
                    }
                }
            });
        }
        self
    }

    pub fn definition<K, V>(&mut self, name: K, value: V) -> &mut Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.definitions.push((name.into(), value.into()));
        self
    }

    pub fn definitions<T, K, V>(&mut self, definitions: T) -> &mut Self
    where
        T: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.definitions
            .extend(definitions.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    pub fn allowlist<T>(&mut self, allowlist: T) -> &mut Self
    where
        T: IntoIterator,
        T::Item: Into<String>,
    {
        self.allowlist
            .extend(allowlist.into_iter().map(|x| x.into()));
        self
    }

    pub fn blocklist<T>(&mut self, blocklist: T) -> &mut Self
    where
        T: IntoIterator,
        T::Item: Into<String>,
    {
        self.blocklist
            .extend(blocklist.into_iter().map(|x| x.into()));
        self
    }

    pub fn raw_line<T: Into<String>>(&mut self, line: T) -> &mut Self {
        self.header_codes.push(line.into());
        self
    }

    pub fn raw_lines<T>(&mut self, lines: T) -> &mut Self
    where
        T: IntoIterator,
        T::Item: Into<String>,
    {
        self.header_codes
            .extend(lines.into_iter().map(|x| x.into()));
        self
    }

    pub fn tail_raw_line<T: Into<String>>(&mut self, line: T) -> &mut Self {
        self.footer_codes.push(line.into());
        self
    }

    pub fn tail_raw_lines<T>(&mut self, lines: T) -> &mut Self
    where
        T: IntoIterator,
        T::Item: Into<String>,
    {
        self.footer_codes
            .extend(lines.into_iter().map(|x| x.into()));
        self
    }

    pub fn derive<N, T>(&mut self, types: T, traits: N) -> &mut Self
    where
        T: IntoIterator,
        T::Item: Into<String>,
        N: IntoIterator,
        N::Item: Into<String>,
    {
        let mut types = types.into_iter().map(|x| x.into()).collect::<Vec<String>>();
        let traits = traits
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<String>>();
        if types.is_empty() {
            types.push(String::new())
        }
        for ty in types.iter() {
            if !self.derive.contains_key(ty) {
                self.derive.insert(ty.clone(), Vec::new());
            }
            let lst = self.derive.get_mut(ty).unwrap();
            for tr in traits.iter() {
                if !lst.contains(tr) {
                    lst.push(tr.clone());
                }
            }
        }
        self
    }

    pub fn generate(&mut self, f: Option<Box<BeforeBindgenCb>>) -> io::Result<()> {
        use bindgen::callbacks::ParseCallbacks;
        #[derive(Debug)]
        struct DependCallbacks {
            root: String,
            cell: RefCell<(fs::File, HashSet<String>)>,
        }
        impl ParseCallbacks for DependCallbacks {
            fn include_file(&self, filename: &str) {
                let filename = Bindgen::norm_path(filename);
                if filename.starts_with(&self.root) {
                    let mut cell = self.cell.borrow_mut();
                    if !cell.1.contains(&filename) {
                        let _ = writeln!(cell.0, "{}", &filename);
                        rerun_if_changed(&filename);
                        cell.1.insert(filename);
                    }
                }
            }
        }
        impl DependCallbacks {
            fn new(root: &Path, dep_file: &Path, headers: &[String]) -> io::Result<Self> {
                let cb = Self {
                    root: Bindgen::norm_path(root),
                    cell: RefCell::new((
                        fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .create(true)
                            .open(dep_file)?,
                        HashSet::new(),
                    )),
                };

                for header in headers.iter() {
                    cb.include_file(header);
                }
                // Write an empty line to seperate the original headers from parsed dependencies.
                writeln!(cb.cell.borrow_mut().0)?;

                Ok(cb)
            }

            fn is_rebuild_required(rs_file: &Path, dep_file: &Path, headers: &[String]) -> bool {
                if let Ok(metadata) = fs::metadata(rs_file) {
                    let rs_mtime = FileTime::from_last_modification_time(&metadata);
                    if let Ok(f) = fs::File::open(dep_file) {
                        #[allow(clippy::lines_filter_map_ok)]
                        let lines: Vec<String> = io::BufReader::new(f)
                            .lines()
                            .map_while(Result::ok)
                            .collect();

                        // Compare the current headers to the previous headers.
                        let old: Vec<&String> =
                            lines.iter().take_while(|&x| !x.is_empty()).collect();
                        let matching = headers
                            .iter()
                            .zip(old.iter())
                            .filter(|&(a, &b)| a == b)
                            .count();
                        if matching == headers.len() && matching == old.len() {
                            let mut skip = true;
                            for dep in lines.iter().filter(|&x| !x.is_empty()) {
                                match fs::metadata(dep)
                                    .map(|x| FileTime::from_last_modification_time(&x))
                                {
                                    Ok(mtime) => {
                                        // Check <rs_file> and header file's update timestamp.
                                        if rs_mtime < mtime {
                                            skip = false;
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        skip = false;
                                        break;
                                    }
                                }
                            }
                            if skip {
                                for dep in lines.iter().filter(|&x| !x.is_empty()) {
                                    rerun_if_changed(dep);
                                }
                                return false;
                            }
                        }
                    }
                }
                true
            }
        }

        let root = Self::norm_path(cargo::workspace_dir());
        let rs_file = match self.rs_file.as_ref() {
            Some(x) => Self::norm_path(realpath(x)),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "No <rs_file>")),
        };

        // Sort headers & derive crates.
        self.headers.sort();

        // File to store dependencies.
        let dep_file = out_dir()
            .with_file_name(
                rs_file
                    .strip_prefix(&root)
                    .and_then(|x| x.strip_prefix('/'))
                    .unwrap_or(&rs_file)
                    .replace(':', "_")
                    .replace('/', "__"),
            )
            .with_extension("leach.d");
        let hash_file = dep_file.with_extension("hash");

        // Watch the output file.
        rerun_if_changed(&rs_file);

        // Check timestamp of dependencies.
        let hash = {
            let mut hasher = DefaultHasher::new();
            self.hash(&mut hasher);
            hasher.finish()
        };
        if !self.is_hash_changed(&hash_file, hash)
            && !DependCallbacks::is_rebuild_required(
                Path::new(&rs_file),
                dep_file.as_ref(),
                self.headers.as_slice(),
            )
        {
            return Ok(());
        }
        // Create file to store dependencies.
        let depen_callback = Box::new(DependCallbacks::new(
            Path::new(&root),
            &dep_file,
            self.headers.as_slice(),
        )?);

        // Create builder.
        let mut builder = Self::default_builder();

        // Common derivation.
        if let Some(traits) = self.derive.get("") {
            for tr in traits {
                match tr.as_str() {
                    "Copy" => builder = builder.derive_copy(true),
                    "Debug" => builder = builder.derive_debug(true),
                    "Default" => builder = builder.derive_default(true),
                    "Hash" => builder = builder.derive_hash(true),
                    "PartialOrd" => builder = builder.derive_partialord(true),
                    "Ord" => builder = builder.derive_ord(true),
                    "PartialEq" => builder = builder.derive_partialeq(true),
                    "Eq" => builder = builder.derive_eq(true),
                    _ => (),
                }
            }
        }

        // C headers
        for header in self.headers.iter() {
            builder = builder.header(header);
        }

        // Include directories
        for include in self.includes.iter() {
            builder = builder.clang_arg(format!("-I{include}"))
        }

        // Macro definitions
        for (name, value) in self.definitions.iter() {
            builder = builder.clang_arg(format!("-D{name}={value}"))
        }

        // Header codes
        if self.allow_bad_code_styles {
            builder = builder
                .raw_line("#![allow(dead_code)]")
                .raw_line("#![allow(improper_ctypes)]")
                .raw_line("#![allow(improper_ctypes_definitions)]")
                .raw_line("#![allow(non_camel_case_types)]")
                .raw_line("#![allow(non_snake_case)]")
                .raw_line("#![allow(non_upper_case_globals)]")
                .raw_line("#![allow(clippy::missing_safety_doc)]")
                .raw_line("#![allow(clippy::missing_transmute_annotations)]")
                .raw_line("#![allow(clippy::too_many_arguments)]")
                .raw_line("#![allow(clippy::useless_transmute)]");
            if !self.header_codes.is_empty() {
                builder = builder.raw_line("");
            }
        }
        for line in self.header_codes.iter() {
            builder = builder.raw_line(line);
        }

        // Set allowlist
        for name in self.allowlist.iter() {
            builder = builder
                .allowlist_function(name)
                .allowlist_type(name)
                .allowlist_var(name);
        }

        // Set blocklist
        for name in self.blocklist.iter() {
            builder = builder.blocklist_item(name);
        }

        // Store depenencies.
        builder = builder.parse_callbacks(depen_callback);

        // Apply custom operation on the builder.
        if let Some(f) = f {
            builder = f(self, builder)?;
        }

        // Build the FFI file.
        let bindings = builder
            .generate()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Write the .rs file.
        let mut buf = Vec::<u8>::new();
        let mut w = io::Cursor::new(&mut buf);
        bindings.write(Box::new(&mut w))?;
        if !self.footer_codes.is_empty() {
            w.write_all(b"\n")?;
            for line in self.footer_codes.iter() {
                w.write_all(line.as_bytes())?;
                w.write_all(b"\n")?;
            }
        }
        w.flush()?;
        let file = fs::OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(&rs_file)?;
        Self::apply_derive(self, file, buf)?;

        self.write_hash(&hash_file, hash)
    }

    fn is_hash_changed(&self, hash_file: &Path, hash: u64) -> bool {
        if let Ok(mut f) = fs::File::open(hash_file) {
            let mut buf = String::new();
            f.read_to_string(&mut buf).ok();
            if buf.parse::<u64>() == Ok(hash) {
                return false;
            }
        }
        true
    }

    fn write_hash(&self, hash_file: &Path, hash: u64) -> io::Result<()> {
        let mut f = fs::File::create(hash_file)?;
        f.write_all(hash.to_string().as_bytes())
    }

    fn apply_derive(&self, mut file: fs::File, text: Vec<u8>) -> io::Result<()> {
        let mut lines: VecDeque<Cow<'_, str>> = text
            .split(|&x| x == b'\n')
            .map(|x| String::from_utf8_lossy(x.strip_suffix(&[b'\r']).unwrap_or(x)))
            .collect();

        let derive_re = Regex::new(r"^#\[derive\(([[[:word:]], ]+)\)\]$").unwrap();
        let type_re = Regex::new(r"^pub (?:enum|struct) ([[:word:]]+) \{$").unwrap();

        // UTF-8 BOM
        file.write_all(b"\xEF\xBB\xBF")?;

        // Remove all empty lines at the tail.
        while let Some(line) = lines.back() {
            if line.is_empty() {
                lines.pop_back();
            } else {
                break;
            }
        }

        while let Some(line) = lines.pop_front() {
            if let Some(cap) = derive_re.captures(&line) {
                let derived = cap[1].split(',').map(|x| x.trim()).collect::<Vec<&str>>();
                let mut traits = derived.clone();
                for next_line in lines.iter() {
                    if let Some(cap) = type_re.captures(next_line) {
                        for ty in ["", &cap[1]] {
                            if let Some(derive) = self.derive.get(ty) {
                                for pattern in derive {
                                    if let Some(tr) = pattern.strip_prefix('-') {
                                        if let Some(i) = traits.iter().position(|&x| x == tr) {
                                            traits.remove(i);
                                        }
                                    } else {
                                        let tr = pattern.strip_prefix('+').unwrap_or(pattern);
                                        if !traits.contains(&tr)
                                            && (derived.contains(&tr) || !self.is_auto_derive(tr))
                                        {
                                            traits.push(tr);
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
                if !traits.is_empty() {
                    file.write_all(format!("#[derive({})]", traits.join(", ")).as_bytes())?;
                } else {
                    traits.sort();
                    file.write_all(b"// No derivation")?;
                }
            } else {
                file.write_all(line.as_bytes())?;
            }
            file.write_all(b"\n")?;
        }
        Ok(())
    }

    fn is_auto_derive(&self, trait_: &str) -> bool {
        self.derive
            .get("")
            .map(|x| x.iter().any(|x| x == trait_))
            .unwrap_or(false)
            && [
                "Copy",
                "Debug",
                "Default",
                "Hash",
                "PartialOrd",
                "Ord",
                "PartialEq",
                "Eq",
            ]
            .contains(&trait_)
    }

    fn norm_path<P: AsRef<Path>>(path: P) -> String {
        path.as_ref().to_string_lossy().as_ref().replace('\\', "/")
    }

    fn default_builder() -> bindgen::Builder {
        bindgen::Builder::default()
            .disable_header_comment()
            .layout_tests(false)
            .formatter(bindgen::Formatter::Rustfmt)
            .prepend_enum_name(false)
            .size_t_is_usize(true)
    }
}
