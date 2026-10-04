//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the port builder: a recipe realized as a phase script over its
//! fetched source against a private sysroot, then install processing.
//!
//! The derivation declares everything the build reads: the expanded recipe
//! (a JSON document the ports generator writes; buildutil parses no recipe
//! file), the target triple and the host variable naming it, the source,
//! vendor, sysroot and build-dependency derivations, the sysroot
//! composition manifest, the patches, the license corpus and the stage
//! layout. The builder knows none of these names; they arrive as
//! arguments, so no project policy lives here.
//!
//! Phase order: the private sysroot view (composed by `buildutil-sysroot` from
//! the sysroot derivation and the build dependencies' stages), unpack,
//! autoreconf, patches, the autoconf cache, then prepare, configure, build
//! and install. After the script, the declarative install rows, exclude
//! globs, the strip pass, license staging and the stage layout check run
//! in Rust — deterministic work stays out of the shell. The shell sees
//! `SRCDIR`, `STAGE`, `SYSROOT`, `REPOROOT`, `PORTDIR`, `NPROC`, `CC`,
//! `CXX`, `CFLAGS`, `LDFLAGS`, `AR`, `RANLIB`, `STRIP` and
//! `TOOLCHAIN_PREFIX`.

use crate::sdk_wire::Value;
use buildutil_compose::glob::glob_match;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Autotools,
    CMake,
    Make,
    Cargo,
    Targets,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installer {
    Destdir,
    Manifest,
    Snippet,
}

#[derive(Debug, Clone)]
pub struct InstallFile {
    pub src: String,
    pub dest: String,
    pub mode: u32,
}

#[derive(Debug, Clone)]
pub struct InstallSymlink {
    pub link: String,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct InstallTree {
    pub src: String,
    pub dest: String,
}

#[derive(Debug, Clone)]
pub struct TargetRule {
    pub name: String,
    pub sources: Vec<String>,
    pub extra_flags: Vec<String>,
}

/// The expanded recipe as the derivation declares it.
#[derive(Debug, Clone)]
pub struct PortRecipe {
    pub name: String,
    pub version: String,
    pub description: String,
    /// The license identifiers whose texts are staged.
    pub licenses: Vec<String>,
    pub style: Style,
    pub configure: Vec<String>,
    pub autoreconf: bool,
    pub env: Vec<(String, String)>,
    pub autoconf_cache: Vec<(String, String)>,
    pub prepare: Option<String>,
    pub configure_snippet: Option<String>,
    pub build_snippet: Option<String>,
    pub install_snippet: Option<String>,
    pub installer: Installer,
    pub make_target: String,
    pub install_files: Vec<InstallFile>,
    pub install_symlinks: Vec<InstallSymlink>,
    pub install_trees: Vec<InstallTree>,
    pub exclude: Vec<String>,
    pub nostrip: Vec<String>,
    pub libs: Vec<TargetRule>,
    pub targets: Vec<TargetRule>,
    pub targets_cflags: Vec<String>,
    /// The Cargo configuration text, `{vendor}` standing for the vendored
    /// crate directory; empty for a non-Cargo port.
    pub cargo_config: String,
    /// The carried lockfile a Cargo port builds against (repository path).
    pub cargo_lockfile: String,
}

fn text(value: &Value, key: &str) -> Result<String, String> {
    match value.get(key) {
        None => Ok(String::new()),
        Some(v) => v
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("port recipe: `{key}` must be a string")),
    }
}

fn texts(value: &Value, key: &str) -> Result<Vec<String>, String> {
    match value.get(key) {
        None => Ok(Vec::new()),
        Some(v) => v
            .as_str_list()
            .ok_or_else(|| format!("port recipe: `{key}` must be a list of strings")),
    }
}

fn pairs(value: &Value, key: &str) -> Result<Vec<(String, String)>, String> {
    let Some(list) = value.get(key) else {
        return Ok(Vec::new());
    };
    list.as_list()
        .ok_or_else(|| format!("port recipe: `{key}` must be a list of pairs"))?
        .iter()
        .map(|pair| match pair.as_str_list().as_deref() {
            Some([k, v]) => Ok((k.clone(), v.clone())),
            _ => Err(format!("port recipe: `{key}` holds an entry that is not a pair")),
        })
        .collect()
}

fn rows<T>(value: &Value, key: &str, row: impl Fn(&Value) -> Result<T, String>) -> Result<Vec<T>, String> {
    match value.get(key) {
        None => Ok(Vec::new()),
        Some(v) => v
            .as_list()
            .ok_or_else(|| format!("port recipe: `{key}` must be a list"))?
            .iter()
            .map(row)
            .collect(),
    }
}

fn rules(value: &Value, key: &str) -> Result<Vec<TargetRule>, String> {
    rows(value, key, |row| {
        Ok(TargetRule {
            name: text(row, "name")?,
            sources: texts(row, "sources")?,
            extra_flags: texts(row, "extra-flags")?,
        })
    })
}

impl PortRecipe {
    /// Read the expanded recipe from its JSON text.
    pub fn from_json(json: &str) -> Result<PortRecipe, String> {
        let value = Value::parse_json(json).map_err(|e| format!("port recipe: {e}"))?;
        let style = match text(&value, "style")?.as_str() {
            "autotools" => Style::Autotools,
            "cmake" => Style::CMake,
            "make" => Style::Make,
            "cargo" => Style::Cargo,
            "targets" => Style::Targets,
            "custom" => Style::Custom,
            other => return Err(format!("port recipe: unknown style `{other}`")),
        };
        let installer = match text(&value, "installer")?.as_str() {
            "destdir" => Installer::Destdir,
            "manifest" => Installer::Manifest,
            "snippet" => Installer::Snippet,
            other => return Err(format!("port recipe: unknown installer `{other}`")),
        };
        let snippet = |phase: &str| -> Result<Option<String>, String> {
            match value.get("snippets").and_then(|s| s.get(phase)) {
                None => Ok(None),
                Some(body) => body
                    .as_str()
                    .map(|b| Some(b.to_string()))
                    .ok_or_else(|| format!("port recipe: snippet `{phase}` must be a string")),
            }
        };
        let name = text(&value, "name")?;
        if name.is_empty() {
            return Err("port recipe: `name` is missing".to_string());
        }
        Ok(PortRecipe {
            version: text(&value, "version")?,
            description: text(&value, "description")?,
            licenses: texts(&value, "licenses")?,
            style,
            configure: texts(&value, "configure")?,
            autoreconf: value.get("autoreconf").and_then(Value::as_bool).unwrap_or(false),
            env: pairs(&value, "env")?,
            autoconf_cache: pairs(&value, "autoconf-cache")?,
            prepare: snippet("prepare")?,
            configure_snippet: snippet("configure")?,
            build_snippet: snippet("build")?,
            install_snippet: snippet("install")?,
            installer,
            make_target: text(&value, "make-target")?,
            install_files: rows(&value, "files", |row| {
                let mode = text(row, "mode")?;
                Ok(InstallFile {
                    src: text(row, "src")?,
                    dest: text(row, "dest")?,
                    mode: u32::from_str_radix(mode.trim_start_matches("0o"), 8)
                        .map_err(|_| format!("port recipe: mode `{mode}` is not octal"))?,
                })
            })?,
            install_symlinks: rows(&value, "symlinks", |row| {
                Ok(InstallSymlink {
                    link: text(row, "link")?,
                    target: text(row, "target")?,
                })
            })?,
            install_trees: rows(&value, "trees", |row| {
                Ok(InstallTree {
                    src: text(row, "src")?,
                    dest: text(row, "dest")?,
                })
            })?,
            exclude: texts(&value, "exclude")?,
            nostrip: texts(&value, "nostrip")?,
            libs: rules(&value, "libs")?,
            targets: rules(&value, "targets")?,
            targets_cflags: texts(&value, "targets-cflags")?,
            cargo_config: text(&value, "cargo-config")?,
            cargo_lockfile: text(&value, "cargo-lockfile")?,
            name,
        })
    }
}

/// `value` split at its first `sep`.
fn split(flag: &str, value: &str, sep: char) -> Result<(String, String), String> {
    value
        .split_once(sep)
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .ok_or_else(|| format!("port: `{flag} {value}` needs `{sep}`"))
}

/// The derivation's declared port arguments.
#[derive(Debug, Clone, Default)]
pub struct PortArgs {
    pub triple: String,
    /// The recipe-visible variable naming the target triple, and its value.
    pub host_variable: Option<(String, String)>,
    pub source: String,
    pub tarball: String,
    pub subdir: String,
    pub vendor: Option<String>,
    /// The sysroot derivation and the directory under it.
    pub sysroot: (String, String),
    pub sysroot_manifest: String,
    /// Build dependencies: the owner name and the derivation whose `stage/`
    /// joins the sysroot.
    pub build_dependencies: Vec<(String, String)>,
    pub patches: Vec<String>,
    pub port_dir: String,
    pub licenses: String,
    pub license_dest: String,
    pub stage_roots: Vec<String>,
    pub runtime_dependencies: Vec<String>,
    pub recipe: String,
}

impl PortArgs {
    /// Parse the derivation's arguments (after the tool word).
    pub fn parse(argv: &[String]) -> Result<PortArgs, String> {
        let mut out = PortArgs::default();
        let mut words = argv.iter();
        let mut sysroot = None;
        while let Some(flag) = words.next() {
            let value = words
                .next()
                .ok_or_else(|| format!("port: `{flag}` needs a value"))?
                .clone();
            match flag.as_str() {
                "--triple" => out.triple = value,
                "--host-variable" => out.host_variable = Some(split(flag, &value, '=')?),
                "--source" => out.source = value,
                "--tarball" => out.tarball = value,
                "--subdir" => out.subdir = value,
                "--vendor" => out.vendor = Some(value),
                "--sysroot" => sysroot = Some(split(flag, &value, ':')?),
                "--sysroot-manifest" => out.sysroot_manifest = value,
                "--build-dependency" => out.build_dependencies.push(split(flag, &value, '=')?),
                "--patch" => out.patches.push(value),
                "--port-dir" => out.port_dir = value,
                "--licenses" => out.licenses = value,
                "--license-dest" => out.license_dest = value,
                "--stage-root" => out.stage_roots.push(value),
                "--runtime-dependency" => out.runtime_dependencies.push(value),
                "--recipe" => out.recipe = value,
                other => return Err(format!("port: unknown argument `{other}`")),
            }
        }
        out.sysroot = sysroot.ok_or("port: `--sysroot <derivation>:<dir>` is required")?;
        for (flag, value) in [
            ("--triple", &out.triple),
            ("--source", &out.source),
            ("--tarball", &out.tarball),
            ("--subdir", &out.subdir),
            ("--sysroot-manifest", &out.sysroot_manifest),
            ("--port-dir", &out.port_dir),
            ("--licenses", &out.licenses),
            ("--license-dest", &out.license_dest),
            ("--recipe", &out.recipe),
        ] {
            if value.is_empty() {
                return Err(format!("port: `{flag}` is required"));
            }
        }
        if out.stage_roots.is_empty() {
            return Err("port: at least one `--stage-root` is required".to_string());
        }
        Ok(out)
    }
}

/// Double-quote so `${VAR}` references in recipe arguments still expand
/// from the exported cross environment; only quote, backslash and backtick
/// are escaped. Recipes are first-party repository content — the
/// environment is the interface, not an injection surface.
fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'-' | b'+' | b'.' | b'/' | b'=' | b':' | b',')
        })
    {
        s.to_string()
    } else {
        format!(
            "\"{}\"",
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('`', "\\`")
        )
    }
}

/// A path the build reaches, made absolute without resolving links, so it
/// holds after the script changes directory.
fn absolute(path: &Path) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|e| format!("cannot make {} absolute: {e}", path.display()))
}

/// Everything the phase script needs, resolved for this run.
pub struct PortPaths {
    pub source_out: PathBuf,
    pub vendor: Option<PathBuf>,
    pub sysroot: PathBuf,
    pub sysroot_base: PathBuf,
    pub dep_stages: Vec<(String, PathBuf)>,
    pub stage: PathBuf,
    /// The staged repository root: patches, the sysroot manifest, the port
    /// directory and the license corpus are declared sources under it.
    pub repo_root: PathBuf,
    pub cc: String,
    pub cxx: String,
    pub ar: String,
    pub ranlib: String,
    pub strip: String,
    pub rustc: String,
    pub cargo: String,
    pub toolchain_prefix: PathBuf,
    pub arch: String,
    pub nproc: usize,
}

impl PortPaths {
    fn cflags(&self, args: &PortArgs) -> String {
        format!(
            "-fno-stack-protector -fPIC --target={} --sysroot={}",
            args.triple,
            self.sysroot.display()
        )
    }

    fn ldflags(&self, args: &PortArgs) -> String {
        format!("--target={} --sysroot={}", args.triple, self.sysroot.display())
    }
}

/// Resolve the declared inputs through the build's dependency views
/// (`stage/dep/<name>`), never concrete provider store directories.
pub fn resolve_paths(
    dep_names: &[String],
    args: &PortArgs,
    arch: &str,
    build_dir: &Path,
    stage: &Path,
    out_dir: &Path,
    toolbin: &Path,
) -> Result<PortPaths, String> {
    let dep = |name: &str| -> Result<PathBuf, String> {
        if !dep_names.iter().any(|d| d == name) {
            return Err(format!("port: `{name}` is not a declared dependency"));
        }
        absolute(&stage.join("dep").join(name))
    };
    let tool = |t: &str| -> Result<String, String> {
        let path = toolbin.join(t);
        if path.exists() {
            Ok(absolute(&path)?.to_string_lossy().into_owned())
        } else {
            Err(format!("port: tool `{t}` is not declared"))
        }
    };
    let clang = tool("clang")?;
    let toolchain_prefix = Path::new(&clang)
        .parent()
        .and_then(|bin| bin.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut dep_stages = Vec::new();
    for (owner, drv) in &args.build_dependencies {
        dep_stages.push((owner.clone(), dep(drv)?.join("stage")));
    }
    let vendor = match &args.vendor {
        Some(drv) => Some(dep(drv)?.join("vendor")),
        None => None,
    };
    Ok(PortPaths {
        source_out: dep(&args.source)?,
        vendor,
        sysroot: absolute(&build_dir.join("sr"))?,
        sysroot_base: dep(&args.sysroot.0)?.join(&args.sysroot.1),
        dep_stages,
        stage: absolute(&out_dir.join("stage"))?,
        repo_root: absolute(stage)?,
        cc: clang,
        cxx: tool("clang++")?,
        ar: tool("llvm-ar")?,
        ranlib: tool("llvm-ranlib")?,
        strip: tool("llvm-strip")?,
        rustc: tool("rustc").unwrap_or_default(),
        cargo: tool("cargo").unwrap_or_default(),
        toolchain_prefix,
        arch: arch.to_string(),
        nproc: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
    })
}

/// The exported build environment: the cross toolchain contract every
/// phase (and every `${VAR}` reference in recipe snippets) sees.
pub fn cross_env(recipe: &PortRecipe, args: &PortArgs, paths: &PortPaths) -> Vec<(String, String)> {
    let sysroot = paths.sysroot.display().to_string();
    let pkg_path = format!("{s}/usr/lib/pkgconfig:{s}/usr/share/pkgconfig", s = sysroot);
    let mut vars: Vec<(String, String)> = vec![
        ("CC".into(), paths.cc.clone()),
        ("CXX".into(), paths.cxx.clone()),
        ("CFLAGS".into(), paths.cflags(args)),
        // Autotools preprocessor probes run $CPP directly without
        // appending $CFLAGS, so the target and sysroot flags ride along.
        ("CPP".into(), format!("{} {} -E", paths.cc, paths.cflags(args))),
        ("CXXCPP".into(), format!("{} {} -E", paths.cxx, paths.cflags(args))),
        ("LDFLAGS".into(), paths.ldflags(args)),
        ("LDSHARED".into(), format!("{} -shared", paths.cc)),
        ("LIBS".into(), String::new()),
        ("AR".into(), paths.ar.clone()),
        ("RANLIB".into(), paths.ranlib.clone()),
        ("STRIP".into(), paths.strip.clone()),
        ("PKG_CONFIG_LIBDIR".into(), pkg_path.clone()),
        ("PKG_CONFIG_PATH".into(), pkg_path),
        ("PKG_CONFIG_SYSROOT_DIR".into(), sysroot.clone()),
        // Host helper builds (mkbuiltins and the like) use the build host's
        // own compiler.
        ("CC_FOR_BUILD".into(), "cc".into()),
        ("CFLAGS_FOR_BUILD".into(), String::new()),
        ("LDFLAGS_FOR_BUILD".into(), String::new()),
        ("cross_compiling".into(), "yes".into()),
        ("SYSROOT".into(), sysroot),
        ("STAGE".into(), paths.stage.display().to_string()),
        ("REPOROOT".into(), paths.repo_root.display().to_string()),
        ("NPROC".into(), paths.nproc.to_string()),
        (
            "TOOLCHAIN_PREFIX".into(),
            paths.toolchain_prefix.display().to_string(),
        ),
        ("ARCH".into(), paths.arch.clone()),
        (
            "PORTDIR".into(),
            paths.repo_root.join(&args.port_dir).display().to_string(),
        ),
    ];
    if let Some((name, value)) = &args.host_variable {
        vars.push((name.clone(), value.clone()));
    }
    for (k, v) in &recipe.env {
        if let Some(slot) = vars.iter_mut().find(|(name, _)| name == k) {
            slot.1 = v.clone();
        } else {
            vars.push((k.clone(), v.clone()));
        }
    }
    // EXTRA_CFLAGS, EXTRA_LDFLAGS and EXTRA_LIBS append to the computed value
    // instead of replacing it.
    for (extra_key, base_key) in [
        ("EXTRA_CFLAGS", "CFLAGS"),
        ("EXTRA_LDFLAGS", "LDFLAGS"),
        ("EXTRA_LIBS", "LIBS"),
    ] {
        if let Some(pos) = vars.iter().position(|(name, _)| name == extra_key) {
            let extra = vars.remove(pos).1;
            if let Some(slot) = vars.iter_mut().find(|(name, _)| name == base_key) {
                slot.1.push(' ');
                slot.1.push_str(&extra);
            }
        }
    }
    vars
}

/// Recipe snippets run in a subshell: a phase that changes directory or
/// shell state cannot perturb the phases after it.
fn push_phase(s: &mut String, phase: &str, body: &str) {
    s.push_str(&format!("# --- {} (snippet) ---\n(\nset -eu\n", phase));
    s.push_str(body);
    if !body.ends_with('\n') {
        s.push('\n');
    }
    s.push_str(")\n");
}

pub fn build_script(recipe: &PortRecipe, args: &PortArgs, paths: &PortPaths) -> String {
    let mut s = String::from("set -eu\numask 022\n");
    // The private sysroot view, composed before any configure or compile
    // phase; it does not depend on the unpacked source.
    s.push_str("buildutil-sysroot compose --manifest ");
    s.push_str(&sh_quote(
        &paths.repo_root.join(&args.sysroot_manifest).display().to_string(),
    ));
    s.push_str(" --out ");
    s.push_str(&sh_quote(&paths.sysroot.display().to_string()));
    s.push_str(" --base ");
    s.push_str(&sh_quote(&paths.sysroot_base.display().to_string()));
    for (owner, stage) in &paths.dep_stages {
        s.push(' ');
        s.push_str(&sh_quote(owner));
        s.push(' ');
        s.push_str(&sh_quote(&stage.display().to_string()));
    }
    s.push('\n');

    s.push_str(&format!("export SRCDIR=\"$PWD/{}\"\n", args.subdir));
    // tar detects the compression from the payload.
    s.push_str(&format!(
        "tar -xf {}\n",
        sh_quote(&paths.source_out.join(&args.tarball).display().to_string())
    ));
    s.push_str(&format!("cd {}\n", sh_quote(&args.subdir)));

    if recipe.autoreconf {
        s.push_str("autoreconf -fi .\n");
    }
    for patch in &args.patches {
        s.push_str(&format!(
            "patch -p1 --forward -i {}\n",
            sh_quote(&paths.repo_root.join(patch).display().to_string())
        ));
    }
    if !recipe.autoconf_cache.is_empty() {
        s.push_str("cat > config.cache <<'BUILDUTIL_EOF'\n");
        for (k, v) in &recipe.autoconf_cache {
            s.push_str(&format!("{}=${{{}={}}}\n", k, k, v));
        }
        s.push_str("BUILDUTIL_EOF\n");
    }
    if let Some(body) = &recipe.prepare {
        push_phase(&mut s, "prepare", body);
    }
    if let Some(body) = &recipe.configure_snippet {
        push_phase(&mut s, "configure", body);
    } else {
        match recipe.style {
            Style::Autotools => {
                let mut configure = vec![
                    format!("--host={}", args.triple),
                    "--build=$(cc -dumpmachine)".to_string(),
                    "--prefix=/usr".to_string(),
                ];
                configure.extend(recipe.configure.iter().map(|a| sh_quote(a)));
                s.push_str(&format!("./configure {}\n", configure.join(" ")));
            }
            Style::CMake => {
                let mut cmake = vec![
                    format!("-DCMAKE_C_COMPILER={}", sh_quote(&paths.cc)),
                    format!("-DCMAKE_CXX_COMPILER={}", sh_quote(&paths.cxx)),
                    format!("-DCMAKE_ASM_COMPILER={}", sh_quote(&paths.cc)),
                    format!("-DCMAKE_C_FLAGS={}", sh_quote(&paths.cflags(args))),
                    format!("-DCMAKE_CXX_FLAGS={}", sh_quote(&paths.cflags(args))),
                    format!("-DCMAKE_ASM_FLAGS={}", sh_quote(&paths.cflags(args))),
                    format!("-DCMAKE_EXE_LINKER_FLAGS={}", sh_quote(&paths.ldflags(args))),
                    "-DCMAKE_INSTALL_PREFIX=/usr".to_string(),
                ];
                cmake.extend(recipe.configure.iter().map(|a| sh_quote(a)));
                s.push_str("mkdir -p _build\ncd _build\n");
                s.push_str(&format!("cmake {} ..\n", cmake.join(" ")));
                s.push_str("cd ..\n");
            }
            Style::Make | Style::Custom | Style::Targets | Style::Cargo => {}
        }
    }
    if let Some(body) = &recipe.build_snippet {
        push_phase(&mut s, "build", body);
    } else {
        match recipe.style {
            Style::Autotools | Style::Make | Style::Custom => s.push_str("make -j\"$NPROC\"\n"),
            Style::CMake => s.push_str("cmake --build _build -j \"$NPROC\"\n"),
            Style::Targets => emit_targets(&mut s, recipe),
            Style::Cargo => emit_cargo(&mut s, recipe, args, paths),
        }
    }
    match recipe.installer {
        Installer::Destdir => {
            if let Some(body) = &recipe.install_snippet {
                push_phase(&mut s, "install", body);
            } else {
                match recipe.style {
                    Style::CMake => {
                        s.push_str("DESTDIR=\"$STAGE\" cmake --install _build --prefix /usr\n")
                    }
                    _ => s.push_str(&format!(
                        "make -j\"$NPROC\" {} DESTDIR=\"$STAGE\" prefix=/usr PREFIX=/usr\n",
                        sh_quote(&recipe.make_target)
                    )),
                }
            }
        }
        Installer::Snippet => {
            if let Some(body) = &recipe.install_snippet {
                push_phase(&mut s, "install", body);
            }
        }
        // Declarative rows are applied after the script.
        Installer::Manifest => {}
    }
    s
}

fn emit_targets(s: &mut String, recipe: &PortRecipe) {
    s.push_str("mkdir -p _build/obj\n");
    let common = recipe
        .targets_cflags
        .iter()
        .map(|f| sh_quote(f))
        .collect::<Vec<_>>()
        .join(" ");
    for lib in &recipe.libs {
        let mut objs = Vec::new();
        let flags = lib
            .extra_flags
            .iter()
            .map(|f| sh_quote(f))
            .collect::<Vec<_>>()
            .join(" ");
        for (i, source) in lib.sources.iter().enumerate() {
            // Shell globs expand deterministically (POSIX sorted).
            if source.contains('*') {
                s.push_str(&format!(
                    "for f in {}; do o=\"_build/obj/{}_$(basename \"$f\" .c)_{}.o\"; $CC $CFLAGS {} {} -c -o \"$o\" \"$f\"; done\n",
                    source, lib.name, i, flags, common
                ));
                objs.push(format!("_build/obj/{}_*_{}.o", lib.name, i));
            } else {
                let obj = format!(
                    "_build/obj/{}_{}_{}.o",
                    lib.name,
                    Path::new(source)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("obj"),
                    i
                );
                s.push_str(&format!(
                    "$CC $CFLAGS {} {} -c -o {} {}\n",
                    flags,
                    common,
                    sh_quote(&obj),
                    sh_quote(source)
                ));
                objs.push(obj);
            }
        }
        s.push_str(&format!("$AR rcs _build/lib{}.a {}\n", lib.name, objs.join(" ")));
    }
    for target in &recipe.targets {
        let flags = target
            .extra_flags
            .iter()
            .map(|f| sh_quote(f))
            .collect::<Vec<_>>()
            .join(" ");
        let lib_path = if recipe.libs.is_empty() { "" } else { "-L_build" };
        let sources = target
            .sources
            .iter()
            .map(|f| sh_quote(f))
            .collect::<Vec<_>>()
            .join(" ");
        s.push_str(&format!("mkdir -p \"$(dirname _build/{})\"\n", target.name));
        s.push_str(&format!(
            "$CC $CFLAGS {} {} $LDFLAGS {} -o _build/{} {} $LIBS\n",
            flags,
            common,
            lib_path,
            sh_quote(&target.name),
            sources
        ));
    }
}

/// A Cargo build against the vendored crates: the carried lockfile, the
/// declared configuration (patches and the source replacement), offline.
fn emit_cargo(s: &mut String, recipe: &PortRecipe, args: &PortArgs, paths: &PortPaths) {
    let triple_env = args.triple.replace('-', "_").to_uppercase();
    if !recipe.cargo_lockfile.is_empty() {
        s.push_str(&format!(
            "cp {} Cargo.lock\n",
            sh_quote(&paths.repo_root.join(&recipe.cargo_lockfile).display().to_string())
        ));
    }
    let vendor = paths
        .vendor
        .as_ref()
        .map(|v| v.display().to_string())
        .unwrap_or_default();
    s.push_str("mkdir -p .cargo\n");
    s.push_str("cat > .cargo/config.toml <<'BUILDUTIL_EOF'\n");
    s.push_str(&recipe.cargo_config.replace("{vendor}", &vendor));
    if !recipe.cargo_config.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("BUILDUTIL_EOF\n");
    s.push_str(&format!(
        "export CARGO_TARGET_{}_LINKER=\"$CC\"\nexport CARGO_BUILD_JOBS=\"$NPROC\"\nexport RUSTC={}\n",
        triple_env,
        sh_quote(&paths.rustc)
    ));
    // A port's LIBRARY_PATH folds into target rustflags (-L for the target
    // linker) and leaves the environment — kept there it would leak into
    // host build-script link lines.
    s.push_str("rust_l_flags=\"\"\nif [ -n \"${LIBRARY_PATH:-}\" ]; then\n  old_ifs=\"$IFS\"; IFS=:\n  for d in $LIBRARY_PATH; do [ -n \"$d\" ] && rust_l_flags=\"$rust_l_flags -C link-arg=-L$d\"; done\n  IFS=\"$old_ifs\"; unset LIBRARY_PATH\nfi\n");
    s.push_str(&format!(
        "export CARGO_TARGET_{}_RUSTFLAGS=\"-C linker=$CC -C link-arg=--target={} -C link-arg=--sysroot=$SYSROOT$rust_l_flags\"\n",
        triple_env, args.triple
    ));
    // Progress and diagnostics reach the build screen as cargo's JSON
    // messages, diagnostics rendered in color.
    let mut cargo = vec![
        "build".to_string(),
        "--release".to_string(),
        "--offline".to_string(),
        "--locked".to_string(),
        "--message-format=json-diagnostic-rendered-ansi".to_string(),
        format!("--target={}", args.triple),
    ];
    cargo.extend(recipe.configure.iter().map(|a| sh_quote(a)));
    s.push_str(&format!("{} {}\n", sh_quote(&paths.cargo), cargo.join(" ")));
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn make_symlink(target: &Path, link: &Path) -> Result<(), String> {
    crate::platform::create_symlink(target, link, crate::platform::SymlinkKind::File)
        .map_err(|e| format!("cannot symlink {}: {}", link.display(), e))
}

/// The install rows, exclude globs, strip pass, license staging and layout
/// check, over the build's working directory and output stage.
pub fn post_process(
    recipe: &PortRecipe,
    args: &PortArgs,
    build_cwd: &Path,
    stage: &Path,
    repo_root: &Path,
    strip_tool: &Path,
) -> Result<(), String> {
    let src_dir = build_cwd.join(&args.subdir);
    for row in &recipe.install_files {
        let src = src_dir.join(&row.src);
        let dest = stage.join(&row.dest);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        fs::copy(&src, &dest).map_err(|e| {
            format!("cannot install {} -> {}: {}", src.display(), dest.display(), e)
        })?;
        set_mode(&dest, row.mode).map_err(|e| format!("cannot chmod {}: {}", dest.display(), e))?;
    }
    for row in &recipe.install_trees {
        copy_tree_into(&src_dir.join(&row.src), &stage.join(&row.dest))?;
    }
    for row in &recipe.install_symlinks {
        let link = stage.join(&row.link);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        let _ = fs::remove_file(&link);
        make_symlink(Path::new(&row.target), &link)?;
    }
    if !recipe.exclude.is_empty() {
        let mut rels = Vec::new();
        collect_rels(stage, stage, &mut rels)?;
        for rel in rels {
            if recipe.exclude.iter().any(|p| glob_match(p, &rel)) {
                let path = stage.join(&rel);
                if fs::symlink_metadata(&path).map(|m| m.is_dir()).unwrap_or(false) {
                    fs::remove_dir_all(&path)
                        .map_err(|e| format!("cannot exclude {}: {}", path.display(), e))?;
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        prune_empty_dirs(stage, stage)?;
    }
    let mut rels = Vec::new();
    collect_rels(stage, stage, &mut rels)?;
    for rel in &rels {
        if recipe.nostrip.iter().any(|p| glob_match(p, rel)) {
            continue;
        }
        let path = stage.join(rel);
        if is_elf(&path) {
            let out = std::process::Command::new(strip_tool)
                .arg("--strip-all")
                .arg(&path)
                .output()
                .map_err(|e| format!("cannot run strip: {}", e))?;
            if !out.status.success() {
                return Err(format!(
                    "strip failed for {}: {}",
                    path.display(),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
        }
    }
    // After excludes and strip: an exclude aimed at bulky upstream docs must
    // never remove license text.
    stage_licenses(recipe, args, stage, repo_root)?;
    validate_stage_layout(stage, &args.stage_roots)
}

/// Stage the text of every declared license identifier from the declared
/// corpus. An identifier without text is an error: an image must not ship
/// the gap.
fn stage_licenses(recipe: &PortRecipe, args: &PortArgs, stage: &Path, repo_root: &Path) -> Result<(), String> {
    let corpus = repo_root.join(&args.licenses);
    let dest_dir = stage.join(&args.license_dest);
    fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("cannot create {}: {}", dest_dir.display(), e))?;
    for id in &recipe.licenses {
        let src = corpus.join(id);
        if !src.is_file() {
            return Err(format!(
                "port `{}` declares license `{}`, which has no text in {}/ — add it before this port can ship",
                recipe.name, id, args.licenses
            ));
        }
        fs::copy(&src, dest_dir.join(id))
            .map_err(|e| format!("cannot stage license {}: {}", src.display(), e))?;
    }
    Ok(())
}

fn copy_tree_into(src: &Path, dest: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(src).map_err(|e| format!("stat {}: {}", src.display(), e))?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(src).map_err(|e| format!("readlink: {}", e))?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
        }
        let _ = fs::remove_file(dest);
        make_symlink(&target, dest)?;
    } else if meta.is_dir() {
        fs::create_dir_all(dest).map_err(|e| format!("mkdir {}: {}", dest.display(), e))?;
        for entry in fs::read_dir(src).map_err(|e| format!("read {}: {}", src.display(), e))? {
            let entry = entry.map_err(|e| format!("read_dir entry: {}", e))?;
            copy_tree_into(&entry.path(), &dest.join(entry.file_name()))?;
        }
    } else {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
        }
        fs::copy(src, dest)
            .map_err(|e| format!("cannot copy {} -> {}: {}", src.display(), dest.display(), e))?;
    }
    Ok(())
}

fn collect_rels(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {}", dir.display(), e))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("stat {}: {}", path.display(), e))?;
        let rel = path
            .strip_prefix(root)
            .map_err(|e| format!("strip_prefix: {}", e))?
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 path: {}", path.display()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        out.push(rel);
        if meta.is_dir() && !meta.file_type().is_symlink() {
            collect_rels(root, &path, out)?;
        }
    }
    Ok(())
}

fn prune_empty_dirs(root: &Path, dir: &Path) -> Result<bool, String> {
    let mut empty = true;
    for entry in fs::read_dir(dir).map_err(|e| format!("cannot read {}: {}", dir.display(), e))? {
        let entry = entry.map_err(|e| format!("read_dir entry: {}", e))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("stat {}: {}", path.display(), e))?;
        if meta.is_dir() && !meta.file_type().is_symlink() {
            if prune_empty_dirs(root, &path)? {
                let _ = fs::remove_dir(&path);
            } else {
                empty = false;
            }
        } else {
            empty = false;
        }
    }
    Ok(empty && dir != root)
}

fn is_elf(path: &Path) -> bool {
    use std::io::Read;
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {}
        _ => return false,
    }
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    matches!(f.read_exact(&mut magic), Ok(())) && magic == [0x7F, b'E', b'L', b'F']
}

/// The stage tree holds only the declared top-level entries.
fn validate_stage_layout(stage: &Path, roots: &[String]) -> Result<(), String> {
    for entry in fs::read_dir(stage).map_err(|e| format!("cannot read {}: {}", stage.display(), e))? {
        let entry = entry.map_err(|e| format!("read_dir entry: {}", e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !roots.iter().any(|root| root == &name) {
            return Err(format!(
                "stage layout violation: unexpected top-level entry `{}` (declared roots: {})",
                name,
                roots.join(", ")
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn sample_args() -> Vec<String> {
        argv(&[
            "--triple", "x86_64-unknown-example",
            "--host-variable", "EXAMPLE_HOST=x86_64-unknown-example",
            "--source", "src-demo",
            "--tarball", "source.tar",
            "--subdir", "demo-1.0",
            "--sysroot", "base:sysroot",
            "--sysroot-manifest", "manifests/sysroot.manifest",
            "--build-dependency", "zlib=build-zlib",
            "--patch", "recipes/demo/patches/01.patch",
            "--port-dir", "recipes/demo",
            "--licenses", "recipes/LICENSES",
            "--license-dest", "usr/share/licenses/demo",
            "--stage-root", "usr",
            "--runtime-dependency", "build-zlib",
            "--recipe", r#"{"name":"demo","version":"1.0","style":"autotools","installer":"destdir","make-target":"install","configure":["--disable-nls"],"licenses":["MIT"],"env":[["EXTRA_CFLAGS","-O2"]],"snippets":{"prepare":"echo ${SRCDIR}"}}"#,
        ])
    }

    #[test]
    fn required_port_arguments_carry_every_project_fact() {
        let args = PortArgs::parse(&sample_args()).unwrap();
        assert_eq!(args.sysroot, ("base".to_string(), "sysroot".to_string()));
        assert_eq!(args.build_dependencies, vec![("zlib".to_string(), "build-zlib".to_string())]);
        assert_eq!(
            args.host_variable,
            Some(("EXAMPLE_HOST".to_string(), "x86_64-unknown-example".to_string()))
        );
        let recipe = PortRecipe::from_json(&args.recipe).unwrap();
        assert_eq!(recipe.style, Style::Autotools);
        assert_eq!(recipe.prepare.as_deref(), Some("echo ${SRCDIR}"));
        let mut missing = sample_args();
        let at = missing.iter().position(|w| w == "--triple").unwrap();
        missing.drain(at..at + 2);
        assert!(PortArgs::parse(&missing).is_err());
    }

    #[test]
    fn required_script_uses_only_declared_names() {
        let args = PortArgs::parse(&sample_args()).unwrap();
        let recipe = PortRecipe::from_json(&args.recipe).unwrap();
        let paths = PortPaths {
            source_out: PathBuf::from("/b/stage/dep/src-demo"),
            vendor: None,
            sysroot: PathBuf::from("/b/sr"),
            sysroot_base: PathBuf::from("/b/stage/dep/base/sysroot"),
            dep_stages: vec![("zlib".into(), PathBuf::from("/b/stage/dep/build-zlib/stage"))],
            stage: PathBuf::from("/b/out/stage"),
            repo_root: PathBuf::from("/b/stage"),
            cc: "/t/clang".into(),
            cxx: "/t/clang++".into(),
            ar: "/t/llvm-ar".into(),
            ranlib: "/t/llvm-ranlib".into(),
            strip: "/t/llvm-strip".into(),
            rustc: String::new(),
            cargo: String::new(),
            toolchain_prefix: PathBuf::from("/"),
            arch: "x86_64".into(),
            nproc: 4,
        };
        let script = build_script(&recipe, &args, &paths);
        assert!(script.contains("--manifest /b/stage/manifests/sysroot.manifest"));
        assert!(script.contains("zlib /b/stage/dep/build-zlib/stage"));
        assert!(script.contains("--host=x86_64-unknown-example"));
        assert!(script.contains("patch -p1 --forward -i /b/stage/recipes/demo/patches/01.patch"));
        let env = cross_env(&recipe, &args, &paths);
        assert!(env.iter().any(|(k, v)| k == "EXAMPLE_HOST" && v == "x86_64-unknown-example"));
        assert!(env.iter().any(|(k, v)| k == "CFLAGS" && v.ends_with(" -O2")));
        assert!(env.iter().any(|(k, v)| k == "PORTDIR" && v == "/b/stage/recipes/demo"));
    }
}
