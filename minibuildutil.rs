//! SPDX-License-Identifier: GPL-2.0-only
//! minibuildutil — staged native self-host frontend
//!
//! This crate root contains only the reusable engine planes plus the generic
//! builder registry. It evaluates the root buildutil.toml's target-scoped native
//! frontend graph, realizes the full buildutil with the bootstrap-captured ambient
//! toolchain, and publishes that result at bootstrap.ninja's requested path.

// First, so its print macros and their std shadows are in scope everywhere.
#[macro_use]
pub mod term;
pub mod crypto;
pub mod eval;
pub mod events;
pub mod exec;
pub mod glob;
mod inputs;
pub mod invocation;
#[path = "sdk/wire.rs"]
pub mod sdk_wire;
pub(crate) use crypto::sha256 as input_sha256;
pub(crate) use source::filter as input_filter;
pub(crate) use spec::toml as input_toml;
pub mod log;
pub mod paths;
pub mod platform;
pub mod source;
pub mod spec;
pub mod state;
pub mod store;
pub mod tools;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

struct Args {
    repo_root: PathBuf,
    state_root: PathBuf,
    rustc: PathBuf,
    linker: PathBuf,
    rustc_identity: PathBuf,
    output: PathBuf,
    exec_host: String,
}

fn value(argv: &[String], flag: &str) -> Result<PathBuf, String> {
    let pos = argv
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| format!("minibuildutil: missing {flag}"))?;
    argv.get(pos + 1)
        .map(PathBuf::from)
        .ok_or_else(|| format!("minibuildutil: {flag} needs a value"))
}

fn string_value(argv: &[String], flag: &str) -> Result<String, String> {
    value(argv, flag).map(|v| v.to_string_lossy().into_owned())
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = Args {
        repo_root: value(&argv, "--repo-root")?,
        state_root: value(&argv, "--state-root")?,
        rustc: value(&argv, "--rustc")?,
        linker: value(&argv, "--linker")?,
        rustc_identity: value(&argv, "--rustc-identity")?,
        output: value(&argv, "--output")?,
        exec_host: string_value(&argv, "--exec-host")?,
    };
    let expected = 14;
    if argv.len() != expected {
        return Err(format!(
            "minibuildutil: expected {expected} arguments, got {}",
            argv.len()
        ));
    }
    Ok(args)
}

fn canonical_tool(path: &Path, label: &str) -> Result<PathBuf, String> {
    let absolute_without_following = |candidate: &Path| -> Result<PathBuf, String> {
        if !candidate.is_file() {
            return Err(format!(
                "minibuildutil: {label} is not a file: {}",
                candidate.display()
            ));
        }
        if candidate.is_absolute() {
            Ok(candidate.to_path_buf())
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(candidate))
                .map_err(|e| format!("minibuildutil: cannot resolve {label}: {e}"))
        }
    };
    let has_parent = path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    if path.is_absolute() || has_parent {
        // Preserve rustup-style argv[0] dispatch symlinks: canonicalizing
        // `~/.cargo/bin/rustc` to the rustup binary changes its behaviour.
        return absolute_without_following(path);
    }
    let search = std::env::var_os("PATH")
        .ok_or_else(|| format!("minibuildutil: PATH is unset while resolving {label}"))?;
    for dir in std::env::split_paths(&search) {
        let candidate = dir.join(path);
        if candidate.is_file() {
            return absolute_without_following(&candidate);
        }
        #[cfg(windows)]
        {
            let exe = candidate.with_extension("exe");
            if exe.is_file() {
                return absolute_without_following(&exe);
            }
        }
    }
    Err(format!(
        "minibuildutil: cannot find {label} `{}` on PATH",
        path.display()
    ))
}

fn publish(source: &Path, output: &Path) -> Result<(), String> {
    let parent = output
        .parent()
        .ok_or_else(|| format!("minibuildutil: output has no parent: {}", output.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("minibuildutil: cannot create {}: {e}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        output.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    std::fs::copy(source, &tmp).map_err(|e| {
        format!(
            "minibuildutil: cannot copy {} to {}: {e}",
            source.display(),
            tmp.display()
        )
    })?;
    #[cfg(windows)]
    if output.exists() {
        std::fs::remove_file(output)
            .map_err(|e| format!("minibuildutil: cannot replace {}: {e}", output.display()))?;
    }
    std::fs::rename(&tmp, output).map_err(|e| {
        format!(
            "minibuildutil: cannot publish {} as {}: {e}",
            tmp.display(),
            output.display()
        )
    })?;
    // `bootstrap.ninja -nt <seed>` is the wrapper's convergence gate.  A
    // store-cached selfhost output can contain identical bytes, but it still
    // must become newer than regenerated bootstrap metadata.
    OpenOptions::new()
        .write(true)
        .open(output)
        .and_then(|file| file.set_modified(SystemTime::now()))
        .map_err(|e| {
            format!(
                "minibuildutil: cannot refresh {} mtime: {e}",
                output.display()
            )
        })
}

fn rustc_binary(command: &Path) -> Result<PathBuf, String> {
    let output = crate::invocation::isolated(command)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("minibuildutil: cannot query rustc sysroot: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "minibuildutil: rustc --print sysroot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let direct = sysroot
        .join("bin")
        .join(if cfg!(windows) { "rustc.exe" } else { "rustc" });
    if direct.is_file() {
        Ok(direct)
    } else {
        Ok(command.to_path_buf())
    }
}

fn run(args: &Args) -> Result<i32, String> {
    let repo_root = std::fs::canonicalize(&args.repo_root).map_err(|e| {
        format!(
            "minibuildutil: cannot resolve repo root {}: {e}",
            args.repo_root.display()
        )
    })?;
    let state_root = if args.state_root.is_absolute() {
        args.state_root.clone()
    } else {
        repo_root.join(&args.state_root)
    };
    let rustc = rustc_binary(&canonical_tool(&args.rustc, "rustc")?)?;
    let linker = canonical_tool(&args.linker, "linker")?;
    let identity_record = std::fs::read(&args.rustc_identity).map_err(|e| {
        format!(
            "minibuildutil: cannot read rustc identity {}: {e}",
            args.rustc_identity.display()
        )
    })?;

    let store = store::Store::open(&state_root)?;
    source::statcache::load_file_cache(&state_root, &repo_root);
    source::activate(&state_root)?;

    let (spec, target) = spec::load_native_frontend(&repo_root, &args.exec_host)?;
    for dspec in spec.drvs.values() {
        spec::builders::validate(dspec, &spec.flagsets)?;
        if !dspec.native_frontend && dspec.builder != "source-tree" {
            return Err(format!(
                "minibuildutil: scoped derivation `{}` is not native-frontend",
                dspec.name
            ));
        }
    }
    let config = spec::configres::Config::from_values(BTreeMap::new());
    let mut toolchain =
        tools::Toolchain::with_native_frontend_tools(&state_root, rustc, linker, &identity_record);
    let targets = vec![target.clone()];
    let git_state = eval::graph::git_state(&spec.repo_root);
    let evaluated = eval::graph::evaluate(&spec, &config, &mut toolchain, &targets, &git_state)?;

    // The native frontend's closure is its own class: every tool it runs is
    // the ambient compiler bootstrap.ninja captured, and every dependency is
    // another native-frontend derivation, so no store provider — a host
    // compiler least of all — can enter it, whatever the specification
    // names its toolchains.
    for recipe in evaluated.recipes.values() {
        if recipe.builder == "source-tree" {
            continue;
        }
        if !recipe.tools.iter().any(|(tool, _)| tool == "rustc") {
            return Err(format!(
                "minibuildutil: `{}` has no rustc provider",
                recipe.name
            ));
        }
        if let Some((tool, _)) = recipe
            .tools
            .iter()
            .find(|(_, locator)| !locator.starts_with("host-sha256:"))
        {
            return Err(format!(
                "minibuildutil: `{}` did not resolve {tool} to the ambient provider",
                recipe.name
            ));
        }
        if let Some(dep) = recipe.dep_names.iter().find(|dep| {
            !spec
                .drvs
                .get(dep.as_str())
                .is_some_and(|d| d.native_frontend)
        }) {
            return Err(format!(
                "minibuildutil: native frontend closure reaches `{dep}`, which is not native-frontend"
            ));
        }
    }
    let (_plan_path, _, plan) = eval::plan::emit(&spec, &evaluated, &state_root, &git_state)?;

    let sandbox = exec::sandbox::platform_sandbox();
    let builders = exec::builder::BuilderRegistry::core();
    let logger = log::Logger::new(false);
    let jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let outcome = exec::pool::realize(
        &plan,
        &store,
        sandbox.as_ref(),
        &builders,
        jobs,
        exec::AuditMode::Warn,
        false,
        false,
        &std::collections::BTreeSet::new(),
        &logger,
    )?;
    events::emit_summary(&outcome.summary(&plan));
    if !outcome.failed.is_empty() {
        // Each failure was reported by its build events and the summary.
        return Ok(1);
    }
    let store_name = outcome
        .store_names
        .get(&target)
        .ok_or_else(|| format!("minibuildutil: target `{target}` produced no store output"))?;
    store.add_root(&format!("native-frontend-{}", args.exec_host), store_name)?;
    let built = store.root.join(store_name).join("buildutil");
    publish(&built, &args.output)?;
    source::statcache::flush_file_cache();
    log::success(
        "minibuildutil",
        &format!(
            "built {} with ambient rustc; closure = [{}]",
            args.output.display(),
            evaluated.order.join(", ")
        ),
    );
    Ok(0)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(result) = exec::dispatch_internal_command(&argv) {
        match result {
            Ok(code) => std::process::exit(code),
            Err(err) => {
                term::error(&err);
                std::process::exit(1);
            }
        }
    }
    // The self-host build is drawn here, like any build a person watches;
    // internal commands above stream their events to their parent instead.
    let args = parse_args();
    let state_root = args.as_ref().ok().map(|args| {
        if args.state_root.is_absolute() {
            args.state_root.clone()
        } else {
            args.repo_root.join(&args.state_root)
        }
    });
    let view = std::sync::Arc::new(std::sync::Mutex::new(term::view::BuildView::new(
        term::view::Options {
            state_root,
            ..term::view::Options::for_terminal()
        },
    )));
    let sink = std::sync::Arc::clone(&view);
    events::install_local_sink(Box::new(move |line| {
        sink.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .event(line)
    }));
    let result = args.and_then(|args| run(&args));
    view.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .finish();
    match result {
        Ok(0) => {}
        Ok(code) => {
            source::statcache::flush_file_cache();
            std::process::exit(code);
        }
        Err(err) => {
            source::statcache::flush_file_cache();
            term::error(&err);
            std::process::exit(1);
        }
    }
}
