// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the cmd cluster: CLI surface, command handlers, gen/selfcheck.
//!
//! Child modules: `usage` (help printing), `build` (build/dev/eval/plan/realize),
//! `report` (header/summary/eval-progress reporting), `query` (why/graph/explain/log),
//! `store` (store subcommands), `remote` (remote build), `gen` (bootstrap gen +
//! selfcheck), `conformance` (executable corpus),
//! `driver` (daily-driver commands: setup/run/fmt/check/tc/...).

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod app;
pub mod build;
pub mod conformance;
pub mod driver;
pub mod engine;
pub mod r#gen;
pub mod generate;
pub(crate) mod input_resolution;
pub(crate) mod inputs;
pub mod launch;
pub mod query;
pub mod remote;
pub mod report;
pub mod store;
pub mod usage;

#[derive(Clone)]
pub struct Args {
    pub(crate) argv: Vec<String>,
    pub(crate) command: String,
    pub(crate) targets: Vec<String>,
    pub(crate) arch: String,
    pub(crate) build_host: String,
    pub(crate) backend: String,
    pub(crate) store: Option<PathBuf>,
    pub(crate) stamp: Option<PathBuf>,
    pub(crate) jobs: usize,
    pub(crate) overrides: Vec<(String, String)>,
    pub(crate) input_overrides: Vec<(String, PathBuf)>,
    pub(crate) locked: bool,
    pub(crate) audit: crate::exec::AuditMode,
    pub(crate) keep_going: bool,
    pub(crate) keep_failed: bool,
    /// `buildutil check --rerun`: realize the named checks again, bypassing
    /// local reuse, substitution and a concurrent builder's result.
    pub(crate) rerun: bool,
    pub(crate) no_source_cache: bool,
    pub(crate) no_daemon: bool,
    pub(crate) selfcheck: bool,
    pub(crate) verbose: bool,
    pub(crate) timings: bool,
    /// `--build-output=all|failed|none` (`-q` is `failed`): which builder
    /// output the build screen shows. Display only; never forwarded into
    /// evaluation or identity.
    pub(crate) build_output: crate::term::view::OutputMode,
    /// `--domain <group>`: a `[packages]` group whose closure query
    /// commands restrict themselves to. `None` applies no restriction.
    pub(crate) domain: Option<String>,
    /// The kind table this invocation's target words resolve through, when
    /// a command hands its words to another (`check` to the build engine).
    /// `None` derives it from the command.
    pub(crate) scope: Option<crate::spec::kinds::Scope>,
    /// Everything after `--`: an app's own arguments, never parsed as
    /// buildutil options.
    pub(crate) app_args: Vec<String>,
    pub(crate) events: Option<PathBuf>,
    pub(crate) trace: Option<PathBuf>,
    pub(crate) stream_events: bool,
    pub(crate) header_report: Option<PathBuf>,
    pub(crate) header_seed: Option<PathBuf>,
}

struct GlobalFlag {
    name: &'static str,
    value: Option<&'static str>,
    prefix: bool,
}

impl GlobalFlag {
    fn matches(&self, arg: &str) -> bool {
        let _takes_value = self.value.is_some();
        if self.prefix {
            arg.starts_with(self.name)
        } else {
            arg == self.name
        }
    }
}

// The single table of buildutil-global flag names. parse_args owns their values;
// command handlers receive only the remaining command-local tokens in
// Args::targets.
const BUILDUTIL_GLOBAL_FLAGS: &[GlobalFlag] = &[
    GlobalFlag {
        name: "--locked",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--override-input",
        value: Some("input"),
        prefix: false,
    },
    GlobalFlag {
        name: "--arch",
        value: Some("x86_64"),
        prefix: false,
    },
    GlobalFlag {
        name: "--build-host",
        value: Some("x86_64-unknown-linux-gnu"),
        prefix: false,
    },
    GlobalFlag {
        name: "--backend",
        value: Some("local"),
        prefix: false,
    },
    GlobalFlag {
        name: "--store",
        value: Some(".buildutil-test-state"),
        prefix: false,
    },
    GlobalFlag {
        name: "--jobs",
        value: Some("1"),
        prefix: false,
    },
    GlobalFlag {
        name: "--stamp",
        value: Some("stamp"),
        prefix: false,
    },
    GlobalFlag {
        name: "--domain",
        value: Some("engine"),
        prefix: false,
    },
    GlobalFlag {
        name: "--events",
        value: Some("events.jsonl"),
        prefix: false,
    },
    GlobalFlag {
        name: "--trace",
        value: Some("trace.json"),
        prefix: false,
    },
    GlobalFlag {
        name: "--stream-events",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--header-report",
        value: Some("header.json"),
        prefix: false,
    },
    GlobalFlag {
        name: "--header-seed",
        value: Some("seed.json"),
        prefix: false,
    },
    GlobalFlag {
        name: "--selfcheck",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--keep-going",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "-k",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--keep-failed",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "-K",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--no-source-cache",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--no-daemon",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--timings",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--audit=warn",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--audit=error",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "-v",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "-q",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--build-output=all",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--build-output=failed",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "--build-output=none",
        value: None,
        prefix: false,
    },
    GlobalFlag {
        name: "-D",
        value: None,
        prefix: true,
    },
];

fn is_declared_global_flag(arg: &str) -> bool {
    BUILDUTIL_GLOBAL_FLAGS.iter().any(|flag| flag.matches(arg))
}

pub fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut args = Args {
        argv: argv.to_vec(),
        command: argv.first().cloned().unwrap_or_default(),
        targets: Vec::new(),
        arch: "x86_64".to_string(),
        build_host: crate::host::DEFAULT_BUILD_HOST.to_string(),
        backend: crate::host::DEFAULT_BACKEND.to_string(),
        store: None,
        stamp: None,
        jobs: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        overrides: Vec::new(),
        input_overrides: Vec::new(),
        locked: false,
        audit: crate::exec::AuditMode::Warn,
        keep_going: false,
        keep_failed: false,
        rerun: false,
        no_source_cache: false,
        no_daemon: false,
        selfcheck: false,
        verbose: false,
        timings: false,
        build_output: crate::term::view::OutputMode::All,
        domain: None,
        scope: None,
        app_args: Vec::new(),
        events: None,
        trace: None,
        stream_events: false,
        header_report: None,
        header_seed: None,
    };
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--locked" => args.locked = true,
            "--override-input" => {
                i += 1;
                let name = argv
                    .get(i)
                    .ok_or("--override-input needs an input name and path:checkout")?
                    .clone();
                i += 1;
                let value = argv.get(i).ok_or("--override-input needs path:checkout")?;
                let checkout = value
                    .strip_prefix("path:")
                    .filter(|path| !path.is_empty())
                    .ok_or("--override-input supports path:checkout")?;
                args.input_overrides.push((name, PathBuf::from(checkout)));
            }
            "--arch" => {
                i += 1;
                args.arch = argv.get(i).ok_or("--arch needs a value")?.clone();
            }
            "--build-host" => {
                i += 1;
                args.build_host = argv.get(i).ok_or("--build-host needs a value")?.clone();
            }
            "--backend" => {
                i += 1;
                args.backend = argv.get(i).ok_or("--backend needs a value")?.clone();
            }
            "--store" => {
                i += 1;
                args.store = Some(PathBuf::from(argv.get(i).ok_or("--store needs a dir")?));
            }
            "--jobs" => {
                i += 1;
                args.jobs = argv
                    .get(i)
                    .ok_or("--jobs needs a number")?
                    .parse()
                    .map_err(|_| "--jobs needs a number".to_string())?;
            }
            "--stamp" => {
                i += 1;
                args.stamp = Some(PathBuf::from(argv.get(i).ok_or("--stamp needs a path")?));
            }
            "--domain" => {
                i += 1;
                let v = argv.get(i).ok_or("--domain needs a [packages] group")?;
                args.domain = Some(v.clone());
            }
            "--" => {
                args.app_args = argv[i + 1..].to_vec();
                break;
            }
            "--events" => {
                i += 1;
                args.events = Some(PathBuf::from(argv.get(i).ok_or("--events needs a path")?));
            }
            "--trace" => {
                i += 1;
                args.trace = Some(PathBuf::from(argv.get(i).ok_or("--trace needs a path")?));
            }
            "--stream-events" => args.stream_events = true,
            "--header-report" => {
                i += 1;
                args.header_report = Some(PathBuf::from(
                    argv.get(i).ok_or("--header-report needs a path")?,
                ));
            }
            "--header-seed" => {
                i += 1;
                args.header_seed = Some(PathBuf::from(
                    argv.get(i).ok_or("--header-seed needs a path")?,
                ));
            }
            "--selfcheck" => args.selfcheck = true,
            "--keep-going" | "-k" => args.keep_going = true,
            "--keep-failed" | "-K" => args.keep_failed = true,
            "--rerun" => args.rerun = true,
            "--no-source-cache" => args.no_source_cache = true,
            "--no-daemon" => args.no_daemon = true,
            "--timings" => args.timings = true,
            "--audit=warn" => args.audit = crate::exec::AuditMode::Warn,
            "--audit=error" => args.audit = crate::exec::AuditMode::Error,
            "-v" => args.verbose = true,
            "-q" => args.build_output = crate::term::view::OutputMode::Failed,
            _ if arg.starts_with("--build-output=") => {
                let value = &arg["--build-output=".len()..];
                args.build_output =
                    crate::term::view::OutputMode::parse(value).ok_or_else(|| {
                        format!(
                            "--build-output: unknown value `{}` (all|failed|none)",
                            value
                        )
                    })?;
            }
            _ if arg.starts_with("-D") => {
                let (k, v) = arg[2..]
                    .split_once('=')
                    .ok_or_else(|| format!("malformed override `{}` (use -DKEY=value)", arg))?;
                args.overrides.push((k.to_string(), v.to_string()));
            }
            _ if is_declared_global_flag(arg) => {
                return Err(format!(
                    "internal error: unhandled buildutil-global flag `{arg}`"
                ));
            }
            _ => args.targets.push(arg.clone()),
        }
        i += 1;
    }
    if args.rerun && !matches!(args.command.as_str(), "check" | "__realize-plan") {
        return Err("--rerun applies only to `buildutil check`".to_string());
    }
    if args.locked && args.command != "build" {
        return Err("--locked applies to `buildutil build`".to_string());
    }
    Ok(args)
}

impl Args {
    /// What the build screen shows for this invocation.
    pub(crate) fn view_options(&self) -> crate::term::view::Options {
        let state_root = std::env::current_dir()
            .ok()
            .and_then(|cwd| repo_root_from(&cwd).ok())
            .map(|repo_root| state_root_from_repo(self, &repo_root));
        crate::term::view::Options {
            verbose: self.verbose,
            output: self.build_output,
            timings: self.timings || self.verbose,
            targets: self.targets.clone(),
            state_root,
            ..crate::term::view::Options::for_terminal()
        }
    }
}

pub(crate) fn repo_root_from(cwd: &Path) -> Result<PathBuf, String> {
    let mut repo_root = cwd.to_path_buf();
    while !repo_root.join("buildutil.toml").is_file() {
        if !repo_root.pop() {
            return Err(
                "no buildutil.toml here or above — run buildutil inside the repository".to_string(),
            );
        }
    }
    Ok(repo_root)
}

pub(super) fn repo_root_from_cwd() -> Result<PathBuf, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let cwd = crate::invocation::request_cwd()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let cwd = std::env::current_dir().map_err(|e| format!("cannot determine repo root: {}", e))?;
    repo_root_from(&cwd)
}

pub(super) fn state_root_from_repo(args: &Args, repo_root: &Path) -> PathBuf {
    state_root_from_repo_for(args, repo_root, None)
}

pub(crate) fn state_root_from_repo_for(
    args: &Args,
    repo_root: &Path,
    request_store: Option<std::ffi::OsString>,
) -> PathBuf {
    args.store
        .clone()
        .or_else(|| request_store.map(PathBuf::from))
        .or_else(|| crate::invocation::ambient_var_os("BUILDUTIL_STORE").map(PathBuf::from))
        .unwrap_or_else(|| repo_root.join(".buildutil"))
}

pub(super) fn executor_runtime_flags(args: &Args) -> Vec<String> {
    let mut out = vec!["--jobs".to_string(), args.jobs.to_string()];
    match args.audit {
        crate::exec::AuditMode::Warn => out.push("--audit=warn".to_string()),
        crate::exec::AuditMode::Error => out.push("--audit=error".to_string()),
    }
    if args.keep_going {
        out.push("--keep-going".to_string());
    }
    if args.keep_failed {
        out.push("--keep-failed".to_string());
    }
    if args.rerun {
        out.push("--rerun".to_string());
    }
    if let Some(path) = &args.events {
        out.push("--events".to_string());
        out.push(path.to_string_lossy().into_owned());
    }
    if let Some(path) = &args.trace {
        out.push("--trace".to_string());
        out.push(path.to_string_lossy().into_owned());
    }
    if args.verbose {
        out.push("-v".to_string());
    }
    out
}

pub struct Context {
    pub(crate) repo_root: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) store: crate::store::Store,
    pub(crate) config: Arc<crate::spec::configres::Config>,
    pub(crate) spec: Arc<crate::spec::Spec>,
    pub(crate) toolchain: crate::tools::Toolchain,
    pub(crate) build_host: crate::host::BuildHost,
    pub(crate) backend: crate::host::ExecBackend,
    git_state: std::sync::OnceLock<(String, String)>,
    pub(crate) inputs: crate::cmd::input_resolution::Resolution,
    _input_lease: Option<crate::state::StoreSharedLease>,
}

impl Context {
    pub(crate) fn git_state(&self) -> &(String, String) {
        self.git_state
            .get_or_init(|| crate::eval::graph::git_state(&self.repo_root))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_daemon_parts(
        repo_root: PathBuf,
        state_root: PathBuf,
        store: crate::store::Store,
        config: Arc<crate::spec::configres::Config>,
        spec: Arc<crate::spec::Spec>,
        toolchain: crate::tools::Toolchain,
        build_host: crate::host::BuildHost,
        backend: crate::host::ExecBackend,
        initial_git_state: (String, String),
        input_lease: crate::state::StoreSharedLease,
    ) -> Self {
        let git_state = std::sync::OnceLock::new();
        let _ = git_state.set(initial_git_state);
        Self {
            repo_root,
            state_root,
            store,
            config,
            spec,
            toolchain,
            build_host,
            backend,
            git_state,
            inputs: crate::cmd::input_resolution::Resolution::default(),
            _input_lease: Some(input_lease),
        }
    }
}

/// Open the evaluation context of `args`: the specification, its resolved
/// configuration and the store. When generators are declared, the
/// generation phase runs here, so every command that evaluates sees the
/// complete specification.
pub fn open_context(args: &Args) -> Result<Context, String> {
    let mut ctx = open_static_context(args)?;
    ctx._input_lease = Some(ctx.store.acquire_shared_lease()?);
    ctx.inputs = inputs::resolve_context(&ctx, args, false)?;
    inputs::install(&mut ctx)?;
    generate::run(&mut ctx, args)?;
    Ok(ctx)
}

/// The context with the static specification only: generators not run.
fn open_static_context(args: &Args) -> Result<Context, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(result) = crate::daemon::state::with_active_daemon(|state| state.open_context(args))
    {
        return result;
    }
    let repo_root = repo_root_from_cwd()?;
    let store_root =
        crate::state::absolute_root(&repo_root, &state_root_from_repo(args, &repo_root));
    let build_host = crate::host::BuildHost::resolve(&args.build_host)?;
    let backend = crate::host::ExecBackend::resolve(&args.backend)?;
    let store = crate::store::Store::open(&store_root)?;
    let input_lease = store.acquire_shared_lease()?;
    // Source-hash cache: the registry folds the toolchain derivations into
    // every closure, so eval hashes the LLVM/rust submodules. Pass the
    // canonical repo_root so the cache can prune to paths under it and bind
    // the on-disk namespace. Flushed in main().
    if !args.no_source_cache {
        crate::source::statcache::load_file_cache(&store_root, &repo_root);
    }
    crate::source::activate(&store_root)?;

    let spec = crate::spec::load_with_input_overrides(
        &repo_root,
        &args.arch,
        build_host.triple(),
        &args.input_overrides,
    )?;
    for dspec in spec.drvs.values() {
        crate::spec::builders::validate(dspec, &spec.flagsets)?;
    }
    let config = crate::spec::configres::Config::open(
        &repo_root,
        &store_root,
        &args.arch,
        spec.configuration.as_ref(),
        &args.overrides,
    )?;
    let toolchain = crate::tools::Toolchain::new(&store_root);
    Ok(Context {
        repo_root,
        state_root: store_root,
        store,
        config: Arc::new(config),
        spec: Arc::new(spec),
        toolchain,
        build_host,
        backend,
        git_state: std::sync::OnceLock::new(),
        inputs: crate::cmd::input_resolution::Resolution::default(),
        _input_lease: Some(input_lease),
    })
}

pub(crate) fn evaluate_plan_with_progress_scoped(
    spec: &crate::spec::Spec,
    config: &crate::spec::configres::Config,
    toolchain: &mut crate::tools::Toolchain,
    targets: &[String],
    state_root: &Path,
    enabled: bool,
    git_state: (String, String),
    memo_scope: &crate::source::EvaluationMemoScope,
    mut progress: impl FnMut(crate::eval::graph::EvalProgress) + Send,
) -> Result<crate::eval::cache::CachedPlan, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(result) = crate::daemon::state::with_active_daemon(|state| {
        state.evaluate_plan_with_progress(
            spec,
            config,
            toolchain,
            targets,
            enabled,
            git_state.clone(),
            memo_scope,
            &mut progress,
        )
    }) {
        return result;
    }
    crate::eval::cache::evaluate_plan_with_progress_scoped(
        spec,
        config,
        toolchain,
        targets,
        state_root,
        enabled,
        git_state,
        memo_scope,
        &mut progress,
    )
}

pub(crate) fn evaluate_plan_with_progress(
    spec: &crate::spec::Spec,
    config: &crate::spec::configres::Config,
    toolchain: &mut crate::tools::Toolchain,
    targets: &[String],
    state_root: &Path,
    enabled: bool,
    git_state: (String, String),
    progress: impl FnMut(crate::eval::graph::EvalProgress) + Send,
) -> Result<crate::eval::cache::CachedPlan, String> {
    let memo_scope = crate::source::EvaluationMemoScope::new();
    evaluate_plan_with_progress_scoped(
        spec,
        config,
        toolchain,
        targets,
        state_root,
        enabled,
        git_state,
        &memo_scope,
        progress,
    )
}

pub(crate) fn daemon_snapshot_still_current(
    spec: &crate::spec::Spec,
    resolved: &crate::eval::graph::ResolvedSources,
) -> Result<bool, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(result) = crate::daemon::state::with_active_daemon(|state| {
        state.snapshot_still_current(spec, resolved)
    }) {
        return result;
    }
    Ok(true)
}

/// The license check's flag that repairs what it reports.
const LICENSE_FIX: &str = "--fix";
/// The license check's option naming another repository root; its
/// directory follows.
const LICENSE_ROOT: &str = "--root";
/// The conformance check's flag that re-pins its corpus.
const CONFORMANCE_BLESS: &str = "--bless";

/// A `check` invocation's words: the checks it names and the built-in
/// checks' own options, which may stand anywhere among them.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CheckWords {
    /// The words naming checks, in order.
    pub(crate) checks: Vec<String>,
    /// The license check's options in order, `--root` with its directory.
    pub(crate) license: Vec<String>,
    /// The conformance check's `--bless`.
    pub(crate) bless: bool,
}

/// Split a `check` invocation's target words into the checks it names and
/// the built-in checks' options.
pub(crate) fn check_words(args: &Args) -> Result<CheckWords, String> {
    let mut out = CheckWords::default();
    let mut words = args.targets.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            LICENSE_FIX => out.license.push(word.clone()),
            LICENSE_ROOT => {
                let dir = words
                    .next()
                    .ok_or_else(|| format!("check: {LICENSE_ROOT} needs a directory"))?;
                out.license.push(word.clone());
                out.license.push(dir.clone());
            }
            CONFORMANCE_BLESS => out.bless = true,
            _ => out.checks.push(word.clone()),
        }
    }
    Ok(out)
}

/// The engine request a bare `buildutil check` makes for the `[checks]` group
/// `default`: the invocation's arguments without the license check's
/// options, which apply to the license check it runs beside the group.
pub(crate) fn bare_check_request(args: &Args) -> Vec<String> {
    let mut request = vec![
        "check".to_string(),
        crate::spec::kinds::DEFAULT_GROUP.to_string(),
    ];
    request.extend(without_license_options(args.argv.get(1..).unwrap_or(&[])));
    request
}

/// `argv` without the license check's options: the arguments of the request
/// that realizes the declared checks a bare `buildutil check` runs beside it.
/// A global option's value is kept whatever it reads.
pub(crate) fn without_license_options(argv: &[String]) -> Vec<String> {
    let takes_value = |arg: &str| {
        BUILDUTIL_GLOBAL_FLAGS
            .iter()
            .any(|flag| !flag.prefix && flag.value.is_some() && flag.name == arg)
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--" {
            out.extend_from_slice(&argv[i..]);
            break;
        }
        if takes_value(arg) {
            out.extend_from_slice(&argv[i..argv.len().min(i + 2)]);
            i += 2;
            continue;
        }
        match arg {
            LICENSE_FIX => i += 1,
            LICENSE_ROOT => i += 2,
            _ => {
                out.push(argv[i].clone());
                i += 1;
            }
        }
    }
    out
}

/// The kind table an invocation's target words resolve through.
pub(crate) fn scope_of(args: &Args) -> crate::spec::kinds::Scope {
    use crate::spec::kinds::Scope;
    args.scope.unwrap_or(match args.command.as_str() {
        "build" => Scope::Packages,
        "check" => Scope::Checks,
        _ => Scope::Query,
    })
}

/// Resolve an invocation's target words into evaluation targets through its
/// kind table. `build` and `check` with no words take their table's
/// `default` group.
pub(crate) fn resolve_targets(
    spec: &crate::spec::Spec,
    args: &Args,
    words: &[String],
) -> Result<Vec<String>, String> {
    use crate::spec::kinds::{DEFAULT_GROUP, Scope};
    let scope = scope_of(args);
    let defaulted;
    let words = if words.is_empty() && matches!(scope, Scope::Packages | Scope::Checks) {
        defaulted = vec![DEFAULT_GROUP.to_string()];
        &defaulted
    } else {
        words
    };
    let targets = spec.kinds.resolve(scope, words, |name| {
        spec.drvs.contains_key(name) || spec.variants.contains_key(name)
    })?;
    match &args.domain {
        None => Ok(targets),
        Some(group) => restrict_to_domain(spec, group, targets),
    }
}

/// Keep the targets inside the closure of the `[packages]` group `group`.
pub(crate) fn restrict_to_domain(
    spec: &crate::spec::Spec,
    group: &str,
    targets: Vec<String>,
) -> Result<Vec<String>, String> {
    let members = domain_closure(spec, group)?;
    let kept: Vec<String> = targets
        .into_iter()
        .filter(|target| {
            let text = target.trim_start_matches(crate::spec::kinds::OPTIONAL_PREFIX);
            crate::spec::address::parse(text)
                .map(|address| {
                    members.contains(crate::spec::variant_base(&spec.variants, address.name()))
                })
                .unwrap_or(false)
        })
        .collect();
    if kept.is_empty() {
        return Err(format!(
            "no requested target lies in the closure of `{group}`"
        ));
    }
    Ok(kept)
}

/// The static derivation closure of a `[packages]` group.
pub(crate) fn domain_closure(
    spec: &crate::spec::Spec,
    group: &str,
) -> Result<std::collections::BTreeSet<String>, String> {
    use crate::spec::kinds::Kind;
    if !spec.kinds.is_group(Kind::Packages, group) {
        return Err(format!("--domain: `{group}` is not a [packages] group"));
    }
    let members = spec.kinds.expand_group(Kind::Packages, group)?;
    Ok(crate::eval::graph::closure(spec, &members)?
        .into_iter()
        .collect())
}

pub(super) fn positional<'a>(args: &'a Args) -> Vec<&'a str> {
    args.targets
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(|s| s.as_str())
        .collect()
}

/// The value following `flag` in the positional args (store subcommands carry
/// their own `--k v` options after the subcommand word).
pub(super) fn flag_value<'a>(args: &'a Args, flag: &str) -> Option<&'a str> {
    let mut it = args.targets.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().map(|s| s.as_str());
        }
    }
    None
}

pub(super) fn flag_present(args: &Args, flag: &str) -> bool {
    args.targets.iter().any(|a| a == flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_failed_parses_long_and_short_flags() {
        let long = parse_args(&[
            "build".to_string(),
            "host-stdenv".to_string(),
            "--keep-failed".to_string(),
        ])
        .unwrap();
        assert!(long.keep_failed);
        assert_eq!(long.targets, vec!["host-stdenv"]);

        let short = parse_args(&[
            "build".to_string(),
            "host-stdenv".to_string(),
            "-K".to_string(),
        ])
        .unwrap();
        assert!(short.keep_failed);
        assert_eq!(short.targets, vec!["host-stdenv"]);
    }

    #[test]
    fn no_daemon_flag_is_not_a_target() {
        let args = parse_args(&[
            "build".to_string(),
            "kernite".to_string(),
            "--no-daemon".to_string(),
        ])
        .unwrap();
        assert!(args.no_daemon);
        assert_eq!(args.targets, vec!["kernite"]);
    }

    #[test]
    fn required_only_the_words_after_the_separator_reach_an_app() {
        let args = parse_args(
            &[
                "run",
                "qemu",
                "image-disk-bios",
                "-DX=1",
                "--jobs",
                "3",
                "--",
                "--smp",
                "4",
                "-v",
                "--store",
                "elsewhere",
            ]
            .map(str::to_string),
        )
        .unwrap();
        assert_eq!(args.targets, vec!["qemu", "image-disk-bios"]);
        assert_eq!(args.overrides, vec![("X".to_string(), "1".to_string())]);
        assert_eq!(args.jobs, 3);
        assert!(!args.verbose);
        assert_eq!(args.store, None);
        assert_eq!(args.app_args, ["--smp", "4", "-v", "--store", "elsewhere"]);
        assert_eq!(scope_of(&args), crate::spec::kinds::Scope::Query);
    }

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn required_the_license_check_options_parse_wherever_they_stand() {
        let words = |argv: &[&str]| check_words(&parse_args(&strings(argv)).unwrap());
        let license = |checks: &[&str], options: &[&str]| CheckWords {
            checks: strings(checks),
            license: strings(options),
            bless: false,
        };
        for (argv, expected) in [
            (
                &["check", "license", "--fix"][..],
                license(&["license"], &["--fix"]),
            ),
            (
                &["check", "license", "--root", "lib/nt"][..],
                license(&["license"], &["--root", "lib/nt"]),
            ),
            (
                &["check", "--root", "lib/nt", "license"][..],
                license(&["license"], &["--root", "lib/nt"]),
            ),
            (&["check", "--fix"][..], license(&[], &["--fix"])),
            (
                &["check", "--fix", "--arch", "aarch64", "--root", "lib/nt"][..],
                license(&[], &["--fix", "--root", "lib/nt"]),
            ),
            (&["check", "kernite", "-k"][..], license(&["kernite"], &[])),
        ] {
            assert_eq!(words(argv).unwrap(), expected, "{argv:?}");
        }
        assert!(words(&["check", "conformance", "--bless"]).unwrap().bless);
        assert!(words(&["check", "license", "--root"]).is_err());
        // The license check and a bare check run in the client; declared
        // checks are engine requests.
        for argv in [
            &["check", "--root", "lib/nt", "license"][..],
            &["check", "license", "--fix"][..],
            &["check", "--fix"][..],
            &["check"][..],
        ] {
            assert!(!engine::is_engine_request(&strings(argv)), "{argv:?}");
        }
        assert!(engine::is_engine_request(&strings(&["check", "kernite"])));
    }

    #[test]
    fn required_a_nameless_check_gives_its_options_to_the_license_check_only() {
        for (argv, license) in [
            (&["check", "--fix"][..], &["--fix"][..]),
            (
                &["check", "--root", "lib/nt"][..],
                &["--root", "lib/nt"][..],
            ),
            (
                &["check", "--root", "lib/nt", "-DX=1", "--fix", "-v"][..],
                &["--root", "lib/nt", "--fix"][..],
            ),
        ] {
            let args = parse_args(&strings(argv)).unwrap();
            // The license check runs with the options, in the client.
            let words = check_words(&args).unwrap();
            assert!(words.checks.is_empty(), "{argv:?}");
            assert_eq!(words.license, strings(license), "{argv:?}");
            assert!(!engine::is_engine_request(&strings(argv)), "{argv:?}");
            // The default group's request carries no option as a word.
            let request = bare_check_request(&args);
            let build = parse_args(&request).unwrap();
            assert_eq!(build.targets, ["default"], "{argv:?}");
            assert_eq!(build.overrides, args.overrides, "{argv:?}");
            assert_eq!(build.verbose, args.verbose, "{argv:?}");
            assert_eq!(
                check_words(&build).unwrap(),
                CheckWords {
                    checks: strings(&["default"]),
                    ..CheckWords::default()
                }
            );
            assert!(engine::is_engine_request(&request), "{argv:?}");
        }
    }

    #[test]
    fn required_a_bare_check_forwards_everything_but_the_license_options() {
        assert_eq!(
            without_license_options(&strings(&[
                "--fix", "--store", "--fix", "-v", "--root", "lib/nt", "-DX=1", "--arch",
                "aarch64", "--", "--fix",
            ])),
            strings(&[
                "--store", "--fix", "-v", "-DX=1", "--arch", "aarch64", "--", "--fix"
            ])
        );
    }

    #[test]
    fn buildutil_global_flag_table_never_reaches_targets() {
        for flag in BUILDUTIL_GLOBAL_FLAGS {
            let token = if flag.prefix {
                format!("{}TEST_FLAG=true", flag.name)
            } else {
                flag.name.to_string()
            };
            let mut flag_tokens = vec![token.clone()];
            if let Some(value) = flag.value {
                flag_tokens.push(value.to_string());
            }
            if flag.name == "--override-input" {
                flag_tokens.push("path:/tmp/input-checkout".into());
            }
            for before_target in [true, false] {
                let mut argv = vec!["build".to_string()];
                if before_target {
                    argv.extend(flag_tokens.iter().cloned());
                }
                argv.push("sentinel-target".to_string());
                if !before_target {
                    argv.extend(flag_tokens.iter().cloned());
                }
                let parsed = parse_args(&argv)
                    .unwrap_or_else(|error| panic!("{} did not parse: {error}", flag.name));
                assert_eq!(
                    parsed.targets,
                    vec!["sentinel-target"],
                    "buildutil-global flag {} survived into Args::targets as {:?}",
                    flag.name,
                    parsed.targets
                );
                assert!(!parsed.targets.contains(&token));
            }
        }
    }
}
