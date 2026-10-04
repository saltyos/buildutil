// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — daily-driver commands
//!
//! setup/run/gdb/fmt/check/tc/bootstrap: thin orchestration over the
//! derivation engine, apps and the formatter.

use super::conformance::run;
use super::{Args, launch};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::host::interrupt::{InterruptCleanup, InterruptGuard};
use crate::log::Logger;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::{SystemTime, UNIX_EPOCH};

static ROOTFS_COPY_SEQ: AtomicU64 = AtomicU64::new(0);

fn repo_root() -> Result<PathBuf, String> {
    super::repo_root_from_cwd()
}

/// Run an interactive program (a TUI, a debugger, a VM console) on the
/// terminal. The status row is down and buildutil's own output is held until
/// it exits.
fn sh_terminal(root: &Path, program: &str, args: &[String]) -> Result<i32, String> {
    #[cfg(unix)]
    let _signals = crate::host::interrupt::TerminalSignalsToChild::install();
    let lease = crate::term::handover();
    let status = crate::invocation::command(program)
        .args(args)
        .current_dir(root)
        .terminal(&lease)
        .status()
        .map_err(|e| format!("cannot run {}: {}", program, e))?;
    drop(lease);
    Ok(status.code().unwrap_or(1))
}

fn arch_of(args: &[String]) -> String {
    let mut arch = "x86_64".to_string();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--arch" {
            if let Some(v) = args.get(i + 1) {
                arch = v.clone();
            }
        }
        i += 1;
    }
    arch
}

fn read_root_path(state_root: &Path, root_name: &str, context: &str) -> Result<PathBuf, String> {
    let link = state_root.join("roots").join(root_name);
    let target = std::fs::read_link(&link).map_err(|e| format!("{context}: {}", e))?;
    if target.is_absolute() {
        Ok(target)
    } else {
        Ok(link
            .parent()
            .ok_or_else(|| format!("{context}: malformed root path {}", link.display()))?
            .join(target))
    }
}

fn value_of<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            return args.get(i + 1).map(|s| s.as_str());
        }
        i += 1;
    }
    None
}

fn build_host_of(args: &[String]) -> Result<crate::host::BuildHost, String> {
    crate::host::BuildHost::resolve(
        value_of(args, "--build-host").unwrap_or(crate::host::DEFAULT_BUILD_HOST),
    )
}

fn backend_of(args: &[String]) -> Result<crate::host::ExecBackend, String> {
    crate::host::ExecBackend::resolve(
        value_of(args, "--backend").unwrap_or(crate::host::DEFAULT_BACKEND),
    )
}

fn append_build_host_backend(
    out: &mut Vec<String>,
    build_host: &crate::host::BuildHost,
    backend: &crate::host::ExecBackend,
) {
    out.push("--build-host".to_string());
    out.push(build_host.triple().to_string());
    out.push("--backend".to_string());
    out.push(backend.as_str().to_string());
}

/// `buildutil setup [--arch <a>]` — seed the persistent override file with the
/// architecture and resolve the configuration in process, reporting any
/// diagnostic now rather than at the first build.
pub fn cmd_setup(args: &[String]) -> Result<i32, String> {
    let root = repo_root()?;
    let arch = arch_of(args);
    let state_root = crate::invocation::ambient_var_os("BUILDUTIL_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".buildutil"));
    let config = crate::state::config_file(&state_root, &arch);
    if let Some(parent) = config.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    let logger = Logger::new(args.iter().any(|a| a == "-v"));
    let build_host = build_host_of(args)?;
    let spec = crate::spec::load(&root, &arch, build_host.triple())?;
    if !config.is_file() {
        // The option graph names the option that carries the architecture.
        let seed = match spec
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.arch_option.as_ref())
        {
            Some(option) => format!("{option} = \"{arch}\"\n"),
            None => String::new(),
        };
        std::fs::write(&config, seed)
            .map_err(|e| format!("cannot seed {}: {}", config.display(), e))?;
    }
    crate::spec::configres::Config::open(
        &root,
        &state_root,
        &arch,
        spec.configuration.as_ref(),
        &[],
    )?;
    logger.success(
        "setup",
        &format!("Resolved configuration for {arch} ({})", config.display()),
    );
    Ok(0)
}

/// Realize `target` of a self-tool specification — the native frontend's
/// class: its derivations compile with the ambient compiler — and return its
/// output directory.
pub(crate) fn realize_self_tool_spec(
    root: &Path,
    state_root: &Path,
    spec: crate::spec::Spec,
    target: &str,
) -> Result<PathBuf, String> {
    let _ = root;
    let exec_host = crate::host::exec_host_triple();
    let identity_path = state_root
        .join("bootstrap")
        .join(&exec_host)
        .join("rustc.vv");
    let identity = std::fs::read(&identity_path).map_err(|e| {
        format!(
            "cannot read the ambient compiler identity {}: {e} — run ./buildutil once to bootstrap",
            identity_path.display()
        )
    })?;
    let ambient = |var: &str, default: &str| -> Result<PathBuf, String> {
        let command = crate::invocation::ambient_var_os(var)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default));
        if command.components().count() > 1 {
            return Ok(command);
        }
        let path = crate::invocation::ambient_var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .map(|dir| dir.join(&command))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| format!("{} (`{}`) is not on PATH", var, command.display()))
    };
    let rustc = ambient("BUILDUTIL_RUSTC", "rustc")?;
    let linker = ambient("BUILDUTIL_LINKER", "cc")?;
    let target = target.to_string();
    for dspec in spec.drvs.values() {
        crate::spec::builders::validate(dspec, &spec.flagsets)?;
        if !dspec.native_frontend {
            return Err(format!(
                "self-tool `{target}` reaches `{}`, which is not native-frontend",
                dspec.name
            ));
        }
    }
    let store = crate::store::Store::open(state_root)?;
    crate::source::activate(state_root)?;
    let config = crate::spec::configres::Config::from_values(std::collections::BTreeMap::new());
    let mut toolchain =
        crate::tools::Toolchain::with_native_frontend_tools(state_root, rustc, linker, &identity);
    let targets = vec![target.clone()];
    let git_state = crate::eval::graph::git_state(&spec.repo_root);
    let evaluated =
        crate::eval::graph::evaluate(&spec, &config, &mut toolchain, &targets, &git_state)?;
    let (_path, _hash, plan) = crate::eval::plan::emit(&spec, &evaluated, state_root, &git_state)?;
    let sandbox = crate::exec::sandbox::platform_sandbox();
    let builders = crate::exec::builder::BuilderRegistry::core();
    let logger = Logger::new(false);
    let jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let outcome = crate::exec::pool::realize(
        &plan,
        &store,
        sandbox.as_ref(),
        &builders,
        jobs,
        crate::exec::AuditMode::Warn,
        false,
        false,
        &std::collections::BTreeSet::new(),
        &logger,
    )?;
    if !outcome.failed.is_empty() {
        return Err(format!("self-tool `{target}` failed to build"));
    }
    let store_name = outcome
        .store_names
        .get(&target)
        .ok_or_else(|| format!("self-tool `{target}` produced no store output"))?;
    Ok(store.root.join(store_name))
}

fn run_declared_launcher(
    root: &Path,
    command: &[String],
    launcher_args: &[String],
) -> Result<i32, String> {
    let (program, prefix) = command
        .split_first()
        .ok_or_else(|| "[launch].command must not be empty".to_string())?;
    let mut command_args = prefix.to_vec();
    command_args.extend_from_slice(launcher_args);
    sh_terminal(root, program, &command_args)
}

fn validate_utm_compatibility(launcher_args: &[String]) -> Result<(), String> {
    if !launcher_args.iter().any(|arg| arg == "--utm") {
        return Ok(());
    }
    let incompatible: Vec<&str> = ["--test-exit", "--cpu", "--kvm"]
        .into_iter()
        .filter(|flag| launcher_args.iter().any(|arg| arg == *flag))
        .collect();
    if incompatible.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "--utm cannot honor launcher flag(s): {}",
            incompatible.join(", ")
        ))
    }
}

fn missing_artifact_error(command: &str, artifact: &Path) -> String {
    format!(
        "image missing at {} — produce it with `{command}`",
        artifact.display()
    )
}

fn without_standalone_flag(args: &[String], flag: &str) -> Vec<String> {
    let mut out = args.to_vec();
    out.retain(|arg| arg != flag);
    out
}

/// Absolute `--run-state` value for the launcher.
fn launcher_run_state(root: &Path, state_root: &Path) -> String {
    crate::state::run_dir(&crate::state::absolute_root(root, state_root))
        .to_string_lossy()
        .into_owned()
}

/// Output directory of a dev-built `target`. Only dev launches resolve the
/// execution backend; store launches need none, so a host without a container
/// runtime can still launch store images.
fn dev_output_root(
    args: &Args,
    root: &Path,
    state_root: &Path,
    arch: &str,
    target: &str,
) -> Result<PathBuf, String> {
    let backend = crate::host::ExecBackend::resolve(&args.backend)?;
    Ok(crate::state::dev_dir(
        &crate::state::absolute_root(root, state_root),
        backend.dev_output_name()?,
        arch,
        target,
    )
    .join("out"))
}

/// Create `<run-dir>/log/<UTC date>/<stem>-<HHMMSS>Z.log`, suffixing `-2`,
/// `-3`, ... when a log from the same second already exists.
fn create_run_log(
    root: &Path,
    state_root: &Path,
    stem: &str,
) -> Result<(PathBuf, std::fs::File), String> {
    let (day, time) = crate::host::utc_date_and_time();
    let dir = crate::state::run_dir(&crate::state::absolute_root(root, state_root))
        .join("log")
        .join(day);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    for n in 1..=100u32 {
        let name = if n == 1 {
            format!("{stem}-{time}.log")
        } else {
            format!("{stem}-{time}-{n}.log")
        };
        let path = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create {}: {e}", path.display())),
        }
    }
    Err(format!("cannot create a {stem} log in {}", dir.display()))
}

/// `buildutil run <app> [<package>...] [--dev] [-- <arguments>]` runs an app
/// after preparing its inputs; `buildutil run` with launcher options alone
/// launches an already-realized boot image through the `[launch]` tables.
pub fn cmd_run(args: &Args) -> Result<i32, String> {
    let root = repo_root()?;
    if let Some(word) = args.targets.first().filter(|word| !word.starts_with('-')) {
        let build_host = crate::host::BuildHost::resolve(&args.build_host)?;
        let spec = crate::spec::load(&root, &args.arch, build_host.triple())?;
        let app = spec.kinds.apps.get(word).cloned().ok_or_else(|| {
            let known: Vec<&str> = spec.kinds.apps.keys().map(String::as_str).collect();
            format!(
                "run: `{word}` is not an app (declared apps: {})",
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            )
        })?;
        return super::app::run(args, &root, word, &app);
    }
    validate_utm_compatibility(&args.targets)?;
    let config = launch::Launch::load(&root)?;
    let arch = &args.arch;
    let force_uefi = args.targets.iter().any(|arg| arg == "--uefi");
    let dev = args.targets.iter().any(|arg| arg == "--dev");
    let image = config.image(arch, force_uefi);
    let build_command = image.build_invocation(arch, dev);
    let state_root = super::state_root_from_repo(args, &root);
    let disk = if dev {
        dev_output_root(args, &root, &state_root, arch, &image.build_target)?.join(&image.file)
    } else {
        let entry = read_root_path(
            &state_root,
            &format!("latest-{}-{}", image.build_target, arch),
            &format!("run: image root missing — run `{build_command}`"),
        )?;
        entry.join(&image.file)
    };
    if !disk.is_file() {
        return Err(format!(
            "run: {}",
            missing_artifact_error(&build_command, &disk)
        ));
    }

    let mut launcher_args: Vec<String> = vec![
        "--arch".to_string(),
        arch.clone(),
        "--disk".to_string(),
        disk.to_string_lossy().into_owned(),
        "--run-state".to_string(),
        launcher_run_state(&root, &state_root),
    ];
    launcher_args.extend(without_standalone_flag(&args.targets, "--dev"));
    validate_utm_compatibility(&launcher_args)?;
    run_declared_launcher(&root, &config.command, &launcher_args)
}

/// Copy the declared rootfs artifact into the writable runtime disk directory.
/// The package variant is built first so its declared port dependencies are realized.
pub(crate) fn cmd_mkrootfs(args: &Args) -> Result<i32, String> {
    let root = repo_root()?;
    if args.targets.iter().any(|arg| arg != "--with-ports") {
        return Err("mkrootfs: only --with-ports and build options are accepted".into());
    }
    let state_root = crate::state::absolute_root(&root, &super::state_root_from_repo(args, &root));
    let with_ports = args.targets.iter().any(|arg| arg == "--with-ports");
    let rootfs = launch::Rootfs::load(&root, with_ports)?;
    let image = rootfs.image;
    if with_ports {
        let mut build = args.clone();
        build.command = "build".into();
        build.targets = vec![format!("drv:{}", image.build_target)];
        build.argv = vec!["build".into(), format!("drv:{}", image.build_target)];
        build.argv.extend(
            args.argv
                .iter()
                .skip(1)
                .filter(|arg| *arg != "--with-ports")
                .cloned(),
        );
        for (key, value) in &rootfs.config {
            if let Some((_, requested)) = args
                .overrides
                .iter()
                .find(|(requested, _)| requested == key)
            {
                if requested != value {
                    return Err(format!(
                        "mkrootfs: --with-ports requires {key}={value}, conflicting with -D{key}={requested}"
                    ));
                }
            } else {
                build.overrides.push((key.clone(), value.clone()));
                build.argv.push(format!("-D{key}={value}"));
            }
        }
        let code = super::build::cmd_build(&build)?;
        if code != 0 {
            return Ok(code);
        }
    }
    let store = crate::store::Store::open(&state_root)?;
    let _lease = store.acquire_shared_lease()?;
    let entry = read_root_path(
        &state_root,
        &format!("latest-{}-{}", image.build_target, args.arch),
        &format!(
            "mkrootfs: image root missing — run `{}`",
            image.build_invocation(&args.arch, false)
        ),
    )?;
    let source = entry.join(&image.file);
    if !source.is_file() {
        return Err(missing_artifact_error(
            &image.build_invocation(&args.arch, false),
            &source,
        ));
    }
    let directory = crate::state::run_dir(&state_root)
        .join("disk")
        .join(&args.arch);
    std::fs::create_dir_all(&directory)
        .map_err(|e| format!("mkrootfs: cannot create {}: {e}", directory.display()))?;
    let target = directory.join(
        std::path::Path::new(&image.file)
            .file_name()
            .ok_or("rootfs output has no filename")?,
    );
    let temporary = directory.join(format!(
        ".{}.tmp-{}-{}",
        target.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        ROOTFS_COPY_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| format!("mkrootfs: cannot create copy: {e}"))?;
    let result = (|| {
        let mut input = std::fs::File::open(&source)
            .map_err(|e| format!("mkrootfs: cannot open {}: {e}", source.display()))?;
        std::io::copy(&mut input, &mut file)
            .map_err(|e| format!("mkrootfs: cannot copy {}: {e}", source.display()))?;
        let mut permissions = file.metadata().map_err(|e| e.to_string())?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o644);
        }
        #[cfg(not(unix))]
        {
            permissions.set_readonly(false);
        }
        file.set_permissions(permissions)
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        std::fs::rename(&temporary, &target)
            .map_err(|e| format!("mkrootfs: cannot publish {}: {e}", target.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    crate::log::success(
        "mkrootfs",
        &format!("Copied {} to {}", source.display(), target.display()),
    );
    Ok(0)
}

/// Stop a launcher process group. The launcher replaces itself with the VM, so
/// killing the group also covers a wrapper that did not replace itself.
/// Best-effort — a reaped child is a no-op.
fn kill_group(pid: i32) {
    crate::platform::terminate_process_group(pid as u32);
}

/// `--smp N` from the args, if the caller pinned a CPU count.
fn smp_of(args: &[String]) -> Option<u32> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--smp" {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
        i += 1;
    }
    None
}

struct TestPassResult {
    code: i32,
    label: String,
}

/// Boot the CI image once under QEMU and reduce the serial stream to an exit
/// code. A clean pass/fail powers the guest off (runner SystemControl
/// SHUTDOWN) and QEMU exits on its own; a panic (`halt_forever`) or hang can
/// only be ended by the host, so we scan + time out + kill the group. A win32
/// smoke-test failure blocks the runner (it is ordered `After` it), so we
/// treat that verdict as terminal too.
fn run_test_pass(
    root: &Path,
    state_root: &Path,
    arch: &str,
    disk: &Path,
    smp: u32,
    passthrough: &[String],
    command: &[String],
    test: &launch::Test,
) -> Result<TestPassResult, String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let mut launcher_args: Vec<String> = vec![
        "--arch".to_string(),
        arch.to_string(),
        "--disk".to_string(),
        disk.to_string_lossy().into_owned(),
        "--run-state".to_string(),
        launcher_run_state(root, state_root),
        "--test-exit".to_string(),
        "--headless".to_string(),
        "--smp".to_string(),
        smp.to_string(),
    ];
    launcher_args.extend(passthrough.iter().cloned());
    validate_utm_compatibility(&launcher_args)?;
    let (log_path, log_file) = create_run_log(root, state_root, &format!("test-{arch}-smp{smp}"))?;
    crate::log::info("test", &format!("serial log: {}", log_path.display()));

    let (program, prefix) = command
        .split_first()
        .ok_or_else(|| "[launch].command must not be empty".to_string())?;
    let mut cmd = crate::invocation::command(program);
    cmd.args(prefix)
        .args(&launcher_args)
        .current_dir(root)
        .stdin(crate::invocation::Io::Null)
        .stdout(crate::invocation::Io::Piped);
    // Own process group so the whole VM can be torn down as a unit.
    cmd.new_process_group();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("test: cannot launch {}: {}", program, e))?;
    let pid = child.id() as i32;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "test: no serial pipe".to_string())?;

    let matched = Arc::new(
        test.verdicts
            .iter()
            .map(|_| AtomicBool::new(false))
            .collect::<Vec<_>>(),
    );
    let last = Arc::new(Mutex::new(Instant::now()));

    // The reader never writes to the terminal itself: a slow consumer of
    // buildutil's stdout must not stall verdicts or the inactivity clock.
    let (display_tx, display_rx) = std::sync::mpsc::channel::<String>();
    let display = std::thread::spawn(move || {
        for line in display_rx {
            crate::term::result_raw(line.as_bytes());
        }
    });
    let reader = {
        let matched = matched.clone();
        let verdicts = test.verdicts.clone();
        let last = last.clone();
        std::thread::spawn(move || {
            let mut log = log_file;
            let mut br = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match br.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                // Record activity, the log, and verdicts before showing the
                // line: a slow terminal must not delay the inactivity clock.
                if let Ok(mut t) = last.lock() {
                    *t = Instant::now();
                }
                let _ = log.write_all(line.as_bytes());
                if let Some((index, _)) = verdicts
                    .iter()
                    .enumerate()
                    .find(|(_, verdict)| verdict.matches_line(line.trim()))
                {
                    matched[index].store(true, Ordering::SeqCst);
                }
                let _ = display_tx.send(line.clone());
            }
        })
    };

    let wall = Duration::from_secs(test.wall_timeout_secs);
    let inactivity = Duration::from_secs(test.inactivity_timeout_secs);
    let grace = Duration::from_secs(test.kill_grace_secs);
    let start = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|e| format!("test: waitpid: {}", e))?
            .is_some()
        {
            break; // guest powered off (clean pass or fail) or QEMU exited
        }
        if test
            .verdicts
            .iter()
            .enumerate()
            .any(|(index, verdict)| verdict.kill && matched[index].load(Ordering::SeqCst))
        {
            std::thread::sleep(grace);
            kill_group(pid);
            break;
        }
        let idle = last.lock().map(|t| t.elapsed()).unwrap_or_default();
        if start.elapsed() >= wall || idle >= inactivity {
            if let Some(index) = test
                .verdicts
                .iter()
                .position(launch::Verdict::matches_timeout)
            {
                matched[index].store(true, Ordering::SeqCst);
            }
            kill_group(pid);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.wait();
    let _ = reader.join();
    let _ = display.join();

    Ok(test
        .verdicts
        .iter()
        .enumerate()
        .find(|(index, _)| matched[*index].load(Ordering::SeqCst))
        .map(|(_, verdict)| TestPassResult {
            code: verdict.code,
            label: verdict.label.clone(),
        })
        .unwrap_or_else(|| TestPassResult {
            code: test.no_verdict_code,
            label: "no verdict".to_string(),
        }))
}

/// `buildutil test [--arch A] [--smp N] [launcher passthrough...]` — boot an
/// already-realized CI image and reduce its serial verdicts to an exit code.
pub fn cmd_test(args: &Args) -> Result<i32, String> {
    let root = repo_root()?;
    let mut compatibility_args = args.targets.clone();
    compatibility_args.push("--test-exit".to_string());
    validate_utm_compatibility(&compatibility_args)?;
    let config = launch::Launch::load(&root)?;
    let arch = &args.arch;
    let dev = args.targets.iter().any(|arg| arg == "--dev");
    let image = config.test_image(arch, args.targets.iter().any(|arg| arg == "--uefi"));
    let build_command = image.build_invocation(arch, dev);
    let state_root = super::state_root_from_repo(args, &root);
    let image_root = if dev {
        dev_output_root(args, &root, &state_root, arch, &image.build_target)?
    } else {
        read_root_path(
            &state_root,
            &format!("latest-{}-{}", image.build_target, arch),
            &format!("test: image root missing — run `{build_command}`"),
        )?
    };
    let disk = image_root.join(&image.file);
    if !disk.is_file() {
        return Err(format!(
            "test: {}",
            missing_artifact_error(&build_command, &disk)
        ));
    }
    if dev {
        // A store test image is a configuration variant, so its identity
        // carries its configuration; a dev tree has no store identity.
        crate::log::info(
            "test",
            "--dev boots a dev tree, which has no store identity recording its configuration",
        );
    }

    let passes: Vec<u32> = match smp_of(&args.targets) {
        Some(n) => vec![n],
        None => config.test.smp_passes.clone(),
    };
    let mut passthrough = Vec::new();
    let mut index = 0;
    while index < args.targets.len() {
        match args.targets[index].as_str() {
            "--smp" | "--disk" => index += 2,
            "--dev" | "--test-exit" | "--headless" => index += 1,
            _ => {
                passthrough.push(args.targets[index].clone());
                index += 1;
            }
        }
    }

    let mut worst: Option<TestPassResult> = None;
    for smp in passes {
        crate::log::info("test", &format!("boot arch={} smp={}", arch, smp));
        let result = run_test_pass(
            &root,
            &state_root,
            arch,
            &disk,
            smp,
            &passthrough,
            &config.command,
            &config.test,
        )?;
        let verdict = format!(
            "arch={} smp={}: {} (exit {})",
            arch, smp, result.label, result.code
        );
        if result.code == 0 {
            crate::log::success("test", &verdict);
        } else {
            crate::log::error("test", &verdict);
        }
        if result.code != 0
            && worst
                .as_ref()
                .map(|current| result.code > current.code)
                .unwrap_or(true)
        {
            worst = Some(result);
        }
    }
    match worst {
        Some(result) => {
            crate::log::error("test", &format!("failed: {}", result.label));
            Ok(result.code)
        }
        None => {
            crate::log::success("test", "passed");
            Ok(0)
        }
    }
}

/// `buildutil config [--arch <a>]` edits the architecture's persistent
/// `.buildutil/config/<arch>/config`; an explicit verb operates on its named graph.
pub fn cmd_config(args: &[String]) -> Result<i32, String> {
    if args.first().is_some_and(|arg| !arg.starts_with('-')) {
        let lease = (args[0] == "menuconfig").then(crate::term::handover);
        let result = crate::config::run(args);
        drop(lease);
        return result;
    }
    let root = repo_root()?;
    config_editor(&root, args)
}

/// The terminal layer exists for Linux and macOS; a Windows host runs
/// the editor inside WSL, as it runs builds.
#[cfg(windows)]
fn config_editor(root: &Path, args: &[String]) -> Result<i32, String> {
    let mut inner = vec![
        "--cd".to_string(),
        root.to_string_lossy().into_owned(),
        "./buildutil".to_string(),
        "config".to_string(),
    ];
    inner.extend(args.iter().cloned());
    sh_terminal(root, "wsl", &inner)
}

#[cfg(not(windows))]
fn config_editor(root: &Path, args: &[String]) -> Result<i32, String> {
    let arch = arch_of(args);
    let state_root = crate::invocation::ambient_var_os("BUILDUTIL_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".buildutil"));
    let build_host = build_host_of(args)?;
    let spec = crate::spec::load(root, &arch, build_host.triple())?;
    let configuration = spec
        .configuration
        .as_ref()
        .ok_or("no [configuration] table names the option graph")?;
    let config = crate::state::config_file(&state_root, &arch);
    if !config.is_file() {
        return Err(format!(
            "no configuration for `{arch}` at {} — run `buildutil setup --arch {arch}`",
            config.display()
        ));
    }
    let lease = crate::term::handover();
    let result = crate::config::run(&[
        "menuconfig".to_string(),
        "--graph".to_string(),
        root.join(&configuration.graph)
            .to_string_lossy()
            .into_owned(),
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
    ]);
    drop(lease);
    result
}

/// `buildutil gdb [--arch <a>]` — attach to the QEMU gdb server with the
/// kernel symbols from the store.
pub fn cmd_gdb(args: &Args) -> Result<i32, String> {
    let root = repo_root()?;
    let config = launch::Launch::load(&root)?;
    let arch = &args.arch;
    let state_root = super::state_root_from_repo(args, &root);
    let build_command = format!(
        "buildutil build {} --arch {}",
        config.gdb.build_target, arch
    );
    let entry = read_root_path(
        &state_root,
        &format!("latest-{}-{}", config.gdb.build_target, arch),
        &format!("gdb: kernel root missing — run `{build_command}`"),
    )?;
    let symbol_file = entry.join(&config.gdb.symbol_file);
    if !symbol_file.is_file() {
        return Err(format!(
            "gdb: symbols missing at {} — produce them with `{build_command}`",
            symbol_file.display()
        ));
    }
    sh_terminal(
        &root,
        &config.gdb.program,
        &[
            "-ex".to_string(),
            format!("target remote {}", config.gdb.remote),
            "-ex".to_string(),
            format!("symbol-file {}", symbol_file.display()),
        ],
    )
}

/// `buildutil fmt [--check]` — the declared formatter module.
pub fn cmd_fmt(args: &Args) -> Result<i32, String> {
    super::app::format(args, &repo_root()?)
}

/// `buildutil check [<check>...]` — declared checks resolve through `[checks]`
/// and pass exactly when their derivations build; `license`, `conformance`,
/// `plan-parity`, `daemon-parity` and `daemon-races` are built-in checks run
/// by name, each by itself. Bare `buildutil check` runs the `[checks]` group
/// `default` and the `license` check. A built-in check's own options — the
/// license check's `--fix` and `--root <dir>`, the conformance check's
/// `--bless` — may stand anywhere and apply only where their check runs.
pub fn cmd_check(
    parsed: &Args,
    build: impl Fn(&[String]) -> Result<i32, String>,
) -> Result<i32, String> {
    use crate::spec::kinds::{BUILTIN_CHECKS, Scope};
    let root = repo_root()?;
    let logger = Logger::new(parsed.verbose);
    let words = super::check_words(parsed)?;
    let first = words.checks.first().map(String::as_str);
    if let Some(option) = words.license.first()
        && !matches!(first, None | Some("license"))
    {
        return Err(format!(
            "check: `{option}` is an option of the license check; use it with `buildutil check license` or a bare `buildutil check`"
        ));
    }
    if words.bless && first != Some("conformance") {
        return Err("check: `--bless` is an option of `buildutil check conformance`".to_string());
    }
    let rest = words.checks.get(1..).unwrap_or(&[]);
    // A built-in check runs by itself; only the parity checks take words,
    // the targets they evaluate.
    let alone = |name: &str| match rest.first() {
        Some(extra) => Err(format!(
            "check: `{name}` runs by itself; `{extra}` is not one of its arguments"
        )),
        None => Ok(()),
    };
    match first {
        Some("license") => {
            alone("license")?;
            let state_root = super::state_root_from_repo(parsed, &root);
            crate::license::run(&words.license, &parsed.arch, &state_root, build)
        }
        Some("conformance") => {
            alone("conformance")?;
            logger.info("check", "Running conformance suite");
            run(&root, words.bless, &logger)
        }
        Some("plan-parity") => cmd_check_plan_parity(&root, parsed, rest),
        Some("daemon-parity") => cmd_check_daemon_parity(&root, parsed, rest),
        Some("daemon-races") => cmd_check_daemon_races(&root, parsed, rest),
        Some(_) => {
            if let Some(builtin) = rest
                .iter()
                .find(|word| BUILTIN_CHECKS.contains(&word.as_str()))
            {
                return Err(format!(
                    "check: `{builtin}` is a built-in check; run it by itself"
                ));
            }
            // Declared checks: ordinary derivations realized by the engine,
            // including their tool providers and required-check edges.
            let mut checks = parsed.clone();
            checks.scope = Some(Scope::Checks);
            checks.targets = words.checks.clone();
            super::build::cmd_build(&checks)
        }
        None => {
            // The license check takes the options; the default group's
            // request carries none of them.
            let state_root = super::state_root_from_repo(parsed, &root);
            let license = crate::license::run(&words.license, &parsed.arch, &state_root, build)?;
            let checks = super::engine::request(&super::bare_check_request(parsed), parsed)?;
            Ok(if checks != 0 { checks } else { license })
        }
    }
}

/// The state root the built-in checks' own commands name, absolute.
fn check_state_root(root: &Path, parsed: &Args) -> PathBuf {
    crate::state::absolute_root(root, &super::state_root_from_repo(parsed, root))
}

fn cmd_check_plan_parity(root: &Path, parsed: &Args, words: &[String]) -> Result<i32, String> {
    let state_root = check_state_root(root, parsed);
    let arch = parsed.arch.clone();
    let build_host = crate::host::BuildHost::resolve(&parsed.build_host)?;
    let backend = crate::host::ExecBackend::resolve(&parsed.backend)?;
    let targets = plan_parity_targets(words);
    let host_plan_args =
        plan_command_args(parsed, &targets, &arch, build_host.triple(), &state_root);
    let host = run_plan_command(&host_plan_args, false)?;
    // The executor carries no git: the repository identity its evaluation
    // records is the one the host plan records.
    let host_plan = {
        let _plan_lease = crate::state::lock_plan(&state_root, &host.0)?;
        crate::eval::plan::load_attested(Path::new(&host.1), &host.0)?
    };
    let git_identity = format!("{} {}", host_plan.git_rev, host_plan.git_dirty);

    let tmp_dir = state_root.join("tmp");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("cannot create {}: {}", tmp_dir.display(), e))?;
    let out_name = format!("plan-parity-container-{}.out", std::process::id());
    let host_out = tmp_dir.join(&out_name);
    let _ = std::fs::remove_file(&host_out);
    let container_out = Path::new("/buildutil-state").join("tmp").join(&out_name);
    let mut inner_args = plan_command_args(
        parsed,
        &targets,
        &arch,
        build_host.triple(),
        Path::new("/buildutil-state"),
    );
    inner_args.push("--backend".to_string());
    inner_args.push(crate::host::ExecBackend::LocalLinux.as_str().to_string());
    // The container's own process evaluates: the attestation is in its
    // environment, and a daemon socket under the shared state root is the
    // host's.
    inner_args.push("--no-daemon".to_string());
    let spec = crate::spec::load(root, &arch, build_host.triple())?;
    let code = crate::host::container::run_plan_parity_in_container(
        root,
        &state_root,
        &build_host,
        &backend,
        spec.executor_image.as_ref(),
        &git_identity,
        &inner_args,
        &container_out,
    )?;
    if code != 0 {
        return Ok(code);
    }
    let container_text = std::fs::read_to_string(&host_out).map_err(|e| {
        format!(
            "cannot read container plan output {}: {}",
            host_out.display(),
            e
        )
    })?;
    let container = parse_plan_output(&container_text)?;
    let _ = std::fs::remove_file(&host_out);
    if host.0 == container.0 {
        crate::log::success("check", &format!("plan parity holds ({})", host.0));
        Ok(0)
    } else {
        crate::log::error("check", "plan parity mismatch");
        say!("  host      : {} {}", host.0, host.1);
        say!("  container : {} {}", container.0, container.1);
        Ok(1)
    }
}

/// A source-directory edit used only while this check owns the file.  The
/// `tools/buildutil` derivation declares its whole source directory, so these
/// exact create/replace/remove operations are observable plan inputs without
/// changing any user-owned source file.
#[cfg(any(target_os = "macos", target_os = "linux"))]
struct DaemonParityEdit {
    path: PathBuf,
    exists: bool,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl DaemonParityEdit {
    fn remove_stale(root: &Path) -> Result<(), String> {
        let source_dir = root.join("tools/buildutil");
        for entry in std::fs::read_dir(&source_dir)
            .map_err(|e| format!("cannot scan {}: {e}", source_dir.display()))?
        {
            let entry = entry.map_err(|e| format!("cannot scan {}: {e}", source_dir.display()))?;
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".daemon-parity-")
            {
                continue;
            }
            std::fs::remove_file(entry.path()).map_err(|e| {
                format!(
                    "cannot remove stale daemon parity edit {}: {e}",
                    entry.path().display()
                )
            })?;
        }
        Ok(())
    }

    fn new(root: &Path) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self {
            path: root
                .join("tools/buildutil")
                .join(format!(".daemon-parity-{}-{nonce}", std::process::id())),
            exists: false,
        }
    }

    fn interrupt_cleanup(&self) -> Box<dyn FnMut() + Send> {
        let path = self.path.clone();
        Box::new(move || {
            let _ = std::fs::remove_file(&path);
        })
    }

    fn set(&mut self, bytes: Option<&[u8]>) -> Result<(), String> {
        match (self.exists, bytes) {
            (false, Some(bytes)) => {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&self.path)
                    .map_err(|e| {
                        format!(
                            "cannot create daemon parity edit {}: {e}",
                            self.path.display()
                        )
                    })?;
                self.exists = true;
                file.write_all(bytes).map_err(|e| {
                    format!(
                        "cannot write daemon parity edit {}: {e}",
                        self.path.display()
                    )
                })?;
                file.sync_all().map_err(|e| {
                    format!(
                        "cannot sync daemon parity edit {}: {e}",
                        self.path.display()
                    )
                })?;
            }
            (true, Some(bytes)) => {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&self.path)
                    .map_err(|e| {
                        format!(
                            "cannot replace daemon parity edit {}: {e}",
                            self.path.display()
                        )
                    })?;
                file.write_all(bytes).map_err(|e| {
                    format!(
                        "cannot write daemon parity edit {}: {e}",
                        self.path.display()
                    )
                })?;
                file.sync_all().map_err(|e| {
                    format!(
                        "cannot sync daemon parity edit {}: {e}",
                        self.path.display()
                    )
                })?;
            }
            (true, None) => {
                std::fs::remove_file(&self.path).map_err(|e| {
                    format!(
                        "cannot remove daemon parity edit {}: {e}",
                        self.path.display()
                    )
                })?;
                self.exists = false;
            }
            (false, None) => {}
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Drop for DaemonParityEdit {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        self.exists = false;
    }
}

fn cmd_check_daemon_parity(root: &Path, parsed: &Args, words: &[String]) -> Result<i32, String> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (root, parsed, words);
        return Err("check daemon-parity requires the Unix daemon client".to_string());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        DaemonParityEdit::remove_stale(root)?;
        let state_root = check_state_root(root, parsed);
        let build_host = crate::host::BuildHost::resolve(&parsed.build_host)?;
        let targets = plan_parity_targets(words);
        let plan_args = plan_command_args(
            parsed,
            &targets,
            &parsed.arch,
            build_host.triple(),
            &state_root,
        );
        let interrupt_guard = InterruptGuard::install();
        let mut edit = DaemonParityEdit::new(root);
        let cases: [(&str, Option<&[u8]>); 4] = [
            ("absent", None),
            ("created", Some(b"daemon parity source: first\n")),
            ("replaced", Some(b"daemon parity source: second\n")),
            ("removed", None),
        ];
        let mut baseline = None;

        for (name, bytes) in cases {
            if interrupt_guard.was_interrupted() {
                return Err("check daemon-parity interrupted".to_string());
            }
            edit.set(bytes)?;
            let daemon =
                run_plan_command_interruptible(&plan_args, false, edit.interrupt_cleanup())?;
            let no_daemon =
                run_plan_command_interruptible(&plan_args, true, edit.interrupt_cleanup())?;
            if daemon.0 != no_daemon.0 {
                crate::log::error("check", &format!("daemon parity: {name} mismatch"));
                say!("  daemon    : {} {}", daemon.0, daemon.1);
                say!("  no-daemon : {} {}", no_daemon.0, no_daemon.1);
                return Ok(1);
            }

            match name {
                "absent" => baseline = Some(daemon.0.clone()),
                "created" | "replaced" => {
                    if baseline.as_ref() == Some(&daemon.0) {
                        crate::log::error(
                            "check",
                            &format!("daemon parity: the {name} edit did not change the plan hash"),
                        );
                        return Ok(1);
                    }
                }
                "removed" if baseline.as_ref() != Some(&daemon.0) => {
                    crate::log::error(
                        "check",
                        "daemon parity: removing the edit did not restore the baseline hash",
                    );
                    return Ok(1);
                }
                _ => {}
            }
        }

        crate::log::success(
            "check",
            "daemon parity holds (create/replace/remove edit matrix)",
        );
        Ok(0)
    }
}

fn cmd_check_daemon_races(root: &Path, parsed: &Args, words: &[String]) -> Result<i32, String> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (root, parsed, words);
        return Err("check daemon-races requires the Unix daemon client".to_string());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if cmd_check_daemon_parity(root, parsed, words)? != 0 {
            return Ok(1);
        }
        let state_root = check_state_root(root, parsed);
        let build_host = crate::host::BuildHost::resolve(&parsed.build_host)?;
        let targets = plan_parity_targets(words);
        let plan_args = plan_command_args(
            parsed,
            &targets,
            &parsed.arch,
            build_host.triple(),
            &state_root,
        );
        let mut verify_args = vec!["daemon".to_string(), "verify".to_string()];
        verify_args.extend(plan_args.into_iter().skip(1));
        let code = run_command(&verify_args)?;
        if code == 0 {
            crate::log::success("check", "daemon races: resident and fresh snapshot agree");
        }
        Ok(code)
    }
}

/// The targets a parity check evaluates: the words after its name, or the
/// `[packages]` group `default`.
fn plan_parity_targets(words: &[String]) -> Vec<String> {
    if words.is_empty() {
        vec![crate::spec::kinds::DEFAULT_GROUP.to_string()]
    } else {
        words.to_vec()
    }
}

/// The `buildutil plan` invocation a parity check compares, with the
/// invocation's configuration overrides.
fn plan_command_args(
    parsed: &Args,
    targets: &[String],
    arch: &str,
    build_host: &str,
    state_root: &Path,
) -> Vec<String> {
    let mut out = Vec::new();
    out.push("plan".to_string());
    out.extend(targets.iter().cloned());
    out.push("--arch".to_string());
    out.push(arch.to_string());
    out.push("--build-host".to_string());
    out.push(build_host.to_string());
    out.push("--store".to_string());
    out.push(state_root.to_string_lossy().into_owned());
    for (key, value) in &parsed.overrides {
        out.push(format!("-D{key}={value}"));
    }
    out
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_plan_command_interruptible(
    args: &[String],
    no_daemon: bool,
    interrupt_cleanup: Box<dyn FnMut() + Send>,
) -> Result<(String, String), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate running buildutil binary: {}", e))?;
    let mut command = crate::invocation::command(&exe);
    command.args(args);
    if no_daemon {
        command.arg("--no-daemon");
    }
    let interrupt_guard = InterruptGuard::install();
    command
        .stdout(crate::invocation::Io::Piped)
        .stderr(crate::invocation::Io::Piped);
    command.new_process_group();
    let child = command
        .spawn()
        .map_err(|e| format!("cannot run host plan command: {}", e))?;
    let _request_group = crate::platform::register_request_process_group(child.id());
    let interrupt_cleanup = InterruptCleanup::start(child.id(), interrupt_cleanup);
    let output = child
        .wait_with_output()
        .map_err(|e| format!("cannot wait for host plan command: {}", e))?;
    interrupt_cleanup.finish()?;
    if interrupt_guard.was_interrupted() {
        return Err("host plan command interrupted".to_string());
    }
    parse_plan_command_output(output)
}

fn run_plan_command(args: &[String], no_daemon: bool) -> Result<(String, String), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate running buildutil binary: {}", e))?;
    let mut command = crate::invocation::command(&exe);
    command.args(args);
    if no_daemon {
        command.arg("--no-daemon");
    }
    let output = command
        .output()
        .map_err(|e| format!("cannot run host plan command: {}", e))?;
    parse_plan_command_output(output)
}

fn parse_plan_command_output(output: std::process::Output) -> Result<(String, String), String> {
    if !output.status.success() {
        if !output.stderr.is_empty() {
            crate::term::line(String::from_utf8_lossy(&output.stderr).trim_end());
        }
        return Err(format!(
            "host plan command failed with {}",
            output.status.code().unwrap_or(1)
        ));
    }
    parse_plan_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_command(args: &[String]) -> Result<i32, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate running buildutil binary: {}", e))?;
    let output = crate::invocation::command(&exe)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run buildutil command: {}", e))?;
    if !output.status.success() && !output.stderr.is_empty() {
        crate::term::line(String::from_utf8_lossy(&output.stderr).trim_end());
    }
    Ok(output.status.code().unwrap_or(1))
}

fn parse_plan_output(text: &str) -> Result<(String, String), String> {
    let line = text
        .lines()
        .rev()
        .find(|line| {
            let mut parts = line.split_whitespace();
            let Some(hash) = parts.next() else {
                return false;
            };
            let Some(_) = parts.next() else {
                return false;
            };
            hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .ok_or_else(|| format!("plan output did not contain `<hash> <path>`: {text:?}"))?;
    let mut parts = line.split_whitespace();
    let hash = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    Ok((hash, path))
}

fn tc_help_arg(arg: &str) -> bool {
    arg == "help" || arg == "--help" || arg == "-h"
}

fn print_tc_help() {
    say!("Usage: buildutil tc setup [options]");
    say!("Creates the resolved toolchain state directories.");
    say!("Usage: buildutil tc plan [options]");
    say!("");
    say!("Shows the target architecture, Linux build host, execution backend and the");
    say!("state locations a build uses.");
    say!("");
    say!("Options:");
    say!("  --arch <a>           Target architecture (default: x86_64)");
    say!("  --build-host <h>     auto, x86_64-unknown-linux-musl, aarch64-unknown-linux-musl");
    say!("  --backend <b>        auto, local-linux, docker, nerdctl, wsl, remote");
    say!("  --store <dir>        Buildutil state root (default: .buildutil)");
}

/// `buildutil tc setup` creates state directories; `tc plan` reports them. The toolchains
/// themselves are `[packages]` built with `buildutil build`.
pub fn cmd_tc(args: &Args) -> Result<i32, String> {
    let root = repo_root()?;
    let state_root = super::state_root_from_repo(args, &root);
    let arch = args.arch.clone();
    let build_host = crate::host::BuildHost::resolve(&args.build_host)?;
    let backend = crate::host::ExecBackend::resolve(&args.backend)?;
    let positional: Vec<&str> = args.targets.iter().map(String::as_str).collect();
    if positional.iter().any(|p| tc_help_arg(p)) {
        print_tc_help();
        return Ok(0);
    }
    match positional.as_slice() {
        [] => {
            print_tc_help();
            Ok(0)
        }
        ["setup"] => {
            let state_root = crate::state::absolute_root(&root, &state_root);
            for path in [
                crate::state::seed_dir(&state_root, build_host.triple()),
                crate::state::config_root(&state_root, &arch),
                state_root.join("store"),
                crate::state::plans_dir(&state_root),
                crate::state::exec_dir(&state_root),
                crate::state::logs_dir(&state_root),
            ] {
                std::fs::create_dir_all(&path).map_err(|error| {
                    format!("tc setup: cannot create {}: {error}", path.display())
                })?;
            }
            crate::log::success(
                "tc",
                &format!("Created state directories in {}", state_root.display()),
            );
            Ok(0)
        }
        ["plan"] => {
            say!("buildutil tc plan");
            say!("  exec host          : {}", crate::host::exec_host_triple());
            say!("  target arch        : {}", arch);
            say!("  build host         : {}", build_host);
            say!("  execution backend  : {}", backend.as_str());
            if backend.needs_container() {
                say!("  container platform : {}", build_host.container_platform());
                say!("  container mode     : executor image from the pinned seed and stage-0 Rust");
                say!("  state mount        : /buildutil-state:rw");
                say!("  plans dir          : /buildutil-state/plans");
                say!("  exec dir           : /buildutil-state/exec/<bootstrap-hash>");
            }
            say!(
                "  seed dir           : {}",
                crate::state::seed_dir(&state_root, build_host.triple()).display()
            );
            say!(
                "  config file        : {}",
                crate::state::config_file(&state_root, &arch).display()
            );
            say!(
                "  store dir          : {}",
                state_root.join("store").display()
            );
            say!(
                "  log dir            : {}",
                crate::state::logs_dir(&state_root).display()
            );
            Ok(0)
        }
        other => Err(format!(
            "tc: unknown command `{}`; use `tc setup` or `tc plan`",
            other.join(" ")
        )),
    }
}

/// `buildutil bootstrap [--from=N]` — the from-scratch pipeline through the
/// store: the ordered (targets, architecture) steps of the root
/// `[[bootstrap.step]]` list, from step N (counting from 0). Each step
/// resolves its architecture's configuration, then builds its targets. The
/// first step needs the pinned seed on disk: the output of an earlier
/// build of its seed derivation, or of the first-seed recipe.
pub fn cmd_bootstrap(
    args: &[String],
    build: impl Fn(&[String]) -> Result<i32, String>,
) -> Result<i32, String> {
    let root = repo_root()?;
    let logger = Logger::new(args.iter().any(|a| a == "-v"));
    let mut from = 0usize;
    for arg in args {
        if let Some(v) = arg.strip_prefix("--from=") {
            from = v
                .parse()
                .map_err(|_| "bootstrap: --from takes a step number")?;
        }
    }
    let build_host = build_host_of(args)?;
    let backend = backend_of(args)?;
    let state_root = crate::invocation::ambient_var_os("BUILDUTIL_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".buildutil"));
    let first_arch = {
        let table = crate::spec::toml::parse_file(&root.join("buildutil.toml"))?;
        table
            .tables
            .iter()
            .find(|t| t.path.first().map(String::as_str) == Some("bootstrap"))
            .and_then(|t| t.get("arch"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or("bootstrap: buildutil.toml declares no [[bootstrap.step]]")?
    };
    let spec = crate::spec::load(&root, &first_arch, build_host.triple())?;
    if spec.bootstrap_steps.is_empty() {
        return Err("bootstrap: buildutil.toml declares no [[bootstrap.step]]".to_string());
    }
    if from >= spec.bootstrap_steps.len() {
        return Err(format!(
            "bootstrap: --from={from}, but there are {} steps",
            spec.bootstrap_steps.len()
        ));
    }
    if from == 0 {
        let seed = state_root.join(
            &spec
                .executor_image
                .as_ref()
                .ok_or("no [executor-image] table declares the pinned seed")?
                .seed,
        );
        if !seed.is_file() {
            return Err(format!(
                "bootstrap: the pinned seed is missing at {} — place the output of \
                 its seed derivation or of the first-seed recipe there",
                seed.display()
            ));
        }
    }
    let total = spec.bootstrap_steps.len();
    for (index, step) in spec.bootstrap_steps.iter().enumerate().skip(from) {
        logger.info(
            "bootstrap",
            &format!(
                "Bootstrap step {index} of {total}: {} for {}",
                step.targets.join(", "),
                step.arch
            ),
        );
        // The configuration resolves at the start of every evaluation.
        let code = cmd_setup(&["--arch".to_string(), step.arch.clone()])?;
        if code != 0 {
            return Ok(code);
        }
        let mut build_args = step.targets.clone();
        build_args.extend(["--arch".to_string(), step.arch.clone()]);
        append_build_host_backend(&mut build_args, &build_host, &backend);
        let code = build(&build_args)?;
        if code != 0 {
            return Ok(code);
        }
    }
    logger.success("bootstrap", "Bootstrap complete");
    Ok(0)
}
