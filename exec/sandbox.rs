//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — sandboxed builder execution
//!
//! `SandboxExec` is the seam between the engine and platform isolation, with
//! a grade ladder (`caps` > `namespace` > `audit`) keyed to trust:
//!
//! - **`AuditSandbox`** (the self-tool class, on every host): the
//!   environment (built from empty; PATH is a private toolbin of declared
//!   tools), working directory, and output location are ENFORCED;
//!   filesystem reads are AUDITED post-hoc via depfiles; network/randomness
//!   are trusted. Its realizations are never signed or substituted. A
//!   non-Linux host realizes nothing else.
//! - **`NamespaceSandbox`** (Linux): an unprivileged user + mount + PID +
//!   network namespace, entered by re-executing this buildutil binary as an
//!   internal `__sandbox` helper. The build sees a fresh tmpfs root holding
//!   only the build dir (read-write), the declared input providers and tool
//!   trees (read-only), `/proc`, and minimal `/dev`; no host tree is
//!   exposed. Network is loopback alone except for fixed-output derivations.
//!   The stage environment contributes `/bin/sh`, read-only mounts at fixed
//!   paths (the dynamic loader and libc at `/lib`, trust anchors) and, where
//!   a derivation declares `system-features = ["kvm"]` and the worker grants
//!   it, `/dev/kvm`. `allowed_read` / `net` are the enforcing interface.
//! - **`caps`** (SaltyOS): hermeticity by the absence of ambient authority.
//!
//! The enforcing sandbox is genuinely Linux-only, so all of it — the
//! `NamespaceSandbox`, the mount-plan computation, the plan serialization,
//! and their tests — is `#[cfg(target_os = "linux")]`. Nothing here is
//! `#[allow(dead_code)]`: a construct that a platform does not use is simply
//! not compiled for it.

use crate::invocation::{Cmd, Io};
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
use std::io::Read;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::Mutex;

/// The constant path the per-build directory is mounted at inside the
/// namespace sandbox. Every enforcing build runs under `/build` regardless of
/// where its hash-named build dir lives on the host, so compilers embed
/// `/build/...` — reproducible and location-independent — with no per-tool
/// path remapping (the Nix `sandbox-build-dir` approach). Because the remap
/// target is byte-identical across runs and machines, a `/build/stage/dep/…`
/// path in an output is NOT a leak: a build tool that only ever executes
/// inside a sandbox (a compiler wrapper naming its staged sysroot, say) may
/// embed it. The reference scanner's build-private needle is the per-run
/// host build dir alone (`realize::scan_references`). Ungated: exec-token
/// expansion names this remap target from every platform that emits argv
/// destined for a namespace-grade builder.
pub const SANDBOX_BUILD: &str = "/build";

/// Network policy for a build (enforced only at namespace grade).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetPolicy {
    Deny,
    /// Fixed-output derivations only — the output is verified against a
    /// declared content hash, so the network cannot perturb identity.
    Allow,
}

pub struct BuildPlan {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    /// Root of the staged inputs (`<build-dir>/stage`). The build dir (its
    /// parent) is the only writable surface bound into the namespace.
    #[cfg(target_os = "linux")]
    pub stage_root: PathBuf,
    /// Read roots bound read-only at namespace grade: dependency provider
    /// dirs and toolchain payload trees.
    #[cfg(target_os = "linux")]
    pub allowed_read: Vec<PathBuf>,
    /// Denied except for fixed-output derivations.
    #[cfg(target_os = "linux")]
    pub net: NetPolicy,
    /// The jobserver FIFO, bound read-write so a sandboxed inner tool can
    /// join the shared job pool. `None` for a serial build.
    #[cfg(target_os = "linux")]
    pub jobserver_fifo: Option<PathBuf>,
    /// The POSIX shell to expose at the well-known `/bin/sh` inside the
    /// sandbox (its binary + closure are already in `allowed_read`). Builders
    /// whose inner tools spawn `/bin/sh -c` — script-dag's ninja — need it;
    /// `None` leaves the sandbox without a `/bin/sh`.
    #[cfg(target_os = "linux")]
    pub shell: Option<PathBuf>,
    /// Provider directories bound read-only at fixed paths in the private
    /// root: (target path, host source), from the stage environment.
    #[cfg(target_os = "linux")]
    pub mounts: Vec<(PathBuf, PathBuf)>,
    /// Paths inside the build dir remounted read-only: a dev build's staged
    /// source views.
    #[cfg(target_os = "linux")]
    pub readonly: Vec<PathBuf>,
    /// Host device nodes passed into `/dev` (`/dev/kvm` when granted).
    #[cfg(target_os = "linux")]
    pub devices: Vec<PathBuf>,
}

pub struct ExecResult {
    pub status: ExitStatus,
    pub log: String,
}

/// Which of a builder's standard streams a chunk of output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout = 0,
    Stderr = 1,
}

impl OutputStream {
    pub fn as_str(self) -> &'static str {
        match self {
            OutputStream::Stdout => "stdout",
            OutputStream::Stderr => "stderr",
        }
    }
}

/// Receives builder output as it arrives, tagged with its stream.
pub type OutputSink<'a> = dyn Fn(OutputStream, &[u8]) + Sync + 'a;

pub trait SandboxExec: Sync {
    /// The grade recorded in store metadata (`audit` | `namespace` | `caps`).
    fn grade(&self) -> &'static str;
    fn run(&self, plan: &BuildPlan, output: Option<&OutputSink<'_>>) -> Result<ExecResult, String>;
}

/// The directories of each ambient tool's installation that hold
/// executables: the directory its path names, the directory it resolves to,
/// and the `bin`, `sbin` and `libexec` beside a conventional `bin`.
#[cfg(any(target_os = "linux", test))]
fn ambient_tool_dirs(tool_paths: &[PathBuf]) -> Result<BTreeSet<PathBuf>, String> {
    let mut dirs = BTreeSet::new();
    for path in tool_paths {
        if !path.is_absolute() {
            return Err(format!(
                "ambient tool path is not absolute: {}",
                path.display()
            ));
        }
        let resolved = std::fs::canonicalize(path)
            .map_err(|e| format!("cannot resolve ambient tool {}: {e}", path.display()))?;
        if !resolved.is_file() {
            return Err(format!(
                "ambient tool is not a file: {}",
                resolved.display()
            ));
        }
        // A dispatcher symlink's own directory, and the real tool's.
        if let Some(parent) = path.parent() {
            dirs.insert(parent.to_path_buf());
        }
        let parent = resolved.parent().map(Path::to_path_buf).ok_or_else(|| {
            format!(
                "ambient tool has no installation directory: {}",
                resolved.display()
            )
        })?;
        let conventional_bin = parent
            .file_name()
            .is_some_and(|name| matches!(name.to_str(), Some("bin" | "sbin" | "libexec")));
        let prefix = if conventional_bin {
            parent.parent().unwrap_or(&parent).to_path_buf()
        } else {
            parent.clone()
        };
        dirs.insert(parent);
        for rel in ["bin", "sbin", "libexec"] {
            let dir = prefix.join(rel);
            if dir.is_dir() {
                dirs.insert(dir);
            }
        }
    }
    Ok(dirs)
}

#[cfg(any(target_os = "linux", test))]
fn compiler_program_dirs(compiler: &Path, search: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let output = crate::invocation::isolated(compiler)
        .arg("-print-search-dirs")
        .env_clear()
        .output()
        .map_err(|e| {
            format!(
                "cannot query ambient compiler search dirs from {}: {e}",
                compiler.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "ambient compiler {} -print-search-dirs failed: {}",
            compiler.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let programs = stdout
        .lines()
        .find_map(|line| line.strip_prefix("programs: ="))
        .ok_or_else(|| {
            format!(
                "ambient compiler {} did not report a programs search path",
                compiler.display()
            )
        })?;
    for dir in std::env::split_paths(programs) {
        if dir.is_dir() {
            let resolved = std::fs::canonicalize(&dir).map_err(|e| {
                format!(
                    "cannot resolve ambient compiler program dir {}: {e}",
                    dir.display()
                )
            })?;
            search.insert(resolved);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn compiler_helper(
    compiler: &Path,
    helper: &str,
    search: &BTreeSet<PathBuf>,
) -> Result<PathBuf, String> {
    let output = crate::invocation::isolated(compiler)
        .arg(format!("-print-prog-name={helper}"))
        .env_clear()
        .output()
        .map_err(|e| {
            format!(
                "cannot query ambient compiler helper `{helper}` from {}: {e}",
                compiler.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "ambient compiler {} could not resolve helper `{helper}`: {}",
            compiler.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let reported = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let resolved = if reported.is_absolute() && reported.is_file() {
        Some(reported.clone())
    } else {
        search
            .iter()
            .map(|dir| dir.join(&reported))
            .find(|candidate| candidate.is_file())
    }
    .ok_or_else(|| {
        format!(
            "ambient compiler {} reported helper `{helper}` as `{}`, but it was not found in [{}]",
            compiler.display(),
            reported.display(),
            search
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    std::fs::canonicalize(&resolved).map_err(|e| {
        format!(
            "cannot resolve ambient compiler helper {}: {e}",
            resolved.display()
        )
    })
}

/// The directories a self-tool's ambient executables need on PATH beside
/// its private toolbin, on a Linux host: each tool's installation
/// directories, and for the C compiler its program search path and the
/// directories of the linker and assembler it runs. A Linux C compiler may
/// name those helpers bare and find them through PATH. The audit grade runs
/// these tools unconfined, so nothing here is a read allowance.
#[cfg(any(target_os = "linux", test))]
pub fn ambient_program_dirs(tools: &[(String, PathBuf)]) -> Result<Vec<PathBuf>, String> {
    let paths: Vec<PathBuf> = tools.iter().map(|(_, path)| path.clone()).collect();
    let mut dirs = ambient_tool_dirs(&paths)?;
    for (name, compiler) in tools {
        if name != "cc" {
            continue;
        }
        compiler_program_dirs(compiler, &mut dirs)?;
        for helper in ["ld", "as"] {
            let helper = compiler_helper(compiler, helper, &dirs)?;
            if let Some(parent) = helper.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
    }
    Ok(dirs.into_iter().collect())
}

/// The audit grade: environment/cwd/output enforcement and post-hoc read
/// auditing. The self-tool class runs here on every host, because its
/// ambient compiler cannot be held to declared inputs; nothing outside the
/// class does.
pub struct AuditSandbox;

impl SandboxExec for AuditSandbox {
    fn grade(&self) -> &'static str {
        "audit"
    }

    fn run(&self, plan: &BuildPlan, output: Option<&OutputSink<'_>>) -> Result<ExecResult, String> {
        let (program, args) = plan
            .argv
            .split_first()
            .ok_or_else(|| "empty argv".to_string())?;
        let mut cmd = crate::invocation::isolated(program);
        cmd.args(args)
            .current_dir(&plan.cwd)
            .env_clear()
            .stdin(Io::Null)
            .stdout(Io::Piped)
            .stderr(Io::Piped);
        for (k, v) in &plan.env {
            cmd.env(k, v);
        }
        cmd.new_process_group();
        run_command_capture(&mut cmd, program, output)
    }
}

pub(super) fn run_command_capture(
    cmd: &mut Cmd,
    program: &str,
    output: Option<&OutputSink<'_>>,
) -> Result<ExecResult, String> {
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot exec `{}`: {}", program, e))?;
    let _request_group = crate::platform::register_request_process_group(child.id());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("cannot capture stdout for `{}`", program))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("cannot capture stderr for `{}`", program))?;
    // One log for both streams, appended in arrival order, so the retained
    // log reads like the terminal would have shown it. Each stream appends
    // only up to its last line feed or carriage return: a chunk boundary can
    // split an escape sequence or a UTF-8 character, neither of which
    // contains those bytes, and the other stream's bytes must not land inside
    // it. A carriage-return progress display keeps the held part bounded.
    let log = Mutex::new(Vec::new());

    fn drain<R: Read>(
        mut reader: R,
        stream: OutputStream,
        log: &Mutex<Vec<u8>>,
        output: Option<&OutputSink<'_>>,
    ) -> Result<(), String> {
        let mut buf = [0u8; 8192];
        let mut pending = Vec::new();
        loop {
            let n = match reader.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    if let Ok(mut log) = log.lock() {
                        log.extend_from_slice(&pending);
                    }
                    return Err(format!("cannot read builder output: {}", e));
                }
            };
            if n == 0 {
                if !pending.is_empty() {
                    log.lock()
                        .map_err(|_| "builder log lock poisoned".to_string())?
                        .extend_from_slice(&pending);
                }
                return Ok(());
            }
            pending.extend_from_slice(&buf[..n]);
            if let Some(end) = pending.iter().rposition(|&b| b == b'\n' || b == b'\r') {
                log.lock()
                    .map_err(|_| "builder log lock poisoned".to_string())?
                    .extend(pending.drain(..=end));
            }
            if let Some(output) = output {
                output(stream, &buf[..n]);
            }
        }
    }

    let status = std::thread::scope(|scope| {
        let stdout_thread = scope.spawn(|| drain(stdout, OutputStream::Stdout, &log, output));
        let stderr_thread = scope.spawn(|| drain(stderr, OutputStream::Stderr, &log, output));
        let status = child
            .wait()
            .map_err(|e| format!("cannot wait for `{}`: {}", program, e))?;
        stdout_thread
            .join()
            .map_err(|_| "stdout reader panicked".to_string())??;
        stderr_thread
            .join()
            .map_err(|_| "stderr reader panicked".to_string())??;
        Ok::<ExitStatus, String>(status)
    })?;
    let log = log
        .into_inner()
        .map_err(|_| "builder log lock poisoned".to_string())?;
    Ok(ExecResult {
        status,
        log: String::from_utf8_lossy(&log).into_owned(),
    })
}

/// Pick the platform implementation. Linux enforces via namespaces; every
/// other host has only the audit grade, and realizes only self-tools.
pub fn platform_sandbox() -> Box<dyn SandboxExec> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::NamespaceSandbox)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(AuditSandbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_exec_streams_output_while_preserving_log_order() {
        // A bare ambient `/bin/sh` is not hermetic: inside the Linux
        // namespace sandbox that runs this derivation, only declared inputs
        // are mounted, so the shell must come from the test derivation's
        // own declared seed dependency, which its builder passes as
        // `BUILDUTIL_CONTRACT_SEED`. The seed's tools are static.
        let seed = PathBuf::from(
            std::env::var_os("BUILDUTIL_CONTRACT_SEED")
                .expect("run the declared test-buildutil derivation to supply its seed"),
        );
        let sh = seed.join("bin/sh");
        let cwd = std::env::temp_dir();
        let plan = BuildPlan {
            argv: vec![
                sh.to_string_lossy().into_owned(),
                "-c".to_string(),
                "printf '[1/2] out\\n'; printf '[2/2] err\\n' >&2".to_string(),
            ],
            env: Vec::new(),
            cwd,
            #[cfg(target_os = "linux")]
            stage_root: std::env::temp_dir(),
            #[cfg(target_os = "linux")]
            allowed_read: Vec::new(),
            #[cfg(target_os = "linux")]
            net: NetPolicy::Deny,
            #[cfg(target_os = "linux")]
            jobserver_fifo: None,
            #[cfg(target_os = "linux")]
            shell: None,
            #[cfg(target_os = "linux")]
            mounts: Vec::new(),
            #[cfg(target_os = "linux")]
            readonly: Vec::new(),
            #[cfg(target_os = "linux")]
            devices: Vec::new(),
        };
        let streamed = Mutex::new(Vec::new());
        let sink = |stream: OutputStream, bytes: &[u8]| {
            streamed
                .lock()
                .expect("stream lock")
                .push((stream, String::from_utf8_lossy(bytes).into_owned()));
        };

        let result = AuditSandbox.run(&plan, Some(&sink)).expect("audit run");

        assert!(result.status.success());
        // Two pipes read by two threads fix no order across streams; the
        // log holds both lines, each whole.
        assert!(result.log.contains("[1/2] out\n"), "{}", result.log);
        assert!(result.log.contains("[2/2] err\n"), "{}", result.log);
        let streamed = streamed.into_inner().expect("stream lock");
        let joined = |want: OutputStream| {
            streamed
                .iter()
                .filter(|(s, _)| *s == want)
                .map(|(_, text)| text.as_str())
                .collect::<String>()
        };
        assert_eq!(joined(OutputStream::Stdout), "[1/2] out\n");
        assert_eq!(joined(OutputStream::Stderr), "[2/2] err\n");
    }

    #[test]
    fn ambient_tool_dirs_cover_the_installation() {
        let fixture =
            std::env::temp_dir().join(format!(
                "buildutil-ambient-tool-dirs-{}",
                std::process::id()
            ));
        let prefix = fixture.join("toolchain");
        let tool = prefix.join("bin/rustc");
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(tool.parent().unwrap()).unwrap();
        std::fs::create_dir_all(prefix.join("libexec")).unwrap();
        std::fs::write(&tool, b"tool").unwrap();

        let dirs = ambient_tool_dirs(std::slice::from_ref(&tool)).unwrap();
        let real = std::fs::canonicalize(&prefix).unwrap();
        assert!(dirs.contains(tool.parent().unwrap()));
        assert!(dirs.contains(&real.join("bin")));
        assert!(dirs.contains(&real.join("libexec")));
        assert!(!dirs.contains(&real.join("sbin")));

        std::fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn no_ambient_tools_add_no_path_entries() {
        assert!(ambient_program_dirs(&[]).unwrap().is_empty());
    }
}

/// Entry point for the `__sandbox <plan-file>` re-exec: enter the namespaces
/// and exec the builder as PID 1. Only meaningful on Linux.
pub fn run_helper(args: &[String]) -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    {
        let plan_file = args
            .first()
            .ok_or_else(|| "__sandbox: missing plan file".to_string())?;
        let text = std::fs::read_to_string(plan_file)
            .map_err(|e| format!("__sandbox: cannot read plan: {}", e))?;
        let plan = linux::parse_plan(&text)?;
        linux::enter_and_exec(plan)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        Err("the namespace sandbox is only available on Linux".to_string())
    }
}

// ---------------------------------------------------------------------------
// Linux enforcing sandbox.

#[cfg(target_os = "linux")]
mod linux {
    use super::{BuildPlan, ExecResult, NetPolicy, OutputSink, SandboxExec};
    use crate::invocation::Io;
    use std::ffi::CString;
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    const CLONE_NEWNS: i32 = 0x0002_0000;
    const CLONE_NEWUSER: i32 = 0x1000_0000;
    const CLONE_NEWPID: i32 = 0x2000_0000;
    const CLONE_NEWNET: i32 = 0x4000_0000;
    const MS_RDONLY: u64 = 1;
    const MS_NOSUID: u64 = 2;
    const MS_NODEV: u64 = 4;
    const MS_NOEXEC: u64 = 8;
    const MS_NOATIME: u64 = 1024;
    const MS_NODIRATIME: u64 = 2048;
    const MS_REMOUNT: u64 = 32;
    const MS_BIND: u64 = 4096;
    const MS_REC: u64 = 16384;
    const MS_RELATIME: u64 = 1 << 21;
    const MS_PRIVATE: u64 = 1 << 18;
    const MNT_DETACH: i32 = 2;

    // SAFETY: standard libc signatures; every pointer is null, a valid
    // NUL-terminated C string or a live `struct ifreq` owned by the caller
    // across the call. musl declares ioctl's request as `int`; both
    // architectures pass it in a register, so this declaration serves both
    // C libraries.
    unsafe extern "C" {
        fn unshare(flags: i32) -> i32;
        fn mount(
            source: *const core::ffi::c_char,
            target: *const core::ffi::c_char,
            fstype: *const core::ffi::c_char,
            flags: u64,
            data: *const core::ffi::c_void,
        ) -> i32;
        fn umount2(target: *const core::ffi::c_char, flags: i32) -> i32;
        fn pivot_root(new_root: *const core::ffi::c_char, put_old: *const core::ffi::c_char)
        -> i32;
        fn getuid() -> u32;
        fn getgid() -> u32;
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn ioctl(fd: i32, request: core::ffi::c_ulong, ...) -> i32;
        fn close(fd: i32) -> i32;
    }

    /// One bind mount into the private root: a host `source` path mounted at
    /// `target` inside the new root, read-only or read-write. Most binds are
    /// identity-mapped (`target == source`); the build dir is the exception —
    /// its hash-named host path maps to the constant `SANDBOX_BUILD` so the
    /// build always runs at `/build`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Bind {
        pub source: PathBuf,
        pub target: PathBuf,
        pub readonly: bool,
    }

    /// The bind set: the build dir read-write (the only writable surface —
    /// stage, out, home, tmp, toolbin all live under it), and every declared
    /// read root read-only. The enforcing read set is exactly this list, so an
    /// undeclared path is simply absent from the new root and access to it
    /// fails closed.
    pub fn bind_plan(
        build_dir: &Path,
        allowed_read: &[PathBuf],
        jobserver_fifo: Option<&Path>,
        net: NetPolicy,
        mounts: &[(PathBuf, PathBuf)],
        readonly: &[PathBuf],
    ) -> Vec<Bind> {
        let mut binds = vec![Bind {
            source: build_dir.to_path_buf(),
            target: PathBuf::from(super::SANDBOX_BUILD),
            readonly: false,
        }];
        // Read-only views inside the writable build dir, bound over it after
        // the build dir itself, at their `/build` location.
        for path in readonly {
            if let Ok(rel) = path.strip_prefix(build_dir) {
                binds.push(Bind {
                    source: path.clone(),
                    target: Path::new(super::SANDBOX_BUILD).join(rel),
                    readonly: true,
                });
            }
        }
        // Read-only binds: dependency providers, per-tool closures, sources.
        // Drop anything under the read-write build dir (already covered) and
        // any ancestor of it (a read-only bind there would shadow the build
        // dir's own out/). Then keep only the *maximal* paths: two entries can
        // nest — a tool binary under its toolchain prefix, a library under a
        // bound directory — and binding a descendant after its ancestor needs
        // a mountpoint created under an already-read-only mount, which fails
        // EROFS. An ancestor bind already exposes everything beneath it.
        let mut ro: Vec<PathBuf> = Vec::new();
        for p in allowed_read {
            if p.starts_with(build_dir) || build_dir.starts_with(p) {
                continue;
            }
            ro.push(p.clone());
        }
        ro.sort();
        ro.dedup();
        for p in &ro {
            if ro.iter().any(|q| q != p && p.starts_with(q)) {
                continue; // nested under another read-only bind
            }
            binds.push(Bind {
                source: p.clone(),
                target: p.clone(),
                readonly: true,
            });
        }
        // A network-allowed build (fixed-output fetch) needs the host's
        // name-resolution surface — the private root has no /etc. Transport
        // configuration, not an identity input: the declared output hash is
        // the trust anchor. Deny-net builds get none of it.
        if net == NetPolicy::Allow {
            for etc in [
                "/etc/resolv.conf",
                "/etc/hosts",
                "/etc/nsswitch.conf",
                "/etc/gai.conf",
            ] {
                let p = PathBuf::from(etc);
                if p.is_file() {
                    binds.push(Bind {
                        source: p.clone(),
                        target: p,
                        readonly: true,
                    });
                }
            }
        }
        // Stage mounts: a provider directory at a fixed path of the private
        // root (the dynamic loader's `/lib`), always read-only.
        for (target, source) in mounts {
            binds.push(Bind {
                source: source.clone(),
                target: target.clone(),
                readonly: true,
            });
        }
        // The jobserver FIFO needs read+write (a client reads a token and
        // writes it back), so it is bound read-write, not into the read set.
        if let Some(fifo) = jobserver_fifo {
            if !fifo.starts_with(build_dir) {
                binds.push(Bind {
                    source: fifo.to_path_buf(),
                    target: fifo.to_path_buf(),
                    readonly: false,
                });
            }
        }
        binds
    }

    /// Serialize a plan for the `__sandbox` helper. One directive per line; the
    /// value is the rest of the line, so argv tokens and env values (which
    /// never contain newlines — validated at spec load) survive verbatim.
    ///
    /// The cwd, argv and env values are rewritten from the host build-dir path
    /// to `SANDBOX_BUILD` (`/build`): the build dir is bind-mounted there, so
    /// the builder runs entirely under `/build` and its outputs embed that
    /// constant path, not the hash-named host location. Each bind is emitted as
    /// `<target>\t<source>` (tab-separated — paths never contain tabs).
    fn serialize_plan(
        newroot: &Path,
        plan: &BuildPlan,
        binds: &[Bind],
        build_dir: &Path,
    ) -> String {
        let bd = build_dir.to_string_lossy();
        let remap = |v: &str| v.replace(&*bd, super::SANDBOX_BUILD);
        let mut s = String::new();
        s.push_str(&format!("newroot {}\n", newroot.display()));
        s.push_str(&format!("cwd {}\n", remap(&plan.cwd.to_string_lossy())));
        s.push_str(&format!(
            "net {}\n",
            if plan.net == NetPolicy::Deny {
                "deny"
            } else {
                "allow"
            }
        ));
        if let Some(shell) = &plan.shell {
            s.push_str(&format!("shell {}\n", shell.display()));
        }
        for device in &plan.devices {
            s.push_str(&format!("device {}\n", device.display()));
        }
        for b in binds {
            s.push_str(&format!(
                "{} {}\t{}\n",
                if b.readonly { "bind-ro" } else { "bind-rw" },
                b.target.display(),
                b.source.display()
            ));
        }
        for (k, v) in &plan.env {
            s.push_str(&format!("env {}={}\n", k, remap(v)));
        }
        for arg in &plan.argv {
            s.push_str(&format!("arg {}\n", remap(arg)));
        }
        s
    }

    /// A parsed `__sandbox` plan.
    pub struct ParsedPlan {
        pub newroot: PathBuf,
        pub cwd: PathBuf,
        pub net_deny: bool,
        pub shell: Option<PathBuf>,
        pub devices: Vec<PathBuf>,
        pub binds: Vec<Bind>,
        pub env: Vec<(String, String)>,
        pub argv: Vec<String>,
    }

    pub fn parse_plan(text: &str) -> Result<ParsedPlan, String> {
        let mut p = ParsedPlan {
            newroot: PathBuf::new(),
            cwd: PathBuf::new(),
            net_deny: true,
            shell: None,
            devices: Vec::new(),
            binds: Vec::new(),
            env: Vec::new(),
            argv: Vec::new(),
        };
        for line in text.lines() {
            let Some((key, val)) = line.split_once(' ') else {
                continue;
            };
            match key {
                "newroot" => p.newroot = PathBuf::from(val),
                "cwd" => p.cwd = PathBuf::from(val),
                "net" => p.net_deny = val == "deny",
                "shell" => p.shell = Some(PathBuf::from(val)),
                "device" => p.devices.push(PathBuf::from(val)),
                "bind-rw" | "bind-ro" => {
                    let (target, source) = val.split_once('\t').unwrap_or((val, val));
                    p.binds.push(Bind {
                        source: PathBuf::from(source),
                        target: PathBuf::from(target),
                        readonly: key == "bind-ro",
                    });
                }
                "env" => {
                    if let Some((k, v)) = val.split_once('=') {
                        p.env.push((k.to_string(), v.to_string()));
                    }
                }
                "arg" => p.argv.push(val.to_string()),
                _ => {}
            }
        }
        if p.argv.is_empty() {
            return Err("sandbox plan has empty argv".to_string());
        }
        Ok(p)
    }

    /// Linux enforcing sandbox: re-exec this binary as `__sandbox <plan>`,
    /// which enters the namespaces and execs the builder, and capture output.
    pub struct NamespaceSandbox;

    impl SandboxExec for NamespaceSandbox {
        fn grade(&self) -> &'static str {
            "namespace"
        }

        fn run(
            &self,
            plan: &BuildPlan,
            output: Option<&OutputSink<'_>>,
        ) -> Result<ExecResult, String> {
            let build_dir = plan
                .stage_root
                .parent()
                .ok_or_else(|| "stage_root has no parent (build dir)".to_string())?;
            let binds = bind_plan(
                build_dir,
                &plan.allowed_read,
                plan.jobserver_fifo.as_deref(),
                plan.net,
                &plan.mounts,
                &plan.readonly,
            );
            let newroot = build_dir.join(".sandbox-root");
            let plan_text = serialize_plan(&newroot, plan, &binds, build_dir);
            let plan_file = build_dir.join(".sandbox-plan");
            std::fs::write(&plan_file, &plan_text)
                .map_err(|e| format!("cannot write sandbox plan: {}", e))?;

            let exe = std::env::current_exe()
                .map_err(|e| format!("cannot find the buildutil binary for re-exec: {}", e))?;
            let exe_name = exe.display().to_string();
            let mut cmd = crate::invocation::isolated(exe);
            cmd.arg("__sandbox")
                .arg(&plan_file)
                .stdin(Io::Null)
                .stdout(Io::Piped)
                .stderr(Io::Piped)
                .new_process_group();
            super::run_command_capture(&mut cmd, &exe_name, output)
        }
    }

    fn cstr(p: &Path) -> Result<CString, String> {
        CString::new(p.as_os_str().as_bytes()).map_err(|_| "path has interior NUL".to_string())
    }

    fn cstr_s(s: &str) -> CString {
        CString::new(s).expect("static string has no NUL")
    }

    fn ck(ret: i32, what: &str) -> Result<(), String> {
        if ret == 0 {
            Ok(())
        } else {
            Err(format!(
                "{} failed: {}",
                what,
                std::io::Error::last_os_error()
            ))
        }
    }

    /// Bring up the loopback interface of the network namespace this process
    /// just entered, which starts with `lo` down.
    fn loopback_up() -> Result<(), String> {
        const AF_INET: i32 = 2;
        const SOCK_DGRAM: i32 = 2;
        const SOCK_CLOEXEC: i32 = 0o2_000_000;
        const SIOCSIFFLAGS: core::ffi::c_ulong = 0x8914;
        const IFF_UP: i16 = 0x1;
        const IFF_LOOPBACK: i16 = 0x8;
        const IFF_RUNNING: i16 = 0x40;

        /// `struct ifreq` with the flags member of its union, which starts
        /// the union: 40 bytes on both architectures.
        #[repr(C)]
        struct IfReq {
            name: [u8; 16],
            flags: i16,
            pad: [u8; 22],
        }

        // SAFETY: socket takes integers only and returns a descriptor or -1.
        let fd = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(format!(
                "cannot open a socket to bring lo up: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut request = IfReq {
            name: [0; 16],
            flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
            pad: [0; 22],
        };
        request.name[..2].copy_from_slice(b"lo");
        // SAFETY: `fd` is the socket opened above, and `request` is a live,
        // correctly laid out `struct ifreq` for the duration of the call.
        let result = unsafe { ioctl(fd, SIOCSIFFLAGS, &mut request as *mut IfReq) };
        let error = std::io::Error::last_os_error();
        // SAFETY: `fd` is owned here and closed exactly once.
        unsafe {
            close(fd);
        }
        if result != 0 {
            return Err(format!("bringing lo up failed: {error}"));
        }
        Ok(())
    }

    /// The lock-down flags (nosuid/nodev/…) the just-created bind at
    /// `target` inherited from its source superblock, read back from
    /// /proc/self/mounts. A read-only remount inside a user namespace may
    /// only ADD restrictions — dropping an inherited flag is EPERM — so the
    /// remount must carry these forward (the bubblewrap/Nix approach).
    /// Exact mount-point match first (the bind IS a mount point), longest
    /// prefix as the fallback; a parse failure degrades to 0, and the
    /// remount then fails loudly if flags were in fact required.
    fn existing_lockdown_flags(target: &Path) -> u64 {
        let Ok(text) = std::fs::read_to_string("/proc/self/mounts") else {
            return 0;
        };
        let want = target.to_string_lossy().into_owned();
        let mut best_len = 0usize;
        let mut flags = 0u64;
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(_src), Some(mnt), Some(_fs), Some(opts)) =
                (it.next(), it.next(), it.next(), it.next())
            else {
                continue;
            };
            // /proc/self/mounts escapes spaces in mount points as \040.
            let mnt = mnt.replace("\\040", " ");
            let matches = mnt == want
                || (want.starts_with(&mnt)
                    && (mnt == "/" || want.as_bytes().get(mnt.len()) == Some(&b'/')));
            if !matches || mnt.len() < best_len {
                continue;
            }
            best_len = mnt.len();
            flags = 0;
            for opt in opts.split(',') {
                flags |= match opt {
                    "nosuid" => MS_NOSUID,
                    "nodev" => MS_NODEV,
                    "noexec" => MS_NOEXEC,
                    "noatime" => MS_NOATIME,
                    "nodiratime" => MS_NODIRATIME,
                    "relatime" => MS_RELATIME,
                    _ => 0,
                };
            }
        }
        flags
    }

    /// Bind-mount `source` at `target`; `ro` needs a follow-up remount because
    /// MS_RDONLY is ignored on the initial bind. The remount preserves the
    /// bind's inherited lock-down flags — inside a user namespace they can
    /// only be added to, never dropped.
    fn bind(source: &Path, target: &Path, ro: bool) -> Result<(), String> {
        let src = cstr(source)?;
        let tgt = cstr(target)?;
        // SAFETY: src/tgt are valid C strings; null fstype/data are valid for
        // a bind mount.
        let r = unsafe {
            mount(
                src.as_ptr(),
                tgt.as_ptr(),
                std::ptr::null(),
                MS_BIND | MS_REC,
                std::ptr::null(),
            )
        };
        ck(r, &format!("bind {}", source.display()))?;
        if ro {
            let keep = existing_lockdown_flags(target);
            // SAFETY: same target; remount applies the read-only flag on top
            // of the inherited lock-down set.
            let r = unsafe {
                mount(
                    std::ptr::null(),
                    tgt.as_ptr(),
                    std::ptr::null(),
                    MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC | keep,
                    std::ptr::null(),
                )
            };
            ck(r, &format!("bind-ro remount {}", target.display()))?;
        }
        Ok(())
    }

    /// Recreate `path` (absolute) under `newroot` as an empty dir or file so a
    /// bind mount has a mount point.
    fn make_target(newroot: &Path, path: &Path, is_dir: bool) -> Result<PathBuf, String> {
        let rel = path.strip_prefix("/").unwrap_or(path);
        let target = newroot.join(rel);
        if is_dir {
            std::fs::create_dir_all(&target).map_err(|e| format!("mkdir target: {}", e))?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir target parent: {}", e))?;
            }
            std::fs::write(&target, b"").map_err(|e| format!("touch target: {}", e))?;
        }
        Ok(target)
    }

    fn exec_builder_error(prog: &str, error: &std::io::Error, binds: &[Bind]) -> String {
        let program = Path::new(prog);
        let exists = program.exists();
        let covering: Vec<String> = binds
            .iter()
            .filter(|bind| program.is_absolute() && program.starts_with(&bind.target))
            .map(|bind| {
                format!(
                    "{} <- {} ({})",
                    bind.target.display(),
                    bind.source.display(),
                    if bind.readonly { "ro" } else { "rw" }
                )
            })
            .collect();
        let coverage = if covering.is_empty() {
            "none".to_string()
        } else {
            covering.join(", ")
        };
        let mount_plan = binds
            .iter()
            .map(|bind| {
                format!(
                    "{} ({})",
                    bind.target.display(),
                    if bind.readonly { "ro" } else { "rw" }
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let enoent_hint = if error.kind() == std::io::ErrorKind::NotFound {
            "; ENOENT can also mean the ELF interpreter named by an existing program is absent"
        } else {
            ""
        };
        format!(
            "cannot exec builder `{prog}` after pivot_root: {error}; \
             program exists inside sandbox={exists}; covering mounts=[{coverage}]; \
             mount plan=[{mount_plan}]{enoent_hint}"
        )
    }

    pub fn enter_and_exec(plan: ParsedPlan) -> Result<i32, String> {
        // SAFETY: getuid/getgid are always safe.
        let uid = unsafe { getuid() };
        let gid = unsafe { getgid() };

        // 1. User namespace, then map container-root to the invoking uid/gid.
        // SAFETY: unshare with a valid flag.
        ck(unsafe { unshare(CLONE_NEWUSER) }, "unshare(NEWUSER)")?;
        std::fs::write("/proc/self/setgroups", "deny").map_err(|e| format!("setgroups: {}", e))?;
        std::fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid))
            .map_err(|e| format!("uid_map: {}", e))?;
        std::fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid))
            .map_err(|e| format!("gid_map: {}", e))?;

        // 2. Mount + PID (+ network unless a fetch) namespaces.
        let mut flags = CLONE_NEWNS | CLONE_NEWPID;
        if plan.net_deny {
            flags |= CLONE_NEWNET;
        }
        // SAFETY: unshare with valid flags.
        ck(unsafe { unshare(flags) }, "unshare(NS|PID[|NET])")?;
        // A fresh network namespace holds only a loopback interface that is
        // down. Bring it up, as Nix's sandbox does, so a build may serve and
        // reach 127.0.0.1 while no other network exists.
        if plan.net_deny {
            loopback_up()?;
        }

        // 3. Private mount propagation, then a fresh tmpfs root.
        let root = cstr_s("/");
        let none = cstr_s("none");
        // SAFETY: valid C strings; MS_PRIVATE|MS_REC on "/".
        ck(
            unsafe {
                mount(
                    none.as_ptr(),
                    root.as_ptr(),
                    std::ptr::null(),
                    MS_PRIVATE | MS_REC,
                    std::ptr::null(),
                )
            },
            "make / private",
        )?;
        std::fs::create_dir_all(&plan.newroot).map_err(|e| format!("mkdir newroot: {}", e))?;
        let newroot_c = cstr(&plan.newroot)?;
        let tmpfs = cstr_s("tmpfs");
        // SAFETY: valid C strings; tmpfs mount at the new root.
        ck(
            unsafe {
                mount(
                    tmpfs.as_ptr(),
                    newroot_c.as_ptr(),
                    tmpfs.as_ptr(),
                    0,
                    std::ptr::null(),
                )
            },
            "mount tmpfs root",
        )?;

        // 4. Bind the build dir (rw) and every declared read root (ro).
        for b in &plan.binds {
            let is_dir = b.source.is_dir();
            let target = make_target(&plan.newroot, &b.target, is_dir)?;
            bind(&b.source, &target, b.readonly)?;
        }

        // 5. Minimal /dev (best effort — a missing controlling tty is normal).
        let dev = plan.newroot.join("dev");
        std::fs::create_dir_all(&dev).map_err(|e| format!("mkdir /dev: {}", e))?;
        for node in ["null", "zero", "full", "random", "urandom", "tty"] {
            let src = Path::new("/dev").join(node);
            if !src.exists() {
                continue;
            }
            let tgt = dev.join(node);
            if std::fs::write(&tgt, b"").is_ok() {
                let _ = bind(&src, &tgt, false);
            }
        }
        // Granted devices must arrive, unlike the best-effort nodes above:
        // the executor already confirmed it can open them.
        for device in &plan.devices {
            let name = device
                .file_name()
                .ok_or_else(|| format!("device {} has no name", device.display()))?;
            let tgt = dev.join(name);
            std::fs::write(&tgt, b"").map_err(|e| format!("mknod target {}: {e}", tgt.display()))?;
            bind(device, &tgt, false)?;
        }
        // 5b. A POSIX shell at the well-known /bin/sh: script-dag's inner
        // ninja spawns `/bin/sh -c` for every rule (an absolute path, not via
        // PATH). The shell binary and its ELF closure are already bound
        // read-only through the read set; expose the shell here at /bin/sh.
        if let Some(shell) = &plan.shell {
            let bindir = plan.newroot.join("bin");
            std::fs::create_dir_all(&bindir).map_err(|e| format!("mkdir /bin: {}", e))?;
            let link = bindir.join("sh");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(shell, &link)
                .map_err(|e| format!("symlink /bin/sh -> {}: {}", shell.display(), e))?;
        }

        std::fs::create_dir_all(plan.newroot.join("proc"))
            .map_err(|e| format!("mkdir /proc: {}", e))?;

        // 6. pivot_root into the new root. The old root (with its proc) stays
        // attached at /.oldroot for now — the pre-exec step below needs a
        // fully visible proc instance still present to mount a fresh proc in
        // this non-initial user namespace, then detaches it.
        let oldroot = plan.newroot.join(".oldroot");
        std::fs::create_dir_all(&oldroot).map_err(|e| format!("mkdir .oldroot: {}", e))?;
        let newroot_c = cstr(&plan.newroot)?;
        let oldroot_c = cstr(&oldroot)?;
        // SAFETY: both are valid C strings naming mounted directories.
        ck(
            unsafe { pivot_root(newroot_c.as_ptr(), oldroot_c.as_ptr()) },
            "pivot_root",
        )?;
        std::env::set_current_dir("/").map_err(|e| format!("chdir /: {}", e))?;

        // 7. Exec the builder as PID 1 (NEWPID was unshared before this fork).
        //    The pre-exec hook mounts a fresh /proc for the new PID namespace
        //    and only then detaches the old root, so a fully visible proc
        //    instance (/.oldroot/proc) is present when the new proc is mounted
        //    — the kernel requires that in a non-initial user namespace.
        let (prog, rest) = plan
            .argv
            .split_first()
            .ok_or_else(|| "empty argv".to_string())?;
        // The builder writes to this process's own stdout and stderr: the
        // pipes the realizing buildutil reads. They are passed explicitly.
        let own = |fd: std::os::fd::BorrowedFd<'_>| {
            fd.try_clone_to_owned()
                .map(|owned| Io::File(std::fs::File::from(owned)))
                .map_err(|e| format!("cannot hand builder its output stream: {}", e))
        };
        {
            use std::io::IsTerminal;
            if std::io::stdout().is_terminal() || std::io::stderr().is_terminal() {
                return Err(
                    "__sandbox is internal to buildutil: its output must be the realizing buildutil's pipes"
                        .to_string(),
                );
            }
        }
        let stdout = own(std::io::stdout().as_fd())?;
        let stderr = own(std::io::stderr().as_fd())?;
        let mut cmd = crate::invocation::isolated(prog);
        cmd.args(rest)
            .current_dir(&plan.cwd)
            .env_clear()
            .stdin(Io::Null)
            .stdout(stdout)
            .stderr(stderr);
        for (k, v) in &plan.env {
            cmd.env(k, v);
        }
        // SAFETY: the closure is async-signal-safe — two syscalls with static
        // C strings, no allocation. It runs in the forked child, which is in
        // the new PID namespace, so the fresh proc reflects that namespace and
        // the mount is permitted (CAP_SYS_ADMIN over the new pid ns's user
        // ns). The old root's proc is still attached at /.oldroot here,
        // satisfying the fs_fully_visible requirement; we detach it only after
        // the new proc is mounted.
        unsafe {
            cmd.pre_exec(|| {
                let src = c"proc";
                let tgt = c"/proc";
                let fs = c"proc";
                let r = mount(src.as_ptr(), tgt.as_ptr(), fs.as_ptr(), 0, std::ptr::null());
                if r != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let old = c"/.oldroot";
                if umount2(old.as_ptr(), MNT_DETACH) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = cmd
            .status()
            .map_err(|e| exec_builder_error(prog, &e, &plan.binds))?;
        Ok(status.code().unwrap_or(1))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bind_plan_build_dir_rw_and_dedup() {
            let build = PathBuf::from("/b/tmp/x.build");
            let reads = vec![
                PathBuf::from("/b/store/dep1"),
                PathBuf::from("/b/tmp/x.build/toolbin"), // inside build dir → skipped
                PathBuf::from("/toolchain/prefix"),
            ];
            let binds = bind_plan(&build, &reads, None, NetPolicy::Deny, &[], &[]);
            // The build dir is the read-write bind, mapped to the constant
            // /build (not its host path).
            assert_eq!(binds[0].source, build);
            assert_eq!(binds[0].target, PathBuf::from("/build"));
            assert!(!binds[0].readonly);
            let ro: Vec<&PathBuf> = binds
                .iter()
                .filter(|b| b.readonly)
                .map(|b| &b.source)
                .collect();
            assert_eq!(
                ro,
                vec![
                    &PathBuf::from("/b/store/dep1"),
                    &PathBuf::from("/toolchain/prefix")
                ]
            );
            // Read-only binds are identity-mapped (target == source).
            assert!(
                binds
                    .iter()
                    .filter(|b| b.readonly)
                    .all(|b| b.source == b.target)
            );
        }

        #[test]
        fn plan_round_trips() {
            // A realistic hash-named build dir (as in production) — the host
            // build-dir path is remapped to /build in cwd/env/argv.
            let bd = "/work/repo/.buildutil/tmp/deadbeefcafe0123-mica-x86_64.build";
            let plan = BuildPlan {
                argv: vec!["/bin/sh".into(), "-c".into(), "echo hi > out".into()],
                env: vec![
                    ("PATH".into(), format!("{bd}/toolbin")),
                    ("K".into(), "v=w".into()),
                ],
                cwd: PathBuf::from(format!("{bd}/stage/build")),
                stage_root: PathBuf::from(format!("{bd}/stage")),
                allowed_read: vec![PathBuf::from("/store/d1")],
                net: NetPolicy::Deny,
                jobserver_fifo: Some(PathBuf::from("/tmp/js/pool.fifo")),
                shell: Some(PathBuf::from("/store/seed/bin/sh")),
                mounts: vec![(PathBuf::from("/lib"), PathBuf::from("/store/seed/lib"))],
                readonly: vec![PathBuf::from(format!("{bd}/stage/kernite"))],
                devices: vec![PathBuf::from("/dev/kvm")],
            };
            let binds = bind_plan(
                Path::new(bd),
                &plan.allowed_read,
                plan.jobserver_fifo.as_deref(),
                plan.net,
                &plan.mounts,
                &plan.readonly,
            );
            let text = serialize_plan(
                Path::new(&format!("{bd}/.sandbox-root")),
                &plan,
                &binds,
                Path::new(bd),
            );
            let parsed = parse_plan(&text).unwrap();
            assert_eq!(parsed.newroot, PathBuf::from(format!("{bd}/.sandbox-root")));
            // cwd and env are remapped from the host build dir to /build.
            assert_eq!(parsed.cwd, PathBuf::from("/build/stage/build"));
            assert!(parsed.net_deny);
            assert_eq!(parsed.shell, plan.shell);
            assert_eq!(parsed.devices, plan.devices);
            // A stage mount binds its provider at the fixed target.
            assert!(parsed.binds.iter().any(|b| b.target == PathBuf::from("/lib")
                && b.source == PathBuf::from("/store/seed/lib")
                && b.readonly));
            // A dev build's source view is read-only at its /build path.
            assert!(parsed.binds.iter().any(|b| b.target
                == PathBuf::from("/build/stage/kernite")
                && b.readonly));
            assert_eq!(parsed.argv, plan.argv); // no build-dir substring, unchanged
            assert!(parsed.env.iter().any(|(k, v)| k == "K" && v == "v=w"));
            assert!(
                parsed
                    .env
                    .iter()
                    .any(|(k, v)| k == "PATH" && v == "/build/toolbin")
            );
            // The build dir binds its host source at the constant target
            // /build, read-write.
            assert!(parsed.binds.iter().any(|b| b.source == PathBuf::from(bd)
                && b.target == PathBuf::from("/build")
                && !b.readonly));
            assert!(
                parsed
                    .binds
                    .iter()
                    .any(|b| b.source == PathBuf::from("/store/d1") && b.readonly)
            );
            // The jobserver FIFO is bound read-write.
            assert!(
                parsed
                    .binds
                    .iter()
                    .any(|b| b.source == PathBuf::from("/tmp/js/pool.fifo") && !b.readonly)
            );
        }

        #[test]
        fn exec_error_names_program_and_mount_coverage() {
            let binds = vec![
                Bind {
                    source: PathBuf::from("/host/rust"),
                    target: PathBuf::from("/toolchain/rust"),
                    readonly: true,
                },
                Bind {
                    source: PathBuf::from("/host/build"),
                    target: PathBuf::from("/build"),
                    readonly: false,
                },
            ];
            let error = std::io::Error::from(std::io::ErrorKind::NotFound);
            let message = exec_builder_error("/toolchain/rust/bin/rustc", &error, &binds);
            assert!(message.contains("`/toolchain/rust/bin/rustc`"));
            assert!(message.contains("/toolchain/rust <- /host/rust (ro)"));
            assert!(message.contains("ELF interpreter"));
        }
    }
}
