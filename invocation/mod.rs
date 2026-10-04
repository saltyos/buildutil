//! SPDX-License-Identifier: GPL-2.0-only
//! Invocation-scoped process inputs shared by the full and bootstrap frontends.
//!
//! Ordinary invocations inherit the launching process. The resident daemon
//! installs one explicit request context, so cwd, ambient values, cancellation,
//! and host-command lookup cannot fall through to the daemon's launch context.
//!
//! Child processes are built with `Cmd`. Its stdio setters accept only `Io`,
//! which has no terminal variant: a stream the caller leaves unset is
//! captured and forwarded through `term`, and the terminal itself is reached
//! only with a `term::TtyLease`. No child can write past the status row.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone)]
pub struct RequestContext {
    pub cwd: PathBuf,
    pub env: BTreeMap<String, OsString>,
    pub cancel: Arc<AtomicBool>,
}

static REQUEST_CONTEXT: OnceLock<Mutex<Option<Arc<RequestContext>>>> = OnceLock::new();

fn request_slot() -> &'static Mutex<Option<Arc<RequestContext>>> {
    REQUEST_CONTEXT.get_or_init(|| Mutex::new(None))
}

pub struct RequestContextGuard;

impl Drop for RequestContextGuard {
    fn drop(&mut self) {
        *request_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

pub fn install_request_context(context: Arc<RequestContext>) -> RequestContextGuard {
    *request_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(context);
    RequestContextGuard
}

pub fn request_context() -> Option<Arc<RequestContext>> {
    request_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

pub fn request_cwd() -> Option<PathBuf> {
    request_context().map(|context| context.cwd.clone())
}

pub fn request_env(name: &str) -> Option<OsString> {
    request_context().and_then(|context| context.env.get(name).cloned())
}

pub fn ambient_var_os(name: &str) -> Option<OsString> {
    match request_context() {
        Some(context) => context.env.get(name).cloned(),
        None => std::env::var_os(name),
    }
}

pub fn ambient_var(name: &str) -> Result<String, std::env::VarError> {
    match ambient_var_os(name) {
        Some(value) => value.into_string().map_err(std::env::VarError::NotUnicode),
        None => Err(std::env::VarError::NotPresent),
    }
}

pub fn request_cancelled() -> bool {
    request_context().is_some_and(|context| context.cancel.load(Ordering::Acquire))
}

fn command_path(program: &OsStr) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.components().count() != 1 {
        return Some(path.to_path_buf());
    }
    let paths = ambient_var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(path);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(target_os = "windows")]
        {
            let candidate = dir.join(format!("{}.exe", path.to_string_lossy()));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Construct a host command under the current invocation's environment.
/// A daemon request resolves PATH itself and starts the child from exactly the
/// allowlisted environment carried on the wire.
pub fn command(program: impl AsRef<OsStr>) -> Cmd {
    let program = program.as_ref();
    let Some(context) = request_context() else {
        return Cmd::wrap(Command::new(program));
    };
    let mut command = match command_path(program) {
        Some(path) => Command::new(path),
        None => Command::new(Path::new("/__buildutil_request_path_missing__").join(program)),
    };
    command.env_clear().envs(context.env.iter());
    Cmd::wrap(command)
}

/// Construct a command that ignores the invocation environment: builders
/// and probes that set their own environment explicitly.
pub fn isolated(program: impl AsRef<OsStr>) -> Cmd {
    Cmd::wrap(Command::new(program))
}

/// Where a child's standard stream goes. There is no terminal variant; see
/// `Cmd::terminal`.
pub enum Io {
    Null,
    Piped,
    /// An open file or descriptor the caller names explicitly.
    #[cfg(target_os = "linux")]
    File(std::fs::File),
}

impl Io {
    fn stdio(self) -> Stdio {
        match self {
            Io::Null => Stdio::null(),
            Io::Piped => Stdio::piped(),
            #[cfg(target_os = "linux")]
            Io::File(file) => Stdio::from(file),
        }
    }
}

/// A child process under construction. Streams left unset are not
/// inherited: stdin reads nothing, and stdout and stderr are captured and
/// forwarded line by line to `term` (stdout as results, stderr as durable
/// lines).
pub struct Cmd {
    inner: Command,
    stdin: bool,
    stdout: bool,
    stderr: bool,
}

impl Cmd {
    fn wrap(inner: Command) -> Cmd {
        Cmd {
            inner,
            stdin: false,
            stdout: false,
            stderr: false,
        }
    }

    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Cmd {
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Cmd
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    pub fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Cmd {
        self.inner.env(key, value);
        self
    }

    pub fn env_clear(&mut self) -> &mut Cmd {
        self.inner.env_clear();
        self
    }

    pub fn current_dir(&mut self, dir: impl AsRef<Path>) -> &mut Cmd {
        self.inner.current_dir(dir);
        self
    }

    pub fn stdin(&mut self, io: Io) -> &mut Cmd {
        self.inner.stdin(io.stdio());
        self.stdin = true;
        self
    }

    pub fn stdout(&mut self, io: Io) -> &mut Cmd {
        self.inner.stdout(io.stdio());
        self.stdout = true;
        self
    }

    pub fn stderr(&mut self, io: Io) -> &mut Cmd {
        self.inner.stderr(io.stdio());
        self.stderr = true;
        self
    }

    /// Give the child the terminal on all three streams, for as long as
    /// `lease` lives.
    pub fn terminal(&mut self, _lease: &crate::term::TtyLease) -> &mut Cmd {
        self.inner
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        self.stdin = true;
        self.stdout = true;
        self.stderr = true;
        self
    }

    /// Start the child in its own process group so it can be torn down as a
    /// unit.
    pub fn new_process_group(&mut self) -> &mut Cmd {
        crate::platform::configure_process_group(&mut self.inner);
        self
    }

    /// # Safety
    ///
    /// The same obligations as `std::os::unix::process::CommandExt::pre_exec`:
    /// `f` runs in the forked child before exec and may only call
    /// async-signal-safe functions.
    #[cfg(target_os = "linux")]
    pub unsafe fn pre_exec<F>(&mut self, f: F) -> &mut Cmd
    where
        F: FnMut() -> std::io::Result<()> + Send + Sync + 'static,
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: forwarded; the caller upholds `pre_exec`'s contract.
        unsafe {
            self.inner.pre_exec(f);
        }
        self
    }

    #[cfg(test)]
    pub fn get_program(&self) -> &OsStr {
        self.inner.get_program()
    }

    #[cfg(test)]
    pub fn get_envs(&self) -> std::process::CommandEnvs<'_> {
        self.inner.get_envs()
    }

    fn default_stdin(&mut self) {
        if !self.stdin {
            self.inner.stdin(Stdio::null());
            self.stdin = true;
        }
    }

    /// Run to completion capturing stdout and stderr, as `Command::output`.
    pub fn output(&mut self) -> std::io::Result<Output> {
        self.default_stdin();
        self.inner.output()
    }

    /// Run to completion; unset output streams are forwarded to `term`.
    pub fn status(&mut self) -> std::io::Result<ExitStatus> {
        let mut child = self.spawn_captured()?;
        let (out, err) = (child.stdout.take(), child.stderr.take());
        std::thread::scope(|scope| {
            if let Some(out) = out {
                scope.spawn(move || forward(out, crate::term::result));
            }
            if let Some(err) = err {
                scope.spawn(move || forward(err, crate::term::line));
            }
            child.wait()
        })
    }

    /// Start the child; unset output streams are forwarded to `term` by
    /// threads that `Spawned::wait` joins.
    pub fn spawn(&mut self) -> std::io::Result<Spawned> {
        let forward_out = !self.stdout;
        let forward_err = !self.stderr;
        let mut child = self.spawn_captured()?;
        let mut forwarders = Vec::new();
        if forward_out {
            if let Some(out) = child.stdout.take() {
                forwarders.push(std::thread::spawn(move || {
                    forward(out, crate::term::result)
                }));
            }
        }
        if forward_err {
            if let Some(err) = child.stderr.take() {
                forwarders.push(std::thread::spawn(move || forward(err, crate::term::line)));
            }
        }
        Ok(Spawned { child, forwarders })
    }

    fn spawn_captured(&mut self) -> std::io::Result<Child> {
        self.default_stdin();
        if !self.stdout {
            self.inner.stdout(Stdio::piped());
        }
        if !self.stderr {
            self.inner.stderr(Stdio::piped());
        }
        self.inner.spawn()
    }
}

/// A started child. Output the caller left unset is forwarded by threads;
/// `wait` returns only after the child exited and that output was written,
/// so no trailing lines are lost when the caller returns.
pub struct Spawned {
    child: Child,
    forwarders: Vec<std::thread::JoinHandle<()>>,
}

impl std::ops::Deref for Spawned {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for Spawned {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Spawned {
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        for forwarder in self.forwarders.drain(..) {
            let _ = forwarder.join();
        }
        Ok(status)
    }

    pub fn wait_with_output(self) -> std::io::Result<Output> {
        let Spawned { child, forwarders } = self;
        let output = child.wait_with_output();
        for forwarder in forwarders {
            let _ = forwarder.join();
        }
        output
    }
}

/// Copy a child's stream to `sink` one line at a time.
fn forward(stream: impl Read, sink: fn(&str)) {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                }
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                sink(&String::from_utf8_lossy(&buf));
            }
        }
    }
}

pub fn command_exists(name: &str) -> bool {
    command_path(OsStr::new(name)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_environment_does_not_fall_through_to_process_ambient_values() {
        let root =
            std::env::temp_dir().join(format!("buildutil-invocation-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let tool = root.join("request-tool");
        std::fs::write(&tool, b"").unwrap();
        let context = Arc::new(RequestContext {
            cwd: PathBuf::from("/request"),
            env: BTreeMap::from([("PATH".to_string(), root.clone().into_os_string())]),
            cancel: Arc::new(AtomicBool::new(false)),
        });
        let _request = install_request_context(context);
        assert_eq!(ambient_var_os("PATH"), Some(root.clone().into_os_string()));
        assert_eq!(ambient_var_os("HOME"), None);
        assert_eq!(request_cwd(), Some(PathBuf::from("/request")));
        let command = command("request-tool");
        assert_eq!(command.get_program(), tool.as_os_str());
        assert_eq!(
            command
                .get_envs()
                .map(|(key, value)| (key.to_os_string(), value.map(OsStr::to_os_string)))
                .collect::<Vec<_>>(),
            vec![("PATH".into(), Some(root.into_os_string()))]
        );
        drop(_request);
        let _ = std::fs::remove_dir_all(tool.parent().unwrap());
    }
}
