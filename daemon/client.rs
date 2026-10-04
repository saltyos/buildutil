// SPDX-License-Identifier: GPL-2.0-only
//! Daemon client, rotation, and safe in-process fallback selection.

use super::proto::{self, Frame, Handshake, Request};
use super::server;
use super::state::ENV_ALLOWLIST;
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CONNECT_WAIT: Duration = Duration::from_secs(3);
const RETRY_ATTEMPTS: usize = 5;
const RETRY_DELAY: Duration = Duration::from_millis(200);

enum RequestFailure {
    Unavailable(String),
    InFlight(String),
}

pub fn eligible(argv: &[String]) -> bool {
    let Some(command) = argv.first().map(String::as_str) else {
        return false;
    };
    crate::cmd::engine::is_engine_request(argv)
        && !argv.iter().any(|arg| arg == "--no-daemon")
        && std::env::var_os("BUILDUTIL_NO_DAEMON").is_none()
        && std::env::var_os("BUILDUTIL_STORE_EXECUTOR_ACTIVE").is_none()
        && !matches!(command, "__realize-plan" | "__sandbox" | "__daemon")
}

pub fn maybe_run(argv: &[String], args: &crate::cmd::Args) -> Option<Result<i32, String>> {
    if !eligible(argv) || args.no_daemon {
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    let repo_root = crate::cmd::repo_root_from(&cwd).ok()?;
    let state_root = crate::cmd::state_root_from_repo(args, &repo_root);
    if let Some(store) = std::env::var_os("BUILDUTIL_STORE") {
        if canonical(Path::new(&store)) != canonical(&state_root) {
            crate::log::info(
                "daemon",
                "Daemon bypassed: BUILDUTIL_STORE resolves outside its state root",
            );
            return None;
        }
    }
    // A caller that asked for the event stream gets it unchanged on stdout.
    let opts = (!args.stream_events).then(|| args.view_options());
    match run_request_with_retries(&repo_root, &state_root, &cwd, argv, opts.as_ref()) {
        Ok(code) => Some(Ok(code)),
        Err(RequestFailure::Unavailable(error)) => {
            crate::log::warn(
                "daemon",
                &format!("Daemon unavailable ({error}); running without it"),
            );
            None
        }
        Err(RequestFailure::InFlight(error)) => Some(Err(format!(
            "daemon request failed after submission; refusing an unsafe replay: {error}"
        ))),
    }
}

pub fn status(args: &crate::cmd::Args) -> Result<i32, String> {
    let repo = crate::cmd::repo_root_from_cwd()?;
    let state = crate::cmd::state_root_from_repo(args, &repo);
    match connect_existing(&repo, &state) {
        Ok(mut stream) => {
            proto::write_frame(&mut stream, &Frame::Status)?;
            match proto::read_frame(&mut stream)? {
                Some(Frame::StatusReport(status)) => {
                    out!("running");
                    out!("watcher: {}", status.watcher_health);
                    out!("events-since-baseline: {}", status.events_since_baseline);
                    for record in status.history {
                        let code = record
                            .code
                            .map(|code| code.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        out!(
                            "request: {} outcome={} code={} duration={}ms argv={:?}",
                            record.id,
                            record.outcome,
                            code,
                            record.duration_ms,
                            record.argv
                        );
                    }
                    Ok(0)
                }
                Some(Frame::Error(error)) => Err(error),
                _ => Err("daemon did not return watcher status".to_string()),
            }
        }
        Err(_) => {
            out!("stopped");
            Ok(1)
        }
    }
}

pub fn stop(args: &crate::cmd::Args) -> Result<i32, String> {
    let repo = crate::cmd::repo_root_from_cwd()?;
    let state = crate::cmd::state_root_from_repo(args, &repo);
    let force = args.targets.iter().any(|arg| arg == "--force");
    if let Some(code) = stopped_daemon_result(&state, force, |state_root| {
        crate::host::container::reap_orphan_resident_containers(state_root)
    }) {
        return Ok(code);
    }
    let mut stream = match connect_existing(&repo, &state) {
        Ok(stream) => stream,
        Err(error) => {
            if let Some(code) = stopped_daemon_result(&state, force, |state_root| {
                crate::host::container::reap_orphan_resident_containers(state_root)
            }) {
                return Ok(code);
            }
            return Err(error);
        }
    };
    proto::write_frame(&mut stream, &Frame::Stop { force })?;
    match proto::read_frame(&mut stream)? {
        Some(Frame::Stopped) => {
            wait_for_daemon_exit(&state, None)?;
            Ok(0)
        }
        Some(Frame::Error(error)) => Err(error),
        _ => Err("daemon stop did not acknowledge".into()),
    }
}

fn stopped_daemon_result(
    state_root: &Path,
    force: bool,
    reap_orphan: impl FnOnce(&Path),
) -> Option<i32> {
    if server::endpoint_path(state_root).exists() {
        return None;
    }
    if force {
        reap_orphan(state_root);
    }
    Some(0)
}

pub fn restart(args: &crate::cmd::Args) -> Result<i32, String> {
    let _ = stop(args);
    let repo = crate::cmd::repo_root_from_cwd()?;
    let state = crate::cmd::state_root_from_repo(args, &repo);
    let cwd = std::env::current_dir().map_err(|e| format!("cannot determine cwd: {e}"))?;
    connect_or_spawn(&repo, &state, &cwd).map(|_| 0)
}

pub fn verify(args: &crate::cmd::Args) -> Result<i32, String> {
    let repo = crate::cmd::repo_root_from_cwd()?;
    let state = crate::cmd::state_root_from_repo(args, &repo);
    let cwd = std::env::current_dir().map_err(|e| format!("cannot determine cwd: {e}"))?;
    let mut stream = connect_or_spawn(&repo, &state, &cwd)?;
    let mut argv = vec!["__daemon-verify".to_string()];
    argv.extend(args.argv.iter().skip(2).cloned());
    run_request(&mut stream, &argv, &cwd, Some(&args.view_options()))
}

fn run_request_with_retries(
    repo_root: &Path,
    state_root: &Path,
    cwd: &Path,
    argv: &[String],
    opts: Option<&crate::term::view::Options>,
) -> Result<i32, RequestFailure> {
    run_request_with_retries_with(
        || connect_or_spawn(repo_root, state_root, cwd),
        |stream| run_request(stream, argv, cwd, opts),
    )
}

fn run_request_with_retries_with<T>(
    connect: impl FnOnce() -> Result<T, String>,
    submit: impl FnOnce(&mut T) -> Result<i32, String>,
) -> Result<i32, RequestFailure> {
    let mut stream = connect().map_err(RequestFailure::Unavailable)?;
    submit(&mut stream).map_err(RequestFailure::InFlight)
}

fn connect_or_spawn(repo_root: &Path, state_root: &Path, cwd: &Path) -> Result<UnixStream, String> {
    connect_or_spawn_with(
        || connect_existing(repo_root, state_root),
        || spawn_detached(state_root, cwd),
        std::thread::sleep,
    )
}

fn connect_or_spawn_with<T>(
    mut connect: impl FnMut() -> Result<T, String>,
    mut spawn: impl FnMut() -> Result<(), String>,
    mut sleep: impl FnMut(Duration),
) -> Result<T, String> {
    let mut last = "daemon endpoint is unavailable".to_string();
    for _ in 0..RETRY_ATTEMPTS {
        match connect() {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
        sleep(RETRY_DELAY);
    }
    // A running daemon owns the startup flock.  Retry its socket first; only
    // then attempt a detached start, whose lock collision is non-fatal because
    // another process may have won the same startup race.
    if let Err(error) = spawn() {
        last = format!("daemon spawn: {error}");
    }
    let deadline = Instant::now() + CONNECT_WAIT;
    while Instant::now() < deadline {
        match connect() {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
        sleep(RETRY_DELAY);
    }
    Err(last)
}

fn connect_existing(repo_root: &Path, state_root: &Path) -> Result<UnixStream, String> {
    let path = endpoint(state_root)?;
    let mut stream = UnixStream::connect(&path)
        .map_err(|e| format!("cannot connect daemon {}: {e}", path.display()))?;
    let requested = handshake(repo_root, state_root);
    stream
        .set_read_timeout(Some(RETRY_DELAY))
        .map_err(|e| format!("cannot configure daemon handshake timeout: {e}"))?;
    let response = proto::write_frame(&mut stream, &Frame::Handshake(requested.clone()))
        .and_then(|_| read_handshake_until(&mut stream, Instant::now() + CONNECT_WAIT));
    let _ = stream.set_read_timeout(None);
    let response = match response {
        Ok(response) => response,
        Err(error) if proto::is_timeout_error(&error) => return Err(error),
        Err(error) => {
            if request_rotation(&mut stream, state_root).is_ok() {
                return Err("stale daemon protocol; old daemon exited for rotation".into());
            }
            return Err(error);
        }
    };
    let Some(Frame::Handshake(actual)) = response else {
        return Err("daemon did not send a handshake".into());
    };
    if !server::handshake_matches(&requested, &actual) {
        request_rotation(&mut stream, state_root)?;
        return Err("stale daemon identity; old daemon exited for rotation".into());
    }
    Ok(stream)
}

fn read_handshake_until<R: Read>(
    reader: &mut R,
    deadline: Instant,
) -> Result<Option<Frame>, String> {
    loop {
        match proto::read_frame(reader) {
            // `is_timeout_error` excludes partial frames, so retrying cannot
            // discard framing state already consumed from the stream.
            Err(error) if proto::is_timeout_error(&error) && Instant::now() < deadline => {}
            result => return result,
        }
    }
}

fn request_rotation(stream: &mut UnixStream, state_root: &Path) -> Result<(), String> {
    proto::write_frame(stream, &Frame::Stop { force: true })?;
    stream
        .set_read_timeout(Some(RETRY_DELAY))
        .map_err(|e| format!("cannot configure stale-daemon stop timeout: {e}"))?;
    let response = proto::read_frame(stream);
    let _ = stream.set_read_timeout(None);
    match response? {
        Some(Frame::Stopped) => wait_for_daemon_exit(state_root, Some(CONNECT_WAIT)),
        Some(Frame::Error(error)) => Err(format!("stale daemon rejected stop: {error}")),
        Some(frame) => Err(format!(
            "stale daemon sent unexpected stop response: {frame:?}"
        )),
        None => Err("stale daemon disconnected before acknowledging stop".to_string()),
    }
}

fn wait_for_daemon_exit(state_root: &Path, timeout: Option<Duration>) -> Result<(), String> {
    let endpoint = server::endpoint_path(state_root);
    let socket = server::socket_path(state_root);
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    while endpoint.exists() || socket.exists() {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err("daemon did not remove its endpoint after stop".to_string());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

fn run_request(
    stream: &mut UnixStream,
    argv: &[String],
    cwd: &Path,
    opts: Option<&crate::term::view::Options>,
) -> Result<i32, String> {
    let mut daemon_argv = argv.to_vec();
    if !daemon_argv.iter().any(|arg| arg == "--stream-events") {
        daemon_argv.push("--stream-events".into());
    }
    stream
        .set_write_timeout(Some(RETRY_DELAY))
        .map_err(|e| format!("cannot configure daemon request write timeout: {e}"))?;
    let written = proto::write_frame(
        stream,
        &Frame::Request(Request {
            id: request_id(),
            argv: daemon_argv,
            cwd: cwd.as_os_str().as_bytes().to_vec(),
            env: request_env(),
        }),
    );
    let _ = stream.set_write_timeout(None);
    written?;
    let mut view = opts.map(|opts| crate::term::view::BuildView::new(opts.clone()));
    let result = drive_request(stream, view.as_mut());
    if let Some(view) = view.as_mut() {
        view.finish();
    }
    result
}

/// Draw one request's frames until the daemon reports its exit code; with no
/// view, pass events and output through unchanged.
fn drive_request(
    stream: &mut UnixStream,
    mut view: Option<&mut crate::term::view::BuildView>,
) -> Result<i32, String> {
    use crate::term::view::Stream;
    let interrupt = crate::host::interrupt::InterruptGuard::install();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| format!("cannot configure daemon client socket: {e}"))?;
    let mut cancelling = None;
    loop {
        if interrupt.was_interrupted() && cancelling.is_none() {
            proto::write_frame(stream, &Frame::Cancel)?;
            cancelling = Some(Instant::now() + Duration::from_secs(2));
        }
        match proto::read_frame(stream) {
            Ok(Some(Frame::Event(line))) => match view.as_deref_mut() {
                Some(view) => view.event(&line),
                None => crate::term::result(&line),
            },
            Ok(Some(Frame::Output {
                stream: which,
                bytes,
            })) => {
                let which = if which == "stdout" {
                    Stream::Stdout
                } else {
                    Stream::Stderr
                };
                match view.as_deref_mut() {
                    Some(view) => view.raw(which, &bytes),
                    None if which == Stream::Stdout => crate::term::result_raw(&bytes),
                    None => crate::term::line_raw(&bytes),
                }
            }
            Ok(Some(Frame::Queued { position })) => {
                let text = format!("daemon request queued (position {position})");
                match view.as_deref_mut() {
                    Some(view) => view.tagged("info", &text),
                    None => crate::term::info(&text),
                }
            }
            Ok(Some(Frame::Exit { code })) => {
                if cancelling.is_some() {
                    if let Some(view) = view.as_deref_mut() {
                        view.interrupted();
                    }
                }
                return Ok(code);
            }
            Ok(Some(Frame::Error(error))) => return Err(error),
            Ok(Some(_)) => {}
            Ok(None) => return Err("daemon disconnected before reporting an exit code".into()),
            Err(error) if proto::is_timeout_error(&error) => {
                if cancelling.is_some_and(|deadline| Instant::now() >= deadline) {
                    if let Some(view) = view.as_deref_mut() {
                        view.interrupted();
                    }
                    return Ok(130);
                }
                if let Some(view) = view.as_deref_mut() {
                    view.tick();
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn request_env() -> BTreeMap<String, Vec<u8>> {
    let mut env = ENV_ALLOWLIST
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| ((*key).to_string(), value.into_vec())))
        .collect::<BTreeMap<_, _>>();
    restore_request_sdkroot(&mut env, crate::exec::build::ambient_sdkroot);
    env
}

fn restore_request_sdkroot(
    env: &mut BTreeMap<String, Vec<u8>>,
    resolve: impl FnOnce() -> Option<String>,
) {
    if !env.contains_key("SDKROOT")
        && let Some(sdkroot) = resolve()
    {
        env.insert("SDKROOT".to_string(), sdkroot.into_bytes());
    }
}

fn endpoint(state_root: &Path) -> Result<PathBuf, String> {
    let endpoint = server::endpoint_path(state_root);
    let text = std::fs::read_to_string(&endpoint)
        .map_err(|e| format!("cannot read daemon endpoint {}: {e}", endpoint.display()))?;
    let text = text.trim();
    let path = match text.strip_prefix("hex:") {
        Some(encoded) => PathBuf::from(std::ffi::OsString::from_vec(proto::decode_bytes(encoded)?)),
        None => PathBuf::from(text),
    };
    if path == server::socket_path(state_root) {
        Ok(path)
    } else {
        Err("daemon endpoint does not match this state root".into())
    }
}

fn handshake(repo_root: &Path, state_root: &Path) -> Handshake {
    Handshake {
        protocol_version: proto::PROTOCOL_VERSION,
        binary_identity: crate::store::buildutil_self_identity(),
        repo_root: canonical(repo_root).as_os_str().as_bytes().to_vec(),
        state_root: canonical(state_root).as_os_str().as_bytes().to_vec(),
    }
}

fn request_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{now}", std::process::id())
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn spawn_detached(state_root: &Path, cwd: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn fork() -> i32;
        fn setsid() -> i32;
        fn chdir(path: *const std::ffi::c_char) -> i32;
        fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        fn dup2(from: i32, to: i32) -> i32;
        fn close(fd: i32) -> i32;
        fn execv(path: *const std::ffi::c_char, argv: *const *const std::ffi::c_char) -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
    }
    let binary =
        std::env::current_exe().map_err(|e| format!("cannot locate buildutil binary: {e}"))?;
    let binary_c = CString::new(binary.as_os_str().as_bytes())
        .map_err(|_| "buildutil binary path contains NUL")?;
    let cwd_c = CString::new(cwd.as_os_str().as_bytes()).map_err(|_| "daemon cwd contains NUL")?;
    let daemon = CString::new("__daemon").expect("literal has no NUL");
    let store = CString::new("--store").expect("literal has no NUL");
    let dev_null = CString::new("/dev/null").expect("literal has no NUL");
    let state = CString::new(state_root.as_os_str().as_bytes())
        .map_err(|_| "daemon state root contains NUL")?;
    // SAFETY: fork has no Rust-level preconditions; the child only invokes
    // async-signal-safe POSIX calls before exec/_exit.
    let first = unsafe { fork() };
    if first < 0 {
        return Err(format!(
            "cannot fork daemon: {}",
            std::io::Error::last_os_error()
        ));
    }
    if first > 0 {
        let mut status = 0; // SAFETY: waits for the direct first child only.
        let _ = unsafe { waitpid(first, &mut status, 0) };
        return Ok(());
    }
    // SAFETY: first child creates an independent session before the second
    // fork, so it cannot acquire the caller's terminal again.
    if unsafe { setsid() } < 0 {
        // SAFETY: this child must not run Rust destructors after fork.
        unsafe { _exit(1) };
    }
    // SAFETY: second fork follows the usual double-fork daemonisation pattern.
    let second = unsafe { fork() };
    if second < 0 {
        // SAFETY: this child must not run Rust destructors after fork.
        unsafe { _exit(1) };
    }
    if second > 0 {
        // SAFETY: the first child exits after creating the detached grandchild.
        unsafe { _exit(0) };
    }
    // SAFETY: CString pointers remain live until exec replaces this process.
    if unsafe { chdir(cwd_c.as_ptr() as *const std::ffi::c_char) } != 0 {
        // SAFETY: this child must not run Rust destructors after fork.
        unsafe { _exit(1) };
    }
    const O_RDWR: i32 = 2;
    // SAFETY: `/dev/null` is a valid NUL-terminated path; without O_CREAT the
    // variadic mode argument is neither required nor read.
    let null_fd = unsafe { open(dev_null.as_ptr(), O_RDWR) };
    if null_fd < 0 {
        // SAFETY: this child must not run Rust destructors after fork.
        unsafe { _exit(1) };
    }
    for target in 0..=2 {
        // SAFETY: null_fd is open and dup2 atomically replaces each inherited
        // standard descriptor in the detached grandchild.
        if unsafe { dup2(null_fd, target) } < 0 {
            // SAFETY: this child must not run Rust destructors after fork.
            unsafe { _exit(1) };
        }
    }
    if null_fd > 2 {
        // SAFETY: null_fd is no longer needed after all three dup2 calls.
        let _ = unsafe { close(null_fd) };
    }
    let argv: [*const std::ffi::c_char; 5] = [
        binary_c.as_ptr() as *const std::ffi::c_char,
        daemon.as_ptr() as *const std::ffi::c_char,
        store.as_ptr() as *const std::ffi::c_char,
        state.as_ptr() as *const std::ffi::c_char,
        std::ptr::null(),
    ];
    // SAFETY: argv is null terminated and every pointer refers to a NUL-terminated CString.
    unsafe { execv(binary_c.as_ptr() as *const std::ffi::c_char, argv.as_ptr()) };
    // SAFETY: exec failed; no Rust destructors are safe after fork in this child.
    unsafe { _exit(1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StartingDaemon {
        timeouts: usize,
        response: std::io::Cursor<Vec<u8>>,
    }

    impl Read for StartingDaemon {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.timeouts > 0 {
                self.timeouts -= 1;
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            self.response.read(out)
        }
    }

    #[test]
    fn starting_daemon_handshake_timeout_retries_without_rotation() {
        let expected = Frame::Handshake(Handshake {
            protocol_version: proto::PROTOCOL_VERSION,
            binary_identity: "same-binary".into(),
            repo_root: b"/repo".to_vec(),
            state_root: b"/state".to_vec(),
        });
        let mut bytes = Vec::new();
        proto::write_frame(&mut bytes, &expected).unwrap();
        let mut daemon = StartingDaemon {
            timeouts: 2,
            response: std::io::Cursor::new(bytes),
        };

        assert_eq!(
            read_handshake_until(&mut daemon, Instant::now() + CONNECT_WAIT).unwrap(),
            Some(expected)
        );
        assert_eq!(daemon.timeouts, 0);
    }

    #[test]
    fn stale_identity_rotates_then_uses_fresh_daemon_without_fallback() {
        let connect_attempts = std::cell::Cell::new(0usize);
        let spawn_attempts = std::cell::Cell::new(0usize);
        let stale_daemon_rotated = std::cell::Cell::new(false);
        let fresh_daemon_used = std::cell::Cell::new(false);
        let result = run_request_with_retries_with(
            || {
                connect_or_spawn_with(
                    || {
                        let attempt = connect_attempts.get() + 1;
                        connect_attempts.set(attempt);
                        match attempt {
                            1 => {
                                stale_daemon_rotated.set(true);
                                Err("stale daemon identity; old daemon exited for rotation".into())
                            }
                            2..=RETRY_ATTEMPTS => Err("daemon endpoint is unavailable".into()),
                            _ => Ok("fresh-daemon"),
                        }
                    },
                    || {
                        spawn_attempts.set(spawn_attempts.get() + 1);
                        Ok(())
                    },
                    |_| {},
                )
            },
            |daemon| {
                assert_eq!(*daemon, "fresh-daemon");
                fresh_daemon_used.set(true);
                Ok(0)
            },
        );

        assert!(matches!(result, Ok(0)));
        assert!(stale_daemon_rotated.get());
        assert!(fresh_daemon_used.get());
        assert_eq!(connect_attempts.get(), RETRY_ATTEMPTS + 1);
        assert_eq!(spawn_attempts.get(), 1);
    }

    #[test]
    fn request_env_resolves_missing_sdkroot_per_request() {
        let mut env = BTreeMap::new();
        restore_request_sdkroot(&mut env, || Some("/request/sdk".to_string()));
        assert_eq!(env.get("SDKROOT"), Some(&b"/request/sdk".to_vec()));
    }

    #[test]
    fn request_env_preserves_supplied_sdkroot_without_probe() {
        let mut env = BTreeMap::from([("SDKROOT".to_string(), b"/supplied/sdk".to_vec())]);
        restore_request_sdkroot(&mut env, || {
            panic!("supplied SDKROOT must suppress probing")
        });
        assert_eq!(env.get("SDKROOT"), Some(&b"/supplied/sdk".to_vec()));
    }

    #[test]
    fn forced_stop_is_idempotent_when_the_endpoint_is_absent() {
        let state_root = std::env::temp_dir().join(format!(
            "buildutil-daemon-stop-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut reaped = false;
        assert_eq!(
            stopped_daemon_result(&state_root, true, |_| reaped = true),
            Some(0)
        );
        assert!(reaped);

        let mut plain_reap = false;
        assert_eq!(
            stopped_daemon_result(&state_root, false, |_| plain_reap = true),
            Some(0)
        );
        assert!(!plain_reap);
    }
}
