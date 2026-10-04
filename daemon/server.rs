// SPDX-License-Identifier: GPL-2.0-only
//! Unix-domain daemon server and its single-flight request queue.

use super::proto::{self, Frame, Handshake, Request, RequestRecord};
use super::state::{self, DaemonState};
use crate::invocation::RequestContext;
use std::any::Any;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_IDLE_SECS: u64 = 30 * 60;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_HISTORY_LIMIT: usize = 32;
const SIGTERM_NUM: i32 = 15;
const SIG_ERR: usize = usize::MAX;

static SIGTERM_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Installs one request's SDKROOT without mutating the daemon's process
/// environment. The single-flight executor makes this shared seam safe for
/// build workers, and Drop prevents one request from leaking into the next.
struct RequestSdkrootGuard<'a> {
    slot: &'a Mutex<Option<Option<String>>>,
}

impl RequestSdkrootGuard<'static> {
    fn install(value: Option<String>) -> Self {
        Self::install_in(crate::exec::build::request_sdkroot_slot(), value)
    }
}

impl<'a> RequestSdkrootGuard<'a> {
    fn install_in(slot: &'a Mutex<Option<Option<String>>>, value: Option<String>) -> Self {
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(value);
        Self { slot }
    }
}

impl Drop for RequestSdkrootGuard<'_> {
    fn drop(&mut self) {
        *self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

#[derive(Clone)]
struct DaemonLog {
    file: Arc<Mutex<File>>,
}

impl DaemonLog {
    fn open(state_root: &Path) -> Result<Self, String> {
        let path = state_root.join("daemon").join("daemon.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("cannot open daemon log {}: {e}", path.display()))?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    fn line(&self, message: impl AsRef<str>) {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = writeln!(
            file,
            "{}.{:03} {}",
            elapsed.as_secs(),
            elapsed.subsec_millis(),
            message.as_ref()
        );
        let _ = file.flush();
    }
}

fn install_panic_log(log: DaemonLog) {
    panic::set_hook(Box::new(move |info| {
        log.line(format!("panic: {info}"));
    }));
}

unsafe extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

extern "C" fn daemon_sigterm_handler(_signum: i32) {
    SIGTERM_REQUESTED.store(true, Ordering::SeqCst);
}

struct DaemonSignalGuard {
    previous: usize,
}

impl DaemonSignalGuard {
    fn install() -> Self {
        SIGTERM_REQUESTED.store(false, Ordering::SeqCst);
        let handler = daemon_sigterm_handler as *const () as usize;
        // SAFETY: `daemon_sigterm_handler` has the C signal-handler ABI and
        // only stores to an AtomicBool, which is async-signal-safe here.
        let previous = unsafe { signal(SIGTERM_NUM, handler) };
        Self { previous }
    }
}

impl Drop for DaemonSignalGuard {
    fn drop(&mut self) {
        if self.previous != SIG_ERR {
            // SAFETY: `previous` is the disposition returned by signal() at
            // installation time, so restoring it is valid.
            unsafe { signal(SIGTERM_NUM, self.previous) };
        }
    }
}

pub fn socket_path(state_root: &Path) -> PathBuf {
    let state_root = super::watch::normalize_path(state_root);
    let digest = crate::crypto::sha256::hash_bytes(state_root.as_os_str().as_bytes());
    let dir = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    dir.join(format!("buildutil-{}/sock", &digest[..16]))
}

pub fn endpoint_path(state_root: &Path) -> PathBuf {
    state_root.join("daemon").join("endpoint")
}

fn identity(repo_root: &Path, state_root: &Path) -> Handshake {
    Handshake {
        protocol_version: proto::PROTOCOL_VERSION,
        binary_identity: crate::store::buildutil_self_identity(),
        repo_root: canonical(repo_root).as_os_str().as_bytes().to_vec(),
        state_root: canonical(state_root).as_os_str().as_bytes().to_vec(),
    }
}

pub fn handshake_matches(expected: &Handshake, received: &Handshake) -> bool {
    expected.protocol_version == received.protocol_version
        && expected.binary_identity == received.binary_identity
        && expected.repo_root == received.repo_root
        && expected.state_root == received.state_root
}

fn handshake_difference(expected: &Handshake, received: &Handshake) -> String {
    let mut differences = Vec::new();
    if expected.protocol_version != received.protocol_version {
        differences.push(format!(
            "protocol_version expected {} got {}",
            expected.protocol_version, received.protocol_version
        ));
    }
    if expected.binary_identity != received.binary_identity {
        differences.push("binary_identity differs".to_string());
    }
    if expected.repo_root != received.repo_root {
        differences.push(format!(
            "repo_root expected {:?} got {:?}",
            expected.repo_root, received.repo_root
        ));
    }
    if expected.state_root != received.state_root {
        differences.push(format!(
            "state_root expected {:?} got {:?}",
            expected.state_root, received.state_root
        ));
    }
    if differences.is_empty() {
        "match".to_string()
    } else {
        differences.join("; ")
    }
}

pub fn run(args: &crate::cmd::Args) -> Result<i32, String> {
    let _signals = DaemonSignalGuard::install();
    let repo_root = crate::cmd::repo_root_from_cwd()?;
    let state_root = crate::cmd::state_root_from_repo(args, &repo_root);
    let state_root = canonical(&state_root);
    let repo_root = canonical(&repo_root);
    let lock = acquire_start_lock(&state_root)?;
    let log = DaemonLog::open(&state_root)?;
    install_panic_log(log.clone());
    log.line(format!(
        "daemon starting repo_root={} state_root={}",
        repo_root.display(),
        state_root.display()
    ));
    let path = socket_path(&state_root);
    prepare_socket_dir(&path)?;
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .map_err(|e| format!("cannot bind daemon socket {}: {e}", path.display()))?;
    crate::platform::set_mode(&path, 0o600)
        .map_err(|e| format!("cannot secure daemon socket {}: {e}", path.display()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot configure daemon socket: {e}"))?;
    let endpoint = endpoint_path(&state_root);
    if let Some(parent) = endpoint.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "cannot create daemon endpoint directory {}: {e}",
                parent.display()
            )
        })?;
    }
    std::fs::write(
        &endpoint,
        format!("hex:{}", proto::encode_bytes(path.as_os_str().as_bytes())).as_bytes(),
    )
    .map_err(|e| format!("cannot write daemon endpoint {}: {e}", endpoint.display()))?;
    crate::platform::set_mode(&endpoint, 0o600)
        .map_err(|e| format!("cannot secure daemon endpoint {}: {e}", endpoint.display()))?;

    let state = Arc::new(Mutex::new(DaemonState::new(
        repo_root.clone(),
        state_root.clone(),
    )?));
    for transition in state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take_watcher_transitions()
    {
        log.line(transition);
    }
    state::install_active_daemon(state.clone());
    let queue = Arc::new(Queue::default());
    let history = Arc::new(Mutex::new(VecDeque::<RequestRecord>::new()));
    let stopping = Arc::new(AtomicBool::new(false));
    let expected = identity(&repo_root, &state_root);
    let idle = Duration::from_secs(
        std::env::var("BUILDUTIL_DAEMON_IDLE_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_IDLE_SECS),
    );
    let executor_queue = queue.clone();
    let executor_stop = stopping.clone();
    let executor_state = state.clone();
    let executor_log = log.clone();
    let executor_history = history.clone();
    let executor = std::thread::spawn(move || {
        execute_loop(
            executor_queue,
            executor_state,
            executor_stop,
            executor_history,
            executor_log,
        )
    });
    let mut last_activity = Instant::now();
    let mut was_idle = true;
    let mut accept_error = None;
    while !stopping.load(Ordering::Acquire) && !SIGTERM_REQUESTED.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                // BSD/macOS accepts inherit O_NONBLOCK from the listener; request frames need blocking reads.
                if let Err(error) = stream.set_nonblocking(false) {
                    log.line(format!(
                        "cannot configure accepted daemon connection: {error}"
                    ));
                    request_stop(&stopping, &queue, &path, false, &history, &log);
                    accept_error = Some(format!("daemon accepted socket setup: {error}"));
                    break;
                }
                last_activity = Instant::now();
                log.line("accepted daemon connection");
                let queue = queue.clone();
                let stopping = stopping.clone();
                let expected = expected.clone();
                let log = log.clone();
                let socket = path.clone();
                let state = state.clone();
                let history = history.clone();
                std::thread::spawn(move || {
                    handle_connection(
                        stream, expected, queue, stopping, socket, state, history, log,
                    )
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if SIGTERM_REQUESTED.load(Ordering::Acquire) {
                    log.line("SIGTERM requested daemon shutdown");
                    request_stop(&stopping, &queue, &path, false, &history, &log);
                    continue;
                }
                if queue.is_idle() {
                    if !was_idle {
                        last_activity = Instant::now();
                    }
                    was_idle = true;
                    if last_activity.elapsed() >= idle {
                        log.line("daemon idle timeout requested shutdown");
                        request_stop(&stopping, &queue, &path, false, &history, &log);
                    }
                } else {
                    was_idle = false;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error)
                if SIGTERM_REQUESTED.load(Ordering::Acquire)
                    || error.kind() == std::io::ErrorKind::Interrupted =>
            {
                log.line(format!("daemon accept interrupted: {error}"));
                request_stop(&stopping, &queue, &path, false, &history, &log);
            }
            Err(error) => {
                log.line(format!("daemon accept error: {error}"));
                request_stop(&stopping, &queue, &path, false, &history, &log);
                accept_error = Some(format!("daemon accept: {error}"));
                break;
            }
        }
    }
    request_stop(&stopping, &queue, &path, false, &history, &log);
    log.line("daemon draining executor");
    if executor.join().is_err() {
        log.line("daemon executor thread panicked while shutting down");
    }
    let resident_container_runtimes = {
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.flush();
        state.shutdown();
        state.resident_container_runtimes()
    };
    for runtime in resident_container_runtimes {
        if let Err(error) =
            crate::host::container::teardown_resident_container(&runtime, &state_root)
        {
            log.line(format!(
                "resident container teardown failed for {runtime}: {error}"
            ));
            if accept_error.is_none() {
                accept_error = Some(format!("resident container teardown: {error}"));
            }
        }
    }
    crate::host::container::reap_orphan_resident_containers(&state_root);
    state::clear_active_daemon();
    let _ = std::fs::remove_file(&endpoint);
    let _ = std::fs::remove_file(&path);
    drop(lock);
    log.line("daemon shutdown complete");
    match accept_error {
        Some(error) => Err(error),
        None => Ok(0),
    }
}

struct Job {
    request: Request,
    submitted_at: Instant,
    writer: Arc<Mutex<UnixStream>>,
    cancel: Arc<AtomicBool>,
    phase: Arc<Mutex<JobPhase>>,
}

#[derive(Clone)]
struct JobControl {
    cancel: Arc<AtomicBool>,
    phase: Arc<Mutex<JobPhase>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JobPhase {
    Queued,
    Running,
    Finished,
}

#[derive(Default)]
struct Queue {
    inner: Mutex<QueueInner>,
    ready: Condvar,
}
struct QueueInner {
    jobs: VecDeque<Job>,
    running: bool,
    accepting: bool,
    active: Option<JobControl>,
}

impl Default for QueueInner {
    fn default() -> Self {
        Self {
            jobs: VecDeque::new(),
            running: false,
            accepting: true,
            active: None,
        }
    }
}

impl Queue {
    fn push(&self, job: Job) -> Result<usize, Job> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !inner.accepting {
            return Err(job);
        }
        let position = inner.jobs.len() + usize::from(inner.running) + 1;
        inner.jobs.push_back(job);
        self.ready.notify_one();
        Ok(position)
    }
    fn pop(&self, stopping: &AtomicBool) -> Option<Job> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while inner.jobs.is_empty() && !stopping.load(Ordering::Acquire) {
            inner = self
                .ready
                .wait(inner)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        let job = inner.jobs.pop_front();
        inner.running = job.is_some();
        inner.active = job.as_ref().map(|job| JobControl {
            cancel: job.cancel.clone(),
            phase: job.phase.clone(),
        });
        job
    }
    fn finished(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.running = false;
        inner.active = None;
    }
    fn is_idle(&self) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !inner.running && inner.jobs.is_empty()
    }
    fn wake(&self) {
        self.ready.notify_all();
    }

    fn stop_accepting(&self) -> Vec<Job> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.accepting = false;
        inner.jobs.drain(..).collect()
    }

    fn cancel_active(&self) {
        let active = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .clone();
        if let Some(active) = active {
            cancel_job(&active.cancel, &active.phase);
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    expected: Handshake,
    queue: Arc<Queue>,
    stopping: Arc<AtomicBool>,
    socket: PathBuf,
    state: Arc<Mutex<DaemonState>>,
    history: Arc<Mutex<VecDeque<RequestRecord>>>,
    log: DaemonLog,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        handle_connection_inner(
            &mut stream,
            expected,
            queue,
            stopping,
            socket,
            state,
            history,
            log.clone(),
        )
    }));
    if let Err(payload) = result {
        let text = panic_text(payload);
        log.line(format!("daemon connection handler panic: {text}"));
        if let Err(error) = proto::write_frame(
            &mut stream,
            &Frame::Error(format!("daemon connection panicked: {text}")),
        ) {
            log.line(format!(
                "daemon connection panic frame write failed: {error}"
            ));
        }
    }
}

fn handle_connection_inner(
    mut stream: &mut UnixStream,
    expected: Handshake,
    queue: Arc<Queue>,
    stopping: Arc<AtomicBool>,
    socket: PathBuf,
    state: Arc<Mutex<DaemonState>>,
    history: Arc<Mutex<VecDeque<RequestRecord>>>,
    log: DaemonLog,
) {
    let peer_uid = match crate::platform::unix_peer_uid(&stream) {
        Ok(uid) => uid,
        Err(error) => {
            log.line(format!("peer credential lookup failed: {error}"));
            if let Err(error) = proto::write_frame(
                &mut stream,
                &Frame::Error("daemon peer credential lookup failed".into()),
            ) {
                log.line(format!("peer credential error frame write failed: {error}"));
            }
            return;
        }
    };
    if peer_uid != crate::platform::current_uid() {
        log.line(format!("peer UID mismatch: got {peer_uid}"));
        if let Err(error) = proto::write_frame(
            &mut stream,
            &Frame::Error("daemon peer UID mismatch".into()),
        ) {
            log.line(format!("peer UID mismatch frame write failed: {error}"));
        }
        return;
    }
    if let Err(error) = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)) {
        log.line(format!(
            "cannot configure daemon handshake timeout: {error}"
        ));
        return;
    }
    let client = match proto::read_frame(&mut stream) {
        Ok(Some(Frame::Handshake(client))) => client,
        Ok(Some(frame)) => {
            log.line(format!("expected handshake, received {frame:?}"));
            if let Err(error) = proto::write_frame(
                &mut stream,
                &Frame::Error("expected daemon handshake".into()),
            ) {
                log.line(format!(
                    "expected-handshake error frame write failed: {error}"
                ));
            }
            return;
        }
        Ok(None) => {
            log.line("connection closed before daemon handshake");
            return;
        }
        Err(error) => {
            log.line(format!("daemon handshake read failed: {error}"));
            return;
        }
    };
    if let Err(error) = stream.set_read_timeout(None) {
        log.line(format!("cannot clear daemon handshake timeout: {error}"));
        return;
    }
    let difference = handshake_difference(&expected, &client);
    if difference == "match" {
        log.line("daemon handshake accepted");
    } else {
        log.line(format!("daemon handshake mismatch: {difference}"));
    }
    if let Err(error) = proto::write_frame(&mut stream, &Frame::Handshake(expected.clone())) {
        log.line(format!("daemon handshake response write failed: {error}"));
        return;
    }
    let frame = match proto::read_frame(&mut stream) {
        Ok(Some(frame)) => frame,
        Ok(None) => {
            log.line("connection closed after daemon handshake before request");
            return;
        }
        Err(error) => {
            log.line(format!("daemon post-handshake frame read failed: {error}"));
            return;
        }
    };
    match frame {
        Frame::Status => {
            let (status, transitions) = {
                let mut state = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let status = state.watcher_status();
                let transitions = state.take_watcher_transitions();
                (status, transitions)
            };
            for transition in transitions {
                log.line(transition);
            }
            if let Err(error) = proto::write_frame(
                &mut stream,
                &Frame::StatusReport(proto::StatusReport {
                    watcher_health: status.health,
                    events_since_baseline: status.events_since_baseline,
                    history: history
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .iter()
                        .cloned()
                        .collect(),
                }),
            ) {
                log.line(format!("daemon status response write failed: {error}"));
            }
        }
        Frame::Stop { force } => {
            log.line(format!(
                "daemon {} stop requested by client",
                if force { "forced" } else { "graceful" }
            ));
            if let Err(error) = proto::write_frame(&mut stream, &Frame::Stopped) {
                log.line(format!("daemon stop acknowledgement write failed: {error}"));
            }
            request_stop(&stopping, &queue, &socket, force, &history, &log);
        }
        Frame::Request(mut request) => {
            if !handshake_matches(&expected, &client) {
                log.line(format!(
                    "rejecting request after handshake mismatch: {difference}"
                ));
                if let Err(error) = proto::write_frame(
                    &mut stream,
                    &Frame::Error(format!("daemon handshake mismatch: {difference}")),
                ) {
                    log.line(format!("handshake mismatch error write failed: {error}"));
                }
                return;
            }
            if request.id.is_empty() || request.id.len() > 128 {
                let _ = proto::write_frame(
                    &mut stream,
                    &Frame::Error("daemon request id is empty or too long".to_string()),
                );
                return;
            }
            log.line(format!(
                "daemon request received id={} argv={:?} cwd_bytes={:?}",
                request.id, request.argv, request.cwd
            ));
            let writer = match stream.try_clone() {
                Ok(writer) => Arc::new(Mutex::new(writer)),
                Err(error) => {
                    log.line(format!("daemon request writer clone failed: {error}"));
                    return;
                }
            };
            request
                .env
                .retain(|key, _| super::state::ENV_ALLOWLIST.contains(&key.as_str()));
            let cancel = Arc::new(AtomicBool::new(false));
            let phase = Arc::new(Mutex::new(JobPhase::Queued));
            let job = Job {
                request,
                submitted_at: Instant::now(),
                writer,
                cancel: cancel.clone(),
                phase: phase.clone(),
            };
            let position = match queue.push(job) {
                Ok(position) => position,
                Err(job) => {
                    let _ = write_job(
                        &job,
                        Frame::Error("daemon is stopping; request was not queued".to_string()),
                    );
                    let duration_ms = job.submitted_at.elapsed().as_millis();
                    push_history(
                        &history,
                        RequestRecord {
                            id: job.request.id,
                            argv: history_argv(&job.request.argv),
                            outcome: "rejected".to_string(),
                            code: None,
                            duration_ms,
                        },
                    );
                    return;
                }
            };
            if position > 1 {
                if let Err(error) = write_to(&stream, &Frame::Queued { position }) {
                    log.line(format!("daemon queued response write failed: {error}"));
                }
            }
            // The read half remains dedicated to cancellation.  A disconnect
            // has the same semantics as Ctrl-C: cancel the queued/running job.
            loop {
                match proto::read_frame(&mut stream) {
                    Ok(Some(Frame::Cancel)) => {
                        log.line("daemon request cancellation received");
                        cancel_job(&cancel, &phase);
                        break;
                    }
                    Ok(None) => {
                        log.line("daemon request client disconnected; cancelling request");
                        cancel_job(&cancel, &phase);
                        break;
                    }
                    Err(error) => {
                        log.line(format!(
                            "daemon request control read failed; cancelling request: {error}"
                        ));
                        cancel_job(&cancel, &phase);
                        break;
                    }
                    Ok(Some(_)) => {}
                }
            }
        }
        _ => {
            log.line(format!(
                "unexpected daemon frame after handshake: {frame:?}"
            ));
            if let Err(error) =
                proto::write_frame(&mut stream, &Frame::Error("expected daemon request".into()))
            {
                log.line(format!("unexpected-frame error write failed: {error}"));
            }
        }
    }
}

fn cancel_job(cancel: &AtomicBool, phase: &Mutex<JobPhase>) {
    cancel.store(true, Ordering::Release);
    let phase = phase
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *phase == JobPhase::Running {
        crate::host::interrupt::request_interrupt();
    }
}

fn write_to(stream: &UnixStream, frame: &Frame) -> Result<(), String> {
    proto::write_frame(&mut stream.try_clone().map_err(|e| e.to_string())?, frame)
}

fn execute_loop(
    queue: Arc<Queue>,
    state: Arc<Mutex<DaemonState>>,
    stopping: Arc<AtomicBool>,
    history: Arc<Mutex<VecDeque<RequestRecord>>>,
    log: DaemonLog,
) {
    loop {
        let Some(job) = queue.pop(&stopping) else {
            break;
        };
        crate::host::interrupt::clear_interrupt();
        *job.phase
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = JobPhase::Running;
        let cancelled = job.cancel.clone();
        log.line(format!("daemon request start argv={:?}", job.request.argv));
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            execute_request(&job, &state, log.clone())
        }));
        *job.phase
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = JobPhase::Finished;
        let (outcome, code) = match &result {
            Ok(Ok(code)) => (
                if *code == 130 { "cancelled" } else { "exit" }.to_string(),
                Some(*code),
            ),
            Ok(Err(_)) => ("error".to_string(), None),
            Err(_) => ("panic".to_string(), None),
        };
        push_history(
            &history,
            RequestRecord {
                id: job.request.id.clone(),
                argv: history_argv(&job.request.argv),
                outcome,
                code,
                duration_ms: job.submitted_at.elapsed().as_millis(),
            },
        );
        match result {
            Ok(Ok(code)) => {
                log.line(format!("daemon request end code={code}"));
                if let Err(error) = write_job(&job, Frame::Exit { code }) {
                    log.line(format!("daemon exit frame write failed: {error}"));
                }
            }
            Ok(Err(error)) => {
                log.line(format!("daemon executor error: {error}"));
                if let Err(write_error) = write_job(&job, Frame::Error(error)) {
                    log.line(format!(
                        "daemon executor error frame write failed: {write_error}"
                    ));
                }
            }
            Err(payload) => {
                let text = panic_text(payload);
                // `execute_request` owns OutputCapture, whose Drop restores the
                // saved descriptors before this catch boundary can send Error.
                log.line(format!("daemon executor panic: {text}"));
                if let Err(error) = write_job(
                    &job,
                    Frame::Error(format!("daemon request panicked: {text}")),
                ) {
                    log.line(format!("daemon panic frame write failed: {error}"));
                }
            }
        }
        // `flush_file_cache` is a no-op unless this request inserted content,
        // so this preserves the existing merge-on-flush policy while making a
        // completed dirty request durable before the next queue item starts.
        let maintenance = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut state = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.flush();
            state.take_watcher_transitions()
        }));
        match maintenance {
            Ok(transitions) => {
                for transition in transitions {
                    log.line(transition);
                }
            }
            Err(payload) => {
                log.line(format!(
                    "daemon post-request maintenance panic: {}",
                    panic_text(payload)
                ));
            }
        }
        queue.finished();
        if crate::host::interrupt::interrupt_requested() && !cancelled.load(Ordering::Acquire) {
            log.line("daemon interrupt requested shutdown");
            stopping.store(true, Ordering::Release);
            queue.wake();
        }
        if SIGTERM_REQUESTED.load(Ordering::Acquire) {
            log.line("daemon SIGTERM observed by executor");
            stopping.store(true, Ordering::Release);
            queue.wake();
        }
    }
}

fn execute_request(
    job: &Job,
    state: &Arc<Mutex<DaemonState>>,
    log: DaemonLog,
) -> Result<i32, String> {
    let context = Arc::new(RequestContext {
        cwd: PathBuf::from(std::ffi::OsString::from_vec(job.request.cwd.clone())),
        env: job
            .request
            .env
            .iter()
            .map(|(key, value)| (key.clone(), std::ffi::OsString::from_vec(value.clone())))
            .collect(),
        cancel: job.cancel.clone(),
    });
    let _request = crate::invocation::install_request_context(context);
    if job.cancel.load(Ordering::Acquire) {
        return Ok(130);
    }
    let sdkroot = job
        .request
        .env
        .get("SDKROOT")
        .cloned()
        .map(std::ffi::OsString::from_vec)
        .map(std::ffi::OsString::into_string)
        .transpose()
        .map_err(|_| "daemon SDKROOT is not valid UTF-8".to_string())?;
    let _sdkroot = RequestSdkrootGuard::install(sdkroot);
    let mut capture = OutputCapture::install(job.writer.clone(), log)?;
    // The server executes exactly one request at a time.  That invariant makes
    // this temporary process-wide fd swap sound; worker output and JSONL events
    // are relayed before the saved descriptors are restored.
    let mut code = if job.request.argv.first().map(String::as_str) == Some("__daemon-verify") {
        state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .verify(&job.request.argv)?
    } else {
        crate::run_argv_in_process(job.request.argv.clone(), false)
    };
    if job.cancel.load(Ordering::Acquire) {
        code = 130;
    }
    capture.restore()?;
    Ok(code)
}

fn request_stop(
    stopping: &AtomicBool,
    queue: &Queue,
    socket: &Path,
    force: bool,
    history: &Mutex<VecDeque<RequestRecord>>,
    log: &DaemonLog,
) {
    stopping.store(true, Ordering::Release);
    for job in queue.stop_accepting() {
        if let Err(error) = write_job(
            &job,
            Frame::Error("daemon is stopping; queued request was rejected".to_string()),
        ) {
            log.line(format!("queued stop rejection write failed: {error}"));
        }
        let duration_ms = job.submitted_at.elapsed().as_millis();
        push_history(
            history,
            RequestRecord {
                id: job.request.id,
                argv: history_argv(&job.request.argv),
                outcome: "rejected".to_string(),
                code: None,
                duration_ms,
            },
        );
    }
    if force {
        queue.cancel_active();
    }
    queue.wake();
    // The listener is nonblocking, but this wake connection also covers a
    // platform implementation that is blocked in accept while Stop arrives.
    let _ = UnixStream::connect(socket);
}

fn write_job(job: &Job, frame: Frame) -> Result<(), String> {
    proto::write_frame(
        &mut *job
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        &frame,
    )
}

fn history_argv(argv: &[String]) -> Vec<String> {
    argv.iter()
        .filter(|arg| arg.as_str() != "--stream-events")
        .cloned()
        .collect()
}

fn push_history(history: &Mutex<VecDeque<RequestRecord>>, record: RequestRecord) {
    let mut history = history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    history.push_front(record);
    history.truncate(REQUEST_HISTORY_LIMIT);
}

fn panic_text(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

struct OutputCapture {
    stdout_saved: Option<RawFd>,
    stderr_saved: Option<RawFd>,
    stdout: Option<std::thread::JoinHandle<()>>,
    stderr: Option<std::thread::JoinHandle<()>>,
}

impl OutputCapture {
    fn install(writer: Arc<Mutex<UnixStream>>, log: DaemonLog) -> Result<Self, String> {
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = match pipe() {
            Ok(pair) => pair,
            Err(error) => {
                close_fd(stdout_read);
                close_fd(stdout_write);
                return Err(error);
            }
        };
        let stdout_saved = match duplicate(1) {
            Ok(fd) => fd,
            Err(error) => {
                close_fd(stdout_read);
                close_fd(stdout_write);
                close_fd(stderr_read);
                close_fd(stderr_write);
                return Err(error);
            }
        };
        let stderr_saved = match duplicate(2) {
            Ok(fd) => fd,
            Err(error) => {
                close_fd(stdout_saved);
                close_fd(stdout_read);
                close_fd(stdout_write);
                close_fd(stderr_read);
                close_fd(stderr_write);
                return Err(error);
            }
        };
        let mut capture = Self {
            stdout_saved: Some(stdout_saved),
            stderr_saved: Some(stderr_saved),
            stdout: None,
            stderr: None,
        };
        // The daemon's single-flight executor is the invariant that makes
        // this process-global descriptor replacement sound.
        if let Err(error) = replace_fd(stdout_write, 1) {
            close_fd(stdout_read);
            close_fd(stdout_write);
            close_fd(stderr_read);
            close_fd(stderr_write);
            let _ = capture.restore();
            return Err(error);
        }
        close_fd(stdout_write);
        if let Err(error) = replace_fd(stderr_write, 2) {
            close_fd(stderr_read);
            close_fd(stderr_write);
            let _ = capture.restore();
            return Err(error);
        }
        close_fd(stderr_write);
        let stdout_writer = writer.clone();
        capture.stdout = match std::thread::Builder::new()
            .name("buildutil-daemon-stdout".to_string())
            .spawn({
                let log = log.clone();
                move || relay_stdout(stdout_read, stdout_writer, log)
            }) {
            Ok(thread) => Some(thread),
            Err(error) => {
                close_fd(stdout_read);
                close_fd(stderr_read);
                let _ = capture.restore();
                return Err(format!("cannot start daemon stdout relay: {error}"));
            }
        };
        capture.stderr = match std::thread::Builder::new()
            .name("buildutil-daemon-stderr".to_string())
            .spawn(move || relay_bytes(stderr_read, "stderr", writer, log))
        {
            Ok(thread) => Some(thread),
            Err(error) => {
                close_fd(stderr_read);
                let _ = capture.restore();
                return Err(format!("cannot start daemon stderr relay: {error}"));
            }
        };
        Ok(capture)
    }

    fn restore(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Some(saved) = self.stdout_saved.take() {
            if let Err(error) = restore_fd(saved, 1) {
                errors.push(error);
            }
            close_fd(saved);
        }
        if let Some(saved) = self.stderr_saved.take() {
            if let Err(error) = restore_fd(saved, 2) {
                errors.push(error);
            }
            close_fd(saved);
        }
        if let Some(thread) = self.stdout.take() {
            if thread.join().is_err() {
                errors.push("daemon stdout relay panicked".to_string());
            }
        }
        if let Some(thread) = self.stderr.take() {
            if thread.join().is_err() {
                errors.push("daemon stderr relay panicked".to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for OutputCapture {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn relay_stdout(fd: RawFd, writer: Arc<Mutex<UnixStream>>, log: DaemonLog) {
    // SAFETY: `fd` is the read end returned by `pipe`; this thread becomes its
    // unique owner and closes it when the File drops.
    let mut file = unsafe { File::from_raw_fd(fd) };
    const OUTPUT_CHUNK: usize = 256 * 1024;
    let mut read_buffer = [0u8; 64 * 1024];
    let mut pending = Vec::with_capacity(OUTPUT_CHUNK);
    let mut raw_until_newline = false;
    loop {
        let count = match file.read(&mut read_buffer) {
            Ok(count) => count,
            Err(error) => {
                log.line(format!("daemon stdout relay read failed: {error}"));
                break;
            }
        };
        if count == 0 {
            break;
        }
        pending.extend_from_slice(&read_buffer[..count]);
        loop {
            if raw_until_newline {
                if let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                    let bytes = pending.drain(..=end).collect::<Vec<_>>();
                    if !relay_output_chunk(&writer, "stdout", &bytes, &log) {
                        return;
                    }
                    raw_until_newline = false;
                    continue;
                }
                while pending.len() >= OUTPUT_CHUNK {
                    let bytes = pending.drain(..OUTPUT_CHUNK).collect::<Vec<_>>();
                    if !relay_output_chunk(&writer, "stdout", &bytes, &log) {
                        return;
                    }
                }
                break;
            }
            if let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let bytes = pending.drain(..=end).collect::<Vec<_>>();
                let event = std::str::from_utf8(&bytes)
                    .ok()
                    .map(|line| line.trim_end_matches(['\r', '\n']));
                let frame = match event {
                    Some(event) if crate::events::parse_stream_event(event).is_some() => {
                        Frame::Event(event.to_string())
                    }
                    _ => Frame::Output {
                        stream: "stdout".to_string(),
                        bytes,
                    },
                };
                if let Err(error) = proto::write_frame(
                    &mut *writer
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                    &frame,
                ) {
                    log.line(format!("daemon stdout relay frame write failed: {error}"));
                    return;
                }
                continue;
            }
            if pending.len() >= OUTPUT_CHUNK {
                let bytes = pending.drain(..OUTPUT_CHUNK).collect::<Vec<_>>();
                if !relay_output_chunk(&writer, "stdout", &bytes, &log) {
                    return;
                }
                raw_until_newline = true;
                continue;
            }
            break;
        }
    }
    if !pending.is_empty() {
        let _ = relay_output_chunk(&writer, "stdout", &pending, &log);
    }
}

fn relay_output_chunk(
    writer: &Arc<Mutex<UnixStream>>,
    stream: &str,
    bytes: &[u8],
    log: &DaemonLog,
) -> bool {
    if let Err(error) = proto::write_frame(
        &mut *writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        &Frame::Output {
            stream: stream.to_string(),
            bytes: bytes.to_vec(),
        },
    ) {
        log.line(format!("daemon {stream} relay frame write failed: {error}"));
        false
    } else {
        true
    }
}

fn relay_bytes(fd: RawFd, stream: &str, writer: Arc<Mutex<UnixStream>>, log: DaemonLog) {
    // SAFETY: `fd` is the read end returned by `pipe`; this thread becomes its
    // unique owner and closes it when the File drops.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = [0u8; 8192];
    loop {
        let count = match file.read(&mut bytes) {
            Ok(count) => count,
            Err(error) => {
                log.line(format!("daemon {stream} relay read failed: {error}"));
                break;
            }
        };
        if count == 0 {
            break;
        }
        if let Err(error) = proto::write_frame(
            &mut *writer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            &Frame::Output {
                stream: stream.to_string(),
                bytes: bytes[..count].to_vec(),
            },
        ) {
            log.line(format!("daemon {stream} relay frame write failed: {error}"));
            break;
        }
    }
}

fn acquire_start_lock(state_root: &Path) -> Result<File, String> {
    let path = state_root.join("daemon").join("lock");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create daemon directory {}: {e}", parent.display()))?;
        crate::platform::set_mode(parent, 0o700)
            .map_err(|e| format!("cannot secure daemon directory {}: {e}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| format!("cannot open daemon lock {}: {e}", path.display()))?;
    if crate::platform::lock_exclusive(&file, true)
        .map_err(|e| format!("cannot lock daemon startup {}: {e}", path.display()))?
    {
        Ok(file)
    } else {
        Err("daemon already starting or running".to_string())
    }
}

fn prepare_socket_dir(socket: &Path) -> Result<(), String> {
    let dir = socket.parent().ok_or("daemon socket has no parent")?;
    std::fs::create_dir_all(dir).map_err(|e| {
        format!(
            "cannot create daemon socket directory {}: {e}",
            dir.display()
        )
    })?;
    crate::platform::set_mode(dir, 0o700).map_err(|e| {
        format!(
            "cannot secure daemon socket directory {}: {e}",
            dir.display()
        )
    })
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn pipe() -> Result<(RawFd, RawFd), String> {
    let mut fds = [0; 2];
    unsafe extern "C" {
        fn pipe(fds: *mut i32) -> i32;
    }
    // SAFETY: `fds` has room for the two descriptors written by pipe.
    if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("daemon pipe: {}", std::io::Error::last_os_error()));
    }
    if let Err(error) = set_cloexec(fds[0]).and_then(|_| set_cloexec(fds[1])) {
        close_fd(fds[0]);
        close_fd(fds[1]);
        return Err(error);
    }
    Ok((fds[0], fds[1]))
}
fn duplicate(fd: RawFd) -> Result<RawFd, String> {
    unsafe extern "C" {
        fn dup(fd: i32) -> i32;
    }
    // SAFETY: dup only reads the supplied open descriptor.
    let out = unsafe { dup(fd) };
    if out >= 0 {
        if let Err(error) = set_cloexec(out) {
            close_fd(out);
            Err(error)
        } else {
            Ok(out)
        }
    } else {
        Err(format!("daemon dup: {}", std::io::Error::last_os_error()))
    }
}
fn set_cloexec(fd: RawFd) -> Result<(), String> {
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, argument: i32) -> i32;
    }
    // SAFETY: fd is open and fcntl only reads its descriptor flags.
    let flags = unsafe { fcntl(fd, F_GETFD, 0) };
    if flags < 0 {
        return Err(format!(
            "daemon fcntl(F_GETFD): {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fd remains open and the updated flags preserve every existing bit.
    if unsafe { fcntl(fd, F_SETFD, flags | FD_CLOEXEC) } < 0 {
        Err(format!(
            "daemon fcntl(F_SETFD): {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}
fn replace_fd(from: RawFd, to: RawFd) -> Result<(), String> {
    unsafe extern "C" {
        fn dup2(from: i32, to: i32) -> i32;
    }
    // SAFETY: both descriptors are owned by this process; dup2 atomically replaces `to`.
    if unsafe { dup2(from, to) } >= 0 {
        Ok(())
    } else {
        Err(format!("daemon dup2: {}", std::io::Error::last_os_error()))
    }
}
fn restore_fd(from: RawFd, to: RawFd) -> Result<(), String> {
    replace_fd(from, to)
}
fn close_fd(fd: RawFd) {
    unsafe extern "C" {
        fn close(fd: i32) -> i32;
    }
    // SAFETY: every caller passes a descriptor it owns exactly once.
    let _ = unsafe { close(fd) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::net::Shutdown;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn bytes(value: &str) -> Vec<u8> {
        value.as_bytes().to_vec()
    }

    #[test]
    fn socket_path_is_state_root_specific() {
        assert_ne!(
            socket_path(Path::new("/tmp/a")),
            socket_path(Path::new("/tmp/b"))
        );
        assert_eq!(
            socket_path(Path::new("/tmp/a")),
            socket_path(Path::new("/tmp/a"))
        );
    }

    #[test]
    fn request_sdkroot_guard_clears_request_local_value() {
        let slot = Mutex::new(None);
        {
            let _guard = RequestSdkrootGuard::install_in(&slot, Some("/request/sdk".to_string()));
            assert_eq!(
                slot.lock().unwrap().clone(),
                Some(Some("/request/sdk".to_string()))
            );
        }
        assert_eq!(slot.lock().unwrap().clone(), None);
    }

    #[test]
    fn request_history_is_bounded_and_newest_first() {
        let history = Mutex::new(VecDeque::new());
        for index in 0..40 {
            push_history(
                &history,
                RequestRecord {
                    id: index.to_string(),
                    argv: vec!["build".into()],
                    outcome: "exit".into(),
                    code: Some(0),
                    duration_ms: index,
                },
            );
        }
        let history = history.lock().unwrap();
        assert_eq!(history.len(), REQUEST_HISTORY_LIMIT);
        assert_eq!(history.front().unwrap().id, "39");
        assert_eq!(history.back().unwrap().id, "8");
    }

    #[test]
    fn queue_is_fifo_and_single_flight() {
        let queue = Queue::default();
        let (left, _right) = UnixStream::pair().unwrap();
        let writer = Arc::new(Mutex::new(left));
        for name in ["first", "second"] {
            assert!(
                queue
                    .push(Job {
                        request: Request {
                            id: name.into(),
                            argv: vec![name.into()],
                            cwd: bytes("/"),
                            env: Default::default(),
                        },
                        submitted_at: Instant::now(),
                        writer: writer.clone(),
                        cancel: Arc::new(AtomicBool::new(false)),
                        phase: Arc::new(Mutex::new(JobPhase::Queued)),
                    })
                    .is_ok()
            );
        }
        let stop = AtomicBool::new(false);
        assert_eq!(queue.pop(&stop).unwrap().request.argv[0], "first");
        queue.finished();
        assert_eq!(queue.pop(&stop).unwrap().request.argv[0], "second");
    }

    #[test]
    fn graceful_stop_rejects_queued_work_and_force_cancels_active_work() {
        let queue = Queue::default();
        let (left, _right) = UnixStream::pair().unwrap();
        let queued_cancel = Arc::new(AtomicBool::new(false));
        assert!(
            queue
                .push(Job {
                    request: Request {
                        id: "queued".into(),
                        argv: vec!["build".into()],
                        cwd: bytes("/"),
                        env: BTreeMap::new(),
                    },
                    submitted_at: Instant::now(),
                    writer: Arc::new(Mutex::new(left)),
                    cancel: queued_cancel,
                    phase: Arc::new(Mutex::new(JobPhase::Queued)),
                })
                .is_ok()
        );
        assert_eq!(queue.stop_accepting().len(), 1);

        let active_queue = Queue::default();
        let (left, _right) = UnixStream::pair().unwrap();
        let active_cancel = Arc::new(AtomicBool::new(false));
        let phase = Arc::new(Mutex::new(JobPhase::Queued));
        assert!(
            active_queue
                .push(Job {
                    request: Request {
                        id: "active".into(),
                        argv: vec!["build".into()],
                        cwd: bytes("/"),
                        env: BTreeMap::new(),
                    },
                    submitted_at: Instant::now(),
                    writer: Arc::new(Mutex::new(left)),
                    cancel: active_cancel.clone(),
                    phase: phase.clone(),
                })
                .is_ok()
        );
        let stop = AtomicBool::new(false);
        let _job = active_queue.pop(&stop).unwrap();
        *phase.lock().unwrap() = JobPhase::Running;
        active_queue.cancel_active();
        assert!(active_cancel.load(Ordering::Acquire));
        crate::host::interrupt::clear_interrupt();
    }

    #[test]
    fn client_disconnect_cancellation_sets_the_request_token() {
        crate::host::interrupt::clear_interrupt();
        let cancel = AtomicBool::new(false);
        let phase = Mutex::new(JobPhase::Queued);
        // The client EOF branch and explicit Cancel frame both call this
        // helper. A queued request needs only its request-local token.
        cancel_job(&cancel, &phase);
        assert!(cancel.load(Ordering::Acquire));
        assert!(!crate::host::interrupt::interrupt_requested());

        cancel.store(false, Ordering::Release);
        *phase.lock().unwrap() = JobPhase::Running;
        cancel_job(&cancel, &phase);
        assert!(cancel.load(Ordering::Acquire));
        assert!(crate::host::interrupt::interrupt_requested());
        crate::host::interrupt::clear_interrupt();
    }

    #[test]
    fn listener_connections_preserve_queue_order() {
        let path =
            std::env::temp_dir().join(format!(
                "buildutil-daemon-queue-{}.sock",
                std::process::id()
            ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let queue = Arc::new(Queue::default());
        let server_queue = queue.clone();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).unwrap();
                let name = if byte[0] == b'a' { "first" } else { "second" };
                assert!(
                    server_queue
                        .push(Job {
                            request: Request {
                                id: name.into(),
                                argv: vec![name.into()],
                                cwd: bytes("/"),
                                env: Default::default(),
                            },
                            submitted_at: Instant::now(),
                            writer: Arc::new(Mutex::new(stream)),
                            cancel: Arc::new(AtomicBool::new(false)),
                            phase: Arc::new(Mutex::new(JobPhase::Queued)),
                        })
                        .is_ok()
                );
            }
        });
        for byte in [b'a', b'b'] {
            let mut client = UnixStream::connect(&path).unwrap();
            client.write_all(&[byte]).unwrap();
        }
        server.join().unwrap();
        let stop = AtomicBool::new(false);
        assert_eq!(queue.pop(&stop).unwrap().request.argv[0], "first");
        queue.finished();
        assert_eq!(queue.pop(&stop).unwrap().request.argv[0], "second");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn handshake_mismatch_is_detectable_for_rotation() {
        let mut expected = Handshake {
            protocol_version: 1,
            binary_identity: "a".into(),
            repo_root: bytes("/repo"),
            state_root: bytes("/state"),
        };
        assert!(handshake_matches(&expected, &expected));
        expected.binary_identity = "b".into();
        assert!(!handshake_matches(
            &expected,
            &Handshake {
                protocol_version: 1,
                binary_identity: "a".into(),
                repo_root: bytes("/repo"),
                state_root: bytes("/state")
            }
        ));
    }

    #[test]
    fn queued_cancellation_does_not_interrupt_the_running_request() {
        crate::host::interrupt::clear_interrupt();
        let cancel = AtomicBool::new(false);
        let queued = Mutex::new(JobPhase::Queued);
        cancel_job(&cancel, &queued);
        assert!(cancel.load(Ordering::Acquire));
        assert!(!crate::host::interrupt::interrupt_requested());

        let running_cancel = AtomicBool::new(false);
        let running = Mutex::new(JobPhase::Running);
        cancel_job(&running_cancel, &running);
        assert!(crate::host::interrupt::interrupt_requested());
        crate::host::interrupt::clear_interrupt();

        let finished_cancel = AtomicBool::new(false);
        let finished = Mutex::new(JobPhase::Finished);
        cancel_job(&finished_cancel, &finished);
        assert!(finished_cancel.load(Ordering::Acquire));
        assert!(!crate::host::interrupt::interrupt_requested());
    }

    #[test]
    fn stdout_relay_chunks_a_giant_line_below_the_frame_limit() {
        let (read_fd, write_fd) = pipe().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let log_path = std::env::temp_dir().join(format!(
            "buildutil-daemon-relay-{}-{}.log",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let log = DaemonLog {
            file: Arc::new(Mutex::new(File::create(&log_path).unwrap())),
        };
        let relay =
            std::thread::spawn(move || relay_stdout(read_fd, Arc::new(Mutex::new(server)), log));
        let payload = vec![b'x'; 1024 * 1024 + 123];
        let expected = payload.len();
        let writer = std::thread::spawn(move || {
            // SAFETY: write_fd is the uniquely-owned pipe write end.
            let mut file = unsafe { File::from_raw_fd(write_fd) };
            file.write_all(&payload).unwrap();
        });
        let mut received = 0;
        while received < expected {
            match proto::read_frame(&mut client).unwrap().unwrap() {
                Frame::Output { stream, bytes } => {
                    assert_eq!(stream, "stdout");
                    assert!(bytes.len() <= 256 * 1024);
                    received += bytes.len();
                }
                frame => panic!("unexpected relay frame: {frame:?}"),
            }
        }
        writer.join().unwrap();
        relay.join().unwrap();
        assert_eq!(received, expected);
        let _ = std::fs::remove_file(log_path);
    }

    #[test]
    fn handler_accepts_a_request_after_the_handshake() {
        let root = std::env::temp_dir().join(format!(
            "buildutil-daemon-handler-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let log = DaemonLog {
            file: Arc::new(Mutex::new(File::create(root.join("daemon.log")).unwrap())),
        };
        let expected = Handshake {
            protocol_version: proto::PROTOCOL_VERSION,
            binary_identity: "test".into(),
            repo_root: bytes("/repo"),
            state_root: bytes("/state"),
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        let queue = Arc::new(Queue::default());
        let handler_queue = queue.clone();
        let handler_expected = expected.clone();
        let handler_state = Arc::new(Mutex::new(
            DaemonState::new(root.clone(), root.join("state")).unwrap(),
        ));
        let socket = root.join("socket");
        let handler = std::thread::spawn(move || {
            handle_connection(
                server,
                handler_expected,
                handler_queue,
                Arc::new(AtomicBool::new(false)),
                socket,
                handler_state,
                Arc::new(Mutex::new(VecDeque::new())),
                log,
            )
        });
        proto::write_frame(&mut client, &Frame::Handshake(expected)).unwrap();
        assert!(matches!(
            proto::read_frame(&mut client).unwrap(),
            Some(Frame::Handshake(_))
        ));
        proto::write_frame(
            &mut client,
            &Frame::Request(Request {
                id: "handler-request".into(),
                argv: vec!["build".into(), "default".into()],
                cwd: bytes("/repo"),
                env: BTreeMap::from([("PATH".into(), bytes("/usr/bin:/bin"))]),
            }),
        )
        .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        handler.join().unwrap();
        let stop = AtomicBool::new(false);
        assert_eq!(
            queue.pop(&stop).unwrap().request.argv,
            vec!["build".to_string(), "default".to_string()]
        );
        crate::host::interrupt::clear_interrupt();
        let _ = std::fs::remove_dir_all(root);
    }
}
