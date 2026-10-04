//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — host: signal/interrupt plumbing for long-running backends
//!
//! Both container runs and WSL runs need cooperative interrupt handling:
//! SIGINT / SIGTERM (and SIGHUP on Unix) flip a flag the run loop polls, and
//! a side thread takes a per-run cleanup action (kill the container, stop
//! the recorded child). The C runtime's signal() exists on every host;
//! stopping the child is POSIX kill() on Unix and the platform's process
//! termination on Windows.

use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
const SIGHUP_NUM: c_int = 1;
const SIGINT_NUM: c_int = 2;
const SIGTERM_NUM: c_int = 15;
const SIG_ERR: usize = usize::MAX;

/// The signals an interrupt arrives as. The Windows C runtime knows only
/// SIGINT and SIGTERM of these, and hands any other number to its
/// invalid-parameter handler.
#[cfg(unix)]
const INTERRUPT_SIGNALS: [c_int; 3] = [SIGINT_NUM, SIGTERM_NUM, SIGHUP_NUM];
#[cfg(windows)]
const INTERRUPT_SIGNALS: [c_int; 2] = [SIGINT_NUM, SIGTERM_NUM];

static INTERRUPT_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_STATE: Mutex<SignalState> = Mutex::new(SignalState {
    users: 0,
    previous: [(0, SIG_ERR); 3],
});

struct SignalState {
    users: usize,
    previous: [(c_int, usize); 3],
}

unsafe extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
    #[cfg(unix)]
    fn kill(pid: c_int, sig: c_int) -> c_int;
}

extern "C" fn buildutil_interrupt_handler(_signum: c_int) {
    INTERRUPT_REQUESTED.store(true, Ordering::SeqCst);
}

pub(crate) struct InterruptGuard;

impl InterruptGuard {
    pub(crate) fn install() -> Self {
        // Do not clear a cancellation that arrived immediately before a child
        // backend installed its cleanup guard. The daemon executor owns the
        // single reset point at request start.
        let mut state = SIGNAL_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.users == 0 {
            let handler = buildutil_interrupt_handler as *const () as usize;
            for (idx, sig) in INTERRUPT_SIGNALS.into_iter().enumerate() {
                // SAFETY: `buildutil_interrupt_handler` has the C signal-handler
                // ABI. The final guard restores this exact disposition.
                let old = unsafe { signal(sig, handler) };
                state.previous[idx] = (sig, old);
            }
        }
        state.users += 1;
        InterruptGuard
    }

    pub(crate) fn was_interrupted(&self) -> bool {
        INTERRUPT_REQUESTED.load(Ordering::SeqCst)
    }
}

/// While an interactive child holds the terminal, Ctrl-C and Ctrl-\ belong
/// to the child: this process records them instead of dying, as `system(3)`
/// does, so it outlives the child and restores the terminal state. The
/// handlers are caught, not ignored, so the child starts with the default
/// dispositions after exec.
#[cfg(unix)]
pub(crate) struct TerminalSignalsToChild {
    previous: [(c_int, usize); 2],
}

#[cfg(unix)]
const SIGQUIT_NUM: c_int = 3;

#[cfg(unix)]
extern "C" fn buildutil_deferred_signal(_signum: c_int) {}

#[cfg(unix)]
impl TerminalSignalsToChild {
    pub(crate) fn install() -> Self {
        let mut previous = [(0, SIG_ERR); 2];
        for (idx, sig) in [SIGINT_NUM, SIGQUIT_NUM].into_iter().enumerate() {
            // SAFETY: the handler has the C signal-handler ABI and does
            // nothing; drop restores the returned disposition.
            let old = unsafe { signal(sig, buildutil_deferred_signal as *const () as usize) };
            previous[idx] = (sig, old);
        }
        TerminalSignalsToChild { previous }
    }
}

#[cfg(unix)]
impl Drop for TerminalSignalsToChild {
    fn drop(&mut self) {
        for (sig, handler) in self.previous {
            if handler != SIG_ERR {
                // SAFETY: restores the disposition `install` replaced.
                unsafe {
                    signal(sig, handler);
                }
            }
        }
    }
}

/// Ask a child process to stop, as a terminating signal to this process
/// would have.
#[cfg(unix)]
pub(crate) fn forward_termination(pid: u32) {
    // SAFETY: kill with a positive pid signals exactly that process.
    unsafe {
        kill(pid as c_int, SIGTERM_NUM);
    }
}

/// Cooperative cancellation entry point for the daemon control socket.  The
/// active backend's existing cleanup thread observes this same flag and kills
/// the request-owned wrapper/process group before the request returns.
pub(crate) fn request_interrupt() {
    INTERRUPT_REQUESTED.store(true, Ordering::SeqCst);
    crate::platform::interrupt_request_process_group();
}

pub(crate) fn clear_interrupt() {
    INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);
    crate::platform::clear_request_process_group_interrupt();
}

pub(crate) fn interrupt_requested() -> bool {
    INTERRUPT_REQUESTED.load(Ordering::SeqCst)
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        let mut state = SIGNAL_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.users = state.users.saturating_sub(1);
        if state.users == 0 {
            for (sig, handler) in state.previous {
                if handler != SIG_ERR {
                    // SAFETY: `handler` is the exact process signal
                    // disposition returned by the first guard's installation.
                    unsafe {
                        signal(sig, handler);
                    }
                }
            }
            state.previous = [(0, SIG_ERR); 3];
        }
    }
}

pub(crate) struct InterruptCleanup {
    done: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Stop the process a run started, as a terminating signal would.
fn stop_child(pid: u32) {
    #[cfg(unix)]
    // SAFETY: `pid` comes from `std::process::Child::id` for the process
    // owned by this run; kill with a positive pid signals exactly it.
    unsafe {
        kill(pid as c_int, SIGTERM_NUM);
    }
    #[cfg(windows)]
    crate::platform::terminate_process_group(pid);
}

impl InterruptCleanup {
    pub(crate) fn start(child_pid: u32, mut cleanup: Box<dyn FnMut() + Send>) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let thread_done = done.clone();
        let thread = std::thread::spawn(move || {
            while !thread_done.load(Ordering::Acquire) {
                if INTERRUPT_REQUESTED.load(Ordering::Acquire) {
                    cleanup();
                    stop_child(child_pid);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        });
        InterruptCleanup {
            done,
            thread: Some(thread),
        }
    }

    pub(crate) fn finish(mut self) -> Result<(), String> {
        self.done.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "interrupt cleanup thread panicked".to_string())?;
        }
        Ok(())
    }
}

impl Drop for InterruptCleanup {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn container_interrupt_cleanup(
    runtime: &str,
    container: &str,
) -> Box<dyn FnMut() + Send> {
    let runtime = runtime.to_string();
    let container = container.to_string();
    Box::new(move || {
        let _ = crate::invocation::command(&runtime)
            .args(["rm", "-f", &container])
            .stdout(crate::invocation::Io::Null)
            .stderr(crate::invocation::Io::Null)
            .status();
    })
}
