// SPDX-License-Identifier: GPL-2.0-only
//! macOS FSEvents backend.  Paths are watched as individual file events; any
//! FSEvents loss/coverage flag is surfaced as an uncertainty instead of being
//! interpreted as a normal invalidation.

use super::watch::{self, PendingEvents, WatchEvent, Watcher};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::raw::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFArrayRef = *const c_void;
type CFRunLoopRef = *const c_void;

#[repr(C)]
struct FSEventStreamOpaque {
    _private: [u8; 0],
}

type FSEventStreamRef = *mut FSEventStreamOpaque;
type FSEventStreamEventId = u64;
type FSEventStreamEventFlags = u32;

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_FSEVENT_STREAM_EVENT_ID_SINCE_NOW: FSEventStreamEventId = u64::MAX;
const K_FSEVENT_STREAM_CREATE_FLAG_USE_CF_TYPES: u32 = 0x0000_0001;
const K_FSEVENT_STREAM_CREATE_FLAG_WATCH_ROOT: u32 = 0x0000_0004;
const K_FSEVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x0000_0010;
const FSEVENT_LATENCY_SECONDS: f64 = 0.3;
const K_FSEVENT_STREAM_EVENT_FLAG_MUST_SCAN_SUBDIRS: u32 = 0x0000_0001;
const K_FSEVENT_STREAM_EVENT_FLAG_USER_DROPPED: u32 = 0x0000_0002;
const K_FSEVENT_STREAM_EVENT_FLAG_KERNEL_DROPPED: u32 = 0x0000_0004;
const K_FSEVENT_STREAM_EVENT_FLAG_EVENT_IDS_WRAPPED: u32 = 0x0000_0008;
const K_FSEVENT_STREAM_EVENT_FLAG_ROOT_CHANGED: u32 = 0x0000_0020;
const K_FSEVENT_STREAM_EVENT_FLAG_UNMOUNT: u32 = 0x0000_0080;

#[repr(C)]
struct CFArrayCallBacks {
    version: isize,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

#[repr(C)]
struct FSEventStreamContext {
    version: isize,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

type FSEventStreamCallback = extern "C" fn(
    FSEventStreamRef,
    *mut c_void,
    usize,
    *const c_void,
    *const FSEventStreamEventFlags,
    *const FSEventStreamEventId,
);

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: *const c_void,
        callback: FSEventStreamCallback,
        context: *mut FSEventStreamContext,
        paths_to_watch: CFArrayRef,
        since_when: FSEventStreamEventId,
        latency: f64,
        flags: u32,
    ) -> FSEventStreamRef;
    fn FSEventStreamScheduleWithRunLoop(
        stream: FSEventStreamRef,
        run_loop: CFRunLoopRef,
        run_loop_mode: CFStringRef,
    );
    fn FSEventStreamStart(stream: FSEventStreamRef) -> u8;
    fn FSEventStreamStop(stream: FSEventStreamRef);
    fn FSEventStreamInvalidate(stream: FSEventStreamRef);
    fn FSEventStreamRelease(stream: FSEventStreamRef);
    fn FSEventStreamSetExclusionPaths(stream: FSEventStreamRef, paths: CFArrayRef) -> u8;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: CFArrayCallBacks;
    static kCFRunLoopDefaultMode: CFStringRef;
    fn CFStringCreateWithCString(
        alloc: *const c_void,
        c_str: *const std::ffi::c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFStringGetCString(
        value: CFStringRef,
        buffer: *mut std::ffi::c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        count: isize,
        callbacks: *const CFArrayCallBacks,
    ) -> CFArrayRef;
    fn CFArrayGetValueAtIndex(array: CFArrayRef, index: isize) -> *const c_void;
    fn CFRelease(value: CFTypeRef);
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRunInMode(mode: CFStringRef, seconds: f64, return_after_source_handled: u8) -> i32;
    fn CFRunLoopStop(run_loop: CFRunLoopRef);
}

struct CallbackState {
    pending: Arc<PendingEvents>,
}

pub struct FseventsWatcher {
    pending: Arc<PendingEvents>,
    stopping: Arc<AtomicBool>,
    run_loop: Arc<Mutex<usize>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    startup_diagnostics: Vec<String>,
}

struct StreamStartup {
    diagnostics: Vec<String>,
    exclusion_installed: bool,
}

impl FseventsWatcher {
    pub fn start(
        repo_root: &Path,
        state_root: &Path,
        structural_fallback: bool,
    ) -> Result<Self, String> {
        let repo_root = watch::normalize_path(repo_root);
        let (roots, exclusions, root_files) = if structural_fallback {
            structural_roots(&repo_root, state_root)?
        } else {
            (
                vec![repo_root.clone()],
                watch::kernel_exclusion_paths(&repo_root, state_root),
                Vec::new(),
            )
        };
        let initial_roots = roots.clone();
        let initial_root_files = root_files.clone();
        let roots = c_paths(&roots, "watch root")?;
        let exclusions = c_paths(
            &exclusions.into_iter().take(8).collect::<Vec<_>>(),
            "exclusion",
        )?;
        let pending = Arc::new(PendingEvents::default());
        let stopping = Arc::new(AtomicBool::new(false));
        let run_loop = Arc::new(Mutex::new(0usize));
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let thread_pending = pending.clone();
        let thread_stopping = stopping.clone();
        let thread_run_loop = run_loop.clone();
        let thread = std::thread::Builder::new()
            .name("buildutil-fsevents".to_string())
            .spawn(move || {
                run_stream(
                    roots,
                    exclusions,
                    thread_pending,
                    thread_stopping,
                    thread_run_loop,
                    started_tx,
                )
            })
            .map_err(|e| format!("cannot start FSEvents thread: {e}"))?;
        // This receive is the installation barrier. The worker only signals
        // after it has scheduled and started the stream on its own run loop,
        // so callers cannot mutate the watched tree before FSEvents accepts
        // events for it.
        match started_rx.recv() {
            Ok(Ok(startup)) => {
                if !structural_fallback && !startup.exclusion_installed {
                    stopping.store(true, Ordering::Release);
                    let current = *run_loop
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if current != 0 {
                        // SAFETY: the worker published this live run loop
                        // before sending its startup result.
                        unsafe { CFRunLoopStop(current as CFRunLoopRef) };
                    }
                    let _ = thread.join();
                    let mut fallback = Self::start(&repo_root, state_root, true)?;
                    fallback
                        .startup_diagnostics
                        .splice(0..0, startup.diagnostics);
                    return Ok(fallback);
                }
                let mut threads = vec![thread];
                let mut diagnostics = startup.diagnostics;
                if structural_fallback {
                    let monitor = start_top_level_monitor(
                        repo_root.clone(),
                        root_files,
                        pending.clone(),
                        stopping.clone(),
                    );
                    let (root_thread, line) = match monitor {
                        Ok(monitor) => monitor,
                        Err(error) => {
                            stopping.store(true, Ordering::Release);
                            let current = *run_loop
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if current != 0 {
                                // SAFETY: the stream worker published this run loop.
                                unsafe { CFRunLoopStop(current as CFRunLoopRef) };
                            }
                            for thread in threads {
                                let _ = thread.join();
                            }
                            return Err(error);
                        }
                    };
                    threads.push(root_thread);
                    diagnostics.push(line);
                    match structural_roots(&repo_root, state_root) {
                        Ok((current_roots, _, current_root_files))
                            if current_roots == initial_roots
                                && current_root_files == initial_root_files => {}
                        Ok(_) => pending.push(WatchEvent::Uncertain(format!(
                                "FSEvents structural fallback top-level scope changed during installation at {}",
                                repo_root.display()
                            ))),
                        Err(error) => pending.push(WatchEvent::Uncertain(error)),
                    }
                }
                Ok(Self {
                    pending,
                    stopping,
                    run_loop,
                    threads,
                    startup_diagnostics: diagnostics,
                })
            }
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err("FSEvents thread exited before initialization".to_string())
            }
        }
    }

    fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let run_loop = *self
            .run_loop
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if run_loop != 0 {
            // SAFETY: the FSEvents worker stored this live CFRunLoopRef before
            // reporting readiness and clears it only after the loop returns.
            unsafe { CFRunLoopStop(run_loop as CFRunLoopRef) };
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Watcher for FseventsWatcher {
    fn drain(&mut self) -> Vec<WatchEvent> {
        self.pending.take()
    }

    fn shutdown(&mut self) {
        self.stop();
    }

    fn platform_name(&self) -> &'static str {
        "fsevents"
    }

    fn startup_diagnostics(&self) -> &[String] {
        &self.startup_diagnostics
    }

    fn quiesce_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(350)
    }
}

impl Drop for FseventsWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn c_paths(paths: &[PathBuf], kind: &str) -> Result<Vec<CString>, String> {
    paths
        .iter()
        .map(|path| {
            let text = path
                .to_str()
                .ok_or_else(|| format!("FSEvents {kind} is not UTF-8: {}", path.display()))?;
            CString::new(text.as_bytes())
                .map_err(|_| format!("FSEvents {kind} contains NUL: {}", path.display()))
        })
        .collect()
}

fn c_path_list(paths: &[CString]) -> String {
    paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(", ")
}

fn structural_roots(
    repo_root: &Path,
    state_root: &Path,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>), String> {
    let state_root = watch::normalize_path(state_root);
    let mut roots = Vec::new();
    let mut root_files = Vec::new();
    for entry in std::fs::read_dir(repo_root)
        .map_err(|e| format!("cannot enumerate FSEvents top-level fallback: {e}"))?
    {
        let entry = entry.map_err(|e| format!("cannot read FSEvents top-level entry: {e}"))?;
        let path = watch::normalize_path(&entry.path());
        let file_type = entry.file_type().map_err(|e| {
            format!(
                "cannot stat FSEvents top-level entry {}: {e}",
                path.display()
            )
        })?;
        let name = entry.file_name();
        if state_root != path && state_root.starts_with(&path) {
            return Err(format!(
                "FSEvents structural fallback cannot isolate nested state root {} beneath {}",
                state_root.display(),
                path.display()
            ));
        }
        let excluded = name.as_bytes() == b".buildutil" || state_root == path;
        if file_type.is_dir() {
            if !excluded {
                roots.push(path);
            }
        } else if !excluded {
            root_files.push(path);
        }
    }
    roots.sort();
    root_files.sort();
    Ok((roots, Vec::new(), root_files))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KEvent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: *mut c_void,
}

#[repr(C)]
struct Timespec {
    tv_sec: std::ffi::c_long,
    tv_nsec: std::ffi::c_long,
}

unsafe extern "C" {
    fn kqueue() -> i32;
    fn kevent(
        queue: i32,
        changes: *const KEvent,
        change_count: i32,
        events: *mut KEvent,
        event_count: i32,
        timeout: *const Timespec,
    ) -> i32;
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
}

const O_EVTONLY: i32 = 0x0000_8000;
const EVFILT_VNODE: i16 = -4;
const EV_ADD: u16 = 0x0001;
const EV_ENABLE: u16 = 0x0004;
const EV_CLEAR: u16 = 0x0020;
const NOTE_DELETE: u32 = 0x0000_0001;
const NOTE_WRITE: u32 = 0x0000_0002;
const NOTE_EXTEND: u32 = 0x0000_0004;
const NOTE_ATTRIB: u32 = 0x0000_0008;
const NOTE_LINK: u32 = 0x0000_0010;
const NOTE_RENAME: u32 = 0x0000_0020;
const NOTE_REVOKE: u32 = 0x0000_0040;
const VNODE_FLAGS: u32 =
    NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE;

fn start_top_level_monitor(
    repo_root: PathBuf,
    root_files: Vec<PathBuf>,
    pending: Arc<PendingEvents>,
    stopping: Arc<AtomicBool>,
) -> Result<(std::thread::JoinHandle<()>, String), String> {
    let count = root_files.len();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("buildutil-fsevents-top-level".to_string())
        .spawn(move || run_top_level_monitor(repo_root, root_files, pending, stopping, started_tx))
        .map_err(|e| format!("cannot start FSEvents top-level monitor: {e}"))?;
    match started_rx.recv() {
        Ok(Ok(())) => Ok((
            thread,
            format!("FSEvents structural fallback active: kqueue root + {count} root files"),
        )),
        Ok(Err(error)) => {
            let _ = thread.join();
            Err(error)
        }
        Err(_) => {
            let _ = thread.join();
            Err("FSEvents top-level monitor exited before initialization".to_string())
        }
    }
}

fn run_top_level_monitor(
    repo_root: PathBuf,
    root_files: Vec<PathBuf>,
    pending: Arc<PendingEvents>,
    stopping: Arc<AtomicBool>,
    started: mpsc::SyncSender<Result<(), String>>,
) {
    // SAFETY: kqueue has no Rust-side preconditions and returns an owned fd.
    let queue = unsafe { kqueue() };
    if queue < 0 {
        let _ = started.send(Err(format!(
            "cannot create top-level kqueue: {}",
            std::io::Error::last_os_error()
        )));
        return;
    }
    let mut watched = BTreeMap::new();
    let mut paths = Vec::with_capacity(root_files.len() + 1);
    paths.push(repo_root.clone());
    paths.extend(root_files);
    for path in paths {
        let c_path = match CString::new(path.as_os_str().as_bytes()) {
            Ok(path) => path,
            Err(_) => {
                let _ = started.send(Err(format!(
                    "top-level watch path contains NUL: {}",
                    path.display()
                )));
                close_kqueue(queue, &watched);
                return;
            }
        };
        // SAFETY: c_path is NUL terminated and O_EVTONLY needs no mode argument.
        let fd = unsafe { open(c_path.as_ptr(), O_EVTONLY) };
        if fd < 0 {
            let _ = started.send(Err(format!(
                "cannot open top-level watch path {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
            close_kqueue(queue, &watched);
            return;
        }
        let change = KEvent {
            ident: fd as usize,
            filter: EVFILT_VNODE,
            flags: EV_ADD | EV_ENABLE | EV_CLEAR,
            fflags: VNODE_FLAGS,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: queue and fd are open; change points to one initialized event.
        if unsafe { kevent(queue, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
            // SAFETY: fd was opened above and is not yet in watched.
            let _ = unsafe { close(fd) };
            let _ = started.send(Err(format!(
                "cannot register top-level watch {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
            close_kqueue(queue, &watched);
            return;
        }
        watched.insert(fd, path);
    }
    if started.send(Ok(())).is_err() {
        stopping.store(true, Ordering::Release);
    }
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let mut events = [KEvent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }; 16];
    while !stopping.load(Ordering::Acquire) {
        // SAFETY: events is writable for 16 entries and timeout is initialized.
        let count = unsafe {
            kevent(
                queue,
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as i32,
                &timeout,
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            pending.push(WatchEvent::Uncertain(format!(
                "top-level kqueue failed: {error}"
            )));
            break;
        }
        let mut batch = Vec::with_capacity(count as usize);
        for event in &events[..count as usize] {
            let Some(path) = watched.get(&(event.ident as i32)) else {
                batch.push(WatchEvent::Uncertain(
                    "top-level kqueue returned an unknown fd".to_string(),
                ));
                continue;
            };
            if path == &repo_root {
                batch.push(WatchEvent::Uncertain(format!(
                    "FSEvents structural fallback top-level listing changed at {}",
                    repo_root.display()
                )));
            } else {
                batch.push(WatchEvent::Path(path.clone()));
                if event.fflags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE) != 0 {
                    batch.push(WatchEvent::Uncertain(format!(
                        "FSEvents structural fallback root file watch changed identity at {}",
                        path.display()
                    )));
                }
            }
        }
        pending.push_batch(batch);
    }
    close_kqueue(queue, &watched);
}

fn close_kqueue(queue: i32, watched: &BTreeMap<i32, PathBuf>) {
    for fd in watched.keys() {
        // SAFETY: each fd is owned exactly once by this monitor.
        let _ = unsafe { close(*fd) };
    }
    // SAFETY: queue is the owned kqueue descriptor.
    let _ = unsafe { close(queue) };
}

fn run_stream(
    roots: Vec<CString>,
    exclusions: Vec<CString>,
    pending: Arc<PendingEvents>,
    stopping: Arc<AtomicBool>,
    run_loop_slot: Arc<Mutex<usize>>,
    started: mpsc::SyncSender<Result<StreamStartup, String>>,
) {
    if roots.is_empty() {
        let _ = started.send(Ok(StreamStartup {
            diagnostics: vec![
                "FSEvents structural fallback has no recursive top-level directories".to_string(),
            ],
            exclusion_installed: true,
        }));
        while !stopping.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        return;
    }
    let mut root_strings = Vec::with_capacity(roots.len());
    for root in &roots {
        // SAFETY: root is a valid NUL-terminated UTF-8 CString for this call;
        // CoreFoundation returns an owned reference on success.
        let string = unsafe {
            CFStringCreateWithCString(std::ptr::null(), root.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        };
        if string.is_null() {
            for value in root_strings {
                // SAFETY: every value was created and is owned by this worker.
                unsafe { CFRelease(value) };
            }
            let _ = started.send(Err("cannot create FSEvents watch CFString".to_string()));
            return;
        }
        root_strings.push(string);
    }
    // SAFETY: values remains live for this call; the standard CF callbacks
    // retain the referenced CFString for the returned array.
    let paths = unsafe {
        CFArrayCreate(
            std::ptr::null(),
            root_strings.as_ptr(),
            root_strings.len() as isize,
            std::ptr::addr_of!(kCFTypeArrayCallBacks),
        )
    };
    if paths.is_null() {
        for value in root_strings {
            // SAFETY: every value is an owned CFString reference.
            unsafe { CFRelease(value) };
        }
        let _ = started.send(Err("cannot create FSEvents path array".to_string()));
        return;
    }
    let state = Box::into_raw(Box::new(CallbackState { pending }));
    let mut context = FSEventStreamContext {
        version: 0,
        info: state.cast(),
        retain: std::ptr::null(),
        release: std::ptr::null(),
        copy_description: std::ptr::null(),
    };
    // SAFETY: FSEventStreamCreate copies `context` during this call. Its
    // `info` member points at CallbackState, which remains allocated until the
    // stream is stopped, invalidated, and released below.
    let stream = unsafe {
        FSEventStreamCreate(
            std::ptr::null(),
            event_callback,
            &mut context,
            paths,
            K_FSEVENT_STREAM_EVENT_ID_SINCE_NOW,
            FSEVENT_LATENCY_SECONDS,
            K_FSEVENT_STREAM_CREATE_FLAG_USE_CF_TYPES
                | K_FSEVENT_STREAM_CREATE_FLAG_FILE_EVENTS
                | K_FSEVENT_STREAM_CREATE_FLAG_WATCH_ROOT,
        )
    };
    if stream.is_null() {
        // SAFETY: all three values are still uniquely owned by this worker.
        unsafe {
            drop(Box::from_raw(state));
            CFRelease(paths);
            for value in root_strings {
                CFRelease(value);
            }
        }
        let _ = started.send(Err("cannot create FSEvents stream".to_string()));
        return;
    }
    // Exclusions are an accelerator for queue capacity, not correctness. If
    // CoreServices rejects them, the stream remains valid and dispatch-level
    // filtering still ignores daemon-owned paths.
    let exclusion_result =
        (!exclusions.is_empty()).then(|| set_exclusion_paths(stream, &exclusions));
    let exclusion_installed = exclusion_result.unwrap_or(true);
    let root_list = c_path_list(&roots);
    let exclusion_list = c_path_list(&exclusions);
    // SAFETY: this worker owns the stream and schedules it on its current
    // run loop, using the framework-provided default run-loop mode.
    let current_run_loop = unsafe { CFRunLoopGetCurrent() };
    // SAFETY: stream and run loop remain live until CFRunLoopRun returns.
    unsafe { FSEventStreamScheduleWithRunLoop(stream, current_run_loop, kCFRunLoopDefaultMode) };
    // SAFETY: stream is a newly-created, scheduled FSEvent stream.
    if unsafe { FSEventStreamStart(stream) } == 0 {
        // SAFETY: stream has not started callbacks, so immediate teardown is safe.
        unsafe {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            drop(Box::from_raw(state));
            CFRelease(paths);
            for value in root_strings {
                CFRelease(value);
            }
        }
        let _ = started.send(Err("cannot start FSEvents stream".to_string()));
        return;
    }
    *run_loop_slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = current_run_loop as usize;
    if started
        .send(Ok(StreamStartup {
            diagnostics: vec![format!(
                "FSEvents stream start roots=[{root_list}] exclusions=[{exclusion_list}] SetExclusionPaths={} latency={FSEVENT_LATENCY_SECONDS:.3}s ordering=create->exclude->schedule->start",
                exclusion_result
                    .map(|result| result.to_string())
                    .unwrap_or_else(|| "not-called(empty)".to_string())
            )],
            exclusion_installed,
        }))
        .is_err()
    {
        stopping.store(true, Ordering::Release);
    }
    while !stopping.load(Ordering::Acquire) {
        // SAFETY: this thread owns the scheduled CoreFoundation run loop. A
        // bounded mode run closes the stop-before-run race without leaving a
        // stream alive after shutdown.
        unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 0) };
    }
    // SAFETY: no more callbacks are allowed after stop/invalidate. The worker
    // then releases every owned CoreFoundation reference and callback state.
    unsafe {
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        drop(Box::from_raw(state));
        CFRelease(paths);
        for value in root_strings {
            CFRelease(value);
        }
    }
    *run_loop_slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = 0;
}

fn set_exclusion_paths(stream: FSEventStreamRef, exclusions: &[CString]) -> bool {
    if exclusions.is_empty() {
        return true;
    }
    let mut strings = Vec::with_capacity(exclusions.len());
    for exclusion in exclusions {
        // SAFETY: exclusion is a valid NUL-terminated UTF-8 CString for this
        // call. CoreFoundation returns an owned reference on success.
        let value = unsafe {
            CFStringCreateWithCString(
                std::ptr::null(),
                exclusion.as_ptr(),
                K_CF_STRING_ENCODING_UTF8,
            )
        };
        if value.is_null() {
            for string in strings {
                // SAFETY: every entry is an owned CFString reference created
                // earlier in this loop.
                unsafe { CFRelease(string) };
            }
            return false;
        }
        strings.push(value);
    }
    // SAFETY: strings remains live for this call and the standard callbacks
    // retain every CFString for the returned array.
    let array = unsafe {
        CFArrayCreate(
            std::ptr::null(),
            strings.as_ptr(),
            strings.len() as isize,
            std::ptr::addr_of!(kCFTypeArrayCallBacks),
        )
    };
    if array.is_null() {
        for string in strings {
            // SAFETY: every entry is an owned CFString reference.
            unsafe { CFRelease(string) };
        }
        return false;
    }
    // SAFETY: stream is newly-created and not yet scheduled; array is a live
    // CFArray containing at most eight absolute exclusion paths.
    let installed = unsafe { FSEventStreamSetExclusionPaths(stream, array) } != 0;
    // SAFETY: the call above has completed. Release the array and the creator
    // references; the array's callbacks balanced their own retains.
    unsafe { CFRelease(array) };
    for string in strings {
        // SAFETY: every entry is an owned CFString reference.
        unsafe { CFRelease(string) };
    }
    installed
}

extern "C" fn event_callback(
    _stream: FSEventStreamRef,
    info: *mut c_void,
    count: usize,
    paths: *const c_void,
    flags: *const FSEventStreamEventFlags,
    _ids: *const FSEventStreamEventId,
) {
    // SAFETY: FSEvents invokes the callback with the context pointer supplied
    // at stream creation and parallel arrays containing `count` entries.
    let state = unsafe { &*(info.cast::<CallbackState>()) };
    let mut batch = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: UseCFTypes requests a CFArray of CFString paths, valid for
        // this callback invocation.
        let raw_path = unsafe { CFArrayGetValueAtIndex(paths as CFArrayRef, index as isize) };
        let path = cf_string_path(raw_path as CFStringRef);
        // SAFETY: `flags` has one entry per event as documented by FSEvents.
        let flag = unsafe { *flags.add(index) };
        if flag
            & (K_FSEVENT_STREAM_EVENT_FLAG_MUST_SCAN_SUBDIRS
                | K_FSEVENT_STREAM_EVENT_FLAG_USER_DROPPED
                | K_FSEVENT_STREAM_EVENT_FLAG_KERNEL_DROPPED
                | K_FSEVENT_STREAM_EVENT_FLAG_EVENT_IDS_WRAPPED
                | K_FSEVENT_STREAM_EVENT_FLAG_ROOT_CHANGED
                | K_FSEVENT_STREAM_EVENT_FLAG_UNMOUNT)
            != 0
        {
            batch.push(WatchEvent::Uncertain(format!(
                "FSEvents flags 0x{flag:08x} at {} require a full stat-diff",
                path.as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<undecodable-path>".to_string())
            )));
            continue;
        }
        match path {
            Some(path) => batch.push(WatchEvent::Path(path)),
            None => batch.push(WatchEvent::Uncertain(
                "FSEvents produced a path that could not be decoded".to_string(),
            )),
        }
    }
    state.pending.push_batch(batch);
}

fn cf_string_path(value: CFStringRef) -> Option<std::path::PathBuf> {
    let mut buffer = [0 as std::ffi::c_char; 4096];
    // SAFETY: buffer is writable for its full stated capacity; CoreFoundation
    // writes a NUL-terminated UTF-8 representation on success.
    let ok = unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: CFStringGetCString succeeded and documented a NUL terminator.
    let value = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
        .to_str()
        .ok()?;
    Some(value.into())
}
