// SPDX-License-Identifier: GPL-2.0-only
//! Linux inotify backend. Watches are installed recursively before the first
//! daemon baseline and for every directory created or moved into the tree.

use super::watch::{self, PendingEvents, WatchEvent, Watcher};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const IN_NONBLOCK: i32 = 0x0000_0800;
const IN_CLOEXEC: i32 = 0x0008_0000;
const IN_MODIFY: u32 = 0x0000_0002;
const IN_ATTRIB: u32 = 0x0000_0004;
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;
const IN_DELETE_SELF: u32 = 0x0000_0400;
const IN_MOVE_SELF: u32 = 0x0000_0800;
const IN_UNMOUNT: u32 = 0x0000_2000;
const IN_Q_OVERFLOW: u32 = 0x0000_4000;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_ISDIR: u32 = 0x4000_0000;
const WATCH_MASK: u32 = IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_UNMOUNT
    | IN_ONLYDIR;

#[repr(C)]
#[derive(Clone, Copy)]
struct InotifyEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
}

unsafe extern "C" {
    fn inotify_init1(flags: i32) -> i32;
    fn inotify_add_watch(fd: i32, pathname: *const std::ffi::c_char, mask: u32) -> i32;
    fn read(fd: i32, buffer: *mut std::ffi::c_void, count: usize) -> isize;
    fn close(fd: i32) -> i32;
}

pub struct InotifyWatcher {
    pending: Arc<PendingEvents>,
    stopping: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct WatchScope {
    state_root: Option<PathBuf>,
}

impl WatchScope {
    fn new(repo_root: &Path, state_root: &Path) -> Self {
        let repo_root = watch::normalize_path(repo_root);
        let state_root = watch::normalize_path(state_root);
        let state_root = state_root.starts_with(&repo_root).then_some(state_root);
        Self { state_root }
    }

    fn excludes(&self, path: &Path) -> bool {
        self.state_root
            .as_ref()
            .is_some_and(|state_root| path.starts_with(state_root))
    }
}

struct OwnedFd(i32);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // SAFETY: OwnedFd is the unique owner of this inotify descriptor.
        unsafe { close(self.0) };
    }
}

impl InotifyWatcher {
    pub fn start(repo_root: &Path, state_root: &Path) -> Result<Self, String> {
        // SAFETY: inotify_init1 has no Rust-side preconditions.
        let raw_fd = unsafe { inotify_init1(IN_NONBLOCK | IN_CLOEXEC) };
        if raw_fd < 0 {
            return Err(format!(
                "cannot create inotify fd: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = OwnedFd(raw_fd);
        let scope = WatchScope::new(repo_root, state_root);
        let mut watched = BTreeMap::new();
        if let Err(error) = register_tree(fd.0, repo_root, &scope, &mut watched) {
            return Err(error);
        }
        let pending = Arc::new(PendingEvents::default());
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_pending = pending.clone();
        let worker_stopping = stopping.clone();
        let thread = match std::thread::Builder::new()
            .name("buildutil-inotify".to_string())
            .spawn(move || run(fd, watched, scope, worker_pending, worker_stopping))
        {
            Ok(thread) => thread,
            Err(error) => {
                return Err(format!("cannot start inotify thread: {error}"));
            }
        };
        Ok(Self {
            pending,
            stopping,
            thread: Some(thread),
        })
    }

    fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Watcher for InotifyWatcher {
    fn drain(&mut self) -> Vec<WatchEvent> {
        self.pending.take()
    }

    fn shutdown(&mut self) {
        self.stop();
    }

    fn platform_name(&self) -> &'static str {
        "inotify"
    }
}

impl Drop for InotifyWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn register_tree(
    fd: i32,
    root: &Path,
    scope: &WatchScope,
    watched: &mut BTreeMap<i32, PathBuf>,
) -> Result<(), String> {
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        if scope.excludes(&dir) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&dir)
            .map_err(|e| format!("cannot stat inotify directory {}: {e}", dir.display()))?;
        if !metadata.is_dir() {
            continue;
        }
        add_watch(fd, &dir, watched)?;
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("cannot read inotify directory {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read inotify entry: {e}"))?;
            if entry
                .file_type()
                .map_err(|e| format!("cannot stat inotify entry {}: {e}", entry.path().display()))?
                .is_dir()
            {
                dirs.push(entry.path());
            }
        }
    }
    Ok(())
}

fn add_watch(fd: i32, path: &Path, watched: &mut BTreeMap<i32, PathBuf>) -> Result<(), String> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("inotify path contains NUL: {}", path.display()))?;
    // SAFETY: c_path is NUL terminated and valid for this syscall; fd is an
    // open inotify descriptor owned by the watcher thread.
    let wd = unsafe { inotify_add_watch(fd, c_path.as_ptr(), WATCH_MASK) };
    if wd < 0 {
        let error = std::io::Error::last_os_error();
        let detail = if error.raw_os_error() == Some(28) {
            "inotify max_user_watches exhausted (ENOSPC)".to_string()
        } else {
            error.to_string()
        };
        return Err(format!(
            "cannot install inotify watch for {}: {detail}",
            path.display()
        ));
    }
    watched.insert(wd, path.to_path_buf());
    Ok(())
}

fn run(
    fd: OwnedFd,
    mut watched: BTreeMap<i32, PathBuf>,
    scope: WatchScope,
    pending: Arc<PendingEvents>,
    stopping: Arc<AtomicBool>,
) {
    let mut bytes = [0u8; 64 * 1024];
    while !stopping.load(Ordering::Acquire) {
        // SAFETY: bytes is writable for the supplied length and fd remains
        // owned by this thread until the loop exits.
        let count = unsafe { read(fd.0, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            pending.push(WatchEvent::Uncertain(format!(
                "inotify read failed: {error}"
            )));
            break;
        }
        if count == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        let mut at = 0usize;
        let count = count as usize;
        let mut batch = Vec::new();
        while at < count {
            if count - at < std::mem::size_of::<InotifyEvent>() {
                uncertain(&mut batch, "truncated inotify event".to_string());
                break;
            }
            // SAFETY: the bounds check above guarantees a complete header;
            // read_unaligned handles the byte buffer's alignment.
            let event =
                unsafe { std::ptr::read_unaligned(bytes[at..].as_ptr().cast::<InotifyEvent>()) };
            let record_len = std::mem::size_of::<InotifyEvent>() + event.len as usize;
            if record_len > count - at {
                uncertain(
                    &mut batch,
                    "inotify event name exceeds read buffer".to_string(),
                );
                break;
            }
            handle_event(
                fd.0,
                event,
                &bytes[at..at + record_len],
                &scope,
                &mut watched,
                &mut batch,
            );
            at += record_len;
        }
        pending.push_batch(batch);
    }
}

fn handle_event(
    fd: i32,
    event: InotifyEvent,
    bytes: &[u8],
    scope: &WatchScope,
    watched: &mut BTreeMap<i32, PathBuf>,
    pending: &mut Vec<WatchEvent>,
) {
    if event.mask & IN_Q_OVERFLOW != 0 {
        uncertain(pending, "inotify queue overflow".to_string());
        return;
    }
    let Some(parent) = watched.get(&event.wd).cloned() else {
        uncertain(
            pending,
            format!("inotify event for unknown watch {}", event.wd),
        );
        return;
    };
    let name_start = std::mem::size_of::<InotifyEvent>();
    let name = bytes[name_start..]
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    let path = if name.is_empty() {
        parent.clone()
    } else {
        parent.join(std::ffi::OsStr::from_bytes(name))
    };
    pending.push(WatchEvent::Path(path.clone()));

    if event.mask & IN_UNMOUNT != 0 {
        uncertain(pending, format!("inotify unmount at {}", path.display()));
        return;
    }
    if event.mask & IN_IGNORED != 0 {
        watched.remove(&event.wd);
        if path.is_dir()
            && let Err(error) = register_tree(fd, &path, scope, watched)
        {
            uncertain(pending, error);
        }
        return;
    }
    if event.mask & (IN_MOVE_SELF | IN_DELETE_SELF) != 0 {
        if path.is_dir()
            && let Err(error) = register_tree(fd, &path, scope, watched)
        {
            // A removed directory has already dirtied its parent. A failed
            // re-watch for an existing directory is uncertainty because child
            // events could otherwise be missed.
            if path.exists() {
                uncertain(pending, error);
            }
        }
    }
    if event.mask & IN_ISDIR != 0 && event.mask & (IN_CREATE | IN_MOVED_TO) != 0 {
        if let Err(error) = register_tree(fd, &path, scope, watched) {
            uncertain(pending, error);
        }
    }
    // Renames intentionally dirty both IN_MOVED_FROM and IN_MOVED_TO paths.
    // This avoids depending on a matching cookie if either half is dropped.
    let _ = event.cookie;
}

fn uncertain(pending: &mut Vec<WatchEvent>, reason: String) {
    pending.push(WatchEvent::Uncertain(reason));
}
