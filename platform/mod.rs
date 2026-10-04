//! SPDX-License-Identifier: GPL-2.0-only
//! Portable host filesystem, process, and locking semantics.

use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::os::unix::net::UnixStream;

// Both full buildutil and minibuildutil compile this module. The full daemon uses the
// registry to cancel every request-owned process group created by the parallel
// realization pool; minibuildutil keeps the same builder-spawn boundary without
// importing the full-only host module.
static REQUEST_PROCESS_GROUPS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static REQUEST_PROCESS_GROUPS_INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub struct RequestProcessGroup {
    pid: u32,
}

pub fn register_request_process_group(pid: u32) -> RequestProcessGroup {
    REQUEST_PROCESS_GROUPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(pid);
    if REQUEST_PROCESS_GROUPS_INTERRUPTED.load(Ordering::Acquire) {
        #[cfg(any(unix, windows))]
        terminate_process_group(pid);
    }
    RequestProcessGroup { pid }
}

impl Drop for RequestProcessGroup {
    fn drop(&mut self) {
        let mut groups = REQUEST_PROCESS_GROUPS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(index) = groups.iter().position(|pid| *pid == self.pid) {
            groups.swap_remove(index);
        }
    }
}

pub fn interrupt_request_process_group() {
    REQUEST_PROCESS_GROUPS_INTERRUPTED.store(true, Ordering::Release);
    let groups = REQUEST_PROCESS_GROUPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    for pid in groups {
        #[cfg(any(unix, windows))]
        terminate_process_group(pid);
    }
}

pub fn clear_request_process_group_interrupt() {
    REQUEST_PROCESS_GROUPS_INTERRUPTED.store(false, Ordering::Release);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymlinkKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug)]
pub struct StatFields {
    pub mtime_s: i64,
    pub mtime_ns: i64,
    pub ctime_s: i64,
    pub ctime_ns: i64,
    pub ino: u64,
    pub dev: u64,
    pub mode: u32,
}

pub fn os_str_bytes(value: &OsStr) -> &[u8] {
    value.as_encoded_bytes()
}

#[cfg(unix)]
pub fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    File::open("/dev/urandom")?.read_exact(bytes)
}

/// Start the child as the leader of a new session, which is also a new
/// process group: the group can be torn down as a unit, and the child has no
/// controlling terminal, so it cannot write to the terminal through
/// `/dev/tty` either.
#[cfg(unix)]
pub fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe extern "C" {
        fn setsid() -> i32;
    }
    // SAFETY: setsid is async-signal-safe and touches only the forked child.
    unsafe {
        command.pre_exec(|| {
            if setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(unix)]
pub fn terminate_process_group(pid: u32) {
    const SIGKILL: std::os::raw::c_int = 9;
    unsafe extern "C" {
        fn kill(pid: std::os::raw::c_int, signal: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    // SAFETY: negative pid targets the process group created by
    // `configure_process_group`; the second call covers an exec that did not
    // establish a separate group before cancellation reached it.
    unsafe {
        kill(-(pid as i32), SIGKILL);
        kill(pid as i32, SIGKILL);
    }
}

#[cfg(target_os = "linux")]
pub fn current_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no preconditions and returns the caller's effective
    // identity for this process.
    unsafe { geteuid() }
}

#[cfg(target_os = "macos")]
pub fn current_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no preconditions and returns the caller's effective
    // identity for this process.
    unsafe { geteuid() }
}

#[cfg(target_os = "linux")]
pub fn unix_peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct UCred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    unsafe extern "C" {
        fn getsockopt(
            fd: i32,
            level: i32,
            option: i32,
            value: *mut std::ffi::c_void,
            len: *mut u32,
        ) -> i32;
    }
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    let mut credential = UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<UCred>() as u32;
    // SAFETY: `credential` and `length` point to writable storage of the
    // exact ABI layout Linux expects for SO_PEERCRED.
    let result = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credential as *mut UCred).cast(),
            &mut length,
        )
    };
    if result == 0 && length as usize == std::mem::size_of::<UCred>() {
        Ok(credential.uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
pub fn unix_peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn getpeereid(fd: i32, euid: *mut u32, egid: *mut u32) -> i32;
    }
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: `uid` and `gid` are valid mutable output locations and the fd
    // belongs to this connected Unix socket.
    if unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
pub fn terminate_process_group(pid: u32) {
    let _ = crate::invocation::isolated("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdout(crate::invocation::Io::Null)
        .stderr(crate::invocation::Io::Null)
        .status();
}

#[cfg(windows)]
pub fn configure_process_group(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
pub fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buffer.is_empty() {
        let count = file.read_at(buffer, offset)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        offset += count as u64;
        buffer = &mut buffer[count..];
    }
    Ok(())
}

#[cfg(windows)]
pub fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buffer.is_empty() {
        let count = file.seek_read(buffer, offset)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        offset += count as u64;
        buffer = &mut buffer[count..];
    }
    Ok(())
}

#[cfg(windows)]
pub fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes
                .len()
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidInput)?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

#[cfg(unix)]
pub fn file_mode(metadata: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(windows)]
pub fn file_mode(metadata: &Metadata) -> u32 {
    let base = if metadata.is_dir() { 0o755 } else { 0o644 };
    if metadata.permissions().readonly() {
        base & !0o222
    } else {
        base
    }
}

#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    std::fs::set_permissions(path, permissions)
}

#[cfg(unix)]
pub fn create_symlink(target: &Path, link: &Path, _kind: SymlinkKind) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub fn create_symlink(target: &Path, link: &Path, kind: SymlinkKind) -> io::Result<()> {
    match kind {
        SymlinkKind::File => std::os::windows::fs::symlink_file(target, link),
        SymlinkKind::Directory => std::os::windows::fs::symlink_dir(target, link),
    }
}

pub fn create_symlink_auto(target: &Path, link: &Path) -> io::Result<()> {
    let resolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        link.parent().unwrap_or_else(|| Path::new(".")).join(target)
    };
    let kind = if resolved.is_dir() {
        SymlinkKind::Directory
    } else {
        SymlinkKind::File
    };
    create_symlink(target, link, kind)
}

#[cfg(unix)]
pub fn stat_fields(metadata: &Metadata) -> StatFields {
    use std::os::unix::fs::MetadataExt;
    StatFields {
        mtime_s: metadata.mtime(),
        mtime_ns: metadata.mtime_nsec(),
        ctime_s: metadata.ctime(),
        ctime_ns: metadata.ctime_nsec(),
        ino: metadata.ino(),
        dev: metadata.dev(),
        mode: metadata.mode(),
    }
}

#[cfg(windows)]
pub fn stat_fields(metadata: &Metadata) -> StatFields {
    use std::os::windows::fs::MetadataExt;
    let modified = metadata.last_write_time();
    let created = metadata.creation_time();
    StatFields {
        mtime_s: (modified / 10_000_000) as i64,
        mtime_ns: ((modified % 10_000_000) * 100) as i64,
        ctime_s: (created / 10_000_000) as i64,
        ctime_ns: ((created % 10_000_000) * 100) as i64,
        // Stable Windows MetadataExt does not expose the file index. The cache
        // still keys by canonical path and checks size/write/create time both
        // before and after the read; creation time is the replacement token.
        ino: created,
        dev: 0,
        mode: file_mode(metadata),
    }
}

pub fn device_id(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| stat_fields(&metadata).dev)
}

#[cfg(unix)]
pub fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(windows)]
pub fn same_file(a: &Path, b: &Path) -> bool {
    file_identity(a).is_some_and(|identity| Some(identity) == file_identity(b))
}

#[cfg(windows)]
fn file_identity(path: &Path) -> Option<(u32, u64)> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct FileInformation {
        attributes: u32,
        creation: FileTime,
        access: FileTime,
        write: FileTime,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut c_void, info: *mut FileInformation) -> i32;
    }
    let file = File::open(path).ok()?;
    let mut info = FileInformation {
        attributes: 0,
        creation: FileTime { low: 0, high: 0 },
        access: FileTime { low: 0, high: 0 },
        write: FileTime { low: 0, high: 0 },
        volume_serial: 0,
        size_high: 0,
        size_low: 0,
        links: 0,
        index_high: 0,
        index_low: 0,
    };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    (ok != 0).then_some((
        info.volume_serial,
        ((info.index_high as u64) << 32) | info.index_low as u64,
    ))
}

#[cfg(unix)]
pub fn lock_exclusive(file: &File, nonblocking: bool) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    let operation = LOCK_EX | if nonblocking { LOCK_NB } else { 0 };
    if unsafe { flock(file.as_raw_fd(), operation) } == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if nonblocking && error.kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

#[cfg(unix)]
pub fn lock_shared(file: &File, nonblocking: bool) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    const LOCK_SH: i32 = 1;
    const LOCK_NB: i32 = 4;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    let operation = LOCK_SH | if nonblocking { LOCK_NB } else { 0 };
    if unsafe { flock(file.as_raw_fd(), operation) } == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if nonblocking && error.kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

#[cfg(windows)]
pub fn lock_exclusive(file: &File, nonblocking: bool) -> io::Result<bool> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }
    unsafe extern "system" {
        fn LockFileEx(
            file: *mut c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    let flags = LOCKFILE_EXCLUSIVE_LOCK
        | if nonblocking {
            LOCKFILE_FAIL_IMMEDIATELY
        } else {
            0
        };
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok != 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if nonblocking && matches!(error.raw_os_error(), Some(33 | 158)) {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

#[cfg(windows)]
pub fn lock_shared(file: &File, nonblocking: bool) -> io::Result<bool> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }
    unsafe extern "system" {
        fn LockFileEx(
            file: *mut c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    let flags = if nonblocking {
        LOCKFILE_FAIL_IMMEDIATELY
    } else {
        0
    };
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok != 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if nonblocking && matches!(error.raw_os_error(), Some(33 | 158)) {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

/// Columns of the terminal behind stderr, when stderr is a terminal whose
/// size the host reports.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn stderr_columns() -> Option<usize> {
    #[repr(C)]
    struct Winsize {
        rows: u16,
        cols: u16,
        xpixel: u16,
        ypixel: u16,
    }
    #[cfg(target_os = "linux")]
    const TIOCGWINSZ: u64 = 0x5413;
    #[cfg(target_os = "macos")]
    const TIOCGWINSZ: u64 = 0x4008_7468;
    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
    }
    let mut ws = Winsize {
        rows: 0,
        cols: 0,
        xpixel: 0,
        ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes one struct winsize through the pointer.
    let ok = unsafe { ioctl(2, TIOCGWINSZ, &mut ws as *mut Winsize) } == 0;
    (ok && ws.cols > 0).then_some(ws.cols as usize)
}

#[cfg(windows)]
pub fn stderr_columns() -> Option<usize> {
    #[repr(C)]
    struct Coord {
        x: i16,
        y: i16,
    }
    #[repr(C)]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }
    #[repr(C)]
    struct ScreenBufferInfo {
        size: Coord,
        cursor: Coord,
        attributes: u16,
        window: SmallRect,
        max_window: Coord,
    }
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
        fn GetConsoleScreenBufferInfo(
            console: *mut std::ffi::c_void,
            info: *mut ScreenBufferInfo,
        ) -> i32;
    }
    // SAFETY: GetStdHandle has no preconditions; the info struct matches
    // CONSOLE_SCREEN_BUFFER_INFO and is written only on success.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        let mut info: ScreenBufferInfo = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) == 0 {
            return None;
        }
        let cols = info.window.right as i32 - info.window.left as i32 + 1;
        (cols > 0).then_some(cols as usize)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn stderr_columns() -> Option<usize> {
    None
}

/// Make the console behind stderr interpret ANSI control sequences. Unix
/// terminals always do; a Windows console needs virtual terminal processing
/// switched on, and reports whether that succeeded.
#[cfg(windows)]
pub fn enable_ansi_stderr() -> bool {
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
        fn GetConsoleMode(console: *mut std::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(console: *mut std::ffi::c_void, mode: u32) -> i32;
    }
    // SAFETY: console mode calls on the process's stderr handle; `mode` is a
    // valid out-pointer.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
pub fn enable_ansi_stderr() -> bool {
    true
}
