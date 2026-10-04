//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — POSIX jobserver (concurrency control)
//!
//! One token pool bounds buildutil's own worker pool, every inner ninja, and
//! every port `make` together. The pool is a named FIFO in the GNU-make /
//! ninja-1.13 style (`--jobserver-auth=fifo:PATH`): a client is entitled to
//! one *implicit* job slot (granted by the parent that spawned it) and must
//! obtain an *explicit* token — one byte read from the FIFO, written back
//! verbatim on release — for each additional concurrent job.
//!
//! buildutil is the master: it creates the FIFO, primes it with `jobs - 1`
//! tokens (it keeps one implicit slot for its own first worker), and gates
//! every worker on `acquire()` / `release()`. Inner tools inherit
//! `MAKEFLAGS` and draw from the same FIFO, so total job concurrency across
//! the whole build tree tracks `jobs`.
//!
//! Fallback — token leasing — for a builder that cannot join the jobserver
//! (an old configure script, an odd port build system pinned to `-jN`):
//! buildutil `try_lease`s a bounded share of the currently-free tokens (never
//! blocking, so it cannot deadlock the pool) and pins that builder's `-j` to
//! the grant.
//!
//! Parallelism is deliberately kept OUT of the derivation preimage
//! (`MAKEFLAGS` / `NPROC` are injected as runtime env, never a hashed input),
//! so token counts and lease sizes never perturb an artifact's identity.
//!
//! Runtime note: the concurrency invariant and the Linux namespace-sandbox
//! FIFO bind are exercised only by a real multi-job build (and, for the
//! bind, only on Linux); the token mechanics below are unit-tested directly.

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::Condvar;
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};

// SAFETY: standard libc; `path` is a valid NUL-terminated C string.
#[cfg(unix)]
unsafe extern "C" {
    fn mkfifo(path: *const u8, mode: u32) -> i32;
}

#[cfg(all(unix, target_os = "linux"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(all(unix, not(target_os = "linux")))]
const O_NONBLOCK: i32 = 0x0004;

/// Distinguishes concurrently-live jobservers (in production there is one per
/// realize(), but tests create several) so their FIFOs never collide.
#[cfg(unix)]
static POOL_SEQ: AtomicU64 = AtomicU64::new(0);

/// One acquired job slot. The owner hands it back to `Jobserver::release`
/// (or lets a `Lease` do so) — dropping a bare `Slot` does not auto-release.
pub enum Slot {
    /// The master's single free slot.
    Implicit,
    /// A byte read from the FIFO; the exact value is written back on release.
    Explicit(u8),
}

pub struct Jobserver {
    #[cfg(unix)]
    fifo: PathBuf,
    /// Reads block until a token is available; serialized so one waiter is
    /// served per token that arrives.
    #[cfg(unix)]
    read: Mutex<File>,
    /// A non-blocking view of the same FIFO for `try_acquire`.
    #[cfg(unix)]
    nb_read: Mutex<File>,
    #[cfg(unix)]
    write: Mutex<File>,
    #[cfg(windows)]
    explicit: Mutex<usize>,
    #[cfg(windows)]
    available: Condvar,
    /// The master's implicit slot — taken by the first concurrent worker.
    implicit: AtomicBool,
    jobs: usize,
}

#[cfg(unix)]
fn cstr(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = path.as_os_str().as_encoded_bytes().to_vec();
    if bytes.contains(&0) {
        return Err("jobserver path has interior NUL".to_string());
    }
    bytes.push(0);
    Ok(bytes)
}

#[cfg(unix)]
impl Jobserver {
    /// Create a FIFO jobserver with `jobs` total slots. Returns `None` for
    /// `jobs <= 1` — a serial build needs no pool (and no `MAKEFLAGS`).
    pub fn new(jobs: usize) -> Result<Option<Jobserver>, String> {
        if jobs <= 1 {
            return Ok(None);
        }
        let seq = POOL_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!(
                "buildutil-jobserver-{}-{}",
                std::process::id(),
                seq
            ));
        std::fs::create_dir_all(&dir).map_err(|e| format!("jobserver dir: {}", e))?;
        let fifo = dir.join("pool.fifo");
        let _ = std::fs::remove_file(&fifo);
        let c = cstr(&fifo)?;
        // SAFETY: c is a valid NUL-terminated path; 0o600 is a valid mode.
        let r = unsafe { mkfifo(c.as_ptr(), 0o600) };
        if r != 0 {
            return Err(format!(
                "mkfifo {}: {}",
                fifo.display(),
                std::io::Error::last_os_error()
            ));
        }
        // Open read+write so the FIFO stays open without a peer and blocking
        // reads block only when genuinely empty (the standard jobserver
        // trick). A third, O_NONBLOCK view backs try_acquire.
        let opts = || {
            let mut o = OpenOptions::new();
            o.read(true).write(true);
            o
        };
        let write = opts()
            .open(&fifo)
            .map_err(|e| format!("open jobserver fifo (w): {}", e))?;
        let read = opts()
            .open(&fifo)
            .map_err(|e| format!("open jobserver fifo (r): {}", e))?;
        let nb_read = opts()
            .custom_flags(O_NONBLOCK)
            .open(&fifo)
            .map_err(|e| format!("open jobserver fifo (nb): {}", e))?;
        let js = Jobserver {
            fifo,
            read: Mutex::new(read),
            nb_read: Mutex::new(nb_read),
            write: Mutex::new(write),
            implicit: AtomicBool::new(true),
            jobs,
        };
        // Prime jobs-1 explicit tokens ('+' as GNU make does; clients treat
        // the value as opaque and write it back unchanged).
        {
            let mut w = js.write.lock().expect("jobserver write lock");
            let tokens = vec![b'+'; jobs - 1];
            w.write_all(&tokens)
                .map_err(|e| format!("prime jobserver: {}", e))?;
        }
        Ok(Some(js))
    }

    /// Acquire a slot, blocking until one is free: the implicit slot first,
    /// then an explicit FIFO token.
    pub fn acquire(&self) -> Slot {
        if self.take_implicit() {
            return Slot::Implicit;
        }
        let mut buf = [0u8; 1];
        loop {
            let mut r = self.read.lock().expect("jobserver read lock");
            match r.read(&mut buf) {
                Ok(1) => return Slot::Explicit(buf[0]),
                Ok(_) => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Slot::Implicit, // never wedge the pool
            }
        }
    }

    /// Try to acquire one *explicit* token without blocking. Returns `None`
    /// when the FIFO is momentarily empty. Does not take the implicit slot —
    /// that is reserved for the blocking `acquire` path.
    pub fn try_acquire(&self) -> Option<Slot> {
        let mut buf = [0u8; 1];
        let mut r = self.nb_read.lock().expect("jobserver nb lock");
        match r.read(&mut buf) {
            Ok(1) => Some(Slot::Explicit(buf[0])),
            _ => None,
        }
    }

    fn take_implicit(&self) -> bool {
        self.implicit
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Return a slot to the pool.
    pub fn release(&self, slot: Slot) {
        match slot {
            Slot::Implicit => self.implicit.store(true, Ordering::SeqCst),
            Slot::Explicit(byte) => {
                let mut w = self.write.lock().expect("jobserver write lock");
                let _ = w.write_all(&[byte]);
            }
        }
    }

    /// Lease up to `max` currently-free explicit tokens for a builder that
    /// cannot join the jobserver. Non-blocking: it grants only what is free
    /// right now (possibly zero), so leasing can never deadlock the pool. The
    /// caller runs at `-j(len()+1)` (its own implicit slot plus the grant);
    /// dropping the `Lease` reclaims the tokens.
    pub fn try_lease(&self, max: usize) -> Lease<'_> {
        let mut slots = Vec::new();
        for _ in 0..max {
            match self.try_acquire() {
                Some(slot) => slots.push(slot),
                None => break,
            }
        }
        Lease { js: self, slots }
    }

    /// The `MAKEFLAGS` value inner jobserver-aware tools parse to join.
    pub fn makeflags(&self) -> String {
        format!(
            "-j{} --jobserver-auth=fifo:{}",
            self.jobs,
            self.fifo.display()
        )
    }

    /// The FIFO path — bound read-write into the namespace sandbox so a
    /// sandboxed inner tool can join the pool (Linux only).
    #[cfg(target_os = "linux")]
    pub fn fifo_path(&self) -> &Path {
        &self.fifo
    }
}

#[cfg(windows)]
impl Jobserver {
    pub fn new(jobs: usize) -> Result<Option<Jobserver>, String> {
        if jobs <= 1 {
            return Ok(None);
        }
        Ok(Some(Jobserver {
            explicit: Mutex::new(jobs - 1),
            available: Condvar::new(),
            implicit: AtomicBool::new(true),
            jobs,
        }))
    }

    pub fn acquire(&self) -> Slot {
        if self.take_implicit() {
            return Slot::Implicit;
        }
        let mut available = self.explicit.lock().expect("jobserver token lock");
        while *available == 0 {
            available = self
                .available
                .wait(available)
                .expect("jobserver token wait");
        }
        *available -= 1;
        Slot::Explicit(b'+')
    }

    pub fn try_acquire(&self) -> Option<Slot> {
        let mut available = self.explicit.lock().expect("jobserver token lock");
        if *available == 0 {
            None
        } else {
            *available -= 1;
            Some(Slot::Explicit(b'+'))
        }
    }

    fn take_implicit(&self) -> bool {
        self.implicit
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn release(&self, slot: Slot) {
        match slot {
            Slot::Implicit => self.implicit.store(true, Ordering::SeqCst),
            Slot::Explicit(byte) => {
                let _ = byte;
                *self.explicit.lock().expect("jobserver token lock") += 1;
                self.available.notify_one();
            }
        }
    }

    pub fn try_lease(&self, max: usize) -> Lease<'_> {
        let mut slots = Vec::new();
        for _ in 0..max {
            let Some(slot) = self.try_acquire() else {
                break;
            };
            slots.push(slot);
        }
        Lease { js: self, slots }
    }

    /// Windows has no POSIX FIFO namespace to pass through to child tools.
    /// Each buildutil worker already owns one global token, so forcing inner tools
    /// serial preserves the global `jobs` bound without an independent pool.
    pub fn makeflags(&self) -> String {
        let _ = self.jobs;
        "-j1".to_string()
    }
}

#[cfg(unix)]
impl Drop for Jobserver {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.fifo);
        if let Some(dir) = self.fifo.parent() {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

#[cfg(windows)]
impl Drop for Jobserver {
    fn drop(&mut self) {}
}

/// Tokens leased to a non-jobserver builder; reclaimed on drop. `len()` is
/// the explicit grant (the builder also has its own implicit slot).
pub struct Lease<'a> {
    js: &'a Jobserver,
    slots: Vec<Slot>,
}

impl Lease<'_> {
    /// The explicit-token grant (the builder also has its own implicit slot).
    pub fn len(&self) -> usize {
        self.slots.len()
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        for slot in self.slots.drain(..) {
            self.js.release(slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_then_explicit_then_refill() {
        let js = Jobserver::new(3).unwrap().expect("pool for jobs>1");
        // 1 implicit + 2 explicit = 3 slots.
        let a = js.acquire();
        assert!(matches!(a, Slot::Implicit));
        let b = js.acquire();
        let c = js.acquire();
        assert!(matches!(b, Slot::Explicit(_)));
        assert!(matches!(c, Slot::Explicit(_)));
        // Release one explicit and reacquire it.
        js.release(c);
        let d = js.acquire();
        assert!(matches!(d, Slot::Explicit(_)));
        js.release(d);
        js.release(b);
        js.release(a);
        // The implicit is available again.
        assert!(matches!(js.acquire(), Slot::Implicit));
    }

    #[test]
    fn try_acquire_is_nonblocking_when_empty() {
        let js = Jobserver::new(2).unwrap().unwrap();
        // 1 explicit token in the fifo.
        let first = js.try_acquire();
        assert!(matches!(first, Some(Slot::Explicit(_))));
        // Now empty — try_acquire returns immediately without blocking.
        assert!(js.try_acquire().is_none());
        js.release(first.unwrap());
        assert!(js.try_acquire().is_some());
    }

    #[test]
    fn makeflags_names_the_fifo() {
        let js = Jobserver::new(4).unwrap().unwrap();
        let mf = js.makeflags();
        if cfg!(windows) {
            assert_eq!(mf, "-j1");
        } else {
            assert!(mf.starts_with("-j4 --jobserver-auth=fifo:"));
        }
    }

    #[test]
    fn serial_build_has_no_pool() {
        assert!(Jobserver::new(1).unwrap().is_none());
    }

    #[test]
    fn try_lease_bounded_by_free_tokens_and_reclaims() {
        let js = Jobserver::new(4).unwrap().unwrap(); // 3 explicit tokens free
        {
            let lease = js.try_lease(10); // asks 10, only 3 available
            assert_eq!(lease.len(), 3);
            // Pool drained: a further non-blocking lease grants nothing.
            assert_eq!(js.try_lease(1).len(), 0);
        }
        // Reclaimed on drop.
        assert_eq!(js.try_lease(10).len(), 3);
    }
}
