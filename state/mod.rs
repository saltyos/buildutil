//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — repository-local state paths and locks

use std::path::{Path, PathBuf};

use std::fs::File;

#[must_use]
pub struct PlanLock {
    _file: File,
}

#[must_use]
pub struct ExecutorLock {
    _file: File,
}

/// Store-wide shared lease held by realization work.
#[must_use]
pub struct StoreSharedLease {
    _file: File,
}

/// Store-wide exclusive lease held by destructive store maintenance.
///
/// Lock order is always this lease before any per-derivation
/// `locks/<hash>.building` lock. A realizer only acquires the shared form;
/// it must never upgrade to or acquire the exclusive form.
#[must_use]
pub struct StoreExclusiveLease {
    _file: File,
}

pub fn config_root(state_root: &Path, arch: &str) -> PathBuf {
    state_root.join("config").join(arch)
}

/// The persistent override file of an architecture's configuration: the
/// first of the three override layers.
pub fn config_file(state_root: &Path, arch: &str) -> PathBuf {
    config_root(state_root, arch).join("config")
}

pub fn seed_dir(state_root: &Path, build_host: &str) -> PathBuf {
    state_root.join("sources/seed").join(build_host)
}

pub fn source_cas_dir(state_root: &Path) -> PathBuf {
    state_root.join("sources/cas")
}

pub fn source_tree_dir(state_root: &Path) -> PathBuf {
    state_root.join("sources/tree")
}

pub fn source_gittree_dir(state_root: &Path) -> PathBuf {
    state_root.join("sources/gittree")
}

pub fn source_tmp_dir(state_root: &Path) -> PathBuf {
    state_root.join("sources/tmp")
}

pub fn plans_dir(state_root: &Path) -> PathBuf {
    state_root.join("plans")
}

/// The state root as an absolute path. `--store` and `BUILDUTIL_STORE` may name
/// it relative to the repository, while builders and launchers run with other
/// working directories.
pub fn absolute_root(repo_root: &Path, state_root: &Path) -> PathBuf {
    if state_root.is_absolute() {
        state_root.to_path_buf()
    } else {
        repo_root.join(state_root)
    }
}

/// Persistent dev-build tree for one target. Each execution backend owns its
/// own subtree, so an incremental tree written by one backend is never
/// continued by another.
pub fn dev_dir(state_root: &Path, backend: &str, arch: &str, target: &str) -> PathBuf {
    state_root.join("dev").join(backend).join(arch).join(target)
}

pub fn plan_lock_path(state_root: &Path, hash32: &str) -> PathBuf {
    plans_dir(state_root).join(format!("{hash32}.plan.lock"))
}

pub fn lock_plan(state_root: &Path, hash32: &str) -> Result<PlanLock, String> {
    lock_plan_with(state_root, hash32, false)?.ok_or_else(|| {
        format!(
            "cannot lock plan {}",
            plan_lock_path(state_root, hash32).display()
        )
    })
}

pub fn try_lock_plan(state_root: &Path, hash32: &str) -> Result<Option<PlanLock>, String> {
    lock_plan_with(state_root, hash32, true)
}

fn lock_plan_with(
    state_root: &Path,
    hash32: &str,
    nonblocking: bool,
) -> Result<Option<PlanLock>, String> {
    let path = plan_lock_path(state_root, hash32);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)
        .map_err(|e| format!("cannot open plan lock {}: {}", path.display(), e))?;
    let acquired = crate::platform::lock_exclusive(&file, nonblocking)
        .map_err(|e| format!("cannot lock plan {}: {e}", path.display()))?;
    Ok(acquired.then_some(PlanLock { _file: file }))
}

pub fn exec_dir(state_root: &Path) -> PathBuf {
    state_root.join("exec")
}

pub fn executor_lock_path(state_root: &Path, hash32: &str) -> PathBuf {
    exec_dir(state_root).join(format!("{hash32}.lock"))
}

pub fn store_lease_path(state_root: &Path) -> PathBuf {
    state_root.join("locks").join("gc.lease")
}

pub fn lock_store_shared(state_root: &Path) -> Result<StoreSharedLease, String> {
    let file = lock_store_file(state_root)?;
    match crate::platform::lock_shared(&file, true).map_err(|e| {
        format!(
            "cannot lock store lease {}: {e}",
            store_lease_path(state_root).display()
        )
    })? {
        true => Ok(StoreSharedLease { _file: file }),
        false => {
            crate::log::info("store", "waiting for GC to release the store lease");
            crate::platform::lock_shared(&file, false).map_err(|e| {
                format!(
                    "cannot lock store lease {}: {e}",
                    store_lease_path(state_root).display()
                )
            })?;
            Ok(StoreSharedLease { _file: file })
        }
    }
}

pub fn lock_store_exclusive(state_root: &Path) -> Result<StoreExclusiveLease, String> {
    let file = lock_store_file(state_root)?;
    match crate::platform::lock_exclusive(&file, true).map_err(|e| {
        format!(
            "cannot lock store lease {}: {e}",
            store_lease_path(state_root).display()
        )
    })? {
        true => Ok(StoreExclusiveLease { _file: file }),
        false => {
            crate::log::info(
                "store",
                "waiting for active builds to release the store lease",
            );
            crate::platform::lock_exclusive(&file, false).map_err(|e| {
                format!(
                    "cannot lock store lease {}: {e}",
                    store_lease_path(state_root).display()
                )
            })?;
            Ok(StoreExclusiveLease { _file: file })
        }
    }
}

fn lock_store_file(state_root: &Path) -> Result<File, String> {
    let path = store_lease_path(state_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)
        .map_err(|e| format!("cannot open store lease {}: {}", path.display(), e))
}

pub fn lock_executor(state_root: &Path, hash32: &str) -> Result<ExecutorLock, String> {
    let path = executor_lock_path(state_root, hash32);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)
        .map_err(|e| format!("cannot open executor lock {}: {}", path.display(), e))?;
    crate::platform::lock_exclusive(&file, false)
        .map_err(|e| format!("cannot lock executor {}: {e}", path.display()))?;
    Ok(ExecutorLock { _file: file })
}

pub fn cache_dir(state_root: &Path) -> PathBuf {
    state_root.join("cache")
}

pub fn logs_dir(state_root: &Path) -> PathBuf {
    state_root.join("logs")
}

/// Runtime state of what buildutil launches: `run/<module>/` for each app's
/// module, and the VM logs and persistent firmware variables of the declared
/// launcher, which `run` and `test` hand this directory to. buildutil creates it
/// and never reads or prunes it.
pub fn run_dir(state_root: &Path) -> PathBuf {
    state_root.join("run")
}

/// Persistent content-keyed Git blob digest map. The key contains no inode or
/// checkout path, so it remains valid across host/container bind mounts.
pub fn git_blob_memo(state_root: &Path) -> PathBuf {
    cache_dir(state_root).join("git-blob-map")
}

/// On-disk stat-cache file (`BLDSTAT1` binary format). Persisted from
/// `main()` exit; the lock file is a separate inode so atomic renames inside
/// `flush_file_cache` never invalidate the in-flight flock.
pub fn stat_cache_path(state_root: &Path) -> PathBuf {
    cache_dir(state_root).join("stat-cache.v1")
}

/// Companion flock file for [`stat_cache_path`].
pub fn stat_cache_lock_path(state_root: &Path) -> PathBuf {
    cache_dir(state_root).join("stat-cache.lock")
}
