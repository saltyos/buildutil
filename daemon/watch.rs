// SPDX-License-Identifier: GPL-2.0-only
//! Native file-watch abstraction for daemon source invalidation.
//!
//! A watcher is only an accelerator.  Backends report every condition that
//! could lose ordering or coverage as [`WatchEvent::Uncertain`]; callers must
//! then return to the ordinary stat-diff path until a fresh baseline exists.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchEvent {
    Path(PathBuf),
    Uncertain(String),
}

/// Callback-facing queue. Producers build a batch without holding the lock,
/// then publish it with one constant-time Vec push. Consumers swap all batches
/// out and flatten them only after releasing the producer lock.
#[derive(Default)]
pub struct PendingEvents {
    batches: Mutex<Vec<Vec<WatchEvent>>>,
    producer_lost_events: AtomicBool,
}

impl PendingEvents {
    pub fn push_batch(&self, batch: Vec<WatchEvent>) {
        if batch.is_empty() {
            return;
        }
        match self.batches.try_lock() {
            Ok(mut batches) => batches.push(batch),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner().push(batch),
            Err(std::sync::TryLockError::WouldBlock) => {
                // A native callback must never wait behind a daemon drain.
                // Losing this batch is uncertainty, surfaced on the next take.
                self.producer_lost_events.store(true, Ordering::Release);
            }
        }
    }

    pub fn push(&self, event: WatchEvent) {
        self.push_batch(vec![event]);
    }

    pub fn take(&self) -> Vec<WatchEvent> {
        let batches = std::mem::take(
            &mut *self
                .batches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let total = batches.iter().map(Vec::len).sum();
        let mut events = Vec::with_capacity(total);
        for batch in batches {
            events.extend(batch);
        }
        if self.producer_lost_events.swap(false, Ordering::AcqRel) {
            events.push(WatchEvent::Uncertain(
                "watcher pending buffer contention dropped events".to_string(),
            ));
        }
        events
    }
}

pub trait Watcher: Send {
    /// Take the events accumulated since the prior drain.
    fn drain(&mut self) -> Vec<WatchEvent>;

    /// Stop worker threads and release the native watch object.
    fn shutdown(&mut self);

    fn platform_name(&self) -> &'static str;

    fn startup_diagnostics(&self) -> &[String] {
        &[]
    }

    fn quiesce_duration(&self) -> Duration {
        Duration::from_millis(50)
    }
}

/// Return the physical spelling of a path while preserving a missing suffix.
///
/// Watchers receive deletion and rename events after the affected leaf may no
/// longer exist. Canonicalizing only the complete path would then leave a
/// logical alias such as `/var/...` unmatched against an installed
/// `/private/var/...` root. Resolve the closest extant ancestor instead and
/// reconstruct the missing suffix beneath it.
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut missing = Vec::<OsString>::new();
    loop {
        if let Ok(mut normalized) = std::fs::canonicalize(&existing) {
            for component in missing.iter().rev() {
                normalized.push(component);
            }
            return normalized;
        }
        let Some(component) = existing.file_name().map(OsString::from) else {
            return path.to_path_buf();
        };
        missing.push(component);
        if !existing.pop() {
            return path.to_path_buf();
        }
    }
}

#[cfg(any(target_os = "macos", test))]
pub fn kernel_exclusion_paths(repo_root: &Path, state_root: &Path) -> Vec<PathBuf> {
    let repo_root = normalize_path(repo_root);
    let state_root = normalize_path(state_root);
    let mut paths = Vec::with_capacity(1);
    if state_root != repo_root && state_root.starts_with(&repo_root) {
        paths.push(state_root);
    }
    paths
}

pub fn start(
    repo_root: &Path,
    state_root: &Path,
    structural_fallback: bool,
) -> Result<Box<dyn Watcher>, String> {
    let repo_root = normalize_path(repo_root);
    let state_root = normalize_path(state_root);
    if state_root == repo_root {
        return Err("daemon state root equals the repository watch root".to_string());
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(super::fsevents::FseventsWatcher::start(
            &repo_root,
            &state_root,
            structural_fallback,
        )?));
    }
    #[cfg(target_os = "linux")]
    {
        let _ = structural_fallback;
        return Ok(Box::new(super::inotify::InotifyWatcher::start(
            &repo_root,
            &state_root,
        )?));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (repo_root, state_root, structural_fallback);
        Err("no native daemon watcher is available on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn pending_events_publish_batches_and_swap_without_loss() {
        let pending = PendingEvents::default();
        pending.push_batch(vec![
            WatchEvent::Path(PathBuf::from("first")),
            WatchEvent::Path(PathBuf::from("second")),
        ]);
        pending.push(WatchEvent::Uncertain("third".to_string()));

        assert_eq!(
            pending.take(),
            vec![
                WatchEvent::Path(PathBuf::from("first")),
                WatchEvent::Path(PathBuf::from("second")),
                WatchEvent::Uncertain("third".to_string()),
            ]
        );
        assert!(pending.take().is_empty());
    }

    #[test]
    fn pending_event_producer_never_waits_for_the_consumer_lock() {
        let pending = PendingEvents::default();
        let held = pending.batches.lock().expect("pending lock");
        pending.push(WatchEvent::Path(PathBuf::from("dropped")));
        drop(held);

        assert_eq!(
            pending.take(),
            vec![WatchEvent::Uncertain(
                "watcher pending buffer contention dropped events".to_string()
            )]
        );
    }

    #[cfg(unix)]
    #[test]
    fn normalize_path_resolves_an_existing_symlink_for_a_deleted_leaf() {
        let root = std::env::temp_dir().join(format!(
            "buildutil-watcher-normalize-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        let physical = root.join("physical");
        let alias = root.join("alias");
        std::fs::create_dir_all(&physical).expect("create physical directory");
        std::os::unix::fs::symlink(&physical, &alias).expect("create directory alias");

        assert_eq!(
            normalize_path(&alias.join("deleted.txt")),
            normalize_path(&physical).join("deleted.txt")
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn kernel_exclusions_keep_internal_state_first_and_omit_external_state() {
        let repo = normalize_path(&std::env::temp_dir().join("buildutil-watch-scope-repo"));
        let internal = repo.join(".buildutil");
        let paths = kernel_exclusion_paths(&repo, &internal);
        assert_eq!(paths, vec![internal]);

        let external = repo
            .parent()
            .expect("repo parent")
            .join("buildutil-external-store");
        let paths = kernel_exclusion_paths(&repo, &external);
        assert!(paths.is_empty());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn platform_watcher_reports_file_mutations() {
        let root = std::env::temp_dir().join(format!(
            "buildutil-watcher-smoke-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create watcher root");
        let watched_root = normalize_path(&root);
        let mut watcher =
            start(&root, &root.join(".buildutil"), false).expect("start platform watcher");
        #[cfg(target_os = "macos")]
        assert!(
            watcher
                .startup_diagnostics()
                .iter()
                .any(|line| line.contains("SetExclusionPaths="))
        );
        let file = root.join("changed.txt");
        std::fs::write(&file, "first\n").expect("create watched file");
        std::fs::write(&file, "second\n").expect("modify watched file");
        std::fs::remove_file(&file).expect("remove watched file");

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_root = false;
        while Instant::now() < deadline && !saw_root {
            for event in watcher.drain() {
                match event {
                    WatchEvent::Path(path) if path.starts_with(&watched_root) => saw_root = true,
                    WatchEvent::Path(_) => {}
                    WatchEvent::Uncertain(reason) => panic!("watcher became uncertain: {reason}"),
                }
            }
            if !saw_root {
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        watcher.shutdown();
        let _ = std::fs::remove_dir_all(root);
        assert!(saw_root, "watcher did not report a tempdir mutation");
    }
}
