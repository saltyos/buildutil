//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage: worktree walks

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use super::filehash;
use super::tree::{read_symlink_target, rel_path_string};
use super::{SourceCas, TreeEntry, TreeObject, WorktreeFile};

pub(super) fn collect_filtered_pure(
    root: &Path,
    filter: &super::SourceFilter,
) -> Result<TreeObject, String> {
    let mut object = TreeObject {
        entries: Vec::new(),
        targets: std::collections::BTreeMap::new(),
    };
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let files = pipeline_worktree_files(None, |submit| {
        pure_walk(&root, &root, filter, &mut object, submit)
    })?;
    object.entries.extend(files);
    object.entries.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(object)
}

fn pure_walk(
    root: &Path,
    dir: &Path,
    filter: &super::SourceFilter,
    object: &mut TreeObject,
    submit: &mut dyn FnMut(WorktreeFile) -> Result<(), String>,
) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {}", dir.display(), e))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("read entry under {}: {}", dir.display(), e))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = entry
            .metadata()
            .map_err(|e| format!("cannot stat {}: {}", path.display(), e))?;
        let rel = rel_path_string(root, &path)?;
        if filter.excludes(&rel, meta.is_dir()) {
            continue;
        }
        if meta.file_type().is_symlink() {
            let target = read_symlink_target(&path)?;
            let hash = crate::crypto::sha256::hash_bytes(target.as_bytes());
            object.targets.entry(hash.clone()).or_insert(target);
            object.entries.push(TreeEntry {
                rel,
                hash,
                kind: 'l',
            });
        } else if meta.is_dir() {
            if std::fs::symlink_metadata(path.join(".git")).is_ok() {
                continue;
            }
            let nested = filter.enter(&path, &rel)?;
            pure_walk(
                root,
                &path,
                nested.as_ref().unwrap_or(filter),
                object,
                submit,
            )?;
        } else if meta.is_file() {
            let snapshot = super::statcache::file_snapshot(&meta)
                .ok_or_else(|| format!("source is not a file: {}", path.display()))?;
            let kind = snapshot.kind();
            submit(WorktreeFile {
                rel,
                path,
                kind,
                snapshot,
            })?;
        } else {
            return Err(format!(
                "special file cannot enter source CAS: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn pipeline_worktree_files(
    cas: Option<&SourceCas>,
    walk: impl FnOnce(&mut dyn FnMut(WorktreeFile) -> Result<(), String>) -> Result<(), String>,
) -> Result<Vec<TreeEntry>, String> {
    let workers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(super::WALK_WORKER_CAP)
        .max(1);
    thread::scope(|scope| {
        let (task_tx, task_rx) = mpsc::sync_channel::<WorktreeFile>(workers * 2);
        let task_rx = Arc::new(Mutex::new(task_rx));
        let (result_tx, result_rx) = mpsc::channel::<Result<TreeEntry, String>>();
        let mut handles = Vec::new();
        for _ in 0..workers {
            let cas = cas.cloned();
            let task_rx = Arc::clone(&task_rx);
            let result_tx = result_tx.clone();
            handles.push(scope.spawn(move || {
                loop {
                    // Only dequeue is serialized. The receiver mutex is
                    // released before hashing, so shard lookups, reads, and CAS
                    // publication run concurrently across all workers.
                    let file = match task_rx.lock().expect("worktree queue lock").recv() {
                        Ok(file) => file,
                        Err(_) => break,
                    };
                    let hash = match &cas {
                        Some(cas) => cas
                            .hash_and_ingest_worktree_file(&file)
                            .map(|(hash, _)| hash),
                        None => filehash::hash_file_with_snapshot(&file.path, &file.snapshot),
                    };
                    let result = hash.map(|hash| TreeEntry {
                        rel: file.rel,
                        hash,
                        kind: file.kind,
                    });
                    if result_tx.send(result).is_err() {
                        break;
                    }
                }
            }));
        }
        drop(result_tx);
        let mut submitted = 0usize;
        let mut submit = |file| {
            task_tx
                .send(file)
                .map_err(|_| "worktree file workers stopped".to_string())?;
            submitted += 1;
            Ok(())
        };
        let walk_result = walk(&mut submit);
        drop(submit);
        drop(task_tx);
        let mut join_error = None;
        for handle in handles {
            if handle.join().is_err() {
                join_error = Some("worktree file worker panicked".to_string());
            }
        }
        if let Err(error) = walk_result {
            return Err(error);
        }
        if let Some(error) = join_error {
            return Err(error);
        }
        let mut out = Vec::new();
        for result in result_rx {
            out.push(result?);
        }
        debug_assert_eq!(out.len(), submitted);
        Ok(out)
    })
}

pub(super) fn worker_count(items: usize, cap: usize) -> usize {
    let available = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    items.min(cap).min(available).max(1)
}

pub(super) fn hash_file_uncached(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    let mut h = crate::crypto::sha256::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize_hex())
}
