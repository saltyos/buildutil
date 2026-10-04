//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ChildStdin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

pub mod filehash;
pub(crate) mod filter;
pub mod git;
pub mod statcache;
mod tree;
mod worktree;

#[cfg(test)]
mod tests;

pub(crate) use filter::{SOURCE_FILTER_FILE, SourceFilter};
const TREE_OBJECT_HEADER: &str = "buildutil-source-tree";
const WALK_WORKER_CAP: usize = 8;
const GIT_BLOB_WORKER_CAP: usize = 4;
/// Namespace every memo whose value depends on git-object ingestion semantics.
/// Bump whenever the conversion, filtering, mode, or tree-manifest contract
/// changes so an older result can never be mistaken for a current one.
const GIT_INGEST_SCHEMA_VERSION: u32 = 4;

static ACTIVE_SOURCE_CAS: Mutex<Option<SourceCas>> = Mutex::new(None);
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static HYBRID_FS_FILES: AtomicU64 = AtomicU64::new(0);

/// Nanoseconds spent in `hash_and_ingest_dir` during the current eval — the
/// source-ingestion phase timer. Accumulated across every referencing node, so
/// a per-invocation dir memo's effect shows as a drop here. Reset at the start
/// of each `evaluate_with_progress` pass via `reset_eval_phase_timers`.
static SOURCE_INGEST_NS: AtomicU64 = AtomicU64::new(0);

/// Nanoseconds spent in `closure()` (dependency-order resolution) and in the
/// residual instantiation loop (loop total minus source-ingest minus probe) for
/// the current eval. Set once per pass by `evaluate_with_progress`.
static CLOSURE_NS: AtomicU64 = AtomicU64::new(0);
static INSTANTIATE_NS: AtomicU64 = AtomicU64::new(0);

/// RAII phase timer: adds its lifetime (nanoseconds) to `sink` on drop, so a
/// scope with multiple early returns is timed without a return at each exit.
pub(crate) struct PhaseTimer<'a> {
    start: std::time::Instant,
    sink: &'a AtomicU64,
}

impl<'a> PhaseTimer<'a> {
    pub(crate) fn new(sink: &'a AtomicU64) -> Self {
        PhaseTimer {
            start: std::time::Instant::now(),
            sink,
        }
    }
}

impl Drop for PhaseTimer<'_> {
    fn drop(&mut self) {
        self.sink
            .fetch_add(self.start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
}

/// Per-invocation dir memo: canonical path → dirhash. Active only inside an eval
/// (guarded by a `DirMemoScope`), so within one eval a directory ingested by
/// multiple referencing derivations — including via the worktree walk — is
/// hashed exactly once. `None` outside an eval, so direct callers (tests) never
/// share state. `Mutex` for the parallel eval still to come.
static DIR_MEMO: Mutex<Option<BTreeMap<PathBuf, String>>> = Mutex::new(None);

/// RAII activation of `DIR_MEMO` for the duration of one eval pass.
pub(crate) struct DirMemoScope(());

impl DirMemoScope {
    pub(crate) fn new() -> Self {
        *DIR_MEMO.lock().expect("dir memo lock") = Some(BTreeMap::new());
        DirMemoScope(())
    }
}

impl Drop for DirMemoScope {
    fn drop(&mut self) {
        *DIR_MEMO.lock().expect("dir memo lock") = None;
    }
}

/// RAII lifetime for mutable Git observations and filtered-blob results. A new
/// scope is created for every evaluator pass, including each `dev --watch`
/// iteration, so neither cache can carry a clean probe or converted blob across
/// a worktree/config mutation between evaluations.
pub(crate) struct GitEvalCacheScope(());

impl GitEvalCacheScope {
    pub(crate) fn new() -> Self {
        git::begin_repo_probe_eval();
        statcache::begin_git_blob_memo_eval();
        GitEvalCacheScope(())
    }
}

impl Drop for GitEvalCacheScope {
    fn drop(&mut self) {
        statcache::end_git_blob_memo_eval();
        git::end_repo_probe_eval();
    }
}

/// Own every mutable source observation for one evaluation request. Keeping
/// this guard alive through a post-evaluation snapshot check lets that check
/// reuse same-request repository and blob observations; the check still
/// bypasses the directory-result memo and revalidates the source tree.
pub(crate) struct EvaluationMemoScope {
    _git_eval_caches: GitEvalCacheScope,
    _dir_memo: DirMemoScope,
}

impl EvaluationMemoScope {
    pub(crate) fn new() -> Self {
        EvaluationMemoScope {
            _git_eval_caches: GitEvalCacheScope::new(),
            _dir_memo: DirMemoScope::new(),
        }
    }
}

fn dir_memo_get(canon: &Path) -> Option<String> {
    DIR_MEMO
        .lock()
        .expect("dir memo lock")
        .as_ref()
        .and_then(|m| m.get(canon).cloned())
}

fn dir_memo_put(canon: PathBuf, dirhash: &str) {
    if let Some(map) = DIR_MEMO.lock().expect("dir memo lock").as_mut() {
        map.insert(canon, dirhash.to_string());
    }
}

/// Test-only serial guard. `ACTIVE_SOURCE_CAS` (here) plus `FILE_HASH_CACHE`
/// and `GIT_BLOB_MEMO` (in `statcache`) are process-global singletons, so any
/// test that activates the CAS or loads / records into a cache clobbers a
/// sibling's global state when they run concurrently (the source CAS then
/// reads from the wrong root). Every such test — here and in `plan` / `realize`
/// — holds this guard for its whole body, so the suite is safe at the default
/// thread count.
#[cfg(test)]
static CAS_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the CAS test guard, tolerating poisoning so one panicking test fails
/// on its own instead of cascade-failing every sibling.
#[cfg(test)]
pub(crate) fn cas_test_guard() -> std::sync::MutexGuard<'static, ()> {
    CAS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

#[derive(Clone)]
pub struct SourceCas {
    state_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceTreePathKind {
    Leaf,
    Directory,
}

impl SourceTreePathKind {
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::Leaf => "file",
            Self::Directory => "directory",
        }
    }
}

#[derive(Clone)]
struct TreeObject {
    entries: Vec<TreeEntry>,
    targets: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeEntry {
    rel: String,
    hash: String,
    kind: char,
}

#[derive(Clone)]
struct WorktreeFile {
    rel: String,
    path: PathBuf,
    kind: char,
    snapshot: statcache::FileSnapshot,
}

#[derive(Clone)]
struct GitBlobTask {
    oid: String,
    /// Path relative to the ingested root — stored as the `TreeEntry.rel`.
    entry_rel: String,
    /// Repo-relative path — used for the `cat-file --filters` lookup and the
    /// path component of the repo/schema/conversion/oid/path blob memo key.
    blob_rel: String,
    kind: char,
    symlink: bool,
}

struct GitTreeEntry {
    mode: String,
    kind: String,
    object: String,
    path: String,
}

struct GitBlobBatch {
    repo: PathBuf,
    child: Option<crate::invocation::Spawned>,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
}

/// Outcome of an object-db tree walk (`collect_git_tree`) that may legitimately
/// decline rather than fail. Distinguishes a guard refusal (an unclean gitlink
/// whose object-db tree would diverge from the checked-out bytes) from a genuine
/// error, so callers can fall back to the worktree walk without surfacing it.
#[derive(Debug)]
enum GitTreeErr {
    /// A guard refused the object-db path — an unclean, unresolvable, or
    /// uninitialized gitlink that would make the recorded-commit tree diverge
    /// from the checked-out bytes. The caller MUST fall back to the worktree
    /// walk, which reads the correct checked-out bytes. This is not an error.
    FallBack,
    /// A genuine failure (I/O, corrupt object, protocol error) that must
    /// surface as a build error.
    Hard(String),
}

impl From<String> for GitTreeErr {
    fn from(message: String) -> Self {
        GitTreeErr::Hard(message)
    }
}

impl SourceCas {
    pub fn open(state_root: &Path) -> Result<Self, String> {
        let cas = SourceCas {
            state_root: state_root.to_path_buf(),
        };
        for dir in [
            crate::state::source_cas_dir(state_root),
            crate::state::source_tree_dir(state_root),
            crate::state::source_gittree_dir(state_root),
            crate::state::source_tmp_dir(state_root),
        ] {
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
        }
        Ok(cas)
    }

    pub fn blob_path(&self, hash: &str, kind: char) -> PathBuf {
        let mut name = hash.to_string();
        if kind == 'x' {
            name.push_str(".x");
        }
        crate::state::source_cas_dir(&self.state_root)
            .join(hash.get(..2).unwrap_or(hash))
            .join(name)
    }

    pub fn tree_path(&self, dirhash: &str) -> PathBuf {
        crate::state::source_tree_dir(&self.state_root).join(dirhash)
    }

    pub fn hash_and_ingest_file(&self, path: &Path) -> Result<(String, char), String> {
        self.hash_and_ingest_file_inner(path, true)
    }

    fn hash_and_ingest_file_inner(
        &self,
        path: &Path,
        try_reflink: bool,
    ) -> Result<(String, char), String> {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let meta = std::fs::metadata(&canonical)
            .map_err(|e| format!("cannot stat {}: {}", canonical.display(), e))?;
        let snapshot = statcache::file_snapshot(&meta)
            .ok_or_else(|| format!("source is not a file: {}", canonical.display()))?;
        self.hash_and_ingest_file_snapshot(&canonical, &snapshot, try_reflink)
    }

    fn hash_and_ingest_worktree_file(&self, file: &WorktreeFile) -> Result<(String, char), String> {
        self.hash_and_ingest_file_snapshot(&file.path, &file.snapshot, true)
    }

    fn hash_and_ingest_file_snapshot(
        &self,
        path: &Path,
        snapshot: &statcache::FileSnapshot,
        try_reflink: bool,
    ) -> Result<(String, char), String> {
        let kind = snapshot.kind();
        let cache_token = statcache::file_cache_key_for_canonical(path, snapshot);
        if let Some(hash) = cache_token
            .as_ref()
            .and_then(statcache::cached_file_hash_for_key)
        {
            if self.blob_path(&hash, kind).is_file() {
                if !statcache::cache_token_still_matches(
                    cache_token.as_ref().expect("cache hit has token"),
                ) {
                    return Err(format!("source changed while ingesting {}", path.display()));
                }
                return Ok((hash, kind));
            }
        }
        if try_reflink {
            let tmp = self.tmp_path("blob");
            match git::reflink_file(path, &tmp) {
                Ok(()) => {
                    let hash = worktree::hash_file_uncached(&tmp)?;
                    self.publish_blob_tmp(&tmp, &hash, kind)?;
                    self.finish_file_snapshot(path, snapshot, cache_token, &hash)?;
                    return Ok((hash, kind));
                }
                Err(()) => {
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }
        let mut input = std::fs::File::open(path)
            .map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
        let (hash, kind) = self.ingest_reader(&mut input, kind)?;
        self.finish_file_snapshot(path, snapshot, cache_token, &hash)?;
        Ok((hash, kind))
    }

    fn finish_file_snapshot(
        &self,
        path: &Path,
        snapshot: &statcache::FileSnapshot,
        cache_token: Option<statcache::FileCacheToken>,
        hash: &str,
    ) -> Result<(), String> {
        let stable = match cache_token {
            Some(token) => statcache::record_file_hash_for_key(token, hash),
            None => statcache::snapshot_still_matches(path, snapshot),
        };
        if stable {
            Ok(())
        } else {
            Err(format!("source changed while ingesting {}", path.display()))
        }
    }

    pub fn hash_and_ingest_dir(&self, root: &Path) -> Result<String, String> {
        let _timer = PhaseTimer::new(&SOURCE_INGEST_NS);
        let canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        if let Some(dirhash) = dir_memo_get(&canon) {
            return Ok(dirhash);
        }
        let dirhash = self.ingest_dir_uncached(&canon)?;
        dir_memo_put(canon, &dirhash);
        Ok(dirhash)
    }

    /// Re-ingest a directory without consulting the per-request result memo.
    /// Snapshot validation must observe a source edit made after Stage 1, while
    /// the lower-level git and blob memo scopes remain available to this pass.
    pub(crate) fn recheck_and_ingest_dir(&self, root: &Path) -> Result<String, String> {
        let _timer = PhaseTimer::new(&SOURCE_INGEST_NS);
        let canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        self.ingest_dir_uncached(&canon)
    }

    fn ingest_dir_uncached(&self, root: &Path) -> Result<String, String> {
        let filter = SourceFilter::load_for_walk(root)?;
        // Prewarm produces only a candidate. The exact route is revalidated
        // here, immediately before any object-db memo/tree can be consumed.
        let checked = git::checked_git_tree_for_ingest(root, &filter, "");
        if let Some(checked) = checked.as_ref() {
            match self.ingest_checked_git_tree(root, checked) {
                Ok(dirhash) => {
                    trace_object_route(root, checked);
                    return Ok(dirhash);
                }
                Err(GitTreeErr::FallBack) => {}
                Err(GitTreeErr::Hard(e)) => return Err(e),
            }
        }
        if let Some(hybrid) = git::checked_hybrid_git_tree_for_ingest(root, &filter, "") {
            match self.ingest_checked_hybrid_tree(root, &hybrid, &filter, "") {
                Ok((dirhash, files)) => {
                    trace_source_route("hybrid", root, Some(files));
                    return Ok(dirhash);
                }
                Err(GitTreeErr::FallBack) => {}
                Err(GitTreeErr::Hard(e)) => return Err(e),
            }
        }
        let object = self.collect_worktree(root, &filter)?;
        let dirhash = self.write_tree_object(&object)?;
        flush_ingest_caches();
        Ok(dirhash)
    }

    /// Publish a `sources/gittree` memo entry (a `<dir>/<filter.hash>` file whose
    /// first line is the tree dirhash, followed by one `gitlink` line per nested
    /// checkout the ingest descended into) via a temp file + atomic rename. A
    /// failure only forfeits the cache, so callers ignore the result.
    fn publish_gittree_memo(&self, memo: &Path, content: &str) -> Result<(), String> {
        if let Some(parent) = memo.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        let tmp = self.tmp_path("gittree-memo");
        std::fs::write(&tmp, content)
            .map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
        match std::fs::rename(&tmp, memo) {
            Ok(()) => Ok(()),
            Err(_) if memo.is_file() => {
                let _ = std::fs::remove_file(&tmp);
                Ok(())
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(format!("cannot publish {}: {}", memo.display(), e))
            }
        }
    }

    pub fn materialize_tree(&self, dirhash: &str, dest: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dest)
            .map_err(|e| format!("cannot create {}: {}", dest.display(), e))?;
        self.materialize_tree_at(dirhash, dest, &[])
    }

    pub fn materialize_tree_with_holes(
        &self,
        dirhash: &str,
        dest: &Path,
        holes: &[String],
    ) -> Result<(), String> {
        std::fs::create_dir_all(dest)
            .map_err(|e| format!("cannot create {}: {}", dest.display(), e))?;
        self.materialize_tree_at(dirhash, dest, holes)
    }

    pub(crate) fn classify_tree_paths(
        &self,
        dirhash: &str,
        paths: &[String],
    ) -> Result<Vec<Option<SourceTreePathKind>>, String> {
        let object = self.load_tree_object(dirhash)?;
        paths
            .iter()
            .map(|path| classify_tree_path(&object.entries, path))
            .collect()
    }

    pub fn verify_tree_complete(&self, dirhash: &str) -> Result<(), String> {
        let object = self.load_tree_object(dirhash)?;
        for entry in object.entries {
            match entry.kind {
                'f' | 'x' => {
                    let blob = self.blob_path(&entry.hash, entry.kind);
                    if !blob.is_file() {
                        return Err(format!("tree {dirhash} missing blob {}", entry.hash));
                    }
                }
                'l' => {
                    if !object.targets.contains_key(&entry.hash) {
                        return Err(format!("tree {dirhash} missing symlink {}", entry.hash));
                    }
                }
                _ => return Err(format!("tree {dirhash} has invalid kind {}", entry.kind)),
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn ingest_git_tree(&self, checkout: &Path) -> Result<String, String> {
        if let Some(treeid) = git::clean_checkout_tree_id(checkout) {
            match self.ingest_clean_git_tree(checkout, &treeid) {
                Ok(dirhash) => Ok(dirhash),
                Err(GitTreeErr::FallBack) => self.hash_and_ingest_dir(checkout),
                Err(GitTreeErr::Hard(e)) => Err(e),
            }
        } else {
            self.hash_and_ingest_dir(checkout)
        }
    }

    /// Differential-test oracle: ingest only bytes and modes observed through
    /// filesystem syscalls. It deliberately bypasses every git probe, object-db
    /// shortcut, gittree memo, and blob memo.
    #[cfg(test)]
    fn ingest_pure_fs_oracle(&self, root: &Path) -> Result<String, String> {
        let filter = SourceFilter::load_for_walk(root)?;
        let object = self.collect_worktree(root, &filter)?;
        self.write_tree_object(&object)
    }

    pub(crate) fn tree_blob_refs(&self, dirhash: &str) -> Result<Vec<(String, char)>, String> {
        let object = self.load_tree_object(dirhash)?;
        let mut refs = Vec::new();
        for entry in object.entries {
            if matches!(entry.kind, 'f' | 'x') {
                refs.push((entry.hash, entry.kind));
            }
        }
        Ok(refs)
    }

    #[cfg(test)]
    fn ingest_clean_git_tree(&self, checkout: &Path, treeid: &str) -> Result<String, GitTreeErr> {
        let filter = SourceFilter::load_for_walk(checkout).map_err(GitTreeErr::Hard)?;
        let checked =
            git::checked_git_tree_for_ingest(checkout, &filter, "").ok_or(GitTreeErr::FallBack)?;
        if !checked.repo_prefix.is_empty() || checked.tree_id != treeid {
            return Err(GitTreeErr::FallBack);
        }
        self.ingest_checked_git_tree(checkout, &checked)
    }

    fn ingest_checked_git_tree(
        &self,
        checkout: &Path,
        checked: &git::CheckedGitTree,
    ) -> Result<String, GitTreeErr> {
        let filter = SourceFilter::load_for_walk(checkout)?;
        let memo = self.gittree_memo_path(checked, &filter);
        if let Ok(text) = std::fs::read_to_string(&memo) {
            let mut lines = text.lines();
            if let Some(dirhash) = lines.next().map(str::trim) {
                // The key covers only this repository; nested checkouts are
                // revalidated, since their untracked content and own filters
                // can change without changing the recorded gitlinks.
                if self.tree_path(dirhash).is_file() && gitlinks_still_valid(checkout, lines) {
                    return Ok(dirhash.to_string());
                }
            }
        }
        let mut object = TreeObject {
            entries: Vec::new(),
            targets: BTreeMap::new(),
        };
        let mut gitlinks = Vec::new();
        self.collect_git_tree(checked, "", &filter, &mut object, &mut gitlinks)?;
        let dirhash = self.write_tree_object(&object)?;
        let mut content = format!("{dirhash}\n");
        for link in &gitlinks {
            content.push_str(&format!(
                "gitlink {} {} {}\n",
                link.commit, link.filter_hash, link.entry_rel
            ));
        }
        self.publish_gittree_memo(&memo, &content)?;
        flush_ingest_caches();
        Ok(dirhash)
    }

    fn ingest_checked_hybrid_tree(
        &self,
        checkout: &Path,
        hybrid: &git::CheckedHybridTree,
        filter: &SourceFilter,
        entry_prefix: &str,
    ) -> Result<(String, usize), GitTreeErr> {
        let mut object = TreeObject {
            entries: Vec::new(),
            targets: BTreeMap::new(),
        };
        self.collect_git_tree_skipping(
            &hybrid.checked,
            entry_prefix,
            filter,
            &hybrid.changed,
            &mut object,
        )?;
        let mut fs_files = 0usize;
        for rel in &hybrid.changed {
            let path = checkout.join(rel);
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let entry_rel = tree::join_rel(entry_prefix, rel);
            if filter.excludes(&entry_rel, meta.is_dir()) {
                continue;
            }
            if meta.is_dir() && git::has_own_git_dir(&path) {
                continue;
            }
            let before = object.entries.len();
            let files = worktree::pipeline_worktree_files(Some(self), |submit| {
                self.walk_overlay_path(checkout, &path, entry_prefix, filter, &mut object, submit)
            })?;
            fs_files += files.len();
            object.entries.extend(files);
            debug_assert!(object.entries.len() >= before);
        }
        object.entries.sort_by(|a, b| a.rel.cmp(&b.rel));
        let dirhash = self.write_tree_object(&object)?;
        flush_ingest_caches();
        Ok((dirhash, fs_files))
    }

    fn collect_git_tree_skipping(
        &self,
        checked: &git::CheckedGitTree,
        entry_prefix: &str,
        filter: &SourceFilter,
        skipped: &[String],
        object: &mut TreeObject,
    ) -> Result<(), GitTreeErr> {
        let mut tasks = Vec::new();
        let mut nested_dirs = BTreeMap::new();
        for entry in git::git_ls_tree(&checked.toplevel, &checked.tree_id)? {
            if skipped
                .iter()
                .any(|path| entry.path == *path || entry.path.starts_with(&format!("{path}/")))
            {
                continue;
            }
            let entry_rel = tree::join_rel(entry_prefix, &entry.path);
            let blob_rel = tree::join_rel(&checked.repo_prefix, &entry.path);
            if filter.excludes_path_or_parent(&entry_rel, entry.mode == "160000") {
                continue;
            }
            match (entry.mode.as_str(), entry.kind.as_str()) {
                ("160000", "commit") => continue,
                _ if under_plain_nested_checkout(
                    &checked.toplevel,
                    &blob_rel,
                    &mut nested_dirs,
                ) =>
                {
                    return Err(GitTreeErr::FallBack);
                }
                ("120000", "blob") => tasks.push(GitBlobTask {
                    oid: entry.object,
                    entry_rel,
                    blob_rel,
                    kind: 'l',
                    symlink: true,
                }),
                (_, "blob") => {
                    let kind = if entry.mode == "100755" { 'x' } else { 'f' };
                    if let Some(hash) = self.git_blob_memo_hit(
                        &checked.toplevel,
                        &checked.conversion_state,
                        &entry.object,
                        &blob_rel,
                        kind,
                    )? {
                        object.entries.push(TreeEntry {
                            rel: entry_rel,
                            hash,
                            kind,
                        });
                    } else {
                        tasks.push(GitBlobTask {
                            oid: entry.object,
                            entry_rel,
                            blob_rel,
                            kind,
                            symlink: false,
                        });
                    }
                }
                _ => {}
            }
        }
        let fetched = self.parallel_git_blobs(checked, tasks)?;
        object.entries.extend(fetched.entries);
        for (hash, target) in fetched.targets {
            object.targets.entry(hash).or_insert(target);
        }
        Ok(())
    }

    fn walk_overlay_path(
        &self,
        root: &Path,
        path: &Path,
        entry_prefix: &str,
        filter: &SourceFilter,
        object: &mut TreeObject,
        submit: &mut dyn FnMut(WorktreeFile) -> Result<(), String>,
    ) -> Result<(), String> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("cannot stat {}: {}", path.display(), e))?;
        let rel = tree::join_rel(entry_prefix, &tree::rel_path_string(root, path)?);
        if filter.excludes(&rel, meta.is_dir()) {
            return Ok(());
        }
        if meta.file_type().is_symlink() {
            let target = tree::read_symlink_target(path)?;
            let hash = crate::crypto::sha256::hash_bytes(target.as_bytes());
            object.targets.entry(hash.clone()).or_insert(target);
            object.entries.push(TreeEntry {
                rel,
                hash,
                kind: 'l',
            });
        } else if meta.is_dir() {
            if git::has_own_git_dir(path) {
                return Ok(());
            }
            let nested = filter.enter(path, &rel)?;
            let filter = nested.as_ref().unwrap_or(filter);
            let mut children = std::fs::read_dir(path)
                .map_err(|e| format!("cannot read {}: {}", path.display(), e))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("read entry under {}: {}", path.display(), e))?;
            children.sort_by_key(|e| e.file_name());
            for child in children {
                self.walk_overlay_path(root, &child.path(), entry_prefix, filter, object, submit)?;
            }
        } else if meta.is_file() {
            let snapshot = statcache::file_snapshot(&meta)
                .ok_or_else(|| format!("source is not a file: {}", path.display()))?;
            submit(WorktreeFile {
                rel,
                path: path.to_path_buf(),
                kind: snapshot.kind(),
                snapshot,
            })?;
        } else {
            return Err(format!(
                "special file cannot enter source CAS: {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn gittree_memo_path(&self, checked: &git::CheckedGitTree, filter: &SourceFilter) -> PathBuf {
        let mut h = crate::crypto::sha256::Sha256::new();
        h.update(&GIT_INGEST_SCHEMA_VERSION.to_le_bytes());
        h.update(checked.head_tree.as_bytes());
        h.update(b"\0");
        h.update(checked.tree_id.as_bytes());
        h.update(b"\0");
        h.update(checked.repo_prefix.as_bytes());
        h.update(b"\0");
        h.update(checked.conversion_state.as_bytes());
        crate::state::source_gittree_dir(&self.state_root)
            .join(format!("v{GIT_INGEST_SCHEMA_VERSION}"))
            .join("toplevel")
            .join(h.finalize_hex())
            .join(&filter.hash)
    }

    fn collect_worktree(&self, root: &Path, filter: &SourceFilter) -> Result<TreeObject, String> {
        let mut object = TreeObject {
            entries: Vec::new(),
            targets: BTreeMap::new(),
        };
        let files = worktree::pipeline_worktree_files(Some(self), |submit| {
            self.walk_worktree(root, root, filter, &mut object, submit)
        })?;
        trace_source_route("walk", root, Some(files.len()));
        object.entries.extend(files);
        object.entries.sort_by(|a, b| a.rel.cmp(&b.rel));
        Ok(object)
    }

    fn walk_worktree(
        &self,
        root: &Path,
        dir: &Path,
        filter: &SourceFilter,
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
            let rel = tree::rel_path_string(root, &path)?;
            if filter.excludes(&rel, meta.is_dir()) {
                continue;
            }
            if meta.file_type().is_symlink() {
                let target = tree::read_symlink_target(&path)?;
                let hash = crate::crypto::sha256::hash_bytes(target.as_bytes());
                object.targets.entry(hash.clone()).or_insert(target);
                object.entries.push(TreeEntry {
                    rel,
                    hash,
                    kind: 'l',
                });
            } else if meta.is_dir() {
                if git::has_own_git_dir(&path) {
                    continue;
                }
                let nested = filter.enter(&path, &rel)?;
                self.walk_worktree(
                    root,
                    &path,
                    nested.as_ref().unwrap_or(filter),
                    object,
                    submit,
                )?;
            } else if meta.is_file() {
                let snapshot = statcache::file_snapshot(&meta)
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

    fn collect_git_tree(
        &self,
        checked: &git::CheckedGitTree,
        entry_prefix: &str,
        filter: &SourceFilter,
        object: &mut TreeObject,
        _gitlinks: &mut Vec<GitlinkMemo>,
    ) -> Result<(), GitTreeErr> {
        let mut tasks = Vec::new();
        let mut nested_dirs = BTreeMap::new();
        for entry in git::git_ls_tree(&checked.toplevel, &checked.tree_id)? {
            // `entry_rel` is relative to the ingested root — it is what the tree
            // stores and what `.buildutilignore` matches, mirroring the worktree
            // walk. `blob_rel` is repo-relative so `cat-file --filters` resolves
            // `.gitattributes` correctly and the blob memo is keyed by the path
            // the filtered bytes actually depend on. They differ only
            // when a src-dir is a subtree of its enclosing git toplevel.
            let entry_rel = tree::join_rel(entry_prefix, &entry.path);
            let blob_rel = tree::join_rel(&checked.repo_prefix, &entry.path);
            if filter.excludes_path_or_parent(&entry_rel, entry.mode == "160000") {
                continue;
            }
            match (entry.mode.as_str(), entry.kind.as_str()) {
                ("160000", "commit") => continue,
                _ if under_plain_nested_checkout(
                    &checked.toplevel,
                    &blob_rel,
                    &mut nested_dirs,
                ) =>
                {
                    return Err(GitTreeErr::FallBack);
                }
                ("120000", "blob") => {
                    tasks.push(GitBlobTask {
                        oid: entry.object,
                        entry_rel,
                        blob_rel,
                        kind: 'l',
                        symlink: true,
                    });
                }
                (_, "blob") => {
                    let kind = if entry.mode == "100755" { 'x' } else { 'f' };
                    if let Some(hash) = self.git_blob_memo_hit(
                        &checked.toplevel,
                        &checked.conversion_state,
                        &entry.object,
                        &blob_rel,
                        kind,
                    )? {
                        object.entries.push(TreeEntry {
                            rel: entry_rel,
                            hash,
                            kind,
                        });
                    } else {
                        tasks.push(GitBlobTask {
                            oid: entry.object,
                            entry_rel,
                            blob_rel,
                            kind,
                            symlink: false,
                        });
                    }
                }
                _ => {}
            }
        }
        let fetched = self.parallel_git_blobs(checked, tasks)?;
        object.entries.extend(fetched.entries);
        for (hash, target) in fetched.targets {
            object.targets.entry(hash).or_insert(target);
        }
        object.entries.sort_by(|a, b| a.rel.cmp(&b.rel));
        Ok(())
    }

    fn parallel_git_blobs(
        &self,
        checked: &git::CheckedGitTree,
        tasks: Vec<GitBlobTask>,
    ) -> Result<TreeObject, String> {
        if tasks.is_empty() {
            return Ok(TreeObject {
                entries: Vec::new(),
                targets: BTreeMap::new(),
            });
        }
        let workers = worktree::worker_count(tasks.len(), GIT_BLOB_WORKER_CAP);
        let mut chunks = vec![Vec::new(); workers];
        for (idx, task) in tasks.into_iter().enumerate() {
            chunks[idx % workers].push(task);
        }
        let cas = self.clone();
        thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in chunks {
                let cas = cas.clone();
                let repo = checked.toplevel.clone();
                let conversion_state = checked.conversion_state.clone();
                handles.push(scope.spawn(move || {
                    let mut blobs = GitBlobBatch::open(&repo)?;
                    let mut object = TreeObject {
                        entries: Vec::new(),
                        targets: BTreeMap::new(),
                    };
                    for task in chunk {
                        let data = blobs.blob(&task.oid, &task.blob_rel)?;
                        if task.symlink {
                            let target = String::from_utf8(data).map_err(|_| {
                                format!("non-UTF-8 symlink target in git tree: {}", task.entry_rel)
                            })?;
                            tree::reject_newline_target(&target, &task.entry_rel)?;
                            let hash = crate::crypto::sha256::hash_bytes(target.as_bytes());
                            object.targets.entry(hash.clone()).or_insert(target);
                            object.entries.push(TreeEntry {
                                rel: task.entry_rel,
                                hash,
                                kind: 'l',
                            });
                        } else {
                            let hash = cas.ingest_git_blob_bytes(
                                &repo,
                                &conversion_state,
                                &task.oid,
                                &task.blob_rel,
                                &data,
                                task.kind,
                            )?;
                            object.entries.push(TreeEntry {
                                rel: task.entry_rel,
                                hash,
                                kind: task.kind,
                            });
                        }
                    }
                    blobs.finish()?;
                    Ok::<TreeObject, String>(object)
                }));
            }
            let mut merged = TreeObject {
                entries: Vec::new(),
                targets: BTreeMap::new(),
            };
            for handle in handles {
                let object = handle
                    .join()
                    .map_err(|_| "git blob worker panicked".to_string())??;
                merged.entries.extend(object.entries);
                for (hash, target) in object.targets {
                    merged.targets.entry(hash).or_insert(target);
                }
            }
            Ok(merged)
        })
    }

    fn git_blob_memo_hit(
        &self,
        repo: &Path,
        conversion_state: &str,
        oid: &str,
        rel: &str,
        kind: char,
    ) -> Result<Option<String>, String> {
        let Some(hash) = statcache::cached_git_blob_hash(
            repo,
            GIT_INGEST_SCHEMA_VERSION,
            conversion_state,
            oid,
            rel,
        ) else {
            return Ok(None);
        };
        if self.blob_path(&hash, kind).is_file() {
            return Ok(Some(hash));
        }
        let other = if kind == 'x' { 'f' } else { 'x' };
        if self.blob_path(&hash, other).is_file() {
            self.publish_blob_from_existing(&hash, other, kind)?;
            return Ok(Some(hash));
        }
        Ok(None)
    }

    fn ingest_git_blob_bytes(
        &self,
        repo: &Path,
        conversion_state: &str,
        oid: &str,
        rel: &str,
        data: &[u8],
        kind: char,
    ) -> Result<String, String> {
        let (hash, _) = self.ingest_bytes(data, kind)?;
        statcache::record_git_blob_hash(
            repo,
            GIT_INGEST_SCHEMA_VERSION,
            conversion_state,
            oid,
            rel,
            &hash,
        );
        Ok(hash)
    }

    fn ingest_reader(&self, input: &mut dyn Read, kind: char) -> Result<(String, char), String> {
        let tmp = self.tmp_path("blob");
        let mut out = std::fs::File::create(&tmp)
            .map_err(|e| format!("cannot create {}: {}", tmp.display(), e))?;
        let mut h = crate::crypto::sha256::Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = input
                .read(&mut buf)
                .map_err(|e| format!("cannot read source: {}", e))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])
                .map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
        }
        out.sync_all()
            .map_err(|e| format!("cannot sync {}: {}", tmp.display(), e))?;
        drop(out);
        let hash = h.finalize_hex();
        self.publish_blob_tmp(&tmp, &hash, kind)?;
        Ok((hash, kind))
    }

    fn ingest_bytes(&self, data: &[u8], kind: char) -> Result<(String, char), String> {
        let hash = crate::crypto::sha256::hash_bytes(data);
        let final_path = self.blob_path(&hash, kind);
        if final_path.is_file() {
            return Ok((hash, kind));
        }
        let tmp = self.tmp_path("blob");
        std::fs::write(&tmp, data).map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
        self.publish_blob_tmp(&tmp, &hash, kind)?;
        Ok((hash, kind))
    }

    fn publish_blob_from_existing(
        &self,
        hash: &str,
        from_kind: char,
        to_kind: char,
    ) -> Result<(), String> {
        let src = self.blob_path(hash, from_kind);
        let tmp = self.tmp_path("blob");
        if git::reflink_file(&src, &tmp).is_err() {
            std::fs::copy(&src, &tmp).map_err(|e| {
                format!("cannot copy {} -> {}: {}", src.display(), tmp.display(), e)
            })?;
        }
        self.publish_blob_tmp(&tmp, hash, to_kind)
    }

    fn publish_blob_tmp(&self, tmp: &Path, hash: &str, kind: char) -> Result<(), String> {
        let final_path = self.blob_path(hash, kind);
        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        crate::platform::set_mode(tmp, if kind == 'x' { 0o555 } else { 0o444 })
            .map_err(|e| format!("cannot chmod {}: {}", tmp.display(), e))?;
        match std::fs::hard_link(tmp, &final_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) if final_path.is_file() => {}
            Err(e) => {
                let _ = std::fs::remove_file(tmp);
                return Err(format!(
                    "cannot publish blob {}: {}",
                    final_path.display(),
                    e
                ));
            }
        }
        std::fs::remove_file(tmp).map_err(|e| format!("cannot remove {}: {}", tmp.display(), e))?;
        Ok(())
    }

    fn write_tree_object(&self, object: &TreeObject) -> Result<String, String> {
        let entries = tree::manifest_entries(&object.entries);
        let dirhash = crate::crypto::sha256::hash_bytes(entries.as_bytes());
        let path = self.tree_path(&dirhash);
        if path.is_file() {
            return Ok(dirhash);
        }
        let mut text = String::new();
        writeln!(&mut text, "{TREE_OBJECT_HEADER}").expect("write to string");
        writeln!(&mut text, "format: 1").expect("write to string");
        writeln!(&mut text, "dir-hash: {dirhash}").expect("write to string");
        writeln!(&mut text, "entries:").expect("write to string");
        text.push_str(&entries);
        writeln!(&mut text, "targets:").expect("write to string");
        for (hash, target) in &object.targets {
            writeln!(&mut text, "{hash}={target}").expect("write to string");
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        let tmp = self.tmp_path("tree");
        std::fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) if path.is_file() => {}
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(format!(
                    "cannot publish tree object {}: {}",
                    path.display(),
                    e
                ));
            }
        }
        std::fs::remove_file(&tmp)
            .map_err(|e| format!("cannot remove {}: {}", tmp.display(), e))?;
        Ok(dirhash)
    }

    fn load_tree_object(&self, dirhash: &str) -> Result<TreeObject, String> {
        let path = self.tree_path(dirhash);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read tree object {}: {}", path.display(), e))?;
        tree::parse_tree_object(&text, dirhash)
    }

    fn materialize_tree_at(
        &self,
        dirhash: &str,
        dest: &Path,
        holes: &[String],
    ) -> Result<(), String> {
        let object = self.load_tree_object(dirhash)?;
        for entry in object.entries {
            if holes.iter().any(|hole| path_under(&entry.rel, hole)) {
                continue;
            }
            let out = dest.join(&entry.rel);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {}", out.display(), e))?;
            }
            match entry.kind {
                'f' | 'x' => {
                    let blob = self.blob_path(&entry.hash, entry.kind);
                    match std::fs::hard_link(&blob, &out) {
                        Ok(()) => {}
                        Err(_) => {
                            std::fs::copy(&blob, &out).map_err(|e| {
                                format!(
                                    "cannot copy {} -> {}: {}",
                                    blob.display(),
                                    out.display(),
                                    e
                                )
                            })?;
                            let perms = std::fs::metadata(&blob)
                                .map_err(|e| format!("cannot stat {}: {}", blob.display(), e))?
                                .permissions();
                            std::fs::set_permissions(&out, perms)
                                .map_err(|e| format!("cannot chmod {}: {}", out.display(), e))?;
                        }
                    }
                }
                'l' => {
                    let target = object
                        .targets
                        .get(&entry.hash)
                        .ok_or_else(|| format!("tree object lacks target for {}", entry.hash))?;
                    crate::platform::create_symlink_auto(Path::new(target), &out)
                        .map_err(|e| format!("cannot symlink {}: {}", out.display(), e))?;
                }
                _ => return Err(format!("invalid tree entry kind `{}`", entry.kind)),
            }
        }
        Ok(())
    }

    fn tmp_path(&self, kind: &str) -> PathBuf {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        crate::state::source_tmp_dir(&self.state_root).join(format!(
            "{}-{}-{}",
            std::process::id(),
            seq,
            kind
        ))
    }
}

/// A nested checkout a Git-object ingest descended into. A memoised tree
/// stays valid only while each one still passes its route guard under an
/// unchanged filter.
struct GitlinkMemo {
    entry_rel: String,
    commit: String,
    filter_hash: String,
}

/// Recheck the `gitlink <commit> <filter-hash> <entry_rel>` lines of a
/// gittree memo against the checkout at `checkout`.
fn gitlinks_still_valid<'a>(checkout: &Path, lines: impl Iterator<Item = &'a str>) -> bool {
    for line in lines {
        let mut fields = line.splitn(4, ' ');
        let (Some("gitlink"), Some(commit), Some(filter_hash), Some(entry_rel)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        let dir = checkout.join(entry_rel);
        let Ok(filter) = SourceFilter::for_nested_repository(&dir, entry_rel) else {
            return false;
        };
        if filter.hash != filter_hash
            || git::checked_gitlink_tree(&dir, commit, &filter, entry_rel).is_none()
        {
            return false;
        }
    }
    true
}

/// Whether tracked `blob_rel` lies inside a checkout that is not a gitlink of
/// this repository. Such a checkout is its own filter scope, which the object
/// route cannot apply to paths it lists as ordinary blobs, so callers fall
/// back to the filesystem walk. `seen` caches per-directory answers.
fn under_plain_nested_checkout(
    toplevel: &Path,
    blob_rel: &str,
    seen: &mut BTreeMap<String, bool>,
) -> bool {
    let mut dir = String::new();
    let parts: Vec<&str> = blob_rel.split('/').collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        if !dir.is_empty() {
            dir.push('/');
        }
        dir.push_str(part);
        let nested = *seen
            .entry(dir.clone())
            .or_insert_with(|| git::has_own_git_dir(&toplevel.join(&dir)));
        if nested {
            return true;
        }
    }
    false
}

fn trace_source_route(route: &str, root: &Path, files: Option<usize>) {
    #[cfg(test)]
    if route == "hybrid" {
        HYBRID_FS_FILES.store(files.unwrap_or(0) as u64, Ordering::Relaxed);
    }
    if std::env::var_os("BUILDUTIL_TRACE_SOURCE_ROUTES").is_none() {
        return;
    }
    match files {
        Some(files) => crate::log::info(
            "source",
            &format!(
                "source-route={route} root={} walk-files={files}",
                root.display()
            ),
        ),
        None => crate::log::info(
            "source",
            &format!("source-route={route} root={}", root.display()),
        ),
    }
}

#[cfg(test)]
fn hybrid_fs_files() -> u64 {
    HYBRID_FS_FILES.load(Ordering::Relaxed)
}

fn trace_object_route(root: &Path, checked: &git::CheckedGitTree) {
    if std::env::var_os("BUILDUTIL_TRACE_SOURCE_ROUTES").is_some() {
        crate::log::info(
            "source",
            &format!(
                "source-route=object-db root={} repo-prefix={} tree={}",
                root.display(),
                checked.repo_prefix,
                checked.tree_id
            ),
        );
    }
}

fn path_under(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn classify_tree_path(
    entries: &[TreeEntry],
    path: &str,
) -> Result<Option<SourceTreePathKind>, String> {
    if path.is_empty() {
        return Err("cannot classify an empty source-tree path".to_string());
    }

    let mut kind = None;
    for entry in entries {
        if entry.rel == path {
            if kind == Some(SourceTreePathKind::Directory) {
                return Err(format!(
                    "source tree contains both file `{path}` and entries below it"
                ));
            }
            kind = Some(SourceTreePathKind::Leaf);
            continue;
        }
        if path_under(&entry.rel, path) {
            if kind == Some(SourceTreePathKind::Leaf) {
                return Err(format!(
                    "source tree contains both file `{path}` and entries below it"
                ));
            }
            kind = Some(SourceTreePathKind::Directory);
            continue;
        }
        if path_under(path, &entry.rel) {
            return Err(format!(
                "source-overlay destination `{path}` has file ancestor `{}` in the source tree",
                entry.rel
            ));
        }
    }
    Ok(kind)
}

pub fn activate(state_root: &Path) -> Result<(), String> {
    let cas = SourceCas::open(state_root)?;
    *ACTIVE_SOURCE_CAS.lock().expect("source CAS lock") = Some(cas);
    Ok(())
}

pub fn active() -> Option<SourceCas> {
    ACTIVE_SOURCE_CAS
        .lock()
        .expect("source CAS lock")
        .as_ref()
        .cloned()
}

pub fn hash_and_ingest_file(path: &Path) -> Result<(String, char), String> {
    if let Some(cas) = active() {
        cas.hash_and_ingest_file(path)
    } else {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot stat {}: {}", path.display(), e))?;
        let kind = if crate::platform::file_mode(&meta) & 0o111 != 0 {
            'x'
        } else {
            'f'
        };
        Ok((filehash::hash_file(path)?, kind))
    }
}

/// Capture symbolic bootstrap data as a plain, immutable CAS blob.
pub(crate) fn ingest_bytes(bytes: &[u8]) -> Result<String, String> {
    let cas = active().ok_or("source CAS is not active")?;
    cas.ingest_reader(&mut std::io::Cursor::new(bytes), 'f')
        .map(|(hash, _)| hash)
}

pub fn hash_and_ingest_dir(root: &Path) -> Result<String, String> {
    if let Some(cas) = active() {
        cas.hash_and_ingest_dir(root)
    } else {
        let filter = SourceFilter::load_for_walk(root)?;
        let object = worktree::collect_filtered_pure(root, &filter)?;
        Ok(crate::crypto::sha256::hash_bytes(
            tree::manifest_entries(&object.entries).as_bytes(),
        ))
    }
}

/// Capture one repository with the lock's selection rules and publish its CAS tree.
pub(crate) fn ingest_repository(root: &Path, excluded: &[String]) -> Result<String, String> {
    ingest_selected_tree(root, excluded, true)
}

/// Select a derivation's own subtree from an already captured repository.
/// Its filter has already selected content, so an enclosing checkout cannot
/// filter the immutable view again.
pub(crate) fn input_subtree(content: &str, relative: &str) -> Result<String, String> {
    crate::inputs::codec::clean_path(relative)?;
    let hash = content
        .strip_prefix("tree:")
        .ok_or("input lacks a tree address")?;
    let cas = active().ok_or("source CAS is not active")?;
    let captured = cas.load_tree_object(hash)?;
    let prefix = format!("{relative}/");
    let mut object = TreeObject {
        entries: Vec::new(),
        targets: std::collections::BTreeMap::new(),
    };
    for entry in captured.entries {
        if let Some(rel) = entry.rel.strip_prefix(&prefix) {
            if let Some(target) = captured.targets.get(&entry.hash) {
                object.targets.insert(entry.hash.clone(), target.clone());
            }
            object.entries.push(TreeEntry {
                rel: rel.to_string(),
                kind: entry.kind,
                hash: entry.hash,
            });
        }
    }
    cas.write_tree_object(&object)
}

/// Read specification bytes from the selected CAS tree rather than a second
/// checkout read that could describe a different input graph.
pub(crate) fn input_file(content: &str, relative: &str) -> Result<Vec<u8>, String> {
    crate::inputs::codec::clean_path(relative)?;
    let hash = content
        .strip_prefix("tree:")
        .ok_or("input lacks a tree address")?;
    let cas = active().ok_or("source CAS is not active")?;
    let captured = cas.load_tree_object(hash)?;
    let entry = captured
        .entries
        .iter()
        .find(|entry| entry.rel == relative && matches!(entry.kind, 'f' | 'x'))
        .ok_or_else(|| {
            format!("input specification `{relative}` is not selected repository content")
        })?;
    std::fs::read(cas.blob_path(&entry.hash, entry.kind))
        .map_err(|e| format!("cannot read captured input specification: {e}"))
}

/// A source projection supplied entirely by dependency outputs has no
/// checkout sources of its own.
pub(crate) fn empty_tree() -> Result<String, String> {
    if let Some(cas) = active() {
        cas.write_tree_object(&TreeObject {
            entries: Vec::new(),
            targets: BTreeMap::new(),
        })
    } else {
        Ok(crate::crypto::sha256::hash_bytes(b""))
    }
}

/// Capture an owner's subtree while inheriting that repository's source filter.
pub(crate) fn ingest_owned_subtree(root: &Path, excluded: &[String]) -> Result<String, String> {
    ingest_selected_tree(root, excluded, false)
}

fn ingest_selected_tree(
    root: &Path,
    excluded: &[String],
    independent: bool,
) -> Result<String, String> {
    let ingest = |path: &Path| {
        let Some(cas) = active() else {
            return crate::inputs::content::file(path);
        };
        let before = std::fs::symlink_metadata(path)
            .map_err(|e| format!("cannot stat input {}: {e}", path.display()))?;
        let snapshot = statcache::file_snapshot(&before).ok_or("input is not a file")?;
        let mut reader = std::fs::File::open(path)
            .map_err(|e| format!("cannot open input {}: {e}", path.display()))?;
        let result = cas.ingest_reader(&mut reader, snapshot.kind())?;
        if !statcache::snapshot_still_matches(path, &snapshot) {
            return Err(format!("input changed during capture: {}", path.display()));
        }
        Ok(result)
    };
    let captured = if independent {
        crate::inputs::content::capture_with(root, excluded, ingest)?
    } else {
        crate::inputs::content::capture_owned_with(root, excluded, ingest)?
    };
    let Some(cas) = active() else {
        return Ok(captured.hash());
    };
    let object = TreeObject {
        entries: captured
            .entries
            .into_iter()
            .map(|(rel, kind, hash)| TreeEntry { rel, kind, hash })
            .collect(),
        targets: captured.targets,
    };
    cas.write_tree_object(&object)
}

/// Re-read a directory for evaluation snapshot validation without accepting a
/// cached directory result from the current request.
pub(crate) fn recheck_and_ingest_dir(root: &Path) -> Result<String, String> {
    if let Some(cas) = active() {
        cas.recheck_and_ingest_dir(root)
    } else {
        let filter = SourceFilter::load_for_walk(root)?;
        let object = worktree::collect_filtered_pure(root, &filter)?;
        Ok(crate::crypto::sha256::hash_bytes(
            tree::manifest_entries(&object.entries).as_bytes(),
        ))
    }
}

pub fn blob_path(hash: &str, kind: char) -> Result<PathBuf, String> {
    Ok(active()
        .ok_or_else(|| "source CAS is not active".to_string())?
        .blob_path(hash, kind))
}

pub fn materialize_tree(dirhash: &str, dest: &Path) -> Result<(), String> {
    active()
        .ok_or_else(|| "source CAS is not active".to_string())?
        .materialize_tree(dirhash, dest)
}

pub fn materialize_tree_with_holes(
    dirhash: &str,
    dest: &Path,
    holes: &[String],
) -> Result<(), String> {
    active()
        .ok_or_else(|| "source CAS is not active".to_string())?
        .materialize_tree_with_holes(dirhash, dest, holes)
}

pub(crate) fn classify_tree_paths(
    dirhash: &str,
    paths: &[String],
) -> Result<Vec<Option<SourceTreePathKind>>, String> {
    active()
        .ok_or_else(|| "source CAS is not active".to_string())?
        .classify_tree_paths(dirhash, paths)
}

pub fn verify_tree_complete(dirhash: &str) -> Result<(), String> {
    active()
        .ok_or_else(|| "source CAS is not active".to_string())?
        .verify_tree_complete(dirhash)
}

/// Source-ingestion phase time (ms) for the current eval — see `SOURCE_INGEST_NS`.
pub fn source_ingest_ms() -> u128 {
    (SOURCE_INGEST_NS.load(Ordering::Relaxed) / 1_000_000) as u128
}

/// Closure (dependency-order resolution) phase time (ms) for the current eval.
pub fn closure_ms() -> u128 {
    (CLOSURE_NS.load(Ordering::Relaxed) / 1_000_000) as u128
}

/// Residual instantiation phase time (ms) for the current eval (loop total
/// minus source-ingest minus git-probe).
pub fn instantiate_ms() -> u128 {
    (INSTANTIATE_NS.load(Ordering::Relaxed) / 1_000_000) as u128
}

/// Record the closure / residual-instantiate phase durations for `--timings`.
pub(crate) fn set_closure_ns(ns: u64) {
    CLOSURE_NS.store(ns, Ordering::Relaxed);
}
pub(crate) fn set_instantiate_ns(ns: u64) {
    INSTANTIATE_NS.store(ns, Ordering::Relaxed);
}
pub(crate) fn set_source_ingest_ns(ns: u64) {
    SOURCE_INGEST_NS.store(ns, Ordering::Relaxed);
}

/// Zero every per-eval phase timer (closure, source ingest, git probe,
/// residual instantiate) at the start of each `evaluate_with_progress` pass.
pub fn reset_eval_phase_timers() {
    SOURCE_INGEST_NS.store(0, Ordering::Relaxed);
    CLOSURE_NS.store(0, Ordering::Relaxed);
    INSTANTIATE_NS.store(0, Ordering::Relaxed);
    git::reset_probe_ns();
}

/// Warm the exact referenced source routes in parallel before the serial
/// instantiate loop — see `git::prewarm_probes`.
pub(crate) fn prewarm_probes(dirs: &[PathBuf]) {
    git::prewarm_probes(dirs);
}

fn flush_ingest_caches() {
    // Nothing to flush mid-ingest: the git-blob memo is evaluation-local and
    // never persisted, while the file stat cache flushes exit-only
    // from `main()` (see the join-comment at `statcache::flush_file_cache`).
    // Kept as the single mid-ingest hook so a future persisted cache has one
    // place to wire into.
}
