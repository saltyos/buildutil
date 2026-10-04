//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — store garbage collection: mark-and-sweep from roots, tmp-build
//! sweep, source-CAS sweep, and the mark plan sources / sweep helpers.
//!
//! Free GC helpers shared with sibling store submodules:
//!   `sanitize_temp_root_label` — used by `Store::add_temp_roots` (mod.rs)
//!   `same_inode` — used by `Store::optimise_with_lease` (maintain.rs)

use super::Store;
use super::{GcOptions, GcPolicy, GcProgress, GcReport, GcSweep};
use crate::source::SourceCas;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct SourceGcReport {
    cas_swept: usize,
    plans_swept: usize,
    bytes: u64,
}

#[derive(Default)]
struct SourceMarks {
    cas: BTreeSet<String>,
    trees: BTreeSet<String>,
    exec: BTreeSet<String>,
}

impl Store {
    pub(super) fn collect_valid_roots(
        &self,
        dry_run: bool,
        prune_older_than_days: Option<u64>,
    ) -> Result<BTreeMap<String, String>, String> {
        let roots_dir = self.state.join("roots");
        let cutoff = prune_older_than_days.map(|days| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(days.saturating_mul(86400))
        });
        let mut roots = BTreeMap::new();
        for entry in std::fs::read_dir(&roots_dir).map_err(|e| format!("cannot read roots: {e}"))? {
            let entry = entry.map_err(|e| format!("roots entry: {e}"))?;
            let root_name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let Ok(target) = std::fs::read_link(&path) else {
                continue;
            };
            if root_name.starts_with(super::INDIRECT_ROOT_PREFIX) {
                // An indirect root names a link an app keeps in its run
                // state; the root lives while that link names a store
                // entry and is pruned once the app removes it.
                match self.indirect_root_target(&target) {
                    Some(name) => {
                        roots.insert(root_name, name);
                    }
                    None => {
                        if !dry_run {
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
                continue;
            }
            if root_name.starts_with("latest-") {
                if let Some(cutoff) = cutoff {
                    let mtime = std::fs::symlink_metadata(&path)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if mtime < cutoff {
                        if !dry_run {
                            let _ = std::fs::remove_file(&path);
                        }
                        continue;
                    }
                }
            }
            let Some(name) = target.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                if !dry_run {
                    let _ = std::fs::remove_file(&path);
                }
                continue;
            };
            if !self.has_named(&name) {
                if !dry_run {
                    let _ = std::fs::remove_file(&path);
                }
                continue;
            }
            if target.is_absolute() && !dry_run {
                self.add_root(&root_name, &name)?;
            }
            roots.insert(root_name, name);
        }
        Ok(roots)
    }

    fn mark_roots(
        &self,
        options: &GcOptions,
        seeded_roots: Option<&BTreeMap<String, String>>,
        progress: &mut dyn FnMut(GcProgress),
    ) -> Result<(BTreeSet<String>, BTreeSet<String>, usize), String> {
        let mut live: BTreeSet<String> = BTreeSet::new();
        let mut live_drv: BTreeSet<String> = BTreeSet::new();
        let mut queue: Vec<String> = Vec::new();
        let mut roots_scanned = 0usize;
        let persistent = match seeded_roots {
            Some(roots) => roots.clone(),
            None => {
                self.collect_valid_roots(options.dry_run, options.prune_roots_older_than_days)?
            }
        };
        for name in persistent.into_values() {
            progress(GcProgress::Root(name.clone()));
            queue.push(name);
            roots_scanned += 1;
        }
        let temproots_dir = self.state.join("temproots");
        match std::fs::read_dir(&temproots_dir) {
            Ok(rd) => {
                for entry in rd {
                    let entry = entry.map_err(|e| format!("temp root entry: {}", e))?;
                    let path = entry.path();
                    let file_name = entry.file_name().to_string_lossy().into_owned();
                    if !file_name.ends_with(".roots") {
                        continue;
                    }
                    let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
                        continue;
                    };
                    // A temp-root file whose flock is not held is stale. It is
                    // not a root and can be removed opportunistically.
                    match crate::platform::lock_exclusive(&file, true) {
                        Ok(true) => {
                            let _ = std::fs::remove_file(&path);
                            continue;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            return Err(format!(
                                "cannot inspect temp root {}: {}",
                                path.display(),
                                err
                            ));
                        }
                    }
                    let Ok(text) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    progress(GcProgress::TempRoot(file_name));
                    roots_scanned += 1;
                    for line in text.lines().map(str::trim) {
                        if !line.is_empty() && !line.starts_with('#') {
                            queue.push(line.to_string());
                        }
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot read temp roots: {}", e)),
        }
        while let Some(name) = queue.pop() {
            if !live.insert(name.clone()) {
                continue;
            }
            if let Ok(meta) = self.read_meta(&name) {
                if !meta.drv_hash.is_empty() {
                    live_drv.insert(meta.drv_hash.clone());
                }
                queue.extend(meta.refs);
                queue.extend(meta.references);
            }
        }
        Ok((live, live_drv, roots_scanned))
    }

    /// Provider-aware mark-and-sweep GC. Liveness flows from persistent roots
    /// and flock-held temporary roots over `ref:` edges in union with the
    /// scan-recorded `reference:` edges. `repo_root` is the on-disk
    /// location of the legacy un-migrated text caches (`src-hash-cache`,
    /// `tool-id-cache`) — they are unlinked unconditionally when present.
    pub fn gc_report_with_lease(
        &self,
        lease: &crate::state::StoreExclusiveLease,
        options: &GcOptions,
        repo_root: Option<&Path>,
        progress: &mut dyn FnMut(GcProgress),
    ) -> Result<GcReport, String> {
        self.gc_report_seeded_with_lease(lease, options, repo_root, None, progress)
    }

    pub fn gc_report_seeded_with_lease(
        &self,
        _lease: &crate::state::StoreExclusiveLease,
        options: &GcOptions,
        repo_root: Option<&Path>,
        seeded_roots: Option<&BTreeMap<String, String>>,
        progress: &mut dyn FnMut(GcProgress),
    ) -> Result<GcReport, String> {
        // The exclusive store lease was acquired before entering this method,
        // so the temp-root scan below observes a quiesced set of realizers.
        let mut report = GcReport::default();

        progress(GcProgress::Phase("Sweeping tmp build dirs"));
        let (tmp_swept, active_tmp_skipped) =
            self.gc_tmp_build_dirs_with(options.dry_run, progress)?;
        report.bytes_reclaimed += tmp_swept.iter().map(|s| s.bytes).sum::<u64>();
        report.tmp_swept = tmp_swept;
        report.active_tmp_skipped = active_tmp_skipped;

        progress(GcProgress::Phase("Marking roots"));
        let (live, live_drv, roots_scanned) = self.mark_roots(options, seeded_roots, progress)?;
        report.roots_scanned = roots_scanned;

        progress(GcProgress::Phase("Scanning store entries"));
        let store_entries = self.list()?;
        let total_entries = store_entries.len();
        let mut dead: Vec<(String, u64, u64)> = Vec::new();
        for (idx, name) in store_entries.into_iter().enumerate() {
            let is_live = live.contains(&name);
            let size = if is_live {
                0
            } else {
                dir_size(&self.root.join(&name))
            };
            progress(GcProgress::StoreScan {
                index: idx + 1,
                total: total_entries,
                name: name.clone(),
                live: is_live,
                bytes: size,
            });
            if is_live {
                continue;
            }
            let mtime = std::fs::metadata(self.meta_path(&name))
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            dead.push((name, mtime, size));
        }

        progress(GcProgress::Phase("Planning sweep"));
        let selected_names: Vec<String> =
            if options.policy.max_age_days.is_none() && options.policy.min_free.is_none() {
                dead.iter().map(|(n, _, _)| n.clone()).collect()
            } else {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut sel: BTreeSet<String> = BTreeSet::new();
                if let Some(days) = options.policy.max_age_days {
                    let cutoff = now.saturating_sub(days.saturating_mul(86400));
                    for (n, mt, _) in &dead {
                        if *mt < cutoff {
                            sel.insert(n.clone());
                        }
                    }
                }
                if let Some(target) = options.policy.min_free {
                    let mut reclaimed: u64 = dead
                        .iter()
                        .filter(|(n, _, _)| sel.contains(n))
                        .map(|(_, _, s)| *s)
                        .sum();
                    let mut rest: Vec<&(String, u64, u64)> =
                        dead.iter().filter(|(n, _, _)| !sel.contains(n)).collect();
                    rest.sort_by_key(|(_, mt, _)| *mt);
                    for (n, _, s) in rest {
                        if reclaimed >= target {
                            break;
                        }
                        sel.insert(n.clone());
                        reclaimed += s;
                    }
                }
                sel.into_iter().collect()
            };
        let selected: Vec<(String, u64)> = selected_names
            .into_iter()
            .filter_map(|selected| {
                dead.iter()
                    .find(|(name, _, _)| name == &selected)
                    .map(|(name, _, bytes)| (name.clone(), *bytes))
            })
            .collect();
        for (idx, (name, bytes)) in selected.iter().enumerate() {
            progress(GcProgress::PlanStore {
                index: idx + 1,
                total: selected.len(),
                name: name.clone(),
                bytes: *bytes,
            });
        }

        progress(GcProgress::Phase("Sweeping store entries"));
        for (idx, (name, bytes)) in selected.iter().enumerate() {
            progress(GcProgress::SweepStore {
                index: idx + 1,
                total: selected.len(),
                name: name.clone(),
                bytes: *bytes,
                dry_run: options.dry_run,
            });
            if !options.dry_run {
                std::fs::remove_dir_all(self.root.join(name))
                    .map_err(|e| format!("cannot sweep {}: {}", name, e))?;
                let _ = std::fs::remove_file(self.meta_path(name));
                let _ = std::fs::remove_file(self.state.join("drv").join(format!("{}.drv", name)));
                let _ = std::fs::remove_file(self.log_path(name));
                let _ = std::fs::remove_dir_all(self.artifacts_path(name));
            }
            report.bytes_reclaimed += *bytes;
            report.store_swept.push(GcSweep {
                name: name.clone(),
                bytes: *bytes,
            });
        }

        // Sweep orphaned realization records.
        if !options.dry_run {
            if let Ok(rd) = std::fs::read_dir(self.state.join("realizations")) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        let drv = text
                            .lines()
                            .find_map(|l| l.strip_prefix("drv: "))
                            .unwrap_or("");
                        if !drv.is_empty() && !live_drv.contains(drv) {
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
            }
        }
        progress(GcProgress::Phase("Sweeping source CAS"));
        let source_report = self.gc_source_cas(options)?;
        report.bytes_reclaimed += source_report.bytes;
        report.cas_swept = source_report.cas_swept;
        report.plans_swept = source_report.plans_swept;

        progress(GcProgress::Phase("Sweeping legacy text caches"));
        let (legacy_count, legacy_bytes) =
            sweep_legacy_text_caches(&self.state, repo_root, options.dry_run)?;
        report.legacy_caches_swept = legacy_count;
        report.bytes_reclaimed += legacy_bytes;
        Ok(report)
    }

    #[cfg(test)]
    pub fn gc(&self, policy: &GcPolicy) -> Result<Vec<String>, String> {
        let options = GcOptions {
            policy: *policy,
            dry_run: false,
            prune_roots_older_than_days: None,
        };
        let lease = self.acquire_exclusive_lease()?;
        Ok(self
            .gc_report_with_lease(&lease, &options, None, &mut |_| {})?
            .store_swept
            .into_iter()
            .map(|s| s.name)
            .collect())
    }

    /// Sweep stale failed build directories from `tmp/`. A build dir is only
    /// eligible when it has a store-name-shaped `<hash32>-... .build` name and
    /// its corresponding per-derivation flock is not held by a running build.
    #[cfg(test)]
    pub fn gc_tmp_build_dirs(&self) -> Result<Vec<super::TmpBuildSweep>, String> {
        Ok(self.gc_tmp_build_dirs_with(false, &mut |_| {})?.0)
    }

    fn gc_tmp_build_dirs_with(
        &self,
        dry_run: bool,
        progress: &mut dyn FnMut(GcProgress),
    ) -> Result<(Vec<GcSweep>, Vec<String>), String> {
        let tmp_dir = self.state.join("tmp");
        let mut swept = Vec::new();
        let mut active_skipped = Vec::new();
        let rd = match std::fs::read_dir(&tmp_dir) {
            Ok(rd) => rd
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("tmp entry: {}", e))?,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((swept, active_skipped)),
            Err(e) => return Err(format!("cannot read tmp dir {}: {}", tmp_dir.display(), e)),
        };
        let mut candidates = Vec::new();
        for entry in rd {
            let file_type = entry
                .file_type()
                .map_err(|e| format!("tmp entry type {}: {}", entry.path().display(), e))?;
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(hash32) = tmp_build_lock_hash(&name) else {
                continue;
            };
            let hash32 = hash32.to_string();
            candidates.push((entry.path(), name, hash32));
        }
        candidates.sort_by(|a, b| a.1.cmp(&b.1));
        let total = candidates.len();
        for (idx, (path, name, hash32)) in candidates.into_iter().enumerate() {
            let Some(_lock) = self.try_lock_hash(&hash32)? else {
                progress(GcProgress::SkipActiveTmp(name.clone()));
                active_skipped.push(name);
                continue;
            };
            let bytes = dir_size(&path);
            progress(GcProgress::SweepTmp {
                index: idx + 1,
                total,
                name: name.clone(),
                bytes,
                dry_run,
            });
            if !dry_run {
                std::fs::remove_dir_all(&path)
                    .map_err(|e| format!("cannot sweep tmp build dir {}: {}", path.display(), e))?;
            }
            swept.push(GcSweep { name, bytes });
        }
        swept.sort_by(|a, b| a.name.cmp(&b.name));
        active_skipped.sort();
        Ok((swept, active_skipped))
    }

    fn gc_source_cas(&self, options: &GcOptions) -> Result<SourceGcReport, String> {
        let cas = SourceCas::open(&self.state)?;
        let mut marks = SourceMarks::default();
        let mut dead_plans = Vec::new();
        for plan_path in list_plan_files(&self.state)? {
            let Some(hash32) = plan_hash_from_file(&plan_path) else {
                continue;
            };
            let Some(plan_lock) = crate::state::try_lock_plan(&self.state, &hash32)? else {
                let plan = crate::eval::plan::load(&plan_path)?;
                mark_plan_sources(&cas, &plan, &mut marks)?;
                continue;
            };
            if self.retain_plan(&plan_path, options.policy) {
                let plan = crate::eval::plan::load(&plan_path)?;
                mark_plan_sources(&cas, &plan, &mut marks)?;
            } else {
                dead_plans.push((plan_path, plan_lock));
            }
        }

        let mut report = SourceGcReport::default();
        report.cas_swept += sweep_legacy_worktree(&self.state, options.dry_run, &mut report.bytes)?;
        report.cas_swept += sweep_source_cas_files(
            &crate::state::source_cas_dir(&self.state),
            &marks.cas,
            options.dry_run,
            &mut report.bytes,
        )?;
        report.cas_swept += sweep_named_files(
            &crate::state::source_tree_dir(&self.state),
            &marks.trees,
            options.dry_run,
            &mut report.bytes,
        )?;
        report.cas_swept += sweep_gittree_memos(
            &crate::state::source_gittree_dir(&self.state),
            &marks.trees,
            options.dry_run,
            &mut report.bytes,
        )?;
        report.cas_swept += sweep_named_dirs(
            &crate::state::exec_dir(&self.state),
            &marks.exec,
            options.dry_run,
            &mut report.bytes,
        )?;
        for (path, _plan_lock) in dead_plans {
            let bytes = file_size(&path);
            if !options.dry_run {
                let _ = std::fs::remove_file(&path);
            }
            report.bytes += bytes;
            report.plans_swept += 1;
        }
        sweep_evalcache_entries(&self.state, options.dry_run)?;
        Ok(report)
    }

    fn retain_plan(&self, path: &Path, policy: GcPolicy) -> bool {
        let Some(days) = policy.max_age_days else {
            return true;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cutoff = now.saturating_sub(days.saturating_mul(86400));
        let mtime = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        mtime >= cutoff
    }
}

fn sweep_evalcache_entries(state: &Path, dry_run: bool) -> Result<(), String> {
    let dir = crate::state::cache_dir(state).join("evalcache");
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read eval cache {}: {e}", dir.display())),
    };
    for entry in rd {
        let entry = entry.map_err(|e| format!("eval cache entry: {e}"))?;
        let path = entry.path();
        let plan_hash = std::fs::read_to_string(&path).ok().and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("plan: ").map(str::to_string))
        });
        let live = plan_hash
            .filter(|hash| hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|hash| {
                crate::state::plans_dir(state)
                    .join(format!("{hash}.plan"))
                    .is_file()
            })
            .unwrap_or(false);
        if !live && !dry_run {
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(())
}

fn list_plan_files(state: &Path) -> Result<Vec<PathBuf>, String> {
    let plans = crate::state::plans_dir(state);
    let rd = match std::fs::read_dir(&plans) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read plans dir {}: {}", plans.display(), e)),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| format!("plan entry: {}", e))?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("plan") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn plan_hash_from_file(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let hash = name.strip_suffix(".plan")?;
    (hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hash.to_string())
}

fn mark_plan_sources(
    cas: &SourceCas,
    plan: &crate::eval::plan::ExecPlan,
    marks: &mut SourceMarks,
) -> Result<(), String> {
    for entry in &plan.bootstrap {
        mark_blob(cas, marks, &entry.hash, entry.kind);
    }
    marks.exec.insert(plan.bootstrap_hash());
    for node in &plan.nodes {
        for (kind, _rel, hash) in &node.srcs {
            mark_blob(cas, marks, hash, *kind);
        }
        for (_rel, hash) in node.srcdirs.iter().chain(node.source_roots.iter()) {
            mark_tree(cas, marks, hash)?;
        }
        for (_rel, hash) in node
            .exec
            .srcdirs
            .iter()
            .chain(node.exec.source_roots.iter())
        {
            mark_tree(cas, marks, hash)?;
        }
    }
    Ok(())
}

fn mark_tree(cas: &SourceCas, marks: &mut SourceMarks, dirhash: &str) -> Result<(), String> {
    if !marks.trees.insert(dirhash.to_string()) {
        return Ok(());
    }
    for (hash, kind) in cas.tree_blob_refs(dirhash)? {
        mark_blob(cas, marks, &hash, kind);
    }
    Ok(())
}

fn mark_blob(cas: &SourceCas, marks: &mut SourceMarks, hash: &str, kind: char) {
    marks.cas.insert(cas_blob_name(hash, kind));
    let other = if kind == 'x' { 'f' } else { 'x' };
    if cas.blob_path(hash, other).is_file() {
        marks.cas.insert(cas_blob_name(hash, other));
    }
}

fn cas_blob_name(hash: &str, kind: char) -> String {
    if kind == 'x' {
        format!("{hash}.x")
    } else {
        hash.to_string()
    }
}

fn sweep_legacy_worktree(state: &Path, dry_run: bool, bytes: &mut u64) -> Result<usize, String> {
    let path = state.join("sources/worktree");
    if !path.exists() {
        return Ok(0);
    }
    *bytes += dir_size(&path);
    if !dry_run {
        std::fs::remove_dir_all(&path)
            .map_err(|e| format!("cannot sweep {}: {}", path.display(), e))?;
    }
    Ok(1)
}

/// Dead pre-stat-cache text caches — `cache/src-hash-cache` (the old
/// composite-keyed hash cache that accreted forever and was rewritten
/// wholesale after every ingested dir) and `cache/tool-id-cache`
/// (no longer produced by any code path). They live under
/// `<repo_root>/cache/`, `<state>/cache/`, and — from an older layout —
/// bare at `<state>/`. They are unlinked
/// unconditionally when present — never migrated, ~90% garbage; bytes
/// reclaimed roll into `bytes_reclaimed` so the cost can only ever be
/// free on the user's side.
fn sweep_legacy_text_caches(
    state: &Path,
    repo_root: Option<&Path>,
    dry_run: bool,
) -> Result<(usize, u64), String> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Some(repo) = repo_root {
        paths.push(repo.join("cache/src-hash-cache"));
        paths.push(repo.join("cache/tool-id-cache"));
    }
    paths.push(state.join("cache/src-hash-cache"));
    paths.push(state.join("cache/tool-id-cache"));
    // An older layout wrote these bare at the state root (no `cache/` prefix);
    // they still linger on real checkouts, so sweep that spelling too.
    paths.push(state.join("src-hash-cache"));
    paths.push(state.join("tool-id-cache"));

    let mut count = 0usize;
    let mut bytes = 0u64;
    for path in &paths {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if !meta.is_file() {
            // Symlinks to /dev/null left behind by past runs; remove cleanly.
            if meta.file_type().is_symlink() {
                bytes += 0;
                if !dry_run {
                    let _ = std::fs::remove_file(path);
                }
                count += 1;
            }
            continue;
        }
        bytes += meta.len();
        if !dry_run {
            std::fs::remove_file(path)
                .map_err(|e| format!("cannot sweep {}: {}", path.display(), e))?;
        }
        count += 1;
    }
    Ok((count, bytes))
}

fn sweep_source_cas_files(
    root: &Path,
    live: &BTreeSet<String>,
    dry_run: bool,
    bytes: &mut u64,
) -> Result<usize, String> {
    let mut swept = 0;
    let rd = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("cannot read {}: {}", root.display(), e)),
    };
    for shard in rd {
        let shard = shard.map_err(|e| format!("source CAS shard: {}", e))?;
        let path = shard.path();
        if !path.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?
        {
            let entry = entry.map_err(|e| format!("source CAS entry: {}", e))?;
            if !entry.path().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if live.contains(&name) {
                continue;
            }
            *bytes += file_size(&entry.path());
            if !dry_run {
                std::fs::remove_file(entry.path())
                    .map_err(|e| format!("cannot sweep {}: {}", name, e))?;
            }
            swept += 1;
        }
        if !dry_run {
            remove_dir_if_empty(&path);
        }
    }
    Ok(swept)
}

fn sweep_named_files(
    root: &Path,
    live: &BTreeSet<String>,
    dry_run: bool,
    bytes: &mut u64,
) -> Result<usize, String> {
    let rd = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("cannot read {}: {}", root.display(), e)),
    };
    let mut swept = 0;
    for entry in rd {
        let entry = entry.map_err(|e| format!("source entry: {}", e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if live.contains(&name) {
            continue;
        }
        *bytes += file_size(&path);
        if !dry_run {
            std::fs::remove_file(&path)
                .map_err(|e| format!("cannot sweep {}: {}", path.display(), e))?;
        }
        swept += 1;
    }
    Ok(swept)
}

fn sweep_named_dirs(
    root: &Path,
    live: &BTreeSet<String>,
    dry_run: bool,
    bytes: &mut u64,
) -> Result<usize, String> {
    let rd = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("cannot read {}: {}", root.display(), e)),
    };
    let mut swept = 0;
    for entry in rd {
        let entry = entry.map_err(|e| format!("source dir entry: {}", e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if live.contains(&name) {
            continue;
        }
        let lock_path = root.join(format!("{name}.lock"));
        if lock_is_held(&lock_path)? {
            continue;
        }
        *bytes += dir_size(&path);
        if !dry_run {
            std::fs::remove_dir_all(&path)
                .map_err(|e| format!("cannot sweep {}: {}", path.display(), e))?;
            let _ = std::fs::remove_file(lock_path);
        }
        swept += 1;
    }
    Ok(swept)
}

fn lock_is_held(path: &Path) -> Result<bool, String> {
    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        return Ok(false);
    };
    match crate::platform::lock_exclusive(&file, true) {
        Ok(true) => Ok(false),
        Ok(false) => Ok(true),
        Err(err) => Err(format!("cannot inspect lock {}: {}", path.display(), err)),
    }
}

fn sweep_gittree_memos(
    root: &Path,
    live_trees: &BTreeSet<String>,
    dry_run: bool,
    bytes: &mut u64,
) -> Result<usize, String> {
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    let mut swept = 0;
    for path in files {
        let dirhash = std::fs::read_to_string(&path).unwrap_or_default();
        if live_trees.contains(dirhash.trim()) {
            continue;
        }
        *bytes += file_size(&path);
        if !dry_run {
            std::fs::remove_file(&path)
                .map_err(|e| format!("cannot sweep {}: {}", path.display(), e))?;
        }
        swept += 1;
    }
    if !dry_run {
        remove_empty_descendants(root);
    }
    Ok(swept)
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read {}: {}", root.display(), e)),
    };
    for entry in rd {
        let entry = entry.map_err(|e| format!("source memo entry: {}", e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    out.sort();
    Ok(())
}

fn remove_empty_descendants(root: &Path) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    for dir in &dirs {
        remove_empty_descendants(dir);
    }
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for dir in dirs {
        remove_dir_if_empty(&dir);
    }
    remove_dir_if_empty(root);
}

fn remove_dir_if_empty(path: &Path) {
    if std::fs::read_dir(path)
        .map(|mut rd| rd.next().is_none())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir(path);
    }
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

pub(super) fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else {
                continue;
            };
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                if let Ok(m) = e.metadata() {
                    total += m.len();
                }
            }
        }
    }
    total
}

fn tmp_build_lock_hash(name: &str) -> Option<&str> {
    let store_name = name.strip_suffix(".build")?;
    let (hash32, _) = store_name.split_once('-')?;
    if hash32.len() == 32 && hash32.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hash32)
    } else {
        None
    }
}

pub(super) fn sanitize_temp_root_label(label: &str) -> String {
    let mut out = String::new();
    for b in label.bytes().take(64) {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "root".to_string()
    } else {
        out
    }
}

pub(super) fn same_inode(a: &Path, b: &Path) -> bool {
    crate::platform::same_file(a, b)
}
