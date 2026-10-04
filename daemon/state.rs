// SPDX-License-Identifier: GPL-2.0-only
//! Resident daemon state and request-scoped process inputs.
//!
//! Disk remains the authoritative cache.  This layer only keeps the parsed
//! forms that the normal pipeline already writes to disk. A native watcher may
//! accelerate a verified quiet generation, but disk stat-diff remains the
//! correctness fallback for every watcher uncertainty.

use super::watch::{self, WatchEvent, Watcher};
use crate::cmd::{Args, Context};
use crate::eval::cache::{self, CachedPlan};
use crate::eval::graph::{self, EvalProgress, Evaluated};
use crate::eval::plan;
use crate::events::EvalCacheState;
use crate::spec::configres::Config;
use crate::spec::{self, Spec};
use crate::tools::Toolchain;
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Environment accepted from a daemon client.  This is deliberately narrow:
/// it carries host-tool discovery and presentation controls, never build
/// identity or arbitrary ambient configuration.
pub const ENV_ALLOWLIST: &[&str] = &[
    "BUILDUTIL_STORE",
    "BUILDUTIL_RUSTC",
    "BUILDUTIL_LINKER",
    "BUILDUTIL_STATCACHE_MAX_BYTES",
    "SDKROOT",
    "SOURCE_DATE_EPOCH",
    "PATH",
    "HOME",
    "TMPDIR",
    "TERM",
    "NO_COLOR",
];

static ACTIVE_DAEMON: OnceLock<Mutex<Option<Arc<Mutex<DaemonState>>>>> = OnceLock::new();

fn daemon_slot() -> &'static Mutex<Option<Arc<Mutex<DaemonState>>>> {
    ACTIVE_DAEMON.get_or_init(|| Mutex::new(None))
}

pub fn install_active_daemon(state: Arc<Mutex<DaemonState>>) {
    *daemon_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(state);
}

pub fn clear_active_daemon() {
    *daemon_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

pub fn is_active_daemon() -> bool {
    daemon_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

pub fn with_active_daemon<T>(f: impl FnOnce(&mut DaemonState) -> T) -> Option<T> {
    let state = daemon_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()?;
    // A request panic is contained by the daemon executor.  Retaining a
    // poisoned mutex here would turn that one request into a permanent daemon
    // outage; disk remains the authority for any subsequently reused cache.
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Some(f(&mut state))
}

fn request_cancellation_token() -> graph::CancellationToken {
    crate::invocation::request_context()
        .map(|context| graph::CancellationToken::from_flag(context.cancel.clone()))
        .unwrap_or_else(graph::CancellationToken::never)
}

#[derive(Clone, PartialEq, Eq)]
struct SpecConfigKey {
    arch: String,
    build_host: String,
    overrides: Vec<(String, String)>,
}

struct SpecConfigEntry {
    key: SpecConfigKey,
    spec: Arc<Spec>,
    config: Arc<Config>,
    /// The configuration's input files — the option graph and the
    /// persistent override file — each with its stamp, `None` when absent.
    config_stamps: Vec<(PathBuf, Option<FileStamp>)>,
}

fn config_stamps(paths: Vec<PathBuf>) -> Vec<(PathBuf, Option<FileStamp>)> {
    paths
        .into_iter()
        .map(|path| {
            let stamp = FileStamp::read(&path).ok();
            (path, stamp)
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    mtime_s: i64,
    mtime_ns: i64,
    ctime_s: i64,
    ctime_ns: i64,
    ino: u64,
    dev: u64,
}

impl FileStamp {
    fn read(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("cannot stat cached file {}: {e}", path.display()))?;
        let fields = crate::platform::stat_fields(&metadata);
        Ok(Self {
            len: metadata.len(),
            mtime_s: fields.mtime_s,
            mtime_ns: fields.mtime_ns,
            ctime_s: fields.ctime_s,
            ctime_ns: fields.ctime_ns,
            ino: fields.ino,
            dev: fields.dev,
        })
    }
}

struct ResidentPlan {
    eval_key: String,
    evaluated: Evaluated,
    plan: crate::eval::plan::ExecPlan,
    plan_hash: String,
    path: PathBuf,
    stamp: FileStamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchHealth {
    AwaitingBaseline,
    Healthy,
    Unhealthy,
}

impl WatchHealth {
    fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingBaseline => "awaiting-baseline",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchStatus {
    pub health: String,
    pub events_since_baseline: usize,
}

struct WatchState {
    watcher: Option<Box<dyn Watcher>>,
    health: WatchHealth,
    reason: Option<String>,
    // Raw watcher arrivals are observability only: daemon self-writes under
    // .buildutil/ are expected while evaluating.
    event_generation: u64,
    // Only a dispatch-table invalidation may change this generation. It is
    // the mixed-generation and zero-stat safety boundary.
    relevant_generation: u64,
    baseline_event_generation: Option<u64>,
    baseline_relevant_generation: Option<u64>,
    request_relevant_generation: u64,
    dirty_sources: BTreeSet<String>,
    reset_sources: bool,
    spec_dirty: bool,
    config_dirty: bool,
    // Git commands used by the current evaluation can refresh .git/index.
    // Defer their effect to the next request so they never invalidate the
    // evaluation that performed the probe.
    git_identity_stale: bool,
    cached_git_state: Option<(String, String)>,
    observed_git_state: Option<(String, String)>,
    quiesce_ns: u64,
    snapshot_quiesce_ms: u128,
    transitions: Vec<String>,
    relevant_paths_since_request: Vec<PathBuf>,
    structural_fallback: bool,
}

impl WatchState {
    fn new(repo_root: &Path, state_root: &Path) -> Self {
        let mut state = Self {
            watcher: None,
            health: WatchHealth::Unhealthy,
            reason: None,
            event_generation: 0,
            relevant_generation: 0,
            baseline_event_generation: None,
            baseline_relevant_generation: None,
            request_relevant_generation: 0,
            dirty_sources: BTreeSet::new(),
            reset_sources: false,
            spec_dirty: true,
            config_dirty: true,
            git_identity_stale: false,
            cached_git_state: None,
            observed_git_state: None,
            quiesce_ns: 0,
            snapshot_quiesce_ms: 0,
            transitions: Vec::new(),
            relevant_paths_since_request: Vec::new(),
            structural_fallback: false,
        };
        state.install(repo_root, state_root);
        state
    }

    fn install(&mut self, repo_root: &Path, state_root: &Path) {
        if let Err(reason) = git_metadata_is_watched(repo_root) {
            self.degrade(reason);
            return;
        }
        match watch::start(repo_root, state_root, self.structural_fallback) {
            Ok(watcher) => {
                let platform = watcher.platform_name();
                self.transitions
                    .extend(watcher.startup_diagnostics().iter().cloned());
                self.watcher = Some(watcher);
                self.set_health(
                    WatchHealth::AwaitingBaseline,
                    None,
                    format!("watcher health -> awaiting-baseline ({platform})"),
                );
            }
            Err(error) => self.degrade(format!("watch installation failed: {error}")),
        }
    }

    fn set_health(&mut self, health: WatchHealth, reason: Option<String>, message: String) {
        if self.health != health || self.reason != reason {
            self.transitions.push(message);
        }
        self.health = health;
        self.reason = reason;
    }

    fn degrade(&mut self, reason: String) {
        if reason.starts_with("FSEvents flags ") {
            self.structural_fallback = true;
        }
        if let Some(mut watcher) = self.watcher.take() {
            watcher.shutdown();
        }
        self.baseline_event_generation = None;
        self.baseline_relevant_generation = None;
        self.git_identity_stale = false;
        self.cached_git_state = None;
        self.observed_git_state = None;
        self.set_health(
            WatchHealth::Unhealthy,
            Some(reason.clone()),
            format!("watcher health -> unhealthy: {reason}"),
        );
    }

    fn begin_request(
        &mut self,
        repo_root: &Path,
        state_root: &Path,
        declared_sources: &BTreeSet<String>,
    ) -> bool {
        if self.health == WatchHealth::Unhealthy {
            self.transitions.push(format!(
                "watcher recovery -> reinstalling before full stat-diff (previous: {})",
                self.reason.as_deref().unwrap_or("unknown")
            ));
            self.install(repo_root, state_root);
        }
        self.rebaseline_request(repo_root, state_root, declared_sources)
    }

    fn rebaseline_request(
        &mut self,
        repo_root: &Path,
        state_root: &Path,
        declared_sources: &BTreeSet<String>,
    ) -> bool {
        let drained_reset = self.drain(repo_root, state_root, declared_sources);
        let reset_sources = self.reset_sources || drained_reset;
        self.request_relevant_generation = self.relevant_generation;
        self.relevant_paths_since_request.clear();
        reset_sources
    }

    fn poll(
        &mut self,
        repo_root: &Path,
        state_root: &Path,
        declared_sources: &BTreeSet<String>,
    ) -> bool {
        self.drain(repo_root, state_root, declared_sources)
    }

    fn drain(
        &mut self,
        repo_root: &Path,
        state_root: &Path,
        declared_sources: &BTreeSet<String>,
    ) -> bool {
        if self.watcher.is_none() {
            return false;
        }
        // Swap once before quiescing so producers never wait behind the sleep,
        // then swap again to include the events published during the barrier.
        let quiesce = std::time::Instant::now();
        let watcher = self.watcher.as_mut().expect("watcher checked above");
        let quiesce_duration = watcher.quiesce_duration();
        let mut events = watcher.drain();
        std::thread::sleep(quiesce_duration);
        events.extend(watcher.drain());
        self.quiesce_ns = self
            .quiesce_ns
            .saturating_add(quiesce.elapsed().as_nanos() as u64);
        let path_count = events
            .iter()
            .filter(|event| matches!(event, WatchEvent::Path(_)))
            .count();
        if path_count > 0 {
            let sample = events
                .iter()
                .filter_map(|event| match event {
                    WatchEvent::Path(path) => Some(path.display().to_string()),
                    WatchEvent::Uncertain(_) => None,
                })
                .take(10)
                .collect::<Vec<_>>()
                .join(", ");
            self.transitions.push(format!(
                "watcher drain delivered {path_count} path events sample=[{sample}]"
            ));
        }
        let fsevents = self
            .watcher
            .as_ref()
            .is_some_and(|watcher| watcher.platform_name() == "fsevents");
        let normalized_state_root = fsevents.then(|| watch::normalize_path(state_root));
        let mut reset = false;
        for event in events {
            match event {
                WatchEvent::Path(path) => {
                    self.event_generation = self.event_generation.saturating_add(1);
                    if normalized_state_root.as_ref().is_some_and(|state_root| {
                        watch::normalize_path(&path).starts_with(state_root)
                    }) {
                        self.relevant_generation = self.relevant_generation.saturating_add(1);
                        self.structural_fallback = true;
                        self.degrade(format!(
                            "FSEvents exclusion delivered state-root path {}; structural fallback required",
                            path.display()
                        ));
                        break;
                    }
                    reset |= self.dispatch_path(repo_root, state_root, declared_sources, &path);
                }
                WatchEvent::Uncertain(reason) => {
                    self.event_generation = self.event_generation.saturating_add(1);
                    self.relevant_generation = self.relevant_generation.saturating_add(1);
                    self.degrade(reason);
                    break;
                }
            }
        }
        reset
    }

    fn dispatch_path(
        &mut self,
        repo_root: &Path,
        state_root: &Path,
        declared_sources: &BTreeSet<String>,
        path: &Path,
    ) -> bool {
        let repo_root = watch::normalize_path(repo_root);
        let state_root = watch::normalize_path(state_root);
        let path = watch::normalize_path(path);
        if path.starts_with(&state_root) {
            if path.starts_with(state_root.join("config")) {
                self.relevant_generation = self.relevant_generation.saturating_add(1);
                self.config_dirty = true;
            }
            // State output never participates in the source dirty set.
            return false;
        }
        let Ok(rel) = path.strip_prefix(&repo_root) else {
            self.relevant_generation = self.relevant_generation.saturating_add(1);
            self.degrade(format!(
                "watcher reported path outside repository: {}",
                path.display()
            ));
            return false;
        };
        let rel = normalize_rel(rel);
        if rel.is_empty() {
            self.relevant_generation = self.relevant_generation.saturating_add(1);
            self.degrade("watcher reported repository-root replacement".to_string());
            return false;
        }
        if is_git_surface(&rel) {
            // A git probe may itself refresh .git/index. It is not a source
            // content change, so do not restart the evaluation that issued the
            // probe. The next request re-probes the identity and starts its
            // request-owned repository-probe scope from scratch.
            self.git_identity_stale = true;
            return false;
        }

        let mut reset = false;
        let mut relevant = false;
        // Every repository's filter decides which files its declared sources
        // include, so a nested repository's filter resets sources as the
        // root's does.
        if rel == ".buildutilignore" || rel.ends_with("/.buildutilignore") {
            self.reset_sources = true;
            reset = true;
            relevant = true;
        }
        // Generator inputs are declared sources of the generators'
        // derivations, which every request evaluates again.
        if rel == "buildutil.toml" || rel.ends_with("/buildutil.toml") {
            self.spec_dirty = true;
            relevant = true;
        }
        for root in declared_sources {
            if paths_intersect(&rel, root) {
                self.dirty_sources.insert(root.clone());
                relevant = true;
            }
        }
        if relevant {
            self.relevant_generation = self.relevant_generation.saturating_add(1);
            self.relevant_paths_since_request.push(path);
            // A declared source change can flip the worktree dirty bit even
            // when it does not alter git metadata.
            self.cached_git_state = None;
            self.observed_git_state = None;
        }
        reset
    }

    #[cfg(test)]
    fn can_reuse_sources(&self) -> bool {
        self.health == WatchHealth::Healthy
            && self.baseline_relevant_generation == Some(self.relevant_generation)
            && !self.git_identity_stale
            && !self.reset_sources
    }

    fn can_reuse_cached_sources(&self) -> bool {
        self.health == WatchHealth::Healthy
            && self.baseline_relevant_generation.is_some()
            && !self.git_identity_stale
            && !self.reset_sources
    }

    fn dirty_sources(&self) -> &BTreeSet<String> {
        &self.dirty_sources
    }

    fn spec_dirty(&self) -> bool {
        self.spec_dirty
    }

    fn config_dirty(&self) -> bool {
        self.config_dirty
    }

    fn clear_context_dirty(&mut self) {
        self.spec_dirty = false;
        self.config_dirty = false;
    }

    fn git_state(&mut self, repo_root: &Path, force_fresh: bool) -> (String, String) {
        self.git_state_with(force_fresh, || graph::git_state(repo_root))
    }

    fn git_state_with<F>(&mut self, force_fresh: bool, probe: F) -> (String, String)
    where
        F: FnOnce() -> (String, String),
    {
        if !force_fresh
            && !self.git_identity_stale
            && self.health == WatchHealth::Healthy
            && self.baseline_relevant_generation == Some(self.relevant_generation)
            && let Some(state) = &self.cached_git_state
        {
            return state.clone();
        }
        let state = probe();
        let identity_changed = self.git_identity_stale
            && self
                .cached_git_state
                .as_ref()
                .is_some_and(|cached| cached != &state);
        self.git_identity_stale = false;
        if identity_changed {
            // Git identity is part of the eval key and substituted env. Do a
            // full source resolution before retaining another baseline.
            self.reset_sources = true;
        }
        self.cached_git_state = Some(state.clone());
        self.observed_git_state = Some(state.clone());
        state
    }

    fn snapshot_still_current(
        &mut self,
        spec: &Spec,
        resolved: &graph::ResolvedSources,
        state_root: &Path,
    ) -> Result<bool, String> {
        let before = self.quiesce_ns;
        let result = self.snapshot_still_current_inner(spec, resolved, state_root);
        self.snapshot_quiesce_ms = self.quiesce_ns.saturating_sub(before) as u128 / 1_000_000;
        result
    }

    fn snapshot_still_current_inner(
        &mut self,
        spec: &Spec,
        resolved: &graph::ResolvedSources,
        state_root: &Path,
    ) -> Result<bool, String> {
        if self.health == WatchHealth::AwaitingBaseline {
            return self.verify_rebaseline_and_mark(spec, resolved, state_root);
        }
        if self.health == WatchHealth::Unhealthy {
            return cache::evaluation_snapshot_still_current_with_cancel(
                spec,
                resolved,
                &request_cancellation_token(),
            );
        }
        let declared = declared_sources_for_spec(spec)?;
        if !self.generation_matches_request(&spec.repo_root, state_root, &declared) {
            if self.health != WatchHealth::Healthy {
                return cache::evaluation_snapshot_still_current_with_cancel(
                    spec,
                    resolved,
                    &request_cancellation_token(),
                );
            }
            return self.verify_rebaseline_and_mark(spec, resolved, state_root);
        }
        self.mark_baseline(resolved);
        Ok(true)
    }

    fn verify_rebaseline_and_mark(
        &mut self,
        spec: &Spec,
        resolved: &graph::ResolvedSources,
        state_root: &Path,
    ) -> Result<bool, String> {
        let current = cache::evaluation_snapshot_still_current_with_cancel(
            spec,
            resolved,
            &request_cancellation_token(),
        )?;
        if !current {
            return Ok(false);
        }
        let declared = declared_sources_for_spec(spec)?;
        self.rebaseline_request(&spec.repo_root, state_root, &declared);
        // The first stat-diff validates the evaluated snapshot; this second
        // one closes changes that raced with the baseline barrier.
        let current = cache::evaluation_snapshot_still_current_with_cancel(
            spec,
            resolved,
            &request_cancellation_token(),
        )?;
        if current && self.health != WatchHealth::Unhealthy {
            self.mark_baseline(resolved);
        }
        Ok(current)
    }

    fn generation_matches_request(
        &mut self,
        repo_root: &Path,
        state_root: &Path,
        declared_sources: &BTreeSet<String>,
    ) -> bool {
        self.poll(repo_root, state_root, declared_sources);
        let matches = self.health == WatchHealth::Healthy
            && self.relevant_generation == self.request_relevant_generation;
        if !matches {
            for path in std::mem::take(&mut self.relevant_paths_since_request) {
                self.transitions.push(format!(
                    "watcher mid-eval relevant event triggered snapshot verification: {}",
                    path.display()
                ));
            }
        }
        matches
    }

    fn mark_baseline(&mut self, resolved: &graph::ResolvedSources) {
        self.baseline_event_generation = Some(self.event_generation);
        self.baseline_relevant_generation = Some(self.relevant_generation);
        self.dirty_sources.retain(|root| {
            !resolved.blobs.contains_key(root) && !resolved.trees.contains_key(root)
        });
        self.reset_sources = false;
        self.cached_git_state = self.observed_git_state.clone();
        self.set_health(
            WatchHealth::Healthy,
            None,
            "watcher health -> healthy (verified baseline)".to_string(),
        );
    }

    fn take_transitions(&mut self) -> Vec<String> {
        std::mem::take(&mut self.transitions)
    }

    fn status(&self) -> WatchStatus {
        let events_since_baseline = self
            .baseline_event_generation
            .map(|baseline| self.event_generation.saturating_sub(baseline) as usize)
            .unwrap_or(self.event_generation as usize);
        let health = match &self.reason {
            Some(reason) => format!("{} ({reason})", self.health.as_str()),
            None => self.health.as_str().to_string(),
        };
        WatchStatus {
            health,
            events_since_baseline,
        }
    }

    fn snapshot_quiesce_ms(&self) -> u128 {
        self.snapshot_quiesce_ms
    }
}

fn normalize_rel(path: &Path) -> String {
    path.to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
        .trim_matches('/')
        .to_string()
}

fn paths_intersect(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|tail| tail.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn is_git_surface(rel: &str) -> bool {
    rel == ".git" || rel.starts_with(".git/") || rel == ".gitmodules" || rel == ".gitattributes"
}

fn git_metadata_is_watched(repo_root: &Path) -> Result<(), String> {
    let dot_git = repo_root.join(".git");
    if std::fs::symlink_metadata(&dot_git)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(format!(
            "git metadata {} is a symlink outside the recursive watcher contract",
            dot_git.display()
        ));
    }
    if !dot_git.is_file() {
        return Ok(());
    }
    let text = std::fs::read_to_string(&dot_git).map_err(|e| {
        format!(
            "cannot read worktree git indirection {}: {e}",
            dot_git.display()
        )
    })?;
    let target = text
        .strip_prefix("gitdir: ")
        .or_else(|| text.strip_prefix("gitdir:"))
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| format!("malformed worktree git indirection {}", dot_git.display()))?;
    let target = PathBuf::from(target);
    let target = if target.is_absolute() {
        target
    } else {
        dot_git.parent().unwrap_or(repo_root).join(target)
    };
    let target = canonical(&target);
    if target.starts_with(repo_root) {
        Ok(())
    } else {
        Err(format!(
            "worktree gitdir {} is outside the FSEvents/inotify root {}",
            target.display(),
            repo_root.display()
        ))
    }
}

fn declared_sources_for_spec(spec: &Spec) -> Result<BTreeSet<String>, String> {
    let mut sources = BTreeSet::new();
    for dspec in spec.drvs.values() {
        if !crate::spec::builders::is_fixed_output(&dspec.builder) {
            sources.extend(dspec.sources.iter().cloned());
        }
        sources.extend(dspec.src_dirs.iter().cloned());
        sources.extend(
            dspec
                .source_roots
                .iter()
                .filter(|root| !dspec.overlay_root(root))
                .cloned(),
        );
    }
    sources.extend(crate::eval::plan::bootstrap::bootstrap_paths(
        &spec.repo_root,
    )?);
    Ok(sources)
}

/// One daemon owns exactly one `(repo_root, state_root)` pair.  The server is
/// single-flight, therefore the ordinary source cache's process-global handle
/// is safe for this resident lifetime.
pub struct DaemonState {
    pub repo_root: PathBuf,
    pub state_root: PathBuf,
    specs: Vec<SpecConfigEntry>,
    eval_lru: VecDeque<ResidentPlan>,
    source_cache: graph::ResolvedSources,
    watch: WatchState,
    resident_container_runtimes: BTreeSet<String>,
}

impl DaemonState {
    pub fn new(repo_root: PathBuf, state_root: PathBuf) -> Result<Self, String> {
        crate::source::statcache::load_file_cache(&state_root, &repo_root);
        crate::source::activate(&state_root)?;
        let watch = WatchState::new(&repo_root, &state_root);
        Ok(Self {
            repo_root,
            state_root,
            specs: Vec::new(),
            eval_lru: VecDeque::new(),
            source_cache: graph::ResolvedSources::default(),
            watch,
            resident_container_runtimes: BTreeSet::new(),
        })
    }

    pub fn open_context(&mut self, args: &Args) -> Result<Context, String> {
        self.begin_request();
        self.open_context_impl(args, false)
    }

    fn open_context_uncached(&mut self, args: &Args) -> Result<Context, String> {
        self.open_context_impl(args, true)
    }

    fn open_context_impl(&mut self, args: &Args, force_reload: bool) -> Result<Context, String> {
        let cwd = crate::invocation::request_cwd().unwrap_or_else(|| self.repo_root.clone());
        let repo_root = crate::cmd::repo_root_from(&cwd)?;
        if canonical(&repo_root) != canonical(&self.repo_root) {
            return Err("daemon request repository differs from daemon repository".to_string());
        }
        let state_root = crate::cmd::state_root_from_repo_for(
            args,
            &repo_root,
            crate::invocation::request_env("BUILDUTIL_STORE"),
        );
        let state_root = crate::state::absolute_root(&repo_root, &state_root);
        if canonical(&state_root) != canonical(&self.state_root) {
            return Err("daemon request state root differs from daemon state root".to_string());
        }
        let build_host = crate::host::BuildHost::resolve(&args.build_host)?;
        let backend = crate::host::ExecBackend::resolve(&args.backend)?;
        let store = crate::store::Store::open(&state_root)?;
        let input_lease = store.acquire_shared_lease()?;
        crate::source::activate(&state_root)?;
        let mut overrides = args.overrides.clone();
        overrides.sort();
        let key = SpecConfigKey {
            arch: args.arch.clone(),
            build_host: build_host.triple().to_string(),
            overrides,
        };

        let position = self.specs.iter().position(|entry| entry.key == key);
        let watcher_current = self.watch.health == WatchHealth::Healthy
            && !self.watch.spec_dirty()
            && !self.watch.config_dirty();
        let (spec, config) = match position {
            Some(index)
                if !force_reload
                    && args.overrides.is_empty()
                    && args.input_overrides.is_empty()
                    && ((watcher_current && self.config_is_current(&self.specs[index]))
                        || self.spec_is_current(&self.specs[index])) =>
            {
                let entry = &self.specs[index];
                let spec = entry.spec.clone();
                let config = entry.config.clone();
                self.clear_context_dirty_if_all_current();
                (spec, config)
            }
            _ => {
                // `-D` resolves again on every request. The parsed
                // spec/config is retained afterwards only as a stale-safe
                // accelerator for a later non-override request.
                let spec = crate::spec::load_with_input_overrides(
                    &repo_root,
                    &args.arch,
                    build_host.triple(),
                    &args.input_overrides,
                )?;
                for dspec in spec.drvs.values() {
                    crate::spec::builders::validate(dspec, &spec.flagsets)?;
                }
                // Stamp the inputs before resolving, so a change during
                // resolution is seen as stale by the next request.
                let stamps = config_stamps(crate::spec::configres::inputs(
                    &repo_root,
                    &state_root,
                    &args.arch,
                    spec.configuration.as_ref(),
                ));
                let config = Config::open(
                    &repo_root,
                    &state_root,
                    &args.arch,
                    spec.configuration.as_ref(),
                    &args.overrides,
                )?;
                let spec = Arc::new(spec);
                let config = Arc::new(config);
                let entry = SpecConfigEntry {
                    key,
                    spec: spec.clone(),
                    config: config.clone(),
                    config_stamps: stamps,
                };
                if let Some(index) = position {
                    self.specs[index] = entry;
                } else {
                    self.specs.push(entry);
                }
                self.clear_context_dirty_if_all_current();
                (spec, config)
            }
        };
        let git_state = self.watch.git_state(&repo_root, force_reload);
        Ok(Context::from_daemon_parts(
            repo_root,
            state_root.clone(),
            store,
            config,
            spec,
            Toolchain::new(&state_root),
            build_host,
            backend,
            git_state,
            input_lease,
        ))
    }

    fn spec_is_current(&self, entry: &SpecConfigEntry) -> bool {
        if !self.config_is_current(entry) {
            return false;
        }
        entry.spec.spec_inputs.iter().all(|input| {
            spec::hash_spec_input(&entry.spec.repo_root, input)
                .map(|hash| hash == input.hash)
                .unwrap_or(false)
        })
    }

    fn clear_context_dirty_if_all_current(&mut self) {
        if self.specs.iter().all(|entry| self.spec_is_current(entry)) {
            self.watch.clear_context_dirty();
        }
    }

    fn config_is_current(&self, entry: &SpecConfigEntry) -> bool {
        let current = config_stamps(crate::spec::configres::inputs(
            &entry.spec.repo_root,
            &self.state_root,
            &entry.key.arch,
            entry.spec.configuration.as_ref(),
        ));
        current == entry.config_stamps
    }

    fn config_for_spec_is_current(&self, spec: &Spec) -> bool {
        self.specs
            .iter()
            .find(|entry| std::ptr::eq(entry.spec.as_ref(), spec))
            .is_none_or(|entry| self.config_is_current(entry))
    }

    fn config_path_for_spec(&self, spec: &Spec) -> Option<PathBuf> {
        self.specs
            .iter()
            .find(|entry| std::ptr::eq(entry.spec.as_ref(), spec))
            .map(|entry| crate::state::config_file(&self.state_root, &entry.key.arch))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_plan_with_progress<F>(
        &mut self,
        spec: &Spec,
        config: &Config,
        toolchain: &mut Toolchain,
        targets: &[String],
        enabled: bool,
        git_state: (String, String),
        _memo_scope: &crate::source::EvaluationMemoScope,
        progress: &mut F,
    ) -> Result<CachedPlan, String>
    where
        F: FnMut(EvalProgress) + Send,
    {
        self.evaluate_plan_with_progress_inner(
            spec,
            config,
            toolchain,
            targets,
            enabled,
            git_state,
            _memo_scope,
            true,
            progress,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_plan_with_progress_inner<F>(
        &mut self,
        spec: &Spec,
        config: &Config,
        toolchain: &mut Toolchain,
        targets: &[String],
        enabled: bool,
        git_state: (String, String),
        _memo_scope: &crate::source::EvaluationMemoScope,
        allow_watcher_reuse: bool,
        progress: &mut F,
    ) -> Result<CachedPlan, String>
    where
        F: FnMut(EvalProgress) + Send,
    {
        if crate::invocation::request_cancelled() {
            return Err("daemon request cancelled".to_string());
        }
        let reusable = allow_watcher_reuse
            .then(|| self.watch.can_reuse_cached_sources())
            .unwrap_or(false)
            .then_some(&self.source_cache);
        let cancel = request_cancellation_token();
        let prepared = graph::prepare_with_progress_reusing(
            spec,
            config,
            targets,
            git_state,
            reusable,
            self.watch.dirty_sources(),
            &cancel,
            progress,
        )?;
        self.merge_sources(&prepared.resolved_sources);
        if crate::invocation::request_cancelled() {
            return Err("daemon request cancelled".to_string());
        }
        let eval_key = cache::eval_key(
            spec,
            config,
            targets,
            &prepared.graph.config_digests(),
            &prepared.resolved_sources,
            &prepared.git_state,
        )?;
        if enabled {
            if let Some(entry) = self.take_resident(&eval_key) {
                let result = CachedPlan {
                    evaluated: entry.evaluated.clone(),
                    path: entry.path.clone(),
                    hash: entry.plan_hash.clone(),
                    plan: entry.plan.clone(),
                    state: EvalCacheState::Hit,
                    emit_ms: 0,
                };
                progress(EvalProgress {
                    current: result.evaluated.order.len(),
                    total: result.evaluated.order.len(),
                    phase: graph::EvalPhase::Evaluated,
                    detail: String::new(),
                    item: None,
                    label: None,
                });
                return Ok(result);
            }
        }
        let resolved = prepared.resolved_sources.clone();
        let git = prepared.git_state.clone();
        if enabled {
            let entry = cache::entry_path(&self.state_root, &eval_key);
            if let Some((path, hash, plan)) = cache::load_hit(&self.state_root, &entry, &resolved) {
                let evaluated = Evaluated::from_cached_plan(&prepared.graph, &plan, resolved);
                progress(EvalProgress {
                    current: evaluated.order.len(),
                    total: evaluated.order.len(),
                    phase: graph::EvalPhase::Evaluated,
                    detail: String::new(),
                    item: None,
                    label: None,
                });
                let result = CachedPlan {
                    evaluated,
                    path,
                    hash,
                    plan,
                    state: EvalCacheState::Hit,
                    emit_ms: 0,
                };
                self.remember(eval_key, &result);
                return Ok(result);
            }
        }
        let evaluated = graph::instantiate_prepared(spec, config, toolchain, prepared, progress)?;
        if crate::invocation::request_cancelled() {
            return Err("daemon request cancelled".to_string());
        }
        let emitted = std::time::Instant::now();
        let (path, hash, plan) = plan::emit(spec, &evaluated, &self.state_root, &git)?;
        let emit_ms = emitted.elapsed().as_millis();
        if enabled {
            cache::write_entry(&cache::entry_path(&self.state_root, &eval_key), &hash)?;
        }
        let result = CachedPlan {
            evaluated,
            path,
            hash,
            plan,
            state: if enabled {
                EvalCacheState::Miss
            } else {
                EvalCacheState::Off
            },
            emit_ms,
        };
        if enabled {
            self.remember(eval_key, &result);
        }
        Ok(result)
    }

    fn merge_sources(&mut self, resolved: &graph::ResolvedSources) {
        self.source_cache.blobs.extend(
            resolved
                .blobs
                .iter()
                .map(|(path, value)| (path.clone(), value.clone())),
        );
        self.source_cache.trees.extend(
            resolved
                .trees
                .iter()
                .map(|(path, value)| (path.clone(), value.clone())),
        );
    }

    fn remember(&mut self, eval_key: String, result: &CachedPlan) {
        let Ok(stamp) = FileStamp::read(&result.path) else {
            self.eval_lru.retain(|entry| entry.eval_key != eval_key);
            return;
        };
        self.eval_lru.retain(|entry| entry.eval_key != eval_key);
        self.eval_lru.push_front(ResidentPlan {
            eval_key,
            evaluated: result.evaluated.clone(),
            plan: result.plan.clone(),
            plan_hash: result.hash.clone(),
            path: result.path.clone(),
            stamp,
        });
        while self.eval_lru.len() > 8 {
            self.eval_lru.pop_back();
        }
    }

    fn take_resident(&mut self, eval_key: &str) -> Option<ResidentPlan> {
        let index = self
            .eval_lru
            .iter()
            .position(|entry| entry.eval_key == eval_key)?;
        let entry = self.eval_lru.remove(index).expect("resident eval index");
        if FileStamp::read(&entry.path).ok() != Some(entry.stamp) {
            return None;
        }
        self.eval_lru.push_front(ResidentPlan {
            eval_key: entry.eval_key.clone(),
            evaluated: entry.evaluated.clone(),
            plan: entry.plan.clone(),
            plan_hash: entry.plan_hash.clone(),
            path: entry.path.clone(),
            stamp: entry.stamp,
        });
        Some(entry)
    }

    pub fn flush(&self) {
        crate::source::statcache::flush_file_cache();
    }

    pub fn snapshot_still_current(
        &mut self,
        spec: &Spec,
        resolved: &graph::ResolvedSources,
    ) -> Result<bool, String> {
        if !self.config_for_spec_is_current(spec) {
            self.watch.config_dirty = true;
            if let Some(path) = self.config_path_for_spec(spec) {
                self.watch.transitions.push(format!(
                    "watcher mid-eval config stamp triggered restart: {}",
                    path.display()
                ));
            }
            self.rebaseline_after_snapshot_change(spec)?;
            return Ok(false);
        }
        let current =
            self.watch
                .snapshot_still_current(spec, resolved, &self.state_root.clone())?;
        if !current {
            self.rebaseline_after_snapshot_change(spec)?;
        }
        Ok(current)
    }

    fn rebaseline_after_snapshot_change(&mut self, spec: &Spec) -> Result<(), String> {
        let declared = declared_sources_for_spec(spec)?;
        let state_root = self.state_root.clone();
        let repo_root = self.repo_root.clone();
        if self
            .watch
            .rebaseline_request(&repo_root, &state_root, &declared)
        {
            self.source_cache = graph::ResolvedSources::default();
            self.watch.dirty_sources.clear();
            self.watch.reset_sources = false;
        }
        Ok(())
    }

    pub fn watcher_snapshot_quiesce_ms(&self) -> u128 {
        self.watch.snapshot_quiesce_ms()
    }

    pub fn watcher_status(&mut self) -> WatchStatus {
        let declared = match self.declared_sources() {
            Ok(declared) => declared,
            Err(error) => {
                self.watch
                    .degrade(format!("cannot enumerate declared sources: {error}"));
                BTreeSet::new()
            }
        };
        let state_root = self.state_root.clone();
        let repo_root = self.repo_root.clone();
        if self.watch.poll(&repo_root, &state_root, &declared) {
            self.source_cache = graph::ResolvedSources::default();
            self.watch.dirty_sources.clear();
        }
        self.watch.status()
    }

    pub fn take_watcher_transitions(&mut self) -> Vec<String> {
        self.watch.take_transitions()
    }

    pub fn record_resident_container_runtime(&mut self, runtime: &str) {
        if matches!(runtime, "docker" | "nerdctl") {
            self.resident_container_runtimes.insert(runtime.to_string());
        }
    }

    pub fn resident_container_runtimes(&self) -> Vec<String> {
        self.resident_container_runtimes.iter().cloned().collect()
    }

    pub fn shutdown(&mut self) {
        if let Some(mut watcher) = self.watch.watcher.take() {
            watcher.shutdown();
        }
    }

    fn begin_request(&mut self) {
        let declared = match self.declared_sources() {
            Ok(declared) => declared,
            Err(error) => {
                self.watch
                    .degrade(format!("cannot enumerate declared sources: {error}"));
                BTreeSet::new()
            }
        };
        let state_root = self.state_root.clone();
        let repo_root = self.repo_root.clone();
        if self.watch.begin_request(&repo_root, &state_root, &declared) {
            self.source_cache = graph::ResolvedSources::default();
            self.watch.dirty_sources.clear();
            self.watch.reset_sources = false;
        }
    }

    fn declared_sources(&self) -> Result<BTreeSet<String>, String> {
        let mut sources = BTreeSet::new();
        for entry in &self.specs {
            sources.extend(declared_sources_for_spec(&entry.spec)?);
        }
        Ok(sources)
    }

    pub fn verify(&mut self, argv: &[String]) -> Result<i32, String> {
        let mut plan_argv = vec!["plan".to_string()];
        plan_argv.extend(argv.iter().skip(1).cloned());
        if plan_argv.len() == 1 {
            plan_argv.push(crate::spec::kinds::DEFAULT_GROUP.to_string());
        }
        let args = crate::cmd::parse_args(&plan_argv)?;
        let mut ctx = self.open_context(&args)?;
        let _store_lease = ctx.store.acquire_shared_lease()?;
        let targets = args.targets.clone();
        let git_state = ctx.git_state().clone();
        let resident_scope = crate::source::EvaluationMemoScope::new();
        let mut resident_progress = |_: EvalProgress| {};
        let resident = self.evaluate_plan_with_progress_inner(
            &ctx.spec,
            &ctx.config,
            &mut ctx.toolchain,
            &targets,
            true,
            git_state.clone(),
            &resident_scope,
            false,
            &mut resident_progress,
        )?;
        if !crate::eval::cache::evaluation_snapshot_still_current_with_cancel(
            &ctx.spec,
            &resident.evaluated.resolved_sources,
            &request_cancellation_token(),
        )? {
            return Err("daemon verify: resident evaluation snapshot changed".to_string());
        }
        let resident_key = cache::eval_key(
            &ctx.spec,
            &ctx.config,
            &targets,
            &resident.evaluated.config_digests,
            &resident.evaluated.resolved_sources,
            &resident.evaluated.git_state,
        )?;
        let mut fresh_ctx = self.open_context_uncached(&args)?;
        let fresh_git_state = fresh_ctx.git_state().clone();
        let fresh_scope = crate::source::EvaluationMemoScope::new();
        let mut fresh_progress = |_: EvalProgress| {};
        let fresh = self.evaluate_plan_with_progress_inner(
            &fresh_ctx.spec,
            &fresh_ctx.config,
            &mut fresh_ctx.toolchain,
            &targets,
            false,
            fresh_git_state,
            &fresh_scope,
            false,
            &mut fresh_progress,
        )?;
        if !crate::eval::cache::evaluation_snapshot_still_current_with_cancel(
            &fresh_ctx.spec,
            &fresh.evaluated.resolved_sources,
            &request_cancellation_token(),
        )? {
            return Err("daemon verify: fresh evaluation snapshot changed".to_string());
        }
        let fresh_key = cache::eval_key(
            &fresh_ctx.spec,
            &fresh_ctx.config,
            &targets,
            &fresh.evaluated.config_digests,
            &fresh.evaluated.resolved_sources,
            &fresh.evaluated.git_state,
        )?;
        if resident_key == fresh_key && resident.hash == fresh.hash {
            out!("agree");
            Ok(0)
        } else {
            out!("disagree");
            Ok(1)
        }
    }
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct FakeEvents(Arc<Mutex<Vec<WatchEvent>>>);

    struct FakeWatcher {
        events: FakeEvents,
        platform: &'static str,
    }

    impl Watcher for FakeWatcher {
        fn drain(&mut self) -> Vec<WatchEvent> {
            std::mem::take(&mut *self.events.0.lock().expect("fake watcher lock"))
        }

        fn shutdown(&mut self) {}

        fn platform_name(&self) -> &'static str {
            self.platform
        }

        fn quiesce_duration(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
    }

    fn fake_watch_state(events: FakeEvents) -> WatchState {
        WatchState {
            watcher: Some(Box::new(FakeWatcher {
                events,
                platform: "fake",
            })),
            health: WatchHealth::Healthy,
            reason: None,
            event_generation: 0,
            relevant_generation: 0,
            baseline_event_generation: Some(0),
            baseline_relevant_generation: Some(0),
            request_relevant_generation: 0,
            dirty_sources: BTreeSet::new(),
            reset_sources: false,
            spec_dirty: false,
            config_dirty: false,
            git_identity_stale: false,
            cached_git_state: Some(("rev".into(), "false".into())),
            observed_git_state: None,
            quiesce_ns: 0,
            snapshot_quiesce_ms: 0,
            transitions: Vec::new(),
            relevant_paths_since_request: Vec::new(),
            structural_fallback: false,
        }
    }

    fn test_paths() -> (PathBuf, PathBuf, BTreeSet<String>) {
        let root = std::env::temp_dir().join(format!(
            "buildutil-daemon-watch-state-{}",
            std::process::id()
        ));
        let state = root.join(".buildutil");
        let roots = BTreeSet::from([
            "src/blob.rs".to_string(),
            "src/tree".to_string(),
            "tools/buildutil".to_string(),
        ]);
        (root, state, roots)
    }

    #[test]
    fn dispatch_table_covers_source_spec_state_and_git_surfaces() {
        let (root, state_root, declared) = test_paths();
        let events = FakeEvents(Arc::new(Mutex::new(Vec::new())));
        let mut watch = fake_watch_state(events);

        assert!(!watch.dispatch_path(
            &root,
            &state_root,
            &declared,
            &root.join("src/tree/changed.rs")
        ));
        assert!(watch.dirty_sources.contains("src/tree"));
        assert!(watch.cached_git_state.is_none());

        watch.dispatch_path(&root, &state_root, &declared, &root.join("buildutil.toml"));
        assert!(watch.spec_dirty);
        watch.spec_dirty = false;
        watch.dispatch_path(
            &root,
            &state_root,
            &declared,
            &root.join("src/tree/buildutil.toml"),
        );
        assert!(watch.spec_dirty);

        assert!(watch.dispatch_path(
            &root,
            &state_root,
            &declared,
            &root.join(".buildutilignore")
        ));
        assert!(watch.reset_sources);
        watch.reset_sources = false;
        assert!(watch.dispatch_path(
            &root,
            &state_root,
            &declared,
            &root.join("vendor/lib/.buildutilignore")
        ));
        assert!(watch.reset_sources);

        let source_dirty = watch.dirty_sources.clone();
        watch.dispatch_path(
            &root,
            &state_root,
            &declared,
            &state_root.join("store/output"),
        );
        assert_eq!(watch.dirty_sources, source_dirty);
        watch.dispatch_path(
            &root,
            &state_root,
            &declared,
            &state_root.join("config/x86_64/config.keyval"),
        );
        assert!(watch.config_dirty);

        watch.reset_sources = false;
        watch.cached_git_state = Some(("rev".into(), "false".into()));
        let relevant_before_git_event = watch.relevant_generation;
        assert!(!watch.dispatch_path(
            &root,
            &state_root,
            &declared,
            &root.join(".git/refs/heads/main")
        ));
        assert!(watch.git_identity_stale);
        assert_eq!(watch.relevant_generation, relevant_before_git_event);
        assert_eq!(watch.cached_git_state, Some(("rev".into(), "false".into())));
        watch.reset_sources = false;
        assert!(!watch.dispatch_path(&root, &state_root, &declared, &root.join(".gitmodules")));
        watch.reset_sources = false;
        assert!(!watch.dispatch_path(&root, &state_root, &declared, &root.join(".gitattributes")));
    }

    #[test]
    fn ignored_events_do_not_retry_but_declared_source_events_do() {
        let (root, state_root, declared) = test_paths();
        let events = FakeEvents(Arc::new(Mutex::new(Vec::new())));
        let mut watch = fake_watch_state(events.clone());
        watch.begin_request(&root, &state_root, &declared);
        assert!(watch.generation_matches_request(&root, &state_root, &declared));
        assert!(watch.can_reuse_sources());

        let ignored = [
            state_root.join("daemon.log"),
            state_root.join("sources/cas-entry"),
            state_root.join("statcache"),
            state_root.join("temproots/request"),
            state_root.join("plans/request"),
            root.join("unrelated-output"),
        ];
        events
            .0
            .lock()
            .expect("fake watcher lock")
            .extend(ignored.iter().cloned().map(WatchEvent::Path));
        assert!(watch.generation_matches_request(&root, &state_root, &declared));
        assert!(watch.can_reuse_sources());
        assert_eq!(watch.relevant_generation, 0);
        assert_eq!(watch.event_generation, ignored.len() as u64);
        assert_eq!(watch.status().events_since_baseline, ignored.len());
        let delivered = format!(
            "watcher drain delivered {} path events sample=[",
            ignored.len()
        );
        assert!(
            watch
                .transitions
                .iter()
                .any(|line| line.contains(&delivered))
        );

        events
            .0
            .lock()
            .expect("fake watcher lock")
            .push(WatchEvent::Path(root.join("src/tree/during-eval.rs")));
        assert!(!watch.generation_matches_request(&root, &state_root, &declared));
        assert!(watch.dirty_sources.contains("src/tree"));
        assert!(!watch.can_reuse_sources());
    }

    #[test]
    fn settled_mid_eval_edit_rebaselines_and_resolves_post_edit_tree() {
        let _guard = crate::source::cas_test_guard();
        let base = std::env::temp_dir().join(format!(
            "buildutil-daemon-mid-eval-retry-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("repo");
        let state_root = base.join("state");
        for dir in [
            "tools/buildutil",
            "tools/buildutil/lib/mica",
            "tools/buildutil/lib/crypto",
            "tools/buildutil/compose",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for (path, bytes) in [
            ("buildutil", b"wrapper\n".as_slice()),
            ("buildutil.toml", b"[native-frontend]\n".as_slice()),
            (".buildutilignore", b"\n".as_slice()),
            ("tools/buildutil/bootstrap.ninja", b"bootstrap\n".as_slice()),
            ("tools/buildutil/main.rs", b"fn main() {}\n".as_slice()),
            ("tools/buildutil/lib/mica/lib.rs", b"pub fn mica() {}\n".as_slice()),
            ("tools/buildutil/lib/crypto/sha256.rs", b"".as_slice()),
            (
                "tools/buildutil/compose/lib.rs",
                b"pub fn compose() {}\n".as_slice(),
            ),
        ] {
            std::fs::write(root.join(path), bytes).unwrap();
        }
        crate::source::activate(&state_root).unwrap();

        let dspec = crate::spec::DrvSpec {
            repository: None,
            name: "frontend".into(),
            builder: "untar".into(),
            tool: "buildutil".into(),
            extra_tools: Vec::new(),
            when: String::new(),
            bootstrap: false,
            native_frontend: false,
            stage: None,
            host_tool: false,
            allowed_refs: crate::spec::RefPolicy::None,
            sources: Vec::new(),
            src_dirs: vec!["tools/buildutil".into()],
            source_roots: Vec::new(),
            source_overlays: Vec::new(),
            deps: Vec::new(),
            outputs: vec!["out".into()],
            argv: vec!["archive".into()],
            env: vec![("BUILDUTIL_FIXED_SHA256".into(), "0".repeat(64))],
            copy: Vec::new(),
            stage_deps: Vec::new(),
            groups: Vec::new(),
            compiles: Vec::new(),
            steps: Vec::new(),
            module: String::new(),
            module_role: String::new(),
            config_keys: Vec::new(),
        };
        let spec = Spec {
            repo_root: root.clone(),
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            target_system: "x86_64".into(),
            flagsets: BTreeMap::new(),
            drvs: BTreeMap::from([("frontend".into(), dspec)]),
            variants: BTreeMap::new(),
            kinds: Default::default(),
            tool_providers: BTreeMap::new(),
            stages: BTreeMap::new(),
            configuration: None,
            executor_image: None,
            modules: BTreeMap::new(),
            generators: BTreeMap::new(),
            bootstrap_steps: Vec::new(),
            pending: None,
            spec_inputs: Vec::new(),
        };
        let config = Config::from_values(BTreeMap::new());
        let targets = vec!["frontend".to_string()];
        let git_state = ("rev".to_string(), "false".to_string());
        let cancel = graph::CancellationToken::never();
        let mut progress = |_: EvalProgress| {};
        let before = graph::prepare_with_progress_reusing(
            &spec,
            &config,
            &targets,
            git_state.clone(),
            None,
            &BTreeSet::new(),
            &cancel,
            &mut progress,
        )
        .unwrap();
        let before_tree = before.resolved_sources.tree("tools/buildutil").unwrap();
        let before_key = cache::eval_key(
            &spec,
            &config,
            &targets,
            &before.graph.config_digests(),
            &before.resolved_sources,
            &git_state,
        )
        .unwrap();

        let events = FakeEvents(Arc::new(Mutex::new(Vec::new())));
        let watch = fake_watch_state(events.clone());
        let mut daemon = DaemonState {
            repo_root: root.clone(),
            state_root: state_root.clone(),
            specs: Vec::new(),
            eval_lru: VecDeque::new(),
            source_cache: before.resolved_sources.clone(),
            watch,
            resident_container_runtimes: BTreeSet::new(),
        };
        let declared = BTreeSet::from(["tools/buildutil".to_string()]);
        daemon.watch.begin_request(&root, &state_root, &declared);
        let edit = root.join("tools/buildutil/.daemon-parity-test");
        std::fs::write(&edit, b"post-edit\n").unwrap();
        events
            .0
            .lock()
            .expect("fake watcher lock")
            .push(WatchEvent::Path(edit.clone()));

        assert!(
            !daemon
                .snapshot_still_current(&spec, &before.resolved_sources)
                .unwrap()
        );
        assert!(daemon.watch.dirty_sources.contains("tools/buildutil"));
        assert_eq!(
            daemon.watch.request_relevant_generation,
            daemon.watch.relevant_generation
        );

        let after = graph::prepare_with_progress_reusing(
            &spec,
            &config,
            &targets,
            git_state.clone(),
            Some(&daemon.source_cache),
            daemon.watch.dirty_sources(),
            &cancel,
            &mut progress,
        )
        .unwrap();
        let after_tree = after.resolved_sources.tree("tools/buildutil").unwrap();
        let after_key = cache::eval_key(
            &spec,
            &config,
            &targets,
            &after.graph.config_digests(),
            &after.resolved_sources,
            &git_state,
        )
        .unwrap();
        assert_ne!(after_tree, before_tree);
        assert_ne!(after_key, before_key);

        daemon.watch.mark_baseline(&after.resolved_sources);
        assert!(
            daemon
                .watch
                .generation_matches_request(&root, &state_root, &declared)
        );
        assert!(!daemon.watch.dirty_sources.contains("tools/buildutil"));

        // A trailing watcher notification for the already-resolved bytes is
        // only a prompt to verify; the authoritative stat-diff accepts it.
        events
            .0
            .lock()
            .expect("fake watcher lock")
            .push(WatchEvent::Path(edit));
        assert!(
            daemon
                .snapshot_still_current(&spec, &after.resolved_sources)
                .unwrap()
        );
        assert_eq!(
            daemon.watch.request_relevant_generation,
            daemon.watch.relevant_generation
        );
        assert!(!daemon.watch.dirty_sources.contains("tools/buildutil"));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn awaiting_baseline_accepts_settled_post_edit_plan() {
        let _guard = crate::source::cas_test_guard();
        let base = std::env::temp_dir().join(format!(
            "buildutil-daemon-awaiting-baseline-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("repo");
        let state_root = base.join("state");
        for dir in [
            "tools/buildutil",
            "tools/buildutil/lib/mica",
            "tools/buildutil/lib/crypto",
            "tools/buildutil/compose",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for (path, bytes) in [
            ("buildutil", b"wrapper\n".as_slice()),
            ("buildutil.toml", b"[native-frontend]\n".as_slice()),
            (".buildutilignore", b"\n".as_slice()),
            ("tools/buildutil/bootstrap.ninja", b"bootstrap\n".as_slice()),
            ("tools/buildutil/main.rs", b"before\n".as_slice()),
            ("tools/buildutil/lib/mica/lib.rs", b"pub fn mica() {}\n".as_slice()),
            ("tools/buildutil/lib/crypto/sha256.rs", b"".as_slice()),
            (
                "tools/buildutil/compose/lib.rs",
                b"pub fn compose() {}\n".as_slice(),
            ),
        ] {
            std::fs::write(root.join(path), bytes).unwrap();
        }
        crate::source::activate(&state_root).unwrap();
        let spec = Spec {
            repo_root: root.clone(),
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            target_system: "x86_64".into(),
            flagsets: BTreeMap::new(),
            drvs: BTreeMap::new(),
            variants: BTreeMap::new(),
            kinds: Default::default(),
            tool_providers: BTreeMap::new(),
            stages: BTreeMap::new(),
            configuration: None,
            executor_image: None,
            modules: BTreeMap::new(),
            generators: BTreeMap::new(),
            bootstrap_steps: Vec::new(),
            pending: None,
            spec_inputs: Vec::new(),
        };
        let config = Config::from_values(BTreeMap::new());
        let targets = Vec::<String>::new();
        let git_state = ("rev".to_string(), "false".to_string());
        let cancel = graph::CancellationToken::never();
        let mut progress = |_: EvalProgress| {};
        let before = graph::prepare_with_progress_reusing(
            &spec,
            &config,
            &targets,
            git_state.clone(),
            None,
            &BTreeSet::new(),
            &cancel,
            &mut progress,
        )
        .unwrap();
        let before_key = cache::eval_key(
            &spec,
            &config,
            &targets,
            &before.graph.config_digests(),
            &before.resolved_sources,
            &git_state,
        )
        .unwrap();

        let edit = root.join("tools/buildutil/main.rs");
        std::fs::write(&edit, b"after changed\n").unwrap();
        let after = graph::prepare_with_progress_reusing(
            &spec,
            &config,
            &targets,
            git_state.clone(),
            None,
            &BTreeSet::new(),
            &cancel,
            &mut progress,
        )
        .unwrap();
        let after_key = cache::eval_key(
            &spec,
            &config,
            &targets,
            &after.graph.config_digests(),
            &after.resolved_sources,
            &git_state,
        )
        .unwrap();
        assert_ne!(after_key, before_key);

        let events = FakeEvents(Arc::new(Mutex::new(Vec::new())));
        let mut watch = fake_watch_state(events.clone());
        watch.health = WatchHealth::AwaitingBaseline;
        watch.baseline_event_generation = None;
        watch.baseline_relevant_generation = None;
        // A fresh daemon begins its first request before it has cached the
        // parsed spec, so the request-start barrier has no declared roots yet.
        watch.begin_request(&root, &state_root, &BTreeSet::new());
        events
            .0
            .lock()
            .expect("fake watcher lock")
            .push(WatchEvent::Path(edit));
        let mut daemon = DaemonState {
            repo_root: root.clone(),
            state_root: state_root.clone(),
            specs: Vec::new(),
            eval_lru: VecDeque::new(),
            source_cache: after.resolved_sources.clone(),
            watch,
            resident_container_runtimes: BTreeSet::new(),
        };

        assert!(
            daemon
                .snapshot_still_current(&spec, &after.resolved_sources)
                .unwrap()
        );
        assert_eq!(daemon.watch.health, WatchHealth::Healthy);
        assert_eq!(
            daemon.watch.request_relevant_generation,
            daemon.watch.relevant_generation
        );
        assert_eq!(
            daemon.watch.baseline_relevant_generation,
            Some(daemon.watch.relevant_generation)
        );
        assert!(daemon.watch.dirty_sources.is_empty());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn git_surface_defers_identity_reprobe_until_the_next_request() {
        let (root, state_root, declared) = test_paths();
        let events = FakeEvents(Arc::new(Mutex::new(Vec::new())));
        let mut watch = fake_watch_state(events.clone());
        watch.begin_request(&root, &state_root, &declared);

        events
            .0
            .lock()
            .expect("fake watcher lock")
            .push(WatchEvent::Path(root.join(".git/index")));
        assert!(watch.generation_matches_request(&root, &state_root, &declared));
        assert!(watch.git_identity_stale);
        assert_eq!(watch.relevant_generation, 0);
        assert!(!watch.can_reuse_sources());

        // Simulate the successful in-flight evaluation. Its own git probe
        // event remains stale for the next request rather than forcing a
        // restart of this one.
        watch.observed_git_state = watch.cached_git_state.clone();
        watch.mark_baseline(&graph::ResolvedSources::default());
        assert!(watch.git_identity_stale);

        watch.begin_request(&root, &state_root, &declared);
        let mut unchanged_probes = 0;
        assert_eq!(
            watch.git_state_with(false, || {
                unchanged_probes += 1;
                ("rev".into(), "false".into())
            }),
            ("rev".into(), "false".into())
        );
        assert_eq!(unchanged_probes, 1);
        assert!(!watch.git_identity_stale);
        assert!(!watch.reset_sources);
        assert!(watch.can_reuse_sources());
        assert!(watch.can_reuse_cached_sources());

        events
            .0
            .lock()
            .expect("fake watcher lock")
            .push(WatchEvent::Path(root.join(".git/HEAD")));
        assert!(watch.generation_matches_request(&root, &state_root, &declared));
        watch.mark_baseline(&graph::ResolvedSources::default());

        watch.begin_request(&root, &state_root, &declared);
        let mut changed_probes = 0;
        assert_eq!(
            watch.git_state_with(false, || {
                changed_probes += 1;
                ("next-rev".into(), "true".into())
            }),
            ("next-rev".into(), "true".into())
        );
        assert_eq!(changed_probes, 1);
        assert!(watch.reset_sources);
        assert!(!watch.can_reuse_sources());
        assert!(!watch.can_reuse_cached_sources());
    }

    #[test]
    fn overflow_degrades_to_stat_diff() {
        let (root, state_root, declared) = test_paths();
        let events = FakeEvents(Arc::new(Mutex::new(vec![WatchEvent::Uncertain(
            "inotify queue overflow".to_string(),
        )])));
        let mut watch = fake_watch_state(events);
        watch.begin_request(&root, &state_root, &declared);
        assert_eq!(watch.health, WatchHealth::Unhealthy);
        assert!(!watch.can_reuse_sources());
        assert!(
            watch
                .take_transitions()
                .iter()
                .any(|line| line.contains("unhealthy"))
        );
    }

    #[test]
    fn recovery_requires_a_new_verified_baseline() {
        let events = FakeEvents(Arc::new(Mutex::new(Vec::new())));
        let mut watch = fake_watch_state(events.clone());
        watch.degrade("inotify queue overflow".to_string());
        assert_eq!(watch.health, WatchHealth::Unhealthy);
        assert!(!watch.can_reuse_sources());

        watch.watcher = Some(Box::new(FakeWatcher {
            events,
            platform: "fake",
        }));
        watch.set_health(
            WatchHealth::AwaitingBaseline,
            None,
            "watcher health -> awaiting-baseline (fake)".to_string(),
        );
        assert!(!watch.can_reuse_sources());

        watch.mark_baseline(&graph::ResolvedSources::default());
        assert_eq!(watch.health, WatchHealth::Healthy);
        assert!(watch.can_reuse_sources());
        assert!(
            watch
                .transitions
                .iter()
                .any(|line| line == "watcher health -> healthy (verified baseline)")
        );
    }

    #[test]
    fn fsevents_state_root_delivery_engages_structural_fallback() {
        let (root, state_root, declared) = test_paths();
        let events = FakeEvents(Arc::new(Mutex::new(vec![WatchEvent::Path(
            state_root.join("store/storm"),
        )])));
        let mut watch = fake_watch_state(events);
        watch.watcher.as_mut().expect("fake watcher").shutdown();
        watch.watcher = Some(Box::new(FakeWatcher {
            events: FakeEvents(Arc::new(Mutex::new(vec![WatchEvent::Path(
                state_root.join("store/storm"),
            )]))),
            platform: "fsevents",
        }));

        watch.begin_request(&root, &state_root, &declared);
        assert_eq!(watch.health, WatchHealth::Unhealthy);
        assert!(watch.structural_fallback);
        assert!(
            watch
                .reason
                .as_deref()
                .is_some_and(|reason| { reason.contains("exclusion delivered state-root path") })
        );
    }

    #[test]
    fn allowlist_filters_untrusted_values() {
        let values: BTreeMap<String, String> = BTreeMap::from([
            ("PATH".into(), "/bin".into()),
            ("LD_PRELOAD".into(), "bad".into()),
        ]);
        let accepted = values
            .into_iter()
            .filter(|(key, _)| ENV_ALLOWLIST.contains(&key.as_str()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(accepted, BTreeMap::from([("PATH".into(), "/bin".into())]));
    }

    #[test]
    fn evalcache_lru_hit_miss_and_eviction() {
        let _guard = crate::source::cas_test_guard();
        let root =
            std::env::temp_dir().join(format!("buildutil-daemon-lru-{}", std::process::id()));
        let mut state = DaemonState::new(root.join("repo"), root.join("state")).unwrap();
        let plan_path = root.join("plan");
        std::fs::write(&plan_path, "plan").unwrap();
        for index in 0..10 {
            state.eval_lru.push_back(ResidentPlan {
                eval_key: index.to_string(),
                evaluated: Evaluated {
                    order: Vec::new(),
                    recipes: BTreeMap::new(),
                    plans: BTreeMap::new(),
                    roots: Vec::new(),
                    configured: BTreeMap::new(),
                    config_digests: BTreeMap::new(),
                    resolved_sources: Default::default(),
                    git_state: (String::new(), String::new()),
                },
                plan: crate::eval::plan::ExecPlan {
                    arch: String::new(),
                    build_host: String::new(),
                    filter_hash: String::new(),
                    git_rev: String::new(),
                    git_dirty: String::new(),
                    targets: Vec::new(),
                    bootstrap: Vec::new(),
                    nodes: Vec::new(),
                },
                plan_hash: String::new(),
                path: plan_path.clone(),
                stamp: FileStamp::read(&plan_path).unwrap(),
            });
            while state.eval_lru.len() > 8 {
                state.eval_lru.pop_front();
            }
        }
        assert_eq!(state.eval_lru.len(), 8);
        assert!(state.take_resident("4").is_some());
        assert_eq!(state.eval_lru.front().unwrap().eval_key, "4");
        assert!(state.take_resident("missing").is_none());
        std::fs::write(&plan_path, "plan changed on disk").unwrap();
        assert!(state.take_resident("5").is_none());
        state.eval_lru.push_front(ResidentPlan {
            eval_key: "new".into(),
            evaluated: Evaluated {
                order: Vec::new(),
                recipes: BTreeMap::new(),
                plans: BTreeMap::new(),
                roots: Vec::new(),
                configured: BTreeMap::new(),
                config_digests: BTreeMap::new(),
                resolved_sources: Default::default(),
                git_state: (String::new(), String::new()),
            },
            plan: crate::eval::plan::ExecPlan {
                arch: String::new(),
                build_host: String::new(),
                filter_hash: String::new(),
                git_rev: String::new(),
                git_dirty: String::new(),
                targets: Vec::new(),
                bootstrap: Vec::new(),
                nodes: Vec::new(),
            },
            plan_hash: String::new(),
            stamp: FileStamp::read(&plan_path).unwrap(),
            path: plan_path,
        });
        assert_eq!(state.eval_lru.len(), 8);
        assert!(state.eval_lru.iter().any(|entry| entry.eval_key == "new"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn spec_input_change_invalidates_resident_spec() {
        let _guard = crate::source::cas_test_guard();
        let root =
            std::env::temp_dir().join(format!("buildutil-daemon-spec-{}", std::process::id()));
        let repo = root.join("repo");
        let state_root = root.join("state");
        let persistent = crate::state::config_file(&state_root, "x86_64");
        std::fs::create_dir_all(persistent.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("buildutil.toml"), "first").unwrap();
        std::fs::write(&persistent, "A = true\n").unwrap();
        let input = crate::spec::SpecInput {
            path: "buildutil.toml".into(),
            hash: crate::spec::hash_spec_input(
                &repo,
                &crate::spec::SpecInput {
                    path: "buildutil.toml".into(),
                    hash: String::new(),
                    kind: crate::spec::SpecInputKind::File,
                },
            )
            .unwrap(),
            kind: crate::spec::SpecInputKind::File,
        };
        let entry = SpecConfigEntry {
            key: SpecConfigKey {
                arch: "x86_64".into(),
                build_host: "x86_64-unknown-linux-gnu".into(),
                overrides: Vec::new(),
            },
            spec: Arc::new(Spec {
                repo_root: repo.clone(),
                arch: "x86_64".into(),
                build_host: "x86_64-unknown-linux-gnu".into(),
                target_system: "x86_64".into(),
                flagsets: BTreeMap::new(),
                drvs: BTreeMap::new(),
                variants: BTreeMap::new(),
                kinds: Default::default(),
                tool_providers: BTreeMap::new(),
                stages: BTreeMap::new(),
                configuration: None,
                executor_image: None,
                modules: BTreeMap::new(),
                generators: BTreeMap::new(),
                bootstrap_steps: Vec::new(),
                pending: None,
                spec_inputs: vec![input],
            }),
            config: Arc::new(Config::from_values(BTreeMap::new())),
            config_stamps: config_stamps(vec![persistent.clone()]),
        };
        let mut daemon = DaemonState::new(repo.clone(), state_root).unwrap();
        assert!(daemon.spec_is_current(&entry));
        std::fs::write(repo.join("buildutil.toml"), "second").unwrap();
        assert!(!daemon.spec_is_current(&entry));
        let spec = entry.spec.clone();
        daemon.specs.push(entry);
        assert!(daemon.config_for_spec_is_current(&spec));
        std::fs::write(&persistent, "A = false\n").unwrap();
        assert!(!daemon.config_for_spec_is_current(&spec));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn context_dirty_clears_only_after_every_cached_key_is_current() {
        let _guard = crate::source::cas_test_guard();
        let root = std::env::temp_dir().join(format!(
            "buildutil-daemon-multi-spec-{}",
            std::process::id()
        ));
        let repo = root.join("repo");
        let state_root = root.join("state");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("buildutil.toml"), "first").unwrap();
        for arch in ["x86_64", "aarch64"] {
            let persistent = crate::state::config_file(&state_root, arch);
            std::fs::create_dir_all(persistent.parent().unwrap()).unwrap();
            std::fs::write(&persistent, "A = true\n").unwrap();
        }

        let make_entry = |arch: &str, build_host: &str| {
            let template = crate::spec::SpecInput {
                path: "buildutil.toml".into(),
                hash: String::new(),
                kind: crate::spec::SpecInputKind::File,
            };
            let input = crate::spec::SpecInput {
                hash: crate::spec::hash_spec_input(&repo, &template).unwrap(),
                ..template
            };
            SpecConfigEntry {
                key: SpecConfigKey {
                    arch: arch.into(),
                    build_host: build_host.into(),
                    overrides: Vec::new(),
                },
                spec: Arc::new(Spec {
                    repo_root: repo.clone(),
                    arch: arch.into(),
                    build_host: build_host.into(),
                    target_system: "x86_64".into(),
                    flagsets: BTreeMap::new(),
                    drvs: BTreeMap::new(),
                    variants: BTreeMap::new(),
                    kinds: Default::default(),
                    tool_providers: BTreeMap::new(),
                    stages: BTreeMap::new(),
                    configuration: None,
                    executor_image: None,
                    modules: BTreeMap::new(),
                    generators: BTreeMap::new(),
                    bootstrap_steps: Vec::new(),
                    pending: None,
                    spec_inputs: vec![input],
                }),
                config: Arc::new(Config::from_values(BTreeMap::new())),
                config_stamps: config_stamps(vec![crate::state::config_file(&state_root, arch)]),
            }
        };

        let mut daemon = DaemonState::new(repo.clone(), state_root.clone()).unwrap();
        daemon.specs = vec![
            make_entry("x86_64", "x86_64-unknown-linux-gnu"),
            make_entry("aarch64", "aarch64-unknown-linux-gnu"),
        ];
        std::fs::write(repo.join("buildutil.toml"), "second").unwrap();
        daemon.watch.spec_dirty = true;

        daemon.specs[0] = make_entry("x86_64", "x86_64-unknown-linux-gnu");
        daemon.clear_context_dirty_if_all_current();
        assert!(daemon.watch.spec_dirty);

        daemon.specs[1] = make_entry("aarch64", "aarch64-unknown-linux-gnu");
        daemon.clear_context_dirty_if_all_current();
        assert!(!daemon.watch.spec_dirty);
        let _ = std::fs::remove_dir_all(root);
    }
}
