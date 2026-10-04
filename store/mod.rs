//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the content-addressed store
//!
//! Layout under the buildutil state root (default `<repo>/.buildutil`, overridable
//! via `--store` / `BUILDUTIL_STORE`):
//!   store/<hash32>-<name>-<arch>/    realized outputs
//!   drv/<store-name>.drv             canonical preimage
//!   meta/<store-name>                flat text: full hash, refs, out hashes
//!   logs/<store-name>.log            builder stdout/stderr
//!   logs/<store-name>/               the builder's retained artifacts
//!   roots/indirect-<hash16>          → a link an app keeps under run/
//!   roots/<root-name>                symlink GC roots
//!   temproots/<pid>-*.roots          flock-held roots for active commands
//!   tmp/<store-name>.build/          private build dirs (same fs → rename)
//!   locks/<hash32>.building          per-derivation flock targets
//!   locks/gc.lease                   store-wide shared/exclusive GC lease
//!
//! Registration is atomic: build in tmp, rename into place, then write the
//! meta file; a lost race discards the local result and reuses the winner.
//! Liveness is mark-and-sweep from roots following `ref:` (declared build
//! dependency) and `reference:` (scan-recorded runtime reference) lines.

use crate::store::derivation::Derivation;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Name prefix of the persistent roots that name a link under `run/`
/// instead of a store entry (`Store::add_indirect_root`).
pub const INDIRECT_ROOT_PREFIX: &str = "indirect-";

pub(super) static TEMP_ROOT_SEQ: AtomicU64 = AtomicU64::new(0);

/// GC policy knobs. With both unset, all dead (unreachable) entries are
/// swept. `max_age_days` limits sweeping to dead entries older than the
/// cutoff; `min_free` sweeps dead entries oldest-first until at least that
/// many bytes have been reclaimed.
#[derive(Default, Clone, Copy)]
pub struct GcPolicy {
    pub max_age_days: Option<u64>,
    pub min_free: Option<u64>,
}

pub struct Store {
    /// The state root (`.buildutil`): admin dirs live directly under it.
    state: PathBuf,
    /// The entries dir (`<state>/store`): realized outputs live here.
    pub root: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcSweep {
    pub name: String,
    pub bytes: u64,
}

#[cfg(test)]
type TmpBuildSweep = GcSweep;

#[derive(Default, Clone, Copy)]
pub struct GcOptions {
    pub policy: GcPolicy,
    pub dry_run: bool,
    pub prune_roots_older_than_days: Option<u64>,
}

#[derive(Default, Debug)]
pub struct GcReport {
    pub store_swept: Vec<GcSweep>,
    pub tmp_swept: Vec<GcSweep>,
    pub bytes_reclaimed: u64,
    pub active_tmp_skipped: Vec<String>,
    pub roots_scanned: usize,
    pub cas_swept: usize,
    pub plans_swept: usize,
    /// Dead pre-stat-cache files swept for size only (legacy
    /// `src-hash-cache` / `tool-id-cache` text caches — never migrated,
    /// always unlinked). Bytes are folded into `bytes_reclaimed` so a
    /// legacy sweep can only ever free disk.
    pub legacy_caches_swept: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcProgress {
    Phase(&'static str),
    Root(String),
    TempRoot(String),
    StoreScan {
        index: usize,
        total: usize,
        name: String,
        live: bool,
        bytes: u64,
    },
    PlanStore {
        index: usize,
        total: usize,
        name: String,
        bytes: u64,
    },
    SweepTmp {
        index: usize,
        total: usize,
        name: String,
        bytes: u64,
        dry_run: bool,
    },
    SkipActiveTmp(String),
    SweepStore {
        index: usize,
        total: usize,
        name: String,
        bytes: u64,
        dry_run: bool,
    },
}

#[must_use]
pub struct BuildLock {
    /// The open fd owns the advisory flock. Dropping it releases the lock, even
    /// when the holder dies by SIGKILL or container teardown.
    _file: File,
}

#[must_use]
pub struct TempRoot {
    path: PathBuf,
    file: File,
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl TempRoot {
    /// Append one store name to this flock-held root file and make it visible
    /// to GC readers before the associated realization becomes schedulable.
    pub fn append(&mut self, store_name: &str) -> Result<(), String> {
        if store_name.is_empty() {
            return Ok(());
        }
        writeln!(self.file, "{}", store_name)
            .map_err(|e| format!("cannot write temp root {}: {}", self.path.display(), e))?;
        self.file
            .flush()
            .map_err(|e| format!("cannot flush temp root {}: {}", self.path.display(), e))
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub struct Meta {
    pub drv_hash: String,
    pub refs: Vec<String>,
    /// Store entries this entry's realized bytes actually reference —
    /// recorded by the reference scan for hosted outputs (a subset of the
    /// dependency closure by construction). GC liveness follows these in
    /// union with `refs`.
    pub references: Vec<String>,
    pub outs: Vec<(String, String)>,
    /// Directory outputs: (relpath, tree-manifest hash).
    pub outdirs: Vec<(String, String)>,
    pub sandbox: String,
    /// A port's runtime closure edges (port names).
    pub runtime_deps: Vec<String>,
    /// Built by the self-tool class from an ambient compiler: never signed
    /// or substituted.
    pub self_tool: bool,
}

/// Canonical realization-manifest text: `out:` / `outdir:` lines sorted by
/// relpath (a file and a directory can never share a relpath, so the sort is
/// total). `outs` / `outdirs` are `(relpath, hash)`.
pub fn realization_manifest(outs: &[(String, String)], outdirs: &[(String, String)]) -> String {
    let mut entries: Vec<(String, String)> = Vec::new();
    for (rel, h) in outs {
        entries.push((rel.clone(), format!("out: {} {}\n", h, rel)));
    }
    for (rel, h) in outdirs {
        entries.push((rel.clone(), format!("outdir: {} {}\n", h, rel)));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.into_iter().map(|(_, line)| line).collect()
}

/// The realization digest: SHA-256 over the canonical manifest. A function of
/// output CONTENT only (never of the drv hash), so two derivations realizing
/// identical bytes share one digest — the key early-cutoff invariant.
pub fn realization_digest(outs: &[(String, String)], outdirs: &[(String, String)]) -> String {
    crate::crypto::sha256::hash_bytes(realization_manifest(outs, outdirs).as_bytes())
}

impl Meta {
    pub fn digest(&self) -> String {
        realization_digest(&self.outs, &self.outdirs)
    }
}

/// Producer provenance for the buildutil engine that wrote a realization record.
/// This is not part of derivation identity or realization digest; build-tool
/// authority comes from store provider edges. Falls back to `"buildutil"` if the
/// running binary is unreadable.
pub(crate) fn buildutil_self_identity() -> String {
    use std::sync::OnceLock;
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        match std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::read(p).ok())
        {
            Some(bytes) => format!(
                "sha256:{};buildutil",
                crate::crypto::sha256::hash_bytes(&bytes)
            ),
            None => "buildutil".to_string(),
        }
    })
    .clone()
}

impl Store {
    pub fn open(state: &Path) -> Result<Store, String> {
        for sub in [
            "store",
            "drv",
            "meta",
            "logs",
            "roots",
            "temproots",
            "tmp",
            "locks",
            "realizations",
        ] {
            std::fs::create_dir_all(state.join(sub))
                .map_err(|e| format!("cannot create store dir {}: {}", state.display(), e))?;
        }
        Ok(Store {
            state: state.to_path_buf(),
            root: state.join("store"),
        })
    }

    pub fn out_path(&self, drv: &Derivation) -> PathBuf {
        self.root.join(drv.store_name())
    }

    fn meta_path(&self, store_name: &str) -> PathBuf {
        self.state.join("meta").join(store_name)
    }

    pub fn log_path(&self, store_name: &str) -> PathBuf {
        self.state.join(self.log_name(store_name))
    }

    /// The retained build log of `store_name`, relative to the state root.
    /// Events carry this form so each client resolves it against its own
    /// view of the state root (a container mounts it elsewhere).
    pub fn log_name(&self, store_name: &str) -> String {
        format!("logs/{}.log", store_name)
    }

    /// The retained-artifact directory beside `store_name`'s build log: what
    /// a builder wrote to its artifact directory in the latest attempt,
    /// passed or failed. Never part of an output or its identity.
    pub fn artifacts_path(&self, store_name: &str) -> PathBuf {
        self.state.join("logs").join(store_name)
    }

    pub fn tmp_build_dir(&self, store_name: &str) -> PathBuf {
        self.state.join("tmp").join(format!("{}.build", store_name))
    }

    /// Create one flock-held temporary-root file for a realization command.
    /// Store names are appended as their outputs become reusable.
    pub fn create_temp_root(&self, label: &str) -> Result<TempRoot, String> {
        let dir = self.state.join("temproots");
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create temp roots dir {}: {}", dir.display(), e))?;
        let seq = TEMP_ROOT_SEQ.fetch_add(1, Ordering::Relaxed);
        let stem = format!(
            "{}-{}-{}",
            std::process::id(),
            seq,
            crate::store::gc::sanitize_temp_root_label(label)
        );
        let path = dir.join(format!("{}.roots", stem));
        let tmp = dir.join(format!("{}.tmp", stem));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("cannot create temp root {}: {}", tmp.display(), e))?;
        if let Err(err) = crate::platform::lock_exclusive(&file, false) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("cannot lock temp root {}: {}", tmp.display(), err));
        }
        if let Err(err) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!(
                "cannot publish temp root {}: {}",
                path.display(),
                err
            ));
        }
        Ok(TempRoot { path, file })
    }

    pub fn add_temp_roots(
        &self,
        label: &str,
        store_names: &[String],
    ) -> Result<Option<TempRoot>, String> {
        let roots: Vec<&str> = store_names
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        if roots.is_empty() {
            return Ok(None);
        }
        let mut temp_root = self.create_temp_root(label)?;
        for root in roots {
            temp_root.append(root)?;
        }
        Ok(Some(temp_root))
    }

    /// Validate a candidate warm-store realization before it is reused.
    ///
    /// `untar` is the bootstrap cycle breaker and therefore has no explicit
    /// store tool whose realization digest could carry extractor semantics.
    /// Its recursive output pin is the authority instead: it is identity-
    /// bearing and is rechecked against the actual store bytes at every reuse
    /// boundary. A missing pin or a corrupted/tampered tree fails closed.
    pub fn validate_reuse(&self, drv: &Derivation) -> Result<bool, String> {
        if !self.out_path(drv).is_dir() {
            return Ok(false);
        }
        let meta = match self.read_meta(&drv.store_name()) {
            Ok(meta) => meta,
            Err(_) => return Ok(false),
        };
        if meta.drv_hash != drv.hash() {
            return Err(format!(
                "cached `{}` has drv hash {}, expected {}",
                drv.store_name(),
                meta.drv_hash,
                drv.hash()
            ));
        }
        if drv.builder == "untar" {
            let declared = drv
                .fixed_output_pin("tree-sha256")
                .filter(|pin| !pin.is_empty())
                .ok_or_else(|| {
                    format!(
                        "cached untar `{}` has no identity-bearing tree pin",
                        drv.name
                    )
                })?;
            let actual = crate::source::filehash::hash_tree_with_dir_modes(&self.out_path(drv))?;
            if actual != declared {
                return Err(format!(
                    "cached untar `{}` tree hash mismatch\n  declared {}\n  actual   {}\n  at {}",
                    drv.name,
                    declared,
                    actual,
                    self.out_path(drv).display()
                ));
            }
        }
        Ok(true)
    }

    /// Realized-signal predicate keyed by store name (no `Derivation`
    /// required): the out dir exists AND the meta parses. Call sites that
    /// already have a store name (e.g. `dry_resolve`'s realized signal) do
    /// not need to reconstruct a derivation to assert realized-ness. NOT
    /// meta-only: a meta-without-dir is treated as absent (a meta-with-no-dir
    /// is the signature of an interrupted GC / repair).
    pub fn has_named(&self, store_name: &str) -> bool {
        self.root.join(store_name).is_dir() && self.read_meta(store_name).is_ok()
    }

    pub fn state_dir(&self) -> &Path {
        &self.state
    }

    pub fn acquire_shared_lease(&self) -> Result<crate::state::StoreSharedLease, String> {
        crate::state::lock_store_shared(&self.state)
    }

    pub fn acquire_exclusive_lease(&self) -> Result<crate::state::StoreExclusiveLease, String> {
        crate::state::lock_store_exclusive(&self.state)
    }

    /// Install a verified substituted entry: move the staged tree into
    /// place and write the (already-verified) meta text. A lost race
    /// keeps the local winner.
    pub fn install_substituted(
        &self,
        store_name: &str,
        staging: &Path,
        meta_text: &str,
    ) -> Result<(), String> {
        let dest = self.root.join(store_name);
        match std::fs::rename(staging, &dest) {
            Ok(()) => {}
            Err(_) if dest.is_dir() => {
                let _ = std::fs::remove_dir_all(staging);
                return Ok(());
            }
            Err(e) => {
                return Err(format!("cannot install substituted {}: {}", store_name, e));
            }
        }
        let meta_path = self.meta_path(store_name);
        let tmp = meta_path.with_extension("tmp");
        std::fs::write(&tmp, meta_text).map_err(|e| format!("cannot write meta: {}", e))?;
        std::fs::rename(&tmp, &meta_path).map_err(|e| format!("cannot commit meta: {}", e))?;
        Ok(())
    }

    /// Configured substituter base URLs (`<state>/substituters`, one per
    /// line). Absent file = substitution OFF.
    pub fn substituters(&self) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(self.state.join("substituters")) else {
            return Vec::new();
        };
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect()
    }

    pub fn read_meta(&self, store_name: &str) -> Result<Meta, String> {
        let path = self.meta_path(store_name);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read meta {}: {}", path.display(), e))?;
        let mut meta = Meta {
            drv_hash: String::new(),
            refs: Vec::new(),
            references: Vec::new(),
            outs: Vec::new(),
            outdirs: Vec::new(),
            sandbox: String::new(),
            runtime_deps: Vec::new(),
            self_tool: false,
        };
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("drv: ") {
                meta.drv_hash = v.to_string();
            } else if let Some(v) = line.strip_prefix("ref: ") {
                meta.refs.push(v.to_string());
            } else if let Some(v) = line.strip_prefix("reference: ") {
                meta.references.push(v.to_string());
            } else if let Some(v) = line.strip_prefix("out: ") {
                let (h, rel) = v
                    .split_once(' ')
                    .ok_or_else(|| format!("malformed out line in {}", path.display()))?;
                meta.outs.push((rel.to_string(), h.to_string()));
            } else if let Some(v) = line.strip_prefix("outdir: ") {
                let (h, rel) = v
                    .split_once(' ')
                    .ok_or_else(|| format!("malformed outdir line in {}", path.display()))?;
                meta.outdirs.push((rel.to_string(), h.to_string()));
            } else if let Some(v) = line.strip_prefix("sandbox: ") {
                meta.sandbox = v.to_string();
            } else if let Some(v) = line.strip_prefix("runtime-dep: ") {
                meta.runtime_deps.push(v.to_string());
            } else if line == "self-tool: true" {
                meta.self_tool = true;
            }
        }
        if meta.drv_hash.is_empty() {
            return Err(format!("meta {} has no drv hash", path.display()));
        }
        Ok(meta)
    }

    /// The realization record path for a drv hash (keyed by the same 32-hex
    /// prefix as store names and build locks).
    pub fn realization_path(&self, drv_hash: &str) -> PathBuf {
        self.state.join("realizations").join(&drv_hash[..32])
    }

    /// Recompute a realized entry's realization digest from its meta — used on
    /// the reuse and substitute paths, where no fresh build produced it.
    pub fn digest_of(&self, store_name: &str) -> Result<String, String> {
        Ok(self.read_meta(store_name)?.digest())
    }

    /// Write (atomically) the realization record for a realized derivation.
    /// Audit-grade records carry no signatures; signing is grade-keyed and
    /// lands with the enforcing sandboxes.
    pub fn write_realization(
        &self,
        drv_hash: &str,
        digest: &str,
        outs: &[(String, String)],
        outdirs: &[(String, String)],
        sandbox: &str,
        provider: &str,
    ) -> Result<(), String> {
        let mut rec = String::from("buildutil-realization\nformat: 1\n");
        rec.push_str(&format!("drv: {}\n", drv_hash));
        rec.push_str(&format!("digest: {}\n", digest));
        rec.push_str(&realization_manifest(outs, outdirs));
        rec.push_str(&format!("sandbox: {}\n", sandbox));
        rec.push_str(&format!("buildutil: {}\n", buildutil_self_identity()));
        rec.push_str(&format!("provider: {}\n", provider));
        let path = self.realization_path(drv_hash);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &rec).map_err(|e| format!("cannot write realization: {}", e))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("cannot commit realization: {}", e))?;
        Ok(())
    }

    /// The realization digest recorded for a drv hash, if a record exists.
    pub fn read_realization_digest(&self, drv_hash: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.realization_path(drv_hash)).ok()?;
        text.lines()
            .find_map(|l| l.strip_prefix("digest: ").map(str::to_string))
    }

    pub fn write_drv(&self, drv: &Derivation) -> Result<(), String> {
        let path = self
            .state
            .join("drv")
            .join(format!("{}.drv", drv.store_name()));
        std::fs::write(&path, drv.preimage())
            .map_err(|e| format!("cannot write {}: {}", path.display(), e))
    }

    fn try_lock_hash(&self, hash32: &str) -> Result<Option<BuildLock>, String> {
        let path = self
            .state
            .join("locks")
            .join(format!("{}.building", hash32));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|e| format!("cannot open build lock {}: {}", path.display(), e))?;
        match crate::platform::lock_exclusive(&file, true) {
            Ok(true) => Ok(Some(BuildLock { _file: file })),
            Ok(false) => Ok(None),
            Err(err) => Err(format!(
                "cannot lock build lock {}: {}",
                path.display(),
                err
            )),
        }
    }

    /// Acquire the per-derivation build lock; returns `Ok(None)` when another
    /// realizer holds it. The lock file is only the stable flock target: it may
    /// remain on disk after the holder exits, and that is not lock ownership.
    pub fn try_lock(&self, drv: &Derivation) -> Result<Option<BuildLock>, String> {
        let hash = drv.hash();
        self.try_lock_hash(&hash[..32])
    }

    /// The store name a GC root currently points at, if it exists.
    pub fn read_root(&self, root_name: &str) -> Option<String> {
        if root_name.starts_with(INDIRECT_ROOT_PREFIX) {
            let target = std::fs::read_link(self.state.join("roots").join(root_name)).ok()?;
            return self.indirect_root_target(&target);
        }
        let target = std::fs::read_link(self.state.join("roots").join(root_name)).ok()?;
        let name = target.file_name()?.to_string_lossy().into_owned();
        self.has_named(&name).then_some(name)
    }

    /// Refresh a named GC root with a relative symlink, publishing it by
    /// atomic rename so readers never observe a missing/partial root.
    pub fn add_root(&self, root_name: &str, store_name: &str) -> Result<(), String> {
        let link = self.state.join("roots").join(root_name);
        let seq = TEMP_ROOT_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .state
            .join("roots")
            .join(format!(".root-{}-{seq}.tmp", std::process::id()));
        crate::platform::create_symlink(
            &Path::new("..").join("store").join(store_name),
            &tmp,
            crate::platform::SymlinkKind::Directory,
        )
        .map_err(|e| format!("cannot create root {}: {}", tmp.display(), e))?;
        match std::fs::rename(&tmp, &link) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(format!("cannot publish root {}: {}", link.display(), e))
            }
        }
    }

    /// Register `link` — a symlink an app keeps under the state root's run
    /// directory — as an indirect GC root: the store entry `link` names
    /// stays alive until the app removes or repoints the link. Returns the
    /// root's name.
    pub fn add_indirect_root(&self, link: &Path) -> Result<String, String> {
        let absolute =
            |path: &Path| std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let run = absolute(&crate::state::run_dir(&self.state));
        let link = absolute(link);
        let rel = link.strip_prefix(&run).map_err(|_| {
            format!(
                "indirect root {} is not under {}",
                link.display(),
                run.display()
            )
        })?;
        if rel.as_os_str().is_empty()
            || rel
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "indirect root {} is not a clean path",
                link.display()
            ));
        }
        let rel = rel
            .to_str()
            .ok_or_else(|| format!("indirect root {} is not UTF-8", link.display()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let root_name = format!(
            "{INDIRECT_ROOT_PREFIX}{}",
            &crate::crypto::sha256::hash_bytes(rel.as_bytes())[..16]
        );
        let target = Path::new("..").join("run").join(&rel);
        let final_link = self.state.join("roots").join(&root_name);
        let seq = TEMP_ROOT_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .state
            .join("roots")
            .join(format!(".root-{}-{seq}.tmp", std::process::id()));
        crate::platform::create_symlink(&target, &tmp, crate::platform::SymlinkKind::File)
            .map_err(|e| format!("cannot create root {}: {}", tmp.display(), e))?;
        std::fs::rename(&tmp, &final_link).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot publish root {}: {}", final_link.display(), e)
        })?;
        Ok(root_name)
    }

    /// The store entry an indirect root's link names, or `None` once the
    /// link is gone or names no realized entry.
    pub(super) fn indirect_root_target(&self, root_target: &Path) -> Option<String> {
        let link = if root_target.is_absolute() {
            root_target.to_path_buf()
        } else {
            self.state.join("roots").join(root_target)
        };
        let rel = root_target.strip_prefix("../run").ok()?;
        if rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return None;
        }
        let entry = std::fs::read_link(&link).ok()?;
        let name = entry.file_name()?.to_string_lossy().into_owned();
        self.has_named(&name).then_some(name)
    }

    /// Return normalized, non-dangling persistent roots. Absolute legacy
    /// targets are migrated to relative links; dangling roots are pruned.
    pub fn valid_roots_for_gc(
        &self,
        dry_run: bool,
        prune_older_than_days: Option<u64>,
    ) -> Result<BTreeMap<String, String>, String> {
        self.collect_valid_roots(dry_run, prune_older_than_days)
    }

    /// Atomically converge every `latest-*` root to `desired`, preserving
    /// non-latest administrative roots.
    pub fn sync_latest_roots(&self, desired: &BTreeMap<String, String>) -> Result<(), String> {
        let roots = self.state.join("roots");
        for entry in std::fs::read_dir(&roots).map_err(|e| format!("cannot read roots: {e}"))? {
            let entry = entry.map_err(|e| format!("roots entry: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("latest-") && !desired.contains_key(&name) {
                std::fs::remove_file(entry.path())
                    .map_err(|e| format!("cannot remove root {name}: {e}"))?;
            }
        }
        for (root, store_name) in desired {
            if root.starts_with("latest-") {
                self.add_root(root, store_name)?;
            }
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for entry in
            std::fs::read_dir(&self.root).map_err(|e| format!("cannot read store: {}", e))?
        {
            let entry = entry.map_err(|e| format!("store entry: {}", e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.') && entry.path().is_dir() {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }
}

pub mod derivation;
mod gc;
mod maintain;
mod register;
pub mod remote;
pub mod substitute;

#[cfg(test)]
mod tests;

/// Publish latest roots only for successfully realized plain targets.
pub(crate) fn publish_latest_roots(
    store: &crate::store::Store,
    targets: &[String],
    arch: &str,
    outcome: &crate::exec::RealizeOutcome,
) -> Result<(), String> {
    let failed: std::collections::BTreeSet<&str> = outcome
        .failed
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    for target in targets {
        // A configured node is published under the name it was requested
        // by (`publish_request_roots`); its key is no root name.
        if failed.contains(target.as_str()) || target.contains('@') {
            continue;
        }
        // A build that stopped at its first failure leaves later targets
        // unrealized; only a successful outcome must cover every target.
        let Some(store_name) = outcome.store_names.get(target) else {
            if failed.is_empty() {
                return Err(format!("realization outcome omitted target `{target}`"));
            }
            continue;
        };
        store.add_root(&format!("latest-{target}-{arch}"), store_name)?;
    }
    Ok(())
}
