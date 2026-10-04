//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — single-build driver: stage inputs, exec builder, capture output,
//! register into the store (or, in dev mode, return a live build dir)
//!
//! The whole per-derivation lifecycle lives here. `build_one` is the unit
//! of work the scheduler hands to a worker thread, and it is the only path
//! that may write to a build dir and rename an output into the store. It
//! keeps two distinct entry points — `dev_build` (live-sources, persistent
//! build dir, no registration) and the hermetic `build_one` (tmp dir, store
//! registration) — but the bulk of the staging / exec / capture / register
//! logic is shared.

use super::builder::{BuilderContext, BuilderRegistry};
use super::env::apply_setup_env_hooks;
use super::jobserver::{Jobserver, Lease};
use super::output::BuildOutput;
use super::refscan::{allowed_store_refs, dep_closure, scan_references};
use super::sandbox::{BuildPlan, ExecResult, SandboxExec};
use super::stage::{
    hardlink_or_copy, materialize_source_overlay, stage_source_root, symlink_into,
    symlink_stage_aware,
};
use super::tokens::{expand_tool_versions, resolve_clang_tokens, resolve_exec_tokens, stage_tool};
use crate::eval::graph::Recipe;
use crate::eval::ninja_emit;
use crate::eval::plan::{ExecNode, ExecPlan};
use crate::spec::builders;
use crate::spec::{DrvSpec, RefPolicy};
use crate::store::Store;
use crate::store::derivation::{DepRef, Derivation};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static REQUEST_SDKROOT: OnceLock<Mutex<Option<Option<String>>>> = OnceLock::new();

pub(crate) fn request_sdkroot_slot() -> &'static Mutex<Option<Option<String>>> {
    REQUEST_SDKROOT.get_or_init(|| Mutex::new(None))
}

#[cfg(any(target_os = "linux", test))]
fn extend_path_env(env: &mut [(String, String)], dirs: &[PathBuf]) -> Result<(), String> {
    if dirs.is_empty() {
        return Ok(());
    }
    let path = env
        .iter_mut()
        .rev()
        .find(|(key, _)| key == "PATH")
        .ok_or_else(|| "builder environment has no PATH entry".to_string())?;
    let mut entries: Vec<PathBuf> = std::env::split_paths(&path.1).collect();
    for dir in dirs {
        if !entries.contains(dir) {
            entries.push(dir.clone());
        }
    }
    path.1 = std::env::join_paths(entries)
        .map_err(|e| format!("cannot construct ambient tool PATH: {e}"))?
        .into_string()
        .map_err(|_| "ambient tool PATH is not valid UTF-8".to_string())?;
    Ok(())
}

pub(crate) fn ambient_sdkroot() -> Option<String> {
    if let Some(value) = request_sdkroot_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
    {
        return value;
    }
    if cfg!(target_os = "macos") {
        crate::invocation::command("xcrun")
            .args(["--show-sdk-path"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

fn restore_sdkroot(env: &mut Vec<(String, String)>, sdkroot: Option<String>) {
    if let Some(sdkroot) = sdkroot {
        env.push(("SDKROOT".to_string(), sdkroot));
    }
}

#[cfg(test)]
mod ambient_path_tests {
    use super::{extend_path_env, restore_sdkroot};
    use std::path::PathBuf;

    #[test]
    fn ambient_program_dirs_follow_private_toolbin_on_path() {
        let mut env = vec![("PATH".to_string(), "/build/toolbin".to_string())];
        let dirs = vec![
            PathBuf::from("/usr/lib/gcc/triple/version"),
            PathBuf::from("/usr/bin"),
        ];
        extend_path_env(&mut env, &dirs).unwrap();
        assert_eq!(
            std::env::split_paths(&env[0].1).collect::<Vec<_>>(),
            vec![
                PathBuf::from("/build/toolbin"),
                PathBuf::from("/usr/lib/gcc/triple/version"),
                PathBuf::from("/usr/bin")
            ]
        );
    }

    #[test]
    fn no_ambient_program_dirs_leave_path_unchanged() {
        let mut env = vec![("PATH".to_string(), "/build/toolbin".to_string())];
        extend_path_env(&mut env, &[]).unwrap();
        assert_eq!(env[0].1, "/build/toolbin");
    }

    #[test]
    fn supplied_sdkroot_is_restored_without_an_ambient_probe() {
        let mut env = Vec::new();
        restore_sdkroot(&mut env, Some("/sdk".to_string()));
        restore_sdkroot(&mut env, None);
        assert_eq!(env, vec![("SDKROOT".to_string(), "/sdk".to_string())]);
    }
}

/// Dev-build the tip derivation in a persistent per-target dir against live
/// sources — dependencies must already be realized in the store. Returns the
/// dev output dir; the output never enters the store, is never signed, and
/// never substitutes (it is outside the model by definition). Incrementality
/// comes from the persistent build dir plus the builder's own dirty tracking
/// (ninja / rustc), with no store round-trip.
/// What a dev build produced: its output dir, or a failure already reported
/// through the build events.
pub enum DevOutcome {
    Built(String),
    Failed,
}

pub fn dev_build(
    plan: &ExecPlan,
    store: &Store,
    registry: &BuilderRegistry,
    name: &str,
    dev_dir: &Path,
) -> Result<DevOutcome, String> {
    let _dev_build_lock = lock_dev_build_dir(dev_dir)?;
    // Dev builds run in the same sandbox as store builds: the staged source
    // views are read-only and the persistent dev directory is writable.
    let sandbox = crate::exec::sandbox::platform_sandbox();
    let logger = crate::log::Logger::new(true);
    let recipes = plan.recipes();
    let recipe = recipes
        .get(name)
        .ok_or_else(|| format!("dev: no recipe for `{name}`"))?;
    let node = plan
        .node(name)
        .ok_or_else(|| format!("dev: no execution node for `{name}`"))?;
    let drv = dry_finalize_one(store, plan, &recipes, name, recipe)?;
    let hash = drv.hash()[..12].to_string();
    logger.start_job(name, "Staging", 0, 1);
    let result = build_one(
        plan,
        store,
        sandbox.as_ref(),
        registry,
        None,
        &drv,
        name,
        node,
        super::AuditMode::Warn,
        &logger,
        false,
        Some(dev_dir),
    );
    Ok(match result {
        Ok((out, verdict)) => {
            logger.finish_job(name, "Realized", 1, 1, &hash, verdict.as_deref());
            DevOutcome::Built(out)
        }
        Err(e) => {
            let store_name = drv.store_name();
            let log = store
                .log_path(&store_name)
                .exists()
                .then(|| store.log_name(&store_name));
            logger.fail_job(name, 1, 1, &hash, &e, log.as_deref());
            DevOutcome::Failed
        }
    })
}

fn lock_dev_build_dir(dev_dir: &Path) -> Result<File, String> {
    std::fs::create_dir_all(dev_dir)
        .map_err(|e| format!("cannot create dev dir {}: {}", dev_dir.display(), e))?;
    let path = dev_dir.join(".dev-build.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)
        .map_err(|e| format!("cannot open dev build lock {}: {}", path.display(), e))?;
    crate::platform::lock_exclusive(&file, false)
        .map_err(|e| format!("cannot lock dev build dir {}: {e}", dev_dir.display()))?;
    Ok(file)
}

pub(super) fn exec_spec(node: &ExecNode) -> DrvSpec {
    DrvSpec {
        repository: None,
        name: node.base_name().to_string(),
        builder: node.builder.clone(),
        tool: node.exec.tool.clone(),
        extra_tools: node.exec.extra_tools.clone(),
        when: String::new(),
        bootstrap: false,
        native_frontend: node.is_self_tool(),
        stage: None,
        host_tool: node.exec.host_tool,
        allowed_refs: node.exec.allowed_refs.clone(),
        sources: node.srcs.iter().map(|(_, rel, _)| rel.clone()).collect(),
        src_dirs: node
            .srcdirs
            .iter()
            .chain(node.exec.srcdirs.iter())
            .map(|(rel, _)| rel.clone())
            .collect(),
        source_roots: node
            .source_roots
            .iter()
            .chain(node.exec.source_roots.iter())
            .map(|(rel, _)| rel.clone())
            .collect(),
        source_overlays: node.source_overlays.clone(),
        deps: node.deps.clone(),
        outputs: node.outputs.clone(),
        argv: node.exec.argv.clone(),
        env: node.exec.env.clone(),
        copy: node.exec.copy.clone(),
        stage_deps: node.exec.stage_deps.clone(),
        groups: Vec::new(),
        compiles: node.active_plan.compiles.clone(),
        steps: node.active_plan.steps.clone(),
        module: String::new(),
        module_role: String::new(),
        config_keys: Vec::new(),
    }
}

fn dry_finalize_one(
    store: &Store,
    plan: &ExecPlan,
    recipes: &BTreeMap<String, Recipe>,
    name: &str,
    recipe: &Recipe,
) -> Result<Derivation, String> {
    let in_closure: BTreeSet<&str> = plan.nodes.iter().map(|node| node.name.as_str()).collect();
    let mut deps = Vec::new();
    for dep_name in &recipe.dep_names {
        if !in_closure.contains(dep_name.as_str()) {
            continue;
        }
        let dep_recipe = recipes
            .get(dep_name)
            .ok_or_else(|| format!("`{name}` references missing dep `{dep_name}`"))?;
        let dep_drv = dry_finalize_one(store, plan, recipes, dep_name, dep_recipe)?;
        let store_name = dep_drv.store_name();
        let digest = store
            .digest_of(&store_name)
            .map_err(|_| format!("dev: dependency `{dep_name}` is not realized"))?;
        deps.push(DepRef {
            name: dep_name.clone(),
            digest,
            store_name,
        });
    }
    Ok(recipe.finalize(deps))
}

/// Move what the builder wrote to its artifact directory beside the build
/// log. An empty directory leaves nothing behind.
fn retain_artifacts(written: &Path, retained: &Path) -> Result<(), String> {
    let empty = std::fs::read_dir(written)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(true);
    if empty {
        return Ok(());
    }
    let _ = std::fs::remove_dir_all(retained);
    if std::fs::rename(written, retained).is_ok() {
        return Ok(());
    }
    // A build directory on another filesystem than the logs.
    copy_tree(written, retained)
        .map_err(|e| format!("cannot retain artifacts in {}: {e}", retained.display()))
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

pub(super) struct BuildDirFailureGuard {
    active: bool,
    keep_failed: bool,
    path: PathBuf,
}

impl BuildDirFailureGuard {
    pub(super) fn new(active: bool, path: PathBuf, keep_failed: bool) -> Self {
        BuildDirFailureGuard {
            active,
            keep_failed,
            path,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for BuildDirFailureGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if self.keep_failed {
            crate::log::info(
                "build",
                &format!("kept the failed build directory {}", self.path.display()),
            );
        } else {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_one(
    plan: &ExecPlan,
    store: &Store,
    sandbox: &dyn SandboxExec,
    registry: &BuilderRegistry,
    jobserver: Option<&Jobserver>,
    drv: &Derivation,
    name: &str,
    node: &ExecNode,
    audit: super::AuditMode,
    logger: &crate::log::Logger,
    keep_failed: bool,
    // Dev mode: run in this persistent dir against live sources, skip the
    // store-hermetic tail (depfile audit, leak scan, registration), and
    // return the output dir path instead of a store digest. `None` is the
    // normal hermetic build, byte-for-byte unchanged.
    dev_dir: Option<&Path>,
) -> Result<(String, Option<String>), String> {
    let dspec = exec_spec(node);
    let store_name = drv.store_name();
    // Process builders on native hosts are restricted to the self-tool class.
    // Source-tree outputs only materialize immutable CAS data and run no tool.
    if !cfg!(target_os = "linux") && !node.is_self_tool() && node.builder != "source-tree" {
        return Err(format!(
            "`{name}` is realized only on a Linux build host; build it through a Linux backend (docker, nerdctl, wsl or remote)"
        ));
    }
    // The self-tool class runs at audit grade on every host: its ambient
    // compiler cannot be held to declared inputs, so no enforcing grade is
    // claimed for it.
    let sandbox: &dyn SandboxExec = if node.is_self_tool() {
        &super::sandbox::AuditSandbox
    } else {
        sandbox
    };
    let build_start = Instant::now();
    // A retained log and artifact directory always belong to the latest
    // attempt: a failure before the builder runs must not point at an
    // earlier attempt's.
    let _ = std::fs::remove_file(store.log_path(&store_name));
    if dev_dir.is_none() {
        let _ = std::fs::remove_dir_all(store.artifacts_path(&store_name));
    }

    let build_dir = match dev_dir {
        Some(d) => d.to_path_buf(),
        None => store.tmp_build_dir(&store_name),
    };
    if dev_dir.is_none() {
        let _ = std::fs::remove_dir_all(&build_dir);
    }
    let mut build_dir_guard =
        BuildDirFailureGuard::new(dev_dir.is_none(), build_dir.clone(), keep_failed);
    let dep_store_names: Vec<String> = drv.deps.iter().map(|dep| dep.store_name.clone()).collect();
    let _input_temp_roots = if dev_dir.is_none() {
        store.add_temp_roots(&format!("{}-inputs", name), &dep_store_names)?
    } else {
        None
    };
    // The build cwd sits INSIDE the stage: staged repo sources resolve as
    // `../<repo-rel>` and staged dep files as plain cwd-relative paths, so
    // the cwd remap keeps every input path out of the produced artifacts.
    let stage = build_dir.join("stage");
    let cwd = stage.join("build");
    let out_dir = build_dir.join("out");
    let home = build_dir.join("home");
    let tmp = build_dir.join("tmp");
    let toolbin = build_dir.join("toolbin");
    let artifacts = build_dir.join(super::tokens::ARTIFACTS_DIR);
    let _ = std::fs::remove_dir_all(&artifacts);
    for dir in [&stage, &cwd, &out_dir, &home, &tmp, &toolbin, &artifacts] {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    }

    // Stage declared inputs at their repo-relative paths.
    for (kind, rel, hash) in &node.srcs {
        let blob = crate::source::blob_path(hash, *kind)?;
        hardlink_or_copy(&blob, &stage.join(rel))?;
    }
    for (rel, dirhash) in &node.srcdirs {
        stage_source_root(&stage, rel, dirhash, &[])?;
    }
    for (rel, dirhash) in &node.exec.srcdirs {
        stage_source_root(&stage, rel, dirhash, &[])?;
    }
    let overlay_dests: Vec<String> = dspec
        .source_overlays
        .iter()
        .map(|(_, dest)| dest.clone())
        .collect();
    // Staging holes remove the on-disk destination, so retain the canonical
    // source-tree shape for validation when the dep overlay is applied below.
    let mut overlay_dest_kinds = BTreeMap::new();
    for (rel, dirhash) in &node.source_roots {
        overlay_dest_kinds.extend(stage_source_root(&stage, rel, dirhash, &overlay_dests)?);
    }
    for (rel, dirhash) in &node.exec.source_roots {
        overlay_dest_kinds.extend(stage_source_root(&stage, rel, dirhash, &overlay_dests)?);
    }

    // Dependency-path virtualization: materialize `stage/dep/<name>` onto
    // each dependency's provider directory (a symlink at audit grade). Every
    // `{dep:NAME}` reference then resolves through this stage root — as
    // `../dep/NAME` in argv, or the host `stage/dep/NAME` for buildutil-internal
    // staging. Audit-grade symlinks can still be exposed by realpath-like
    // tools, so the output scanner remains the authority for leak rejection.
    for dep in &drv.deps {
        symlink_into(
            &store.root.join(&dep.store_name),
            &stage.join("dep").join(&dep.name),
        )?;
    }
    // The dep view covers the TRANSITIVE closure, not just the direct edges:
    // a store tool's wrapper resolves its own runtime through
    // `stage/dep/<name>` (host-stdenv's cc execs the tc clang that way), and
    // that provider sits one edge past the tool's consumer. Same set the
    // enforcing sandbox binds.
    if !drv.deps.is_empty() {
        let direct: BTreeSet<&str> = drv.deps.iter().map(|d| d.name.as_str()).collect();
        for store_name in dep_closure(store, drv)? {
            let Some(name) = super::refscan::store_entry_drv_name(&store_name) else {
                continue;
            };
            if direct.contains(name) {
                continue;
            }
            symlink_into(&store.root.join(&store_name), &stage.join("dep").join(name))?;
        }
    }

    for (src_token, dest_rel) in &dspec.source_overlays {
        let src = resolve_exec_tokens(src_token, &stage, &out_dir, &stage, drv, false)?;
        let dest = stage.join(dest_rel);
        materialize_source_overlay(
            Path::new(&src),
            &dest,
            overlay_dest_kinds.get(dest_rel).copied(),
        )?;
        if !dest.exists() {
            return Err(format!(
                "source-overlay `{}` -> `{}` did not materialize",
                src_token, dest_rel
            ));
        }
    }

    // Stage declared dependency files at their cwd-relative positions.
    for (src_token, dest_rel) in &dspec.stage_deps {
        let src = resolve_exec_tokens(src_token, &stage, &out_dir, &stage, drv, false)?;
        symlink_stage_aware(Path::new(&src), &cwd.join(dest_rel), &stage)?;
    }

    // Private toolbin: PATH contains only the declared tools; helper
    // binaries beside a tool's real prefix stay reachable because the
    // resolved real path is what gets executed. External tools come from the
    // eval-resolved host paths; store tools resolve from their toolchain
    // derivation's provider dir. In-process builders run no subprocess at all
    // and therefore have no runtime tool to stage.
    let builder = registry.resolve(&dspec.builder)?;
    let in_process_builder = builder.is_in_process();
    // Staged tools by name: exactly the declared ones, each at its
    // provider's real path. The enforcing sandbox binds the shell from it.
    #[cfg(target_os = "linux")]
    let mut staged_tools: BTreeMap<String, PathBuf> = BTreeMap::new();
    let tool_path = if in_process_builder {
        PathBuf::new()
    } else {
        let path = stage_tool(&dspec.tool, drv, store, &toolbin)?;
        #[cfg(target_os = "linux")]
        staged_tools.insert(dspec.tool.clone(), path.clone());
        path
    };
    if !in_process_builder {
        for extra in &dspec.extra_tools {
            if extra == &dspec.tool {
                continue;
            }
            let _path = stage_tool(extra, drv, store, &toolbin)?;
            #[cfg(target_os = "linux")]
            staged_tools.insert(extra.clone(), _path);
        }
    }

    // Builder-specific execution shape is selected only through the
    // registered interface. The engine retains the shared staging/sandbox
    // lifecycle; extensions own only their kind-specific hooks.
    let mut extra_env: Vec<(String, String)> = Vec::new();
    // Join the shared job pool: jobserver-aware inner tools (ninja 1.13,
    // make 4.4+) parse MAKEFLAGS and draw from the same FIFO. Parallelism is
    // runtime-only and never enters the derivation identity.
    if let Some(js) = jobserver {
        extra_env.push(("MAKEFLAGS".to_string(), js.makeflags()));
    }
    // A builder's leased slots (if any) live for the whole external run.
    let mut builder_lease: Option<Lease<'_>> = None;
    // `{tool-version:*}` expansions, one version query per tool per build.
    let tool_versions: RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
    let verdict: RefCell<Option<String>> = RefCell::new(None);
    let builder_ctx = BuilderContext {
        dspec: &dspec,
        drv,
        node,
        store,
        name,
        store_name: &store_name,
        build_dir: &build_dir,
        stage: &stage,
        cwd: &cwd,
        out_dir: &out_dir,
        toolbin: &toolbin,
        tool_path: &tool_path,
        tool_versions: &tool_versions,
        target_arch: &plan.arch,
        build_host: &plan.build_host,
        verdict: &verdict,
    };
    let prepared = builder.prepare(&builder_ctx, &mut extra_env)?;
    // Leasing fallback: a builder pinned to `-j$NPROC` may ignore MAKEFLAGS,
    // so bound it to a free share of the pool and pin NPROC to the grant.
    if let (Some(js), Some(max)) = (jobserver, prepared.lease_slots) {
        let lease = js.try_lease(max);
        extra_env.push(("NPROC".to_string(), (lease.len() + 1).to_string()));
        builder_lease = Some(lease);
    }
    let argv = prepared.argv;

    // script-dag: emit the inner build.ninja into the cwd; the declared
    // ninja tool runs it with full parallelism.
    if !node.active_plan.compiles.is_empty() || !node.active_plan.steps.is_empty() {
        let resolve = |s: &str| {
            expand_tool_versions(
                resolve_clang_tokens(
                    resolve_exec_tokens(
                        s,
                        Path::new(".."),
                        Path::new("../../out"),
                        &stage,
                        drv,
                        true,
                    )?,
                    &toolbin,
                )?,
                &toolbin,
                &node.exec.version_flags,
                &tool_versions,
            )
        };
        let ninja_text = ninja_emit::emit(&node.active_plan, &resolve)?;
        std::fs::write(cwd.join("build.ninja"), ninja_text)
            .map_err(|e| format!("cannot write inner build.ninja: {}", e))?;
    }

    let mut env = Vec::new();
    apply_setup_env_hooks(&mut env, drv, &stage)?;
    env.extend(drv.env.clone());
    env.extend(extra_env);
    // A self-tool links against the client's platform SDK; the scrubbed
    // environment drops SDKROOT, so restore the ambient value for it alone.
    if node.is_self_tool() {
        restore_sdkroot(&mut env, ambient_sdkroot());
    }
    env.push(("HOME".to_string(), home.to_string_lossy().into_owned()));
    env.push(("TMPDIR".to_string(), tmp.to_string_lossy().into_owned()));
    // Relative to the builder's working directory, so the same value names
    // the directory at every grade; a construction detail, never identity.
    env.push((
        "BUILDUTIL_ARTIFACTS".to_string(),
        format!("../../{}", super::tokens::ARTIFACTS_DIR),
    ));
    env.push(("PATH".to_string(), toolbin.to_string_lossy().into_owned()));
    // A self-tool's ambient C compiler may find its linker and assembler
    // through PATH; no other derivation names an ambient tool.
    #[cfg(target_os = "linux")]
    {
        let ambient_tools = super::tokens::ambient_tools(drv)?;
        if !ambient_tools.is_empty() {
            if !node.is_self_tool() {
                return Err(format!(
                    "`{name}` names an ambient tool, which only the self-tool class may"
                ));
            }
            extend_path_env(
                &mut env,
                &super::sandbox::ambient_program_dirs(&ambient_tools)?,
            )?;
        }
    }

    // The stage's `/bin/sh` and read-only mounts (the dynamic loader and
    // libc at `/lib`, trust anchors) come from declared providers in the
    // derivation's own closure; nothing else of any provider reaches the
    // build's PATH or root.
    #[cfg(target_os = "linux")]
    let closure_store_names: BTreeSet<String> = if drv.deps.is_empty() {
        BTreeSet::new()
    } else {
        dep_closure(store, drv)?
    };
    #[cfg(target_os = "linux")]
    let shell: Option<PathBuf> = match &node.exec.shell {
        Some(tool) => Some(staged_tools.get(tool).cloned().ok_or_else(|| {
            format!("`{name}`: shell tool `{tool}` is not among its staged tools")
        })?),
        None => None,
    };
    #[cfg(target_os = "linux")]
    let mounts: Vec<(PathBuf, PathBuf)> = {
        let mut out = Vec::new();
        for (target, dep_key, rel) in &node.exec.mounts {
            let dep = drv
                .deps
                .iter()
                .find(|dep| dep.name == *dep_key)
                .ok_or_else(|| {
                    format!(
                        "`{name}`: mount `{target}` names `{dep_key}`, which is not a dependency"
                    )
                })?;
            let source = store.root.join(&dep.store_name).join(rel);
            if !source.is_dir() {
                return Err(format!(
                    "`{name}`: mount `{target}` source {} is not a directory",
                    source.display()
                ));
            }
            out.push((PathBuf::from(target), source));
        }
        out
    };
    // `system-features = ["kvm"]` is an allowance: the device is passed only
    // where this worker can open it, and the builder decides acceleration.
    #[cfg(target_os = "linux")]
    let devices: Vec<PathBuf> = {
        let kvm = Path::new("/dev/kvm");
        let declared = node.exec.env.iter().any(|(key, value)| {
            key == crate::spec::SYSTEM_FEATURES_ENV && value.split(',').any(|f| f == "kvm")
        });
        let granted = declared
            && std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(kvm)
                .is_ok();
        if granted {
            vec![kvm.to_path_buf()]
        } else {
            Vec::new()
        }
    };
    // A dev build's staged source views are read-only inside the sandbox;
    // only the rest of the persistent dev directory is writable.
    #[cfg(target_os = "linux")]
    let readonly: Vec<PathBuf> = if dev_dir.is_some() {
        let mut views: Vec<PathBuf> = node
            .srcs
            .iter()
            .map(|(_, rel, _)| stage.join(rel))
            .chain(node.srcdirs.iter().map(|(rel, _)| stage.join(rel)))
            .chain(node.source_roots.iter().map(|(rel, _)| stage.join(rel)))
            .chain(node.exec.srcdirs.iter().map(|(rel, _)| stage.join(rel)))
            .chain(
                node.exec
                    .source_roots
                    .iter()
                    .map(|(rel, _)| stage.join(rel)),
            )
            .filter(|path| path.exists())
            .collect();
        views.sort();
        views.dedup();
        views
    } else {
        Vec::new()
    };

    logger.step(name, builder.action(&dspec.builder));
    if builder.is_in_process() {
        builder.realize_in_process(&builder_ctx)?;
    } else {
        let emit = |framed: super::output::Framed<'_>| match framed {
            super::output::Framed::Line(line, stream) => logger.output(name, line, stream.as_str()),
            super::output::Framed::Item(counter, text) => logger.item(name, counter, text),
        };
        let output = BuildOutput::new(&emit);
        let output_sink =
            |stream: super::sandbox::OutputStream, chunk: &[u8]| output.ingest(stream, chunk);
        let result = {
            // The enforcing sandbox interface is Linux-only; the audit
            // sandbox needs just argv/env/cwd.
            #[cfg(target_os = "linux")]
            let plan = {
                // The enforcing read set: the transitive dependency-provider
                // closure, which holds every tool behind the private toolbin
                // — at namespace grade the only host paths bound into the
                // build. Transitive, so a store tool's own runtime providers
                // are visible wherever the tool runs.
                let allowed_read: Vec<PathBuf> = closure_store_names
                    .iter()
                    .map(|sn| store.root.join(sn))
                    .collect();
                BuildPlan {
                    argv,
                    env,
                    cwd: cwd.clone(),
                    stage_root: stage.clone(),
                    allowed_read,
                    // Network belongs to fixed-output derivations, whose
                    // declared pin decides what they may produce.
                    net: if crate::spec::builders::is_fixed_output(&dspec.builder) {
                        super::sandbox::NetPolicy::Allow
                    } else {
                        super::sandbox::NetPolicy::Deny
                    },
                    jobserver_fifo: jobserver.map(|js| js.fifo_path().to_path_buf()),
                    shell,
                    mounts,
                    readonly,
                    devices,
                }
            };
            #[cfg(not(target_os = "linux"))]
            let plan = BuildPlan {
                argv,
                env,
                cwd: cwd.clone(),
            };
            let result = sandbox.run(&plan, Some(&output_sink));
            output.finish();
            result?
        };
        // The build subprocess is done; return any leased pool tokens now.
        drop(builder_lease);
        // The retained log is for reading and searching, so escape
        // sequences the tools wrote for a terminal are removed.
        let log_path = store.log_path(&store_name);
        let _ = std::fs::write(&log_path, crate::term::strip_escapes(result.log.as_bytes()));
        if dev_dir.is_none() {
            retain_artifacts(&artifacts, &store.artifacts_path(&store_name))?;
        }
        if !result.status.success() {
            // The output already streamed as build events and the caller
            // names the retained log; the reason is the status, or what
            // the builder reports it means.
            return Err(builder.failure_reason(&builder_ctx, &result.status.to_string()));
        }
    }

    builder.post_process(&builder_ctx)?;

    // Declared post-builder copies (e.g. the sibling include next to a
    // generated source).
    for (src_token, dest_rel) in &dspec.copy {
        let src = resolve_exec_tokens(src_token, &stage, &out_dir, &stage, drv, false)?;
        std::fs::copy(&src, out_dir.join(dest_rel))
            .map_err(|e| format!("cannot copy {} -> {}: {}", src, dest_rel, e))?;
    }

    // Depfile audit: reads recorded by the compilers must fall inside the
    // declared universe (stage, dep stores, toolchain trees, build dir).
    // Skipped in dev mode, where live sources are read by paths outside any
    // declared set by design.
    if dev_dir.is_none() {
        let allowed: Vec<PathBuf> = vec![build_dir.clone(), store.root.clone()];
        let violations = crate::exec::depinfo::audit(&build_dir, &allowed);
        if !violations.is_empty() {
            let listed = violations.join("\n  ");
            // Hard error at enforcing grades (namespace/caps) or when the CLI
            // forces it; warn at audit grade (macOS), where reads are only
            // audited post-hoc.
            if audit == super::AuditMode::Error || sandbox.grade() != "audit" {
                return Err(format!("`{}` read undeclared inputs:\n  {}", name, listed));
            }
            logger.warn(
                "build",
                &format!("`{}` read undeclared inputs:\n  {}", name, listed),
            );
        }
    }

    // Builder-specific output post-conditions.
    builders::check_outputs(&dspec, &out_dir)?;

    // Every declared output must exist; any undeclared file is a hard
    // error. A trailing slash declares a directory output whose whole tree
    // is the product (tree-manifest hashed at registration).
    let declared: BTreeSet<&str> = drv
        .outputs
        .iter()
        .map(|s| s.trim_end_matches('/'))
        .collect();
    for output in &drv.outputs {
        if let Some(dir) = output.strip_suffix('/') {
            if !out_dir.join(dir).is_dir() {
                return Err(format!(
                    "`{}` did not produce declared output directory `{}`",
                    name, output
                ));
            }
        } else if !out_dir.join(output).is_file() {
            return Err(format!(
                "`{}` did not produce declared output `{}`",
                name, output
            ));
        }
    }
    let mut undeclared = Vec::new();
    for entry in std::fs::read_dir(&out_dir).map_err(|e| format!("read out dir: {}", e))? {
        let entry = entry.map_err(|e| format!("out dir entry: {}", e))?;
        let fname = entry.file_name().to_string_lossy().into_owned();
        if !declared.contains(fname.as_str()) {
            undeclared.push(fname);
        }
    }
    if !undeclared.is_empty() {
        return Err(format!(
            "`{}` produced undeclared outputs: {}",
            name,
            undeclared.join(", ")
        ));
    }

    // Dev mode stops here: outputs live in the persistent dev dir, never
    // enter the store, are never signed, and never substitute. Return the
    // output dir so `buildutil run --dev` can consume it.
    if dev_dir.is_some() {
        return Ok((out_dir.display().to_string(), verdict.take()));
    }

    // Reference scan: the per-run build dir is a real host path unique to this
    // realization; it is non-reproducible and must never appear in a realized
    // output. The sandbox-constant `/build` (holding the private
    // HOME/TMPDIR/toolbin and the `/build/stage/dep/` staged views) is NOT such
    // a leak — it is the reproducible remap target, byte-identical across runs
    // and machines, so a build tool that only ever executes inside a sandbox
    // (a compiler wrapper that must name its staged sysroot, say) may embed it.
    // A store reference is legal only when the derivation declares it through
    // its allowed-reference policy. The default policy must carry none. A
    // violation is a hard error at enforcing grades (namespace/caps) and a
    // warning at audit grade, where dependency-path virtualization has not
    // yet scrubbed every reference. No exemption list.
    let closure = dep_closure(store, drv)?;
    let legal = allowed_store_refs(&dspec.allowed_refs, &closure);
    let build_needles = [build_dir.clone()];
    let (violations, references) = scan_references(
        &out_dir,
        &store.root,
        &build_needles,
        &legal,
        !matches!(dspec.allowed_refs, RefPolicy::None),
    );
    if !violations.is_empty() {
        let listed = violations.join("\n  ");
        if sandbox.grade() == "audit" {
            logger.warn(
                "build",
                &format!(
                    "`{}` embeds build-private or undeclared store references in outputs:\n  {}",
                    name, listed
                ),
            );
        } else {
            return Err(format!(
                "`{}` embeds build-private or undeclared store references in outputs:\n  {}",
                name, listed
            ));
        }
    }

    store.write_drv(drv)?;
    let mut extra_meta = Vec::new();
    builder.append_metadata(&builder_ctx, &mut extra_meta)?;
    // The scan-recorded runtime reference set: what these bytes point at in
    // the store, kept alive by GC directly (in union with the ref: edges).
    for reference in &references {
        extra_meta.push(format!("reference: {}", reference));
    }
    if node.is_self_tool() {
        extra_meta.push("self-tool: true".to_string());
    }
    extra_meta.push(format!("wall: {:.3}", build_start.elapsed().as_secs_f64()));
    let digest = store.register(drv, &out_dir, sandbox.grade(), &extra_meta)?;
    build_dir_guard.disarm();
    let _ = std::fs::remove_dir_all(&build_dir);
    Ok((digest, verdict.take()))
}
