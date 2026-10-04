//! SPDX-License-Identifier: GPL-2.0-only
//! Whole-evaluation cache keyed by the fully resolved stage-1 input set.
#![allow(dead_code)] // minibuildutil shares this module but does not use the cache.

use super::graph::{self, EvalPhase, EvalProgress, Evaluated, ResolvedSources};
use super::plan::{self, ExecPlan};
use crate::events::EvalCacheState;
use crate::spec::Spec;
use crate::spec::configres::Config;
use crate::tools::Toolchain;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const EVALCACHE_FORMAT: u32 = 3;

pub(crate) struct CachedPlan {
    pub evaluated: Evaluated,
    pub path: PathBuf,
    pub hash: String,
    pub plan: ExecPlan,
    pub state: EvalCacheState,
    pub emit_ms: u128,
}

pub(crate) fn evaluate_plan_with_progress(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    targets: &[String],
    state_root: &Path,
    enabled: bool,
    git_state: (String, String),
    mut progress: impl FnMut(EvalProgress) + Send,
) -> Result<CachedPlan, String> {
    let memo_scope = crate::source::EvaluationMemoScope::new();
    evaluate_plan_with_progress_scoped(
        spec,
        config,
        toolchain,
        targets,
        state_root,
        enabled,
        git_state,
        &memo_scope,
        &mut progress,
    )
}

/// Evaluate under a request-owned source memo scope. The scope must cover any
/// subsequent [`evaluation_snapshot_still_current`] call so its re-read uses
/// only this request's source and repository observations.
pub(crate) fn evaluate_plan_with_progress_scoped<F>(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    targets: &[String],
    state_root: &Path,
    enabled: bool,
    git_state: (String, String),
    _memo_scope: &crate::source::EvaluationMemoScope,
    progress: &mut F,
) -> Result<CachedPlan, String>
where
    F: FnMut(EvalProgress) + Send,
{
    let cancel = graph::CancellationToken::never();
    let prepared =
        graph::prepare_with_progress(spec, config, targets, git_state, &cancel, progress)?;
    let key = eval_key(
        spec,
        config,
        targets,
        &prepared.graph.config_digests(),
        &prepared.resolved_sources,
        &prepared.git_state,
    )?;
    let entry = entry_path(state_root, &key);
    if enabled {
        if let Some((path, hash, plan)) = load_hit(state_root, &entry, &prepared.resolved_sources) {
            let evaluated = Evaluated::from_cached_plan(
                &prepared.graph,
                &plan,
                prepared.resolved_sources.clone(),
            );
            progress(EvalProgress {
                current: evaluated.order.len(),
                total: evaluated.order.len(),
                phase: EvalPhase::Evaluated,
                detail: String::new(),
                item: None,
                label: None,
            });
            return Ok(CachedPlan {
                evaluated,
                path,
                hash,
                plan,
                state: EvalCacheState::Hit,
                emit_ms: 0,
            });
        }
    }

    let evaluated = graph::instantiate_prepared(spec, config, toolchain, prepared, progress)?;
    let t_emit = std::time::Instant::now();
    let (path, hash, plan) = plan::emit(spec, &evaluated, state_root, &evaluated.git_state)?;
    let emit_ms = t_emit.elapsed().as_millis();
    if enabled {
        write_entry(&entry, &hash)?;
    }
    Ok(CachedPlan {
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
    })
}

/// Re-read every Stage-1 input after Stage-2 completes.  Per-file double-stat
/// prevents torn reads, while this end generation check prevents a coherent
/// but mixed-time snapshot (an early file changing after it was hashed).
/// Callers must discard the context and re-open the spec before retrying.
pub(crate) fn evaluation_snapshot_still_current(
    spec: &Spec,
    resolved: &ResolvedSources,
) -> Result<bool, String> {
    evaluation_snapshot_still_current_with_cancel(
        spec,
        resolved,
        &graph::CancellationToken::never(),
    )
}

pub(crate) fn evaluation_snapshot_still_current_with_cancel(
    spec: &Spec,
    resolved: &ResolvedSources,
    cancel: &graph::CancellationToken,
) -> Result<bool, String> {
    if cancel.is_cancelled() {
        return Err("evaluation cancelled".to_string());
    }
    let mut work =
        Vec::with_capacity(spec.spec_inputs.len() + resolved.blobs.len() + resolved.trees.len());
    for input in &spec.spec_inputs {
        work.push(SnapshotWork::Spec(input.clone()));
    }
    for (rel, (expected_hash, expected_kind)) in &resolved.blobs {
        work.push(SnapshotWork::Blob {
            rel: rel.clone(),
            expected_hash: expected_hash.clone(),
            expected_kind: *expected_kind,
        });
    }
    for (rel, expected_hash) in &resolved.trees {
        work.push(SnapshotWork::Tree {
            rel: rel.clone(),
            expected_hash: expected_hash.clone(),
        });
    }

    let work = Arc::new(work);
    let next = AtomicUsize::new(0);
    let results = Mutex::new(
        std::iter::repeat_with(|| None)
            .take(work.len())
            .collect::<Vec<Option<Result<bool, String>>>>(),
    );
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(4)
        .max(1);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let work = Arc::clone(&work);
            let next = &next;
            let results = &results;
            let cancel = cancel.clone();
            scope.spawn(move || {
                loop {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = work.get(idx) else {
                        break;
                    };
                    results.lock().expect("snapshot result lock")[idx] =
                        Some(item.still_current(spec));
                }
            });
        }
    });
    if cancel.is_cancelled() {
        return Err("evaluation cancelled".to_string());
    }
    for result in results.into_inner().expect("snapshot result lock") {
        if !result.expect("snapshot worker result")? {
            return Ok(false);
        }
    }
    Ok(true)
}

enum SnapshotWork {
    Spec(crate::spec::SpecInput),
    Blob {
        rel: String,
        expected_hash: String,
        expected_kind: char,
    },
    Tree {
        rel: String,
        expected_hash: String,
    },
}

impl SnapshotWork {
    fn still_current(&self, spec: &Spec) -> Result<bool, String> {
        match self {
            SnapshotWork::Spec(input) => {
                Ok(crate::spec::hash_spec_input(&spec.repo_root, input)? == input.hash.as_str())
            }
            SnapshotWork::Blob {
                rel,
                expected_hash,
                expected_kind,
            } => {
                let (actual_hash, actual_kind) =
                    crate::source::hash_and_ingest_file(&spec.source_path(rel)?)?;
                Ok(actual_hash == expected_hash.as_str() && actual_kind == *expected_kind)
            }
            SnapshotWork::Tree { rel, expected_hash } => {
                let actual = if rel.starts_with("overlay-root:") {
                    crate::source::empty_tree()?
                } else if let Some((owner, relative)) = spec.source_repository(rel) {
                    crate::source::input_subtree(&owner.content, relative)?
                } else {
                    let path = spec.source_path(rel)?;
                    let holes = crate::inputs::validate_source(&spec.repo_root, rel)?;
                    if holes.is_empty() {
                        crate::source::recheck_and_ingest_dir(&path)?
                    } else {
                        crate::source::ingest_owned_subtree(&path, &holes)?
                    }
                };
                Ok(actual == expected_hash.as_str())
            }
        }
    }
}

pub(crate) fn eval_key(
    spec: &Spec,
    config: &Config,
    targets: &[String],
    config_digests: &std::collections::BTreeMap<String, String>,
    resolved: &ResolvedSources,
    git_state: &(String, String),
) -> Result<String, String> {
    let mut text = String::new();
    writeln!(&mut text, "buildutil-eval-key").expect("write string");
    writeln!(&mut text, "evalcache-format: {EVALCACHE_FORMAT}").expect("write string");
    writeln!(
        &mut text,
        "preimage-format: {}",
        crate::store::derivation::PREIMAGE_FORMAT
    )
    .expect("write string");
    writeln!(&mut text, "plan-format: {}", plan::PLAN_FORMAT).expect("write string");
    writeln!(&mut text, "arch: {}", spec.arch).expect("write string");
    writeln!(&mut text, "build-host: {}", spec.build_host).expect("write string");
    for target in targets {
        writeln!(&mut text, "target: {target}").expect("write string");
    }
    for input in &spec.spec_inputs {
        writeln!(&mut text, "spec: {}=sha256:{}", input.path, input.hash).expect("write string");
    }
    for (name, value) in &config.values {
        writeln!(&mut text, "config: {name}={value}").expect("write string");
    }
    // A configured node's configuration comes from a separate resolution;
    // its values, not only its override set, decide the plan.
    for (key, digest) in config_digests {
        writeln!(&mut text, "configured: {key}=sha256:{digest}").expect("write string");
    }
    let ignore_hash = crate::source::filehash::hash_file(&spec.repo_root.join(".buildutilignore"))?;
    writeln!(&mut text, "buildutilignore: sha256:{ignore_hash}").expect("write string");
    writeln!(&mut text, "git-rev: {}", git_state.0).expect("write string");
    writeln!(&mut text, "git-dirty: {}", git_state.1).expect("write string");

    let mut bootstrap = String::new();
    for rel in plan::bootstrap::bootstrap_paths(&spec.repo_root)? {
        let (hash, kind) = resolved.blob(&rel)?;
        writeln!(&mut bootstrap, "{kind} {rel} sha256:{hash}").expect("write string");
    }
    writeln!(
        &mut text,
        "bootstrap-set: sha256:{}",
        crate::crypto::sha256::hash_bytes(bootstrap.as_bytes())
    )
    .expect("write string");
    for (path, id) in resolved.mappings() {
        writeln!(&mut text, "source: {path}={id}").expect("write string");
    }
    Ok(crate::crypto::sha256::hash_bytes(text.as_bytes())[..32].to_string())
}

pub(crate) fn entry_path(state_root: &Path, key: &str) -> PathBuf {
    crate::state::cache_dir(state_root)
        .join("evalcache")
        .join(key)
}

pub(crate) fn load_hit(
    state_root: &Path,
    entry: &Path,
    resolved: &ResolvedSources,
) -> Option<(PathBuf, String, ExecPlan)> {
    let text = std::fs::read_to_string(entry).ok()?;
    let mut lines = text.lines();
    let valid_header =
        lines.next() == Some("buildutil-eval-cache") && lines.next() == Some("format: 1");
    let hash = lines
        .next()
        .and_then(|line| line.strip_prefix("plan: "))
        .filter(|hash| hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string);
    let Some(hash) = hash.filter(|_| valid_header && lines.next().is_none()) else {
        let _ = std::fs::remove_file(entry);
        return None;
    };
    let path = crate::state::plans_dir(state_root).join(format!("{hash}.plan"));
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = std::fs::remove_file(entry);
            return None;
        }
    };
    if crate::crypto::sha256::hash_bytes(&bytes)[..32] != hash {
        let _ = std::fs::remove_file(entry);
        return None;
    }
    let plan = match plan::load(&path) {
        Ok(plan) => plan,
        Err(_) => {
            let _ = std::fs::remove_file(entry);
            return None;
        }
    };
    if !plan_sources_are_resolved(&plan, resolved) {
        let _ = std::fs::remove_file(entry);
        return None;
    }
    Some((path, hash, plan))
}

fn plan_sources_are_resolved(plan: &ExecPlan, resolved: &ResolvedSources) -> bool {
    let blobs: BTreeSet<(&str, char)> = resolved
        .blobs
        .values()
        .map(|(hash, kind)| (hash.as_str(), *kind))
        .collect();
    let trees: BTreeSet<&str> = resolved.trees.values().map(String::as_str).collect();
    plan.bootstrap
        .iter()
        .all(|entry| blobs.contains(&(entry.hash.as_str(), entry.kind)))
        && plan.nodes.iter().all(|node| {
            node.srcs
                .iter()
                .all(|(kind, _, hash)| blobs.contains(&(hash.as_str(), *kind)))
                && node
                    .srcdirs
                    .iter()
                    .chain(node.source_roots.iter())
                    .chain(node.exec.srcdirs.iter())
                    .chain(node.exec.source_roots.iter())
                    .all(|(_, hash)| trees.contains(hash.as_str()))
        })
}

pub(crate) fn write_entry(path: &Path, plan_hash: &str) -> Result<(), String> {
    let dir = path.parent().ok_or("eval cache entry has no parent")?;
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("cannot create eval cache {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.{}.tmp", plan_hash, std::process::id()));
    let text = format!("buildutil-eval-cache\nformat: 1\nplan: {plan_hash}\n");
    std::fs::write(&tmp, text)
        .map_err(|e| format!("cannot write eval cache {}: {e}", tmp.display()))?;
    if path.is_file() {
        std::fs::remove_file(path)
            .map_err(|e| format!("cannot replace eval cache {}: {e}", path.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("cannot publish eval cache {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn target_order_is_part_of_eval_key() {
        let root = std::env::temp_dir().join(format!("buildutil-eval-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tools/buildutil")).unwrap();
        std::fs::create_dir_all(root.join("tools/buildutil/lib/mica")).unwrap();
        std::fs::create_dir_all(root.join("tools/buildutil/compose")).unwrap();
        std::fs::write(root.join(".buildutilignore"), b"").unwrap();
        std::fs::write(root.join("buildutil"), b"").unwrap();
        std::fs::write(root.join("buildutil.toml"), b"").unwrap();
        std::fs::write(root.join(crate::paths::BOOTSTRAP_NINJA), b"").unwrap();
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
        let mut resolved = ResolvedSources::default();
        for rel in plan::bootstrap::bootstrap_paths(&root).unwrap() {
            resolved.blobs.insert(rel, ("0".repeat(64), 'f'));
        }
        let config = Config::from_values(BTreeMap::new());
        let git = ("unknown".into(), "false".into());
        let ab = eval_key(
            &spec,
            &config,
            &["a".into(), "b".into()],
            &Default::default(),
            &resolved,
            &git,
        )
        .unwrap();
        let ba = eval_key(
            &spec,
            &config,
            &["b".into(), "a".into()],
            &Default::default(),
            &resolved,
            &git,
        )
        .unwrap();
        assert_ne!(ab, ba);
        // Golden value pinned to the current eval-key preimage (format
        // versions, the bootstrap path set, and this fixture's inputs). No
        // environment-dependent input feeds this key: `spec.repo_root` only
        // selects which files get content-hashed (`.buildutilignore`, here
        // empty), never contributing its own path bytes, and
        // `bootstrap_paths` returns the same fixed relative-path list on any
        // host. Recompute and update this literal if the preimage changes.
        assert_eq!(ab, "7fc5a425004167c4f6e43fd3705ae769");
        let _ = std::fs::remove_dir_all(root);
    }

    fn empty_plan() -> ExecPlan {
        ExecPlan {
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            filter_hash: "1".repeat(64),
            git_rev: "unknown".into(),
            git_dirty: "false".into(),
            targets: Vec::new(),
            bootstrap: Vec::new(),
            nodes: Vec::new(),
        }
    }

    #[test]
    fn corrupt_or_missing_plan_downgrades_hit_to_miss() {
        let state = std::env::temp_dir().join(format!("buildutil-eval-hit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        let plan = empty_plan();
        let text = plan::render(&plan).unwrap();
        let hash = crate::crypto::sha256::hash_bytes(text.as_bytes())[..32].to_string();
        let plan_path = crate::state::plans_dir(&state).join(format!("{hash}.plan"));
        std::fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
        std::fs::write(&plan_path, &text).unwrap();
        let entry = entry_path(&state, &"2".repeat(32));
        write_entry(&entry, &hash).unwrap();
        assert!(load_hit(&state, &entry, &ResolvedSources::default()).is_some());

        std::fs::write(&plan_path, format!("{text}corrupt\n")).unwrap();
        assert!(load_hit(&state, &entry, &ResolvedSources::default()).is_none());
        assert!(!entry.exists());

        write_entry(&entry, &hash).unwrap();
        std::fs::remove_file(&plan_path).unwrap();
        assert!(load_hit(&state, &entry, &ResolvedSources::default()).is_none());
        assert!(!entry.exists());
        let _ = std::fs::remove_dir_all(state);
    }

    #[test]
    fn plan_source_cross_check_requires_stage_one_presence() {
        let mut plan = empty_plan();
        plan.bootstrap.push(plan::BootstrapEntry {
            kind: 'f',
            rel: "buildutil".into(),
            hash: "3".repeat(64),
        });
        assert!(!plan_sources_are_resolved(
            &plan,
            &ResolvedSources::default()
        ));
        let mut resolved = ResolvedSources::default();
        resolved
            .blobs
            .insert("buildutil".into(), ("3".repeat(64), 'f'));
        assert!(plan_sources_are_resolved(&plan, &resolved));
    }

    #[test]
    fn plan_source_cross_check_indexes_hashes_across_plan_sections() {
        let blob_hash = "4".repeat(64);
        let tree_hash = "5".repeat(64);
        let mut plan = empty_plan();
        plan.bootstrap.push(plan::BootstrapEntry {
            kind: 'f',
            rel: "buildutil".into(),
            hash: blob_hash.clone(),
        });
        plan.nodes.push(plan::ExecNode {
            name: "demo".into(),
            arch: "x86_64".into(),
            builder: "script-dag".into(),
            tools: Vec::new(),
            env: Vec::new(),
            srcs: vec![('f', "src/input".into(), blob_hash.clone())],
            srcdirs: vec![("src".into(), tree_hash.clone())],
            source_roots: vec![("root".into(), tree_hash.clone())],
            source_overlays: Vec::new(),
            deps: Vec::new(),
            config: Vec::new(),
            module_config: None,
            argv: Vec::new(),
            plan: Vec::new(),
            outputs: Vec::new(),
            exec: plan::ExecMeta {
                tool: "sh".into(),
                extra_tools: Vec::new(),
                env: Vec::new(),
                srcdirs: vec![("exec-src".into(), tree_hash.clone())],
                source_roots: vec![("exec-root".into(), tree_hash.clone())],
                argv: Vec::new(),
                stage_deps: Vec::new(),
                copy: Vec::new(),
                host_tool: false,
                allowed_refs: crate::spec::RefPolicy::None,
                shell: None,
                mounts: Vec::new(),
                version_flags: Vec::new(),
                substituter: None,
                module_config_text: String::new(),
            },
            active_plan: crate::spec::ActivePlan {
                compiles: Vec::new(),
                steps: Vec::new(),
            },
        });

        let mut resolved = ResolvedSources::default();
        resolved
            .blobs
            .insert("stage-one-other-path".into(), (blob_hash, 'f'));
        resolved
            .trees
            .insert("stage-one-other-tree".into(), tree_hash);
        assert!(plan_sources_are_resolved(&plan, &resolved));

        plan.nodes[0].srcs[0].0 = 'x';
        assert!(!plan_sources_are_resolved(&plan, &resolved));
    }

    #[test]
    fn evaluation_generation_check_detects_mid_eval_source_change() {
        let _guard = crate::source::cas_test_guard();
        let base =
            std::env::temp_dir().join(format!("buildutil-eval-generation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("repo");
        let state = base.join("state");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("buildutil.toml"), b"spec-v1\n").unwrap();
        std::fs::write(repo.join("input.rs"), b"source-v1\n").unwrap();
        crate::source::activate(&state).unwrap();
        let (source_hash, source_kind) =
            crate::source::hash_and_ingest_file(&repo.join("input.rs")).unwrap();
        let spec_hash = crate::source::filehash::hash_file(&repo.join("buildutil.toml")).unwrap();
        let spec = Spec {
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
            spec_inputs: vec![crate::spec::SpecInput {
                path: "buildutil.toml".into(),
                hash: spec_hash,
                kind: crate::spec::SpecInputKind::File,
            }],
        };
        let mut resolved = ResolvedSources::default();
        resolved
            .blobs
            .insert("input.rs".into(), (source_hash, source_kind));
        assert!(evaluation_snapshot_still_current(&spec, &resolved).unwrap());

        std::fs::write(repo.join("input.rs"), b"source-v2\n").unwrap();
        assert!(!evaluation_snapshot_still_current(&spec, &resolved).unwrap());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn evaluation_generation_check_rechecks_memoized_directories() {
        let _guard = crate::source::cas_test_guard();
        let base = std::env::temp_dir().join(format!(
            "buildutil-eval-directory-generation-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("repo");
        let state = base.join("state");
        std::fs::create_dir_all(repo.join("tree")).unwrap();
        std::fs::write(repo.join("tree/input"), b"source-v1\n").unwrap();
        crate::source::activate(&state).unwrap();
        let _memo_scope = crate::source::EvaluationMemoScope::new();
        let tree_hash = crate::source::hash_and_ingest_dir(&repo.join("tree")).unwrap();
        let spec = Spec {
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
            spec_inputs: Vec::new(),
        };
        let mut resolved = ResolvedSources::default();
        resolved.trees.insert("tree".into(), tree_hash);

        assert!(evaluation_snapshot_still_current(&spec, &resolved).unwrap());
        std::fs::write(repo.join("tree/input"), b"source-v2\n").unwrap();
        assert!(!evaluation_snapshot_still_current(&spec, &resolved).unwrap());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn required_generated_declarations_are_current_by_their_recorded_hash() {
        let base = std::env::temp_dir().join(format!(
            "buildutil-eval-generated-input-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("buildutil.toml"), b"spec-v1\n").unwrap();
        let generated = crate::spec::SpecInput {
            path: "ports".into(),
            hash: crate::crypto::sha256::hash_bytes(b"[derivation.port-demo]\n"),
            kind: crate::spec::SpecInputKind::Generated,
        };
        let file = crate::spec::SpecInput {
            path: "buildutil.toml".into(),
            hash: crate::source::filehash::hash_file(&repo.join("buildutil.toml")).unwrap(),
            kind: crate::spec::SpecInputKind::File,
        };
        let spec = Spec {
            repo_root: repo.clone(),
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-musl".into(),
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
            spec_inputs: vec![file, generated],
        };
        // A generated input has no checkout form: the generation phase of
        // each evaluation decides it, so a snapshot check never re-reads it.
        assert!(evaluation_snapshot_still_current(&spec, &ResolvedSources::default()).unwrap());
        std::fs::write(repo.join("buildutil.toml"), b"spec-v2\n").unwrap();
        assert!(!evaluation_snapshot_still_current(&spec, &ResolvedSources::default()).unwrap());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn cancelled_snapshot_stops_before_taking_work() {
        let token =
            graph::CancellationToken::from_flag(Arc::new(std::sync::atomic::AtomicBool::new(true)));
        let spec = Spec {
            repo_root: PathBuf::from("/unused"),
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
        assert_eq!(
            evaluation_snapshot_still_current_with_cancel(
                &spec,
                &ResolvedSources::default(),
                &token,
            )
            .unwrap_err(),
            "evaluation cancelled"
        );
    }
}
