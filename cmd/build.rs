// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — build/dev/eval/plan/realize-plan command handlers.

use crate::store::publish_latest_roots;
use std::path::{Path, PathBuf};

use super::report::{BuildHeaderInputs, build_header_report, config_hash, emit_eval_progress};
use super::{
    Args, executor_runtime_flags, flag_present, open_context, positional, repo_root_from_cwd,
};

/// The nodes `buildutil check --rerun` realizes again: the requested checks,
/// which are the plan's targets.
fn rerun_nodes(
    args: &Args,
    plan: &crate::eval::plan::ExecPlan,
) -> std::collections::BTreeSet<String> {
    if args.rerun {
        plan.targets.iter().cloned().collect()
    } else {
        std::collections::BTreeSet::new()
    }
}

pub fn cmd_build(args: &Args) -> Result<i32, String> {
    cmd_build_attempt(args, 0)
}

fn cmd_build_attempt(args: &Args, source_retry: usize) -> Result<i32, String> {
    let requested_backend = crate::host::ExecBackend::resolve(&args.backend)?;
    if requested_backend == crate::host::ExecBackend::Wsl {
        let repo_root = repo_root_from_cwd()?;
        return crate::host::wsl::run_wsl_backend(&repo_root, &args.argv);
    }
    let logger = crate::log::Logger::new(args.verbose);
    let t_context = std::time::Instant::now();
    let mut ctx = open_context(args)?;
    // Evaluation materializes source CAS and plan objects that realization
    // consumes. Hold the shared store lease across that entire check/use span
    // so a concurrent age-based GC cannot remove a warm plan or its sources.
    let store_lease = ctx.store.acquire_shared_lease()?;
    let context_ms = t_context.elapsed().as_millis();
    let targets = super::resolve_targets(&ctx.spec, args, &args.targets)?;

    let t_git_identity = std::time::Instant::now();
    let (rev, dirty) = ctx.git_state().clone();
    let git_identity_ms = t_git_identity.elapsed().as_millis();
    let git_identity = if dirty == "true" {
        format!("{}-dirty", rev)
    } else {
        rev
    };
    let cfg_hash = config_hash(&ctx.config);
    let debug = ctx
        .spec
        .configuration
        .as_ref()
        .and_then(|configuration| configuration.profile_option.as_ref())
        .and_then(|option| ctx.config.values.get(option))
        .is_some_and(|value| value == "true");
    let profile = if debug { "debug" } else { "release" };

    let header_seed = match &args.header_seed {
        Some(path) => Some(crate::events::read_header_seed(path)?),
        None => None,
    };

    let start_time = std::time::Instant::now();
    let eval_git_state = ctx.git_state().clone();
    let memo_scope = crate::source::EvaluationMemoScope::new();
    let cached_eval = crate::cmd::evaluate_plan_with_progress_scoped(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &targets,
        &ctx.state_root,
        !args.no_source_cache,
        eval_git_state,
        &memo_scope,
        |progress| {
            if progress.phase != crate::eval::graph::EvalPhase::Evaluated {
                emit_eval_progress(start_time, progress, None, None);
            }
        },
    )?;
    let t_verify = std::time::Instant::now();
    ctx.inputs.revalidate(false)?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let snapshot_is_current = match crate::daemon::state::with_active_daemon(|state| {
        state.snapshot_still_current(&ctx.spec, &cached_eval.evaluated.resolved_sources)
    }) {
        Some(result) => result?,
        None => crate::eval::cache::evaluation_snapshot_still_current(
            &ctx.spec,
            &cached_eval.evaluated.resolved_sources,
        )?,
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let snapshot_is_current = crate::eval::cache::evaluation_snapshot_still_current(
        &ctx.spec,
        &cached_eval.evaluated.resolved_sources,
    )?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let watcher_quiesce_ms =
        crate::daemon::state::with_active_daemon(|state| state.watcher_snapshot_quiesce_ms())
            .unwrap_or(0);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let watcher_quiesce_ms = 0;
    let verify_ms = t_verify
        .elapsed()
        .as_millis()
        .saturating_sub(watcher_quiesce_ms);
    if !snapshot_is_current {
        if source_retry >= 3 {
            return Err(
                "source tree kept changing during evaluation; refusing a mixed-generation plan"
                    .to_string(),
            );
        }
        logger.info(
            "eval",
            "Source or build specification changed during evaluation; restarting Stage-1/2",
        );
        drop(store_lease);
        return cmd_build_attempt(args, source_retry + 1);
    }
    let eval_total_ms = start_time.elapsed().as_millis();
    let eval_ms = eval_total_ms
        .saturating_sub(cached_eval.emit_ms)
        .saturating_sub(verify_ms);
    let evalcache = cached_eval.state;
    let emit_ms = cached_eval.emit_ms;
    let plan_hash = cached_eval.hash;
    let exec_plan = cached_eval.plan;
    let evaluated = cached_eval.evaluated;
    // A cached evaluation instantiated nothing, so name every configured
    // node for the screen before realization reports it by key.
    for key in evaluated.configured.keys() {
        crate::events::emit_configured(key, &evaluated.readable(key));
    }
    if evaluated.roots.is_empty() {
        // Every requested member dropped out: configuration disabled it.
        logger.info(
            "build",
            "Nothing to build: configuration disables every requested member",
        );
        return Ok(0);
    }
    // Capture the eval-phase breakdown now, before emit/verify add their own
    // source-stat work to the shared counters.
    let closure_ms = crate::source::closure_ms();
    let probe_wall_ms = crate::source::git::probe_wall_ms();
    let probe_ms = crate::source::git::probe_ms();
    let source_ms = crate::source::source_ingest_ms();
    let instantiate_ms = crate::source::instantiate_ms();

    let t_scan = std::time::Instant::now();
    let dry_resolved = evaluated.dry_resolve(&ctx.store);
    let cache_candidates = dry_resolved.values().filter(|r| r.digest.is_some()).count();
    let cache_scan_ms = t_scan.elapsed().as_millis();
    emit_eval_progress(
        start_time,
        crate::eval::graph::EvalProgress {
            current: evaluated.order.len(),
            total: evaluated.order.len(),
            phase: crate::eval::graph::EvalPhase::Evaluated,
            detail: String::new(),
            item: None,
            label: None,
        },
        Some(cache_candidates),
        Some(cache_candidates),
    );

    let elapsed = start_time.elapsed();
    let timings = crate::events::EvalTimings {
        context_ms,
        statcache_load_ms: crate::source::statcache::statcache_load_ms(),
        git_identity_ms,
        eval_ms,
        closure_ms,
        probe_wall_ms,
        probe_ms,
        source_ms,
        instantiate_ms,
        cache_scan_ms,
        emit_ms,
        verify_ms,
        evalcache,
        statcache_hits: crate::source::statcache::statcache_hits(),
        statcache_misses: crate::source::statcache::statcache_misses(),
        total_ms: context_ms + git_identity_ms + eval_ms + cache_scan_ms + emit_ms + verify_ms,
        ..Default::default()
    };
    let header_inputs = BuildHeaderInputs {
        git_identity,
        cfg_hash,
        profile: profile.to_string(),
        resolved: evaluated.order.len(),
        eval_elapsed: elapsed,
        timings: Some(timings),
    };
    let mut header = build_header_report(&ctx, args, header_inputs, header_seed.as_ref());

    match ctx.backend {
        crate::host::ExecBackend::Docker | crate::host::ExecBackend::Nerdctl => {
            let code = crate::host::container::run_plan_in_container(
                &ctx.repo_root,
                &ctx.state_root,
                &ctx.build_host,
                &ctx.backend,
                ctx.spec.executor_image.as_ref(),
                &plan_hash,
                Some(&header),
                &executor_runtime_flags(args),
            )?;
            if code == 0 {
                publish_request_roots(&ctx.store, &evaluated, &exec_plan.arch)?;
            }
            return Ok(code);
        }
        crate::host::ExecBackend::Remote => {
            return Err("remote backend requires a configured remote builder".to_string());
        }
        crate::host::ExecBackend::LocalLinux => {}
        crate::host::ExecBackend::Wsl => unreachable!("wsl backend is handled before evaluation"),
    }

    header.tools = crate::exec::report::toolchain_report(&exec_plan, &ctx.store, &dry_resolved);
    crate::events::emit_header(&header);

    let sandbox = crate::exec::sandbox::platform_sandbox();
    let builders = crate::full_builders();
    let outcome = crate::exec::pool::realize(
        &exec_plan,
        &ctx.store,
        sandbox.as_ref(),
        &builders,
        args.jobs,
        args.audit,
        args.keep_going,
        args.keep_failed,
        &rerun_nodes(args, &exec_plan),
        &logger,
    )?;
    publish_latest_roots(&ctx.store, &exec_plan.targets, &exec_plan.arch, &outcome)?;
    if outcome.failed.is_empty() {
        publish_request_roots(&ctx.store, &evaluated, &exec_plan.arch)?;
    }
    let summary = outcome.summary(&exec_plan);
    crate::events::emit_summary(&summary);

    // Observability: optional event/trace streams, plus a cache-statistics
    // summary printed after every build.
    if let Some(path) = &args.events {
        crate::exec::trace::write_events_jsonl(&outcome.events, path)?;
    }
    if let Some(path) = &args.trace {
        crate::exec::trace::write_trace(&outcome.events, path)?;
    }
    if outcome.failed.is_empty() {
        if let Some(stamp) = &args.stamp {
            if let Some(parent) = stamp.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(stamp, b"")
                .map_err(|e| format!("cannot write stamp {}: {}", stamp.display(), e))?;
        }
    }
    Ok(if outcome.failed.is_empty() { 0 } else { 1 })
}

/// Publish `latest-<name>-<arch>` for every live root requested by a plain
/// name whose node is a configured one (a variant): the plan names it by its
/// key, the person by the variant's name. Called on the host after a
/// successful realization, local or in a container.
pub(crate) fn publish_request_roots(
    store: &crate::store::Store,
    evaluated: &crate::eval::graph::Evaluated,
    arch: &str,
) -> Result<(), String> {
    let requests: Vec<&(String, String)> = evaluated
        .roots
        .iter()
        .filter(|(request, key)| {
            request != key
                && matches!(
                    crate::spec::address::parse(request),
                    Ok(crate::spec::address::Address::Plain(_))
                )
        })
        .collect();
    if requests.is_empty() {
        return Ok(());
    }
    let resolved = evaluated.dry_resolve(store);
    for (request, key) in requests {
        match resolved.get(key) {
            Some(node) if node.digest.is_some() => {
                store.add_root(&format!("latest-{request}-{arch}"), &node.store_name)?;
            }
            _ => {
                return Err(format!(
                    "realized `{request}` ({key}) is missing from the store"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) struct WorldEvaluation {
    /// Root name → store name of every current world root.
    pub roots: std::collections::BTreeMap<String, String>,
    /// Names whose `latest-` roots this world owns: a `--domain` group's
    /// closure, or every name when no domain is given.
    pub owned: Option<std::collections::BTreeSet<String>>,
}

/// Evaluate one architecture's requested world without realizing anything.
/// `dry_resolve` supplies the memoized realization digest closure; only
/// current identities already present in the store become world roots.
pub(crate) fn evaluate_world_roots(
    args: &Args,
    arch: &str,
    words: &[String],
) -> Result<WorldEvaluation, String> {
    let mut eval_args = args.clone();
    eval_args.arch = arch.to_string();
    eval_args.scope = Some(crate::spec::kinds::Scope::Packages);
    let mut ctx = open_context(&eval_args)?;
    let words: Vec<String> = match (&args.domain, words.is_empty()) {
        (Some(group), true) => vec![group.clone()],
        _ => words.to_vec(),
    };
    let targets = super::resolve_targets(&ctx.spec, &eval_args, &words)?;
    let owned = match &args.domain {
        Some(group) => {
            let mut names = super::domain_closure(&ctx.spec, group)?;
            for (name, _) in &ctx.spec.variants {
                if names.contains(crate::spec::variant_base(&ctx.spec.variants, name)) {
                    names.insert(name.clone());
                }
            }
            Some(names)
        }
        None => None,
    };
    let git_state = ctx.git_state().clone();
    let evaluated = crate::cmd::evaluate_plan_with_progress(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &targets,
        &ctx.state_root,
        !args.no_source_cache,
        git_state,
        |_| {},
    )?
    .evaluated;
    let resolved = evaluated.dry_resolve(&ctx.store);
    let mut current = std::collections::BTreeMap::new();
    for (request, key) in &evaluated.roots {
        if !matches!(
            crate::spec::address::parse(request),
            Ok(crate::spec::address::Address::Plain(_))
        ) {
            continue;
        }
        let Some(result) = resolved.get(key) else {
            continue;
        };
        if result.digest.is_some() {
            current.insert(
                format!("latest-{request}-{arch}"),
                result.store_name.clone(),
            );
        }
    }
    Ok(WorldEvaluation {
        roots: current,
        owned,
    })
}

pub fn cmd_plan(args: &Args) -> Result<i32, String> {
    cmd_plan_attempt(args, 0)
}

fn cmd_plan_attempt(args: &Args, source_retry: usize) -> Result<i32, String> {
    let t_context = std::time::Instant::now();
    let mut ctx = open_context(args)?;
    let store_lease = ctx.store.acquire_shared_lease()?;
    let context_ms = t_context.elapsed().as_millis();
    if args.targets.is_empty() {
        return Err("plan: name at least one target".to_string());
    }
    // Resolution and the `--domain` restriction happen before evaluation:
    // an execution plan carries configured nodes, not the words that named
    // them.
    let roots = super::resolve_targets(&ctx.spec, args, &args.targets)?;
    let t_eval = std::time::Instant::now();
    let eval_git_state = ctx.git_state().clone();
    let cached_eval = crate::cmd::evaluate_plan_with_progress(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &roots,
        &ctx.state_root,
        !args.no_source_cache,
        eval_git_state,
        |_| {},
    )?;
    let evalcache = cached_eval.state;
    let emit_ms = cached_eval.emit_ms;
    if !crate::cmd::daemon_snapshot_still_current(
        &ctx.spec,
        &cached_eval.evaluated.resolved_sources,
    )? {
        if source_retry < 3 {
            drop(store_lease);
            return cmd_plan_attempt(args, source_retry + 1);
        }
        return Err("source tree changed during daemon plan evaluation".to_string());
    }
    let path = cached_eval.path;
    let hash = cached_eval.hash;
    let eval_ms = t_eval.elapsed().as_millis().saturating_sub(emit_ms);
    let (closure_ms, probe_wall_ms, probe_ms, source_ms, instantiate_ms) = (
        crate::source::closure_ms(),
        crate::source::git::probe_wall_ms(),
        crate::source::git::probe_ms(),
        crate::source::source_ingest_ms(),
        crate::source::instantiate_ms(),
    );
    if args.timings || args.verbose {
        crate::events::emit_timings(&crate::events::EvalTimings {
            context_ms,
            statcache_load_ms: crate::source::statcache::statcache_load_ms(),
            eval_ms,
            closure_ms,
            probe_wall_ms,
            probe_ms,
            source_ms,
            instantiate_ms,
            emit_ms,
            evalcache,
            total_ms: context_ms + eval_ms + emit_ms,
            ..Default::default()
        });
    }
    out!("{} {}", hash, path.display());
    Ok(0)
}

fn plan_hash_from_path(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid plan path {}", path.display()))?;
    let hash = name
        .strip_suffix(".plan")
        .ok_or_else(|| format!("plan path must end in .plan: {}", path.display()))?;
    if hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hash.to_string())
    } else {
        Err(format!("plan filename does not carry a hash: {name}"))
    }
}

fn checked_store_executor_derivation(
    plan: &crate::eval::plan::ExecPlan,
    build_host: &str,
    platform: &str,
    image_id: &str,
) -> Result<crate::store::derivation::Derivation, String> {
    let drv = crate::eval::plan::container_executor_derivation(
        &plan.bootstrap_digest(),
        build_host,
        platform,
        image_id,
    );
    let expected_drv = std::env::var(crate::host::container::EXECUTOR_DRV_ENV)
        .map_err(|_| "__realize-plan: missing executor derivation identity".to_string())?;
    let expected_store = std::env::var(crate::host::container::EXECUTOR_STORE_ENV)
        .map_err(|_| "__realize-plan: missing executor store identity".to_string())?;
    if drv.hash() != expected_drv || drv.store_name() != expected_store {
        return Err(format!(
            "executor identity mismatch: contract={expected_drv}/{expected_store}, computed={}/{}",
            drv.hash(),
            drv.store_name()
        ));
    }
    Ok(drv)
}

fn run_through_store_executor(
    plan: &crate::eval::plan::ExecPlan,
    store: &crate::store::Store,
    state_root: &Path,
    build_host: &str,
    platform: &str,
    image_id: &str,
) -> Result<i32, String> {
    let drv = checked_store_executor_derivation(plan, build_host, platform, image_id)?;
    let executor_path = store.out_path(&drv).join("buildutil-realize");
    // Keep the pinned executor alive across registration and re-exec. The
    // command-level shared store lease separately excludes GC for this span.
    let _executor_root = store.add_temp_roots("realize-executor", &[drv.store_name()])?;
    if !store.validate_reuse(&drv)? {
        let current = std::env::current_exe()
            .map_err(|e| format!("cannot locate bootstrap executor: {e}"))?;
        let out = state_root.join("tmp").join(format!(
            ".{}-{}.executor",
            drv.store_name(),
            std::process::id()
        ));
        std::fs::create_dir(&out)
            .map_err(|e| format!("cannot create executor output {}: {e}", out.display()))?;
        std::fs::copy(&current, out.join("buildutil-realize"))
            .map_err(|e| format!("cannot install realize executor: {e}"))?;
        store.write_drv(&drv)?;
        // The executor is the wrapper's own bootstrap from the image's
        // stage-0 rustc and seed clang: a self-tool build, unconfined and
        // never signed.
        store.register(&drv, &out, "audit", &["self-tool: true".to_string()])?;
    }
    store.add_root(
        &format!("container-executor-{}", build_host.replace('/', "_")),
        &drv.store_name(),
    )?;
    let status = crate::invocation::command(&executor_path)
        .args(std::env::args().skip(1))
        .env("BUILDUTIL_STORE_EXECUTOR_ACTIVE", drv.store_name())
        .status()
        .map_err(|e| format!("cannot enter store realize executor: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

fn verify_active_store_executor(
    plan: &crate::eval::plan::ExecPlan,
    store: &crate::store::Store,
    build_host: &str,
    platform: &str,
    image_id: &str,
) -> Result<(), String> {
    let drv = checked_store_executor_derivation(plan, build_host, platform, image_id)?;
    let executor_path = store.out_path(&drv).join("buildutil-realize");
    let current = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("cannot resolve active executor: {e}"))?;
    let expected = std::fs::canonicalize(&executor_path).map_err(|e| {
        format!(
            "cannot resolve expected executor {}: {e}",
            executor_path.display()
        )
    })?;
    if current != expected || !store.validate_reuse(&drv)? {
        return Err("active realize executor is not the pinned store artifact".to_string());
    }
    Ok(())
}

pub fn cmd_realize_plan(args: &Args) -> Result<i32, String> {
    let plan_path = args
        .targets
        .first()
        .map(PathBuf::from)
        .ok_or("__realize-plan: missing <plan-path>")?;
    let state_root = args
        .store
        .clone()
        .or_else(|| std::env::var_os("BUILDUTIL_STORE").map(PathBuf::from))
        .ok_or("__realize-plan: --store <state> is required")?;
    let hash32 = plan_hash_from_path(&plan_path)?;
    let store = crate::store::Store::open(&state_root)?;
    // Both the coordinator's pinned-executor reuse check and the executor's
    // realization run under this shared lease. Shared holders coexist across
    // the re-exec boundary while GC waits for both to leave.
    let _store_lease = store.acquire_shared_lease()?;
    // Note: cmd_realize_plan consumes a plan; it does not re-ingest sources.
    // The repo-relative-path cache is therefore intentionally left uncached
    // here — there is nothing repo-local to re-stat, and inferring the
    // repo root from cwd would couple a sandboxed tool to the invoker's
    // working directory. Hashable file content (when needed) goes through
    // `source::hash_and_ingest_file` without the stat cache.
    crate::source::activate(&state_root)?;
    let requested_build_host = std::env::var(crate::host::container::REALIZE_BUILD_HOST_ENV)
        .map_err(|_| "__realize-plan: missing attested build-host environment".to_string())?;
    let requested_platform =
        std::env::var(crate::host::container::REALIZE_PLATFORM_ENV).map_err(|_| {
            "__realize-plan: missing attested container platform environment".to_string()
        })?;
    let image_id = std::env::var(crate::host::container::EXECUTOR_IMAGE_ID_ENV)
        .map_err(|_| "__realize-plan: missing executor image content id".to_string())?;
    let image_hash = image_id.strip_prefix("sha256:").unwrap_or(&image_id);
    if image_hash.len() != 64 || !image_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "__realize-plan: invalid executor image id `{image_id}`"
        ));
    }
    if std::env::var_os("BUILDUTIL_STORE_EXECUTOR_ACTIVE").is_none() {
        let exec_plan = crate::eval::plan::load_attested(&plan_path, &hash32)?;
        crate::eval::plan::verify_realize_contract(
            &exec_plan,
            &requested_build_host,
            &requested_platform,
            &crate::host::executor_build_host(),
        )?;
        return run_through_store_executor(
            &exec_plan,
            &store,
            &state_root,
            &requested_build_host,
            &requested_platform,
            &image_id,
        );
    }

    // The store executor is the source-CAS consumer. Its plan lease starts
    // before the attested plan read and remains held through completeness
    // validation and realization, closing GC's check/use race. The coordinator
    // branch above never takes this lease, so it cannot hold the lock while
    // waiting for the executor that acquires it.
    let _plan_lease = crate::state::lock_plan(&state_root, &hash32)?;
    let exec_plan = crate::eval::plan::load_attested(&plan_path, &hash32)?;
    crate::eval::plan::verify_realize_contract(
        &exec_plan,
        &requested_build_host,
        &requested_platform,
        &crate::host::executor_build_host(),
    )?;
    verify_active_store_executor(
        &exec_plan,
        &store,
        &requested_build_host,
        &requested_platform,
        &image_id,
    )?;
    crate::eval::plan::verify_source_cas_complete(&exec_plan, &state_root)?;

    let logger = crate::log::Logger::new(args.verbose);
    if let Some(path) = &args.header_report {
        let mut report = crate::events::read_header_file(path)?;
        let order = exec_plan
            .nodes
            .iter()
            .map(|node| node.name.clone())
            .collect::<Vec<_>>();
        let dry_resolved =
            crate::eval::graph::dry_resolve_recipes(&order, &exec_plan.recipes(), &store);
        report.tools = crate::exec::report::toolchain_report(&exec_plan, &store, &dry_resolved);
        crate::events::emit_header(&report);
    }
    let sandbox = crate::exec::sandbox::platform_sandbox();
    let builders = crate::full_builders();
    let outcome = crate::exec::pool::realize(
        &exec_plan,
        &store,
        sandbox.as_ref(),
        &builders,
        args.jobs,
        args.audit,
        args.keep_going,
        args.keep_failed,
        &rerun_nodes(args, &exec_plan),
        &logger,
    )?;
    publish_latest_roots(&store, &exec_plan.targets, &exec_plan.arch, &outcome)?;
    let summary = outcome.summary(&exec_plan);
    crate::events::emit_summary(&summary);
    if let Some(path) = &args.events {
        crate::exec::trace::write_events_jsonl(&outcome.events, path)?;
    }
    if let Some(path) = &args.trace {
        crate::exec::trace::write_trace(&outcome.events, path)?;
    }
    Ok(if outcome.failed.is_empty() { 0 } else { 1 })
}

pub fn cmd_dev_build(args: &Args) -> Result<i32, String> {
    if args.targets.len() != 5 {
        return Err(
            "__dev-build: expected <plan-path> <target> <label> <dev-backend> <dev-dir>"
                .to_string(),
        );
    }
    let plan_path = PathBuf::from(&args.targets[0]);
    let target = &args.targets[1];
    let label = &args.targets[2];
    // The outer buildutil names the backend that owns the dev tree; resolving it
    // here would select local-linux inside the container.
    let dev_backend = crate::host::ExecBackend::parse(&args.targets[3])?.dev_output_name()?;
    let dev_dir = PathBuf::from(&args.targets[4]);
    let state_root = args
        .store
        .clone()
        .or_else(|| std::env::var_os("BUILDUTIL_STORE").map(PathBuf::from))
        .ok_or("__dev-build: --store <state> is required")?;
    let hash32 = plan_hash_from_path(&plan_path)?;
    let store = crate::store::Store::open(&state_root)?;
    let _store_lease = store.acquire_shared_lease()?;
    crate::source::activate(&state_root)?;
    let requested_build_host = std::env::var(crate::host::container::REALIZE_BUILD_HOST_ENV)
        .map_err(|_| "__dev-build: missing attested build-host environment".to_string())?;
    let requested_platform = std::env::var(crate::host::container::REALIZE_PLATFORM_ENV)
        .map_err(|_| "__dev-build: missing attested container platform environment".to_string())?;
    let _plan_lease = crate::state::lock_plan(&state_root, &hash32)?;
    let exec_plan = crate::eval::plan::load_attested(&plan_path, &hash32)?;
    crate::eval::plan::verify_realize_contract(
        &exec_plan,
        &requested_build_host,
        &requested_platform,
        &crate::host::executor_build_host(),
    )?;
    crate::eval::plan::verify_source_cas_complete(&exec_plan, &state_root)?;
    if exec_plan.targets.len() != 1 || exec_plan.targets[0].as_str() != target.as_str() {
        return Err(format!(
            "__dev-build: plan target mismatch: expected only `{target}`, got {:?}",
            exec_plan.targets
        ));
    }
    let expected_dev_dir = crate::state::dev_dir(&state_root, dev_backend, &exec_plan.arch, label);
    if dev_dir.as_path() != expected_dev_dir.as_path() {
        return Err(format!(
            "__dev-build: dev output path mismatch: expected {}, got {}",
            expected_dev_dir.display(),
            dev_dir.display()
        ));
    }

    let builders = crate::full_builders();
    let logger = crate::log::Logger::new(args.verbose);
    match crate::exec::build::dev_build(&exec_plan, &store, &builders, target, &dev_dir)? {
        crate::exec::build::DevOutcome::Built(out) => {
            logger.info("dev", &format!("{} -> {}", target, out));
            Ok(0)
        }
        crate::exec::build::DevOutcome::Failed => Ok(1),
    }
}

pub fn cmd_dev(args: &Args) -> Result<i32, String> {
    cmd_dev_attempt(args, 0)
}

fn cmd_dev_attempt(args: &Args, source_retry: usize) -> Result<i32, String> {
    let requested_backend = crate::host::ExecBackend::resolve(&args.backend)?;
    if requested_backend == crate::host::ExecBackend::Wsl {
        let repo_root = repo_root_from_cwd()?;
        return crate::host::wsl::run_wsl_backend(&repo_root, &args.argv);
    }

    let mut ctx = open_context(args)?;
    let mut store_lease = Some(ctx.store.acquire_shared_lease()?);
    let word = positional(args)
        .first()
        .copied()
        .ok_or("dev: name a target")?
        .to_string();
    let request =
        match super::resolve_targets(&ctx.spec, args, std::slice::from_ref(&word))?.as_slice() {
            [one] => one
                .trim_start_matches(crate::spec::kinds::OPTIONAL_PREFIX)
                .to_string(),
            _ => return Err(format!("dev: `{word}` names more than one derivation")),
        };
    let eval_git_state = ctx.git_state().clone();
    let cached_eval = crate::cmd::evaluate_plan_with_progress(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        std::slice::from_ref(&request),
        &ctx.state_root,
        !args.no_source_cache,
        eval_git_state,
        |_| {},
    )?;
    if !crate::cmd::daemon_snapshot_still_current(
        &ctx.spec,
        &cached_eval.evaluated.resolved_sources,
    )? {
        if source_retry < 3 {
            drop(store_lease.take());
            return cmd_dev_attempt(args, source_retry + 1);
        }
        return Err("source tree changed during daemon dev evaluation".to_string());
    }
    let ev = cached_eval.evaluated;
    // The tip is a configured node: a variant's dev build reads the
    // variant's configuration. Its dev tree is named by the name it was
    // requested by, so `buildutil run --dev` finds a variant's tree by name;
    // any other address names it by its key.
    let target = ev
        .roots
        .first()
        .map(|(_, key)| key.clone())
        .ok_or_else(|| format!("dev: `{word}` is disabled by configuration"))?;
    let label = match crate::spec::address::parse(&request) {
        Ok(crate::spec::address::Address::Plain(name)) => name,
        _ => target.clone(),
    };
    // Dependencies are requested in their readable form, which evaluates
    // each under exactly its relevant overrides.
    let dep_names: Vec<String> = ev
        .recipes
        .get(&target)
        .ok_or_else(|| format!("dev: `{}` is not in the graph", target))?
        .dep_names
        .iter()
        .map(|key| ev.readable(key))
        .collect();
    match ctx.backend {
        crate::host::ExecBackend::Docker | crate::host::ExecBackend::Nerdctl => {
            if !dep_names.is_empty() {
                let eval_git_state = ctx.git_state().clone();
                let dep_plan = crate::cmd::evaluate_plan_with_progress(
                    &ctx.spec,
                    &ctx.config,
                    &mut ctx.toolchain,
                    &dep_names,
                    &ctx.state_root,
                    !args.no_source_cache,
                    eval_git_state,
                    |_| {},
                )?;
                let dry_resolved = dep_plan.evaluated.dry_resolve(&ctx.store);
                if dry_resolved
                    .values()
                    .any(|resolved| resolved.digest.is_none())
                {
                    let code = crate::host::container::run_plan_in_container(
                        &ctx.repo_root,
                        &ctx.state_root,
                        &ctx.build_host,
                        &ctx.backend,
                        ctx.spec.executor_image.as_ref(),
                        &dep_plan.hash,
                        None,
                        &executor_runtime_flags(args),
                    )?;
                    if code != 0 {
                        return Ok(code);
                    }
                }
            }

            let dev_dir = crate::state::dev_dir(
                &crate::state::absolute_root(&ctx.repo_root, &ctx.state_root),
                ctx.backend.dev_output_name()?,
                &args.arch,
                &label,
            );
            let watch = flag_present(args, "--watch");
            loop {
                if store_lease.is_none() {
                    store_lease = Some(ctx.store.acquire_shared_lease()?);
                }
                let eval_git_state = ctx.git_state().clone();
                let target_plan = crate::cmd::evaluate_plan_with_progress(
                    &ctx.spec,
                    &ctx.config,
                    &mut ctx.toolchain,
                    std::slice::from_ref(&request),
                    &ctx.state_root,
                    !args.no_source_cache,
                    eval_git_state,
                    |_| {},
                )?;
                if !crate::cmd::daemon_snapshot_still_current(
                    &ctx.spec,
                    &target_plan.evaluated.resolved_sources,
                )? {
                    return Err("source tree changed during daemon dev evaluation".to_string());
                }
                let code = crate::host::container::run_dev_build_in_container(
                    &ctx.repo_root,
                    &ctx.state_root,
                    &ctx.build_host,
                    &ctx.backend,
                    ctx.spec.executor_image.as_ref(),
                    &target_plan.hash,
                    &target,
                    &label,
                    &dev_dir,
                    args.jobs,
                    args.verbose,
                )?;
                if code != 0 || !watch {
                    return Ok(code);
                }
                drop(store_lease.take());
                wait_for_source_change(&ctx.spec, &target_plan.plan, &target);
            }
        }
        crate::host::ExecBackend::Remote => {
            return Err("remote backend requires a configured remote builder".to_string());
        }
        crate::host::ExecBackend::LocalLinux => {}
        crate::host::ExecBackend::Wsl => unreachable!("wsl backend is handled before evaluation"),
    }
    let builders = crate::full_builders();

    // 1. Realize the tip's dependency closure into the store (pure, cached).
    let _dep_outcome = if !dep_names.is_empty() {
        let eval_git_state = ctx.git_state().clone();
        let dep_plan = crate::cmd::evaluate_plan_with_progress(
            &ctx.spec,
            &ctx.config,
            &mut ctx.toolchain,
            &dep_names,
            &ctx.state_root,
            !args.no_source_cache,
            eval_git_state,
            |_| {},
        )?
        .plan;
        let sandbox = crate::exec::sandbox::platform_sandbox();
        let logger = crate::log::Logger::new(args.verbose);
        let outcome = crate::exec::pool::realize(
            &dep_plan,
            &ctx.store,
            sandbox.as_ref(),
            &builders,
            args.jobs,
            args.audit,
            false,
            args.keep_failed,
            &std::collections::BTreeSet::new(),
            &logger,
        )?;
        crate::events::emit_summary(&outcome.summary(&dep_plan));
        if !outcome.failed.is_empty() {
            // Each failure was reported by its build events and the summary.
            return Ok(1);
        }
        Some(outcome)
    } else {
        None
    };

    // 2. Dev-build the tip in a persistent per-target dir.
    let dev_dir = crate::state::dev_dir(
        &crate::state::absolute_root(&ctx.repo_root, &ctx.state_root),
        ctx.backend.dev_output_name()?,
        &args.arch,
        &label,
    );
    let watch = flag_present(args, "--watch");
    let logger = crate::log::Logger::new(args.verbose);
    let mut code;
    loop {
        if store_lease.is_none() {
            store_lease = Some(ctx.store.acquire_shared_lease()?);
        }
        let eval_git_state = ctx.git_state().clone();
        let exec_plan = crate::cmd::evaluate_plan_with_progress(
            &ctx.spec,
            &ctx.config,
            &mut ctx.toolchain,
            std::slice::from_ref(&request),
            &ctx.state_root,
            !args.no_source_cache,
            eval_git_state,
            |_| {},
        )?;
        if !crate::cmd::daemon_snapshot_still_current(
            &ctx.spec,
            &exec_plan.evaluated.resolved_sources,
        )? {
            return Err("source tree changed during daemon dev evaluation".to_string());
        }
        let exec_plan = exec_plan.plan;
        // A failure is reported by its build events; under --watch the next
        // source change retries, otherwise it sets the exit code.
        code = match crate::exec::build::dev_build(
            &exec_plan, &ctx.store, &builders, &target, &dev_dir,
        ) {
            Ok(crate::exec::build::DevOutcome::Built(out)) => {
                logger.info("dev", &format!("{} -> {}", target, out));
                0
            }
            Ok(crate::exec::build::DevOutcome::Failed) => 1,
            Err(e) => {
                logger.error("dev", &format!("Dev build of {} failed: {}", target, e));
                1
            }
        };
        if !watch {
            break;
        }
        drop(store_lease.take());
        wait_for_source_change(&ctx.spec, &exec_plan, &target);
    }
    Ok(code)
}

/// Block (polling, no external crates) until any declared source of `drv`
/// changes mtime — the `buildutil dev --watch` rebuild trigger.
fn wait_for_source_change(
    spec: &crate::spec::Spec,
    plan: &crate::eval::plan::ExecPlan,
    target: &str,
) {
    let mut roots: Vec<PathBuf> = Vec::new();
    let Some(node) = plan.node(target) else {
        return;
    };
    for (_, rel, _) in &node.srcs {
        roots.push(spec.repo_root.join(rel));
    }
    for (rel, _) in &node.srcdirs {
        roots.push(spec.repo_root.join(rel));
    }
    for (rel, _) in &node.source_roots {
        roots.push(spec.repo_root.join(rel));
    }
    let newest = |roots: &[PathBuf]| -> std::time::SystemTime {
        let mut newest = std::time::UNIX_EPOCH;
        let mut stack: Vec<PathBuf> = roots.to_vec();
        while let Some(p) = stack.pop() {
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if md.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&p) {
                    for e in rd.flatten() {
                        stack.push(e.path());
                    }
                }
            } else if let Ok(m) = md.modified() {
                if m > newest {
                    newest = m;
                }
            }
        }
        newest
    };
    let base = newest(&roots);
    crate::log::info(
        "dev",
        &format!(
            "watching {} source root(s); edit to rebuild, Ctrl-C to stop",
            roots.len()
        ),
    );
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if newest(&roots) > base {
            return;
        }
    }
}

pub fn cmd_eval(args: &Args) -> Result<i32, String> {
    cmd_eval_attempt(args, 0)
}

fn cmd_eval_attempt(args: &Args, source_retry: usize) -> Result<i32, String> {
    let t_context = std::time::Instant::now();
    let mut ctx = open_context(args)?;
    let store_lease = ctx.store.acquire_shared_lease()?;
    let context_ms = t_context.elapsed().as_millis();
    if args.targets.is_empty() {
        return Err("eval: name at least one target".to_string());
    }
    let targets = super::resolve_targets(&ctx.spec, args, &args.targets)?;
    let t_eval = std::time::Instant::now();
    let eval_git_state = ctx.git_state().clone();
    let cached_eval = crate::cmd::evaluate_plan_with_progress(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &targets,
        &ctx.state_root,
        !args.no_source_cache,
        eval_git_state,
        |progress| {
            emit_eval_progress(t_eval, progress, None, None);
        },
    )?;
    let evalcache = cached_eval.state;
    let emit_ms = cached_eval.emit_ms;
    if !crate::cmd::daemon_snapshot_still_current(
        &ctx.spec,
        &cached_eval.evaluated.resolved_sources,
    )? {
        if source_retry < 3 {
            drop(store_lease);
            return cmd_eval_attempt(args, source_retry + 1);
        }
        return Err("source tree changed during daemon eval evaluation".to_string());
    }
    let evaluated = cached_eval.evaluated;
    let eval_ms = t_eval.elapsed().as_millis().saturating_sub(emit_ms);
    // Under staged resolution a node's identity depends on its dependencies'
    // realization digests, known only once those dependencies are realized.
    // eval is read-only: it prints identities for the nodes it can resolve
    // from the store and reports the rest as unresolved.
    let t_scan = std::time::Instant::now();
    let drvs = evaluated.dry_resolve(&ctx.store);
    let cache_scan_ms = t_scan.elapsed().as_millis();
    for name in &evaluated.order {
        match drvs.get(name) {
            Some(r) => {
                let status = if r.digest.is_some() {
                    "realized"
                } else {
                    "would build"
                };
                out!("{} {} ({})", r.drv.hash(), r.store_name, status);
            }
            None => out!(
                "{}  <unresolved: dependencies not realized>",
                evaluated.readable(name)
            ),
        }
    }
    if args.timings {
        let timings = crate::events::EvalTimings {
            context_ms,
            statcache_load_ms: crate::source::statcache::statcache_load_ms(),
            eval_ms,
            closure_ms: crate::source::closure_ms(),
            probe_wall_ms: crate::source::git::probe_wall_ms(),
            probe_ms: crate::source::git::probe_ms(),
            source_ms: crate::source::source_ingest_ms(),
            instantiate_ms: crate::source::instantiate_ms(),
            cache_scan_ms,
            emit_ms,
            evalcache,
            statcache_hits: crate::source::statcache::statcache_hits(),
            statcache_misses: crate::source::statcache::statcache_misses(),
            total_ms: context_ms + eval_ms + cache_scan_ms + emit_ms,
            ..Default::default()
        };
        crate::events::emit_timings(&timings);
    }
    Ok(0)
}
