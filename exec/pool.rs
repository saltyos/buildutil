//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — realization scheduler (N-way worker pool over a dep-counting queue)
//!
//! The pool walks the evaluated closure topo-first: every dependent waits on
//! a single blocking dependency count. Workers pull from the ready queue,
//! finalize each derivation using its dependencies' now-known realization
//! digests + providers (the staged-resolution step that lets later passes
//! hash the preimage), and then either reuse the cached result or build it.
//! Build failures take their transitive dependents out of the queue as
//! "skipped" under keep-going.

use super::build::build_one;
use crate::eval::plan::{ExecNode, ExecPlan};
use crate::store::Store;
use crate::store::derivation::Derivation;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static LAST_REALIZE_MS: AtomicU64 = AtomicU64::new(0);

/// Wall-clock duration of the most recent [`realize`] invocation. The value
/// is observability-only and does not affect the execution plan or store.
pub fn realize_ms() -> u128 {
    LAST_REALIZE_MS.load(Ordering::Relaxed) as u128
}

struct RealizeTimer {
    started: Instant,
}

impl RealizeTimer {
    fn start() -> Self {
        LAST_REALIZE_MS.store(0, Ordering::Relaxed);
        Self {
            started: Instant::now(),
        }
    }
}

impl Drop for RealizeTimer {
    fn drop(&mut self) {
        let elapsed_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        LAST_REALIZE_MS.store(elapsed_ms, Ordering::Relaxed);
    }
}

/// The realization digest of an already-realized entry: the record's digest
/// when a record exists (authoritative), else recomputed from meta (e.g. a
/// substituted entry before its record is installed). Both agree by
/// construction (register writes them from the same manifest).
pub(super) fn realized_digest(
    store: &Store,
    drv_hash: &str,
    store_name: &str,
) -> Result<String, String> {
    match store.read_realization_digest(drv_hash) {
        Some(d) => Ok(d),
        None => store.digest_of(store_name),
    }
}

struct PoolState {
    ready: VecDeque<String>,
    blocked: BTreeMap<String, usize>,
    dependents: BTreeMap<String, Vec<String>>,
    remaining: usize,
    built: Vec<String>,
    cached: Vec<String>,
    failed: Vec<(String, String)>,
    /// A failure without keep-going: start nothing new and let running
    /// builds finish.
    stopped: bool,
    /// Realized nodes: name → (realization digest, provider store name). A
    /// node is finalized (its preimage hashed) only once every dependency is
    /// present here — the staged-resolution readiness step.
    realized: BTreeMap<String, (String, String)>,
    events: Vec<super::Event>,
}

/// Under keep-going, a failed derivation takes its transitive dependents
/// out of the queue as skipped.
fn skip_dependents(st: &mut PoolState, root: &str) {
    let mut queue = vec![root.to_string()];
    while let Some(name) = queue.pop() {
        let Some(children) = st.dependents.remove(&name) else {
            continue;
        };
        for child in children {
            if st.blocked.remove(&child).is_some() {
                st.remaining -= 1;
                st.failed.push((
                    child.clone(),
                    format!("skipped: dependency `{}` failed", name),
                ));
                queue.push(child);
            }
        }
    }
}

/// Realize one finalized derivation end to end (cache check → build-or-wait).
/// Returns (built_here, realization_digest): `built_here` is true when this
/// call built it, false when reused or substituted; the digest is always
/// resolved so the scheduler can unblock dependents (whose preimages embed
/// it). A `rerun` node skips reuse, substitution and a concurrent builder's
/// result and always builds; `substituter` is the store tool its stage
/// declares for fetching signed realizations.
fn realize_one(
    plan: &ExecPlan,
    store: &Store,
    sandbox: &dyn super::sandbox::SandboxExec,
    builders: &super::builder::BuilderRegistry,
    jobserver: Option<&super::jobserver::Jobserver>,
    drv: &Derivation,
    name: &str,
    node: &ExecNode,
    audit: super::AuditMode,
    logger: &crate::log::Logger,
    keep_failed: bool,
    rerun: bool,
    substituter: Option<&Path>,
    on_build_start: Option<&dyn Fn(&'static str)>,
) -> Result<(bool, String, Option<String>), String> {
    let store_name = drv.store_name();
    if !rerun && store.validate_reuse(drv)? {
        return Ok((false, realized_digest(store, &drv.hash(), &store_name)?, None));
    }
    // Signed substitution (OFF unless substituters are configured): a
    // verified remote entry replaces the local build; any failure falls
    // back silently. It runs on the Linux build host only, never for the
    // self-tool class, and only with the store curl the stage declares.
    let substituters = store.substituters();
    if let Some(curl) = substituter.filter(|_| {
        !rerun && !substituters.is_empty() && cfg!(target_os = "linux") && !node.is_self_tool()
    }) {
        let refs: Vec<String> = drv.deps.iter().map(|d| d.store_name.clone()).collect();
        if crate::store::substitute::try_substitute(
            store,
            Path::new(""),
            curl,
            &substituters,
            &drv.hash(),
            &store_name,
            &refs,
        )? {
            if !store.validate_reuse(drv)? {
                return Err(format!(
                    "substituter reported success without installing `{store_name}`"
                ));
            }
            return Ok((false, realized_digest(store, &drv.hash(), &store_name)?, None));
        }
    }
    loop {
        let Some(_build_lock) = store.try_lock(drv)? else {
            std::thread::sleep(std::time::Duration::from_millis(200));
            if !rerun && store.validate_reuse(drv)? {
                return Ok((false, realized_digest(store, &drv.hash(), &store_name)?, None));
            }
            continue;
        };
        if !rerun && store.validate_reuse(drv)? {
            return Ok((false, realized_digest(store, &drv.hash(), &store_name)?, None));
        }
        // The build starts by staging its inputs; `build_one` reports the
        // builder's own action once staging is done.
        if let Some(on_build_start) = on_build_start {
            on_build_start("Staging");
        }
        return build_one(
            plan,
            store,
            sandbox,
            builders,
            jobserver,
            drv,
            name,
            node,
            audit,
            logger,
            keep_failed,
            None,
        )
        .map(|(digest, verdict)| (true, digest, verdict));
    }
}

/// Realize the evaluated closure with an N-way worker pool.
pub fn realize(
    plan: &ExecPlan,
    store: &Store,
    sandbox: &dyn super::sandbox::SandboxExec,
    builders: &super::builder::BuilderRegistry,
    jobs: usize,
    audit: super::AuditMode,
    keep_going: bool,
    keep_failed: bool,
    rerun: &BTreeSet<String>,
    logger: &crate::log::Logger,
) -> Result<super::RealizeOutcome, String> {
    let _timer = RealizeTimer::start();
    // This protects every cache check, substitution install, and build-lock
    // acquisition below. The shared store lease is always outermost.
    let _store_lease = store.acquire_shared_lease()?;
    let temp_root = Mutex::new(store.create_temp_root("realize")?);
    let recipes = plan.recipes();
    let order: Vec<String> = plan.nodes.iter().map(|node| node.name.clone()).collect();
    let in_closure: BTreeSet<&str> = order.iter().map(|s| s.as_str()).collect();
    let mut state = PoolState {
        ready: VecDeque::new(),
        blocked: BTreeMap::new(),
        dependents: BTreeMap::new(),
        remaining: order.len(),
        built: Vec::new(),
        cached: Vec::new(),
        failed: Vec::new(),
        stopped: false,
        realized: BTreeMap::new(),
        events: Vec::new(),
    };
    for name in &order {
        let recipe = &recipes[name];
        let unmet = recipe
            .dep_names
            .iter()
            .filter(|d| in_closure.contains(d.as_str()))
            .count();
        if unmet == 0 {
            state.ready.push_back(name.clone());
        } else {
            state.blocked.insert(name.clone(), unmet);
        }
        for dep in &recipe.dep_names {
            if in_closure.contains(dep.as_str()) {
                state
                    .dependents
                    .entry(dep.clone())
                    .or_default()
                    .push(name.clone());
            }
        }
    }

    let shared = Mutex::new(state);
    let cond = Condvar::new();
    let jobs = jobs.max(1);
    // One token pool bounds buildutil's workers, inner ninjas, and port make
    // together; serial builds (jobs==1) need no pool.
    let jobserver = super::jobserver::Jobserver::new(jobs)?;

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    // Pop a ready node and finalize its derivation using its
                    // dependencies' now-known realization digests + providers
                    // (the staged-resolution step).
                    let (name, drv) = {
                        let mut st = shared.lock().expect("pool lock");
                        loop {
                            if st.stopped || st.remaining == 0 {
                                return;
                            }
                            if let Some(name) = st.ready.pop_front() {
                                let recipe = &recipes[&name];
                                let mut deps = Vec::with_capacity(recipe.dep_names.len());
                                for dep_name in &recipe.dep_names {
                                    if !in_closure.contains(dep_name.as_str()) {
                                        continue;
                                    }
                                    let (digest, store_name) = st
                                        .realized
                                        .get(dep_name)
                                        .expect("dependency realized before dependent is ready")
                                        .clone();
                                    deps.push(crate::store::derivation::DepRef {
                                        name: dep_name.clone(),
                                        digest,
                                        store_name,
                                    });
                                }
                                break (name, recipe.finalize(deps));
                            }
                            st = cond.wait(st).expect("pool wait");
                        }
                    };
                    // Draw a job slot from the shared pool for the duration of
                    // this build (a cache hit returns it near-instantly).
                    let slot = jobserver.as_ref().map(|js| js.acquire());
                    let start_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    let inst = Instant::now();
                    let drv_hash = drv.hash()[..12].to_string();
                    // Emitted under the pool lock, like finish events, so a
                    // start never carries a count older than one already sent.
                    let on_build_start = |action: &'static str| {
                        let st = shared.lock().expect("pool lock");
                        let completed = st.built.len() + st.cached.len() + st.failed.len();
                        logger.start_job(&name, action, completed, order.len());
                    };
                    let node = plan
                        .node(&name)
                        .expect("recipe order references missing execution node");
                    // The substituter's provider is in the node's closure,
                    // so it is realized by now.
                    let substituter = node.exec.substituter.as_ref().and_then(|(key, rel)| {
                        let st = shared.lock().expect("pool lock");
                        st.realized
                            .get(key)
                            .map(|(_, provider)| store.root.join(provider).join(rel))
                    });
                    let result = realize_one(
                        plan,
                        store,
                        sandbox,
                        builders,
                        jobserver.as_ref(),
                        &drv,
                        &name,
                        node,
                        audit,
                        logger,
                        keep_failed,
                        rerun.contains(&name),
                        substituter.as_deref(),
                        Some(&on_build_start),
                    )
                    .and_then(|(built, digest, verdict)| {
                        let store_name = drv.store_name();
                        temp_root
                            .lock()
                            .expect("temp root lock")
                            .append(&store_name)?;
                        Ok((built, digest, store_name, verdict))
                    });
                    let dur_secs = inst.elapsed().as_secs_f64();
                    if let (Some(js), Some(s)) = (jobserver.as_ref(), slot) {
                        js.release(s);
                    }
                    let mut st = shared.lock().expect("pool lock");
                    let total = order.len();

                    match result {
                        Ok((built, digest, store_name, verdict)) => {
                            st.realized
                                .insert(name.clone(), (digest.clone(), store_name));
                            st.events.push(super::Event {
                                name: name.clone(),
                                hash: drv_hash.clone(),
                                kind: if built { "realized" } else { "cached" },
                                start_ms,
                                dur_secs,
                                digest: Some(digest),
                                msg: None,
                            });
                            if built {
                                st.built.push(name.clone());
                            } else {
                                st.cached.push(name.clone());
                            }
                            let completed = st.built.len() + st.cached.len() + st.failed.len();
                            let outcome = if built { "Realized" } else { "Cached" };
                            logger.finish_job(
                                &name,
                                outcome,
                                completed,
                                total,
                                &drv_hash,
                                verdict.as_deref(),
                            );
                        }
                        Err(e) => {
                            st.events.push(super::Event {
                                name: name.clone(),
                                hash: drv_hash.clone(),
                                kind: "failed",
                                start_ms,
                                dur_secs,
                                digest: None,
                                msg: Some(e.clone()),
                            });
                            let completed = st.built.len() + st.cached.len() + st.failed.len() + 1;
                            // The failure is reported once, by its finish
                            // event; a log exists only when this attempt ran
                            // the builder (`build_one` removes an earlier one).
                            let log = store
                                .log_path(&drv.store_name())
                                .exists()
                                .then(|| store.log_name(&drv.store_name()));
                            logger.fail_job(&name, completed, total, &drv_hash, &e, log.as_deref());
                            st.failed.push((name.clone(), e));
                            if keep_going {
                                st.remaining -= 1;
                                skip_dependents(&mut st, &name);
                                cond.notify_all();
                                continue;
                            } else {
                                st.stopped = true;
                                cond.notify_all();
                                return;
                            }
                        }
                    }
                    st.remaining -= 1;
                    if let Some(children) = st.dependents.remove(&name) {
                        for child in children {
                            if let Some(count) = st.blocked.get_mut(&child) {
                                *count -= 1;
                                if *count == 0 {
                                    st.blocked.remove(&child);
                                    st.ready.push_back(child);
                                }
                            }
                        }
                    }
                    cond.notify_all();
                }
            });
        }
    });

    let state = shared.into_inner().expect("pool lock");
    let temp_root = temp_root.into_inner().expect("temp root lock");
    let store_names = state
        .realized
        .into_iter()
        .map(|(name, (_digest, store_name))| (name, store_name))
        .collect();
    Ok(super::RealizeOutcome {
        built: state.built,
        cached: state.cached,
        failed: state.failed,
        store_names,
        events: state.events,
        _temp_root: temp_root,
    })
}
