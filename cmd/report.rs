// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — header/summary/eval-progress reporting primitives.

use super::Args;
use super::Context;

pub fn config_hash(config: &crate::spec::configres::Config) -> String {
    let mut preimage = String::new();
    for (k, v) in &config.values {
        preimage.push_str(&format!("{}={}\n", k, v));
    }
    crate::crypto::sha256::hash_bytes(preimage.as_bytes())[..12].to_string()
}

pub struct BuildHeaderInputs {
    pub git_identity: String,
    pub cfg_hash: String,
    pub profile: String,
    pub resolved: usize,
    pub eval_elapsed: std::time::Duration,
    pub timings: Option<crate::events::EvalTimings>,
}

pub fn build_header_report(
    ctx: &Context,
    args: &Args,
    inputs: BuildHeaderInputs,
    seed: Option<&crate::events::HeaderSeed>,
) -> crate::events::HeaderReport {
    let source_dir = seed
        .map(|s| s.source_dir.clone())
        .unwrap_or_else(|| ctx.repo_root.display().to_string());
    let build_host = seed
        .map(|s| s.build_host.clone())
        .unwrap_or_else(|| ctx.build_host.to_string());
    let backend = seed
        .map(|s| s.backend.clone())
        .unwrap_or_else(|| ctx.backend.as_str().to_string());
    crate::events::HeaderReport {
        source_dir,
        target_system: ctx.spec.target_system.clone(),
        build_host,
        backend,
        git_rev: inputs.git_identity,
        config_hash: inputs.cfg_hash,
        inputs: ctx.inputs.report(),
        profile: inputs.profile,
        tools: Vec::new(),
        config: ctx
            .config
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        targets: args.targets.clone(),
        resolved: inputs.resolved,
        eval_ms: inputs.eval_elapsed.as_millis(),
        timings: inputs.timings,
    }
}

pub fn emit_eval_progress(
    start_time: std::time::Instant,
    progress: crate::eval::graph::EvalProgress,
    cache_candidates: Option<usize>,
    cutoff_candidates: Option<usize>,
) {
    use crate::eval::graph::{EvalItem, EvalPhase};
    if let Some(label) = &progress.label {
        crate::events::emit_configured(&progress.detail, label);
    }
    let item = progress.item.clone();
    let name = progress.detail.clone();
    let (current, total) = (progress.current, progress.total);
    crate::events::emit_resolve(&crate::events::ResolveReport {
        current,
        total,
        phase: progress.phase,
        detail: progress.detail,
        elapsed_ms: start_time.elapsed().as_millis(),
        cache_candidates,
        cutoff_candidates,
    });
    // Each evaluation item is a job like a derivation: the same start and
    // finish events, so the screen draws both with one mechanism.
    let (active, done) = match progress.phase {
        EvalPhase::ResolvingSources => ("Resolving", "Resolved"),
        EvalPhase::Instantiating => ("Evaluating", "Evaluated"),
        EvalPhase::Evaluated => return,
    };
    match item {
        Some(EvalItem::Started) => crate::events::emit_start(&name, "", active, current, total),
        Some(EvalItem::Finished(hash)) => {
            crate::events::emit_finish(&name, &hash, done, current, total, None, None)
        }
        None => {}
    }
}
