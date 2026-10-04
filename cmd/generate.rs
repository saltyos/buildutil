// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the generation phase, between the static specification and full
//! evaluation.
//!
//! A pending specification declares generators. Each is an ordinary
//! derivation of the static graph — its module's store build, its declared
//! inputs — whose output is its declarations, so the store caches it by
//! the generator's identity and its inputs' hash like any derivation. The
//! phase evaluates the generators' closure, realizes what the store lacks
//! through the invocation's backend, reads each generator's declarations
//! and merges them atomically. A generator that fails, or is cancelled,
//! publishes nothing: the evaluation fails, and no earlier output stands
//! in for it.

use super::{Args, Context, executor_runtime_flags};
use std::sync::Arc;

/// Run the generation phase when `ctx`'s specification is pending, leaving
/// the complete specification in its place.
pub(crate) fn run(ctx: &mut Context, args: &Args) -> Result<(), String> {
    if !ctx.spec.is_pending() {
        return Ok(());
    }
    if ctx.spec.generators.is_empty() {
        ctx.spec = Arc::new(crate::spec::finish_generation((*ctx.spec).clone(), &[])?);
        return Ok(());
    }
    let targets = crate::spec::generator_closure(&ctx.spec);
    let git_state = ctx.git_state().clone();
    let cached = super::evaluate_plan_with_progress(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &targets,
        &ctx.state_root,
        !args.no_source_cache,
        git_state,
        |_| {},
    )?;
    let evaluated = cached.evaluated;
    let missing = evaluated
        .dry_resolve(&ctx.store)
        .values()
        .any(|node| node.digest.is_none());
    if missing {
        realize(ctx, args, &cached.plan, &cached.hash)?;
    }
    let resolved = evaluated.dry_resolve(&ctx.store);
    let mut generated = Vec::new();
    for generator in ctx.spec.generators.values() {
        let key = evaluated
            .roots
            .iter()
            .find(|(request, _)| request == &generator.derivation)
            .map(|(_, key)| key)
            .ok_or_else(|| {
                format!(
                    "generator `{}` is disabled by configuration; a generator must always run",
                    generator.name
                )
            })?;
        let node = resolved
            .get(key)
            .filter(|node| node.digest.is_some())
            .ok_or_else(|| {
                format!(
                    "generator `{}` failed; evaluation stops without its declarations",
                    generator.name
                )
            })?;
        let path = ctx
            .store
            .root
            .join(&node.store_name)
            .join(crate::sdk_wire::GENERATED_FILE);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "generator `{}`: cannot read {}: {e}",
                generator.name,
                path.display()
            )
        })?;
        generated.push((generator.name.clone(), text));
    }
    let spec = (*ctx.spec).clone();
    ctx.spec = Arc::new(crate::spec::finish_generation(spec, &generated)?);
    Ok(())
}

fn realize(
    ctx: &Context,
    args: &Args,
    plan: &crate::eval::plan::ExecPlan,
    plan_hash: &str,
) -> Result<(), String> {
    let code = match ctx.backend {
        crate::host::ExecBackend::Docker | crate::host::ExecBackend::Nerdctl => {
            crate::host::container::run_plan_in_container(
                &ctx.repo_root,
                &ctx.state_root,
                &ctx.build_host,
                &ctx.backend,
                ctx.spec.executor_image.as_ref(),
                plan_hash,
                None,
                &executor_runtime_flags(args),
            )?
        }
        crate::host::ExecBackend::LocalLinux => {
            let sandbox = crate::exec::sandbox::platform_sandbox();
            let builders = crate::full_builders();
            let logger = crate::log::Logger::new(args.verbose);
            let outcome = crate::exec::pool::realize(
                plan,
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
            if outcome.failed.is_empty() { 0 } else { 1 }
        }
        crate::host::ExecBackend::Remote => {
            return Err("remote backend requires a configured remote builder".to_string());
        }
        crate::host::ExecBackend::Wsl => {
            return Err("the wsl backend evaluates inside WSL; generation runs there".to_string());
        }
    };
    if code != 0 {
        return Err(
            "the generation phase failed; evaluation stops without generated declarations"
                .to_string(),
        );
    }
    Ok(())
}
