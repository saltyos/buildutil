// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — read-only derivation-graph queries: why-depends/graph/explain/log.
//!
//! Words resolve through the query scope: `[packages]` names and groups,
//! names exposed in `[checks]`, and `drv:<name>` for any derivation.

use super::{Args, Context, open_context, positional};

/// Resolve one word to one address; a group names several and is refused.
fn one_target(ctx: &Context, args: &Args, word: &str) -> Result<String, String> {
    let targets = super::resolve_targets(&ctx.spec, args, &[word.to_string()])?;
    match targets.as_slice() {
        [one] => Ok(one
            .trim_start_matches(crate::spec::kinds::OPTIONAL_PREFIX)
            .to_string()),
        _ => Err(format!("`{word}` names more than one derivation")),
    }
}

/// The derivation name an address configures.
fn derivation_of(ctx: &Context, address: &str) -> Result<String, String> {
    let parsed = crate::spec::address::parse(address)?;
    Ok(crate::spec::variant_base(&ctx.spec.variants, parsed.name()).to_string())
}

pub fn cmd_why_depends(args: &Args) -> Result<i32, String> {
    let ctx = open_context(args)?;
    let ts = positional(args);
    let from = *ts
        .first()
        .ok_or("why-depends: <target> <dep> [--runtime]")?;
    let to = *ts.get(1).ok_or("why-depends: name a <dep> target")?;
    let from = derivation_of(&ctx, &one_target(&ctx, args, from)?)?;
    let to = derivation_of(&ctx, &one_target(&ctx, args, to)?)?;
    let runtime = args.targets.iter().any(|a| a == "--runtime");
    let domain = match &args.domain {
        Some(group) => Some(super::domain_closure(&ctx.spec, group)?),
        None => None,
    };
    crate::eval::observe::why_depends(&ctx.spec, &ctx.store, &from, &to, runtime, domain.as_ref())
}

pub fn cmd_graph(args: &Args) -> Result<i32, String> {
    let ctx = open_context(args)?;
    let roots = match positional(args).first() {
        Some(word) => Some(super::resolve_targets(&ctx.spec, args, &[word.to_string()])?),
        None => None,
    };
    let domain = match &args.domain {
        Some(group) => Some(super::domain_closure(&ctx.spec, group)?),
        None => None,
    };
    crate::eval::observe::graph_dot(&ctx.spec, roots.as_deref(), domain.as_ref())
}

pub fn cmd_explain(args: &Args) -> Result<i32, String> {
    let mut ctx = open_context(args)?;
    let word = positional(args)
        .first()
        .copied()
        .ok_or("explain: name a target")?
        .to_string();
    let target = one_target(&ctx, args, &word)?;
    let git_state = ctx.git_state().clone();
    crate::eval::observe::explain(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &ctx.store,
        &target,
        &git_state,
    )
}

pub fn cmd_log(args: &Args) -> Result<i32, String> {
    let mut ctx = open_context(args)?;
    let word = positional(args)
        .first()
        .copied()
        .ok_or("log: name a target")?
        .to_string();
    let target = one_target(&ctx, args, &word)?;
    let git_state = ctx.git_state().clone();
    crate::eval::observe::log(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &ctx.store,
        &target,
        &git_state,
    )
}
