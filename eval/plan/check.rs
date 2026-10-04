//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — plan validators and CAS presence checks

use super::{ExecNode, ExecPlan};
use crate::spec::{ActivePlan, RefPolicy};
use std::path::Path;

pub(super) fn validate_plan(plan: &ExecPlan) -> Result<(), String> {
    for value in [
        &plan.arch,
        &plan.build_host,
        &plan.filter_hash,
        &plan.git_rev,
        &plan.git_dirty,
    ] {
        super::wire::reject_newline(value, "plan header")?;
    }
    super::wire::parse_hex(&plan.filter_hash, 64, "filter-hash")?;
    for target in &plan.targets {
        super::wire::reject_newline(target, "target")?;
    }
    for entry in &plan.bootstrap {
        super::wire::validate_kind(entry.kind, "bootstrap")?;
        super::wire::reject_clean_rel(&entry.rel, "bootstrap")?;
        super::wire::parse_hex(&entry.hash, 64, "bootstrap hash")?;
    }
    let mut keys = std::collections::BTreeSet::new();
    for node in &plan.nodes {
        validate_node(node)?;
        validate_key(&node.name)?;
        if !keys.insert(node.name.as_str()) {
            return Err(format!("plan has two nodes keyed `{}`", node.name));
        }
    }
    for node in &plan.nodes {
        for (target, dep, _) in &node.exec.mounts {
            if !node.deps.contains(dep) {
                return Err(format!(
                    "node `{}` mounts `{target}` from `{dep}`, which is not one of its dependencies",
                    node.name
                ));
            }
        }
        if let Some((key, _)) = &node.exec.substituter
            && !keys.contains(key.as_str())
        {
            return Err(format!(
                "node `{}` substitutes through `{key}`, which is no node of the plan",
                node.name
            ));
        }
        for dep in &node.deps {
            if !keys.contains(dep.as_str()) {
                return Err(format!(
                    "node `{}` depends on `{dep}`, which is no node of the plan",
                    node.name
                ));
            }
        }
    }
    for target in &plan.targets {
        if !keys.contains(target.as_str()) {
            return Err(format!("target `{target}` is no node of the plan"));
        }
    }
    Ok(())
}

/// A node key is a derivation name, or `<name>@<hash>` for a configured node.
fn validate_key(key: &str) -> Result<(), String> {
    match crate::spec::address::parse(key) {
        Ok(crate::spec::address::Address::Plain(_) | crate::spec::address::Address::Hash(..)) => {
            Ok(())
        }
        _ => Err(format!("`{key}` is not a node key")),
    }
}

pub(super) fn validate_node(node: &ExecNode) -> Result<(), String> {
    // A module builder carries its configuration's digest and text, the
    // digest matching the text; no other builder carries either.
    if node.builder == "module" {
        let digest = node.module_config.as_deref().ok_or_else(|| {
            format!("module node `{}` lacks its module-config digest", node.name)
        })?;
        if crate::crypto::sha256::hash_bytes(node.exec.module_config_text.as_bytes()) != digest {
            return Err(format!(
                "module node `{}`: exec-module-config does not match its module-config digest",
                node.name
            ));
        }
    } else if node.module_config.is_some() || !node.exec.module_config_text.is_empty() {
        return Err(format!(
            "node `{}` carries a module configuration but its builder is `{}`",
            node.name, node.builder
        ));
    }
    for value in [&node.name, &node.arch, &node.builder] {
        super::wire::reject_newline(value, "node")?;
    }
    validate_pairs(&node.tools, "tool")?;
    validate_pairs(&node.env, "env")?;
    for (kind, rel, hash) in &node.srcs {
        super::wire::validate_kind(*kind, "src")?;
        super::wire::reject_clean_rel(rel, "src")?;
        super::wire::parse_hex(hash, 64, "src hash")?;
    }
    for (rel, hash) in node
        .srcdirs
        .iter()
        .chain(node.source_roots.iter())
        .chain(node.exec.srcdirs.iter())
        .chain(node.exec.source_roots.iter())
    {
        super::wire::reject_clean_rel(rel, "tree source")?;
        super::wire::parse_hex(hash, 64, "tree hash")?;
    }
    validate_pairs(&node.source_overlays, "source-overlay")?;
    for dep in &node.deps {
        super::wire::reject_newline(dep, "dep")?;
        if dep.contains("sha256:") || dep.contains("/.buildutil/store/") {
            return Err(format!("dep line must carry a name only: `{dep}`"));
        }
    }
    validate_pairs(&node.config, "config")?;
    validate_list(&node.argv, "argv")?;
    validate_list(&node.plan, "plan")?;
    validate_list(&node.outputs, "out")?;
    super::wire::reject_newline(&node.exec.tool, "exec-tool")?;
    validate_list(&node.exec.extra_tools, "exec-extra-tool")?;
    validate_pairs(&node.exec.env, "exec-env")?;
    validate_pairs(&node.exec.srcdirs, "exec-srcdir")?;
    validate_pairs(&node.exec.source_roots, "exec-source-root")?;
    validate_list(&node.exec.argv, "exec-argv")?;
    validate_pairs(&node.exec.stage_deps, "exec-stage-dep")?;
    validate_pairs(&node.exec.copy, "exec-copy")?;
    match &node.exec.allowed_refs {
        RefPolicy::None | RefPolicy::Closure => {}
        RefPolicy::List(items) => validate_list(items, "exec-allowed-ref")?,
    }
    for value in node.exec.shell.iter() {
        super::wire::reject_newline(value, "exec-shell")?;
    }
    for (target, dep, rel) in &node.exec.mounts {
        for value in [target, dep, rel] {
            super::wire::reject_newline(value, "exec-mount")?;
        }
    }
    validate_pairs(&node.exec.version_flags, "exec-version-flag")?;
    if let Some((key, rel)) = &node.exec.substituter {
        super::wire::reject_newline(key, "exec-substituter")?;
        super::wire::reject_newline(rel, "exec-substituter")?;
    }
    validate_active_plan(&node.active_plan)?;
    Ok(())
}

pub(super) fn validate_active_plan(plan: &ActivePlan) -> Result<(), String> {
    for group in &plan.compiles {
        for value in [
            &group.when,
            &group.kind,
            &group.tool,
            &group.scan_dir,
            &group.scan_ext,
            &group.obj,
        ] {
            super::wire::reject_newline(value, "xplan-compile")?;
        }
        validate_list(&group.flags, "xplan-compile-flag")?;
        validate_list(&group.sources, "xplan-compile-source")?;
        validate_list(&group.scan_exclude, "xplan-compile-scan-exclude")?;
    }
    for step in &plan.steps {
        for value in [&step.when, &step.tool, &step.capture] {
            super::wire::reject_newline(value, "xplan-step")?;
        }
        validate_list(&step.argv, "xplan-step-argv")?;
        validate_list(&step.outputs, "xplan-step-output")?;
    }
    Ok(())
}

pub(super) fn validate_pairs(pairs: &[(String, String)], ctx: &str) -> Result<(), String> {
    for (k, v) in pairs {
        super::wire::reject_newline(k, ctx)?;
        super::wire::reject_newline(v, ctx)?;
    }
    Ok(())
}

pub(super) fn validate_list(items: &[String], ctx: &str) -> Result<(), String> {
    for item in items {
        super::wire::reject_newline(item, ctx)?;
    }
    Ok(())
}

pub(super) fn check_blob(
    state_root: &Path,
    hash: &str,
    kind: char,
    ctx: &str,
) -> Result<(), String> {
    super::wire::parse_hex(hash, 64, ctx)?;
    let path = if kind == 'x' {
        crate::state::source_cas_dir(state_root)
            .join(&hash[..2])
            .join(format!("{hash}.x"))
    } else {
        crate::state::source_cas_dir(state_root)
            .join(&hash[..2])
            .join(hash)
    };
    if path.is_file() {
        Ok(())
    } else {
        Err(format!(
            "source CAS missing blob for {ctx}: {}",
            path.display()
        ))
    }
}

pub(super) fn check_tree(state_root: &Path, hash: &str, ctx: &str) -> Result<(), String> {
    super::wire::parse_hex(hash, 64, ctx)?;
    let path = crate::state::source_tree_dir(state_root).join(hash);
    if path.is_file() {
        Ok(())
    } else {
        Err(format!(
            "source CAS missing tree object for {ctx}: {}",
            path.display()
        ))
    }
}
