//! SPDX-License-Identifier: GPL-2.0-only
//! Lower required validation into the ordinary, identity-bearing build graph.
//!
//! Before checks are dependencies. After checks execute in the subject's DAG,
//! before registration: an unchecked artifact never acquires a realization
//! digest, so neither substitution, consumers nor latest publication can use it.
//! There is deliberately no executor-only policy or second plan interpretation.

use super::{DrvSpec, tables, toml};
use std::collections::{BTreeMap, BTreeSet};

fn within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn extend_unique<T: PartialEq + Clone>(into: &mut Vec<T>, from: &[T]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

fn output_overlap(left: &str, right: &str) -> bool {
    let left = left.trim_end_matches('/');
    let right = right.trim_end_matches('/');
    within(left, right) || within(right, left)
}

pub(super) fn apply(doc: &toml::Doc, drvs: &mut BTreeMap<String, DrvSpec>) -> Result<(), String> {
    apply_for(doc, drvs, None)
}

pub(super) fn apply_for(
    doc: &toml::Doc,
    drvs: &mut BTreeMap<String, DrvSpec>,
    owner: Option<&str>,
) -> Result<(), String> {
    let rules: Vec<_> = doc.tables_under(&["required-check"]).collect();
    for table in &rules {
        if table.path.len() != 2 {
            return Err("required-check: expected a named policy table".into());
        }
    }
    let mut validators = BTreeSet::new();
    for table in &rules {
        validators.insert(tables::need_str(table, "derivation", "required-check")?);
    }
    let original = drvs.clone();
    for table in rules {
        let context = format!("required-check.{}", table.path[1]);
        for entry in &table.entries {
            if !["derivation", "artifacts", "source-scope", "phase"].contains(&entry.key.as_str()) {
                return Err(format!("{context}: unknown key `{}`", entry.key));
            }
        }
        let validator = tables::need_str(table, "derivation", &context)?;
        let check = original
            .get(&validator)
            .ok_or_else(|| format!("{context}: unknown check derivation `{validator}`"))?;
        // A successful build of a validator with its verdict step disabled is
        // not evidence. This applies equally to prerequisite and inline checks.
        if check.steps.iter().any(|step| !step.when.is_empty()) {
            return Err(format!(
                "{context}: required check steps cannot be conditionally skipped"
            ));
        }
        let phase = tables::need_str(table, "phase", &context)?;
        if phase != "before" && phase != "after" {
            return Err(format!("{context}: phase must be before or after"));
        }
        let artifacts = tables::opt_str_list(table, "artifacts", &context)?;
        let roots = tables::opt_str_list(table, "source-scope", &context)?;
        if artifacts.is_empty() && roots.is_empty() {
            return Err(format!("{context}: declare artifacts or source-scope"));
        }
        for root in &roots {
            if root.is_empty()
                || root.starts_with('/')
                || root
                    .split('/')
                    .any(|part| part.is_empty() || part == ".." || part == ".")
            {
                return Err(format!(
                    "{context}: source scope must be a normalized relative path: {root}"
                ));
            }
        }
        for artifact in &artifacts {
            if !original.contains_key(artifact) || validators.contains(artifact) {
                return Err(format!("{context}: invalid subject `{artifact}`"));
            }
        }
        let mut matched = false;
        for (name, subject) in drvs.iter_mut() {
            if validators.contains(name) {
                continue;
            }
            let same_owner = subject.repository.as_ref().map(|repo| repo.name.as_str()) == owner;
            let source_match = same_owner
                && original[name]
                    .sources
                    .iter()
                    .chain(&original[name].src_dirs)
                    .chain(&original[name].source_roots)
                    .any(|path| {
                        roots
                            .iter()
                            .any(|root| within(path, root) || within(root, path))
                    });
            if !artifacts.contains(name) && !source_match {
                continue;
            }
            matched = true;
            if !check.when.is_empty() && check.when != subject.when {
                return Err(format!(
                    "{context}: `{name}` can be enabled while `{validator}` is disabled"
                ));
            }
            if phase == "before" {
                extend_unique(&mut subject.deps, &[validator.clone()]);
                continue;
            }
            if check.repository.as_ref().map(|repo| &repo.name)
                != subject.repository.as_ref().map(|repo| &repo.name)
            {
                return Err(format!(
                    "{context}: an after check and its subject must own the same source view"
                ));
            }
            if subject.builder != "script-dag"
                || check.builder != "script-dag"
                || check.steps.is_empty()
                || !check.compiles.is_empty()
                || !check.copy.is_empty()
                || !check.stage_deps.is_empty()
                || !check.source_overlays.is_empty()
                || !check.groups.is_empty()
                || !check.argv.is_empty()
                || check.bootstrap != subject.bootstrap
                || check.native_frontend != subject.native_frontend
                || check.host_tool != subject.host_tool
                || check.allowed_refs != subject.allowed_refs
            {
                return Err(format!(
                    "{context}: after checks require a script-dag subject and a steps-only validator with the same tool grade, host execution mode and reference policy"
                ));
            }
            if !check.deps.contains(name) {
                return Err(format!(
                    "{context}: after check must declare its subject `{name}` as a dependency"
                ));
            }
            let translate = |text: &str| {
                text.replace(&format!("{{dep:{name}}}"), "{out}")
                    .replace(&format!("{{dep-abs:{name}}}"), "{out-abs}")
            };
            // A steps-only validator has no compile objects of its own. Do
            // not accidentally bind its token to the subject's compile fanout.
            if check
                .steps
                .iter()
                .flat_map(|step| &step.argv)
                .any(|arg| arg.contains("{objs}"))
            {
                return Err(format!(
                    "{context}: after check cannot reference subject compile objects with {{objs}}"
                ));
            }
            extend_unique(&mut subject.sources, &check.sources);
            extend_unique(&mut subject.src_dirs, &check.src_dirs);
            extend_unique(&mut subject.source_roots, &check.source_roots);
            extend_unique(&mut subject.extra_tools, &check.extra_tools);
            extend_unique(&mut subject.extra_tools, &[check.tool.clone()]);
            for step in &check.steps {
                extend_unique(&mut subject.extra_tools, &[step.tool.clone()]);
                let mut step = step.clone();
                step.argv = step.argv.iter().map(|arg| translate(arg)).collect();
                step.outputs = step.outputs.iter().map(|arg| translate(arg)).collect();
                step.capture = translate(&step.capture);
                for output in &step.outputs {
                    if subject
                        .steps
                        .iter()
                        .flat_map(|step| &step.outputs)
                        .any(|existing| output_overlap(existing, output))
                    {
                        return Err(format!(
                            "{context}: check step output collides with subject step output `{output}`"
                        ));
                    }
                }
                subject.steps.push(step);
            }
            for output in &check.outputs {
                if subject
                    .outputs
                    .iter()
                    .any(|existing| output_overlap(existing, output))
                {
                    return Err(format!(
                        "{context}: check output collides with subject output `{output}`"
                    ));
                }
                subject.outputs.push(output.clone());
            }
            for (key, value) in &check.env {
                let value = translate(value);
                if subject
                    .env
                    .iter()
                    .any(|(existing, contents)| existing == key && contents != &value)
                {
                    return Err(format!("{context}: conflicting environment key `{key}`"));
                }
                extend_unique(&mut subject.env, &[(key.clone(), value)]);
            }
            let deps: Vec<_> = check
                .deps
                .iter()
                .filter(|dep| *dep != name)
                .cloned()
                .collect();
            extend_unique(&mut subject.deps, &deps);
            tables::validate_source_projection(subject, &context)?;
        }
        if !matched {
            return Err(format!("{context}: policy matches no subjects"));
        }
    }
    // Reject policy-induced cycles at loading, including an indirect path from
    // a prerequisite back to its subject. No scheduler or backend may bypass it.
    fn visit(
        name: &str,
        drvs: &BTreeMap<String, DrvSpec>,
        active: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if done.contains(name) {
            return Ok(());
        }
        if !active.insert(name.to_string()) {
            return Err(format!(
                "required checks introduce a dependency cycle at `{name}`"
            ));
        }
        if let Some(drv) = drvs.get(name) {
            for dep in &drv.deps {
                visit(dep, drvs, active, done)?;
            }
        }
        active.remove(name);
        done.insert(name.to_string());
        Ok(())
    }
    let mut done = BTreeSet::new();
    for name in drvs.keys() {
        visit(name, drvs, &mut BTreeSet::new(), &mut done)?;
    }
    Ok(())
}

/// Every required check names a `[checks]` entry, so the check a policy
/// demands is also the one `buildutil check` runs by name.
pub(super) fn validate_kinds(doc: &toml::Doc, kinds: &super::kinds::Kinds) -> Result<(), String> {
    for table in doc.tables_under(&["required-check"]) {
        let context = format!("required-check.{}", table.path[1]);
        let validator = tables::need_str(table, "derivation", &context)?;
        if !kinds.is_exposed(super::kinds::Kind::Checks, &validator) {
            return Err(format!(
                "{context}: `{validator}` is not exposed in [checks]"
            ));
        }
    }
    Ok(())
}
