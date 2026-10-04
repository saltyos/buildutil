// SPDX-License-Identifier: GPL-2.0-only
//! Load selected repository specifications and enforce their published-output boundary.

use super::{DrvSpec, GeneratorOwner, Repository, Spec, kinds};
use std::collections::BTreeMap;

/// The resolver supplies immutable source views, independently of acquisition provenance.
pub(crate) struct Selected {
    pub(crate) repository: Repository,
    pub(crate) source: bool,
    pub(crate) inputs: BTreeMap<String, String>,
}

/// Input names are local; dependency-output tokens bind to the root's one resolution.
pub(crate) fn rename_source_edges(drv: &mut DrvSpec, names: &BTreeMap<String, String>) {
    for dep in &mut drv.deps {
        if let Some(resolved) = names.get(dep) {
            *dep = resolved.clone();
        }
    }
    let rewrite = |text: &mut String| {
        for (local, resolved) in names {
            *text = text
                .replace(&format!("{{dep:{local}}}"), &format!("{{dep:{resolved}}}"))
                .replace(
                    &format!("{{dep-abs:{local}}}"),
                    &format!("{{dep-abs:{resolved}}}"),
                );
        }
    };
    for text in &mut drv.argv {
        rewrite(text);
    }
    for (_, text) in &mut drv.env {
        rewrite(text);
    }
    for pairs in [&mut drv.copy, &mut drv.stage_deps, &mut drv.source_overlays] {
        for (text, _) in pairs {
            rewrite(text);
        }
    }
    for (_, flags) in &mut drv.groups {
        for flag in flags {
            rewrite(flag);
        }
    }
    for group in &mut drv.compiles {
        for text in group.flags.iter_mut().chain(&mut group.sources) {
            rewrite(text);
        }
    }
    for step in &mut drv.steps {
        for text in step.argv.iter_mut().chain(&mut step.outputs) {
            rewrite(text);
        }
        rewrite(&mut step.capture);
    }
    if let super::RefPolicy::List(allowed) = &mut drv.allowed_refs {
        for name in allowed {
            if let Some(resolved) = names.get(name) {
                *name = resolved.clone();
            }
        }
    }
}

pub(crate) fn bind_stage(
    drv: &mut DrvSpec,
    names: &BTreeMap<String, String>,
) -> Result<(), String> {
    let name = super::stages::stage_name(drv);
    drv.stage = Some(
        names
            .get(name)
            .ok_or_else(|| {
                format!(
                    "input derivation `{}` has no owning stage `{name}`",
                    drv.name
                )
            })?
            .clone(),
    );
    Ok(())
}

fn merge<T>(
    into: &mut BTreeMap<String, T>,
    from: BTreeMap<String, T>,
    kind: &str,
) -> Result<(), String> {
    for (name, value) in from {
        if into.insert(name.clone(), value).is_some() {
            return Err(format!(
                "ambiguous {kind} name `{name}` across repository inputs"
            ));
        }
    }
    Ok(())
}

/// Extend the static graph only after the complete input graph passed resolution checks.
pub(crate) fn install(
    mut spec: Spec,
    root_edges: &BTreeMap<String, String>,
    mut selected: BTreeMap<String, Selected>,
) -> Result<Spec, String> {
    for target in root_edges.values() {
        selected
            .get_mut(target)
            .ok_or_else(|| format!("unresolved root input `{target}`"))?
            .repository
            .consumers
            .insert(String::new());
    }
    let edges = selected
        .iter()
        .flat_map(|(name, input)| {
            input
                .inputs
                .values()
                .map(|target| (name.clone(), target.clone()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for (owner, target) in edges {
        selected
            .get_mut(&target)
            .ok_or_else(|| format!("unresolved input `{target}`"))?
            .repository
            .consumers
            .insert(owner);
    }
    let root_sources = root_edges
        .iter()
        .filter_map(|(local, resolved)| {
            selected
                .get(resolved)
                .filter(|input| input.source)
                .map(|_| (local.clone(), resolved.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    if let Some(pending) = &mut spec.pending {
        pending.root_sources = root_sources.clone();
    }
    for drv in spec.drvs.values_mut() {
        rename_source_edges(drv, &root_sources);
    }
    for (local, resolved) in &root_sources {
        if local != resolved {
            spec.drvs.remove(local);
        }
    }
    for (name, input) in &selected {
        if !input.source {
            continue;
        }
        let mut repository = input.repository.clone();
        repository.published.insert(name.clone());
        let mut drv = crate::inputs::source_derivation(name, &repository.content)?;
        drv.repository = Some(repository);
        if spec
            .drvs
            .get(name)
            .is_some_and(|drv| drv.builder != "source-tree")
            || spec.variants.contains_key(name)
        {
            return Err(format!(
                "input `{name}` has an ambiguous published output name"
            ));
        }
        spec.drvs.insert(name.clone(), drv);
    }
    for (name, input) in &selected {
        if input.source {
            continue;
        }
        let source_names = input
            .inputs
            .iter()
            .filter_map(|(local, target)| {
                selected
                    .get(target)
                    .filter(|child| child.source)
                    .map(|_| (local.clone(), target.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let source_contents = input
            .inputs
            .iter()
            .filter_map(|(local, target)| {
                selected
                    .get(target)
                    .filter(|child| child.source)
                    .map(|child| (local.clone(), child.repository.content.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut imported = super::load_impl(
            &input.repository.root,
            &spec.arch,
            &spec.build_host,
            None,
            &[],
            Some(&source_contents),
        )?;
        let mut repository = input.repository.clone();
        repository.source_names = source_names.clone();
        repository
            .published
            .extend(imported.kinds.packages.expose.keys().cloned());
        repository
            .published
            .extend(imported.kinds.checks.expose.keys().cloned());
        repository
            .variants
            .extend(imported.variants.keys().cloned());
        for local in source_names.keys() {
            imported.drvs.remove(local);
        }
        for drv in imported.drvs.values_mut() {
            rename_source_edges(drv, &source_names);
            drv.repository = Some(repository.clone());
        }
        for variant in imported.variants.values_mut() {
            if let Some(target) = source_names.get(&variant.base) {
                variant.base = target.clone();
            }
        }
        for provider in imported.tool_providers.values_mut() {
            if let Some(target) = source_names.get(&provider.derivation) {
                provider.derivation = target.clone();
            }
        }
        for stage in imported.stages.values_mut() {
            for provider in stage.tools.values_mut() {
                if let Some(target) = source_names.get(&provider.derivation) {
                    provider.derivation = target.clone();
                }
            }
            for mount in &mut stage.mounts {
                if let Some(target) = source_names.get(&mount.derivation) {
                    mount.derivation = target.clone();
                }
            }
        }
        for stage in ["default", "bootstrap"] {
            imported
                .stages
                .entry(stage.into())
                .or_insert_with(|| super::StageSpec {
                    name: stage.into(),
                    tools: BTreeMap::new(),
                    default_tools: Vec::new(),
                    shell: None,
                    mounts: Vec::new(),
                    substituter: None,
                });
        }
        let stage_names = imported
            .stages
            .keys()
            .map(|stage| (stage.clone(), format!("input-{name}-{stage}")))
            .collect::<BTreeMap<_, _>>();
        let mut owned_stages = BTreeMap::new();
        for (stage, mut value) in imported.stages {
            value.name = stage_names[&stage].clone();
            for (alias, provider) in &imported.tool_providers {
                value
                    .tools
                    .entry(alias.clone())
                    .or_insert_with(|| provider.clone());
            }
            owned_stages.insert(value.name.clone(), value);
        }
        for drv in imported.drvs.values_mut() {
            bind_stage(drv, &stage_names)?;
        }
        let pending = imported
            .pending
            .take()
            .ok_or("input specification lost its generation context")?;
        let destination = spec
            .pending
            .as_mut()
            .ok_or("root specification lost its input-resolution context")?;
        for generator in imported.generators.keys() {
            destination.owners.insert(
                generator.clone(),
                GeneratorOwner {
                    repository: repository.clone(),
                    arch_table: pending.arch_table.clone(),
                    build_host_table: pending.build_host_table.clone(),
                    source_names: source_names.clone(),
                    stages: stage_names.clone(),
                },
            );
        }
        destination
            .input_checks
            .push((repository, pending.root_doc));
        for (kind, table) in [
            (kinds::Kind::Packages, imported.kinds.packages),
            (kinds::Kind::Checks, imported.kinds.checks),
        ] {
            for (published, origin) in table.expose {
                let already = match kind {
                    kinds::Kind::Packages => spec.kinds.packages.expose.contains_key(&published),
                    kinds::Kind::Checks => spec.kinds.checks.expose.contains_key(&published),
                };
                if !already {
                    spec.kinds
                        .expose(kind, &published, &format!("input {name}: {origin}"))?;
                }
            }
        }
        merge(&mut spec.drvs, imported.drvs, "derivation output")?;
        merge(
            &mut spec.variants,
            imported.variants,
            "configuration variant",
        )?;
        merge(&mut spec.flagsets, imported.flagsets, "flagset")?;
        merge(&mut spec.modules, imported.modules, "module")?;
        merge(&mut spec.generators, imported.generators, "generator")?;
        merge(&mut spec.stages, owned_stages, "stage")?;
    }
    super::validate_variant_cycles(&spec.variants)?;
    super::validate_generator_closures(&spec)?;
    validate_visibility(&spec)?;
    Ok(spec)
}

fn visible(spec: &Spec, owner: &str, edge: &str) -> bool {
    let base = super::variant_base(&spec.variants, edge);
    let Some(target) = spec.drvs.get(base) else {
        return true;
    };
    match &target.repository {
        None => owner.is_empty(),
        Some(target) => {
            target.name == owner
                || (target.consumers.contains(owner) && target.published.contains(edge))
        }
    }
}

/// A globally unambiguous name does not grant access to a transitive or private output.
pub(crate) fn validate_visibility(spec: &Spec) -> Result<(), String> {
    super::validate_variant_cycles(&spec.variants)?;
    for drv in spec.drvs.values() {
        let owner = drv
            .repository
            .as_ref()
            .map(|owner| owner.name.as_str())
            .unwrap_or("");
        for edge in drv.deps.iter().cloned().chain(
            std::iter::once(&drv.tool)
                .chain(&drv.extra_tools)
                .filter_map(|tool| {
                    spec.declared_tool(drv, tool)
                        .map(|provider| provider.derivation.clone())
                }),
        ) {
            if !visible(spec, owner, &edge) {
                return Err(format!(
                    "derivation `{}` uses `{edge}` outside its own repository and declared input publications",
                    drv.name
                ));
            }
        }
    }
    for variant in spec.variants.values() {
        let owner = spec
            .drvs
            .values()
            .filter_map(|drv| drv.repository.as_ref())
            .find(|owner| owner.variants.contains(&variant.name))
            .map(|owner| owner.name.as_str())
            .unwrap_or("");
        if !visible(spec, owner, &variant.base) {
            return Err(format!(
                "variant `{}` uses private input output `{}`",
                variant.name, variant.base
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dependency_supplies_the_whole_source_projection_without_checkout_reads() {
        let mut drv = DrvSpec::new("compiler", "script", "sh");
        drv.deps = vec!["compiler-source".into()];
        drv.source_roots = vec!["compiler".into()];
        drv.source_overlays = vec![("{dep:compiler-source}/source".into(), "compiler".into())];
        assert!(drv.overlay_root("compiler"));
        assert_eq!(drv.source_root_key("compiler"), "overlay-root:compiler");
        assert!(!drv.overlay_root("compiler/vendor"));
    }

    #[test]
    fn local_source_edges_bind_one_shared_resolution() {
        let mut drv = DrvSpec::new("compiler", "script", "sh");
        drv.deps = vec!["library".into()];
        drv.argv = vec![
            "{dep:library}/source".into(),
            "{dep-abs:library}/source".into(),
        ];
        rename_source_edges(
            &mut drv,
            &BTreeMap::from([("library".into(), "shared-source".into())]),
        );
        assert_eq!(drv.deps, ["shared-source"]);
        assert_eq!(
            drv.argv,
            [
                "{dep:shared-source}/source",
                "{dep-abs:shared-source}/source"
            ]
        );
    }

    #[test]
    fn input_specifications_keep_their_own_sources_and_only_publish_exposed_outputs() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "buildutil-input-spec-{}-{stamp}",
            std::process::id()
        ));
        let input = root.join("captured");
        std::fs::create_dir_all(root.join("consumer")).unwrap();
        std::fs::create_dir_all(input.join("library")).unwrap();
        std::fs::write(root.join("buildutil.toml"), "[buildutil]\nsubsystems = [\"consumer\"]\n[arch.x86_64]\n[input.api]\nurl = \"https://example.org/api\"\n").unwrap();
        std::fs::write(root.join("consumer/buildutil.toml"), "[derivation.consumer]\nbuilder = \"script\"\ntool = \"sh\"\ndeps = [\"headers\"]\nsources = [\"src/main.c\"]\noutputs = [\"program\"]\nargv = [\"{dep:headers}/include/api.h\"]\n").unwrap();
        std::fs::write(
            input.join("buildutil.toml"),
            "[buildutil]\nsubsystems = [\"library\"]\n[arch.x86_64]\n",
        )
        .unwrap();
        std::fs::write(input.join("library/buildutil.toml"), "[packages]\nexpose = [\"headers\"]\n[derivation.headers]\nbuilder = \"script\"\ntool = \"sh\"\nsources = [\"src/api.h\"]\noutputs = [\"include/\"]\n[derivation.private-helper]\nbuilder = \"script\"\ntool = \"sh\"\noutputs = [\"private\"]\n").unwrap();
        let initial = super::super::load(&root, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
        let repository = Repository {
            name: "api".into(),
            root: input.clone(),
            content: format!("tree:{}", "1".repeat(64)),
            rev: "2".repeat(40),
            dirty: false,
            consumers: Default::default(),
            published: Default::default(),
            variants: Default::default(),
            source_names: Default::default(),
        };
        let installed = install(
            initial,
            &BTreeMap::from([("api".into(), "api".into())]),
            BTreeMap::from([(
                "api".into(),
                Selected {
                    repository,
                    source: false,
                    inputs: Default::default(),
                },
            )]),
        )
        .unwrap();
        let mut complete = super::super::finish_generation(installed, &[]).unwrap();
        assert_eq!(complete.drvs["consumer"].sources, ["src/main.c"]);
        assert!(complete.drvs["consumer"].repository.is_none());
        assert_eq!(complete.drvs["headers"].sources, ["src/api.h"]);
        let owner = complete.drvs["headers"].repository.as_ref().unwrap();
        assert_eq!(owner.root, input);
        assert_eq!(
            complete
                .source_path(&owner.source_key("src/api.h"))
                .unwrap(),
            input.join("src/api.h")
        );
        complete.drvs.get_mut("consumer").unwrap().deps = vec!["private-helper".into()];
        assert!(
            validate_visibility(&complete)
                .unwrap_err()
                .contains("outside its own repository")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
