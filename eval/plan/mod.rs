//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — evaluated execution plan serialization
//!
//! Nodes are configured-node keys (`<name>` or `<name>@<hash>`); `dep:` and
//! `target:` lines name keys. `render(load(p)) == p` over the conformance
//! corpus; any byte change here is a wire-format break and a format bump.

use crate::eval::graph::{Evaluated, Recipe};
use crate::spec::{ActivePlan, DrvSpec, RefPolicy, Spec, address};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(crate) mod bootstrap;
pub(super) mod check;
pub(super) mod wire;

#[cfg(test)]
mod tests;

const PLAN_HEADER: &str = "buildutil-plan";
pub(crate) const PLAN_FORMAT: &str = "2";

pub fn container_executor_derivation(
    bootstrap_hash: &str,
    build_host: &str,
    platform: &str,
    image_id: &str,
) -> crate::store::derivation::Derivation {
    crate::store::derivation::Derivation::seal(crate::store::derivation::DrvParts {
        name: "buildutil-realize-executor".to_string(),
        arch: build_host.to_string(),
        builder: "container-executor".to_string(),
        tools: Vec::new(),
        env: vec![
            (
                "BUILDUTIL_EXECUTOR_IMAGE_ID".to_string(),
                image_id.to_string(),
            ),
            (
                "BUILDUTIL_EXECUTOR_PLATFORM".to_string(),
                platform.to_string(),
            ),
        ],
        srcs: vec![("bootstrap-closure".to_string(), bootstrap_hash.to_string())],
        srcdirs: Vec::new(),
        source_roots: Vec::new(),
        source_overlays: Vec::new(),
        copy: Vec::new(),
        stage_deps: Vec::new(),
        allowed_refs: RefPolicy::None,
        deps: Vec::new(),
        config: Vec::new(),
        module_config: None,
        argv: vec!["realize-only".to_string()],
        plan: Vec::new(),
        outputs: vec!["buildutil-realize".to_string()],
    })
}

#[derive(Debug, Clone)]
pub struct BootstrapEntry {
    pub kind: char,
    pub rel: String,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct ExecMeta {
    pub tool: String,
    pub extra_tools: Vec<String>,
    pub env: Vec<(String, String)>,
    pub srcdirs: Vec<(String, String)>,
    pub source_roots: Vec<(String, String)>,
    pub argv: Vec<String>,
    pub stage_deps: Vec<(String, String)>,
    pub copy: Vec<(String, String)>,
    pub host_tool: bool,
    pub allowed_refs: RefPolicy,
    /// The staged tool bound at `/bin/sh`, from the node's stage.
    pub shell: Option<String>,
    /// Directories bound read-only at fixed paths: (target path, dependency
    /// key, provider-relative directory), from the node's stage.
    pub mounts: Vec<(String, String, String)>,
    /// Version-query arguments of tools that declare one: (tool, flag).
    pub version_flags: Vec<(String, String)>,
    /// The tool that substitutes this node's realization: (provider node
    /// key, provider-relative path). Present only when the provider is in
    /// the node's own closure, so it is realized before the node.
    pub substituter: Option<(String, String)>,
    /// A module builder's effective module configuration as canonical JSON;
    /// its digest is the node's `module-config` identity line.
    pub module_config_text: String,
}

#[derive(Debug, Clone)]
pub struct ExecNode {
    /// The node key: the derivation name, or `<name>@<hash>` for a
    /// configured node.
    pub name: String,
    pub arch: String,
    pub builder: String,
    pub tools: Vec<(String, String)>,
    pub env: Vec<(String, String)>,
    pub srcs: Vec<(char, String, String)>,
    pub srcdirs: Vec<(String, String)>,
    pub source_roots: Vec<(String, String)>,
    pub source_overlays: Vec<(String, String)>,
    pub deps: Vec<String>,
    pub config: Vec<(String, String)>,
    /// A module builder's module-configuration digest.
    pub module_config: Option<String>,
    pub argv: Vec<String>,
    pub plan: Vec<String>,
    pub outputs: Vec<String>,
    pub exec: ExecMeta,
    pub active_plan: ActivePlan,
}

#[derive(Debug, Clone)]
pub struct ExecPlan {
    pub arch: String,
    pub build_host: String,
    pub filter_hash: String,
    pub git_rev: String,
    pub git_dirty: String,
    pub targets: Vec<String>,
    pub bootstrap: Vec<BootstrapEntry>,
    pub nodes: Vec<ExecNode>,
}

impl ExecPlan {
    pub fn bootstrap_digest(&self) -> String {
        let mut block = String::new();
        for entry in &self.bootstrap {
            writeln!(
                &mut block,
                "bootstrap: {} {} sha256:{}",
                entry.kind, entry.rel, entry.hash
            )
            .expect("write to string");
        }
        crate::crypto::sha256::hash_bytes(block.as_bytes())
    }

    pub fn bootstrap_hash(&self) -> String {
        self.bootstrap_digest()[..32].to_string()
    }

    pub fn recipes(&self) -> BTreeMap<String, Recipe> {
        self.nodes
            .iter()
            .map(|node| (node.name.clone(), node.recipe()))
            .collect()
    }

    pub fn node(&self, name: &str) -> Option<&ExecNode> {
        self.nodes.iter().find(|node| node.name == name)
    }
}

impl ExecNode {
    /// Whether this node belongs to the self-tool class: it compiles with
    /// the ambient compiler bootstrap.ninja captured. Only such a node runs
    /// at audit grade, and it is never signed or substituted.
    pub fn is_self_tool(&self) -> bool {
        self.tools
            .iter()
            .any(|(_, locator)| locator.starts_with("host-sha256:"))
    }

    /// The derivation name the node's preimage carries.
    pub fn base_name(&self) -> &str {
        address::base_name(&self.name)
    }

    pub fn recipe(&self) -> Recipe {
        Recipe {
            name: self.base_name().to_string(),
            arch: self.arch.clone(),
            builder: self.builder.clone(),
            tools: self.tools.clone(),
            env: self.env.clone(),
            srcs: self.srcs.clone(),
            srcdirs: self.srcdirs.clone(),
            source_roots: self.source_roots.clone(),
            source_overlays: self.source_overlays.clone(),
            copy: self.exec.copy.clone(),
            stage_deps: self.exec.stage_deps.clone(),
            allowed_refs: self.exec.allowed_refs.clone(),
            dep_names: self.deps.clone(),
            config: self.config.clone(),
            module_config: self.module_config.clone(),
            argv: self.argv.clone(),
            plan: self.plan.clone(),
            outputs: self.outputs.clone(),
        }
    }
}

pub fn render(plan: &ExecPlan) -> Result<String, String> {
    check::validate_plan(plan)?;
    let mut out = String::new();
    writeln!(&mut out, "{PLAN_HEADER}").expect("write to string");
    writeln!(&mut out, "format: {PLAN_FORMAT}").expect("write to string");
    writeln!(&mut out, "arch: {}", plan.arch).expect("write to string");
    writeln!(&mut out, "build-host: {}", plan.build_host).expect("write to string");
    writeln!(&mut out, "filter: buildutilignore-v1").expect("write to string");
    writeln!(&mut out, "filter-hash: {}", plan.filter_hash).expect("write to string");
    writeln!(&mut out, "git-rev: {}", plan.git_rev).expect("write to string");
    writeln!(&mut out, "git-dirty: {}", plan.git_dirty).expect("write to string");
    for target in &plan.targets {
        writeln!(&mut out, "target: {target}").expect("write to string");
    }
    for entry in &plan.bootstrap {
        writeln!(
            &mut out,
            "bootstrap: {} {} sha256:{}",
            entry.kind, entry.rel, entry.hash
        )
        .expect("write to string");
    }
    for node in &plan.nodes {
        writeln!(&mut out, "drv {}", node.name).expect("write to string");
        wire::line(&mut out, "arch", &node.arch);
        wire::line(&mut out, "builder", &node.builder);
        for (k, v) in &node.tools {
            wire::line(&mut out, "tool", &format!("{k}={v}"));
        }
        for (k, v) in &node.env {
            wire::line(&mut out, "env", &format!("{k}={v}"));
        }
        for (kind, rel, hash) in &node.srcs {
            wire::line(&mut out, "src", &format!("{kind} {rel} sha256:{hash}"));
        }
        for (rel, hash) in &node.srcdirs {
            wire::line(&mut out, "srcdir", &format!("{rel} tree:{hash}"));
        }
        for (rel, hash) in &node.source_roots {
            wire::line(&mut out, "source-root", &format!("{rel} tree:{hash}"));
        }
        for (src, dest) in &node.source_overlays {
            wire::line(&mut out, "source-overlay", &format!("{src}={dest}"));
        }
        for dep in &node.deps {
            wire::line(&mut out, "dep", dep);
        }
        for (k, v) in &node.config {
            wire::line(&mut out, "config", &format!("{k}={v}"));
        }
        if let Some(digest) = &node.module_config {
            wire::line(&mut out, "module-config", &format!("sha256:{digest}"));
        }
        for arg in &node.argv {
            wire::line(&mut out, "argv", arg);
        }
        for plan_line in &node.plan {
            wire::line(&mut out, "plan", plan_line);
        }
        for output in &node.outputs {
            wire::line(&mut out, "out", output);
        }
        wire::line(&mut out, "exec-tool", &node.exec.tool);
        for tool in &node.exec.extra_tools {
            wire::line(&mut out, "exec-extra-tool", tool);
        }
        for (k, v) in &node.exec.env {
            wire::line(&mut out, "exec-env", &format!("{k}={v}"));
        }
        for (rel, hash) in &node.exec.srcdirs {
            wire::line(&mut out, "exec-srcdir", &format!("{rel} tree:{hash}"));
        }
        for (rel, hash) in &node.exec.source_roots {
            wire::line(&mut out, "exec-source-root", &format!("{rel} tree:{hash}"));
        }
        for arg in &node.exec.argv {
            wire::line(&mut out, "exec-argv", arg);
        }
        for (src, dest) in &node.exec.stage_deps {
            wire::line(&mut out, "exec-stage-dep", &format!("{src}={dest}"));
        }
        for (src, dest) in &node.exec.copy {
            wire::line(&mut out, "exec-copy", &format!("{src}={dest}"));
        }
        wire::line(
            &mut out,
            "exec-host-tool",
            if node.exec.host_tool { "true" } else { "false" },
        );
        if !node.exec.module_config_text.is_empty() {
            wire::line(
                &mut out,
                "exec-module-config",
                &node.exec.module_config_text,
            );
        }
        match &node.exec.allowed_refs {
            RefPolicy::None => wire::line(&mut out, "exec-allowed-refs", "none"),
            RefPolicy::Closure => wire::line(&mut out, "exec-allowed-refs", "closure"),
            RefPolicy::List(items) => {
                for name in items {
                    wire::line(&mut out, "exec-allowed-ref", name);
                }
            }
        }
        if let Some(shell) = &node.exec.shell {
            wire::line(&mut out, "exec-shell", shell);
        }
        for (target, dep, rel) in &node.exec.mounts {
            wire::line(&mut out, "exec-mount", &format!("{target}={dep}:{rel}"));
        }
        for (tool, flag) in &node.exec.version_flags {
            wire::line(&mut out, "exec-version-flag", &format!("{tool}={flag}"));
        }
        if let Some((key, rel)) = &node.exec.substituter {
            wire::line(&mut out, "exec-substituter", &format!("{key}:{rel}"));
        }
        wire::render_xplan(&mut out, &node.active_plan);
        writeln!(&mut out, "end").expect("write to string");
    }
    Ok(out)
}

pub fn load(path: &Path) -> Result<ExecPlan, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read plan {}: {}", path.display(), e))?;
    parse(&text)
}

/// Load a plan only after its full bytes reproduce the content-addressed name
/// selected by the dispatcher.  Callers acquire the plan lease before this
/// function so GC cannot replace the check/use boundary with absence.
pub fn load_attested(path: &Path, expected_hash32: &str) -> Result<ExecPlan, String> {
    if expected_hash32.len() != 32 || !expected_hash32.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("invalid expected plan hash `{expected_hash32}`"));
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("cannot read plan {}: {}", path.display(), e))?;
    let actual = crate::crypto::sha256::hash_bytes(&bytes);
    if actual[..32] != *expected_hash32 {
        return Err(format!(
            "plan hash mismatch for {}: expected {}, got {}",
            path.display(),
            expected_hash32,
            &actual[..32]
        ));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("plan {} is not UTF-8", path.display()))?;
    parse(text)
}

pub fn verify_realize_contract(
    plan: &ExecPlan,
    requested_build_host: &str,
    requested_platform: &str,
    actual_executor_host: &str,
) -> Result<(), String> {
    let expected_platform = match plan.build_host.as_str() {
        "x86_64-unknown-linux-musl" => "linux/amd64",
        "aarch64-unknown-linux-musl" => "linux/arm64",
        other => return Err(format!("unsupported realize build host `{other}`")),
    };
    if plan.build_host != requested_build_host {
        return Err(format!(
            "realize build-host mismatch: plan={}, requested={requested_build_host}",
            plan.build_host
        ));
    }
    if expected_platform != requested_platform {
        return Err(format!(
            "realize platform mismatch: build-host {} requires {}, requested {}",
            plan.build_host, expected_platform, requested_platform
        ));
    }
    if plan.build_host != actual_executor_host {
        return Err(format!(
            "realize executor-host mismatch: plan={}, executor={actual_executor_host}",
            plan.build_host
        ));
    }
    for node in &plan.nodes {
        for (tool, locator) in &node.tools {
            if locator.starts_with("host:") || locator.starts_with("host-sha256:") {
                return Err(format!(
                    "realize plan `{}` references ambient tool `{}` ({})",
                    node.name, tool, locator
                ));
            }
        }
    }
    Ok(())
}

pub fn verify_source_cas_complete(plan: &ExecPlan, state_root: &Path) -> Result<(), String> {
    let cas = crate::source::SourceCas::open(state_root)?;
    for entry in &plan.bootstrap {
        if !cas
            .blob_path(
                &entry.hash,
                if entry.kind == 'l' { 'f' } else { entry.kind },
            )
            .is_file()
        {
            return Err("source CAS incomplete — re-run from the host".to_string());
        }
    }
    for node in &plan.nodes {
        for (kind, _rel, hash) in &node.srcs {
            if !cas.blob_path(hash, *kind).is_file() {
                return Err("source CAS incomplete — re-run from the host".to_string());
            }
        }
        for (_rel, hash) in node.srcdirs.iter().chain(node.source_roots.iter()) {
            if crate::source::verify_tree_complete(hash).is_err() {
                return Err("source CAS incomplete — re-run from the host".to_string());
            }
        }
        for (_rel, hash) in node
            .exec
            .srcdirs
            .iter()
            .chain(node.exec.source_roots.iter())
        {
            if crate::source::verify_tree_complete(hash).is_err() {
                return Err("source CAS incomplete — re-run from the host".to_string());
            }
        }
    }
    Ok(())
}

pub fn parse(text: &str) -> Result<ExecPlan, String> {
    if !text.ends_with('\n') {
        return Err("plan is not newline-terminated".to_string());
    }
    if text.contains('\r') {
        return Err("plan contains carriage returns".to_string());
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut p = wire::Parser { lines, idx: 0 };
    p.expect_exact(PLAN_HEADER)?;
    p.expect_value("format", PLAN_FORMAT)?;
    let arch = p.take_value("arch")?;
    let build_host = p.take_value("build-host")?;
    p.expect_value("filter", "buildutilignore-v1")?;
    let filter_hash = wire::parse_hex(&p.take_value("filter-hash")?, 64, "filter-hash")?;
    let git_rev = p.take_value("git-rev")?;
    let git_dirty = p.take_value("git-dirty")?;
    if git_dirty != "true" && git_dirty != "false" {
        return Err(format!(
            "git-dirty must be true or false, got `{git_dirty}`"
        ));
    }
    let mut targets = Vec::new();
    let mut bootstrap = Vec::new();
    loop {
        let Some(line) = p.peek() else {
            break;
        };
        if line.starts_with("target: ") {
            targets.push(p.take_value("target")?);
        } else if line.starts_with("bootstrap: ") {
            bootstrap.push(wire::parse_bootstrap(&p.take_value("bootstrap")?)?);
        } else {
            break;
        }
    }
    let mut nodes = Vec::new();
    while let Some(line) = p.peek() {
        let Some(name) = line.strip_prefix("drv ") else {
            return Err(format!(
                "line {}: unknown top-level key `{line}`",
                p.line_no()
            ));
        };
        let name = name.to_string();
        wire::reject_newline(&name, "drv name")?;
        p.idx += 1;
        nodes.push(p.parse_node(name)?);
    }
    let plan = ExecPlan {
        arch,
        build_host,
        filter_hash,
        git_rev,
        git_dirty,
        targets,
        bootstrap,
        nodes,
    };
    check::validate_plan(&plan)?;
    Ok(plan)
}

pub fn emit(
    spec: &Spec,
    evaluated: &Evaluated,
    state_root: &Path,
    git_state: &(String, String),
) -> Result<(PathBuf, String, ExecPlan), String> {
    let filter = crate::source::SourceFilter::load(&spec.repo_root)?;
    let (git_rev, git_dirty) = git_state.clone();
    let bootstrap = bootstrap::bootstrap_paths(&spec.repo_root)?
        .into_iter()
        .map(|rel| {
            evaluated
                .resolved_sources
                .blob(&rel)
                .map(|(hash, kind)| BootstrapEntry { kind, rel, hash })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut nodes = Vec::new();
    for key in &evaluated.order {
        let recipe = evaluated
            .recipes
            .get(key)
            .ok_or_else(|| format!("evaluated order references missing recipe `{key}`"))?;
        let dspec = spec
            .drvs
            .get(address::base_name(key))
            .ok_or_else(|| format!("plan emit cannot find spec for `{key}`"))?;
        nodes.push(build_node(spec, key, recipe, dspec, evaluated, state_root)?);
    }
    let live = evaluated.recipes.keys().cloned().collect();
    let plan = ExecPlan {
        arch: spec.arch.clone(),
        build_host: spec.build_host.clone(),
        filter_hash: filter.hash,
        git_rev,
        git_dirty,
        targets: realization_targets(evaluated, &live),
        bootstrap,
        nodes,
    };
    let text = render(&plan)?;
    let hash = crate::crypto::sha256::hash_bytes(text.as_bytes());
    let short = hash[..32].to_string();
    let dir = crate::state::plans_dir(state_root);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    let path = dir.join(format!("{short}.plan"));
    if !path.is_file() {
        let tmp = dir.join(format!(".{short}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {}", tmp.display(), e))?;
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) if path.is_file() => {}
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(format!("cannot publish plan {}: {}", path.display(), e));
            }
        }
        std::fs::remove_file(&tmp)
            .map_err(|e| format!("cannot remove {}: {}", tmp.display(), e))?;
    }
    Ok((path, short, plan))
}

/// The keys of the live requested roots, in request order, each once.
fn realization_targets(evaluated: &Evaluated, live: &BTreeSet<String>) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for (_, key) in &evaluated.roots {
        if live.contains(key) && !targets.contains(key) {
            targets.push(key.clone());
        }
    }
    targets
}

fn build_node(
    spec: &Spec,
    key: &str,
    recipe: &Recipe,
    dspec: &DrvSpec,
    evaluated: &Evaluated,
    state_root: &Path,
) -> Result<ExecNode, String> {
    let mut srcs = Vec::new();
    for (kind, rel, hash) in &recipe.srcs {
        check::check_blob(
            state_root,
            hash,
            *kind,
            &format!("{} source {}", recipe.name, rel),
        )?;
        srcs.push((*kind, rel.clone(), hash.clone()));
    }
    for (rel, hash) in &recipe.srcdirs {
        if hash != "fixed-output" {
            check::check_tree(state_root, hash, &format!("{} srcdir {}", recipe.name, rel))?;
        }
    }
    for (rel, hash) in &recipe.source_roots {
        if hash != "fixed-output" {
            check::check_tree(
                state_root,
                hash,
                &format!("{} source-root {}", recipe.name, rel),
            )?;
        }
    }
    let srcdirs: Vec<(String, String)> = recipe
        .srcdirs
        .iter()
        .filter(|(_, hash)| hash != "fixed-output")
        .cloned()
        .collect();
    let source_roots: Vec<(String, String)> = recipe
        .source_roots
        .iter()
        .filter(|(_, hash)| hash != "fixed-output")
        .cloned()
        .collect();
    let mut exec_srcdirs = Vec::new();
    let mut exec_source_roots = Vec::new();
    if crate::spec::builders::is_fixed_output(&dspec.builder) {
        for rel in &dspec.src_dirs {
            let hash = evaluated.resolved_sources.tree(rel)?;
            check::check_tree(
                state_root,
                &hash,
                &format!("{} exec-srcdir {}", recipe.name, rel),
            )?;
            exec_srcdirs.push((rel.clone(), hash));
        }
        for rel in &dspec.source_roots {
            let hash = evaluated.resolved_sources.tree(rel)?;
            check::check_tree(
                state_root,
                &hash,
                &format!("{} exec-source-root {}", recipe.name, rel),
            )?;
            exec_source_roots.push((rel.clone(), hash));
        }
    }
    let mut exec_argv = if crate::spec::builders::is_fixed_output(&dspec.builder) {
        let empty_config = crate::spec::configres::Config::from_values(BTreeMap::new());
        let mut view = empty_config.view();
        let mut argv = spec.eval_argv(dspec, &mut view)?;
        // eval_argv prefixes the tool; exec-argv carries the raw arguments —
        // the tool rides separately in exec-tool, and the fixed-output
        // executors (fetch URL, untar archive) index into raw argv.
        if argv.first() == Some(&dspec.tool) {
            argv.remove(0);
        }
        argv
    } else {
        recipe.argv.clone()
    };
    if dspec.builder == "untar" {
        validate_untar_argv(&recipe.name, &exec_argv)?;
    }
    if exec_argv.is_empty() {
        exec_argv.push(dspec.tool.clone());
    }
    let stage_facts = stage_facts(spec, key, recipe, dspec, evaluated)?;
    Ok(ExecNode {
        name: key.to_string(),
        arch: recipe.arch.clone(),
        builder: recipe.builder.clone(),
        tools: recipe.tools.clone(),
        env: recipe.env.clone(),
        srcs,
        srcdirs,
        source_roots,
        source_overlays: recipe.source_overlays.clone(),
        deps: recipe.dep_names.clone(),
        config: recipe.config.clone(),
        module_config: recipe.module_config.clone(),
        argv: recipe.argv.clone(),
        plan: recipe.plan.clone(),
        outputs: recipe.outputs.clone(),
        exec: ExecMeta {
            tool: dspec.tool.clone(),
            extra_tools: dspec.extra_tools.clone(),
            env: dspec.env.clone(),
            srcdirs: exec_srcdirs,
            source_roots: exec_source_roots,
            argv: exec_argv,
            stage_deps: dspec.stage_deps.clone(),
            copy: dspec.copy.clone(),
            host_tool: dspec.host_tool,
            allowed_refs: dspec.allowed_refs.clone(),
            shell: stage_facts.shell,
            mounts: stage_facts.mounts,
            version_flags: stage_facts.version_flags,
            substituter: stage_facts.substituter,
            module_config_text: if dspec.builder == "module" {
                spec.modules
                    .get(&dspec.module)
                    .map(|module| module.config_json.clone())
                    .ok_or_else(|| format!("`{key}` runs undeclared module `{}`", dspec.module))?
            } else {
                String::new()
            },
        },
        active_plan: evaluated
            .plans
            .get(key)
            .cloned()
            .unwrap_or_else(|| ActivePlan {
                compiles: Vec::new(),
                steps: Vec::new(),
            }),
    })
}

/// The execution facts a node takes from its stage.
struct StageFacts {
    shell: Option<String>,
    mounts: Vec<(String, String, String)>,
    version_flags: Vec<(String, String)>,
    substituter: Option<(String, String)>,
}

/// The dependency key through which `recipe` reaches derivation `base`.
fn dep_key_for<'a>(recipe: &'a Recipe, base: &str) -> Option<&'a String> {
    recipe
        .dep_names
        .iter()
        .find(|key| address::base_name(key) == base)
}

fn stage_facts(
    spec: &Spec,
    key: &str,
    recipe: &Recipe,
    dspec: &DrvSpec,
    evaluated: &Evaluated,
) -> Result<StageFacts, String> {
    let mut facts = StageFacts {
        shell: None,
        mounts: Vec::new(),
        version_flags: Vec::new(),
        substituter: None,
    };
    if dspec.native_frontend || crate::spec::builders::is_in_process(&dspec.builder) {
        return Ok(facts);
    }
    let declared: Vec<&String> = std::iter::once(&dspec.tool)
        .chain(dspec.extra_tools.iter())
        .collect();
    for tool in &declared {
        if let Some(flag) = spec
            .declared_tool(dspec, tool)
            .and_then(|provider| provider.version_flag.clone())
        {
            facts.version_flags.push(((*tool).clone(), flag));
        }
    }
    facts.version_flags.sort();
    facts.version_flags.dedup();
    let Some(stage) = spec.stage_for(dspec) else {
        return Ok(facts);
    };
    facts.shell = stage
        .shell
        .clone()
        .filter(|shell| declared.iter().any(|tool| *tool == shell));
    for mount in &stage.mounts {
        let dep = dep_key_for(recipe, &mount.derivation).ok_or_else(|| {
            format!(
                "`{key}`: stage `{}` mounts `{}` from `{}`, which is not among its dependencies",
                stage.name, mount.target, mount.derivation
            )
        })?;
        facts
            .mounts
            .push((mount.target.clone(), dep.clone(), mount.path.clone()));
    }
    if let Some(tool) = &stage.substituter
        && let Some(provider) = spec.declared_tool(dspec, tool)
        && let Some(provider_key) = closure_key(evaluated, key, &provider.derivation)
    {
        facts.substituter = Some((provider_key, provider.path.clone()));
    }
    Ok(facts)
}

/// The key of a node named `base` among `key`'s transitive dependencies.
fn closure_key(evaluated: &Evaluated, key: &str, base: &str) -> Option<String> {
    let mut stack: Vec<&String> = evaluated.recipes.get(key)?.dep_names.iter().collect();
    let mut seen = BTreeSet::new();
    while let Some(dep) = stack.pop() {
        if !seen.insert(dep.clone()) {
            continue;
        }
        if address::base_name(dep) == base {
            return Some(dep.clone());
        }
        if let Some(recipe) = evaluated.recipes.get(dep) {
            stack.extend(recipe.dep_names.iter());
        }
    }
    None
}

pub fn validate_untar_argv(name: &str, argv: &[String]) -> Result<(), String> {
    // The archive follows the `untar` marker; eval_argv prefixes the tool,
    // so the marker's position is not fixed.
    let archive = argv
        .iter()
        .position(|a| a == "untar")
        .and_then(|i| argv.get(i + 1))
        .ok_or_else(|| format!("untar `{name}` lacks an archive argv"))?;
    if archive
        .strip_prefix("{srcroot}/.buildutil/")
        .is_some_and(|rest| !rest.is_empty())
    {
        Ok(())
    } else {
        Err(format!(
            "untar `{name}` archive path must be {{srcroot}}/.buildutil/<rest>, got `{archive}`"
        ))
    }
}

pub fn write_bootstrap_exec_dir(plan: &ExecPlan, state_root: &Path) -> Result<PathBuf, String> {
    let root = crate::state::exec_dir(state_root).join(plan.bootstrap_hash());
    if root.is_dir() {
        return Ok(root);
    }
    let tmp =
        crate::state::exec_dir(state_root).join(format!(".bootstrap-{}.tmp", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    for entry in &plan.bootstrap {
        let src = crate::source::blob_path(
            &entry.hash,
            if entry.kind == 'l' { 'f' } else { entry.kind },
        )?;
        if !src.is_file() {
            return Err(format!(
                "bootstrap blob missing for {} sha256:{}",
                entry.rel, entry.hash
            ));
        }
        let dst = tmp.join(&entry.rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        if entry.kind == 'l' {
            let target = std::fs::read_to_string(&src).map_err(|e| e.to_string())?;
            crate::platform::create_symlink_auto(Path::new(&target), &dst)
                .map_err(|e| e.to_string())?;
        } else {
            std::fs::hard_link(&src, &dst).map_err(|e| {
                format!("cannot link {} -> {}: {}", src.display(), dst.display(), e)
            })?;
        }
    }
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    match std::fs::rename(&tmp, &root) {
        Ok(()) => Ok(root),
        Err(_) if root.is_dir() => {
            let _ = std::fs::remove_dir_all(&tmp);
            Ok(root)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(format!("cannot publish bootstrap exec dir: {}", e))
        }
    }
}
