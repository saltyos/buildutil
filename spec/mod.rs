//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — build-spec loading (buildutil.toml)
//!
//! The root `buildutil.toml` names the subsystem spec files explicitly (never
//! directory-globbed) and carries per-arch tables and shared flagsets. Every
//! file may declare `[derivation.<name>]` tables, configuration variants
//! (`variant-of` plus a `config` override table), output-kind tables,
//! modules (`[module.<name>]`) and generators (`[generate.<name>]`).
//!
//! Loading has two ends. The static load parses every file, synthesizes
//! the derivations modules, generators, the formatter and build-host apps
//! run as, and applies the stage environments. When no generator is
//! declared, it then validates the whole specification. Otherwise the
//! specification stays pending: only the generators' closures, which must
//! be static, are checked, the generation phase realizes the generators,
//! and `finish_generation` merges their declarations and runs every
//! validation once.
//!
//! Argv tokens, resolved in two phases:
//!   eval-phase (enters the drv hash): `{arch}`, `{build.host.triple}`,
//!   `{build.host.arch}`, `{build-host.<key>}` (build-host table),
//!   `{target.<key>}` (arch table), `{flagset:<name>}` (splice, with its
//!   config-gated flag groups), `{config.<KEY>}` (recorded into the projection)
//!   exec-phase (symbolic in the hash, real paths at execution):
//!   `{srcroot}` / `{srcroot-abs}` (staged sources), `{out}` / `{out-abs}`
//!   (output dir), `{dep:<name>}` / `{dep-abs:<name>}` (dep store dir)
//! Step-table `each` / `{item}` expands at spec load alongside compile-group
//! `{stem}` / `{path}` template expansion; it is not an argv-token phase.
//! Dependency names take `{arch}` and `{target.<key>}`.
//!
//! Source sets are explicit file lists or declared subtrees — no globs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod address;
pub mod builders;
pub mod configres;
pub(crate) mod inputs;
pub mod kinds;
pub mod modules;
pub mod toml;

mod required_checks;
pub mod stages;
mod tables;

pub use stages::{ConfigurationSpec, ExecutorImageSpec, StageSpec, ToolProviderSpec};

/// The environment entry carrying a derivation's declared
/// `system-features`; the executor reads it to decide which host devices a
/// build may reach.
pub const SYSTEM_FEATURES_ENV: &str = "BUILDUTIL_SYSTEM_FEATURES";

/// The environment entries naming a module builder's module and the role it
/// runs in; they are part of the derivation's identity.
pub const MODULE_ENV: &str = "BUILDUTIL_MODULE";
pub const MODULE_ROLE_ENV: &str = "BUILDUTIL_MODULE_ROLE";
/// The environment entry listing a module builder's declared configuration
/// keys, the only ones its module may read.
pub const MODULE_CONFIG_KEYS_ENV: &str = "BUILDUTIL_MODULE_CONFIG_KEYS";
/// The environment entry naming a module builder's declared dependencies
/// that are configuration variants, `<variant>=<base>` joined by commas: the
/// outputs of a variant edge are staged under its base's name, and the
/// module reads them under the name its derivation declares.
pub const MODULE_INPUTS_ENV: &str = "BUILDUTIL_MODULE_INPUTS";

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Default)]
pub struct Flagset {
    pub flags: Vec<String>,
    /// (`when` predicate, flags) applied in order after `flags`.
    pub groups: Vec<(String, Vec<String>)>,
    /// Config keys holding comma-separated cfg-name aggregates (configuration
    /// `*_RUST_CFGS`); each name expands to `--cfg <name>` after the
    /// groups. The read is recorded into the config projection.
    pub cfg_each: Vec<String>,
    /// Appended last (e.g. `-Z unstable-options`).
    pub tail: Vec<String>,
}

/// One `[[derivation.X.compile]]` fan-out: N sources compiled with shared
/// flags inside a script-dag derivation's inner ninja.
#[derive(Debug, Clone)]
pub struct CompileGroup {
    /// Config predicate; empty = always active.
    pub when: String,
    /// Command shape: `cc` (clang -MMD -c), `cc-simple` (clang -c, no
    /// depfile), `nasm` (nasm -o out in).
    pub kind: String,
    pub tool: String,
    pub flags: Vec<String>,
    pub sources: Vec<String>,
    /// Fan-out discovery: sorted scan of a declared subtree for
    /// `scan-ext` files at plan evaluation. Discovery shapes the inner
    /// ninja only — the input hash covers the whole tree via src-dirs.
    pub scan_dir: String,
    pub scan_ext: String,
    pub scan_exclude: Vec<String>,
    /// Object-name template; `{stem}` = source filename without extension,
    /// `{path}` = the full source path underscorified.
    pub obj: String,
}

/// One serial `[[derivation.X.step]]` after the compile fan-outs (links,
/// objcopy, script invocations). `{objs}` in argv expands to every compile
/// object in declaration order. A step table's optional `each` list expands
/// `{item}` templates in argv, outputs, and capture before `Step` construction.
#[derive(Debug, Clone)]
pub struct Step {
    pub when: String,
    pub tool: String,
    pub argv: Vec<String>,
    /// Redirect the step's stdout into this cwd-relative file (must also
    /// be listed in outputs).
    pub capture: String,
    /// Produced paths (cwd-relative or `{out}/...`) — the inner ninja's
    /// dependency edges between steps.
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RefPolicy {
    #[default]
    None,
    Closure,
    List(Vec<String>),
}

#[derive(Debug, Clone, Default)]
pub struct DrvSpec {
    pub name: String,
    pub builder: String,
    pub tool: String,
    /// Additional declared tools reachable through the private toolbin
    /// (e.g. rustfmt for bindgen); provider-tracked like the main tool.
    pub extra_tools: Vec<String>,
    /// Config predicate for the whole derivation (e.g. the BIOS boot chain
    /// exists only on x86_64); empty = always.
    pub when: String,
    /// Bootstrap-grade: the reserved `buildutil` tool resolves to
    /// `buildutil-bootstrap`, and without an explicit `stage` the derivation
    /// uses the `bootstrap` stage. Default false.
    pub bootstrap: bool,
    /// Native self-host frontend: compiler tools resolve to the ambient
    /// bootstrap-captured provider rather than either store toolchain grade.
    /// Valid only in the target-scoped native frontend graph.
    pub native_frontend: bool,
    /// The stage whose environment and tool providers this derivation
    /// uses; `None` selects `bootstrap` for a bootstrap-grade derivation and
    /// `default` otherwise.
    pub stage: Option<String>,
    /// Target-independent host tool: the output is a build-machine artifact
    /// (a host toolchain stage, a compiler wrapper) whose bytes do not vary
    /// with the configured target arch. The recipe pins its store suffix to
    /// `host-<build-host>`, so both target architectures share one
    /// build-host realization — an LLVM stage builds once per build host,
    /// not once per target. Default false.
    pub host_tool: bool,
    /// allowedReferences analog: which store references may remain in this
    /// output after realization. Default `None` is the freestanding contract:
    /// no store-root references are legal.
    pub allowed_refs: RefPolicy,
    pub sources: Vec<String>,
    pub src_dirs: Vec<String>,
    /// Repo-relative roots staged as execroot source projections.
    pub source_roots: Vec<String>,
    /// (`{dep:*}` source path, repo-relative destination) projected under a
    /// declared source root.
    pub source_overlays: Vec<(String, String)>,
    pub deps: Vec<String>,
    pub outputs: Vec<String>,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    /// (source token, output-relative dest) copied into the output dir
    /// after the builder succeeds (declared outputs cover them).
    pub copy: Vec<(String, String)>,
    /// (dep-file token, cwd-relative dest) symlinked into the build cwd
    /// before the builder runs — dependency outputs referenced by relative
    /// path so the cwd remap keeps them out of the artifacts.
    pub stage_deps: Vec<(String, String)>,
    pub groups: Vec<(String, Vec<String>)>,
    /// script-dag inner DAG: compile fan-outs then serial steps.
    pub compiles: Vec<CompileGroup>,
    pub steps: Vec<Step>,
    /// A module builder's module (`builder = "module"`); empty otherwise.
    pub module: String,
    /// The role a module builder's module runs in: `builder` for a declared
    /// derivation, or the role buildutil synthesized it for.
    pub module_role: String,
    /// The configuration keys a module builder may read; they enter its
    /// projection whether or not the module reads them.
    pub config_keys: Vec<String>,
    /// Captured owner of an input's specification. Checkout locations never
    /// enter a recipe; staged paths remain relative to this repository.
    pub repository: Option<Repository>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    pub root: PathBuf,
    pub content: String,
    pub rev: String,
    pub dirty: bool,
    pub consumers: std::collections::BTreeSet<String>,
    pub published: std::collections::BTreeSet<String>,
    pub variants: std::collections::BTreeSet<String>,
    pub source_names: BTreeMap<String, String>,
}

impl Repository {
    pub(crate) fn source_key(&self, relative: &str) -> String {
        format!("input:{}:{}/{relative}", self.name, self.content)
    }
}

impl DrvSpec {
    pub(crate) fn source_key(&self, relative: &str) -> String {
        self.repository
            .as_ref()
            .map(|owner| owner.source_key(relative))
            .unwrap_or_else(|| relative.to_string())
    }

    pub(crate) fn overlay_root(&self, relative: &str) -> bool {
        self.source_overlays.iter().any(|(source, destination)| {
            destination == relative
                && (source.starts_with("{dep:") || source.starts_with("{dep-abs:"))
        })
    }

    pub(crate) fn source_root_key(&self, relative: &str) -> String {
        let key = self.source_key(relative);
        if self.overlay_root(relative) {
            format!("overlay-root:{key}")
        } else {
            key
        }
    }
}

impl DrvSpec {
    /// An empty declaration of `name` with its builder and tool.
    pub fn new(name: &str, builder: &str, tool: &str) -> DrvSpec {
        DrvSpec {
            name: name.to_string(),
            builder: builder.to_string(),
            tool: tool.to_string(),
            ..DrvSpec::default()
        }
    }
}

/// A script-dag derivation's config-filtered inner DAG, resolved during
/// the hash pass and consumed at realization by the ninja emitter.
#[derive(Debug, Clone)]
pub struct ActivePlan {
    pub compiles: Vec<CompileGroup>,
    pub steps: Vec<Step>,
}

/// A configuration variant: a public name for `base` evaluated with
/// `overrides` layered over the persistent and `-D` configuration. It has no
/// recipe of its own; the configured nodes it reaches keep their base names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    pub name: String,
    /// The derivation or variant this one configures.
    pub base: String,
    pub overrides: address::Overrides,
}

/// One step of `buildutil bootstrap`: build `targets` for `arch`, after
/// resolving that architecture's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapStep {
    pub targets: Vec<String>,
    pub arch: String,
}

/// What a pending specification keeps to merge generated declarations and
/// validate the result.
#[derive(Debug, Clone)]
pub struct Pending {
    root_doc: toml::Doc,
    arch_table: BTreeMap<String, String>,
    build_host_table: BTreeMap<String, String>,
    owners: BTreeMap<String, GeneratorOwner>,
    input_checks: Vec<(Repository, toml::Doc)>,
    root_sources: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct GeneratorOwner {
    repository: Repository,
    arch_table: BTreeMap<String, String>,
    build_host_table: BTreeMap<String, String>,
    source_names: BTreeMap<String, String>,
    stages: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub repo_root: PathBuf,
    pub arch: String,
    pub build_host: String,
    /// The target system the build report names (`[buildutil] target-system`,
    /// `{arch}` expanded); the architecture alone when undeclared.
    pub target_system: String,
    pub flagsets: BTreeMap<String, Flagset>,
    pub drvs: BTreeMap<String, DrvSpec>,
    /// Configuration variants by public name; disjoint from `drvs`.
    pub variants: BTreeMap<String, Variant>,
    /// The merged output-kind tables.
    pub kinds: kinds::Kinds,
    /// Manifest-declared tool aliases, usable by name from any stage. The
    /// engine's reserved names cannot be declared.
    pub tool_providers: BTreeMap<String, ToolProviderSpec>,
    /// The stage environments, `inherit` applied.
    pub stages: BTreeMap<String, StageSpec>,
    /// The option graph resolved in process and its editor; `None` when no
    /// file declares `[configuration]`.
    pub configuration: Option<ConfigurationSpec>,
    /// The container executor image's inputs; `None` when no file declares
    /// `[executor-image]`.
    pub executor_image: Option<ExecutorImageSpec>,
    /// Declared modules by name.
    pub modules: BTreeMap<String, modules::ModuleSpec>,
    /// Declared generators by name.
    pub generators: BTreeMap<String, modules::GeneratorSpec>,
    /// `buildutil bootstrap`'s ordered steps (`[[bootstrap.step]]`).
    pub bootstrap_steps: Vec<BootstrapStep>,
    /// Set while generated declarations are still to be merged; the
    /// specification is then validated only for its generators' closures.
    pub pending: Option<Box<Pending>>,
    /// Every file-system input consumed while constructing this spec. Paths
    /// are repo-relative and hashes are full SHA-256. The kind distinguishes
    /// regular files from generated declarations so snapshot validation
    /// never re-hashes an output from the checkout.
    pub spec_inputs: Vec<SpecInput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecInputKind {
    File,
    /// A generator's declarations: the path names the generator, the hash
    /// the declarations' content.
    Generated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecInput {
    pub path: String,
    pub hash: String,
    pub kind: SpecInputKind,
}

/// The top-level tables a specification file may hold. Anything else is a
/// load error rather than silently ignored input.
const ROOT_TABLES: &[&str] = &[
    "buildutil",
    "packages",
    "checks",
    "apps",
    "formatter",
    "derivation",
    "flagset",
    "module",
    "generate",
    "arch",
    "build-host",
    "stage",
    "tool-provider",
    "configuration",
    "executor-image",
    "license",
    "required-check",
    "native-frontend",
    "bootstrap",
    "launch",
    "input",
    "lock",
];
const SUBSYSTEM_TABLES: &[&str] = &[
    "packages",
    "checks",
    "apps",
    "formatter",
    "derivation",
    "module",
    "generate",
    "build-host",
    "stage",
    "tool-provider",
    "configuration",
    "executor-image",
    "input",
];
/// What generated declarations may hold: derivations and kind-table
/// contributions.
const GENERATED_TABLES: &[&str] = &["derivation", "packages", "checks"];

fn check_tables(doc: &toml::Doc, allowed: &[&str], origin: &str) -> Result<(), String> {
    for table in &doc.tables {
        if let Some(first) = table.path.first() {
            if !allowed.contains(&first.as_str()) {
                return Err(format!(
                    "{origin}: [{}{}] is not a table this file may declare",
                    if table.is_array { "[" } else { "" },
                    table.path.join(".")
                ));
            }
        } else if !table.entries.is_empty() {
            return Err(format!("{origin}: keys before the first table"));
        }
    }
    Ok(())
}

struct LoadScope {
    subsystems: Vec<String>,
    target: String,
    /// A derivation the scope adds to its subsystems' own, such as a
    /// client app module's self-tool build.
    extra: Option<DrvSpec>,
}

/// The expansion context shared by declared, synthesized and generated
/// derivations.
struct Expand<'a> {
    arch: &'a str,
    build_host: &'a str,
    build_host_table: &'a BTreeMap<String, String>,
    arch_table: &'a BTreeMap<String, String>,
}

/// Load the complete store/OS graph used by the developer-facing buildutil. The
/// result is pending when generators are declared: run the generation
/// phase and `finish_generation` before evaluating anything but the
/// generators.
pub fn load(repo_root: &Path, arch: &str, build_host: &str) -> Result<Spec, String> {
    load_impl(repo_root, arch, build_host, None, &[], None)
}

/// Load source-input declarations using this invocation's explicit checkout choices.
pub(crate) fn load_with_input_overrides(
    repo_root: &Path,
    arch: &str,
    build_host: &str,
    overrides: &[(String, PathBuf)],
) -> Result<Spec, String> {
    load_impl(repo_root, arch, build_host, None, overrides, None)
}

/// Load only the native self-host target and its declared dependency closure.
/// The root `[native-frontend]` table owns both the target and subsystem set,
/// so minibuildutil evaluates the same buildutil.toml language without parsing the
/// unrelated OS/toolchain graph for a non-Linux execution host.
pub fn load_native_frontend(repo_root: &Path, build_host: &str) -> Result<(Spec, String), String> {
    load_self_tool(repo_root, build_host, None)
}

/// Load one self-tool target — the native frontend by default, or another
/// native-frontend derivation such as the configuration editor — with the
/// `[native-frontend]` subsystem set and its dependency closure.
pub fn load_self_tool(
    repo_root: &Path,
    build_host: &str,
    target: Option<&str>,
) -> Result<(Spec, String), String> {
    load_self_tool_with(repo_root, build_host, target.map(str::to_string), None)
}

/// Load the self-tool build of a client app's module: the module's native
/// derivation over the `[native-frontend]` subsystems, which provide the
/// self-tool SDK.
pub fn load_self_tool_module(
    repo_root: &Path,
    build_host: &str,
    module: &modules::ModuleSpec,
) -> Result<(Spec, String), String> {
    let drv = modules::native_module_derivation(module);
    load_self_tool_with(repo_root, build_host, Some(drv.name.clone()), Some(drv))
}

fn load_self_tool_with(
    repo_root: &Path,
    build_host: &str,
    target: Option<String>,
    extra: Option<DrvSpec>,
) -> Result<(Spec, String), String> {
    let root_doc = toml::parse_file(&repo_root.join("buildutil.toml"))?;
    let table = root_doc
        .table(&["native-frontend"])
        .ok_or("buildutil.toml: missing [native-frontend] table")?;
    let ctx = "[native-frontend]";
    let target = match target {
        Some(target) => target,
        None => tables::need_str(table, "target", ctx)?,
    };
    let arch = tables::need_str(table, "arch", ctx)?;
    let subsystems = tables::opt_str_list(table, "subsystems", ctx)?;
    if subsystems.is_empty() {
        return Err("[native-frontend] needs at least one subsystem".to_string());
    }
    let scope = LoadScope {
        subsystems,
        target: target.clone(),
        extra,
    };
    let spec = load_impl(repo_root, &arch, build_host, Some(&scope), &[], None)?;
    Ok((spec, target))
}

fn load_impl(
    repo_root: &Path,
    arch: &str,
    build_host: &str,
    scope: Option<&LoadScope>,
    overrides: &[(String, PathBuf)],
    input_sources: Option<&BTreeMap<String, String>>,
) -> Result<Spec, String> {
    use crate::spec::tables::{
        expand_arch, expand_build_host, expand_build_host_table, expand_target, flag_groups,
        opt_str_list,
    };

    let root_path = repo_root.join("buildutil.toml");
    let root_doc = toml::parse_file(&root_path)?;
    check_tables(&root_doc, ROOT_TABLES, "buildutil.toml")?;
    let buildutil_table = root_doc
        .table(&["buildutil"])
        .ok_or("buildutil.toml: missing [buildutil] table")?;
    let input_declarations = crate::inputs::codec::declarations(&root_doc)?;
    let mut subsystems = match scope {
        Some(scope) => scope.subsystems.clone(),
        None => opt_str_list(buildutil_table, "subsystems", "[buildutil]")?,
    };
    subsystems.retain(|subsystem| {
        !input_declarations
            .values()
            .any(|input| input.path.as_ref() == Some(subsystem))
    });

    let mut arch_table = BTreeMap::new();
    match root_doc.table(&["arch", arch]) {
        Some(t) => {
            for e in &t.entries {
                let v = e
                    .value
                    .as_str()
                    .ok_or_else(|| format!("[arch.{}] {} must be a string", arch, e.key))?;
                arch_table.insert(e.key.clone(), v.to_string());
            }
        }
        None => return Err(format!("buildutil.toml: no [arch.{}] table", arch)),
    }

    // Every file is parsed up front: the build-host tables of all of them
    // expand values in each.
    let mut subsystem_docs = Vec::new();
    for subsystem in &subsystems {
        let path = repo_root.join(subsystem).join("buildutil.toml");
        let doc = toml::parse_file(&path)?;
        check_tables(
            &doc,
            SUBSYSTEM_TABLES,
            &format!("{subsystem}/buildutil.toml"),
        )?;
        subsystem_docs.push((subsystem.clone(), path, doc));
    }
    let mut build_host_merged = BTreeMap::new();
    stages::merge_build_host(&root_doc, &root_path, build_host, &mut build_host_merged)?;
    for (_, path, doc) in &subsystem_docs {
        stages::merge_build_host(doc, path, build_host, &mut build_host_merged)?;
    }
    let build_host_table: BTreeMap<String, String> = build_host_merged
        .into_iter()
        .map(|(key, (value, _))| (key, value))
        .collect();
    let expand = Expand {
        arch,
        build_host,
        build_host_table: &build_host_table,
        arch_table: &arch_table,
    };

    let target_system = match buildutil_table.get("target-system") {
        None => arch.to_string(),
        Some(value) => value
            .as_str()
            .ok_or("[buildutil] target-system must be a string")?
            .replace("{arch}", arch),
    };
    let mut kinds = kinds::Kinds::default();
    if scope.is_none() {
        kinds.merge_doc(&root_doc, "buildutil.toml")?;
    }
    let mut variants: BTreeMap<String, Variant> = BTreeMap::new();
    // The root file declares no recipes, only configuration variants: a
    // public name for a subsystem's derivation under overrides.
    for table in root_doc.tables_under(&["derivation"]) {
        if table.path.len() != 2 || table.is_array {
            continue;
        }
        let name = table.path[1].clone();
        let ctx = format!("buildutil.toml: [derivation.{name}]");
        if table.get("variant-of").is_none() {
            return Err(format!(
                "{ctx}: the root file declares derivations only as configuration variants"
            ));
        }
        let variant = parse_variant(&root_doc, table, &name, &ctx)?;
        if variants.insert(name.clone(), variant).is_some() {
            return Err(format!("{ctx}: duplicate derivation `{name}`"));
        }
    }

    let mut flagsets = BTreeMap::new();
    for table in root_doc.tables_under(&["flagset"]) {
        if table.path.len() != 2 {
            continue;
        }
        let name = table.path[1].clone();
        let ctx = format!("[flagset.{}]", name);
        let mut fs = Flagset {
            flags: opt_str_list(table, "flags", &ctx)?,
            groups: flag_groups(&root_doc, &["flagset", &name])?,
            cfg_each: opt_str_list(table, "cfg-each", &ctx)?,
            tail: opt_str_list(table, "tail", &ctx)?,
        };
        expand_arch(&mut fs.flags, arch);
        expand_arch(&mut fs.tail, arch);
        expand_build_host(&mut fs.flags, build_host);
        expand_build_host(&mut fs.tail, build_host);
        for (_, flags) in fs.groups.iter_mut() {
            expand_arch(flags, arch);
            expand_build_host(flags, build_host);
            for item in flags.iter_mut() {
                *item = expand_build_host_table(item, &build_host_table)?;
                *item = expand_target(item, &arch_table)?;
            }
        }
        // {target.<key>} is arch-table data; expand it at load so flagsets
        // are plain strings afterwards.
        for item in fs.flags.iter_mut().chain(fs.tail.iter_mut()) {
            *item = expand_build_host_table(item, &build_host_table)?;
            *item = expand_target(item, &arch_table)?;
        }
        flagsets.insert(name, fs);
    }

    let mut drvs = BTreeMap::new();
    let mut tool_providers = BTreeMap::new();
    let mut raw_stages = BTreeMap::new();
    let mut configuration = None;
    let mut executor_image = None;
    let mut module_specs = BTreeMap::new();
    let mut generators = BTreeMap::new();
    let expand_host = |value: &str| -> Result<String, String> {
        let mut out = vec![value.to_string()];
        expand_arch(&mut out, arch);
        expand_build_host(&mut out, build_host);
        expand_build_host_table(&out[0], &build_host_table)
    };
    stages::load_tool_providers(&root_doc, &root_path, &mut tool_providers)?;
    stages::load_stages(&root_doc, &root_path, &mut raw_stages)?;
    stages::load_configuration(&root_doc, &root_path, &mut configuration)?;
    stages::load_executor_image(&root_doc, &root_path, &expand_host, &mut executor_image)?;
    modules::parse_modules(&root_doc, "buildutil.toml", &mut module_specs)?;
    let mut generated_drvs = Vec::new();
    if scope.is_none() {
        modules::parse_generators(
            &root_doc,
            "buildutil.toml",
            &mut generators,
            &mut generated_drvs,
        )?;
    }
    for (subsystem, path, doc) in &subsystem_docs {
        let path = path.clone();
        let origin = format!("{subsystem}/buildutil.toml");
        stages::load_tool_providers(doc, &path, &mut tool_providers)?;
        stages::load_stages(doc, &path, &mut raw_stages)?;
        stages::load_configuration(doc, &path, &mut configuration)?;
        stages::load_executor_image(doc, &path, &expand_host, &mut executor_image)?;
        modules::parse_modules(doc, &origin, &mut module_specs)?;
        if scope.is_none() {
            kinds.merge_doc(doc, &origin)?;
            modules::parse_generators(doc, &origin, &mut generators, &mut generated_drvs)?;
        }
        parse_derivation_tables(
            doc,
            &path.display().to_string(),
            &expand,
            &mut drvs,
            &mut variants,
        )?;
    }
    let lock = if input_sources.is_some() {
        None
    } else {
        crate::inputs::codec::Lock::read(&repo_root.join("buildutil.lock"))?
    };
    let bootstrap_selections = if scope.is_some() {
        crate::inputs::bootstrap::selections(repo_root, &BTreeMap::new())?
    } else {
        Vec::new()
    };
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let override_cwd = crate::invocation::request_cwd()
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|e| e.to_string())?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let override_cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    for (name, input) in &input_declarations {
        if !input.source {
            continue;
        }
        let checkout = overrides
            .iter()
            .find(|(selected_name, _)| selected_name == name)
            .map(|(_, path)| {
                if path.is_absolute() {
                    path.clone()
                } else {
                    override_cwd.join(path)
                }
            })
            .or_else(|| {
                bootstrap_selections
                    .iter()
                    .find(|(selected_name, _, _)| selected_name == name)
                    .map(|(_, path, _)| path.clone())
            })
            .or_else(|| input.path.as_ref().map(|path| repo_root.join(path)));
        if overrides
            .iter()
            .any(|(selected_name, _)| selected_name == name)
            && !checkout.as_ref().is_some_and(|path| path.is_dir())
        {
            return Err(format!(
                "--override-input `{name}` is not a readable checkout"
            ));
        }
        let content = if let Some(content) = input_sources.and_then(|sources| sources.get(name)) {
            content.clone()
        } else {
            match checkout
                .as_ref()
                .filter(|path| path.is_dir() && (scope.is_some() || path.join(".git").exists()))
            {
                Some(path) => format!("tree:{}", crate::source::ingest_repository(path, &[])?),
                None => lock
                    .as_ref()
                    .and_then(|lock| {
                        lock.inputs
                            .get(name)
                            .and_then(|entry| lock.entries.get(entry))
                    })
                    .map(|entry| entry.content.clone())
                    .ok_or_else(|| {
                        format!("input `{name}` has no checkout or buildutil.lock entry")
                    })?,
            }
        };
        let source = crate::inputs::source_derivation(name, &content)?;
        if drvs.insert(name.clone(), source).is_some() || variants.contains_key(name) {
            return Err(format!(
                "input `{name}` has an ambiguous published output name"
            ));
        }
    }
    let bootstrap_steps = parse_bootstrap_steps(&root_doc)?;

    // The derivations buildutil runs modules as.
    let mut synthesized = Vec::new();
    if let Some(scope) = scope {
        if let Some(extra) = &scope.extra {
            synthesized.push(extra.clone());
        }
    } else {
        for module in module_specs.values() {
            synthesized.push(modules::module_derivation(module));
            let (alias, provider) = modules::module_tool_provider(module);
            if tool_providers.insert(alias.clone(), provider).is_some() {
                return Err(format!(
                    "tool provider `{alias}` is buildutil's own name for module `{}`",
                    module.name
                ));
            }
        }
        synthesized.extend(generated_drvs);
        if let Some(formatter) = &kinds.formatter {
            synthesized.push(modules::formatter_derivation(formatter));
        }
        for (name, app) in &kinds.apps {
            if app.runs_on == kinds::RunsOn::BuildHost {
                synthesized.push(modules::app_derivation(name, app, arch));
            }
        }
    }
    for mut spec in synthesized {
        let ctx = format!("derivation `{}`", spec.name);
        expand_derivation(&mut spec, &expand, &ctx)?;
        if drvs.contains_key(&spec.name) || variants.contains_key(&spec.name) {
            return Err(format!(
                "`{}` is the name buildutil gives a module's derivation; a specification may not declare it",
                spec.name
            ));
        }
        drvs.insert(spec.name.clone(), spec);
    }
    module_references(&drvs, &module_specs)?;

    if let Some(scope) = scope {
        validate_tool_provider_derivations(&tool_providers, &BTreeMap::new(), &drvs)?;
        if !drvs.contains_key(&scope.target) {
            return Err(format!(
                "[native-frontend] target `{}` is not defined by its scoped subsystems",
                scope.target
            ));
        }
        let mut keep = std::collections::BTreeSet::new();
        let mut stack = vec![scope.target.clone()];
        while let Some(name) = stack.pop() {
            if !keep.insert(name.clone()) {
                continue;
            }
            let drv = drvs.get(&name).ok_or_else(|| {
                format!(
                    "native frontend derivation `{}` depends on out-of-scope `{}`",
                    scope.target, name
                )
            })?;
            stack.extend(drv.deps.iter().cloned());
        }
        drvs.retain(|name, _| keep.contains(name));
        tool_providers.retain(|_, provider| keep.contains(&provider.derivation));
        variants.clear();
    }

    // Resolve the stage environments and give every derivation its own:
    // the stage's default tools and mount providers become declarations.
    let stage_specs = if scope.is_some() {
        BTreeMap::new()
    } else {
        stages::resolve_stages(&raw_stages, &tool_providers)?
    };
    stages::apply_stage_environment(&mut drvs, &stage_specs, false)?;

    let spec_inputs = collect_spec_inputs(repo_root, &subsystems)?;
    let mut spec = Spec {
        repo_root: repo_root.to_path_buf(),
        arch: arch.to_string(),
        build_host: build_host.to_string(),
        target_system,
        flagsets,
        drvs,
        variants,
        kinds,
        tool_providers,
        stages: stage_specs,
        configuration,
        executor_image,
        modules: module_specs,
        generators,
        bootstrap_steps,
        pending: None,
        spec_inputs,
    };
    if scope.is_some() {
        finish(&mut spec, None)?;
        return Ok(spec);
    }
    let has_repository_inputs = input_declarations.values().any(|input| !input.source);
    if spec.generators.is_empty() && !has_repository_inputs && input_sources.is_none() {
        finish(&mut spec, Some(&root_doc))?;
        return Ok(spec);
    }
    if !has_repository_inputs && input_sources.is_none() {
        validate_generator_closures(&spec)?;
    }
    spec.pending = Some(Box::new(Pending {
        root_doc,
        arch_table,
        build_host_table,
        owners: BTreeMap::new(),
        input_checks: Vec::new(),
        root_sources: BTreeMap::new(),
    }));
    Ok(spec)
}

/// Merge the declarations the generators returned, `(generator, text)`, into
/// a pending specification and validate the result. A generated name that
/// collides with a static or another generated one, and a generated table
/// other than a derivation or a kind-table contribution, are refused; the
/// merge publishes nothing unless every generator's output is accepted.
pub fn finish_generation(mut spec: Spec, generated: &[(String, String)]) -> Result<Spec, String> {
    let pending = spec
        .pending
        .take()
        .ok_or("the specification is not waiting for generated declarations")?;
    let expand = Expand {
        arch: &spec.arch,
        build_host: &spec.build_host,
        build_host_table: &pending.build_host_table,
        arch_table: &pending.arch_table,
    };
    let mut new_drvs: BTreeMap<String, DrvSpec> = BTreeMap::new();
    let mut new_variants: BTreeMap<String, Variant> = BTreeMap::new();
    let mut kinds = spec.kinds.clone();
    let mut inputs = Vec::new();
    let mut publications: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    let mut owned_variants: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for (generator, text) in generated {
        let owner = pending.owners.get(generator);
        let expand = owner
            .map(|owner| Expand {
                arch: &spec.arch,
                build_host: &spec.build_host,
                build_host_table: &owner.build_host_table,
                arch_table: &owner.arch_table,
            })
            .unwrap_or_else(|| Expand {
                arch: expand.arch,
                build_host: expand.build_host,
                build_host_table: expand.build_host_table,
                arch_table: expand.arch_table,
            });
        let origin = format!("generator `{generator}`");
        let doc = toml::parse(Path::new(&origin), text)?;
        check_tables(&doc, GENERATED_TABLES, &origin)?;
        let mut drvs_here = BTreeMap::new();
        let mut variants_here = BTreeMap::new();
        parse_derivation_tables(&doc, &origin, &expand, &mut drvs_here, &mut variants_here)?;
        if let Some(owner) = owner {
            for drv in drvs_here.values_mut() {
                inputs::rename_source_edges(drv, &owner.source_names);
                inputs::bind_stage(drv, &owner.stages)?;
                drv.repository = Some(owner.repository.clone());
            }
            let mut output_kinds = kinds::Kinds::default();
            output_kinds.merge_doc(&doc, &origin)?;
            publications
                .entry(owner.repository.name.clone())
                .or_default()
                .extend(
                    output_kinds
                        .packages
                        .expose
                        .keys()
                        .chain(output_kinds.checks.expose.keys())
                        .cloned(),
                );
            owned_variants
                .entry(owner.repository.name.clone())
                .or_default()
                .extend(variants_here.keys().cloned());
        } else {
            for drv in drvs_here.values_mut() {
                inputs::rename_source_edges(drv, &pending.root_sources);
            }
        }
        for name in drvs_here.keys().chain(variants_here.keys()) {
            if spec.drvs.contains_key(name) || spec.variants.contains_key(name) {
                return Err(format!(
                    "{origin} declares `{name}`, which a specification file already declares"
                ));
            }
            if new_drvs.contains_key(name) || new_variants.contains_key(name) {
                return Err(format!(
                    "{origin} declares `{name}`, which another generator already declares"
                ));
            }
        }
        for dspec in drvs_here.values() {
            if dspec.builder == "module" && dspec.module_role == modules::ROLE_GENERATOR {
                return Err(format!("{origin} declares a generator"));
            }
        }
        kinds.merge_doc(&doc, &origin)?;
        new_drvs.extend(drvs_here);
        new_variants.extend(variants_here);
        inputs.push(SpecInput {
            path: generator.clone(),
            hash: crate::crypto::sha256::hash_bytes(text.as_bytes()),
            kind: SpecInputKind::Generated,
        });
    }
    stages::apply_stage_environment(&mut new_drvs, &spec.stages, false)?;
    module_references(&new_drvs, &spec.modules)?;
    spec.drvs.extend(new_drvs);
    spec.variants.extend(new_variants);
    spec.kinds = kinds;
    spec.spec_inputs.extend(inputs);
    for drv in spec.drvs.values_mut() {
        if let Some(owner) = &mut drv.repository {
            if let Some(names) = publications.get(&owner.name) {
                owner.published.extend(names.iter().cloned());
            }
            if let Some(names) = owned_variants.get(&owner.name) {
                owner.variants.extend(names.iter().cloned());
            }
        }
    }
    for (owner, doc) in &pending.input_checks {
        required_checks::apply_for(doc, &mut spec.drvs, Some(&owner.name))?;
    }
    finish(&mut spec, Some(&pending.root_doc))?;
    inputs::validate_visibility(&spec)?;
    Ok(spec)
}

/// The generators and every derivation they reach, which must all be static:
/// a generator cannot depend on another's output.
pub fn generator_closure(spec: &Spec) -> Vec<String> {
    spec.generators
        .values()
        .map(|generator| generator.derivation.clone())
        .collect()
}

fn validate_generator_closures(spec: &Spec) -> Result<(), String> {
    for generator in spec.generators.values() {
        let mut stack = vec![generator.derivation.clone()];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(name) = stack.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let base = variant_base(&spec.variants, &name).to_string();
            let Some(dspec) = spec.drvs.get(&base) else {
                return Err(format!(
                    "generator `{}` reaches `{name}`, which no specification file declares; a generator's closure must be static",
                    generator.name
                ));
            };
            stack.extend(dspec.deps.iter().cloned());
            for tool in std::iter::once(&dspec.tool).chain(dspec.extra_tools.iter()) {
                if let Some(provider) = spec.declared_tool(dspec, tool) {
                    stack.push(provider.derivation.clone());
                }
            }
        }
    }
    Ok(())
}

/// Every validation over a complete specification: required checks, the
/// variants, dependency and token references, the kind tables and the tool
/// providers. `root_doc` is `None` for a scoped self-tool load.
fn finish(spec: &mut Spec, root_doc: Option<&toml::Doc>) -> Result<(), String> {
    if let Some(root_doc) = root_doc {
        required_checks::apply(root_doc, &mut spec.drvs)?;
        for name in spec.drvs.keys() {
            if spec.variants.contains_key(name) {
                return Err(format!("duplicate derivation `{name}`"));
            }
        }
    }
    validate_variants(&spec.variants, &spec.drvs)?;
    // The self-tool class is built from ambient compilers and never enters
    // a store derivation's closure.
    for (name, dspec) in &spec.drvs {
        if dspec.native_frontend {
            continue;
        }
        for dep in &dspec.deps {
            if spec.drvs.get(dep).is_some_and(|d| d.native_frontend) {
                return Err(format!(
                    "derivation `{name}` depends on self-tool `{dep}`; only the self-tool class may"
                ));
            }
        }
    }
    validate_references(&spec.drvs, &spec.variants)?;
    spec.kinds
        .validate(|name| spec.drvs.contains_key(name) || spec.variants.contains_key(name))?;
    if let Some(root_doc) = root_doc {
        required_checks::validate_kinds(root_doc, &spec.kinds)?;
        for app in spec.kinds.apps.values() {
            if !spec.modules.contains_key(&app.module) {
                return Err(format!(
                    "{}: an app names module `{}`, which no [module.*] table declares",
                    app.origin, app.module
                ));
            }
        }
        if let Some(formatter) = &spec.kinds.formatter {
            if !spec.modules.contains_key(&formatter.module) {
                return Err(format!(
                    "{}: the formatter names module `{}`, which no [module.*] table declares",
                    formatter.origin, formatter.module
                ));
            }
        }
        for step in &spec.bootstrap_steps {
            if step.targets.is_empty() {
                return Err("[[bootstrap.step]] needs at least one target".to_string());
            }
        }
    }
    validate_tool_provider_derivations(&spec.tool_providers, &spec.stages, &spec.drvs)
}

/// Dependencies resolve to derivations or variants; a variant edge is named
/// by the variant, its outputs by the base derivation's name, and a
/// derivation reaches at most one configuration of any base.
fn validate_references(
    drvs: &BTreeMap<String, DrvSpec>,
    variants: &BTreeMap<String, Variant>,
) -> Result<(), String> {
    use crate::spec::tables::tool_version_tokens;
    for (name, spec) in drvs {
        let mut bases: BTreeMap<String, &str> = BTreeMap::new();
        for dep in &spec.deps {
            if !drvs.contains_key(dep) && !variants.contains_key(dep) {
                return Err(format!(
                    "derivation `{}` depends on unknown `{}`",
                    name, dep
                ));
            }
            let base = variant_base(variants, dep).to_string();
            if let Some(other) = bases.insert(base.clone(), dep) {
                return Err(format!(
                    "derivation `{name}` depends on `{other}` and `{dep}`, two configurations of `{base}`"
                ));
            }
        }
        if let RefPolicy::List(allowed) = &spec.allowed_refs {
            for allowed_name in allowed {
                if !drvs.contains_key(allowed_name) {
                    return Err(format!(
                        "derivation `{}` allowed-references names unknown `{}`",
                        name, allowed_name
                    ));
                }
            }
        }
        let check_token = |token: &str| -> Result<(), String> {
            if variants.contains_key(token) {
                return Err(format!(
                    "derivation `{name}` references {{dep:{token}}}; a variant's outputs are named by its base, {{dep:{}}}",
                    variant_base(variants, token)
                ));
            }
            if !bases.contains_key(token) {
                return Err(format!(
                    "derivation `{}` references {{dep:{}}} without declaring it",
                    name, token
                ));
            }
            Ok(())
        };
        for arg in spec
            .argv
            .iter()
            .chain(spec.steps.iter().flat_map(|step| step.argv.iter()))
        {
            for token in dep_tokens(arg) {
                check_token(&token)?;
            }
        }
        for (src, _) in spec
            .copy
            .iter()
            .chain(spec.stage_deps.iter())
            .chain(spec.source_overlays.iter())
        {
            for token in dep_tokens(src) {
                check_token(&token)?;
            }
        }
        // A version query runs the staged tool, so the token is a tool
        // dependency like any other — undeclared means an empty toolbin slot
        // at build time.
        for arg in spec
            .argv
            .iter()
            .chain(spec.steps.iter().flat_map(|s| s.argv.iter()))
            .chain(spec.compiles.iter().flat_map(|c| c.flags.iter()))
        {
            for token in tool_version_tokens(arg) {
                if token != spec.tool && !spec.extra_tools.iter().any(|t| t == &token) {
                    return Err(format!(
                        "derivation `{}` references {{tool-version:{}}} without declaring tool `{}`",
                        name, token, token
                    ));
                }
            }
        }
    }
    Ok(())
}

/// A module builder names a declared module and runs as its tool.
fn module_references(
    drvs: &BTreeMap<String, DrvSpec>,
    modules: &BTreeMap<String, modules::ModuleSpec>,
) -> Result<(), String> {
    for (name, dspec) in drvs {
        if dspec.builder != "module" {
            if !dspec.module.is_empty() || !dspec.config_keys.is_empty() {
                return Err(format!(
                    "derivation `{name}` declares `module` or `config-keys` without builder = \"module\""
                ));
            }
            continue;
        }
        if !modules.contains_key(&dspec.module) {
            return Err(format!(
                "derivation `{name}` runs module `{}`, which no [module.*] table declares",
                dspec.module
            ));
        }
    }
    Ok(())
}

/// Parse `[[bootstrap.step]]`: the ordered (targets, architecture) steps
/// `buildutil bootstrap` runs.
fn parse_bootstrap_steps(root_doc: &toml::Doc) -> Result<Vec<BootstrapStep>, String> {
    let mut steps = Vec::new();
    for table in &root_doc.tables {
        if table.path.first().map(String::as_str) != Some("bootstrap") {
            continue;
        }
        if table.path.len() != 2 || table.path[1] != "step" || !table.is_array {
            return Err(format!(
                "buildutil.toml: [{}] is not a bootstrap table (use [[bootstrap.step]])",
                table.path.join(".")
            ));
        }
        let ctx = "buildutil.toml: [[bootstrap.step]]";
        for entry in &table.entries {
            if !["targets", "arch"].contains(&entry.key.as_str()) {
                return Err(format!("{ctx}: unknown key `{}`", entry.key));
            }
        }
        steps.push(BootstrapStep {
            targets: tables::opt_str_list(table, "targets", ctx)?,
            arch: tables::need_str(table, "arch", ctx)?,
        });
    }
    Ok(steps)
}

/// Parse every `[derivation.<name>]` of one document into `drvs` and
/// `variants`, expanded for the architecture and build host.
fn parse_derivation_tables(
    doc: &toml::Doc,
    origin: &str,
    expand: &Expand<'_>,
    drvs: &mut BTreeMap<String, DrvSpec>,
    variants: &mut BTreeMap<String, Variant>,
) -> Result<(), String> {
    use crate::spec::tables::{compile_groups, flag_groups, opt_str_list, ref_policy, step_list};
    use crate::spec::toml::Value;
    for table in doc.tables_under(&["derivation"]) {
        if table.path.len() != 2 || table.is_array {
            continue;
        }
        let name = table.path[1].clone();
        let ctx = format!("{}: [derivation.{}]", origin, name);
        if drvs.contains_key(&name) || variants.contains_key(&name) {
            return Err(format!("{}: duplicate derivation `{}`", ctx, name));
        }
        if table.get("variant-of").is_some() {
            let variant = parse_variant(doc, table, &name, &ctx)?;
            variants.insert(name, variant);
            continue;
        }
        let builder = tables::need_str(table, "builder", &ctx)?;
        if builder == "source-tree" {
            return Err(format!(
                "{ctx}: source-tree outputs are synthesized from declared repository inputs"
            ));
        }
        let module = table
            .get("module")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{ctx}: `module` must be a string"))
            })
            .transpose()?
            .unwrap_or_default();
        // A module builder runs its module's executable; the tool is buildutil's.
        let tool = if builder == "module" {
            if table.get("tool").is_some() {
                return Err(format!(
                    "{ctx}: a module builder runs its module and declares no `tool`"
                ));
            }
            if module.is_empty() {
                return Err(format!("{ctx}: builder = \"module\" needs `module`"));
            }
            modules::module_tool(&module)
        } else {
            tables::need_str(table, "tool", &ctx)?
        };
        let mut spec = DrvSpec {
            repository: None,
            name: name.clone(),
            builder: builder.clone(),
            tool,
            extra_tools: opt_str_list(table, "extra-tools", &ctx)?,
            sources: opt_str_list(table, "sources", &ctx)?,
            src_dirs: opt_str_list(table, "src-dirs", &ctx)?,
            source_roots: opt_str_list(table, "source-roots", &ctx)?,
            source_overlays: {
                let raw = opt_str_list(table, "source-overlays", &ctx)?;
                let mut out = Vec::new();
                for item in raw {
                    let (src, dest) = item.rsplit_once(':').ok_or_else(|| {
                        format!(
                            "{}: source-overlays entries are `src-token:repo-rel-dest`",
                            ctx
                        )
                    })?;
                    out.push((src.to_string(), dest.to_string()));
                }
                out
            },
            deps: opt_str_list(table, "deps", &ctx)?,
            outputs: opt_str_list(table, "outputs", &ctx)?,
            argv: opt_str_list(table, "argv", &ctx)?,
            env: {
                // `env` accepts both TOML forms: an inline table
                // (`env = { K = "v" }`) and a `[derivation.<name>.env]`
                // sub-table. The flat table model keeps a sub-table separate
                // from its derivation table (like `[[…​.step]]`), so consult
                // `doc` for it too; entries from both forms are merged.
                let mut out = Vec::new();
                match table.get("env") {
                    None => {}
                    Some(Value::Inline(pairs)) => {
                        for (k, v) in pairs {
                            let v = v
                                .as_str()
                                .ok_or_else(|| format!("{}: env values must be strings", ctx))?;
                            out.push((k.clone(), v.to_string()));
                        }
                    }
                    Some(_) => {
                        return Err(format!("{}: inline `env` must be a table", ctx));
                    }
                }
                if let Some(sub) = doc.table(&["derivation", name.as_str(), "env"]) {
                    for e in &sub.entries {
                        let v = e
                            .value
                            .as_str()
                            .ok_or_else(|| format!("{}: env values must be strings", ctx))?;
                        out.push((e.key.clone(), v.to_string()));
                    }
                }
                out
            },
            copy: {
                let raw = opt_str_list(table, "copy", &ctx)?;
                let mut out = Vec::new();
                for item in raw {
                    let (src, dest) = item
                        .rsplit_once(':')
                        .ok_or_else(|| format!("{}: copy entries are `src-token:dest-rel`", ctx))?;
                    out.push((src.to_string(), dest.to_string()));
                }
                out
            },
            stage_deps: {
                let raw = opt_str_list(table, "stage-deps", &ctx)?;
                let mut out = Vec::new();
                for item in raw {
                    let (src, dest) = item.rsplit_once(':').ok_or_else(|| {
                        format!("{}: stage-deps entries are `dep-token:cwd-rel`", ctx)
                    })?;
                    out.push((src.to_string(), dest.to_string()));
                }
                out
            },
            groups: flag_groups(doc, &["derivation", &name])?,
            when: table
                .get("when")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            bootstrap: table
                .get("bootstrap")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            native_frontend: table
                .get("native-frontend")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            stage: match table.get("stage") {
                None => None,
                Some(value) => Some(
                    value
                        .as_str()
                        .ok_or_else(|| format!("{ctx}: `stage` must be a string"))?
                        .to_string(),
                ),
            },
            host_tool: table
                .get("host-tool")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            allowed_refs: ref_policy(table, &ctx)?,
            compiles: compile_groups(doc, &name)?,
            steps: step_list(doc, &name)?,
            module_role: if builder == "module" {
                modules::ROLE_BUILDER.to_string()
            } else {
                String::new()
            },
            module,
            config_keys: opt_str_list(table, "config-keys", &ctx)?,
        };
        if spec.outputs.is_empty() {
            return Err(format!("{}: a derivation needs outputs", ctx));
        }
        // An optional allowance, not a scheduling constraint: the
        // declaration enters identity through the environment, and the
        // executing worker passes the device only where it grants it.
        let features = opt_str_list(table, "system-features", &ctx)?;
        for feature in &features {
            if feature != "kvm" {
                return Err(format!(
                    "{ctx}: unknown system feature `{feature}` (known: kvm)"
                ));
            }
        }
        if !features.is_empty() {
            if spec.env.iter().any(|(k, _)| k == SYSTEM_FEATURES_ENV) {
                return Err(format!(
                    "{ctx}: {SYSTEM_FEATURES_ENV} is set through `system-features`"
                ));
            }
            spec.env
                .push((SYSTEM_FEATURES_ENV.to_string(), features.join(",")));
        }
        expand_derivation(&mut spec, expand, &ctx)?;
        drvs.insert(name, spec);
    }
    Ok(())
}

/// The load-time expansions every derivation receives, declared,
/// synthesized or generated alike, and the shape checks on the result.
fn expand_derivation(spec: &mut DrvSpec, expand: &Expand<'_>, ctx: &str) -> Result<(), String> {
    use crate::spec::tables::{
        expand_arch, expand_build_host, expand_build_host_one, expand_build_host_table,
        expand_target, no_newlines, validate_source_projection,
    };
    let (arch, build_host) = (expand.arch, expand.build_host);
    let build_host_table = expand.build_host_table;
    let arch_table = expand.arch_table;
    // A trailing slash declares a directory output; nesting another
    // declaration under it would make the undeclared-file check
    // ambiguous.
    for dir_out in spec.outputs.iter().filter_map(|o| o.strip_suffix('/')) {
        for other in &spec.outputs {
            if other.trim_end_matches('/') != dir_out && other.starts_with(&format!("{}/", dir_out))
            {
                return Err(format!(
                    "{}: output `{}` is nested under directory output `{}/`",
                    ctx, other, dir_out
                ));
            }
        }
    }
    for list in [
        &mut spec.sources,
        &mut spec.src_dirs,
        &mut spec.source_roots,
        &mut spec.outputs,
        &mut spec.argv,
        &mut spec.deps,
    ] {
        expand_arch(list, arch);
        expand_build_host(list, build_host);
    }
    for (_, value) in spec.env.iter_mut() {
        expand_build_host_one(value, build_host);
        *value = expand_build_host_table(value, build_host_table)?;
    }
    for (src, dest) in spec
        .copy
        .iter_mut()
        .chain(spec.stage_deps.iter_mut())
        .chain(spec.source_overlays.iter_mut())
    {
        expand_build_host_one(src, build_host);
        expand_build_host_one(dest, build_host);
        *src = expand_build_host_table(src, build_host_table)?;
        *dest = expand_build_host_table(dest, build_host_table)?;
    }
    for (src, dest) in spec.source_overlays.iter_mut() {
        *src = src.replace("{arch}", arch);
        *dest = dest.replace("{arch}", arch);
        *src = expand_target(src, arch_table)?;
        *dest = expand_target(dest, arch_table)?;
    }
    for (_, flags) in spec.groups.iter_mut() {
        expand_arch(flags, arch);
        expand_build_host(flags, build_host);
        for item in flags.iter_mut() {
            *item = expand_build_host_table(item, build_host_table)?;
            *item = expand_target(item, arch_table)?;
        }
    }
    for item in spec
        .argv
        .iter_mut()
        .chain(spec.outputs.iter_mut())
        .chain(spec.sources.iter_mut())
        .chain(spec.src_dirs.iter_mut())
        .chain(spec.source_roots.iter_mut())
        .chain(spec.deps.iter_mut())
    {
        *item = expand_build_host_table(item, build_host_table)?;
        *item = expand_target(item, arch_table)?;
    }
    for group in spec.compiles.iter_mut() {
        expand_arch(&mut group.flags, arch);
        expand_arch(&mut group.sources, arch);
        expand_arch(&mut group.scan_exclude, arch);
        expand_build_host(&mut group.flags, build_host);
        expand_build_host(&mut group.sources, build_host);
        expand_build_host(&mut group.scan_exclude, build_host);
        group.scan_dir = group.scan_dir.replace("{arch}", arch);
        expand_build_host_one(&mut group.scan_dir, build_host);
        group.scan_dir = expand_build_host_table(&group.scan_dir, build_host_table)?;
        for item in group
            .flags
            .iter_mut()
            .chain(group.sources.iter_mut())
            .chain(group.scan_exclude.iter_mut())
        {
            *item = expand_build_host_table(item, build_host_table)?;
            *item = expand_target(item, arch_table)?;
        }
    }
    for step in spec.steps.iter_mut() {
        expand_arch(&mut step.argv, arch);
        expand_arch(&mut step.outputs, arch);
        step.capture = step.capture.replace("{arch}", arch);
        expand_build_host(&mut step.argv, build_host);
        expand_build_host(&mut step.outputs, build_host);
        expand_build_host_one(&mut step.capture, build_host);
        step.capture = expand_build_host_table(&step.capture, build_host_table)?;
        step.capture = expand_target(&step.capture, arch_table)?;
        for item in step.argv.iter_mut() {
            *item = expand_build_host_table(item, build_host_table)?;
            *item = expand_target(item, arch_table)?;
        }
        for item in step.outputs.iter_mut() {
            *item = expand_build_host_table(item, build_host_table)?;
            *item = expand_target(item, arch_table)?;
        }
    }
    // An arch table leaves a dependency out for its architecture by
    // mapping the key to an empty string.
    spec.deps.retain(|dep| !dep.is_empty());
    no_newlines(&spec.argv, ctx)?;
    no_newlines(&spec.outputs, ctx)?;
    validate_source_projection(spec, ctx)?;
    Ok(())
}

/// The derivation a name finally configures: itself for a derivation, the
/// end of the `variant-of` chain for a variant.
pub fn variant_base<'a>(variants: &'a BTreeMap<String, Variant>, name: &'a str) -> &'a str {
    let mut current = name;
    let mut steps = 0;
    while let Some(variant) = variants.get(current) {
        current = &variant.base;
        steps += 1;
        if steps > variants.len() {
            break;
        }
    }
    current
}

fn parse_variant(
    doc: &toml::Doc,
    table: &toml::Table,
    name: &str,
    ctx: &str,
) -> Result<Variant, String> {
    use crate::spec::toml::Value;
    for entry in &table.entries {
        if !["variant-of", "config"].contains(&entry.key.as_str()) {
            return Err(format!(
                "{ctx}: a variant declares only `variant-of` and `config`, not `{}`",
                entry.key
            ));
        }
    }
    let base = tables::need_str(table, "variant-of", ctx)?;
    let mut overrides = address::Overrides::new();
    let mut add = |key: &str, value: &Value| -> Result<(), String> {
        let text = match value {
            Value::Str(text) => text.clone(),
            Value::Bool(flag) => flag.to_string(),
            Value::Int(number) => number.to_string(),
            _ => {
                return Err(format!(
                    "{ctx}: config.{key} must be a string, boolean or integer"
                ));
            }
        };
        if key.is_empty() || text.contains('\n') {
            return Err(format!("{ctx}: config.{key} is malformed"));
        }
        if overrides.insert(key.to_string(), text).is_some() {
            return Err(format!("{ctx}: config.{key} is declared twice"));
        }
        Ok(())
    };
    match table.get("config") {
        None => {}
        Some(Value::Inline(pairs)) => {
            for (key, value) in pairs {
                add(key, value)?;
            }
        }
        Some(_) => return Err(format!("{ctx}: `config` must be a table of overrides")),
    }
    if let Some(sub) = doc.table(&["derivation", name, "config"]) {
        for entry in &sub.entries {
            add(&entry.key, &entry.value)?;
        }
    }
    if overrides.is_empty() {
        return Err(format!(
            "{ctx}: a variant needs at least one config override"
        ));
    }
    Ok(Variant {
        name: name.to_string(),
        base,
        overrides,
    })
}

/// A variant configures a declared derivation or variant; a chain composes
/// its overrides and may neither loop nor set one key to two values.
fn validate_variant_cycles(variants: &BTreeMap<String, Variant>) -> Result<(), String> {
    for name in variants.keys() {
        let mut seen = std::collections::BTreeSet::new();
        let mut current = name.as_str();
        while let Some(variant) = variants.get(current) {
            if !seen.insert(current) {
                return Err(format!("configuration variant cycle through `{current}`"));
            }
            current = &variant.base;
        }
    }
    Ok(())
}

fn validate_variants(
    variants: &BTreeMap<String, Variant>,
    drvs: &BTreeMap<String, DrvSpec>,
) -> Result<(), String> {
    for (name, variant) in variants {
        let mut seen = std::collections::BTreeSet::new();
        let mut composed = address::Overrides::new();
        let mut current = variant;
        loop {
            if !seen.insert(current.name.clone()) {
                return Err(format!(
                    "variant `{name}` configures itself through `{}`",
                    current.name
                ));
            }
            for (key, value) in &current.overrides {
                match composed.get(key) {
                    Some(existing) if existing != value => {
                        return Err(format!(
                            "variant `{name}` sets {key} to `{existing}` and, through `{}`, to `{value}`",
                            current.name
                        ));
                    }
                    _ => {
                        composed.insert(key.clone(), value.clone());
                    }
                }
            }
            if let Some(next) = variants.get(&current.base) {
                current = next;
            } else if drvs.contains_key(&current.base) {
                break;
            } else {
                return Err(format!(
                    "variant `{}` configures unknown `{}`",
                    current.name, current.base
                ));
            }
        }
    }
    Ok(())
}

fn validate_tool_provider_derivations(
    providers: &BTreeMap<String, ToolProviderSpec>,
    stages: &BTreeMap<String, StageSpec>,
    drvs: &BTreeMap<String, DrvSpec>,
) -> Result<(), String> {
    for (alias, provider) in providers {
        if !drvs.contains_key(&provider.derivation) {
            return Err(format!(
                "tool provider `{alias}` names missing derivation `{}`",
                provider.derivation
            ));
        }
    }
    for stage in stages.values() {
        for (tool, provider) in &stage.tools {
            if !drvs.contains_key(&provider.derivation) {
                return Err(format!(
                    "stage `{}`: tool `{tool}` names missing derivation `{}`",
                    stage.name, provider.derivation
                ));
            }
        }
        for mount in &stage.mounts {
            if !drvs.contains_key(&mount.derivation) {
                return Err(format!(
                    "stage `{}`: mount `{}` names missing derivation `{}`",
                    stage.name, mount.target, mount.derivation
                ));
            }
        }
    }
    Ok(())
}

fn collect_spec_inputs(repo_root: &Path, subsystems: &[String]) -> Result<Vec<SpecInput>, String> {
    let mut paths = vec!["buildutil.toml".to_string()];
    for subsystem in subsystems {
        paths.push(format!("{subsystem}/buildutil.toml"));
    }
    paths.sort();
    paths.dedup();
    let mut out = Vec::new();
    for rel in paths {
        let hash = crate::source::filehash::hash_file(&repo_root.join(&rel))?;
        out.push(SpecInput {
            path: rel,
            hash,
            kind: SpecInputKind::File,
        });
    }
    Ok(out)
}

/// The current hash of a static specification input. A generated input has
/// no checkout form; the generation phase decides whether it is current, so
/// it reports its recorded hash.
pub(crate) fn hash_spec_input(repo_root: &Path, input: &SpecInput) -> Result<String, String> {
    match input.kind {
        SpecInputKind::File => crate::source::filehash::hash_file(&repo_root.join(&input.path)),
        SpecInputKind::Generated => Ok(input.hash.clone()),
    }
}

pub fn dep_tokens(arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    for prefix in ["{dep:", "{dep-abs:"] {
        let mut rest = arg;
        while let Some(start) = rest.find(prefix) {
            let tail = &rest[start + prefix.len()..];
            if let Some(end) = tail.find('}') {
                out.push(tail[..end].to_string());
                rest = &tail[end + 1..];
            } else {
                break;
            }
        }
    }
    out
}

impl Spec {
    pub(crate) fn source_repository<'a>(
        &'a self,
        key: &'a str,
    ) -> Option<(&'a Repository, &'a str)> {
        for drv in self.drvs.values() {
            if let Some(owner) = &drv.repository {
                if let Some(relative) = key.strip_prefix(&owner.source_key("")) {
                    return Some((owner, relative));
                }
            }
        }
        None
    }
    /// Resolve evaluation-only source keys without exposing another owner's
    /// checkout through a staged source path.
    pub(crate) fn source_path(&self, key: &str) -> Result<PathBuf, String> {
        if key.starts_with("input:") {
            if let Some((owner, relative)) = self.source_repository(key) {
                crate::inputs::codec::clean_path(relative)?;
                return Ok(owner.root.join(relative));
            }
            return Err(format!(
                "source key `{key}` has no resolved repository owner"
            ));
        }
        Ok(self.repo_root.join(key))
    }

    /// The stage whose environment a derivation uses, when declared.
    pub fn stage_for(&self, dspec: &DrvSpec) -> Option<&StageSpec> {
        self.stages.get(stages::stage_name(dspec))
    }

    /// The declared provider of `tool` for `dspec`: its stage's map first,
    /// then the `[tool-provider]` aliases. `None` for reserved names and
    /// for the native frontend, whose tools are ambient.
    pub fn declared_tool(&self, dspec: &DrvSpec, tool: &str) -> Option<&ToolProviderSpec> {
        if dspec.native_frontend || crate::tools::is_reserved(tool) {
            return None;
        }
        let staged = self
            .stage_for(dspec)
            .and_then(|stage| stage.tools.get(tool));
        if dspec.repository.is_some() {
            staged
        } else {
            staged.or_else(|| self.tool_providers.get(tool))
        }
    }

    /// Select the provider of `tool` for `dspec`: a reserved name through
    /// the engine, any other through the declarations.
    pub fn tool_provider(&self, dspec: &DrvSpec, tool: &str) -> Option<crate::tools::ToolProvider> {
        let mode = crate::tools::ToolMode::for_derivation(dspec.bootstrap, dspec.native_frontend);
        crate::tools::tool_provider(tool, mode).or_else(|| {
            self.declared_tool(dspec, tool)
                .map(|provider| crate::tools::ToolProvider::Store {
                    drv: provider.derivation.clone(),
                    relpath: provider.path.clone(),
                })
        })
    }

    /// Resolve a selected provider through the ordinary Toolchain locator.
    pub fn tool_locator(
        &self,
        toolchain: &crate::tools::Toolchain,
        dspec: &DrvSpec,
        tool: &str,
    ) -> crate::tools::ToolLocator {
        toolchain.locator_for_provider(tool, self.tool_provider(dspec, tool))
    }

    /// Whether the generation phase has yet to run.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Expand a drv's argv into its eval-phase form: flagsets spliced,
    /// flag-groups applied against the configuration (recording the
    /// projection), `{config.*}` substituted. `{srcroot}`/`{out}`/`{dep:*}`
    /// stay symbolic.
    pub fn eval_argv(
        &self,
        drv: &DrvSpec,
        view: &mut configres::ConfigView<'_>,
    ) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        out.push(drv.tool.clone());
        let mut args = self.splice_flagsets(&drv.argv, view)?;
        match drv.builder.as_str() {
            "clang-obj" | "clang-link" => color_diagnostics(Compiler::Clang, &mut args),
            "rustc-crate" => color_diagnostics(Compiler::Rustc, &mut args),
            _ => {}
        }
        out.extend(args);
        for (when, flags) in &drv.groups {
            if view.eval_when(when)? {
                out.extend(flags.iter().cloned());
            }
        }
        tables::subst_config(&mut out, view)?;
        // A module builder's declared keys enter its projection whether or
        // not its module reads them: the module sees exactly these.
        for key in &drv.config_keys {
            view.get(key)?;
        }
        Ok(out)
    }

    /// Expand `{flagset:*}` tokens (recursively — flagsets may reference
    /// other flagsets) with their config-gated groups and cfg aggregates.
    fn splice_flagsets(
        &self,
        items: &[String],
        view: &mut configres::ConfigView<'_>,
    ) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for item in items {
            let Some(name) = item
                .strip_prefix("{flagset:")
                .and_then(|r| r.strip_suffix('}'))
            else {
                out.push(item.clone());
                continue;
            };
            let fs = self
                .flagsets
                .get(name)
                .ok_or_else(|| format!("unknown flagset `{}`", name))?;
            out.extend(self.splice_flagsets(&fs.flags, view)?);
            for (when, flags) in &fs.groups {
                if view.eval_when(when)? {
                    out.extend(self.splice_flagsets(flags, view)?);
                }
            }
            for key in &fs.cfg_each {
                let list = view.get(key)?.to_string();
                for cfg in list.split(',').filter(|s| !s.is_empty()) {
                    out.push("--cfg".to_string());
                    out.push(cfg.to_string());
                }
            }
            out.extend(fs.tail.iter().cloned());
        }
        Ok(out)
    }

    /// Filter a script-dag derivation's compile groups and steps against
    /// the configuration and substitute `{config.*}`; the reads are
    /// recorded into the projection.
    pub fn eval_plan(
        &self,
        drv: &DrvSpec,
        view: &mut configres::ConfigView<'_>,
    ) -> Result<ActivePlan, String> {
        let mut plan = ActivePlan {
            compiles: Vec::new(),
            steps: Vec::new(),
        };
        for group in &drv.compiles {
            if view.eval_when(&group.when)? {
                let mut group = group.clone();
                group.flags = self.splice_flagsets(&group.flags, view)?;
                if matches!(group.kind.as_str(), "cc" | "cc-simple") {
                    color_diagnostics(Compiler::Clang, &mut group.flags);
                }
                tables::subst_config(&mut group.flags, view)?;
                if !group.scan_dir.is_empty() {
                    group.sources = tables::scan_sources(
                        drv.repository
                            .as_ref()
                            .map(|owner| &owner.root)
                            .unwrap_or(&self.repo_root),
                        &group.scan_dir,
                        &group.scan_ext,
                        &group.scan_exclude,
                    )?;
                }
                plan.compiles.push(group);
            }
        }
        for step in &drv.steps {
            if view.eval_when(&step.when)? {
                let mut step = step.clone();
                step.argv = self.splice_flagsets(&step.argv, view)?;
                tables::subst_config(&mut step.argv, view)?;
                tables::subst_config(&mut step.outputs, view)?;
                plan.steps.push(step);
            }
        }
        Ok(plan)
    }
}

enum Compiler {
    Clang,
    Rustc,
}

/// Request colored diagnostics from a compiler buildutil runs itself, unless the
/// declaration already chose. The request is part of the evaluated arguments,
/// so it is constant and hashed; the build view removes the escapes where
/// color is off, so identity never depends on one invocation's terminal.
fn color_diagnostics(compiler: Compiler, args: &mut Vec<String>) {
    let (flag, chosen): (&str, fn(&str) -> bool) = match compiler {
        Compiler::Clang => ("-fcolor-diagnostics", |a| {
            a == "-fcolor-diagnostics"
                || a == "-fno-color-diagnostics"
                || a.starts_with("-fdiagnostics-color")
                || a == "-fno-diagnostics-color"
        }),
        Compiler::Rustc => ("--color=always", |a| {
            a == "--color" || a.starts_with("--color=")
        }),
    };
    if !args.iter().any(|a| chosen(a)) {
        args.insert(0, flag.to_string());
    }
}
