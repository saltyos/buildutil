//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — stage environments, declared tool providers and build-host tables
//!
//! Owns the declarative side of the host boundary: which derivation provides
//! each tool a derivation declares (`[tool-provider.<alias>]` and the
//! per-stage `tools` maps), what every derivation of a stage receives
//! (`default-tools`, the tool bound at `/bin/sh`, read-only `mounts` such as
//! the dynamic loader and libc at `/lib`, and the tool that substitutes its
//! realizations), the `[configuration]` table naming the option graph and
//! its editor, and the merge of `[build-host.<triple>]` tables from every
//! specification file. The engine names no provider itself; the reserved
//! names in `crate::tools` are the only exception.
//!
//! A derivation's stage is its `stage` key, else `bootstrap` for a
//! bootstrap-grade derivation, else `default`.

use std::collections::BTreeMap;
use std::path::Path;

use super::DrvSpec;
use super::tables;
use super::toml::{Doc, Table, Value};

/// A tool's provider: a derivation output path, with the facts the
/// executor needs to run it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolProviderSpec {
    pub derivation: String,
    pub path: String,
    /// The argument `{tool-version:<tool>}` passes to query the tool's
    /// version; `--version` when undeclared.
    pub version_flag: Option<String>,
}

/// A directory of a provider bound read-only at a fixed path inside the
/// build's private root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    /// Absolute path inside the build root (`/lib`).
    pub target: String,
    pub derivation: String,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageSpec {
    pub name: String,
    /// Tool name → provider, after `inherit` is applied.
    pub tools: BTreeMap<String, ToolProviderSpec>,
    /// Tools every derivation of the stage has in its toolbin.
    pub default_tools: Vec<String>,
    /// The default tool bound at `/bin/sh`.
    pub shell: Option<String>,
    pub mounts: Vec<Mount>,
    /// The tool that fetches this stage's substitutable realizations.
    pub substituter: Option<String>,
}

/// The option graph shared by engine evaluation and the configuration commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationSpec {
    /// Repository-relative directory of the option graph's `*.toml` files.
    pub graph: String,
    /// An optional declared editor derivation.
    pub editor: Option<String>,
    /// The option `buildutil setup --arch <a>` seeds with the architecture.
    pub arch_option: Option<String>,
    /// A boolean option whose true value makes the build report name its
    /// profile `debug` rather than `release`.
    pub profile_option: Option<String>,
}

/// The executor image's inputs: the pinned seed, which is the image's
/// first layer, and the stage-0 Rust distribution archives merged into its
/// second. Values are expanded for the build host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorImageSpec {
    /// State-relative path of the seed archive (`sources/seed/<host>/…`).
    pub seed: String,
    pub seed_sha256: String,
    /// (URL, sha256) of each distribution component archive (`.tar.gz`).
    pub rust_archives: Vec<(String, String)>,
    /// Image-relative directory the distribution is installed under.
    pub rust_prefix: String,
}

/// A `[stage.<name>]` table as declared, before `inherit` and alias
/// resolution, which may reach tables in other files.
#[derive(Clone, Debug)]
pub struct RawStage {
    manifest: String,
    inherit: Option<String>,
    tools: Vec<(String, String)>,
    default_tools: Vec<String>,
    shell: Option<String>,
    mounts: Vec<Mount>,
    substituter: Option<String>,
}

/// The stage name a derivation's tools resolve through.
pub fn stage_name(dspec: &DrvSpec) -> &str {
    match &dspec.stage {
        Some(name) => name,
        None if dspec.bootstrap => "bootstrap",
        None => "default",
    }
}

fn check_keys(table: &Table, allowed: &[&str], ctx: &str) -> Result<(), String> {
    for entry in &table.entries {
        if !allowed.contains(&entry.key.as_str()) {
            return Err(format!("{ctx}: unknown key `{}`", entry.key));
        }
    }
    Ok(())
}

fn opt_string(table: &Table, key: &str, ctx: &str) -> Result<Option<String>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| format!("{ctx}: `{key}` must be a string")),
    }
}

fn validate_provider_path(path: &str, context: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!(
            "{context}: path must be a normalized relative provider path"
        ));
    }
    Ok(())
}

/// `<derivation>:<relative path>`.
fn parse_provider_ref(value: &str, context: &str) -> Result<(String, String), String> {
    let (derivation, path) = value
        .split_once(':')
        .ok_or_else(|| format!("{context}: `{value}` must be `<derivation>:<path>`"))?;
    if derivation.is_empty() {
        return Err(format!("{context}: `{value}` names no derivation"));
    }
    validate_provider_path(path, context)?;
    Ok((derivation.to_string(), path.to_string()))
}

pub fn load_tool_providers(
    doc: &Doc,
    manifest: &Path,
    providers: &mut BTreeMap<String, ToolProviderSpec>,
) -> Result<(), String> {
    for table in doc.tables_under(&["tool-provider"]) {
        if table.path.len() != 2 || table.is_array {
            return Err(format!(
                "{}: [tool-provider] entries must be named tables",
                manifest.display()
            ));
        }
        let alias = &table.path[1];
        let context = format!("{}: [tool-provider.{alias}]", manifest.display());
        if crate::tools::is_reserved(alias) {
            return Err(format!(
                "{context}: `{alias}` is reserved by the engine and takes no declared provider"
            ));
        }
        if providers.contains_key(alias) {
            return Err(format!(
                "{context}: duplicate tool provider alias `{alias}`"
            ));
        }
        check_keys(table, &["derivation", "path", "version-flag"], &context)?;
        let derivation = tables::need_str(table, "derivation", &context)?;
        let path = tables::need_str(table, "path", &context)?;
        validate_provider_path(&path, &context)?;
        let version_flag = opt_string(table, "version-flag", &context)?;
        providers.insert(
            alias.clone(),
            ToolProviderSpec {
                derivation,
                path,
                version_flag,
            },
        );
    }
    Ok(())
}

pub fn load_stages(
    doc: &Doc,
    manifest: &Path,
    stages: &mut BTreeMap<String, RawStage>,
) -> Result<(), String> {
    for table in doc.tables_under(&["stage"]) {
        if table.path.len() != 2 || table.is_array {
            return Err(format!(
                "{}: [stage] entries must be named tables",
                manifest.display()
            ));
        }
        let name = &table.path[1];
        let context = format!("{}: [stage.{name}]", manifest.display());
        if stages.contains_key(name) {
            return Err(format!("{context}: stage `{name}` is declared twice"));
        }
        check_keys(
            table,
            &[
                "inherit",
                "tools",
                "default-tools",
                "shell",
                "mounts",
                "substituter",
            ],
            &context,
        )?;
        let mut tools = Vec::new();
        for item in tables::opt_str_list(table, "tools", &context)? {
            let (tool, provider) = item
                .split_once('=')
                .ok_or_else(|| format!("{context}: tools entry `{item}` is not `<tool>=<provider>`"))?;
            if tool.is_empty() || provider.is_empty() {
                return Err(format!("{context}: tools entry `{item}` is incomplete"));
            }
            if crate::tools::is_reserved(tool) {
                return Err(format!(
                    "{context}: `{tool}` is reserved by the engine and takes no declared provider"
                ));
            }
            if tools.iter().any(|(t, _): &(String, String)| t == tool) {
                return Err(format!("{context}: tool `{tool}` is mapped twice"));
            }
            tools.push((tool.to_string(), provider.to_string()));
        }
        let mut mounts = Vec::new();
        for item in tables::opt_str_list(table, "mounts", &context)? {
            let (target, provider) = item.split_once('=').ok_or_else(|| {
                format!("{context}: mounts entry `{item}` is not `<path>=<derivation>:<dir>`")
            })?;
            if !target.starts_with('/')
                || target.split('/').skip(1).any(|c| c.is_empty() || c == "." || c == "..")
                || target == "/"
            {
                return Err(format!(
                    "{context}: mount target `{target}` must be a normalized absolute path below /"
                ));
            }
            let (derivation, path) = parse_provider_ref(provider, &context)?;
            mounts.push(Mount {
                target: target.to_string(),
                derivation,
                path,
            });
        }
        stages.insert(
            name.clone(),
            RawStage {
                manifest: manifest.display().to_string(),
                inherit: opt_string(table, "inherit", &context)?,
                tools,
                default_tools: tables::opt_str_list(table, "default-tools", &context)?,
                shell: opt_string(table, "shell", &context)?,
                mounts,
                substituter: opt_string(table, "substituter", &context)?,
            },
        );
    }
    Ok(())
}

/// Apply `inherit` chains and resolve every tool entry to a provider: a
/// `<derivation>:<path>` entry is its own provider, any other names a
/// `[tool-provider]` alias.
pub fn resolve_stages(
    raw: &BTreeMap<String, RawStage>,
    providers: &BTreeMap<String, ToolProviderSpec>,
) -> Result<BTreeMap<String, StageSpec>, String> {
    let mut out = BTreeMap::new();
    for name in raw.keys() {
        let mut chain = vec![name.clone()];
        let mut current = name;
        while let Some(parent) = &raw[current].inherit {
            if chain.contains(parent) {
                return Err(format!(
                    "stage `{name}` inherits in a cycle: {} -> {parent}",
                    chain.join(" -> ")
                ));
            }
            if !raw.contains_key(parent) {
                return Err(format!(
                    "{}: [stage.{current}] inherits unknown stage `{parent}`",
                    raw[current].manifest
                ));
            }
            chain.push(parent.clone());
            current = parent;
        }
        let mut stage = StageSpec {
            name: name.clone(),
            tools: BTreeMap::new(),
            default_tools: Vec::new(),
            shell: None,
            mounts: Vec::new(),
            substituter: None,
        };
        // Farthest ancestor first, so a nearer stage replaces what it
        // inherits.
        for member in chain.iter().rev() {
            let decl = &raw[member];
            let context = format!("{}: [stage.{member}]", decl.manifest);
            for (tool, provider) in &decl.tools {
                let resolved = if provider.contains(':') {
                    let (derivation, path) = parse_provider_ref(provider, &context)?;
                    ToolProviderSpec {
                        derivation,
                        path,
                        version_flag: None,
                    }
                } else {
                    providers.get(provider).cloned().ok_or_else(|| {
                        format!("{context}: tool `{tool}` names unknown provider `{provider}`")
                    })?
                };
                stage.tools.insert(tool.clone(), resolved);
            }
            for tool in &decl.default_tools {
                if !stage.default_tools.contains(tool) {
                    stage.default_tools.push(tool.clone());
                }
            }
            if decl.shell.is_some() {
                stage.shell = decl.shell.clone();
            }
            for mount in &decl.mounts {
                stage.mounts.retain(|m| m.target != mount.target);
                stage.mounts.push(mount.clone());
            }
            if decl.substituter.is_some() {
                stage.substituter = decl.substituter.clone();
            }
        }
        let context = format!("{}: [stage.{name}]", raw[name].manifest);
        for tool in stage
            .default_tools
            .iter()
            .chain(stage.shell.iter())
            .chain(stage.substituter.iter())
        {
            if !stage.tools.contains_key(tool) && !providers.contains_key(tool) {
                return Err(format!("{context}: `{tool}` has no provider in this stage"));
            }
        }
        if let Some(shell) = &stage.shell {
            if !stage.default_tools.contains(shell) {
                return Err(format!(
                    "{context}: shell `{shell}` must be one of the stage's default-tools"
                ));
            }
        }
        out.insert(name.clone(), stage);
    }
    Ok(out)
}

pub fn load_configuration(
    doc: &Doc,
    manifest: &Path,
    out: &mut Option<ConfigurationSpec>,
) -> Result<(), String> {
    let Some(table) = doc.table(&["configuration"]) else {
        return Ok(());
    };
    let context = format!("{}: [configuration]", manifest.display());
    if out.is_some() {
        return Err(format!("{context}: [configuration] is declared twice"));
    }
    check_keys(
        table,
        &["graph", "editor", "arch-option", "profile-option"],
        &context,
    )?;
    let graph = tables::need_str(table, "graph", &context)?;
    if graph.is_empty()
        || graph.starts_with('/')
        || graph
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!(
            "{context}: graph must be a clean repository-relative directory"
        ));
    }
    *out = Some(ConfigurationSpec {
        graph,
        editor: opt_string(table, "editor", &context)?,
        arch_option: opt_string(table, "arch-option", &context)?,
        profile_option: opt_string(table, "profile-option", &context)?,
    });
    Ok(())
}

/// Read the `[executor-image]` table of one file. `expand` applies the
/// build-host and architecture expansions every value receives.
pub fn load_executor_image(
    doc: &Doc,
    manifest: &Path,
    expand: &dyn Fn(&str) -> Result<String, String>,
    out: &mut Option<ExecutorImageSpec>,
) -> Result<(), String> {
    let Some(table) = doc.table(&["executor-image"]) else {
        return Ok(());
    };
    let context = format!("{}: [executor-image]", manifest.display());
    if out.is_some() {
        return Err(format!("{context}: [executor-image] is declared twice"));
    }
    check_keys(
        table,
        &["seed", "seed-sha256", "rust-archives", "rust-prefix"],
        &context,
    )?;
    let seed = expand(&tables::need_str(table, "seed", &context)?)?;
    validate_provider_path(&seed, &context)?;
    let seed_sha256 = expand(&tables::need_str(table, "seed-sha256", &context)?)?;
    let hex64 = |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex64(&seed_sha256) {
        return Err(format!("{context}: seed-sha256 must be 64 hex digits"));
    }
    let mut rust_archives = Vec::new();
    for item in tables::opt_str_list(table, "rust-archives", &context)? {
        let item = expand(&item)?;
        let (url, sha) = item
            .rsplit_once('=')
            .ok_or_else(|| format!("{context}: rust-archives entry `{item}` is not `<url>=<sha256>`"))?;
        if !url.starts_with("https://") || !url.ends_with(".tar.gz") {
            return Err(format!(
                "{context}: `{url}` must be an https URL of a .tar.gz archive"
            ));
        }
        if !hex64(sha) {
            return Err(format!("{context}: `{url}` needs a 64-hex sha256 pin"));
        }
        rust_archives.push((url.to_string(), sha.to_string()));
    }
    if rust_archives.is_empty() {
        return Err(format!("{context}: rust-archives names no archive"));
    }
    let rust_prefix = tables::need_str(table, "rust-prefix", &context)?;
    validate_provider_path(&rust_prefix, &context)?;
    *out = Some(ExecutorImageSpec {
        seed,
        seed_sha256,
        rust_archives,
        rust_prefix,
    });
    Ok(())
}

/// Merge the `[build-host.<triple>]` table of one file into `table`; a key
/// declared by two files is refused.
pub fn merge_build_host(
    doc: &Doc,
    manifest: &Path,
    build_host: &str,
    table: &mut BTreeMap<String, (String, String)>,
) -> Result<(), String> {
    let Some(t) = doc.table(&["build-host", build_host]) else {
        return Ok(());
    };
    for e in &t.entries {
        let Value::Str(v) = &e.value else {
            return Err(format!(
                "{}: [build-host.{}] {} must be a string",
                manifest.display(),
                build_host,
                e.key
            ));
        };
        let here = manifest.display().to_string();
        if let Some((_, first)) = table.get(&e.key) {
            return Err(format!(
                "[build-host.{}] {} is declared by both {} and {}",
                build_host, e.key, first, here
            ));
        }
        table.insert(e.key.clone(), (v.clone(), here));
    }
    Ok(())
}

/// Give every derivation its stage's environment: the default tools join
/// its declared tools and the mount providers join its dependencies, so
/// both enter its identity like any declaration. An in-process builder
/// runs no tool and receives neither; a native-frontend derivation uses
/// only its ambient compiler.
pub fn apply_stage_environment(
    drvs: &mut BTreeMap<String, DrvSpec>,
    stages: &BTreeMap<String, StageSpec>,
    require_stages: bool,
) -> Result<(), String> {
    for dspec in drvs.values_mut() {
        if dspec.native_frontend || super::builders::is_in_process(&dspec.builder) {
            continue;
        }
        let name = stage_name(dspec).to_string();
        let Some(stage) = stages.get(&name) else {
            if dspec.stage.is_some() || require_stages {
                return Err(format!(
                    "derivation `{}` uses stage `{name}`, which no [stage] table declares",
                    dspec.name
                ));
            }
            continue;
        };
        for tool in &stage.default_tools {
            if dspec.tool != *tool && !dspec.extra_tools.contains(tool) {
                dspec.extra_tools.push(tool.clone());
            }
        }
        for mount in &stage.mounts {
            if mount.derivation != dspec.name && !dspec.deps.contains(&mount.derivation) {
                dspec.deps.push(mount.derivation.clone());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> Doc {
        super::super::toml::parse(Path::new("t.toml"), text).unwrap()
    }

    #[test]
    fn stages_inherit_and_replace_providers() {
        let d = doc(
            "[tool-provider.nasm-two]\n\
             derivation = \"host-nasm\"\n\
             path = \"bin/nasm\"\n\
             version-flag = \"-v\"\n\
             [stage.seed]\n\
             tools = [\"sh=seed:bin/sh\", \"cmake=seed:bin/cmake\"]\n\
             default-tools = [\"sh\"]\n\
             shell = \"sh\"\n\
             mounts = [\"/lib=seed:lib\"]\n\
             substituter = \"sh\"\n\
             [stage.default]\n\
             inherit = \"seed\"\n\
             tools = [\"cmake=host-cmake:bin/cmake\", \"nasm=nasm-two\"]\n",
        );
        let mut providers = BTreeMap::new();
        load_tool_providers(&d, Path::new("t.toml"), &mut providers).unwrap();
        let mut raw = BTreeMap::new();
        load_stages(&d, Path::new("t.toml"), &mut raw).unwrap();
        let stages = resolve_stages(&raw, &providers).unwrap();
        let default = &stages["default"];
        assert_eq!(default.tools["sh"].derivation, "seed");
        assert_eq!(default.tools["cmake"].derivation, "host-cmake");
        assert_eq!(default.tools["nasm"].version_flag.as_deref(), Some("-v"));
        assert_eq!(default.shell.as_deref(), Some("sh"));
        assert_eq!(default.mounts[0].target, "/lib");
        assert_eq!(stages["seed"].tools["cmake"].derivation, "seed");
    }

    #[test]
    fn reserved_names_and_bad_mounts_are_refused() {
        let mut raw = BTreeMap::new();
        let d = doc("[stage.x]\ntools = [\"buildutil=a:b\"]\n");
        assert!(load_stages(&d, Path::new("t.toml"), &mut raw).is_err());
        let d = doc("[stage.x]\nmounts = [\"lib=a:lib\"]\n");
        assert!(load_stages(&d, Path::new("t.toml"), &mut raw).is_err());
        let d = doc("[stage.x]\nmounts = [\"/lib=a:../lib\"]\n");
        assert!(load_stages(&d, Path::new("t.toml"), &mut raw).is_err());
    }

    #[test]
    fn shell_must_be_a_default_tool_and_inherit_cycles_fail() {
        let d = doc("[stage.x]\ntools = [\"sh=a:bin/sh\"]\nshell = \"sh\"\n");
        let mut raw = BTreeMap::new();
        load_stages(&d, Path::new("t.toml"), &mut raw).unwrap();
        assert!(resolve_stages(&raw, &BTreeMap::new()).is_err());

        let d = doc("[stage.a]\ninherit = \"b\"\n[stage.b]\ninherit = \"a\"\n");
        let mut raw = BTreeMap::new();
        load_stages(&d, Path::new("t.toml"), &mut raw).unwrap();
        assert!(resolve_stages(&raw, &BTreeMap::new()).is_err());
    }

    #[test]
    fn build_host_keys_merge_across_files_and_refuse_duplicates() {
        let mut table = BTreeMap::new();
        let a = doc("[build-host.h]\nseed-sha256 = \"aa\"\n");
        let b = doc("[build-host.h]\nloader = \"ld\"\n");
        merge_build_host(&a, Path::new("a.toml"), "h", &mut table).unwrap();
        merge_build_host(&b, Path::new("b.toml"), "h", &mut table).unwrap();
        assert_eq!(table["loader"].0, "ld");
        assert!(merge_build_host(&a, Path::new("c.toml"), "h", &mut table).is_err());
    }
}
