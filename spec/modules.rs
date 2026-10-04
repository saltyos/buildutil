//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — module declarations and the derivations buildutil synthesizes for them
//!
//! `[module.<name>]` declares a module by its source crate (`src`, plus any
//! `src-dirs` the crate includes); `[module.<name>.config]` and its nested
//! tables are its configuration, passed to the module unchanged. buildutil
//! builds every module twice over: `buildutil-module-<name>`, a bootstrap-grade
//! store derivation against the store SDK for the roles that run on the
//! build host, and `buildutil-module-<name>-native`, a self-tool against the
//! client's SDK for client apps. Each build records the SDK version the
//! module answers with. `[generate.<name>]` declares a generator; buildutil
//! synthesizes `buildutil-generate-<name>`, whose output is the generated
//! declarations. The formatter and build-host apps run as
//! `buildutil-formatter` and `buildutil-app-<name>`, uncached, on the dev path.
//!
//! The effective module configuration is canonical JSON; its SHA-256 is the
//! `module-config:` identity line of every derivation the module builds or
//! generates, and the JSON itself travels to the module at execution.

use std::collections::BTreeMap;

use super::kinds::{AppSpec, FormatterSpec};
use super::stages::ToolProviderSpec;
use super::tables;
use super::toml::{Doc, Table, Value as TomlValue};
use super::{DrvSpec, RefPolicy, Step};
use crate::sdk_wire::Value;

/// The store and self-tool SDK derivations every module links.
pub const SDK_DRV: &str = "lib-buildutil-sdk";
pub const SDK_NATIVE_DRV: &str = "lib-buildutil-sdk-native";
/// The module executable inside a module derivation's output.
pub const MODULE_BINARY: &str = "module";

const MODULE_DRV_PREFIX: &str = "buildutil-module-";
const NATIVE_SUFFIX: &str = "-native";
const GENERATOR_DRV_PREFIX: &str = "buildutil-generate-";
pub const FORMATTER_DRV: &str = "buildutil-formatter";
const APP_DRV_PREFIX: &str = "buildutil-app-";

/// The roles a module runs in, as the request names them.
pub const ROLE_BUILDER: &str = "builder";
pub const ROLE_GENERATOR: &str = "generator";
pub const ROLE_FORMATTER: &str = "formatter";
pub const ROLE_CLIENT_APP: &str = "client-app";
pub const ROLE_BUILD_HOST_APP: &str = "build-host-app";

#[derive(Clone, Debug)]
pub struct ModuleSpec {
    pub name: String,
    /// Repository directory holding the crate's `main.rs`.
    pub src: String,
    /// Further repository directories the crate includes.
    pub src_dirs: Vec<String>,
    /// The effective configuration.
    pub config: Value,
    /// Its canonical JSON text and that text's SHA-256.
    pub config_json: String,
    pub config_digest: String,
    pub origin: String,
}

#[derive(Clone, Debug)]
pub struct GeneratorSpec {
    pub name: String,
    pub module: String,
    /// The synthesized derivation that runs it.
    pub derivation: String,
    pub origin: String,
}

pub fn module_derivation_name(module: &str) -> String {
    format!("{MODULE_DRV_PREFIX}{module}")
}

pub fn native_module_derivation_name(module: &str) -> String {
    format!("{MODULE_DRV_PREFIX}{module}{NATIVE_SUFFIX}")
}

pub fn generator_derivation_name(generator: &str) -> String {
    format!("{GENERATOR_DRV_PREFIX}{generator}")
}

pub fn app_derivation_name(app: &str) -> String {
    format!("{APP_DRV_PREFIX}{app}")
}

/// The tool name a module builder's derivation runs: the module's store
/// executable.
pub fn module_tool(module: &str) -> String {
    module_derivation_name(module)
}

fn clean_dir(value: &str, ctx: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!(
            "{ctx}: `{value}` is not a clean repository-relative directory"
        ));
    }
    Ok(())
}

/// A TOML value as a wire value: inline tables become tables.
pub fn wire_value(value: &TomlValue) -> Value {
    match value {
        TomlValue::Str(text) => Value::Str(text.clone()),
        TomlValue::Int(number) => Value::Int(*number),
        TomlValue::Bool(flag) => Value::Bool(*flag),
        TomlValue::Array(items) => Value::List(items.iter().map(wire_value).collect()),
        TomlValue::Inline(pairs) => Value::Table(
            pairs
                .iter()
                .map(|(key, item)| (key.clone(), wire_value(item)))
                .collect(),
        ),
    }
}

/// Insert `entries` at `path` inside `root`, creating tables on the way.
/// An array-of-tables element appends to a list there.
fn insert_config(
    root: &mut BTreeMap<String, Value>,
    path: &[String],
    array: bool,
    entries: BTreeMap<String, Value>,
    ctx: &str,
) -> Result<(), String> {
    let Some((last, parents)) = path.split_last() else {
        for (key, value) in entries {
            if root.insert(key.clone(), value).is_some() {
                return Err(format!("{ctx}: `{key}` is declared twice"));
            }
        }
        return Ok(());
    };
    let mut current = root;
    for part in parents {
        let slot = current
            .entry(part.clone())
            .or_insert_with(|| Value::Table(BTreeMap::new()));
        current = match slot {
            Value::Table(map) => map,
            Value::List(items) => match items.last_mut() {
                Some(Value::Table(map)) => map,
                _ => return Err(format!("{ctx}: `{part}` is not a table")),
            },
            _ => return Err(format!("{ctx}: `{part}` is not a table")),
        };
    }
    if array {
        match current
            .entry(last.clone())
            .or_insert_with(|| Value::List(Vec::new()))
        {
            Value::List(items) => items.push(Value::Table(entries)),
            _ => return Err(format!("{ctx}: `{last}` is not an array of tables")),
        }
        return Ok(());
    }
    match current
        .entry(last.clone())
        .or_insert_with(|| Value::Table(BTreeMap::new()))
    {
        Value::Table(map) => {
            for (key, value) in entries {
                if map.insert(key.clone(), value).is_some() {
                    return Err(format!("{ctx}: `{last}.{key}` is declared twice"));
                }
            }
            Ok(())
        }
        _ => Err(format!("{ctx}: `{last}` is not a table")),
    }
}

fn entries_of(table: &Table) -> BTreeMap<String, Value> {
    table
        .entries
        .iter()
        .map(|entry| (entry.key.clone(), wire_value(&entry.value)))
        .collect()
}

/// Read one file's `[module.*]` tables into `out`.
pub fn parse_modules(
    doc: &Doc,
    origin: &str,
    out: &mut BTreeMap<String, ModuleSpec>,
) -> Result<(), String> {
    let mut configs: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    let mut declared: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for table in &doc.tables {
        if table.path.first().map(String::as_str) != Some("module") {
            continue;
        }
        let Some(name) = table.path.get(1) else {
            return Err(format!(
                "{origin}: modules are declared as named tables, [module.<name>]"
            ));
        };
        let ctx = format!("{origin}: [module.{name}]");
        if table.path.len() == 2 {
            if table.is_array {
                return Err(format!("{ctx} is not an array"));
            }
            for entry in &table.entries {
                if !["src", "src-dirs", "config"].contains(&entry.key.as_str()) {
                    return Err(format!("{ctx}: unknown key `{}`", entry.key));
                }
            }
            let src = tables::need_str(table, "src", &ctx)?;
            clean_dir(&src, &ctx)?;
            let src_dirs = tables::opt_str_list(table, "src-dirs", &ctx)?;
            for dir in &src_dirs {
                clean_dir(dir, &ctx)?;
            }
            if declared.insert(name.clone(), (src, src_dirs)).is_some() {
                return Err(format!("{ctx} is declared twice"));
            }
            if let Some(inline) = table.get("config") {
                let TomlValue::Inline(pairs) = inline else {
                    return Err(format!("{ctx}: `config` must be a table"));
                };
                let entries = pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), wire_value(v)))
                    .collect();
                insert_config(
                    configs.entry(name.clone()).or_default(),
                    &[],
                    false,
                    entries,
                    &ctx,
                )?;
            }
            continue;
        }
        if table.path[2] != "config" {
            return Err(format!(
                "{origin}: [{}] is not a module table (use [module.{name}] or [module.{name}.config])",
                table.path.join(".")
            ));
        }
        insert_config(
            configs.entry(name.clone()).or_default(),
            &table.path[3..],
            table.is_array,
            entries_of(table),
            &format!("{origin}: [{}]", table.path.join(".")),
        )?;
    }
    for name in configs.keys() {
        if !declared.contains_key(name) {
            return Err(format!(
                "{origin}: [module.{name}.config] configures a module the file does not declare"
            ));
        }
    }
    for (name, (src, src_dirs)) in declared {
        if let Some(existing) = out.get(&name) {
            return Err(format!(
                "module `{name}` is declared in {} and in {origin}",
                existing.origin
            ));
        }
        let config = Value::Table(configs.remove(&name).unwrap_or_default());
        let config_json = config.to_json();
        let config_digest = crate::crypto::sha256::hash_bytes(config_json.as_bytes());
        out.insert(
            name.clone(),
            ModuleSpec {
                name,
                src,
                src_dirs,
                config,
                config_json,
                config_digest,
                origin: origin.to_string(),
            },
        );
    }
    Ok(())
}

/// Read one file's `[generate.*]` tables: each becomes its synthesized
/// derivation, still unexpanded.
pub fn parse_generators(
    doc: &Doc,
    origin: &str,
    generators: &mut BTreeMap<String, GeneratorSpec>,
    drvs: &mut Vec<DrvSpec>,
) -> Result<(), String> {
    for table in &doc.tables {
        if table.path.first().map(String::as_str) != Some("generate") {
            continue;
        }
        if table.path.len() != 2 || table.is_array {
            return Err(format!(
                "{origin}: generators are declared as named tables, [generate.<name>]"
            ));
        }
        let name = table.path[1].clone();
        let ctx = format!("{origin}: [generate.{name}]");
        for entry in &table.entries {
            if ![
                "module",
                "sources",
                "src-dirs",
                "deps",
                "config-keys",
                "extra-tools",
                "argv",
            ]
            .contains(&entry.key.as_str())
            {
                return Err(format!("{ctx}: unknown key `{}`", entry.key));
            }
        }
        let module = tables::need_str(table, "module", &ctx)?;
        let derivation = generator_derivation_name(&name);
        if let Some(existing) = generators.get(&name) {
            return Err(format!(
                "generator `{name}` is declared in {} and in {origin}",
                existing.origin
            ));
        }
        generators.insert(
            name.clone(),
            GeneratorSpec {
                name: name.clone(),
                module: module.clone(),
                derivation: derivation.clone(),
                origin: origin.to_string(),
            },
        );
        let mut spec = DrvSpec::new(&derivation, "module", &module_tool(&module));
        spec.module = module;
        spec.module_role = ROLE_GENERATOR.to_string();
        spec.sources = tables::opt_str_list(table, "sources", &ctx)?;
        spec.src_dirs = tables::opt_str_list(table, "src-dirs", &ctx)?;
        spec.deps = tables::opt_str_list(table, "deps", &ctx)?;
        spec.config_keys = tables::opt_str_list(table, "config-keys", &ctx)?;
        spec.extra_tools = tables::opt_str_list(table, "extra-tools", &ctx)?;
        spec.argv = tables::opt_str_list(table, "argv", &ctx)?;
        spec.outputs = vec![crate::sdk_wire::GENERATED_FILE.to_string()];
        drvs.push(spec);
    }
    Ok(())
}

/// The store build of `module`: compile against the bootstrap-grade SDK
/// with the stage-0 Rust provider, then record the SDK version the
/// executable answers with.
pub fn module_derivation(module: &ModuleSpec) -> DrvSpec {
    let name = module_derivation_name(&module.name);
    let mut spec = DrvSpec::new(&name, "script-dag", "ninja");
    spec.bootstrap = true;
    spec.host_tool = true;
    spec.allowed_refs = RefPolicy::Closure;
    spec.extra_tools = vec!["rustc".to_string(), "cc".to_string(), "sh".to_string()];
    spec.src_dirs = std::iter::once(module.src.clone())
        .chain(module.src_dirs.iter().cloned())
        .collect();
    spec.deps = vec![SDK_DRV.to_string()];
    spec.outputs = vec![
        MODULE_BINARY.to_string(),
        crate::sdk_wire::VERSION_RECORD.to_string(),
    ];
    spec.steps = vec![
        Step {
            when: String::new(),
            tool: "rustc".to_string(),
            argv: vec![
                "--edition=2024".to_string(),
                "-O".to_string(),
                format!("--crate-name={}", crate_name(&module.name)),
                "-C".to_string(),
                "link-arg=--target={build.host.triple}".to_string(),
                "--remap-path-prefix".to_string(),
                "{srcroot-abs}=/src".to_string(),
                "--extern".to_string(),
                format!("buildutil_sdk={{dep:{SDK_DRV}}}/libbuildutil_sdk.rlib"),
                "-L".to_string(),
                format!("{{dep:{SDK_DRV}}}"),
                "-o".to_string(),
                format!("{{out}}/{MODULE_BINARY}"),
                format!("{{srcroot}}/{}/main.rs", module.src),
            ],
            capture: String::new(),
            outputs: vec![format!("{{out}}/{MODULE_BINARY}")],
        },
        Step {
            when: String::new(),
            tool: "sh".to_string(),
            argv: vec![
                "-c".to_string(),
                format!("exec \"$0\" {}", crate::sdk_wire::VERSION_ARGUMENT),
                format!("{{out}}/{MODULE_BINARY}"),
            ],
            capture: format!("{{out}}/{}", crate::sdk_wire::VERSION_RECORD),
            outputs: vec![format!("{{out}}/{}", crate::sdk_wire::VERSION_RECORD)],
        },
    ];
    spec
}

/// The self-tool build of `module` for client apps, from the client's
/// ambient compiler against the self-tool SDK. buildutil asks the executable
/// for its SDK version before running it.
pub fn native_module_derivation(module: &ModuleSpec) -> DrvSpec {
    let name = native_module_derivation_name(&module.name);
    let mut spec = DrvSpec::new(&name, "rustc-crate", "rustc");
    spec.native_frontend = true;
    spec.host_tool = true;
    spec.extra_tools = vec!["cc".to_string()];
    spec.src_dirs = std::iter::once(module.src.clone())
        .chain(module.src_dirs.iter().cloned())
        .collect();
    spec.deps = vec![SDK_NATIVE_DRV.to_string()];
    spec.outputs = vec![MODULE_BINARY.to_string()];
    spec.argv = vec![
        "--edition=2024".to_string(),
        "-O".to_string(),
        format!("--crate-name={}", crate_name(&module.name)),
        "-C".to_string(),
        "linker=cc".to_string(),
        "--remap-path-prefix".to_string(),
        "{buildroot-abs}=/build".to_string(),
        "--extern".to_string(),
        format!("buildutil_sdk={{dep:{SDK_NATIVE_DRV}}}/libbuildutil_sdk.rlib"),
        "-L".to_string(),
        format!("{{dep:{SDK_NATIVE_DRV}}}"),
        "-o".to_string(),
        format!("{{out}}/{MODULE_BINARY}"),
        format!("{{srcroot}}/{}/main.rs", module.src),
    ];
    spec
}

fn crate_name(module: &str) -> String {
    format!("buildutil_module_{}", module.replace('-', "_"))
}

/// The tool provider a module builder names: the module's store executable.
pub fn module_tool_provider(module: &ModuleSpec) -> (String, ToolProviderSpec) {
    (
        module_tool(&module.name),
        ToolProviderSpec {
            derivation: module_derivation_name(&module.name),
            path: MODULE_BINARY.to_string(),
            version_flag: None,
        },
    )
}

fn returned_outputs() -> Vec<String> {
    vec![
        format!("{}/", crate::sdk_wire::RETURNED_DIR),
        crate::sdk_wire::RETURNED_LIST.to_string(),
    ]
}

/// The formatter's run: its module over the declared source sets with the
/// declared store tools, returning edited files.
pub fn formatter_derivation(formatter: &FormatterSpec) -> DrvSpec {
    let mut spec = DrvSpec::new(FORMATTER_DRV, "module", &module_tool(&formatter.module));
    spec.module = formatter.module.clone();
    spec.module_role = ROLE_FORMATTER.to_string();
    spec.host_tool = true;
    spec.src_dirs = formatter.src_dirs.clone();
    spec.sources = formatter.sources.clone();
    spec.extra_tools = formatter.tools.clone();
    spec.outputs = returned_outputs();
    spec
}

/// A build-host app's run: its module with the architecture's default
/// inputs as dependencies, the declared store tools and source sets.
pub fn app_derivation(name: &str, app: &AppSpec, arch: &str) -> DrvSpec {
    let mut spec = DrvSpec::new(&app_derivation_name(name), "module", &module_tool(&app.module));
    spec.module = app.module.clone();
    spec.module_role = ROLE_BUILD_HOST_APP.to_string();
    spec.deps = app.inputs.get(arch).cloned().unwrap_or_default();
    spec.extra_tools = app.tools.clone();
    spec.src_dirs = app.src_dirs.clone();
    spec.sources = app.sources.clone();
    spec.outputs = returned_outputs();
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<BTreeMap<String, ModuleSpec>, String> {
        let doc = super::super::toml::parse(std::path::Path::new("m.toml"), text).unwrap();
        let mut out = BTreeMap::new();
        parse_modules(&doc, "m.toml", &mut out)?;
        Ok(out)
    }

    #[test]
    fn required_module_configuration_nests_and_digests_canonically() {
        let a = parse(
            "[module.vm]\nsrc = \"tools/modules/vm\"\n\
             [module.vm.config]\nexpected-programs = [\"runner\", \"smoke\"]\n\
             [module.vm.config.checks.check-guest]\nprofile = \"disk\"\n",
        )
        .unwrap();
        let b = parse(
            "[module.vm.config.checks.check-guest]\nprofile = \"disk\"\n\
             [module.vm]\nsrc = \"tools/modules/vm\"\n\
             [module.vm.config]\nexpected-programs = [\"runner\", \"smoke\"]\n",
        )
        .unwrap();
        let vm = &a["vm"];
        assert_eq!(
            vm.config.lookup("checks.check-guest.profile").and_then(Value::as_str),
            Some("disk")
        );
        assert_eq!(vm.config_digest, b["vm"].config_digest, "order does not matter");
        let c = parse(
            "[module.vm]\nsrc = \"tools/modules/vm\"\n\
             [module.vm.config]\nexpected-programs = [\"runner\"]\n",
        )
        .unwrap();
        assert_ne!(vm.config_digest, c["vm"].config_digest);
    }

    #[test]
    fn required_module_declarations_are_refused_when_malformed() {
        assert!(parse("[module.vm]\nsrc = \"../escape\"\n").is_err());
        assert!(parse("[module.vm.config]\nx = 1\n").is_err());
        assert!(parse("[module.vm]\nsrc = \"a\"\nbogus = 1\n").is_err());
        assert!(parse("[module.vm]\nsrc = \"a\"\n[module.vm.other]\nx = 1\n").is_err());
    }
}
