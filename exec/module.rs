//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the `module` builder: a declared module runs as the builder of a
//! derivation, in the same private build directory and sandbox as any
//! other builder.
//!
//! Before the module runs, the SDK version recorded beside its executable is
//! compared with the SDK this buildutil provides; a module without a record,
//! built against another major version or against a newer minor is refused.
//! The request names only what the derivation declares: its configuration
//! keys and their values, its module configuration, dependencies under the
//! names it declares them by, tools and staged sources, as paths relative
//! to the build's working directory so they hold at every sandbox grade. After the run, the verdict the
//! module wrote decides the derivation together with the exit status: a
//! missing verdict, or one that disagrees with the status, fails it.

use super::builder::{Builder, BuilderContext, PreparedBuilder};
use super::tokens::{ARTIFACTS_DIR, resolve_exec_tokens};
use crate::sdk_wire::{self, Value};
use std::path::Path;

/// The request and verdict files, in the build's working directory.
pub(crate) const REQUEST_FILE: &str = "buildutil-module.request";
const VERDICT_FILE: &str = "buildutil-module.verdict";
/// Where an uncached run (the formatter, a build-host app) finds what buildutil
/// wrote for it before dispatching it, relative to its build directory: the
/// graph and plan query answers, the arguments after `--` and the whole
/// resolved configuration, which an uncached role reads in place of
/// declared keys.
pub(crate) const UNCACHED_DIR: &str = "uncached";
pub(crate) const GRAPH_QUERY_FILE: &str = "graph.json";
pub(crate) const PLAN_QUERY_FILE: &str = "plan.json";
pub(crate) const ARGUMENTS_FILE: &str = "arguments.json";
pub(crate) const CONFIG_FILE: &str = "config.json";

pub(crate) struct ModuleBuilder;

pub(crate) static MODULE_BUILDER: ModuleBuilder = ModuleBuilder;

fn env_value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Refuse a module whose recorded SDK version this buildutil does not provide.
pub(crate) fn check_module_version(executable: &Path) -> Result<(), String> {
    let record = executable.with_file_name(sdk_wire::VERSION_RECORD);
    let text = std::fs::read_to_string(&record).map_err(|_| {
        format!(
            "module {} carries no SDK version record; buildutil refuses to run it",
            executable.display()
        )
    })?;
    check_recorded_version(&text)
}

pub(crate) fn check_recorded_version(text: &str) -> Result<(), String> {
    let recorded = sdk_wire::parse_version(text)?;
    sdk_wire::check_compatible(recorded, sdk_wire::VERSION)
        .map_err(|e| format!("module refused before it runs: it was {e}"))
}

impl Builder for ModuleBuilder {
    fn label(&self) -> &'static str {
        "module"
    }

    fn action(&self, _kind: &str) -> &'static str {
        "Running"
    }

    fn prepare(
        &self,
        ctx: &BuilderContext<'_>,
        extra_env: &mut Vec<(String, String)>,
    ) -> Result<PreparedBuilder, String> {
        check_module_version(ctx.tool_path)?;
        let module = env_value(&ctx.node.env, crate::spec::MODULE_ENV)
            .ok_or_else(|| format!("`{}` names no module", ctx.name))?;
        let role = env_value(&ctx.node.env, crate::spec::MODULE_ROLE_ENV)
            .ok_or_else(|| format!("`{}` names no module role", ctx.name))?;
        let declared: Vec<&str> = env_value(&ctx.node.env, crate::spec::MODULE_CONFIG_KEYS_ENV)
            .map(|keys| keys.split(',').filter(|k| !k.is_empty()).collect())
            .unwrap_or_default();
        let module_config = Value::parse_json(&ctx.node.exec.module_config_text)
            .map_err(|e| format!("`{}`: malformed module configuration: {e}", ctx.name))?;

        let mut request = Value::table();
        request.set("sdk", Value::str(sdk_wire::version_text(sdk_wire::VERSION)));
        request.set("role", Value::str(role));
        request.set("module", Value::str(module));
        request.set("name", Value::str(ctx.dspec.name.clone()));
        request.set("arch", Value::str(ctx.target_arch));
        request.set("build-host", Value::str(ctx.build_host));
        // Only the declared keys: a module reading any other key fails.
        let mut config = Value::table();
        for key in declared {
            let value = ctx
                .node
                .config
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .ok_or_else(|| {
                    format!("`{}` declares configuration key `{key}` it did not resolve", ctx.name)
                })?;
            config.set(key, Value::Str(value));
        }
        let cached = matches!(
            role,
            crate::spec::modules::ROLE_BUILDER | crate::spec::modules::ROLE_GENERATOR
        );
        let uncached_dir = ctx.build_dir.join(UNCACHED_DIR);
        // An uncached run reads the whole resolved configuration instead.
        if !cached {
            if let Ok(text) = std::fs::read_to_string(uncached_dir.join(CONFIG_FILE)) {
                config = Value::parse_json(&text)
                    .ok()
                    .filter(|value| value.as_table().is_some())
                    .ok_or_else(|| format!("`{}`: malformed {CONFIG_FILE}", ctx.name))?;
            }
        }
        request.set("config", config);
        request.set("module-config", module_config);
        let mut arguments = Vec::new();
        for arg in ctx.drv.argv.iter().skip(1) {
            arguments.push(Value::Str(resolve_exec_tokens(
                arg,
                Path::new(".."),
                Path::new("../../out"),
                ctx.stage,
                ctx.drv,
                true,
            )?));
        }
        // An uncached run also takes the arguments the person gave after
        // `--`, which buildutil wrote beside its build before dispatching it.
        if !cached {
            if let Ok(text) = std::fs::read_to_string(uncached_dir.join(ARGUMENTS_FILE)) {
                let given = Value::parse_json(&text)
                    .ok()
                    .and_then(|value| value.as_str_list())
                    .ok_or_else(|| format!("`{}`: malformed {ARGUMENTS_FILE}", ctx.name))?;
                arguments.extend(given.into_iter().map(Value::Str));
            }
        }
        request.set("arguments", Value::List(arguments));
        // Inputs go by the names the derivation declares: a variant edge's
        // outputs are staged under its base's name.
        let declared = env_value(&ctx.node.env, crate::spec::MODULE_INPUTS_ENV).unwrap_or("");
        let declared_as: Vec<(&str, &str)> =
            declared.split(',').filter_map(|pair| pair.split_once('=')).collect();
        let mut inputs = Value::table();
        let mut store_names = Value::table();
        let mut order = Vec::new();
        for dep in &ctx.drv.deps {
            let name = declared_as
                .iter()
                .find(|(_, base)| *base == dep.name)
                .map(|(variant, _)| *variant)
                .unwrap_or(&dep.name);
            inputs.set(name, Value::str(format!("../dep/{}", dep.name)));
            store_names.set(name, Value::str(dep.store_name.clone()));
            order.push(Value::str(name));
        }
        request.set("inputs", inputs);
        request.set("input-store-names", store_names);
        request.set("input-order", Value::List(order));
        let mut tools = Value::table();
        for tool in std::iter::once(&ctx.dspec.tool).chain(ctx.dspec.extra_tools.iter()) {
            if tool != &ctx.dspec.tool {
                tools.set(tool, Value::str(format!("../../toolbin/{tool}")));
            }
        }
        request.set("tools", tools);
        request.set("outputs", Value::str_list(ctx.dspec.outputs.clone()));
        let mut paths = Value::table();
        paths.set("source-root", Value::str(".."));
        paths.set("out", Value::str("../../out"));
        paths.set("artifacts", Value::str(format!("../../{ARTIFACTS_DIR}")));
        paths.set("temp", Value::str("../../tmp"));
        request.set("paths", paths);
        // An uncached run (the formatter, a build-host app) finds the query
        // answers buildutil wrote into its build directory before dispatching.
        if !cached {
            let mut queries = Value::table();
            for (which, file) in [("graph", GRAPH_QUERY_FILE), ("plan", PLAN_QUERY_FILE)] {
                if uncached_dir.join(file).is_file() {
                    queries.set(which, Value::str(format!("../../{UNCACHED_DIR}/{file}")));
                }
            }
            request.set("queries", queries);
        }
        let mut results = Value::table();
        results.set("verdict", Value::str(VERDICT_FILE));
        request.set("results", results);

        let _ = std::fs::remove_file(ctx.cwd.join(VERDICT_FILE));
        std::fs::write(ctx.cwd.join(REQUEST_FILE), request.to_json())
            .map_err(|e| format!("cannot write the module request: {e}"))?;
        extra_env.push((sdk_wire::REQUEST_ENV.to_string(), REQUEST_FILE.to_string()));
        // A module drives its own subprocesses (a port's make, a VM); it
        // runs with its share of the job pool, which the engine exports as
        // NPROC.
        let slots = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .saturating_sub(1);
        Ok(PreparedBuilder {
            argv: vec![ctx.tool_path.to_string_lossy().into_owned()],
            lease_slots: Some(slots),
        })
    }

    fn post_process(&self, ctx: &BuilderContext<'_>) -> Result<(), String> {
        // The run exited 0; its verdict must exist and agree.
        let (code, summary) = read_verdict(ctx.cwd).ok_or_else(|| {
            format!("module of `{}` exited without writing a verdict", ctx.name)
        })??;
        if code != 0 {
            return Err(format!(
                "verdict {code} disagrees with the module's successful exit{}",
                if summary.is_empty() { String::new() } else { format!(": {summary}") }
            ));
        }
        *ctx.verdict.borrow_mut() = (!summary.is_empty()).then_some(summary);
        Ok(())
    }

    fn failure_reason(&self, ctx: &BuilderContext<'_>, status: &str) -> String {
        match read_verdict(ctx.cwd) {
            Some(Ok((code, summary))) if code != 0 => {
                if summary.is_empty() {
                    format!("verdict {code}")
                } else {
                    format!("verdict {code}: {summary}")
                }
            }
            Some(Ok(_)) => format!(
                "the module failed ({status}) with a passing verdict, which disagrees"
            ),
            Some(Err(e)) => e,
            None => format!("the module failed ({status}) without writing a verdict"),
        }
    }
}

/// The verdict a module wrote: `None` when it wrote none.
fn read_verdict(cwd: &Path) -> Option<Result<(i64, String), String>> {
    let text = std::fs::read_to_string(cwd.join(VERDICT_FILE)).ok()?;
    Some((|| {
        let value = Value::parse_json(&text).map_err(|e| format!("malformed verdict: {e}"))?;
        let code = value
            .get("code")
            .and_then(Value::as_int)
            .ok_or("the verdict has no code")?;
        let summary = value
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok((code, summary))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_module_versions_are_refused_before_running() {
        let (major, minor, _) = sdk_wire::VERSION;
        assert!(check_recorded_version(&format!("{major}.{minor}.0\n")).is_ok());
        assert!(check_recorded_version(&format!("{major}.{}.0", minor + 1)).is_err());
        assert!(check_recorded_version(&format!("{}.0.0", major + 1)).is_err());
        let dir = std::env::temp_dir().join(format!(
            "buildutil-module-version-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("module");
        std::fs::write(&exe, b"").unwrap();
        let _ = std::fs::remove_file(dir.join(sdk_wire::VERSION_RECORD));
        assert!(check_module_version(&exe).is_err(), "no record is refused");
        std::fs::write(
            dir.join(sdk_wire::VERSION_RECORD),
            sdk_wire::version_text(sdk_wire::VERSION),
        )
        .unwrap();
        assert!(check_module_version(&exe).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn required_a_verdict_must_exist_and_agree() {
        let dir = std::env::temp_dir().join(format!(
            "buildutil-module-verdict-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(dir.join(VERDICT_FILE));
        assert!(read_verdict(&dir).is_none());
        std::fs::write(dir.join(VERDICT_FILE), "{\"code\":2,\"summary\":\"panic\"}").unwrap();
        assert_eq!(read_verdict(&dir).unwrap().unwrap(), (2, "panic".to_string()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
