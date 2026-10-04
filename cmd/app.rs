// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — apps and the formatter: modules buildutil runs uncached.
//!
//! `buildutil run <app>` prepares the app's inputs through an ordinary engine
//! request — `build`, or `dev` with `--dev` for a client app — and a failed,
//! cancelled or disconnected preparation launches nothing. The prepared
//! inputs are held by a temporary root while the app runs. Every uncached
//! run is offered the read-only graph query (the specification's
//! derivations, evaluated under the configuration) and the plan query (the
//! prepared inputs' configured nodes, client paths and closures). A client
//! app runs its module's self-tool build here, under the terminal lease,
//! with the inputs' client paths and the arguments after `--`; the module
//! may register indirect GC roots for work that outlives it. A build-host
//! app and the formatter run their module's store build on the build host,
//! through the dev path, which runs them uncached; the queries and the
//! arguments after `--` reach them through their build directory, and the
//! work-tree files they return are written here, each only if it still
//! holds what the module read, replaced atomically.

use super::{Args, flag_present};
use crate::exec::module::{
    ARGUMENTS_FILE, CONFIG_FILE, GRAPH_QUERY_FILE, PLAN_QUERY_FILE, UNCACHED_DIR,
};
use crate::sdk_wire::{self, Value};
use crate::spec::kinds::{AppSpec, RunsOn, Scope};
use crate::spec::modules;
use std::path::{Path, PathBuf};

/// `buildutil run <app> [<package>...] [--dev] [-- <arguments>]`.
pub fn run(args: &Args, root: &Path, name: &str, app: &AppSpec) -> Result<i32, String> {
    // On Windows the whole invocation runs in WSL, so a client app drives
    // WSL's QEMU and every module builds for Linux.
    if crate::host::ExecBackend::resolve(&args.backend)? == crate::host::ExecBackend::Wsl {
        return crate::host::wsl::run_wsl_backend(root, &args.argv);
    }
    let dev = args.targets.iter().any(|arg| arg == "--dev");
    if let Some(flag) = args.targets[1..]
        .iter()
        .find(|word| word.starts_with('-') && word.as_str() != "--dev")
    {
        return Err(format!(
            "run: `{flag}` is not a buildutil option; an app's own arguments follow `--`"
        ));
    }
    let named: Vec<String> = args.targets[1..]
        .iter()
        .filter(|word| !word.starts_with('-'))
        .cloned()
        .collect();
    match app.runs_on {
        RunsOn::Client => run_client_app(args, root, name, app, named, dev),
        RunsOn::BuildHost => {
            if !named.is_empty() || dev {
                return Err(format!(
                    "run: `{name}` runs on the build host with its declared inputs from the store; it takes no packages and no `--dev`"
                ));
            }
            let inputs = app.inputs.get(&args.arch).cloned().unwrap_or_default();
            run_build_host(
                args,
                root,
                &modules::app_derivation_name(name),
                &inputs,
                &format!("run: app `{name}` has no build-host run"),
            )
        }
    }
}

/// `buildutil fmt [--check]`: the formatter's module over its declared source
/// sets; `--check` reports its edits as problems instead of writing them.
pub fn format(args: &Args, root: &Path) -> Result<i32, String> {
    if crate::host::ExecBackend::resolve(&args.backend)? == crate::host::ExecBackend::Wsl {
        return crate::host::wsl::run_wsl_backend(root, &args.argv);
    }
    if !args.app_args.is_empty() {
        return Err("fmt: the formatter takes no arguments after `--`".to_string());
    }
    let missing = "fmt: no [formatter] table names a formatter module";
    if !flag_present(args, "--check") {
        return run_build_host(args, root, modules::FORMATTER_DRV, &[], missing);
    }
    let edits = match run_uncached(args, root, modules::FORMATTER_DRV, &[], missing)? {
        Ok(edits) => edits,
        Err(code) => return Ok(code),
    };
    for edit in &edits {
        crate::term::error(&format!("{}: needs formatting", edit.rel));
    }
    if edits.is_empty() {
        crate::log::success("fmt", "Formatting is clean");
        Ok(0)
    } else {
        crate::log::error("fmt", &format!("{} files need formatting", edits.len()));
        Ok(1)
    }
}

/// The build options of an invocation, as arguments for the engine request
/// that prepares an app's inputs. Global options never reach the app.
fn build_options(args: &Args) -> Vec<String> {
    let mut out = vec!["--arch".to_string(), args.arch.clone()];
    out.extend(["--build-host".to_string(), args.build_host.clone()]);
    out.extend(["--backend".to_string(), args.backend.clone()]);
    if let Some(path) = &args.store {
        out.push("--store".to_string());
        out.push(path.to_string_lossy().into_owned());
    }
    out.extend(["--jobs".to_string(), args.jobs.to_string()]);
    for (name, value) in &args.overrides {
        out.push(format!("-D{name}={value}"));
    }
    if args.keep_going {
        out.push("--keep-going".to_string());
    }
    if args.keep_failed {
        out.push("--keep-failed".to_string());
    }
    if args.no_source_cache {
        out.push("--no-source-cache".to_string());
    }
    if args.verbose {
        out.push("-v".to_string());
    }
    out
}

/// Where the dev build of `label` puts its outputs.
fn dev_output(args: &Args, root: &Path, label: &str) -> Result<PathBuf, String> {
    let state_root = super::state_root_from_repo(args, root);
    let backend = crate::host::ExecBackend::resolve(&args.backend)?;
    Ok(crate::state::dev_dir(
        &crate::state::absolute_root(root, &state_root),
        backend.dev_output_name()?,
        &args.arch,
        label,
    ))
}

/// A prepared input as the app sees it.
struct Prepared {
    request: String,
    key: String,
    path: PathBuf,
    store_name: Option<String>,
    closure: Vec<(String, String, PathBuf)>,
}

/// Realize `inputs` through an ordinary engine request: `build`, or `dev`
/// with one request per input. `Some(code)` is a preparation that failed and
/// reported itself.
fn realize_inputs(args: &Args, inputs: &[String], dev: bool) -> Result<Option<i32>, String> {
    if inputs.is_empty() {
        return Ok(None);
    }
    let options = build_options(args);
    let requests: Vec<Vec<String>> = if dev {
        // A dev build takes one tip; each input is its own request.
        inputs
            .iter()
            .map(|input| {
                let mut argv = vec!["dev".to_string(), input.clone()];
                argv.extend(options.iter().cloned());
                argv
            })
            .collect()
    } else {
        let mut argv = vec!["build".to_string()];
        argv.extend(inputs.iter().cloned());
        argv.extend(options.iter().cloned());
        vec![argv]
    };
    for argv in requests {
        let code = super::engine::request(&argv, args)?;
        if code != 0 {
            return Ok(Some(code));
        }
    }
    Ok(None)
}

/// The exact identities the preparation realized: the same words evaluated
/// again (a cached plan), never a possibly older root. Every realized input
/// and its closure are held by the returned temporary root until it drops.
fn prepared_inputs(
    ctx: &mut super::Context,
    root: &Path,
    args: &Args,
    inputs: &[String],
    dev: bool,
    label: &str,
) -> Result<(Vec<Prepared>, Option<crate::store::TempRoot>), String> {
    if inputs.is_empty() {
        return Ok((Vec::new(), None));
    }
    let targets = super::resolve_targets(&ctx.spec, args, inputs)?;
    let git_state = ctx.git_state().clone();
    let evaluated = super::evaluate_plan_with_progress(
        &ctx.spec,
        &ctx.config,
        &mut ctx.toolchain,
        &targets,
        &ctx.state_root,
        !args.no_source_cache,
        git_state,
        |_| {},
    )?
    .evaluated;
    let resolved = evaluated.dry_resolve(&ctx.store);
    let store_root = crate::state::absolute_root(root, &ctx.state_root).join("store");
    let mut prepared = Vec::new();
    let mut held = Vec::new();
    for (request, key) in &evaluated.roots {
        let closure: Vec<(String, String, PathBuf)> = closure_of(&evaluated, key)
            .into_iter()
            .filter_map(|dep| {
                let node = resolved.get(&dep).filter(|node| node.digest.is_some())?;
                let base = crate::spec::address::base_name(&dep).to_string();
                Some((base, dep, store_root.join(&node.store_name)))
            })
            .collect();
        for (_, _, path) in &closure {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                held.push(file_name.to_string());
            }
        }
        if dev {
            let tip = match crate::spec::address::parse(request) {
                Ok(crate::spec::address::Address::Plain(plain)) => plain,
                _ => key.clone(),
            };
            prepared.push(Prepared {
                request: request.clone(),
                key: key.clone(),
                path: dev_output(args, root, &tip)?.join("out"),
                store_name: None,
                closure,
            });
        } else {
            let node = resolved
                .get(key)
                .filter(|node| node.digest.is_some())
                .ok_or_else(|| format!("run: prepared input `{request}` is not realized"))?;
            held.push(node.store_name.clone());
            prepared.push(Prepared {
                request: request.clone(),
                key: key.clone(),
                path: store_root.join(&node.store_name),
                store_name: Some(node.store_name.clone()),
                closure,
            });
        }
    }
    held.sort();
    held.dedup();
    let guard = ctx.store.add_temp_roots(label, &held)?;
    Ok((prepared, guard))
}

/// The plan query: the prepared inputs' configured nodes with their client
/// paths, store entries and dependency closures.
fn plan_query(prepared: &[Prepared], dev: bool) -> Value {
    let mut inputs = Vec::new();
    for input in prepared {
        let mut entry = Value::table();
        entry.set("request", Value::str(input.request.clone()));
        entry.set("key", Value::str(input.key.clone()));
        entry.set("path", Value::str(input.path.to_string_lossy()));
        if let Some(store_name) = &input.store_name {
            entry.set("store-name", Value::str(store_name.clone()));
        }
        entry.set(
            "closure",
            Value::List(
                input
                    .closure
                    .iter()
                    .map(|(base, key, path)| {
                        let mut node = Value::table();
                        node.set("name", Value::str(base.clone()));
                        node.set("key", Value::str(key.clone()));
                        node.set("path", Value::str(path.to_string_lossy()));
                        node
                    })
                    .collect(),
            ),
        );
        inputs.push(entry);
    }
    let mut plan = Value::table();
    plan.set("dev", Value::Bool(dev));
    plan.set("inputs", Value::List(inputs));
    plan
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    std::fs::write(path, value.to_json())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// The whole resolved configuration, which an uncached role reads.
fn config_value(ctx: &super::Context) -> Value {
    let mut config = Value::table();
    for (key, value) in &ctx.config.values {
        config.set(key, Value::str(value.clone()));
    }
    config
}

fn run_client_app(
    args: &Args,
    root: &Path,
    name: &str,
    app: &AppSpec,
    named: Vec<String>,
    dev: bool,
) -> Result<i32, String> {
    let inputs = if named.is_empty() {
        app.inputs.get(&args.arch).cloned().unwrap_or_default()
    } else {
        named
    };
    if let Some(code) = realize_inputs(args, &inputs, dev)? {
        return Ok(code);
    }
    let mut prepared_args = args.clone();
    prepared_args.scope = Some(Scope::Packages);
    let mut ctx = super::open_context(&prepared_args)?;
    let module = ctx
        .spec
        .modules
        .get(&app.module)
        .cloned()
        .ok_or_else(|| format!("run: app `{name}` names undeclared module `{}`", app.module))?;
    let (prepared, _held) =
        prepared_inputs(&mut ctx, root, &prepared_args, &inputs, dev, &format!("app-{name}"))?;

    let state_root = crate::state::absolute_root(root, &ctx.state_root);
    let run_state = crate::state::run_dir(&state_root).join(&app.module);
    std::fs::create_dir_all(&run_state)
        .map_err(|e| format!("run: cannot create {}: {e}", run_state.display()))?;

    let executable = realize_client_module(root, &state_root, &module)?;
    let session = run_state
        .join("requests")
        .join(format!("{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&session)
        .map_err(|e| format!("run: cannot create {}: {e}", session.display()))?;
    let plan_file = session.join(PLAN_QUERY_FILE);
    write_json(&plan_file, &plan_query(&prepared, dev))?;
    let graph_file = session.join(GRAPH_QUERY_FILE);
    write_json(&graph_file, &graph_query(&ctx, root))?;

    let mut request = Value::table();
    request.set("sdk", Value::str(sdk_wire::version_text(sdk_wire::VERSION)));
    request.set("role", Value::str(modules::ROLE_CLIENT_APP));
    request.set("module", Value::str(app.module.clone()));
    request.set("name", Value::str(name));
    request.set("arch", Value::str(args.arch.clone()));
    request.set("build-host", Value::str(ctx.build_host.triple()));
    request.set("config", config_value(&ctx));
    request.set("module-config", module.config.clone());
    request.set("arguments", Value::str_list(args.app_args.clone()));
    let mut input_map = Value::table();
    for input in &prepared {
        input_map.set(&input.request, Value::str(input.path.to_string_lossy()));
    }
    request.set("inputs", input_map);
    request.set(
        "input-order",
        Value::str_list(prepared.iter().map(|input| input.request.clone())),
    );
    let mut paths = Value::table();
    paths.set("run-state", Value::str(run_state.to_string_lossy()));
    paths.set("state-root", Value::str(state_root.to_string_lossy()));
    paths.set("temp", Value::str(session.to_string_lossy()));
    paths.set("source-root", Value::str(root.to_string_lossy()));
    request.set("paths", paths);
    let mut queries = Value::table();
    queries.set("plan", Value::str(plan_file.to_string_lossy()));
    queries.set("graph", Value::str(graph_file.to_string_lossy()));
    request.set("queries", queries);
    let buildutil = std::env::current_exe()
        .map_err(|e| format!("run: cannot locate the buildutil executable: {e}"))?;
    request.set("buildutil", Value::str(buildutil.to_string_lossy()));
    let request_file = session.join("request.json");
    write_json(&request_file, &request)?;
    drop(ctx);

    #[cfg(unix)]
    let _signals = crate::host::interrupt::TerminalSignalsToChild::install();
    let lease = crate::term::handover();
    let status = crate::invocation::command(&executable)
        .env(sdk_wire::REQUEST_ENV, &request_file)
        .current_dir(root)
        .terminal(&lease)
        .status()
        .map_err(|e| format!("run: cannot start module `{}`: {e}", app.module))?;
    drop(lease);
    let _ = std::fs::remove_dir_all(&session);
    Ok(status.code().unwrap_or(1))
}

/// Every configured node `key` reaches, excluding itself.
fn closure_of(evaluated: &crate::eval::graph::Evaluated, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<&String> = evaluated
        .recipes
        .get(key)
        .map(|recipe| recipe.dep_names.iter().collect())
        .unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(dep) = stack.pop() {
        if !seen.insert(dep.clone()) {
            continue;
        }
        out.push(dep.clone());
        if let Some(recipe) = evaluated.recipes.get(dep) {
            stack.extend(recipe.dep_names.iter());
        }
    }
    out.sort();
    out
}

/// Build a client app's module on this client from its ambient compiler
/// and refuse it unless it was built against an SDK this buildutil provides.
fn realize_client_module(
    root: &Path,
    state_root: &Path,
    module: &modules::ModuleSpec,
) -> Result<PathBuf, String> {
    let exec_host = crate::host::exec_host_triple();
    let (spec, target) = crate::spec::load_self_tool_module(root, &exec_host, module)?;
    let out = super::driver::realize_self_tool_spec(root, state_root, spec, &target)?;
    let executable = out.join(modules::MODULE_BINARY);
    let answer = crate::invocation::isolated(&executable)
        .arg(sdk_wire::VERSION_ARGUMENT)
        .stdin(crate::invocation::Io::Null)
        .stdout(crate::invocation::Io::Piped)
        .stderr(crate::invocation::Io::Piped)
        .output()
        .map_err(|e| format!("cannot run module `{}`: {e}", module.name))?;
    if !answer.status.success() {
        return Err(format!(
            "module `{}` does not answer the SDK version query; buildutil refuses to run it",
            module.name
        ));
    }
    crate::exec::module::check_recorded_version(&String::from_utf8_lossy(&answer.stdout))
        .map_err(|e| format!("`{}`: {e}", module.name))?;
    Ok(executable)
}

/// Run a store module uncached on the build host and write the work-tree
/// files it returns.
fn run_build_host(
    args: &Args,
    root: &Path,
    drv: &str,
    inputs: &[String],
    missing: &str,
) -> Result<i32, String> {
    let edits = match run_uncached(args, root, drv, inputs, missing)? {
        Ok(edits) => edits,
        Err(code) => return Ok(code),
    };
    if edits.is_empty() {
        return Ok(0);
    }
    let edits: Vec<crate::license::Edit> = edits
        .into_iter()
        .map(|edit| crate::license::Edit {
            rel: edit.rel,
            path: edit.path,
            before: edit.before,
            after: edit.after,
            action: "Wrote",
        })
        .collect();
    let (_, problems) = crate::license::apply_edits(&edits);
    for (kind, path, detail) in &problems {
        crate::term::error(&format!("{path}: {kind}: {detail}"));
    }
    Ok(if problems.is_empty() { 0 } else { 1 })
}

/// A returned work-tree file, checked against the work tree.
struct Returned {
    rel: String,
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Vec<u8>,
}

/// The uncached run of `drv` on the build host: its `inputs` realized and
/// held, the queries and the arguments after `--` written into its build
/// directory, then its dev run. Returns the files it returned that differ
/// from the work tree, each kept only if the work tree still holds what the
/// module read; `Err(code)` inside `Ok` is a preparation or run that failed
/// and reported itself. `missing` is the error when `drv` is not declared.
fn run_uncached(
    args: &Args,
    root: &Path,
    drv: &str,
    inputs: &[String],
    missing: &str,
) -> Result<Result<Vec<Returned>, i32>, String> {
    if let Some(code) = realize_inputs(args, inputs, false)? {
        return Ok(Err(code));
    }
    let out_root = dev_output(args, root, drv)?;
    let uncached = out_root.join(UNCACHED_DIR);
    let _ = std::fs::remove_dir_all(&uncached);
    let held = {
        let mut prepared_args = args.clone();
        prepared_args.scope = Some(Scope::Packages);
        let mut ctx = super::open_context(&prepared_args)?;
        if !ctx.spec.drvs.contains_key(drv) {
            return Err(missing.to_string());
        }
        let label = format!("uncached-{drv}");
        let (prepared, held) =
            prepared_inputs(&mut ctx, root, &prepared_args, inputs, false, &label)?;
        std::fs::create_dir_all(&uncached)
            .map_err(|e| format!("cannot create {}: {e}", uncached.display()))?;
        write_json(&uncached.join(GRAPH_QUERY_FILE), &graph_query(&ctx, root))?;
        write_json(&uncached.join(PLAN_QUERY_FILE), &plan_query(&prepared, false))?;
        write_json(&uncached.join(ARGUMENTS_FILE), &Value::str_list(args.app_args.clone()))?;
        write_json(&uncached.join(CONFIG_FILE), &config_value(&ctx))?;
        held
    };
    let mut argv = vec!["dev".to_string(), format!("{}{drv}", crate::spec::kinds::DRV_PREFIX)];
    argv.extend(build_options(args));
    let code = super::engine::request(&argv, args);
    let _ = std::fs::remove_dir_all(&uncached);
    drop(held);
    let code = code?;
    if code != 0 {
        return Ok(Err(code));
    }
    let out = out_root.join("out");
    let list = std::fs::read_to_string(out.join(sdk_wire::RETURNED_LIST))
        .map_err(|e| format!("`{drv}` returned no file list: {e}"))?;
    let mut edits = Vec::new();
    for line in list.lines().filter(|line| !line.is_empty()) {
        let (based_on, rel) = line
            .split_once(' ')
            .ok_or_else(|| format!("`{drv}`: malformed returned-file line `{line}`"))?;
        let clean = !rel.is_empty()
            && !rel.starts_with('/')
            && rel.split('/').all(|c| !c.is_empty() && c != "." && c != "..");
        if !clean {
            return Err(format!("`{drv}` returned `{rel}`, which is not a clean repository path"));
        }
        let after = std::fs::read(out.join(sdk_wire::RETURNED_DIR).join(rel))
            .map_err(|e| format!("`{drv}`: cannot read returned `{rel}`: {e}"))?;
        let path = root.join(rel);
        let before = match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        if based_on != "-" {
            let current = before.as_ref().map(|b| crate::crypto::sha256::hash_bytes(b));
            if current.as_deref() != Some(based_on) {
                crate::term::error(&format!("{rel}: conflict: file changed since `{drv}` read it"));
                continue;
            }
        }
        if before.as_deref() == Some(after.as_slice()) {
            continue;
        }
        edits.push(Returned {
            rel: rel.to_string(),
            path,
            before,
            after,
        });
    }
    Ok(Ok(edits))
}

/// The read-only graph query: every derivation with its builder, whether
/// the configuration enables it, its arguments and steps evaluated under
/// the configuration, its dependencies, outputs and staged dependency files
/// and its latest realized store entry, with the client's roots for
/// rewriting build-host paths.
fn graph_query(ctx: &super::Context, root: &Path) -> Value {
    let state_root = crate::state::absolute_root(root, &ctx.state_root);
    let mut derivations = Vec::new();
    for (name, dspec) in &ctx.spec.drvs {
        let mut entry = Value::table();
        entry.set("name", Value::str(name.clone()));
        entry.set("builder", Value::str(dspec.builder.clone()));
        entry.set("host-tool", Value::Bool(dspec.host_tool));
        entry.set("deps", Value::str_list(dspec.deps.clone()));
        entry.set("outputs", Value::str_list(dspec.outputs.clone()));
        entry.set(
            "stage-deps",
            Value::List(
                dspec
                    .stage_deps
                    .iter()
                    .map(|(src, dest)| Value::str_list([src.clone(), dest.clone()]))
                    .collect(),
            ),
        );
        // A derivation the configuration cannot evaluate carries the error
        // in its entry; a module that needs the entry reports it.
        if let Err(error) = evaluate_entry(&ctx.spec, &ctx.config, dspec, &mut entry) {
            entry.set("error", Value::str(error));
        }
        let root_name = format!("latest-{name}-{}", ctx.spec.arch);
        if let Ok(target) = std::fs::read_link(state_root.join("roots").join(&root_name)) {
            if let Some(store_name) = target.file_name().and_then(|n| n.to_str()) {
                entry.set("latest", Value::str(store_name));
            }
        }
        derivations.push(entry);
    }
    let mut client = Value::table();
    client.set("repo-root", Value::str(root.to_string_lossy()));
    client.set("state-root", Value::str(state_root.to_string_lossy()));
    let mut out = Value::table();
    out.set("arch", Value::str(ctx.spec.arch.clone()));
    out.set("target-system", Value::str(ctx.spec.target_system.clone()));
    out.set("client", client);
    out.set("derivations", Value::List(derivations));
    out
}

/// Evaluate `dspec` under the configuration into its graph-query entry:
/// whether the configuration enables it, and an enabled derivation's
/// arguments and script steps.
fn evaluate_entry(
    spec: &crate::spec::Spec,
    config: &crate::spec::configres::Config,
    dspec: &crate::spec::DrvSpec,
    entry: &mut Value,
) -> Result<(), String> {
    let mut view = config.view();
    let active = view.eval_when(&dspec.when)?;
    entry.set("active", Value::Bool(active));
    if active && !crate::spec::builders::is_fixed_output(&dspec.builder) {
        entry.set("argv", Value::str_list(spec.eval_argv(dspec, &mut view)?));
        if dspec.builder == "script-dag" {
            let plan = spec.eval_plan(dspec, &mut view)?;
            entry.set(
                "steps",
                Value::List(
                    plan.steps
                        .iter()
                        .map(|step| Value::str_list(step.argv.clone()))
                        .collect(),
                ),
            );
        }
    }
    Ok(())
}
