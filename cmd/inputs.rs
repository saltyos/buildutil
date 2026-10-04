// SPDX-License-Identifier: GPL-2.0-only
//! Input commands and acquisition through the existing tool providers and backends.

use super::input_resolution::{Acquisition, Resolution};
use super::{Args, Context};
use crate::inputs::content;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct Fetcher<'a> {
    ctx: &'a Context,
    args: &'a Args,
}

impl Fetcher<'_> {
    fn request(
        &self,
        url: &str,
        pin: Option<&str>,
    ) -> Result<crate::exec::input_fetch::Request, String> {
        let doc = crate::spec::toml::parse_file(&self.ctx.repo_root.join("buildutil.toml"))?;
        let stage_name = doc
            .table(&["lock"])
            .and_then(|table| table.get("fetch-stage"))
            .and_then(crate::spec::toml::Value::as_str)
            .unwrap_or("default");
        let stage = self
            .ctx
            .spec
            .stages
            .get(stage_name)
            .ok_or_else(|| format!("input acquisition: unknown fetch stage `{stage_name}`"))?;
        let shell = stage
            .shell
            .clone()
            .ok_or("input acquisition stage has no declared shell")?;
        let mut wanted: BTreeSet<String> = stage.default_tools.iter().cloned().collect();
        wanted.insert(shell.clone());
        wanted.insert("curl".to_string());
        let mut providers = BTreeMap::new();
        for tool in wanted {
            let provider = stage
                .tools
                .get(&tool)
                .or_else(|| self.ctx.spec.tool_providers.get(&tool))
                .ok_or_else(|| format!("input acquisition: no declared provider for `{tool}`"))?;
            providers.insert(tool, provider.clone());
        }
        let mut targets: BTreeSet<String> = providers
            .values()
            .map(|provider| provider.derivation.clone())
            .collect();
        targets.extend(stage.mounts.iter().map(|mount| mount.derivation.clone()));
        let targets = targets.into_iter().collect::<Vec<_>>();
        let mut toolchain = crate::tools::Toolchain::new(&self.ctx.state_root);
        let evaluated = crate::eval::graph::evaluate(
            &self.ctx.spec,
            &self.ctx.config,
            &mut toolchain,
            &targets,
            self.ctx.git_state(),
        )?;
        let (_, hash, plan) = crate::eval::plan::emit(
            &self.ctx.spec,
            &evaluated,
            &self.ctx.state_root,
            self.ctx.git_state(),
        )?;
        match self.ctx.backend {
            crate::host::ExecBackend::LocalLinux => {
                let sandbox = crate::exec::sandbox::platform_sandbox();
                let outcome = crate::exec::pool::realize(
                    &plan,
                    &self.ctx.store,
                    sandbox.as_ref(),
                    &crate::full_builders(),
                    self.args.jobs,
                    self.args.audit,
                    false,
                    self.args.keep_failed,
                    &BTreeSet::new(),
                    &crate::log::Logger::new(self.args.verbose),
                )?;
                if !outcome.failed.is_empty() {
                    return Err("repository input acquisition tools failed to build".into());
                }
            }
            crate::host::ExecBackend::Docker | crate::host::ExecBackend::Nerdctl => {
                let code = crate::host::container::run_plan_in_container(
                    &self.ctx.repo_root,
                    &self.ctx.state_root,
                    &self.ctx.build_host,
                    &self.ctx.backend,
                    self.ctx.spec.executor_image.as_ref(),
                    &hash,
                    None,
                    &super::executor_runtime_flags(self.args),
                )?;
                if code != 0 {
                    return Err(format!(
                        "repository input acquisition tools failed (exit {code})"
                    ));
                }
            }
            _ => {
                return Err(
                    "repository input acquisition requires the resolved Linux build backend".into(),
                );
            }
        }
        let realized = evaluated.dry_resolve(&self.ctx.store);
        let store_name = |name: &str| -> Result<String, String> {
            realized
                .get(name)
                .filter(|node| node.digest.is_some())
                .map(|node| node.store_name.clone())
                .ok_or_else(|| format!("repository input provider `{name}` was not realized"))
        };
        let mut closure: BTreeSet<String> = realized
            .values()
            .filter(|node| node.digest.is_some())
            .map(|node| node.store_name.clone())
            .collect();
        let mut pending: Vec<String> = closure.iter().cloned().collect();
        while let Some(name) = pending.pop() {
            let meta = self.ctx.store.read_meta(&name)?;
            for name in meta.refs.into_iter().chain(meta.references) {
                if closure.insert(name.clone()) {
                    pending.push(name);
                }
            }
        }
        let tools = providers
            .into_iter()
            .map(|(tool, provider)| {
                store_name(&provider.derivation)
                    .map(|name| (tool, format!("{name}/{}", provider.path)))
            })
            .collect::<Result<_, _>>()?;
        let mounts = stage
            .mounts
            .iter()
            .map(|mount| {
                store_name(&mount.derivation)
                    .map(|name| (mount.target.clone(), format!("{name}/{}", mount.path)))
            })
            .collect::<Result<_, _>>()?;
        Ok(crate::exec::input_fetch::Request {
            url: url.to_string(),
            sha256: pin.map(str::to_string),
            tools,
            providers: closure.into_iter().collect(),
            mounts,
            shell,
        })
    }
}

impl Acquisition for Fetcher<'_> {
    fn archive(&mut self, url: &str, sha256: Option<&str>) -> Result<(PathBuf, String), String> {
        if let Some(pin) = sha256 {
            let path = self
                .ctx
                .state_root
                .join("sources/input-archives")
                .join(format!("{pin}.tar"));
            if path.is_file() {
                if content::file(&path)?.0 != pin {
                    return Err(format!(
                        "repository input archive cache differs from sha256:{pin}"
                    ));
                }
                return Ok((path, pin.to_string()));
            }
        }
        let _lease = self.ctx.store.acquire_shared_lease()?;
        let request = self.request(url, sha256)?;
        let seq = REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = crate::state::plans_dir(&self.ctx.state_root)
            .join(format!("input-fetch-{}-{seq}.toml", std::process::id()));
        std::fs::create_dir_all(crate::state::plans_dir(&self.ctx.state_root))
            .map_err(|e| e.to_string())?;
        std::fs::create_dir_all(self.ctx.state_root.join("tmp")).map_err(|e| e.to_string())?;
        request.write(&path)?;
        match self.ctx.backend {
            crate::host::ExecBackend::LocalLinux => {
                crate::exec::input_fetch::acquire(&self.ctx.state_root, &path)?
            }
            crate::host::ExecBackend::Docker | crate::host::ExecBackend::Nerdctl => {
                let code = crate::host::container::run_input_acquisition(
                    &self.ctx.repo_root,
                    &self.ctx.state_root,
                    &self.ctx.build_host,
                    &self.ctx.backend,
                    self.ctx.spec.executor_image.as_ref(),
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .ok_or("input request has no filename")?,
                )?;
                if code != 0 {
                    return Err(format!("repository archive fetch failed (exit {code})"));
                }
            }
            _ => return Err("repository input acquisition requires a Linux build backend".into()),
        }
        let pin = std::fs::read_to_string(path.with_extension("sha256"))
            .map_err(|e| format!("repository fetch produced no archive pin: {e}"))?
            .trim()
            .to_string();
        if !crate::inputs::codec::hex(&pin, 64) {
            return Err("repository fetch produced a malformed archive pin".into());
        }
        let path = self
            .ctx
            .state_root
            .join("sources/input-archives")
            .join(format!("{pin}.tar"));
        if content::file(&path)?.0 != pin {
            return Err("repository archive changed after acquisition".into());
        }
        Ok((path, pin))
    }
}

pub(crate) fn resolve_context(
    ctx: &Context,
    args: &Args,
    updating: bool,
) -> Result<Resolution, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let cwd = crate::invocation::request_cwd()
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|e| e.to_string())?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let overrides = args
        .input_overrides
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                if path.is_absolute() {
                    path.clone()
                } else {
                    cwd.join(path)
                },
            )
        })
        .collect::<Vec<_>>();
    let mut acquisition = Fetcher { ctx, args };
    let resolution = super::input_resolution::resolve(
        &ctx.repo_root,
        &ctx.state_root,
        &overrides,
        args.locked,
        updating,
        &mut acquisition,
    )?;
    if !updating {
        let doc = crate::spec::toml::parse_file(&ctx.repo_root.join("buildutil.toml"))?;
        let lock = crate::inputs::codec::Lock::read(&ctx.repo_root.join("buildutil.lock"))?;
        for name in crate::inputs::codec::bootstrap_inputs(&doc)? {
            let input = resolution
                .inputs
                .get(&name)
                .and_then(|name| resolution.nodes.get(name))
                .ok_or_else(|| format!("bootstrap: unresolved input `{name}`"))?;
            if input.ahead {
                let entry_name = lock
                    .as_ref()
                    .and_then(|lock| lock.inputs.get(&name))
                    .map(String::as_str)
                    .unwrap_or(&name);
                return Err(format!(
                    "bootstrap: input `{name}` differs from buildutil.lock [input.{entry_name}].content"
                ));
            }
        }
    }
    Ok(resolution)
}

/// Specifications and declared own-tree sources are read from the same
/// immutable capture that supplied the lock comparison.
pub(crate) fn install(ctx: &mut Context) -> Result<(), String> {
    let mut selected = BTreeMap::new();
    for (name, input) in &ctx.inputs.nodes {
        let root = if input.declaration.source {
            input.root.clone()
        } else {
            let seq = REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let parent = ctx.state_root.join("sources/input-specs");
            std::fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
            let path = parent.join(format!("{}-{}-{seq}", name, std::process::id()));
            std::fs::create_dir(&path)
                .map_err(|e| format!("cannot create input specification view: {e}"))?;
            crate::source::materialize_tree(input.content.trim_start_matches("tree:"), &path)?;
            path
        };
        selected.insert(
            name.clone(),
            crate::spec::inputs::Selected {
                repository: crate::spec::Repository {
                    name: name.clone(),
                    root,
                    content: input.content.clone(),
                    rev: input.rev.clone(),
                    dirty: input.dirty,
                    consumers: BTreeSet::new(),
                    published: BTreeSet::new(),
                    variants: BTreeSet::new(),
                    source_names: BTreeMap::new(),
                },
                source: input.declaration.source,
                inputs: input.inputs.clone(),
            },
        );
    }
    let mut spec = crate::spec::inputs::install((*ctx.spec).clone(), &ctx.inputs.inputs, selected)?;
    for drv in spec.drvs.values() {
        crate::spec::builders::validate(drv, &spec.flagsets)?;
    }
    for (name, input) in &ctx.inputs.nodes {
        spec.spec_inputs.push(crate::spec::SpecInput {
            path: format!("input.{name}"),
            hash: input.content.trim_start_matches("tree:").to_string(),
            kind: crate::spec::SpecInputKind::Generated,
        });
    }
    ctx.spec = std::sync::Arc::new(spec);
    Ok(())
}

/// Capture verified input pins; neither dirtiness nor failed acquisition can replace the lock.
pub(crate) fn cmd_lock(args: &Args) -> Result<i32, String> {
    if crate::host::ExecBackend::resolve(&args.backend)? == crate::host::ExecBackend::Wsl {
        return crate::host::wsl::run_wsl_backend(&super::repo_root_from_cwd()?, &args.argv);
    }
    if !args.targets.is_empty() {
        return Err(
            "lock: inputs come from [input] declarations; no target arguments are accepted".into(),
        );
    }
    let ctx = super::open_static_context(args)?;
    let _lease = ctx.store.acquire_shared_lease()?;
    let resolution = resolve_context(&ctx, args, true)?;
    super::input_resolution::update(&ctx.repo_root, &resolution)?;
    crate::log::success(
        "lock",
        &format!(
            "Wrote {} with {} verified input entries",
            ctx.repo_root.join("buildutil.lock").display(),
            resolution.nodes.len()
        ),
    );
    Ok(0)
}
