//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the port builder's registration: it reads its declared
//! arguments, writes the phase script, and after the run applies install
//! processing and records the runtime dependencies its arguments name.

use super::portbuild::{self, PortArgs, PortRecipe};
use crate::exec::builder::{Builder, BuilderContext, BuilderRegistry, PreparedBuilder};

pub(super) fn register(registry: &mut BuilderRegistry) {
    registry.register(&PORT_BUILDER);
}

struct PortBuilder;

static PORT_BUILDER: PortBuilder = PortBuilder;

/// The derivation's arguments after the tool word, and its expanded recipe.
fn declared(ctx: &BuilderContext<'_>) -> Result<(PortArgs, PortRecipe), String> {
    let args = PortArgs::parse(ctx.drv.argv.get(1..).unwrap_or(&[]))
        .map_err(|e| format!("`{}`: {e}", ctx.name))?;
    let recipe = PortRecipe::from_json(&args.recipe).map_err(|e| format!("`{}`: {e}", ctx.name))?;
    Ok((args, recipe))
}

impl Builder for PortBuilder {
    fn label(&self) -> &'static str {
        "port"
    }

    fn prepare(
        &self,
        ctx: &BuilderContext<'_>,
        extra_env: &mut Vec<(String, String)>,
    ) -> Result<PreparedBuilder, String> {
        let (args, recipe) = declared(ctx)?;
        let dep_names: Vec<String> = ctx.drv.deps.iter().map(|d| d.name.clone()).collect();
        let paths = portbuild::resolve_paths(
            &dep_names,
            &args,
            ctx.target_arch,
            ctx.build_dir,
            ctx.stage,
            ctx.out_dir,
            ctx.toolbin,
        )?;
        std::fs::create_dir_all(&paths.stage).map_err(|e| format!("cannot create stage: {}", e))?;
        // The port environment replaces the generic one, MAKEFLAGS included:
        // parallelism reaches the phases through the leased NPROC.
        *extra_env = portbuild::cross_env(&recipe, &args, &paths);
        let lease_slots = paths.nproc.saturating_sub(1);
        let script = portbuild::build_script(&recipe, &args, &paths);
        std::fs::write(ctx.cwd.join("build.sh"), script)
            .map_err(|e| format!("cannot write build.sh: {}", e))?;
        Ok(PreparedBuilder {
            argv: vec![
                ctx.tool_path.to_string_lossy().into_owned(),
                "build.sh".to_string(),
            ],
            lease_slots: Some(lease_slots),
        })
    }

    fn post_process(&self, ctx: &BuilderContext<'_>) -> Result<(), String> {
        let (args, recipe) = declared(ctx)?;
        let strip_tool = ctx.toolbin.join("llvm-strip");
        if !strip_tool.exists() {
            return Err("the port build needs llvm-strip declared as a tool".to_string());
        }
        portbuild::post_process(
            &recipe,
            &args,
            ctx.cwd,
            &ctx.out_dir.join("stage"),
            ctx.stage,
            &strip_tool,
        )
    }

    fn append_metadata(
        &self,
        ctx: &BuilderContext<'_>,
        metadata: &mut Vec<String>,
    ) -> Result<(), String> {
        let (args, recipe) = declared(ctx)?;
        metadata.push(format!("port: {} {}", recipe.name, recipe.version));
        if !recipe.description.is_empty() {
            metadata.push(format!("description: {}", recipe.description));
        }
        if !recipe.licenses.is_empty() {
            metadata.push(format!("license: {}", recipe.licenses.join(" OR ")));
        }
        for dependency in &args.runtime_dependencies {
            metadata.push(format!("runtime-dep: {}", dependency));
        }
        Ok(())
    }
}
