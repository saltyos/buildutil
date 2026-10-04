//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — builder interface and core command-builder implementation

use super::tokens::{
    expand_tool_versions, fetch_script, resolve_clang_tokens, resolve_exec_tokens,
};
use crate::eval::plan::ExecNode;
use crate::spec::DrvSpec;
use crate::store::Store;
use crate::store::derivation::Derivation;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

/// Realization-time state exposed to builder implementations. The engine owns
/// staging, tool resolution, sandbox execution, output validation, and store
/// registration; a builder owns only its kind-specific preparation and hooks.
pub struct BuilderContext<'a> {
    pub dspec: &'a DrvSpec,
    pub drv: &'a Derivation,
    pub node: &'a ExecNode,
    pub store: &'a Store,
    pub name: &'a str,
    pub store_name: &'a str,
    pub build_dir: &'a Path,
    pub stage: &'a Path,
    pub cwd: &'a Path,
    pub out_dir: &'a Path,
    pub toolbin: &'a Path,
    pub tool_path: &'a Path,
    pub tool_versions: &'a RefCell<BTreeMap<String, String>>,
    /// The configured target architecture and the build host of the plan.
    pub target_arch: &'a str,
    pub build_host: &'a str,
    /// A passing verdict's summary, shown with the completion line.
    pub verdict: &'a RefCell<Option<String>>,
}

pub struct PreparedBuilder {
    pub argv: Vec<String>,
    /// Maximum explicit jobserver tokens to lease. The engine acquires and
    /// holds them around the external run, then appends the resulting NPROC.
    pub lease_slots: Option<usize>,
}

impl PreparedBuilder {
    pub fn external(argv: Vec<String>) -> Self {
        PreparedBuilder {
            argv,
            lease_slots: None,
        }
    }

    pub fn in_process() -> Self {
        PreparedBuilder::external(Vec::new())
    }
}

/// One builder-kind implementation. Implementations may prepare an external
/// command or realize in-process, then apply kind-specific postconditions and
/// metadata without exposing extension modules to the exec core.
pub trait Builder: Sync {
    fn label(&self) -> &'static str;

    fn supports(&self, kind: &str) -> bool {
        self.label() == kind
    }

    fn is_in_process(&self) -> bool {
        false
    }

    fn action(&self, _kind: &str) -> &'static str {
        "Compiling"
    }

    fn prepare(
        &self,
        ctx: &BuilderContext<'_>,
        extra_env: &mut Vec<(String, String)>,
    ) -> Result<PreparedBuilder, String>;

    fn realize_in_process(&self, _ctx: &BuilderContext<'_>) -> Result<(), String> {
        Err(format!("builder `{}` is not in-process", self.label()))
    }

    fn post_process(&self, _ctx: &BuilderContext<'_>) -> Result<(), String> {
        Ok(())
    }

    /// Why an external run that exited with `status` failed the derivation.
    fn failure_reason(&self, _ctx: &BuilderContext<'_>, status: &str) -> String {
        format!("builder failed ({status})")
    }

    fn append_metadata(
        &self,
        _ctx: &BuilderContext<'_>,
        _metadata: &mut Vec<String>,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// The builder registry is assembled by the frontend composition root. The
/// core contributes the generic command builder; the full buildutil frontend adds
/// peripheral implementations from toolchain.
pub struct BuilderRegistry {
    builders: Vec<&'static dyn Builder>,
}

impl BuilderRegistry {
    pub fn core() -> Self {
        let mut registry = BuilderRegistry {
            builders: vec![&CORE_COMMAND_BUILDER],
        };
        registry.register(&UNTAR_BUILDER);
        registry.register(&SOURCE_TREE_BUILDER);
        registry.register(&super::module::MODULE_BUILDER);
        registry
    }

    pub fn register(&mut self, builder: &'static dyn Builder) {
        self.builders.push(builder);
    }

    pub fn resolve(&self, kind: &str) -> Result<&dyn Builder, String> {
        let mut found: Option<&dyn Builder> = None;
        for builder in &self.builders {
            if builder.supports(kind) {
                if let Some(prev) = found {
                    return Err(format!(
                        "builder `{kind}` is registered by both `{}` and `{}`",
                        prev.label(),
                        builder.label()
                    ));
                }
                found = Some(*builder);
            }
        }
        found.ok_or_else(|| format!("builder `{kind}` has no registered implementation"))
    }
}

struct CoreCommandBuilder;
struct UntarBuilder;

static CORE_COMMAND_BUILDER: CoreCommandBuilder = CoreCommandBuilder;
static UNTAR_BUILDER: UntarBuilder = UntarBuilder;
struct SourceTreeBuilder;
static SOURCE_TREE_BUILDER: SourceTreeBuilder = SourceTreeBuilder;

impl Builder for SourceTreeBuilder {
    fn label(&self) -> &'static str {
        "source-tree"
    }
    fn is_in_process(&self) -> bool {
        true
    }
    fn prepare(
        &self,
        _ctx: &BuilderContext<'_>,
        _env: &mut Vec<(String, String)>,
    ) -> Result<PreparedBuilder, String> {
        Ok(PreparedBuilder::in_process())
    }
    fn realize_in_process(&self, ctx: &BuilderContext<'_>) -> Result<(), String> {
        let hash = ctx
            .drv
            .srcdirs
            .iter()
            .find(|(path, _)| path == "source")
            .map(|(_, hash)| hash)
            .ok_or("source input has no captured tree")?;
        crate::source::materialize_tree(hash, &ctx.out_dir.join("source"))
    }
}

impl Builder for CoreCommandBuilder {
    fn label(&self) -> &'static str {
        "core-command"
    }

    fn supports(&self, kind: &str) -> bool {
        !matches!(kind, "port" | "untar" | "module" | "source-tree")
    }

    fn action(&self, kind: &str) -> &'static str {
        match kind {
            "fetch" => "Fetching",
            _ => "Compiling",
        }
    }

    fn prepare(
        &self,
        ctx: &BuilderContext<'_>,
        _extra_env: &mut Vec<(String, String)>,
    ) -> Result<PreparedBuilder, String> {
        let argv = match ctx.dspec.builder.as_str() {
            "fetch" => {
                let script = fetch_script(ctx.dspec)?;
                std::fs::write(ctx.cwd.join("fetch.sh"), script)
                    .map_err(|e| format!("cannot write fetch.sh: {}", e))?;
                vec![
                    ctx.tool_path.to_string_lossy().into_owned(),
                    "fetch.sh".to_string(),
                ]
            }
            _ => {
                // In argv both {srcroot} and {out} resolve relative to the
                // cwd (`stage/build`), preserving location independence.
                let mut argv = Vec::new();
                for (i, arg) in ctx.drv.argv.iter().enumerate() {
                    if i == 0 {
                        argv.push(ctx.tool_path.to_string_lossy().into_owned());
                        continue;
                    }
                    argv.push(expand_tool_versions(
                        resolve_clang_tokens(
                            resolve_exec_tokens(
                                arg,
                                Path::new(".."),
                                Path::new("../../out"),
                                ctx.stage,
                                ctx.drv,
                                true,
                            )?,
                            ctx.toolbin,
                        )?,
                        ctx.toolbin,
                        &ctx.node.exec.version_flags,
                        ctx.tool_versions,
                    )?);
                }
                argv
            }
        };
        Ok(PreparedBuilder::external(argv))
    }

    fn post_process(&self, ctx: &BuilderContext<'_>) -> Result<(), String> {
        if ctx.dspec.builder == "fetch" {
            let declared = ctx
                .dspec
                .env
                .iter()
                .find(|(k, _)| k == "BUILDUTIL_FIXED_SHA256")
                .map(|(_, v)| v.clone())
                .ok_or_else(|| format!("fetch `{}` lacks a declared sha256", ctx.name))?;
            let actual = crate::source::filehash::hash_file(&ctx.out_dir.join("source.tar"))?;
            if actual != declared {
                return Err(format!(
                    "fetch `{}`: checksum mismatch\n  declared {}\n  actual   {}",
                    ctx.name, declared, actual
                ));
            }
        }
        Ok(())
    }
}

impl Builder for UntarBuilder {
    fn label(&self) -> &'static str {
        "untar"
    }

    fn is_in_process(&self) -> bool {
        true
    }

    fn action(&self, _kind: &str) -> &'static str {
        "Importing"
    }

    fn prepare(
        &self,
        _ctx: &BuilderContext<'_>,
        _extra_env: &mut Vec<(String, String)>,
    ) -> Result<PreparedBuilder, String> {
        Ok(PreparedBuilder::in_process())
    }

    fn realize_in_process(&self, ctx: &BuilderContext<'_>) -> Result<(), String> {
        let declared = ctx
            .dspec
            .env
            .iter()
            .find(|(k, _)| k == "BUILDUTIL_FIXED_SHA256")
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| format!("untar `{}` lacks a declared sha256", ctx.name))?;
        let arg = ctx
            .dspec
            .argv
            .iter()
            .position(|a| a == "untar")
            .and_then(|i| ctx.dspec.argv.get(i + 1))
            .ok_or_else(|| format!("untar `{}` names no archive path", ctx.name))?;
        let rel = arg.strip_prefix("{srcroot}/.buildutil/").ok_or_else(|| {
            format!(
                "untar `{}`: archive path must be {{srcroot}}/.buildutil/<rest>, got `{}`",
                ctx.name, arg
            )
        })?;
        let archive = ctx.store.state_dir().join(rel);
        if !archive.is_file() {
            return Err(format!(
                "untar `{}`: import blob missing at {} — provision it on this host \
                 (see tools/toolchain/buildutil.toml) or substitute the realization",
                ctx.name,
                archive.display()
            ));
        }
        let actual = crate::source::filehash::hash_file(&archive)?;
        if actual != declared {
            return Err(format!(
                "untar `{}`: archive hash mismatch\n  declared {}\n  actual   {}\n  at {}",
                ctx.name,
                declared,
                actual,
                archive.display()
            ));
        }
        crate::exec::untar::extract(&archive, ctx.out_dir)?;

        let tree_hash = crate::source::filehash::hash_tree_with_dir_modes(ctx.out_dir)?;
        let declared_tree = ctx
            .dspec
            .env
            .iter()
            .find(|(k, _)| k == "BUILDUTIL_FIXED_TREE_SHA256")
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                format!(
                    "untar `{}` lacks BUILDUTIL_FIXED_TREE_SHA256; extracted tree would be {}",
                    ctx.name, tree_hash
                )
            })?;
        if declared_tree != tree_hash {
            return Err(format!(
                "untar `{}`: extracted tree hash mismatch\n  declared {}\n  actual   {}",
                ctx.name, declared_tree, tree_hash
            ));
        }

        let log_path = ctx.store.log_path(ctx.store_name);
        let _ = std::fs::write(
            &log_path,
            format!(
                "untar: {} verified sha256:{} tree_sha256:{}\n",
                archive.display(),
                actual,
                tree_hash
            ),
        );
        Ok(())
    }
}
