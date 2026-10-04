//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — plan wire codec (low-level line parser and renderer helpers)

use super::{BootstrapEntry, ExecMeta, ExecNode};
use crate::spec::{ActivePlan, CompileGroup, RefPolicy, Step};
use std::fmt::Write as _;
use std::path::Path;

pub(super) fn line(out: &mut String, key: &str, value: &str) {
    writeln!(out, "{key}: {value}").expect("write to string");
}

pub(super) fn render_xplan(out: &mut String, plan: &ActivePlan) {
    for group in &plan.compiles {
        writeln!(out, "xplan-compile").expect("write to string");
        line(out, "xplan-compile-when", &group.when);
        line(out, "xplan-compile-kind", &group.kind);
        line(out, "xplan-compile-tool", &group.tool);
        for flag in &group.flags {
            line(out, "xplan-compile-flag", flag);
        }
        for source in &group.sources {
            line(out, "xplan-compile-source", source);
        }
        line(out, "xplan-compile-scan-dir", &group.scan_dir);
        line(out, "xplan-compile-scan-ext", &group.scan_ext);
        for exclude in &group.scan_exclude {
            line(out, "xplan-compile-scan-exclude", exclude);
        }
        line(out, "xplan-compile-obj", &group.obj);
        writeln!(out, "xplan-end").expect("write to string");
    }
    for step in &plan.steps {
        writeln!(out, "xplan-step").expect("write to string");
        line(out, "xplan-step-when", &step.when);
        line(out, "xplan-step-tool", &step.tool);
        for arg in &step.argv {
            line(out, "xplan-step-argv", arg);
        }
        line(out, "xplan-step-capture", &step.capture);
        for output in &step.outputs {
            line(out, "xplan-step-output", output);
        }
        writeln!(out, "xplan-end").expect("write to string");
    }
}

pub(super) struct Parser<'a> {
    pub(super) lines: Vec<&'a str>,
    pub(super) idx: usize,
}

impl<'a> Parser<'a> {
    pub(super) fn line_no(&self) -> usize {
        self.idx + 1
    }

    pub(super) fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.idx).copied()
    }

    pub(super) fn next(&mut self) -> Result<&'a str, String> {
        let line = self
            .peek()
            .ok_or_else(|| "unexpected end of plan".to_string())?;
        self.idx += 1;
        Ok(line)
    }

    pub(super) fn expect_exact(&mut self, expected: &str) -> Result<(), String> {
        let line = self.next()?;
        if line == expected {
            Ok(())
        } else {
            Err(format!(
                "line {}: expected `{expected}`, got `{line}`",
                self.idx
            ))
        }
    }

    pub(super) fn take_value(&mut self, key: &str) -> Result<String, String> {
        let line = self.next()?;
        let prefix = format!("{key}: ");
        line.strip_prefix(&prefix)
            .map(str::to_string)
            .ok_or_else(|| format!("line {}: expected `{key}:`, got `{line}`", self.idx))
    }

    pub(super) fn expect_value(&mut self, key: &str, expected: &str) -> Result<(), String> {
        let value = self.take_value(key)?;
        if value == expected {
            Ok(())
        } else {
            Err(format!("line {}: expected {key}: {expected}", self.idx))
        }
    }

    pub(super) fn parse_node(&mut self, name: String) -> Result<ExecNode, String> {
        let mut node = ExecNode {
            name,
            arch: String::new(),
            builder: String::new(),
            tools: Vec::new(),
            env: Vec::new(),
            srcs: Vec::new(),
            srcdirs: Vec::new(),
            source_roots: Vec::new(),
            source_overlays: Vec::new(),
            deps: Vec::new(),
            config: Vec::new(),
            module_config: None,
            argv: Vec::new(),
            plan: Vec::new(),
            outputs: Vec::new(),
            exec: ExecMeta {
                tool: String::new(),
                extra_tools: Vec::new(),
                env: Vec::new(),
                srcdirs: Vec::new(),
                source_roots: Vec::new(),
                argv: Vec::new(),
                stage_deps: Vec::new(),
                copy: Vec::new(),
                host_tool: false,
                allowed_refs: RefPolicy::None,
                shell: None,
                mounts: Vec::new(),
                version_flags: Vec::new(),
                substituter: None,
                module_config_text: String::new(),
            },
            active_plan: ActivePlan {
                compiles: Vec::new(),
                steps: Vec::new(),
            },
        };
        let mut allowed_refs_scalar = false;
        let mut allowed_refs_list = false;
        loop {
            let line = self
                .peek()
                .ok_or_else(|| format!("drv `{}` is truncated before end", node.name))?;
            if line == "end" {
                self.idx += 1;
                break;
            }
            if line == "xplan-compile" {
                self.idx += 1;
                node.active_plan.compiles.push(self.parse_compile()?);
                continue;
            }
            if line == "xplan-step" {
                self.idx += 1;
                node.active_plan.steps.push(self.parse_step()?);
                continue;
            }
            let (key, value) = split_key_value(line)
                .ok_or_else(|| format!("line {}: malformed node line `{line}`", self.line_no()))?;
            self.idx += 1;
            match key {
                "arch" => set_once(&mut node.arch, value, "arch")?,
                "builder" => set_once(&mut node.builder, value, "builder")?,
                "tool" => node.tools.push(parse_pair(value, "tool")?),
                "env" => node.env.push(parse_pair(value, "env")?),
                "src" => node.srcs.push(parse_src(value)?),
                "srcdir" => node.srcdirs.push(parse_tree_ref(value, "srcdir")?),
                "source-root" => node
                    .source_roots
                    .push(parse_tree_ref(value, "source-root")?),
                "source-overlay" => node
                    .source_overlays
                    .push(parse_pair(value, "source-overlay")?),
                "dep" => node.deps.push(value.to_string()),
                "config" => node.config.push(parse_pair(value, "config")?),
                "module-config" => {
                    if node.module_config.is_some() {
                        return Err("module-config cannot be repeated".to_string());
                    }
                    let digest = value.strip_prefix("sha256:").ok_or_else(|| {
                        format!("module-config must be sha256:<hex>, got `{value}`")
                    })?;
                    node.module_config = Some(parse_hex(digest, 64, "module-config")?);
                }
                "exec-module-config" => set_once(
                    &mut node.exec.module_config_text,
                    value,
                    "exec-module-config",
                )?,
                "argv" => node.argv.push(value.to_string()),
                "plan" => node.plan.push(value.to_string()),
                "out" => node.outputs.push(value.to_string()),
                "exec-tool" => set_once(&mut node.exec.tool, value, "exec-tool")?,
                "exec-extra-tool" => node.exec.extra_tools.push(value.to_string()),
                "exec-env" => node.exec.env.push(parse_pair(value, "exec-env")?),
                "exec-srcdir" => node
                    .exec
                    .srcdirs
                    .push(parse_tree_ref(value, "exec-srcdir")?),
                "exec-source-root" => node
                    .exec
                    .source_roots
                    .push(parse_tree_ref(value, "exec-source-root")?),
                "exec-argv" => node.exec.argv.push(value.to_string()),
                "exec-stage-dep" => node
                    .exec
                    .stage_deps
                    .push(parse_pair(value, "exec-stage-dep")?),
                "exec-copy" => node.exec.copy.push(parse_pair(value, "exec-copy")?),
                "exec-host-tool" => {
                    node.exec.host_tool = match value {
                        "true" => true,
                        "false" => false,
                        _ => {
                            return Err(format!(
                                "exec-host-tool must be true or false, got `{value}`"
                            ));
                        }
                    };
                }
                "exec-allowed-refs" => {
                    if allowed_refs_scalar || allowed_refs_list {
                        return Err(
                            "exec-allowed-refs cannot be repeated or combined with exec-allowed-ref"
                                .to_string(),
                        );
                    }
                    allowed_refs_scalar = true;
                    node.exec.allowed_refs = match value {
                        "none" => RefPolicy::None,
                        "closure" => RefPolicy::Closure,
                        _ => {
                            return Err(format!(
                                "exec-allowed-refs must be none or closure, got `{value}`"
                            ));
                        }
                    };
                }
                "exec-allowed-ref" => match &mut node.exec.allowed_refs {
                    RefPolicy::None => {
                        if allowed_refs_scalar {
                            return Err(
                                "exec-allowed-ref cannot be combined with exec-allowed-refs"
                                    .to_string(),
                            );
                        }
                        allowed_refs_list = true;
                        node.exec.allowed_refs = RefPolicy::List(vec![value.to_string()]);
                    }
                    RefPolicy::List(items) => {
                        allowed_refs_list = true;
                        items.push(value.to_string());
                    }
                    RefPolicy::Closure => {
                        return Err(
                            "exec-allowed-ref cannot be combined with exec-allowed-refs: closure"
                                .to_string(),
                        );
                    }
                },
                "exec-shell" => {
                    if node.exec.shell.is_some() {
                        return Err("exec-shell cannot be repeated".to_string());
                    }
                    node.exec.shell = Some(value.to_string());
                }
                "exec-mount" => {
                    let (target, provider) = parse_pair(value, "exec-mount")?;
                    let (dep, rel) = provider
                        .split_once(':')
                        .ok_or_else(|| format!("exec-mount `{value}` lacks `<dep>:<dir>`"))?;
                    reject_clean_rel(rel, "exec-mount")?;
                    if !target.starts_with('/') {
                        return Err(format!("exec-mount target `{target}` is not absolute"));
                    }
                    node.exec
                        .mounts
                        .push((target, dep.to_string(), rel.to_string()));
                }
                "exec-version-flag" => node
                    .exec
                    .version_flags
                    .push(parse_pair(value, "exec-version-flag")?),
                "exec-substituter" => {
                    if node.exec.substituter.is_some() {
                        return Err("exec-substituter cannot be repeated".to_string());
                    }
                    let (key, rel) = value.split_once(':').ok_or_else(|| {
                        format!("exec-substituter `{value}` lacks `<key>:<path>`")
                    })?;
                    reject_clean_rel(rel, "exec-substituter")?;
                    node.exec.substituter = Some((key.to_string(), rel.to_string()));
                }
                _ => return Err(format!("line {}: unknown key `{key}`", self.idx)),
            }
        }
        if node.arch.is_empty() || node.builder.is_empty() || node.exec.tool.is_empty() {
            return Err(format!("drv `{}` is missing required fields", node.name));
        }
        Ok(node)
    }

    pub(super) fn parse_compile(&mut self) -> Result<CompileGroup, String> {
        let when = self.take_value("xplan-compile-when")?;
        let kind = self.take_value("xplan-compile-kind")?;
        let tool = self.take_value("xplan-compile-tool")?;
        let mut flags = Vec::new();
        while self
            .peek()
            .is_some_and(|line| line.starts_with("xplan-compile-flag: "))
        {
            flags.push(self.take_value("xplan-compile-flag")?);
        }
        let mut sources = Vec::new();
        while self
            .peek()
            .is_some_and(|line| line.starts_with("xplan-compile-source: "))
        {
            sources.push(self.take_value("xplan-compile-source")?);
        }
        let scan_dir = self.take_value("xplan-compile-scan-dir")?;
        let scan_ext = self.take_value("xplan-compile-scan-ext")?;
        let mut scan_exclude = Vec::new();
        while self
            .peek()
            .is_some_and(|line| line.starts_with("xplan-compile-scan-exclude: "))
        {
            scan_exclude.push(self.take_value("xplan-compile-scan-exclude")?);
        }
        let obj = self.take_value("xplan-compile-obj")?;
        self.expect_exact("xplan-end")?;
        Ok(CompileGroup {
            when,
            kind,
            tool,
            flags,
            sources,
            scan_dir,
            scan_ext,
            scan_exclude,
            obj,
        })
    }

    pub(super) fn parse_step(&mut self) -> Result<Step, String> {
        let when = self.take_value("xplan-step-when")?;
        let tool = self.take_value("xplan-step-tool")?;
        let mut argv = Vec::new();
        while self
            .peek()
            .is_some_and(|line| line.starts_with("xplan-step-argv: "))
        {
            argv.push(self.take_value("xplan-step-argv")?);
        }
        let capture = self.take_value("xplan-step-capture")?;
        let mut outputs = Vec::new();
        while self
            .peek()
            .is_some_and(|line| line.starts_with("xplan-step-output: "))
        {
            outputs.push(self.take_value("xplan-step-output")?);
        }
        self.expect_exact("xplan-end")?;
        Ok(Step {
            when,
            tool,
            argv,
            capture,
            outputs,
        })
    }
}

pub(super) fn parse_bootstrap(value: &str) -> Result<BootstrapEntry, String> {
    let mut parts = value.splitn(3, ' ');
    let kind = parse_kind(parts.next().unwrap_or(""), "bootstrap")?;
    let rel = parts
        .next()
        .ok_or_else(|| format!("invalid bootstrap line `{value}`"))?
        .to_string();
    let hash = parts
        .next()
        .and_then(|v| v.strip_prefix("sha256:"))
        .ok_or_else(|| format!("invalid bootstrap hash in `{value}`"))?;
    Ok(BootstrapEntry {
        kind,
        rel,
        hash: parse_hex(hash, 64, "bootstrap hash")?,
    })
}

pub(super) fn parse_src(value: &str) -> Result<(char, String, String), String> {
    let mut parts = value.splitn(3, ' ');
    let kind = parse_kind(parts.next().unwrap_or(""), "src")?;
    let rel = parts
        .next()
        .ok_or_else(|| format!("invalid src line `{value}`"))?
        .to_string();
    let hash = parts
        .next()
        .and_then(|v| v.strip_prefix("sha256:"))
        .ok_or_else(|| format!("invalid src hash in `{value}`"))?;
    Ok((kind, rel, parse_hex(hash, 64, "src hash")?))
}

pub(super) fn parse_tree_ref(value: &str, ctx: &str) -> Result<(String, String), String> {
    let (rel, hash) = value
        .rsplit_once(" tree:")
        .ok_or_else(|| format!("invalid {ctx} line `{value}`"))?;
    Ok((rel.to_string(), parse_hex(hash, 64, ctx)?))
}

pub(super) fn parse_pair(value: &str, ctx: &str) -> Result<(String, String), String> {
    let (k, v) = value
        .split_once('=')
        .ok_or_else(|| format!("{ctx} line lacks `=`: `{value}`"))?;
    Ok((k.to_string(), v.to_string()))
}

pub(super) fn parse_kind(value: &str, ctx: &str) -> Result<char, String> {
    let mut chars = value.chars();
    let Some(kind) = chars.next() else {
        return Err(format!("{ctx} kind is empty"));
    };
    if chars.next().is_some() {
        return Err(format!("{ctx} kind must be one char, got `{value}`"));
    }
    validate_kind(kind, ctx)?;
    Ok(kind)
}

pub(super) fn validate_kind(kind: char, ctx: &str) -> Result<(), String> {
    if kind == 'f' || kind == 'x' || (kind == 'l' && ctx == "bootstrap") {
        Ok(())
    } else {
        Err(format!("{ctx} kind must be f or x, got `{kind}`"))
    }
}

pub(super) fn parse_hex(value: &str, len: usize, ctx: &str) -> Result<String, String> {
    if value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(value.to_string())
    } else {
        Err(format!("{ctx} must be {len} hex characters, got `{value}`"))
    }
}

pub(super) fn reject_newline(value: &str, ctx: &str) -> Result<(), String> {
    if value.contains('\n') {
        Err(format!("{ctx} contains a newline"))
    } else {
        Ok(())
    }
}

pub(super) fn reject_clean_rel(value: &str, ctx: &str) -> Result<(), String> {
    reject_newline(value, ctx)?;
    if value.is_empty()
        || Path::new(value).is_absolute()
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        Err(format!("{ctx} path must be clean relative, got `{value}`"))
    } else {
        Ok(())
    }
}

pub(super) fn split_key_value(line: &str) -> Option<(&str, &str)> {
    line.split_once(": ")
}

pub(super) fn set_once(dst: &mut String, value: &str, key: &str) -> Result<(), String> {
    if dst.is_empty() {
        *dst = value.to_string();
        Ok(())
    } else {
        Err(format!("duplicate key `{key}`"))
    }
}
