//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — spec load helpers
//!
//! TOML-shape parsing helpers and argv token expansion (arch / build-host /
//! target-table / config / dep). All `pub(crate)` so the loader in mod.rs
//! and its sibling modules (modules, stages, required_checks) can call them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use super::configres::ConfigView;
use super::toml::{Doc, Table, Value};
use super::{CompileGroup, DrvSpec, RefPolicy, Step};

pub(crate) fn need_str(table: &Table, key: &str, ctx: &str) -> Result<String, String> {
    table
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("{}: missing string key `{}`", ctx, key))
}

pub(crate) fn opt_str_list(table: &Table, key: &str, ctx: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(v) => v
            .str_items()
            .ok_or_else(|| format!("{}: `{}` must be an array of strings", ctx, key)),
    }
}

pub(crate) fn ref_policy(table: &Table, ctx: &str) -> Result<RefPolicy, String> {
    match table.get("allowed-references") {
        None => Ok(RefPolicy::None),
        Some(Value::Str(s)) if s == "none" => Ok(RefPolicy::None),
        Some(Value::Str(s)) if s == "closure" => Ok(RefPolicy::Closure),
        Some(Value::Str(s)) => Err(format!(
            "{}: allowed-references string must be `none` or `closure`, got `{}`",
            ctx, s
        )),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                let Some(name) = item.as_str() else {
                    return Err(format!(
                        "{}: allowed-references list must contain strings",
                        ctx
                    ));
                };
                out.push(name.to_string());
            }
            Ok(RefPolicy::List(out))
        }
        Some(_) => Err(format!(
            "{}: allowed-references must be `none`, `closure`, or an array of derivation names",
            ctx
        )),
    }
}

pub(crate) fn no_newlines(items: &[String], ctx: &str) -> Result<(), String> {
    for item in items {
        if item.contains('\n') {
            return Err(format!("{}: value contains a newline: {:?}", ctx, item));
        }
    }
    Ok(())
}

fn clean_rel_path(kind: &str, path: &str, ctx: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{}: {} path must not be empty", ctx, kind));
    }
    let p = Path::new(path);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!(
            "{}: {} path must be clean repo-relative, got `{}`",
            ctx, kind, path
        ));
    }
    Ok(())
}

fn path_under_root(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{}/", root))
}

pub(crate) fn validate_source_projection(spec: &DrvSpec, ctx: &str) -> Result<(), String> {
    for root in &spec.source_roots {
        clean_rel_path("source-roots", root, ctx)?;
    }
    for (src, dest) in &spec.source_overlays {
        if super::dep_tokens(src).is_empty() {
            return Err(format!(
                "{}: source-overlays source `{}` must reference a declared {{dep:*}}",
                ctx, src
            ));
        }
        clean_rel_path("source-overlays destination", dest, ctx)?;
        if !spec
            .source_roots
            .iter()
            .any(|root| path_under_root(dest, root))
        {
            return Err(format!(
                "{}: source-overlays destination `{}` must be inside a declared source-root",
                ctx, dest
            ));
        }
    }
    Ok(())
}

pub(crate) fn flag_groups(
    doc: &Doc,
    prefix: &[&str],
) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut out = Vec::new();
    for table in doc.tables_under(prefix) {
        if table.path.len() != prefix.len() + 1
            || table.path[prefix.len()] != "flag-group"
            || !table.is_array
        {
            continue;
        }
        let ctx = format!("[{}]", table.path.join("."));
        let when = need_str(table, "when", &ctx)?;
        let flags = opt_str_list(table, "flags", &ctx)?;
        out.push((when, flags));
    }
    Ok(out)
}

/// Expand `{arch}` early; every other token survives into resolution.
pub(crate) fn expand_arch(items: &mut [String], arch: &str) {
    for item in items.iter_mut() {
        if item.contains("{arch}") {
            *item = item.replace("{arch}", arch);
        }
    }
}

fn build_host_arch(build_host: &str) -> &str {
    build_host
        .split_once('-')
        .map(|(arch, _)| arch)
        .unwrap_or(build_host)
}

pub(crate) fn expand_build_host_one(item: &mut String, build_host: &str) {
    if item.contains("{build.host.triple}") || item.contains("{build-host}") {
        *item = item
            .replace("{build.host.triple}", build_host)
            .replace("{build-host}", build_host);
    }
    if item.contains("{build.host.arch}") || item.contains("{build-host-arch}") {
        *item = item
            .replace("{build.host.arch}", build_host_arch(build_host))
            .replace("{build-host-arch}", build_host_arch(build_host));
    }
}

pub(crate) fn expand_build_host(items: &mut [String], build_host: &str) {
    for item in items.iter_mut() {
        expand_build_host_one(item, build_host);
    }
}

pub(crate) fn expand_build_host_table(
    item: &str,
    build_host_table: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut out = item.to_string();
    while let Some(start) = out.find("{build-host.") {
        let end = out[start..]
            .find('}')
            .map(|i| start + i)
            .ok_or_else(|| format!("unterminated {{build-host.*}} in `{}`", item))?;
        let key = &out[start + "{build-host.".len()..end];
        let value = build_host_table
            .get(key)
            .ok_or_else(|| format!("unknown build-host-table key `{}` in `{}`", key, item))?;
        out = format!("{}{}{}", &out[..start], value, &out[end + 1..]);
    }
    Ok(out)
}

pub(crate) fn compile_groups(doc: &Doc, drv: &str) -> Result<Vec<CompileGroup>, String> {
    let mut out = Vec::new();
    for table in doc.tables_under(&["derivation", drv]) {
        if !table.is_array || table.path.len() != 3 || table.path[2] != "compile" {
            continue;
        }
        let ctx = format!("[[derivation.{}.compile]]", drv);
        let kind = need_str(table, "kind", &ctx)?;
        if !["cc", "cc-simple", "nasm"].contains(&kind.as_str()) {
            return Err(format!("{}: unknown compile kind `{}`", ctx, kind));
        }
        let obj = need_str(table, "obj", &ctx)?;
        if !obj.contains("{stem}") && !obj.contains("{path}") {
            return Err(format!("{}: obj template needs {{stem}} or {{path}}", ctx));
        }
        let group = CompileGroup {
            when: table
                .get("when")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            kind,
            tool: need_str(table, "tool", &ctx)?,
            flags: opt_str_list(table, "flags", &ctx)?,
            sources: opt_str_list(table, "sources", &ctx)?,
            scan_dir: table
                .get("scan-dir")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            scan_ext: table
                .get("scan-ext")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            scan_exclude: opt_str_list(table, "scan-exclude", &ctx)?,
            obj,
        };
        if group.sources.is_empty() == group.scan_dir.is_empty() {
            return Err(format!("{}: declare either sources or scan-dir", ctx));
        }
        if !group.scan_dir.is_empty() && group.scan_ext.is_empty() {
            return Err(format!("{}: scan-dir needs scan-ext", ctx));
        }
        out.push(group);
    }
    Ok(out)
}

pub(crate) fn step_list(doc: &Doc, drv: &str) -> Result<Vec<Step>, String> {
    let mut out = Vec::new();
    for table in doc.tables_under(&["derivation", drv]) {
        if !table.is_array || table.path.len() != 3 || table.path[2] != "step" {
            continue;
        }
        let ctx = format!("[[derivation.{}.step]]", drv);
        let when = table
            .get("when")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tool = need_str(table, "tool", &ctx)?;
        let argv = opt_str_list(table, "argv", &ctx)?;
        let capture = table
            .get("capture")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let outputs = opt_str_list(table, "outputs", &ctx)?;
        let has_each = table.get("each").is_some();
        let each = opt_str_list(table, "each", &ctx)?;

        let push_step = |out: &mut Vec<Step>, step: Step| -> Result<(), String> {
            if step.outputs.is_empty() {
                return Err(format!("{}: a step needs outputs", ctx));
            }
            if !step.capture.is_empty() && !step.outputs.iter().any(|o| o == &step.capture) {
                return Err(format!("{}: capture file must be listed in outputs", ctx));
            }
            out.push(step);
            Ok(())
        };

        if !has_each {
            if argv
                .iter()
                .chain(outputs.iter())
                .any(|value| value.contains("{item}"))
                || capture.contains("{item}")
                || tool.contains("{item}")
                || when.contains("{item}")
            {
                return Err(format!("{}: {{item}} requires `each`", ctx));
            }
            push_step(
                &mut out,
                Step {
                    when,
                    tool,
                    argv,
                    capture,
                    outputs,
                },
            )?;
            continue;
        }

        if each.is_empty() {
            return Err(format!("{}: `each` must not be empty", ctx));
        }
        if tool.contains("{item}") || when.contains("{item}") {
            return Err(format!(
                "{}: {{item}} is not allowed in step `tool` or `when`",
                ctx
            ));
        }
        if outputs.iter().any(|output| !output.contains("{item}")) {
            return Err(format!(
                "{}: every output must contain {{item}} when `each` is present",
                ctx
            ));
        }
        let mut seen = BTreeSet::new();
        for item in &each {
            if item.is_empty() || item.contains('\n') || item.contains('{') || item.contains('}') {
                return Err(format!(
                    "{}: `each` item must be a non-empty plain literal: {:?}",
                    ctx, item
                ));
            }
            if !seen.insert(item) {
                return Err(format!("{}: duplicate `each` item `{}`", ctx, item));
            }
        }

        for item in each {
            push_step(
                &mut out,
                Step {
                    when: when.clone(),
                    tool: tool.clone(),
                    argv: argv
                        .iter()
                        .map(|value| value.replace("{item}", &item))
                        .collect(),
                    capture: capture.replace("{item}", &item),
                    outputs: outputs
                        .iter()
                        .map(|value| value.replace("{item}", &item))
                        .collect(),
                },
            )?;
        }
    }
    Ok(out)
}

pub(crate) fn expand_target(
    item: &str,
    arch_table: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut out = item.to_string();
    while let Some(start) = out.find("{target.") {
        let end = out[start..]
            .find('}')
            .map(|i| start + i)
            .ok_or_else(|| format!("unterminated {{target.*}} in `{}`", item))?;
        let key = &out[start + "{target.".len()..end];
        let value = arch_table
            .get(key)
            .ok_or_else(|| format!("unknown arch-table key `{}` in `{}`", key, item))?;
        out = format!("{}{}{}", &out[..start], value, &out[end + 1..]);
    }
    Ok(out)
}

/// Sorted recursive scan for a compile group's fan-out sources. Returns
/// repo-relative paths; `exclude` entries are repo-relative dir prefixes.
pub(crate) fn scan_sources(
    repo_root: &Path,
    dir: &str,
    ext: &str,
    exclude: &[String],
) -> Result<Vec<String>, String> {
    fn walk(
        repo_root: &Path,
        rel: &str,
        ext: &str,
        exclude: &[String],
        out: &mut Vec<String>,
        holes: &[String],
        scan_root: &str,
    ) -> Result<(), String> {
        if exclude.iter().any(|e| rel == e)
            || holes.iter().any(|hole| {
                rel == format!("{scan_root}/{hole}")
                    || rel.starts_with(&format!("{scan_root}/{hole}/"))
            })
        {
            return Ok(());
        }
        let abs = repo_root.join(rel);
        let mut entries: Vec<_> = std::fs::read_dir(&abs)
            .map_err(|e| format!("cannot scan {}: {}", abs.display(), e))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("scan entry under {}: {}", rel, e))?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = format!("{}/{}", rel, name);
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if meta.is_symlink() {
                if path.is_file() && name.ends_with(ext) {
                    out.push(child);
                }
                continue;
            }
            if meta.is_dir() {
                if std::fs::symlink_metadata(path.join(".git")).is_ok() {
                    continue;
                }
                walk(repo_root, &child, ext, exclude, out, holes, scan_root)?;
            } else if name.ends_with(ext) {
                out.push(child);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    let holes = crate::inputs::validate_source(repo_root, dir)?;
    walk(repo_root, dir, ext, exclude, &mut out, &holes, dir)?;
    out.sort();
    Ok(out)
}

/// Substitute `{config.KEY}` in place, recording the reads.
pub(crate) fn subst_config(items: &mut [String], view: &mut ConfigView<'_>) -> Result<(), String> {
    for item in items.iter_mut() {
        while let Some(start) = item.find("{config.") {
            let end = item[start..]
                .find('}')
                .map(|i| start + i)
                .ok_or_else(|| format!("unterminated {{config.*}} in `{}`", item))?;
            let key = item[start + "{config.".len()..end].to_string();
            let value = view.get(&key)?.to_string();
            *item = format!("{}{}{}", &item[..start], value, &item[end + 1..]);
        }
    }
    Ok(())
}

pub(crate) fn tool_version_tokens(arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = arg;
    while let Some(start) = rest.find("{tool-version:") {
        let tail = &rest[start + "{tool-version:".len()..];
        if let Some(end) = tail.find('}') {
            out.push(tail[..end].to_string());
            rest = &tail[end + 1..];
        } else {
            break;
        }
    }
    out
}
