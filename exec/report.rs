//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — toolchain report
//!
//! A concrete (host or store) toolchain pinned at plan time is named by
//! `<store-root>/<store-name>/<relpath>`; the version string is the only
//! observable identity for a runtime report. We re-run the staged
//! `rustc --version` / `clang --version` against the tool's effective
//! library search path (the union of the tool's lib dirs plus its declared
//! provider closure) and emit one `ToolReport` per selected tool with
//! store-name + locator + observed version.

use crate::eval::graph::ResolvedDrv;
use crate::eval::plan::ExecPlan;
use crate::events::ToolReport;
use crate::store::Store;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub fn toolchain_report(
    plan: &ExecPlan,
    store: &Store,
    resolved: &BTreeMap<String, ResolvedDrv>,
) -> Vec<ToolReport> {
    let mut out = Vec::new();
    for wanted in ["rustc", "clang"] {
        let mut selected = None;
        for locator in plan
            .nodes
            .iter()
            .flat_map(|node| node.tools.iter())
            .filter_map(|(tool, marker)| {
                if tool == wanted && marker.starts_with("store:") {
                    Some(marker.clone())
                } else {
                    None
                }
            })
        {
            let Some((provider, relpath)) = locator
                .strip_prefix("store:")
                .and_then(|rest| rest.split_once(':'))
            else {
                continue;
            };
            let Some(resolved) = resolved.get(provider) else {
                continue;
            };
            if resolved.digest.is_none() {
                continue;
            }
            let store_name = &resolved.store_name;
            let path = store.root.join(store_name).join(relpath);
            let lib_paths = tool_runtime_library_paths(store, store_name);
            let Some(version) = query_tool_version(&path, wanted, &lib_paths) else {
                continue;
            };
            selected = Some(ToolReport {
                name: wanted.to_string(),
                version,
                locator,
            });
        }
        if let Some(report) = selected {
            out.push(report);
        }
    }
    out
}

fn tool_runtime_library_paths(store: &Store, store_name: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();
    for name in std::iter::once(store_name.to_string()).chain(
        store
            .read_meta(store_name)
            .map(|meta| meta.refs)
            .unwrap_or_default(),
    ) {
        let root = store.root.join(name);
        for rel in ["lib", "usr/lib"] {
            let dir = root.join(rel);
            if dir.is_dir() && seen.insert(dir.clone()) {
                paths.push(dir);
            }
        }
    }
    paths
}

fn query_tool_version(path: &Path, tool: &str, lib_paths: &[PathBuf]) -> Option<String> {
    let query = if tool == "nasm" { "-v" } else { "--version" };
    let mut cmd = crate::invocation::command(path);
    cmd.arg(query);
    if !lib_paths.is_empty() {
        let mut ld_paths = lib_paths.to_vec();
        if let Some(existing) = crate::invocation::ambient_var_os("LD_LIBRARY_PATH") {
            ld_paths.extend(std::env::split_paths(&existing));
        }
        if let Ok(joined) = std::env::join_paths(ld_paths) {
            cmd.env("LD_LIBRARY_PATH", joined);
        }
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    for stream in [&output.stdout, &output.stderr] {
        if let Some(line) = String::from_utf8_lossy(stream)
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            return Some(line.to_string());
        }
    }
    None
}
