//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — builder templates
//!
//! Builders are data-defined: a derivation's spec carries the tool and the
//! full argv (transcribed command lines), so a template here validates the
//! declared shape rather than synthesizing it — a misdeclared derivation
//! fails at spec load or output capture, not deep inside a compile.

use super::{DrvSpec, Flagset};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The builder names the engine accepts. `script-dag` runs an inner ninja
/// over declared compile groups and steps; `fetch` is the fixed-output
/// network derivation and the only networked builder; `untar` imports a
/// pinned archive in process; `port` realizes an expanded port recipe from
/// its declared arguments; `module` runs a declared module as the builder;
/// the rest are plain single-command templates. FHS composition
/// and the stage-0 Rust assembly run as `script-dag` steps against
/// standalone store tools and scripts (`buildutil-compose`, `buildutil-sysroot`,
/// `stage0-assemble.sh`).
pub const KNOWN: &[&str] = &[
    "bindgen",
    "rustc-crate",
    "nasm",
    "clang-obj",
    "clang-link",
    "ld-lld",
    "lld-link",
    "objcopy",
    "strip",
    "ar",
    "script-dag",
    "fetch",
    "port",
    "untar",
    "module",
    "source-tree",
];

/// Fixed-output derivations: identity is the declared content pin. Network
/// belongs to these alone, and among them only `fetch` runs a subprocess.
pub fn is_fixed_output(builder: &str) -> bool {
    matches!(builder, "fetch" | "untar")
}

pub fn is_in_process(builder: &str) -> bool {
    matches!(builder, "untar" | "source-tree")
}

fn argv_has_prefix(
    arguments: &[String],
    flagsets: &BTreeMap<String, Flagset>,
    prefix: &str,
    visited: &mut BTreeSet<String>,
) -> bool {
    arguments.iter().any(|argument| {
        if argument.starts_with(prefix) {
            return true;
        }
        let Some(name) = argument
            .strip_prefix("{flagset:")
            .and_then(|rest| rest.strip_suffix('}'))
        else {
            return false;
        };
        if !visited.insert(name.to_string()) {
            return false;
        }
        let Some(flagset) = flagsets.get(name) else {
            return false;
        };
        argv_has_prefix(&flagset.flags, flagsets, prefix, visited)
            || argv_has_prefix(&flagset.tail, flagsets, prefix, visited)
    })
}

pub fn validate(spec: &DrvSpec, flagsets: &BTreeMap<String, Flagset>) -> Result<(), String> {
    if spec.bootstrap && spec.native_frontend {
        return Err(format!(
            "derivation `{}`: bootstrap and native-frontend provider grades are mutually exclusive",
            spec.name
        ));
    }
    if spec.native_frontend && (spec.builder != "rustc-crate" || spec.tool != "rustc") {
        return Err(format!(
            "derivation `{}`: native-frontend is reserved for rustc-crate targets",
            spec.name
        ));
    }
    if !KNOWN.contains(&spec.builder.as_str()) {
        return Err(format!(
            "derivation `{}`: unknown builder `{}` (known: {})",
            spec.name,
            spec.builder,
            KNOWN.join(", ")
        ));
    }
    if spec.builder != "script-dag" && (!spec.compiles.is_empty() || !spec.steps.is_empty()) {
        return Err(format!(
            "derivation `{}`: compile/step tables need builder = \"script-dag\"",
            spec.name
        ));
    }
    match spec.builder.as_str() {
        "bindgen" => {
            if !spec.argv.iter().any(|a| a == "--output") {
                return Err(format!(
                    "derivation `{}`: bindgen builders pass `--output {{out}}/<file>`",
                    spec.name
                ));
            }
        }
        "rustc-crate" => {
            let has_crate_name =
                argv_has_prefix(&spec.argv, flagsets, "--crate-name", &mut BTreeSet::new());
            if !has_crate_name {
                return Err(format!(
                    "derivation `{}`: rustc-crate builders pass `--crate-name`",
                    spec.name
                ));
            }
        }
        "script-dag" => {
            if spec.compiles.is_empty() && spec.steps.is_empty() {
                return Err(format!(
                    "derivation `{}`: script-dag needs compile groups or steps",
                    spec.name
                ));
            }
            if !spec.argv.is_empty() {
                return Err(format!(
                    "derivation `{}`: script-dag argv is generated — declare steps instead",
                    spec.name
                ));
            }
            // Every inner tool must be declared so its store provider enters
            // the dependency graph and becomes reachable via the private toolbin.
            let declared = |t: &str| t == spec.tool || spec.extra_tools.iter().any(|e| e == t);
            for group in &spec.compiles {
                if !declared(&group.tool) {
                    return Err(format!(
                        "derivation `{}`: compile tool `{}` not in tool/extra-tools",
                        spec.name, group.tool
                    ));
                }
                // Group sources must be covered by the declared inputs.
                for source in &group.sources {
                    let covered = spec.sources.iter().any(|s| s == source)
                        || spec
                            .src_dirs
                            .iter()
                            .any(|d| source.starts_with(&format!("{}/", d)))
                        || spec
                            .source_roots
                            .iter()
                            .any(|d| source.starts_with(&format!("{}/", d)));
                    if !covered {
                        return Err(format!(
                            "derivation `{}`: compile source `{}` not covered by sources/src-dirs",
                            spec.name, source
                        ));
                    }
                }
            }
            for step in &spec.steps {
                if !declared(&step.tool) {
                    return Err(format!(
                        "derivation `{}`: step tool `{}` not in tool/extra-tools",
                        spec.name, step.tool
                    ));
                }
            }
        }
        "untar" => {
            for key in ["BUILDUTIL_FIXED_SHA256", "BUILDUTIL_FIXED_TREE_SHA256"] {
                let value = spec
                    .env
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                if value.is_empty() {
                    return Err(format!(
                        "derivation `{}`: untar needs a non-empty {}",
                        spec.name, key
                    ));
                }
            }
        }
        "module" => {
            if spec.module.is_empty() {
                return Err(format!(
                    "derivation `{}`: builder = \"module\" needs `module`",
                    spec.name
                ));
            }
            for key in &spec.config_keys {
                if key.is_empty() || key.contains(['=', ' ', '\n']) {
                    return Err(format!(
                        "derivation `{}`: config-keys holds a malformed key `{key}`",
                        spec.name
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Post-builder output conditions beyond file existence.
pub fn check_outputs(spec: &DrvSpec, out_dir: &Path) -> Result<(), String> {
    match spec.builder.as_str() {
        // rmeta outputs must be non-empty rustc metadata blobs.
        "rustc-crate" => {
            for output in &spec.outputs {
                if output.ends_with(".rmeta") {
                    let meta = std::fs::metadata(out_dir.join(output))
                        .map_err(|e| format!("`{}`: missing {}: {}", spec.name, output, e))?;
                    if meta.len() == 0 {
                        return Err(format!("`{}`: {} is empty", spec.name, output));
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
