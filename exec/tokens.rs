//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — exec-token resolution
//!
//! Recipes carry symbolic placeholders — `{srcroot}`, `{srcroot-abs}`,
//! `{out}`, `{out-abs}`, `{artifacts}`, `{buildroot-abs}`, `{dep:NAME}`, `{dep-abs:NAME}`,
//! `{self-hash}`, `{tool-version:NAME}`
//! — that are unresolved at evaluation time and resolved only at execution:
//!
//! - `{dep:NAME}` never expands to a concrete store directory. In `dep_rel`
//!   mode (argv / script-dag, run with cwd = `stage/build`) it becomes the
//!   stage-relative `../dep/NAME`; otherwise (buildutil-internal staging of dep
//!   files) it becomes the host path `stage/dep/NAME` — either way pointing
//!   at the `stage/dep/NAME` root the caller materializes onto the provider
//!   directory.
//! - `{dep-abs:NAME}` is the absolute staged view for tools such as CMake
//!   that reject relative compiler paths; namespace builds remap that host
//!   build-dir prefix to `/build`. Audit-grade symlinks can still be exposed
//!   by realpath; the output scanner is the authority that rejects
//!   store-path leaks.
//! - `{clang-resource-dir}` and `{clang-rt-builtins:<target>}` resolve
//!   through the staged clang provider.
//! - `{tool-version:NAME}` runs the staged tool with the version flag its
//!   provider declares (`--version` when none) and splices the first line.
//! - `{artifacts}` is the retained-artifact directory beside `{out}`: what a
//!   builder writes there is kept beside its build log, outside the output.
//! - `{self-hash}` is the derivation's own identity: the hash digits that
//!   begin its store name `<hash32>-<name>-<arch>`, the same literal at every
//!   grade and backend. The derivation hash is computed over the recipe with
//!   every token still symbolic, so this expansion never feeds back into it.
//!
//! Together these functions shape every argv a builder receives and every
//! `stage_deps` / `source_overlays` entry that needs runtime resolution.

use crate::spec::DrvSpec;
use crate::store::Store;
use crate::store::derivation::Derivation;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The build-directory entry a builder writes retained artifacts into; a
/// sibling of the output directory.
pub(super) const ARTIFACTS_DIR: &str = "artifacts";

/// clang-derived paths (resource dir, target builtins archive) resolve once
/// per process from the staged clang provider.
fn clang_query(clang: &Path, args: &[&str]) -> Result<String, String> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
    let key = format!("{}|{}", clang.display(), args.join(" "));
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(v) = cache.lock().expect("clang query cache").get(&key) {
        return Ok(v.clone());
    }
    let out = crate::invocation::command(clang)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {}: {}", clang.display(), e))?;
    if !out.status.success() {
        return Err(format!("{} {} failed", clang.display(), args.join(" ")));
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    cache
        .lock()
        .expect("clang query cache")
        .insert(key, value.clone());
    Ok(value)
}

/// `{clang-resource-dir}` and `{clang-rt-builtins:<target>}` stay symbolic in
/// derivation identity and resolve through the staged clang provider only here.
pub(super) fn resolve_clang_tokens(s: String, toolbin: &Path) -> Result<String, String> {
    if !s.contains("{clang-") {
        return Ok(s);
    }
    let clang = toolbin.join("clang");
    if !clang.exists() {
        return Err("a {clang-*} token needs clang declared as a tool".to_string());
    }
    let mut out = s;
    if out.contains("{clang-resource-dir}") {
        let dir = clang_query(&clang, &["--print-resource-dir"])?;
        out = out.replace("{clang-resource-dir}", &dir);
    }
    while let Some(start) = out.find("{clang-rt-builtins:") {
        let end = out[start..]
            .find('}')
            .map(|i| start + i)
            .ok_or("unterminated {clang-rt-builtins:*}")?;
        let target = out[start + "{clang-rt-builtins:".len()..end].to_string();
        let path = clang_query(
            &clang,
            &[&format!("--target={}", target), "-print-libgcc-file-name"],
        )?;
        out = format!("{}{}{}", &out[..start], path, &out[end + 1..]);
    }
    Ok(out)
}

/// Substitute the exec-phase tokens with real paths. Dependency-path
/// virtualization: `{dep:NAME}` never expands to a concrete store directory.
/// In `dep_rel` mode (argv / script-dag, run with cwd = `stage/build`) it
/// becomes the stage-relative `../dep/NAME`; otherwise (buildutil-internal
/// staging of dep files) it becomes the host path `stage/dep/NAME` — either
/// way pointing at the `stage/dep/NAME` root the caller materializes onto the
/// provider directory. `{dep-abs:NAME}` is the absolute staged view for tools
/// such as CMake that reject relative compiler paths; namespace builds remap
/// that host build-dir prefix to `/build`. `{self-hash}` becomes the hash
/// digits that begin `drv`'s store name, at every grade alike.
/// Audit-grade symlinks can still be exposed by realpath; the output scanner
/// is the authority that rejects store-path leaks.
pub(super) fn resolve_exec_tokens(
    arg: &str,
    srcroot: &Path,
    out_dir: &Path,
    stage: &Path,
    drv: &Derivation,
    dep_rel: bool,
) -> Result<String, String> {
    let mut out = arg.to_string();
    // Absolute tokens name paths the BUILDER dereferences. Under the Linux
    // namespace sandbox the build dir is bind-mounted at the constant
    // SANDBOX_BUILD, so builder-facing (dep_rel) expansions must be rooted
    // there — the hash-named host path does not exist inside the namespace.
    // Host-side staging expansions and audit-grade builds, the self-tool
    // class on every host, use real paths.
    let sandbox_abs = dep_rel && cfg!(target_os = "linux") && !is_self_tool(drv);
    let abs_stage: PathBuf = if sandbox_abs {
        Path::new(crate::exec::sandbox::SANDBOX_BUILD).join("stage")
    } else {
        stage.to_path_buf()
    };
    if out.contains("{srcroot}") {
        out = out.replace("{srcroot}", &srcroot.to_string_lossy());
    }
    if out.contains("{srcroot-abs}") {
        out = out.replace("{srcroot-abs}", &abs_stage.to_string_lossy());
    }
    if out.contains("{out}") {
        out = out.replace("{out}", &out_dir.to_string_lossy());
    }
    if out.contains("{artifacts}") {
        out = out.replace(
            "{artifacts}",
            &out_dir.with_file_name(ARTIFACTS_DIR).to_string_lossy(),
        );
    }
    if out.contains("{out-abs}") {
        let out_abs = if sandbox_abs {
            Path::new(crate::exec::sandbox::SANDBOX_BUILD).join("out")
        } else if out_dir.is_absolute() {
            out_dir.to_path_buf()
        } else {
            stage
                .parent()
                .map(|build_dir| build_dir.join("out"))
                .unwrap_or_else(|| out_dir.to_path_buf())
        };
        out = out.replace("{out-abs}", &out_abs.to_string_lossy());
    }
    if out.contains("{buildroot-abs}") {
        let buildroot = if sandbox_abs {
            PathBuf::from(crate::exec::sandbox::SANDBOX_BUILD)
        } else {
            stage
                .parent()
                .ok_or_else(|| format!("stage has no build root: {}", stage.display()))?
                .to_path_buf()
        };
        out = out.replace("{buildroot-abs}", &buildroot.to_string_lossy());
    }
    // The derivation's own identity names no location, so no grade
    // virtualizes it.
    if out.contains("{self-hash}") {
        out = out.replace("{self-hash}", drv.name_hash());
    }
    while let Some(start) = out.find("{dep-abs:") {
        let end = out[start..]
            .find('}')
            .map(|i| start + i)
            .ok_or_else(|| format!("unterminated {{dep-abs:*}} in `{}`", arg))?;
        let name = out[start + "{dep-abs:".len()..end].to_string();
        drv.deps
            .iter()
            .find(|d| d.name == name)
            .ok_or_else(|| format!("`{}` references undeclared dep `{}`", drv.name, name))?;
        let repl = abs_stage
            .join("dep")
            .join(&name)
            .to_string_lossy()
            .into_owned();
        out = format!("{}{}{}", &out[..start], repl, &out[end + 1..]);
    }
    while let Some(start) = out.find("{dep:") {
        let end = out[start..]
            .find('}')
            .map(|i| start + i)
            .ok_or_else(|| format!("unterminated {{dep:*}} in `{}`", arg))?;
        let name = out[start + "{dep:".len()..end].to_string();
        drv.deps
            .iter()
            .find(|d| d.name == name)
            .ok_or_else(|| format!("`{}` references undeclared dep `{}`", drv.name, name))?;
        let repl = if dep_rel {
            format!("../dep/{}", name)
        } else {
            stage.join("dep").join(&name).to_string_lossy().into_owned()
        };
        out = format!("{}{}{}", &out[..start], repl, &out[end + 1..]);
    }
    Ok(out)
}

/// Expand `{tool-version:NAME}` against the staged toolbin: run the staged
/// tool's version query and splice its first line. Eval leaves the token
/// symbolic for store tools (their binaries exist only once the provider is
/// realized; the provider's dep digest already carries the identity), so
/// the version string is an exec-phase resolution like every other token.
pub(super) fn expand_tool_versions(
    arg: String,
    toolbin: &Path,
    flags: &[(String, String)],
    cache: &RefCell<BTreeMap<String, String>>,
) -> Result<String, String> {
    let mut out = arg;
    while let Some(start) = out.find("{tool-version:") {
        let end = out[start..]
            .find('}')
            .map(|i| start + i)
            .ok_or_else(|| format!("unterminated {{tool-version:*}} in `{}`", out))?;
        let tool = out[start + "{tool-version:".len()..end].to_string();
        let mut cache = cache.borrow_mut();
        let version = match cache.get(&tool) {
            Some(v) => v.clone(),
            None => {
                let path = toolbin.join(&tool);
                let query = flags
                    .iter()
                    .find(|(name, _)| *name == tool)
                    .map(|(_, flag)| flag.as_str())
                    .unwrap_or("--version");
                let run = crate::invocation::command(&path).arg(query).output();
                let line = match run {
                    Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                    _ => {
                        return Err(format!(
                            "cannot query `{} {}` for {{tool-version:{}}} (is the tool staged?)",
                            path.display(),
                            query,
                            tool
                        ));
                    }
                };
                cache.insert(tool.clone(), line.clone());
                line
            }
        };
        out = format!("{}{}{}", &out[..start], version, &out[end + 1..]);
    }
    Ok(out)
}

/// The fixed-output fetch script: download, verify happens in Rust after
/// the run (fetch is the only networked builder). The output path is computed FROM THE
/// CWD (`stage/build` → `../../out`) at script start: the script must work
/// at both grades, and under the namespace sandbox the build dir lives at
/// the constant `/build`, not its hash-named host path.
pub(super) fn fetch_script(dspec: &DrvSpec) -> Result<String, String> {
    let url = dspec
        .argv
        .first()
        .ok_or_else(|| format!("fetch `{}` has no URL", dspec.name))?;
    Ok(fetch_script_url(url))
}

pub(crate) fn fetch_script_url(url: &str) -> String {
    // TLS trust anchors reach the build through the stage environment's
    // mounts; transport trust is advisory anyway — the declared sha256 is
    // the real gate.
    let mut s = String::from("set -eu\numask 022\nout=\"$(cd ../../out && pwd)\"\n");
    s.push_str(&format!(
        "curl -fL --retry 3 -o \"$out/source.tar\" '{}'\n",
        url.replace('\'', "'\\''")
    ));
    s
}

/// Symlink one builder tool into the private toolbin and return its real
/// path. An external tool comes from the eval-resolved host path; a store
/// tool resolves from its toolchain derivation's provider
/// dir, located by the dep edge the tool contributed at eval.
pub(super) fn stage_tool(
    tool: &str,
    drv: &Derivation,
    store: &Store,
    toolbin: &Path,
) -> Result<PathBuf, String> {
    // A store tool: the eval pass recorded its provider as a
    // `store:<drv>:<relpath>` marker in the recipe's tools. Parse it to locate
    // the provider dir via the dependency edge the marker created.
    let marker = drv
        .tools
        .iter()
        .find(|(t, _)| t == tool)
        .map(|(_, v)| v.as_str());
    if let Some(real) = marker.map(host_tool_path).transpose()?.flatten() {
        crate::exec::stage::symlink_into(&real, &toolbin.join(tool))?;
        return Ok(real);
    }
    let Some((drv_name, relpath)) = marker
        .and_then(|m| m.strip_prefix("store:"))
        .and_then(|rest| rest.split_once(':'))
    else {
        return Err(format!("tool `{}` was not resolved at eval time", tool));
    };
    let dep = drv
        .deps
        .iter()
        .find(|d| d.name == drv_name)
        .ok_or_else(|| {
            format!(
                "store tool `{}` needs dependency `{}`, which is not present",
                tool, drv_name
            )
        })?;
    let real = store.root.join(&dep.store_name).join(relpath);
    crate::exec::stage::symlink_into(&real, &toolbin.join(tool))?;
    Ok(real)
}

/// The tool-marker prefix of an ambient tool, which only the self-tool class
/// names.
const AMBIENT_MARKER: &str = "host-sha256:";

/// Whether `drv` belongs to the self-tool class, which runs at audit grade:
/// an ambient tool marks it, as it marks the plan node.
fn is_self_tool(drv: &Derivation) -> bool {
    drv.tools
        .iter()
        .any(|(_, marker)| marker.starts_with(AMBIENT_MARKER))
}

fn host_tool_path(marker: &str) -> Result<Option<PathBuf>, String> {
    let Some(rest) = marker.strip_prefix(AMBIENT_MARKER) else {
        return Ok(None);
    };
    let Some((identity, path)) = rest.split_once(':') else {
        return Err("ambient tool marker lacks its identity/path separator".to_string());
    };
    if identity.is_empty() || path.is_empty() {
        return Err("ambient tool marker has an empty identity or path".to_string());
    }
    Ok(Some(PathBuf::from(path)))
}

/// Return every ambient executable declared by this derivation. On Linux a
/// self-tool's PATH gains the directories these tools run their helpers
/// from; any other derivation naming one is refused.
#[cfg(target_os = "linux")]
pub(super) fn ambient_tools(drv: &Derivation) -> Result<Vec<(String, PathBuf)>, String> {
    let mut tools = Vec::new();
    for (tool, marker) in &drv.tools {
        if let Some(path) = host_tool_path(marker)
            .map_err(|e| format!("invalid provider for ambient tool `{tool}`: {e}"))?
        {
            tools.push((tool.clone(), path));
        }
    }
    tools.sort();
    tools.dedup();
    Ok(tools)
}

#[cfg(test)]
mod tests {
    use super::{host_tool_path, resolve_exec_tokens};
    use crate::spec::RefPolicy;
    use crate::store::derivation::{Derivation, DrvParts};
    use std::path::{Path, PathBuf};

    #[test]
    fn self_hash_expands_to_the_store_name_hash_at_every_grade() {
        let drv = Derivation::seal(DrvParts {
            name: "signed-image".to_string(),
            arch: "x86_64".to_string(),
            builder: "script-dag".to_string(),
            tools: vec![],
            env: vec![],
            srcs: vec![],
            srcdirs: vec![],
            source_roots: vec![],
            source_overlays: vec![],
            copy: vec![],
            stage_deps: vec![],
            allowed_refs: RefPolicy::None,
            deps: vec![],
            config: vec![],
            module_config: None,
            argv: vec!["sign".to_string(), "{self-hash}".to_string()],
            plan: vec![],
            outputs: vec![],
        });
        // The identity is computed over the token itself, never its value.
        assert!(drv.preimage().contains("argv: {self-hash}\n"));
        let store_name = drv.store_name();
        let (hash, _) = store_name.split_once('-').unwrap();
        assert_eq!(hash.len(), 32);
        assert!(hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(drv.name_hash(), hash);
        // Builder-facing and host-side expansion alike; on Linux the first
        // takes the namespace sandbox's path branch.
        for dep_rel in [true, false] {
            let resolved = resolve_exec_tokens(
                "{self-hash} {out}/manifest.{self-hash}",
                Path::new(".."),
                Path::new("../../out"),
                Path::new("/tmp/buildutil-build/stage"),
                &drv,
                dep_rel,
            )
            .unwrap();
            assert_eq!(resolved, format!("{hash} ../../out/manifest.{hash}"));
        }
    }

    #[test]
    fn ambient_marker_parser_preserves_colons_in_tool_paths() {
        assert_eq!(
            host_tool_path("host-sha256:identity:C:\\toolchain\\bin\\rustc.exe").unwrap(),
            Some(PathBuf::from("C:\\toolchain\\bin\\rustc.exe"))
        );
    }

    #[test]
    fn ambient_marker_parser_rejects_missing_identity_or_path() {
        assert!(host_tool_path("host-sha256::/usr/bin/rustc").is_err());
        assert!(host_tool_path("host-sha256:identity:").is_err());
    }
}
