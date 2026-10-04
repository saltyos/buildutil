// SPDX-License-Identifier: GPL-2.0-only
//! Runs repository license checking and optional repairs.
//! This module owns CLI reporting; rules parses policy, walk selects files, and header and texts check content.

mod header;
mod rules;
mod texts;
mod walk;

#[cfg(test)]
mod tests;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// A prepared replacement or creation based on inspected file bytes.
pub(crate) struct Edit {
    /// Repository-relative diagnostic path.
    pub(crate) rel: String,
    /// Host filesystem path.
    pub(crate) path: PathBuf,
    /// Inspected bytes, or none for a new file.
    pub(crate) before: Option<Vec<u8>>,
    /// Complete replacement bytes.
    pub(crate) after: Vec<u8>,
    /// Repair action printed after replacement.
    pub(crate) action: &'static str,
}

pub(crate) type Report = (&'static str, String, String);

fn conflict(edit: &Edit) -> Option<Report> {
    match (&edit.before, fs::symlink_metadata(&edit.path)) {
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
        (None, _) => Some((
            "conflict",
            edit.rel.clone(),
            "new file path now exists".into(),
        )),
        (Some(before), Ok(meta)) if meta.is_file() && !meta.file_type().is_symlink() => {
            match fs::read(&edit.path) {
                Ok(now) if now == *before => None,
                Ok(_) => Some((
                    "conflict",
                    edit.rel.clone(),
                    "file changed since inspection".into(),
                )),
                Err(error) => Some(("conflict", edit.rel.clone(), error.to_string())),
            }
        }
        (Some(_), _) => Some((
            "conflict",
            edit.rel.clone(),
            "file changed since inspection".into(),
        )),
    }
}

/// Apply `edits` together: each file is written beside itself and renamed
/// over it only after confirming it still holds the bytes inspected, so a
/// file changed meanwhile is reported and nothing is replaced.
pub(crate) fn apply_edits(edits: &[Edit]) -> (usize, Vec<Report>) {
    let problems: Vec<_> = edits.iter().filter_map(conflict).collect();
    if !problems.is_empty() {
        return (0, problems);
    }
    let mut staged = Vec::new();
    for edit in edits {
        let Some(parent) = edit.path.parent() else {
            for (_, path) in &staged {
                let _ = fs::remove_file(path);
            }
            return (
                0,
                vec![("write", edit.rel.clone(), "path has no parent".into())],
            );
        };
        if let Err(error) = fs::create_dir_all(parent) {
            for (_, path) in &staged {
                let _ = fs::remove_file(path);
            }
            return (0, vec![("write", edit.rel.clone(), error.to_string())]);
        }
        let temp = parent.join(format!(
            ".buildutil-edit-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(&edit.after)?;
            if edit.before.is_some() {
                file.set_permissions(fs::metadata(&edit.path)?.permissions())?;
            }
            file.sync_all()
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            for (_, path) in &staged {
                let _ = fs::remove_file(path);
            }
            return (0, vec![("write", edit.rel.clone(), error.to_string())]);
        }
        staged.push((edit, temp));
    }
    let problems: Vec<_> = edits.iter().filter_map(conflict).collect();
    if !problems.is_empty() {
        for (_, path) in &staged {
            let _ = fs::remove_file(path);
        }
        return (0, problems);
    }
    let mut rewritten = 0;
    for (edit, temp) in &staged {
        if let Some(problem) = conflict(edit) {
            for (_, path) in &staged {
                let _ = fs::remove_file(path);
            }
            return (rewritten, vec![problem]);
        }
        if let Err(error) = fs::rename(temp, &edit.path) {
            for (_, path) in &staged {
                let _ = fs::remove_file(path);
            }
            return (
                rewritten,
                vec![("write", edit.rel.clone(), error.to_string())],
            );
        }
        out!("{} {}", edit.action, edit.rel);
        rewritten += 1;
    }
    (rewritten, Vec::new())
}

/// Check or fix licenses under the selected repository root.
pub(crate) fn run(
    args: &[String],
    arch: &str,
    state_root: &Path,
    build: impl Fn(&[String]) -> Result<i32, String>,
) -> Result<i32, String> {
    let mut fix = false;
    let mut root = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fix" if !fix => fix = true,
            "--root" if root.is_none() => {
                i += 1;
                root = Some(PathBuf::from(
                    args.get(i)
                        .ok_or("check license: --root needs a directory")?,
                ));
            }
            other => {
                return Err(format!(
                    "check license: unknown or repeated argument `{other}`"
                ));
            }
        }
        i += 1;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let cwd = crate::invocation::request_cwd()
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|e| format!("cannot determine repository root: {e}"))?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine repository root: {e}"))?;
    let root = match root {
        Some(root) if root.is_absolute() => root,
        Some(root) => cwd.join(root),
        None => crate::cmd::repo_root_from(&cwd)?,
    };
    let policy = rules::load_policy(&root)?;
    let mut load = || {
        let derivation = policy
            .corpus
            .as_ref()
            .ok_or("[license].corpus is required for SPDX text checking")?;
        // The corpus is a fixed-output input, not an exposed package.
        let args = vec![
            format!("{}{derivation}", crate::spec::kinds::DRV_PREFIX),
            "--arch".into(),
            arch.into(),
            "--store".into(),
            state_root.display().to_string(),
        ];
        let code = build(&args)?;
        if code != 0 {
            return Err(format!(
                "license corpus `{derivation}` realization failed with exit code {code}"
            ));
        }
        let absolute = crate::state::absolute_root(&root, state_root);
        let archive = absolute
            .join("roots")
            .join(format!("latest-{derivation}-{arch}"))
            .join("source.tar");
        texts::corpus(&archive)
    };
    check_with_corpus(&root, fix, &mut load)
}

#[cfg(test)]
fn check(root: &Path, fix: bool) -> Result<i32, String> {
    check_with_corpus(root, fix, &mut || Err("test corpus unavailable".into()))
}

fn check_with_corpus(
    root: &Path,
    fix: bool,
    load_corpus: &mut impl FnMut() -> Result<std::collections::BTreeMap<String, Vec<u8>>, String>,
) -> Result<i32, String> {
    let policy = rules::load_policy(root)?;
    let walk = walk::collect_with_roots(root, &policy.rules, &policy.roots)?;
    let mut covered = 0usize;
    let mut edits = Vec::new();
    let mut problems: Vec<Report> = Vec::new();
    for file in &walk.files {
        if rules::is_text_path(&policy.roots, &file.rel) {
            covered += 1;
            continue;
        }
        let Some(rule) = rules::select(&policy.rules, &file.rel) else {
            problems.push((
                "uncovered",
                file.rel.clone(),
                "no license rule matches".into(),
            ));
            continue;
        };
        covered += 1;
        if !rule.header {
            continue;
        }
        let bytes = match fs::read(&file.path) {
            Ok(bytes) => bytes,
            Err(e) => {
                problems.push(("read", file.rel.clone(), e.to_string()));
                continue;
            }
        };
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(e) => {
                problems.push(("encoding", file.rel.clone(), format!("invalid UTF-8: {e}")));
                continue;
            }
        };
        let inspection = match header::inspect(&file.rel, text, rule, fix) {
            Ok(result) => result,
            Err(e) => {
                problems.push(("syntax", file.rel.clone(), e));
                continue;
            }
        };
        if let Some(repaired) = inspection.repaired {
            if fix {
                edits.push(Edit {
                    rel: file.rel.clone(),
                    path: file.path.clone(),
                    before: Some(bytes),
                    after: repaired.into_bytes(),
                    action: inspection.action.unwrap_or("rewrite"),
                });
            }
        } else {
            for problem in inspection.problems {
                problems.push((problem.kind, file.rel.clone(), problem.detail));
            }
        }
    }
    let text_result = texts::check(root, &policy, &walk, fix, load_corpus)?;
    for problem in text_result.problems {
        problems.push((problem.kind, problem.path, problem.detail));
    }
    edits.extend(text_result.edits);
    let (rewritten, write_problems) = if fix && problems.is_empty() {
        apply_edits(&edits)
    } else {
        (0, Vec::new())
    };
    problems.extend(write_problems);
    for (kind, path, detail) in &problems {
        crate::log::error("license", &format!("{path}: {kind}: {detail}"));
    }
    out!(
        "license: covered={covered} pruned={} rewritten={rewritten} problems={}",
        walk.pruned,
        problems.len()
    );
    Ok(if problems.is_empty() { 0 } else { 1 })
}
