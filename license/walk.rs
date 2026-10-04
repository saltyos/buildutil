// SPDX-License-Identifier: GPL-2.0-only
//! Walks the filtered repository source set for license checking.
//! This module owns path normalization, pruning and file I/O; header and texts handle content.

use super::rules::Rule;
use crate::source::SourceFilter;
use std::fs;
use std::path::{Path, PathBuf};

/// A source file and its normalized repository-relative path.
pub(crate) struct File {
    /// Path on the host filesystem.
    pub(crate) path: PathBuf,
    /// Slash-separated path for globs and diagnostics.
    pub(crate) rel: String,
}

/// Paths to inspect, with pruned subtrees counted as covered.
pub(crate) struct Walk {
    /// Files that require a rule decision.
    pub(crate) files: Vec<File>,
    /// Number of safely pruned subtrees.
    pub(crate) pruned: usize,
    /// Pruned directory and the single rule covering all its files.
    pub(crate) pruned_rules: Vec<(String, usize)>,
}

/// Walk the same filtered filesystem namespace used by buildutil sources.
#[cfg(test)]
pub(crate) fn collect(root: &Path, rules: &[Rule]) -> Result<Walk, String> {
    collect_with_roots(root, rules, &[])
}

/// Walk source and declared LICENSES trees even when a headerless rule prunes a parent.
pub(crate) fn collect_with_roots(
    root: &Path,
    rules: &[Rule],
    roots: &[String],
) -> Result<Walk, String> {
    let filter = SourceFilter::load_for_walk(root)?;
    let mut out = Walk {
        files: Vec::new(),
        pruned: 0,
        pruned_rules: Vec::new(),
    };
    visit(root, "", &filter, rules, roots, &mut out)?;
    out.files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn visit(
    dir: &Path,
    rel_dir: &str,
    filter: &SourceFilter,
    rules: &[Rule],
    roots: &[String],
    out: &mut Walk,
) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read entry in {}: {e}", dir.display()))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 path in {}", dir.display()))?;
        if name == ".git" {
            continue;
        }
        let rel = if rel_dir.is_empty() {
            name.to_owned()
        } else {
            format!("{rel_dir}/{name}")
        };
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if kind.is_symlink() || filter.excludes(&rel, kind.is_dir()) {
            continue;
        }
        if kind.is_dir() {
            // A nested repository is governed by its own filter, as for git.
            let nested_filter = filter.enter(&path, &rel)?;
            let filter = nested_filter.as_ref().unwrap_or(filter);
            let license_tree = roots.iter().any(|root| {
                let tree = if root.is_empty() {
                    "LICENSES".to_string()
                } else {
                    format!("{root}/LICENSES")
                };
                tree == rel
                    || tree.starts_with(&format!("{rel}/"))
                    || rel.starts_with(&format!("{tree}/"))
            });
            let nested_root = roots
                .iter()
                .any(|root| root.starts_with(&format!("{rel}/")));
            if let Some(rule_index) =
                prune_rule(&rel, rules).filter(|_| !license_tree && !nested_root)
            {
                out.pruned += 1;
                if contains_file(&path, &rel, filter)? {
                    out.pruned_rules.push((rel, rule_index));
                }
            } else {
                visit(&path, &rel, filter, rules, roots, out)?;
            }
        } else if kind.is_file() {
            out.files.push(File { path, rel });
        }
    }
    Ok(())
}

fn contains_file(dir: &Path, rel_dir: &str, filter: &SourceFilter) -> Result<bool, String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("cannot read entry in {}: {e}", dir.display()))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 path in {}", dir.display()))?;
        if name == ".git" {
            continue;
        }
        let rel = format!("{rel_dir}/{name}");
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", entry.path().display()))?;
        if kind.is_symlink() || filter.excludes(&rel, kind.is_dir()) {
            continue;
        }
        if kind.is_file() {
            return Ok(true);
        }
        if kind.is_dir() {
            let path = entry.path();
            let nested_filter = filter.enter(&path, &rel)?;
            if contains_file(&path, &rel, nested_filter.as_ref().unwrap_or(filter))? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn within(path: &str, dir: &str) -> bool {
    path == dir || path.starts_with(&format!("{dir}/"))
}

/// Return true only when a literal subtree exclusion cannot lose an earlier rule.
#[cfg(test)]
pub(crate) fn prune(dir: &str, rules: &[Rule]) -> bool {
    prune_rule(dir, rules).is_some()
}

fn prune_rule(dir: &str, rules: &[Rule]) -> Option<usize> {
    for (index, rule) in rules.iter().enumerate() {
        if rule.header {
            continue;
        }
        for pattern in &rule.paths {
            let Some(prefix) = pattern.strip_suffix("/**") else {
                continue;
            };
            if prefix.is_empty()
                || prefix.chars().any(|c| matches!(c, '*' | '?' | '[' | ']'))
                || !within(dir, prefix)
            {
                continue;
            }
            let earlier_can_match = rules[..index].iter().flat_map(|r| &r.paths).any(|p| {
                let literal = p
                    .split(|c| matches!(c, '*' | '?' | '['))
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('/');
                literal.is_empty() || literal.starts_with(dir) || dir.starts_with(literal)
            });
            if !earlier_can_match {
                return Some(index);
            }
        }
    }
    None
}
