//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage: filter
//!
//! Parses `.buildutilignore` and answers which walk paths are excluded from the
//! source set. Rules are scoped like `.gitignore`: anchored and slash-bearing
//! patterns match from the directory holding the file, and a nested
//! repository is governed only by its own `.buildutilignore`. Walkers position a
//! filter with `load_for_walk` and switch it at nested repositories with
//! `enter`; the walks themselves live in mod.rs, worktree.rs and git.rs.

use std::path::Path;

pub(crate) const SOURCE_FILTER_FILE: &str = ".buildutilignore";

/// Repository-scoped source selection, shared with the independent bootstrap checker.
pub(crate) struct SourceFilter {
    rules: Vec<SourceFilterRule>,
    base: String,
    scope: String,
    pub(crate) hash: String,
}

struct SourceFilterRule {
    pattern: String,
    rooted: bool,
    dir_only: bool,
    has_slash: bool,
}

fn repository_root(path: &Path) -> bool {
    std::fs::symlink_metadata(path.join(".git")).is_ok()
}

/// The nearest repository root strictly above `dir`.
fn enclosing_repository(dir: &Path) -> Option<std::path::PathBuf> {
    let mut cur = dir.to_path_buf();
    while cur.pop() {
        if repository_root(&cur) {
            return Some(cur);
        }
    }
    None
}

/// Whether `dir`, a nested repository root, is a submodule the repository
/// enclosing it tracks in its `.gitmodules`: part of that repository's
/// source tree, not a separately declared input. Each submodule is its own
/// walk root; the walk of its superproject still stops at it.
pub(crate) fn tracked_submodule(dir: &Path) -> bool {
    let Some(parent) = enclosing_repository(dir) else {
        return false;
    };
    let rel = rel_below(&parent, dir);
    let Ok(text) = std::fs::read_to_string(parent.join(".gitmodules")) else {
        return false;
    };
    text.lines().any(|line| {
        line.trim()
            .strip_prefix("path")
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('='))
            .is_some_and(|value| value.trim() == rel)
    })
}

/// `/`-separated path of `desc` below `ancestor` ("" when they are equal).
fn rel_below(ancestor: &Path, desc: &Path) -> String {
    desc.strip_prefix(ancestor)
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

impl SourceFilter {
    /// The filter of the repository rooted at `repo_root`, positioned for a
    /// walk from that root.
    pub(crate) fn load(repo_root: &Path) -> Result<Self, String> {
        Self::load_file(repo_root, String::new(), String::new())
    }

    fn load_file(dir: &Path, base: String, scope: String) -> Result<Self, String> {
        let path = dir.join(SOURCE_FILTER_FILE);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        Self::parse(&text, SOURCE_FILTER_FILE, base, scope)
    }

    /// The filter governing a walk rooted at `root`: the nearest
    /// `.buildutilignore` at or above it inside the same repository. Reaching a
    /// repository root without one ends the search with no rules, so rules
    /// of an enclosing repository never apply inside a nested checkout.
    pub(crate) fn load_for_walk(root: &Path) -> Result<Self, String> {
        let mut walk_dir = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        if walk_dir.is_file() {
            walk_dir.pop();
        }
        let mut cur = walk_dir.clone();
        loop {
            let base = rel_below(&cur, &walk_dir);
            if cur.join(SOURCE_FILTER_FILE).is_file() {
                return Self::load_file(&cur, base, String::new());
            }
            if repository_root(&cur) || !cur.pop() {
                return Self::parse("", SOURCE_FILTER_FILE, base, String::new());
            }
        }
    }

    /// Position the nearest rules within an explicitly resolved owner. An
    /// immutable input view needs no Git metadata to establish its boundary.
    pub(crate) fn load_for_owned_walk(owner: &Path, root: &Path) -> Result<Self, String> {
        let owner = owner.canonicalize().map_err(|e| e.to_string())?;
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        if !root.starts_with(&owner) {
            return Err("source filter walk escapes its owner".into());
        }
        let mut current = root.clone();
        loop {
            let base = rel_below(&current, &root);
            if current.join(SOURCE_FILTER_FILE).is_file() {
                return Self::load_file(&current, base, String::new());
            }
            if current == owner || !current.pop() {
                return Self::parse("", SOURCE_FILTER_FILE, base, String::new());
            }
        }
    }

    /// The filter for directory `dir`, reached at walk-relative `rel`. A
    /// nested repository brings its own rules, or none, in place of this
    /// filter; any other directory stays under this filter (`None`).
    pub(crate) fn enter(&self, dir: &Path, rel: &str) -> Result<Option<Self>, String> {
        if !repository_root(dir) {
            return Ok(None);
        }
        Self::for_nested_repository(dir, rel).map(Some)
    }

    /// The filter of the repository checked out at `dir`, reached at
    /// walk-relative `rel`: its own `.buildutilignore`, or no rules.
    pub(crate) fn for_nested_repository(dir: &Path, rel: &str) -> Result<Self, String> {
        if dir.join(SOURCE_FILTER_FILE).is_file() {
            Self::load_file(dir, String::new(), rel.to_string())
        } else {
            Self::parse("", SOURCE_FILTER_FILE, String::new(), rel.to_string())
        }
    }

    fn parse(text: &str, name: &str, base: String, scope: String) -> Result<Self, String> {
        let mut rules = Vec::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('!') {
                return Err(format!(
                    "{}:{}: negated patterns are not supported in buildutil source filters",
                    name,
                    idx + 1
                ));
            }
            let rooted = line.starts_with('/');
            let without_root = line.strip_prefix('/').unwrap_or(line);
            let dir_only = without_root.ends_with('/');
            let pattern = without_root
                .trim_end_matches('/')
                .trim_start_matches("./")
                .to_string();
            if pattern.is_empty() {
                return Err(format!(
                    "{}:{}: empty buildutil source filter pattern",
                    name,
                    idx + 1
                ));
            }
            rules.push(SourceFilterRule {
                has_slash: pattern.contains('/'),
                pattern,
                rooted,
                dir_only,
            });
        }
        let hash = crate::input_sha256::hash_bytes(format!("{text}\0{base}\0{scope}").as_bytes());
        Ok(SourceFilter {
            rules,
            base,
            scope,
            hash,
        })
    }

    /// Whether walk-relative `rel` is outside the source set. Paths outside
    /// this filter's scope are not its to judge.
    pub(crate) fn excludes(&self, rel: &str, is_dir: bool) -> bool {
        // Git administrative state is never source content. In particular, an
        // initialized submodule normally exposes `.git` as a gitdir *file*,
        // while a standalone nested checkout exposes it as a directory. Treat
        // both shapes identically and do so independently of `.buildutilignore` so
        // the filesystem and object-db routes have the same namespace.
        if rel.split('/').any(|part| part == ".git") {
            return true;
        }
        let local = if self.scope.is_empty() {
            rel
        } else if let Some(rest) = rel
            .strip_prefix(self.scope.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
        {
            rest
        } else {
            return false;
        };
        if local.is_empty() || local == "." {
            return false;
        }
        let path = if self.base.is_empty() {
            local.to_string()
        } else {
            format!("{}/{local}", self.base)
        };
        if path == SOURCE_FILTER_FILE {
            return true;
        }
        self.rules
            .iter()
            .any(|rule| rule.matches(&path, local, is_dir))
    }

    pub(super) fn excludes_path_or_parent(&self, rel: &str, is_dir: bool) -> bool {
        let mut cur = String::new();
        let parts: Vec<_> = rel.split('/').collect();
        for (idx, part) in parts.iter().enumerate() {
            if !cur.is_empty() {
                cur.push('/');
            }
            cur.push_str(part);
            let final_part = idx + 1 == parts.len();
            if self.excludes(&cur, if final_part { is_dir } else { true }) {
                return true;
            }
        }
        false
    }
}

impl SourceFilterRule {
    /// `path` is relative to the filter's repository root; `local` is the
    /// part of it below the walk root.
    fn matches(&self, path: &str, local: &str, is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        if self.rooted || self.has_slash {
            return crate::glob::glob_match(&self.pattern, path);
        }
        let basename = local.rsplit('/').next().unwrap_or(local);
        if crate::glob::glob_match(&self.pattern, basename) {
            return true;
        }
        is_dir
            && local
                .split('/')
                .any(|part| crate::glob::glob_match(&self.pattern, part))
    }
}
