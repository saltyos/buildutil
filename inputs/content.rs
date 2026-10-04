// SPDX-License-Identifier: GPL-2.0-only
//! Selected repository content using the source CAS manifest grammar.

use crate::input_filter::SourceFilter;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path};

/// Captured leaf identities and symlink targets; directories have no identity.
pub(crate) struct Tree {
    pub(crate) entries: Vec<(String, char, String)>,
    pub(crate) targets: BTreeMap<String, String>,
}

impl Tree {
    pub(crate) fn hash(&self) -> String {
        let mut manifest = String::new();
        for (rel, kind, hash) in &self.entries {
            manifest.push_str(&format!("{hash}  {kind} {rel}\n"));
        }
        crate::input_sha256::hash_bytes(manifest.as_bytes())
    }
}

/// Hash a file without caches and reject a change observed across its read.
pub(crate) fn file(path: &Path) -> Result<(String, char), String> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !before.is_file() {
        return Err(format!(
            "input source is not a regular file: {}",
            path.display()
        ));
    }
    let mut reader =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let opened = reader
        .metadata()
        .map_err(|e| format!("cannot stat opened {}: {e}", path.display()))?;
    if !same_file(&before, &opened) {
        return Err(format!("input changed while opening {}", path.display()));
    }
    let mut hasher = crate::input_sha256::Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let size = reader
            .read(&mut buffer)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    let after = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot recheck {}: {e}", path.display()))?;
    if !same_file(&before, &after) {
        return Err(format!("input changed while reading {}", path.display()));
    }
    Ok((hasher.finalize_hex(), kind(&before)))
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    let same = left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && kind(left) == kind(right);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && left.ino() == right.ino()
            && left.dev() == right.dev()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

fn kind(meta: &std::fs::Metadata) -> char {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 != 0 {
            return 'x';
        }
    }
    'f'
}

pub(crate) fn confined_link(root: &Path, path: &Path, target: &Path) -> Result<(), String> {
    let relative = path
        .parent()
        .ok_or("input symlink has no parent")?
        .strip_prefix(root)
        .map_err(|e| e.to_string())?;
    let mut depth = relative.components().count();
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            _ => {
                return Err(format!(
                    "input symlink escapes its repository: {}",
                    path.display()
                ));
            }
        }
    }
    if let Ok(actual) = std::fs::canonicalize(path) {
        if !actual.starts_with(root) {
            return Err(format!(
                "input symlink escapes its repository: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Select one repository under its own filter, excluding separately declared inputs.
/// The callback can ingest files in the same read that computes their digest.
pub(crate) fn capture_with(
    root: &Path,
    excluded: &[String],
    mut ingest: impl FnMut(&Path) -> Result<(String, char), String>,
) -> Result<Tree, String> {
    capture_with_filter(root, excluded, true, &mut ingest)
}

/// Capture an owner's subtree under the nearest filter within that repository.
pub(crate) fn capture_owned_with(
    root: &Path,
    excluded: &[String],
    mut ingest: impl FnMut(&Path) -> Result<(String, char), String>,
) -> Result<Tree, String> {
    capture_with_filter(root, excluded, false, &mut ingest)
}

fn capture_with_filter(
    root: &Path,
    excluded: &[String],
    independent: bool,
    ingest: &mut impl FnMut(&Path) -> Result<(String, char), String>,
) -> Result<Tree, String> {
    let root = root
        .canonicalize()
        .map_err(|e| format!("cannot open input {}: {e}", root.display()))?;
    let filter = if independent {
        SourceFilter::for_nested_repository(&root, "")?
    } else {
        SourceFilter::load_for_walk(&root)?
    };
    let mut tree = Tree {
        entries: Vec::new(),
        targets: BTreeMap::new(),
    };
    fn walk(
        root: &Path,
        dir: &Path,
        filter: &SourceFilter,
        excluded: &[String],
        tree: &mut Tree,
        ingest: &mut impl FnMut(&Path) -> Result<(String, char), String>,
    ) -> Result<(), String> {
        let mut entries = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot read input {}: {e}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("cannot list input {}: {e}", dir.display()))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or_else(|| format!("input path is not UTF-8: {}", path.display()))?
                .replace('\\', "/");
            if rel.chars().any(char::is_control) {
                return Err(format!("input path contains a control character: {rel:?}"));
            }
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("cannot stat input {}: {e}", path.display()))?;
            if filter.excludes(&rel, meta.is_dir())
                || excluded
                    .iter()
                    .any(|hole| rel == *hole || rel.starts_with(&format!("{hole}/")))
            {
                continue;
            }
            if meta.is_symlink() {
                let target = std::fs::read_link(&path)
                    .map_err(|e| format!("cannot read input symlink {}: {e}", path.display()))?;
                confined_link(root, &path, &target)?;
                let target = target
                    .to_str()
                    .ok_or("input symlink target is not UTF-8")?
                    .to_string();
                if target.contains('\n') {
                    return Err(format!("input symlink target contains newline at {rel}"));
                }
                let hash = crate::input_sha256::hash_bytes(target.as_bytes());
                tree.targets.insert(hash.clone(), target);
                tree.entries.push((rel, 'l', hash));
            } else if meta.is_dir() {
                if std::fs::symlink_metadata(path.join(".git")).is_ok() {
                    continue;
                }
                walk(root, &path, filter, excluded, tree, ingest)?;
            } else if meta.is_file() {
                let (hash, kind) = ingest(&path)?;
                tree.entries.push((rel, kind, hash));
            } else {
                return Err(format!("input contains a special file: {}", path.display()));
            }
        }
        Ok(())
    }
    walk(&root, &root, &filter, excluded, &mut tree, ingest)?;
    tree.entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(tree)
}

pub(crate) fn capture(root: &Path, excluded: &[String]) -> Result<Tree, String> {
    capture_with(root, excluded, file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_bytes_ignore_metadata_and_declared_child_repositories() {
        let root =
            std::env::temp_dir().join(format!("buildutil-input-content-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("child")).unwrap();
        std::fs::write(root.join(".git"), "gitdir: ignored").unwrap();
        std::fs::write(root.join("child/file"), "child").unwrap();
        std::fs::write(root.join("own"), "selected").unwrap();
        std::fs::write(root.join(".buildutilignore"), "scratch\n").unwrap();
        let first = capture(&root, &["child".into()]).unwrap().hash();
        std::fs::write(root.join("scratch"), "dirty but unselected").unwrap();
        std::fs::write(root.join(".git"), "different metadata").unwrap();
        assert_eq!(first, capture(&root, &["child".into()]).unwrap().hash());
        std::fs::write(root.join(".buildutilignore"), "# same selection\nscratch\n").unwrap();
        assert_eq!(first, capture(&root, &["child".into()]).unwrap().hash());
        std::fs::write(root.join("own"), "changed").unwrap();
        assert_ne!(first, capture(&root, &["child".into()]).unwrap().hash());
        std::fs::remove_dir_all(root).unwrap();
    }
}
