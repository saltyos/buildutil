// SPDX-License-Identifier: GPL-2.0-only
//! Shared source-input capture and bootstrap policy for both engine entry points.

pub(crate) mod bootstrap;
pub(crate) mod codec;
pub(crate) mod content;

use std::path::Path;
/// The selected tree is an ordinary dependency output, captured before execution.
pub(crate) fn source_derivation(name: &str, content: &str) -> Result<crate::spec::DrvSpec, String> {
    let hash = content
        .strip_prefix("tree:")
        .filter(|hash| codec::hex(hash, 64))
        .ok_or("source input has a malformed content address")?;
    let mut spec = crate::spec::DrvSpec::new(name, "source-tree", "");
    spec.env = vec![("BUILDUTIL_INPUT_TREE".into(), hash.to_string())];
    spec.outputs = vec!["source/".into()];
    Ok(spec)
}

/// An owner's source declarations cannot read a separately declared repository.
pub(crate) fn validate_source(owner: &Path, relative: &str) -> Result<Vec<String>, String> {
    let owner = owner
        .canonicalize()
        .map_err(|e| format!("cannot resolve source owner: {e}"))?;
    let path = owner.join(relative);
    let resolved = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve declared source {}: {e}", path.display()))?;
    if !resolved.starts_with(&owner) {
        return Err(format!(
            "declared source `{relative}` escapes its repository"
        ));
    }
    let doc = crate::input_toml::parse_file(&owner.join("buildutil.toml"))?;
    let declarations = codec::declarations(&doc)?;
    let mut excluded = Vec::new();
    for (name, input) in declarations {
        let Some(checkout) = input.path else {
            continue;
        };
        let child = owner.join(&checkout);
        let child = child.canonicalize().unwrap_or(child);
        if resolved.starts_with(&child) {
            return Err(format!(
                "source `{relative}` enters input `{name}`; consume its declared published output through {{dep:<name>}}"
            ));
        }
        if let Ok(hole) = child.strip_prefix(&resolved) {
            if !hole.as_os_str().is_empty() {
                excluded.push(hole.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut ancestor = resolved.clone();
    while ancestor != owner {
        if ancestor.join(".git").exists() {
            return Err(format!(
                "source `{relative}` enters another repository without a published input output"
            ));
        }
        if !ancestor.pop() {
            break;
        }
    }
    if resolved.is_dir() {
        let filter = crate::source::SourceFilter::load_for_owned_walk(&owner, &resolved)?;
        validate_tree_links(&owner, &resolved, &resolved, &filter, &excluded)?;
    }
    Ok(excluded)
}

fn validate_tree_links(
    owner: &Path,
    root: &Path,
    dir: &Path,
    filter: &crate::source::SourceFilter,
    excluded: &[String],
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("cannot inspect source tree: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("source path is not UTF-8")?
            .replace('\\', "/");
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if filter.excludes(&relative, meta.is_dir())
            || excluded
                .iter()
                .any(|hole| relative == *hole || relative.starts_with(&format!("{hole}/")))
        {
            continue;
        }
        if meta.is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| e.to_string())?;
            content::confined_link(owner, &path, &target)?;
            if let Ok(resolved) = path.canonicalize() {
                let mut ancestor = resolved.clone();
                while ancestor != owner {
                    if ancestor.join(".git").exists() {
                        return Err(format!(
                            "source symlink {} enters another repository",
                            path.display()
                        ));
                    }
                    if !ancestor.pop() {
                        break;
                    }
                }
                let doc = crate::input_toml::parse_file(&owner.join("buildutil.toml"))?;
                for (name, input) in codec::declarations(&doc)? {
                    if input
                        .path
                        .as_ref()
                        .is_some_and(|relative| resolved.starts_with(owner.join(relative)))
                    {
                        return Err(format!(
                            "source symlink {} enters input `{name}`",
                            path.display()
                        ));
                    }
                }
            }
        } else if meta.is_dir() && std::fs::symlink_metadata(path.join(".git")).is_err() {
            validate_tree_links(owner, root, &path, filter, excluded)?;
        }
    }
    Ok(())
}

/// Strictly compare only the bootstrap inputs selected by the root declaration.
pub(crate) fn verify_bootstrap(root: &Path) -> Result<String, String> {
    bootstrap::verify(root)
}
