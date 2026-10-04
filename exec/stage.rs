//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — build-dir staging helpers (symlinks, source overlays, src trees)
//!
//! The stage tree is the only writable surface visible to a builder: sources
//! at their repo-relative paths, a private toolbin, and dep roots pointing
//! into the store. Each helper is local to one layout decision (a symlink,
//! an overlay, a tree from the source CAS) so callers in build.rs/pool.rs
//! compose them without owning the layout itself.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

pub(super) fn symlink_into(target: &Path, link: &Path) -> Result<(), String> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    // Idempotent: a persistent dev-mode build dir may already hold the link.
    let _ = std::fs::remove_file(link);
    crate::platform::create_symlink_auto(target, link).map_err(|e| {
        format!(
            "cannot link {} -> {}: {}",
            link.display(),
            target.display(),
            e
        )
    })
}

fn remove_existing_path(path: &Path) -> Result<(), String> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.is_dir() && !meta.file_type().is_symlink() {
            std::fs::remove_dir_all(path)
                .map_err(|e| format!("cannot remove {}: {}", path.display(), e))?;
        } else {
            std::fs::remove_file(path)
                .map_err(|e| format!("cannot remove {}: {}", path.display(), e))?;
        }
    }
    Ok(())
}

pub(super) fn materialize_source_overlay(
    src: &Path,
    dest: &Path,
    expected_dest_kind: Option<crate::source::SourceTreePathKind>,
) -> Result<(), String> {
    let source_kind = source_overlay_path_kind(src)?;
    if let Some(expected) = expected_dest_kind
        && source_kind != expected
    {
        return Err(format!(
            "source-overlay shape mismatch for {} -> {}: source is a {}, but destination is a {} in the source tree",
            src.display(),
            dest.display(),
            source_kind.description(),
            expected.description()
        ));
    }
    remove_existing_path(dest)?;
    materialize_source_overlay_entry(src, dest)
}

fn source_overlay_path_kind(path: &Path) -> Result<crate::source::SourceTreePathKind, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat source-overlay {}: {}", path.display(), e))?;
    if meta.is_dir() && !meta.file_type().is_symlink() {
        Ok(crate::source::SourceTreePathKind::Directory)
    } else if meta.is_file() || meta.file_type().is_symlink() {
        Ok(crate::source::SourceTreePathKind::Leaf)
    } else {
        Err(format!(
            "unsupported source-overlay input {}",
            path.display()
        ))
    }
}

fn materialize_source_overlay_entry(src: &Path, dest: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(src)
        .map_err(|e| format!("cannot stat source-overlay {}: {}", src.display(), e))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }

    if meta.is_dir() && !meta.file_type().is_symlink() {
        std::fs::create_dir_all(dest)
            .map_err(|e| format!("cannot create overlay dir {}: {}", dest.display(), e))?;
        let mut entries: Vec<_> = std::fs::read_dir(src)
            .map_err(|e| format!("cannot read overlay dir {}: {}", src.display(), e))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("overlay entry under {}: {}", src.display(), e))?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            materialize_source_overlay_entry(&entry.path(), &dest.join(entry.file_name()))?;
        }
        return Ok(());
    }

    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(src)
            .map_err(|e| format!("cannot read overlay symlink {}: {}", src.display(), e))?;
        crate::platform::create_symlink_auto(&target, dest).map_err(|e| {
            format!(
                "cannot link overlay symlink {} -> {}: {}",
                dest.display(),
                target.display(),
                e
            )
        })?;
        return Ok(());
    }

    if meta.is_file() {
        match std::fs::hard_link(src, dest) {
            Ok(()) => Ok(()),
            Err(_) => std::fs::copy(src, dest)
                .map(|_| ())
                .map_err(|e| format!("cannot copy overlay file {}: {}", src.display(), e)),
        }
    } else {
        Err(format!(
            "unsupported source-overlay input {}",
            src.display()
        ))
    }
}

pub(super) fn stage_local_symlink_target(stage: &Path, target: &Path, link: &Path) -> PathBuf {
    if !target.starts_with(stage) {
        return target.to_path_buf();
    }
    let Ok(target_rel) = target.strip_prefix(stage) else {
        return target.to_path_buf();
    };
    let Some(link_parent) = link.parent() else {
        return target.to_path_buf();
    };
    let Ok(parent_rel) = link_parent.strip_prefix(stage) else {
        return target.to_path_buf();
    };
    let mut rel = PathBuf::new();
    for component in parent_rel.components() {
        if matches!(component, Component::Normal(_)) {
            rel.push("..");
        }
    }
    rel.push(target_rel);
    rel
}

pub(super) fn symlink_stage_aware(target: &Path, link: &Path, stage: &Path) -> Result<(), String> {
    let target = stage_local_symlink_target(stage, target, link);
    symlink_into(&target, link)
}

pub(super) fn hardlink_or_copy(src: &Path, dst: &Path) -> Result<(), String> {
    remove_existing_path(dst)?;
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    match std::fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => std::fs::copy(src, dst)
            .map(|_| ())
            .map_err(|e| format!("cannot copy {} -> {}: {}", src.display(), dst.display(), e)),
    }
}

pub(super) fn stage_source_root(
    stage: &Path,
    root_rel: &str,
    dirhash: &str,
    overlay_dests: &[String],
) -> Result<BTreeMap<String, crate::source::SourceTreePathKind>, String> {
    let dst_root = stage.join(root_rel);
    remove_existing_path(&dst_root)?;

    let mut destinations_by_hole: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for dest in overlay_dests {
        let dest_path = Path::new(dest);
        let Ok(suffix) = dest_path.strip_prefix(Path::new(root_rel)) else {
            continue;
        };
        let mut components = Vec::new();
        for component in suffix.components() {
            let Component::Normal(component) = component else {
                return Err(format!(
                    "source-overlay destination `{dest}` is not a clean relative path"
                ));
            };
            components.push(
                component
                    .to_str()
                    .ok_or_else(|| format!("source-overlay destination `{dest}` is not UTF-8"))?,
            );
        }
        destinations_by_hole
            .entry(components.join("/"))
            .or_default()
            .push(dest.clone());
    }

    if destinations_by_hole.is_empty() {
        crate::source::materialize_tree(dirhash, &dst_root)?;
        return Ok(BTreeMap::new());
    }

    let holes: Vec<String> = destinations_by_hole
        .keys()
        .filter(|hole| !hole.is_empty())
        .cloned()
        .collect();
    // Tree objects contain canonical leaf entries rather than explicit
    // directories. Classify every exact hole before materialization so the
    // later overlay source can be checked against the original tree shape.
    let kinds = crate::source::classify_tree_paths(dirhash, &holes)?;
    let mut destination_kinds = BTreeMap::new();
    for (hole, kind) in holes.iter().zip(kinds) {
        if let Some(kind) = kind {
            for dest in &destinations_by_hole[hole] {
                destination_kinds.insert(dest.clone(), kind);
            }
        }
    }

    if let Some(root_destinations) = destinations_by_hole.get("") {
        for dest in root_destinations {
            destination_kinds.insert(dest.clone(), crate::source::SourceTreePathKind::Directory);
        }
        // Replacing the source root itself is a directory overlay. Leaving the
        // root absent avoids giving the CAS an empty-path hole sentinel.
        return Ok(destination_kinds);
    }

    crate::source::materialize_tree_with_holes(dirhash, &dst_root, &holes)?;
    Ok(destination_kinds)
}
