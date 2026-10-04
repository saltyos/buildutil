//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage: tree-object manifest codec

use std::collections::BTreeMap;
use std::path::Path;

use super::{TreeEntry, TreeObject};

pub(super) fn manifest_entries(entries: &[TreeEntry]) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut out = String::new();
    for entry in sorted {
        out.push_str(&entry.hash);
        out.push_str("  ");
        out.push(entry.kind);
        out.push(' ');
        out.push_str(&entry.rel);
        out.push('\n');
    }
    out
}

pub(super) fn parse_tree_object(text: &str, expected_dirhash: &str) -> Result<TreeObject, String> {
    let mut lines = text.split_inclusive('\n');
    expect_line(lines.next(), super::TREE_OBJECT_HEADER)?;
    expect_line(lines.next(), "format: 1")?;
    expect_line(lines.next(), &format!("dir-hash: {expected_dirhash}"))?;
    expect_line(lines.next(), "entries:")?;
    let mut entries = Vec::new();
    let mut entries_block = String::new();
    loop {
        let Some(line) = lines.next() else {
            return Err("tree object lacks targets block".to_string());
        };
        let trimmed = line.trim_end_matches('\n');
        if trimmed == "targets:" {
            break;
        }
        entries_block.push_str(line);
        entries.push(parse_entry_line(trimmed)?);
    }
    let actual = crate::crypto::sha256::hash_bytes(entries_block.as_bytes());
    if actual != expected_dirhash {
        return Err(format!(
            "tree object dir-hash mismatch: expected {}, entries hash {}",
            expected_dirhash, actual
        ));
    }
    let mut targets = BTreeMap::new();
    for line in lines {
        let trimmed = line.trim_end_matches('\n');
        if trimmed.is_empty() {
            continue;
        }
        let (hash, target) = trimmed
            .split_once('=')
            .ok_or_else(|| format!("invalid target line `{trimmed}`"))?;
        reject_newline_target(target, hash)?;
        if crate::crypto::sha256::hash_bytes(target.as_bytes()) != hash {
            return Err(format!("symlink target hash mismatch for {hash}"));
        }
        targets.insert(hash.to_string(), target.to_string());
    }
    for entry in &entries {
        if entry.kind == 'l' {
            match targets.get(&entry.hash) {
                Some(target)
                    if crate::crypto::sha256::hash_bytes(target.as_bytes()) == entry.hash => {}
                _ => {
                    return Err(format!(
                        "tree object lacks verified target for {}",
                        entry.hash
                    ));
                }
            }
        }
    }
    Ok(TreeObject { entries, targets })
}

fn expect_line(line: Option<&str>, expected: &str) -> Result<(), String> {
    match line.map(|s| s.trim_end_matches('\n')) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("expected `{expected}`, got `{actual}`")),
        None => Err(format!("expected `{expected}`, got EOF")),
    }
}

fn parse_entry_line(line: &str) -> Result<TreeEntry, String> {
    let (hash, rest) = line
        .split_once("  ")
        .ok_or_else(|| format!("invalid tree entry `{line}`"))?;
    let mut chars = rest.chars();
    let kind = chars
        .next()
        .ok_or_else(|| format!("invalid tree entry `{line}`"))?;
    if !matches!(kind, 'f' | 'x' | 'l') || chars.next() != Some(' ') {
        return Err(format!("invalid tree entry kind in `{line}`"));
    }
    let rel = chars.as_str();
    if rel.is_empty() {
        return Err(format!("empty tree entry path in `{line}`"));
    }
    Ok(TreeEntry {
        rel: rel.to_string(),
        hash: hash.to_string(),
        kind,
    })
}

pub(super) fn read_symlink_target(path: &Path) -> Result<String, String> {
    let target =
        std::fs::read_link(path).map_err(|e| format!("readlink {}: {}", path.display(), e))?;
    let target = target.to_string_lossy().into_owned();
    reject_newline_target(&target, &path.display().to_string())?;
    Ok(target)
}

pub(super) fn reject_newline_target(target: &str, ctx: &str) -> Result<(), String> {
    if target.contains('\n') {
        return Err(format!("symlink target contains newline at {ctx}"));
    }
    Ok(())
}

pub(super) fn rel_path_string(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|e| format!("strip_prefix {}: {}", path.display(), e))?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(if rel.is_empty() { ".".to_string() } else { rel })
}

pub(super) fn join_rel(prefix: &str, rel: &str) -> String {
    if prefix.is_empty() {
        rel.to_string()
    } else {
        format!("{prefix}/{rel}")
    }
}
