//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage: file hashing

use std::io::Read;
use std::path::Path;

use crate::crypto::sha256::{Sha256, hash_bytes};

/// Persistent repo-relative-path → sha256 cache for source files, stored
/// at `<state>/cache/stat-cache.v1` as a binary `FLKSTAT1` file with a
/// sha256 trailer. An optimization only, never an identity source. The
/// store registry folds the toolchain derivations into every consumer's
/// closure, so eval hashes the multi-gigabyte LLVM/rust submodules; with
/// the cache a stat-identical tree costs stats, not reads. Inactive (`None`)
/// until `load_file_cache` runs — unit tests and one-shot subcommands hash
/// directly.

pub fn hash_file(path: &Path) -> Result<String, String> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let metadata = std::fs::metadata(&canonical)
        .map_err(|e| format!("cannot stat {}: {}", canonical.display(), e))?;
    let snapshot = super::statcache::file_snapshot(&metadata)
        .ok_or_else(|| format!("source is not a file: {}", canonical.display()))?;
    hash_file_with_snapshot(&canonical, &snapshot)
}

pub(crate) fn hash_file_with_snapshot(
    path: &Path,
    snapshot: &super::statcache::FileSnapshot,
) -> Result<String, String> {
    let cache_token = super::statcache::file_cache_key_for_canonical(path, snapshot);
    if let Some(hit) = cache_token
        .as_ref()
        .and_then(super::statcache::cached_file_hash_for_key)
    {
        if super::statcache::cache_token_still_matches(
            cache_token.as_ref().expect("cache hit has token"),
        ) {
            return Ok(hit);
        }
        return Err(format!("source changed while hashing {}", path.display()));
    }
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let digest = h.finalize_hex();
    let stable = match cache_token {
        Some(token) => super::statcache::record_file_hash_for_key(token, &digest),
        None => super::statcache::snapshot_still_matches(path, snapshot),
    };
    if stable {
        Ok(digest)
    } else {
        Err(format!("source changed while hashing {}", path.display()))
    }
}

/// One manifest line per entry, sorted by relative path:
/// `<sha256>  <kind> <rel-path>` where kind is `f` (file), `x` (file with
/// any exec bit), or `l` (symlink; the target string is hashed as content).
#[cfg(test)]
pub fn dir_manifest(root: &Path) -> Result<String, String> {
    let mut entries: Vec<(String, String, char)> = Vec::new();
    walk(root, root, &mut entries)?;
    entries.sort();
    let mut out = String::new();
    for (rel, hash, kind) in entries {
        out.push_str(&hash);
        out.push_str("  ");
        out.push(kind);
        out.push(' ');
        out.push_str(&rel);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
pub fn hash_dir(root: &Path) -> Result<String, String> {
    Ok(hash_bytes(dir_manifest(root)?.as_bytes()))
}

/// Canonical manifest of a store OUTPUT tree, one line per entry sorted by
/// relative path: `<sha256> <kind> <octal-mode> <rel-path>` where kind is
/// `f` (regular file), `l` (symlink; the target string is the hashed
/// content and the mode is 777), or `d` (empty directory; content hash of
/// the empty string). Unlike `dir_manifest` (source trees, git-faithful:
/// exec bit only), output trees carry full `mode & 0o7777` — builders run
/// under a fixed umask, so modes are deterministic and install semantics
/// depend on them. Non-UTF-8 names and special files (fifo, socket,
/// device) are rejected: they cannot be represented in the store.
pub fn tree_manifest(root: &Path) -> Result<String, String> {
    build_tree_manifest(root, false)
}

pub fn hash_tree(root: &Path) -> Result<String, String> {
    Ok(hash_bytes(tree_manifest(root)?.as_bytes()))
}

/// Like `tree_manifest`, but records a `d` entry for EVERY directory
/// (including non-empty ones), not just empty ones — a seed-import archive's
/// directory modes (e.g. `bin/` at 0755) matter for a bootstrap primitive's
/// output pin the way `tree_manifest`'s empty-dir-only convention (for
/// source trees, where non-empty dir modes carry no information) does not.
/// Kept as a separate function so `tree_manifest`/`hash_tree` stay
/// byte-for-byte unchanged.
pub fn tree_manifest_with_dir_modes(root: &Path) -> Result<String, String> {
    build_tree_manifest(root, true)
}

pub fn hash_tree_with_dir_modes(root: &Path) -> Result<String, String> {
    Ok(hash_bytes(tree_manifest_with_dir_modes(root)?.as_bytes()))
}

fn build_tree_manifest(root: &Path, all_dirs: bool) -> Result<String, String> {
    let mut entries: Vec<(String, String, char, u32)> = Vec::new();
    tree_walk(root, root, all_dirs, &mut entries)?;
    entries.sort();
    let mut out = String::new();
    for (rel, hash, kind, mode) in entries {
        out.push_str(&format!("{} {} {:04o} {}\n", hash, kind, mode, rel));
    }
    Ok(out)
}

fn utf8_rel(path: &Path, root: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|e| format!("strip_prefix {}: {}", path.display(), e))?;
    match rel.to_str() {
        Some(s) => Ok(s.to_string()),
        None => Err(format!("non-UTF-8 path in output tree: {}", path.display())),
    }
}

fn tree_walk(
    root: &Path,
    dir: &Path,
    all_dirs: bool,
    out: &mut Vec<(String, String, char, u32)>,
) -> Result<(), String> {
    let rd =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read dir {}: {}", dir.display(), e))?;
    let mut saw_entry = false;
    for entry in rd {
        saw_entry = true;
        let entry = entry.map_err(|e| format!("read_dir entry in {}: {}", dir.display(), e))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("stat {}: {}", path.display(), e))?;
        let rel = utf8_rel(&path, root)?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = std::fs::read_link(&path)
                .map_err(|e| format!("readlink {}: {}", path.display(), e))?;
            let target = target
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 symlink target at {}", path.display()))?;
            out.push((rel, hash_bytes(target.as_bytes()), 'l', 0o777));
        } else if ft.is_dir() {
            tree_walk(root, &path, all_dirs, out)?;
        } else if ft.is_file() {
            out.push((
                rel,
                hash_file(&path)?,
                'f',
                crate::platform::file_mode(&meta) & 0o7777,
            ));
        } else {
            return Err(format!("special file in output tree: {}", path.display()));
        }
    }
    if (all_dirs || !saw_entry) && dir != root {
        let rel = utf8_rel(dir, root)?;
        let meta =
            std::fs::symlink_metadata(dir).map_err(|e| format!("stat {}: {}", dir.display(), e))?;
        out.push((
            rel,
            hash_bytes(b""),
            'd',
            crate::platform::file_mode(&meta) & 0o7777,
        ));
    }
    Ok(())
}

#[cfg(test)]
fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String, char)>) -> Result<(), String> {
    let rd =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read dir {}: {}", dir.display(), e))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("read_dir entry in {}: {}", dir.display(), e))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("stat {}: {}", path.display(), e))?;
        let rel = path
            .strip_prefix(root)
            .map_err(|e| format!("strip_prefix {}: {}", path.display(), e))?
            .to_string_lossy()
            .into_owned();
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&path)
                .map_err(|e| format!("readlink {}: {}", path.display(), e))?;
            out.push((rel, hash_bytes(target.to_string_lossy().as_bytes()), 'l'));
        } else if meta.is_dir() {
            walk(root, &path, out)?;
        } else {
            let kind = {
                if crate::platform::file_mode(&meta) & 0o111 != 0 {
                    'x'
                } else {
                    'f'
                }
            };
            out.push((rel, hash_file(&path)?, kind));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{dir_manifest, hash_dir, tree_manifest, tree_manifest_with_dir_modes};

    #[test]
    fn tree_manifest_records_modes_symlinks_and_empty_dirs() {
        let dir = std::env::temp_dir().join(format!("buildutil-tree-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::create_dir_all(dir.join("var/empty")).unwrap();
        std::fs::write(dir.join("usr/bin/tool"), "#!/bin/sh\n").unwrap();
        crate::platform::set_mode(&dir.join("usr/bin/tool"), 0o755).unwrap();
        crate::platform::create_symlink_auto(
            std::path::Path::new("tool"),
            &dir.join("usr/bin/alias"),
        )
        .unwrap();
        crate::platform::set_mode(&dir.join("var/empty"), 0o755).unwrap();

        let manifest = tree_manifest(&dir).unwrap();
        let lines: Vec<&str> = manifest.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].ends_with(" l 0777 usr/bin/alias"), "{}", lines[0]);
        assert!(lines[1].ends_with(" f 0755 usr/bin/tool"), "{}", lines[1]);
        assert!(lines[2].ends_with(" d 0755 var/empty"), "{}", lines[2]);
        // Mode change alone changes the manifest.
        crate::platform::set_mode(&dir.join("usr/bin/tool"), 0o700).unwrap();
        assert_ne!(tree_manifest(&dir).unwrap(), manifest);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tree_manifest_with_dir_modes_records_non_empty_dirs_too() {
        let dir =
            std::env::temp_dir().join(format!(
                "buildutil-tree-dirmodes-test-{}",
                std::process::id()
            ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::create_dir_all(dir.join("var/empty")).unwrap();
        std::fs::write(dir.join("usr/bin/tool"), "#!/bin/sh\n").unwrap();
        // Pin every directory's mode explicitly — a builder's create_dir_all
        // default is umask-dependent, and this test asserts exact modes.
        for sub in ["usr", "usr/bin", "var", "var/empty"] {
            crate::platform::set_mode(&dir.join(sub), 0o755).unwrap();
        }

        // The empty-dir-only variant never mentions `usr` or `usr/bin` — only
        // the leaf empty dir and the file/symlink entries appear.
        let plain = tree_manifest(&dir).unwrap();
        assert!(!plain.contains(" usr\n") && !plain.contains(" usr/bin\n"));

        // The dir-mode-inclusive variant records every directory, non-empty
        // or not, with its mode.
        let with_modes = tree_manifest_with_dir_modes(&dir).unwrap();
        let lines: Vec<&str> = with_modes.lines().collect();
        assert_eq!(lines.len(), 5); // usr, usr/bin, usr/bin/tool, var, var/empty
        assert!(
            lines.iter().any(|l| l.ends_with(" d 0755 usr")),
            "{:?}",
            lines
        );
        assert!(
            lines.iter().any(|l| l.ends_with(" d 0755 usr/bin")),
            "{:?}",
            lines
        );
        assert!(
            lines.iter().any(|l| l.ends_with(" d 0755 var")),
            "{:?}",
            lines
        );
        assert!(
            lines.iter().any(|l| l.ends_with(" d 0755 var/empty")),
            "{:?}",
            lines
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_manifest_is_sorted_and_mode_aware() {
        let dir = std::env::temp_dir().join(format!("buildutil-hash-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("b.txt"), "b").unwrap();
        std::fs::write(dir.join("sub/a.txt"), "a").unwrap();
        std::fs::write(dir.join("tool"), "#!/bin/sh\n").unwrap();
        crate::platform::set_mode(&dir.join("tool"), 0o755).unwrap();
        crate::platform::create_symlink_auto(std::path::Path::new("b.txt"), &dir.join("ln"))
            .unwrap();

        let manifest = dir_manifest(&dir).unwrap();
        let lines: Vec<&str> = manifest.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].ends_with("f b.txt"));
        assert!(lines[1].ends_with("l ln"));
        assert!(lines[2].ends_with("f sub/a.txt"));
        assert!(lines[3].ends_with("x tool"));

        let h1 = hash_dir(&dir).unwrap();
        std::fs::write(dir.join("sub/a.txt"), "changed").unwrap();
        let h2 = hash_dir(&dir).unwrap();
        assert_ne!(h1, h2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
