//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — FHS projection of store output trees
//!
//! Composes immutable store trees (the sysroot base, port stage trees)
//! into a fresh target tree: a private per-derivation sysroot for port
//! builds, or the rootfs staging tree for image assembly. Because every
//! source is an immutable store output, projection is always a one-shot
//! compose into an empty target — there is no incremental overlay state
//! to reconcile.
//!
//! Rules carried over from the sysroot overlay contract (docs/spec/ports.rst):
//! - one owner per path: a collision between two owners is a hard error;
//! - hardlink-first copy (same filesystem), byte copy as the fallback;
//! - `prefix=` rewrite for pkg-config metadata under `usr/lib/pkgconfig/`,
//!   multiarch `usr/lib/<tuple>/pkgconfig/`, and `usr/share/pkgconfig/` —
//!   ALWAYS as copy-then-rewrite, never
//!   through a hardlink, so the store original is never mutated;
//! - optional dev-file filter for runtime projections (headers, static
//!   archives, pkg-config metadata, man pages never reach the rootfs).

use crate::glob::glob_match;
use crate::manifest::{ComposeManifest, Filter};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn is_pc_file(rel: &str) -> bool {
    if !rel.ends_with(".pc") {
        return false;
    }
    rel.starts_with("usr/lib/pkgconfig/")
        || rel.starts_with("usr/share/pkgconfig/")
        || (rel.starts_with("usr/lib/")
            && rel
                .strip_prefix("usr/lib/")
                .is_some_and(|rest| rest.contains("/pkgconfig/")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    Directory,
    File,
    Symlink,
}

/// One projection target being composed; tracks path ownership across all
/// composed sources so collisions name both owners.
pub struct Projection {
    target: std::path::PathBuf,
    manifest: ComposeManifest,
    owners: BTreeMap<String, (String, NodeKind)>,
    /// (owner, rel) pairs actually placed, in compose order.
    placed: Vec<(String, String)>,
}

impl Projection {
    pub fn new(target: &Path, manifest: ComposeManifest) -> Result<Projection, String> {
        if matches!(fs::symlink_metadata(target), Ok(meta) if meta.file_type().is_symlink()) {
            return Err(format!(
                "projection target must not be a symlink: {}",
                target.display()
            ));
        }
        fs::create_dir_all(target)
            .map_err(|e| format!("cannot create {}: {}", target.display(), e))?;
        if fs::read_dir(target)
            .map_err(|e| format!("cannot inspect {}: {e}", target.display()))?
            .next()
            .is_some()
        {
            return Err(format!(
                "projection target must be empty: {}",
                target.display()
            ));
        }
        Ok(Projection {
            target: target.to_path_buf(),
            manifest,
            owners: BTreeMap::new(),
            placed: Vec::new(),
        })
    }

    /// Compose one immutable source tree under the given owner name.
    pub fn compose(&mut self, owner: &str, src_root: &Path) -> Result<usize, String> {
        if owner.is_empty()
            || owner == "."
            || owner == ".."
            || owner.contains('/')
            || owner.contains('\\')
        {
            return Err(format!(
                "projection owner is not a path-safe name: `{owner}`"
            ));
        }
        let mut nodes = Vec::new();
        walk_rel(src_root, src_root, &mut nodes)?;
        nodes.sort_by(|a, b| a.0.cmp(&b.0));
        nodes.retain(|(rel, _)| {
            self.manifest.filter != Filter::Runtime
                || !self
                    .manifest
                    .excludes
                    .iter()
                    .any(|pattern| glob_match(pattern, rel))
        });
        for (rel, kind) in &nodes {
            for (index, _) in rel.match_indices('/') {
                let ancestor = &rel[..index];
                if let Some((ancestor_owner, ancestor_kind)) = self.owners.get(ancestor) {
                    if *ancestor_kind != NodeKind::Directory {
                        return Err(format!(
                            "projection ancestor conflict: {rel} from {owner} descends through {ancestor} owned by {ancestor_owner} as {ancestor_kind:?}"
                        ));
                    }
                }
            }
            if let Some((previous, previous_kind)) = self.owners.get(rel) {
                if *kind != NodeKind::Directory || *previous_kind != NodeKind::Directory {
                    return Err(format!(
                        "projection conflict: {rel} owned by both {previous} and {owner} ({previous_kind:?} vs {kind:?})"
                    ));
                }
            }
            if *kind != NodeKind::Directory {
                let prefix = format!("{rel}/");
                if let Some((descendant, (previous, _))) =
                    self.owners.range(prefix.clone()..).next()
                {
                    if descendant.starts_with(&prefix) {
                        return Err(format!(
                            "projection ancestor conflict: {rel} from {owner} would replace ancestor of {descendant} owned by {previous}"
                        ));
                    }
                }
            }
        }
        let mut placed = 0usize;
        for (rel, kind) in nodes {
            let src = src_root.join(&rel);
            let dst = self.target.join(&rel);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
            }
            if kind == NodeKind::Symlink {
                let target = fs::read_link(&src)
                    .map_err(|e| format!("readlink {}: {}", src.display(), e))?;
                crate::platform::symlink(&target, &dst)
                    .map_err(|e| format!("cannot create symlink {}: {}", dst.display(), e))?;
            } else if kind == NodeKind::Directory {
                fs::create_dir_all(&dst)
                    .map_err(|e| format!("cannot create {}: {}", dst.display(), e))?;
            } else if is_pc_file(&rel) {
                // pkg-config metadata is rewritten for the projected view;
                // copy so the store original stays untouched.
                copy_file(&src, &dst)?;
                rewrite_pc_for_projection(&dst, &rel, &self.target)?;
            } else if fs::hard_link(&src, &dst).is_err() {
                copy_file(&src, &dst)?;
            }
            self.owners
                .entry(rel.clone())
                .or_insert_with(|| (owner.to_string(), kind));
            self.placed.push((owner.to_string(), rel));
            placed += 1;
        }
        Ok(placed)
    }

    /// Write per-owner provenance under `.port-provenance/` in the target
    /// (rootfs staging introspection; build sysroots skip this).
    pub fn write_provenance(&self) -> Result<(), String> {
        let dir = self.target.join(".port-provenance");
        self.ensure_generated_parent(".port-provenance", true)?;
        let mut by_owner: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (owner, rel) in &self.placed {
            by_owner.entry(owner).or_default().push(rel);
        }
        for (owner, rels) in by_owner {
            let mut body = String::from("# SaltyOS projection provenance\n");
            for rel in rels {
                body.push_str(rel);
                body.push('\n');
            }
            let path = dir.join(format!("{}.files", owner));
            fs::write(&path, body)
                .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        }
        Ok(())
    }

    /// Write a declarative setup hook for consumers of this projected host
    /// package view. This is buildutil's analogue of Nix stdenv setup hooks:
    /// build inputs advertise their include/lib/pkg-config search roots, and
    /// the realizer folds them into the build environment for direct consumers.
    pub fn write_setup_env(&self) -> Result<(), String> {
        let mut lines = String::from("# buildutil setup-env v1\n");
        for rel in pkg_config_dirs(&self.target)? {
            lines.push_str(&format!("append-path PKG_CONFIG_LIBDIR {rel}\n"));
        }
        if lines.contains("PKG_CONFIG_LIBDIR") {
            lines.push_str("set-path PKG_CONFIG_SYSROOT_DIR .\n");
        }
        if self.target.join("usr/include").is_dir() {
            lines.push_str("append-flag BUILDUTIL_CFLAGS_COMPILE -isystem usr/include\n");
        }
        for rel in multiarch_dirs(&self.target, "usr/include")? {
            lines.push_str(&format!(
                "append-flag BUILDUTIL_CFLAGS_COMPILE -isystem {rel}\n"
            ));
        }
        for rel in multiarch_dirs(&self.target, "usr/lib")? {
            lines.push_str(&format!("append-flag BUILDUTIL_LDFLAGS -L {rel}\n"));
        }
        if self.target.join("usr/lib").is_dir() {
            lines.push_str("append-flag BUILDUTIL_LDFLAGS -L usr/lib\n");
        }
        let path = self.target.join(&self.manifest.setup_env_path);
        if let Some(parent) = path.parent() {
            let rel = parent
                .strip_prefix(&self.target)
                .map_err(|e| format!("setup-env parent escaped projection target: {e}"))?;
            self.ensure_generated_parent(
                rel.to_str().ok_or("setup-env parent is not UTF-8")?,
                true,
            )?;
        }
        fs::write(&path, lines).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        Ok(())
    }

    pub fn finish(&self) -> Result<(), String> {
        if self.manifest.emit_provenance {
            self.write_provenance()?;
        }
        if self.manifest.emit_setup_env {
            self.write_setup_env()?;
        }
        Ok(())
    }

    fn ensure_generated_parent(&self, rel: &str, include_leaf: bool) -> Result<(), String> {
        let mut current = self.target.clone();
        let components: Vec<&str> = rel.split('/').filter(|part| !part.is_empty()).collect();
        let limit = if include_leaf {
            components.len()
        } else {
            components.len().saturating_sub(1)
        };
        let mut logical = String::new();
        for component in components.into_iter().take(limit) {
            if !logical.is_empty() {
                logical.push('/');
            }
            logical.push_str(component);
            if let Some((owner, kind)) = self.owners.get(&logical) {
                if *kind != NodeKind::Directory {
                    return Err(format!(
                        "projection generated path `{rel}` descends through `{logical}` owned by {owner} as {kind:?}"
                    ));
                }
            }
            current.push(component);
            if matches!(fs::symlink_metadata(&current), Ok(meta) if meta.file_type().is_symlink()) {
                return Err(format!(
                    "projection generated path `{rel}` descends through symlink {}",
                    current.display()
                ));
            }
            fs::create_dir_all(&current)
                .map_err(|e| format!("cannot create {}: {e}", current.display()))?;
        }
        Ok(())
    }
}

fn pkg_config_dirs(root: &Path) -> Result<Vec<String>, String> {
    let mut dirs = Vec::new();
    for rel in multiarch_dirs(root, "usr/lib")? {
        let pc = format!("{rel}/pkgconfig");
        if root.join(&pc).is_dir() {
            dirs.push(pc);
        }
    }
    for rel in ["usr/lib/pkgconfig", "usr/share/pkgconfig"] {
        if root.join(rel).is_dir() {
            dirs.push(rel.to_string());
        }
    }
    Ok(dirs)
}

fn multiarch_dirs(root: &Path, parent_rel: &str) -> Result<Vec<String>, String> {
    let parent = root.join(parent_rel);
    if !parent.is_dir() {
        return Ok(Vec::new());
    }
    let mut dirs = Vec::new();
    for entry in fs::read_dir(&parent).map_err(|e| format!("read {}: {}", parent.display(), e))? {
        let entry = entry.map_err(|e| format!("read_dir entry in {}: {}", parent.display(), e))?;
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains("-linux-gnu") {
                dirs.push(format!("{parent_rel}/{name}"));
            }
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn walk_rel(root: &Path, dir: &Path, out: &mut Vec<(String, NodeKind)>) -> Result<(), String> {
    let rd = fs::read_dir(dir).map_err(|e| format!("cannot read dir {}: {}", dir.display(), e))?;
    let mut saw = false;
    for entry in rd {
        saw = true;
        let entry = entry.map_err(|e| format!("read_dir entry in {}: {}", dir.display(), e))?;
        let path = entry.path();
        let meta =
            fs::symlink_metadata(&path).map_err(|e| format!("stat {}: {}", path.display(), e))?;
        if meta.is_dir() && !meta.file_type().is_symlink() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("strip_prefix {}: {}", path.display(), e))?
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 path: {}", path.display()))?
                .to_string();
            out.push((rel, NodeKind::Directory));
            walk_rel(root, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("strip_prefix {}: {}", path.display(), e))?
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 path: {}", path.display()))?
                .to_string();
            out.push((
                rel,
                if meta.file_type().is_symlink() {
                    NodeKind::Symlink
                } else {
                    NodeKind::File
                },
            ));
        }
    }
    let _ = saw;
    Ok(())
}

fn copy_file(src: &Path, dst: &Path) -> Result<(), String> {
    let tmp = dst.with_extension("projection-tmp");
    fs::copy(src, &tmp)
        .map_err(|e| format!("cannot copy {} -> {}: {}", src.display(), tmp.display(), e))?;
    fs::rename(&tmp, dst).map_err(|e| {
        format!(
            "cannot rename {} -> {}: {}",
            tmp.display(),
            dst.display(),
            e
        )
    })?;
    Ok(())
}

/// Rewrite `.pc` metadata so pkg-config resolves the projected tree through
/// PKG_CONFIG_SYSROOT_DIR. Multiarch package metadata in Debian-style sysroots
/// relies on the compiler implicitly searching `/usr/include/<tuple>`; a
/// projection is a private sysroot, so expose that path explicitly in Cflags.
fn rewrite_pc_for_projection(
    pc_path: &Path,
    rel: &str,
    projection_root: &Path,
) -> Result<(), String> {
    let content =
        fs::read_to_string(pc_path).map_err(|e| format!("read {}: {}", pc_path.display(), e))?;
    let mut out = String::with_capacity(content.len());
    let mut changed = false;
    let multiarch = pkgconfig_multiarch(rel)
        .filter(|triple| projection_root.join("usr/include").join(triple).is_dir());
    for line in content.lines() {
        if !changed {
            if let Some(rest) = line.strip_prefix("prefix=") {
                if rest != "/usr" {
                    out.push_str("prefix=/usr\n");
                    changed = true;
                    continue;
                }
            }
        }
        if let Some(triple) = multiarch {
            if line.starts_with("Cflags:") {
                let flag = format!("-I${{includedir}}/{}", triple);
                if !line.contains(&flag) {
                    out.push_str(line);
                    out.push(' ');
                    out.push_str(&flag);
                    out.push('\n');
                    changed = true;
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if changed {
        fs::write(pc_path, out).map_err(|e| format!("write {}: {}", pc_path.display(), e))?;
    }
    Ok(())
}

fn pkgconfig_multiarch(rel: &str) -> Option<&str> {
    let rest = rel.strip_prefix("usr/lib/")?;
    let (triple, _) = rest.split_once("/pkgconfig/")?;
    if triple.is_empty() || triple == "pkgconfig" {
        None
    } else {
        Some(triple)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(filter: &str, excludes: &[&str], setup: bool) -> ComposeManifest {
        let mut text = format!(
            "schema buildutil-compose-v1\nlayout fhs\nfilter {filter}\nsetup-env-path buildutil-support/setup-env\nemit-setup-env {}\nemit-provenance false\n",
            if setup { "true" } else { "false" }
        );
        for exclude in excludes {
            text.push_str(&format!("exclude {exclude}\n"));
        }
        ComposeManifest::parse(&text, "test manifest").unwrap()
    }

    #[test]
    fn glob_and_dev_filter() {
        assert!(glob_match("usr/share/man/", "usr/share/man/man1/x.1"));
        assert!(glob_match("usr/lib/*.la", "usr/lib/libx.la"));
        assert!(!glob_match("usr/lib/*.la", "usr/lib/sub/libx.la"));
        assert!(glob_match("usr/lib/**/*.a", "usr/lib/sub/libx.a"));
        let policy = manifest(
            "runtime",
            &["usr/include/**", "usr/lib/*/pkgconfig/**"],
            false,
        );
        assert!(
            policy
                .excludes
                .iter()
                .any(|p| glob_match(p, "usr/include/zlib.h"))
        );
        assert!(
            policy
                .excludes
                .iter()
                .any(|p| glob_match(p, "usr/lib/x86_64-linux-gnu/pkgconfig/openssl.pc"))
        );
        assert!(
            !policy
                .excludes
                .iter()
                .any(|p| glob_match(p, "usr/bin/bash"))
        );
    }

    #[test]
    fn compose_conflicts_and_pc_cow() {
        let base = std::env::temp_dir().join(format!("buildutil-proj-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let a = base.join("a");
        let b = base.join("b");
        fs::create_dir_all(a.join("usr/lib/pkgconfig")).unwrap();
        fs::create_dir_all(a.join("usr/lib/x86_64-linux-gnu/pkgconfig")).unwrap();
        fs::create_dir_all(a.join("usr/include/x86_64-linux-gnu/openssl")).unwrap();
        fs::create_dir_all(b.join("usr/bin")).unwrap();
        fs::create_dir_all(a.join("usr/lib/sub")).unwrap();
        fs::write(a.join("usr/lib/pkgconfig/x.pc"), "prefix=/opt\nName: x\n").unwrap();
        fs::write(
            a.join("usr/lib/x86_64-linux-gnu/pkgconfig/y.pc"),
            "prefix=/opt/y\nincludedir=${prefix}/include\nName: y\nCflags: -I${includedir}\n",
        )
        .unwrap();
        fs::write(
            a.join("usr/include/x86_64-linux-gnu/openssl/opensslconf.h"),
            "#define X 1\n",
        )
        .unwrap();
        fs::write(a.join("usr/lib/sub/libx.a"), "ar").unwrap();
        fs::write(b.join("usr/bin/tool"), "elf").unwrap();

        let target = base.join("sysroot");
        let mut p = Projection::new(&target, manifest("full", &[], true)).unwrap();
        p.compose("a", &a).unwrap();
        p.compose("b", &b).unwrap();
        // .pc rewritten in the projection, store original untouched (no
        // shared inode).
        let projected = fs::read_to_string(target.join("usr/lib/pkgconfig/x.pc")).unwrap();
        assert!(projected.starts_with("prefix=/usr\n"));
        let multi_projected =
            fs::read_to_string(target.join("usr/lib/x86_64-linux-gnu/pkgconfig/y.pc")).unwrap();
        assert!(multi_projected.starts_with("prefix=/usr\n"));
        assert!(
            multi_projected.contains("Cflags: -I${includedir} -I${includedir}/x86_64-linux-gnu\n")
        );
        p.write_setup_env().unwrap();
        let setup = fs::read_to_string(target.join("buildutil-support/setup-env")).unwrap();
        assert!(
            setup.contains("append-path PKG_CONFIG_LIBDIR usr/lib/x86_64-linux-gnu/pkgconfig\n")
        );
        assert!(setup.contains("set-path PKG_CONFIG_SYSROOT_DIR .\n"));
        assert!(setup.contains("append-flag BUILDUTIL_CFLAGS_COMPILE -isystem usr/include\n"));
        assert!(
            setup.contains(
                "append-flag BUILDUTIL_CFLAGS_COMPILE -isystem usr/include/x86_64-linux-gnu\n"
            )
        );
        assert!(setup.contains("append-flag BUILDUTIL_LDFLAGS -L usr/lib/x86_64-linux-gnu\n"));
        let orig = fs::read_to_string(a.join("usr/lib/pkgconfig/x.pc")).unwrap();
        assert!(orig.starts_with("prefix=/opt\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let src_ino = fs::metadata(a.join("usr/lib/pkgconfig/x.pc"))
                .unwrap()
                .ino();
            let dst_ino = fs::metadata(target.join("usr/lib/pkgconfig/x.pc"))
                .unwrap()
                .ino();
            assert_ne!(src_ino, dst_ino);
            // Non-.pc files hardlink.
            assert_eq!(
                fs::metadata(a.join("usr/lib/sub/libx.a")).unwrap().ino(),
                fs::metadata(target.join("usr/lib/sub/libx.a"))
                    .unwrap()
                    .ino()
            );
        }

        // A second owner claiming the same path is fatal.
        let c = base.join("c");
        fs::create_dir_all(c.join("usr/bin")).unwrap();
        fs::write(c.join("usr/bin/tool"), "other").unwrap();
        let err = p.compose("c", &c).unwrap_err();
        assert!(err.contains("owned by both b and c"), "{}", err);

        // Runtime filter drops dev payload.
        let rt = base.join("rootfs");
        let mut r = Projection::new(
            &rt,
            manifest(
                "runtime",
                &[
                    "usr/lib/**/*.a",
                    "usr/lib/pkgconfig/**",
                    "usr/lib/*/pkgconfig/**",
                ],
                false,
            ),
        )
        .unwrap();
        r.compose("a", &a).unwrap();
        r.compose("b", &b).unwrap();
        assert!(!rt.join("usr/lib/pkgconfig/x.pc").exists());
        assert!(!rt.join("usr/lib/x86_64-linux-gnu/pkgconfig/y.pc").exists());
        assert!(!rt.join("usr/lib/sub/libx.a").exists());
        assert!(rt.join("usr/bin/tool").exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn rejects_symlink_ancestor_from_an_earlier_owner() {
        let base =
            std::env::temp_dir().join(format!(
                "buildutil-proj-symlink-escape-{}",
                std::process::id()
            ));
        let _ = fs::remove_dir_all(&base);
        let a = base.join("a");
        let b = base.join("b");
        let escape = base.join("escape");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(b.join("usr/bin")).unwrap();
        fs::create_dir_all(&escape).unwrap();
        crate::platform::symlink(&escape, &a.join("usr")).unwrap();
        fs::write(b.join("usr/bin/tool"), b"tool").unwrap();
        let target = base.join("out");
        let mut projection = Projection::new(&target, manifest("full", &[], false)).unwrap();
        projection.compose("a", &a).unwrap();
        let err = projection.compose("b", &b).unwrap_err();
        assert!(err.contains("conflict") && err.contains("Symlink"), "{err}");
        assert!(!escape.join("bin/tool").exists());
        let _ = fs::remove_dir_all(&base);
    }
}
