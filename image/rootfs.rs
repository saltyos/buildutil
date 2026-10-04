//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — rootfs image assembly (manifest mode)
//!
//! Loads `dst=src` manifests (with `@include` recursion and `@symlink:`
//! entries), expands directory sources, projects declared package stage
//! trees, folds in the `/etc` template tree and the empty directories the
//! derivation names, and writes the SaltyFS image in-process via
//! crate::saltyfs. Every directory and path it adds is an argument.

use std::path::{Path, PathBuf};

use super::cpio;
use super::saltyfs::build::{BuildStats, build_to_file};
use super::saltyfs::{Contents, FileSource, FsSpec};

struct Entry {
    dst: String,
    src: String,
    manifest_dir: PathBuf,
}

fn load_manifest(path: &Path, out: &mut Vec<Entry>) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read manifest {}: {}", path.display(), e))?;
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(include) = line.strip_prefix("@include ") {
            load_manifest(&dir.join(include.trim()), out)?;
            continue;
        }
        let Some((dst, src)) = line.split_once('=') else {
            return Err(format!(
                "{}:{}: invalid entry (expected dst=src): {}",
                path.display(),
                lineno + 1,
                line
            ));
        };
        let (dst, src) = (dst.trim(), src.trim());
        if dst.is_empty() || src.is_empty() {
            return Err(format!(
                "{}:{}: empty dst or src",
                path.display(),
                lineno + 1
            ));
        }
        out.push(Entry {
            dst: dst.to_string(),
            src: src.to_string(),
            manifest_dir: dir.clone(),
        });
    }
    Ok(())
}

/// Resolve a manifest source path without depending on the process cwd:
/// absolute paths pass through; `./`/`../` prefer the declaring manifest's
/// directory; everything else prefers the repo root.
fn resolve_source(src: &str, manifest_dir: &Path, repo_root: &Path) -> PathBuf {
    let p = PathBuf::from(src);
    if p.is_absolute() {
        return p;
    }
    let candidates: Vec<PathBuf> = if src.starts_with("./") || src.starts_with("../") {
        vec![manifest_dir.join(&p), repo_root.join(&p)]
    } else {
        vec![repo_root.join(&p), manifest_dir.join(&p)]
    };
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    candidates[0].clone()
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| format!("cannot read {}: {}", dir.display(), e))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for e in entries {
            if e.is_dir() {
                stack.push(e);
            } else if e.is_file() {
                out.push(e);
            }
        }
    }
    out.sort();
    Ok(out)
}

pub struct RootfsArgs {
    pub output: PathBuf,
    pub size_bytes: u64,
    pub label: String,
    pub manifests: Vec<PathBuf>,
    pub optional_manifests: Vec<PathBuf>,
    /// Port closure: (name, store entry dir) — each entry's `stage/`
    /// tree projects into the rootfs through the runtime filter.
    pub packages: Vec<(String, PathBuf)>,
    pub compose_manifest: Option<PathBuf>,
    pub permissions: Option<PathBuf>,
    /// The tree copied under `/etc`.
    pub etc_dir: PathBuf,
    /// Directories that exist in the image even when empty.
    pub empty_dirs: Vec<String>,
    pub repo_root: PathBuf,
    pub epoch_secs: u64,
    /// `epoch_secs` came from a declared clock rather than the fallback.
    pub clock_valid: bool,
}

pub fn build(args: &RootfsArgs) -> Result<BuildStats, String> {
    let mut entries: Vec<Entry> = Vec::new();
    for m in &args.manifests {
        load_manifest(m, &mut entries)?;
    }
    for m in &args.optional_manifests {
        if m.exists() {
            load_manifest(m, &mut entries)?;
        }
    }
    if entries.is_empty() && args.packages.is_empty() {
        return Err("rootfs: no manifest entries".to_string());
    }

    let mut files: Vec<(String, FileSource)> = Vec::new();
    let mut symlinks: Vec<(String, Vec<u8>)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for e in &entries {
        if let Some(target) = e.src.strip_prefix("@symlink:") {
            symlinks.push((e.dst.clone(), target.as_bytes().to_vec()));
            continue;
        }
        let src = resolve_source(&e.src, &e.manifest_dir, &args.repo_root);
        if !src.exists() {
            missing.push(format!("{} <- {}", e.dst, e.src));
            continue;
        }
        if src.is_dir() {
            for child in walk_files(&src)? {
                let rel = child
                    .strip_prefix(&src)
                    .map_err(|_| format!("walk escaped {}", src.display()))?;
                let dst = format!("{}/{}", e.dst.trim_end_matches('/'), rel.display());
                files.push((dst, FileSource::Path(child)));
            }
        } else {
            files.push((e.dst.clone(), FileSource::Path(src)));
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "rootfs: {} source file(s) not found:\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }

    // Port closure: project each package's stage tree through the
    // runtime filter (dev payload dropped, pkg-config prefixes rewritten
    // copy-on-write) into a staging dir, then carry its files/symlinks.
    if !args.packages.is_empty() {
        // Staging lives in TMPDIR (the sandbox's private tmp inside a
        // derivation), never beside the output.
        let staging = std::env::temp_dir().join(format!(
            "{}.pkgroot",
            args.output
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("rootfs")
        ));
        let _ = std::fs::remove_dir_all(&staging);
        let manifest_path = args
            .compose_manifest
            .as_ref()
            .ok_or("rootfs: package projection requires --compose-manifest")?;
        let manifest = buildutil_compose::manifest::ComposeManifest::load(manifest_path)?;
        let mut projection = buildutil_compose::projection::Projection::new(&staging, manifest)?;
        for (name, entry_dir) in &args.packages {
            projection.compose(name, &entry_dir.join("stage"))?;
        }
        projection.finish()?;
        let mut stack = vec![staging.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)
                .map_err(|e| format!("cannot read {}: {}", dir.display(), e))?
            {
                let entry = entry.map_err(|e| format!("read_dir entry: {}", e))?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path)
                    .map_err(|e| format!("stat {}: {}", path.display(), e))?;
                let rel = path
                    .strip_prefix(&staging)
                    .map_err(|_| "walk escaped staging".to_string())?;
                let dst = format!("/{}", rel.display());
                if meta.file_type().is_symlink() {
                    let target = std::fs::read_link(&path)
                        .map_err(|e| format!("readlink {}: {}", path.display(), e))?;
                    symlinks.push((dst, target.to_string_lossy().into_owned().into_bytes()));
                } else if meta.is_dir() {
                    stack.push(path);
                } else {
                    files.push((dst, FileSource::Path(path)));
                }
            }
        }
    }

    // The /etc template tree.
    let etc_dir = &args.etc_dir;
    if etc_dir.is_dir() {
        for child in walk_files(&etc_dir)? {
            let rel = child
                .strip_prefix(&etc_dir)
                .map_err(|_| format!("walk escaped {}", etc_dir.display()))?;
            files.push((format!("etc/{}", rel.display()), FileSource::Path(child)));
        }
    }

    let permissions = match &args.permissions {
        Some(p) if p.exists() => cpio::load_permissions(p)?,
        _ => Default::default(),
    };

    build_to_file(
        &args.output,
        &FsSpec {
            size_bytes: args.size_bytes,
            label: args.label.clone(),
            epoch_secs: args.epoch_secs,
            clock_valid: args.clock_valid,
            casefold_root: false,
            extra_incompat: 0,
            compat_ro_flags: 0,
            casefold_version: 0,
        },
        &Contents {
            files,
            empty_dirs: args.empty_dirs.clone(),
            symlinks,
            directory_links: Vec::new(),
            permissions,
        },
    )
}

fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_uppercase();
    let (num, mul) = match t.chars().last() {
        Some('K') => (&t[..t.len() - 1], 1024u64),
        Some('M') => (&t[..t.len() - 1], 1024 * 1024),
        Some('G') => (&t[..t.len() - 1], 1024 * 1024 * 1024),
        _ => (t.as_str(), 1),
    };
    num.parse::<u64>()
        .map(|n| n * mul)
        .map_err(|_| format!("invalid size `{}`", s))
}

/// `buildutil rootfs` entry point.
pub fn run(args: &[String]) -> Result<i32, String> {
    let mut output: Option<PathBuf> = None;
    let mut size = 256 * 1024 * 1024u64;
    let mut label = "rootfs".to_string();
    let mut manifests: Vec<PathBuf> = Vec::new();
    let mut optional_manifests: Vec<PathBuf> = Vec::new();
    let mut permissions: Option<PathBuf> = None;
    let mut etc_dir: Option<PathBuf> = None;
    let mut empty_dirs: Vec<String> = Vec::new();
    let mut repo_root_arg: Option<PathBuf> = None;
    let mut packages: Vec<(String, PathBuf)> = Vec::new();
    let mut compose_manifest: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize, what: &str| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", what))
        };
        match args[i].as_str() {
            "--output" | "-o" => output = Some(PathBuf::from(take(&mut i, "--output")?)),
            "--size" | "-s" => size = parse_size(&take(&mut i, "--size")?)?,
            "--label" => label = take(&mut i, "--label")?,
            "--manifest" | "-m" => manifests.push(PathBuf::from(take(&mut i, "--manifest")?)),
            "--manifest-optional" => {
                optional_manifests.push(PathBuf::from(take(&mut i, "--manifest-optional")?));
            }
            "--permissions" => permissions = Some(PathBuf::from(take(&mut i, "--permissions")?)),
            "--etc-dir" => etc_dir = Some(PathBuf::from(take(&mut i, "--etc-dir")?)),
            "--dir" => {
                let dir = take(&mut i, "--dir")?;
                if !dir.starts_with('/') {
                    return Err(format!("rootfs: --dir `{dir}` must be an absolute image path"));
                }
                empty_dirs.push(dir);
            }
            "--repo-root" => repo_root_arg = Some(PathBuf::from(take(&mut i, "--repo-root")?)),
            "--package" => {
                let spec = take(&mut i, "--package")?;
                let (name, dir) = spec
                    .split_once('=')
                    .ok_or("--package takes name=<store-entry-dir>")?;
                packages.push((name.to_string(), PathBuf::from(dir)));
            }
            "--compose-manifest" => {
                compose_manifest = Some(PathBuf::from(take(&mut i, "--compose-manifest")?));
            }
            other => return Err(format!("rootfs: unknown argument `{}`", other)),
        }
        i += 1;
    }
    let output = output.ok_or("rootfs: --output is required")?;
    let etc_dir = etc_dir.ok_or("rootfs: --etc-dir names the /etc template tree")?;
    if manifests.is_empty() && optional_manifests.is_empty() && packages.is_empty() {
        return Err("rootfs: name at least one --manifest or --package".to_string());
    }
    let repo_root = match repo_root_arg {
        Some(p) => p,
        None => {
            std::env::current_dir().map_err(|e| format!("cannot determine repo root: {}", e))?
        }
    };
    let declared_epoch: Option<u64> = crate::invocation::ambient_var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok());
    let (epoch_secs, clock_valid) = (declared_epoch.unwrap_or(1), declared_epoch.is_some());
    let stats = build(&RootfsArgs {
        output: output.clone(),
        size_bytes: size,
        label,
        manifests,
        optional_manifests,
        packages,
        compose_manifest,
        permissions,
        etc_dir,
        empty_dirs,
        repo_root,
        epoch_secs,
        clock_valid,
    })?;
    crate::log::success(
        "rootfs",
        &format!(
            "wrote {} ({} files, {}/{} blocks used)",
            output.display(),
            stats.files,
            stats.used_blocks,
            stats.total_blocks
        ),
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_include_symlink_and_dir_expansion() {
        let dir = std::env::temp_dir().join(format!("buildutil-rootfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
        std::fs::write(dir.join("bin-init"), vec![0x7Fu8, b'E', b'L', b'F']).unwrap();
        std::fs::write(dir.join("tree/a.txt"), b"a").unwrap();
        std::fs::write(dir.join("tree/sub/b.txt"), b"b").unwrap();
        std::fs::write(dir.join("inner.manifest"), "/opt/tree=./tree\n").unwrap();
        std::fs::write(
            dir.join("main.manifest"),
            "# comment\n/bin/init=./bin-init\n/bin/sh=@symlink:/bin/init\n@include inner.manifest\n",
        )
        .unwrap();

        let out = dir.join("rootfs.img");
        let stats = build(&RootfsArgs {
            output: out.clone(),
            size_bytes: 4 * 1024 * 1024,
            label: "rootfs".to_string(),
            manifests: vec![dir.join("main.manifest")],
            optional_manifests: vec![dir.join("absent.manifest")],
            packages: Vec::new(),
            compose_manifest: None,
            permissions: None,
            etc_dir: dir.join("no-etc"),
            empty_dirs: vec!["/var".to_string(), "/var/log".to_string()],
            repo_root: dir.clone(),
            epoch_secs: 1,
            clock_valid: true,
        })
        .unwrap();
        assert_eq!(stats.files, 3); // init + 2 expanded tree files

        let dump = super::super::saltyfs::read::dump_text(&out).unwrap();
        assert!(dump.contains("file /bin/init "));
        assert!(dump.contains("symlink /bin/sh -> /bin/init"));
        assert!(dump.contains("file /opt/tree/a.txt "));
        assert!(dump.contains("file /opt/tree/sub/b.txt "));
        assert!(dump.contains("dir /var/log "));
        assert!(!dump.contains("ERROR"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
