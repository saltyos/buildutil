//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — cross-compilation sysroot assembly
//!
//! Builds the FHS-shaped cross sysroot that port builds (and the
//! self-hosting toolchain) compile against: the C library headers, the C++
//! headers when the llvm-project payload is present, the runtime
//! libraries and CRT objects, the PIE linker scripts, and the musl-style
//! empty stub archives (libm/libpthread/librt/libdl/libutil fold into
//! libc.so; the stubs satisfy unconditional `-lm`-style link lines).
//!
//! Two consumers share the core: the `buildutil sysroot` CLI assembles from a
//! build directory, and the `sysroot-base` derivation assembles from dep
//! store outputs into the store (the projection base for port builds).

use crate::manifest::ComposeManifest;
use crate::projection::Projection;
use std::fs;
use std::path::{Path, PathBuf};

/// (dest name under usr/lib, build-dir-relative source).
const REQUIRED_BUILD_FILES: &[(&str, &str)] = &[
    ("libc.so", "lib/c/libc.so"),
    ("libc.a", "lib/c/libc.a"),
    ("libsystem.so", "lib/system/libsystem.so"),
    ("libsystem.a", "lib/system/libsystem.a"),
    ("crt_start.o", "lib/system/crt_start.o"),
    ("crt_start_static.o", "lib/system/crt_start_static.o"),
    ("core.o", "lib/system/core-system.o"),
    ("compiler_builtins.o", "lib/system/compiler_builtins-system.o"),
    ("dyld", "lib/dyld/dyld"),
];

const OPTIONAL_BUILD_FILES: &[(&str, &str)] = &[
    ("libc++.so", "lib/cxx/libc++.so"),
];

const STUB_LIBS: &[&str] = &["libm.a", "libpthread.a", "librt.a", "libdl.a", "libutil.a"];

fn copy_file(src: &Path, dst: &Path) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    // Staged sources are read-only CAS hardlinks; tree composition may land
    // on the same destination twice, and a bare fs::copy would both refuse
    // the read-only overwrite and propagate the 0444 mode into the output.
    // Replace, then normalize to the umask shape (exec class preserved).
    if fs::symlink_metadata(dst).is_ok() {
        fs::remove_file(dst).map_err(|e| format!("cannot replace {}: {}", dst.display(), e))?;
    }
    fs::copy(src, dst)
        .map_err(|e| format!("cannot copy {} -> {}: {}", src.display(), dst.display(), e))?;
    let exec = crate::platform::mode(
        &fs::metadata(src).map_err(|e| format!("stat {}: {}", src.display(), e))?,
    ) & 0o111
        != 0;
    crate::platform::set_mode(dst, if exec { 0o755 } else { 0o644 })
        .map_err(|e| format!("cannot chmod {}: {}", dst.display(), e))?;
    Ok(())
}

fn copy_tree(src_root: &Path, dst_root: &Path) -> Result<usize, String> {
    let mut count = 0usize;
    let mut stack = vec![src_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {}", dir.display(), e))?
        {
            let entry = entry.map_err(|e| format!("read_dir entry: {}", e))?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|e| format!("stat {}: {}", path.display(), e))?;
            let rel = path
                .strip_prefix(src_root)
                .map_err(|e| format!("strip_prefix: {}", e))?
                .to_path_buf();
            if meta.is_dir() && !meta.file_type().is_symlink() {
                stack.push(path);
            } else if meta.file_type().is_symlink() {
                let target = fs::read_link(&path)
                    .map_err(|e| format!("readlink {}: {}", path.display(), e))?;
                let dst = dst_root.join(&rel);
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
                }
                let _ = fs::remove_file(&dst);
                crate::platform::symlink(&target, &dst)
                    .map_err(|e| format!("cannot symlink {}: {}", dst.display(), e))?;
                count += 1;
            } else {
                copy_file(&path, &dst_root.join(&rel))?;
                count += 1;
            }
        }
    }
    Ok(count)
}

pub struct SysrootInputs {
    /// Repo root — C library headers, linker scripts, C++ header payload.
    pub repo_root: PathBuf,
    /// Where the built libraries live: a meson build dir (CLI) or a
    /// staging dir composed from dep store outputs (derivation).
    pub build_dir: PathBuf,
}

/// Assemble the sysroot tree into `output` (fresh or incremental — files
/// are always rewritten; stale-entry reconciliation does not exist because
/// callers hand a fresh target).
pub fn assemble(inputs: &SysrootInputs, output: &Path) -> Result<usize, String> {
    let include_dir = output.join("usr/include");
    let lib_dir = output.join("usr/lib");
    fs::create_dir_all(&include_dir)
        .map_err(|e| format!("cannot create {}: {}", include_dir.display(), e))?;
    fs::create_dir_all(&lib_dir)
        .map_err(|e| format!("cannot create {}: {}", lib_dir.display(), e))?;

    let mut copied = 0usize;

    let header_src = inputs.repo_root.join("lib/c/include");
    if !header_src.is_dir() {
        return Err(format!(
            "header directory not found: {}",
            header_src.display()
        ));
    }
    copied += copy_tree(&header_src, &include_dir)?;

    // C++ headers ride along when the llvm-project payload is checked out.
    let cxx_inc_src = inputs
        .repo_root
        .join("toolchain/llvm-project/libcxx/include");
    if cxx_inc_src.is_dir() {
        let cxx_dst = output.join("usr/include/c++/v1");
        copied += copy_tree(&cxx_inc_src, &cxx_dst)?;
        let cxxabi = inputs
            .repo_root
            .join("toolchain/llvm-project/libcxxabi/include");
        if cxxabi.is_dir() {
            copied += copy_tree(&cxxabi, &cxx_dst)?;
        }
        for extra in ["__config_site", "__assertion_handler"] {
            let src = inputs.repo_root.join("lib/cxx/include").join(extra);
            if src.is_file() {
                copy_file(&src, &cxx_dst.join(extra))?;
                copied += 1;
            }
        }
    }

    for (dest, rel) in REQUIRED_BUILD_FILES {
        let src = inputs.build_dir.join(rel);
        if !src.is_file() {
            return Err(format!(
                "required sysroot input not found: {}",
                src.display()
            ));
        }
        copy_file(&src, &lib_dir.join(dest))?;
        copied += 1;
    }
    for (dest, rel) in OPTIONAL_BUILD_FILES {
        let src = inputs.build_dir.join(rel);
        if src.is_file() {
            copy_file(&src, &lib_dir.join(dest))?;
            copied += 1;
        } else {
            eprintln!(
                "buildutil sysroot: optional input not found, skipping: {}",
                src.display()
            );
        }
    }

    // The names the clang driver looks up on the sysroot's library path.
    for script in ["pie-executable.ld", "static-pie-executable.ld"] {
        let src = inputs.repo_root.join("lib/system/link").join(script);
        if !src.is_file() {
            return Err(format!("linker script not found: {}", src.display()));
        }
        copy_file(&src, &lib_dir.join(script))?;
        copied += 1;
    }

    for name in STUB_LIBS {
        fs::write(lib_dir.join(name), b"!<arch>\n")
            .map_err(|e| format!("cannot write stub {}: {}", name, e))?;
        copied += 1;
    }

    Ok(copied)
}

/// Compose a private per-derivation sysroot view: the assembled base plus
/// each build-dep port's stage tree.
pub fn compose_view(
    target: &Path,
    base: &Path,
    deps: &[(String, PathBuf)],
    manifest: ComposeManifest,
) -> Result<(), String> {
    let mut projection = Projection::new(target, manifest)?;
    projection.compose("__base__", base)?;
    for (owner, stage) in deps {
        projection.compose(owner, stage)?;
    }
    projection.finish()?;
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut build_dir: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut stamp: Option<PathBuf> = None;
    let mut clean = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--build-dir" => {
                i += 1;
                build_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--build-dir needs a path")?,
                ));
            }
            "--output" | "-o" => {
                i += 1;
                output = Some(PathBuf::from(args.get(i).ok_or("--output needs a path")?));
            }
            "--stamp" => {
                i += 1;
                stamp = Some(PathBuf::from(args.get(i).ok_or("--stamp needs a path")?));
            }
            "--clean" => clean = true,
            "-v" => {}
            other => return Err(format!("sysroot: unknown argument `{}`", other)),
        }
        i += 1;
    }
    let build_dir = build_dir.ok_or("sysroot: --build-dir is required")?;
    let output = output.ok_or("sysroot: --output is required")?;
    let repo_root =
        std::env::current_dir().map_err(|e| format!("cannot determine repo root: {}", e))?;
    if clean && output.exists() {
        fs::remove_dir_all(&output)
            .map_err(|e| format!("cannot clean {}: {}", output.display(), e))?;
    }
    let copied = assemble(
        &SysrootInputs {
            repo_root,
            build_dir,
        },
        &output,
    )?;
    eprintln!("buildutil sysroot: {} ({} files)", output.display(), copied);
    if let Some(stamp) = stamp {
        if let Some(parent) = stamp.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&stamp, b"")
            .map_err(|e| format!("cannot write stamp {}: {}", stamp.display(), e))?;
    }
    Ok(())
}
