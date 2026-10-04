// SPDX-License-Identifier: GPL-2.0-only
//! buildutil-sysroot — CLI front end for cross-sysroot assembly and composition.
//!
//! Usage:
//!   buildutil-sysroot assemble --repo-root <DIR> --build-dir <DIR> --out <DIR> [--stamp <FILE>] [--clean]
//!   buildutil-sysroot compose --out <DIR> --base <DIR> [OWNER STAGE ...]

use buildutil_compose::manifest::ComposeManifest;
use buildutil_compose::sysroot::{self, SysrootInputs};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn run_assemble(args: &[String]) -> Result<(), String> {
    let mut repo_root: Option<PathBuf> = None;
    let mut build_dir: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut stamp: Option<PathBuf> = None;
    let mut clean = false;
    let mut manifest: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo-root" => {
                i += 1;
                repo_root = Some(PathBuf::from(
                    args.get(i).ok_or("--repo-root needs a path")?,
                ));
            }
            "--build-dir" => {
                i += 1;
                build_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--build-dir needs a path")?,
                ));
            }
            "--out" => {
                i += 1;
                out = Some(PathBuf::from(args.get(i).ok_or("--out needs a path")?));
            }
            "--stamp" => {
                i += 1;
                stamp = Some(PathBuf::from(args.get(i).ok_or("--stamp needs a path")?));
            }
            "--clean" => clean = true,
            "--manifest" => {
                i += 1;
                manifest = Some(PathBuf::from(args.get(i).ok_or("--manifest needs a path")?));
            }
            other => {
                return Err(format!(
                    "buildutil-sysroot assemble: unknown argument `{}`",
                    other
                ));
            }
        }
        i += 1;
    }

    let repo_root = repo_root.ok_or("buildutil-sysroot assemble: --repo-root is required")?;
    let build_dir = build_dir.ok_or("buildutil-sysroot assemble: --build-dir is required")?;
    let out = out.ok_or("buildutil-sysroot assemble: --out is required")?;
    ComposeManifest::load(&manifest.ok_or("buildutil-sysroot assemble: --manifest is required")?)?;

    if clean && out.exists() {
        fs::remove_dir_all(&out).map_err(|e| format!("cannot clean {}: {}", out.display(), e))?;
    }

    let copied = sysroot::assemble(
        &SysrootInputs {
            repo_root,
            build_dir,
        },
        &out,
    )?;
    eprintln!(
        "buildutil-sysroot assemble: {} ({} files)",
        out.display(),
        copied
    );

    if let Some(stamp) = stamp {
        if let Some(parent) = stamp.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        fs::write(&stamp, b"")
            .map_err(|e| format!("cannot write stamp {}: {}", stamp.display(), e))?;
    }
    Ok(())
}

fn run_compose(args: &[String]) -> Result<(), String> {
    let mut out: Option<PathBuf> = None;
    let mut base: Option<PathBuf> = None;
    let mut deps: Vec<(String, PathBuf)> = Vec::new();
    let mut manifest: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = Some(PathBuf::from(args.get(i).ok_or("--out needs a path")?));
            }
            "--base" => {
                i += 1;
                base = Some(PathBuf::from(args.get(i).ok_or("--base needs a path")?));
            }
            "--manifest" => {
                i += 1;
                manifest = Some(PathBuf::from(args.get(i).ok_or("--manifest needs a path")?));
            }
            owner => {
                i += 1;
                let stage = args
                    .get(i)
                    .ok_or_else(|| format!("owner `{}` needs a stage path", owner))?;
                deps.push((owner.to_string(), PathBuf::from(stage)));
            }
        }
        i += 1;
    }

    let out = out.ok_or("buildutil-sysroot compose: --out is required")?;
    let base = base.ok_or("buildutil-sysroot compose: --base is required")?;

    let manifest =
        ComposeManifest::load(
            &manifest.ok_or("buildutil-sysroot compose: --manifest is required")?,
        )?;
    sysroot::compose_view(&out, &base, &deps, manifest)?;
    eprintln!(
        "buildutil-sysroot compose: {} ({} dep(s))",
        out.display(),
        deps.len()
    );
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let (subcommand, rest) = args
        .split_first()
        .ok_or("buildutil-sysroot: expected a subcommand (`assemble` or `compose`)")?;
    match subcommand.as_str() {
        "assemble" => run_assemble(rest),
        "compose" => run_compose(rest),
        other => Err(format!(
            "buildutil-sysroot: unknown subcommand `{}` (expected `assemble` or `compose`)",
            other
        )),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}
