// SPDX-License-Identifier: GPL-2.0-only
//! buildutil-compose — CLI front end for FHS projection.
//!
//! Composes one or more immutable store output trees into a fresh target
//! tree under a chosen filter (build-time `full` view or runtime-stripped
//! `runtime` view). One derivation call per projection target: the
//! derivation's own build script supplies the ordered (owner, path) pairs.
//!
//! Usage: buildutil-compose --manifest <FILE> --out <DIR> OWNER PATH [OWNER PATH ...]

use buildutil_compose::manifest::ComposeManifest;
use buildutil_compose::projection::Projection;
use std::path::PathBuf;
use std::process::ExitCode;

fn run(args: &[String]) -> Result<(), String> {
    let mut manifest: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut pairs: Vec<(String, PathBuf)> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest = Some(PathBuf::from(args.get(i).ok_or("--manifest needs a path")?));
            }
            "--out" => {
                i += 1;
                out = Some(PathBuf::from(args.get(i).ok_or("--out needs a path")?));
            }
            owner => {
                i += 1;
                let path = args
                    .get(i)
                    .ok_or_else(|| format!("owner `{}` needs a path", owner))?;
                pairs.push((owner.to_string(), PathBuf::from(path)));
            }
        }
        i += 1;
    }

    let manifest =
        ComposeManifest::load(&manifest.ok_or("buildutil-compose: --manifest is required")?)?;
    let out = out.ok_or("buildutil-compose: --out is required")?;
    if pairs.is_empty() {
        return Err("buildutil-compose: at least one OWNER PATH pair is required".to_string());
    }

    let mut projection = Projection::new(&out, manifest)?;
    let mut total = 0usize;
    for (owner, path) in &pairs {
        total += projection.compose(owner, path)?;
    }
    projection.finish()?;
    eprintln!("buildutil-compose: {} ({} files)", out.display(), total);
    Ok(())
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
