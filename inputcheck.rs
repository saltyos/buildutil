// SPDX-License-Identifier: GPL-2.0-only
//! Bootstrap input verification before the configuration library can be compiled.

#[path = "inputs/bootstrap.rs"]
mod bootstrap;
#[path = "inputs/codec.rs"]
mod codec;
#[path = "inputs/content.rs"]
mod content;
mod glob;
#[path = "source/filter.rs"]
mod input_filter;
#[path = "lib/crypto/sha256.rs"]
mod input_sha256;
#[path = "spec/toml.rs"]
mod input_toml;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static SNAPSHOT_SEQ: AtomicU64 = AtomicU64::new(0);

fn run(args: &[String]) -> Result<(), String> {
    let mut root = None;
    let mut overrides = BTreeMap::new();
    let mut materialize = None;
    let mut record = None;
    let mut print_content = false;
    let mut passthrough = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => passthrough = true,
            "--repo-root" if !passthrough => {
                i += 1;
                root = Some(PathBuf::from(
                    args.get(i).ok_or("inputcheck: --repo-root needs a path")?,
                ));
            }
            "--override-input" => {
                i += 1;
                let name = args
                    .get(i)
                    .ok_or("inputcheck: --override-input needs a name")?
                    .clone();
                i += 1;
                let path = args
                    .get(i)
                    .and_then(|value| value.strip_prefix("path:"))
                    .filter(|path| !path.is_empty())
                    .ok_or("inputcheck: --override-input needs path:checkout")?;
                if overrides
                    .insert(name.clone(), PathBuf::from(path))
                    .is_some()
                {
                    return Err(format!("duplicate --override-input `{name}`"));
                }
            }
            "--materialize" if !passthrough => {
                i += 1;
                let name = args
                    .get(i)
                    .ok_or("inputcheck: --materialize needs an input and destination")?
                    .clone();
                i += 1;
                let destination = PathBuf::from(
                    args.get(i)
                        .ok_or("inputcheck: --materialize needs a destination")?,
                );
                materialize = Some((name, destination));
            }
            "--record-selection" if !passthrough => {
                i += 1;
                record = Some(PathBuf::from(
                    args.get(i)
                        .ok_or("inputcheck: --record-selection needs a path")?,
                ));
            }
            "--print-content" if !passthrough => print_content = true,
            _ => {}
        }
        i += 1;
    }
    let root = root.ok_or("inputcheck: --repo-root is required")?;
    let selections = bootstrap::selections(&root, &overrides)?;
    if let Some(record) = record {
        let parent = record
            .parent()
            .ok_or("inputcheck: selection record has no parent")?;
        let destination = parent.join("input-sources");
        let mut text = "[selection]\n".to_string();
        for (name, source, content) in &selections {
            let hash = content
                .strip_prefix("tree:")
                .ok_or("inputcheck: invalid content address")?;
            let target = destination.join(hash);
            if !target.exists() {
                snapshot(source, &target, hash)?;
            }
            if content::capture(&target, &[])?.hash() != hash {
                return Err(format!(
                    "inputcheck: snapshot differs from buildutil.lock [input.{name}].content"
                ));
            }
            let path = target
                .canonicalize()
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .into_owned();
            text.push_str(&format!(
                "{name} = \"{}\"\n",
                path.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
        std::fs::write(&record, text)
            .map_err(|e| format!("inputcheck: cannot record selected inputs: {e}"))?;
    }
    if let Some((name, destination)) = materialize {
        let (_, selected, identity) = selections
            .iter()
            .find(|(input, _, _)| input == &name)
            .ok_or_else(|| format!("inputcheck: `{name}` is not a bootstrap input"))?;
        let hash = identity
            .strip_prefix("tree:")
            .ok_or("inputcheck: invalid content address")?;
        let target = destination.join(hash);
        if !target.exists() {
            snapshot(selected, &target, hash)?;
        }
        if content::capture(&target, &[])?.hash() != hash {
            return Err(format!(
                "inputcheck: bootstrap snapshot differs from buildutil.lock [input.{name}].content"
            ));
        }
        println!(
            "{}",
            target
                .canonicalize()
                .map_err(|e| format!("inputcheck: cannot resolve snapshot: {e}"))?
                .display()
        );
    }
    if print_content {
        for (name, _, content) in &selections {
            println!("{name} {content}");
        }
    }
    Ok(())
}

fn snapshot(source: &Path, target: &Path, hash: &str) -> Result<(), String> {
    let source = source.canonicalize().map_err(|e| e.to_string())?;
    let seq = SNAPSHOT_SEQ.fetch_add(1, Ordering::Relaxed);
    let temp = target.with_file_name(format!(".{hash}-{}-{seq}", std::process::id()));
    if let Some(parent) = temp.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir(&temp).map_err(|e| format!("inputcheck: cannot create snapshot: {e}"))?;
    let result = (|| {
        let tree = content::capture_with(&source, &[], |path| {
            let relative = path.strip_prefix(&source).map_err(|e| e.to_string())?;
            let output = temp.join(relative);
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::copy(path, &output)
                .map_err(|e| format!("inputcheck: cannot capture {}: {e}", path.display()))?;
            let result = content::file(&output)?;
            let mut permissions = std::fs::metadata(&output)
                .map_err(|e| e.to_string())?
                .permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(if result.1 == 'x' { 0o555 } else { 0o444 });
            }
            #[cfg(not(unix))]
            {
                permissions.set_readonly(true);
            }
            std::fs::set_permissions(&output, permissions).map_err(|e| e.to_string())?;
            Ok(result)
        })?;
        for (rel, kind, digest) in &tree.entries {
            if *kind != 'l' {
                continue;
            }
            let output = temp.join(rel);
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let target = Path::new(
                tree.targets
                    .get(digest)
                    .ok_or("inputcheck: missing symlink target")?,
            );
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(target, &output).map_err(|e| e.to_string())?;
            }
            #[cfg(windows)]
            {
                if source.join(rel).is_dir() {
                    std::os::windows::fs::symlink_dir(target, &output)
                } else {
                    std::os::windows::fs::symlink_file(target, &output)
                }
                .map_err(|e| e.to_string())?;
            }
        }
        if tree.hash() != hash || content::capture(&temp, &[])?.hash() != hash {
            return Err(
                "inputcheck: checkout changed while capturing the locked content".to_string(),
            );
        }
        match std::fs::rename(&temp, target) {
            Ok(()) => Ok(()),
            Err(_) if target.exists() && content::capture(target, &[])?.hash() == hash => Ok(()),
            Err(e) => Err(format!("inputcheck: cannot publish snapshot: {e}")),
        }
    })();
    if temp.exists() {
        let _ = std::fs::remove_dir_all(temp);
    }
    result
}

fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("buildutil: {error}");
        std::process::exit(1);
    }
}
