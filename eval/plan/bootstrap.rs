//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — plan bootstrap: the source set every host must seed to realize
//! anything else

use super::BootstrapEntry;
use std::path::Path;

#[allow(dead_code)] // Full buildutil dispatches containers; minibuildutil consumes the path list.
pub(crate) fn collect_bootstrap(repo_root: &Path) -> Result<Vec<BootstrapEntry>, String> {
    let rels = bootstrap_paths(repo_root)?;
    let mut out = Vec::new();
    for rel in rels {
        let (hash, kind) = ingest_blob(repo_root, &rel)?;
        out.push(BootstrapEntry { kind, rel, hash });
    }
    Ok(out)
}

pub(crate) fn bootstrap_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let mut rels = vec![
        "buildutil".to_string(),
        "buildutil.toml".to_string(),
        // The source-filter contract is loaded directly (not walk-tolerantly)
        // during plan emission, so the repo-free projection must carry it or the
        // container's native evaluation fails reading it; it also keeps the
        // ingested executor-source set identical between host and container.
        crate::source::SOURCE_FILTER_FILE.to_string(),
        crate::paths::BOOTSTRAP_NINJA.to_string(),
        // Shared by both executor stages and external host tools. It lies
        // outside the executor subtree but is a direct Rust module input.
        "tools/buildutil/lib/crypto/sha256.rs".to_string(),
        // The module wire, compiled into buildutil as `sdk_wire`.
        crate::paths::SDK_WIRE.to_string(),
    ];
    // The lock pins the declared inputs, which the bootstrap does not build;
    // a repository that has declared none has no lock to carry.
    if repo_root.join("buildutil.lock").is_file() {
        rels.push("buildutil.lock".to_string());
    }
    collect_executor_sources(repo_root, crate::paths::BUILDUTIL, &mut rels)?;
    let doc = crate::spec::toml::parse_file(&repo_root.join("buildutil.toml"))?;
    let declarations = crate::inputs::codec::declarations(&doc)?;
    for (name, selected, _) in
        crate::inputs::bootstrap::selections(repo_root, &std::collections::BTreeMap::new())?
    {
        let prefix = crate::inputs::bootstrap::projection_path(&name, &declarations[&name]);
        for (relative, _, _) in crate::inputs::content::capture(&selected, &[])?.entries {
            rels.push(format!("{prefix}/{relative}"));
        }
    }
    collect_executor_sources(repo_root, "tools/buildutil/compose", &mut rels)?;
    rels.sort();
    rels.dedup();
    Ok(rels)
}

/// Bootstrap projections read the independently pinned selection, with its declared destination.
pub(crate) fn ingest_blob(repo_root: &Path, rel: &str) -> Result<(String, char), String> {
    let doc = crate::spec::toml::parse_file(&repo_root.join("buildutil.toml"))?;
    let declarations = crate::inputs::codec::declarations(&doc)?;
    let mut path = repo_root.join(rel);
    for (name, selected, _) in
        crate::inputs::bootstrap::selections(repo_root, &std::collections::BTreeMap::new())?
    {
        let prefix = crate::inputs::bootstrap::projection_path(&name, &declarations[&name]);
        if let Some(relative) = rel.strip_prefix(&format!("{prefix}/")) {
            path = selected.join(relative);
            break;
        }
    }
    if std::fs::symlink_metadata(&path)
        .map_err(|e| e.to_string())?
        .is_symlink()
    {
        let target = std::fs::read_link(&path).map_err(|e| e.to_string())?;
        let target = target
            .to_str()
            .ok_or("bootstrap symlink target is not UTF-8")?;
        let hash = crate::source::ingest_bytes(target.as_bytes())?;
        Ok((hash, 'l'))
    } else {
        crate::source::hash_and_ingest_file(&path)
    }
}

fn collect_executor_sources(
    repo_root: &Path,
    rel_dir: &str,
    rels: &mut Vec<String>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(repo_root.join(rel_dir))
        .map_err(|e| format!("cannot read executor dir {}: {}", rel_dir, e))?
    {
        let entry = entry.map_err(|e| format!("read executor entry: {}", e))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let rel = format!("{rel_dir}/{name}");
        let path = entry.path();
        if path.is_dir() {
            collect_executor_sources(repo_root, &rel, rels)?;
        } else if path.is_file() && (name.ends_with(".rs") || name == "buildutil.toml") {
            rels.push(rel);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn required_container_executor_surface_includes_graph_and_all_native_sources() {
        let root =
            std::env::temp_dir().join(format!("buildutil-executor-inputs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in [
            "tools/buildutil/nested",
            "tools/buildutil/lib/mica",
            "tools/buildutil/lib/crypto",
            "tools/buildutil/sdk",
            "tools/buildutil/compose",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for file in [
            "buildutil",
            "buildutil.toml",
            crate::paths::BOOTSTRAP_NINJA,
            "tools/buildutil/buildutil.toml",
            "tools/buildutil/main.rs",
            "tools/buildutil/nested/mod.rs",
            "tools/buildutil/lib/mica/lib.rs",
            "tools/buildutil/lib/crypto/sha256.rs",
            crate::paths::SDK_WIRE,
            "tools/buildutil/compose/buildutil.toml",
            "tools/buildutil/compose/lib.rs",
        ] {
            std::fs::write(root.join(file), file.as_bytes()).unwrap();
        }
        std::fs::write(root.join("tools/buildutil/README.md"), b"not an input").unwrap();
        std::fs::write(root.join("buildutil.toml"), "[lock]\nbootstrap-inputs = [\"language\"]\n[input.language]\nkind = \"source\"\nurl = \"https://example.org/language/{rev}.tar.gz\"\npath = \"tools/buildutil/lib/mica\"\n").unwrap();
        let tree = crate::inputs::content::capture(&root.join("tools/buildutil/lib/mica"), &[])
            .unwrap()
            .hash();
        let entry = crate::inputs::codec::Entry {
            url: "https://example.org/language/archive.tar.gz".into(),
            rev: "1".repeat(40),
            sha256: "2".repeat(64),
            subdir: None,
            content: format!("tree:{tree}"),
            inputs: std::collections::BTreeMap::new(),
        };
        let lock = crate::inputs::codec::Lock {
            inputs: std::collections::BTreeMap::from([("language".into(), "language-pin".into())]),
            entries: std::collections::BTreeMap::from([("language-pin".into(), entry)]),
        };
        std::fs::write(root.join("buildutil.lock"), lock.render().unwrap()).unwrap();
        let paths = super::bootstrap_paths(&root).unwrap();
        for required in [
            "buildutil",
            "buildutil.toml",
            crate::source::SOURCE_FILTER_FILE,
            crate::paths::BOOTSTRAP_NINJA,
            "tools/buildutil/buildutil.toml",
            "tools/buildutil/nested/mod.rs",
            "tools/buildutil/lib/mica/lib.rs",
            "tools/buildutil/lib/crypto/sha256.rs",
            crate::paths::SDK_WIRE,
            "tools/buildutil/compose/buildutil.toml",
            "tools/buildutil/compose/lib.rs",
        ] {
            assert!(
                paths.iter().any(|path| path == required),
                "missing {required}"
            );
        }
        assert!(!paths.iter().any(|path| path.ends_with("README.md")));
        let _ = std::fs::remove_dir_all(root);
    }
}
