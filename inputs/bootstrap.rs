// SPDX-License-Identifier: GPL-2.0-only
//! Content verification shared by the standalone bootstrap checker and the engine.

use super::{codec, content};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) fn projection_path(name: &str, declaration: &codec::Declaration) -> String {
    declaration
        .path
        .clone()
        .unwrap_or_else(|| format!("buildutil-inputs/{name}"))
}

/// Every bootstrap read is selected by the root specification and pinned by its lock.
pub(crate) fn selections(
    root: &Path,
    overrides: &BTreeMap<String, PathBuf>,
) -> Result<Vec<(String, PathBuf, String)>, String> {
    let mut selected_overrides = BTreeMap::new();
    if let Some(path) = std::env::var_os("BUILDUTIL_BOOTSTRAP_SELECTION") {
        let doc = crate::input_toml::parse_file(Path::new(&path))?;
        let table = doc
            .table(&["selection"])
            .ok_or("bootstrap selection lacks [selection]")?;
        for entry in &table.entries {
            codec::name(&entry.key)?;
            let path = entry
                .value
                .as_str()
                .ok_or("bootstrap selection path is not a string")?;
            if !Path::new(path).is_absolute() {
                return Err("bootstrap selection path is not absolute".into());
            }
            selected_overrides.insert(entry.key.clone(), PathBuf::from(path));
        }
    }
    selected_overrides.extend(
        overrides
            .iter()
            .map(|(name, path)| (name.clone(), path.clone())),
    );
    let doc = crate::input_toml::parse_file(&root.join("buildutil.toml"))?;
    let declarations = codec::declarations(&doc)?;
    let names = codec::bootstrap_inputs(&doc)?;
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let lock = codec::Lock::read(&root.join("buildutil.lock"))?.ok_or_else(|| {
        format!(
            "bootstrap: missing buildutil.lock [input.{}] entry",
            names[0]
        )
    })?;
    let mut out = Vec::new();
    for name in names {
        let declaration = declarations
            .get(&name)
            .ok_or_else(|| format!("bootstrap: undeclared input `{name}`"))?;
        let entry_name = lock
            .inputs
            .get(&name)
            .ok_or_else(|| format!("bootstrap: missing buildutil.lock [input.{name}] entry"))?;
        let entry = &lock.entries[entry_name];
        let selected = match selected_overrides.get(&name) {
            Some(path) => path.clone(),
            None => root.join(projection_path(&name, declaration)),
        };
        let excluded = if declaration.source {
            Vec::new()
        } else {
            codec::declarations(&crate::input_toml::parse_file(
                &selected.join("buildutil.toml"),
            )?)?
            .values()
            .filter_map(|input| input.path.clone())
            .collect()
        };
        let actual = format!("tree:{}", content::capture(&selected, &excluded)?.hash());
        if actual != entry.content {
            return Err(format!(
                "bootstrap: selected input `{name}` content {actual} differs from buildutil.lock [input.{entry_name}].content = {}",
                entry.content
            ));
        }
        out.push((name, selected, actual));
    }
    Ok(out)
}

pub(crate) fn verify(root: &Path) -> Result<String, String> {
    let mut proof = String::new();
    for (name, _, content) in selections(root, &BTreeMap::new())? {
        proof.push_str(&format!("{name} {content}\n"));
    }
    Ok(crate::input_sha256::hash_bytes(proof.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_compares_selected_content_with_the_named_lock_entry() {
        let root = std::env::temp_dir().join(format!(
            "buildutil-bootstrap-content-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("library")).unwrap();
        std::fs::write(root.join("library/lib.rs"), "pub fn value() {}\n").unwrap();
        std::fs::write(root.join("library/.buildutilignore"), "scratch\n").unwrap();
        std::fs::write(root.join("buildutil.toml"), "[lock]\nbootstrap-inputs = [\"config-library\"]\n[input.config-library]\nkind = \"source\"\nurl = \"https://example.org/library/{rev}.tar.gz\"\npath = \"library\"\n").unwrap();
        let tree = format!(
            "tree:{}",
            content::capture(&root.join("library"), &[]).unwrap().hash()
        );
        let entry = codec::Entry {
            url: "https://example.org/library/release.tar.gz".into(),
            rev: "1".repeat(40),
            sha256: "2".repeat(64),
            subdir: None,
            content: tree,
            inputs: BTreeMap::new(),
        };
        let lock = codec::Lock {
            inputs: BTreeMap::from([("config-library".into(), "configuration-pin".into())]),
            entries: BTreeMap::from([("configuration-pin".into(), entry)]),
        };
        std::fs::write(root.join("buildutil.lock"), lock.render().unwrap()).unwrap();
        assert!(verify(&root).is_ok());
        std::fs::write(root.join("library/scratch"), "unselected changes\n").unwrap();
        assert!(verify(&root).is_ok());
        std::fs::write(root.join("library/lib.rs"), "pub fn changed() {}\n").unwrap();
        assert!(
            verify(&root)
                .unwrap_err()
                .contains("[input.configuration-pin].content")
        );
        std::fs::remove_file(root.join("buildutil.lock")).unwrap();
        assert!(
            verify(&root)
                .unwrap_err()
                .contains("[input.config-library]")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
