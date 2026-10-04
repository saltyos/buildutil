//! SPDX-License-Identifier: GPL-2.0-only
//! Declarative, identity-bearing composition policy.

use std::path::{Component, Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    Full,
    Runtime,
}

#[derive(Debug, Clone)]
pub struct ComposeManifest {
    pub filter: Filter,
    pub excludes: Vec<String>,
    pub setup_env_path: String,
    pub emit_setup_env: bool,
    pub emit_provenance: bool,
}

impl ComposeManifest {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read compose manifest {}: {e}", path.display()))?;
        Self::parse(&text, &path.display().to_string())
    }

    pub fn parse(text: &str, context: &str) -> Result<Self, String> {
        let mut schema = None;
        let mut layout = None;
        let mut filter = None;
        let mut setup_env_path = None;
        let mut emit_setup_env = false;
        let mut emit_provenance = false;
        let mut excludes = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once(' ')
                .ok_or_else(|| format!("{context}:{}: expected `key value`", index + 1))?;
            let value = value.trim();
            match key {
                "schema" => schema = Some(value),
                "layout" => layout = Some(value),
                "filter" => {
                    filter = Some(match value {
                        "full" => Filter::Full,
                        "runtime" => Filter::Runtime,
                        _ => {
                            return Err(format!(
                                "{context}:{}: unknown filter `{value}`",
                                index + 1
                            ));
                        }
                    })
                }
                "exclude" => excludes.push(value.to_string()),
                "setup-env-path" => setup_env_path = Some(value.to_string()),
                "emit-setup-env" => emit_setup_env = parse_bool(value, context, index + 1)?,
                "emit-provenance" => emit_provenance = parse_bool(value, context, index + 1)?,
                _ => return Err(format!("{context}:{}: unknown key `{key}`", index + 1)),
            }
        }
        if schema != Some("buildutil-compose-v1") {
            return Err(format!("{context}: schema must be `buildutil-compose-v1`"));
        }
        if layout != Some("fhs") {
            return Err(format!("{context}: layout must be `fhs`"));
        }
        let setup_env_path =
            setup_env_path.ok_or_else(|| format!("{context}: missing setup-env-path"))?;
        let setup_path = Path::new(&setup_env_path);
        if setup_path.is_absolute()
            || setup_path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(format!(
                "{context}: setup-env-path must stay relative: `{setup_env_path}`"
            ));
        }
        Ok(Self {
            filter: filter.ok_or_else(|| format!("{context}: missing filter"))?,
            excludes,
            setup_env_path,
            emit_setup_env,
            emit_provenance,
        })
    }
}

fn parse_bool(value: &str, context: &str, line: usize) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!(
            "{context}:{line}: expected true or false, got `{value}`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{ComposeManifest, Filter};

    #[test]
    fn checked_in_manifests_are_valid_and_distinct() {
        let full = ComposeManifest::parse(
            include_str!("manifests/projection-full.manifest"),
            "projection-full.manifest",
        )
        .unwrap();
        assert_eq!(full.filter, Filter::Full);
        assert!(full.emit_setup_env);
        assert!(!full.emit_provenance);

        let runtime = ComposeManifest::parse(
            include_str!("manifests/projection-runtime.manifest"),
            "projection-runtime.manifest",
        )
        .unwrap();
        assert_eq!(runtime.filter, Filter::Runtime);
        assert!(!runtime.excludes.is_empty());
        assert!(!runtime.emit_setup_env);
        assert!(runtime.emit_provenance);

        let sysroot = ComposeManifest::parse(
            include_str!("manifests/sysroot.manifest"),
            "sysroot.manifest",
        )
        .unwrap();
        assert_eq!(sysroot.filter, Filter::Full);
        assert!(!sysroot.emit_setup_env);
        assert!(!sysroot.emit_provenance);
    }

    #[test]
    fn manifest_contract_fails_closed() {
        let error = ComposeManifest::parse(
            "schema buildutil-compose-v1\nlayout fhs\nfilter full\n",
            "incomplete.manifest",
        )
        .unwrap_err();
        assert!(error.contains("missing setup-env-path"), "{error}");

        let error = ComposeManifest::parse(
            "schema buildutil-compose-v1\nlayout fhs\nfilter full\nsetup-env-path ../escape\n",
            "escape.manifest",
        )
        .unwrap_err();
        assert!(error.contains("must stay relative"), "{error}");
    }
}
