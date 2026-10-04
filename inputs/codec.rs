// SPDX-License-Identifier: GPL-2.0-only
//! Repository declarations and canonical content locks, independent of the evaluator.

use crate::input_toml::{Doc, Table, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

/// A repository edge declared by its consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub(crate) url: String,
    pub(crate) path: Option<String>,
    pub(crate) source: bool,
    pub(crate) subdir: Option<String>,
    pub(crate) api_level: Option<(u32, u32)>,
    pub(crate) min_api_level: Option<(u32, u32)>,
}

/// A verified archive and the selected repository tree it supplies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) url: String,
    pub(crate) rev: String,
    pub(crate) sha256: String,
    pub(crate) subdir: Option<String>,
    pub(crate) content: String,
    pub(crate) inputs: BTreeMap<String, String>,
}

/// Root-local edges and their resolved, possibly shared, repository entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Lock {
    pub(crate) inputs: BTreeMap<String, String>,
    pub(crate) entries: BTreeMap<String, Entry>,
}

pub(crate) fn name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(format!("invalid input name `{value}`"));
    }
    Ok(())
}

pub(crate) fn clean_path(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.contains(['\\', ':'])
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part == ".git")
        || Path::new(value)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!(
            "input path must be clean and repository-relative: `{value}`"
        ));
    }
    Ok(())
}

pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn string(table: &Table, key: &str, context: &str) -> Result<String, String> {
    table
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{context}: missing string `{key}`"))
}

fn optional(table: &Table, key: &str, context: &str) -> Result<Option<String>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::Str(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{context}.{key} must be a string")),
    }
}

fn keys(table: &Table, allowed: &[&str], context: &str) -> Result<(), String> {
    if table.is_array {
        return Err(format!("{context}: an array of tables is not allowed"));
    }
    for entry in &table.entries {
        if !allowed.contains(&entry.key.as_str()) {
            return Err(format!("{context}: unknown key `{}`", entry.key));
        }
    }
    Ok(())
}

fn mapping(table: &Table, key: &str, context: &str) -> Result<BTreeMap<String, String>, String> {
    let Some(Value::Inline(items)) = table.get(key) else {
        return Err(format!("{context}.{key} must be an inline table"));
    };
    let mut out = BTreeMap::new();
    for (local, value) in items {
        name(local)?;
        let target = value
            .as_str()
            .ok_or_else(|| format!("{context}.{key}.{local} must name an entry"))?;
        name(target)?;
        if out.insert(local.clone(), target.to_string()).is_some() {
            return Err(format!("{context}.{key}: duplicate input `{local}`"));
        }
    }
    Ok(out)
}

fn level(value: Option<String>, context: &str) -> Result<Option<(u32, u32)>, String> {
    value
        .map(|value| {
            let (major, minor) = value
                .split_once('.')
                .ok_or_else(|| format!("{context}: expected major.minor"))?;
            Ok((
                major
                    .parse()
                    .map_err(|_| format!("{context}: invalid major"))?,
                minor
                    .parse()
                    .map_err(|_| format!("{context}: invalid minor"))?,
            ))
        })
        .transpose()
}

pub(crate) fn declarations(doc: &Doc) -> Result<BTreeMap<String, Declaration>, String> {
    let mut out = BTreeMap::new();
    for table in doc.tables_under(&["input"]) {
        if table.path.len() != 2 {
            return Err(format!(
                "invalid input declaration [{}]",
                table.path.join(".")
            ));
        }
        let local = &table.path[1];
        name(local)?;
        let context = format!("[input.{local}]");
        keys(
            table,
            &[
                "url",
                "path",
                "kind",
                "subdir",
                "api-level",
                "min-api-level",
            ],
            &context,
        )?;
        let url = string(table, "url", &context)?;
        if url.is_empty() || url.chars().any(char::is_control) {
            return Err(format!("{context}: invalid origin URL"));
        }
        let path = optional(table, "path", &context)?;
        let subdir = optional(table, "subdir", &context)?;
        for path in path.iter().chain(subdir.iter()) {
            clean_path(path)?;
        }
        let source = match optional(table, "kind", &context)?.as_deref() {
            None => false,
            Some("source") => true,
            Some(kind) => return Err(format!("{context}: unknown kind `{kind}`")),
        };
        let declaration = Declaration {
            url,
            path,
            source,
            subdir,
            api_level: level(optional(table, "api-level", &context)?, &context)?,
            min_api_level: level(optional(table, "min-api-level", &context)?, &context)?,
        };
        if out.insert(local.clone(), declaration).is_some() {
            return Err(format!("duplicate input `{local}`"));
        }
    }
    Ok(out)
}

/// Bootstrap reads are an explicit policy of the root specification.
pub(crate) fn bootstrap_inputs(doc: &Doc) -> Result<Vec<String>, String> {
    let Some(table) = doc.table(&["lock"]) else {
        return Ok(Vec::new());
    };
    keys(table, &["bootstrap-inputs", "fetch-stage"], "[lock]")?;
    let _ = optional(table, "fetch-stage", "[lock]")?;
    let mut names = match table.get("bootstrap-inputs") {
        None => Vec::new(),
        Some(value) => value
            .str_items()
            .ok_or("[lock].bootstrap-inputs must be a string array")?,
    };
    names.sort();
    let mut previous = None;
    for value in &names {
        name(value)?;
        if previous == Some(value) {
            return Err(format!("duplicate bootstrap input `{value}`"));
        }
        previous = Some(value);
    }
    Ok(names)
}

pub(crate) fn minimum(root: &Declaration, nested: &Declaration, path: &str) -> Result<(), String> {
    if let Some((major, minor)) = nested.min_api_level {
        match root.api_level {
            Some((provided_major, provided_minor))
                if major == provided_major && minor <= provided_minor => {}
            _ => {
                return Err(format!(
                    "input `{path}` requires API level {major}.{minor}, incompatible with its root resolution"
                ));
            }
        }
    }
    Ok(())
}

impl Lock {
    pub(crate) fn read(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(path, &text).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        }
    }

    pub(crate) fn parse(path: &Path, text: &str) -> Result<Self, String> {
        let doc = crate::input_toml::parse(path, text)?;
        let table = doc
            .table(&["lock"])
            .ok_or("buildutil.lock: missing [lock]")?;
        keys(table, &["format", "inputs"], "buildutil.lock [lock]")?;
        if table.get("format") != Some(&Value::Int(1)) {
            return Err("buildutil.lock: unsupported lock format (expected 1)".to_string());
        }
        let mut lock = Self {
            inputs: mapping(table, "inputs", "[lock]")?,
            entries: BTreeMap::new(),
        };
        for table in &doc.tables {
            match table.path.as_slice() {
                [] if table.entries.is_empty() => {}
                [kind] if kind == "lock" => {}
                [kind, entry_name] if kind == "input" => {
                    name(entry_name)?;
                    let context = format!("buildutil.lock [input.{entry_name}]");
                    keys(
                        table,
                        &["url", "rev", "sha256", "content", "subdir", "inputs"],
                        &context,
                    )?;
                    let entry = Entry {
                        url: string(table, "url", &context)?,
                        rev: string(table, "rev", &context)?,
                        sha256: string(table, "sha256", &context)?,
                        content: string(table, "content", &context)?,
                        subdir: optional(table, "subdir", &context)?,
                        inputs: mapping(table, "inputs", &context)?,
                    };
                    if lock.entries.insert(entry_name.clone(), entry).is_some() {
                        return Err(format!("{context}: duplicate entry"));
                    }
                }
                _ => {
                    return Err(format!(
                        "buildutil.lock: invalid table [{}]",
                        table.path.join(".")
                    ));
                }
            }
        }
        lock.validate()?;
        Ok(lock)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        for (entry_name, entry) in &self.entries {
            name(entry_name)?;
            let context = format!("buildutil.lock [input.{entry_name}]");
            if !hex(&entry.sha256, 64)
                || !entry
                    .content
                    .strip_prefix("tree:")
                    .is_some_and(|hash| hex(hash, 64))
            {
                return Err(format!("{context}: malformed sha256 or content address"));
            }
            if !(hex(&entry.rev, 40) || hex(&entry.rev, 64)) {
                return Err(format!("{context}: rev must be a full committed revision"));
            }
            if !entry.url.contains("://")
                || entry.url.contains(['{', '}'])
                || entry.url.chars().any(char::is_control)
            {
                return Err(format!(
                    "{context}: url must name an archive location, without a checkout path or template"
                ));
            }
            if let Some(subdir) = &entry.subdir {
                clean_path(subdir)?;
            }
        }
        let check_edges = |edges: &BTreeMap<String, String>| -> Result<(), String> {
            for (local, target) in edges {
                name(local)?;
                name(target)?;
                if !self.entries.contains_key(target) {
                    return Err(format!(
                        "buildutil.lock: input `{local}` names missing entry `{target}`"
                    ));
                }
            }
            Ok(())
        };
        check_edges(&self.inputs)?;
        for entry in self.entries.values() {
            check_edges(&entry.inputs)?;
        }
        fn visit(
            lock: &Lock,
            value: &str,
            active: &mut BTreeSet<String>,
            done: &mut BTreeSet<String>,
        ) -> Result<(), String> {
            if done.contains(value) {
                return Ok(());
            }
            if !active.insert(value.to_string()) {
                return Err(format!("buildutil.lock: cycle through input `{value}`"));
            }
            for child in lock.entries[value].inputs.values() {
                visit(lock, child, active, done)?;
            }
            active.remove(value);
            done.insert(value.to_string());
            Ok(())
        }
        let mut active = BTreeSet::new();
        let mut done = BTreeSet::new();
        for value in self.entries.keys() {
            visit(self, value, &mut active, &mut done)?;
        }
        Ok(())
    }

    /// Deterministic LF text; paths of local checkouts never enter this representation.
    pub(crate) fn render(&self) -> Result<String, String> {
        self.validate()?;
        let mut text = format!(
            "[lock]\nformat = 1\ninputs = {}\n",
            render_map(&self.inputs)
        );
        for (entry_name, entry) in &self.entries {
            text.push_str(&format!("\n[input.{entry_name}]\n"));
            for (key, value) in [
                ("url", &entry.url),
                ("rev", &entry.rev),
                ("sha256", &entry.sha256),
                ("content", &entry.content),
            ] {
                text.push_str(&format!("{key} = {}\n", quote(value)));
            }
            if let Some(subdir) = &entry.subdir {
                text.push_str(&format!("subdir = {}\n", quote(subdir)));
            }
            text.push_str(&format!("inputs = {}\n", render_map(&entry.inputs)));
        }
        Ok(text)
    }
}

fn quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    )
}

fn render_map(map: &BTreeMap<String, String>) -> String {
    format!(
        "{{ {} }}",
        map.iter()
            .map(|(key, value)| format!("{key} = {}", quote(value)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Lock {
        Lock {
            inputs: BTreeMap::from([("source".into(), "source".into())]),
            entries: BTreeMap::from([(
                "source".into(),
                Entry {
                    url: "https://example.org/source.tar.gz".into(),
                    rev: "1".repeat(40),
                    sha256: "2".repeat(64),
                    content: format!("tree:{}", "3".repeat(64)),
                    subdir: Some("source".into()),
                    inputs: BTreeMap::new(),
                },
            )]),
        }
    }
    #[test]
    fn canonical_lock_roundtrips_and_has_no_checkout_path() {
        let lock = sample();
        let text = lock.render().unwrap();
        assert_eq!(
            Lock::parse(Path::new("buildutil.lock"), &text).unwrap(),
            lock
        );
        assert!(text.ends_with('\n'));
        assert!(!text.contains("path ="));
    }
    #[test]
    fn malformed_and_cyclic_locks_are_refused() {
        let mut lock = sample();
        lock.entries
            .get_mut("source")
            .unwrap()
            .inputs
            .insert("self".into(), "source".into());
        assert!(lock.validate().unwrap_err().contains("cycle"));
        let text = sample().render().unwrap();
        for text in [
            text.replace("format = 1", "format = 2"),
            text.replace("tree:", "blob:"),
            text.replace("sha256 =", "absent ="),
        ] {
            assert!(Lock::parse(Path::new("buildutil.lock"), &text).is_err());
        }
    }
    #[test]
    fn minimum_api_levels_hold_with_or_without_a_lock() {
        let doc = crate::input_toml::parse(Path::new("buildutil.toml"), "[input.a]\nurl = \"https://example.org/a\"\napi-level = \"1.4\"\n[input.b]\nurl = \"https://example.org/a\"\nmin-api-level = \"1.3\"\n").unwrap();
        let inputs = declarations(&doc).unwrap();
        assert!(minimum(&inputs["a"], &inputs["b"], "b").is_ok());
        let mut bad = inputs["b"].clone();
        bad.min_api_level = Some((2, 0));
        assert!(minimum(&inputs["a"], &bad, "b").is_err());
    }
}
