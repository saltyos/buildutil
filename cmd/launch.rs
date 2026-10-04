// SPDX-License-Identifier: GPL-2.0-only
//! Declarative launcher configuration from the repository's `[launch]` tables.

use crate::spec::toml::{self, Doc, Table, Value};
use std::path::Path;

#[derive(Clone)]
pub struct Image {
    pub build_target: String,
    pub file: String,
}

#[derive(Clone)]
pub enum VerdictMatch {
    Contains(String),
    Exact(String),
    HexNonzeroAfter(String),
    Timeout,
}

#[derive(Clone)]
pub struct Verdict {
    pub label: String,
    pub matcher: VerdictMatch,
    pub code: i32,
    pub kill: bool,
}

impl Verdict {
    pub fn matches_line(&self, line: &str) -> bool {
        match &self.matcher {
            VerdictMatch::Contains(pattern) => line.contains(pattern),
            VerdictMatch::Exact(pattern) => line == pattern,
            VerdictMatch::HexNonzeroAfter(pattern) => line
                .find(pattern)
                .and_then(|index| line[index + pattern.len()..].split_whitespace().next())
                .map(|word| word.trim_start_matches("0x").trim_start_matches("0X"))
                .and_then(|word| u64::from_str_radix(word, 16).ok())
                .is_some_and(|value| value != 0),
            VerdictMatch::Timeout => false,
        }
    }

    pub fn matches_timeout(&self) -> bool {
        matches!(&self.matcher, VerdictMatch::Timeout)
    }
}

#[derive(Clone)]
pub struct Test {
    /// The test images: packages whose configuration is part of their
    /// identity (configuration variants), by firmware.
    default_image: Image,
    uefi_image: Image,
    pub smp_passes: Vec<u32>,
    pub wall_timeout_secs: u64,
    pub inactivity_timeout_secs: u64,
    pub kill_grace_secs: u64,
    pub no_verdict_code: i32,
    pub verdicts: Vec<Verdict>,
}

#[derive(Clone)]
pub struct Gdb {
    pub program: String,
    pub build_target: String,
    pub symbol_file: String,
    pub remote: String,
}

pub struct Launch {
    pub command: Vec<String>,
    uefi_arches: Vec<String>,
    default_image: Image,
    uefi_image: Image,
    pub test: Test,
    pub gdb: Gdb,
}

impl Launch {
    pub fn load(repo_root: &Path) -> Result<Self, String> {
        let path = repo_root.join("buildutil.toml");
        let doc = toml::parse_file(&path)?;
        let launch = need_table(&doc, &["launch"])?;
        let command = need_str_list(launch, "command", "[launch]")?;
        if command.is_empty() {
            return Err("[launch].command must not be empty".to_string());
        }
        let uefi_arches = need_str_list(launch, "uefi-arches", "[launch]")?;
        let default_image = parse_image(&doc, "default")?;
        let uefi_image = parse_image(&doc, "uefi")?;
        let test = parse_test(&doc)?;
        let gdb = parse_gdb(&doc)?;
        Ok(Self {
            command,
            uefi_arches,
            default_image,
            uefi_image,
            test,
            gdb,
        })
    }

    pub fn image(&self, arch: &str, force_uefi: bool) -> &Image {
        if self.uses_uefi(arch, force_uefi) {
            &self.uefi_image
        } else {
            &self.default_image
        }
    }

    pub fn test_image(&self, arch: &str, force_uefi: bool) -> &Image {
        if self.uses_uefi(arch, force_uefi) {
            &self.test.uefi_image
        } else {
            &self.test.default_image
        }
    }

    fn uses_uefi(&self, arch: &str, force_uefi: bool) -> bool {
        force_uefi || self.uefi_arches.iter().any(|candidate| candidate == arch)
    }
}

impl Image {
    pub fn build_invocation(&self, arch: &str, dev: bool) -> String {
        let verb = if dev { "dev" } else { "build" };
        format!("buildutil {verb} {} --arch {arch}", self.build_target)
    }
}

/// The rootfs image and configuration required by its declared package closure.
pub(crate) struct Rootfs {
    pub(crate) image: Image,
    pub(crate) config: Vec<(String, String)>,
}

impl Rootfs {
    /// Read the base or port projection from the root's launcher declarations.
    pub(crate) fn load(root: &Path, with_ports: bool) -> Result<Self, String> {
        let doc = toml::parse_file(&root.join("buildutil.toml"))?;
        let path = [
            "launch",
            "rootfs",
            if with_ports { "ports" } else { "default" },
        ];
        let image = parse_image_at(&doc, &path)?;
        crate::inputs::codec::clean_path(&image.file)?;
        let table = need_table(&doc, &path)?;
        let mut config = Vec::new();
        match table.get("config") {
            None => {}
            Some(Value::Inline(values)) => {
                for (key, value) in values {
                    let value = match value {
                        Value::Str(value) => value.clone(),
                        Value::Bool(value) => value.to_string(),
                        Value::Int(value) => value.to_string(),
                        _ => {
                            return Err(format!(
                                "[{}].config.{key} must be a scalar",
                                path.join(".")
                            ));
                        }
                    };
                    if config.iter().any(|(other, _)| other == key) {
                        return Err(format!("duplicate rootfs configuration key `{key}`"));
                    }
                    config.push((key.clone(), value));
                }
            }
            Some(_) => {
                return Err(format!(
                    "[{}].config must be an inline table",
                    path.join(".")
                ));
            }
        }
        Ok(Self { image, config })
    }
}

fn need_table<'a>(doc: &'a Doc, path: &[&str]) -> Result<&'a Table, String> {
    doc.table(path)
        .ok_or_else(|| format!("missing [{}] table in buildutil.toml", path.join(".")))
}

fn need_value<'a>(table: &'a Table, key: &str, context: &str) -> Result<&'a Value, String> {
    table
        .get(key)
        .ok_or_else(|| format!("{context}: missing `{key}`"))
}

fn need_str(table: &Table, key: &str, context: &str) -> Result<String, String> {
    need_value(table, key, context)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{context}.{key} must be a string"))
}

fn optional_bool(table: &Table, key: &str, context: &str) -> Result<bool, String> {
    match table.get(key) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("{context}.{key} must be a boolean")),
        None => Ok(false),
    }
}

fn need_int(table: &Table, key: &str, context: &str) -> Result<i64, String> {
    match need_value(table, key, context)? {
        Value::Int(value) => Ok(*value),
        _ => Err(format!("{context}.{key} must be an integer")),
    }
}

fn need_u64(table: &Table, key: &str, context: &str) -> Result<u64, String> {
    need_int(table, key, context)?
        .try_into()
        .map_err(|_| format!("{context}.{key} must be non-negative"))
}

fn need_i32(table: &Table, key: &str, context: &str) -> Result<i32, String> {
    need_int(table, key, context)?
        .try_into()
        .map_err(|_| format!("{context}.{key} is outside the i32 range"))
}

fn need_str_list(table: &Table, key: &str, context: &str) -> Result<Vec<String>, String> {
    need_value(table, key, context)?
        .str_items()
        .ok_or_else(|| format!("{context}.{key} must be an array of strings"))
}

fn need_u32_list(table: &Table, key: &str, context: &str) -> Result<Vec<u32>, String> {
    let Value::Array(items) = need_value(table, key, context)? else {
        return Err(format!("{context}.{key} must be an array of integers"));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Int(value) = item else {
            return Err(format!("{context}.{key} must be an array of integers"));
        };
        out.push(
            (*value)
                .try_into()
                .map_err(|_| format!("{context}.{key} entries must fit in u32"))?,
        );
    }
    if out.is_empty() {
        return Err(format!("{context}.{key} must not be empty"));
    }
    Ok(out)
}

fn parse_image(doc: &Doc, variant: &str) -> Result<Image, String> {
    parse_image_at(doc, &["launch", "image", variant])
}

fn parse_image_at(doc: &Doc, path: &[&str]) -> Result<Image, String> {
    let context = format!("[{}]", path.join("."));
    let table = need_table(doc, path)?;
    Ok(Image {
        build_target: need_str(table, "build-target", &context)?,
        file: need_str(table, "file", &context)?,
    })
}

fn parse_test(doc: &Doc) -> Result<Test, String> {
    let context = "[launch.test]";
    let table = need_table(doc, &["launch", "test"])?;
    let mut verdicts = Vec::new();
    for table in doc.tables.iter().filter(|table| {
        table.is_array
            && table.path.len() == 3
            && table.path[0] == "launch"
            && table.path[1] == "test"
            && table.path[2] == "verdict"
    }) {
        let row = "[[launch.test.verdict]]";
        let label = need_str(table, "label", row)?;
        let kind = need_str(table, "match", row)?;
        let matcher = match kind.as_str() {
            "contains" => VerdictMatch::Contains(need_str(table, "pattern", row)?),
            "exact" => VerdictMatch::Exact(need_str(table, "pattern", row)?),
            "hex-nonzero-after" => VerdictMatch::HexNonzeroAfter(need_str(table, "pattern", row)?),
            "timeout" => VerdictMatch::Timeout,
            _ => return Err(format!("{row}: unknown match kind `{kind}`")),
        };
        verdicts.push(Verdict {
            label,
            matcher,
            code: need_i32(table, "code", row)?,
            kill: optional_bool(table, "kill", row)?,
        });
    }
    if verdicts.is_empty() {
        return Err("[launch.test]: at least one verdict row is required".to_string());
    }
    Ok(Test {
        default_image: parse_image_at(doc, &["launch", "test", "image", "default"])?,
        uefi_image: parse_image_at(doc, &["launch", "test", "image", "uefi"])?,
        smp_passes: need_u32_list(table, "smp-passes", context)?,
        wall_timeout_secs: need_u64(table, "wall-timeout-secs", context)?,
        inactivity_timeout_secs: need_u64(table, "inactivity-timeout-secs", context)?,
        kill_grace_secs: need_u64(table, "kill-grace-secs", context)?,
        no_verdict_code: need_i32(table, "no-verdict-code", context)?,
        verdicts,
    })
}

fn parse_gdb(doc: &Doc) -> Result<Gdb, String> {
    let context = "[launch.gdb]";
    let table = need_table(doc, &["launch", "gdb"])?;
    Ok(Gdb {
        program: need_str(table, "program", context)?,
        build_target: need_str(table, "build-target", context)?,
        symbol_file: need_str(table, "symbol-file", context)?,
        remote: need_str(table, "remote", context)?,
    })
}

#[cfg(test)]
mod rootfs_tests {
    #[test]
    fn rootfs_variants_read_their_target_file_and_required_configuration() {
        let root =
            std::env::temp_dir().join(format!("buildutil-rootfs-launch-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("buildutil.toml"), "[launch.rootfs.default]\nbuild-target = \"base-image\"\nfile = \"base.img\"\n[launch.rootfs.ports]\nbuild-target = \"package-image\"\nfile = \"packages.img\"\nconfig = { ENABLE_PACKAGES = true }\n").unwrap();
        let base = super::Rootfs::load(&root, false).unwrap();
        let packages = super::Rootfs::load(&root, true).unwrap();
        assert_eq!(base.image.build_target, "base-image");
        assert_eq!(base.image.file, "base.img");
        assert!(base.config.is_empty());
        assert_eq!(packages.image.build_target, "package-image");
        assert_eq!(
            packages.config,
            vec![("ENABLE_PACKAGES".into(), "true".into())]
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
