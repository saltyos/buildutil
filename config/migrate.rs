//! SPDX-License-Identifier: GPL-2.0-only
//! Configuration graph seeding from meson.options
//!
//! `buildutil config migrate-options --meson-options <file> --out <dir>` tokenizes the
//! meson `option(...)` calls and emits a starter graph (`seed.toml`) to be
//! hand-annotated (choices, derived options, depends_on) and split into the
//! per-subsystem `config/*.toml` files. This is an authoring aid, not a
//! standing artifact — meson.options is deleted once the graph lands.

use mica::config::diag::{Code, Diagnostic};
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
enum MesonValue {
    Str(String),
    Bool(bool),
    Int(i64),
    Array(Vec<String>),
}

#[derive(Debug)]
struct MesonOption {
    name: String,
    ty: String,
    value: Option<MesonValue>,
    choices: Vec<String>,
    min: Option<i64>,
    max: Option<i64>,
    description: Option<String>,
}

fn strip_comments(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        let mut in_str = false;
        let mut cut = line.len();
        for (i, ch) in line.char_indices() {
            match ch {
                '\'' => in_str = !in_str,
                '#' if !in_str => {
                    cut = i;
                    break;
                }
                _ => {}
            }
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

/// Extract the argument bodies of every top-level `option(...)` call.
fn option_calls(src: &str) -> Result<Vec<String>, Diagnostic> {
    let mut calls = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while let Some(pos) = src[i..].find("option") {
        let start = i + pos;
        let after = start + "option".len();
        // Must be a bare identifier followed by '('.
        let prev_ok =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let mut j = after;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n') {
            j += 1;
        }
        if !prev_ok || j >= bytes.len() || bytes[j] != b'(' {
            i = after;
            continue;
        }
        // Balanced-paren scan, quote-aware.
        let mut depth = 0usize;
        let mut in_str = false;
        let mut k = j;
        let mut end = None;
        while k < bytes.len() {
            match bytes[k] as char {
                '\'' => in_str = !in_str,
                '(' if !in_str => depth += 1,
                ')' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(k);
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        let Some(end) = end else {
            return Err(Diagnostic::new(
                Code::EParse,
                "unbalanced parentheses in option()",
            ));
        };
        calls.push(src[j + 1..end].to_string());
        i = end + 1;
    }
    Ok(calls)
}

/// Split an argument body on top-level commas (quote- and bracket-aware).
fn split_args(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut cur = String::new();
    for ch in body.chars() {
        match ch {
            '\'' => {
                in_str = !in_str;
                cur.push(ch);
            }
            '[' | '(' if !in_str => {
                depth += 1;
                cur.push(ch);
            }
            ']' | ')' if !in_str => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if !in_str && depth == 0 => {
                parts.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(ch),
        }
    }
    let last = cur.trim();
    if !last.is_empty() {
        parts.push(last.to_string());
    }
    parts
}

fn parse_meson_value(s: &str) -> Result<MesonValue, Diagnostic> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('\'') {
        let Some(end) = rest.find('\'') else {
            return Err(Diagnostic::new(
                Code::EParse,
                format!("unterminated string: {}", s),
            ));
        };
        return Ok(MesonValue::Str(rest[..end].to_string()));
    }
    if s == "true" {
        return Ok(MesonValue::Bool(true));
    }
    if s == "false" {
        return Ok(MesonValue::Bool(false));
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        let mut items = Vec::new();
        for part in split_args(inner) {
            match parse_meson_value(&part)? {
                MesonValue::Str(v) => items.push(v),
                _ => {
                    return Err(Diagnostic::new(
                        Code::EParse,
                        format!("non-string array element: {}", part),
                    ));
                }
            }
        }
        return Ok(MesonValue::Array(items));
    }
    if let Ok(n) = s.parse::<i64>() {
        return Ok(MesonValue::Int(n));
    }
    Err(Diagnostic::new(
        Code::EParse,
        format!("unrecognized meson value: {}", s),
    ))
}

fn parse_option_call(body: &str) -> Result<MesonOption, Diagnostic> {
    let args = split_args(body);
    let Some(first) = args.first() else {
        return Err(Diagnostic::new(Code::EParse, "empty option() call"));
    };
    let MesonValue::Str(name) = parse_meson_value(first)? else {
        return Err(Diagnostic::new(
            Code::EParse,
            "option() name must be a string",
        ));
    };
    let mut opt = MesonOption {
        name,
        ty: String::new(),
        value: None,
        choices: Vec::new(),
        min: None,
        max: None,
        description: None,
    };
    for arg in &args[1..] {
        let Some(colon) = arg.find(':') else {
            return Err(Diagnostic::new(
                Code::EParse,
                format!("expected `key: value` in option(): {}", arg),
            ));
        };
        let key = arg[..colon].trim();
        let value = parse_meson_value(&arg[colon + 1..])?;
        match (key, value) {
            ("type", MesonValue::Str(t)) => opt.ty = t,
            ("value", v) => opt.value = Some(v),
            ("choices", MesonValue::Array(items)) => opt.choices = items,
            ("min", MesonValue::Int(n)) => opt.min = Some(n),
            ("max", MesonValue::Int(n)) => opt.max = Some(n),
            ("description", MesonValue::Str(d)) => opt.description = Some(d),
            (k, v) => {
                return Err(Diagnostic::new(
                    Code::EParse,
                    format!("unsupported option() kwarg `{}: {:?}`", k, v),
                ));
            }
        }
    }
    if opt.ty.is_empty() {
        return Err(Diagnostic::new(
            Code::EParse,
            format!("option `{}` has no type", opt.name),
        ));
    }
    Ok(opt)
}

fn seed_entry(opt: &MesonOption) -> Result<String, Diagnostic> {
    let mut out = String::new();
    let upper = opt.name.to_uppercase();
    match opt.ty.as_str() {
        "boolean" => {
            out.push_str(&format!("[option.{}]\n", upper));
            out.push_str("type = \"bool\"\n");
            if let Some(MesonValue::Bool(b)) = &opt.value {
                out.push_str(&format!("default = {}\n", b));
            }
        }
        "string" => {
            out.push_str(&format!("[option.{}]\n", upper));
            out.push_str("type = \"string\"\n");
            if let Some(MesonValue::Str(s)) = &opt.value {
                out.push_str(&format!("default = \"{}\"\n", s));
            }
        }
        "integer" => {
            out.push_str(&format!("[option.{}]\n", upper));
            out.push_str("type = \"int\"\n");
            if let Some(MesonValue::Int(n)) = &opt.value {
                out.push_str(&format!("default = {}\n", n));
            }
            if let Some(n) = opt.min {
                out.push_str(&format!("min = {}\n", n));
            }
            if let Some(n) = opt.max {
                out.push_str(&format!("max = {}\n", n));
            }
        }
        "combo" => {
            out.push_str(&format!("[choice.{}]\n", opt.name));
            if let Some(MesonValue::Str(v)) = &opt.value {
                out.push_str(&format!("default = \"{}_{}\"\n", upper, v.to_uppercase()));
            }
            if let Some(d) = &opt.description {
                out.push_str(&format!("help = \"{}\"\n", d.replace('"', "\\\"")));
            }
            for choice in &opt.choices {
                out.push_str(&format!(
                    "  [choice.{}.option.{}_{}]\n",
                    opt.name,
                    upper,
                    choice.to_uppercase()
                ));
            }
            return Ok(out);
        }
        other => {
            return Err(Diagnostic::new(
                Code::EParse,
                format!("option `{}`: unsupported meson type `{}`", opt.name, other),
            ));
        }
    }
    if let Some(d) = &opt.description {
        out.push_str(&format!("help = \"{}\"\n", d.replace('"', "\\\"")));
    }
    Ok(out)
}

/// Read meson.options and write `<out_dir>/seed.toml`.
pub fn migrate(meson_options: &Path, out_dir: &Path) -> Result<usize, Vec<Diagnostic>> {
    let src = std::fs::read_to_string(meson_options).map_err(|e| {
        vec![Diagnostic::new(
            Code::EParse,
            format!("cannot read {}: {}", meson_options.display(), e),
        )]
    })?;
    let cleaned = strip_comments(&src);
    let calls = option_calls(&cleaned).map_err(|d| vec![d])?;
    let mut out = String::from(
        "# SPDX-License-Identifier: GPL-2.0-only\n\
         # Seeded from meson.options by `buildutil config migrate-options` — hand-annotate\n\
         # (depends_on / select / computed derived options) and split into the\n\
         # per-subsystem config/*.toml files.\n",
    );
    let mut errors = Vec::new();
    let mut count = 0;
    for call in &calls {
        match parse_option_call(call).and_then(|opt| seed_entry(&opt)) {
            Ok(entry) => {
                out.push('\n');
                out.push_str(&entry);
                count += 1;
            }
            Err(d) => errors.push(d),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        return Err(vec![Diagnostic::new(
            Code::EParse,
            format!("cannot create {}: {}", out_dir.display(), e),
        )]);
    }
    let path = out_dir.join("seed.toml");
    if let Err(e) = std::fs::write(&path, out) {
        return Err(vec![Diagnostic::new(
            Code::EParse,
            format!("cannot write {}: {}", path.display(), e),
        )]);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# Comment
option('arch',
  type: 'combo',
  choices: ['x86_64', 'aarch64'],
  value: 'x86_64',
  description: 'Target CPU architecture')

option('build_boot',
  type: 'boolean',
  value: true,
  description: 'Build the bootloader')

option('kernel_stack_size',
  type: 'integer',
  min: 4096,
  max: 65536,
  value: 16384,
  description: 'Kernel stack size')

option('kernel_debug_modules',
  type: 'string',
  value: '',
  description: 'Comma-separated modules (e.g., mm,ipc)')
"#;

    #[test]
    fn parses_all_call_shapes() {
        let cleaned = strip_comments(SAMPLE);
        let calls = option_calls(&cleaned).unwrap();
        assert_eq!(calls.len(), 4);
        let opts: Vec<MesonOption> = calls
            .iter()
            .map(|c| parse_option_call(c).unwrap())
            .collect();
        assert_eq!(opts[0].name, "arch");
        assert_eq!(opts[0].ty, "combo");
        assert_eq!(opts[0].choices, vec!["x86_64", "aarch64"]);
        assert_eq!(opts[1].value, Some(MesonValue::Bool(true)));
        assert_eq!(opts[2].min, Some(4096));
        assert_eq!(opts[2].max, Some(65536));
        // The description's parenthesized comma-list must not confuse the
        // splitter (quote-aware).
        assert_eq!(opts[3].name, "kernel_debug_modules");
    }

    #[test]
    fn seed_shapes() {
        let cleaned = strip_comments(SAMPLE);
        let calls = option_calls(&cleaned).unwrap();
        let combo = seed_entry(&parse_option_call(&calls[0]).unwrap()).unwrap();
        assert!(combo.contains("[choice.arch]"));
        assert!(combo.contains("default = \"ARCH_X86_64\""));
        assert!(combo.contains("[choice.arch.option.ARCH_AARCH64]"));
        let boolean = seed_entry(&parse_option_call(&calls[1]).unwrap()).unwrap();
        assert!(boolean.contains("[option.BUILD_BOOT]"));
        assert!(boolean.contains("default = true"));
        let integer = seed_entry(&parse_option_call(&calls[2]).unwrap()).unwrap();
        assert!(integer.contains("min = 4096"));
        assert!(integer.contains("max = 65536"));
    }
}
