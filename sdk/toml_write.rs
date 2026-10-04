// SPDX-License-Identifier: GPL-2.0-only
//! Writing buildutil's TOML subset: the text a generator returns as derivation
//! declarations and kind-table contributions. The values are the reader's
//! own (`toml::Value`), so everything written here reads back unchanged.

use crate::toml::Value;

/// One table or array-of-tables element in declaration order.
struct Section {
    path: Vec<String>,
    array: bool,
    entries: Vec<(String, Value)>,
}

/// A document built table by table.
#[derive(Default)]
pub struct Document {
    sections: Vec<Section>,
}

/// A handle to the section most recently opened.
pub struct SectionRef<'a> {
    entries: &'a mut Vec<(String, Value)>,
}

impl SectionRef<'_> {
    pub fn set(&mut self, key: &str, value: Value) -> &mut Self {
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
        } else {
            self.entries.push((key.to_string(), value));
        }
        self
    }

    pub fn str(&mut self, key: &str, value: impl Into<String>) -> &mut Self {
        self.set(key, Value::Str(value.into()))
    }

    pub fn bool(&mut self, key: &str, value: bool) -> &mut Self {
        self.set(key, Value::Bool(value))
    }

    pub fn list<I, S>(&mut self, key: &str, items: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.set(
            key,
            Value::Array(items.into_iter().map(|s| Value::Str(s.into())).collect()),
        )
    }
}

impl Document {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open `[path]`; a table opened twice is refused when rendered.
    pub fn table(&mut self, path: &[&str]) -> SectionRef<'_> {
        self.sections.push(Section {
            path: path.iter().map(|p| p.to_string()).collect(),
            array: false,
            entries: Vec::new(),
        });
        let last = self.sections.len() - 1;
        SectionRef {
            entries: &mut self.sections[last].entries,
        }
    }

    /// Open one more `[[path]]` element.
    pub fn array_table(&mut self, path: &[&str]) -> SectionRef<'_> {
        self.sections.push(Section {
            path: path.iter().map(|p| p.to_string()).collect(),
            array: true,
            entries: Vec::new(),
        });
        let last = self.sections.len() - 1;
        SectionRef {
            entries: &mut self.sections[last].entries,
        }
    }

    pub fn render(&self) -> Result<String, String> {
        let mut out = String::new();
        let mut seen = std::collections::BTreeSet::new();
        for section in &self.sections {
            for part in &section.path {
                check_key(part)?;
            }
            if !section.array && !seen.insert(section.path.clone()) {
                return Err(format!("table [{}] is written twice", section.path.join(".")));
            }
            if !out.is_empty() {
                out.push('\n');
            }
            if section.array {
                out.push_str(&format!("[[{}]]\n", section.path.join(".")));
            } else {
                out.push_str(&format!("[{}]\n", section.path.join(".")));
            }
            for (key, value) in &section.entries {
                check_key(key)?;
                out.push_str(key);
                out.push_str(" = ");
                render_value(value, &mut out)?;
                out.push('\n');
            }
        }
        Ok(out)
    }
}

fn check_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!("`{key}` is not a bare key"));
    }
    Ok(())
}

/// Render one value on one line. The reader accepts the escapes `\"`,
/// `\\`, `\n` and `\t`; any other control character cannot be written.
pub fn render_value(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Str(text) => {
            out.push('"');
            for ch in text.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\t' => out.push_str("\\t"),
                    c if c.is_control() => {
                        return Err(format!(
                            "a string holds control character U+{:04X}, which the TOML subset cannot carry",
                            c as u32
                        ));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Int(number) => out.push_str(&number.to_string()),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                render_value(item, out)?;
            }
            out.push(']');
        }
        Value::Inline(pairs) => {
            out.push('{');
            for (index, (key, item)) in pairs.iter().enumerate() {
                check_key(key)?;
                out.push_str(if index > 0 { ", " } else { " " });
                out.push_str(key);
                out.push_str(" = ");
                render_value(item, out)?;
            }
            out.push_str(if pairs.is_empty() { "}" } else { " }" });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_written_declarations_read_back() {
        let mut doc = Document::new();
        doc.table(&["derivation", "port-demo"])
            .str("builder", "module")
            .list("deps", ["a", "b"])
            .set(
                "env",
                Value::Inline(vec![("SCRIPT".into(), Value::Str("a \"b\"\nc\\d".into()))]),
            );
        doc.table(&["packages"]).list("expose", ["port-demo"]);
        let text = doc.render().unwrap();
        let parsed = crate::toml::parse(std::path::Path::new("generated.toml"), &text).unwrap();
        let table = parsed.table(&["derivation", "port-demo"]).unwrap();
        assert_eq!(table.get("builder").unwrap().as_str(), Some("module"));
        match table.get("env").unwrap() {
            Value::Inline(pairs) => {
                assert_eq!(pairs[0].1.as_str(), Some("a \"b\"\nc\\d"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let mut twice = Document::new();
        twice.table(&["x"]);
        twice.table(&["x"]);
        assert!(twice.render().is_err());
    }
}
