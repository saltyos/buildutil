//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — TOML-subset parser for build specs and recipes
//!
//! Wider than mica's deliberately flat config grammar: supports table
//! headers (`[a.b]`), arrays of tables (`[[program]]`), inline tables
//! (`{ k = v, ... }`), single- and multi-line arrays of mixed
//! string/int/bool values, basic strings, ints, bools. Still rejected:
//! floats, dates, literal strings, dotted keys in key position.

use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
    Inline(Vec<(String, Value)>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn str_items(&self) -> Option<Vec<String>> {
        match self {
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    out.push(item.as_str()?.to_string());
                }
                Some(out)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub path: Vec<String>,
    /// True for `[[a.b]]` array-of-tables headers.
    pub is_array: bool,
    pub entries: Vec<Entry>,
}

impl Table {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|e| e.key == key).map(|e| &e.value)
    }
}

#[derive(Debug, Clone)]
pub struct Doc {
    pub tables: Vec<Table>,
}

impl Doc {
    pub fn table(&self, path: &[&str]) -> Option<&Table> {
        self.tables
            .iter()
            .find(|t| t.path.len() == path.len() && t.path.iter().zip(path).all(|(a, b)| a == b))
    }

    pub fn tables_under<'a>(&'a self, prefix: &'a [&str]) -> impl Iterator<Item = &'a Table> {
        self.tables.iter().filter(move |t| {
            t.path.len() > prefix.len() && t.path.iter().zip(prefix).all(|(a, b)| a == b)
        })
    }
}

fn is_bare_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn err(file: &Path, line: u32, msg: impl Into<String>) -> String {
    format!("{}:{}: {}", file.display(), line, msg.into())
}

struct Cursor<'a> {
    lines: Vec<&'a str>,
    /// Index of the current line (0-based) and byte offset within it.
    line: usize,
    col: usize,
    file: &'a Path,
}

impl<'a> Cursor<'a> {
    fn lineno(&self) -> u32 {
        (self.line + 1) as u32
    }

    fn rest(&self) -> &'a str {
        self.lines
            .get(self.line)
            .map(|l| &l[self.col..])
            .unwrap_or("")
    }

    fn at_eof(&self) -> bool {
        self.line >= self.lines.len()
    }

    /// Skip spaces/tabs; when `across_lines`, also skip comments and line
    /// breaks (used inside arrays).
    fn skip_ws(&mut self, across_lines: bool) {
        loop {
            let rest = self.rest();
            let trimmed = rest.trim_start_matches([' ', '\t']);
            self.col += rest.len() - trimmed.len();
            if !across_lines {
                return;
            }
            if trimmed.is_empty() || trimmed.starts_with('#') {
                if self.line >= self.lines.len() {
                    return;
                }
                self.line += 1;
                self.col = 0;
                if self.at_eof() {
                    return;
                }
                continue;
            }
            return;
        }
    }

    fn advance(&mut self, n: usize) {
        self.col += n;
    }

    fn parse_string(&mut self) -> Result<String, String> {
        let rest = self.rest();
        debug_assert!(rest.starts_with('"'));
        let bytes = rest.as_bytes();
        let mut out = String::new();
        let mut i = 1;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    self.advance(i + 1);
                    return Ok(out);
                }
                b'\\' => {
                    i += 1;
                    match bytes.get(i) {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'n') => out.push('\n'),
                        Some(b't') => out.push('\t'),
                        _ => return Err(err(self.file, self.lineno(), "unsupported escape")),
                    }
                }
                _ => {
                    let ch_len = rest[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
                    out.push_str(&rest[i..i + ch_len]);
                    i += ch_len - 1;
                }
            }
            i += 1;
        }
        Err(err(self.file, self.lineno(), "unterminated string"))
    }

    /// TOML literal multiline string (`'''...'''`): raw content, no escape
    /// processing — the shape recipe snippets use so shell bodies survive
    /// byte-for-byte. A newline immediately after the opening delimiter is
    /// trimmed (TOML semantics).
    fn parse_multiline_literal(&mut self) -> Result<String, String> {
        let open_line = self.lineno();
        self.advance(3);
        let mut out = String::new();
        let mut first = true;
        loop {
            if self.at_eof() {
                return Err(err(self.file, open_line, "unterminated ''' string"));
            }
            let rest = self.rest();
            if let Some(pos) = rest.find("'''") {
                out.push_str(&rest[..pos]);
                self.advance(pos + 3);
                return Ok(out);
            }
            if first && self.col >= self.lines[self.line].len() {
                // Opening delimiter at end of line: trim the newline.
            } else {
                out.push_str(rest);
                out.push('\n');
            }
            first = false;
            self.line += 1;
            self.col = 0;
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws(false);
        let rest = self.rest();
        if rest.starts_with("'''") {
            return Ok(Value::Str(self.parse_multiline_literal()?));
        }
        if rest.starts_with('"') {
            return Ok(Value::Str(self.parse_string()?));
        }
        if rest.starts_with('[') {
            self.advance(1);
            let mut items = Vec::new();
            loop {
                self.skip_ws(true);
                if self.at_eof() {
                    return Err(err(self.file, self.lineno(), "unterminated array"));
                }
                if self.rest().starts_with(']') {
                    self.advance(1);
                    return Ok(Value::Array(items));
                }
                items.push(self.parse_value()?);
                self.skip_ws(true);
                if self.rest().starts_with(',') {
                    self.advance(1);
                } else if !self.rest().starts_with(']') {
                    return Err(err(
                        self.file,
                        self.lineno(),
                        "expected ',' or ']' in array",
                    ));
                }
            }
        }
        if rest.starts_with('{') {
            self.advance(1);
            let mut pairs: Vec<(String, Value)> = Vec::new();
            loop {
                self.skip_ws(false);
                if self.rest().starts_with('}') {
                    self.advance(1);
                    return Ok(Value::Inline(pairs));
                }
                let key = self.parse_bare_key()?;
                self.skip_ws(false);
                if !self.rest().starts_with('=') {
                    return Err(err(
                        self.file,
                        self.lineno(),
                        "expected `=` in inline table",
                    ));
                }
                self.advance(1);
                let value = self.parse_value()?;
                if pairs.iter().any(|(k, _)| *k == key) {
                    return Err(err(
                        self.file,
                        self.lineno(),
                        format!("duplicate key `{}`", key),
                    ));
                }
                pairs.push((key, value));
                self.skip_ws(false);
                if self.rest().starts_with(',') {
                    self.advance(1);
                } else if !self.rest().starts_with('}') {
                    return Err(err(
                        self.file,
                        self.lineno(),
                        "expected ',' or '}' in inline table",
                    ));
                }
            }
        }
        // Bare word: bool or integer.
        let end = rest
            .as_bytes()
            .iter()
            .position(|&b| !(is_bare_key_byte(b) || b == b'+'))
            .unwrap_or(rest.len());
        let word = &rest[..end];
        match word {
            "true" => {
                self.advance(4);
                return Ok(Value::Bool(true));
            }
            "false" => {
                self.advance(5);
                return Ok(Value::Bool(false));
            }
            "" => return Err(err(self.file, self.lineno(), "expected a value")),
            _ => {}
        }
        let (neg, digits) = match word.strip_prefix('-') {
            Some(d) => (true, d),
            None => (false, word),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err(
                self.file,
                self.lineno(),
                format!("invalid value `{}`", word),
            ));
        }
        let mag: i64 = digits.parse().map_err(|_| {
            err(
                self.file,
                self.lineno(),
                format!("integer out of range `{}`", word),
            )
        })?;
        self.advance(end);
        Ok(Value::Int(if neg { -mag } else { mag }))
    }

    fn parse_bare_key(&mut self) -> Result<String, String> {
        self.skip_ws(false);
        let rest = self.rest();
        if rest.starts_with('"') {
            return self.parse_string();
        }
        let end = rest
            .as_bytes()
            .iter()
            .position(|&b| !is_bare_key_byte(b))
            .unwrap_or(rest.len());
        if end == 0 {
            return Err(err(
                self.file,
                self.lineno(),
                format!("expected a key: `{}`", rest),
            ));
        }
        let key = rest[..end].to_string();
        self.advance(end);
        Ok(key)
    }

    fn expect_line_end(&mut self) -> Result<(), String> {
        self.skip_ws(false);
        let rest = self.rest();
        if rest.is_empty() || rest.starts_with('#') {
            self.line += 1;
            self.col = 0;
            Ok(())
        } else {
            Err(err(
                self.file,
                self.lineno(),
                format!("unexpected trailing content: `{}`", rest),
            ))
        }
    }
}

pub fn parse(file: &Path, src: &str) -> Result<Doc, String> {
    let mut doc = Doc {
        tables: vec![Table {
            path: Vec::new(),
            is_array: false,
            entries: Vec::new(),
        }],
    };
    let mut cur = Cursor {
        lines: src.lines().collect(),
        line: 0,
        col: 0,
        file,
    };

    while !cur.at_eof() {
        cur.skip_ws(false);
        let rest = cur.rest();
        if rest.is_empty() || rest.starts_with('#') {
            cur.line += 1;
            cur.col = 0;
            continue;
        }
        if rest.starts_with('[') {
            let is_array = rest.starts_with("[[");
            cur.advance(if is_array { 2 } else { 1 });
            let mut path = Vec::new();
            loop {
                path.push(cur.parse_bare_key()?);
                cur.skip_ws(false);
                if cur.rest().starts_with('.') {
                    cur.advance(1);
                    continue;
                }
                break;
            }
            let closer = if is_array { "]]" } else { "]" };
            if !cur.rest().starts_with(closer) {
                return Err(err(cur.file, cur.lineno(), "unterminated table header"));
            }
            cur.advance(closer.len());
            let line = cur.lineno();
            cur.expect_line_end()?;
            // Plain tables must be unique; array-of-tables headers repeat.
            if !is_array && doc.tables.iter().any(|t| !t.is_array && t.path == path) {
                return Err(err(
                    file,
                    line,
                    format!("duplicate table `[{}]`", path.join(".")),
                ));
            }
            doc.tables.push(Table {
                path,
                is_array,
                entries: Vec::new(),
            });
            continue;
        }
        // key = value
        let key = cur.parse_bare_key()?;
        cur.skip_ws(false);
        if !cur.rest().starts_with('=') {
            return Err(err(
                cur.file,
                cur.lineno(),
                format!("expected `=` after `{}`", key),
            ));
        }
        cur.advance(1);
        let line = cur.lineno();
        let value = cur.parse_value()?;
        cur.expect_line_end()?;
        let table = doc.tables.last_mut().expect("root table always present");
        if table.entries.iter().any(|e| e.key == key) {
            return Err(err(file, line, format!("duplicate key `{}`", key)));
        }
        table.entries.push(Entry { key, value });
    }
    Ok(doc)
}

pub fn parse_file(path: &Path) -> Result<Doc, String> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    parse(path, &src)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(src: &str) -> Doc {
        parse(Path::new("t.toml"), src).expect("parse should succeed")
    }

    #[test]
    fn multiline_arrays_and_headers() {
        let doc = parse_ok(
            "[derivation.uapi-src]\nbuilder = \"bindgen\"\nsources = [\n  \"a.h\",  # one\n  \"b.h\",\n]\noutputs = [\"uapi.rs\"]\n",
        );
        let t = doc.table(&["derivation", "uapi-src"]).unwrap();
        assert_eq!(t.get("builder").unwrap().as_str(), Some("bindgen"));
        assert_eq!(
            t.get("sources").unwrap().str_items().unwrap(),
            vec!["a.h", "b.h"]
        );
    }

    #[test]
    fn arrays_of_tables() {
        let doc = parse_ok("[[program]]\nname = \"a\"\n[[program]]\nname = \"b\"\n");
        let programs: Vec<_> = doc
            .tables
            .iter()
            .filter(|t| t.is_array && t.path == ["program"])
            .collect();
        assert_eq!(programs.len(), 2);
        assert_eq!(programs[1].get("name").unwrap().as_str(), Some("b"));
    }

    #[test]
    fn inline_tables() {
        let doc =
            parse_ok("[extern-map]\nuapi = { drv = \"uapi-trona\", rmeta = \"libuapi.rmeta\" }\n");
        let t = doc.table(&["extern-map"]).unwrap();
        let Value::Inline(pairs) = t.get("uapi").unwrap() else {
            panic!("expected an inline table");
        };
        assert_eq!(
            pairs[0],
            ("drv".to_string(), Value::Str("uapi-trona".into()))
        );
        assert_eq!(
            pairs[1],
            ("rmeta".to_string(), Value::Str("libuapi.rmeta".into()))
        );
    }

    #[test]
    fn mixed_values_and_comments() {
        let doc = parse_ok("n = 4\nflag = true\nneg = -2  # trailing\n");
        let root = &doc.tables[0];
        assert_eq!(root.get("n"), Some(&Value::Int(4)));
        assert_eq!(root.get("flag"), Some(&Value::Bool(true)));
        assert_eq!(root.get("neg"), Some(&Value::Int(-2)));
    }

    #[test]
    fn rejections() {
        assert!(parse(Path::new("t"), "k = 1.5\n").is_err());
        assert!(parse(Path::new("t"), "k = 'lit'\n").is_err());
        assert!(parse(Path::new("t"), "[a]\n[a]\n").is_err());
        assert!(parse(Path::new("t"), "k = [1,\n").is_err());
        assert!(parse(Path::new("t"), "k = { a = 1, a = 2 }\n").is_err());
        assert!(parse(Path::new("t"), "k = true junk\n").is_err());
    }

    #[test]
    fn tables_under_prefix() {
        let doc = parse_ok("[flagset.kernel]\nflags = []\n[flagset.pe]\nflags = []\n");
        let names: Vec<String> = doc
            .tables_under(&["flagset"])
            .map(|t| t.path[1].clone())
            .collect();
        assert_eq!(names, vec!["kernel", "pe"]);
    }
}
