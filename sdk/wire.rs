// SPDX-License-Identifier: GPL-2.0-only
//! The wire between buildutil and a module: the SDK version, the value model a
//! request, a module configuration and a result are made of, and its
//! canonical JSON text.
//!
//! buildutil compiles this file as its `sdk_wire` module and the SDK as its
//! `wire` module, so both sides read and write exactly one format. The
//! format is internal to the SDK: a module sees only the SDK's API, and the
//! version below is the contract a module is built against.
//!
//! A request is one JSON object in the file `REQUEST_ENV` names. A builder
//! or generator writes its verdict as one JSON object to the path the
//! request's `results.verdict` names. Relative paths in a request resolve
//! against the directory holding the request file.

use std::collections::BTreeMap;

/// The SDK's semantic version. A module built against it records this
/// value; buildutil runs the module only when the recorded major equals this
/// major and the recorded minor is not higher than this minor.
pub const VERSION: (u32, u32, u32) = (1, 0, 0);

/// The argument a module answers with its compiled-in SDK version, which
/// its derivation records beside the executable.
pub const VERSION_ARGUMENT: &str = "--buildutil-sdk-version";

/// The environment variable naming the request file.
pub const REQUEST_ENV: &str = "BUILDUTIL_MODULE_REQUEST";

/// The file, beside a module executable, recording the SDK version the
/// module was built against.
pub const VERSION_RECORD: &str = "sdk-version";

/// The file a generator writes its declarations to, in its output.
pub const GENERATED_FILE: &str = "generated.toml";

/// The directory, and the manifest of `<based-on-sha256|-> <path>` lines, a
/// formatter or build-host app returns work-tree files in, in its output.
pub const RETURNED_DIR: &str = "files";
pub const RETURNED_LIST: &str = "files.list";

pub fn version_text(version: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

pub fn parse_version(text: &str) -> Result<(u32, u32, u32), String> {
    let text = text.trim();
    let mut parts = text.split('.');
    let mut next = || -> Result<u32, String> {
        parts
            .next()
            .filter(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|part| part.parse().ok())
            .ok_or_else(|| format!("`{text}` is not a <major>.<minor>.<patch> version"))
    };
    let version = (next()?, next()?, next()?);
    if parts.next().is_some() {
        return Err(format!("`{text}` is not a <major>.<minor>.<patch> version"));
    }
    Ok(version)
}

/// Whether a module recorded against `recorded` may run under `provided`:
/// the majors are equal and the recorded minor is not higher.
pub fn check_compatible(recorded: (u32, u32, u32), provided: (u32, u32, u32)) -> Result<(), String> {
    if recorded.0 != provided.0 {
        return Err(format!(
            "built against SDK {}, and this buildutil provides SDK {} (another major version)",
            version_text(recorded),
            version_text(provided)
        ));
    }
    if recorded.1 > provided.1 {
        return Err(format!(
            "built against SDK {}, newer than the SDK {} this buildutil provides",
            version_text(recorded),
            version_text(provided)
        ));
    }
    Ok(())
}

/// A wire value. Tables keep their keys sorted, so equal values have equal
/// text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Value>),
    Table(BTreeMap<String, Value>),
}

impl Value {
    pub fn table() -> Value {
        Value::Table(BTreeMap::new())
    }

    pub fn str(text: impl Into<String>) -> Value {
        Value::Str(text.into())
    }

    pub fn str_list<I, S>(items: I) -> Value
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Value::List(items.into_iter().map(|item| Value::Str(item.into())).collect())
    }

    /// Set `key` in a table; a value of another kind is left unchanged.
    pub fn set(&mut self, key: &str, value: Value) {
        if let Value::Table(map) = self {
            map.insert(key.to_string(), value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Table(map) => map.get(key),
            _ => None,
        }
    }

    /// Follow a dotted path through nested tables.
    pub fn lookup(&self, path: &str) -> Option<&Value> {
        let mut current = self;
        for part in path.split('.') {
            current = current.get(part)?;
        }
        Some(current)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(number) => Some(*number),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_table(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Table(map) => Some(map),
            _ => None,
        }
    }

    /// A list whose every item is a string.
    pub fn as_str_list(&self) -> Option<Vec<String>> {
        self.as_list()?
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect()
    }

    /// The canonical text: no insignificant whitespace, table keys in byte
    /// order, strings escaped only where JSON requires it.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
            Value::Int(number) => out.push_str(&number.to_string()),
            Value::Str(text) => write_json_string(text, out),
            Value::List(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            Value::Table(map) => {
                out.push('{');
                for (index, (key, value)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_json_string(key, out);
                    out.push(':');
                    value.write_json(out);
                }
                out.push('}');
            }
        }
    }

    /// Parse JSON text. Numbers must be integers; a table key given twice
    /// is refused.
    pub fn parse_json(text: &str) -> Result<Value, String> {
        let mut parser = JsonParser {
            bytes: text.as_bytes(),
            text,
            at: 0,
        };
        parser.skip_ws();
        let value = parser.value(0)?;
        parser.skip_ws();
        if parser.at != parser.bytes.len() {
            return Err(parser.error("trailing text after the value"));
        }
        Ok(value)
    }
}

fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Nesting deeper than this is refused rather than recursed into.
const MAX_DEPTH: usize = 64;

struct JsonParser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
}

impl JsonParser<'_> {
    fn error(&self, what: &str) -> String {
        format!("JSON at byte {}: {what}", self.at)
    }

    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.at) {
            self.at += 1;
        }
    }

    fn eat(&mut self, literal: &str) -> bool {
        if self.text[self.at..].starts_with(literal) {
            self.at += literal.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting is too deep"));
        }
        match self.bytes.get(self.at) {
            None => Err(self.error("unexpected end of text")),
            Some(b'n') if self.eat("null") => Ok(Value::Null),
            Some(b't') if self.eat("true") => Ok(Value::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(Value::Bool(false)),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.bytes.get(self.at) == Some(&b']') {
                    self.at += 1;
                    return Ok(Value::List(items));
                }
                loop {
                    self.skip_ws();
                    items.push(self.value(depth + 1)?);
                    self.skip_ws();
                    match self.bytes.get(self.at) {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Value::List(items));
                        }
                        _ => return Err(self.error("expected `,` or `]`")),
                    }
                }
            }
            Some(b'{') => {
                self.at += 1;
                let mut map = BTreeMap::new();
                self.skip_ws();
                if self.bytes.get(self.at) == Some(&b'}') {
                    self.at += 1;
                    return Ok(Value::Table(map));
                }
                loop {
                    self.skip_ws();
                    if self.bytes.get(self.at) != Some(&b'"') {
                        return Err(self.error("expected a string key"));
                    }
                    let key = self.string()?;
                    self.skip_ws();
                    if self.bytes.get(self.at) != Some(&b':') {
                        return Err(self.error("expected `:`"));
                    }
                    self.at += 1;
                    self.skip_ws();
                    let value = self.value(depth + 1)?;
                    if map.insert(key.clone(), value).is_some() {
                        return Err(self.error(&format!("key `{key}` appears twice")));
                    }
                    self.skip_ws();
                    match self.bytes.get(self.at) {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Value::Table(map));
                        }
                        _ => return Err(self.error("expected `,` or `}`")),
                    }
                }
            }
            Some(_) => Err(self.error("unexpected character")),
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.at;
        if self.bytes.get(self.at) == Some(&b'-') {
            self.at += 1;
        }
        while let Some(b'0'..=b'9') = self.bytes.get(self.at) {
            self.at += 1;
        }
        if let Some(b'.' | b'e' | b'E') = self.bytes.get(self.at) {
            return Err(self.error("only integers are part of the wire"));
        }
        self.text[start..self.at]
            .parse()
            .map(Value::Int)
            .map_err(|_| self.error("malformed integer"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .text
            .get(self.at..self.at + 4)
            .ok_or_else(|| self.error("truncated \\u escape"))?;
        let code = u32::from_str_radix(digits, 16).map_err(|_| self.error("malformed \\u escape"))?;
        self.at += 4;
        Ok(code)
    }

    fn string(&mut self) -> Result<String, String> {
        // The opening quote.
        self.at += 1;
        let mut out = String::new();
        loop {
            let Some(&byte) = self.bytes.get(self.at) else {
                return Err(self.error("unterminated string"));
            };
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let escape = self
                        .bytes
                        .get(self.at)
                        .copied()
                        .ok_or_else(|| self.error("truncated escape"))?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let high = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&high) {
                                if !self.eat("\\u") {
                                    return Err(self.error("unpaired surrogate"));
                                }
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return Err(self.error("unpaired surrogate"));
                                }
                                0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                            } else {
                                high
                            };
                            out.push(
                                char::from_u32(code)
                                    .ok_or_else(|| self.error("escape is not a character"))?,
                            );
                        }
                        _ => return Err(self.error("unknown escape")),
                    }
                }
                byte if byte < 0x20 => return Err(self.error("control character in a string")),
                _ => {
                    let ch = self.text[self.at..]
                        .chars()
                        .next()
                        .ok_or_else(|| self.error("truncated character"))?;
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_json_round_trips_canonically() {
        let mut value = Value::table();
        value.set("zeta", Value::Int(-4));
        value.set("alpha", Value::str("line\n\"quoted\"\u{1}é"));
        value.set(
            "list",
            Value::List(vec![Value::Bool(true), Value::Null, Value::str_list(["a"])]),
        );
        let text = value.to_json();
        assert_eq!(
            text,
            "{\"alpha\":\"line\\n\\\"quoted\\\"\\u0001é\",\"list\":[true,null,[\"a\"]],\"zeta\":-4}"
        );
        assert_eq!(Value::parse_json(&text).unwrap(), value);
        assert_eq!(
            Value::parse_json(" { \"a\" : \"\\ud83d\\ude00\" } ").unwrap(),
            {
                let mut v = Value::table();
                v.set("a", Value::str("😀"));
                v
            }
        );
        assert!(Value::parse_json("{\"a\":1,\"a\":2}").is_err());
        assert!(Value::parse_json("1.5").is_err());
    }

    #[test]
    fn required_versions_follow_the_major_and_minor_rule() {
        assert!(check_compatible((1, 0, 0), (1, 0, 0)).is_ok());
        assert!(check_compatible((1, 0, 3), (1, 2, 0)).is_ok());
        assert!(check_compatible((1, 3, 0), (1, 2, 0)).is_err());
        assert!(check_compatible((2, 0, 0), (1, 9, 0)).is_err());
        assert_eq!(parse_version("1.0.0\n").unwrap(), (1, 0, 0));
        assert!(parse_version("1.0").is_err());
        assert!(parse_version("1.0.0.1").is_err());
    }
}
