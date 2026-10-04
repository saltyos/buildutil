//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — a JSON value reader for tool messages
//!
//! Builders run tools that report in JSON lines (cargo's
//! `--message-format=json`, forwarded by the Rust bootstrap's
//! `--json-output`). This module parses one such line into a `Value`; it
//! owns no knowledge of any tool's schema, which `exec::output` applies. It
//! only reads: buildutil writes its own event JSON in `events`.

/// A parsed JSON value. Numbers keep their source text, since no reader
/// here does arithmetic on them.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object.
    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Parse `text` as exactly one JSON value, surrounded only by whitespace.
pub(crate) fn parse(text: &str) -> Option<Value> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
        depth: 0,
    };
    let value = p.value()?;
    p.skip_ws();
    (p.pos == p.bytes.len()).then_some(value)
}

/// Nesting deeper than this is rejected so a hostile line cannot exhaust
/// the stack.
const MAX_DEPTH: usize = 128;

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        (self.bytes.get(self.pos) == Some(&byte)).then(|| self.pos += 1)
    }

    fn literal(&mut self, word: &str, value: Value) -> Option<Value> {
        let end = self.pos + word.len();
        (self.bytes.get(self.pos..end) == Some(word.as_bytes())).then(|| {
            self.pos = end;
            value
        })
    }

    fn value(&mut self) -> Option<Value> {
        self.skip_ws();
        match *self.bytes.get(self.pos)? {
            b'n' => self.literal("null", Value::Null),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'"' => self.string().map(Value::String),
            b'[' => self.nested(Self::array),
            b'{' => self.nested(Self::object),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn nested(&mut self, parse: fn(&mut Self) -> Option<Value>) -> Option<Value> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let value = parse(self);
        self.depth -= 1;
        value
    }

    fn array(&mut self) -> Option<Value> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.eat(b']').is_some() {
            return Some(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            if self.eat(b']').is_some() {
                return Some(Value::Array(items));
            }
            self.eat(b',')?;
        }
    }

    fn object(&mut self) -> Option<Value> {
        self.eat(b'{')?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.eat(b'}').is_some() {
            return Some(Value::Object(members));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.eat(b':')?;
            let value = self.value()?;
            members.push((key, value));
            self.skip_ws();
            if self.eat(b'}').is_some() {
                return Some(Value::Object(members));
            }
            self.eat(b',')?;
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.pos;
        self.eat(b'-');
        let digits = |p: &mut Self| {
            let from = p.pos;
            while p.bytes.get(p.pos).is_some_and(u8::is_ascii_digit) {
                p.pos += 1;
            }
            p.pos > from
        };
        if !digits(self) {
            return None;
        }
        if self.eat(b'.').is_some() && !digits(self) {
            return None;
        }
        if matches!(self.bytes.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !digits(self) {
                return None;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
        Some(Value::Number(text.to_string()))
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = std::str::from_utf8(self.bytes.get(self.pos..self.pos + 4)?).ok()?;
        let code = u32::from_str_radix(digits, 16).ok()?;
        self.pos += 4;
        Some(code)
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        loop {
            let byte = *self.bytes.get(self.pos)?;
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let escape = *self.bytes.get(self.pos)?;
                    self.pos += 1;
                    let c = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let high = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&high) {
                                self.eat(b'\\')?;
                                self.eat(b'u')?;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return None;
                                }
                                0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                            } else {
                                high
                            };
                            char::from_u32(code)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1f => return None,
                _ => out.push(byte),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_objects_and_escapes_parse() {
        let v = parse(
            r#"{"reason":"compiler-message","target":{"name":"a b"},"message":{"rendered":"x\n\u001b[1m😀"},"n":-1.5e3,"ok":[true,null]}"#,
        )
        .unwrap();
        assert_eq!(
            v.get("reason").and_then(Value::as_str),
            Some("compiler-message")
        );
        assert_eq!(
            v.get("target")
                .and_then(|t| t.get("name"))
                .and_then(Value::as_str),
            Some("a b")
        );
        assert_eq!(
            v.get("message")
                .and_then(|m| m.get("rendered"))
                .and_then(Value::as_str),
            Some("x\n\u{1b}[1m\u{1f600}")
        );
        assert_eq!(v.get("n"), Some(&Value::Number("-1.5e3".into())));
    }

    #[test]
    fn malformed_and_trailing_input_is_rejected() {
        for text in [
            "",
            "{",
            r#"{"a":1,}"#,
            r#"{"a":1} x"#,
            r#""\ud800""#,
            "\"tab\tinside\"",
            "01x",
        ] {
            assert_eq!(parse(text), None, "{text:?}");
        }
        let deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert_eq!(parse(&deep), None);
    }
}
