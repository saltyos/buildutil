//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — configured-node keys and the two command-input address forms.
//!
//! A configured node is a derivation evaluated under the configuration
//! overrides that reach it and change what it reads. Its canonical key is the
//! base name alone for the default configuration and `<name>@<hash>`
//! otherwise, the hash covering the sorted override set; screens show the
//! readable form `<name>[KEY=value,…]`. This module owns both spellings, their
//! parsing and the escaping of the readable form. It never evaluates.

use std::collections::BTreeMap;

/// Hexadecimal digits of the override-set digest carried by a key.
pub const KEY_HASH_LEN: usize = 16;

/// A sorted, duplicate-free override set.
pub type Overrides = BTreeMap<String, String>;

/// The digest of an override set: SHA-256 over one `KEY=value` line per
/// entry in key order, truncated to `KEY_HASH_LEN` digits.
pub fn override_hash(overrides: &Overrides) -> String {
    let mut text = String::new();
    for (key, value) in overrides {
        text.push_str(key);
        text.push('=');
        text.push_str(value);
        text.push('\n');
    }
    crate::crypto::sha256::hash_bytes(text.as_bytes())[..KEY_HASH_LEN].to_string()
}

/// The canonical graph key of `name` under `overrides`.
pub fn node_key(name: &str, overrides: &Overrides) -> String {
    if overrides.is_empty() {
        name.to_string()
    } else {
        format!("{name}@{}", override_hash(overrides))
    }
}

/// The derivation name a key belongs to.
pub fn base_name(key: &str) -> &str {
    key.split_once('@').map(|(name, _)| name).unwrap_or(key)
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, ']' | ',' | '=' | '\\' | ' ') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// The readable form `<name>[KEY=value,…]`, keys sorted, `]`, `,`, `=`, `\`
/// and spaces inside a key or value escaped by `\`. The default
/// configuration's node reads as its bare name.
pub fn readable(name: &str, overrides: &Overrides) -> String {
    if overrides.is_empty() {
        return name.to_string();
    }
    let body = overrides
        .iter()
        .map(|(key, value)| format!("{}={}", escape(key), escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}[{body}]")
}

/// One parsed command-input address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// A bare name.
    Plain(String),
    /// `<name>[KEY=value,…]`: the named derivation under these overrides.
    Configured(String, Overrides),
    /// `<name>@<hash>`: a node of the current evaluation.
    Hash(String, String),
}

impl Address {
    pub fn name(&self) -> &str {
        match self {
            Address::Plain(name) | Address::Configured(name, _) | Address::Hash(name, _) => name,
        }
    }

    /// The canonical internal spelling: the bare name, the readable form or
    /// the key.
    pub fn render(&self) -> String {
        match self {
            Address::Plain(name) => name.clone(),
            Address::Configured(name, overrides) => readable(name, overrides),
            Address::Hash(name, hash) => format!("{name}@{hash}"),
        }
    }
}

/// Parse `name`, `name@hash` or `name[K=v,…]`. The name itself is a
/// derivation name and so carries none of `@[]\,=` or spaces; the first `[`
/// or `@` ends it, so an override value may hold either unescaped.
pub fn parse(text: &str) -> Result<Address, String> {
    let bracket = text.find('[');
    let at = text.find('@');
    if let Some(at) = at
        && bracket.is_none_or(|bracket| at < bracket)
    {
        let (name, hash) = (&text[..at], &text[at + 1..]);
        check_name(name, text)?;
        if hash.len() != KEY_HASH_LEN || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "`{text}`: a node key is `<name>@<{KEY_HASH_LEN} hexadecimal digits>`"
            ));
        }
        return Ok(Address::Hash(name.to_string(), hash.to_ascii_lowercase()));
    }
    let Some(open) = text.find('[') else {
        check_name(text, text)?;
        return Ok(Address::Plain(text.to_string()));
    };
    let name = &text[..open];
    check_name(name, text)?;
    let body = &text[open + 1..];
    let mut overrides = Overrides::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_value = false;
    let mut chars = body.chars();
    let mut closed = false;
    let mut finish =
        |key: &mut String, value: &mut String, in_value: &mut bool| -> Result<(), String> {
            if !*in_value || key.is_empty() {
                return Err(format!("`{text}`: each override is `KEY=value`"));
            }
            if overrides
                .insert(std::mem::take(key), std::mem::take(value))
                .is_some()
            {
                return Err(format!("`{text}`: an override key is repeated"));
            }
            *in_value = false;
            Ok(())
        };
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let escaped = chars
                    .next()
                    .ok_or_else(|| format!("`{text}`: a trailing `\\` escapes nothing"))?;
                if in_value {
                    value.push(escaped);
                } else {
                    key.push(escaped);
                }
            }
            '=' if !in_value => in_value = true,
            ',' => finish(&mut key, &mut value, &mut in_value)?,
            ']' => {
                finish(&mut key, &mut value, &mut in_value)?;
                closed = true;
                if chars.next().is_some() {
                    return Err(format!("`{text}`: text follows the closing `]`"));
                }
                break;
            }
            '=' | ' ' => {
                return Err(format!("`{text}`: `{ch}` inside an override must be escaped"));
            }
            other => {
                if in_value {
                    value.push(other);
                } else {
                    key.push(other);
                }
            }
        }
    }
    if !closed {
        return Err(format!("`{text}`: the override list lacks its closing `]`"));
    }
    Ok(Address::Configured(name.to_string(), overrides))
}

fn check_name(name: &str, text: &str) -> Result<(), String> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| matches!(c, '@' | '[' | ']' | '\\' | ',' | '=' | ' ' | '?') || c.is_control())
    {
        return Err(format!("`{text}` does not name a derivation"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(pairs: &[(&str, &str)]) -> Overrides {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn required_configured_key_is_name_at_sixteen_digit_hash() {
        let overrides = set(&[("TEST_AUTOSHUTDOWN", "true")]);
        let key = node_key("image-disk-bios", &overrides);
        let (name, hash) = key.split_once('@').unwrap();
        assert_eq!(name, "image-disk-bios");
        assert_eq!(hash.len(), KEY_HASH_LEN);
        assert_eq!(hash, override_hash(&overrides));
        assert_eq!(
            override_hash(&overrides),
            crate::crypto::sha256::hash_bytes(b"TEST_AUTOSHUTDOWN=true\n")[..16]
        );
        assert_eq!(node_key("kernite", &Overrides::new()), "kernite");
        assert_eq!(base_name(&key), "image-disk-bios");
        assert_eq!(base_name("kernite"), "kernite");
    }

    #[test]
    fn required_readable_form_escapes_and_round_trips() {
        let overrides = set(&[("B", "x y"), ("A", "a,b=c]d\\e")]);
        let text = readable("drv", &overrides);
        assert_eq!(text, "drv[A=a\\,b\\=c\\]d\\\\e,B=x\\ y]");
        assert_eq!(
            parse(&text).unwrap(),
            Address::Configured("drv".into(), overrides)
        );
    }

    #[test]
    fn required_address_forms_parse_and_reject_malformed_input() {
        assert_eq!(parse("kernite").unwrap(), Address::Plain("kernite".into()));
        let hash = "0123456789abcdef";
        assert_eq!(
            parse(&format!("kernite@{hash}")).unwrap(),
            Address::Hash("kernite".into(), hash.into())
        );
        let odd = set(&[("URL", "a@b[c")]);
        assert_eq!(
            parse(&readable("img", &odd)).unwrap(),
            Address::Configured("img".into(), odd)
        );
        for bad in [
            "kernite@123",
            "kernite@zzzzzzzzzzzzzzzz",
            "kernite[A=1",
            "kernite[A]",
            "kernite[A=1,A=2]",
            "kernite[A=1]x",
            "kernite[A=1 2]",
            "[A=1]",
            "?kernite",
        ] {
            assert!(parse(bad).is_err(), "{bad} parsed");
        }
    }
}
