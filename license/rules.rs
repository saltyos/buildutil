// SPDX-License-Identifier: GPL-2.0-only
//! Parses ordered license declarations from the root build specification.
//! This module owns policy validation and selection; header, texts and walk apply the selected rule.

use crate::spec::toml::{self, Doc, Table, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A declaration governing the first matching repository-relative path.
#[derive(Clone, Debug)]
pub(crate) struct Rule {
    /// Globs in declaration order.
    pub(crate) paths: Vec<String>,
    /// Expected SPDX expression, compared literally with a tag.
    pub(crate) expression: String,
    /// Whether a matching file must contain a tag.
    pub(crate) header: bool,
    /// Whether a tag may appear inside the leading comment banner.
    pub(crate) banner: bool,
    /// Optional comment marker overriding the file type default.
    pub(crate) comment: Option<String>,
    /// Whether matching source is supplied with its own license texts.
    pub(crate) upstream: bool,
    /// Whether matching files are license texts rather than tagged source.
    pub(crate) license_text: bool,
}

/// Roots and corpus configuration together with ordered source rules.
pub(crate) struct Policy {
    /// Repository-relative directories owning LICENSES trees.
    pub(crate) roots: Vec<String>,
    /// Name of the derivation whose output contains source.tar.
    pub(crate) corpus: Option<String>,
    /// Ordered source rules.
    pub(crate) rules: Vec<Rule>,
}

/// Load complete license policy from the root specification.
pub(crate) fn load_policy(root: &Path) -> Result<Policy, String> {
    let file = root.join("buildutil.toml");
    parse_policy(&toml::parse_file(&file)?).map_err(|e| format!("{}: {e}", file.display()))
}

/// Parse and validate the license tables of a root specification.
#[cfg(test)]
pub(crate) fn load(root: &Path) -> Result<Vec<Rule>, String> {
    let file = root.join("buildutil.toml");
    parse(&toml::parse_file(&file)?).map_err(|e| format!("{}: {e}", file.display()))
}

/// Validate license tables in a parsed specification.
#[cfg(test)]
pub(crate) fn parse(doc: &Doc) -> Result<Vec<Rule>, String> {
    Ok(parse_policy(doc)?.rules)
}

/// Validate complete license policy in a parsed specification.
pub(crate) fn parse_policy(doc: &Doc) -> Result<Policy, String> {
    let parent: Vec<_> = doc
        .tables
        .iter()
        .filter(|t| t.path == ["license"])
        .collect();
    if parent.len() != 1 || parent[0].is_array {
        return Err("[license]: expected one table".into());
    }
    for entry in &parent[0].entries {
        if !["roots", "corpus"].contains(&entry.key.as_str()) {
            return Err(format!("[license]: unknown key `{}`", entry.key));
        }
    }
    let roots = match parent[0].get("roots") {
        Some(value) => value
            .str_items()
            .ok_or("[license].roots must be an array of strings")?,
        None => Vec::new(),
    };
    let mut seen_roots = std::collections::BTreeSet::new();
    for root in &roots {
        if root.starts_with('/')
            || root.contains('\\')
            || root.contains(':')
            || root
                .split('/')
                .any(|part| part == "." || part == ".." || (part.is_empty() && !root.is_empty()))
            || !seen_roots.insert(root.clone())
        {
            return Err(format!(
                "[license].roots: invalid or duplicate root `{root}`"
            ));
        }
    }
    let corpus = match parent[0].get("corpus") {
        Some(Value::Str(value)) if !value.is_empty() => Some(value.clone()),
        None => None,
        _ => return Err("[license].corpus must be a non-empty derivation name".into()),
    };
    let mut rules = Vec::new();
    for table in &doc.tables {
        if table.path.first().is_none_or(|p| p != "license") || table.path == ["license"] {
            continue;
        }
        if table.path != ["license", "rule"] || !table.is_array {
            return Err(format!(
                "[{}]: expected [[license.rule]]",
                table.path.join(".")
            ));
        }
        let ctx = format!("[[license.rule]] #{}", rules.len() + 1);
        for entry in &table.entries {
            if ![
                "paths",
                "expression",
                "header",
                "placement",
                "comment",
                "upstream",
                "kind",
            ]
            .contains(&entry.key.as_str())
            {
                return Err(format!("{ctx}: unknown key `{}`", entry.key));
            }
        }
        let paths = value(table, "paths", &ctx)?
            .str_items()
            .ok_or_else(|| format!("{ctx}.paths must be an array of strings"))?;
        if paths.is_empty()
            || paths
                .iter()
                .any(|p| p.is_empty() || p.starts_with('/') || p.contains('\\'))
        {
            return Err(format!(
                "{ctx}.paths must contain non-empty repository-relative /-separated globs"
            ));
        }
        let license_text = match table.get("kind") {
            Some(Value::Str(v)) if v == "license-text" => true,
            None => false,
            _ => return Err(format!("{ctx}.kind must be `license-text`")),
        };
        let expression = if license_text {
            if table.get("expression").is_some() {
                return Err(format!(
                    "{ctx}: license-text rules cannot have an expression"
                ));
            }
            String::new()
        } else {
            let expression = value(table, "expression", &ctx)?
                .as_str()
                .ok_or_else(|| format!("{ctx}.expression must be a string"))?
                .trim()
                .to_owned();
            validate_expression(&expression).map_err(|e| format!("{ctx}.expression: {e}"))?;
            expression
        };
        let upstream = match table.get("upstream") {
            Some(Value::Bool(value)) => *value,
            None => false,
            _ => return Err(format!("{ctx}.upstream must be a boolean")),
        };
        let header = match table.get("header") {
            Some(Value::Bool(v)) => *v,
            None => !license_text,
            _ => return Err(format!("{ctx}.header must be a boolean")),
        };
        if license_text && header {
            return Err(format!("{ctx}: license-text rules imply header = false"));
        }
        let banner = match table.get("placement") {
            Some(Value::Str(v)) if v == "banner" => true,
            Some(Value::Str(v)) if v == "line1" => false,
            None => false,
            _ => return Err(format!("{ctx}.placement must be `line1` or `banner`")),
        };
        let comment = match table.get("comment") {
            Some(Value::Str(v))
                if ["//", "//!", "/* */", "#", ";", "..", "<!-- -->"].contains(&v.as_str()) =>
            {
                Some(v.clone())
            }
            None => None,
            _ => return Err(format!("{ctx}.comment has an unknown marker")),
        };
        rules.push(Rule {
            paths,
            expression,
            header,
            banner,
            comment,
            upstream,
            license_text,
        });
    }
    Ok(Policy {
        roots,
        corpus,
        rules,
    })
}

/// Find the deepest declared root containing a repository-relative path.
pub(crate) fn owning_root<'a>(roots: &'a [String], rel: &str) -> Option<&'a str> {
    roots
        .iter()
        .filter(|root| {
            root.is_empty() || rel == root.as_str() || rel.starts_with(&format!("{root}/"))
        })
        .max_by_key(|root| root.len())
        .map(String::as_str)
}

/// Return whether a path belongs to a root's dedicated license records.
pub(crate) fn is_text_path(roots: &[String], rel: &str) -> bool {
    roots.iter().any(|root| {
        let license = if root.is_empty() {
            "LICENSE.md".to_string()
        } else {
            format!("{root}/LICENSE.md")
        };
        let tree = if root.is_empty() {
            "LICENSES/".to_string()
        } else {
            format!("{root}/LICENSES/")
        };
        rel == license.as_str() || rel.starts_with(&tree)
    })
}

/// Split an expression into license operands, exceptions, and OR-only use.
pub(crate) fn identifiers(expression: &str) -> Vec<(String, bool, bool)> {
    let mut out = Vec::new();
    if let Ok(tree) = expression_tree(expression) {
        collect_identifiers(&tree, false, &mut out);
    }
    out
}

/// An SPDX license expression. An exception applies to one license
/// (`<license> WITH <exception>`), never to a compound expression.
enum Expr {
    Id(String),
    With(String, String),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

fn collect_identifiers(tree: &Expr, in_or: bool, out: &mut Vec<(String, bool, bool)>) {
    match tree {
        Expr::Id(id) => out.push((id.clone(), false, in_or)),
        Expr::With(license, exception) => {
            out.push((license.clone(), false, in_or));
            out.push((exception.clone(), true, false));
        }
        Expr::And(terms) => {
            for term in terms {
                collect_identifiers(term, false, out);
            }
        }
        Expr::Or(terms) => {
            for term in terms {
                collect_identifiers(term, true, out);
            }
        }
    }
}

/// Map each exception to the licenses it is applied to.
pub(crate) fn exception_bases(expression: &str) -> BTreeMap<String, BTreeSet<String>> {
    fn visit(tree: &Expr, out: &mut BTreeMap<String, BTreeSet<String>>) {
        match tree {
            Expr::With(license, exception) => {
                out.entry(exception.clone())
                    .or_default()
                    .insert(license.clone());
            }
            Expr::And(terms) | Expr::Or(terms) => {
                for term in terms {
                    visit(term, out);
                }
            }
            Expr::Id(_) => {}
        }
    }
    let mut out = BTreeMap::new();
    if let Ok(tree) = expression_tree(expression) {
        visit(&tree, &mut out);
    }
    out
}

fn expression_tree(input: &str) -> Result<Expr, &'static str> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset].is_ascii_whitespace() {
            offset += 1;
            continue;
        }
        if matches!(bytes[offset], b'(' | b')') {
            tokens.push(&input[offset..offset + 1]);
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < bytes.len()
            && (bytes[offset].is_ascii_alphanumeric() || b".+-".contains(&bytes[offset]))
        {
            offset += 1;
        }
        if offset == start {
            return Err("invalid SPDX expression token");
        }
        tokens.push(&input[start..offset]);
    }
    struct Parser<'a> {
        tokens: Vec<&'a str>,
        pos: usize,
    }
    impl<'a> Parser<'a> {
        fn peek(&self) -> Option<&'a str> {
            self.tokens.get(self.pos).copied()
        }
        fn take(&mut self) -> Option<&'a str> {
            let token = self.tokens.get(self.pos).copied();
            self.pos += usize::from(token.is_some());
            token
        }
        fn primary(&mut self) -> Result<Expr, &'static str> {
            match self.take() {
                Some("(") => {
                    let tree = self.or()?;
                    if self.take() != Some(")") {
                        return Err("unbalanced parentheses");
                    }
                    Ok(tree)
                }
                Some(token) if !["AND", "OR", "WITH", ")"].contains(&token) => {
                    // `+` is the "or any later version" operator on a license
                    // identifier: one, at the end, never on a reference.
                    let license = token.strip_suffix('+').unwrap_or(token);
                    if license.is_empty()
                        || license.contains('+')
                        || (license.len() != token.len() && is_reference(license))
                    {
                        return Err("`+` follows a license identifier, once");
                    }
                    Ok(Expr::Id(token.to_string()))
                }
                _ => Err("expected an identifier"),
            }
        }
        fn with(&mut self) -> Result<Expr, &'static str> {
            let grouped = self.peek() == Some("(");
            let tree = self.primary()?;
            if self.peek() != Some("WITH") {
                return Ok(tree);
            }
            self.take();
            // An exception applies to one license, not to a parenthesized
            // or compound expression.
            let license = match tree {
                Expr::Id(license) if !grouped => license,
                _ => return Err("WITH applies to a single license identifier"),
            };
            let Some(exception) = self.take() else {
                return Err("expected an exception identifier");
            };
            if ["AND", "OR", "WITH", "(", ")"].contains(&exception) || exception.contains('+') {
                return Err("expected an exception identifier");
            }
            Ok(Expr::With(license, exception.to_string()))
        }
        fn and(&mut self) -> Result<Expr, &'static str> {
            let mut terms = vec![self.with()?];
            while self.peek() == Some("AND") {
                self.take();
                terms.push(self.with()?);
            }
            if terms.len() == 1 {
                Ok(terms.remove(0))
            } else {
                Ok(Expr::And(terms))
            }
        }
        fn or(&mut self) -> Result<Expr, &'static str> {
            let mut terms = vec![self.and()?];
            while self.peek() == Some("OR") {
                self.take();
                terms.push(self.and()?);
            }
            if terms.len() == 1 {
                Ok(terms.remove(0))
            } else {
                Ok(Expr::Or(terms))
            }
        }
    }
    let mut parser = Parser { tokens, pos: 0 };
    let tree = parser.or()?;
    if parser.peek().is_some() {
        return Err("expected AND, OR, or a closing parenthesis");
    }
    Ok(tree)
}

/// Whether `id` names a project's own text (`LicenseRef-`, `AdditionRef-`)
/// rather than an identifier of the SPDX list.
pub(crate) fn is_reference(id: &str) -> bool {
    id.starts_with("LicenseRef-") || id.starts_with("AdditionRef-")
}

/// The SPDX list identifier whose text a license operand uses: a license
/// with the `+` operator ("or any later version") has its license's text.
pub(crate) fn corpus_id(id: &str) -> &str {
    id.strip_suffix('+').unwrap_or(id)
}

fn value<'a>(table: &'a Table, key: &str, ctx: &str) -> Result<&'a Value, String> {
    table
        .get(key)
        .ok_or_else(|| format!("{ctx}: missing `{key}`"))
}

/// Select the first rule with any matching path glob.
pub(crate) fn select<'a>(rules: &'a [Rule], rel: &str) -> Option<&'a Rule> {
    rules
        .iter()
        .find(|rule| rule.paths.iter().any(|p| crate::glob::glob_match(p, rel)))
}

fn validate_expression(expr: &str) -> Result<(), &'static str> {
    expression_tree(expr).map(|_| ())
}
