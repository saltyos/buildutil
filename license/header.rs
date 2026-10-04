// SPDX-License-Identifier: GPL-2.0-only
//! Checks and repairs SPDX tags in one UTF-8 file's text.
//! This module owns text and comment syntax; rules selects policy and walk handles files.

use super::rules::Rule;

/// A single diagnostic for a checked file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Problem {
    /// Stable diagnostic kind.
    pub(crate) kind: &'static str,
    /// Human-readable explanation.
    pub(crate) detail: String,
}

/// The result of inspecting one file, with an optional repaired text.
pub(crate) struct Inspection {
    /// All problems found in the file.
    pub(crate) problems: Vec<Problem>,
    /// Repaired text, absent when unchanged or unsafe to repair.
    pub(crate) repaired: Option<String>,
    /// Action name for a repair.
    pub(crate) action: Option<&'static str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Marker {
    Slash,
    SlashBang,
    Block,
    Continuation,
    Hash,
    Semi,
    Rst,
    Html,
}

impl Marker {
    fn name(self) -> &'static str {
        match self {
            Self::Slash => "//",
            Self::SlashBang => "//!",
            Self::Block | Self::Continuation => "/* */",
            Self::Hash => "#",
            Self::Semi => ";",
            Self::Rst => "..",
            Self::Html => "<!-- -->",
        }
    }
}

struct Tag {
    marker: Marker,
    expression: String,
    multiline_block: bool,
}

fn tag(line: &str) -> Option<Tag> {
    let line = line.trim_start();
    let candidates = [
        ("<!--", Marker::Html),
        ("//!", Marker::SlashBang),
        ("//", Marker::Slash),
        ("/*", Marker::Block),
        ("..", Marker::Rst),
        ("*", Marker::Continuation),
        ("#", Marker::Hash),
        (";", Marker::Semi),
    ];
    for (prefix, marker) in candidates {
        let Some(rest) = line.strip_prefix(prefix) else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(expr) = rest.trim_start().strip_prefix("SPDX-License-Identifier:") else {
            continue;
        };
        if !expr.starts_with(char::is_whitespace) {
            continue;
        }
        let expr = expr.trim();
        let multiline_block = marker == Marker::Block && !expr.ends_with("*/");
        let expr = match marker {
            Marker::Block if !multiline_block => expr.strip_suffix("*/")?.trim_end(),
            Marker::Html => expr.strip_suffix("-->")?.trim_end(),
            _ => expr,
        };
        if expr.is_empty()
            || ["/*", "*/", "<!--", "-->"]
                .iter()
                .any(|fragment| expr.contains(fragment))
        {
            continue;
        }
        return Some(Tag {
            marker,
            expression: expr.to_owned(),
            multiline_block,
        });
    }
    None
}

/// Comment syntax of one file: the markers its policy accepts for the tag,
/// the marker a repair inserts, and the markers that open a comment in the
/// file's language at all. The last set is wider than the first (a Rust
/// `/* */` comment is a comment, though not the accepted tag style) and
/// decides whether a tag-shaped line is a comment with the wrong style or not
/// a comment at all.
struct Syntax {
    accepted: Vec<Marker>,
    insert: Marker,
    comments: Vec<Marker>,
}

impl Syntax {
    /// Whether `marker` opens a comment in this file's language. `//!` is a
    /// `//` comment, and a `*` continuation belongs to a `/* */` block.
    fn is_comment(&self, marker: Marker) -> bool {
        match marker {
            Marker::SlashBang => self.comments.contains(&Marker::Slash),
            Marker::Continuation => self.comments.contains(&Marker::Block),
            other => self.comments.contains(&other),
        }
    }
}

fn syntax(rel: &str, first: &str, override_marker: Option<&str>) -> Result<Syntax, String> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let ext = name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    let (mut accepted, mut insert) = match ext {
        "rs" => (vec![Marker::Slash, Marker::SlashBang], Marker::Slash),
        "c" | "h" => (vec![Marker::Block, Marker::Slash], Marker::Block),
        "ld" => (vec![Marker::Block], Marker::Block),
        "cpp" | "cc" | "hpp" | "hh" | "S" => (vec![Marker::Slash, Marker::Block], Marker::Slash),
        "asm" | "def" => (vec![Marker::Semi], Marker::Semi),
        "rst" => (vec![Marker::Rst], Marker::Rst),
        "md" => (vec![Marker::Html], Marker::Html),
        "sh" | "bash" | "py" | "toml" | "port" | "patch" | "diff" | "service" | "socket"
        | "cap" | "target" | "mount" | "cmake" | "ninja" | "manifest" | "permissions"
        | "packages" | "conf" | "yml" | "yaml" | "mk" => (vec![Marker::Hash], Marker::Hash),
        _ if [
            "Makefile",
            ".gitignore",
            ".gitmodules",
            ".gitattributes",
            ".buildutilignore",
            ".dockerignore",
        ]
        .contains(&name)
            || (!name.contains('.') && first.starts_with("#!")) =>
        {
            (vec![Marker::Hash], Marker::Hash)
        }
        _ => (Vec::new(), Marker::Hash),
    };
    let mut comments = match ext {
        "rs" | "c" | "h" | "cpp" | "cc" | "hpp" | "hh" | "S" => vec![Marker::Slash, Marker::Block],
        _ => accepted.clone(),
    };
    if let Some(value) = override_marker {
        if value == "#" && matches!(ext, "c" | "h" | "S" | "cpp" | "cc" | "hpp" | "hh") {
            return Err(format!(
                "no comment syntax for {rel}: `#` is a preprocessor marker"
            ));
        }
        insert = match value {
            "//" => Marker::Slash,
            "//!" => Marker::SlashBang,
            "/* */" => Marker::Block,
            "#" => Marker::Hash,
            ";" => Marker::Semi,
            ".." => Marker::Rst,
            "<!-- -->" => Marker::Html,
            _ => return Err(format!("no comment syntax for {rel}")),
        };
        accepted.push(insert);
        if !comments.contains(&insert) {
            comments.push(insert);
        }
    }
    if matches!(ext, "S" | "asm") {
        accepted.retain(|m| *m != Marker::SlashBang);
        if insert == Marker::SlashBang {
            return Err(format!(
                "no comment syntax for {rel}: `//!` is invalid in assembly"
            ));
        }
    }
    if accepted.is_empty() {
        return Err(format!(
            "no comment syntax for {rel}; set `comment` on its rule or `header = false`"
        ));
    }
    Ok(Syntax {
        accepted,
        insert,
        comments,
    })
}

fn tag_line(marker: Marker, expr: &str) -> String {
    match marker {
        Marker::Block => format!("/* SPDX-License-Identifier: {expr} */"),
        Marker::Html => format!("<!-- SPDX-License-Identifier: {expr} -->"),
        _ => format!("{} SPDX-License-Identifier: {expr}", marker.name()),
    }
}

fn lines(text: &str) -> (Vec<String>, Vec<String>, &'static str, bool) {
    let mut content = Vec::new();
    let mut endings = Vec::new();
    for segment in text.split_inclusive('\n') {
        if let Some(body) = segment.strip_suffix("\r\n") {
            content.push(body.to_owned());
            endings.push("\r\n".to_owned());
        } else if let Some(body) = segment.strip_suffix('\n') {
            content.push(body.to_owned());
            endings.push("\n".to_owned());
        } else {
            content.push(segment.to_owned());
            endings.push(String::new());
        }
    }
    let ending = match endings.iter().find(|e| !e.is_empty()).map(String::as_str) {
        Some("\r\n") => "\r\n",
        _ => "\n",
    };
    (content, endings, ending, text.ends_with('\n'))
}

fn insert_line(
    content: &mut Vec<String>,
    endings: &mut Vec<String>,
    at: usize,
    value: String,
    ending: &str,
    trailing: bool,
) {
    if at > 0 && endings[at - 1].is_empty() {
        endings[at - 1] = ending.to_owned();
    }
    let new_ending = if at < content.len() || trailing {
        ending
    } else {
        ""
    };
    content.insert(at, value);
    endings.insert(at, new_ending.to_owned());
}

fn rebuild(content: &[String], endings: &[String], ending: &str, trailing: bool) -> String {
    let mut out = String::new();
    for (index, line) in content.iter().enumerate() {
        out.push_str(line);
        if index + 1 == content.len() {
            if trailing {
                out.push_str(if endings[index].is_empty() {
                    ending
                } else {
                    &endings[index]
                });
            }
        } else {
            out.push_str(if endings[index].is_empty() {
                ending
            } else {
                &endings[index]
            });
        }
    }
    out
}

fn banner_end(lines: &[String], required: usize, accepted: &[Marker]) -> usize {
    let mut block = false;
    let mut end = required;
    for line in lines.iter().skip(required) {
        let s = line.trim_start();
        let comment = (s.starts_with("//")
            && (accepted.contains(&Marker::Slash) || accepted.contains(&Marker::SlashBang)))
            || (s.starts_with('#') && accepted.contains(&Marker::Hash))
            || (s.starts_with(';') && accepted.contains(&Marker::Semi))
            || (s.starts_with("..") && accepted.contains(&Marker::Rst))
            || (s.starts_with("<!--") && accepted.contains(&Marker::Html))
            || (s.starts_with("/*") && accepted.contains(&Marker::Block))
            || (s.starts_with('*') && block);
        if s.trim().is_empty() || comment || block || tag(s).is_some() {
            end += 1;
            if s.starts_with("/*") && !s.contains("*/") {
                block = true;
            }
            if s.contains("*/") {
                block = false;
            }
        } else {
            break;
        }
    }
    end
}

fn encoding_line(line: &str) -> bool {
    let line = line.trim_start_matches(|c| matches!(c, ' ' | '\t' | '\x0c'));
    let Some(comment) = line.strip_prefix('#') else {
        return false;
    };
    for (index, _) in comment.match_indices("coding") {
        let rest = &comment[index + "coding".len()..];
        let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
            continue;
        };
        let value = rest.trim_start_matches(|c| matches!(c, ' ' | '\t'));
        if value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return true;
        }
    }
    false
}

/// Inspect and optionally prepare a repair without accessing the filesystem.
pub(crate) fn inspect(rel: &str, text: &str, rule: &Rule, fix: bool) -> Result<Inspection, String> {
    let bom = text.starts_with('\u{feff}');
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let (mut content, mut endings, ending, trailing) = lines(text);
    let first = content.first().map(String::as_str).unwrap_or("");
    let syntax = syntax(rel, first, rule.comment.as_deref())?;
    let (accepted, insert) = (&syntax.accepted, syntax.insert);
    let mut required = usize::from(first.starts_with("#!"));
    if content
        .get(required)
        .is_some_and(|line| encoding_line(line))
    {
        required += 1;
    }
    let banner = banner_end(&content, required, accepted);
    let tags: Vec<_> = content
        .iter()
        .enumerate()
        .skip(required)
        .take(banner.saturating_sub(required))
        .filter_map(|(i, line)| tag(line).map(|t| (i, t)))
        .collect();
    let mut problems = Vec::new();
    let in_banner = tags.len();
    if in_banner > 1 {
        problems.push(Problem {
            kind: "duplicate",
            detail: format!("{in_banner} tag lines in the leading banner"),
        });
    }
    let Some((index, found)) = tags.first() else {
        problems.push(Problem {
            kind: "missing",
            detail: format!("expected tag on line {}", required + 1),
        });
        let repaired = if fix {
            insert_line(
                &mut content,
                &mut endings,
                required,
                tag_line(insert, &rule.expression),
                ending,
                trailing,
            );
            if insert == Marker::Rst
                && content
                    .get(required + 1)
                    .is_some_and(|line| !line.is_empty())
            {
                insert_line(
                    &mut content,
                    &mut endings,
                    required + 1,
                    String::new(),
                    ending,
                    trailing,
                );
            }
            Some(format!(
                "{}{}",
                if bom { "\u{feff}" } else { "" },
                rebuild(&content, &endings, ending, trailing)
            ))
        } else {
            None
        };
        return Ok(Inspection {
            problems,
            repaired,
            action: fix.then_some("insert"),
        });
    };
    if *index != required && (!rule.banner || *index < required || *index >= banner) {
        problems.push(Problem {
            kind: "placement",
            detail: format!(
                "tag on line {}; expected {}",
                index + 1,
                if rule.banner {
                    "leading banner".to_owned()
                } else {
                    format!("line {}", required + 1)
                }
            ),
        });
    }
    if found.expression != rule.expression {
        problems.push(Problem {
            kind: "expression",
            detail: format!("got `{}`; expected `{}`", found.expression, rule.expression),
        });
    }
    if found.marker == Marker::Continuation || !accepted.contains(&found.marker) {
        problems.push(Problem {
            kind: "marker",
            detail: format!("marker `{}` is not accepted", found.marker.name()),
        });
    }
    // A tag behind a marker that is not a comment in this language (`#` in
    // C is a preprocessor line) leaves the file with no valid declaration.
    if !syntax.is_comment(found.marker) {
        problems.push(Problem {
            kind: "missing",
            detail: format!(
                "line {} uses `{}`, which is not a comment here",
                index + 1,
                found.marker.name()
            ),
        });
    }
    if found.marker == Marker::Rst && content.get(*index + 1).is_some_and(|line| !line.is_empty()) {
        problems.push(Problem {
            kind: "spacing",
            detail: "RST tag must be followed by an empty line".into(),
        });
    }
    if problems.is_empty() || !fix || in_banner > 1 {
        return Ok(Inspection {
            problems,
            repaired: None,
            action: None,
        });
    }
    let placement_valid =
        *index == required || (rule.banner && *index >= required && *index < banner);
    let marker_valid = found.marker != Marker::Continuation && accepted.contains(&found.marker);
    if found.multiline_block && (!placement_valid || !marker_valid) {
        return Ok(Inspection {
            problems,
            repaired: None,
            action: None,
        });
    }
    let action = if placement_valid { "rewrite" } else { "move" };
    if placement_valid && marker_valid {
        content[*index] = content[*index].replacen(&found.expression, &rule.expression, 1);
        if found.marker == Marker::Rst
            && content.get(*index + 1).is_some_and(|line| !line.is_empty())
        {
            insert_line(
                &mut content,
                &mut endings,
                *index + 1,
                String::new(),
                ending,
                trailing,
            );
        }
    } else {
        content.remove(*index);
        endings.remove(*index);
        insert_line(
            &mut content,
            &mut endings,
            required,
            tag_line(insert, &rule.expression),
            ending,
            trailing,
        );
        if insert == Marker::Rst
            && content
                .get(required + 1)
                .is_some_and(|line| !line.is_empty())
        {
            insert_line(
                &mut content,
                &mut endings,
                required + 1,
                String::new(),
                ending,
                trailing,
            );
        }
    }
    Ok(Inspection {
        problems,
        repaired: Some(format!(
            "{}{}",
            if bom { "\u{feff}" } else { "" },
            rebuild(&content, &endings, ending, trailing)
        )),
        action: Some(action),
    })
}
