// SPDX-License-Identifier: GPL-2.0-only
//! Checks declared LICENSES trees against source expressions and archive texts.
//! This module owns text declarations and repairs; rules owns source policy and untar owns tar parsing.

use super::Edit;
use super::rules::{self, Policy};
use super::walk::Walk;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// A diagnostic associated with a repository-relative path.
pub(crate) struct Problem {
    /// Short diagnostic category.
    pub(crate) kind: &'static str,
    /// Slash-separated repository-relative path.
    pub(crate) path: String,
    /// Actionable reason for the problem.
    pub(crate) detail: String,
}

/// Text-check results and prepared edits.
pub(crate) struct Outcome {
    /// Problems remaining after any requested repairs.
    pub(crate) problems: Vec<Problem>,
    /// Repairs to apply after every check succeeds.
    pub(crate) edits: Vec<Edit>,
}

struct Declaration {
    ids: Vec<String>,
    body: usize,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
}

fn header(bytes: &[u8], exception: bool) -> Result<Declaration, String> {
    let mut position = 0;
    let mut ids = Vec::new();
    let mut url = false;
    let mut guide = false;
    let mut licenses = false;
    let mut in_guide = false;
    let mut guide_line = false;
    loop {
        let end = bytes[position..]
            .iter()
            .position(|&byte| byte == b'\n')
            .ok_or("missing License-Text line")?
            + position;
        let line = std::str::from_utf8(&bytes[position..end])
            .map_err(|_| "non-UTF-8 header")?
            .trim_end_matches('\r');
        position = end + 1;
        if line == "License-Text:" {
            let empty_end = bytes[position..]
                .iter()
                .position(|&byte| byte == b'\n')
                .ok_or("License-Text needs an empty line")?
                + position;
            if !bytes[position..empty_end].iter().all(|byte| *byte == b'\r') {
                return Err("License-Text needs one empty line".into());
            }
            position = empty_end + 1;
            break;
        }
        if in_guide && (line.starts_with(' ') || line.starts_with('\t')) {
            guide_line = true;
            continue;
        }
        in_guide = false;
        if let Some(id) = line.strip_prefix("Valid-License-Identifier: ") {
            if exception || !valid_id(id) {
                return Err("invalid license identifier line".into());
            }
            ids.push(id.to_string());
        } else if let Some(id) = line.strip_prefix("SPDX-Exception-Identifier: ") {
            if !exception || !ids.is_empty() || !valid_id(id) {
                return Err("invalid exception identifier line".into());
            }
            ids.push(id.to_string());
        } else if let Some(value) = line.strip_prefix("SPDX-Licenses: ") {
            if !exception || licenses || value.split(',').any(|id| !valid_id(id.trim())) {
                return Err("invalid SPDX-Licenses line".into());
            }
            licenses = true;
        } else if let Some(value) = line.strip_prefix("SPDX-URL: ") {
            if url || value.is_empty() {
                return Err("invalid SPDX-URL line".into());
            }
            url = true;
        } else if line == "Usage-Guide:" {
            if guide {
                return Err("duplicate Usage-Guide".into());
            }
            guide = true;
            in_guide = true;
        } else {
            return Err(format!("unknown header line `{line}`"));
        }
    }
    if ids.is_empty()
        || (exception && ids.len() != 1)
        || (!url && !ids.iter().all(|id| rules::is_reference(id)))
        || !guide
        || !guide_line
    {
        return Err("incomplete LICENSES header".into());
    }
    let mut seen = BTreeSet::new();
    if ids.iter().any(|id| !seen.insert(id)) {
        return Err("duplicate identifier in header".into());
    }
    Ok(Declaration {
        ids,
        body: position,
    })
}

fn rel_path(root: &str, tail: &str) -> String {
    if root.is_empty() {
        tail.to_string()
    } else {
        format!("{root}/{tail}")
    }
}

fn host_path(root: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

fn safe_tree(root: &Path, owner: &str) -> Result<(), String> {
    let mut path = root.to_path_buf();
    for part in owner
        .split('/')
        .filter(|part| !part.is_empty())
        .chain(["LICENSES"])
    {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", path.display()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
    }
    Ok(())
}

fn safe_parent(root: &Path, rel: &str) -> Result<(), String> {
    let mut path = root.to_path_buf();
    let mut parts = rel.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            break;
        }
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", path.display()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
    }
    Ok(())
}

fn scan_tree(
    root: &Path,
    rel_root: &str,
    outcome: &mut Outcome,
) -> Vec<(String, Vec<u8>, Declaration)> {
    let tree_rel = rel_path(rel_root, "LICENSES");
    let tree = host_path(root, &tree_rel);
    if !tree.exists() {
        return Vec::new();
    }
    let mut found = Vec::new();
    let dirs = match fs::read_dir(&tree) {
        Ok(value) => value,
        Err(error) => {
            outcome.problems.push(Problem {
                kind: "read",
                path: tree_rel,
                detail: error.to_string(),
            });
            return found;
        }
    };
    for dir in dirs {
        let dir = match dir {
            Ok(dir) => dir,
            Err(error) => {
                outcome.problems.push(Problem {
                    kind: "read",
                    path: tree_rel.clone(),
                    detail: error.to_string(),
                });
                continue;
            }
        };
        let name = dir.file_name().to_string_lossy().into_owned();
        let dir_rel = rel_path(rel_root, &format!("LICENSES/{name}"));
        if !["preferred", "dual", "exceptions", "other", "deprecated"].contains(&name.as_str()) {
            outcome.problems.push(Problem {
                kind: "directory",
                path: dir_rel,
                detail: "unknown LICENSES directory".into(),
            });
            continue;
        }
        let kind = match dir.file_type() {
            Ok(kind) => kind,
            Err(error) => {
                outcome.problems.push(Problem {
                    kind: "read",
                    path: dir_rel.clone(),
                    detail: error.to_string(),
                });
                continue;
            }
        };
        if !kind.is_dir() || kind.is_symlink() {
            outcome.problems.push(Problem {
                kind: "directory",
                path: dir_rel,
                detail: "expected a directory".into(),
            });
            continue;
        }
        let Ok(files) = fs::read_dir(dir.path()) else {
            outcome.problems.push(Problem {
                kind: "read",
                path: dir_rel,
                detail: "cannot list directory".into(),
            });
            continue;
        };
        for file in files {
            let file = match file {
                Ok(file) => file,
                Err(error) => {
                    outcome.problems.push(Problem {
                        kind: "read",
                        path: dir_rel.clone(),
                        detail: error.to_string(),
                    });
                    continue;
                }
            };
            let filename = file.file_name().to_string_lossy().into_owned();
            let rel = format!("{dir_rel}/{filename}");
            if !file
                .file_type()
                .is_ok_and(|kind| kind.is_file() && !kind.is_symlink())
            {
                outcome.problems.push(Problem {
                    kind: "file",
                    path: rel,
                    detail: "expected a regular file".into(),
                });
                continue;
            }
            match fs::read(file.path()) {
                Ok(bytes) => match header(&bytes, name == "exceptions") {
                    Ok(decl) => found.push((rel, bytes, decl)),
                    Err(detail) => outcome.problems.push(Problem {
                        kind: "header",
                        path: rel,
                        detail,
                    }),
                },
                Err(error) => outcome.problems.push(Problem {
                    kind: "read",
                    path: rel,
                    detail: error.to_string(),
                }),
            }
        }
    }
    found
}

/// Index regular license texts from an archive without extracting it.
pub(crate) fn corpus(archive: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut prefixes = BTreeSet::new();
    let mut texts = BTreeMap::new();
    crate::exec::untar::scan_archive(
        archive,
        |path, kind| {
            matches!(kind, b'0' | 0 | b'7')
                && corpus_candidate(path)
                    .and_then(|(_, file)| file)
                    .is_some_and(|file| file.strip_suffix(".txt").is_some_and(valid_id))
        },
        |entry| {
            let Some((prefix, id_file)) = corpus_candidate(&entry.rel) else {
                return Ok(());
            };
            prefixes.insert(prefix.to_string());
            let (Some(id_file), Some(bytes)) = (id_file, entry.body) else {
                return Ok(());
            };
            let Some(id) = id_file.strip_suffix(".txt") else {
                return Ok(());
            };
            if !valid_id(id) {
                return Ok(());
            }
            if texts.insert(id.to_string(), bytes).is_some() {
                return Err(format!(
                    "{}: duplicate corpus text `{id}`",
                    archive.display()
                ));
            }
            Ok(())
        },
    )?;
    if prefixes.len() != 1 {
        return Err(format!(
            "{}: expected exactly one candidate text directory, found {}",
            archive.display(),
            prefixes.len()
        ));
    }
    Ok(texts)
}

fn corpus_candidate(path: &str) -> Option<(&str, Option<&str>)> {
    let parts: Vec<_> = path.split('/').collect();
    match parts.as_slice() {
        ["text"] => Some(("", None)),
        ["text", file] => Some(("", Some(*file))),
        [top, "text"] if !top.is_empty() => Some((*top, None)),
        [top, "text", file] if !top.is_empty() => Some((*top, Some(*file))),
        _ => None,
    }
}

fn new_file(id: &str, exception: bool, bases: &BTreeSet<String>, body: &[u8]) -> Vec<u8> {
    let tag = if exception {
        "SPDX-Exception-Identifier"
    } else {
        "Valid-License-Identifier"
    };
    let exception_lines = if exception {
        format!(
            "SPDX-Licenses: {}\n",
            bases.iter().cloned().collect::<Vec<_>>().join(", ")
        )
    } else {
        String::new()
    };
    let guide = if exception {
        format!("Put SPDX-License-Identifier: <license> WITH {id} in files using this exception.")
    } else {
        format!("Put SPDX-License-Identifier: {id} in files using this text.")
    };
    let page = rules::corpus_id(id);
    let mut output = format!("{tag}: {id}\n{exception_lines}SPDX-URL: https://spdx.org/licenses/{page}.html\nUsage-Guide:\n  {guide}\nLicense-Text:\n\n").into_bytes();
    output.extend_from_slice(body);
    output
}

type Uses = BTreeMap<String, BTreeMap<String, (bool, bool)>>;
type Bases = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

fn record_expression(
    uses: &mut Uses,
    bases: &mut Bases,
    owner: &str,
    expression: &str,
) -> Vec<String> {
    let mut conflicts = Vec::new();
    let root_uses = uses.entry(owner.to_string()).or_default();
    for (id, exception, or_only) in rules::identifiers(expression) {
        let entry = root_uses.entry(id.clone()).or_insert((exception, true));
        if entry.0 != exception {
            conflicts.push(id);
        }
        entry.0 = exception;
        entry.1 &= or_only;
    }
    let root_bases = bases.entry(owner.to_string()).or_default();
    for (id, licenses) in rules::exception_bases(expression) {
        root_bases.entry(id).or_default().extend(licenses);
    }
    conflicts
}

/// Check coverage and text bodies, loading the corpus only when needed.
pub(crate) fn check(
    root: &Path,
    policy: &Policy,
    walk: &Walk,
    fix: bool,
    load_corpus: &mut impl FnMut() -> Result<BTreeMap<String, Vec<u8>>, String>,
) -> Result<Outcome, String> {
    let mut outcome = Outcome {
        problems: Vec::new(),
        edits: Vec::new(),
    };
    let mut uses = Uses::new();
    let mut bases = Bases::new();
    for file in &walk.files {
        if rules::is_text_path(&policy.roots, &file.rel) {
            continue;
        }
        if let (Some(owner), Some(rule)) = (
            rules::owning_root(&policy.roots, &file.rel),
            rules::select(&policy.rules, &file.rel),
        ) {
            if rule.upstream || rule.license_text {
                continue;
            }
            for id in record_expression(&mut uses, &mut bases, owner, &rule.expression) {
                outcome.problems.push(Problem {
                    kind: "kind",
                    path: file.rel.clone(),
                    detail: format!("`{id}` is used as both a license and an exception"),
                });
            }
        }
    }
    for (dir, rule_index) in &walk.pruned_rules {
        let Some(owner) = rules::owning_root(&policy.roots, dir) else {
            continue;
        };
        let Some(rule) = policy.rules.get(*rule_index) else {
            continue;
        };
        if rule.upstream || rule.license_text {
            continue;
        }
        for id in record_expression(&mut uses, &mut bases, owner, &rule.expression) {
            outcome.problems.push(Problem {
                kind: "kind",
                path: dir.clone(),
                detail: format!("`{id}` is used as both a license and an exception"),
            });
        }
    }
    let mut corpus_texts: Option<Result<BTreeMap<String, Vec<u8>>, String>> = None;
    for owner in &policy.roots {
        if let Err(detail) = safe_tree(root, owner) {
            outcome.problems.push(Problem {
                kind: "path",
                path: rel_path(owner, "LICENSES"),
                detail,
            });
            continue;
        }
        let files = scan_tree(root, owner, &mut outcome);
        let mut declared: BTreeMap<String, (bool, String)> = BTreeMap::new();
        for (rel, bytes, declaration) in &files {
            let exception_file = rel.split('/').rev().nth(1) == Some("exceptions");
            for id in &declaration.ids {
                if let Some((_, previous)) =
                    declared.insert(id.clone(), (exception_file, rel.clone()))
                {
                    outcome.problems.push(Problem {
                        kind: "duplicate",
                        path: rel.clone(),
                        detail: format!("`{id}` also declared at {previous}"),
                    });
                }
            }
            let owned = declaration
                .ids
                .iter()
                .filter(|id| rules::is_reference(id))
                .count();
            if owned != 0 && owned != declaration.ids.len() {
                outcome.problems.push(Problem {
                    kind: "header",
                    path: rel.clone(),
                    detail: "project-owned and corpus identifiers cannot share a file".into(),
                });
                continue;
            }
            if owned == declaration.ids.len() {
                if exception_file
                    && !bytes[declaration.body..]
                        .iter()
                        .any(|byte| !byte.is_ascii_whitespace())
                {
                    outcome.problems.push(Problem {
                        kind: "body",
                        path: rel.clone(),
                        detail: "project-owned exception body is empty".into(),
                    });
                }
                continue;
            }
            let texts = corpus_texts.get_or_insert_with(&mut *load_corpus);
            let texts = match texts {
                Ok(texts) => texts,
                Err(detail) => {
                    outcome.problems.push(Problem {
                        kind: "corpus",
                        path: rel.clone(),
                        detail: detail.clone(),
                    });
                    continue;
                }
            };
            let mut expected: Option<&Vec<u8>> = None;
            let mut valid = true;
            for id in &declaration.ids {
                let Some(body) = texts.get(rules::corpus_id(id)) else {
                    outcome.problems.push(Problem {
                        kind: "corpus",
                        path: rel.clone(),
                        detail: format!("missing corpus text `{}`", rules::corpus_id(id)),
                    });
                    valid = false;
                    continue;
                };
                if expected.is_some_and(|first| first != body) {
                    outcome.problems.push(Problem {
                        kind: "corpus",
                        path: rel.clone(),
                        detail: format!("corpus texts for declared identifiers differ at `{id}`"),
                    });
                    valid = false;
                }
                expected.get_or_insert(body);
            }
            if !valid {
                continue;
            }
            let Some(expected) = expected else {
                continue;
            };
            if &bytes[declaration.body..] != expected.as_slice() {
                if fix {
                    let mut replacement = bytes[..declaration.body].to_vec();
                    replacement.extend_from_slice(expected);
                    outcome.edits.push(Edit {
                        rel: rel.clone(),
                        path: host_path(root, rel),
                        before: Some(bytes.clone()),
                        after: replacement,
                        action: "rewrite",
                    });
                } else {
                    outcome.problems.push(Problem {
                        kind: "body",
                        path: rel.clone(),
                        detail: format!("differs from corpus text `{}`", declaration.ids[0]),
                    });
                }
            }
        }
        if let Some(required) = uses.get(owner) {
            for (id, &(exception, or_only)) in required {
                if let Some((actual_exception, actual_path)) = declared.get(id) {
                    if *actual_exception != exception {
                        outcome.problems.push(Problem {
                            kind: "kind",
                            path: actual_path.clone(),
                            detail: format!("`{id}` is declared as the wrong identifier kind"),
                        });
                    }
                    continue;
                }
                let subdir = if exception {
                    "exceptions"
                } else if or_only {
                    "dual"
                } else {
                    "other"
                };
                let rel = rel_path(owner, &format!("LICENSES/{subdir}/{id}"));
                if !fix || rules::is_reference(id) {
                    outcome.problems.push(Problem {
                        kind: "missing",
                        path: rel,
                        detail: format!("identifier `{id}` has no LICENSES declaration"),
                    });
                    continue;
                }
                let texts = corpus_texts.get_or_insert_with(&mut *load_corpus);
                let texts = match texts {
                    Ok(texts) => texts,
                    Err(detail) => {
                        outcome.problems.push(Problem {
                            kind: "corpus",
                            path: rel,
                            detail: detail.clone(),
                        });
                        continue;
                    }
                };
                let Some(body) = texts.get(rules::corpus_id(id)) else {
                    outcome.problems.push(Problem {
                        kind: "corpus",
                        path: rel,
                        detail: format!("missing corpus text `{}`", rules::corpus_id(id)),
                    });
                    continue;
                };
                let path = host_path(root, &rel);
                if let Err(detail) = safe_parent(root, &rel) {
                    outcome.problems.push(Problem {
                        kind: "path",
                        path: rel,
                        detail,
                    });
                    continue;
                }
                if fs::symlink_metadata(&path).is_ok() {
                    outcome.problems.push(Problem {
                        kind: "header",
                        path: rel,
                        detail: "existing file has no valid identifier header".into(),
                    });
                    continue;
                }
                let base_ids = bases
                    .get(owner)
                    .and_then(|items| items.get(id))
                    .cloned()
                    .unwrap_or_default();
                if exception && base_ids.is_empty() {
                    outcome.problems.push(Problem {
                        kind: "expression",
                        path: rel,
                        detail: format!("exception `{id}` has no base license"),
                    });
                    continue;
                }
                outcome.edits.push(Edit {
                    rel,
                    path,
                    before: None,
                    after: new_file(id, exception, &base_ids, body),
                    action: "insert",
                });
            }
        }
    }
    Ok(outcome)
}
