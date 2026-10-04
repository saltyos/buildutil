//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — depfile parsing and the post-hoc read audit
//!
//! Declared inputs are authoritative for hashing; depfiles never feed back
//! into input sets. rustc dep-info and clang -MMD output is captured after
//! a build and audited: a read outside the staged inputs, dep store paths,
//! the toolchain trees, or the build dir means the spec under-declares its
//! sources — warn by default, fail under `--audit=error`.

use std::path::{Path, PathBuf};

/// Parse a Makefile-style depfile (`target: dep dep \` continuations).
pub fn parse(text: &str) -> Vec<String> {
    let joined = text.replace("\\\n", " ");
    let mut deps = Vec::new();
    for line in joined.lines() {
        let Some((_, rhs)) = line.split_once(':') else {
            continue;
        };
        for token in rhs.split_whitespace() {
            deps.push(token.replace("\\ ", " "));
        }
    }
    deps
}

/// Collect every `.d` file under a directory (non-recursive plus one
/// level — build cwds are flat).
fn collect_depfiles(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "d") {
            out.push(path);
        } else if path.is_dir() {
            for sub in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                let sub = sub.path();
                if sub.extension().is_some_and(|e| e == "d") {
                    out.push(sub);
                }
            }
        }
    }
    out.sort();
    out
}

/// Audit the reads recorded in the build dir's depfiles against the
/// allowed roots. Returns the violating paths.
pub fn audit(build_dir: &Path, allowed_roots: &[PathBuf]) -> Vec<String> {
    let mut violations = Vec::new();
    for depfile in collect_depfiles(build_dir) {
        let Ok(text) = std::fs::read_to_string(&depfile) else {
            continue;
        };
        for dep in parse(&text) {
            if dep.ends_with(".o") || dep.ends_with(".obj") || dep.ends_with(".rmeta") {
                continue; // the rule's own target echoes
            }
            let path = if Path::new(&dep).is_absolute() {
                PathBuf::from(&dep)
            } else {
                depfile.parent().unwrap_or(build_dir).join(&dep)
            };
            let Ok(real) = path.canonicalize() else {
                continue; // vanished temp — not a hidden input
            };
            let ok = allowed_roots.iter().any(|root| {
                root.canonicalize()
                    .map(|r| real.starts_with(&r))
                    .unwrap_or(false)
            });
            if !ok {
                violations.push(real.to_string_lossy().into_owned());
            }
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_continuations_and_multiple_rules() {
        let text = "a.o: ../x.c \\\n  ../inc/y.h\nb.o: ../z.c\n";
        let deps = parse(text);
        assert_eq!(deps, vec!["../x.c", "../inc/y.h", "../z.c"]);
    }
}
