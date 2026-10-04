// SPDX-License-Identifier: GPL-2.0-only
//! Tests policy, text repair, and filesystem traversal contracts.
//! These tests use neutral fixtures and leave command dispatch in the parent module.

use super::{Edit, apply_edits, check, check_with_corpus, header, rules, texts, walk};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "license-check-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join(".buildutilignore"), "").unwrap();
        Self(path)
    }

    fn file(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = rel
            .split('/')
            .fold(self.0.clone(), |path, part| path.join(part));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    fn policy(&self, text: &str) {
        self.file("buildutil.toml", text.as_bytes());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn parse(text: &str) -> Result<Vec<rules::Rule>, String> {
    let doc = crate::spec::toml::parse(Path::new("buildutil.toml"), text)?;
    rules::parse(&doc)
}

fn rule() -> rules::Rule {
    rules::Rule {
        paths: vec!["**".into()],
        expression: "MIT".into(),
        header: true,
        banner: false,
        comment: None,
        upstream: false,
        license_text: false,
    }
}

fn inspect(rel: &str, text: &str, fix: bool) -> header::Inspection {
    header::inspect(rel, text, &rule(), fix).unwrap()
}

#[test]
fn rst_tag_spacing_and_multiline_blocks() {
    let inserted = inspect("doc.rst", "Heading\n", true).repaired.unwrap();
    assert_eq!(inserted, ".. SPDX-License-Identifier: MIT\n\nHeading\n");
    let existing = ".. SPDX-License-Identifier: MIT\nHeading\n";
    assert!(
        inspect("doc.rst", existing, false)
            .problems
            .iter()
            .any(|problem| problem.kind == "spacing")
    );
    assert_eq!(
        inspect("doc.rst", existing, true).repaired.unwrap(),
        inserted
    );

    let block = "/* SPDX-License-Identifier: Other\n * description\n */\n";
    assert!(
        inspect("a.c", block, false)
            .problems
            .iter()
            .any(|problem| problem.kind == "expression")
    );
    assert_eq!(
        inspect("a.c", block, true).repaired.unwrap(),
        block.replacen("Other", "MIT", 1)
    );
    let misplaced = format!("/* introduction */\n{block}");
    assert!(inspect("a.c", &misplaced, true).repaired.is_none());
}

#[test]
fn tag_grammar_marker_and_prefix() {
    let inline_code = "/* SPDX-License-Identifier: MIT */ int value;\n";
    let repaired = inspect("a.c", inline_code, true).repaired.unwrap();
    assert!(repaired.contains(inline_code));
    for line in [
        "// SPDX-License-Identifier: MIT /* extra\n",
        "// SPDX-License-Identifier: MIT */\n",
        "// SPDX-License-Identifier: MIT <!-- extra\n",
        "<!-- SPDX-License-Identifier: MIT --> <!-- extra -->\n",
    ] {
        assert!(
            inspect("a.rs", line, false)
                .problems
                .iter()
                .any(|problem| problem.kind == "missing")
        );
    }
    let wrong_marker = inspect("a.rs", "# SPDX-License-Identifier: MIT\nbody\n", true)
        .repaired
        .unwrap();
    assert_eq!(wrong_marker.matches("SPDX-License-Identifier:").count(), 1);
    assert!(wrong_marker.starts_with("// SPDX-License-Identifier: MIT\n"));
    assert_eq!(
        inspect("a.rs", "\u{feff}body\n", true).repaired.unwrap(),
        "\u{feff}// SPDX-License-Identifier: MIT\nbody\n"
    );
    assert_eq!(
        inspect("a.py", "# coding: utf-8\nvalue = 1\n", true)
            .repaired
            .unwrap(),
        "# coding: utf-8\n# SPDX-License-Identifier: MIT\nvalue = 1\n"
    );
    assert_eq!(
        inspect(
            "a.py",
            "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\nvalue = 1\n",
            true
        )
        .repaired
        .unwrap(),
        "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\n# SPDX-License-Identifier: MIT\nvalue = 1\n"
    );
}

#[test]
fn table_validation_and_order() {
    let base = "[license]\n[[license.rule]]\npaths = [\"a/**\"]\nexpression = \"MIT\"\n";
    assert!(
        parse(&base.replace("[license]", "[license]\nextra = true"))
            .unwrap_err()
            .contains("[license]: unknown key")
    );
    assert!(
        parse(&base.replace("expression = \"MIT\"\n", ""))
            .unwrap_err()
            .contains("expression")
    );
    for expr in [
        "MIT OR",
        "(MIT",
        "MIT WITH",
        "MIT && Apache-2.0",
        "MIT Apache-2.0",
    ] {
        assert!(parse(&base.replace("MIT", expr)).is_err(), "{expr}");
    }
    assert!(
        parse(&base.replace("expression =", "header = \"false\"\nexpression ="))
            .unwrap_err()
            .contains("header")
    );
    let rules = parse(&format!(
        "{base}[[license.rule]]\npaths = [\"a/b.rs\"]\nexpression = \"Apache-2.0\"\n"
    ))
    .unwrap();
    assert_eq!(rules::select(&rules, "a/b.rs").unwrap().expression, "MIT");
    assert!(
        parse(&base.replace(
            "MIT",
            "MIT WITH AdditionRef-note OR Apache-2.0 WITH AdditionRef-note"
        ))
        .is_ok()
    );
    assert!(parse(&base.replace("MIT", "(MIT OR Apache-2.0) WITH AdditionRef-note")).is_err());
    assert!(
        parse(&base.replace("expression =", "unknown = 1\nexpression ="))
            .unwrap_err()
            .contains("unknown key")
    );
}

#[test]
fn each_comment_family() {
    let cases = [
        ("a/b.rs", "//"),
        ("a/b.c", "/* */"),
        ("a/b.h", "/* */"),
        ("a/b.ld", "/* */"),
        ("a/b.cpp", "//"),
        ("a/b.cc", "//"),
        ("a/b.hpp", "//"),
        ("a/b.hh", "//"),
        ("a/b.S", "//"),
        ("a/b.asm", ";"),
        ("a/b.def", ";"),
        ("a/b.sh", "#"),
        ("a/b.bash", "#"),
        ("a/b.py", "#"),
        ("a/b.toml", "#"),
        ("a/b.port", "#"),
        ("a/b.patch", "#"),
        ("a/b.diff", "#"),
        ("a/b.service", "#"),
        ("a/b.socket", "#"),
        ("a/b.cap", "#"),
        ("a/b.target", "#"),
        ("a/b.mount", "#"),
        ("a/b.cmake", "#"),
        ("a/b.ninja", "#"),
        ("a/b.manifest", "#"),
        ("a/b.permissions", "#"),
        ("a/b.packages", "#"),
        ("a/b.conf", "#"),
        ("a/b.yml", "#"),
        ("a/b.yaml", "#"),
        ("a/b.mk", "#"),
        ("a/Makefile", "#"),
        ("a/.gitignore", "#"),
        ("a/.gitmodules", "#"),
        ("a/.gitattributes", "#"),
        ("a/.buildutilignore", "#"),
        ("a/.dockerignore", "#"),
        ("a/b.rst", ".."),
        ("a/b.md", "<!-- -->"),
    ];
    for (rel, marker) in cases {
        let result = inspect(rel, "body\n", true);
        let repaired = result.repaired.unwrap();
        let first = repaired.lines().next().unwrap();
        assert!(
            first.starts_with(if marker == "/* */" {
                "/*"
            } else if marker == "<!-- -->" {
                "<!--"
            } else {
                marker
            }),
            "{rel}: {first}"
        );
        assert!(inspect(rel, &repaired, false).problems.is_empty(), "{rel}");
    }
    assert!(
        inspect("a/b.rs", "//! SPDX-License-Identifier: MIT\n", false)
            .problems
            .is_empty()
    );
    assert!(
        inspect("a/b.h", "// SPDX-License-Identifier: MIT\n", false)
            .problems
            .is_empty()
    );
    assert!(
        inspect("a/b.cpp", "/* SPDX-License-Identifier: MIT */\n", false)
            .problems
            .is_empty()
    );
}

#[test]
fn shebang_banner_duplicates_and_assembly() {
    let result = inspect("a/tool", "#!/bin/sh\necho yes\n", true);
    assert_eq!(
        result.repaired.unwrap().lines().nth(1),
        Some("# SPDX-License-Identifier: MIT")
    );
    let mut banner_rule = rule();
    banner_rule.banner = true;
    assert!(
        header::inspect(
            "a/b.rs",
            "// preface\n// SPDX-License-Identifier: MIT\ncode\n",
            &banner_rule,
            false
        )
        .unwrap()
        .problems
        .is_empty()
    );
    assert!(
        header::inspect(
            "a/b.rs",
            "code\n// SPDX-License-Identifier: MIT\n",
            &banner_rule,
            false
        )
        .unwrap()
        .problems
        .iter()
        .any(|p| p.kind == "missing")
    );
    let duplicates = inspect(
        "a/b.rs",
        "// SPDX-License-Identifier: MIT\n// SPDX-License-Identifier: MIT\n",
        true,
    );
    assert!(duplicates.problems.iter().any(|p| p.kind == "duplicate"));
    assert!(duplicates.repaired.is_none());
    let assembly = inspect("a/b.S", "//! SPDX-License-Identifier: MIT\n", true);
    assert!(assembly.problems.iter().any(|p| p.kind == "marker"));
    assert_eq!(
        assembly.repaired.unwrap(),
        "// SPDX-License-Identifier: MIT\n"
    );
    // `#` is not a comment in C: the line has the wrong marker and the file
    // has no valid declaration, and a repair replaces that line in place.
    let preprocessor = inspect("a/b.c", "# SPDX-License-Identifier: MIT\nint x;\n", true);
    let kinds: Vec<_> = preprocessor.problems.iter().map(|p| p.kind).collect();
    assert!(kinds.contains(&"marker"), "{kinds:?}");
    assert!(kinds.contains(&"missing"), "{kinds:?}");
    assert_eq!(
        preprocessor.repaired.unwrap(),
        "/* SPDX-License-Identifier: MIT */\nint x;\n"
    );
    // A Rust block comment is a comment in the wrong style, not a missing tag.
    let block = inspect("a/b.rs", "/* SPDX-License-Identifier: MIT */\n", false);
    let kinds: Vec<_> = block.problems.iter().map(|p| p.kind).collect();
    assert_eq!(kinds, ["marker"]);
    let mut preprocessor_rule = rule();
    preprocessor_rule.comment = Some("#".into());
    assert!(
        header::inspect(
            "a/b.c",
            "# SPDX-License-Identifier: MIT\n",
            &preprocessor_rule,
            false
        )
        .is_err()
    );
}

#[test]
fn repair_preserves_endings_and_is_idempotent() {
    let first = inspect(
        "a/b.rs",
        "// title\r\n// SPDX-License-Identifier: Other\r\ncode\r\n",
        true,
    )
    .repaired
    .unwrap();
    assert_eq!(
        first,
        "// SPDX-License-Identifier: MIT\r\n// title\r\ncode\r\n"
    );
    assert!(inspect("a/b.rs", &first, true).repaired.is_none());
    let no_newline = inspect("a/b.rs", "code", true).repaired.unwrap();
    assert_eq!(no_newline, "// SPDX-License-Identifier: MIT\ncode");
    assert!(!no_newline.ends_with('\n'));
    let moved = inspect("a/b.rs", "code\n// SPDX-License-Identifier: MIT", true)
        .repaired
        .unwrap();
    assert_eq!(
        moved,
        "// SPDX-License-Identifier: MIT\ncode\n// SPDX-License-Identifier: MIT"
    );
    let mixed = inspect("a/b.rs", "code\r\nother\n", true).repaired.unwrap();
    assert_eq!(mixed, "// SPDX-License-Identifier: MIT\r\ncode\r\nother\n");
    let continuation = inspect(
        "a/b.c",
        "/*\n * SPDX-License-Identifier: Other\n */\n",
        true,
    );
    assert_eq!(
        continuation.repaired.unwrap().lines().next(),
        Some("/* SPDX-License-Identifier: MIT */")
    );
    let mut override_rule = rule();
    override_rule.comment = Some(";".into());
    assert!(
        header::inspect(
            "a/b.unknown",
            "; SPDX-License-Identifier: MIT\n",
            &override_rule,
            false
        )
        .unwrap()
        .problems
        .is_empty()
    );
    assert!(
        header::inspect("a/b.unknown", "", &rule(), false)
            .err()
            .is_some_and(|e| e.contains("no comment syntax"))
    );
}

#[test]
fn body_tag_shaped_text_is_not_a_header() {
    let body = "fn make() {\n    let text = r#\"\n# SPDX-License-Identifier: X\n\"#;\n}\n";
    let checked = inspect("a/b.rs", body, false);
    assert_eq!(checked.problems.len(), 1);
    assert_eq!(checked.problems[0].kind, "missing");
    let fixed = inspect("a/b.rs", body, true).repaired.unwrap();
    assert_eq!(fixed, format!("// SPDX-License-Identifier: MIT\n{body}"));
    assert!(fixed.contains("\n# SPDX-License-Identifier: X\n"));

    let correct = format!("// SPDX-License-Identifier: MIT\n{body}");
    let checked = inspect("a/b.rs", &correct, true);
    assert!(checked.problems.is_empty());
    assert!(checked.repaired.is_none());
}

#[test]
fn misplaced_tag_inside_comment_banner_moves() {
    let original = "/* title */\n/* SPDX-License-Identifier: X */\nSECTIONS {}\n";
    let checked = inspect("a/b.ld", original, false);
    assert!(checked.problems.iter().any(|p| p.kind == "placement"));
    let fixed = inspect("a/b.ld", original, true).repaired.unwrap();
    assert_eq!(
        fixed,
        "/* SPDX-License-Identifier: MIT */\n/* title */\nSECTIONS {}\n"
    );
}

#[test]
fn walk_coverage_filters_pruning_and_binary_declaration() {
    let fixture = Fixture::new();
    fixture.policy("[license]\n[[license.rule]]\npaths = [\"a/special.rs\"]\nexpression = \"MIT\"\n[[license.rule]]\npaths = [\"a/**\"]\nexpression = \"MIT\"\nheader = false\n[[license.rule]]\npaths = [\"**\"]\nexpression = \"MIT\"\nheader = false\n");
    fixture.file("a/special.rs", b"// SPDX-License-Identifier: MIT\n");
    fixture.file("a/binary.bin", &[0xff]);
    fixture.file("sub/.git", b"pointer");
    let rules = rules::load(&fixture.0).unwrap();
    assert!(!walk::prune("a", &rules));
    let wildcard_rules = parse("[license]\n[[license.rule]]\npaths = [\"a*/special.rs\"]\nexpression = \"MIT\"\n[[license.rule]]\npaths = [\"ab/**\"]\nexpression = \"MIT\"\nheader = false\n").unwrap();
    assert!(!walk::prune("ab", &wildcard_rules));
    assert!(
        walk::collect(&fixture.0, &rules)
            .unwrap()
            .files
            .iter()
            .any(|f| f.rel == "a/special.rs")
    );
    assert_eq!(check(&fixture.0, false).unwrap(), 0);
}

#[test]
fn exclusions_and_uncovered_files() {
    let fixture = Fixture::new();
    fixture.policy("[license]\n[[license.rule]]\npaths = [\"a/**\"]\nexpression = \"MIT\"\n");
    fixture.file("a/b.rs", b"// SPDX-License-Identifier: MIT\n");
    fixture.file("other.rs", b"// SPDX-License-Identifier: MIT\n");
    fixture.file(".git/ignored", b"invalid");
    fixture.file("ignored/other.rs", b"invalid");
    fs::write(fixture.0.join(".buildutilignore"), "ignored/\n").unwrap();
    let rules = rules::load(&fixture.0).unwrap();
    let files = walk::collect(&fixture.0, &rules).unwrap().files;
    assert!(
        !files
            .iter()
            .any(|f| f.rel.starts_with(".git/") || f.rel.starts_with("ignored/"))
    );
    assert_eq!(check(&fixture.0, false).unwrap(), 1);
}

#[cfg(unix)]
#[test]
fn executable_bit_survives_repair() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.policy(
        "[license]\n[[license.rule]]\npaths = [\"a/**\"]\nexpression = \"MIT\"\n[[license.rule]]\npaths = [\"buildutil.toml\", \".buildutilignore\"]\nexpression = \"MIT\"\nheader = false\n",
    );
    let path = fixture.file("a/tool.sh", b"#!/bin/sh\necho yes\n");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(check(&fixture.0, true).unwrap(), 0);
    assert_ne!(fs::metadata(&path).unwrap().permissions().mode() & 0o111, 0);
}

#[test]
fn unfixable_source_and_corpus_failure_leave_all_files_unchanged() {
    let fixture = Fixture::new();
    fixture.policy(
        "[license]\n[[license.rule]]\npaths = [\"src/**\"]\nexpression = \"MIT\"\n[[license.rule]]\npaths = [\"buildutil.toml\", \".buildutilignore\"]\nkind = \"license-text\"\n",
    );
    let source = fixture.file("src/a.rs", b"body\n");
    fixture.file("uncovered.txt", b"body\n");
    assert_eq!(check(&fixture.0, true).unwrap(), 1);
    assert_eq!(fs::read(&source).unwrap(), b"body\n");
    fs::remove_file(fixture.0.join("uncovered.txt")).unwrap();
    fixture.file("src/unknown", b"body\n");
    assert_eq!(check(&fixture.0, true).unwrap(), 1);
    assert_eq!(fs::read(&source).unwrap(), b"body\n");

    let corpus_fixture = Fixture::new();
    corpus_fixture.policy("[license]\nroots = [\"\"]\ncorpus = \"texts\"\n[[license.rule]]\npaths = [\"src/**\"]\nexpression = \"MIT\"\n[[license.rule]]\npaths = [\"**\"]\nkind = \"license-text\"\n");
    let source = corpus_fixture.file("src/a.rs", b"body\n");
    corpus_fixture.file("LICENSES/other/MIT", b"Valid-License-Identifier: MIT\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nbody\n");
    assert_eq!(
        check_with_corpus(&corpus_fixture.0, true, &mut || Err(
            "corpus unavailable".into()
        ))
        .unwrap(),
        1
    );
    assert_eq!(fs::read(source).unwrap(), b"body\n");
}

#[test]
fn atomic_replacement_rejects_changed_content() {
    let fixture = Fixture::new();
    let path = fixture.file("sample.txt", b"old");
    let edit = Edit {
        rel: "sample.txt".into(),
        path: path.clone(),
        before: Some(b"old".to_vec()),
        after: b"new".to_vec(),
        action: "rewrite",
    };
    fs::write(&path, b"changed").unwrap();
    let (count, problems) = apply_edits(&[edit]);
    assert_eq!(count, 0);
    assert_eq!(problems[0].0, "conflict");
    assert_eq!(fs::read(path).unwrap(), b"changed");
}

fn corpus_texts() -> BTreeMap<String, Vec<u8>> {
    [
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "Classpath-exception-2.0",
    ]
    .into_iter()
    .map(|id| (id.to_string(), format!("body for {id}\n").into_bytes()))
    .collect()
}

fn text_policy(roots: &str, expression: &str) -> String {
    format!(
        "[license]\nroots = {roots}\ncorpus = \"spdx-texts\"\n[[license.rule]]\npaths = [\"src/**\"]\nexpression = \"{expression}\"\nheader = false\n[[license.rule]]\npaths = [\"**\"]\nkind = \"license-text\"\n"
    )
}

fn text_check(fixture: &Fixture, fix: bool) -> i32 {
    check_with_corpus(&fixture.0, fix, &mut || Ok(corpus_texts())).unwrap()
}

#[test]
fn license_text_schema_and_header_validation() {
    let good = text_policy("[\"\"]", "MIT");
    assert!(parse(&good).is_ok());
    assert!(
        parse(&good.replace(
            "kind = \"license-text\"",
            "kind = \"license-text\"\nexpression = \"MIT\""
        ))
        .unwrap_err()
        .contains("cannot have an expression")
    );
    assert!(parse(&good.replace("roots = [\"\"]", "roots = [\"../bad\"]")).is_err());
    let fixture = Fixture::new();
    fixture.policy(&good);
    fixture.file("src/a.rs", b"source");
    fixture.file("LICENSES/dual/MIT", b"Valid-License-Identifier: MIT\nValid-License-Identifier: Apache-2.0\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nbody for MIT\n");
    fixture.file("LICENSES/exceptions/Classpath-exception-2.0", b"SPDX-Exception-Identifier: Classpath-exception-2.0\nSPDX-Licenses: MIT, Apache-2.0\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nbody for Classpath-exception-2.0\n");
    assert_eq!(text_check(&fixture, false), 1);
    assert_eq!(
        check_with_corpus(&fixture.0, false, &mut || {
            let mut texts = corpus_texts();
            texts.insert("Apache-2.0".into(), b"body for MIT\n".to_vec());
            Ok(texts)
        })
        .unwrap(),
        0
    );
    fixture.file("LICENSES/dual/MIT", b"Valid-License-Identifier: MIT\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nbody for MIT\n");
    fixture.file("LICENSES/other/BSD-2-Clause", b"Valid-License-Identifier: BSD-2-Clause\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\n");
    assert_eq!(text_check(&fixture, false), 1);
    fixture.file("LICENSES/unknown/file", b"invalid");
    assert_eq!(text_check(&fixture, false), 1);
}

#[test]
fn project_owned_exception_does_not_require_spdx_url() {
    let fixture = Fixture::new();
    fixture.policy(&text_policy("[\"\"]", "MIT"));
    fixture.file("LICENSES/exceptions/AdditionRef-x", b"SPDX-Exception-Identifier: AdditionRef-x\nSPDX-Licenses: MIT\nUsage-Guide:\n  example\nLicense-Text:\n\nlocal exception\n");
    assert_eq!(text_check(&fixture, false), 0);

    let corpus_fixture = Fixture::new();
    corpus_fixture.policy(&text_policy("[\"\"]", "MIT"));
    corpus_fixture.file("LICENSES/exceptions/Classpath-exception-2.0", b"SPDX-Exception-Identifier: Classpath-exception-2.0\nSPDX-Licenses: MIT\nUsage-Guide:\n  example\nLicense-Text:\n\nbody for Classpath-exception-2.0\n");
    assert_eq!(text_check(&corpus_fixture, false), 1);
}

#[test]
fn nested_roots_upstream_and_license_text_exclusions() {
    let fixture = Fixture::new();
    fixture.policy("[license]\nroots = [\"\", \"vendor/pkg\"]\ncorpus = \"spdx-texts\"\n[[license.rule]]\npaths = [\"vendor/pkg/src/**\"]\nexpression = \"Apache-2.0\"\nheader = false\n[[license.rule]]\npaths = [\"src/**\"]\nexpression = \"MIT\"\nheader = false\n[[license.rule]]\npaths = [\"upstream/**\"]\nexpression = \"BSD-2-Clause\"\nupstream = true\nheader = false\n[[license.rule]]\npaths = [\"**\"]\nkind = \"license-text\"\n");
    fixture.file("src/a.rs", b"source");
    fixture.file("vendor/pkg/src/b.rs", b"source");
    fixture.file("upstream/c.rs", b"source");
    fixture.file("LICENSE.md", b"overview");
    fixture.file("vendor/pkg/LICENSE.md", b"overview");
    assert_eq!(text_check(&fixture, true), 0);
    assert!(fixture.0.join("LICENSES/other/MIT").is_file());
    assert!(
        fixture
            .0
            .join("vendor/pkg/LICENSES/other/Apache-2.0")
            .is_file()
    );
    assert!(!fixture.0.join("LICENSES/other/Apache-2.0").exists());
    assert!(!fixture.0.join("LICENSES/other/BSD-2-Clause").exists());
    assert_eq!(text_check(&fixture, false), 0);
}

#[test]
fn body_repair_project_owned_and_missing_categories() {
    let fixture = Fixture::new();
    fixture.policy(&text_policy("[\"\"]", "MIT OR Apache-2.0"));
    fixture.file("src/a.rs", b"source");
    fixture.file("LICENSES/dual/MIT", b"Valid-License-Identifier: MIT\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nwrong\n");
    fixture.file("LICENSES/other/AdditionRef-local", b"Valid-License-Identifier: AdditionRef-local\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nlocal\n");
    assert_eq!(text_check(&fixture, false), 1);
    assert_eq!(text_check(&fixture, true), 0);
    assert!(
        fs::read_to_string(fixture.0.join("LICENSES/dual/MIT"))
            .unwrap()
            .ends_with("body for MIT\n")
    );
    assert!(fixture.0.join("LICENSES/dual/Apache-2.0").is_file());
    assert_eq!(text_check(&fixture, false), 0);

    let second = Fixture::new();
    second.policy(&text_policy(
        "[\"\"]",
        "MIT AND Apache-2.0 WITH Classpath-exception-2.0",
    ));
    second.file("src/b.rs", b"source");
    assert_eq!(text_check(&second, true), 0);
    assert!(second.0.join("LICENSES/other/MIT").is_file());
    assert!(second.0.join("LICENSES/other/Apache-2.0").is_file());
    assert!(
        second
            .0
            .join("LICENSES/exceptions/Classpath-exception-2.0")
            .is_file()
    );
}

#[test]
fn malformed_text_is_never_rewritten() {
    let fixture = Fixture::new();
    fixture.policy(&text_policy("[\"\"]", "MIT"));
    fixture.file("src/a.rs", b"source");
    let malformed = fixture.file("LICENSES/other/MIT", b"body without a header\n");
    assert_eq!(text_check(&fixture, true), 1);
    assert_eq!(fs::read(malformed).unwrap(), b"body without a header\n");
}

#[test]
fn license_files_need_no_source_rule() {
    let fixture = Fixture::new();
    fixture.policy(
        "[license]\nroots = [\"\"]\ncorpus = \"spdx-texts\"\n[[license.rule]]\npaths = [\"src/**\"]\nexpression = \"MIT\"\nheader = false\n[[license.rule]]\npaths = [\"buildutil.toml\", \".buildutilignore\"]\nkind = \"license-text\"\n",
    );
    fixture.file("src/a.rs", b"source");
    fixture.file("LICENSE.md", b"overview");
    assert_eq!(text_check(&fixture, true), 0);
    assert_eq!(text_check(&fixture, false), 0);
}

#[test]
fn duplicate_identifier_is_reported() {
    let fixture = Fixture::new();
    fixture.policy(&text_policy("[\"\"]", "MIT"));
    fixture.file("src/a.rs", b"source");
    assert_eq!(text_check(&fixture, true), 0);
    let first = fs::read(fixture.0.join("LICENSES/other/MIT")).unwrap();
    fixture.file("LICENSES/preferred/copy", &first);
    assert_eq!(text_check(&fixture, false), 1);
}

#[test]
fn pruned_rules_preserve_identifier_coverage() {
    let fixture = Fixture::new();
    fixture.policy("[license]\nroots = [\"\"]\ncorpus = \"texts\"\n[[license.rule]]\npaths = [\"upstream/**\"]\nexpression = \"BSD-2-Clause\"\nheader = false\nupstream = true\n[[license.rule]]\npaths = [\"src/**\"]\nexpression = \"MIT\"\nheader = false\n[[license.rule]]\npaths = [\"**\"]\nkind = \"license-text\"\n");
    fixture.file("upstream/tree/ignored.rs", b"body");
    fixture.file("src/a.rs", b"body");
    let policy = rules::load_policy(&fixture.0).unwrap();
    let files = walk::collect_with_roots(&fixture.0, &policy.rules, &policy.roots).unwrap();
    assert!(
        files
            .pruned_rules
            .iter()
            .any(|(path, _)| path == "upstream")
    );
    assert!(files.pruned_rules.iter().any(|(path, _)| path == "src"));
    assert!(
        !files
            .files
            .iter()
            .any(|file| file.rel.starts_with("upstream/") || file.rel.starts_with("src/"))
    );
    assert_eq!(text_check(&fixture, true), 0);
    assert!(fixture.0.join("LICENSES/other/MIT").exists());
    assert!(!fixture.0.join("LICENSES/other/BSD-2-Clause").exists());
}

#[test]
fn identifier_kinds_and_corpus_bodies() {
    let fixture = Fixture::new();
    fixture.policy(&text_policy("[\"\"]", "MIT WITH Classpath-exception-2.0"));
    fixture.file("src/a.rs", b"body");
    fixture.file("LICENSES/other/Classpath-exception-2.0", b"Valid-License-Identifier: Classpath-exception-2.0\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nbody for Classpath-exception-2.0\n");
    assert_eq!(text_check(&fixture, true), 1);
    assert!(!fixture.0.join("LICENSES/other/MIT").exists());

    let mixed = Fixture::new();
    mixed.policy(&text_policy("[\"\"]", "MIT"));
    mixed.file("LICENSES/other/mixed", b"Valid-License-Identifier: MIT\nValid-License-Identifier: LicenseRef-local\nSPDX-URL: https://example.invalid\nUsage-Guide:\n  example\nLicense-Text:\n\nbody for MIT\n");
    mixed.file(
        "LICENSES/exceptions/AdditionRef-x",
        b"SPDX-Exception-Identifier: AdditionRef-x\nUsage-Guide:\n  example\nLicense-Text:\n\n",
    );
    assert_eq!(text_check(&mixed, false), 1);
    let empty_exception = Fixture::new();
    empty_exception.policy(&text_policy("[\"\"]", "MIT"));
    empty_exception.file(
        "LICENSES/exceptions/AdditionRef-x",
        b"SPDX-Exception-Identifier: AdditionRef-x\nUsage-Guide:\n  example\nLicense-Text:\n\n",
    );
    assert_eq!(text_check(&empty_exception, false), 1);
}

#[test]
fn generated_exception_names_its_base_licenses() {
    let fixture = Fixture::new();
    fixture.policy(&text_policy(
        "[\"\"]",
        "MIT WITH Classpath-exception-2.0 OR Apache-2.0 WITH Classpath-exception-2.0",
    ));
    fixture.file("src/a.rs", b"body");
    assert_eq!(text_check(&fixture, true), 0);
    let exception = fs::read_to_string(
        fixture
            .0
            .join("LICENSES/exceptions/Classpath-exception-2.0"),
    )
    .unwrap();
    assert!(exception.contains("SPDX-Licenses: Apache-2.0, MIT\n"));
    assert!(exception.contains("SPDX-License-Identifier: <license> WITH Classpath-exception-2.0"));
}

#[test]
fn expression_grouping_and_precedence_classify_dual_use() {
    let ids = rules::identifiers("MIT AND (Apache-2.0 OR BSD-2-Clause)");
    assert_eq!(
        ids,
        vec![
            ("MIT".into(), false, false),
            ("Apache-2.0".into(), false, true),
            ("BSD-2-Clause".into(), false, true)
        ]
    );
    let ids =
        rules::identifiers("(MIT AND BSD-2-Clause) OR Apache-2.0 WITH Classpath-exception-2.0");
    assert!(ids.iter().any(|(id, _, dual)| id == "MIT" && !dual));
    assert!(
        ids.iter()
            .any(|(id, _, dual)| id == "BSD-2-Clause" && !dual)
    );
    assert!(ids.iter().any(|(id, _, dual)| id == "Apache-2.0" && *dual));
    assert!(
        ids.iter()
            .any(|(id, exception, _)| id == "Classpath-exception-2.0" && *exception)
    );
}

#[test]
fn required_an_exception_applies_to_one_license_and_plus_follows_a_license() {
    let policy = |expression: &str| parse(&text_policy("[\"\"]", expression));
    for valid in [
        "GPL-2.0+",
        "GPL-2.0+ WITH Classpath-exception-2.0",
        "MIT AND Apache-2.0 WITH Classpath-exception-2.0",
        "(MIT OR Apache-2.0 WITH Classpath-exception-2.0) AND BSD-2-Clause",
        "LicenseRef-local",
    ] {
        assert!(policy(valid).is_ok(), "{valid}");
    }
    // SPDX applies WITH to a single license: neither a parenthesized nor a
    // compound expression takes an exception, and an exception takes no
    // `+`, which follows a license identifier once.
    for invalid in [
        "(MIT OR Apache-2.0) WITH Classpath-exception-2.0",
        "(MIT) WITH Classpath-exception-2.0",
        "MIT WITH Classpath-exception-2.0 WITH LLVM-exception",
        "MIT WITH Classpath-exception-2.0+",
        "GPL+2.0",
        "MIT++",
        "+",
        "LicenseRef-local+",
    ] {
        assert!(policy(invalid).is_err(), "{invalid}");
    }
    let bases = rules::exception_bases(
        "MIT WITH Classpath-exception-2.0 OR Apache-2.0+ WITH Classpath-exception-2.0",
    );
    assert_eq!(
        bases["Classpath-exception-2.0"],
        ["Apache-2.0+".to_string(), "MIT".to_string()]
            .into_iter()
            .collect::<std::collections::BTreeSet<String>>()
    );
}

#[test]
fn required_a_license_with_the_plus_operator_uses_its_license_text() {
    let fixture = Fixture::new();
    fixture.policy(&text_policy("[\"\"]", "Apache-2.0+"));
    fixture.file("src/a.rs", b"source");
    assert_eq!(text_check(&fixture, false), 1);
    assert_eq!(text_check(&fixture, true), 0);
    let text = fs::read_to_string(fixture.0.join("LICENSES/other/Apache-2.0+")).unwrap();
    assert!(text.starts_with("Valid-License-Identifier: Apache-2.0+\n"));
    assert!(text.contains("SPDX-URL: https://spdx.org/licenses/Apache-2.0.html\n"));
    assert!(text.ends_with("body for Apache-2.0\n"));
    assert_eq!(text_check(&fixture, false), 0);

    // One text declares a license and its or-later form.
    let both = Fixture::new();
    both.policy(&text_policy("[\"\"]", "Apache-2.0 OR Apache-2.0+"));
    both.file("src/a.rs", b"source");
    both.file("LICENSES/dual/Apache-2.0", b"Valid-License-Identifier: Apache-2.0\nValid-License-Identifier: Apache-2.0+\nSPDX-URL: https://spdx.org/licenses/Apache-2.0.html\nUsage-Guide:\n  example\nLicense-Text:\n\nbody for Apache-2.0\n");
    assert_eq!(text_check(&both, false), 0);
}

#[test]
fn corpus_archive_plain_and_gzip() {
    const GZIP: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 19, 237, 205, 177, 9, 2, 81, 16, 4, 208, 141, 173, 194, 10,
        244, 127, 56, 175, 7, 3, 51, 27, 80, 206, 88, 208, 21, 206, 238, 93, 140, 196, 92, 65, 124,
        47, 153, 97, 146, 201, 211, 156, 235, 221, 118, 191, 202, 57, 227, 67, 90, 25, 135, 225,
        153, 229, 61, 203, 230, 165, 215, 222, 91, 239, 99, 44, 91, 124, 193, 237, 154, 135, 75,
        221, 199, 127, 58, 158, 167, 251, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 248, 53, 15, 26, 126, 193,
        193, 0, 40, 0, 0,
    ];
    const TOP_GZIP: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 19, 237, 205, 49, 10, 194, 64, 20, 4, 208, 173, 115, 10, 79,
        96, 18, 76, 114, 7, 11, 59, 47, 144, 224, 118, 66, 32, 89, 33, 222, 222, 143, 149, 88, 139,
        32, 190, 215, 204, 48, 205, 44, 249, 154, 199, 53, 215, 37, 111, 165, 62, 29, 207, 251,
        178, 149, 244, 97, 77, 24, 186, 238, 153, 225, 61, 67, 255, 210, 99, 111, 219, 254, 48,
        164, 93, 147, 190, 224, 182, 150, 113, 137, 251, 244, 159, 166, 249, 114, 175, 18, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 191, 230, 1, 7, 143, 106, 145, 0, 40, 0, 0,
    ];
    let fixture = Fixture::new();
    let gzip = fixture.file("source.tar", GZIP);
    assert_eq!(
        texts::corpus(&gzip).unwrap().get("MIT").unwrap().as_slice(),
        b"body\n"
    );
    let top = fixture.file("top.tar.gz", TOP_GZIP);
    assert_eq!(
        texts::corpus(&top).unwrap().get("MIT").unwrap().as_slice(),
        b"body\n"
    );
    let mut plain = Vec::new();
    let mut block = [0u8; 512];
    block[..12].copy_from_slice(b"text/MIT.txt");
    block[100..108].copy_from_slice(b"0000644\0");
    block[124..136].copy_from_slice(b"00000000005\0");
    block[148..156].fill(b' ');
    block[156] = b'0';
    let checksum: u64 = block.iter().map(|byte| *byte as u64).sum();
    block[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    plain.extend_from_slice(&block);
    plain.extend_from_slice(b"body\n");
    plain.resize(1024, 0);
    plain.resize(2048, 0);
    let tar = fixture.file("plain.tar", &plain);
    assert_eq!(
        texts::corpus(&tar).unwrap().get("MIT").unwrap().as_slice(),
        b"body\n"
    );
    crate::exec::untar::scan_archive(
        &tar,
        |_, _| false,
        |entry| {
            assert!(entry.body.is_none());
            Ok(())
        },
    )
    .unwrap();
    let mut mixed = plain[..1024].to_vec();
    let mut second = block;
    second[..100].fill(0);
    second[..16].copy_from_slice(b"other/text/X.txt");
    second[148..156].fill(b' ');
    let checksum: u64 = second.iter().map(|byte| *byte as u64).sum();
    second[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    mixed.extend_from_slice(&second);
    mixed.extend_from_slice(b"body\n");
    mixed.resize(2048, 0);
    mixed.resize(3072, 0);
    let mixed = fixture.file("mixed.tar", &mixed);
    assert!(texts::corpus(&mixed).is_err());
}
