// SPDX-License-Identifier: GPL-2.0-only
//! KTAP version 1 documents extracted from a raw console stream, and their
//! completeness against an expected-program list the caller passes.
//!
//! The parser reads only KTAP lines — version, `# Subtest:`, plan, result
//! and `#` diagnostic lines — and ignores every other line. Version lines
//! and plans carry the structure; the four-space indentation KUnit emits
//! decides which open stream a line belongs to, so a trailing plan and the
//! enclosing result the runner writes after a nested stream land at the
//! right level. What a finished parse means for a verdict is the caller's
//! policy; this module reports completion, malformation and failure only.

use crate::wire::Value;

/// Spaces per nesting level, as KUnit emits them.
const INDENT: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectiveKind {
    Skip,
    Xfail,
    Timeout,
    Error,
    /// Directive text KTAP does not define; the result keeps its status.
    Other(String),
}

impl DirectiveKind {
    fn as_str(&self) -> &str {
        match self {
            DirectiveKind::Skip => "SKIP",
            DirectiveKind::Xfail => "XFAIL",
            DirectiveKind::Timeout => "TIMEOUT",
            DirectiveKind::Error => "ERROR",
            DirectiveKind::Other(text) => text,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directive {
    pub kind: DirectiveKind,
    /// Text after the directive word (a skip or error reason, a timeout).
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub count: u32,
    /// The reason of a skip-all plan, `1..0 # SKIP <reason>`.
    pub skip_reason: Option<String>,
    /// Whether the plan preceded the stream's results.
    pub leading: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Test {
    pub number: u32,
    pub description: String,
    /// The result line said `ok`.
    pub ok: bool,
    pub directive: Option<Directive>,
    /// The result line's diagnostic data after `#`, directive removed.
    pub data: String,
    /// `#` diagnostic lines between the previous result and this one.
    pub diagnostics: Vec<String>,
    /// The nested stream the child wrote before the runner's result.
    pub nested: Option<Stream>,
}

impl Test {
    /// Whether this test fails: its own `not ok`, or any failing nested
    /// result even under a passing enclosing line.
    pub fn failed(&self) -> bool {
        !self.ok || self.nested.as_ref().is_some_and(Stream::failed)
    }

    /// The skip reason: the directive's text, or for a bare runner `SKIP`
    /// the reason of the child's skip-all plan directly above it.
    pub fn skip_reason(&self) -> Option<String> {
        let directive = self.directive.as_ref()?;
        if directive.kind != DirectiveKind::Skip {
            return None;
        }
        if !directive.text.is_empty() {
            return Some(directive.text.clone());
        }
        self.nested
            .as_ref()
            .and_then(|stream| stream.plan.as_ref())
            .and_then(|plan| plan.skip_reason.clone())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stream {
    /// The `# Subtest:` name following the stream's version line.
    pub name: Option<String>,
    pub plan: Option<Plan>,
    pub tests: Vec<Test>,
    /// Diagnostics after the last result.
    pub trailing_diagnostics: Vec<String>,
    /// Why the stream is malformed: wrong numbering, results beyond the
    /// plan, a second plan, an unsupported version.
    pub malformed: Vec<String>,
}

impl Stream {
    /// Every planned result, nested ones included, has arrived.
    pub fn complete(&self) -> bool {
        let Some(plan) = &self.plan else {
            return false;
        };
        self.tests.len() as u32 == plan.count
            && self
                .tests
                .iter()
                .all(|test| test.nested.as_ref().is_none_or(Stream::complete))
    }

    pub fn is_malformed(&self) -> bool {
        !self.malformed.is_empty()
            || self
                .tests
                .iter()
                .any(|test| test.nested.as_ref().is_some_and(Stream::is_malformed))
    }

    pub fn failed(&self) -> bool {
        self.tests.iter().any(Test::failed)
    }

    /// Every explanation of malformation or incompleteness, nested ones
    /// prefixed by their test.
    pub fn problems(&self) -> Vec<String> {
        let mut out = self.malformed.clone();
        match &self.plan {
            None => out.push("no plan: completion is unproved".to_string()),
            Some(plan) if (self.tests.len() as u32) < plan.count => out.push(format!(
                "{} of {} planned results arrived",
                self.tests.len(),
                plan.count
            )),
            _ => {}
        }
        for test in &self.tests {
            if let Some(nested) = &test.nested {
                for problem in nested.problems() {
                    out.push(format!("{}: {problem}", test.description));
                }
            }
        }
        out
    }
}

/// One program's document: the outer stream whose `# Subtest:` names the
/// program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    pub program: String,
    pub stream: Stream,
}

/// Parse every document in `text`. Lines that are not KTAP are ignored.
pub fn parse(text: &str) -> Vec<Document> {
    let mut parser = Parser::default();
    for raw in text.split('\n') {
        parser.line(raw.trim_end_matches('\r'));
    }
    parser.finish()
}

#[derive(Default)]
struct Parser {
    documents: Vec<Document>,
    /// Open streams, outermost first, with their nesting depth. The
    /// outermost is the current document.
    open: Vec<Stream>,
    /// Indentation of the current document's version line.
    base: usize,
    /// A version line was just read; the next `# Subtest:` names it.
    awaiting_name: bool,
    /// Diagnostics waiting for the next result, per open depth.
    pending: Vec<Vec<String>>,
}

enum Line<'a> {
    Version(&'a str),
    Subtest(&'a str),
    Plan(u32, Option<String>),
    Result {
        ok: bool,
        number: u32,
        description: String,
        directive: Option<Directive>,
        data: String,
    },
    Diagnostic(&'a str),
    Other,
}

fn classify(content: &str) -> Line<'_> {
    if let Some(version) = content.strip_prefix("KTAP version ") {
        return Line::Version(version.trim());
    }
    if let Some(name) = content.strip_prefix("# Subtest:") {
        return Line::Subtest(name.trim());
    }
    if let Some(rest) = content.strip_prefix("1..") {
        let (count, tail) = match rest.find(|c: char| !c.is_ascii_digit()) {
            Some(end) => (&rest[..end], rest[end..].trim()),
            None => (rest, ""),
        };
        if let Ok(count) = count.parse::<u32>() {
            if tail.is_empty() {
                return Line::Plan(count, None);
            }
            if let Some(reason) = tail
                .strip_prefix('#')
                .map(str::trim)
                .and_then(|t| t.strip_prefix("SKIP"))
            {
                return Line::Plan(count, Some(reason.trim().to_string()));
            }
        }
    }
    let (ok, rest) = if let Some(rest) = content.strip_prefix("not ok ") {
        (false, Some(rest))
    } else if let Some(rest) = content.strip_prefix("ok ") {
        (true, Some(rest))
    } else {
        (false, None)
    };
    if let Some(rest) = rest {
        let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if let Ok(number) = rest[..digits_end].parse::<u32>() {
            let after = &rest[digits_end..];
            if after.is_empty() || after.starts_with(' ') {
                let (description, annotation) = match after.find('#') {
                    Some(hash) => (after[..hash].trim(), Some(after[hash + 1..].trim())),
                    None => (after.trim(), None),
                };
                let (directive, data) = match annotation {
                    None => (None, String::new()),
                    Some(text) => split_directive(text),
                };
                return Line::Result {
                    ok,
                    number,
                    description: description.trim_start_matches("- ").to_string(),
                    directive,
                    data,
                };
            }
        }
    }
    if let Some(text) = content.strip_prefix('#') {
        return Line::Diagnostic(text.trim_start());
    }
    Line::Other
}

fn split_directive(text: &str) -> (Option<Directive>, String) {
    let word_end = text.find(char::is_whitespace).unwrap_or(text.len());
    let word = &text[..word_end];
    let rest = text[word_end..].trim().to_string();
    let kind = match word {
        "SKIP" => DirectiveKind::Skip,
        "XFAIL" => DirectiveKind::Xfail,
        "TIMEOUT" => DirectiveKind::Timeout,
        "ERROR" => DirectiveKind::Error,
        "" => return (None, String::new()),
        other if other.bytes().all(|b| b.is_ascii_uppercase()) => {
            DirectiveKind::Other(other.to_string())
        }
        _ => return (None, text.to_string()),
    };
    // A timeout's data is its limit and an error's its cause; both stay
    // with the directive.
    (Some(Directive { kind, text: rest }), String::new())
}

impl Parser {
    fn depth_of(&self, indent: usize) -> usize {
        indent.saturating_sub(self.base) / INDENT
    }

    fn line(&mut self, raw: &str) {
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        let content = raw[indent..].trim_end();
        let line = classify(content);
        if matches!(line, Line::Other) {
            return;
        }
        if self.open.is_empty() {
            // Only a version line opens a document; stray KTAP-looking
            // lines outside any document are not results.
            if let Line::Version(version) = line {
                self.base = indent;
                self.open_stream(version);
            }
            return;
        }
        let depth = self.depth_of(indent);
        if indent < self.base {
            // Left of the document: a line outside it (a log line that
            // happens to look like KTAP) is ignored unless it starts a new
            // document.
            if let Line::Version(version) = line {
                self.close_document();
                self.base = indent;
                self.open_stream(version);
            }
            return;
        }
        match line {
            Line::Version(version) => {
                if depth == 0 {
                    // A new program document at the outer level.
                    self.close_document();
                    self.open_stream(version);
                } else {
                    // A nested stream one level below the deepest open
                    // stream at its parent depth.
                    self.close_deeper_than(depth - 1, None);
                    while self.open.len() < depth {
                        // Skipped levels: record them as a malformed stream.
                        let mut stream = Stream::default();
                        stream
                            .malformed
                            .push("nested stream without an enclosing version line".to_string());
                        self.open.push(stream);
                        self.pending.push(Vec::new());
                    }
                    self.open_stream(version);
                }
            }
            Line::Subtest(name) => {
                if self.awaiting_name && depth + 1 == self.open.len() {
                    if let Some(stream) = self.open.last_mut() {
                        stream.name = Some(name.to_string());
                    }
                    self.awaiting_name = false;
                } else if let Some(pending) = self.pending.get_mut(depth) {
                    pending.push(format!("Subtest: {name}"));
                }
            }
            Line::Plan(count, skip_reason) => {
                self.awaiting_name = false;
                self.close_deeper_than(depth, None);
                let Some(stream) = self.open.get_mut(depth) else {
                    return;
                };
                if stream.plan.is_some() {
                    stream.malformed.push("a second plan".to_string());
                    return;
                }
                let leading = stream.tests.is_empty();
                if (stream.tests.len() as u32) > count {
                    stream.malformed.push(format!(
                        "{} results precede a trailing plan of {count}",
                        stream.tests.len()
                    ));
                }
                if skip_reason.is_some() && count != 0 {
                    stream
                        .malformed
                        .push("a skip plan must plan no results".to_string());
                }
                stream.plan = Some(Plan {
                    count,
                    skip_reason,
                    leading,
                });
            }
            Line::Result {
                ok,
                number,
                description,
                directive,
                data,
            } => {
                self.awaiting_name = false;
                let mut nested = None;
                self.close_deeper_than(depth, Some(&mut nested));
                if depth >= self.open.len() {
                    return;
                }
                let diagnostics = std::mem::take(&mut self.pending[depth]);
                let stream = &mut self.open[depth];
                let expected = stream.tests.len() as u32 + 1;
                if number != expected {
                    if stream.tests.iter().any(|test| test.number == number) {
                        stream.malformed.push(format!("result {number} appears twice"));
                    } else {
                        stream
                            .malformed
                            .push(format!("result {number} where {expected} was due"));
                    }
                }
                if let Some(plan) = &stream.plan {
                    if plan.leading && expected > plan.count {
                        stream.malformed.push(format!(
                            "result {number} is beyond the plan of {}",
                            plan.count
                        ));
                    }
                }
                stream.tests.push(Test {
                    number,
                    description,
                    ok,
                    directive,
                    data,
                    diagnostics,
                    nested,
                });
            }
            Line::Diagnostic(text) => {
                if let Some(pending) = self.pending.get_mut(depth.min(self.open.len() - 1)) {
                    pending.push(text.to_string());
                }
            }
            Line::Other => {}
        }
    }

    fn open_stream(&mut self, version: &str) {
        let mut stream = Stream::default();
        if version != "1" {
            stream
                .malformed
                .push(format!("unsupported KTAP version `{version}`"));
        }
        self.open.push(stream);
        self.pending.push(Vec::new());
        self.awaiting_name = true;
    }

    /// Close every open stream deeper than `depth`. The stream directly at
    /// `depth + 1` is handed to `nested` when the caller is the result that
    /// encloses it; any other closed stream lost its enclosing result.
    fn close_deeper_than(&mut self, depth: usize, mut nested: Option<&mut Option<Stream>>) {
        while self.open.len() > depth + 1 {
            let mut stream = self.open.pop().unwrap_or_default();
            let diagnostics = self.pending.pop().unwrap_or_default();
            stream.trailing_diagnostics.extend(diagnostics);
            let parent_depth = self.open.len() - 1;
            if parent_depth == depth {
                if let Some(slot) = nested.take() {
                    *slot = Some(stream);
                    continue;
                }
            }
            // No result encloses this stream: keep its evidence as a
            // malformed child of the parent's last test.
            stream
                .malformed
                .push("the enclosing result line is missing".to_string());
            let parent = &mut self.open[parent_depth];
            parent.malformed.push(format!(
                "nested stream `{}` has no enclosing result",
                stream.name.clone().unwrap_or_default()
            ));
            if let Some(last) = parent.tests.last_mut() {
                if last.nested.is_none() {
                    last.nested = Some(stream);
                }
            }
        }
    }

    fn close_document(&mut self) {
        if self.open.is_empty() {
            return;
        }
        self.close_deeper_than(0, None);
        let mut stream = self.open.pop().unwrap_or_default();
        stream
            .trailing_diagnostics
            .extend(self.pending.pop().unwrap_or_default());
        self.pending.clear();
        self.awaiting_name = false;
        let program = stream.name.clone().unwrap_or_default();
        self.documents.push(Document { program, stream });
    }

    fn finish(mut self) -> Vec<Document> {
        self.close_document();
        self.documents
    }
}

/// A listed program's state after composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramState {
    /// No document named the program.
    Absent,
    /// Its document is incomplete: the program crashed or was cut off.
    Crashed,
    /// Its document breaks KTAP's numbering or plan rules.
    Malformed,
    /// Complete and valid, with a failing result.
    Failed,
    /// Complete and valid with no failure; skips are not failures.
    Passed,
}

impl ProgramState {
    pub fn as_str(self) -> &'static str {
        match self {
            ProgramState::Absent => "absent",
            ProgramState::Crashed => "crashed",
            ProgramState::Malformed => "malformed",
            ProgramState::Failed => "failed",
            ProgramState::Passed => "passed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProgramResult {
    pub program: String,
    pub state: ProgramState,
    pub document: Option<Document>,
    /// Further documents naming the same program, which do not replace the
    /// first.
    pub repeated: usize,
}

/// Documents composed against the expected-program list: the host's
/// top-level plan.
#[derive(Clone, Debug)]
pub struct Composition {
    pub programs: Vec<ProgramResult>,
    /// Documents naming a program the list does not hold.
    pub unexpected: Vec<Document>,
}

impl Composition {
    /// Whether any expected program's document was found at all.
    pub fn any_parseable(&self) -> bool {
        self.programs.iter().any(|p| p.document.is_some())
    }

    pub fn all_passed(&self) -> bool {
        self.programs
            .iter()
            .all(|p| p.state == ProgramState::Passed)
    }
}

/// Compose `documents` against `expected`. The first document naming a
/// program is its document; a program with no complete document is
/// crashed, and a listed program with none at all is absent.
pub fn compose(documents: &[Document], expected: &[String]) -> Composition {
    let mut programs = Vec::new();
    for name in expected {
        let mut matching = documents.iter().filter(|doc| &doc.program == name);
        let document = matching.next().cloned();
        let repeated = matching.count();
        let state = match &document {
            None => ProgramState::Absent,
            Some(doc) if doc.stream.is_malformed() => ProgramState::Malformed,
            Some(doc) if !doc.stream.complete() => ProgramState::Crashed,
            Some(doc) if doc.stream.failed() => ProgramState::Failed,
            Some(_) => ProgramState::Passed,
        };
        programs.push(ProgramResult {
            program: name.clone(),
            state,
            document,
            repeated,
        });
    }
    let unexpected = documents
        .iter()
        .filter(|doc| !expected.contains(&doc.program))
        .cloned()
        .collect();
    Composition {
        programs,
        unexpected,
    }
}

/// A test and its nested checks as wire values, for a parsed summary.
pub fn test_value(test: &Test) -> Value {
    let mut out = Value::table();
    out.set("number", Value::Int(test.number as i64));
    out.set("name", Value::str(test.description.clone()));
    out.set(
        "result",
        Value::str(if test.failed() {
            "fail"
        } else if test.skip_reason().is_some()
            || test
                .directive
                .as_ref()
                .is_some_and(|d| d.kind == DirectiveKind::Skip)
        {
            "skip"
        } else {
            "pass"
        }),
    );
    out.set("line", Value::str(if test.ok { "ok" } else { "not ok" }));
    if let Some(directive) = &test.directive {
        let mut d = Value::table();
        d.set("kind", Value::str(directive.kind.as_str()));
        d.set("text", Value::str(directive.text.clone()));
        out.set("directive", d);
    }
    if let Some(reason) = test.skip_reason() {
        out.set("skip-reason", Value::str(reason));
    }
    if !test.data.is_empty() {
        out.set("data", Value::str(test.data.clone()));
    }
    out.set("diagnostics", Value::str_list(test.diagnostics.clone()));
    if let Some(nested) = &test.nested {
        out.set("nested", stream_value(nested));
    }
    out
}

/// A stream as wire values: plan, tests, diagnostics and problems.
pub fn stream_value(stream: &Stream) -> Value {
    let mut out = Value::table();
    if let Some(name) = &stream.name {
        out.set("name", Value::str(name.clone()));
    }
    if let Some(plan) = &stream.plan {
        let mut p = Value::table();
        p.set("count", Value::Int(plan.count as i64));
        p.set("leading", Value::Bool(plan.leading));
        if let Some(reason) = &plan.skip_reason {
            p.set("skip-reason", Value::str(reason.clone()));
        }
        out.set("plan", p);
    }
    out.set("complete", Value::Bool(stream.complete()));
    out.set(
        "tests",
        Value::List(stream.tests.iter().map(test_value).collect()),
    );
    out.set(
        "diagnostics",
        Value::str_list(stream.trailing_diagnostics.clone()),
    );
    out.set("problems", Value::str_list(stream.problems()));
    out
}

/// The composed programs as wire values.
pub fn composition_value(composition: &Composition) -> Value {
    let mut programs = Vec::new();
    for program in &composition.programs {
        let mut p = Value::table();
        p.set("program", Value::str(program.program.clone()));
        p.set("state", Value::str(program.state.as_str()));
        if program.repeated > 0 {
            p.set("repeated-documents", Value::Int(program.repeated as i64));
        }
        if let Some(doc) = &program.document {
            p.set("document", stream_value(&doc.stream));
        }
        programs.push(p);
    }
    let mut out = Value::table();
    out.set("programs", Value::List(programs));
    out.set(
        "unexpected",
        Value::List(
            composition
                .unexpected
                .iter()
                .map(|doc| {
                    let mut d = Value::table();
                    d.set("program", Value::str(doc.program.clone()));
                    d.set("document", stream_value(&doc.stream));
                    d
                })
                .collect(),
        ),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "\
boot: noise line
KTAP version 1
# Subtest: fluxd-test-runner
1..3
    KTAP version 1
    # Subtest: test_pipe
    1..2
    ok 1 open
    # expected 2 got 3
    not ok 2 read # value mismatch
ok 1 test_pipe
[    1.000000] I fluxd: unrelated log line
    KTAP version 1
    # Subtest: test_skip
    1..0 # SKIP no display device
ok 2 test_skip # SKIP
ok 3 kernel-taint
KTAP version 1
# Subtest: fluxd-win32-smoke-test
ok 1 console
ok 2 heap
1..2
";

    #[test]
    fn required_nested_failure_propagates_and_skip_reason_comes_from_the_plan() {
        let docs = parse(RUN);
        assert_eq!(docs.len(), 2);
        let runner = &docs[0];
        assert_eq!(runner.program, "fluxd-test-runner");
        assert!(runner.stream.complete());
        assert!(!runner.stream.is_malformed());
        assert!(runner.stream.tests[0].failed());
        assert_eq!(
            runner.stream.tests[0].nested.as_ref().unwrap().tests[1].diagnostics,
            vec!["expected 2 got 3".to_string()]
        );
        assert_eq!(
            runner.stream.tests[1].skip_reason().as_deref(),
            Some("no display device")
        );
        assert!(!runner.stream.tests[1].failed());
        let smoke = &docs[1];
        assert!(smoke.stream.complete(), "trailing plan completes the document");
        assert!(!smoke.stream.plan.as_ref().unwrap().leading);
    }

    #[test]
    fn required_composition_reports_absent_crashed_and_malformed_programs() {
        let expected = vec![
            "fluxd-test-runner".to_string(),
            "fluxd-win32-smoke-test".to_string(),
            "fluxd-test-echo".to_string(),
        ];
        let composition = compose(&parse(RUN), &expected);
        let states: Vec<_> = composition.programs.iter().map(|p| p.state).collect();
        assert_eq!(
            states,
            vec![ProgramState::Failed, ProgramState::Passed, ProgramState::Absent]
        );
        assert!(composition.any_parseable());

        let truncated = "KTAP version 1\n# Subtest: p\n1..2\nok 1 a\n";
        let c = compose(&parse(truncated), &["p".to_string()]);
        assert_eq!(c.programs[0].state, ProgramState::Crashed);

        let beyond = "KTAP version 1\n# Subtest: p\n1..1\nok 1 a\nok 2 b\n";
        let c = compose(&parse(beyond), &["p".to_string()]);
        assert_eq!(c.programs[0].state, ProgramState::Malformed);

        let renumbered = "KTAP version 1\n# Subtest: p\n1..2\nok 1 a\nok 3 b\n";
        let c = compose(&parse(renumbered), &["p".to_string()]);
        assert_eq!(c.programs[0].state, ProgramState::Malformed);

        let none = compose(&parse("just a log\n"), &["p".to_string()]);
        assert!(!none.any_parseable());
    }

    #[test]
    fn required_passing_line_cannot_hide_a_failing_nested_check() {
        let text = "KTAP version 1\n# Subtest: p\n1..1\n    KTAP version 1\n    # Subtest: t\n    1..1\n    not ok 1 x\nok 1 t\n";
        let c = compose(&parse(text), &["p".to_string()]);
        assert_eq!(c.programs[0].state, ProgramState::Failed);
    }

    #[test]
    fn required_timeout_and_error_directives_fail() {
        let text = "KTAP version 1\n# Subtest: p\n1..2\nnot ok 1 slow # TIMEOUT 180s\nnot ok 2 died # ERROR signal 11\n";
        let docs = parse(text);
        let t = &docs[0].stream.tests;
        assert_eq!(t[0].directive.as_ref().unwrap().kind, DirectiveKind::Timeout);
        assert_eq!(t[0].directive.as_ref().unwrap().text, "180s");
        assert_eq!(t[1].directive.as_ref().unwrap().kind, DirectiveKind::Error);
        assert!(t.iter().all(Test::failed));
    }
}
