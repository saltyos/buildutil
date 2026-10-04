//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — captured builder output framed into lines and progress items
//!
//! One `BuildOutput` exists per in-flight build. It frames the builder's
//! stdout and stderr into lines separately, so a partial line on one stream
//! never merges with the other, and hands each result to its emit callback
//! (the build event stream). A carriage return that is not part of CRLF
//! restarts the line, as the tool meant it to overwrite in place. Leading
//! indentation and blank lines are kept because compiler diagnostics depend
//! on them; trailing whitespace is dropped. `finish` emits a final line that
//! ended without a newline. Lines are bounded at MAX_BUILD_OUTPUT_LINE so a
//! runaway log cannot exhaust memory; a longer line keeps its beginning and
//! is marked truncated.
//!
//! Only structured signals are interpreted: an inner ninja status line
//! carrying `PROGRESS_MARKER` (buildutil sets `NINJA_STATUS` to produce it) and a
//! cargo JSON message. Every other line is output, passed on as the tool
//! wrote it; nothing here guesses what a line of text means.

use super::json::{self, Value};
use super::sandbox::OutputStream;
use std::sync::Mutex;

/// Large enough for one cargo JSON diagnostic with its spans and rendering.
const MAX_BUILD_OUTPUT_LINE: usize = 1024 * 1024;
const TRUNCATED: &str = " [line truncated]";

/// The prefix ninja writes before each status line inside a builder.
pub(crate) const PROGRESS_MARKER: &str = "@buildutil ";

/// `NINJA_STATUS` for every builder: `PROGRESS_MARKER`, then ninja's
/// finished and total edge counts.
pub(crate) const NINJA_STATUS: &str = "@buildutil %f/%t ";

/// One framed result of builder output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framed<'a> {
    /// A line for a person, as written, from `stream`.
    Line(&'a str, OutputStream),
    /// A progress item, with the reporting tool's own counter if it has one.
    Item(Option<(usize, usize)>, &'a str),
}

type Emit<'a> = dyn Fn(Framed<'_>) + Sync + 'a;

pub(super) struct BuildOutput<'a> {
    emit: &'a Emit<'a>,
    streams: [Mutex<Framer>; 2],
}

#[derive(Default)]
struct Framer {
    pending: Vec<u8>,
    overlong: bool,
    /// The previous byte was a carriage return.
    cr: bool,
}

impl<'a> BuildOutput<'a> {
    pub(super) fn new(emit: &'a Emit<'a>) -> Self {
        BuildOutput {
            emit,
            streams: [Mutex::new(Framer::default()), Mutex::new(Framer::default())],
        }
    }

    pub(super) fn ingest(&self, stream: OutputStream, bytes: &[u8]) {
        let mut f = self.streams[stream as usize]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for &byte in bytes {
            if f.cr {
                f.cr = false;
                if byte != b'\n' {
                    f.pending.clear();
                    f.overlong = false;
                }
            }
            match byte {
                b'\n' => {
                    let line = std::mem::take(&mut f.pending);
                    self.emit_line(stream, &line, f.overlong);
                    f.overlong = false;
                }
                b'\r' => f.cr = true,
                _ if f.overlong => {}
                _ if f.pending.len() >= MAX_BUILD_OUTPUT_LINE => f.overlong = true,
                _ => f.pending.push(byte),
            }
        }
    }

    /// Emit a last line the builder left without a newline.
    pub(super) fn finish(&self) {
        for stream in [OutputStream::Stdout, OutputStream::Stderr] {
            let mut f = self.streams[stream as usize]
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !f.pending.is_empty() {
                let line = std::mem::take(&mut f.pending);
                self.emit_line(stream, &line, f.overlong);
            }
            *f = Framer::default();
        }
    }

    fn emit_line(&self, stream: OutputStream, bytes: &[u8], truncated: bool) {
        let text = String::from_utf8_lossy(bytes);
        if truncated {
            (self.emit)(Framed::Line(&format!("{}{}", text, TRUNCATED), stream));
        } else {
            frame(text.trim_end(), stream, self.emit);
        }
    }
}

/// Classify one line and emit what it carries.
fn frame(line: &str, stream: OutputStream, emit: &Emit<'_>) {
    if let Some((counter, text)) = marked_progress(line) {
        emit(Framed::Item(Some(counter), text));
        return;
    }
    if line.starts_with('{') {
        if let Some(message) = json::parse(line) {
            if let Some(reason) = cargo_reason(&message) {
                cargo_message(reason, &message, stream, emit);
                return;
            }
        }
    }
    emit(Framed::Line(line, stream));
}

/// `PROGRESS_MARKER n/N description`: the counter and the description.
fn marked_progress(line: &str) -> Option<((usize, usize), &str)> {
    let rest = line.strip_prefix(PROGRESS_MARKER)?;
    let (counter, text) = rest.split_once(' ').unwrap_or((rest, ""));
    let (done, total) = counter.split_once('/')?;
    Some(((done.parse().ok()?, total.parse().ok()?), text))
}

/// The `reason` of a JSON object shaped as one of cargo's documented message
/// records; any other JSON a builder prints is ordinary output.
fn cargo_reason(message: &Value) -> Option<&str> {
    let reason = message.get("reason")?.as_str()?;
    let package = message.get("package_id").and_then(Value::as_str).is_some();
    let shaped = match reason {
        "compiler-artifact" => {
            package
                && message
                    .get("target")
                    .and_then(|t| t.get("name"))
                    .and_then(Value::as_str)
                    .is_some()
        }
        "compiler-message" => {
            package
                && message
                    .get("message")
                    .and_then(|m| m.get("rendered"))
                    .is_some()
        }
        "build-script-executed" => package,
        "build-finished" => message.get("success").and_then(Value::as_bool).is_some(),
        _ => false,
    };
    shaped.then_some(reason)
}

/// A cargo JSON message (`--message-format=json…`): a newly compiled
/// target is a progress item, a compiler message is its rendered text, and
/// the build-script and build-finished records carry nothing for a person.
fn cargo_message(reason: &str, message: &Value, stream: OutputStream, emit: &Emit<'_>) {
    match reason {
        "compiler-artifact" => {
            if message.get("fresh").and_then(Value::as_bool) == Some(true) {
                return;
            }
            if let Some(name) = message
                .get("target")
                .and_then(|t| t.get("name"))
                .and_then(Value::as_str)
            {
                emit(Framed::Item(None, &format!("Compiled {}", name)));
            }
        }
        "compiler-message" => {
            let rendered = message
                .get("message")
                .and_then(|m| m.get("rendered"))
                .and_then(Value::as_str);
            if let Some(rendered) = rendered {
                for line in rendered.trim_end_matches('\n').split('\n') {
                    emit(Framed::Line(line.trim_end(), stream));
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(input: &[(OutputStream, &[u8])]) -> Vec<String> {
        let seen = Mutex::new(Vec::new());
        let emit = |framed: Framed<'_>| {
            let text = match framed {
                Framed::Line(line, stream) => format!("{}:{}", stream.as_str(), line),
                Framed::Item(Some((n, t)), text) => format!("item[{}/{}]:{}", n, t, text),
                Framed::Item(None, text) => format!("item:{}", text),
            };
            seen.lock().unwrap().push(text);
        };
        let output = BuildOutput::new(&emit);
        for (stream, bytes) in input {
            output.ingest(*stream, bytes);
        }
        output.finish();
        seen.into_inner().unwrap()
    }

    #[test]
    fn marked_ninja_status_is_an_item_and_text_is_a_line() {
        let got = collect(&[
            (OutputStream::Stdout, b"@buildutil 3/40 CC stdio/printf.o\n"),
            (OutputStream::Stdout, b"[3/40] not marked\n"),
            (OutputStream::Stderr, b"printf.c:1:2: error: x\n"),
            (OutputStream::Stdout, b"@buildutil nonsense\n"),
        ]);
        assert_eq!(
            got,
            [
                "item[3/40]:CC stdio/printf.o",
                "stdout:[3/40] not marked",
                "stderr:printf.c:1:2: error: x",
                "stdout:@buildutil nonsense",
            ]
        );
    }

    #[test]
    fn cargo_messages_become_items_and_rendered_lines() {
        let artifact =
            br#"{"reason":"compiler-artifact","package_id":"p","target":{"name":"rustc_middle"},"fresh":false}
"#;
        let fresh = br#"{"reason":"compiler-artifact","package_id":"p","target":{"name":"core"},"fresh":true}
"#;
        let diag = br#"{"reason":"compiler-message","package_id":"p","target":{"name":"x"},"message":{"rendered":"warning: unused\n  --> a.rs:1:1\n\n"}}
"#;
        let done = br#"{"reason":"build-finished","success":true}
"#;
        let got = collect(&[
            (OutputStream::Stdout, artifact),
            (OutputStream::Stdout, fresh),
            (OutputStream::Stdout, diag),
            (OutputStream::Stdout, done),
            (OutputStream::Stdout, b"{\"no\":\"reason\"}\n"),
            (
                OutputStream::Stdout,
                b"{\"reason\":\"connection refused\",\"status\":\"failed\"}\n",
            ),
        ]);
        assert_eq!(
            got,
            [
                "item:Compiled rustc_middle",
                "stdout:warning: unused",
                "stdout:  --> a.rs:1:1",
                "stdout:{\"no\":\"reason\"}",
                "stdout:{\"reason\":\"connection refused\",\"status\":\"failed\"}",
            ]
        );
    }

    #[test]
    fn an_overlong_line_keeps_its_beginning_and_is_marked() {
        let mut long = vec![b'x'; MAX_BUILD_OUTPUT_LINE + 10];
        long.push(b'\n');
        long.extend_from_slice(b"next\n");
        let got = collect(&[(OutputStream::Stderr, &long)]);
        assert_eq!(got.len(), 2);
        assert!(got[0].ends_with(TRUNCATED));
        assert_eq!(
            got[0].len(),
            "stderr:".len() + MAX_BUILD_OUTPUT_LINE + TRUNCATED.len()
        );
        assert_eq!(got[1], "stderr:next");
    }
}
