//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the terminal: the single writer of human-facing output
//!
//! Every byte buildutil shows a person goes through this module: durable lines
//! on stderr (`say!`), results for other programs on stdout (`out!`), the
//! one-row status line, and `TtyLease`, the only way to give an interactive
//! child the terminal. Because all writes pass through one lock, a durable
//! line always lands above the status row and nothing is drawn while a child
//! holds the terminal. Colors come from one table of roles (`Role`); escape
//! sequences a tool wrote are measured as zero width and removed where color
//! is off. The build screen that turns events into these writes lives in
//! `view`.
//!
//! The crate roots declare this module first; its `macro_rules!` shadow the
//! std print macros so that writing past it is a compile error outside tests.

use std::io::{IsTerminal, Write};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// A durable line on stderr, drawn above the status row.
macro_rules! say {
    ($($arg:tt)*) => {
        $crate::term::line(&format!($($arg)*))
    };
}

/// A line on stdout, the channel other programs read.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::term::result(&format!($($arg)*))
    };
}

#[cfg(not(test))]
#[allow(unused_macros)] // exists to reject every use
macro_rules! println {
    ($($arg:tt)*) => {
        compile_error!("write stdout through out! (crate::term)")
    };
}

#[cfg(not(test))]
#[allow(unused_macros)] // exists to reject every use
macro_rules! print {
    ($($arg:tt)*) => {
        compile_error!("write stdout through out! or term::result_raw")
    };
}

#[cfg(not(test))]
#[allow(unused_macros)] // exists to reject every use
macro_rules! eprintln {
    ($($arg:tt)*) => {
        compile_error!("write stderr through say! (crate::term)")
    };
}

#[cfg(not(test))]
#[allow(unused_macros)] // exists to reject every use
macro_rules! eprint {
    ($($arg:tt)*) => {
        compile_error!("write stderr through say! (crate::term)")
    };
}

#[cfg(not(test))]
#[allow(unused_macros)] // exists to reject every use
macro_rules! dbg {
    ($($arg:tt)*) => {
        compile_error!("dbg! is not allowed; write through say!")
    };
}

// Declared after the macros so the view sees them in textual scope.
pub mod view;

/// Minimum time between two status redraws.
const REDRAW: Duration = Duration::from_millis(100);

struct State {
    interactive: bool,
    color: bool,
    /// The status text the view wants shown; empty for none.
    status: String,
    /// Whether the status row is currently on screen.
    drawn: bool,
    /// Whether `status` changed since it was last drawn.
    dirty: bool,
    last_draw: Option<Instant>,
    /// A child holds the terminal; output is held until it returns.
    leased: bool,
    held: Vec<u8>,
    ticker: bool,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> MutexGuard<'static, State> {
    STATE
        .get_or_init(|| {
            let tty = std::io::stderr().is_terminal()
                && std::env::var_os("TERM").is_none_or(|t| t != "dumb");
            let interactive = tty && crate::platform::enable_ansi_stderr();
            Mutex::new(State {
                interactive,
                color: interactive && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
                status: String::new(),
                drawn: false,
                dirty: false,
                last_draw: None,
                leased: false,
                held: Vec::new(),
                ticker: false,
            })
        })
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether stderr is a terminal that shows the status row.
pub fn interactive() -> bool {
    state().interactive
}

/// Columns available for one row of output.
pub fn width() -> usize {
    crate::platform::stderr_columns()
        .or_else(|| {
            std::env::var("COLUMNS")
                .ok()
                .and_then(|c| c.trim().parse().ok())
        })
        .filter(|c: &usize| *c > 0)
        .unwrap_or(80)
}

/// Whether this process draws in color.
pub fn color() -> bool {
    state().color
}

/// What a colored piece of text means. Color marks a state, bold a name or
/// a structure, dim supporting detail; everything else is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The title, section headings, and failed names in the summary.
    Heading,
    /// A step in progress (`Staging`, `Compiling`).
    Active,
    /// A newly produced result (`Compiled`, `Realized`), a completed
    /// evaluation phase, and the count of built derivations.
    Built,
    /// A result reused from the store, and its count.
    Cached,
    /// A failure, and the count of failures.
    Failed,
    /// Hashes and log locations.
    Detail,
    /// A configuration value of `true`, `false`, or `auto`.
    True,
    False,
    Auto,
    /// Log level tags.
    Debug,
    Info,
    Success,
    Warning,
    Error,
}

impl Role {
    fn sgr(self) -> &'static str {
        match self {
            Role::Heading => "1",
            Role::Active | Role::Warning => "1;33",
            Role::Built | Role::Auto => "1;34",
            Role::Cached | Role::True | Role::Success => "1;32",
            Role::Failed | Role::False | Role::Error => "1;31",
            Role::Detail => "2",
            Role::Debug => "1;35",
            Role::Info => "1;36",
        }
    }
}

/// `text` in `role`'s style when `color` is set.
pub fn style(role: Role, text: &str, color: bool) -> String {
    if color {
        format!("\x1b[{}m{}\x1b[0m", role.sgr(), text)
    } else {
        text.to_string()
    }
}

/// `text` in `role`'s style when this process draws in color.
pub fn paint(role: Role, text: &str) -> String {
    style(role, text, color())
}

/// The length of the escape sequence at the start of `bytes` (which begins
/// with ESC): a CSI sequence up to its final byte, an OSC string up to BEL
/// or ST, or ESC with its intermediates and one final byte. A sequence cut
/// off by the end of input extends to the end; a CSI broken by a byte its
/// grammar does not allow ends before that byte, so it never swallows text.
fn escape_len(bytes: &[u8]) -> usize {
    match bytes.get(1) {
        Some(b'[') => {
            for (i, b) in bytes.iter().enumerate().skip(2) {
                match b {
                    0x20..=0x3f => {}
                    0x40..=0x7e => return i + 1,
                    _ => return i,
                }
            }
            bytes.len()
        }
        Some(b']') => {
            let mut i = 2;
            while i < bytes.len() {
                if bytes[i] == 0x07 {
                    return i + 1;
                }
                if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'\\') {
                    return i + 2;
                }
                i += 1;
            }
            bytes.len()
        }
        Some(_) => {
            let mut i = 1;
            while bytes.get(i).is_some_and(|b| (0x20..=0x2f).contains(b)) {
                i += 1;
            }
            (i + 1).min(bytes.len())
        }
        None => 1,
    }
}

/// `bytes` without terminal escape sequences.
pub fn strip_escapes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            i += escape_len(&bytes[i..]);
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// `text` with only its SGR (color and style) sequences; cursor movement,
/// screen clearing, titles and the like are removed so tool output can
/// color a line but never move or erase what is already on screen.
pub fn sgr_only(text: &str) -> String {
    let bytes = text.as_bytes();
    if !bytes.contains(&0x1b) {
        return text.to_string();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            let n = escape_len(&bytes[i..]);
            let seq = &bytes[i..i + n];
            if seq.len() >= 3 && seq[1] == b'[' && seq[n - 1] == b'm' {
                out.extend_from_slice(seq);
            }
            i += n;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `text` for the one-row status line: control characters other than
/// escape sequences (a tab, a stray carriage return) become spaces, since a
/// terminal would give them an unknown width.
pub fn single_row(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c != '\x1b' && c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// `text` without terminal escape sequences.
pub fn strip_escapes_str(text: &str) -> String {
    if !text.contains('\x1b') {
        return text.to_string();
    }
    String::from_utf8_lossy(&strip_escapes(text.as_bytes())).into_owned()
}

impl State {
    fn erase_status(&mut self, out: &mut Vec<u8>) {
        if self.drawn {
            out.extend_from_slice(b"\r\x1b[K");
            self.drawn = false;
        }
    }

    fn draw_status(&mut self, out: &mut Vec<u8>) {
        if !self.interactive || self.leased {
            return;
        }
        self.erase_status(out);
        if !self.status.is_empty() {
            let fitted = fit(&self.status, width().saturating_sub(1));
            out.extend_from_slice(fitted.as_bytes());
            self.drawn = true;
        }
        self.dirty = false;
        self.last_draw = Some(Instant::now());
    }

    /// Write `bytes` to stderr above the status row.
    fn durable(&mut self, bytes: &[u8]) {
        if self.leased {
            self.held.extend_from_slice(bytes);
            return;
        }
        let mut out = Vec::new();
        let redraw = self.drawn;
        self.erase_status(&mut out);
        out.extend_from_slice(bytes);
        if redraw {
            self.draw_status(&mut out);
        }
        write_stderr(&out);
    }
}

fn write_stderr(bytes: &[u8]) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(bytes);
    let _ = err.flush();
}

/// `s` cut to `max` display cells. Escape sequences take no cells and are
/// kept whole; when any was kept, the result ends with a reset so a cut
/// never leaves color running into what follows.
pub fn fit(s: &str, max: usize) -> String {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut used = 0;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            let n = escape_len(&bytes[i..]);
            out.push_str(&s[i..i + n]);
            escaped = true;
            i += n;
            continue;
        }
        let Some(c) = s[i..].chars().next() else {
            break;
        };
        let w = cell_width(c);
        if used + w > max {
            break;
        }
        out.push(c);
        used += w;
        i += c.len_utf8();
    }
    if escaped {
        out.push_str("\x1b[0m");
    }
    out
}

pub fn cell_width(c: char) -> usize {
    let cp = c as u32;
    if cp < 0x20 || (0x7f..0xa0).contains(&cp) || (0x0300..=0x036f).contains(&cp) {
        return 0;
    }
    let wide = (0x1100..=0x115f).contains(&cp)
        || ((0x2e80..=0xa4cf).contains(&cp) && cp != 0x303f)
        || (0xac00..=0xd7a3).contains(&cp)
        || (0xf900..=0xfaff).contains(&cp)
        || (0xff00..=0xff60).contains(&cp)
        || (0xffe0..=0xffe6).contains(&cp)
        || (0x1f300..=0x1f64f).contains(&cp)
        || (0x1f680..=0x1f6ff).contains(&cp)
        || (0x1f900..=0x1f9ff).contains(&cp)
        || (0x1fa70..=0x1faff).contains(&cp)
        || (0x20000..=0x3fffd).contains(&cp);
    if wide { 2 } else { 1 }
}

/// Display cells of `s`, escape sequences excluded.
pub fn text_width(s: &str) -> usize {
    strip_escapes_str(s).chars().map(cell_width).sum()
}

/// A durable line (or several, separated by `\n`) on stderr.
pub fn line(text: &str) {
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(b'\n');
    state().durable(&bytes);
}

/// Bytes on stderr exactly as given, above the status row.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn line_raw(bytes: &[u8]) {
    state().durable(bytes);
}

/// `path` as a person should see it: relative to the working directory
/// when inside it, else as given.
pub fn display_path(path: &std::path::Path) -> String {
    let cwd = std::env::current_dir().ok();
    match cwd.as_deref().and_then(|cwd| path.strip_prefix(cwd).ok()) {
        Some(rel) => rel.display().to_string(),
        None => path.display().to_string(),
    }
}

/// A durable `[INFO]` line.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn info(msg: &str) {
    line(&format!(
        "{} {}",
        paint(Role::Info, "[INFO]"),
        capitalized(msg)
    ));
}

/// A durable `[ERROR]` line.
pub fn error(msg: &str) {
    line(&format!(
        "{} {}",
        paint(Role::Error, "[ERROR]"),
        capitalized(msg)
    ));
}

/// A log message as shown: it starts with a capital letter when its first
/// word is plain lowercase prose (`cannot open …`, `dev: …`). A first word
/// that is a path, identifier, flag or value (`src/tree:`, `x86_64`,
/// `source-route=…`, `--dev`, `` `buildutil gen` ``) is data and stays as
/// written.
pub fn capitalized(msg: &str) -> std::borrow::Cow<'_, str> {
    let word = msg.split(char::is_whitespace).next().unwrap_or("");
    let word = word.strip_suffix([':', ',']).unwrap_or(word);
    if word.is_empty() || !word.bytes().all(|b| b.is_ascii_lowercase()) {
        return std::borrow::Cow::Borrowed(msg);
    }
    let mut out = String::with_capacity(msg.len());
    out.push(msg.as_bytes()[0].to_ascii_uppercase() as char);
    out.push_str(&msg[1..]);
    std::borrow::Cow::Owned(out)
}

/// A line on stdout. The status row shares the screen with stdout when both
/// are the terminal, so it is taken down around the write.
pub fn result(text: &str) {
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(b'\n');
    result_raw(&bytes);
}

/// Bytes on stdout, exactly as given.
pub fn result_raw(bytes: &[u8]) {
    let mut s = state();
    let mut pre = Vec::new();
    let redraw = s.drawn;
    s.erase_status(&mut pre);
    write_stderr(&pre);
    {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(bytes);
        let _ = out.flush();
    }
    if redraw {
        let mut post = Vec::new();
        s.draw_status(&mut post);
        write_stderr(&post);
    }
}

/// Show `text` on the status row. Redraws at most every 100 ms; a ticker
/// draws the latest text that arrived in between. Empty text removes it.
pub fn status(text: &str) {
    let mut s = state();
    if !s.interactive || s.status == text {
        return;
    }
    s.status = text.to_string();
    s.dirty = true;
    let due = text.is_empty() || s.last_draw.is_none_or(|t| t.elapsed() >= REDRAW);
    if due && !s.leased {
        let mut out = Vec::new();
        s.draw_status(&mut out);
        write_stderr(&out);
    }
    if !s.ticker {
        s.ticker = true;
        std::thread::spawn(ticker);
    }
}

fn ticker() {
    loop {
        std::thread::sleep(REDRAW);
        let mut s = state();
        if s.dirty && !s.leased {
            let mut out = Vec::new();
            s.draw_status(&mut out);
            write_stderr(&out);
        }
    }
}

/// Remove the status row; used when a command finishes.
pub fn clear_status() {
    let mut s = state();
    s.status.clear();
    s.dirty = false;
    let mut out = Vec::new();
    s.erase_status(&mut out);
    write_stderr(&out);
}

/// The terminal, lent to an interactive child. While a lease exists the
/// status row is down and every durable line is held; dropping the lease
/// writes what was held and brings the status row back. Only a lease can
/// give a child the terminal (`invocation::Cmd::terminal`).
pub struct TtyLease {
    _private: (),
}

pub fn handover() -> TtyLease {
    let mut s = state();
    let mut out = Vec::new();
    s.erase_status(&mut out);
    write_stderr(&out);
    s.leased = true;
    TtyLease { _private: () }
}

impl Drop for TtyLease {
    fn drop(&mut self) {
        let mut s = state();
        s.leased = false;
        let held = std::mem::take(&mut s.held);
        write_stderr(&held);
        if !s.status.is_empty() {
            let mut out = Vec::new();
            s.draw_status(&mut out);
            write_stderr(&out);
        }
    }
}

/// Take the status row down before a panic message prints. The hook must
/// not wait for the lock: the panicking thread may hold it.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(lock) = STATE.get() {
            if let Ok(mut s) = lock.try_lock() {
                let mut out = Vec::new();
                s.erase_status(&mut out);
                s.leased = false;
                write_stderr(&out);
            }
        }
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_counts_display_cells() {
        assert_eq!(fit("abcdef", 4), "abcd");
        assert_eq!(fit("설정abc", 5), "설정a");
        assert_eq!(text_width("설정"), 4);
    }

    #[test]
    fn escapes_take_no_cells_and_a_cut_resets_color() {
        let red = "\x1b[1;31merror\x1b[0m: bad";
        assert_eq!(text_width(red), 10);
        assert_eq!(fit(red, 3), "\x1b[1;31merr\x1b[0m");
        assert_eq!(fit("plain", 3), "pla");
    }

    #[test]
    fn escape_sequences_are_stripped_whole() {
        assert_eq!(
            strip_escapes(b"\x1b[0m\x1b[1m\x1b[38;5;9merror\x1b[0m: x"),
            b"error: x"
        );
        assert_eq!(
            strip_escapes(b"a\x1b]8;;http://x\x07link\x1b]8;;\x1b\\b"),
            b"alinkb"
        );
        assert_eq!(strip_escapes(b"a\x1b(Bb\x1b"), b"ab");
        // A CSI cut off by a line feed ends there instead of eating text.
        assert_eq!(strip_escapes(b"x\x1b[\nerror: y"), b"x\nerror: y");
    }

    #[test]
    fn only_color_survives_for_tool_output() {
        assert_eq!(
            sgr_only("\x1b[2J\x1b[1;31mred\x1b[0m\x1b[3A\x1b]0;title\x07"),
            "\x1b[1;31mred\x1b[0m"
        );
        assert_eq!(single_row("a\tb\rc"), "a b c");
        assert_eq!(text_width("\u{1f680}"), 2);
        assert_eq!(strip_escapes_str("no escapes"), "no escapes");
    }

    #[test]
    fn messages_start_with_a_capital_unless_they_start_with_data() {
        assert_eq!(capitalized("cannot open x"), "Cannot open x");
        assert_eq!(capitalized("dev: no recipe"), "Dev: no recipe");
        assert_eq!(capitalized("Already capital"), "Already capital");
        for data in [
            "kernite/src: missing",
            "x86_64 target",
            "source-route=object-db root=/x",
            "--dev skips validation",
            "`buildutil gen` wrote",
            "a.b failed",
            "",
        ] {
            assert_eq!(capitalized(data), data);
        }
    }

    #[test]
    fn style_applies_only_with_color() {
        assert_eq!(style(Role::Cached, "Cached", false), "Cached");
        assert_eq!(
            style(Role::Cached, "Cached", true),
            "\x1b[1;32mCached\x1b[0m"
        );
    }
}
