//! SPDX-License-Identifier: GPL-2.0-only
//! Configuration editor drawing: color depth, theme, cell canvas, and output
//!
//! Owns everything between a laid-out screen and the bytes sent to the
//! terminal: which color depth the terminal supports, the surface colors
//! derived from its background, a width-aware cell `Canvas`, and `emit`,
//! which turns the difference between two canvases into cursor moves and
//! SGR runs. Layout lives in `view`; terminal I/O lives in `term`.
//!
//! The menu uses terminal-default colors, reverse video for selection, and
//! box glyphs for the dialog and list. ASCII glyphs cover non-UTF-8 locales.

use std::fmt::Write as _;

/// Terminal-default color for the monochrome menu theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Style {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub dim: bool,
    pub reverse: bool,
}

impl Style {
    pub fn fg(self, fg: Color) -> Style {
        Style { fg, ..self }
    }

    pub fn bold(self) -> Style {
        Style { bold: true, ..self }
    }

    pub fn dim(self) -> Style {
        Style { dim: true, ..self }
    }
}

/// What the terminal can display, most capable first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    TrueColor,
    Ansi256,
    Ansi16,
    Mono,
}

impl Depth {
    /// `NO_COLOR` wins; then `COLORTERM`, then `TERM`.
    pub fn detect(var: &dyn Fn(&str) -> Option<String>) -> Depth {
        if var("NO_COLOR").is_some_and(|v| !v.is_empty()) {
            return Depth::Mono;
        }
        let colorterm = var("COLORTERM").unwrap_or_default().to_ascii_lowercase();
        if colorterm == "truecolor" || colorterm == "24bit" {
            return Depth::TrueColor;
        }
        let term = var("TERM").unwrap_or_default();
        if term.contains("256color") {
            Depth::Ansi256
        } else if term.is_empty() || term == "dumb" {
            Depth::Mono
        } else {
            Depth::Ansi16
        }
    }
}

/// Whether the locale can display the Unicode glyph set.
pub fn detect_unicode(var: &dyn Fn(&str) -> Option<String>) -> bool {
    for key in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Some(value) = var(key).filter(|v| !v.is_empty()) {
            let value = value.to_ascii_lowercase();
            return value.contains("utf-8") || value.contains("utf8");
        }
    }
    false
}

/// The symbols the view draws, in a Unicode and an ASCII form.
#[derive(Debug, Clone, Copy)]
pub struct Glyphs {
    pub on: &'static str,
    pub off: &'static str,
    pub forced: &'static str,
    pub radio_on: &'static str,
    pub radio_off: &'static str,
    pub sep: &'static str,
    pub ellipsis: &'static str,
    pub caret: &'static str,
    pub range: &'static str,
    pub cross: &'static str,
    pub arrow: &'static str,
    pub box_h: &'static str,
    pub box_v: &'static str,
    pub box_tl: &'static str,
    pub box_tr: &'static str,
    pub box_bl: &'static str,
    pub box_br: &'static str,
}

impl Glyphs {
    pub fn unicode() -> Glyphs {
        Glyphs {
            on: "[*]",
            off: "[ ]",
            forced: "[-]",
            radio_on: "(*)",
            radio_off: "( )",
            sep: " › ",
            ellipsis: "…",
            caret: "▁",
            range: "…",
            cross: "✗",
            arrow: "->",
            box_h: "─",
            box_v: "│",
            box_tl: "┌",
            box_tr: "┐",
            box_bl: "└",
            box_br: "┘",
        }
    }

    pub fn ascii() -> Glyphs {
        Glyphs {
            on: "[*]",
            off: "[ ]",
            forced: "[-]",
            radio_on: "(*)",
            radio_off: "( )",
            sep: " > ",
            ellipsis: "~",
            caret: "_",
            range: "..",
            cross: "!",
            arrow: "->",
            box_h: "-",
            box_v: "|",
            box_tl: "+",
            box_tr: "+",
            box_bl: "+",
            box_br: "+",
        }
    }
}

/// Named surfaces and accents. Every field is a complete style so the view
/// never combines colors itself.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub depth: Depth,
    pub base: Style,
    pub muted: Style,
    pub title_bar: Style,
    pub cursor: Style,
    pub float: Style,
    pub float_muted: Style,
    pub float_cursor: Style,
    pub status_key: Style,
    pub accent: Color,
    pub on: Color,
    pub forced: Color,
    pub changed: Color,
    pub error: Color,
    pub edit: Color,
}

impl Theme {
    /// The theme for `depth`.
    /// Match menuconfig's monochrome attributes on the terminal's own colors.
    pub fn new(depth: Depth, _bg: Option<(u8, u8, u8)>) -> Theme {
        Theme::flat(depth)
    }

    /// Linux's monochrome menu uses bold titles, dimmed inactive text, and
    /// reverse video on the selected item and active button.
    fn flat(depth: Depth) -> Theme {
        let base = Style::default();
        let reverse = Style {
            reverse: true,
            ..base
        };
        Theme {
            depth,
            base,
            muted: base.dim(),
            title_bar: base.bold(),
            cursor: reverse,
            float: base,
            float_muted: base.dim(),
            float_cursor: reverse,
            status_key: base.bold(),
            accent: Color::Default,
            on: Color::Default,
            forced: Color::Default,
            changed: Color::Default,
            error: Color::Default,
            edit: Color::Default,
        }
    }
}

/// Display width of one character in terminal cells.
pub fn char_width(c: char) -> usize {
    let cp = c as u32;
    if cp < 0x20 || (0x7f..0xa0).contains(&cp) {
        return 0;
    }
    if (0x0300..=0x036f).contains(&cp) || (0x200b..=0x200f).contains(&cp) {
        return 0;
    }
    let wide = (0x1100..=0x115f).contains(&cp)
        || ((0x2e80..=0xa4cf).contains(&cp) && cp != 0x303f)
        || (0xac00..=0xd7a3).contains(&cp)
        || (0xf900..=0xfaff).contains(&cp)
        || (0xfe30..=0xfe4f).contains(&cp)
        || (0xff00..=0xff60).contains(&cp)
        || (0xffe0..=0xffe6).contains(&cp)
        || (0x1f300..=0x1f64f).contains(&cp)
        || (0x1f900..=0x1f9ff).contains(&cp)
        || (0x20000..=0x3fffd).contains(&cp);
    if wide { 2 } else { 1 }
}

pub fn str_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// `s` cut to at most `max` cells, ending in `ellipsis` when cut.
pub fn truncate(s: &str, max: usize, ellipsis: &str) -> String {
    if str_width(s) <= max {
        return s.to_string();
    }
    let room = max.saturating_sub(str_width(ellipsis));
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = char_width(c);
        if used + w > room {
            break;
        }
        out.push(c);
        used += w;
    }
    if max >= str_width(ellipsis) {
        out.push_str(ellipsis);
    }
    out
}

/// Greedy word wrap into lines of at most `width` cells.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let needed = if line.is_empty() {
            str_width(word)
        } else {
            str_width(&line) + 1 + str_width(word)
        };
        if needed > width && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub style: Style,
    /// The right half of a wide character; emitted as nothing.
    pub cont: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canvas {
    pub w: usize,
    pub h: usize,
    cells: Vec<Cell>,
}

impl Canvas {
    pub fn new(w: usize, h: usize, style: Style) -> Canvas {
        Canvas {
            w,
            h,
            cells: vec![
                Cell {
                    ch: ' ',
                    style,
                    cont: false,
                };
                w * h
            ],
        }
    }

    pub fn cell(&self, x: usize, y: usize) -> &Cell {
        &self.cells[y * self.w + x]
    }

    pub fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, style: Style) {
        for row in y..(y + h).min(self.h) {
            for col in x..(x + w).min(self.w) {
                self.cells[row * self.w + col] = Cell {
                    ch: ' ',
                    style,
                    cont: false,
                };
            }
        }
    }

    /// Write `text` at (x, y), clipped at `x + max` cells; returns the cells
    /// written. A wide character that does not fit whole is not written.
    pub fn put(&mut self, x: usize, y: usize, text: &str, style: Style, max: usize) -> usize {
        if y >= self.h {
            return 0;
        }
        let limit = (x + max).min(self.w);
        let mut col = x;
        for c in text.chars() {
            let w = char_width(c);
            if w == 0 {
                continue;
            }
            if col + w > limit {
                break;
            }
            self.cells[y * self.w + col] = Cell {
                ch: c,
                style,
                cont: false,
            };
            if w == 2 {
                self.cells[y * self.w + col + 1] = Cell {
                    ch: ' ',
                    style,
                    cont: true,
                };
            }
            col += w;
        }
        col - x
    }

    /// Write `text` so it ends at column `right` (exclusive).
    pub fn put_right(&mut self, right: usize, y: usize, text: &str, style: Style) -> usize {
        let w = str_width(text).min(right);
        self.put(right - w, y, text, style, w)
    }

    /// Copy a smaller canvas into this one without splitting wide characters.
    pub fn blit(&mut self, x: usize, y: usize, source: &Canvas) {
        for row in 0..source.h {
            let dst = (y + row) * self.w + x;
            let src = row * source.w;
            self.cells[dst..dst + source.w].clone_from_slice(&source.cells[src..src + source.w]);
        }
    }

    /// Reverse the complete rendered item, including spaces between parts.
    pub fn highlight(&mut self, x: usize, y: usize, width: usize) {
        for cell in &mut self.cells[y * self.w + x..y * self.w + x + width] {
            cell.style.reverse = true;
        }
    }

    /// Fade everything already drawn, for the backdrop of a floating window.
    pub fn fade(&mut self) {
        for cell in &mut self.cells {
            cell.style.bold = false;
            cell.style.dim = true;
            cell.style.reverse = false;
        }
    }
}

fn sgr(style: Style, _depth: Depth) -> String {
    let mut out = String::from("\x1b[0");
    if style.bold {
        out.push_str(";1");
    }
    if style.dim {
        out.push_str(";2");
    }
    if style.reverse {
        out.push_str(";7");
    }
    out.push('m');
    out
}

/// The bytes that turn the screen showing `prev` into `next`. With no
/// previous frame, or a different size, the whole screen is cleared and
/// drawn. Changed cells are grouped into runs per row.
pub fn emit(prev: Option<&Canvas>, next: &Canvas, depth: Depth) -> String {
    let full = prev.is_none_or(|p| p.w != next.w || p.h != next.h);
    let mut out = String::new();
    let mut current: Option<Style> = None;
    if full {
        out.push_str("\x1b[0m\x1b[H\x1b[2J");
    }
    for y in 0..next.h {
        let mut x = 0;
        while x < next.w {
            let changed =
                |col: usize| full || prev.is_some_and(|p| p.cell(col, y) != next.cell(col, y));
            if !changed(x) {
                x += 1;
                continue;
            }
            // A run starts at a character's first cell.
            let mut start = x;
            while start > 0 && next.cell(start, y).cont {
                start -= 1;
            }
            let _ = write!(out, "\x1b[{};{}H", y + 1, start + 1);
            let mut col = start;
            while col < next.w && (changed(col) || next.cell(col, y).cont) {
                let cell = next.cell(col, y);
                if !cell.cont {
                    if current != Some(cell.style) {
                        out.push_str(&sgr(cell.style, depth));
                        current = Some(cell.style);
                    }
                    out.push(cell.ch);
                }
                col += 1;
            }
            x = col;
        }
    }
    out.push_str("\x1b[0m");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn depth_prefers_no_color_then_colorterm_then_term() {
        let d = |pairs: &[(&str, &str)]| Depth::detect(&env(pairs));
        assert_eq!(
            d(&[("NO_COLOR", "1"), ("COLORTERM", "truecolor")]),
            Depth::Mono
        );
        assert_eq!(d(&[("COLORTERM", "24bit")]), Depth::TrueColor);
        assert_eq!(d(&[("TERM", "xterm-256color")]), Depth::Ansi256);
        assert_eq!(d(&[("TERM", "xterm")]), Depth::Ansi16);
        assert_eq!(d(&[("TERM", "dumb")]), Depth::Mono);
    }

    #[test]
    fn unicode_follows_the_first_set_locale_variable() {
        assert!(detect_unicode(&env(&[("LANG", "en_US.UTF-8")])));
        assert!(!detect_unicode(&env(&[
            ("LC_ALL", "C"),
            ("LANG", "en_US.UTF-8")
        ])));
        assert!(!detect_unicode(&env(&[])));
    }

    #[test]
    fn menuconfig_palette_uses_monochrome_dialog_attributes() {
        let theme = Theme::new(Depth::TrueColor, None);
        assert_eq!(theme.base.fg, Color::Default);
        assert_eq!(theme.base.bg, Color::Default);
        assert!(theme.cursor.reverse);
        assert!(theme.muted.dim);
        assert!(theme.title_bar.bold);
        assert!(!theme.title_bar.reverse);
    }

    #[test]
    fn widths_count_wide_and_combining_characters() {
        assert_eq!(str_width("abc"), 3);
        assert_eq!(str_width("설정"), 4);
        assert_eq!(str_width("e\u{301}"), 1);
        assert_eq!(truncate("Link-time optimization", 10, "…"), "Link-time…");
        assert_eq!(truncate("설정설정", 5, "~"), "설정~");
    }

    #[test]
    fn wrap_breaks_at_word_boundaries() {
        assert_eq!(
            wrap("rounded up to whole pages", 12),
            vec!["rounded up", "to whole", "pages"]
        );
    }

    #[test]
    fn emit_redraws_only_changed_runs() {
        let a = Canvas::new(10, 2, Style::default());
        let mut b = a.clone();
        b.put(3, 1, "hi", Style::default(), 5);
        let out = emit(Some(&a), &b, Depth::Mono);
        assert_eq!(out, "\x1b[2;4H\x1b[0mhi\x1b[0m");
        assert!(emit(None, &b, Depth::Mono).starts_with("\x1b[0m\x1b[H\x1b[2J"));
    }

    #[test]
    fn wide_characters_occupy_two_cells_and_emit_once() {
        let a = Canvas::new(6, 1, Style::default());
        let mut b = a.clone();
        assert_eq!(b.put(0, 0, "설x", Style::default(), 6), 3);
        assert!(b.cell(1, 0).cont);
        let out = emit(Some(&a), &b, Depth::Mono);
        assert_eq!(out, "\x1b[1;1H\x1b[0m설x\x1b[0m");
    }

    #[test]
    fn monochrome_attributes_are_independent_of_color_depth() {
        let style = Style::default().bold();
        assert_eq!(sgr(style, Depth::TrueColor), "\x1b[0;1m");
        assert_eq!(sgr(style, Depth::Ansi256), "\x1b[0;1m");
        assert_eq!(sgr(style, Depth::Mono), "\x1b[0;1m");
    }
}
