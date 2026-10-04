//! SPDX-License-Identifier: GPL-2.0-only
//! Configuration editor layout: the editor model drawn onto a canvas
//!
//! `draw` is a pure function of the model, theme, and terminal size. A
//! centered outer dialog holds instructions, a bordered menu list, and
//! buttons. Editing, choosing, help, and quit confirmation use nested dialogs.

use super::paint::{self, Canvas, Color, Glyphs, Style, Theme, str_width, truncate, wrap};
use super::{
    App, BUTTONS, CHOICE_BUTTONS, EDIT_BUTTONS, MENU_BUTTONS, Mode, Row, SEARCH_BUTTONS,
    display_value,
};
use mica::config::graph::Type;
use mica::config::resolve::Origin;
use mica::config::toml::Value;

/// Smallest terminal the layout supports.
pub const MIN_W: usize = 60;
pub const MIN_H: usize = 16;

/// Vertical regions within the main dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub list_top: usize,
    pub list_h: usize,
    pub diag_top: usize,
    pub diag_h: usize,
    pub status: usize,
}

fn dialog_width(w: usize) -> usize {
    if w >= MIN_W + 5 { w - 5 } else { w }
}

fn dialog_height(h: usize) -> usize {
    if h >= MIN_H + 4 { h - 4 } else { h }
}

/// Layout uses the same reduced height as the rendered dialog.
pub fn layout(h: usize, diags: usize) -> Layout {
    let h = dialog_height(h.max(MIN_H));
    let status = h - 2;
    let diag_h = diags.min(2);
    let diag_top = status - 1 - diag_h;
    let list_top = 5;
    let list_h = diag_top - 1 - list_top;
    Layout {
        list_top,
        list_h,
        diag_top,
        diag_h,
        status,
    }
}

/// `style` with foreground `color`, unless the surface is reverse video,
/// where a colored foreground would become the background.
fn tint(style: Style, color: Color) -> Style {
    if style.reverse {
        style
    } else {
        style.fg(color)
    }
}

fn muted_on(style: Style, theme: &Theme) -> Style {
    if style.reverse {
        style
    } else {
        Style {
            fg: theme.muted.fg,
            dim: theme.muted.dim,
            ..style
        }
    }
}

/// A solid label in the monochrome dialog palette.
fn chip(_theme: &Theme, _color: Color) -> Style {
    Style {
        reverse: true,
        bold: true,
        ..Style::default()
    }
}

/// `s` fitted into `max` cells by keeping its tail.
fn tail_fit(s: &str, max: usize, ellipsis: &str) -> String {
    if str_width(s) <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(str_width(ellipsis));
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut used = 0;
    for c in chars.iter().rev() {
        let w = paint::char_width(*c);
        if used + w > keep {
            break;
        }
        out.push(*c);
        used += w;
    }
    out.reverse();
    format!("{}{}", ellipsis, out.into_iter().collect::<String>())
}

fn row_title(app: &App<'_>, row: &Row) -> String {
    match row {
        Row::Menu(name) => app
            .graph
            .menus
            .get(name)
            .map(|m| m.title.clone())
            .unwrap_or_else(|| name.clone()),
        Row::Option(name) => app
            .graph
            .options
            .get(name)
            .and_then(|d| d.title.clone())
            .unwrap_or_else(|| name.clone()),
        Row::Choice(name) => app
            .graph
            .choices
            .get(name)
            .and_then(|c| c.title.clone())
            .unwrap_or_else(|| name.clone()),
    }
}

fn member_label(app: &App<'_>, member: &str) -> String {
    app.graph
        .options
        .get(member)
        .and_then(|d| d.title.clone().or_else(|| d.value_label.clone()))
        .unwrap_or_else(|| member.to_string())
}

fn menu_path(app: &App<'_>, menu: Option<&str>, g: &Glyphs) -> String {
    let mut parts = Vec::new();
    let mut cur = menu.map(str::to_string);
    while let Some(m) = cur {
        let def = app.graph.menus.get(&m);
        parts.push(def.map(|d| d.title.clone()).unwrap_or_else(|| m.clone()));
        cur = def.and_then(|d| d.parent.clone());
    }
    parts.push("Top".to_string());
    parts.reverse();
    parts.join(g.sep)
}

fn row_menu(app: &App<'_>, row: &Row) -> Option<String> {
    match row {
        Row::Menu(name) => app.graph.menus.get(name).and_then(|m| m.parent.clone()),
        Row::Option(name) => app.graph.options.get(name).and_then(|d| d.menu.clone()),
        Row::Choice(name) => app.graph.choices.get(name).and_then(|c| c.menu.clone()),
    }
}

/// The glyph and right-hand parts of a list row.
fn row_parts(
    app: &App<'_>,
    row: &Row,
    theme: &Theme,
    g: &Glyphs,
    style: Style,
) -> (Option<(&'static str, Style)>, Vec<(String, Style)>) {
    let muted = muted_on(style, theme);
    let hidden = app.hidden(row);
    match row {
        Row::Menu(_) => (None, vec![("--->".to_string(), style.bold())]),
        Row::Choice(name) => {
            let active = app
                .resolved
                .choices
                .get(name)
                .and_then(|c| c.active.clone())
                .map(|m| member_label(app, &m))
                .unwrap_or_default();
            let mut right = vec![(format!("({}) --->", active), style.bold())];
            if hidden {
                right.push(("hidden".to_string(), muted));
            }
            (None, right)
        }
        Row::Option(name) => {
            let Some(def) = app.graph.options.get(name) else {
                return (None, Vec::new());
            };
            let r = app.resolved.values.get(name);
            let origin = r.map(|r| r.origin);
            let tag = if def.computed {
                Some(("computed".to_string(), muted))
            } else if hidden {
                Some(("hidden".to_string(), muted))
            } else {
                match origin {
                    Some(Origin::Override) => {
                        Some(("override".to_string(), tint(style, theme.changed)))
                    }
                    Some(Origin::Select) => Some((
                        format!("by {}", app.selectors(name).join(", ")),
                        tint(style, theme.forced),
                    )),
                    _ => None,
                }
            };
            match def.ty {
                Type::Bool | Type::ChoiceMember => {
                    let on = r.is_some_and(|r| r.value == Value::Bool(true));
                    let glyph = if origin == Some(Origin::Select) {
                        (g.forced, tint(style, theme.forced))
                    } else if on {
                        (g.on, tint(style, theme.on))
                    } else {
                        (g.off, muted)
                    };
                    (Some(glyph), tag.into_iter().collect())
                }
                Type::Int | Type::IntList | Type::Str => {
                    let value = r.map(|r| display_value(&r.value)).unwrap_or_default();
                    let mut right = vec![if value.is_empty() {
                        ("(empty)".to_string(), muted)
                    } else {
                        (format!("({})", value), style.bold())
                    }];
                    right.extend(tag);
                    (None, right)
                }
            }
        }
    }
}

fn draw_list(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs, l: &Layout) {
    let rows = app.rows();
    let (cursor, scroll) = app.cursor();
    let glyph_w = str_width(g.on);
    let title_x = 4 + glyph_w + 1;
    for i in 0..l.list_h {
        let idx = scroll + i;
        let Some(row) = rows.get(idx) else {
            break;
        };
        let y = l.list_top + i;
        let mut style = if idx == cursor {
            theme.cursor
        } else {
            theme.base
        };
        c.fill(3, y, c.w - 6, 1, theme.base);
        if app.hidden(row) {
            style = muted_on(style, theme);
        }
        let (glyph, mut right) = row_parts(app, row, theme, g, style);
        let mut x = 4;
        let mut selection_start = x;
        if let Some((text, gs)) = glyph {
            x += c.put(x, y, text, gs, glyph_w) + 1;
        } else if matches!(row, Row::Option(name) if app.graph.options.get(name).is_some_and(|d| matches!(d.ty, Type::Int | Type::IntList | Type::Str)))
        {
            let (value, value_style) = right.remove(0);
            let shown = truncate(&value, (c.w - 8) / 3, g.ellipsis);
            x += c.put(x, y, &shown, value_style, c.w - x - 4) + 1;
        } else {
            x += glyph_w + 1;
            selection_start = x;
        }
        let x_end = c.w - 4;
        let trailing = right
            .iter()
            .map(|(text, _)| str_width(text) + 1)
            .sum::<usize>()
            .min((x_end - x) / 3);
        let title = row_title(app, row);
        let room = x_end.saturating_sub(x + trailing);
        let shown = truncate(&title, room, g.ellipsis);
        x += c.put(x, y, &shown, style, room);
        for (text, rs) in &right {
            if x + 2 >= x_end {
                break;
            }
            x += 1;
            let shown = truncate(text, x_end - x, g.ellipsis);
            x += c.put(x, y, &shown, *rs, x_end - x);
        }
        if idx == cursor {
            c.highlight(selection_start, y, x - selection_start);
        }
        if let Mode::Search { .. } = app.mode {
            // Search results say where each match lives.
            let place = menu_path(app, row_menu(app, row).as_deref(), g);
            let place_x = x + 3;
            if place_x < x_end {
                c.put(
                    place_x,
                    y,
                    &truncate(&place, x_end - place_x, g.ellipsis),
                    muted_on(style, theme),
                    x_end - place_x,
                );
            }
        }
    }
    if rows.is_empty() {
        let text = match app.mode {
            Mode::Search { .. } => "no matches",
            _ => "nothing to configure here",
        };
        c.put(title_x, l.list_top, text, theme.muted, c.w - title_x - 4);
    }
}

fn draw_backtitle(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs) {
    let w = c.w;
    let title = format!("{} - SaltyOS Configuration", app.path.display());
    c.put(
        1,
        0,
        &tail_fit(&title, w - 2, g.ellipsis),
        theme.title_bar,
        w - 2,
    );
    let path = menu_path(app, app.frame().menu.as_deref(), g);
    c.put(
        1,
        1,
        &tail_fit(&path, w - 2, g.ellipsis),
        theme.muted,
        w - 2,
    );
}

fn box_at(c: &mut Canvas, g: &Glyphs, style: Style, x: usize, y: usize, w: usize, h: usize) {
    c.put(x, y, g.box_tl, style, 1);
    c.put(x + w - 1, y, g.box_tr, style, 1);
    c.put(x, y + h - 1, g.box_bl, style, 1);
    c.put(x + w - 1, y + h - 1, g.box_br, style, 1);
    for col in (x + 1)..(x + w - 1) {
        c.put(col, y, g.box_h, style, 1);
        c.put(col, y + h - 1, g.box_h, style, 1);
    }
    for row in (y + 1)..(y + h - 1) {
        c.put(x, row, g.box_v, style, 1);
        c.put(x + w - 1, row, g.box_v, style, 1);
    }
}

fn draw_dialog_header(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs, l: &Layout) {
    box_at(c, g, theme.base, 0, 0, c.w, c.h);
    let title = match &app.mode {
        Mode::Search { .. } => "Search Results".to_string(),
        _ => app
            .frame()
            .menu
            .as_ref()
            .and_then(|name| app.graph.menus.get(name))
            .map(|menu| menu.title.clone())
            .unwrap_or_else(|| "Main Menu".to_string()),
    };
    let title = format!(" {} ", truncate(&title, c.w - 6, g.ellipsis));
    c.put(
        (c.w - str_width(&title)) / 2,
        0,
        &title,
        theme.title_bar,
        c.w - 2,
    );

    let instructions = match &app.mode {
        Mode::Search { query, .. } => [
            format!("/ {}{}", query, g.caret),
            "Up/Down move; Left/Right/Tab choose a button.".to_string(),
            format!(
                "{} matches; Enter runs button; Esc cancels.",
                app.rows().len()
            ),
        ],
        _ => [
            "Up/Down move; Left/Right/Tab choose a button.".to_string(),
            "Enter runs button; Space activates the highlighted item.".to_string(),
            "h/? Help, / Search, s Save, Esc Exit, z Hidden.".to_string(),
        ],
    };
    for (i, line) in instructions.iter().enumerate() {
        c.put(
            2,
            i + 1,
            &truncate(line, c.w - 4, g.ellipsis),
            theme.base,
            c.w - 4,
        );
    }

    box_at(c, g, theme.base, 2, 4, c.w - 4, l.list_h + 2);
    if !app.rows().is_empty() {
        let count = format!(" {}/{} ", app.cursor().0 + 1, app.rows().len());
        c.put_right(c.w - 4, 4, &count, theme.title_bar);
    }
}

fn draw_diags(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs, l: &Layout) {
    for (i, d) in app.diags.iter().take(l.diag_h).enumerate() {
        let text = format!("{} {}", g.cross, d);
        c.put(
            2,
            l.diag_top + i,
            &truncate(&text, c.w - 4, g.ellipsis),
            theme.base.bold(),
            c.w - 4,
        );
    }
}

fn location(file: &std::path::Path, line: u32) -> String {
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{}:{}", name, line)
}

/// (symbol, detail parts, help, location) for the information panel.
fn summary(app: &App<'_>, row: &Row, g: &Glyphs) -> (String, Vec<String>, String, String) {
    match row {
        Row::Menu(name) => {
            let def = app.graph.menus.get(name);
            (
                name.clone(),
                vec!["menu".to_string()],
                String::new(),
                def.map(|d| location(&d.file, d.line)).unwrap_or_default(),
            )
        }
        Row::Choice(name) => {
            let def = app.graph.choices.get(name);
            let mut parts = vec!["choice".to_string()];
            if let Some(d) = def {
                parts.push(format!("default {}", member_label(app, &d.default_member)));
            }
            (
                name.clone(),
                parts,
                def.and_then(|d| d.help.clone()).unwrap_or_default(),
                def.map(|d| location(&d.file, d.line)).unwrap_or_default(),
            )
        }
        Row::Option(name) => {
            let Some(def) = app.graph.options.get(name) else {
                return (name.clone(), Vec::new(), String::new(), String::new());
            };
            let mut parts = vec![def.ty.name().to_string()];
            if def.min.is_some() || def.max.is_some() {
                parts.push(format!(
                    "{}{}{}",
                    def.min.map_or(String::new(), |m| m.to_string()),
                    g.range,
                    def.max.map_or(String::new(), |m| m.to_string())
                ));
            }
            if let Some(d) = &def.default {
                parts.push(format!("default {}", d.render()));
            }
            (
                name.clone(),
                parts,
                def.help.clone().unwrap_or_default(),
                location(&def.file, def.line),
            )
        }
    }
}

fn draw_status(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs, l: &Layout) {
    let divider = l.status - 1;
    for x in 1..c.w - 1 {
        c.put(x, divider, g.box_h, theme.base, 1);
    }
    let (buttons, selected): (&[&str], usize) = match &app.mode {
        Mode::Normal => (&MENU_BUTTONS, app.footer_button),
        Mode::Search { .. } => (&SEARCH_BUTTONS, app.footer_button),
        Mode::Edit { .. } => (&EDIT_BUTTONS, app.footer_button),
        Mode::Choice { .. } => (&CHOICE_BUTTONS, app.footer_button),
        Mode::Info => (&["<Close>"], 0),
        Mode::Confirm { button } => (&BUTTONS, *button),
    };
    let total = buttons.iter().map(|s| str_width(s)).sum::<usize>() + (buttons.len() - 1) * 3;
    let mut x = (c.w - total) / 2;
    for (i, label) in buttons.iter().enumerate() {
        let style = if i == selected {
            theme.cursor
        } else {
            theme.status_key
        };
        x += c.put(x, l.status, label, style, c.w - x - 1) + 3;
    }
    if let Some(msg) = &app.message {
        let text = format!(" {} ", truncate(&msg.text, c.w - 8, g.ellipsis));
        c.put(
            3,
            divider,
            &text,
            if msg.error {
                theme.base.bold()
            } else {
                theme.base
            },
            c.w - 6,
        );
    }
}

/// A floating panel `width` × `height` centered on the screen with box borders;
/// returns its top-left corner.
fn float_panel(
    c: &mut Canvas,
    theme: &Theme,
    g: &Glyphs,
    width: usize,
    height: usize,
    title: Option<&str>,
) -> (usize, usize) {
    let width = width.min(c.w);
    let height = height.min(c.h);
    let x = (c.w - width) / 2;
    let y = (c.h - height) / 2;
    c.fill(x, y, width, height, theme.float);
    if width >= 4 && height >= 3 {
        box_at(c, g, theme.float.bold(), x, y, width, height);
        if let Some(t) = title {
            let label = format!(" {} ", truncate(t, width - 4, g.ellipsis));
            c.put(
                x + (width - str_width(&label)) / 2,
                y,
                &label,
                theme.float.bold(),
                width - 2,
            );
        }
    }
    (x, y)
}

fn draw_edit(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs, name: &str, buffer: &str) {
    let width = 48.min(c.w - 4);
    let row = Row::Option(name.to_string());
    let title = row_title(app, &row);
    let (x, y) = float_panel(c, theme, g, width, 8, Some(&title));
    let inner = width - 4;
    let mut detail = name.to_string();
    if let Some(def) = app.graph.options.get(name) {
        if def.min.is_some() || def.max.is_some() {
            detail.push_str(&format!(
                "   {}{}{}",
                def.min.map_or(String::new(), |m| m.to_string()),
                g.range,
                def.max.map_or(String::new(), |m| m.to_string())
            ));
        }
    }
    c.put(x + 2, y + 2, &detail, theme.float_muted, inner);
    c.fill(x + 2, y + 4, inner, 1, theme.float_cursor);
    let shown = tail_fit(buffer, inner.saturating_sub(3), g.ellipsis);
    let used = c.put(x + 3, y + 4, &shown, theme.float_cursor, inner - 1);
    c.put(
        x + 3 + used,
        y + 4,
        g.caret,
        tint(theme.float_cursor, theme.edit),
        1,
    );
    match app.edit_error() {
        Some(err) => c.put(x + 2, y + 6, &err, tint(theme.float, theme.error), inner),
        None => c.put(
            x + 2,
            y + 6,
            "Tab chooses a button; Enter runs it",
            theme.float_muted,
            inner,
        ),
    };
}

fn draw_choice(
    app: &App<'_>,
    c: &mut Canvas,
    theme: &Theme,
    g: &Glyphs,
    name: &str,
    cursor: usize,
) {
    let members = app
        .graph
        .choices
        .get(name)
        .map(|ch| ch.members.clone())
        .unwrap_or_default();
    let active = app
        .resolved
        .choices
        .get(name)
        .and_then(|ch| ch.active.clone());
    let width = 44.min(c.w - 4);
    let row = Row::Choice(name.to_string());
    let title = row_title(app, &row);
    let (x, y) = float_panel(c, theme, g, width, members.len() + 4, Some(&title));
    let inner = width - 4;
    for (i, m) in members.iter().enumerate() {
        let yy = y + 3 + i;
        if yy >= c.h {
            break;
        }
        let style = if i == cursor {
            theme.float_cursor
        } else {
            theme.float
        };
        c.fill(x + 1, yy, width - 2, 1, style);
        let is_active = active.as_deref() == Some(m.as_str());
        let (glyph, gs) = if is_active {
            (g.radio_on, tint(style, theme.on))
        } else {
            (g.radio_off, muted_on(style, theme))
        };
        let used = c.put(x + 2, yy, glyph, gs, inner);
        c.put(
            x + 3 + used,
            yy,
            &member_label(app, m),
            style,
            inner - used - 1,
        );
    }
}

fn draw_full_info(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs) {
    let Some(row) = app.current_row() else {
        return;
    };
    let width = 76.min(c.w - 6);
    let label_w = 13;
    let value_w = width - 4 - label_w;
    let mut fields: Vec<(&str, String)> = Vec::new();
    let (symbol, _, help, _) = summary(app, &row, g);
    fields.push(("Symbol", symbol.clone()));
    fields.push(("Title", row_title(app, &row)));
    match &row {
        Row::Option(name) => {
            if let Some(def) = app.graph.options.get(name) {
                fields.push(("Type", def.ty.name().to_string()));
                if let Some(r) = app.resolved.values.get(name) {
                    fields.push((
                        "Value",
                        format!("{} ({})", display_value(&r.value), r.origin.as_str()),
                    ));
                }
                if let Some(d) = &def.default {
                    fields.push(("Default", d.render()));
                }
                if def.min.is_some() || def.max.is_some() {
                    fields.push((
                        "Range",
                        format!(
                            "{} {} {}",
                            def.min.map_or("-".to_string(), |m| m.to_string()),
                            g.range,
                            def.max.map_or("-".to_string(), |m| m.to_string())
                        ),
                    ));
                }
                if let Some(dep) = &def.depends_on {
                    let mut atoms = Vec::new();
                    dep.atoms(&mut atoms);
                    let vals: Vec<String> = atoms
                        .iter()
                        .map(|a| {
                            let v = app
                                .resolved
                                .values
                                .get(a)
                                .map(|r| display_value(&r.value))
                                .unwrap_or_else(|| "?".to_string());
                            format!("{}={}", a, v)
                        })
                        .collect();
                    fields.push((
                        "Depends on",
                        format!("{}  [{}]", dep.render(), vals.join(", ")),
                    ));
                }
                if !def.select.is_empty() {
                    fields.push(("Selects", def.select.join(", ")));
                }
                let by = app.selectors(name);
                if !by.is_empty() {
                    fields.push(("Selected by", by.join(", ")));
                }
                fields.push(("Defined at", format!("{}:{}", def.file.display(), def.line)));
            }
        }
        Row::Choice(name) => {
            if let Some(def) = app.graph.choices.get(name) {
                fields.push(("Type", "choice".to_string()));
                let active = app
                    .resolved
                    .choices
                    .get(name)
                    .and_then(|ch| ch.active.clone())
                    .unwrap_or_default();
                fields.push(("Value", active));
                fields.push(("Default", def.default_member.clone()));
                fields.push(("Members", def.members.join(", ")));
                if let Some(dep) = &def.depends_on {
                    fields.push(("Depends on", dep.render()));
                }
                fields.push(("Defined at", format!("{}:{}", def.file.display(), def.line)));
            }
        }
        Row::Menu(name) => {
            if let Some(def) = app.graph.menus.get(name) {
                fields.push(("Type", "menu".to_string()));
                if let Some(v) = &def.visible_when {
                    fields.push(("Visible when", v.render()));
                }
                fields.push(("Defined at", format!("{}:{}", def.file.display(), def.line)));
            }
        }
    }
    fields.push((
        "Location",
        menu_path(app, row_menu(app, &row).as_deref(), g),
    ));

    let mut lines: Vec<(Option<&str>, String)> = Vec::new();
    for (label, value) in &fields {
        for (i, part) in wrap(value, value_w).into_iter().enumerate() {
            lines.push((if i == 0 { Some(*label) } else { None }, part));
        }
    }
    if !help.is_empty() {
        lines.push((None, String::new()));
        for part in wrap(&help, width - 4) {
            lines.push((Some(""), part));
        }
    }
    let height = (lines.len() + 2).min(c.h - 2);
    let title = format!("Help: {}", symbol);
    let (x, y) = float_panel(c, theme, g, width, height, Some(&title));
    for (i, (label, text)) in lines.iter().take(height - 2).enumerate() {
        let yy = y + 1 + i;
        match label {
            Some("") => {
                c.put(x + 2, yy, text, theme.float, width - 4);
            }
            Some(label) => {
                c.put(x + 2, yy, label, theme.float_muted, label_w);
                c.put(x + 2 + label_w, yy, text, theme.float, value_w);
            }
            None => {
                c.put(x + 2 + label_w, yy, text, theme.float, value_w);
            }
        }
    }
}

fn draw_confirm(app: &App<'_>, c: &mut Canvas, theme: &Theme, g: &Glyphs, button: usize) {
    const SHOWN: usize = 5;
    let changes = app.changes();
    let width = 60.min(c.w - 4);
    let inner = width - 4;
    let listed = changes.len().min(SHOWN);
    let extra = usize::from(changes.len() > SHOWN);
    let height = 4 + listed + extra + 2;
    let (x, y) = float_panel(c, theme, g, width, height, Some("Unsaved Changes"));
    let title = if changes.len() == 1 {
        "1 unsaved change".to_string()
    } else {
        format!("{} unsaved changes", changes.len())
    };
    c.put(x + 2, y + 1, &title, theme.float.bold(), inner);
    let key_w = changes
        .iter()
        .take(SHOWN)
        .map(|(k, _, _)| str_width(k))
        .max()
        .unwrap_or(0)
        .min(inner / 2);
    for (i, (key, old, new)) in changes.iter().take(SHOWN).enumerate() {
        let yy = y + 3 + i;
        c.put(
            x + 2,
            yy,
            &truncate(key, key_w, g.ellipsis),
            theme.float,
            key_w,
        );
        let text = format!("{} {} {}", old, g.arrow, new);
        c.put(
            x + 2 + key_w + 2,
            yy,
            &text,
            theme.float_muted,
            inner.saturating_sub(key_w + 2),
        );
    }
    if extra == 1 {
        c.put(
            x + 2,
            y + 3 + listed,
            &format!("and {} more", changes.len() - SHOWN),
            theme.float_muted,
            inner,
        );
    }
    let by = y + height - 2;
    let mut bx = x + 2;
    for (i, label) in BUTTONS.iter().enumerate() {
        let text = format!(" {} ", label);
        let style = if i == button {
            chip(theme, theme.accent)
        } else {
            theme.float
        };
        bx += c.put(bx, by, &text, style, x + width - bx) + 2;
    }
}

/// The whole screen for the model at size `w` × `h`.
pub fn draw(app: &App<'_>, theme: &Theme, g: &Glyphs, w: usize, h: usize) -> Canvas {
    let mut c = Canvas::new(w, h, theme.base);
    if w < MIN_W || h < MIN_H {
        let text = format!("terminal too small: needs {}x{}", MIN_W, MIN_H);
        let text = truncate(&text, w, g.ellipsis);
        let x = w.saturating_sub(str_width(&text)) / 2;
        c.put(x, h / 2, &text, theme.muted, w);
        return c;
    }
    let fw = dialog_width(w);
    let fh = dialog_height(h);
    let mut dialog = Canvas::new(fw, fh, theme.base);
    let l = layout(h, app.diags.len());
    draw_backtitle(app, &mut c, theme, g);
    draw_dialog_header(app, &mut dialog, theme, g, &l);
    draw_list(app, &mut dialog, theme, g, &l);
    draw_diags(app, &mut dialog, theme, g, &l);
    match &app.mode {
        Mode::Edit { name, buffer } => {
            dialog.fade();
            draw_edit(app, &mut dialog, theme, g, name, buffer);
        }
        Mode::Choice { name, cursor } => {
            dialog.fade();
            draw_choice(app, &mut dialog, theme, g, name, *cursor);
        }
        Mode::Info => {
            dialog.fade();
            draw_full_info(app, &mut dialog, theme, g);
        }
        Mode::Confirm { button } => {
            dialog.fade();
            draw_confirm(app, &mut dialog, theme, g, *button);
        }
        Mode::Normal | Mode::Search { .. } => {}
    }
    draw_status(app, &mut dialog, theme, g, &l);
    c.blit((w - fw) / 2, (h - fh) / 2, &dialog);
    c
}

#[cfg(test)]
mod tests {
    use super::super::tests_support::sample_app_graph;
    use super::*;
    use super::super::term::Key;
    use mica::config::resolve::Overrides;
    use std::path::Path;

    fn text_of(c: &Canvas, y: usize) -> String {
        (0..c.w)
            .filter(|x| !c.cell(*x, y).cont)
            .map(|x| c.cell(x, y).ch)
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    fn screen(c: &Canvas) -> String {
        (0..c.h)
            .map(|y| text_of(c, y))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn theme() -> Theme {
        Theme::new(paint::Depth::Mono, None)
    }

    #[test]
    fn main_screen_shows_centered_dialog_and_menu_values() {
        let g = sample_app_graph();
        let app = App::new(&g, Path::new("config"), Overrides::default()).unwrap();
        let c = draw(&app, &theme(), &Glyphs::unicode(), 80, 24);
        let s = screen(&c);
        assert!(text_of(&c, 0).contains("SaltyOS Configuration"), "{}", s);
        assert_eq!(c.cell(2, 2).ch, '┌');
        assert_eq!(c.cell(76, 2).ch, '┐');
        assert_eq!(c.cell(4, 6).ch, '┌');
        assert_eq!(c.cell(74, 6).ch, '┐');
        assert_eq!(c.cell(2, 21).ch, '└');
        assert_eq!(c.cell(76, 21).ch, '┘');
        assert!(s.contains("Networking"), "{}", s);
        assert!(s.contains("Stack size") && s.contains("16384"), "{}", s);
        assert!(s.contains("[-] Tracing") && s.contains("by DEBUG"), "{}", s);
        assert!(s.contains("<Select>") && s.contains("<Search>"), "{}", s);
        assert!(!s.contains("DERIVED"), "computed option hidden: {}", s);
    }

    #[test]
    fn ascii_glyphs_replace_every_symbol() {
        let g = sample_app_graph();
        let app = App::new(&g, Path::new("config"), Overrides::default()).unwrap();
        let c = draw(&app, &theme(), &Glyphs::ascii(), 80, 24);
        let s = screen(&c);
        assert!(
            s.contains("[*] Debug build") && s.contains("[-] Tracing"),
            "{}",
            s
        );
        for ch in ['●', '○', '◆', '›', '…', '▾', '↑', '⏎'] {
            assert!(!s.contains(ch), "unexpected {} in {}", ch, s);
        }
    }

    #[test]
    fn a_small_terminal_gets_a_notice_instead_of_a_broken_layout() {
        let g = sample_app_graph();
        let app = App::new(&g, Path::new("config"), Overrides::default()).unwrap();
        let c = draw(&app, &theme(), &Glyphs::unicode(), 40, 10);
        assert!(screen(&c).contains("terminal too small"));
    }

    #[test]
    fn floating_editor_shows_range_errors() {
        let g = sample_app_graph();
        let mut app = App::new(&g, Path::new("config"), Overrides::default()).unwrap();
        let pos = app
            .rows()
            .iter()
            .position(|r| *r == Row::Option("STACK".into()))
            .unwrap();
        app.frames.last_mut().unwrap().cursor = pos;
        app.handle(Key::Enter);
        app.handle(Key::Ctrl('u'));
        for c in "99".chars() {
            app.handle(Key::Char(c));
        }
        let c = draw(&app, &theme(), &Glyphs::unicode(), 80, 24);
        let s = screen(&c);
        assert!(s.contains("below minimum 4096"), "{}", s);
        assert!(s.contains("<Set>") && s.contains("<Clear>"), "{}", s);
    }

    #[test]
    fn layout_keeps_every_region_on_screen() {
        for h in MIN_H..60 {
            let l = layout(h, 2);
            assert_eq!(l.list_top + l.list_h + 1, l.diag_top, "h={}", h);
            assert_eq!(l.diag_top + l.diag_h + 1, l.status, "h={}", h);
            assert_eq!(l.status, dialog_height(h) - 2);
        }
    }

    #[test]
    fn dialog_tracks_terminal_size_and_preserves_minimum() {
        let g = sample_app_graph();
        let app = App::new(&g, Path::new("config"), Overrides::default()).unwrap();
        let wide = draw(&app, &theme(), &Glyphs::ascii(), 160, 40);
        assert_eq!(wide.cell(2, 2).ch, '+');
        assert_eq!(wide.cell(156, 2).ch, '+');
        assert_eq!(wide.cell(2, 37).ch, '+');
        let small = draw(&app, &theme(), &Glyphs::ascii(), MIN_W, MIN_H);
        assert_eq!(small.cell(0, 0).ch, '+');
        assert_eq!(small.cell(MIN_W - 1, MIN_H - 1).ch, '+');
        assert!(screen(&small).contains("Stack size"));
    }

    #[test]
    fn selected_item_highlights_spaces_through_the_arrow() {
        let g = sample_app_graph();
        let mut app = App::new(&g, Path::new("config"), Overrides::default()).unwrap();
        let pos = app
            .rows()
            .iter()
            .position(|row| *row == Row::Menu("net".into()))
            .unwrap();
        app.frames.last_mut().unwrap().cursor = pos;
        let c = draw(&app, &theme(), &Glyphs::ascii(), 80, 24);
        let y = (0..c.h)
            .find(|y| text_of(&c, *y).contains("Networking --->"))
            .unwrap();
        let line = text_of(&c, y);
        let start = line.find("Networking").unwrap();
        let end = start + "Networking --->".len();
        for x in start..end {
            assert!(c.cell(x, y).style.reverse, "unhighlighted cell {x}: {line}");
        }
        assert!(!c.cell(start - 1, y).style.reverse);
        assert!(!c.cell(end + 1, y).style.reverse);
    }

    #[test]
    fn footer_highlight_tracks_keyboard_focus() {
        let g = sample_app_graph();
        let mut app = App::new(&g, Path::new("config"), Overrides::default()).unwrap();
        let y = 2 + layout(24, 0).status;
        let first = draw(&app, &theme(), &Glyphs::ascii(), 80, 24);
        let line = text_of(&first, y);
        let select = line.find("<Select>").unwrap();
        let exit = line.find("< Exit >").unwrap();
        assert!(first.cell(select, y).style.reverse);
        assert!(!first.cell(exit, y).style.reverse);

        app.handle(Key::Right);
        let second = draw(&app, &theme(), &Glyphs::ascii(), 80, 24);
        assert!(!second.cell(select, y).style.reverse);
        assert!(second.cell(exit, y).style.reverse);
    }
}
