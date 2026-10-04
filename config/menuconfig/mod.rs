//! SPDX-License-Identifier: GPL-2.0-only
//! Configuration editor over the option graph
//!
//! This module is the editor model and its event loop: the menu stack, the
//! rows a menu shows, which rows are hidden or locked, edits, search, the
//! unsaved-change set, and key handling for every mode. `term` supplies raw
//! terminal I/O and key decoding, `view` lays the model out on a
//! `paint::Canvas`, and `paint` turns canvases into terminal output.
//!
//! Only values the user owns are editable: a hidden or computed option, and
//! a value forced by `select`, are shown but locked, so every edit made on
//! screen survives into the saved file. Saving writes the minimal-diff
//! `config` — only values that differ from what the defaults resolve
//! to — and is refused while the edited configuration does not resolve.

mod paint;
mod term;
mod view;

use mica::config::diag::{Code, Diagnostic};
use mica::config::expr::{self, CmpVal, EvalCtx};
use mica::config::graph::{Graph, Type};
use mica::config::resolve::{self, Origin, OverrideEntry, Overrides, Resolved};
use mica::config::toml::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use term::Key;

/// A row of the current menu or of the search results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    Menu(String),
    Option(String),
    Choice(String),
}

/// One level of the menu stack; `menu` is `None` at the top level.
#[derive(Debug, Clone, Default)]
struct Frame {
    menu: Option<String>,
    cursor: usize,
    scroll: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Normal,
    Search {
        query: String,
        cursor: usize,
        scroll: usize,
    },
    Edit {
        name: String,
        buffer: String,
    },
    Choice {
        name: String,
        cursor: usize,
    },
    Info,
    Confirm {
        button: usize,
    },
}

#[derive(Debug, Clone)]
struct Message {
    text: String,
    error: bool,
}

/// Confirm-dialog buttons, in display order.
const BUTTONS: [&str; 3] = ["Save", "Discard", "Back"];
const MENU_BUTTONS: [&str; 5] = ["<Select>", "< Exit >", "< Help >", "< Save >", "<Search>"];
const SEARCH_BUTTONS: [&str; 2] = ["<Jump>", "<Cancel>"];
const EDIT_BUTTONS: [&str; 3] = ["<Set>", "<Clear>", "<Cancel>"];
const CHOICE_BUTTONS: [&str; 2] = ["<Select>", "<Back>"];

pub struct App<'g> {
    graph: &'g Graph,
    path: PathBuf,
    overrides: Overrides,
    /// Override entries as last loaded or saved.
    saved: BTreeMap<String, Value>,
    /// The last configuration that resolved; kept while an edit fails.
    resolved: Resolved,
    diags: Vec<Diagnostic>,
    frames: Vec<Frame>,
    mode: Mode,
    /// Focused footer button in the current menu or editor mode.
    footer_button: usize,
    show_hidden: bool,
    message: Option<Message>,
    /// Rows the list area shows; set by the loop from the layout.
    page: usize,
    quit: bool,
}

/// Evaluates `visible_when` guards against a resolved configuration.
struct ResolvedCtx<'a> {
    graph: &'a Graph,
    resolved: &'a Resolved,
}

impl EvalCtx for ResolvedCtx<'_> {
    fn lookup(&mut self, name: &str) -> Result<CmpVal, Diagnostic> {
        if let Some(r) = self.resolved.values.get(name) {
            return Ok(match &r.value {
                Value::Bool(b) => CmpVal::Bool(*b),
                Value::Int(n) => CmpVal::Int(*n),
                Value::Str(s) => CmpVal::Str(s.clone()),
                Value::IntList(items) => CmpVal::Str(resolve::join_ints(items)),
                other => {
                    return Err(Diagnostic::new(
                        Code::EType,
                        format!("`{}` has non-scalar value {:?}", name, other),
                    ));
                }
            });
        }
        if let Some(state) = self.resolved.choices.get(name) {
            let label = state
                .active
                .as_ref()
                .and_then(|m| self.graph.options.get(m))
                .and_then(|m| m.value_label.clone())
                .unwrap_or_default();
            return Ok(CmpVal::Str(label));
        }
        Err(Diagnostic::new(
            Code::EUnknownRef,
            format!("unknown name `{}`", name),
        ))
    }
}

/// Existing override entries needed to reproduce the resolved configuration.
/// A changed dependency can alter another option's default without making
/// that dependent option an override the user has to save.
pub fn minimal_entries(
    graph: &Graph,
    overrides: &Overrides,
) -> Result<Vec<(String, Value)>, Vec<Diagnostic>> {
    let current = resolve::resolve(graph, overrides)?;
    let mut remaining = overrides.entries.clone();
    for name in &graph.decl_order {
        let Some(entry) = remaining.remove(name) else {
            continue;
        };
        let trial = Overrides {
            file: overrides.file.clone(),
            entries: remaining.clone(),
        };
        let redundant = resolve::resolve(graph, &trial)
            .is_ok_and(|without| same_configuration(&current, &without));
        if !redundant {
            remaining.insert(name.clone(), entry);
        }
    }
    Ok(graph
        .decl_order
        .iter()
        .filter_map(|name| {
            remaining
                .get(name)
                .map(|entry| (name.clone(), entry.value.clone()))
        })
        .collect())
}

fn same_configuration(a: &Resolved, b: &Resolved) -> bool {
    a.values.len() == b.values.len()
        && a.values.iter().all(|(name, left)| {
            b.values
                .get(name)
                .is_some_and(|right| left.value == right.value && left.visible == right.visible)
        })
        && a.choices.len() == b.choices.len()
        && a.choices.iter().all(|(name, left)| {
            b.choices
                .get(name)
                .is_some_and(|right| left.active == right.active && left.visible == right.visible)
        })
}

/// The minimal-diff persistent configuration text.
pub fn minimal_diff(graph: &Graph, overrides: &Overrides) -> Result<String, Vec<Diagnostic>> {
    let mut lines = vec![
        "# SPDX-License-Identifier: GPL-2.0-only".to_string(),
        "# Generated by `buildutil config menuconfig` — minimal overrides for the resolved configuration."
            .to_string(),
    ];
    for (name, value) in minimal_entries(graph, overrides)? {
        lines.push(format!("{} = {}", name, toml_value(&value)));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn toml_value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Value::IntList(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => format!("{:?}", other),
    }
}

/// A value as the editor displays it; an integer list in the form the
/// input line accepts.
fn display_value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Str(s) => s.clone(),
        Value::IntList(items) => resolve::join_ints(items),
        other => format!("{:?}", other),
    }
}

/// The integer-list input line: comma-separated decimals, surrounding
/// spaces allowed; an empty line is the empty list.
fn parse_int_list(text: &str) -> Option<Vec<i64>> {
    let text = text.trim();
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.split(',')
        .map(|item| item.trim().parse::<i64>().ok())
        .collect()
}

/// Why `n` cannot be a value (or element) of `def`, or `None`.
fn bound_error(def: &mica::config::graph::OptionDef, n: i64) -> Option<String> {
    if let Some(lo) = def.min.filter(|lo| n < *lo) {
        return Some(format!("below minimum {}", lo));
    }
    if let Some(hi) = def.max.filter(|hi| n > *hi) {
        return Some(format!("above maximum {}", hi));
    }
    None
}

fn entry(value: Value, key: &str) -> OverrideEntry {
    OverrideEntry {
        value,
        line: 0,
        written_as: key.to_string(),
    }
}

fn lower_shortcut(key: Key) -> Key {
    match key {
        Key::Char(c) if c.is_ascii_alphabetic() => Key::Char(c.to_ascii_lowercase()),
        other => other,
    }
}

impl<'g> App<'g> {
    /// An editor over `overrides`. A configuration that no longer resolves
    /// is shown over the defaults with its diagnostics, so it can be fixed.
    pub fn new(graph: &'g Graph, path: &Path, overrides: Overrides) -> Result<Self, String> {
        let (resolved, diags) = match resolve::resolve(graph, &overrides) {
            Ok(r) => (r, Vec::new()),
            Err(d) => (
                resolve::resolve(graph, &Overrides::default()).map_err(|errs| {
                    errs.first()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "the option graph does not resolve".to_string())
                })?,
                d,
            ),
        };
        let saved = overrides
            .entries
            .iter()
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect();
        Ok(App {
            graph,
            path: path.to_path_buf(),
            overrides,
            saved,
            resolved,
            diags,
            frames: vec![Frame::default()],
            mode: Mode::Normal,
            footer_button: 0,
            show_hidden: false,
            message: None,
            page: 10,
            quit: false,
        })
    }

    // ----- rows ---------------------------------------------------------

    fn menu_visible(&self, name: &str) -> bool {
        let Some(menu) = self.graph.menus.get(name) else {
            return false;
        };
        if let Some(guard) = &menu.visible_when {
            let mut ctx = ResolvedCtx {
                graph: self.graph,
                resolved: &self.resolved,
            };
            if !expr::eval(guard, &mut ctx).unwrap_or(false) {
                return false;
            }
        }
        !self.menu_rows(Some(name)).is_empty()
    }

    /// Whether a row is outside what the user can change: an option or
    /// choice whose dependencies are unmet, or a computed option.
    fn hidden(&self, row: &Row) -> bool {
        match row {
            Row::Menu(_) => false,
            Row::Option(name) => {
                self.graph.options.get(name).is_some_and(|d| d.computed)
                    || self.resolved.values.get(name).is_some_and(|r| !r.visible)
            }
            Row::Choice(name) => self.resolved.choices.get(name).is_some_and(|c| !c.visible),
        }
    }

    fn menu_rows(&self, menu: Option<&str>) -> Vec<Row> {
        let mut rows = Vec::new();
        for m in self.graph.menus.values() {
            if m.parent.as_deref() == menu && self.menu_visible(&m.name) {
                rows.push(Row::Menu(m.name.clone()));
            }
        }
        for name in &self.graph.decl_order {
            if let Some(def) = self.graph.options.get(name) {
                if def.parent_choice.is_none() && def.menu.as_deref() == menu {
                    let row = Row::Option(name.clone());
                    if self.show_hidden || !self.hidden(&row) {
                        rows.push(row);
                    }
                }
            }
        }
        for c in self.graph.choices.values() {
            if c.menu.as_deref() == menu {
                let row = Row::Choice(c.name.clone());
                if self.show_hidden || !self.hidden(&row) {
                    rows.push(row);
                }
            }
        }
        rows
    }

    fn search_rows(&self, query: &str) -> Vec<Row> {
        let q = query.to_lowercase();
        let hit = |hay: Option<&str>| hay.is_some_and(|h| h.to_lowercase().contains(&q));
        let mut rows = Vec::new();
        for name in &self.graph.decl_order {
            let Some(def) = self.graph.options.get(name) else {
                continue;
            };
            let row = Row::Option(name.clone());
            if def.parent_choice.is_some() || (!self.show_hidden && self.hidden(&row)) {
                continue;
            }
            if hit(Some(name)) || hit(def.title.as_deref()) || hit(def.help.as_deref()) {
                rows.push(row);
            }
        }
        for c in self.graph.choices.values() {
            let row = Row::Choice(c.name.clone());
            if !self.show_hidden && self.hidden(&row) {
                continue;
            }
            if hit(Some(&c.name)) || hit(c.title.as_deref()) || hit(c.help.as_deref()) {
                rows.push(row);
            }
        }
        rows
    }

    fn rows(&self) -> Vec<Row> {
        match &self.mode {
            Mode::Search { query, .. } => self.search_rows(query),
            _ => self.menu_rows(self.frame().menu.as_deref()),
        }
    }

    fn frame(&self) -> &Frame {
        self.frames.last().expect("the top frame is never popped")
    }

    fn frame_mut(&mut self) -> &mut Frame {
        self.frames
            .last_mut()
            .expect("the top frame is never popped")
    }

    /// (cursor, scroll) of the list the current mode shows.
    fn cursor(&self) -> (usize, usize) {
        match &self.mode {
            Mode::Search { cursor, scroll, .. } => (*cursor, *scroll),
            _ => (self.frame().cursor, self.frame().scroll),
        }
    }

    fn current_row(&self) -> Option<Row> {
        let rows = self.rows();
        rows.get(self.cursor().0.min(rows.len().saturating_sub(1)))
            .cloned()
    }

    fn move_cursor(&mut self, delta: isize) {
        let len = self.rows().len();
        let page = self.page.max(1);
        let (cursor, scroll) = match &mut self.mode {
            Mode::Search { cursor, scroll, .. } => (cursor, scroll),
            _ => {
                let f = self
                    .frames
                    .last_mut()
                    .expect("the top frame is never popped");
                (&mut f.cursor, &mut f.scroll)
            }
        };
        let last = len.saturating_sub(1) as isize;
        *cursor = (*cursor as isize + delta).clamp(0, last.max(0)) as usize;
        if *cursor < *scroll {
            *scroll = *cursor;
        } else if *cursor >= *scroll + page {
            *scroll = *cursor + 1 - page;
        }
    }

    /// Keep the cursor and scroll inside the list after it changed length.
    fn clamp(&mut self) {
        self.move_cursor(0);
    }

    // ----- values -------------------------------------------------------

    fn selectors(&self, name: &str) -> Vec<&str> {
        self.graph
            .options
            .values()
            .filter(|o| {
                o.select.iter().any(|s| s == name)
                    && self
                        .resolved
                        .values
                        .get(&o.name)
                        .is_some_and(|r| r.value == Value::Bool(true))
            })
            .map(|o| o.name.as_str())
            .collect()
    }

    /// Why a row cannot be edited, or `None` when it can.
    fn lock_reason(&self, row: &Row) -> Option<String> {
        match row {
            Row::Menu(_) => None,
            Row::Option(name) => {
                let def = self.graph.options.get(name)?;
                if def.computed {
                    return Some(format!("{} is computed from its default", name));
                }
                let r = self.resolved.values.get(name)?;
                if !r.visible {
                    return Some(match &def.depends_on {
                        Some(dep) => format!("{} requires {}", name, dep.render()),
                        None => format!("{} is hidden", name),
                    });
                }
                if r.origin == Origin::Select {
                    return Some(format!(
                        "{} is forced on by {}",
                        name,
                        self.selectors(name).join(", ")
                    ));
                }
                None
            }
            Row::Choice(name) => {
                let hidden = self.resolved.choices.get(name).is_some_and(|c| !c.visible);
                hidden.then(|| {
                    match self
                        .graph
                        .choices
                        .get(name)
                        .and_then(|c| c.depends_on.as_ref())
                    {
                        Some(dep) => format!("{} requires {}", name, dep.render()),
                        None => format!("{} is hidden", name),
                    }
                })
            }
        }
    }

    /// Re-resolve after an edit. On success the override set is rewritten
    /// to its minimal form, so returning a value to its default removes the
    /// override and leaves no phantom change.
    fn apply(&mut self) {
        match resolve::resolve(self.graph, &self.overrides) {
            Ok(r) => {
                self.resolved = r;
                self.diags.clear();
                if let Ok(entries) = minimal_entries(self.graph, &self.overrides) {
                    let normalized_entries = entries
                        .into_iter()
                        .map(|(k, v)| {
                            let e = entry(v, &k);
                            (k, e)
                        })
                        .collect();
                    let normalized = Overrides {
                        file: self.overrides.file.clone(),
                        entries: normalized_entries,
                    };
                    if let Ok(resolved) = resolve::resolve(self.graph, &normalized) {
                        self.overrides = normalized;
                        self.resolved = resolved;
                    }
                }
            }
            Err(d) => self.diags = d,
        }
        self.clamp();
    }

    fn set(&mut self, name: &str, value: Value) {
        self.overrides
            .entries
            .insert(name.to_string(), entry(value, name));
        self.apply();
    }

    fn select_member(&mut self, choice: &str, member: &str) {
        if let Some(def) = self.graph.choices.get(choice) {
            for m in &def.members {
                self.overrides.entries.remove(m);
            }
        }
        self.set(member, Value::Bool(true));
    }

    fn bool_value(&self, name: &str) -> bool {
        self.resolved
            .values
            .get(name)
            .is_some_and(|r| r.value == Value::Bool(true))
    }

    /// The pending edits: (key, value when last saved, value now), with
    /// `default` for a key that has no override on that side.
    fn changes(&self) -> Vec<(String, String, String)> {
        let now: BTreeMap<&String, &Value> = self
            .overrides
            .entries
            .iter()
            .map(|(k, e)| (k, &e.value))
            .collect();
        let mut keys: Vec<&String> = self.saved.keys().chain(now.keys().copied()).collect();
        keys.sort();
        keys.dedup();
        let show = |v: Option<&Value>| v.map_or("default".to_string(), display_value);
        keys.into_iter()
            .filter(|k| self.saved.get(*k) != now.get(k).copied())
            .map(|k| {
                (
                    k.clone(),
                    show(self.saved.get(k)),
                    show(now.get(k).copied()),
                )
            })
            .collect()
    }

    fn save(&mut self) -> bool {
        if !self.diags.is_empty() {
            self.flash(
                "the configuration does not resolve; fix it before saving",
                true,
            );
            return false;
        }
        let text = match minimal_diff(self.graph, &self.overrides) {
            Ok(t) => t,
            Err(d) => {
                self.diags = d;
                return false;
            }
        };
        if let Err(e) = std::fs::write(&self.path, text) {
            self.flash(
                &format!("cannot write {}: {}", self.path.display(), e),
                true,
            );
            return false;
        }
        self.saved = self
            .overrides
            .entries
            .iter()
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect();
        self.flash(&format!("saved {}", self.path.display()), false);
        true
    }

    fn flash(&mut self, text: &str, error: bool) {
        self.message = Some(Message {
            text: text.to_string(),
            error,
        });
    }

    fn request_quit(&mut self) {
        self.footer_button = 0;
        if self.changes().is_empty() {
            self.quit = true;
        } else {
            self.mode = Mode::Confirm { button: 0 };
        }
    }

    // ----- navigation ---------------------------------------------------

    fn back(&mut self) {
        if self.frames.len() > 1 {
            self.frames.pop();
        }
    }

    fn exit_menu(&mut self) {
        if self.frames.len() > 1 {
            self.back();
        } else {
            self.request_quit();
        }
        self.footer_button = 0;
    }

    fn move_footer(&mut self, count: usize, previous: bool) {
        self.footer_button = if previous {
            (self.footer_button + count - 1) % count
        } else {
            (self.footer_button + 1) % count
        };
    }

    fn activate_menu_button(&mut self) {
        match self.footer_button {
            0 => {
                if let Some(row) = self.current_row() {
                    self.activate(row);
                }
            }
            1 => self.exit_menu(),
            2 => {
                if self.current_row().is_some() {
                    self.mode = Mode::Info;
                    self.footer_button = 0;
                }
            }
            3 => {
                self.save();
            }
            _ => {
                self.mode = Mode::Search {
                    query: String::new(),
                    cursor: 0,
                    scroll: 0,
                };
                self.footer_button = 0;
            }
        }
    }

    /// Open the menu stack at `row`'s menu with the cursor on it.
    fn jump_to(&mut self, row: &Row) {
        let menu = match row {
            Row::Menu(name) => self.graph.menus.get(name).and_then(|m| m.parent.clone()),
            Row::Option(name) => self.graph.options.get(name).and_then(|d| d.menu.clone()),
            Row::Choice(name) => self.graph.choices.get(name).and_then(|c| c.menu.clone()),
        };
        let mut chain = Vec::new();
        let mut cur = menu;
        while let Some(m) = cur {
            cur = self.graph.menus.get(&m).and_then(|d| d.parent.clone());
            chain.push(m);
        }
        chain.reverse();
        self.frames = vec![Frame::default()];
        for m in chain {
            let target = Row::Menu(m.clone());
            let cursor = self.rows().iter().position(|r| *r == target).unwrap_or(0);
            self.frame_mut().cursor = cursor;
            self.clamp();
            self.frames.push(Frame {
                menu: Some(m),
                ..Frame::default()
            });
        }
        let cursor = self.rows().iter().position(|r| r == row).unwrap_or(0);
        self.frame_mut().cursor = cursor;
        self.clamp();
    }

    /// Enter on a row: descend, toggle, or open the editor for its type.
    fn activate(&mut self, row: Row) {
        if let Row::Menu(name) = &row {
            self.frames.push(Frame {
                menu: Some(name.clone()),
                ..Frame::default()
            });
            self.footer_button = 0;
            return;
        }
        if let Some(reason) = self.lock_reason(&row) {
            self.flash(&reason, true);
            return;
        }
        match row {
            Row::Option(name) => match self.graph.options.get(&name).map(|d| d.ty) {
                Some(Type::Bool) => {
                    let v = self.bool_value(&name);
                    self.set(&name, Value::Bool(!v));
                }
                Some(Type::Int | Type::IntList | Type::Str) => {
                    let buffer = self
                        .resolved
                        .values
                        .get(&name)
                        .map(|r| display_value(&r.value))
                        .unwrap_or_default();
                    self.mode = Mode::Edit { name, buffer };
                    self.footer_button = 0;
                }
                _ => {}
            },
            Row::Choice(name) => {
                let active = self
                    .resolved
                    .choices
                    .get(&name)
                    .and_then(|c| c.active.clone());
                let cursor = self
                    .graph
                    .choices
                    .get(&name)
                    .and_then(|c| c.members.iter().position(|m| Some(m) == active.as_ref()))
                    .unwrap_or(0);
                self.mode = Mode::Choice { name, cursor };
                self.footer_button = 0;
            }
            Row::Menu(_) => {}
        }
    }

    /// Why the edit buffer cannot be committed, or `None`.
    fn edit_error(&self) -> Option<String> {
        let Mode::Edit { name, buffer } = &self.mode else {
            return None;
        };
        let def = self.graph.options.get(name)?;
        match def.ty {
            Type::Int => {
                let Ok(n) = buffer.parse::<i64>() else {
                    return Some(if buffer.is_empty() {
                        "enter a number".to_string()
                    } else {
                        "not a number".to_string()
                    });
                };
                bound_error(def, n)
            }
            // Each element of an integer list is checked against the bounds.
            Type::IntList => match parse_int_list(buffer) {
                Some(items) => items
                    .into_iter()
                    .find_map(|n| bound_error(def, n).map(|why| format!("{}: {}", n, why))),
                None => Some("enter numbers separated by commas".to_string()),
            },
            _ => None,
        }
    }

    // ----- keys ---------------------------------------------------------

    pub fn handle(&mut self, key: Key) {
        self.message = None;
        match self.mode.clone() {
            Mode::Normal => self.key_normal(lower_shortcut(key)),
            Mode::Search { .. } => self.key_search(key),
            Mode::Edit { .. } => self.key_edit(key),
            Mode::Choice { name, cursor } => self.key_choice(lower_shortcut(key), name, cursor),
            Mode::Info => {
                self.mode = Mode::Normal;
                self.footer_button = 0;
            }
            Mode::Confirm { button } => self.key_confirm(lower_shortcut(key), button),
        }
    }

    fn key_normal(&mut self, key: Key) {
        let page = self.page.max(1) as isize;
        match key {
            Key::Up => self.move_cursor(-1),
            Key::Down => self.move_cursor(1),
            Key::PageUp => self.move_cursor(-page),
            Key::PageDown => self.move_cursor(page),
            Key::Home => self.move_cursor(isize::MIN / 2),
            Key::End => self.move_cursor(isize::MAX / 2),
            Key::Left => self.move_footer(MENU_BUTTONS.len(), true),
            Key::Right | Key::Tab => self.move_footer(MENU_BUTTONS.len(), false),
            Key::Enter => self.activate_menu_button(),
            Key::Char(' ') => {
                if let Some(row) = self.current_row() {
                    self.activate(row);
                }
            }
            Key::Char(c @ ('y' | 'n')) => {
                if let Some(row @ Row::Option(_)) = self.current_row() {
                    let Row::Option(name) = &row else {
                        return;
                    };
                    if self.graph.options.get(name).map(|d| d.ty) != Some(Type::Bool) {
                        return;
                    }
                    match self.lock_reason(&row) {
                        Some(reason) => self.flash(&reason, true),
                        None => self.set(name, Value::Bool(c == 'y')),
                    }
                }
            }
            Key::Backspace | Key::Esc | Key::Char('e' | 'x') => self.exit_menu(),
            Key::Char('/') => {
                self.mode = Mode::Search {
                    query: String::new(),
                    cursor: 0,
                    scroll: 0,
                };
                self.footer_button = 0;
            }
            Key::Char('h' | '?') => {
                if self.current_row().is_some() {
                    self.mode = Mode::Info;
                    self.footer_button = 0;
                }
            }
            Key::Char('z') => {
                self.show_hidden = !self.show_hidden;
                self.clamp();
            }
            Key::Char('s') => {
                self.save();
            }
            Key::Char('q') | Key::Ctrl('c') => self.request_quit(),
            _ => {}
        }
    }

    fn key_search(&mut self, key: Key) {
        match key {
            Key::Left => self.move_footer(SEARCH_BUTTONS.len(), true),
            Key::Right | Key::Tab => self.move_footer(SEARCH_BUTTONS.len(), false),
            Key::Esc | Key::Ctrl('c') => {
                self.mode = Mode::Normal;
                self.footer_button = 0;
            }
            Key::Enter => {
                if self.footer_button == 1 {
                    self.mode = Mode::Normal;
                } else if let Some(row) = self.current_row() {
                    self.mode = Mode::Normal;
                    self.jump_to(&row);
                }
                self.footer_button = 0;
            }
            Key::Up => self.move_cursor(-1),
            Key::Down => self.move_cursor(1),
            Key::Backspace => {
                let emptied = match &mut self.mode {
                    Mode::Search { query, .. } => query.pop().is_none(),
                    _ => return,
                };
                if emptied {
                    self.mode = Mode::Normal;
                    self.footer_button = 0;
                } else {
                    self.reset_search_cursor();
                    self.footer_button = 0;
                }
            }
            Key::Char(c) => {
                if let Mode::Search { query, .. } = &mut self.mode {
                    query.push(c);
                }
                self.reset_search_cursor();
                self.footer_button = 0;
            }
            _ => {}
        }
    }

    fn reset_search_cursor(&mut self) {
        if let Mode::Search { cursor, scroll, .. } = &mut self.mode {
            *cursor = 0;
            *scroll = 0;
        }
    }

    fn key_edit(&mut self, key: Key) {
        match key {
            Key::Left => {
                self.move_footer(EDIT_BUTTONS.len(), true);
                return;
            }
            Key::Right | Key::Tab => {
                self.move_footer(EDIT_BUTTONS.len(), false);
                return;
            }
            Key::Enter if self.footer_button == 2 => {
                self.mode = Mode::Normal;
                self.footer_button = 0;
                return;
            }
            _ => {}
        }
        let error = self.edit_error();
        let Mode::Edit { name, buffer } = &mut self.mode else {
            return;
        };
        let ty = self.graph.options.get(name.as_str()).map(|d| d.ty);
        match key {
            Key::Esc | Key::Ctrl('c') => {
                self.mode = Mode::Normal;
                self.footer_button = 0;
            }
            Key::Backspace => {
                buffer.pop();
                self.footer_button = 0;
            }
            Key::Ctrl('u') => {
                buffer.clear();
                self.footer_button = 0;
            }
            Key::Enter => {
                if self.footer_button == 1 {
                    buffer.clear();
                    self.footer_button = 0;
                    return;
                }
                if error.is_some() {
                    return;
                }
                let (name, buffer) = (name.clone(), buffer.clone());
                let value = match ty {
                    Some(Type::Int) => match buffer.parse() {
                        Ok(n) => Value::Int(n),
                        Err(_) => return,
                    },
                    Some(Type::IntList) => match parse_int_list(&buffer) {
                        Some(items) => Value::IntList(items),
                        None => return,
                    },
                    _ => Value::Str(buffer),
                };
                self.mode = Mode::Normal;
                self.footer_button = 0;
                self.set(&name, value);
            }
            Key::Char(c) => {
                let accept = match ty {
                    Some(Type::Int) => c.is_ascii_digit() || (c == '-' && buffer.is_empty()),
                    Some(Type::IntList) => c.is_ascii_digit() || c == '-' || c == ',',
                    _ => true,
                };
                if accept {
                    buffer.push(c);
                    self.footer_button = 0;
                }
            }
            _ => {}
        }
    }

    fn key_choice(&mut self, key: Key, name: String, cursor: usize) {
        let members = self
            .graph
            .choices
            .get(&name)
            .map(|c| c.members.clone())
            .unwrap_or_default();
        let last = members.len().saturating_sub(1);
        match key {
            Key::Up => {
                self.mode = Mode::Choice {
                    name,
                    cursor: cursor.saturating_sub(1),
                }
            }
            Key::Down => {
                self.mode = Mode::Choice {
                    name,
                    cursor: (cursor + 1).min(last),
                }
            }
            Key::Left => self.move_footer(CHOICE_BUTTONS.len(), true),
            Key::Right | Key::Tab => self.move_footer(CHOICE_BUTTONS.len(), false),
            Key::Enter if self.footer_button == 1 => {
                self.mode = Mode::Normal;
                self.footer_button = 0;
            }
            Key::Enter | Key::Char(' ') => {
                self.mode = Mode::Normal;
                self.footer_button = 0;
                if let Some(member) = members.get(cursor) {
                    self.select_member(&name, member);
                }
            }
            Key::Esc | Key::Char('q') | Key::Ctrl('c') => {
                self.mode = Mode::Normal;
                self.footer_button = 0;
            }
            _ => {}
        }
    }

    fn key_confirm(&mut self, key: Key, button: usize) {
        let pick = match key {
            Key::Left => {
                self.mode = Mode::Confirm {
                    button: (button + BUTTONS.len() - 1) % BUTTONS.len(),
                };
                return;
            }
            Key::Right | Key::Tab => {
                self.mode = Mode::Confirm {
                    button: (button + 1) % BUTTONS.len(),
                };
                return;
            }
            Key::Enter => button,
            Key::Char('s' | 'y') => 0,
            Key::Char('d' | 'n') => 1,
            Key::Esc | Key::Char('b') | Key::Ctrl('c') => 2,
            _ => return,
        };
        match pick {
            0 => {
                if self.save() {
                    self.quit = true;
                } else {
                    self.mode = Mode::Normal;
                }
            }
            1 => self.quit = true,
            _ => self.mode = Mode::Normal,
        }
    }
}

/// How long to wait for the terminal to answer the background query.
const BACKGROUND_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

/// Run the configuration editor over the graph, writing minimal overrides
/// to `config_path` on save.
pub fn run(graph: &Graph, config_path: &Path) -> Result<i32, String> {
    let overrides = resolve::load_overrides(graph, config_path).map_err(|d| {
        let first = d.first().map(|x| x.to_string()).unwrap_or_default();
        format!("cannot load {}: {}", config_path.display(), first)
    })?;
    let mut app = App::new(graph, config_path, overrides)?;
    let env = |k: &str| std::env::var(k).ok();
    let depth = paint::Depth::detect(&env);
    let glyphs = if paint::detect_unicode(&env) {
        paint::Glyphs::unicode()
    } else {
        paint::Glyphs::ascii()
    };

    let mut tty = term::Tty::open()?;
    let mut decoder = term::Decoder::default();
    let mut queued = Vec::new();
    let mut theme = paint::Theme::new(depth, None);
    if matches!(depth, paint::Depth::TrueColor | paint::Depth::Ansi256) {
        tty.write("\x1b]11;?\x07");
        let deadline = std::time::Instant::now() + BACKGROUND_WAIT;
        let mut buf = [0u8; 256];
        'wait: while std::time::Instant::now() < deadline {
            let n = tty.read(&mut buf);
            decoder.feed(&buf[..n]);
            while let Some(key) = decoder.next(false) {
                if let Key::Background(r, g, b) = key {
                    theme = paint::Theme::new(depth, Some((r, g, b)));
                    break 'wait;
                }
                queued.push(key);
            }
        }
    }

    let mut prev: Option<paint::Canvas> = None;
    let mut buf = [0u8; 256];
    loop {
        for key in queued.drain(..) {
            match key {
                Key::Background(r, g, b) => {
                    theme = paint::Theme::new(depth, Some((r, g, b)));
                    prev = None;
                }
                Key::Ctrl('z') => {
                    tty.suspend()?;
                    prev = None;
                }
                Key::Ctrl('l') => prev = None,
                key => app.handle(key),
            }
        }
        if app.quit {
            break;
        }
        let (w, h) = tty.size();
        app.page = view::layout(h, app.diags.len()).list_h;
        app.clamp();
        let canvas = view::draw(&app, &theme, &glyphs, w, h);
        let out = paint::emit(prev.as_ref(), &canvas, theme.depth);
        tty.write(&out);
        prev = Some(canvas);

        let n = tty.read(&mut buf);
        decoder.feed(&buf[..n]);
        while let Some(key) = decoder.next(n == 0) {
            queued.push(key);
        }
        if term::terminated() {
            break;
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests_support {
    use mica::config::graph::{self, Graph};
    use std::path::Path;

    const SRC: &str = r#"
[menu.net]
title = "Networking"

[option.DEBUG]
type = "bool"
title = "Debug build"
default = true
select = ["TRACE"]
help = "debug build"

[option.TRACE]
type = "bool"
title = "Tracing"
default = false
help = "tracing"

[option.NET_TCP]
type = "bool"
default = false
menu = "net"

[option.NET_UDP]
type = "bool"
default = false
depends_on = "NET_TCP"
menu = "net"

[option.STACK]
type = "int"
title = "Stack size"
default = 16384
min = 4096
max = 65536

[option.DERIVED]
type = "bool"
computed = true
default = "true if DEBUG else false"

[choice.level]
title = "Log level"
default = "LEVEL_INFO"

  [choice.level.option.LEVEL_WARN]
  [choice.level.option.LEVEL_INFO]
  [choice.level.option.LEVEL_DEBUG]
"#;

    /// A graph with a menu, a select chain, a dependency, an integer range,
    /// a computed option, and a choice.
    pub fn sample_app_graph() -> Graph {
        let doc = mica::config::toml::parse(Path::new("t.toml"), SRC).unwrap();
        graph::from_docs(&[doc]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::sample_app_graph;
    use super::*;

    fn app(g: &Graph) -> App<'_> {
        App::new(
            g,
            Path::new("/nonexistent/config"),
            Overrides::default(),
        )
        .unwrap()
    }

    fn type_str(app: &mut App<'_>, s: &str) {
        for c in s.chars() {
            app.handle(Key::Char(c));
        }
    }

    fn cursor_to(app: &mut App<'_>, row: Row) {
        let pos = app.rows().iter().position(|r| *r == row).unwrap();
        app.frame_mut().cursor = pos;
    }

    #[test]
    fn computed_and_unmet_options_are_hidden_until_shown() {
        let g = sample_app_graph();
        let mut a = app(&g);
        let top = a.rows();
        assert!(top.contains(&Row::Menu("net".into())));
        assert!(top.contains(&Row::Option("STACK".into())));
        assert!(!top.contains(&Row::Option("DERIVED".into())));
        a.frames.push(Frame {
            menu: Some("net".into()),
            ..Frame::default()
        });
        assert_eq!(a.rows(), vec![Row::Option("NET_TCP".into())]);
        a.handle(Key::Char('z'));
        assert!(a.rows().contains(&Row::Option("NET_UDP".into())));
    }

    #[test]
    fn select_forced_values_are_locked_so_no_edit_is_lost() {
        let g = sample_app_graph();
        let mut a = app(&g);
        cursor_to(&mut a, Row::Option("TRACE".into()));
        a.handle(Key::Enter);
        assert!(a.bool_value("TRACE"));
        assert!(a.changes().is_empty());
        let msg = a.message.as_ref().unwrap();
        assert!(
            msg.error && msg.text.contains("forced on by DEBUG"),
            "{}",
            msg.text
        );
    }

    #[test]
    fn search_takes_typed_text_and_jumps_to_the_match() {
        let g = sample_app_graph();
        let mut a = app(&g);
        a.handle(Key::Char('/'));
        type_str(&mut a, "tcp");
        assert_eq!(a.rows(), vec![Row::Option("NET_TCP".into())]);
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.frame().menu.as_deref(), Some("net"));
        assert_eq!(a.current_row(), Some(Row::Option("NET_TCP".into())));
    }

    #[test]
    fn menu_arrows_focus_buttons_and_h_opens_help() {
        let g = sample_app_graph();
        let mut a = app(&g);
        let row = a.current_row();
        a.handle(Key::Right);
        assert_eq!(a.footer_button, 1);
        assert_eq!(a.current_row(), row);
        assert_eq!(a.mode, Mode::Normal);
        a.handle(Key::Enter);
        assert!(a.quit, "Enter on Exit should leave an unchanged top menu");

        let mut a = app(&g);
        a.handle(Key::Right);
        a.handle(Key::Right);
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Info);
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Normal);

        let mut a = app(&g);
        a.handle(Key::Char('H'));
        assert_eq!(a.mode, Mode::Info);
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Normal);
        a.handle(Key::Left);
        assert_eq!(a.footer_button, MENU_BUTTONS.len() - 1);
        a.handle(Key::Enter);
        assert!(matches!(a.mode, Mode::Search { .. }));

        let mut a = app(&g);
        a.handle(Key::Enter);
        assert_eq!(a.frame().menu.as_deref(), Some("net"));
        a.handle(Key::Tab);
        a.handle(Key::Enter);
        assert_eq!(a.frame().menu, None);
        assert!(!a.quit);

        let mut a = app(&g);
        cursor_to(&mut a, Row::Option("DEBUG".into()));
        a.handle(Key::Right);
        a.handle(Key::Char(' '));
        assert!(!a.bool_value("DEBUG"));
        assert!(!a.quit);
    }

    #[test]
    fn search_edit_and_choice_buttons_follow_their_focus() {
        let g = sample_app_graph();
        let mut a = app(&g);
        a.handle(Key::Char('/'));
        type_str(&mut a, "tcp");
        a.handle(Key::Right);
        assert_eq!(a.footer_button, 1);
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.frame().menu, None);

        cursor_to(&mut a, Row::Option("STACK".into()));
        a.handle(Key::Enter);
        assert!(matches!(a.mode, Mode::Edit { .. }));
        a.handle(Key::Right);
        a.handle(Key::Enter);
        assert!(matches!(a.mode, Mode::Edit { ref buffer, .. } if buffer.is_empty()));
        assert_eq!(a.footer_button, 0);
        a.handle(Key::Right);
        a.handle(Key::Right);
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.changes().is_empty());

        cursor_to(&mut a, Row::Choice("level".into()));
        a.handle(Key::Enter);
        assert!(matches!(a.mode, Mode::Choice { .. }));
        a.handle(Key::Right);
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.changes().is_empty());
    }

    #[test]
    fn integers_are_typed_and_range_checked() {
        let g = sample_app_graph();
        let mut a = app(&g);
        cursor_to(&mut a, Row::Option("STACK".into()));
        a.handle(Key::Enter);
        a.handle(Key::Ctrl('u'));
        type_str(&mut a, "70000");
        assert_eq!(a.edit_error().as_deref(), Some("above maximum 65536"));
        a.handle(Key::Enter);
        assert!(matches!(a.mode, Mode::Edit { .. }));
        a.handle(Key::Ctrl('u'));
        type_str(&mut a, "32768");
        a.handle(Key::Enter);
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(
            a.changes(),
            vec![("STACK".into(), "default".into(), "32768".into())]
        );
    }

    #[test]
    fn choosing_a_member_replaces_the_previous_one_and_default_leaves_no_change() {
        let g = sample_app_graph();
        let mut a = app(&g);
        a.select_member("level", "LEVEL_DEBUG");
        assert_eq!(a.changes().len(), 1);
        a.select_member("level", "LEVEL_WARN");
        assert_eq!(
            a.changes(),
            vec![("LEVEL_WARN".into(), "default".into(), "true".into())]
        );
        a.select_member("level", "LEVEL_INFO");
        assert!(a.changes().is_empty(), "{:?}", a.changes());
    }

    #[test]
    fn quitting_with_unsaved_changes_asks_and_back_keeps_editing() {
        let g = sample_app_graph();
        let mut a = app(&g);
        a.handle(Key::Char('q'));
        assert!(a.quit, "nothing to save quits at once");
        let mut a = app(&g);
        cursor_to(&mut a, Row::Option("STACK".into()));
        a.set("STACK", Value::Int(8192));
        a.handle(Key::Ctrl('c'));
        assert_eq!(a.mode, Mode::Confirm { button: 0 });
        a.handle(Key::Esc);
        assert_eq!(a.mode, Mode::Normal);
        assert!(!a.quit);
        a.handle(Key::Char('q'));
        a.handle(Key::Char('d'));
        assert!(a.quit);
    }

    #[test]
    fn confirmation_arrows_focus_the_action_enter_will_run() {
        let g = sample_app_graph();
        let mut a = app(&g);
        a.set("STACK", Value::Int(8192));
        a.handle(Key::Char('q'));
        assert_eq!(a.mode, Mode::Confirm { button: 0 });
        a.handle(Key::Right);
        assert_eq!(a.mode, Mode::Confirm { button: 1 });
        a.handle(Key::Tab);
        assert_eq!(a.mode, Mode::Confirm { button: 2 });
        a.handle(Key::Left);
        assert_eq!(a.mode, Mode::Confirm { button: 1 });
        a.handle(Key::Enter);
        assert!(a.quit);
    }

    #[test]
    fn saving_writes_the_minimal_diff_and_clears_changes() {
        let g = sample_app_graph();
        let dir = std::env::temp_dir().join(format!("buildutil-menuconfig-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config");
        let mut a = App::new(&g, &path, Overrides::default()).unwrap();
        a.set("NET_TCP", Value::Bool(true));
        for _ in 0..3 {
            a.handle(Key::Right);
        }
        assert_eq!(a.footer_button, 3);
        a.handle(Key::Enter);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("NET_TCP = true"), "{}", text);
        assert!(!text.contains("DEBUG"), "{}", text);
        assert!(a.changes().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn toggling_back_to_the_default_is_not_a_change() {
        let g = sample_app_graph();
        let mut a = app(&g);
        cursor_to(&mut a, Row::Option("DEBUG".into()));
        a.handle(Key::Enter);
        assert_eq!(
            a.changes(),
            vec![("DEBUG".into(), "default".into(), "false".into())]
        );
        assert_eq!(a.resolved.values["TRACE"].origin, Origin::Default);
        a.handle(Key::Enter);
        assert!(a.changes().is_empty(), "{:?}", a.changes());
        assert_eq!(a.resolved.values["DEBUG"].origin, Origin::Default);
        assert_eq!(a.resolved.values["TRACE"].origin, Origin::Select);
    }

    #[test]
    fn dependent_defaults_are_not_serialized_as_overrides() {
        let doc = mica::config::toml::parse(
            Path::new("dependent.toml"),
            "[option.PARENT]\ntype = \"bool\"\ndefault = true\n\
             [option.CHILD]\ntype = \"bool\"\ndefault = \"true if PARENT else false\"\n",
        )
        .unwrap();
        let g = mica::config::graph::from_docs(&[doc]).unwrap();
        let mut a = app(&g);
        a.set("PARENT", Value::Bool(false));
        assert_eq!(a.resolved.values["CHILD"].value, Value::Bool(false));
        assert_eq!(
            minimal_entries(&g, &a.overrides).unwrap(),
            vec![("PARENT".into(), Value::Bool(false))]
        );
        assert!(!minimal_diff(&g, &a.overrides).unwrap().contains("CHILD ="));

        a.set("CHILD", Value::Bool(true));
        assert_eq!(minimal_entries(&g, &a.overrides).unwrap().len(), 2);
        a.set("PARENT", Value::Bool(true));
        assert!(a.changes().is_empty());
        assert_eq!(a.resolved.values["CHILD"].origin, Origin::Default);
    }
}
