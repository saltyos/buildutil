//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the build screen: build events drawn as durable lines and status
//!
//! `BuildView` is the one place that decides what a person sees of a build.
//! It consumes the JSONL build events, whether they come from the daemon, an
//! engine child process, or in-process producers through the local event
//! sink, plus raw bytes an engine wrote to stdout or stderr. It prints the
//! screen in the order its facts become known: the title, the dependency
//! evaluation phases, the build environment (which needs the evaluated tool
//! versions), then one line per realized, cached, or failed derivation.
//!
//! The view draws only through its `Screen` and reads no process state:
//! whether a status row exists and whether color is on come from `Options`.
//! It interprets no builder text. A progress item (`item` event) goes to the
//! status row; an output line is printed as the tool wrote it, subject to
//! `--build-output`. A derivation's action line (`[n/N] Compiling x`) becomes
//! durable at its first item or output line, with the counter of that moment;
//! a derivation that shows neither gets only its completion line. The durable
//! lines are therefore the same on a terminal and in a pipe; a terminal adds
//! the status row.

use crate::eval::graph::EvalPhase;
use crate::events::{self, EvalTimings, HeaderReport, ResolveReport, StreamEvent, SummaryReport};
use crate::term::{self, Role};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// buildutil's version, shown in the title.
pub const VERSION: &str = "0.0.1";
/// Lines of output kept per derivation for `--build-output=failed`.
pub const TAIL_LINES: usize = 25;

/// Which builder output a person sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Every output line of every builder.
    #[default]
    All,
    /// Only the last lines of a derivation that failed.
    Failed,
    /// None; a failure names its log.
    None,
}

impl OutputMode {
    pub fn parse(value: &str) -> Option<OutputMode> {
        match value {
            "all" => Some(OutputMode::All),
            "failed" => Some(OutputMode::Failed),
            "none" => Some(OutputMode::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub verbose: bool,
    pub output: OutputMode,
    pub timings: bool,
    pub targets: Vec<String>,
    /// A status row is drawn (stderr is a terminal).
    pub interactive: bool,
    /// Styles are drawn, and tool output keeps its escape sequences.
    pub color: bool,
    /// This client's state root, against which event log paths resolve.
    pub state_root: Option<PathBuf>,
}

impl Options {
    /// Status row and color as this process's terminal allows.
    pub fn for_terminal() -> Options {
        Options {
            interactive: term::interactive(),
            color: term::color(),
            ..Options::default()
        }
    }
}

/// Where a view draws.
pub trait Screen {
    /// A durable line above the status row.
    fn line(&mut self, text: &str);
    /// A line on stdout, for other programs.
    fn result(&mut self, text: &str);
    /// Replace the status row; empty text removes it.
    fn status(&mut self, text: &str);
    /// Columns available for the status row.
    fn width(&self) -> usize;
}

/// The process terminal.
pub struct Terminal;

impl Screen for Terminal {
    fn line(&mut self, text: &str) {
        term::line(text);
    }

    fn result(&mut self, text: &str) {
        term::result(text);
    }

    fn status(&mut self, text: &str) {
        term::status(text);
    }

    fn width(&self) -> usize {
        term::width()
    }
}

/// Which stream raw engine bytes arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

struct Running {
    drv: String,
    /// The current step: `Staging`, then the builder's action.
    action: String,
    /// Whether the `<action> <drv>` line has become durable.
    promoted: bool,
    /// The newest counter a structured item carried.
    inner: Option<(usize, usize)>,
    /// The newest item: its counter, its text, and when it arrived.
    item: Option<((usize, usize), String, Instant)>,
    tail: VecDeque<String>,
}

/// The completion verb for a derivation whose step was `action`.
fn completed(action: &str) -> &'static str {
    match action {
        "Compiling" => "Compiled",
        "Fetching" => "Fetched",
        "Running" => "Ran",
        "Importing" => "Imported",
        "Projecting" => "Projected",
        _ => "Realized",
    }
}

fn outcome_role(outcome: &str) -> Role {
    match outcome {
        "Cached" => Role::Cached,
        "Failed" => Role::Failed,
        _ => Role::Built,
    }
}

fn level_tag(level: &str) -> Option<(&'static str, Role)> {
    match level {
        "debug" => Some(("[DEBUG]", Role::Debug)),
        "info" => Some(("[INFO]", Role::Info)),
        "success" => Some(("[SUCCESS]", Role::Success)),
        "warning" => Some(("[WARNING]", Role::Warning)),
        "error" => Some(("[ERROR]", Role::Error)),
        _ => None,
    }
}

fn phase_label(phase: EvalPhase, done: bool) -> &'static str {
    match (phase, done) {
        (EvalPhase::ResolvingSources, false) => "Resolving sources",
        (EvalPhase::ResolvingSources, true) => "Resolved sources",
        (EvalPhase::Instantiating, false) => "Evaluating derivations",
        (EvalPhase::Instantiating, true) => "Evaluated derivations",
        (EvalPhase::Evaluated, _) => "Evaluated",
    }
}

/// `[n/N]` with `n` right-aligned to the width of `N`.
pub fn counter(n: usize, total: usize) -> String {
    let w = total.to_string().len();
    format!("[{:>w$}/{}]", n, total, w = w)
}

/// `s` shortened to `max` cells by cutting its middle.
pub fn elide_middle(s: &str, max: usize) -> String {
    let plain = term::strip_escapes_str(s);
    if term::text_width(&plain) <= max {
        return s.to_string();
    }
    if max < 2 {
        return term::fit(&plain, max);
    }
    let keep = max - 1;
    let head = keep / 2;
    let tail = keep - head;
    let mut back = String::new();
    let mut used = 0;
    for c in plain.chars().rev() {
        let w = term::cell_width(c);
        if used + w > tail {
            break;
        }
        back.insert(0, c);
        used += w;
    }
    format!("{}…{}", term::fit(&plain, head), back)
}

/// `prefix: middle` in `width` cells, eliding the middle first and dropping
/// it when fewer than ten cells remain for it.
fn join_fitted(prefix: &str, middle: &str, width: usize) -> String {
    let room = width.saturating_sub(term::text_width(prefix) + 2);
    if middle.is_empty() || room < 10 {
        return term::fit(prefix, width);
    }
    term::fit(
        &format!("{}: {}", prefix, elide_middle(middle, room)),
        width,
    )
}

/// Where the screen stands between blocks, which decides the blank lines:
/// none between the title and the first section, one before every other
/// section and before the summary, one after the summary when anything
/// follows it, and one closing the lines that followed a summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gap {
    None,
    AfterTitle,
    AfterSummary,
    AfterSummaryLines,
}

pub struct BuildView<S: Screen = Terminal> {
    opts: Options,
    screen: S,
    gap: Gap,
    title_shown: bool,
    eval_section: bool,
    /// Evaluation is under way: job events are evaluation items and belong
    /// to its section, not to Realizing Derivations.
    evaluating: bool,
    /// Latest report of the evaluation phase in progress.
    eval: Option<ResolveReport>,
    realize_section: bool,
    /// A step in progress that has no counter of its own (backend
    /// preparation); shown until the next build event.
    stage: Option<String>,
    running: Vec<Running>,
    /// buildutil's newest counter from a start or finish event.
    counter: (usize, usize),
    partial: [Vec<u8>; 2],
    /// Readable forms of configured-node keys, from `configured` events.
    labels: std::collections::BTreeMap<String, String>,
}

impl BuildView<Terminal> {
    pub fn new(opts: Options) -> BuildView<Terminal> {
        BuildView::with_screen(opts, Terminal)
    }
}

impl<S: Screen> BuildView<S> {
    pub fn with_screen(opts: Options, screen: S) -> BuildView<S> {
        BuildView {
            opts,
            screen,
            gap: Gap::None,
            title_shown: false,
            eval_section: false,
            evaluating: false,
            eval: None,
            realize_section: false,
            stage: None,
            running: Vec::new(),
            counter: (0, 0),
            partial: [Vec::new(), Vec::new()],
            labels: std::collections::BTreeMap::new(),
        }
    }

    fn style(&self, role: Role, text: &str) -> String {
        term::style(role, text, self.opts.color)
    }

    /// The title that opens a build screen; printed once.
    pub fn open(&mut self) {
        if !self.title_shown {
            self.title_shown = true;
            let title = self.style(
                Role::Heading,
                &format!("The Buildutil Build System v{}", VERSION),
            );
            self.note(&title);
            self.gap = Gap::AfterTitle;
        }
    }

    /// A durable line.
    pub fn note(&mut self, text: &str) {
        match self.gap {
            Gap::AfterSummary => {
                self.screen.line("");
                self.gap = Gap::AfterSummaryLines;
            }
            Gap::AfterTitle => self.gap = Gap::None,
            Gap::None | Gap::AfterSummaryLines => {}
        }
        self.screen.line(text);
    }

    /// A blank line that opens a block, unless one already stands there.
    fn block_break(&mut self) {
        match self.gap {
            Gap::AfterTitle => {}
            Gap::None | Gap::AfterSummary | Gap::AfterSummaryLines => self.screen.line(""),
        }
        self.gap = Gap::None;
    }

    /// A tool's line, as written; without color its escape sequences go.
    /// Only color survives: a tool may color a line but never move the
    /// cursor or clear what is already on screen.
    fn tool_line(&mut self, text: &str) {
        if self.opts.color {
            let text = term::sgr_only(text);
            if text.contains('\x1b') {
                self.note(&format!("{}\x1b[0m", text));
            } else {
                self.note(&text);
            }
        } else {
            self.note(&term::strip_escapes_str(text));
        }
    }

    /// Take buildutil's counter from a start or finish event. Starts are
    /// reported outside the scheduler lock, so an older count may arrive
    /// after a newer one; within one build the counter only moves forward.
    fn advance(&mut self, now: (usize, usize)) {
        if now.1 != self.counter.1 || now.0 > self.counter.0 {
            self.counter = now;
        }
    }

    fn section(&mut self, name: &str) {
        self.block_break();
        let heading = self.style(Role::Heading, &format!("-- {} --", name));
        self.note(&heading);
    }

    /// The command ended because the person interrupted it; said once, by
    /// the client that owns the terminal, as ninja and Nix do.
    pub fn interrupted(&mut self) {
        self.tagged("error", "interrupted by the user");
    }

    /// A log message with its level tag.
    pub fn tagged(&mut self, level: &str, msg: &str) {
        match level_tag(level) {
            Some((tag, role)) => {
                let tag = self.style(role, tag);
                self.note(&format!("{} {}", tag, term::capitalized(msg)));
            }
            None => self.note(msg),
        }
    }

    /// One line of an engine's stdout: a build event, or else one of the
    /// engine's results, which stays on stdout.
    pub fn event(&mut self, line: &str) {
        match events::parse_stream_event(line) {
            Some(event) => self.apply(event),
            None => self.screen.result(line),
        }
        self.refresh();
    }

    /// Bytes an engine wrote to its stdout or stderr outside the event
    /// stream. Complete lines are shown; a carriage return without a line
    /// feed restarts the line, as a terminal would overwrite it.
    pub fn raw(&mut self, stream: Stream, bytes: &[u8]) {
        let idx = stream as usize;
        let mut buf = std::mem::take(&mut self.partial[idx]);
        let mut lines = Vec::new();
        for &b in bytes {
            // A carriage return followed by anything but a line feed, even
            // in the next chunk, means the line is being overwritten.
            if buf.last() == Some(&b'\r') && b != b'\n' {
                buf.clear();
            }
            if b == b'\n' {
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                lines.push(String::from_utf8_lossy(&buf).into_owned());
                buf.clear();
            } else {
                buf.push(b);
            }
        }
        self.partial[idx] = buf;
        for line in lines {
            match stream {
                Stream::Stdout => self.screen.result(&line),
                Stream::Stderr => self.tool_line(&line),
            }
        }
        self.refresh();
    }

    /// Periodic work while events are quiet: redraw the status row.
    pub fn tick(&mut self) {
        self.refresh();
    }

    /// The stream ended: print everything still held and take the status
    /// row down.
    pub fn finish(&mut self) {
        for stream in [Stream::Stdout, Stream::Stderr] {
            let rest = std::mem::take(&mut self.partial[stream as usize]);
            if !rest.is_empty() {
                let line = String::from_utf8_lossy(&rest).into_owned();
                match stream {
                    Stream::Stdout => self.screen.result(&line),
                    Stream::Stderr => self.tool_line(&line),
                }
            }
        }
        self.interrupt_eval();
        if self.gap == Gap::AfterSummaryLines {
            self.screen.line("");
            self.gap = Gap::None;
        }
        self.screen.status("");
    }

    fn apply(&mut self, event: StreamEvent) {
        if !matches!(
            event,
            StreamEvent::Progress { .. } | StreamEvent::Configured { .. }
        ) {
            self.stage = None;
        }
        match event {
            StreamEvent::Header(report) => self.header(&report),
            StreamEvent::Resolve(report) => self.resolve(report),
            StreamEvent::Start {
                drv,
                action,
                current,
                total,
            } => self.start(&drv, &action, current, total),
            StreamEvent::Finish {
                drv,
                hash,
                outcome,
                current,
                total,
                msg,
                log,
            } => self.finish_job(&drv, &hash, &outcome, (current, total), msg, log),
            StreamEvent::Step { drv, action } => {
                if let Some(r) = self.running.iter_mut().find(|r| r.drv == drv) {
                    r.action = action;
                }
            }
            StreamEvent::Item { drv, counter, text } => self.item(&drv, counter, text),
            StreamEvent::Output { drv, line } => self.output(&drv, line),
            StreamEvent::Error { msg } => self.tagged("error", &msg),
            StreamEvent::Log { level, msg } => {
                if level == "debug" && !self.opts.verbose {
                    return;
                }
                self.tagged(&level, &msg);
            }
            StreamEvent::Timings(timings) => self.timings_table(&timings),
            StreamEvent::Progress { label } => self.stage = Some(label),
            StreamEvent::Summary(report) => self.summary(&report),
            StreamEvent::Configured { drv, label } => {
                self.labels.insert(drv, label);
            }
        }
    }

    // ----- evaluation --------------------------------------------------

    fn resolve(&mut self, mut report: ResolveReport) {
        if !self.eval_section {
            self.open();
            self.eval_section = true;
            self.section("Dependency Evaluation");
            if !self.opts.targets.is_empty() {
                let targets = self.opts.targets.join(", ");
                self.note(&format!("  evaluating target(s)       : {}", targets));
                self.note("");
            }
        }
        // The phase report only tracks where evaluation stands. Its items
        // (sources, derivations) arrive as job events and are drawn exactly
        // like a build's derivations; the `Evaluated` line closes the phase.
        if report.phase == EvalPhase::Evaluated {
            self.eval = None;
            self.evaluating = false;
            self.running.clear();
            self.counter = (0, 0);
            self.evaluated_line(&report);
        } else {
            let same_phase = self.eval.as_ref().is_some_and(|previous| {
                previous.phase == report.phase && previous.total == report.total
            });
            if same_phase {
                if let Some(previous) = &self.eval {
                    report.current = report.current.max(previous.current);
                }
            } else {
                self.counter = (0, report.total);
            }
            self.advance((report.current, report.total));
            self.evaluating = true;
            self.eval = Some(report);
        }
    }

    /// The durable line of an evaluation phase: its completion, or where it
    /// stood when something interrupted it.
    fn phase_line(&mut self, report: &ResolveReport) {
        let done = report.current >= report.total;
        // Like `Compiling` and `Compiled`: a phase cut off while running
        // keeps the in-progress color, a finished one the result color.
        let role = if done { Role::Built } else { Role::Active };
        let label = self.style(role, phase_label(report.phase, done));
        let text = if done {
            format!("{} {}", counter(report.total, report.total), label)
        } else if report.detail.is_empty() {
            format!("{} {}", counter(report.current, report.total), label)
        } else {
            format!(
                "{} {}: {}",
                counter(report.current, report.total),
                label,
                report.detail
            )
        };
        self.note(&text);
    }

    /// Evaluation stopped before its `Evaluated` report (the stream ended,
    /// or a header or build arrived): leave where it stood, and drop the
    /// items that will never finish.
    fn interrupt_eval(&mut self) {
        if let Some(report) = self.eval.take() {
            self.phase_line(&report);
        }
        if self.evaluating {
            self.evaluating = false;
            self.running.clear();
        }
    }

    /// Printed as soon as evaluation ends: a backend may take minutes
    /// before the header arrives. The phase breakdown is in the timings
    /// table (`--timings`, `-v`).
    fn evaluated_line(&mut self, report: &ResolveReport) {
        let label = self.style(Role::Built, "Evaluated");
        let mut text = format!(
            "{} {} in {}",
            counter(report.current, report.total),
            label,
            events::fmt_ms(report.elapsed_ms)
        );
        if let Some(n) = report.cache_candidates {
            text.push_str(&format!("; cache candidates {}", n));
        }
        self.note(&text);
    }

    fn header(&mut self, report: &HeaderReport) {
        self.open();
        self.interrupt_eval();
        self.section("Build Environment");
        let rows = [
            ("source dir", report.source_dir.clone()),
            ("target system", report.target_system.clone()),
            ("build host", report.build_host.clone()),
            ("backend", report.backend.clone()),
            ("git rev", report.git_rev.clone()),
            ("config hash", report.config_hash.clone()),
        ];
        for (label, value) in rows {
            self.note(&format!("  {:<13} : {}", label, value));
        }
        for input in &report.inputs {
            self.note(&format!("  input         : {input}"));
        }
        for tool in &report.tools {
            self.note(&format!(
                "  {:<13} : {} [{}]",
                tool.name, tool.version, tool.locator
            ));
        }
        self.note(&format!("  {:<13} : {}", "profile", report.profile));
        if self.opts.verbose {
            self.section("Configuration Options");
            for (key, value) in &report.config {
                let shown = match value.as_str() {
                    "true" => self.style(Role::True, value),
                    "false" => self.style(Role::False, value),
                    "auto" => self.style(Role::Auto, value),
                    _ => value.clone(),
                };
                self.note(&format!("  {:<26} : {}", key, shown));
            }
        }
        if self.opts.timings {
            if let Some(t) = &report.timings {
                self.timings_table(t);
            }
        }
    }

    fn timings_table(&mut self, t: &EvalTimings) {
        let fmt = events::fmt_ms;
        self.section("Evaluation Timings");
        let mut rows = vec![
            ("context", fmt(t.context_ms)),
            ("stat cache load", fmt(t.statcache_load_ms)),
        ];
        if t.git_identity_ms > 0 {
            rows.push(("git identity probe", fmt(t.git_identity_ms)));
        }
        rows.push(("eval", fmt(t.eval_ms)));
        if t.closure_ms + t.probe_wall_ms + t.source_ms + t.instantiate_ms > 0 {
            rows.push(("  closure", fmt(t.closure_ms)));
            rows.push(("  git probe wall", fmt(t.probe_wall_ms)));
            rows.push(("    worker sum", fmt(t.probe_ms)));
            rows.push(("  source hash", fmt(t.source_ms)));
            rows.push(("  instantiate", fmt(t.instantiate_ms)));
        }
        rows.push(("cache scan", fmt(t.cache_scan_ms)));
        rows.push(("plan emit", fmt(t.emit_ms)));
        rows.push(("cas verify", fmt(t.verify_ms)));
        rows.push(("total", fmt(t.total_ms)));
        rows.push(("eval cache", t.evalcache.as_str().to_string()));
        if t.statcache_hits + t.statcache_misses > 0 {
            rows.push((
                "stat cache",
                format!("{} hit / {} miss", t.statcache_hits, t.statcache_misses),
            ));
        }
        for (label, value) in rows {
            self.note(&format!("  {:<20} : {}", label, value));
        }
    }

    /// How a derivation is named on screen: a configured node by its
    /// readable form with its key's hash dimmed, any other by its key.
    fn display(&self, drv: &str) -> String {
        match (self.labels.get(drv), drv.split_once('@')) {
            (Some(label), Some((_, hash))) => {
                format!("{label}{}", self.style(Role::Detail, &format!("@{hash}")))
            }
            _ => drv.to_string(),
        }
    }

    // ----- realization -------------------------------------------------

    fn realize_section(&mut self) {
        if !self.realize_section {
            self.realize_section = true;
            self.interrupt_eval();
            self.section("Realizing Derivations");
        }
    }

    fn start(&mut self, drv: &str, action: &str, current: usize, total: usize) {
        if !self.evaluating {
            self.realize_section();
            if current == 0 && self.counter.1 > 0 && self.counter.0 >= self.counter.1 {
                self.counter = (0, total);
            }
        }
        self.advance((current, total));
        if !self.running.iter().any(|r| r.drv == drv) {
            self.running.push(Running {
                drv: drv.to_string(),
                action: action.to_string(),
                promoted: false,
                inner: None,
                item: None,
                tail: VecDeque::new(),
            });
        }
    }

    /// Make the derivation's action line durable, once, with buildutil's
    /// counter as it stands now so scrollback counters never go back.
    fn promote(&mut self, i: usize) {
        if self.running[i].promoted {
            return;
        }
        self.running[i].promoted = true;
        let action = self.style(Role::Active, &self.running[i].action);
        let text = format!(
            "{} {} {}",
            counter(self.counter.0, self.counter.1),
            action,
            self.display(&self.running[i].drv)
        );
        self.note(&text);
    }

    fn item(&mut self, drv: &str, own: Option<(usize, usize)>, text: String) {
        let Some(i) = self.running.iter().position(|r| r.drv == drv) else {
            return;
        };
        self.promote(i);
        let fallback = self.counter;
        let r = &mut self.running[i];
        if own.is_some() {
            r.inner = own;
        }
        // An item without a counter of its own (a cargo artifact) shows the
        // derivation's newest counter, else buildutil's.
        let shown = own.or(r.inner).unwrap_or(fallback);
        let line = self
            .opts
            .verbose
            .then(|| format!("{} {}", counter(shown.0, shown.1), text));
        r.item = Some((shown, text, Instant::now()));
        if let Some(line) = line {
            self.tool_line(&line);
        }
    }

    fn output(&mut self, drv: &str, line: String) {
        let shown = self.opts.verbose || self.opts.output == OutputMode::All;
        let Some(i) = self.running.iter().position(|r| r.drv == drv) else {
            if shown {
                self.tool_line(&line);
            }
            return;
        };
        let tail = &mut self.running[i].tail;
        if tail.len() == TAIL_LINES {
            tail.pop_front();
        }
        tail.push_back(line.clone());
        if shown {
            self.promote(i);
            self.tool_line(&line);
        }
    }

    /// Where a person finds a retained log; without a known state root the
    /// state-relative path is all there is to show.
    fn log_location(&self, log: &str) -> String {
        match &self.opts.state_root {
            Some(root) => log_location(root, log),
            None => log.to_string(),
        }
    }

    fn finish_job(
        &mut self,
        drv: &str,
        hash: &str,
        outcome: &str,
        now: (usize, usize),
        msg: Option<String>,
        log: Option<String>,
    ) {
        if !self.evaluating {
            self.realize_section();
        }
        self.advance(now);
        let mut verb = outcome.to_string();
        if let Some(i) = self.running.iter().position(|r| r.drv == drv) {
            let r = self.running.remove(i);
            if outcome == "Realized" {
                verb = completed(&r.action).to_string();
            }
            let tail_wanted =
                outcome == "Failed" && self.opts.output == OutputMode::Failed && !self.opts.verbose;
            if tail_wanted {
                for line in &r.tail {
                    self.tool_line(line);
                }
            }
        }
        let verb = self.style(outcome_role(outcome), &verb);
        let mut text = format!(
            "{} {} {}",
            counter(self.counter.0, self.counter.1),
            verb,
            self.display(drv)
        );
        if !hash.is_empty() {
            text.push_str(&format!(" ({})", self.style(Role::Detail, hash)));
        }
        // A builder's passing verdict, shown with the completion it decided;
        // the engine does not read what it says.
        if outcome != "Failed" {
            if let Some(verdict) = msg.as_deref().filter(|m| !m.is_empty()) {
                text.push_str(&format!(": {verdict}"));
            }
        }
        self.note(&text);
        if outcome == "Failed" {
            let reason = msg.unwrap_or_else(|| "failed".to_string());
            // The reason leads, so the message starts as prose whatever
            // the derivation is called.
            let text = match log {
                Some(log) => {
                    let location = self.style(Role::Detail, &self.log_location(&log));
                    format!("{} in {}; log: {}", reason, self.display(drv), location)
                }
                None => format!("{} in {}", reason, self.display(drv)),
            };
            self.tagged("error", &text);
        }
    }

    fn summary(&mut self, report: &SummaryReport) {
        self.running.clear();
        self.screen.status("");
        // A later build in the same stream opens its own sections and
        // counts from zero.
        self.eval_section = false;
        self.realize_section = false;
        self.counter = (0, 0);
        self.block_break();
        let failed = if report.failed == 0 {
            "0".to_string()
        } else {
            self.style(Role::Failed, &report.failed.to_string())
        };
        let built = self.style(Role::Built, &report.built.to_string());
        let cached = self.style(Role::Cached, &report.cached.to_string());
        self.note(&format!(
            "{} realized, {} cached, {} failed of {} total",
            built, cached, failed, report.total
        ));
        self.note(&format!(
            "  {:<20} : {}",
            "realize wall",
            events::fmt_ms(report.realize_ms)
        ));
        let reused = report.built + report.cached;
        if reused > 0 {
            let hit = report.cached as f64 / reused as f64 * 100.0;
            self.note(&format!(
                "  {:<20} : {:.0}% ({}/{} reused)",
                "cache hit", hit, report.cached, reused
            ));
        }
        for name in &report.failures {
            let label = self.style(Role::Failed, "failed");
            let name = self.style(Role::Heading, name);
            self.note(&format!("  -> {}: {}", label, name));
        }
        if let (Some(secs), Some(tip)) = (&report.critical_path_secs, &report.critical_path_tip) {
            self.note(&format!(
                "  critical path: {} through {} ({} nodes)",
                secs, tip, report.critical_path_nodes
            ));
        }
        self.gap = Gap::AfterSummary;
    }

    // ----- status row ---------------------------------------------------

    /// The status row text for `width` cells, or empty for none.
    fn status_text(&self, width: usize) -> String {
        if self.running.is_empty() {
            if let Some(r) = &self.eval {
                if r.phase == EvalPhase::ResolvingSources {
                    return String::new();
                }
                let prefix = format!(
                    "{} {}",
                    counter(r.current, r.total),
                    self.style(Role::Active, phase_label(r.phase, false))
                );
                return join_fitted(&prefix, &r.detail, width);
            }
        }
        // The bottom row follows the newest item of any running derivation,
        // or else the first-started derivation's own step.
        let focus = self
            .running
            .iter()
            .filter(|r| r.item.is_some())
            .max_by_key(|r| r.item.as_ref().map(|(_, _, at)| *at))
            .or(self.running.first());
        let Some(focus) = focus else {
            return match &self.stage {
                Some(label) => term::fit(&format!("{}…", label), width),
                None => String::new(),
            };
        };
        match &focus.item {
            Some(((done, total), text, _)) => {
                // A tool's escapes and control characters would give the row
                // an unknown width, so its text is plain; buildutil's own words
                // take their role colors, as on durable lines.
                let text = term::single_row(&term::strip_escapes_str(text));
                let prefix = counter(*done, *total);
                let room = width.saturating_sub(term::text_width(&prefix) + 1);
                term::fit(&format!("{} {}", prefix, elide_middle(&text, room)), width)
            }
            None => term::fit(
                &format!(
                    "{} {} {}",
                    counter(self.counter.0, self.counter.1),
                    self.style(Role::Active, &focus.action),
                    self.display(&focus.drv)
                ),
                width,
            ),
        }
    }

    fn refresh(&mut self) {
        if self.opts.interactive {
            let text = self.status_text(self.screen.width().saturating_sub(1));
            self.screen.status(&text);
        }
    }
}

/// A retained log `log` (relative to `state_root`) as a person should see
/// it: relative to the working directory when inside it, else absolute.
pub fn log_location(state_root: &Path, log: &str) -> String {
    term::display_path(&state_root.join(log))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A screen that records what a view drew.
    #[derive(Default)]
    struct Recorder {
        lines: Vec<String>,
        results: Vec<String>,
        status: String,
    }

    impl Screen for Recorder {
        fn line(&mut self, text: &str) {
            self.lines.push(text.to_string());
        }
        fn result(&mut self, text: &str) {
            self.results.push(text.to_string());
        }
        fn status(&mut self, text: &str) {
            self.status = text.to_string();
        }
        fn width(&self) -> usize {
            81
        }
    }

    fn view(interactive: bool) -> BuildView<Recorder> {
        BuildView::with_screen(
            Options {
                interactive,
                ..Options::default()
            },
            Recorder::default(),
        )
    }

    fn feed(v: &mut BuildView<Recorder>, events: &[String]) {
        for e in events {
            v.event(e);
        }
    }

    fn start(drv: &str, current: usize, total: usize) -> String {
        format!(
            r#"{{"ev":"start","drv":"{drv}","hash":"","action":"Staging","current":{current},"total":{total}}}"#
        )
    }

    fn job(drv: &str, action: &str, current: usize, total: usize) -> String {
        format!(
            r#"{{"ev":"start","drv":"{drv}","hash":"","action":"{action}","current":{current},"total":{total}}}"#
        )
    }

    fn resolve_event(phase: EvalPhase, current: usize, total: usize, detail: &str) -> String {
        events::resolve_json(&ResolveReport {
            current,
            total,
            phase,
            detail: detail.into(),
            elapsed_ms: 0,
            cache_candidates: None,
            cutoff_candidates: None,
        })
    }

    fn done(drv: &str, outcome: &str, current: usize, total: usize, hash: &str) -> String {
        format!(
            r#"{{"ev":"finish","drv":"{drv}","hash":"{hash}","outcome":"{outcome}","current":{current},"total":{total},"msg":null}}"#
        )
    }

    fn step(drv: &str) -> String {
        format!(r#"{{"ev":"step","drv":"{drv}","action":"Compiling"}}"#)
    }

    fn item(drv: &str, counter: Option<(usize, usize)>, text: &str) -> String {
        let (d, t) = counter.map_or(("null".to_string(), "null".to_string()), |(d, t)| {
            (d.to_string(), t.to_string())
        });
        format!(r#"{{"ev":"item","drv":"{drv}","done":{d},"total":{t},"text":"{text}"}}"#)
    }

    fn output(drv: &str, line: &str) -> String {
        format!(r#"{{"ev":"output","drv":"{drv}","line":"{line}","stream":"stderr"}}"#)
    }

    fn finish(drv: &str, outcome: &str, current: usize, total: usize) -> String {
        format!(
            r#"{{"ev":"finish","drv":"{drv}","hash":"abc","outcome":"{outcome}","current":{current},"total":{total},"msg":null}}"#
        )
    }

    fn realize_lines(v: &BuildView<Recorder>) -> Vec<&str> {
        let at = v
            .screen
            .lines
            .iter()
            .position(|l| l == "-- Realizing Derivations --")
            .map_or(0, |i| i + 1);
        v.screen.lines[at..].iter().map(String::as_str).collect()
    }

    #[test]
    fn counters_align_to_the_total() {
        assert_eq!(counter(1, 4574), "[   1/4574]");
        assert_eq!(counter(640, 640), "[640/640]");
    }

    #[test]
    fn the_bottom_row_shows_the_step_then_only_items() {
        let mut v = view(true);
        feed(&mut v, &[start("host-rust", 16, 24)]);
        assert_eq!(v.screen.status, "[16/24] Staging host-rust");
        feed(&mut v, &[step("host-rust")]);
        assert_eq!(v.screen.status, "[16/24] Compiling host-rust");
        assert_eq!(realize_lines(&v), Vec::<&str>::new());
        feed(
            &mut v,
            &[item("host-rust", Some((1, 3)), "python3 x.py install")],
        );
        assert_eq!(realize_lines(&v), ["[16/24] Compiling host-rust"]);
        assert_eq!(v.screen.status, "[1/3] python3 x.py install");
        feed(&mut v, &[item("host-rust", None, "Compiled rustc_middle")]);
        assert_eq!(v.screen.status, "[1/3] Compiled rustc_middle");
    }

    #[test]
    fn terminal_and_pipe_print_the_same_durable_lines() {
        let events = [
            start("quiet", 3, 9),
            step("quiet"),
            start("busy", 3, 9),
            step("busy"),
            item("busy", Some((1, 2)), "CC a.o"),
            output("busy", "a.c:1:2: warning: x"),
            finish("quiet", "Realized", 4, 9),
            finish("busy", "Realized", 5, 9),
        ];
        let mut terminal = view(true);
        let mut pipe = view(false);
        feed(&mut terminal, &events);
        feed(&mut pipe, &events);
        assert_eq!(terminal.screen.lines, pipe.screen.lines);
        assert_eq!(
            realize_lines(&pipe),
            [
                "[3/9] Compiling busy",
                "a.c:1:2: warning: x",
                "[4/9] Compiled quiet (abc)",
                "[5/9] Compiled busy (abc)",
            ]
        );
        assert_eq!(pipe.screen.status, "");
    }

    #[test]
    fn a_late_action_line_uses_the_counter_of_its_moment() {
        let mut v = view(false);
        feed(
            &mut v,
            &[
                start("slow", 22, 24),
                step("slow"),
                start("fast", 22, 24),
                finish("fast", "Cached", 23, 24),
                output("slow", "FAILED: out"),
            ],
        );
        assert_eq!(
            realize_lines(&v),
            [
                "[23/24] Cached fast (abc)",
                "[23/24] Compiling slow",
                "FAILED: out"
            ]
        );
    }

    #[test]
    fn a_stale_start_counter_never_moves_scrollback_back() {
        let mut v = view(false);
        feed(
            &mut v,
            &[
                start("a", 0, 2),
                finish("a", "Cached", 1, 2),
                // Counted before `a` finished, reported after it.
                start("b", 0, 2),
                step("b"),
                output("b", "note"),
            ],
        );
        assert_eq!(
            realize_lines(&v),
            ["[1/2] Cached a (abc)", "[1/2] Compiling b", "note"]
        );
    }

    #[test]
    fn running_steps_show_the_latest_completed_count() {
        let mut v = view(true);
        feed(
            &mut v,
            &[
                start("slow", 0, 2),
                start("fast", 0, 2),
                finish("fast", "Cached", 1, 2),
            ],
        );
        assert_eq!(v.screen.status, "[1/2] Staging slow");
        feed(&mut v, &[step("slow")]);
        assert_eq!(v.screen.status, "[1/2] Compiling slow");
        feed(&mut v, &[finish("slow", "Realized", 2, 2)]);
        feed(&mut v, &[start("next", 0, 2)]);
        assert_eq!(v.screen.status, "[0/2] Staging next");
    }

    #[test]
    fn resolving_sources_uses_a_monotonic_count_without_a_phase_status() {
        let mut v = view(true);
        feed(
            &mut v,
            &[resolve_event(EvalPhase::ResolvingSources, 0, 2, "a")],
        );
        assert_eq!(v.screen.status, "");
        feed(
            &mut v,
            &[
                job("a", "Resolving", 0, 2),
                resolve_event(EvalPhase::ResolvingSources, 0, 2, "b"),
                job("b", "Resolving", 0, 2),
                resolve_event(EvalPhase::ResolvingSources, 2, 2, "b"),
                done("b", "Resolved", 2, 2, "hb"),
            ],
        );
        assert_eq!(v.screen.status, "[2/2] Resolving a");
        feed(
            &mut v,
            &[
                resolve_event(EvalPhase::ResolvingSources, 1, 2, "a"),
                done("a", "Resolved", 1, 2, "ha"),
            ],
        );
        assert_eq!(v.eval.as_ref().map(|report| report.current), Some(2));
        assert_eq!(v.screen.status, "");
        assert_eq!(
            v.screen
                .lines
                .iter()
                .rev()
                .take(2)
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["[2/2] Resolved a (ha)", "[2/2] Resolved b (hb)"]
        );
        feed(
            &mut v,
            &[
                resolve_event(EvalPhase::Instantiating, 0, 2, "x"),
                job("x", "Evaluating", 0, 2),
            ],
        );
        assert_eq!(v.screen.status, "[0/2] Evaluating x");
    }

    #[test]
    fn blank_lines_separate_blocks() {
        let mut v = BuildView::with_screen(
            Options {
                targets: vec!["build".into()],
                ..Options::default()
            },
            Recorder::default(),
        );
        let report = |phase, current, total| ResolveReport {
            current,
            total,
            phase,
            detail: String::new(),
            elapsed_ms: 10,
            cache_candidates: Some(3),
            cutoff_candidates: None,
        };
        v.resolve(report(EvalPhase::ResolvingSources, 0, 1));
        feed(
            &mut v,
            &[
                job("src", "Resolving", 0, 1),
                done("src", "Resolved", 1, 1, "h1"),
            ],
        );
        v.resolve(report(EvalPhase::Evaluated, 2, 2));
        feed(&mut v, &[start("a", 0, 1), finish("a", "Cached", 1, 1)]);
        v.summary(&SummaryReport {
            built: 0,
            cached: 1,
            failed: 0,
            total: 1,
            realize_ms: 5,
            failures: Vec::new(),
            critical_path_secs: None,
            critical_path_tip: None,
            critical_path_nodes: 0,
        });
        v.tagged("success", "built");
        v.finish();
        assert_eq!(
            v.screen.lines,
            [
                "The Buildutil Build System v0.0.1",
                "-- Dependency Evaluation --",
                "  evaluating target(s)       : build",
                "",
                "[1/1] Resolved src (h1)",
                "[2/2] Evaluated in 10ms; cache candidates 3",
                "",
                "-- Realizing Derivations --",
                "[1/1] Cached a (abc)",
                "",
                "0 realized, 1 cached, 0 failed of 1 total",
                "  realize wall         : 5ms",
                "  cache hit            : 100% (1/1 reused)",
                "",
                "[SUCCESS] Built",
                "",
            ]
        );
    }

    #[test]
    fn a_build_ending_in_its_summary_adds_no_trailing_blank() {
        let mut v = view(false);
        feed(&mut v, &[start("a", 0, 1), finish("a", "Cached", 1, 1)]);
        v.summary(&SummaryReport {
            built: 0,
            cached: 1,
            failed: 0,
            total: 1,
            realize_ms: 5,
            failures: Vec::new(),
            critical_path_secs: None,
            critical_path_tip: None,
            critical_path_nodes: 0,
        });
        v.finish();
        assert_eq!(
            v.screen.lines.last().map(String::as_str),
            Some("  cache hit            : 100% (1/1 reused)")
        );
    }

    #[test]
    fn a_finished_count_lets_the_next_build_start_over() {
        let mut v = view(false);
        let round = [
            start("x", 0, 1),
            step("x"),
            output("x", "rebuilt"),
            finish("x", "Realized", 1, 1),
        ];
        feed(&mut v, &round);
        feed(&mut v, &round);
        assert_eq!(
            realize_lines(&v),
            [
                "[0/1] Compiling x",
                "rebuilt",
                "[1/1] Compiled x (abc)",
                "[0/1] Compiling x",
                "rebuilt",
                "[1/1] Compiled x (abc)",
            ]
        );
    }

    #[test]
    fn tool_output_may_color_but_not_move_the_cursor() {
        let mut v = BuildView::with_screen(
            Options {
                color: true,
                ..Options::default()
            },
            Recorder::default(),
        );
        let line = r"\u001b[2J\u001b[1;31mred\u001b[0m\u001b[3A";
        feed(&mut v, &[start("d", 0, 1), output("d", line)]);
        assert_eq!(
            v.screen.lines.last().map(String::as_str),
            Some("\u{1b}[1;31mred\u{1b}[0m\u{1b}[0m")
        );
    }

    #[test]
    fn the_bottom_row_colors_steps_like_durable_lines() {
        let mut v = BuildView::with_screen(
            Options {
                interactive: true,
                color: true,
                ..Options::default()
            },
            Recorder::default(),
        );
        feed(&mut v, &[start("x", 0, 1), step("x")]);
        assert_eq!(
            v.screen.status,
            "[0/1] \u{1b}[1;33mCompiling\u{1b}[0m x\u{1b}[0m"
        );
        assert_eq!(
            term::text_width(&v.screen.status),
            "[0/1] Compiling x".len()
        );
    }

    #[test]
    fn the_newest_item_of_any_derivation_takes_the_bottom_row() {
        let mut v = view(true);
        feed(&mut v, &[start("a", 0, 2), start("b", 0, 2)]);
        feed(&mut v, &[item("a", Some((1, 9)), "CC one.o")]);
        std::thread::sleep(Duration::from_millis(2));
        feed(&mut v, &[item("b", Some((5, 7)), "CC two.o")]);
        assert_eq!(v.screen.status, "[5/7] CC two.o");
    }

    #[test]
    fn the_bottom_row_never_exceeds_the_width() {
        let mut v = view(true);
        feed(
            &mut v,
            &[
                start("host-llvm", 0, 1),
                item(
                    "host-llvm",
                    Some((1, 9)),
                    "Building CXX object tools/clang/lib/Frontend/CMakeFiles/obj.clangFrontend.dir/SerializedDiagnosticPrinter.cpp.o",
                ),
            ],
        );
        for width in [20, 40, 60, 79] {
            let text = v.status_text(width);
            assert!(term::text_width(&text) <= width, "{} > {}", text, width);
        }
        assert!(v.status_text(60).contains('…'));
    }

    #[test]
    fn output_modes_select_what_is_printed() {
        let events = [
            start("big", 0, 1),
            output("big", "line 1"),
            output("big", "line 2"),
            format!(
                r#"{{"ev":"finish","drv":"big","hash":"abc","outcome":"Failed","current":1,"total":1,"msg":"builder failed (exit status: 1)","log":"logs/big.log"}}"#
            ),
        ];
        let mut failed_only = BuildView::with_screen(
            Options {
                output: OutputMode::Failed,
                state_root: Some(PathBuf::from("/state")),
                ..Options::default()
            },
            Recorder::default(),
        );
        feed(&mut failed_only, &events);
        assert_eq!(
            realize_lines(&failed_only),
            [
                "line 1",
                "line 2",
                "[1/1] Failed big (abc)",
                format!(
                    "[ERROR] Builder failed (exit status: 1) in big; log: {}",
                    Path::new("/state").join("logs/big.log").display()
                )
                .as_str(),
            ]
        );
        let mut none = BuildView::with_screen(
            Options {
                output: OutputMode::None,
                ..Options::default()
            },
            Recorder::default(),
        );
        feed(&mut none, &events);
        assert_eq!(
            realize_lines(&none),
            [
                "[1/1] Failed big (abc)",
                "[ERROR] Builder failed (exit status: 1) in big; log: logs/big.log",
            ]
        );
    }

    #[test]
    fn failed_mode_keeps_only_a_bounded_tail() {
        let mut v = BuildView::with_screen(
            Options {
                output: OutputMode::Failed,
                ..Options::default()
            },
            Recorder::default(),
        );
        feed(&mut v, &[start("big", 0, 1)]);
        for n in 0..100 {
            feed(&mut v, &[output("big", &format!("line {}", n))]);
        }
        let r = &v.running[0];
        assert_eq!(r.tail.len(), TAIL_LINES);
        assert_eq!(r.tail.front().map(String::as_str), Some("line 75"));
    }

    #[test]
    fn tool_escapes_pass_with_color_and_go_without() {
        let colored = "\u{1b}[1;33mwarning\u{1b}[0m: x";
        let event = output("d", &colored.replace('\u{1b}', "\\u001b"));
        let mut plain = view(false);
        feed(&mut plain, &[start("d", 0, 1), event.clone()]);
        assert_eq!(
            plain.screen.lines.last().map(String::as_str),
            Some("warning: x")
        );
        let mut color = BuildView::with_screen(
            Options {
                color: true,
                ..Options::default()
            },
            Recorder::default(),
        );
        feed(&mut color, &[start("d", 0, 1), event]);
        assert_eq!(
            color.screen.lines.last().map(String::as_str),
            Some("\u{1b}[1;33mwarning\u{1b}[0m: x\u{1b}[0m")
        );
    }

    #[test]
    fn completion_names_the_finished_step() {
        assert_eq!(completed("Compiling"), "Compiled");
        assert_eq!(completed("Fetching"), "Fetched");
        assert_eq!(completed("Staging"), "Realized");
    }

    #[test]
    fn an_interrupted_evaluation_leaves_where_it_stood() {
        let mut v = view(false);
        v.resolve(ResolveReport {
            current: 5,
            total: 9,
            phase: EvalPhase::ResolvingSources,
            detail: "kernite/src".into(),
            elapsed_ms: 10,
            cache_candidates: None,
            cutoff_candidates: None,
        });
        feed(&mut v, &[job("kernite/src", "Resolving", 5, 9)]);
        v.finish();
        assert_eq!(
            v.screen.lines.last().map(String::as_str),
            Some("[5/9] Resolving sources: kernite/src")
        );
        assert!(v.running.is_empty());
    }

    #[test]
    fn evaluation_items_are_drawn_like_derivations() {
        let mut terminal = view(true);
        let mut pipe = view(false);
        let report = |phase, current, total| ResolveReport {
            current,
            total,
            phase,
            detail: String::new(),
            elapsed_ms: 10,
            cache_candidates: Some(3),
            cutoff_candidates: None,
        };
        for v in [&mut terminal, &mut pipe] {
            v.resolve(report(EvalPhase::ResolvingSources, 0, 2));
            // Two workers: items finish out of start order.
            feed(
                v,
                &[
                    job("a", "Resolving", 0, 2),
                    job("b", "Resolving", 0, 2),
                    done("b", "Resolved", 1, 2, "hb"),
                    done("a", "Resolved", 2, 2, "ha"),
                ],
            );
            v.resolve(report(EvalPhase::Instantiating, 0, 1));
            feed(v, &[job("x", "Evaluating", 0, 1)]);
            if v.opts.interactive {
                assert_eq!(v.screen.status, "[0/1] Evaluating x");
            }
            feed(v, &[done("x", "Evaluated", 1, 1, "")]);
            v.resolve(report(EvalPhase::Evaluated, 1, 1));
        }
        assert_eq!(terminal.screen.lines, pipe.screen.lines);
        assert_eq!(
            pipe.screen.lines,
            [
                "The Buildutil Build System v0.0.1",
                "-- Dependency Evaluation --",
                "[1/2] Resolved b (hb)",
                "[2/2] Resolved a (ha)",
                "[1/1] Evaluated x",
                "[1/1] Evaluated in 10ms; cache candidates 3",
            ]
        );
    }

    #[test]
    fn raw_bytes_split_into_lines_and_carriage_returns_overwrite() {
        let mut v = view(false);
        v.raw(Stream::Stderr, b"50%\r100%\ndone\r\npart");
        assert_eq!(v.partial[Stream::Stderr as usize], b"part");
        v.raw(Stream::Stderr, b"ial 1%\r");
        v.raw(Stream::Stderr, b"2%");
        assert_eq!(v.partial[Stream::Stderr as usize], b"2%");
        assert_eq!(v.screen.lines, ["100%", "done"]);
    }

    #[test]
    fn a_progress_step_shows_until_the_next_build_event() {
        let mut v = view(true);
        v.event(r#"{"ev":"progress","label":"Starting the docker backend"}"#);
        assert_eq!(v.screen.status, "Starting the docker backend…");
        v.event(r#"{"ev":"log","level":"info","context":"x","msg":"x"}"#);
        assert_eq!(v.stage, None);
        assert_eq!(v.screen.lines, ["[INFO] X"]);
    }

    #[test]
    fn output_modes_parse() {
        assert_eq!(OutputMode::parse("failed"), Some(OutputMode::Failed));
        assert_eq!(OutputMode::parse("none"), Some(OutputMode::None));
        assert_eq!(OutputMode::parse("some"), None);
    }
}
