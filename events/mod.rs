//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — structured build-event transport
//!
//! Build events are JSONL lines. A process that streams (`--stream-events`,
//! a daemon request, an engine child) writes them to stdout for its client;
//! a process that shows a person its own build installs a local sink, and
//! every event goes to that sink instead. Producers therefore never format
//! for a terminal: `term::view` is the only consumer that draws events.

use crate::eval::graph::EvalPhase;
use std::io::{Write, stdout};
use std::path::Path;
use std::sync::Mutex;

static EVENT_OUT_LOCK: Mutex<()> = Mutex::new(());

type Sink = Box<dyn Fn(&str) + Send + Sync>;

static LOCAL_SINK: Mutex<Option<Sink>> = Mutex::new(None);

/// Deliver this process's events to `sink` instead of stdout.
pub fn install_local_sink(sink: Sink) {
    *LOCAL_SINK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sink);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolReport {
    pub name: String,
    pub version: String,
    pub locator: String,
}

/// State of the whole-evaluation cache for one invocation. `Off` when the
/// cache is disabled (`--no-source-cache`) or not yet consulted; `Hit`/`Miss`
/// once F is wired.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvalCacheState {
    #[default]
    Off,
    Hit,
    Miss,
}

impl EvalCacheState {
    pub fn as_str(self) -> &'static str {
        match self {
            EvalCacheState::Off => "off",
            EvalCacheState::Hit => "hit",
            EvalCacheState::Miss => "miss",
        }
    }

    fn from_str(s: &str) -> EvalCacheState {
        match s {
            "hit" => EvalCacheState::Hit,
            "miss" => EvalCacheState::Miss,
            _ => EvalCacheState::Off,
        }
    }
}

/// Per-phase evaluation timings. `probe_wall_ms` is critical-path wall time
/// (parallel prewarm counted once); `probe_ms` is summed worker work and can be
/// larger than `eval_ms`. `git_identity_ms` accounts for the build header's
/// separate main-repository probe. These are cache-accelerator instruments,
/// never inputs to a derivation hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvalTimings {
    pub context_ms: u128,
    pub statcache_load_ms: u128,
    pub git_identity_ms: u128,
    pub eval_ms: u128,
    pub closure_ms: u128,
    pub probe_wall_ms: u128,
    /// Summed work across all git-probe workers, not elapsed wall time.
    pub probe_ms: u128,
    pub source_ms: u128,
    pub instantiate_ms: u128,
    pub cache_scan_ms: u128,
    pub emit_ms: u128,
    pub verify_ms: u128,
    pub evalcache: EvalCacheState,
    pub statcache_hits: u64,
    pub statcache_misses: u64,
    pub total_ms: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderReport {
    pub source_dir: String,
    pub target_system: String,
    pub build_host: String,
    pub backend: String,
    pub git_rev: String,
    pub config_hash: String,
    /// Name-ordered provenance of the selected repository inputs.
    pub inputs: Vec<String>,
    pub profile: String,
    pub tools: Vec<ToolReport>,
    pub config: Vec<(String, String)>,
    pub targets: Vec<String>,
    pub resolved: usize,
    pub eval_ms: u128,
    /// Optional per-phase breakdown (additive JSON field; absent on older
    /// producers). See [`EvalTimings`].
    pub timings: Option<EvalTimings>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderSeed {
    pub source_dir: String,
    pub build_host: String,
    pub backend: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryReport {
    pub built: usize,
    pub cached: usize,
    pub failed: usize,
    pub total: usize,
    /// Wall-clock duration spent inside `exec::pool::realize`.
    pub realize_ms: u128,
    pub failures: Vec<String>,
    pub critical_path_secs: Option<String>,
    pub critical_path_tip: Option<String>,
    pub critical_path_nodes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveReport {
    pub current: usize,
    pub total: usize,
    pub phase: EvalPhase,
    pub detail: String,
    pub elapsed_ms: u128,
    pub cache_candidates: Option<usize>,
    pub cutoff_candidates: Option<usize>,
}

pub enum StreamEvent {
    Header(HeaderReport),
    Resolve(ResolveReport),
    Start {
        drv: String,
        action: String,
        current: usize,
        total: usize,
    },
    /// A derivation reached its outcome. A failure carries its reason and
    /// its retained log as a path relative to the state root, so each
    /// client resolves it against its own view of that directory.
    Finish {
        drv: String,
        hash: String,
        outcome: String,
        current: usize,
        total: usize,
        msg: Option<String>,
        log: Option<String>,
    },
    /// A builder output line, as the tool wrote it (escape sequences
    /// included). The JSONL also names its stream, which no consumer here
    /// distinguishes.
    Output {
        drv: String,
        line: String,
    },
    /// A builder reported progress through a structured signal: an inner
    /// ninja status line carrying buildutil's marker, or a cargo message.
    /// `counter` is the reporting tool's own `[n/N]` when it has one.
    Item {
        drv: String,
        counter: Option<(usize, usize)>,
        text: String,
    },
    Error {
        msg: String,
    },
    /// A log message: `level` is debug, info, success, warning, or error.
    Log {
        level: String,
        msg: String,
    },
    Timings(EvalTimings),
    /// A running derivation moved to its next step (from `Staging` to its
    /// builder's action).
    Step {
        drv: String,
        action: String,
    },
    /// A step that shows no other progress is under way (backend
    /// preparation); it lasts until the next build event.
    Progress {
        label: String,
    },
    Summary(SummaryReport),
    /// A configured node's key and its readable form, sent before the key
    /// appears in any other event so screens can show the readable form.
    Configured {
        drv: String,
        label: String,
    },
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_unescape(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let mut hex = String::new();
                for _ in 0..4 {
                    hex.push(chars.next()?);
                }
                let value = u32::from_str_radix(&hex, 16).ok()?;
                out.push(char::from_u32(value)?);
            }
            other => out.push(other),
        }
    }
    Some(out)
}

fn string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let mut escaped = false;
    for (idx, byte) in rest.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return json_unescape(&rest[..idx]);
        }
    }
    None
}

fn usize_field(line: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn opt_usize_field(line: &str, key: &str) -> Option<Option<usize>> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    if line[start..].starts_with("null") {
        return Some(None);
    }
    usize_field(line, key).map(Some)
}

fn u128_field(line: &str, key: &str) -> Option<u128> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn opt_string_field(line: &str, key: &str) -> Option<Option<String>> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    if line[start..].starts_with("null") {
        return Some(None);
    }
    string_field(line, key).map(Some)
}

fn section_between<'a>(line: &'a str, key: &str, next_key: &str) -> Option<&'a str> {
    let start_needle = format!("\"{}\":[", key);
    let start = line.find(&start_needle)? + start_needle.len();
    let end_needle = format!("],\"{}\"", next_key);
    let end = line[start..].find(&end_needle)? + start;
    Some(&line[start..end])
}

fn split_objects(section: &str) -> Vec<&str> {
    if section.trim().is_empty() {
        return Vec::new();
    }
    section
        .split("},{")
        .map(|s| s.trim_start_matches('{').trim_end_matches('}'))
        .collect()
}

fn split_pairs(section: &str) -> Vec<&str> {
    if section.trim().is_empty() {
        return Vec::new();
    }
    section
        .split("],[")
        .map(|s| s.trim_start_matches('[').trim_end_matches(']'))
        .collect()
}

fn parse_string_array(section: &str) -> Vec<String> {
    if section.trim().is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut start = None;
    let mut escaped = false;
    for (index, ch) in section.char_indices() {
        if let Some(begin) = start {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                if let Some(value) = json_unescape(&section[begin..index]) {
                    result.push(value);
                }
                start = None;
            }
        } else if ch == '"' {
            start = Some(index + 1);
        }
    }
    result
}

fn tools_json(tools: &[ToolReport]) -> String {
    tools
        .iter()
        .map(|tool| {
            format!(
                "{{\"name\":\"{}\",\"version\":\"{}\",\"locator\":\"{}\"}}",
                json_escape(&tool.name),
                json_escape(&tool.version),
                json_escape(&tool.locator)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn pairs_json(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("[\"{}\",\"{}\"]", json_escape(k), json_escape(v)))
        .collect::<Vec<_>>()
        .join(",")
}

fn strings_json(items: &[String]) -> String {
    items
        .iter()
        .map(|item| format!("\"{}\"", json_escape(item)))
        .collect::<Vec<_>>()
        .join(",")
}

fn opt_json(value: &Option<String>) -> String {
    match value {
        Some(v) => format!("\"{}\"", json_escape(v)),
        None => "null".to_string(),
    }
}

fn timings_json(t: &EvalTimings) -> String {
    format!(
        "{{\"context_ms\":{},\"statcache_load_ms\":{},\"git_identity_ms\":{},\"eval_ms\":{},\"closure_ms\":{},\
         \"probe_wall_ms\":{},\"probe_ms\":{},\
         \"source_ms\":{},\"instantiate_ms\":{},\"cache_scan_ms\":{},\"emit_ms\":{},\
         \"verify_ms\":{},\"evalcache\":\"{}\",\"statcache_hits\":{},\
         \"statcache_misses\":{},\"total_ms\":{}}}",
        t.context_ms,
        t.statcache_load_ms,
        t.git_identity_ms,
        t.eval_ms,
        t.closure_ms,
        t.probe_wall_ms,
        t.probe_ms,
        t.source_ms,
        t.instantiate_ms,
        t.cache_scan_ms,
        t.emit_ms,
        t.verify_ms,
        t.evalcache.as_str(),
        t.statcache_hits,
        t.statcache_misses,
        t.total_ms
    )
}

fn parse_timings(line: &str) -> Option<EvalTimings> {
    let needle = "\"timings\":{";
    let start = line.find(needle)? + needle.len() - 1;
    // The timings object holds only scalar and one string field — no nested
    // braces — so the first `}` after the opening brace closes it.
    let end = line[start..].find('}')? + start + 1;
    let obj = &line[start..end];
    Some(EvalTimings {
        context_ms: u128_field(obj, "context_ms")?,
        statcache_load_ms: u128_field(obj, "statcache_load_ms").unwrap_or(0),
        git_identity_ms: u128_field(obj, "git_identity_ms").unwrap_or(0),
        eval_ms: u128_field(obj, "eval_ms")?,
        closure_ms: u128_field(obj, "closure_ms")?,
        probe_wall_ms: u128_field(obj, "probe_wall_ms").unwrap_or(0),
        probe_ms: u128_field(obj, "probe_ms")?,
        source_ms: u128_field(obj, "source_ms")?,
        instantiate_ms: u128_field(obj, "instantiate_ms")?,
        cache_scan_ms: u128_field(obj, "cache_scan_ms")?,
        emit_ms: u128_field(obj, "emit_ms")?,
        verify_ms: u128_field(obj, "verify_ms")?,
        evalcache: EvalCacheState::from_str(&string_field(obj, "evalcache")?),
        statcache_hits: u128_field(obj, "statcache_hits")? as u64,
        statcache_misses: u128_field(obj, "statcache_misses")? as u64,
        total_ms: u128_field(obj, "total_ms")?,
    })
}

pub fn header_json(report: &HeaderReport) -> String {
    let timings = match &report.timings {
        Some(t) => format!(",\"timings\":{}", timings_json(t)),
        None => String::new(),
    };
    let timings = format!(",\"inputs\":[{}]{timings}", strings_json(&report.inputs));
    format!(
        "{{\"ev\":\"header\",\"schema\":1,\"source_dir\":\"{}\",\"target_system\":\"{}\",\
         \"build_host\":\"{}\",\"backend\":\"{}\",\"git_rev\":\"{}\",\"config_hash\":\"{}\",\
         \"profile\":\"{}\",\"tools\":[{}],\"config\":[{}],\"targets\":[{}],\
         \"resolved\":{},\"eval_ms\":{}{}}}",
        json_escape(&report.source_dir),
        json_escape(&report.target_system),
        json_escape(&report.build_host),
        json_escape(&report.backend),
        json_escape(&report.git_rev),
        json_escape(&report.config_hash),
        json_escape(&report.profile),
        tools_json(&report.tools),
        pairs_json(&report.config),
        strings_json(&report.targets),
        report.resolved,
        report.eval_ms,
        timings
    )
}

pub fn parse_header_seed_json(line: &str) -> Option<HeaderSeed> {
    Some(HeaderSeed {
        source_dir: string_field(line, "source_dir")?,
        build_host: string_field(line, "build_host")?,
        backend: string_field(line, "backend")?,
    })
}

pub fn parse_header_json(line: &str) -> Option<HeaderReport> {
    if string_field(line, "ev").as_deref() != Some("header") {
        return None;
    }
    let tool_section = section_between(line, "tools", "config")?;
    let config_section = section_between(line, "config", "targets")?;
    let targets_start = line.find("\"targets\":[")? + "\"targets\":[".len();
    let targets_end = line[targets_start..].find("],\"resolved\"")? + targets_start;
    let tools = split_objects(tool_section)
        .into_iter()
        .filter_map(|obj| {
            Some(ToolReport {
                name: string_field(obj, "name")?,
                version: string_field(obj, "version")?,
                locator: string_field(obj, "locator")?,
            })
        })
        .collect();
    let config = split_pairs(config_section)
        .into_iter()
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, ',');
            let k = parts
                .next()?
                .trim()
                .trim_start_matches('"')
                .trim_end_matches('"');
            let v = parts
                .next()?
                .trim()
                .trim_start_matches('"')
                .trim_end_matches('"');
            Some((json_unescape(k)?, json_unescape(v)?))
        })
        .collect();
    Some(HeaderReport {
        source_dir: string_field(line, "source_dir")?,
        target_system: string_field(line, "target_system")?,
        build_host: string_field(line, "build_host")?,
        backend: string_field(line, "backend")?,
        git_rev: string_field(line, "git_rev")?,
        config_hash: string_field(line, "config_hash")?,
        inputs: line
            .find("\"inputs\":[")
            .and_then(|start| {
                let start = start + "\"inputs\":[".len();
                line[start..]
                    .find(']')
                    .map(|end| parse_string_array(&line[start..start + end]))
            })
            .unwrap_or_default(),
        profile: string_field(line, "profile")?,
        tools,
        config,
        targets: parse_string_array(&line[targets_start..targets_end]),
        resolved: usize_field(line, "resolved")?,
        eval_ms: u128_field(line, "eval_ms")?,
        timings: parse_timings(line),
    })
}

pub fn read_header_seed(path: &Path) -> Result<HeaderSeed, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read header seed {}: {}", path.display(), e))?;
    parse_header_seed_json(text.trim())
        .ok_or_else(|| format!("malformed header seed {}", path.display()))
}

pub fn read_header_file(path: &Path) -> Result<HeaderReport, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read header report {}: {}", path.display(), e))?;
    parse_header_json(text.trim())
        .ok_or_else(|| format!("malformed header report {}", path.display()))
}

pub fn emit_header(report: &HeaderReport) {
    emit_line(&header_json(report));
}

pub fn emit_resolve(report: &ResolveReport) {
    emit_line(&resolve_json(report));
}

pub(crate) fn resolve_json(report: &ResolveReport) -> String {
    format!(
        "{{\"ev\":\"resolve\",\"current\":{},\"total\":{},\"phase\":\"{}\",\
         \"detail\":\"{}\",\"elapsed_ms\":{},\"cache_candidates\":{},\
         \"cutoff_candidates\":{}}}",
        report.current,
        report.total,
        report.phase.as_str(),
        json_escape(&report.detail),
        report.elapsed_ms,
        report
            .cache_candidates
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string()),
        report
            .cutoff_candidates
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string())
    )
}

pub fn emit_start(drv: &str, hash: &str, action: &str, current: usize, total: usize) {
    emit_line(&format!(
        "{{\"ev\":\"start\",\"drv\":\"{}\",\"hash\":\"{}\",\"action\":\"{}\",\
         \"current\":{},\"total\":{}}}",
        json_escape(drv),
        json_escape(hash),
        json_escape(action),
        current,
        total
    ));
}

pub fn emit_finish(
    drv: &str,
    hash: &str,
    outcome: &str,
    current: usize,
    total: usize,
    msg: Option<&str>,
    log: Option<&str>,
) {
    emit_line(&finish_json(drv, hash, outcome, current, total, msg, log));
}

fn finish_json(
    drv: &str,
    hash: &str,
    outcome: &str,
    current: usize,
    total: usize,
    msg: Option<&str>,
    log: Option<&str>,
) -> String {
    format!(
        "{{\"ev\":\"finish\",\"drv\":\"{}\",\"hash\":\"{}\",\"outcome\":\"{}\",\
         \"current\":{},\"total\":{},\"msg\":{},\"log\":{}}}",
        json_escape(drv),
        json_escape(hash),
        json_escape(outcome),
        current,
        total,
        opt_json(&msg.map(str::to_string)),
        opt_json(&log.map(str::to_string))
    )
}

pub fn emit_item(drv: &str, counter: Option<(usize, usize)>, text: &str) {
    emit_line(&item_json(drv, counter, text));
}

fn item_json(drv: &str, counter: Option<(usize, usize)>, text: &str) -> String {
    let (done, total) = match counter {
        Some((done, total)) => (done.to_string(), total.to_string()),
        None => ("null".to_string(), "null".to_string()),
    };
    format!(
        "{{\"ev\":\"item\",\"drv\":\"{}\",\"done\":{},\"total\":{},\"text\":\"{}\"}}",
        json_escape(drv),
        done,
        total,
        json_escape(text)
    )
}

pub fn emit_output(drv: &str, line: &str, stream: &str) {
    emit_line(&format!(
        "{{\"ev\":\"output\",\"drv\":\"{}\",\"line\":\"{}\",\"stream\":\"{}\"}}",
        json_escape(drv),
        json_escape(line),
        json_escape(stream)
    ));
}

pub fn emit_log(level: &str, context: &str, msg: &str) {
    emit_line(&format!(
        "{{\"ev\":\"log\",\"level\":\"{}\",\"context\":\"{}\",\"msg\":\"{}\"}}",
        json_escape(level),
        json_escape(context),
        json_escape(msg)
    ));
}

pub fn emit_step(drv: &str, action: &str) {
    emit_line(&format!(
        "{{\"ev\":\"step\",\"drv\":\"{}\",\"action\":\"{}\"}}",
        json_escape(drv),
        json_escape(action)
    ));
}

pub fn emit_configured(drv: &str, label: &str) {
    emit_line(&format!(
        "{{\"ev\":\"configured\",\"drv\":\"{}\",\"label\":\"{}\"}}",
        json_escape(drv),
        json_escape(label)
    ));
}

pub fn emit_progress(label: &str) {
    emit_line(&format!(
        "{{\"ev\":\"progress\",\"label\":\"{}\"}}",
        json_escape(label)
    ));
}

pub fn emit_timings(timings: &EvalTimings) {
    emit_line(&format!(
        "{{\"ev\":\"timings\",\"timings\":{}}}",
        timings_json(timings)
    ));
}

pub fn emit_error(context: &str, msg: &str) {
    emit_line(&format!(
        "{{\"ev\":\"error\",\"context\":\"{}\",\"msg\":\"{}\"}}",
        json_escape(context),
        json_escape(msg)
    ));
}

fn summary_json(report: &SummaryReport) -> String {
    format!(
        "{{\"ev\":\"summary\",\"built\":{},\"cached\":{},\"failed\":{},\"total\":{},\"realize_ms\":{},\
         \"failures\":[{}],\"critical_path_secs\":{},\"critical_path_tip\":{},\
         \"critical_path_nodes\":{}}}",
        report.built,
        report.cached,
        report.failed,
        report.total,
        report.realize_ms,
        strings_json(&report.failures),
        opt_json(&report.critical_path_secs),
        opt_json(&report.critical_path_tip),
        report.critical_path_nodes
    )
}

pub fn emit_summary(report: &SummaryReport) {
    emit_line(&summary_json(report));
}

fn emit_line(line: &str) {
    {
        let sink = LOCAL_SINK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sink) = sink.as_ref() {
            sink(line);
            return;
        }
    }
    let _guard = EVENT_OUT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut out = stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

pub fn forward_stream_event(line: &str) {
    debug_assert!(parse_stream_event(line).is_some());
    emit_line(line);
}

pub fn parse_stream_event(line: &str) -> Option<StreamEvent> {
    let ev = string_field(line, "ev")?;
    match ev.as_str() {
        "header" => parse_header_json(line).map(StreamEvent::Header),
        "resolve" => Some(StreamEvent::Resolve(ResolveReport {
            current: usize_field(line, "current")?,
            total: usize_field(line, "total")?,
            phase: EvalPhase::from_str(&string_field(line, "phase")?)?,
            detail: string_field(line, "detail")?,
            elapsed_ms: u128_field(line, "elapsed_ms")?,
            cache_candidates: opt_usize_field(line, "cache_candidates")?,
            cutoff_candidates: opt_usize_field(line, "cutoff_candidates")?,
        })),
        "start" => Some(StreamEvent::Start {
            drv: string_field(line, "drv")?,
            action: string_field(line, "action")?,
            current: usize_field(line, "current")?,
            total: usize_field(line, "total")?,
        }),
        "finish" => Some(StreamEvent::Finish {
            drv: string_field(line, "drv")?,
            hash: string_field(line, "hash")?,
            outcome: string_field(line, "outcome")?,
            current: usize_field(line, "current")?,
            total: usize_field(line, "total")?,
            msg: opt_string_field(line, "msg")?,
            log: opt_string_field(line, "log").flatten(),
        }),
        "output" => Some(StreamEvent::Output {
            drv: string_field(line, "drv")?,
            line: string_field(line, "line")?,
        }),
        "item" => {
            let done = opt_usize_field(line, "done")?;
            let total = opt_usize_field(line, "total")?;
            Some(StreamEvent::Item {
                drv: string_field(line, "drv")?,
                counter: done.zip(total),
                text: string_field(line, "text")?,
            })
        }
        "log" => Some(StreamEvent::Log {
            level: string_field(line, "level")?,
            msg: string_field(line, "msg")?,
        }),
        "timings" => parse_timings(line).map(StreamEvent::Timings),
        "step" => Some(StreamEvent::Step {
            drv: string_field(line, "drv")?,
            action: string_field(line, "action")?,
        }),
        "configured" => Some(StreamEvent::Configured {
            drv: string_field(line, "drv")?,
            label: string_field(line, "label")?,
        }),
        "progress" => Some(StreamEvent::Progress {
            label: string_field(line, "label")?,
        }),
        "error" => Some(StreamEvent::Error {
            msg: string_field(line, "msg")?,
        }),
        "summary" => {
            let failures_start = line.find("\"failures\":[")? + "\"failures\":[".len();
            let failures_end =
                line[failures_start..].find("],\"critical_path_secs\"")? + failures_start;
            Some(StreamEvent::Summary(SummaryReport {
                built: usize_field(line, "built")?,
                cached: usize_field(line, "cached")?,
                failed: usize_field(line, "failed")?,
                total: usize_field(line, "total")?,
                realize_ms: u128_field(line, "realize_ms").unwrap_or(0),
                failures: parse_string_array(&line[failures_start..failures_end]),
                critical_path_secs: opt_string_field(line, "critical_path_secs")?,
                critical_path_tip: opt_string_field(line, "critical_path_tip")?,
                critical_path_nodes: usize_field(line, "critical_path_nodes")?,
            }))
        }
        _ => None,
    }
}

/// Format a millisecond count compactly: sub-second as `NNNms`, else `N.Ns`.
pub fn fmt_ms(ms: u128) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_report_round_trips() {
        let report = HeaderReport {
            source_dir: "/src".into(),
            target_system: "x86_64-example".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            backend: "docker".into(),
            git_rev: "abc-dirty".into(),
            config_hash: "deadbeef".into(),
            inputs: vec!["library: dirty, ahead of lock".into()],
            profile: "debug".into(),
            tools: vec![ToolReport {
                name: "rustc".into(),
                version: "rustc 1.96.1".into(),
                locator: "store:host-rust:bin/rustc".into(),
            }],
            config: vec![("DEBUG_SYMBOLS".into(), "true".into())],
            targets: vec!["default".into()],
            resolved: 42,
            eval_ms: 123,
            timings: None,
        };
        assert_eq!(parse_header_json(&header_json(&report)), Some(report));
    }

    #[test]
    fn header_report_with_timings_round_trips() {
        let report = HeaderReport {
            source_dir: "/src".into(),
            target_system: "x86_64-example".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            backend: "local-linux".into(),
            git_rev: "abc-dirty".into(),
            config_hash: "deadbeef".into(),
            inputs: Vec::new(),
            profile: "release".into(),
            tools: Vec::new(),
            config: Vec::new(),
            targets: vec!["default".into()],
            resolved: 512,
            eval_ms: 48000,
            timings: Some(EvalTimings {
                context_ms: 2100,
                statcache_load_ms: 650,
                git_identity_ms: 700,
                eval_ms: 48000,
                closure_ms: 30,
                probe_wall_ms: 100,
                probe_ms: 300,
                source_ms: 400,
                instantiate_ms: 120,
                cache_scan_ms: 1200,
                emit_ms: 2000,
                verify_ms: 400,
                evalcache: EvalCacheState::Miss,
                statcache_hits: 91234,
                statcache_misses: 57,
                total_ms: 53700,
            }),
        };
        assert_eq!(parse_header_json(&header_json(&report)), Some(report));
    }

    #[test]
    fn summary_report_with_realize_ms_round_trips() {
        let report = SummaryReport {
            built: 12,
            cached: 34,
            failed: 1,
            total: 47,
            realize_ms: 1234,
            failures: vec!["broken-target".into()],
            critical_path_secs: Some("1.2s".into()),
            critical_path_tip: Some("broken-target".into()),
            critical_path_nodes: 8,
        };
        let parsed = match parse_stream_event(&summary_json(&report)) {
            Some(StreamEvent::Summary(parsed)) => parsed,
            _ => panic!("summary event did not parse"),
        };
        assert_eq!(parsed, report);
    }

    #[test]
    fn header_seed_round_trips() {
        let seed = HeaderSeed {
            source_dir: "/src".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            backend: "docker".into(),
        };
        let text = format!(
            "{{\"schema\":1,\"source_dir\":\"{}\",\"build_host\":\"{}\",\"backend\":\"{}\"}}",
            json_escape(&seed.source_dir),
            json_escape(&seed.build_host),
            json_escape(&seed.backend)
        );
        assert_eq!(parse_header_seed_json(&text), Some(seed));
    }

    #[test]
    fn failed_finish_and_item_events_round_trip() {
        let line = finish_json(
            "foo",
            "abc",
            "Failed",
            1,
            2,
            Some("builder failed"),
            Some("logs/x.log"),
        );
        match parse_stream_event(&line).unwrap() {
            StreamEvent::Finish { msg, log, .. } => {
                assert_eq!(msg.as_deref(), Some("builder failed"));
                assert_eq!(log.as_deref(), Some("logs/x.log"));
            }
            _ => panic!("wrong event"),
        }
        match parse_stream_event(&item_json("d", Some((3, 40)), "CC \"a\".o")).unwrap() {
            StreamEvent::Item { drv, counter, text } => {
                assert_eq!(
                    (drv.as_str(), counter, text.as_str()),
                    ("d", Some((3, 40)), "CC \"a\".o")
                )
            }
            _ => panic!("wrong event"),
        }
        match parse_stream_event(&item_json("d", None, "Compiled core")).unwrap() {
            StreamEvent::Item { counter, .. } => assert_eq!(counter, None),
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn stream_finish_parses_optional_error_message() {
        let line = "{\"ev\":\"finish\",\"drv\":\"foo\",\"hash\":\"abc\",\"outcome\":\"Failed\",\
                    \"current\":1,\"total\":2,\"msg\":\"bad\\nthing\"}";
        match parse_stream_event(line).unwrap() {
            StreamEvent::Finish { msg, .. } => assert_eq!(msg.as_deref(), Some("bad\nthing")),
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn resolve_and_error_events_parse() {
        let report = ResolveReport {
            current: 3,
            total: 9,
            phase: EvalPhase::Instantiating,
            detail: "kernel-main".into(),
            elapsed_ms: 250,
            cache_candidates: Some(2),
            cutoff_candidates: None,
        };
        let json = resolve_json(&report);
        assert!(json.contains("\"phase\":\"instantiating\""));
        assert!(json.contains("\"detail\":\"kernel-main\""));
        assert!(!json.contains("\"name\":"));
        match parse_stream_event(&json).unwrap() {
            StreamEvent::Resolve(parsed) => assert_eq!(parsed, report),
            _ => panic!("wrong event"),
        }

        match parse_stream_event(
            "{\"ev\":\"error\",\"context\":\"eval\",\"msg\":\"bad\\nconfiguration\"}",
        )
        .unwrap()
        {
            StreamEvent::Error { msg } => assert_eq!(msg, "bad\nconfiguration"),
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn completed_resolve_event_preserves_candidate_counts() {
        let report = ResolveReport {
            current: 122,
            total: 122,
            phase: EvalPhase::Evaluated,
            detail: String::new(),
            elapsed_ms: 500,
            cache_candidates: Some(35),
            cutoff_candidates: Some(35),
        };
        let json = resolve_json(&report);
        match parse_stream_event(&json).unwrap() {
            StreamEvent::Resolve(parsed) => assert_eq!(parsed, report),
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn log_timings_and_output_events_parse() {
        match parse_stream_event(
            "{\"ev\":\"log\",\"level\":\"warning\",\"context\":\"eval\",\"msg\":\"x\"}",
        )
        .unwrap()
        {
            StreamEvent::Log { level, msg } => {
                assert_eq!((level.as_str(), msg.as_str()), ("warning", "x"))
            }
            _ => panic!("wrong event"),
        }
        let timings = EvalTimings {
            context_ms: 1,
            eval_ms: 2,
            total_ms: 3,
            ..Default::default()
        };
        let line = format!(
            "{{\"ev\":\"timings\",\"timings\":{}}}",
            timings_json(&timings)
        );
        match parse_stream_event(&line).unwrap() {
            StreamEvent::Timings(parsed) => assert_eq!(parsed, timings),
            _ => panic!("wrong event"),
        }
        match parse_stream_event("{\"ev\":\"progress\",\"label\":\"Starting\"}").unwrap() {
            StreamEvent::Progress { label } => assert_eq!(label, "Starting"),
            _ => panic!("wrong event"),
        }
        match parse_stream_event(
            "{\"ev\":\"output\",\"drv\":\"d\",\"line\":\"  | x\",\"stream\":\"stderr\"}",
        )
        .unwrap()
        {
            StreamEvent::Output { line, .. } => assert_eq!(line, "  | x"),
            _ => panic!("wrong event"),
        }
    }
}
