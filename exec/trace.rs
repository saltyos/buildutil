//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — observability writers (events JSONL, Chrome trace, critical path)
//!
//! Three observable streams share the same per-event input (one Event per
//! realized derivation):
//!
//! - `write_events_jsonl` — one compact JSON object per line, for downstream
//!   `jq` / `clickhouse` ingestion.
//! - `write_trace` — Chrome / Perfetto `chrome://tracing` complete-event JSON
//!   for time-axis visualization of the build wall-clock.
//! - `critical_path` — the longest dependency-weighted chain, useful for
//!   reporting which builds dominated wall time.

use crate::eval::plan::ExecPlan;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Write the build events as JSONL (one object per line), per the spec's
/// event schema.
pub fn write_events_jsonl(events: &[super::Event], path: &Path) -> Result<(), String> {
    let mut s = String::new();
    for e in events {
        let digest = e
            .digest
            .as_deref()
            .map(|d| format!("\"{}\"", d))
            .unwrap_or_else(|| "null".to_string());
        let msg = e
            .msg
            .as_deref()
            .map(|m| format!("\"{}\"", json_escape(m)))
            .unwrap_or_else(|| "null".to_string());
        s.push_str(&format!(
            "{{\"t\": {}, \"ev\": \"{}\", \"drv\": \"{}\", \"hash\": \"{}\", \"digest\": {}, \"secs\": {:.3}, \"msg\": {}}}\n",
            e.start_ms, e.kind, e.name, e.hash, digest, e.dur_secs, msg
        ));
    }
    std::fs::write(path, s)
        .map_err(|err| format!("cannot write events {}: {}", path.display(), err))
}

/// Write a Chrome trace-event JSON (`chrome://tracing` / Perfetto) of the same
/// stream: one complete ("X") event per build, timed in microseconds.
pub fn write_trace(events: &[super::Event], path: &Path) -> Result<(), String> {
    let mut s = String::from("[\n");
    for (i, e) in events.iter().enumerate() {
        if i > 0 {
            s.push_str(",\n");
        }
        s.push_str(&format!(
            "  {{\"name\": \"{}\", \"cat\": \"{}\", \"ph\": \"X\", \"pid\": 1, \"tid\": 1, \"ts\": {}, \"dur\": {}}}",
            json_escape(&e.name),
            e.kind,
            e.start_ms.saturating_mul(1000),
            (e.dur_secs * 1_000_000.0) as u64
        ));
    }
    s.push_str("\n]\n");
    std::fs::write(path, s).map_err(|err| format!("cannot write trace {}: {}", path.display(), err))
}

/// The critical path: the longest dependency chain weighted by per-node build
/// time. Returns the chain (root → leaf order) and its total seconds.
pub fn critical_path(plan: &ExecPlan, events: &[super::Event]) -> (Vec<String>, f64) {
    let dur: BTreeMap<&str, f64> = events
        .iter()
        .map(|e| (e.name.as_str(), e.dur_secs))
        .collect();
    let recipes = plan.recipes();
    let order: Vec<String> = plan.nodes.iter().map(|node| node.name.clone()).collect();
    let in_closure: BTreeSet<&str> = order.iter().map(|s| s.as_str()).collect();
    // `end[n]` = longest weighted path ending at n; plan order is topo
    // (dependencies first), so a single forward pass suffices.
    let mut end: BTreeMap<String, f64> = BTreeMap::new();
    let mut pred: BTreeMap<String, Option<String>> = BTreeMap::new();
    for name in &order {
        let mut best = 0.0f64;
        let mut best_dep: Option<String> = None;
        for dep in &recipes[name].dep_names {
            if !in_closure.contains(dep.as_str()) {
                continue;
            }
            if let Some(&de) = end.get(dep) {
                if de > best {
                    best = de;
                    best_dep = Some(dep.clone());
                }
            }
        }
        end.insert(
            name.clone(),
            best + dur.get(name.as_str()).copied().unwrap_or(0.0),
        );
        pred.insert(name.clone(), best_dep);
    }
    let Some((tip, total)) = end.iter().max_by(|a, b| a.1.total_cmp(b.1)) else {
        return (Vec::new(), 0.0);
    };
    let total = *total;
    let mut chain = Vec::new();
    let mut cur = Some(tip.clone());
    while let Some(n) = cur {
        chain.push(n.clone());
        cur = pred.get(&n).cloned().flatten();
    }
    chain.reverse();
    (chain, total)
}
