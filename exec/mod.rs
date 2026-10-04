//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — realization: staging, execution, output capture, registration
//!
//! A derivation is realized in a private build dir: declared sources are
//! symlinked into a stage tree at their repo-relative paths, the builder
//! runs with cwd inside the stage and an environment built from scratch
//! (PATH = a private toolbin of the declared tools), outputs land in a
//! private `out/` and any undeclared file there is a hard error, then the
//! output dir is atomically registered into the store. Unchanged inputs
//! are reused, not rebuilt.
//!
//! Scheduling is a plain N-way worker pool over a ready queue with
//! dependency counting — no jobserver. Cross-process realizers of the same
//! derivation serialize on the store's build lock.

use crate::store::TempRoot;
use std::collections::BTreeMap;

/// A build event, for the `--events` JSONL stream, the `--trace` Chrome
/// trace, and the cache-statistics summary. `kind` is one of `realized`,
/// `cached`, or `failed`.
#[derive(Clone)]
pub struct Event {
    pub name: String,
    pub hash: String,
    pub kind: &'static str,
    pub start_ms: u128,
    pub dur_secs: f64,
    pub digest: Option<String>,
    pub msg: Option<String>,
}

pub struct RealizeOutcome {
    pub built: Vec<String>,
    pub cached: Vec<String>,
    /// (derivation, error) for every failure. Under keep-going it also holds
    /// the dependents skipped because of a failure; otherwise the pool stops
    /// at the first failure and unstarted derivations appear in no list.
    pub failed: Vec<(String, String)>,
    /// Finalized store name per realized derivation (name → store-name), for
    /// GC-root creation now that hashes are known only after realization.
    pub store_names: BTreeMap<String, String>,
    /// Per-node build events (for `--events` / `--trace` / cache stats).
    pub events: Vec<Event>,
    /// One flock-held temporary root protecting every realized output until
    /// the caller has added any permanent roots it wants to keep.
    pub(crate) _temp_root: TempRoot,
}

impl RealizeOutcome {
    /// The summary a build prints after realization, whether or not a
    /// derivation failed.
    pub fn summary(&self, plan: &crate::eval::plan::ExecPlan) -> crate::events::SummaryReport {
        let (cpath, csecs) = trace::critical_path(plan, &self.events);
        crate::events::SummaryReport {
            built: self.built.len(),
            cached: self.cached.len(),
            failed: self.failed.len(),
            total: plan.nodes.len(),
            realize_ms: pool::realize_ms(),
            failures: self.failed.iter().map(|(name, _)| name.clone()).collect(),
            critical_path_secs: cpath.last().map(|_| format!("{:.1}s", csecs)),
            critical_path_tip: cpath.last().cloned(),
            critical_path_nodes: cpath.len(),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum AuditMode {
    Warn,
    Error,
}

// Internal helpers used across the sibling submodules below. Each module
// groups a coherent concern — staging, reference scanning, token resolution,
// env-hook construction, build-output capture, tool reporting, the per-build
// driver, the scheduler, the observability writers, and tests. The four
// moved siblings (sandbox / jobserver / depinfo / untar) remain independent.
mod env;
pub(crate) mod input_fetch;
mod json;
pub(crate) mod output;
mod refscan;
mod stage;
pub(crate) mod tokens;

pub(crate) mod builder;
pub(crate) mod module;

pub mod build;
pub mod pool;
pub mod report;
pub mod trace;

pub mod depinfo;
pub mod jobserver;
pub mod sandbox;
pub mod untar;

/// Dispatch engine-internal re-exec commands before a frontend interprets its
/// own CLI. NamespaceSandbox deliberately re-execs the current engine binary,
/// so every frontend that can realize derivations must share this seam.
pub fn is_internal_command(argv: &[String]) -> bool {
    matches!(
        argv.first().map(String::as_str),
        Some("__sandbox" | "__acquire-input")
    )
}

pub fn dispatch_internal_command(argv: &[String]) -> Option<Result<i32, String>> {
    if !is_internal_command(argv) {
        return None;
    }
    Some(
        if argv.first().map(String::as_str) == Some("__acquire-input") {
            input_fetch::dispatch(&argv[1..])
        } else {
            sandbox::run_helper(&argv[1..])
        },
    )
}

#[cfg(test)]
mod tests;
