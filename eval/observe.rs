//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — read-only build introspection
//!
//! `why-depends` / `graph --dot` / `explain` / `log`, all computed over
//! retained state — the spec graph, canonical drv texts, meta, logs, and GC
//! roots — with no build side effects.

use super::graph;
use crate::spec::Spec;
use crate::spec::configres::Config;
use crate::store::Store;
use crate::tools::Toolchain;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Adjacency: derivation name → dependency names (build-time; plus a realized
/// entry's `runtime-dep:` closure edges when `runtime`).
fn adjacency(spec: &Spec, store: &Store, runtime: bool) -> BTreeMap<String, Vec<String>> {
    let mut adj: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, d) in &spec.drvs {
        let mut deps = d.deps.clone();
        if runtime {
            if let Some(sn) = store.read_root(&format!("latest-{}-{}", name, spec.arch)) {
                if let Ok(meta) = store.read_meta(&sn) {
                    deps.extend(meta.runtime_deps);
                }
            }
        }
        adj.insert(name.clone(), deps);
    }
    adj
}

/// `buildutil why-depends <from> <to> [--runtime]` — a shortest dependency path.
pub fn why_depends(
    spec: &Spec,
    store: &Store,
    from: &str,
    to: &str,
    runtime: bool,
    domain: Option<&BTreeSet<String>>,
) -> Result<i32, String> {
    if !spec.drvs.contains_key(from) {
        return Err(format!("why-depends: unknown derivation `{}`", from));
    }
    // `--domain` restricts the search to one group's closure: the source must
    // be in it, and traversal never leaves it (a `to` outside it is simply
    // unreachable → "no path").
    if let Some(members) = domain {
        if !members.contains(from) {
            return Err(format!("why-depends: `{from}` is outside the --domain closure"));
        }
    }
    let adj = adjacency(spec, store, runtime);
    let mut prev: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(from.to_string());
    seen.insert(from.to_string());
    let mut found = from == to;
    while let Some(node) = queue.pop_front() {
        if node == to {
            found = true;
            break;
        }
        if let Some(deps) = adj.get(&node) {
            for dep in deps {
                let dep = crate::spec::variant_base(&spec.variants, dep);
                if let Some(members) = domain {
                    if !members.contains(dep) {
                        continue;
                    }
                }
                if seen.insert(dep.to_string()) {
                    prev.insert(dep.to_string(), node.clone());
                    queue.push_back(dep.to_string());
                }
            }
        }
    }
    if !found {
        out!("no dependency path from `{}` to `{}`", from, to);
        return Ok(1);
    }
    let mut path = vec![to.to_string()];
    let mut cur = to.to_string();
    while cur != from {
        let Some(p) = prev.get(&cur).cloned() else {
            break;
        };
        path.push(p.clone());
        cur = p;
    }
    path.reverse();
    out!("{}", path.join(" -> "));
    Ok(0)
}

/// `buildutil graph [<target>] --dot` — DOT export of the (sub)graph.
pub fn graph_dot(
    spec: &Spec,
    roots: Option<&[String]>,
    domain: Option<&BTreeSet<String>>,
) -> Result<i32, String> {
    let names: Vec<String> = match roots {
        Some(roots) => graph::closure(spec, roots)?,
        None => spec.drvs.keys().cloned().collect(),
    };
    // `--domain` renders only that group's closure (and the edges among it).
    let names: Vec<String> = match domain {
        Some(members) => names.into_iter().filter(|n| members.contains(n)).collect(),
        None => names,
    };
    let set: BTreeSet<&str> = names.iter().map(|s| s.as_str()).collect();
    out!("digraph buildutil {{");
    out!("  rankdir=LR;");
    for name in &names {
        for dep in &spec.drvs[name].deps {
            let dep = crate::spec::variant_base(&spec.variants, dep);
            if set.contains(dep) {
                out!("  \"{}\" -> \"{}\";", name, dep);
            }
        }
    }
    out!("}}");
    Ok(0)
}

/// The store entry a query names: the latest root of a plain name, or for a
/// configured address the entry its node realizes under the current
/// evaluation, if realized.
fn entry_of(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    store: &Store,
    target: &str,
    git_state: &(String, String),
) -> Result<Option<String>, String> {
    if matches!(
        crate::spec::address::parse(target)?,
        crate::spec::address::Address::Plain(_)
    ) {
        return Ok(store.read_root(&format!("latest-{}-{}", target, spec.arch)));
    }
    let evaluated = graph::evaluate(spec, config, toolchain, &[target.to_string()], git_state)?;
    let resolved = evaluated.dry_resolve(store);
    Ok(evaluated
        .roots
        .first()
        .and_then(|(_, key)| resolved.get(key))
        .filter(|node| node.digest.is_some())
        .map(|node| node.store_name.clone()))
}

/// `buildutil log <target>` — the retained build log of the last realization,
/// and where its retained artifacts are.
pub fn log(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    store: &Store,
    target: &str,
    git_state: &(String, String),
) -> Result<i32, String> {
    let Some(sn) = entry_of(spec, config, toolchain, store, target, git_state)? else {
        return Err(format!(
            "log: `{}` has no realized root (build it first)",
            target
        ));
    };
    let text = std::fs::read_to_string(store.log_path(&sn))
        .map_err(|e| format!("log: cannot read log for `{}`: {}", target, e))?;
    crate::term::result_raw(text.as_bytes());
    let artifacts = store.artifacts_path(&sn);
    if artifacts.is_dir() {
        crate::log::info("log", &format!("retained artifacts: {}", artifacts.display()));
    }
    Ok(0)
}

/// `buildutil explain <target>` — the rebuild cause: a section-wise diff of the
/// finalized preimage against the last realized `.drv` for the same
/// `name-arch`.
pub fn explain(
    spec: &Spec,
    config: &Config,
    toolchain: &mut Toolchain,
    store: &Store,
    target: &str,
    git_state: &(String, String),
) -> Result<i32, String> {
    let targets = [target.to_string()];
    let evaluated = graph::evaluate(spec, config, toolchain, &targets, git_state)?;
    let drvs = evaluated.dry_resolve(store);
    let key = evaluated
        .roots
        .first()
        .map(|(_, key)| key.clone())
        .ok_or_else(|| format!("explain: `{target}` is disabled by configuration"))?;
    let Some(r) = drvs.get(&key) else {
        return Err(format!(
            "explain: `{}`'s dependencies are not all realized; realize them first",
            target
        ));
    };
    let current = r.drv.preimage();

    let Some(last_sn) = entry_of(spec, config, toolchain, store, target, git_state)? else {
        out!(
            "`{}` has never been realized — a build would create it.",
            target
        );
        return Ok(0);
    };
    let last_path = store
        .state_dir()
        .join("drv")
        .join(format!("{}.drv", last_sn));
    let last = std::fs::read_to_string(&last_path).unwrap_or_default();
    if last == current {
        out!("`{}` is up to date — its preimage is unchanged.", target);
        return Ok(0);
    }

    let (added, removed) = preimage_diff(&last, &current);
    out!("`{}` would rebuild — preimage differs:", target);
    for line in &added {
        out!("  + {}", line);
    }
    for line in &removed {
        out!("  - {}", line);
    }
    Ok(0)
}

/// The `(added, removed)` preimage lines between the last realization and the
/// current one, in file order. Each line carries its section prefix
/// (`src:` / `config:` / `tool:` / …), so the diff directly names what
/// changed — the rebuild cause.
pub fn preimage_diff(old: &str, new: &str) -> (Vec<String>, Vec<String>) {
    let old_set: BTreeSet<&str> = old.lines().collect();
    let new_set: BTreeSet<&str> = new.lines().collect();
    let added = new
        .lines()
        .filter(|l| !old_set.contains(*l))
        .map(String::from)
        .collect();
    let removed = old
        .lines()
        .filter(|l| !new_set.contains(*l))
        .map(String::from)
        .collect();
    (added, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_names_the_changed_lines() {
        let old =
            "buildutil-drv\nformat: 2\nsrc: a.c=sha256:AAA\nconfig: LEVEL=info\ntool: cc=sha256:1;cc\n";
        let new =
            "buildutil-drv\nformat: 2\nsrc: a.c=sha256:BBB\nconfig: LEVEL=debug\ntool: cc=sha256:2;cc\n";
        let (added, removed) = preimage_diff(old, new);
        assert!(added.contains(&"src: a.c=sha256:BBB".to_string()));
        assert!(added.contains(&"config: LEVEL=debug".to_string()));
        assert!(added.contains(&"tool: cc=sha256:2;cc".to_string()));
        assert!(removed.contains(&"src: a.c=sha256:AAA".to_string()));
        assert!(removed.contains(&"config: LEVEL=info".to_string()));
        // Unchanged lines are reported in neither list.
        assert!(!added.iter().any(|l| l.starts_with("format:")));
        assert!(!removed.iter().any(|l| l.starts_with("format:")));
    }
}
