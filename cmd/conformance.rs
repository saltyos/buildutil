// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — the executable conformance corpus runner
//!
//! Two golden suites under `tools/buildutil/conformance/` pin the semantics precisely
//! enough to reimplement against — "specified, not
//! folklore":
//!
//!  - Configuration cases: an option graph plus an override file, paired with an
//!    expected `config.keyval` (a valid resolve) or an expected diagnostic
//!    code (a resolve that must fail loudly). Resolved in process through
//!    mica, the library the engine and configuration commands share. Every keyval case is also a
//!    determinism check — the resolve is run twice and the two tables must
//!    be byte-identical — and an equality check between the in-process
//!    table and the `config.keyval` artifact `buildutil config resolve --out` writes.
//!  - Derivation cases: a declared derivation (`drv.toml`), host-portable
//!    because tool provider markers are given explicitly rather than resolved
//!    from whatever is on the host, paired with the expected canonical preimage
//!    (`expected.drv`) and hash (`expected.hash`). Run by constructing the
//!    `Derivation` and comparing `preimage()` / `hash()`.
//!  - `plan/case-*/`: a canonical evaluated action plan (`input.plan`) paired
//!    with its expected canonical bytes (`expected.plan`) and content hash
//!    (`expected.hash`). Run by loading and re-emitting the plan.
//!
//! `--bless` regenerates every expected file — the sanctioned way to re-pin
//! the corpus after a deliberate format change (e.g. the preimage format
//! bump), rather than hand-editing golden output.

use crate::spec::RefPolicy;
use crate::spec::toml;
use crate::store::derivation::{DepRef, Derivation, DrvParts};
use std::path::{Path, PathBuf};

/// Case directories (`case-*`) under `dir`, sorted by name.
fn case_dirs(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut cases = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read {}: {}", dir.display(), e))? {
        let entry = entry.map_err(|e| format!("entry: {}", e))?;
        if entry.path().is_dir() && entry.file_name().to_string_lossy().starts_with("case-") {
            cases.push(entry.path());
        }
    }
    cases.sort();
    Ok(cases)
}

/// Diagnostic codes (`E_*` / `W_*`) in first-seen order, de-duplicated.
fn diag_codes(diags: &[mica::config::diag::Diagnostic]) -> Vec<String> {
    let mut codes = Vec::new();
    for diag in diags {
        let code = diag.code.as_str().to_string();
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    codes
}

/// Resolve a case in process: its graph under its override file.
fn resolve_case(
    graph: &Path,
    config: &Path,
) -> Result<(String, Vec<String>), Vec<mica::config::diag::Diagnostic>> {
    let g = mica::config::load_graph(graph)?;
    let resolved = mica::config::resolve_layers(&g, Some(config), &[])?;
    let mut table = String::new();
    for (key, value) in mica::config::emit::keyval_rows(&g, &resolved) {
        table.push_str(&format!("{key}={value}\n"));
    }
    Ok((table, diag_codes(&resolved.warnings)))
}

/// The `config.keyval` artifact the library emits for the same inputs.
fn emitted_keyval(graph: &Path, config: &Path, out: &Path) -> Result<String, String> {
    let g = mica::config::load_graph(graph).map_err(|d| mica::config::render_diagnostics(&d))?;
    let resolved = mica::config::resolve_layers(&g, Some(config), &[])
        .map_err(|d| mica::config::render_diagnostics(&d))?;
    mica::config::emit::emit_all(&g, &resolved, out)
        .map_err(|e| format!("emit {}: {}", out.display(), e))?;
    std::fs::read_to_string(out.join("config.keyval"))
        .map_err(|e| format!("read emitted keyval: {}", e))
}

/// Run one configuration case. Returns Ok(true) on pass, Ok(false) on a checked
/// failure (already reported).
fn run_config_case(case: &Path, bless: bool, logger: &crate::log::Logger) -> Result<bool, String> {
    let name = case.file_name().unwrap_or_default().to_string_lossy();
    let graph = case.join("graph");
    let config = case.join("override.config");
    if !graph.is_dir() {
        return Err(format!("{}: no graph/ directory", name));
    }
    if !config.is_file() {
        return Err(format!("{}: no override.config", name));
    }
    let expect_keyval = case.join("expected.keyval");
    let expect_diag = case.join("expected.diag");

    // Mode: an existing expected file selects it; on --bless from scratch,
    // resolve success ⇒ keyval, failure ⇒ diag.
    let first = resolve_case(&graph, &config);
    let keyval_mode = if expect_keyval.is_file() {
        true
    } else if expect_diag.is_file() {
        false
    } else if bless {
        first.is_ok()
    } else {
        return Err(format!(
            "{}: no expected.keyval / expected.diag (run --bless)",
            name
        ));
    };

    let pass = if keyval_mode {
        match first {
            Err(diags) => {
                logger.error(
                    "check",
                    &format!(
                        "conformance config {}: FAIL — resolve errored but a keyval was expected:\n{}",
                        name,
                        mica::config::render_diagnostics(&diags)
                    ),
                );
                false
            }
            Ok((produced, _)) => {
                // Determinism: a second resolve must reproduce the table
                // byte for byte, and the emitted artifact must hold it.
                let second = resolve_case(&graph, &config).map(|(table, _)| table);
                let out = case.join(".out");
                let _ = std::fs::remove_dir_all(&out);
                let emitted = emitted_keyval(&graph, &config, &out);
                let _ = std::fs::remove_dir_all(&out);
                if second.as_ref().ok() != Some(&produced) {
                    logger.error(
                        "check",
                        &format!(
                            "conformance config {}: FAIL — resolve is non-deterministic",
                            name
                        ),
                    );
                    false
                } else if emitted.as_ref().ok() != Some(&produced) {
                    logger.error(
                        "check",
                        &format!(
                            "conformance config {}: FAIL — in-process values differ from the emitted config.keyval",
                            name
                        ),
                    );
                    false
                } else if bless {
                    std::fs::write(&expect_keyval, &produced)
                        .map_err(|e| format!("bless keyval: {}", e))?;
                    true
                } else {
                    let expected = std::fs::read_to_string(&expect_keyval).unwrap_or_default();
                    if expected == produced {
                        true
                    } else {
                        logger.error(
                            "check",
                            &format!("conformance config {}: FAIL — config.keyval mismatch", name),
                        );
                        false
                    }
                }
            }
        }
    } else {
        // Diagnostic case: resolve must fail and emit the expected codes.
        match first {
            Ok(_) => {
                logger.error(
                    "check",
                    &format!(
                        "conformance config {}: FAIL — resolve succeeded but a diagnostic was expected",
                        name
                    ),
                );
                false
            }
            Err(diags) => {
                let observed = diag_codes(&diags);
                if bless {
                    std::fs::write(&expect_diag, format!("{}\n", observed.join("\n")))
                        .map_err(|e| format!("bless diag: {}", e))?;
                    true
                } else {
                    let want: Vec<String> = std::fs::read_to_string(&expect_diag)
                        .unwrap_or_default()
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect();
                    let missing: Vec<&String> =
                        want.iter().filter(|c| !observed.contains(c)).collect();
                    if missing.is_empty() {
                        true
                    } else {
                        logger.error(
                            "check",
                            &format!(
                                "conformance config {}: FAIL — missing diagnostics {:?} (saw {:?})",
                                name, missing, observed
                            ),
                        );
                        false
                    }
                }
            }
        }
    };
    Ok(pass)
}

/// Parse `pairs = ["k=v", ...]` from a case's `drv.toml` into (k, v) tuples,
/// splitting on the FIRST `=` (values may contain `=`).
fn pairs(t: &toml::Table, key: &str) -> Vec<(String, String)> {
    t.get(key)
        .and_then(|v| v.str_items())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| {
            s.split_once('=')
                .map(|(a, b)| (a.to_string(), b.to_string()))
        })
        .collect()
}

fn list(t: &toml::Table, key: &str) -> Vec<String> {
    t.get(key).and_then(|v| v.str_items()).unwrap_or_default()
}

fn string(t: &toml::Table, key: &str) -> String {
    t.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Build a `Derivation` from a case's `drv.toml`.
fn derivation_from_case(case: &Path) -> Result<Derivation, String> {
    let doc = toml::parse_file(&case.join("drv.toml"))?;
    let t = doc
        .table(&[])
        .ok_or_else(|| "drv.toml: no root table".to_string())?;
    let deps = list(t, "deps")
        .into_iter()
        .map(|s| {
            // name=realization-digest[=provider-store-name]
            let mut it = s.splitn(3, '=');
            let name = it.next().unwrap_or("").to_string();
            let digest = it.next().unwrap_or("").to_string();
            let store_name = it
                .next()
                .map(|s| s.to_string())
                .unwrap_or_else(|| name.clone());
            DepRef {
                name,
                digest,
                store_name,
            }
        })
        .collect();
    Ok(Derivation::seal(DrvParts {
        name: string(t, "name"),
        arch: string(t, "arch"),
        builder: string(t, "builder"),
        tools: pairs(t, "tools"),
        env: pairs(t, "env"),
        srcs: pairs(t, "srcs"),
        srcdirs: pairs(t, "srcdirs"),
        source_roots: pairs(t, "source_roots"),
        source_overlays: pairs(t, "source_overlays"),
        copy: pairs(t, "copy"),
        stage_deps: pairs(t, "stage_deps"),
        allowed_refs: RefPolicy::None,
        deps,
        config: pairs(t, "config"),
        module_config: None,
        argv: list(t, "argv"),
        plan: list(t, "plan"),
        outputs: list(t, "outputs"),
    }))
}

/// Run one derivation-preimage case.
fn run_buildutil_case(
    case: &Path,
    bless: bool,
    logger: &crate::log::Logger,
) -> Result<bool, String> {
    let name = case.file_name().unwrap_or_default().to_string_lossy();
    let drv = derivation_from_case(case)?;
    let preimage = drv.preimage();
    let hash = drv.hash();
    let expect_drv = case.join("expected.drv");
    let expect_hash = case.join("expected.hash");
    if bless {
        std::fs::write(&expect_drv, &preimage).map_err(|e| format!("bless drv: {}", e))?;
        std::fs::write(&expect_hash, format!("{}\n", hash))
            .map_err(|e| format!("bless hash: {}", e))?;
        return Ok(true);
    }
    let want_drv = std::fs::read_to_string(&expect_drv)
        .map_err(|e| format!("{}: read expected.drv ({}) — run --bless", name, e))?;
    let want_hash = std::fs::read_to_string(&expect_hash)
        .map_err(|e| format!("{}: read expected.hash ({}) — run --bless", name, e))?
        .trim()
        .to_string();
    let mut ok = true;
    if want_drv != preimage {
        logger.error(
            "check",
            &format!("conformance buildutil {}: FAIL — preimage mismatch", name),
        );
        ok = false;
    }
    if want_hash != hash {
        logger.error(
            "check",
            &format!(
                "conformance buildutil {}: FAIL — hash mismatch (want {}, got {})",
                name, want_hash, hash
            ),
        );
        ok = false;
    }
    Ok(ok)
}

/// Run one action-plan case.
fn run_plan_case(case: &Path, bless: bool, logger: &crate::log::Logger) -> Result<bool, String> {
    let name = case.file_name().unwrap_or_default().to_string_lossy();
    let input = std::fs::read_to_string(case.join("input.plan"))
        .map_err(|e| format!("{}: read input.plan: {}", name, e))?;
    let plan = crate::eval::plan::parse(&input)?;
    let emitted = crate::eval::plan::render(&plan)?;
    let hash = crate::crypto::sha256::hash_bytes(emitted.as_bytes())[..32].to_string();
    let expect_plan = case.join("expected.plan");
    let expect_hash = case.join("expected.hash");
    if bless {
        std::fs::write(case.join("input.plan"), &emitted)
            .map_err(|e| format!("bless canonical input plan: {}", e))?;
        std::fs::write(&expect_plan, &emitted).map_err(|e| format!("bless plan: {}", e))?;
        std::fs::write(&expect_hash, format!("{}\n", hash))
            .map_err(|e| format!("bless plan hash: {}", e))?;
        return Ok(true);
    }
    let want_plan = std::fs::read_to_string(&expect_plan)
        .map_err(|e| format!("{}: read expected.plan ({}) — run --bless", name, e))?;
    let want_hash = std::fs::read_to_string(&expect_hash)
        .map_err(|e| format!("{}: read expected.hash ({}) — run --bless", name, e))?
        .trim()
        .to_string();
    let mut ok = true;
    if input != emitted || want_plan != emitted {
        logger.error(
            "check",
            &format!("conformance plan {}: FAIL — canonical bytes mismatch", name),
        );
        ok = false;
    }
    if want_hash != hash {
        logger.error(
            "check",
            &format!(
                "conformance plan {}: FAIL — hash mismatch (want {}, got {})",
                name, want_hash, hash
            ),
        );
        ok = false;
    }
    Ok(ok)
}

/// Run both conformance suites. `bless` regenerates all expected files.
pub fn run(root: &Path, bless: bool, logger: &crate::log::Logger) -> Result<i32, String> {
    let mut cases = 0usize;
    let mut failures = 0usize;

    let config_root = root.join("tools/buildutil/conformance/config");
    if config_root.is_dir() {
        for case in case_dirs(&config_root)? {
            cases += 1;
            match run_config_case(&case, bless, logger) {
                Ok(true) => {}
                Ok(false) => failures += 1,
                Err(e) => {
                    logger.error("check", &format!("conformance config: ERROR {}", e));
                    failures += 1;
                }
            }
        }
    }

    let buildutil_root = root.join("tools/buildutil/conformance/buildutil");
    if buildutil_root.is_dir() {
        for case in case_dirs(&buildutil_root)? {
            cases += 1;
            match run_buildutil_case(&case, bless, logger) {
                Ok(true) => {}
                Ok(false) => failures += 1,
                Err(e) => {
                    logger.error("check", &format!("conformance buildutil: ERROR {}", e));
                    failures += 1;
                }
            }
        }
    }

    let plan_root = root.join("tools/buildutil/conformance/plan");
    if plan_root.is_dir() {
        for case in case_dirs(&plan_root)? {
            cases += 1;
            match run_plan_case(&case, bless, logger) {
                Ok(true) => {}
                Ok(false) => failures += 1,
                Err(e) => {
                    logger.error("check", &format!("conformance plan: ERROR {}", e));
                    failures += 1;
                }
            }
        }
    }

    let msg = format!(
        "conformance: {}/{} cases {}{}",
        cases - failures,
        cases,
        if bless { "blessed" } else { "passed" },
        if failures == 0 { "" } else { " — FAILURES" }
    );
    if failures == 0 {
        logger.success("check", &msg);
    } else {
        logger.error("check", &msg);
    }
    Ok(if failures == 0 { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_codes_keep_first_seen_order_without_duplicates() {
        use mica::config::diag::{Code, Diagnostic};
        let diags = vec![
            Diagnostic::new(Code::ESelectHidden, "foo"),
            Diagnostic::new(Code::WChoiceRestored, "x"),
            Diagnostic::new(Code::ESelectHidden, "again"),
        ];
        assert_eq!(
            diag_codes(&diags),
            vec!["E_SELECT_HIDDEN", "W_CHOICE_RESTORED"]
        );
    }
}
