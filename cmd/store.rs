// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — store subcommands: ls/verify/gc/optimise/export/add-root/
//! add-indirect-root/sign/resign.

use std::path::{Path, PathBuf};

use super::{Args, flag_present, flag_value};

pub fn cmd_store(args: &Args) -> Result<i32, String> {
    let repo_root =
        std::env::current_dir().map_err(|e| format!("cannot determine repo root: {}", e))?;
    let store_root = args
        .store
        .clone()
        .or_else(|| std::env::var_os("BUILDUTIL_STORE").map(PathBuf::from))
        .unwrap_or_else(|| repo_root.join(".buildutil"));
    let st = crate::store::Store::open(&store_root)?;
    match args.targets.first().map(|s| s.as_str()) {
        Some("ls") => {
            for name in st.list()? {
                out!("{}", name);
            }
            Ok(0)
        }
        Some("verify") => {
            if flag_present(args, "--repair") {
                let lease = st.acquire_exclusive_lease()?;
                let evicted = st.verify_repair_with_lease(&lease)?;
                for name in &evicted {
                    crate::log::warn("store", &format!("evicted corrupt entry {}", name));
                }
                crate::log::success(
                    "store",
                    &format!("Evicted {} corrupt entries", evicted.len()),
                );
                Ok(0)
            } else {
                let corrupt = st.verify()?;
                for c in &corrupt {
                    crate::log::error("store", &format!("corrupt entry {}", c));
                }
                if corrupt.is_empty() {
                    crate::log::success("store", "Store verification found no corrupt entries");
                } else {
                    crate::log::error("store", &format!("Store verification found {} corrupt entries", corrupt.len()));
                }
                Ok(if corrupt.is_empty() { 0 } else { 1 })
            }
        }
        Some("gc") => {
            let world = flag_present(args, "--world");
            if args.argv.iter().any(|arg| arg == "--domain") && !world {
                return Err("store gc: --domain requires --world".to_string());
            }
            let prune_roots_older_than_days = match flag_value(args, "--prune-roots-older-than") {
                Some(value) => Some(value.parse::<u64>().map_err(|_| {
                    "store gc: --prune-roots-older-than needs a day count".to_string()
                })?),
                None => None,
            };
            let options = crate::store::GcOptions {
                dry_run: flag_present(args, "--dry-run"),
                prune_roots_older_than_days,
                policy: crate::store::GcPolicy {
                    max_age_days: flag_value(args, "--max-age").and_then(|v| v.parse().ok()),
                    min_free: flag_value(args, "--min-free").and_then(|v| v.parse().ok()),
                },
            };
            let lease = st.acquire_exclusive_lease()?;
            let mut seeded_roots = None;
            if world {
                let requested = world_targets(args);
                let mut desired = st.valid_roots_for_gc(
                    options.dry_run,
                    options.prune_roots_older_than_days,
                )?;
                let mut current = std::collections::BTreeMap::new();
                let mut owned: Option<std::collections::BTreeSet<String>> = None;
                for arch in ["x86_64", "aarch64"] {
                    let evaluated =
                        crate::cmd::build::evaluate_world_roots(args, arch, &requested)?;
                    current.extend(evaluated.roots);
                    if let Some(names) = evaluated.owned {
                        owned.get_or_insert_with(Default::default).extend(names);
                    }
                }
                desired.retain(|root, _store_name| {
                    let Some(rest) = root.strip_prefix("latest-") else {
                        return true;
                    };
                    // Without a domain this world owns every latest root;
                    // with one, only the roots of names in its closure.
                    match &owned {
                        None => false,
                        Some(names) => !["-x86_64", "-aarch64"].iter().any(|suffix| {
                            rest.strip_suffix(suffix)
                                .is_some_and(|name| names.contains(name))
                        }),
                    }
                });
                desired.extend(current);
                if !options.dry_run {
                    st.sync_latest_roots(&desired)?;
                }
                seeded_roots = Some(desired);
            }
            // Pass the repo_root so the gc can sweep the legacy
            // un-migrated text caches (cache/src-hash-cache,
            // cache/tool-id-cache) that lived under it pre-stat-cache.
            let report = if seeded_roots.is_some() {
                st.gc_report_seeded_with_lease(
                    &lease,
                    &options,
                    Some(&repo_root),
                    seeded_roots.as_ref(),
                    &mut print_gc_progress,
                )?
            } else {
                st.gc_report_with_lease(&lease, &options, Some(&repo_root), &mut print_gc_progress)?
            };
            crate::log::success("store", &format!(
                "GC {}{} store entries, {}{} tmp build dirs, cas_swept={}, plans_swept={}, {}{} legacy caches, {} reclaimed, {} active tmp skipped, {} roots scanned",
                if options.dry_run {
                    "would sweep "
                } else {
                    "swept "
                },
                report.store_swept.len(),
                if options.dry_run {
                    "would sweep "
                } else {
                    "swept "
                },
                report.tmp_swept.len(),
                report.cas_swept,
                report.plans_swept,
                if options.dry_run {
                    "would sweep "
                } else {
                    "swept "
                },
                report.legacy_caches_swept,
                format_bytes(report.bytes_reclaimed),
                report.active_tmp_skipped.len(),
                report.roots_scanned
            ));
            Ok(0)
        }
        Some("optimise") | Some("optimize") => {
            let lease = st.acquire_exclusive_lease()?;
            let (links, saved) = st.optimise_with_lease(&lease)?;
            crate::log::success(
                "store",
                &format!("Optimised the store: {} files hardlinked, {} bytes saved", links, saved),
            );
            Ok(0)
        }
        Some("export") => {
            let out = flag_value(args, "--out").ok_or("export: --out <dir> is required")?;
            let n = crate::store::substitute::export_store(&st, Path::new(out))?;
            crate::log::success("store", &format!("Exported {} entries to {}", n, out));
            Ok(0)
        }
        Some("add-root") => {
            let root_name = args.targets.get(1).ok_or("add-root: missing root name")?;
            let store_name = args.targets.get(2).ok_or("add-root: missing store dir")?;
            st.add_root(root_name, store_name)?;
            Ok(0)
        }
        Some("sign") => {
            let store_name = args.targets.get(1).ok_or("sign: missing store dir name")?;
            let key_path = args.targets.get(2).ok_or("sign: missing key file path")?;
            let seed = crate::store::substitute::read_seed(Path::new(key_path))?;
            crate::store::substitute::sign_realization(&st, store_name, &seed)?;
            crate::log::success("store", &format!("Signed the realization record of {}", store_name));
            Ok(0)
        }
        Some("add-indirect-root") => {
            let link = args
                .targets
                .get(1)
                .ok_or("add-indirect-root: name the link under the run directory")?;
            let link = std::path::absolute(link)
                .map_err(|e| format!("add-indirect-root: {e}"))?;
            let name = st.add_indirect_root(&link)?;
            out!("{name}");
            Ok(0)
        }
        Some("resign") => {
            let key_path = args.targets.get(1).ok_or("resign: missing key file path")?;
            let seed = crate::store::substitute::read_seed(Path::new(key_path))?;
            let count = crate::store::substitute::resign_realizations(&st, &seed)?;
            crate::log::success(
                "store",
                &format!("Signed {count} realization records under the current domain"),
            );
            Ok(0)
        }
        _ => Err(
            "store: expected ls | verify [--repair] | gc [--dry-run] [--max-age N] [--min-free N] [--prune-roots-older-than DAYS] [--world [TARGET...]] [--domain <packages group>] | \
             optimise | export --out <dir> | add-root | add-indirect-root <link> | sign | resign <key>"
                .to_string(),
        ),
    }
}

fn world_targets(args: &Args) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = args.argv.iter().skip_while(|arg| arg.as_str() != "gc");
    let _ = iter.next();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--max-age"
            | "--min-free"
            | "--prune-roots-older-than"
            | "--domain"
            | "--arch"
            | "--build-host"
            | "--backend"
            | "--store"
            | "--config"
            | "--jobs" => {
                let _ = iter.next();
            }
            "--world" | "--dry-run" | "--no-source-cache" | "-v" => {}
            value if value.starts_with('-') => {}
            value => out.push(value.to_string()),
        }
    }
    out
}

fn print_gc_progress(ev: crate::store::GcProgress) {
    match ev {
        // A phase is announced; roots and per-entry scanning are progress on
        // the status row; what is swept or skipped is reported, as Nix
        // reports each path it deletes.
        crate::store::GcProgress::Phase(name) => crate::log::announce("store", name),
        crate::store::GcProgress::Root(name) => {
            crate::events::emit_progress(&format!("Marking roots: {}", name))
        }
        crate::store::GcProgress::TempRoot(name) => {
            crate::events::emit_progress(&format!("Marking roots: temporary root {}", name))
        }
        crate::store::GcProgress::StoreScan {
            index,
            total,
            name,
            live,
            bytes,
        } => {
            let state = if live {
                "live".to_string()
            } else {
                format!("dead, {}", format_bytes(bytes))
            };
            crate::events::emit_progress(&format!(
                "Scanning store entries [{}/{}] {} ({})",
                index, total, name, state
            ));
        }
        crate::store::GcProgress::PlanStore {
            index,
            total,
            name,
            bytes,
        } => crate::events::emit_progress(&format!(
            "Planning sweep [{}/{}] {} ({})",
            index,
            total,
            name,
            format_bytes(bytes)
        )),
        crate::store::GcProgress::SweepTmp {
            index,
            total,
            name,
            bytes,
            dry_run,
        } => crate::log::info(
            "store",
            &format!(
                "GC {} tmp build dir [{}/{}] {} ({})",
                if dry_run { "would sweep" } else { "swept" },
                index,
                total,
                name,
                format_bytes(bytes)
            ),
        ),
        crate::store::GcProgress::SkipActiveTmp(name) => crate::log::info(
            "store",
            &format!("GC skipped active tmp build dir {}", name),
        ),
        crate::store::GcProgress::SweepStore {
            index,
            total,
            name,
            bytes,
            dry_run,
        } => crate::log::info(
            "store",
            &format!(
                "GC {} store entry [{}/{}] {} ({})",
                if dry_run { "would sweep" } else { "swept" },
                index,
                total,
                name,
                format_bytes(bytes)
            ),
        ),
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}
