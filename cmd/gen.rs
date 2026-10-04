// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — bootstrap ninja emission and module selfcheck.
//!
//! `MODULES` mirrors the full frontend tree; `MINIBUILDUTIL_MODULES` mirrors the
//! engine-only crate root. `cmd_gen` drift-checks both sets plus the mica and
//! composition libraries, then writes or verifies the frozen staged ninja.

const MODULES: &[&str] = &[
    "cmd/app.rs",
    "cmd/build.rs",
    "cmd/conformance.rs",
    "cmd/driver.rs",
    "cmd/engine.rs",
    "cmd/gen.rs",
    "cmd/generate.rs",
    "cmd/input_resolution.rs",
    "cmd/inputs.rs",
    "cmd/launch.rs",
    "cmd/mod.rs",
    "cmd/query.rs",
    "cmd/remote.rs",
    "cmd/report.rs",
    "cmd/store.rs",
    "cmd/usage.rs",
    "config/menuconfig/mod.rs",
    "config/menuconfig/paint.rs",
    "config/menuconfig/term.rs",
    "config/menuconfig/view.rs",
    "config/migrate.rs",
    "config/mod.rs",
    "crypto/crc.rs",
    "crypto/detseed.rs",
    "crypto/ed25519.rs",
    "crypto/mod.rs",
    "crypto/sha512.rs",
    "daemon/client.rs",
    "daemon/fsevents.rs",
    "daemon/inotify.rs",
    "daemon/mod.rs",
    "daemon/proto.rs",
    "daemon/server.rs",
    "daemon/state.rs",
    "daemon/watch.rs",
    "eval/cache.rs",
    "eval/graph.rs",
    "eval/mod.rs",
    "eval/ninja_emit.rs",
    "eval/observe.rs",
    "eval/plan/bootstrap.rs",
    "eval/plan/check.rs",
    "eval/plan/mod.rs",
    "eval/plan/tests.rs",
    "eval/plan/wire.rs",
    "events/mod.rs",
    "exec/build.rs",
    "exec/builder.rs",
    "exec/depinfo.rs",
    "exec/env.rs",
    "exec/inflate.rs",
    "exec/input_fetch.rs",
    "exec/jobserver.rs",
    "exec/json.rs",
    "exec/mod.rs",
    "exec/module.rs",
    "exec/output.rs",
    "exec/pool.rs",
    "exec/refscan.rs",
    "exec/report.rs",
    "exec/sandbox.rs",
    "exec/stage.rs",
    "exec/tests.rs",
    "exec/tokens.rs",
    "exec/trace.rs",
    "exec/untar.rs",
    "glob/mod.rs",
    "host/container.rs",
    "host/image.rs",
    "host/interrupt.rs",
    "host/mod.rs",
    "host/wsl.rs",
    "image/bootmanifest.rs",
    "image/cpio.rs",
    "image/disk.rs",
    "image/dump.rs",
    "image/fat.rs",
    "image/gpt.rs",
    "image/mod.rs",
    "image/rootfs.rs",
    "image/saltyfs/build.rs",
    "image/saltyfs/casefold.rs",
    "image/saltyfs/codec.rs",
    "image/saltyfs/mod.rs",
    "image/saltyfs/normalization_tables.rs",
    "image/saltyfs/primitives.rs",
    "image/saltyfs/read.rs",
    "image/saltyfs/read_graph.rs",
    "image/saltyfs/seal.rs",
    "image/saltyfs/sha256.rs",
    "image/saltyfs/snapshot_tests.rs",
    "image/saltyfs/tests.rs",
    "inputs/bootstrap.rs",
    "inputs/codec.rs",
    "inputs/content.rs",
    "inputs/mod.rs",
    "invocation/mod.rs",
    "license/header.rs",
    "license/mod.rs",
    "license/rules.rs",
    "license/tests.rs",
    "license/texts.rs",
    "license/walk.rs",
    "log/mod.rs",
    "paths/mod.rs",
    "platform/mod.rs",
    "source/filehash.rs",
    "source/filter.rs",
    "source/git.rs",
    "source/mod.rs",
    "source/statcache.rs",
    "source/tests.rs",
    "source/tree.rs",
    "source/worktree.rs",
    "spec/address.rs",
    "spec/builders.rs",
    "spec/configres.rs",
    "spec/inputs.rs",
    "spec/kinds.rs",
    "spec/mod.rs",
    "spec/modules.rs",
    "spec/required_checks.rs",
    "spec/stages.rs",
    "spec/tables.rs",
    "spec/tests.rs",
    "spec/toml.rs",
    "state/mod.rs",
    "store/derivation.rs",
    "store/gc.rs",
    "store/maintain.rs",
    "store/mod.rs",
    "store/register.rs",
    "store/remote.rs",
    "store/substitute.rs",
    "store/tests.rs",
    "term/mod.rs",
    "term/view.rs",
    "toolchain/builders.rs",
    "toolchain/mod.rs",
    "toolchain/portbuild.rs",
    "tools/mod.rs",
];

/// The reusable engine crate compiled by bootstrap.ninja. Entry roots and the
/// full-frontend extension directories are excluded from its on-disk
/// scan; everything remaining is an exact, drift-checked manifest.
const MINIBUILDUTIL_MODULES: &[&str] = &[
    "crypto/crc.rs",
    "crypto/detseed.rs",
    "crypto/ed25519.rs",
    "crypto/mod.rs",
    "crypto/sha512.rs",
    "eval/cache.rs",
    "eval/graph.rs",
    "eval/mod.rs",
    "eval/ninja_emit.rs",
    "eval/observe.rs",
    "eval/plan/bootstrap.rs",
    "eval/plan/check.rs",
    "eval/plan/mod.rs",
    "eval/plan/tests.rs",
    "eval/plan/wire.rs",
    "events/mod.rs",
    "exec/build.rs",
    "exec/builder.rs",
    "exec/depinfo.rs",
    "exec/env.rs",
    "exec/inflate.rs",
    "exec/input_fetch.rs",
    "exec/jobserver.rs",
    "exec/json.rs",
    "exec/mod.rs",
    "exec/module.rs",
    "exec/output.rs",
    "exec/pool.rs",
    "exec/refscan.rs",
    "exec/report.rs",
    "exec/sandbox.rs",
    "exec/stage.rs",
    "exec/tests.rs",
    "exec/tokens.rs",
    "exec/trace.rs",
    "exec/untar.rs",
    "glob/mod.rs",
    "inputs/bootstrap.rs",
    "inputs/codec.rs",
    "inputs/content.rs",
    "inputs/mod.rs",
    "invocation/mod.rs",
    "log/mod.rs",
    "paths/mod.rs",
    "platform/mod.rs",
    "source/filehash.rs",
    "source/filter.rs",
    "source/git.rs",
    "source/mod.rs",
    "source/statcache.rs",
    "source/tests.rs",
    "source/tree.rs",
    "source/worktree.rs",
    "spec/address.rs",
    "spec/builders.rs",
    "spec/configres.rs",
    "spec/inputs.rs",
    "spec/kinds.rs",
    "spec/mod.rs",
    "spec/modules.rs",
    "spec/required_checks.rs",
    "spec/stages.rs",
    "spec/tables.rs",
    "spec/tests.rs",
    "spec/toml.rs",
    "state/mod.rs",
    "store/derivation.rs",
    "store/gc.rs",
    "store/maintain.rs",
    "store/mod.rs",
    "store/register.rs",
    "store/remote.rs",
    "store/substitute.rs",
    "store/tests.rs",
    "term/mod.rs",
    "term/view.rs",
    "tools/mod.rs",
];

const BUILDUTIL_CRATE_ROOTS: &[&str] = &["inputcheck.rs", "main.rs", "minibuildutil.rs"];
const MINIBUILDUTIL_EXCLUDE: &[&str] = &[
    "cmd",
    "config",
    "daemon",
    "host",
    "image",
    "license",
    "toolchain",
];

const BOOTSTRAP_HOSTS: &[&str] = &[
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

/// Composition's module siblings of `lib.rs` (byte-sorted; `lib.rs` is the
/// crate root, named separately by its library rule). `bin/` holds
/// the two store-tool CLI entry points (`buildutil-compose`, `buildutil-sysroot`) —
/// their own derivations, not part of `libbuildutil_compose.rlib` — so it is
/// excluded from this scan (see `BUILDUTIL_COMPOSE_EXCLUDE`).
const BUILDUTIL_COMPOSE_MODULES: &[&str] = &[
    "glob.rs",
    "manifest.rs",
    "paths.rs",
    "platform.rs",
    "projection.rs",
    "sysroot.rs",
];

/// Top-level subdirs of `tools/buildutil/compose` that hold separate binaries
/// rather than `libbuildutil_compose.rlib` modules.
const BUILDUTIL_COMPOSE_EXCLUDE: &[&str] = &["bin"];

/// The configuration library's modules beside `lib.rs`, the bootstrap's
/// prerequisites for its rlib.
const MICA_MODULES: &[&str] = &["ast.rs", "eval.rs", "lexer.rs", "parser.rs", "tests.rs", "vercmp.rs"];

pub(super) fn bootstrap_ninja(_repo_root: &std::path::Path) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("# SPDX-License-Identifier: GPL-2.0-only\n");
    out.push_str("# tools/buildutil/bootstrap.ninja — FROZEN. Regenerate: buildutil gen\n");
    out.push_str(
        "# Stage 0 builds minibuildutil; minibuildutil realizes the full native frontend.\n",
    );
    out.push_str("builddir = .buildutil/tmp/bootstrap-ninja\n");
    out.push_str("rule rustcid\n");
    out.push_str(
        "  command = outdir=$$(dirname $out) && mkdir -p $$outdir && tmp=$out.tmp.$$$$ && { printf 'rustc-command: %s\\n' \"$${BUILDUTIL_RUSTC:-rustc}\"; command -v \"$${BUILDUTIL_RUSTC:-rustc}\" 2>/dev/null | sed 's/^/rustc-path: /'; \"$${BUILDUTIL_RUSTC:-rustc}\" -vV; printf 'linker-command: %s\\n' \"$${BUILDUTIL_LINKER:-cc}\"; command -v \"$${BUILDUTIL_LINKER:-cc}\" 2>/dev/null | sed 's/^/linker-path: /'; \"$${BUILDUTIL_LINKER:-cc}\" --version 2>/dev/null || true; } > $$tmp && if test -f $out && cmp -s $out $$tmp; then rm $$tmp; else mv $$tmp $out; fi\n",
    );
    out.push_str("  description = BOOTSTRAP $out\n");
    out.push_str("  restat = 1\n");
    out.push_str("rule inputcheckc\n");
    out.push_str("  command = $${BUILDUTIL_RUSTC:-rustc} --edition=2024 -O -o $out $in\n");
    out.push_str("  description = BOOTSTRAP $out\n");
    out.push_str("rule micac\n");
    out.push_str("  command = $${BUILDUTIL_RUSTC:-rustc} --edition=2024 -O --crate-type=lib --crate-name=mica -o $out $in\n");
    out.push_str("  description = BOOTSTRAP $out\n");
    out.push_str("rule minibuildutilc\n");
    out.push_str(
        "  command = $${BUILDUTIL_RUSTC:-rustc} --edition=2024 -O --extern mica=$mica_rlib -L $mica_dir -o $out $in\n",
    );
    out.push_str("  description = BOOTSTRAP $out\n");
    out.push_str("rule selfhost\n");
    out.push_str(
        "  command = $minibuildutil --repo-root \"$${BUILDUTIL_SELFHOST_REPO_ROOT:-.}\" --state-root \"$${BUILDUTIL_SELFHOST_STATE_ROOT:-.buildutil}\" --rustc \"$${BUILDUTIL_RUSTC:-rustc}\" --linker \"$${BUILDUTIL_LINKER:-cc}\" --rustc-identity $rustc_identity --output $out --exec-host $exec_host\n",
    );
    out.push_str("  description = SELFHOST $out\n");
    out.push_str("rule bootstrap_no_default\n");
    out.push_str(
        "  command = echo 'bootstrap: use ./buildutil, or name .buildutil/bootstrap/<exec-host>/buildutil explicitly' >&2; false\n",
    );
    out.push_str("  description = BOOTSTRAP select host\n");
    out.push_str("build FORCE: phony\n");
    out.push_str("build bootstrap-select-host: bootstrap_no_default\n");
    for host in BOOTSTRAP_HOSTS {
        let dir = format!(".buildutil/bootstrap/{host}");
        out.push_str(&format!("build {dir}/rustc.vv: rustcid FORCE\n"));
        out.push_str(&format!(
            "build {dir}/inputcheck: inputcheckc {engine}/inputcheck.rs | {dir}/rustc.vv",
            engine = crate::paths::BUILDUTIL
        ));
        for module in [
            "inputs/bootstrap.rs",
            "inputs/codec.rs",
            "inputs/content.rs",
            "source/filter.rs",
            "spec/toml.rs",
            "glob/mod.rs",
        ] {
            out.push_str(&format!(" $\n    {}/{}", crate::paths::BUILDUTIL, module));
        }
        out.push_str(" $\n    tools/buildutil/lib/crypto/sha256.rs\n");
        out.push_str(&format!(
            "build {dir}/libmica.rlib: micac {mica}/lib.rs | {dir}/rustc.vv",
            mica = crate::paths::MICA,
        ));
        for module in MICA_MODULES {
            out.push_str(&format!(" $\n    {}/{}", crate::paths::MICA, module));
        }
        out.push('\n');
        out.push_str(&format!(
            "build {dir}/minibuildutil: minibuildutilc {engine}/minibuildutil.rs | {dir}/libmica.rlib {dir}/rustc.vv",
            engine = crate::paths::BUILDUTIL,
        ));
        for module in MINIBUILDUTIL_MODULES {
            out.push_str(&format!(" $\n    {}/{}", crate::paths::BUILDUTIL, module));
        }
        out.push_str(" $\n    tools/buildutil/lib/crypto/sha256.rs");
        out.push_str(&format!(" $\n    {}", crate::paths::SDK_WIRE));
        out.push('\n');
        out.push_str(&format!("  mica_rlib = {dir}/libmica.rlib\n"));
        out.push_str(&format!("  mica_dir = {dir}\n"));
        out.push_str(&format!(
            "build {dir}/buildutil: selfhost {dir}/minibuildutil {dir}/rustc.vv FORCE\n"
        ));
        out.push_str(&format!("  minibuildutil = {dir}/minibuildutil\n"));
        out.push_str(&format!("  rustc_identity = {dir}/rustc.vv\n"));
        out.push_str(&format!("  exec_host = {host}\n"));
    }
    out.push_str("default bootstrap-select-host\n");
    Ok(out)
}

/// Recursively collect a source subtree's `*.rs` module paths, relative to
/// `base`, slash-joined, byte-sorted, with `crate_root` (the crate's root file,
/// named separately by its ninja rule) excluded. `exclude_dirs` names
/// top-level subdirs to skip entirely (e.g. a crate's separately-derived
/// `bin/` CLI entry points that are not part of its library rlib). The
/// on-disk truth a module manifest const must mirror.
fn scan_rs_modules(
    base: &std::path::Path,
    crate_roots: &[&str],
    exclude_dirs: &[&str],
) -> Result<Vec<String>, String> {
    fn walk(
        base: &std::path::Path,
        rel: &str,
        crate_roots: &[&str],
        exclude_dirs: &[&str],
        out: &mut Vec<String>,
    ) -> Result<(), String> {
        for entry in std::fs::read_dir(base.join(rel))
            .map_err(|e| format!("cannot scan {}: {}", base.join(rel).display(), e))?
        {
            let entry = entry.map_err(|e| format!("scan entry: {}", e))?;
            let name = entry.file_name().to_string_lossy().to_string();
            let child = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let path = entry.path();
            if path.is_dir() {
                if exclude_dirs.contains(&child.as_str()) {
                    continue;
                }
                walk(base, &child, crate_roots, exclude_dirs, out)?;
            } else if path.is_file()
                && name.ends_with(".rs")
                && !crate_roots.contains(&child.as_str())
            {
                out.push(child);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(base, "", crate_roots, exclude_dirs, &mut out)?;
    out.sort();
    Ok(out)
}

/// Fail if a module-manifest const has drifted from the on-disk `*.rs` set — the
/// failure a bootstrap generated from a stale manifest would bake in silently (a
/// new module would drop out of the crate's ninja rebuild dependency edges).
fn check_manifest(label: &str, on_disk: &[String], declared: &[&str]) -> Result<(), String> {
    let declared: Vec<String> = declared.iter().map(|m| m.to_string()).collect();
    if on_disk == declared {
        return Ok(());
    }
    let missing: Vec<&String> = on_disk.iter().filter(|m| !declared.contains(m)).collect();
    let extra: Vec<&String> = declared.iter().filter(|m| !on_disk.contains(m)).collect();
    Err(format!(
        "{label} drift — update the const and run `buildutil gen`.\n  on disk, not in const: {:?}\n  in const, not on disk: {:?}",
        missing, extra
    ))
}

pub fn cmd_gen(args: &super::Args) -> Result<i32, String> {
    let repo_root =
        std::env::current_dir().map_err(|e| format!("cannot determine repo root: {}", e))?;
    check_manifest(
        "MODULES",
        &scan_rs_modules(
            &repo_root.join(crate::paths::BUILDUTIL),
            BUILDUTIL_CRATE_ROOTS,
            &[],
        )?,
        MODULES,
    )?;
    check_manifest(
        "MINIBUILDUTIL_MODULES",
        &scan_rs_modules(
            &repo_root.join(crate::paths::BUILDUTIL),
            BUILDUTIL_CRATE_ROOTS,
            MINIBUILDUTIL_EXCLUDE,
        )?,
        MINIBUILDUTIL_MODULES,
    )?;
    check_manifest(
        "BUILDUTIL_COMPOSE_MODULES",
        &scan_rs_modules(
            &repo_root.join(crate::paths::BUILDUTIL_COMPOSE),
            &["lib.rs"],
            BUILDUTIL_COMPOSE_EXCLUDE,
        )?,
        BUILDUTIL_COMPOSE_MODULES,
    )?;
    let path = repo_root.join(crate::paths::BOOTSTRAP_NINJA);
    let generated = bootstrap_ninja(&repo_root)?;
    if args.selfcheck {
        let existing = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        if existing == generated {
            crate::log::success("gen", "bootstrap.ninja is in sync");
            Ok(0)
        } else {
            crate::log::error(
                "gen",
                "bootstrap.ninja has drifted; run `buildutil gen` and commit the result",
            );
            Ok(1)
        }
    } else {
        std::fs::write(&path, generated)
            .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        crate::log::info("gen", &format!("wrote {}", path.display()));
        Ok(0)
    }
}
