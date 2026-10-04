//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — realize/exec test suite (staging, refscan, tokens, env, output,
//! pool integration, declared-hash untar)

use super::AuditMode;
use super::build::BuildDirFailureGuard;
use super::env::apply_setup_env_file;
use super::output::{BuildOutput, Framed};
use super::pool::realize;
use super::refscan::{
    allowed_store_refs, contains_path_token, scan_references, store_entry_drv_name,
};
use super::sandbox::AuditSandbox;
use super::sandbox::OutputStream;
use super::stage::{
    hardlink_or_copy, materialize_source_overlay, stage_local_symlink_target, stage_source_root,
};
use super::tokens::resolve_exec_tokens;
use super::trace::critical_path;
use crate::eval::graph::{Evaluated, Recipe};
use crate::eval::plan::ExecPlan;
use crate::spec::{DrvSpec, RefPolicy, Spec};
use crate::store::Store;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn internal_command_dispatch_claims_namespace_helper() {
    let argv = vec!["__sandbox".to_string()];
    assert!(super::is_internal_command(&argv));
    assert!(super::dispatch_internal_command(&argv).is_some());
}

#[test]
fn internal_command_dispatch_leaves_frontend_commands_alone() {
    let argv = vec!["build".to_string(), "default".to_string()];
    assert!(!super::is_internal_command(&argv));
    assert!(super::dispatch_internal_command(&argv).is_none());
}

#[test]
fn internal_command_classifier_does_not_claim_near_matches() {
    for command in ["sandbox", "__sandboxed", "__realize-plan", "build"] {
        assert!(!super::is_internal_command(&[command.to_string()]));
    }
}

#[test]
fn contains_path_token_matches_at_boundaries() {
    // A path token: the byte after the match is a boundary.
    assert!(contains_path_token(b"HOME=/build", b"/build"));
    assert!(contains_path_token(b"-L/build/stage/dep/x", b"/build"));
    assert!(contains_path_token(b"cc=\"/build\"", b"/build"));
    assert!(contains_path_token(b"a:/build:b", b"/build"));
    assert!(contains_path_token(
        &[b'/', b'b', b'u', b'i', b'l', b'd', 0],
        b"/build"
    ));
    // A longer path component is NOT a match.
    assert!(!contains_path_token(b"/buildroot/x", b"/build"));
    assert!(!contains_path_token(b"abc", b""));
    assert!(!contains_path_token(b"abc", b"abcd"));
}

#[test]
fn dep_abs_exec_token_resolves_to_staged_absolute_path() {
    let drv = crate::store::derivation::Derivation::seal(crate::store::derivation::DrvParts {
        name: "uses-cmake".to_string(),
        arch: "x86_64".to_string(),
        builder: "script-dag".to_string(),
        tools: vec![],
        env: vec![],
        srcs: vec![],
        srcdirs: vec![],
        source_roots: vec![],
        source_overlays: vec![],
        copy: vec![],
        stage_deps: vec![],
        allowed_refs: RefPolicy::None,
        deps: vec![crate::store::derivation::DepRef {
            name: "host-llvm".to_string(),
            digest: "digest".to_string(),
            store_name: "hash-host-llvm".to_string(),
        }],
        config: vec![],
        module_config: None,
        argv: vec![],
        plan: vec![],
        outputs: vec![],
    });
    let stage = Path::new("/tmp/buildutil-build/stage");

    // Host-side / audit-grade expansion (`dep_rel = false`): always the real
    // passed-in stage path, on every platform — there is no sandbox
    // indirection to route through.
    let host_resolved = resolve_exec_tokens(
        "{dep-abs:host-llvm}/bin/clang {srcroot-abs} {out-abs}",
        Path::new(".."),
        Path::new("../../out"),
        stage,
        &drv,
        false,
    )
    .unwrap();
    assert!(host_resolved.contains("/tmp/buildutil-build/stage/dep/host-llvm/bin/clang"));
    assert!(host_resolved.contains("/tmp/buildutil-build/stage"));
    assert!(host_resolved.contains("/tmp/buildutil-build/out"));

    // Builder-facing expansion (`dep_rel = true`): on Linux the enforcing
    // namespace sandbox bind-mounts the build dir at the constant
    // `SANDBOX_BUILD` regardless of the host-side stage path, so this must
    // resolve there instead (see `resolve_exec_tokens`'s `sandbox_abs`
    // branch); every other platform has no such sandbox and still sees the
    // real stage path.
    let dep_resolved = resolve_exec_tokens(
        "{dep-abs:host-llvm}/bin/clang {srcroot-abs} {out-abs}",
        Path::new(".."),
        Path::new("../../out"),
        stage,
        &drv,
        true,
    )
    .unwrap();
    let (expected_stage, expected_out) = if cfg!(target_os = "linux") {
        (
            format!("{}/stage", super::sandbox::SANDBOX_BUILD),
            format!("{}/out", super::sandbox::SANDBOX_BUILD),
        )
    } else {
        (
            "/tmp/buildutil-build/stage".to_string(),
            "/tmp/buildutil-build/out".to_string(),
        )
    };
    assert!(dep_resolved.contains(&format!("{expected_stage}/dep/host-llvm/bin/clang")));
    assert!(dep_resolved.contains(&expected_stage));
    assert!(dep_resolved.contains(&expected_out));
}

#[test]
fn store_entry_names_parse_back_out_of_store_names() {
    let h = "a".repeat(32);
    assert_eq!(
        store_entry_drv_name(&format!("{h}-cross-llvm-aarch64")),
        Some("cross-llvm")
    );
    assert_eq!(
        store_entry_drv_name(&format!("{h}-src-musl-any")),
        Some("src-musl")
    );
    assert_eq!(
        store_entry_drv_name(&format!("{h}-host-llvm-host-aarch64-unknown-linux-musl")),
        Some("host-llvm")
    );
    assert_eq!(
        store_entry_drv_name(&format!("{h}-core-x86_64")),
        Some("core")
    );
    assert_eq!(store_entry_drv_name("short"), None);
    assert_eq!(store_entry_drv_name(&format!("{h}xnodash-y")), None);
}

#[test]
fn failed_build_dir_guard_deletes_by_default_and_keeps_when_requested() {
    let base = std::env::temp_dir().join(format!("buildutil-keep-failed-{}", std::process::id()));
    let delete_dir = base.join("delete.build");
    let keep_dir = base.join("keep.build");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&delete_dir).unwrap();
    std::fs::write(delete_dir.join("artifact"), "failed").unwrap();
    {
        let _guard = BuildDirFailureGuard::new(true, delete_dir.clone(), false);
    }
    assert!(!delete_dir.exists());

    std::fs::create_dir_all(&keep_dir).unwrap();
    std::fs::write(keep_dir.join("artifact"), "failed").unwrap();
    {
        let _guard = BuildDirFailureGuard::new(true, keep_dir.clone(), true);
    }
    assert!(keep_dir.join("artifact").is_file());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn setup_env_hook_merges_paths_and_flags() {
    let base = std::env::temp_dir().join(format!("buildutil-setup-env-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let hook = base.join("setup-env");
    std::fs::write(
        &hook,
        "\
# buildutil setup-env v1
append-path PKG_CONFIG_LIBDIR usr/lib/aarch64-linux-gnu/pkgconfig
set-path PKG_CONFIG_SYSROOT_DIR .
append-flag BUILDUTIL_CFLAGS_COMPILE -isystem usr/include
append-flag BUILDUTIL_CFLAGS_COMPILE -isystem usr/include/aarch64-linux-gnu
append-flag BUILDUTIL_LDFLAGS -L usr/lib/aarch64-linux-gnu
",
    )
    .unwrap();
    let mut env = vec![("BUILDUTIL_CFLAGS_COMPILE".to_string(), "-DOLD".to_string())];
    apply_setup_env_file(&mut env, &hook, Path::new("/build/stage/dep/host-rust-dev")).unwrap();
    let get = |key: &str| {
        env.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    assert_eq!(
        get("PKG_CONFIG_LIBDIR"),
        "/build/stage/dep/host-rust-dev/usr/lib/aarch64-linux-gnu/pkgconfig"
    );
    assert_eq!(
        get("PKG_CONFIG_SYSROOT_DIR"),
        "/build/stage/dep/host-rust-dev"
    );
    assert_eq!(
        get("BUILDUTIL_CFLAGS_COMPILE"),
        "-DOLD -isystem /build/stage/dep/host-rust-dev/usr/include -isystem /build/stage/dep/host-rust-dev/usr/include/aarch64-linux-gnu"
    );
    assert_eq!(
        get("BUILDUTIL_LDFLAGS"),
        "-L /build/stage/dep/host-rust-dev/usr/lib/aarch64-linux-gnu"
    );
    let _ = std::fs::remove_dir_all(&base);
}

fn framed(chunks: &[(OutputStream, &[u8])]) -> Vec<(String, OutputStream)> {
    let seen = std::sync::Mutex::new(Vec::new());
    let emit = |framed: Framed<'_>| {
        if let Framed::Line(line, stream) = framed {
            seen.lock().unwrap().push((line.to_string(), stream));
        }
    };
    let output = BuildOutput::new(&emit);
    for (stream, bytes) in chunks {
        output.ingest(*stream, bytes);
    }
    output.finish();
    drop(output);
    seen.into_inner().unwrap()
}

#[test]
fn build_output_keeps_indentation_and_blank_lines() {
    let lines = framed(&[(
        OutputStream::Stderr,
        b"warning: unused\n  --> a.rs:1:2\n   |\n\nnext  \n",
    )]);
    let text: Vec<&str> = lines.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(
        text,
        vec!["warning: unused", "  --> a.rs:1:2", "   |", "", "next"]
    );
}

#[test]
fn build_output_frames_each_stream_separately() {
    let lines = framed(&[
        (OutputStream::Stdout, b"[1/2] CC a"),
        (OutputStream::Stderr, b"warn"),
        (OutputStream::Stdout, b".o\n"),
        (OutputStream::Stderr, b"ing\n"),
    ]);
    assert_eq!(
        lines,
        vec![
            ("[1/2] CC a.o".to_string(), OutputStream::Stdout),
            ("warning".to_string(), OutputStream::Stderr),
        ]
    );
}

#[test]
fn build_output_overwrites_on_carriage_return_and_flushes_the_last_line() {
    let lines = framed(&[(OutputStream::Stdout, b"10%\r50%\r100%\ndone\r\ntail")]);
    let text: Vec<&str> = lines.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(text, vec!["100%", "done", "tail"]);
}

#[test]
fn stage_local_symlink_target_keeps_overlay_inside_stage() {
    let stage = Path::new("/tmp/build/stage");
    let target = stage.join("dep/rust-vendor/vendor");
    let link = stage.join("toolchain/rust/vendor");
    assert_eq!(
        stage_local_symlink_target(stage, &target, &link),
        PathBuf::from("../../dep/rust-vendor/vendor")
    );
    let external = Path::new("/store/rust-vendor/vendor");
    assert_eq!(
        stage_local_symlink_target(stage, external, &link),
        PathBuf::from("/store/rust-vendor/vendor")
    );
}

#[test]
fn source_overlay_materializes_dep_tree_without_stage_symlink() {
    let base = std::env::temp_dir().join(format!(
        "buildutil-source-overlay-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let src = base.join("store/hash-rust-vendor/vendor");
    let stage = base.join("build/stage");
    let dest = stage.join("toolchain/rust/vendor");
    let real_checkout = base.join("repo/toolchain/rust");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(src.join("crate/src")).unwrap();
    std::fs::create_dir_all(&real_checkout).unwrap();
    std::fs::write(src.join("crate/src/lib.rs"), "pub fn vendored() {}\n").unwrap();

    materialize_source_overlay(&src, &dest, None).unwrap();

    let dest_meta = std::fs::symlink_metadata(&dest).unwrap();
    assert!(dest_meta.is_dir());
    assert!(!dest_meta.file_type().is_symlink());
    assert_eq!(
        std::fs::read_to_string(dest.join("crate/src/lib.rs")).unwrap(),
        "pub fn vendored() {}\n"
    );
    assert!(!real_checkout.join("vendor").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn cas_blob_staging_hardlinks_mode_variants() {
    let _cas_guard = crate::source::cas_test_guard();
    let base = std::env::temp_dir().join(format!(
        "buildutil-cas-blob-stage-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let state = base.join("state");
    let src = base.join("src");
    let stage = base.join("stage");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&stage).unwrap();
    crate::source::activate(&state).unwrap();
    std::fs::write(src.join("plain"), b"same").unwrap();
    std::fs::write(src.join("exec"), b"same").unwrap();
    crate::platform::set_mode(&src.join("exec"), 0o755).unwrap();

    for name in ["plain", "exec"] {
        let (hash, kind) = crate::source::hash_and_ingest_file(&src.join(name)).unwrap();
        let blob = crate::source::blob_path(&hash, kind).unwrap();
        let out = stage.join(name);
        hardlink_or_copy(&blob, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"same");
        let mode = crate::platform::file_mode(&std::fs::metadata(&out).unwrap()) & 0o777;
        assert_eq!(mode, if kind == 'x' { 0o555 } else { 0o444 });
        assert!(crate::platform::same_file(&blob, &out));
    }
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn cas_srcdir_and_source_root_stage_as_real_trees_with_overlay_holes() {
    let _cas_guard = crate::source::cas_test_guard();
    let base = std::env::temp_dir().join(format!(
        "buildutil-cas-root-stage-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let state = base.join("state");
    let src = base.join("repo");
    let stage = base.join("stage");
    crate::source::activate(&state).unwrap();
    std::fs::create_dir_all(src.join("include/sub")).unwrap();
    std::fs::create_dir_all(src.join("root/keep")).unwrap();
    std::fs::create_dir_all(src.join("root/vendor")).unwrap();
    std::fs::write(src.join(".buildutilignore"), "").unwrap();
    std::fs::write(src.join("include/sub/header.h"), b"h").unwrap();
    std::fs::write(src.join("root/keep/file"), b"keep").unwrap();
    std::fs::write(src.join("root/vendor/old"), b"old").unwrap();

    let srcdir_hash = crate::source::hash_and_ingest_dir(&src.join("include")).unwrap();
    stage_source_root(&stage, "include", &srcdir_hash, &[]).unwrap();
    assert_eq!(
        std::fs::read(stage.join("include/sub/header.h")).unwrap(),
        b"h"
    );
    std::fs::write(stage.join("sibling"), b"sibling").unwrap();
    assert!(stage.join("include").is_dir());
    assert!(!stage.join("include").is_symlink());
    assert_eq!(
        std::fs::canonicalize(stage.join("include/sub/../../sibling")).unwrap(),
        std::fs::canonicalize(stage.join("sibling")).unwrap()
    );
    assert!(stage.join("include/sub").is_dir());
    assert!(!stage.join("include/sub").is_symlink());

    let state2 = base.join("state-root");
    let stage2 = base.join("stage-root");
    crate::source::activate(&state2).unwrap();
    let root_hash = crate::source::hash_and_ingest_dir(&src.join("root")).unwrap();
    let overlay_kinds =
        stage_source_root(&stage2, "root", &root_hash, &["root/vendor".to_string()]).unwrap();
    assert!(stage2.join("root/keep").is_dir());
    assert!(!stage2.join("root/keep").is_symlink());
    assert!(!stage2.join("root/vendor").exists());

    let dep_overlay = base.join("dep/vendor");
    std::fs::create_dir_all(&dep_overlay).unwrap();
    std::fs::write(dep_overlay.join("new"), b"new").unwrap();
    materialize_source_overlay(
        &dep_overlay,
        &stage2.join("root/vendor"),
        overlay_kinds.get("root/vendor").copied(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(stage2.join("root/vendor/new")).unwrap(),
        b"new"
    );
    assert!(!stage2.join("root/vendor").is_symlink());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn fixed_output_exec_source_root_stages_with_overlay_holes() {
    let _cas_guard = crate::source::cas_test_guard();
    let base = std::env::temp_dir().join(format!(
        "buildutil-exec-source-root-stage-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let state = base.join("state");
    let src = base.join("repo");
    let stage = base.join("stage");
    crate::source::activate(&state).unwrap();
    std::fs::create_dir_all(src.join("toolchain/rust/src")).unwrap();
    std::fs::create_dir_all(src.join("toolchain/rust/vendor")).unwrap();
    std::fs::write(src.join(".buildutilignore"), "").unwrap();
    std::fs::write(src.join("toolchain/rust/src/lib.rs"), b"rust").unwrap();
    std::fs::write(src.join("toolchain/rust/vendor/old"), b"old").unwrap();

    let root_hash = crate::source::hash_and_ingest_dir(&src.join("toolchain/rust")).unwrap();
    let overlay_kinds = stage_source_root(
        &stage,
        "toolchain/rust",
        &root_hash,
        &["toolchain/rust/vendor".to_string()],
    )
    .unwrap();
    assert_eq!(
        std::fs::read(stage.join("toolchain/rust/src/lib.rs")).unwrap(),
        b"rust"
    );
    assert!(!stage.join("toolchain/rust/vendor").exists());

    let overlay = base.join("dep/vendor");
    std::fs::create_dir_all(&overlay).unwrap();
    std::fs::write(overlay.join("new"), b"new").unwrap();
    materialize_source_overlay(
        &overlay,
        &stage.join("toolchain/rust/vendor"),
        overlay_kinds.get("toolchain/rust/vendor").copied(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(stage.join("toolchain/rust/vendor/new")).unwrap(),
        b"new"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn source_root_overlays_merge_leaf_replace_directory_and_reject_shape_mismatch() {
    let _cas_guard = crate::source::cas_test_guard();
    let base = std::env::temp_dir().join(format!(
        "buildutil-source-overlay-shapes-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let state = base.join("state");
    let src = base.join("repo/root");
    let stage = base.join("stage");
    crate::source::activate(&state).unwrap();
    std::fs::create_dir_all(src.join("generated")).unwrap();
    std::fs::create_dir_all(src.join("vendor")).unwrap();
    std::fs::write(src.join("generated/target.rs"), b"old target").unwrap();
    std::fs::write(src.join("generated/sibling.rs"), b"keep sibling").unwrap();
    std::fs::write(src.join("vendor/old"), b"old vendor").unwrap();

    let root_hash = crate::source::hash_and_ingest_dir(&src).unwrap();
    let overlay_dests = vec![
        "root/generated/target.rs".to_string(),
        "root/vendor".to_string(),
    ];
    let overlay_kinds = stage_source_root(&stage, "root", &root_hash, &overlay_dests).unwrap();
    assert!(!stage.join("root/generated/target.rs").exists());
    assert_eq!(
        std::fs::read(stage.join("root/generated/sibling.rs")).unwrap(),
        b"keep sibling"
    );
    assert!(!stage.join("root/vendor").exists());

    let overlay_file = base.join("dep/target.rs");
    let overlay_dir = base.join("dep/vendor");
    std::fs::create_dir_all(&overlay_dir).unwrap();
    std::fs::write(&overlay_file, b"new target").unwrap();
    std::fs::write(overlay_dir.join("new"), b"new vendor").unwrap();

    let err = materialize_source_overlay(
        &overlay_file,
        &stage.join("root/vendor"),
        overlay_kinds.get("root/vendor").copied(),
    )
    .unwrap_err();
    assert!(err.contains("source-overlay shape mismatch"));
    assert!(err.contains("source is a file, but destination is a directory"));
    let err = materialize_source_overlay(
        &overlay_dir,
        &stage.join("root/generated/target.rs"),
        overlay_kinds.get("root/generated/target.rs").copied(),
    )
    .unwrap_err();
    assert!(err.contains("source is a directory, but destination is a file"));

    materialize_source_overlay(
        &overlay_file,
        &stage.join("root/generated/target.rs"),
        overlay_kinds.get("root/generated/target.rs").copied(),
    )
    .unwrap();
    materialize_source_overlay(
        &overlay_dir,
        &stage.join("root/vendor"),
        overlay_kinds.get("root/vendor").copied(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(stage.join("root/generated/target.rs")).unwrap(),
        b"new target"
    );
    assert_eq!(
        std::fs::read(stage.join("root/generated/sibling.rs")).unwrap(),
        b"keep sibling"
    );
    assert_eq!(
        std::fs::read(stage.join("root/vendor/new")).unwrap(),
        b"new vendor"
    );
    assert!(!stage.join("root/vendor/old").exists());

    let err = stage_source_root(
        &base.join("bad-stage"),
        "root",
        &root_hash,
        &["root/generated/target.rs/child".to_string()],
    )
    .unwrap_err();
    assert!(err.contains("has file ancestor `generated/target.rs`"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn reference_scan_classifies_build_private_and_store_refs() {
    let base = std::env::temp_dir().join(format!("buildutil-refscan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let out = base.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let store_root = PathBuf::from("/some/store/root");
    let build_dir = PathBuf::from("/tmp/priv-build-xyz");
    let build_needles = [build_dir.clone()];
    // A declared dependency the hosted output may legally reference.
    let closure: BTreeSet<String> = [
        "11111111111111111111111111111111-libc-x86_64".to_string(),
        "22222222222222222222222222222222-libm-x86_64".to_string(),
        "33333333333333333333333333333333-libextra-x86_64".to_string(),
    ]
    .into_iter()
    .collect();

    std::fs::write(out.join("clean.txt"), b"nothing to see here").unwrap();
    // Legal store reference (resolves into the closure).
    std::fs::write(
        out.join("wrapper"),
        b"exec /some/store/root/11111111111111111111111111111111-libc-x86_64/bin/ld",
    )
    .unwrap();
    // Transitive closure member used by the list policy check.
    std::fs::write(
        out.join("transitive"),
        b"lib /some/store/root/22222222222222222222222222222222-libm-x86_64/lib/libm.so",
    )
    .unwrap();
    // Closure member not listed by the list policy.
    std::fs::write(
        out.join("unlisted"),
        b"lib /some/store/root/33333333333333333333333333333333-libextra-x86_64/lib/libextra.so",
    )
    .unwrap();
    // Undeclared store reference (not in the closure).
    std::fs::write(
        out.join("leak"),
        b"cc=/some/store/root/zzz-secret-x86_64/bin/cc",
    )
    .unwrap();
    // A `/build/stage/dep/...` staging path is the reproducible remap
    // target, not a leak — it must NOT be flagged.
    std::fs::write(out.join("stage"), b"-L/build/stage/dep/libc/lib").unwrap();
    // Build-private leak via the per-run build dir, as a symlink target.
    crate::platform::create_symlink_auto(
        Path::new("/tmp/priv-build-xyz/home/.cache"),
        &out.join("link"),
    )
    .unwrap();

    // Freestanding (default): EVERY store reference is a violation, as is
    // the per-run build-dir path. The clean file and the reproducible
    // `/build` staging path never appear.
    let none_legal = allowed_store_refs(&RefPolicy::None, &closure);
    let (free, free_refs) = scan_references(&out, &store_root, &build_needles, &none_legal, false);
    assert!(
        free.iter()
            .any(|h| h.starts_with("wrapper") && h.contains("111-libc")),
        "free: {:?}",
        free
    );
    assert!(
        free.iter()
            .any(|h| h.starts_with("leak") && h.contains("zzz-secret")),
        "free: {:?}",
        free
    );
    assert!(
        !free.iter().any(|h| h.starts_with("stage")),
        "free must not flag a reproducible /build staging path: {:?}",
        free
    );
    assert!(
        free.iter()
            .any(|h| h.starts_with("link") && h.contains("build-private")),
        "free: {:?}",
        free
    );
    assert!(
        !free.iter().any(|h| h.starts_with("clean")),
        "free: {:?}",
        free
    );

    // Closure: closure references are allowed; the undeclared reference and
    // the per-run build-dir path remain violations; the `/build` staging
    // path stays clean.
    let closure_legal = allowed_store_refs(&RefPolicy::Closure, &closure);
    let (hosted, hosted_refs) =
        scan_references(&out, &store_root, &build_needles, &closure_legal, true);
    assert!(
        !hosted.iter().any(|h| h.starts_with("wrapper")),
        "closure must allow a declared reference: {:?}",
        hosted
    );
    assert!(
        hosted
            .iter()
            .any(|h| h.starts_with("leak") && h.contains("undeclared")),
        "hosted: {:?}",
        hosted
    );
    assert!(
        !hosted.iter().any(|h| h.starts_with("stage")),
        "hosted must not flag a reproducible /build staging path: {:?}",
        hosted
    );
    assert!(
        hosted
            .iter()
            .any(|h| h.starts_with("link") && h.contains("build-private")),
        "hosted: {:?}",
        hosted
    );

    // The recorded reference set: hosted records exactly the legal hits;
    // freestanding records nothing (every store ref there is a violation).
    assert!(free_refs.is_empty(), "free refs: {:?}", free_refs);
    assert_eq!(
        hosted_refs.into_iter().collect::<Vec<_>>(),
        vec![
            "11111111111111111111111111111111-libc-x86_64".to_string(),
            "22222222222222222222222222222222-libm-x86_64".to_string(),
            "33333333333333333333333333333333-libextra-x86_64".to_string()
        ]
    );

    let list_legal = allowed_store_refs(&RefPolicy::List(vec!["libm".to_string()]), &closure);
    let (listed, listed_refs) =
        scan_references(&out, &store_root, &build_needles, &list_legal, true);
    assert!(
        !listed.iter().any(|h| h.starts_with("transitive")),
        "list policy must allow listed transitive member: {:?}",
        listed
    );
    assert!(
        listed
            .iter()
            .any(|h| h.starts_with("unlisted") && h.contains("undeclared")),
        "list policy must reject unlisted closure member: {:?}",
        listed
    );
    assert_eq!(
        listed_refs.into_iter().collect::<Vec<_>>(),
        vec!["22222222222222222222222222222222-libm-x86_64".to_string()]
    );

    let _ = std::fs::remove_dir_all(&base);
}

// --- Early-cutoff integration test ------------------------------------

fn prepare_plan_repo(repo: &Path) {
    std::fs::create_dir_all(repo.join(crate::paths::BUILDUTIL)).unwrap();
    std::fs::create_dir_all(repo.join("library")).unwrap();
    std::fs::create_dir_all(repo.join("tools/buildutil/compose")).unwrap();
    std::fs::create_dir_all(repo.join("tools/buildutil/lib/crypto")).unwrap();
    std::fs::write(repo.join("tools/buildutil/lib/crypto/sha256.rs"), "").unwrap();
    std::fs::write(repo.join(".buildutilignore"), "").unwrap();
    std::fs::write(repo.join("buildutil"), "#!/bin/sh\n").unwrap();
    std::fs::write(repo.join("buildutil.toml"), "").unwrap();
    crate::platform::set_mode(&repo.join("buildutil"), 0o755).unwrap();
    std::fs::write(repo.join(crate::paths::BOOTSTRAP_NINJA), "").unwrap();
}

fn emit_loaded_plan(
    spec: &Spec,
    evaluated: &Evaluated,
    targets: &[String],
    store: &Store,
) -> ExecPlan {
    let mut evaluated = evaluated.clone();
    // Fixture targets are plain derivation names: each is its own key.
    evaluated.roots = targets
        .iter()
        .map(|target| (target.clone(), target.clone()))
        .collect();
    for rel in crate::eval::plan::bootstrap::bootstrap_paths(&spec.repo_root).unwrap() {
        let (hash, kind) = crate::source::hash_and_ingest_file(&spec.repo_root.join(&rel)).unwrap();
        evaluated.resolved_sources.blobs.insert(rel, (hash, kind));
    }
    for recipe in evaluated.recipes.values() {
        for (kind, rel, hash) in &recipe.srcs {
            evaluated
                .resolved_sources
                .blobs
                .insert(rel.clone(), (hash.clone(), *kind));
        }
    }
    for dspec in spec.drvs.values() {
        for rel in dspec.src_dirs.iter().chain(dspec.source_roots.iter()) {
            let hash = crate::source::hash_and_ingest_dir(&spec.repo_root.join(rel)).unwrap();
            evaluated.resolved_sources.trees.insert(rel.clone(), hash);
        }
    }
    let (_path, _, plan) =
        crate::eval::plan::emit(spec, &evaluated, store.state_dir(), &evaluated.git_state).unwrap();
    crate::eval::plan::verify_source_cas_complete(&plan, store.state_dir()).unwrap();
    plan
}

fn drvspec(
    name: &str,
    builder: &str,
    tool: &str,
    extra_tools: &[&str],
    sources: &[&str],
    deps: &[&str],
    outputs: &[&str],
    argv: &[&str],
) -> DrvSpec {
    DrvSpec {
        repository: None,
        name: name.into(),
        builder: builder.into(),
        tool: tool.into(),
        extra_tools: extra_tools.iter().map(|s| s.to_string()).collect(),
        when: String::new(),
        bootstrap: false,
        native_frontend: false,
        stage: None,
        host_tool: false,
        sources: sources.iter().map(|s| s.to_string()).collect(),
        src_dirs: vec![],
        source_roots: vec![],
        source_overlays: vec![],
        deps: deps.iter().map(|s| s.to_string()).collect(),
        outputs: outputs.iter().map(|s| s.to_string()).collect(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: vec![],
        copy: vec![],
        stage_deps: vec![],
        allowed_refs: RefPolicy::None,
        groups: vec![],
        compiles: vec![],
        steps: vec![],
        module: String::new(),
        module_role: String::new(),
        config_keys: Vec::new(),
    }
}

// The outer derivation supplies a pinned seed. Import its runtime separately
// so nested consumers exercise transitive provider lookup after env_clear().
fn register_contract_tools(spec: &mut Spec, store: &Store, seed: &Path) -> Vec<Recipe> {
    let mut recipes = Vec::new();
    let mut deps = Vec::new();
    for (name, outputs) in [
        ("bootstrap-seed", vec!["bin/sh", "bin/cat", "lib/"]),
        ("contract-tools", vec!["bin/sh", "bin/sh-v2", "bin/ninja"]),
    ] {
        let out = store.state_dir().join(format!("import-{name}"));
        std::fs::create_dir_all(&out).unwrap();
        for rel in &outputs {
            let source = if *rel == "bin/sh-v2" { "bin/sh" } else { rel };
            materialize_source_overlay(&seed.join(source), &out.join(rel), None).unwrap();
        }
        let dep_names: Vec<&str> = deps
            .iter()
            .map(|dep: &crate::store::derivation::DepRef| dep.name.as_str())
            .collect();
        let ds = drvspec(
            name,
            "registered-fixture",
            "sh",
            &[],
            &[],
            &dep_names,
            &outputs,
            &[],
        );
        let mut recipe = recipe_from(spec, &ds, &BTreeMap::new());
        recipe.arch = format!("host-{}", spec.build_host);
        recipe.config.push((
            "fixture-tree-sha256".into(),
            crate::source::filehash::hash_tree(&out).unwrap(),
        ));
        let drv = recipe.finalize(deps.clone());
        store.write_drv(&drv).unwrap();
        let digest = store.register(&drv, &out, "audit", &[]).unwrap();
        deps = vec![crate::store::derivation::DepRef {
            name: name.into(),
            digest,
            store_name: drv.store_name(),
        }];
        spec.drvs.insert(name.into(), ds);
        recipes.push(recipe);
    }
    recipes
}

#[test]
fn required_checks_failed_validation_blocks_cache_consumers_and_latest_after_plan_roundtrip() {
    let _cas_guard = crate::source::cas_test_guard();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "buildutil-required-execution-{}-{nonce}",
        std::process::id()
    ));
    for (arch, phase) in [
        ("x86_64", "before"),
        ("x86_64", "after"),
        ("aarch64", "before"),
        ("aarch64", "after"),
    ] {
        let case = base.join(arch).join(phase);
        let repo = case.join("repo");
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        prepare_plan_repo(&repo);
        let root = format!(
            r#"
[buildutil]
subsystems = ["sub"]
[arch.{arch}]
[packages]
expose = ["consumer", "image"]
[packages.group]
both = ["consumer", "image"]
[checks]
expose = ["validation"]
[required-check.validation]
derivation = "validation"
phase = "{phase}"
artifacts = ["image"]
"#
        );
        std::fs::write(repo.join("buildutil.toml"), root).unwrap();
        let deps = if phase == "after" { "\"image\"" } else { "" };
        std::fs::write(
            repo.join("sub/buildutil.toml"),
            format!(
                r#"
[derivation.image]
builder = "script-dag"
tool = "ninja"
outputs = ["image"]
[[derivation.image.step]]
tool = "sh"
argv = ["-c", "printf artifact > {{out}}/image"]
outputs = ["{{out}}/image"]
[derivation.validation]
builder = "script-dag"
tool = "ninja"
sources = ["contract.sh"]
deps = [{deps}]
outputs = ["verdict"]
[[derivation.validation.step]]
tool = "sh"
argv = ["{{srcroot}}/contract.sh", "{{config.VERDICT}}"]
capture = "{{out}}/verdict"
outputs = ["{{out}}/verdict"]
[derivation.consumer]
builder = "script-dag"
tool = "ninja"
deps = ["image"]
outputs = ["result"]
[[derivation.consumer.step]]
tool = "sh"
argv = ["-c", "test -s {{dep:image}}/image && printf consumed > {{out}}/result"]
outputs = ["{{out}}/result"]
"#
            ),
        )
        .unwrap();
        let store = Store::open(&case.join("state")).unwrap();
        crate::source::activate(store.state_dir()).unwrap();
        let build_host = std::env::var("BUILDUTIL_CONTRACT_BUILD_HOST").expect(
            "run the declared test-buildutil-contract or test-buildutil derivation to supply the build host",
        );
        let seed = PathBuf::from(std::env::var_os("BUILDUTIL_CONTRACT_SEED").expect(
            "run the declared test-buildutil-contract or test-buildutil derivation to supply its seed",
        ));
        let mut spec = crate::spec::load(&repo, arch, &build_host).unwrap();
        let providers = register_contract_tools(&mut spec, &store, &seed);
        let logger = crate::log::Logger::new(false);
        let mut old_roots = BTreeMap::new();
        // Source edits invalidate the validator while artifact contents remain
        // identical. An old successful artifact cannot stand in for its gate.
        for (attempt, (script, verdict)) in [
            ("exit \"$1\"\n", "0"),
            ("exit \"$1\"\n", "0"),
            ("exit 23\n", "0"),
            ("# repaired contract\nexit \"$1\"\n", "0"),
            ("# repaired contract\nexit \"$1\"\n", "23"),
            ("# repaired contract\nexit \"$1\"\n", "0"),
            ("# repaired contract\nexit \"$1\"\n", "0"),
            ("# repaired contract\nexit \"$1\"\n", "0"),
        ]
        .iter()
        .enumerate()
        {
            std::fs::write(repo.join("contract.sh"), script).unwrap();
            if attempt == 6 {
                let gate = if phase == "before" {
                    "validation"
                } else {
                    "image"
                };
                let subject = spec.drvs.get_mut(gate).unwrap();
                subject.extra_tools.push("sh-v2".into());
                subject.steps.last_mut().unwrap().tool = "sh-v2".into();
            }
            if attempt == 7 {
                spec.drvs.get_mut("image").unwrap().steps[0].argv[1] =
                    "printf changed-artifact > {out}/image".into();
            }
            let config = crate::spec::configres::Config::from_values(
                [("VERDICT".into(), verdict.to_string())]
                    .into_iter()
                    .collect(),
            );
            for requested in [
                vec!["image".to_string()],
                vec!["consumer".to_string()],
                vec!["image".to_string(), "consumer".to_string()],
                vec!["consumer".to_string(), "image".to_string()],
            ] {
                let consumer = requested != ["image"];
                let names: Vec<String> = if phase == "before" {
                    vec!["validation", "image", "consumer"]
                } else {
                    vec!["image", "consumer"]
                }
                .into_iter()
                .filter(|name| *name != "consumer" || consumer)
                .map(str::to_string)
                .collect();
                let mut ev = Evaluated {
                    order: names.clone(),
                    recipes: BTreeMap::new(),
                    plans: BTreeMap::new(),
                    roots: Vec::new(),
                    configured: BTreeMap::new(),
                    config_digests: BTreeMap::new(),
                    resolved_sources: Default::default(),
                    git_state: ("fixture".into(), "false".into()),
                };
                ev.order
                    .splice(0..0, providers.iter().map(|recipe| recipe.name.clone()));
                for provider in &providers {
                    ev.recipes.insert(provider.name.clone(), provider.clone());
                }
                for name in names {
                    let ds = &spec.drvs[&name];
                    let mut view = config.view();
                    let plan = spec.eval_plan(ds, &mut view).unwrap();
                    let mut recipe = recipe_from(&spec, ds, &BTreeMap::new());
                    recipe.tools = ["ninja", "sh", "sh-v2"]
                        .into_iter()
                        .map(|tool| (tool.into(), format!("store:contract-tools:bin/{tool}")))
                        .collect();
                    recipe.dep_names.push("contract-tools".into());
                    recipe.argv = spec.eval_argv(ds, &mut view).unwrap();
                    recipe.config = view.projection();
                    recipe.plan = crate::eval::ninja_emit::hash_lines(&plan);
                    ev.plans.insert(name.clone(), plan);
                    ev.recipes.insert(name, recipe);
                }
                let emitted = emit_loaded_plan(&spec, &ev, &requested, &store);
                let wire = crate::eval::plan::render(&emitted).unwrap();
                let plan = crate::eval::plan::parse(&wire).unwrap();
                assert_eq!(crate::eval::plan::render(&plan).unwrap(), wire);
                let outcome = realize(
                    &plan,
                    &store,
                    &AuditSandbox,
                    &super::builder::BuilderRegistry::core(),
                    2,
                    AuditMode::Warn,
                    true,
                    false,
                    &BTreeSet::new(),
                    &logger,
                )
                .unwrap();
                crate::store::publish_latest_roots(&store, &plan.targets, arch, &outcome).unwrap();
                if attempt == 2 || attempt == 4 {
                    assert!(outcome.failed.iter().any(|(name, _)| name == "image"));
                    assert_eq!(
                        outcome.failed.iter().any(|(name, _)| name == "consumer"),
                        consumer
                    );
                    assert!(!outcome.store_names.contains_key("image"));
                    assert!(!outcome.store_names.contains_key("consumer"));
                    let gate = if phase == "before" {
                        "validation"
                    } else {
                        "image"
                    };
                    let resolved = ev.dry_resolve(&store);
                    let resolved = resolved
                        .get(gate)
                        .expect("failed gate has resolved prerequisites");
                    assert!(
                        store
                            .read_realization_digest(&resolved.drv.hash())
                            .is_none()
                    );
                    assert!(
                        !outcome
                            .cached
                            .iter()
                            .any(|name| name == "image" || name == "consumer")
                    );
                    for (name, old) in &old_roots {
                        assert_eq!(
                            &std::fs::read_link(store.state_dir().join("roots").join(name))
                                .unwrap(),
                            old
                        );
                    }
                } else {
                    assert!(outcome.failed.is_empty(), "{phase}: {:?}", outcome.failed);
                    if requested == ["image"] && (attempt == 6 || attempt == 7) {
                        let rebuilt = if attempt == 6 && phase == "before" {
                            "validation"
                        } else {
                            "image"
                        };
                        assert!(
                            outcome.built.contains(&rebuilt.into()),
                            "changed check tool/artifact must revalidate: {arch}/{phase}/{attempt}"
                        );
                    }
                    if attempt == 1 {
                        assert!(outcome.cached.contains(&"image".into()));
                        assert_eq!(outcome.cached.contains(&"consumer".into()), consumer);
                    }
                    for target in &plan.targets {
                        let name = format!("latest-{target}-{arch}");
                        old_roots.insert(
                            name.clone(),
                            std::fs::read_link(store.state_dir().join("roots").join(&name))
                                .unwrap(),
                        );
                    }
                }
            }
        }
    }
    std::fs::remove_dir_all(base).unwrap();
}

fn recipe_from(spec: &Spec, ds: &DrvSpec, tool_paths: &BTreeMap<String, PathBuf>) -> Recipe {
    let Spec { repo_root, .. } = spec;
    let srcs = ds
        .sources
        .iter()
        .map(|s| {
            let (hash, kind) = crate::source::hash_and_ingest_file(&repo_root.join(s)).unwrap();
            (kind, s.clone(), hash)
        })
        .collect();
    let mut tools = Vec::new();
    for tool in std::iter::once(&ds.tool).chain(ds.extra_tools.iter()) {
        if let Some(path) = tool_paths.get(tool) {
            tools.push((tool.clone(), format!("host:{}", path.display())));
        }
    }
    Recipe {
        name: ds.name.clone(),
        arch: spec.arch.clone(),
        builder: ds.builder.clone(),
        tools,
        env: vec![],
        srcs,
        srcdirs: vec![],
        source_roots: vec![],
        source_overlays: vec![],
        copy: ds.copy.clone(),
        stage_deps: ds.stage_deps.clone(),
        allowed_refs: ds.allowed_refs.clone(),
        dep_names: ds.deps.clone(),
        config: vec![],
        module_config: None,
        argv: ds.argv.clone(),
        plan: vec![],
        outputs: ds.outputs.clone(),
    }
}

/// The early-cutoff gate, hermetically at audit grade: a leaf and a
/// dependent that copies the leaf's output. Editing the leaf's SOURCE
/// (new drv hash) while its OUTPUT bytes stay identical must rebuild
/// exactly the leaf — the dependent is a cache hit because the leaf's
/// realization digest is unchanged. Also exercises dependency-path
/// virtualization: the dependent reads `../dep/leaf/result`.
#[test]
fn early_cutoff_rebuilds_only_the_changed_leaf() {
    let _cas_guard = crate::source::cas_test_guard();
    let base = std::env::temp_dir().join(format!("buildutil-cutoff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let repo = base.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let store = Store::open(&base.join("state")).unwrap();
    crate::source::activate(store.state_dir()).unwrap();
    prepare_plan_repo(&repo);
    std::fs::write(repo.join("leaf.txt"), "v1").unwrap();

    // Hermetic tool resolution: `sh`/`cat` must come from a declared
    // dependency closure, not an ambient host path — inside the Linux
    // namespace sandbox that runs this derivation, only declared inputs are
    // mounted (the same fix applied to a direct `AuditSandbox` call in
    // `exec::sandbox::tests::audit_exec_streams_output_while_preserving_log_order`).
    // The seed is already wired to this test binary via `BUILDUTIL_CONTRACT_SEED`.
    let seed = PathBuf::from(
        std::env::var_os("BUILDUTIL_CONTRACT_SEED")
            .expect("run the declared test-buildutil derivation to supply its seed"),
    );

    let leaf_ds = drvspec(
        "leaf",
        "test-cmd",
        "sh",
        &[],
        &["leaf.txt"],
        &["bootstrap-seed"],
        &["result"],
        &["sh", "-c", "printf leafout > {out}/result"],
    );
    let dep_ds = drvspec(
        "dependent",
        "test-cmd",
        "sh",
        &["cat"],
        &[],
        &["leaf", "bootstrap-seed"],
        &["result"],
        &["sh", "-c", "cat ../dep/leaf/result > {out}/result"],
    );
    let mut drvs = BTreeMap::new();
    drvs.insert("leaf".to_string(), leaf_ds);
    drvs.insert("dependent".to_string(), dep_ds);
    let mut spec = Spec {
        repo_root: repo.clone(),
        arch: "x86_64".into(),
        build_host: "x86_64-unknown-linux-gnu".into(),
        target_system: "x86_64".into(),
        flagsets: BTreeMap::new(),
        drvs,
        variants: BTreeMap::new(),
        kinds: Default::default(),
        tool_providers: BTreeMap::new(),
        stages: BTreeMap::new(),
        configuration: None,
        executor_image: None,
        modules: BTreeMap::new(),
        generators: BTreeMap::new(),
        bootstrap_steps: Vec::new(),
        pending: None,
        spec_inputs: Vec::new(),
    };
    // Only `bootstrap-seed` is actually referenced by `leaf`/`dependent`;
    // `contract-tools` (the sibling provider `register_contract_tools` also
    // registers) is left out of this plan's node set so it stays out of
    // `out.built`/`out.cached`.
    let bootstrap_seed = register_contract_tools(&mut spec, &store, &seed)
        .into_iter()
        .find(|recipe| recipe.name == "bootstrap-seed")
        .expect("register_contract_tools always registers bootstrap-seed");

    let make_eval = |spec: &Spec| Evaluated {
        order: vec![
            "bootstrap-seed".to_string(),
            "leaf".to_string(),
            "dependent".to_string(),
        ],
        recipes: {
            let mut r = BTreeMap::new();
            r.insert("bootstrap-seed".to_string(), bootstrap_seed.clone());
            let mut leaf = recipe_from(spec, &spec.drvs["leaf"], &BTreeMap::new());
            leaf.tools = vec![("sh".to_string(), "store:bootstrap-seed:bin/sh".to_string())];
            r.insert("leaf".to_string(), leaf);
            let mut dependent = recipe_from(spec, &spec.drvs["dependent"], &BTreeMap::new());
            dependent.tools = vec![
                ("sh".to_string(), "store:bootstrap-seed:bin/sh".to_string()),
                (
                    "cat".to_string(),
                    "store:bootstrap-seed:bin/cat".to_string(),
                ),
            ];
            r.insert("dependent".to_string(), dependent);
            r
        },
        plans: BTreeMap::new(),
        roots: Vec::new(),
        configured: BTreeMap::new(),
        config_digests: BTreeMap::new(),
        resolved_sources: Default::default(),
        git_state: ("unknown".into(), "false".into()),
    };

    let sandbox = AuditSandbox;
    let builders = super::builder::BuilderRegistry::core();
    let logger = crate::log::Logger::new(false);

    // Run 1 (cold): both build.
    let ev1 = make_eval(&spec);
    let plan1 = emit_loaded_plan(&spec, &ev1, &["dependent".to_string()], &store);
    let out1 = realize(
        &plan1,
        &store,
        &sandbox,
        &builders,
        1,
        AuditMode::Warn,
        false,
        false,
        &BTreeSet::new(),
        &logger,
    )
    .unwrap();
    assert!(out1.failed.is_empty(), "run1 failures: {:?}", out1.failed);
    assert!(out1.built.contains(&"leaf".to_string()));
    assert!(out1.built.contains(&"dependent".to_string()));

    // Edit the leaf SOURCE (new drv hash) but keep its OUTPUT identical.
    std::fs::write(repo.join("leaf.txt"), "v2-entirely-different-source").unwrap();
    let ev2 = make_eval(&spec);
    let plan2 = emit_loaded_plan(&spec, &ev2, &["dependent".to_string()], &store);
    let out2 = realize(
        &plan2,
        &store,
        &sandbox,
        &builders,
        1,
        AuditMode::Warn,
        false,
        false,
        &BTreeSet::new(),
        &logger,
    )
    .unwrap();
    assert!(out2.failed.is_empty(), "run2 failures: {:?}", out2.failed);
    assert_eq!(
        out2.built,
        vec!["leaf".to_string()],
        "only the changed leaf should rebuild"
    );
    assert_eq!(
        out2.cached,
        vec!["bootstrap-seed".to_string(), "dependent".to_string()],
        "dependent must be an early-cutoff cache hit (bootstrap-seed is an \
         unrelated always-cached tool provider)"
    );

    // Observability: events are recorded end to end, with the right kinds.
    let leaf_ev = out2.events.iter().find(|e| e.name == "leaf").unwrap();
    assert_eq!(leaf_ev.kind, "realized");
    let dep_ev = out2.events.iter().find(|e| e.name == "dependent").unwrap();
    assert_eq!(dep_ev.kind, "cached");
    let (chain, _secs) = critical_path(&plan2, &out2.events);
    // The chain now roots at `bootstrap-seed`: `leaf` legitimately depends on
    // it (hermetic `sh` resolution), so it is the true start of the
    // dependency graph feeding `dependent`, not an artifact of the fixture.
    assert_eq!(chain.first().map(String::as_str), Some("bootstrap-seed"));
    assert_eq!(chain.last().map(String::as_str), Some("dependent"));

    let _ = std::fs::remove_dir_all(&base);
}

/// A builder's retained artifacts sit beside its build log and belong to the
/// latest attempt of its derivation: a failed attempt keeps what it wrote,
/// the next attempt replaces the directory whole, and a rerun of a passing
/// derivation leaves its store output and realization digest unchanged while
/// the artifacts follow the rerun. Nothing the builder retains enters its
/// output.
#[test]
fn required_retained_artifacts_follow_the_latest_attempt_beside_the_log() {
    let _cas_guard = crate::source::cas_test_guard();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "buildutil-retained-artifacts-{}-{nonce}",
        std::process::id()
    ));
    let repo = base.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    prepare_plan_repo(&repo);
    let store = Store::open(&base.join("state")).unwrap();
    crate::source::activate(store.state_dir()).unwrap();
    let seed = PathBuf::from(std::env::var_os("BUILDUTIL_CONTRACT_SEED").expect(
        "run the declared test-buildutil-contract or test-buildutil derivation to supply its seed",
    ));
    // The attempt's outcome comes from a file outside the derivation's
    // inputs, so one derivation can fail and then pass.
    let control = base.join("control");
    let script = format!(
        "read verdict < {control}; \
         printf '%s\\n' \"$verdict\" > \"$BUILDUTIL_ARTIFACTS/verdict.log\"; \
         if [ \"$verdict\" = fail ]; then printf stale > \"$BUILDUTIL_ARTIFACTS/stale.log\"; exit 3; fi; \
         printf 'pass\\n' > {{out}}/stamp",
        control = control.display()
    );
    let check_ds = drvspec(
        "check",
        "test-cmd",
        "sh",
        &[],
        &[],
        &["bootstrap-seed"],
        &["stamp"],
        &["sh", "-c", script.as_str()],
    );
    let mut drvs = BTreeMap::new();
    drvs.insert("check".to_string(), check_ds);
    let mut spec = Spec {
        repo_root: repo.clone(),
        arch: "x86_64".into(),
        build_host: "x86_64-unknown-linux-gnu".into(),
        target_system: "x86_64".into(),
        flagsets: BTreeMap::new(),
        drvs,
        variants: BTreeMap::new(),
        kinds: Default::default(),
        tool_providers: BTreeMap::new(),
        stages: BTreeMap::new(),
        configuration: None,
        executor_image: None,
        modules: BTreeMap::new(),
        generators: BTreeMap::new(),
        bootstrap_steps: Vec::new(),
        pending: None,
        spec_inputs: Vec::new(),
    };
    let bootstrap_seed = register_contract_tools(&mut spec, &store, &seed)
        .into_iter()
        .find(|recipe| recipe.name == "bootstrap-seed")
        .expect("register_contract_tools always registers bootstrap-seed");
    let mut check = recipe_from(&spec, &spec.drvs["check"], &BTreeMap::new());
    check.tools = vec![("sh".to_string(), "store:bootstrap-seed:bin/sh".to_string())];
    let ev = Evaluated {
        order: vec!["bootstrap-seed".to_string(), "check".to_string()],
        recipes: [
            ("bootstrap-seed".to_string(), bootstrap_seed),
            ("check".to_string(), check),
        ]
        .into_iter()
        .collect(),
        plans: BTreeMap::new(),
        roots: Vec::new(),
        configured: BTreeMap::new(),
        config_digests: BTreeMap::new(),
        resolved_sources: Default::default(),
        git_state: ("unknown".into(), "false".into()),
    };
    let plan = emit_loaded_plan(&spec, &ev, &["check".to_string()], &store);
    let node = ev
        .dry_resolve(&store)
        .remove("check")
        .expect("the check resolves against its registered seed");
    let artifacts = store.artifacts_path(&node.store_name);
    let log = store.log_path(&node.store_name);
    assert_eq!(artifacts.parent(), log.parent());
    let builders = super::builder::BuilderRegistry::core();
    let logger = crate::log::Logger::new(false);
    let attempt = |verdict: &str, rerun: &[&str]| {
        std::fs::write(&control, format!("{verdict}\n")).unwrap();
        let rerun: BTreeSet<String> = rerun.iter().map(|name| name.to_string()).collect();
        realize(
            &plan,
            &store,
            &AuditSandbox,
            &builders,
            1,
            AuditMode::Warn,
            false,
            false,
            &rerun,
            &logger,
        )
        .unwrap()
    };
    let read = |name: &str| std::fs::read_to_string(artifacts.join(name)).unwrap();

    // A failed attempt keeps its artifacts beside its log and registers
    // nothing.
    let failed = attempt("fail", &[]);
    assert!(failed.failed.iter().any(|(name, _)| name == "check"));
    assert_eq!(read("verdict.log"), "fail\n");
    assert!(artifacts.join("stale.log").is_file());
    assert!(log.is_file());
    assert!(store.read_realization_digest(&node.drv.hash()).is_none());

    // The next attempt of the same derivation replaces the directory whole.
    let passed = attempt("pass", &[]);
    assert!(passed.failed.is_empty(), "{:?}", passed.failed);
    assert!(passed.built.contains(&"check".to_string()));
    assert_eq!(read("verdict.log"), "pass\n");
    assert!(!artifacts.join("stale.log").exists());
    let digest = store
        .read_realization_digest(&node.drv.hash())
        .expect("a passing attempt registers its stamp");
    let output = store.root.join(&passed.store_names["check"]);
    assert_eq!(std::fs::read(output.join("stamp")).unwrap(), b"pass\n");
    assert!(!output.join("verdict.log").exists());

    // A rerun builds again: the stamp and its digest stay, the artifacts are
    // the rerun's.
    let rerun = attempt("again", &["check"]);
    assert!(rerun.failed.is_empty(), "{:?}", rerun.failed);
    assert!(rerun.built.contains(&"check".to_string()));
    assert_eq!(
        store.read_realization_digest(&node.drv.hash()),
        Some(digest)
    );
    assert_eq!(read("verdict.log"), "again\n");

    drop((failed, passed, rerun));
    let _ = std::fs::remove_dir_all(&base);
}

// --- Declared-hash untar import ----------------------------------------

/// One ustar entry: a 512-byte header plus NUL-padded content.
fn tar_entry(name: &str, content: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..107].copy_from_slice(b"0000755");
    header[124..135].copy_from_slice(format!("{:011o}", content.len()).as_bytes());
    header[156] = b'0';
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| *byte as u64).sum();
    header[148..156].copy_from_slice(format!("{:06o}\0 ", checksum).as_bytes());
    let mut v = header;
    v.extend_from_slice(content);
    v.resize(v.len().div_ceil(512) * 512, 0);
    v
}

/// The seed-import path end to end at audit grade: the archive's identity
/// is the declared pin (eval never reads the blob), realization verifies
/// the pin and extracts in-process, and a pin mismatch is a hard error —
/// never a silently different import.
#[test]
fn untar_import_verifies_pin_and_extracts_in_process() {
    let _cas_guard = crate::source::cas_test_guard();
    let base = std::env::temp_dir().join(format!("buildutil-untar-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let repo = base.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let store = Store::open(&base.join("state")).unwrap();
    crate::source::activate(store.state_dir()).unwrap();
    prepare_plan_repo(&repo);

    let mut tar = tar_entry("bin/hello", b"hi from the seed\n");
    tar.extend_from_slice(&[0u8; 1024]);
    std::fs::write(store.state_dir().join("seed.tar"), &tar).unwrap();
    let pin = crate::crypto::sha256::hash_bytes(&tar);
    let expected = base.join("expected-tree");
    crate::exec::untar::extract(&store.state_dir().join("seed.tar"), &expected).unwrap();
    let tree_pin = crate::source::filehash::hash_tree_with_dir_modes(&expected).unwrap();
    std::fs::remove_dir_all(&expected).unwrap();

    let make = |declared: &str, declared_tree: &str| {
        let mut ds = drvspec(
            "seed-import",
            "untar",
            "buildutil",
            &[],
            &[],
            &[],
            &["bin/"],
            &["untar", "{srcroot}/.buildutil/seed.tar", "{out}"],
        );
        ds.env = vec![
            ("BUILDUTIL_FIXED_SHA256".to_string(), declared.to_string()),
            (
                "BUILDUTIL_FIXED_TREE_SHA256".to_string(),
                declared_tree.to_string(),
            ),
        ];
        let mut drvs = BTreeMap::new();
        drvs.insert("seed-import".to_string(), ds);
        let spec = Spec {
            repo_root: repo.clone(),
            arch: "x86_64".into(),
            build_host: "x86_64-unknown-linux-gnu".into(),
            target_system: "x86_64".into(),
            flagsets: BTreeMap::new(),
            drvs,
            variants: BTreeMap::new(),
            kinds: Default::default(),
            tool_providers: BTreeMap::new(),
            stages: BTreeMap::new(),
            configuration: None,
            executor_image: None,
            modules: BTreeMap::new(),
            generators: BTreeMap::new(),
            bootstrap_steps: Vec::new(),
            pending: None,
            spec_inputs: Vec::new(),
        };
        let recipe = Recipe {
            name: "seed-import".into(),
            arch: "any".into(),
            builder: "untar".into(),
            tools: vec![],
            env: vec![],
            srcs: vec![],
            srcdirs: vec![],
            source_roots: vec![],
            source_overlays: vec![],
            copy: vec![],
            stage_deps: vec![],
            allowed_refs: RefPolicy::None,
            dep_names: vec![],
            config: vec![],
            module_config: None,
            argv: vec![
                format!("fixed-output:sha256:{}", declared),
                format!("fixed-output:tree-sha256:{}", declared_tree),
            ],
            plan: vec![],
            outputs: vec!["bin/".into()],
        };
        let evaluated = Evaluated {
            order: vec!["seed-import".to_string()],
            recipes: {
                let mut r = BTreeMap::new();
                r.insert("seed-import".to_string(), recipe);
                r
            },
            plans: BTreeMap::new(),
            roots: Vec::new(),
            configured: BTreeMap::new(),
            config_digests: BTreeMap::new(),
            resolved_sources: Default::default(),
            git_state: ("unknown".into(), "false".into()),
        };
        (spec, evaluated)
    };

    let logger = crate::log::Logger::new(false);
    let builders = crate::exec::builder::BuilderRegistry::core();

    // Wrong pin: hard error, nothing registered.
    let (spec, evaluated) = make(&"0".repeat(64), &tree_pin);
    let bad_plan = emit_loaded_plan(&spec, &evaluated, &["seed-import".to_string()], &store);
    let outcome = realize(
        &bad_plan,
        &store,
        &AuditSandbox,
        &builders,
        1,
        AuditMode::Warn,
        false,
        false,
        &BTreeSet::new(),
        &logger,
    )
    .expect("a failed derivation is an outcome, not an error");
    let err = match outcome.failed.as_slice() {
        [(name, err)] if name == "seed-import" => err.clone(),
        other => panic!("mismatched pin must fail seed-import alone: {other:?}"),
    };
    assert!(outcome.built.is_empty() && outcome.cached.is_empty());
    assert!(err.contains("hash mismatch"), "unexpected error: {err}");
    assert!(store.list().unwrap().is_empty(), "nothing may register");

    // Correct pin: extracted in-process and registered.
    let (spec, evaluated) = make(&pin, &tree_pin);
    let good_plan = emit_loaded_plan(&spec, &evaluated, &["seed-import".to_string()], &store);
    let out = realize(
        &good_plan,
        &store,
        &AuditSandbox,
        &builders,
        1,
        AuditMode::Warn,
        false,
        false,
        &BTreeSet::new(),
        &logger,
    )
    .unwrap();
    assert!(out.failed.is_empty(), "failures: {:?}", out.failed);
    assert_eq!(out.built, vec!["seed-import".to_string()]);
    let entry = store
        .list()
        .unwrap()
        .into_iter()
        .find(|n| n.contains("seed-import"))
        .unwrap();
    let hello = store
        .state_dir()
        .join("store")
        .join(&entry)
        .join("bin/hello");
    assert_eq!(
        std::fs::read(&hello).unwrap(),
        b"hi from the seed\n".to_vec()
    );

    let _ = std::fs::remove_dir_all(&base);
}
