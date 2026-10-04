//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — source content-addressed storage: tests

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::git::{
    attested_bootstrap_content_from, attested_identity_from, clean_checkout_tree_id, git_output,
};
use super::tree::manifest_entries;
use super::worktree::collect_filtered_pure;
use super::{SOURCE_FILTER_FILE, SourceCas, SourceFilter, TreeObject, filehash, statcache};

fn temp_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "buildutil-srccas-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn write_filter(root: &Path, body: &str) {
    std::fs::write(root.join(SOURCE_FILTER_FILE), body).unwrap();
}

#[test]
fn input_subtrees_keep_selected_bytes_and_symlink_targets() {
    let _guard = super::cas_test_guard();
    let base = temp_path("input-subtree");
    let owner = base.join("repository");
    std::fs::create_dir_all(owner.join("src")).unwrap();
    std::fs::write(base.join(SOURCE_FILTER_FILE), "*.rs\n").unwrap();
    std::fs::write(owner.join("src/lib.rs"), "pub fn value() {}\n").unwrap();
    std::fs::write(owner.join("keep.h"), "header\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("../keep.h", owner.join("src/header.h")).unwrap();
    super::activate(&base.join("state")).unwrap();
    let content = format!("tree:{}", super::ingest_repository(&owner, &[]).unwrap());
    let subtree = super::input_subtree(&content, "src").unwrap();
    let output = base.join("selected-src");
    super::materialize_tree(&subtree, &output).unwrap();
    assert_eq!(
        std::fs::read(output.join("lib.rs")).unwrap(),
        b"pub fn value() {}\n"
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::read_link(output.join("header.h")).unwrap(),
        PathBuf::from("../keep.h")
    );
    std::fs::remove_dir_all(base).unwrap();
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn git(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn init_git(dir: &Path) -> bool {
    git(dir, &["init"])
        && git(
            dir,
            &["config", "user.email", "buildutil-test@example.invalid"],
        )
        && git(dir, &["config", "user.name", "buildutil test"])
        && git(dir, &["config", "core.filemode", "true"])
        && git(dir, &["config", "core.autocrlf", "false"])
}

fn commit_all(repo: &Path, message: &str) {
    assert!(git(repo, &["add", "-A"]));
    assert!(git(repo, &["commit", "--no-gpg-sign", "-m", message]));
}

fn assert_route_equivalence(
    cas: &SourceCas,
    root: &Path,
    subtree: &Path,
    expect_top_object_route: bool,
    expect_nested_object_route: bool,
) {
    let top_oracle = cas.ingest_pure_fs_oracle(root).unwrap();
    let top = {
        let _eval = super::GitEvalCacheScope::new();
        let checked = super::git::checked_git_tree(root);
        assert_eq!(
            checked.is_some(),
            expect_top_object_route,
            "unexpected toplevel guard decision for {}",
            root.display()
        );
        cas.ingest_git_tree(root).unwrap()
    };
    assert_eq!(top, top_oracle, "toplevel route differs from pure FS");

    let subtree_oracle = cas.ingest_pure_fs_oracle(subtree).unwrap();
    let subtree_hash = {
        let _eval = super::GitEvalCacheScope::new();
        let checked = super::git::checked_git_tree(subtree);
        assert_eq!(
            checked.is_some(),
            expect_nested_object_route,
            "unexpected nested-route guard decision for {}",
            subtree.display()
        );
        cas.hash_and_ingest_dir(subtree).unwrap()
    };
    assert_eq!(
        subtree_hash, subtree_oracle,
        "subtree route differs from pure FS"
    );
}

fn new_repo_fixture(tag: &str) -> (PathBuf, PathBuf, SourceCas) {
    let base = temp_path(tag);
    let root = base.join("repo");
    let state = base.join("state");
    std::fs::create_dir_all(root.join("sub/deep")).unwrap();
    assert!(init_git(&root));
    write_filter(&root, "");
    (base, root, SourceCas::open(&state).unwrap())
}

#[test]
fn git_identity_matches_tracked_diff_contract() {
    if !git_available() {
        return;
    }
    let root = temp_path("git-identity");
    std::fs::create_dir_all(&root).unwrap();
    assert!(init_git(&root));
    std::fs::write(root.join("tracked.txt"), b"head\n").unwrap();
    commit_all(&root, "head");

    let assert_contract = || {
        let legacy_dirty =
            !(git(&root, &["diff", "--quiet"]) && git(&root, &["diff", "--cached", "--quiet"]));
        let (_, dirty) = super::git::identity_for(&root).unwrap();
        assert_eq!(dirty, legacy_dirty);
    };
    assert_contract();
    std::fs::write(root.join("untracked.txt"), b"ignored by identity\n").unwrap();
    assert_contract();
    std::fs::write(root.join("tracked.txt"), b"worktree\n").unwrap();
    assert_contract();
    assert!(git(&root, &["add", "tracked.txt"]));
    assert_contract();

    std::fs::remove_dir_all(root).unwrap();
}

fn loose_object_path(repo: &Path, oid: &str) -> Option<PathBuf> {
    let (dir, file) = oid.split_at(2);
    let path = repo.join(".git/objects").join(dir).join(file);
    path.is_file().then_some(path)
}

#[test]
fn blob_dual_variant_modes() {
    let root = temp_path("blob-modes");
    let state = root.join(".buildutil");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let plain = root.join("plain");
    let exe = root.join("exe");
    std::fs::write(&plain, b"same").unwrap();
    std::fs::write(&exe, b"same").unwrap();
    crate::platform::set_mode(&plain, 0o644).unwrap();
    crate::platform::set_mode(&exe, 0o755).unwrap();

    let (h1, k1) = cas.hash_and_ingest_file(&plain).unwrap();
    let (h2, k2) = cas.hash_and_ingest_file(&exe).unwrap();

    assert_eq!(h1, h2);
    assert_eq!(k1, 'f');
    assert_eq!(k2, if cfg!(windows) { 'f' } else { 'x' });
    assert_eq!(
        crate::platform::file_mode(&std::fs::metadata(cas.blob_path(&h1, 'f')).unwrap()) & 0o777,
        0o444
    );
    assert_eq!(
        crate::platform::file_mode(
            &std::fs::metadata(cas.blob_path(&h2, if cfg!(windows) { 'f' } else { 'x' })).unwrap()
        ) & 0o777,
        if cfg!(windows) { 0o444 } else { 0o555 }
    );
    assert!(cas.blob_path(&h1, 'f').is_file());
    assert!(
        cas.blob_path(&h2, if cfg!(windows) { 'f' } else { 'x' })
            .is_file()
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn write_once_publish_keeps_preexisting_object() {
    let root = temp_path("write-once");
    let state = root.join(".buildutil");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let src = root.join("src");
    std::fs::write(&src, b"content").unwrap();
    let hash = crate::crypto::sha256::hash_bytes(b"content");
    let final_path = cas.blob_path(&hash, 'f');
    std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
    std::fs::write(&final_path, b"content").unwrap();
    crate::platform::set_mode(&final_path, 0o444).unwrap();

    let (got, kind) = cas.hash_and_ingest_file(&src).unwrap();

    assert_eq!(got, hash);
    assert_eq!(kind, 'f');
    assert_eq!(std::fs::read(&final_path).unwrap(), b"content");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn stat_cache_hit_with_existing_blob_needs_no_tmp_write() {
    let _cas_guard = super::cas_test_guard();
    let root = temp_path("stat-cache");
    let state = root.join(".buildutil");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    statcache::load_file_cache(&state, &root);
    let src = root.join("src");
    std::fs::write(&src, b"cached").unwrap();

    let (hash, kind) = cas.hash_and_ingest_file(&src).unwrap();
    assert_eq!(kind, 'f');
    assert!(cas.blob_path(&hash, kind).is_file());

    let tmp = crate::state::source_tmp_dir(&state);
    crate::platform::set_mode(&tmp, 0o555).unwrap();
    let second = cas.hash_and_ingest_file(&src);
    crate::platform::set_mode(&tmp, 0o755).unwrap();

    assert_eq!(second.unwrap(), (hash, kind));
    assert!(std::fs::read_dir(&tmp).unwrap().next().is_none());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn stat_cache_shards_are_safe_under_parallel_worktree_hashing() {
    let _cas_guard = super::cas_test_guard();
    let base = temp_path("stat-cache-parallel");
    let root = base.join("src");
    let state = base.join("state");
    std::fs::create_dir_all(&root).unwrap();
    write_filter(&root, "");
    for index in 0..128 {
        std::fs::write(
            root.join(format!("file-{index:03}")),
            format!("parallel-cache-{index}\n"),
        )
        .unwrap();
    }
    statcache::load_file_cache(&state, &root);
    let cas = SourceCas::open(&state).unwrap();
    let first = cas.hash_and_ingest_dir(&root).unwrap();
    let hits_before = statcache::statcache_hits();
    let second = cas.hash_and_ingest_dir(&root).unwrap();

    assert_eq!(second, first);
    assert!(
        statcache::statcache_hits() >= hits_before + 128,
        "the warm parallel pass must hit every file"
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn tree_object_round_trip_and_corruption_checks() {
    let root = temp_path("tree-roundtrip");
    let state = root.join(".buildutil");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(root.join("dir")).unwrap();
    write_filter(&root, "");
    std::fs::write(root.join("dir/file"), b"data").unwrap();
    crate::platform::create_symlink_auto(Path::new("file"), &root.join("dir/link")).unwrap();

    let dirhash = cas.hash_and_ingest_dir(&root).unwrap();
    let loaded = cas.load_tree_object(&dirhash).unwrap();
    assert_eq!(
        crate::crypto::sha256::hash_bytes(manifest_entries(&loaded.entries).as_bytes()),
        dirhash
    );

    let path = cas.tree_path(&dirhash);
    let original = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, original.replacen("dir/file", "dir/FILE", 1)).unwrap();
    assert!(cas.load_tree_object(&dirhash).is_err());
    std::fs::write(&path, &original).unwrap();
    let without_targets = original
        .lines()
        .filter(|line| !line.contains("=file"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&path, without_targets).unwrap();
    assert!(cas.load_tree_object(&dirhash).is_err());
    std::fs::write(&path, original).unwrap();
    assert!(cas.load_tree_object(&dirhash).is_ok());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn filtered_walk_matches_hash_dir_when_nothing_is_filtered() {
    let base = temp_path("equivalence");
    let root = base.join("src");
    let state = base.join("state");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    write_filter(&root, "");
    std::fs::write(root.join("a/file"), b"alpha").unwrap();
    std::fs::write(root.join("a/b/exe"), b"beta").unwrap();
    crate::platform::set_mode(&root.join("a/b/exe"), 0o755).unwrap();
    crate::platform::create_symlink_auto(Path::new("../file"), &root.join("a/b/link")).unwrap();

    let cas_hash = cas.hash_and_ingest_dir(&root).unwrap();
    let pure_hash = filehash::hash_dir(&root).unwrap();

    assert_eq!(cas_hash, pure_hash);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn parallel_walk_matches_sequential_manifest_fixture() {
    let base = temp_path("parallel-determinism");
    let root = base.join("src");
    let state = base.join("state");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    std::fs::create_dir_all(root.join("c")).unwrap();
    write_filter(&root, "");
    for idx in 0..24 {
        let path = if idx % 2 == 0 {
            root.join("a").join(format!("file-{idx:02}"))
        } else {
            root.join("a/b").join(format!("file-{idx:02}"))
        };
        std::fs::write(path, format!("content-{idx}\n")).unwrap();
    }
    std::fs::write(root.join("c/tool"), b"#!/bin/sh\n").unwrap();
    crate::platform::set_mode(&root.join("c/tool"), 0o755).unwrap();
    crate::platform::create_symlink_auto(Path::new("../a/file-00"), &root.join("c/link")).unwrap();

    let parallel = cas.hash_and_ingest_dir(&root).unwrap();
    let sequential_manifest = filehash::dir_manifest(&root).unwrap();
    let sequential = crate::crypto::sha256::hash_bytes(sequential_manifest.as_bytes());

    assert_eq!(parallel, sequential);
    assert_eq!(
        manifest_entries(&cas.load_tree_object(&parallel).unwrap().entries),
        sequential_manifest
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn reflink_fallback_ingests_by_copy() {
    let root = temp_path("reflink-fallback");
    let state = root.join(".buildutil");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let src = root.join("src");
    std::fs::write(&src, b"fallback").unwrap();

    let (hash, kind) = cas.hash_and_ingest_file_inner(&src, false).unwrap();

    assert_eq!(hash, crate::crypto::sha256::hash_bytes(b"fallback"));
    assert_eq!(kind, 'f');
    assert_eq!(
        std::fs::read(cas.blob_path(&hash, kind)).unwrap(),
        b"fallback"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn symlink_target_recovers_on_materialize() {
    let root = temp_path("symlink");
    let state = root.join(".buildutil");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    write_filter(&root, "");
    std::fs::write(root.join("target"), b"target").unwrap();
    crate::platform::create_symlink_auto(Path::new("target"), &root.join("link")).unwrap();

    let dirhash = cas.hash_and_ingest_dir(&root).unwrap();
    let out = root.join("out");
    cas.materialize_tree(&dirhash, &out).unwrap();

    assert_eq!(
        std::fs::read_link(out.join("link")).unwrap(),
        PathBuf::from("target")
    );
    assert_eq!(std::fs::read(out.join("target")).unwrap(), b"target");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn gitlink_is_not_part_of_the_parent_source_tree() {
    let _cas_guard = super::cas_test_guard();
    let _eval_caches = super::GitEvalCacheScope::new();
    if !git_available() {
        return;
    }
    let root = temp_path("gitlink");
    let state = root.join("state");
    let cas = SourceCas::open(&state).unwrap();
    let sub = root.join("sub");
    let parent = root.join("parent");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::create_dir_all(&parent).unwrap();
    write_filter(&parent, ".git\n");
    write_filter(&sub, ".git\n");
    if !(init_git(&sub)
        && {
            std::fs::write(sub.join("nested.txt"), b"nested").unwrap();
            git(&sub, &["add", "."])
        }
        && git(&sub, &["commit", "--no-gpg-sign", "-m", "sub"])
        && init_git(&parent)
        && {
            std::fs::write(parent.join("root.txt"), b"root").unwrap();
            true
        }
        && git(
            &parent,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                sub.to_str().unwrap(),
                "vendor/sub",
            ],
        )
        && git(&parent, &["add", "."])
        && git(&parent, &["commit", "--no-gpg-sign", "-m", "parent"]))
    {
        let _ = std::fs::remove_dir_all(&root);
        return;
    }

    let dirhash = cas.ingest_git_tree(&parent).unwrap();
    let filter = SourceFilter::load(&parent).unwrap();
    let pure = collect_filtered_pure(&parent, &filter).unwrap();
    assert_eq!(
        dirhash,
        crate::crypto::sha256::hash_bytes(manifest_entries(&pure.entries).as_bytes())
    );
    let out = root.join("out");
    cas.materialize_tree(&dirhash, &out).unwrap();

    assert_eq!(std::fs::read(out.join("root.txt")).unwrap(), b"root");
    assert!(!out.join("vendor/sub").exists());
    let nested_hash = cas.ingest_git_tree(&parent.join("vendor/sub")).unwrap();
    let nested_out = root.join("nested-out");
    cas.materialize_tree(&nested_hash, &nested_out).unwrap();
    assert_eq!(
        std::fs::read(nested_out.join("nested.txt")).unwrap(),
        b"nested"
    );
    assert!(!out.join(".git").exists());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn dirty_gitlink_recurses_hybrid_without_hashing_unchanged_submodule_files() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let root = temp_path("gitlink-dirty-hybrid");
    let state = root.join("state");
    let cas = SourceCas::open(&state).unwrap();
    let sub = root.join("sub");
    let parent = root.join("parent");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::create_dir_all(&parent).unwrap();
    write_filter(&parent, ".git\n");
    write_filter(&sub, ".git\n");
    assert!(init_git(&sub));
    for i in 0..64 {
        std::fs::write(sub.join(format!("file-{i:03}.txt")), format!("head-{i}\n")).unwrap();
    }
    commit_all(&sub, "sub");
    assert!(init_git(&parent));
    assert!(git(
        &parent,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            sub.to_str().unwrap(),
            "vendor/sub",
        ],
    ));
    commit_all(&parent, "parent");
    std::fs::write(parent.join("vendor/sub/file-011.txt"), b"dirty\n").unwrap();

    let oracle = cas.ingest_pure_fs_oracle(&parent).unwrap();
    let actual = {
        let _eval = super::GitEvalCacheScope::new();
        cas.hash_and_ingest_dir(&parent).unwrap()
    };
    assert_eq!(actual, oracle);
    assert_eq!(super::hybrid_fs_files(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn gittree_memo_hit_requires_tree_object() {
    let _cas_guard = super::cas_test_guard();
    let _eval_caches = super::GitEvalCacheScope::new();
    if !git_available() {
        return;
    }
    let base = temp_path("memo");
    let root = base.join("repo");
    let state = base.join("state");
    let cas = SourceCas::open(&state).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    write_filter(&root, "");
    if !(init_git(&root)
        && {
            std::fs::write(root.join("file"), b"one").unwrap();
            git(&root, &["add", "."])
        }
        && git(&root, &["commit", "--no-gpg-sign", "-m", "one"]))
    {
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    let _tree = clean_checkout_tree_id(&root).unwrap();
    let dirhash = cas.ingest_git_tree(&root).unwrap();
    let checked = super::git::checked_git_tree(&root).unwrap();
    let filter = SourceFilter::load(&root).unwrap();
    let memo = cas.gittree_memo_path(&checked, &filter);
    assert_eq!(std::fs::read_to_string(&memo).unwrap().trim(), dirhash);

    let tree_path = cas.tree_path(&dirhash);
    std::fs::remove_file(&tree_path).unwrap();
    let dirhash2 = cas.ingest_git_tree(&root).unwrap();
    assert_eq!(dirhash2, dirhash);
    assert!(tree_path.is_file());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn oid_memo_hit_skips_git_blob_read() {
    let _cas_guard = super::cas_test_guard();
    let _eval_caches = super::GitEvalCacheScope::new();
    if !git_available() {
        return;
    }
    let base = temp_path("oid-memo");
    let root = base.join("repo");
    let state = base.join("state");
    std::fs::create_dir_all(&root).unwrap();
    write_filter(&root, "");
    if !(init_git(&root)
        && {
            std::fs::write(root.join("file"), b"one").unwrap();
            git(&root, &["add", "."])
        }
        && git(&root, &["commit", "--no-gpg-sign", "-m", "one"]))
    {
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    let cas = SourceCas::open(&state).unwrap();
    let tree = clean_checkout_tree_id(&root).unwrap();
    let checked = super::git::checked_git_tree(&root).unwrap();
    let oid = git_output(&root, &["rev-parse", "HEAD:file"]).unwrap();
    let loose = match loose_object_path(&root, &oid) {
        Some(path) => path,
        None => {
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
    };
    let hash = cas
        .ingest_git_blob_bytes(
            &checked.toplevel,
            &checked.conversion_state,
            &oid,
            "file",
            b"one",
            'f',
        )
        .unwrap();
    // The blob hash is now in the evaluation-local memo; drop the loose object so the
    // re-collect below can only succeed via a memo hit, not a git read.
    std::fs::remove_file(loose).unwrap();

    let filter = SourceFilter::load(&root).unwrap();
    let mut object = TreeObject {
        entries: Vec::new(),
        targets: std::collections::BTreeMap::new(),
    };
    assert_eq!(tree, checked.tree_id);
    cas.collect_git_tree(&checked, "", &filter, &mut object, &mut Vec::new())
        .unwrap();
    let memo_tree = cas.write_tree_object(&object).unwrap();
    let oracle = cas.ingest_pure_fs_oracle(&root).unwrap();
    assert_eq!(memo_tree, oracle, "blob memo hit differs from pure FS");

    assert!(
        object
            .entries
            .iter()
            .any(|entry| { entry.rel == "file" && entry.hash == hash && entry.kind == 'f' })
    );
    // The evaluation-local memo is never persisted, so the legacy
    // `cache/git-blob-map` file must never be created or rewritten.
    let legacy_exists = crate::state::git_blob_memo(&state).exists();
    assert!(
        !legacy_exists,
        "legacy cache/git-blob-map must not be rewritten"
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn oid_memo_backfills_kind_variant_from_other_variant() {
    let _cas_guard = super::cas_test_guard();
    let _eval_caches = super::GitEvalCacheScope::new();
    if !git_available() {
        return;
    }
    let base = temp_path("oid-backfill");
    let root = base.join("repo");
    let state = base.join("state");
    std::fs::create_dir_all(&root).unwrap();
    write_filter(&root, "");
    if !(init_git(&root)
        && {
            std::fs::write(root.join("run"), b"run").unwrap();
            crate::platform::set_mode(&root.join("run"), 0o755).unwrap();
            git(&root, &["add", "."])
        }
        && git(&root, &["update-index", "--chmod=+x", "run"])
        && git(&root, &["commit", "--no-gpg-sign", "-m", "run"]))
    {
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    let cas = SourceCas::open(&state).unwrap();
    let tree = clean_checkout_tree_id(&root).unwrap();
    let checked = super::git::checked_git_tree(&root).unwrap();
    let oid = git_output(&root, &["rev-parse", "HEAD:run"]).unwrap();
    let loose = match loose_object_path(&root, &oid) {
        Some(path) => path,
        None => {
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
    };
    let (hash, _) = cas.ingest_bytes(b"run", 'f').unwrap();
    statcache::record_git_blob_hash(
        &checked.toplevel,
        super::GIT_INGEST_SCHEMA_VERSION,
        &checked.conversion_state,
        &oid,
        "run",
        &hash,
    );
    std::fs::remove_file(loose).unwrap();

    let filter = SourceFilter::load(&root).unwrap();
    let mut object = TreeObject {
        entries: Vec::new(),
        targets: std::collections::BTreeMap::new(),
    };
    assert_eq!(tree, checked.tree_id);
    cas.collect_git_tree(&checked, "", &filter, &mut object, &mut Vec::new())
        .unwrap();
    let memo_tree = cas.write_tree_object(&object).unwrap();
    let oracle = cas.ingest_pure_fs_oracle(&root).unwrap();
    assert_eq!(memo_tree, oracle, "blob memo hit differs from pure FS");

    assert!(cas.blob_path(&hash, 'x').is_file());
    assert!(
        object
            .entries
            .iter()
            .any(|entry| { entry.rel == "run" && entry.hash == hash && entry.kind == 'x' })
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn custom_filter_attr_detected_scoped_and_nested() {
    let _cas_guard = super::cas_test_guard();
    let _eval_caches = super::GitEvalCacheScope::new();
    if !git_available() {
        return;
    }
    // A scoped, nested `filter=lfs` — the exact pattern a toplevel
    // `check-attr -- .` misses. Its driver makes worktree bytes diverge from
    // `git cat-file --filters`, so the toplevel object-db path must refuse and
    // fall back to the walk.
    let root = temp_path("custom-filter");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    assert!(init_git(&root));
    std::fs::write(root.join("sub/.gitattributes"), "*.bin filter=lfs\n").unwrap();
    std::fs::write(root.join("sub/data.bin"), b"x").unwrap();
    std::fs::write(root.join("top.txt"), b"y").unwrap();
    assert!(git(&root, &["add", "-A"]));
    assert!(git(&root, &["commit", "--no-gpg-sign", "-m", "init"]));
    let probe = super::git::probe_for(&root).expect("probe");
    assert!(
        !probe.no_custom_filter_attr.is_safe(),
        "scoped nested filter=lfs must disable the fast path"
    );
    std::fs::remove_dir_all(&root).unwrap();

    // A repo with no filter driver leaves the fast path available.
    let clean = temp_path("no-filter");
    std::fs::create_dir_all(&clean).unwrap();
    assert!(init_git(&clean));
    std::fs::write(clean.join("a.txt"), b"z").unwrap();
    assert!(git(&clean, &["add", "-A"]));
    assert!(git(&clean, &["commit", "--no-gpg-sign", "-m", "init"]));
    let probe2 = super::git::probe_for(&clean).expect("probe2");
    assert!(
        probe2.no_custom_filter_attr.is_safe(),
        "no filter driver keeps the fast path"
    );
    std::fs::remove_dir_all(&clean).unwrap();
}

#[test]
fn git_object_routes_match_pure_fs_across_repo_state_matrix() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }

    // A clean toplevel uses the object db; its ordinary subtree always walks.
    let (base, root, cas) = new_repo_fixture("matrix-clean");
    std::fs::write(root.join("B.txt"), b"upper\n").unwrap();
    std::fs::write(root.join("a.txt"), b"lower\n").unwrap();
    std::fs::write(root.join("sub/data.txt"), b"sub\n").unwrap();
    std::fs::write(root.join("sub/deep/z.txt"), b"deep\n").unwrap();
    commit_all(&root, "clean");
    assert_route_equivalence(&cas, &root, &root.join("sub"), true, false);
    std::fs::remove_dir_all(base).unwrap();

    // Ignored files that the source filter also excludes do not change either
    // route's identity and must not demote a clean checkout to the FS walk.
    let (base, root, cas) = new_repo_fixture("matrix-filtered-ignored");
    write_filter(&root, "__pycache__/\n");
    std::fs::write(root.join(".gitignore"), b"__pycache__/\n").unwrap();
    std::fs::write(root.join("sub/data.txt"), b"tracked\n").unwrap();
    commit_all(&root, "filtered ignored");
    std::fs::create_dir_all(root.join("sub/__pycache__")).unwrap();
    std::fs::write(root.join("sub/__pycache__/generated.pyc"), b"ignored\n").unwrap();
    assert_route_equivalence(&cas, &root, &root.join("sub"), true, false);
    std::fs::remove_dir_all(base).unwrap();

    // A tracked edit invalidates the toplevel proof; both routes read it from FS.
    let (base, root, cas) = new_repo_fixture("matrix-dirty-file");
    std::fs::write(root.join("sub/data.txt"), b"head\n").unwrap();
    commit_all(&root, "head");
    std::fs::write(root.join("sub/data.txt"), b"worktree\n").unwrap();
    assert_route_equivalence(&cas, &root, &root.join("sub"), false, false);
    std::fs::remove_dir_all(base).unwrap();

    // An ancestor attributes edit invalidates the toplevel proof, while the
    // subtree's unconditional walk observes the effective worktree bytes.
    let (base, root, cas) = new_repo_fixture("matrix-dirty-attrs");
    std::fs::write(root.join(".gitattributes"), b"# committed\n").unwrap();
    std::fs::write(root.join("sub/data.txt"), b"line\n").unwrap();
    commit_all(&root, "attrs");
    std::fs::write(root.join(".gitattributes"), b"sub/*.txt text eol=crlf\n").unwrap();
    assert_route_equivalence(&cas, &root, &root.join("sub"), false, false);
    std::fs::remove_dir_all(base).unwrap();

    // An ignored-but-present file is ingested when `.buildutilignore` keeps it, so
    // the toplevel status must detect it and refuse stale HEAD content.
    let (base, root, cas) = new_repo_fixture("matrix-ignored-present");
    std::fs::write(root.join(".gitignore"), b"sub/generated.txt\n").unwrap();
    std::fs::write(root.join("sub/data.txt"), b"tracked\n").unwrap();
    commit_all(&root, "ignored");
    std::fs::write(root.join("sub/generated.txt"), b"generated\n").unwrap();
    assert_route_equivalence(&cas, &root, &root.join("sub"), false, false);
    std::fs::remove_dir_all(base).unwrap();

    // A nested, scoped external filter is detected across all tracked paths.
    let (base, root, cas) = new_repo_fixture("matrix-custom-filter");
    assert!(git(
        &root,
        &["config", "filter.buildutil-test.clean", "cat"]
    ));
    assert!(git(
        &root,
        &["config", "filter.buildutil-test.smudge", "cat"]
    ));
    std::fs::write(
        root.join("sub/.gitattributes"),
        b"deep/*.bin filter=buildutil-test\n",
    )
    .unwrap();
    std::fs::write(root.join("sub/deep/data.bin"), b"payload\n").unwrap();
    commit_all(&root, "filter");
    assert_route_equivalence(&cas, &root, &root.join("sub"), false, false);
    std::fs::remove_dir_all(base).unwrap();

    // Sparse checkout omits tracked paths from disk; object-db ingestion must
    // not silently re-introduce them.
    let (base, root, cas) = new_repo_fixture("matrix-sparse");
    std::fs::write(root.join("sub/keep.txt"), b"keep\n").unwrap();
    std::fs::write(root.join("sub/drop.txt"), b"drop\n").unwrap();
    std::fs::write(root.join("outside.txt"), b"outside\n").unwrap();
    commit_all(&root, "sparse");
    assert!(git(&root, &["config", "core.sparseCheckout", "true"]));
    std::fs::write(
        root.join(".git/info/sparse-checkout"),
        b"/.buildutilignore\n/sub/keep.txt\n",
    )
    .unwrap();
    assert!(git(&root, &["read-tree", "-mu", "HEAD"]));
    assert!(root.join("sub/keep.txt").is_file());
    assert!(!root.join("sub/drop.txt").exists());
    assert_route_equivalence(&cas, &root, &root.join("sub"), false, false);
    std::fs::remove_dir_all(base).unwrap();

    // core.autocrlf changes checkout conversion. The conservative guard refuses
    // it because config can change without refreshing existing worktree bytes.
    let (base, root, cas) = new_repo_fixture("matrix-autocrlf");
    assert!(git(&root, &["config", "core.autocrlf", "true"]));
    std::fs::write(root.join("sub/data.txt"), b"one\r\ntwo\r\n").unwrap();
    commit_all(&root, "autocrlf");
    assert_route_equivalence(&cas, &root, &root.join("sub"), false, false);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn dirty_hybrid_hashes_only_overlay_files_and_matches_full_walk() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let (base, root, cas) = new_repo_fixture("dirty-hybrid-count");
    for i in 0..128 {
        std::fs::write(
            root.join(format!("sub/file-{i:03}.txt")),
            format!("head-{i}\n"),
        )
        .unwrap();
    }
    commit_all(&root, "head");
    std::fs::write(root.join("sub/file-003.txt"), b"modified\n").unwrap();
    std::fs::remove_file(root.join("sub/file-007.txt")).unwrap();
    std::fs::write(root.join("sub/new.txt"), b"untracked\n").unwrap();

    let oracle = cas.ingest_pure_fs_oracle(&root).unwrap();
    let actual = {
        let _eval = super::GitEvalCacheScope::new();
        cas.hash_and_ingest_dir(&root).unwrap()
    };
    assert_eq!(actual, oracle);
    assert_eq!(super::hybrid_fs_files(), 2, "modified + untracked only");
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn filtered_blob_probe_uses_repository_when_started_outside_git() {
    const CHILD: &str = "BUILDUTIL_TEST_FILTERS_PROBE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let base = temp_path("filters-probe-cwd");
        std::fs::create_dir_all(&base).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "source::tests::filtered_blob_probe_uses_repository_when_started_outside_git",
            ])
            .env(CHILD, "1")
            .current_dir(&base)
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "child test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(base).unwrap();
        return;
    }
    if !git_available() {
        return;
    }
    assert!(git_output(Path::new("."), &["rev-parse", "--show-toplevel"]).is_none());
    let (base, root, cas) = new_repo_fixture("filters-probe-repo");
    std::fs::write(root.join("tracked.txt"), b"source\n").unwrap();
    commit_all(&root, "head");
    if !git(&root, &["cat-file", "--batch", "--filters"]) {
        std::fs::remove_dir_all(base).unwrap();
        return;
    }
    let root = root.canonicalize().unwrap();
    assert!(!super::git::filtered_blob_reading_available(&base));
    assert!(super::git::filtered_blob_reading_available(&root));
    assert!(super::git::checked_git_tree(&root).is_some());
    assert_eq!(
        cas.hash_and_ingest_dir(&root).unwrap(),
        cas.ingest_pure_fs_oracle(&root).unwrap()
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn git_blob_content_key_survives_checkout_path_change() {
    let _cas_guard = super::cas_test_guard();
    let base = temp_path("git-blob-persistent");
    let state = base.join("state");
    let repo_a = base.join("host/repo");
    let repo_b = base.join("container/repo");
    std::fs::create_dir_all(&repo_a).unwrap();
    std::fs::create_dir_all(&repo_b).unwrap();
    super::statcache::load_file_cache(&state, &repo_a);
    let conversion = "a".repeat(64);
    let oid = "b".repeat(40);
    let digest = "c".repeat(64);
    {
        let _eval = super::GitEvalCacheScope::new();
        super::statcache::record_git_blob_hash(
            &repo_a,
            super::GIT_INGEST_SCHEMA_VERSION,
            &conversion,
            &oid,
            "tracked.txt",
            &digest,
        );
    }
    {
        let _eval = super::GitEvalCacheScope::new();
        assert_eq!(
            super::statcache::cached_git_blob_hash(
                &repo_b,
                super::GIT_INGEST_SCHEMA_VERSION,
                &conversion,
                &oid,
                "tracked.txt",
            )
            .as_deref(),
            Some(digest.as_str())
        );
    }
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn scoped_hybrid_preserves_sources_and_prunes_ignored_directories() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let (base, root, cas) = new_repo_fixture("scoped-hybrid");
    let selected = root.join("pkg[1]");
    std::fs::create_dir_all(&selected).unwrap();
    std::fs::create_dir_all(root.join("pkg1")).unwrap();
    write_filter(&root, ".buildutil/\n*.o\n");
    std::fs::write(root.join(".gitignore"), b".buildutil/\ngenerated/\n*.o\n").unwrap();
    std::fs::write(selected.join("tracked.txt"), b"head\n").unwrap();
    std::fs::write(selected.join("deleted.txt"), b"head\n").unwrap();
    std::fs::write(root.join("pkg1/outside.txt"), b"head\n").unwrap();
    commit_all(&root, "head");

    std::fs::write(selected.join("tracked.txt"), b"changed\n").unwrap();
    std::fs::remove_file(selected.join("deleted.txt")).unwrap();
    std::fs::write(selected.join("untracked.txt"), b"new\n").unwrap();
    std::fs::write(root.join("pkg1/outside.txt"), b"outside change\n").unwrap();
    std::fs::create_dir_all(selected.join("generated/deep")).unwrap();
    std::fs::write(
        selected.join("generated/deep/keep.txt"),
        b"ignored source\n",
    )
    .unwrap();
    std::fs::write(selected.join("generated/deep/drop.o"), b"excluded\n").unwrap();
    for dir in [root.join(".buildutil"), selected.join(".buildutil")] {
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..128 {
            std::fs::write(dir.join(format!("output-{i}")), b"excluded state\n").unwrap();
        }
    }

    let filter = SourceFilter::load_for_walk(&selected).unwrap();
    assert!(filter.excludes(".buildutil", true));
    let paths = super::git::hybrid_changed_paths(&root, "pkg[1]", &filter, "").unwrap();
    assert_eq!(
        paths,
        ["deleted.txt", "generated", "tracked.txt", "untracked.txt"]
    );
    let oracle = cas.ingest_pure_fs_oracle(&selected).unwrap();
    super::HYBRID_FS_FILES.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    let actual = {
        let _eval = super::GitEvalCacheScope::new();
        cas.hash_and_ingest_dir(&selected).unwrap()
    };
    assert_eq!(actual, oracle, "scoping must preserve ignored source files");
    assert_eq!(super::hybrid_fs_files(), 3);

    // The same query at a repository root must still discover all changes.
    let oracle = cas.ingest_pure_fs_oracle(&root).unwrap();
    let actual = {
        let _eval = super::GitEvalCacheScope::new();
        cas.hash_and_ingest_dir(&root).unwrap()
    };
    assert_eq!(actual, oracle);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn scoped_hybrid_directory_filter_uses_the_ingested_entry_prefix() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let (base, root, _cas) = new_repo_fixture("scoped-hybrid-prefix");
    write_filter(&root, "/vendor/pkg/.buildutil/\n");
    std::fs::write(root.join(".gitignore"), b".buildutil/\ngenerated/\n").unwrap();
    std::fs::write(root.join("sub/tracked.txt"), b"head\n").unwrap();
    commit_all(&root, "head");
    for dir in ["sub/.buildutil", "sub/generated"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
        std::fs::write(root.join(dir).join("data"), b"new\n").unwrap();
    }
    let filter = SourceFilter::load(&root).unwrap();
    assert_eq!(
        super::git::hybrid_changed_paths(&root, "sub", &filter, "vendor/pkg").unwrap(),
        ["generated"]
    );
    assert_eq!(
        super::git::hybrid_changed_paths(&root, "sub", &filter, "other/pkg").unwrap(),
        [".buildutil", "generated"]
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn scoped_hybrid_walks_an_ignored_source_root() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let (base, root, cas) = new_repo_fixture("scoped-hybrid-root");
    std::fs::write(root.join(".gitignore"), b"generated/\n").unwrap();
    commit_all(&root, "head");
    let selected = root.join("generated");
    std::fs::create_dir_all(&selected).unwrap();
    std::fs::write(selected.join("keep.txt"), b"source\n").unwrap();
    let oracle = cas.ingest_pure_fs_oracle(&selected).unwrap();
    let actual = {
        let _eval = super::GitEvalCacheScope::new();
        cas.hash_and_ingest_dir(&selected).unwrap()
    };
    assert_eq!(actual, oracle);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn submodule_git_file_and_git_dir_match_pure_fs() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }

    // Normal `git submodule add`: nested `.git` is a gitdir pointer file.
    let base = temp_path("matrix-gitfile");
    let source = base.join("source");
    let parent = base.join("parent");
    let state = base.join("state");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&parent).unwrap();
    assert!(init_git(&source));
    write_filter(&source, "__pycache__/\n");
    std::fs::write(source.join(".gitignore"), b"__pycache__/\n").unwrap();
    std::fs::create_dir_all(source.join("subtree")).unwrap();
    std::fs::write(source.join("nested.txt"), b"gitfile\n").unwrap();
    std::fs::write(source.join("subtree/data.txt"), b"subtree\n").unwrap();
    commit_all(&source, "source");
    assert!(init_git(&parent));
    write_filter(&parent, "__pycache__/\n");
    std::fs::write(parent.join("root.txt"), b"parent\n").unwrap();
    assert!(git(
        &parent,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            source.to_str().unwrap(),
            "vendor/sub",
        ],
    ));
    commit_all(&parent, "parent");
    let nested = parent.join("vendor/sub");
    assert!(nested.join(".git").is_file());
    std::fs::create_dir_all(nested.join("__pycache__")).unwrap();
    std::fs::write(nested.join("__pycache__/generated.pyc"), b"ignored\n").unwrap();
    let cas = SourceCas::open(&state).unwrap();
    assert_route_equivalence(&cas, &parent, &nested, true, true);
    assert_route_equivalence(&cas, &nested, &nested.join("subtree"), true, true);
    let oracle = cas.ingest_pure_fs_oracle(&parent).unwrap();
    let object = cas.load_tree_object(&oracle).unwrap();
    assert!(
        !object
            .entries
            .iter()
            .any(|entry| entry.rel.split('/').any(|part| part == ".git"))
    );
    std::fs::remove_dir_all(&base).unwrap();

    // Embedded repository added as a gitlink: nested `.git` remains a dir.
    let base = temp_path("matrix-gitdir");
    let parent = base.join("parent");
    let nested = parent.join("vendor/embedded");
    let state = base.join("state");
    std::fs::create_dir_all(&nested).unwrap();
    assert!(init_git(&parent));
    write_filter(&parent, "");
    std::fs::write(parent.join("root.txt"), b"parent\n").unwrap();
    assert!(init_git(&nested));
    write_filter(&nested, "");
    std::fs::write(nested.join("nested.txt"), b"gitdir\n").unwrap();
    commit_all(&nested, "embedded");
    commit_all(&parent, "parent");
    assert!(nested.join(".git").is_dir());
    let cas = SourceCas::open(&state).unwrap();
    assert_route_equivalence(&cas, &parent, &nested, true, true);
    let oracle = cas.ingest_pure_fs_oracle(&parent).unwrap();
    let object = cas.load_tree_object(&oracle).unwrap();
    assert!(
        !object
            .entries
            .iter()
            .any(|entry| entry.rel.split('/').any(|part| part == ".git"))
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn dev_watch_eval_scope_observes_edit_after_clean_probe() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let (base, root, cas) = new_repo_fixture("dev-watch-cache-scope");
    let subtree = root.join("sub");
    std::fs::write(subtree.join("data.txt"), b"head\n").unwrap();
    commit_all(&root, "head");

    let first = {
        let _eval = super::GitEvalCacheScope::new();
        assert!(super::git::checked_git_tree(&root).is_some());
        cas.hash_and_ingest_dir(&root).unwrap()
    };
    std::fs::write(subtree.join("data.txt"), b"edited-after-probe\n").unwrap();
    let second = {
        let _eval = super::GitEvalCacheScope::new();
        assert!(
            super::git::checked_git_tree(&root).is_none(),
            "the second evaluation must not reuse the first clean probe"
        );
        cas.hash_and_ingest_dir(&root).unwrap()
    };
    let oracle = cas.ingest_pure_fs_oracle(&root).unwrap();
    assert_ne!(first, second);
    assert_eq!(second, oracle);
    let out = base.join("out");
    cas.materialize_tree(&second, &out).unwrap();
    assert_eq!(
        std::fs::read(out.join("sub/data.txt")).unwrap(),
        b"edited-after-probe\n"
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn prewarmed_clean_route_is_revalidated_before_object_db_ingest() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let (base, root, cas) = new_repo_fixture("prewarm-revalidate");
    let subtree = root.join("sub");
    std::fs::write(subtree.join("data.txt"), b"head\n").unwrap();
    commit_all(&root, "head");

    let _eval = super::GitEvalCacheScope::new();
    super::git::prewarm_probes(std::slice::from_ref(&root));
    assert!(
        super::git::checked_git_tree(&root).is_some(),
        "the prewarmed candidate starts clean"
    );
    std::fs::write(subtree.join("data.txt"), b"changed-after-prewarm\n").unwrap();
    assert!(
        super::git::checked_git_tree(&root).is_none(),
        "a fresh proof must observe the post-prewarm edit"
    );

    let ingested = cas.hash_and_ingest_dir(&root).unwrap();
    let oracle = cas.ingest_pure_fs_oracle(&root).unwrap();
    assert_eq!(ingested, oracle);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn blob_memo_key_binds_repo_schema_and_conversion_state() {
    let _cas_guard = super::cas_test_guard();
    let base = temp_path("blob-memo-key");
    let repo_a = base.join("a");
    let repo_b = base.join("b");
    std::fs::create_dir_all(&repo_a).unwrap();
    std::fs::create_dir_all(&repo_b).unwrap();
    let _eval = super::GitEvalCacheScope::new();
    statcache::record_git_blob_hash(
        &repo_a,
        super::GIT_INGEST_SCHEMA_VERSION,
        "conversion-a",
        "oid",
        "path",
        "digest",
    );
    assert_eq!(
        statcache::cached_git_blob_hash(
            &repo_a,
            super::GIT_INGEST_SCHEMA_VERSION,
            "conversion-a",
            "oid",
            "path"
        )
        .as_deref(),
        Some("digest")
    );
    assert_eq!(
        statcache::cached_git_blob_hash(
            &repo_b,
            super::GIT_INGEST_SCHEMA_VERSION,
            "conversion-a",
            "oid",
            "path"
        )
        .as_deref(),
        Some("digest")
    );
    assert!(
        statcache::cached_git_blob_hash(
            &repo_a,
            super::GIT_INGEST_SCHEMA_VERSION + 1,
            "conversion-a",
            "oid",
            "path"
        )
        .is_none()
    );
    assert!(
        statcache::cached_git_blob_hash(
            &repo_a,
            super::GIT_INGEST_SCHEMA_VERSION,
            "conversion-b",
            "oid",
            "path"
        )
        .is_none()
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn git_eval_scope_clears_blob_memo_between_evaluations() {
    let _cas_guard = super::cas_test_guard();
    let repo = temp_path("blob-memo-eval-scope");
    std::fs::create_dir_all(&repo).unwrap();
    {
        let _eval = super::GitEvalCacheScope::new();
        statcache::record_git_blob_hash(
            &repo,
            super::GIT_INGEST_SCHEMA_VERSION,
            "conversion",
            "oid",
            "path",
            "digest",
        );
        assert!(
            statcache::cached_git_blob_hash(
                &repo,
                super::GIT_INGEST_SCHEMA_VERSION,
                "conversion",
                "oid",
                "path"
            )
            .is_some()
        );
    }
    {
        let _eval = super::GitEvalCacheScope::new();
        assert!(
            statcache::cached_git_blob_hash(
                &repo,
                super::GIT_INGEST_SCHEMA_VERSION,
                "conversion",
                "oid",
                "path"
            )
            .is_none(),
            "a new evaluation must start with an empty blob memo"
        );
    }
    std::fs::remove_dir_all(repo).unwrap();
}

#[test]
fn conversion_digest_tracks_info_external_attrs_and_autocrlf() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let (base, root, cas) = new_repo_fixture("conversion-state");
    std::fs::write(root.join(".gitattributes"), b"*.txt buildutil-level=root\n").unwrap();
    std::fs::write(
        root.join("sub/.gitattributes"),
        b"*.txt buildutil-level=nested\n",
    )
    .unwrap();
    std::fs::write(root.join("sub/data.txt"), b"data\n").unwrap();
    commit_all(&root, "attributes");

    let (baseline, baseline_memo) = {
        let _eval = super::GitEvalCacheScope::new();
        let checked = super::git::checked_git_tree(&root).unwrap();
        let filter = SourceFilter::load_for_walk(&root).unwrap();
        (
            checked.conversion_state.clone(),
            cas.gittree_memo_path(&checked, &filter),
        )
    };
    std::fs::write(
        root.join(".git/info/attributes"),
        b"*.txt buildutil-info=one\n",
    )
    .unwrap();
    let (info, info_memo) = {
        let _eval = super::GitEvalCacheScope::new();
        let checked = super::git::checked_git_tree(&root).unwrap();
        let filter = SourceFilter::load_for_walk(&root).unwrap();
        (
            checked.conversion_state.clone(),
            cas.gittree_memo_path(&checked, &filter),
        )
    };
    assert_ne!(baseline, info);
    assert_ne!(baseline_memo, info_memo);

    let external = base.join("external.attributes");
    std::fs::write(&external, b"*.txt buildutil-external=one\n").unwrap();
    assert!(git(
        &root,
        &["config", "core.attributesFile", external.to_str().unwrap()]
    ));
    let external_digest = {
        let _eval = super::GitEvalCacheScope::new();
        super::git::probe_for(&root)
            .unwrap()
            .conversion_state
            .unwrap()
    };
    assert_ne!(info, external_digest);

    assert!(git(&root, &["config", "core.autocrlf", "true"]));
    let autocrlf = {
        let _eval = super::GitEvalCacheScope::new();
        let probe = super::git::probe_for(&root).unwrap();
        assert!(!probe.conversion_identity.is_safe());
        probe.conversion_state.unwrap()
    };
    assert_ne!(external_digest, autocrlf);
    std::fs::remove_dir_all(base).unwrap();
}

// Container input attestation (`verified_bootstrap_content`'s repo-free branch): the
// fail-closed matrix, exercised without mutating process env by testing the
// pure `attested_bootstrap_content_from` directly.

const ATTEST_HASH: &str = "0123456789abcdef0123456789abcdef"; // 32 lower hex
const ATTEST_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 64 lower hex

fn attest_projection(base: &Path, dir_name: &str, with_mica: bool) -> PathBuf {
    let repo = base.join(dir_name);
    let mica = repo.join("library");
    std::fs::create_dir_all(&mica).unwrap();
    if with_mica {
        std::fs::write(mica.join("lib.rs"), b"// mica\n").unwrap();
    }
    std::fs::write(
        repo.join("buildutil.toml"),
        "[lock]\nbootstrap-inputs = []\n",
    )
    .unwrap();
    if with_mica {
        std::fs::write(
            repo.join("buildutil.lock"),
            "[lock]\nformat = 1\ninputs = { }\n",
        )
        .unwrap();
    }
    repo
}

#[test]
fn attest_absent_defers_to_git_path() {
    let base = temp_path("attest-absent");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    assert_eq!(attested_bootstrap_content_from(None, None, &repo), Ok(None));
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn attest_valid_returns_pin() {
    let base = temp_path("attest-valid");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    assert_eq!(
        attested_bootstrap_content_from(Some(ATTEST_PIN), Some(ATTEST_HASH), &repo),
        Ok(Some(ATTEST_PIN.to_string()))
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn attest_on_git_checkout_errors() {
    // Anti-injection: env vars must never bypass strict verification where a
    // real .git checkout could run it.
    let base = temp_path("attest-gitdir");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    assert!(attested_bootstrap_content_from(Some(ATTEST_PIN), Some(ATTEST_HASH), &repo).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn attest_partial_errors() {
    let base = temp_path("attest-partial");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    assert!(attested_bootstrap_content_from(Some(ATTEST_PIN), None, &repo).is_err());
    assert!(attested_bootstrap_content_from(None, Some(ATTEST_HASH), &repo).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn attest_malformed_pin_errors() {
    let base = temp_path("attest-badpin");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    assert!(attested_bootstrap_content_from(Some("abc"), Some(ATTEST_HASH), &repo).is_err());
    let upper = "C9D31087FB83F21794DDEE34C0C2C275FF82D016";
    assert!(attested_bootstrap_content_from(Some(upper), Some(ATTEST_HASH), &repo).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn attest_malformed_hash_errors() {
    let base = temp_path("attest-badhash");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    let short = "0123456789abcdef0123456789abcde"; // 31 hex
    assert!(attested_bootstrap_content_from(Some(ATTEST_PIN), Some(short), &repo).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn attest_basename_mismatch_errors() {
    // The exec-dir basename is the content-addressed identity; a mismatch means
    // the attestation is not bound to this projection.
    let base = temp_path("attest-basename");
    let repo = attest_projection(&base, "ffffffffffffffffffffffffffffffff", true);
    assert!(attested_bootstrap_content_from(Some(ATTEST_PIN), Some(ATTEST_HASH), &repo).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn attest_missing_lock_errors() {
    let base = temp_path("attest-nomica");
    let repo = attest_projection(&base, ATTEST_HASH, false);
    assert!(attested_bootstrap_content_from(Some(ATTEST_PIN), Some(ATTEST_HASH), &repo).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

// The repository identity a `.git`-less view takes from the host's plan:
// honored only where the projection attestation holds.

fn attest_identity(identity: &str, repo: &Path) -> Result<Option<(String, bool)>, String> {
    attested_identity_from(Some(identity), Some(ATTEST_PIN), Some(ATTEST_HASH), repo)
}

#[test]
fn identity_attest_absent_defers_to_git() {
    let base = temp_path("identity-absent");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    assert_eq!(
        attested_identity_from(None, Some(ATTEST_PIN), Some(ATTEST_HASH), &repo),
        Ok(None)
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn identity_attest_valid_on_an_attested_projection() {
    let base = temp_path("identity-valid");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    assert_eq!(
        attest_identity("abcdef123456 true", &repo),
        Ok(Some(("abcdef123456".to_string(), true)))
    );
    assert_eq!(
        attest_identity("unknown false", &repo),
        Ok(Some(("unknown".to_string(), false)))
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn identity_attest_needs_a_holding_projection_attestation() {
    // Without the projection attestation, or on a real checkout, git reads
    // the identity; the environment never replaces it there.
    let base = temp_path("identity-unbound");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    assert!(attested_identity_from(Some("abcdef123456 false"), None, None, &repo).is_err());
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    assert!(attest_identity("abcdef123456 false", &repo).is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn identity_attest_malformed_errors() {
    let base = temp_path("identity-malformed");
    let repo = attest_projection(&base, ATTEST_HASH, true);
    for identity in [
        "",
        "abcdef123456",
        "abcdef123456 maybe",
        "abcdef123456 false extra",
        "ab-cd false",
        " false",
    ] {
        assert!(attest_identity(identity, &repo).is_err(), "{identity:?}");
    }
    std::fs::remove_dir_all(&base).unwrap();
}

fn tree_paths(cas: &SourceCas, dirhash: &str) -> Vec<String> {
    let object = cas.load_tree_object(dirhash).unwrap();
    object.entries.into_iter().map(|entry| entry.rel).collect()
}

#[test]
fn parent_filter_stops_at_a_nested_repository() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let base = temp_path("filter-boundary");
    let source = base.join("source");
    let parent = base.join("parent");
    let state = base.join("state");
    std::fs::create_dir_all(source.join("tmp")).unwrap();
    std::fs::create_dir_all(parent.join("tmp")).unwrap();
    assert!(init_git(&source));
    std::fs::write(source.join("fixture.bin"), b"upstream fixture\n").unwrap();
    std::fs::write(source.join("tmp/input.txt"), b"upstream tmp\n").unwrap();
    commit_all(&source, "upstream");
    assert!(init_git(&parent));
    write_filter(&parent, "*.bin\n/tmp/\n");
    std::fs::write(parent.join("root.txt"), b"parent\n").unwrap();
    std::fs::write(parent.join("tmp/scratch.txt"), b"scratch\n").unwrap();
    std::fs::write(parent.join("junk.bin"), b"output\n").unwrap();
    assert!(git(
        &parent,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            source.to_str().unwrap(),
            "vendor/sub",
        ],
    ));
    commit_all(&parent, "parent");
    let nested = parent.join("vendor/sub");
    let cas = SourceCas::open(&state).unwrap();

    // The parent does not enter a separately owned checkout. The independent
    // nested walk uses that repository's own rules.
    let paths = tree_paths(&cas, &cas.ingest_pure_fs_oracle(&parent).unwrap());
    assert!(!paths.iter().any(|path| path.starts_with("vendor/sub/")));
    assert!(!paths.contains(&"vendor/sub/tmp/input.txt".to_string()));
    assert!(!paths.contains(&"junk.bin".to_string()));
    assert!(!paths.iter().any(|path| path.starts_with("tmp/")));
    assert_route_equivalence(&cas, &parent, &nested, true, true);

    // A nested repository's own .buildutilignore governs it.
    write_filter(&nested, "*.bin\n");
    commit_all(&nested, "nested filter");
    assert!(git(&parent, &["add", "vendor/sub"]));
    assert!(git(&parent, &["commit", "--no-gpg-sign", "-m", "bump"]));
    let paths = tree_paths(&cas, &cas.ingest_pure_fs_oracle(&parent).unwrap());
    assert!(!paths.contains(&"vendor/sub/fixture.bin".to_string()));
    assert!(!paths.iter().any(|path| path.starts_with("vendor/sub/")));
    assert!(!paths.contains(&"vendor/sub/tmp/input.txt".to_string()));
    assert_route_equivalence(&cas, &parent, &nested, true, true);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn anchored_patterns_match_from_the_filter_directory() {
    let _cas_guard = super::cas_test_guard();
    let base = temp_path("filter-anchor");
    let root = base.join("repo");
    std::fs::create_dir_all(root.join("a/tmp")).unwrap();
    std::fs::create_dir_all(root.join("a/gen")).unwrap();
    std::fs::create_dir_all(root.join("tmp")).unwrap();
    std::fs::write(root.join("a/tmp/keep.txt"), b"keep\n").unwrap();
    std::fs::write(root.join("a/gen/out.txt"), b"generated\n").unwrap();
    std::fs::write(root.join("tmp/scratch.txt"), b"scratch\n").unwrap();
    write_filter(&root, "/tmp/\n/a/gen/\n");
    let walk_root = root.join("a");
    let filter = SourceFilter::load_for_walk(&walk_root).unwrap();
    let object = collect_filtered_pure(&walk_root, &filter).unwrap();
    let paths: Vec<_> = object
        .entries
        .iter()
        .map(|entry| entry.rel.as_str())
        .collect();
    assert_eq!(paths, vec!["tmp/keep.txt"]);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn load_for_walk_stops_at_a_repository_without_a_filter() {
    let _cas_guard = super::cas_test_guard();
    let base = temp_path("filter-stop");
    let outer = base.join("outer");
    let inner = outer.join("inner");
    std::fs::create_dir_all(inner.join(".git")).unwrap();
    std::fs::create_dir_all(inner.join("src")).unwrap();
    write_filter(&outer, "*.txt\n");
    std::fs::write(inner.join("src/data.txt"), b"data\n").unwrap();
    let filter = SourceFilter::load_for_walk(&inner.join("src")).unwrap();
    assert!(!filter.excludes("data.txt", false));
    let outer_filter = SourceFilter::load_for_walk(&outer).unwrap();
    assert!(outer_filter.excludes("note.txt", false));
    assert!(
        outer_filter
            .enter(&inner, "inner")
            .unwrap()
            .is_some_and(|nested| !nested.excludes("inner/src/data.txt", false))
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn gittree_memo_rechecks_nested_checkouts() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let base = temp_path("memo-nested");
    let source = base.join("source");
    let parent = base.join("parent");
    let state = base.join("state");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&parent).unwrap();
    assert!(init_git(&source));
    std::fs::write(source.join(".gitignore"), b"*.log\n").unwrap();
    std::fs::write(source.join("lib.txt"), b"lib\n").unwrap();
    commit_all(&source, "upstream");
    assert!(init_git(&parent));
    write_filter(&parent, "");
    std::fs::write(parent.join("root.txt"), b"parent\n").unwrap();
    assert!(git(
        &parent,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            source.to_str().unwrap(),
            "vendor/sub",
        ],
    ));
    commit_all(&parent, "parent");
    let cas = SourceCas::open(&state).unwrap();
    let first = {
        let _eval = super::GitEvalCacheScope::new();
        cas.ingest_git_tree(&parent).unwrap()
    };
    assert_eq!(first, cas.ingest_pure_fs_oracle(&parent).unwrap());

    // A nested checkout's untracked content belongs to its independent input.
    std::fs::write(parent.join("vendor/sub/build.log"), b"local\n").unwrap();
    let second = {
        let _eval = super::GitEvalCacheScope::new();
        cas.ingest_git_tree(&parent).unwrap()
    };
    assert_eq!(second, cas.ingest_pure_fs_oracle(&parent).unwrap());
    assert_eq!(first, second);
    assert!(
        !tree_paths(&cas, &second)
            .iter()
            .any(|path| path.starts_with("vendor/sub/"))
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn object_route_defers_to_a_plain_nested_checkout() {
    let _cas_guard = super::cas_test_guard();
    if !git_available() {
        return;
    }
    let base = temp_path("plain-nested");
    let parent = base.join("parent");
    let plain = parent.join("vendor/plain");
    let state = base.join("state");
    std::fs::create_dir_all(&plain).unwrap();
    assert!(init_git(&parent));
    write_filter(&parent, "*.bin\n");
    std::fs::write(parent.join("root.txt"), b"parent\n").unwrap();
    std::fs::write(plain.join("fixture.bin"), b"fixture\n").unwrap();
    std::fs::write(plain.join("keep.txt"), b"keep\n").unwrap();
    commit_all(&parent, "parent");
    // A checkout created inside tracked content is its own filter scope even
    // though the parent still lists its files as ordinary blobs.
    assert!(init_git(&plain));
    let cas = SourceCas::open(&state).unwrap();
    let oracle = cas.ingest_pure_fs_oracle(&parent).unwrap();
    assert!(tree_paths(&cas, &oracle).contains(&"vendor/plain/fixture.bin".to_string()));
    let routed = {
        let _eval = super::GitEvalCacheScope::new();
        cas.ingest_git_tree(&parent).unwrap()
    };
    assert_eq!(routed, oracle);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn a_tracked_submodule_is_a_valid_source_and_an_embedded_checkout_is_not() {
    let base = temp_path("submodule-source");
    let source = base.join("source");
    let parent = base.join("parent");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&parent).unwrap();
    assert!(init_git(&source));
    std::fs::write(source.join("lib.rs"), b"pub fn f() {}\n").unwrap();
    commit_all(&source, "source");
    assert!(init_git(&parent));
    write_filter(&parent, "");
    std::fs::write(parent.join("buildutil.toml"), b"[lock]\n").unwrap();
    assert!(git(
        &parent,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            source.to_str().unwrap(),
            "vendor/sub",
        ],
    ));
    commit_all(&parent, "parent");
    assert!(crate::inputs::validate_source(&parent, "vendor/sub/lib.rs").is_ok());
    let embedded = parent.join("vendor/embedded");
    std::fs::create_dir_all(&embedded).unwrap();
    assert!(init_git(&embedded));
    std::fs::write(embedded.join("lib.rs"), b"pub fn g() {}\n").unwrap();
    let refused = crate::inputs::validate_source(&parent, "vendor/embedded/lib.rs");
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.contains("enters another repository")),
        "{refused:?}"
    );
    std::fs::remove_dir_all(&base).unwrap();
}
