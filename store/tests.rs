//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — store tests

use super::derivation::{DepRef, Derivation, DrvParts};
use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn set_symlink_mtime_old(path: &Path) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_long};
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct Timespec {
        tv_sec: c_long,
        tv_nsec: c_long,
    }
    unsafe extern "C" {
        fn utimensat(
            dirfd: c_int,
            pathname: *const c_char,
            times: *const Timespec,
            flags: c_int,
        ) -> c_int;
    }
    const AT_FDCWD: c_int = -2;
    #[cfg(target_os = "macos")]
    const AT_SYMLINK_NOFOLLOW: c_int = 0x20;
    #[cfg(target_os = "linux")]
    const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
    ];
    // SAFETY: `path` and `times` remain live for the duration of the call.
    assert_eq!(
        unsafe { utimensat(AT_FDCWD, path.as_ptr(), times.as_ptr(), AT_SYMLINK_NOFOLLOW) },
        0
    );
}

fn drv(name: &str, deps: Vec<DepRef>, marker: &str) -> Derivation {
    Derivation::seal(DrvParts {
        name: name.into(),
        arch: "x86_64".into(),
        builder: "test".into(),
        tools: vec![],
        env: vec![("MARK".into(), marker.into())],
        srcs: vec![],
        srcdirs: vec![],
        source_roots: vec![],
        source_overlays: vec![],
        copy: vec![],
        stage_deps: vec![],
        allowed_refs: crate::spec::RefPolicy::None,
        deps,
        config: vec![],
        module_config: None,
        argv: vec!["true".into()],
        plan: vec![],
        outputs: vec!["result".into()],
    })
}

fn untar_drv(name: &str, tree_pin: Option<&str>) -> Derivation {
    let mut argv = vec!["fixed-output:sha256:archive-pin".to_string()];
    if let Some(pin) = tree_pin {
        argv.push(format!("fixed-output:tree-sha256:{pin}"));
    }
    Derivation::seal(DrvParts {
        name: name.into(),
        arch: "host-test".into(),
        builder: "untar".into(),
        tools: vec![],
        env: vec![],
        srcs: vec![],
        srcdirs: vec![],
        source_roots: vec![],
        source_overlays: vec![],
        copy: vec![],
        stage_deps: vec![],
        allowed_refs: crate::spec::RefPolicy::None,
        deps: vec![],
        config: vec![],
        module_config: None,
        argv,
        plan: vec![],
        outputs: vec!["tree/".into()],
    })
}

fn dep_of(d: &Derivation) -> DepRef {
    DepRef {
        name: d.name.clone(),
        digest: "placeholder-digest".into(),
        store_name: d.store_name(),
    }
}

/// Returns the realization digest register computed.
fn fake_build(store: &Store, d: &Derivation, content: &str) -> String {
    let out = store.tmp_build_dir(&d.store_name()).join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("result"), content).unwrap();
    store.write_drv(d).unwrap();
    store.register(d, &out, "audit", &[]).unwrap()
}

fn test_plan(
    bootstrap: crate::eval::plan::BootstrapEntry,
    source: (char, String, String),
    dirhash: String,
) -> crate::eval::plan::ExecPlan {
    crate::eval::plan::ExecPlan {
        arch: "x86_64".to_string(),
        build_host: "x86_64-unknown-linux-gnu".to_string(),
        filter_hash: "0".repeat(64),
        git_rev: "unknown".to_string(),
        git_dirty: "false".to_string(),
        targets: vec!["leaf".to_string()],
        bootstrap: vec![bootstrap],
        nodes: vec![crate::eval::plan::ExecNode {
            name: "leaf".to_string(),
            arch: "x86_64".to_string(),
            builder: "test".to_string(),
            tools: Vec::new(),
            env: Vec::new(),
            srcs: vec![source],
            srcdirs: vec![("src".to_string(), dirhash.clone())],
            source_roots: vec![("root".to_string(), dirhash.clone())],
            source_overlays: Vec::new(),
            deps: Vec::new(),
            config: Vec::new(),
            module_config: None,
            argv: vec!["true".to_string()],
            plan: Vec::new(),
            outputs: vec!["out".to_string()],
            exec: crate::eval::plan::ExecMeta {
                tool: "sh".to_string(),
                extra_tools: Vec::new(),
                env: Vec::new(),
                srcdirs: vec![("exec-src".to_string(), dirhash.clone())],
                source_roots: vec![("exec-root".to_string(), dirhash.clone())],
                argv: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
                stage_deps: Vec::new(),
                copy: Vec::new(),
                host_tool: false,
                allowed_refs: crate::spec::RefPolicy::None,
                shell: None,
                mounts: Vec::new(),
                version_flags: Vec::new(),
                substituter: None,
                module_config_text: String::new(),
            },
            active_plan: crate::spec::ActivePlan {
                compiles: Vec::new(),
                steps: Vec::new(),
            },
        }],
    }
}

fn write_plan(state: &Path, hash32: &str, plan: &crate::eval::plan::ExecPlan) -> PathBuf {
    let plans = crate::state::plans_dir(state);
    std::fs::create_dir_all(&plans).unwrap();
    let path = plans.join(format!("{hash32}.plan"));
    std::fs::write(&path, crate::eval::plan::render(plan).unwrap()).unwrap();
    path
}

fn make_source_plan(
    base: &Path,
    name: &str,
) -> (crate::source::SourceCas, crate::eval::plan::ExecPlan) {
    let state = base.join("state");
    let src = base.join(name);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("boot"), b"boot").unwrap();
    std::fs::write(src.join("file"), b"file").unwrap();
    std::fs::create_dir_all(src.join("tree")).unwrap();
    std::fs::write(src.join("tree/blob"), b"tree").unwrap();
    let cas = crate::source::SourceCas::open(&state).unwrap();
    let (boot_hash, boot_kind) = cas.hash_and_ingest_file(&src.join("boot")).unwrap();
    let (src_hash, src_kind) = cas.hash_and_ingest_file(&src.join("file")).unwrap();
    let dirhash = cas.hash_and_ingest_dir(&src.join("tree")).unwrap();
    let plan = test_plan(
        crate::eval::plan::BootstrapEntry {
            kind: boot_kind,
            rel: "buildutil".to_string(),
            hash: boot_hash,
        },
        (src_kind, "file".to_string(), src_hash),
        dirhash,
    );
    std::fs::create_dir_all(crate::state::exec_dir(&state).join(plan.bootstrap_hash())).unwrap();
    (cas, plan)
}

#[test]
fn build_lock_ignores_stale_lock_files() {
    let root = std::env::temp_dir().join(format!("buildutil-lock-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let d = drv("locked", vec![], "1");
    let stale_path = root
        .join("locks")
        .join(format!("{}.building", &d.hash()[..32]));
    std::fs::write(&stale_path, "stale holder from killed process\n").unwrap();

    let first = store
        .try_lock(&d)
        .unwrap()
        .expect("stale lock file must not block flock acquisition");
    drop(first);
    let second = store
        .try_lock(&d)
        .unwrap()
        .expect("dropping the lock fd must release the flock");
    drop(second);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn store_lease_allows_shared_holders_and_excludes_exclusive_holders() {
    let root =
        std::env::temp_dir().join(format!("buildutil-store-lease-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();

    let shared_one = store.acquire_shared_lease().unwrap();
    let shared_two = store.acquire_shared_lease().unwrap();
    let exclusive_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(crate::state::store_lease_path(&root))
        .unwrap();
    assert!(
        !crate::platform::lock_exclusive(&exclusive_file, true).unwrap(),
        "a separate exclusive fd must conflict with live shared leases"
    );
    drop(shared_one);
    drop(shared_two);

    assert!(crate::platform::lock_exclusive(&exclusive_file, true).unwrap());
    let shared_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(crate::state::store_lease_path(&root))
        .unwrap();
    assert!(
        !crate::platform::lock_shared(&shared_file, true).unwrap(),
        "a separate shared fd must conflict with a live exclusive lease"
    );

    drop(shared_file);
    drop(exclusive_file);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn gc_tmp_build_dirs_sweeps_only_unlocked_store_build_dirs() {
    let root = std::env::temp_dir().join(format!("buildutil-tmpgc-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let d = drv("tmpgc", vec![], "1");
    let build_dir = store.tmp_build_dir(&d.store_name());
    std::fs::create_dir_all(build_dir.join("stage")).unwrap();
    std::fs::write(build_dir.join("stage/file"), "temporary bytes").unwrap();
    let ignored = root.join("tmp").join("not-a-store-name.build");
    std::fs::create_dir_all(&ignored).unwrap();

    let lock = store
        .try_lock(&d)
        .unwrap()
        .expect("test lock should be acquirable");
    assert!(store.gc_tmp_build_dirs().unwrap().is_empty());
    assert!(build_dir.is_dir());
    drop(lock);

    let swept = store.gc_tmp_build_dirs().unwrap();
    assert_eq!(swept.len(), 1);
    assert_eq!(swept[0].name, format!("{}.build", d.store_name()));
    assert!(swept[0].bytes > 0);
    assert!(!build_dir.exists());
    assert!(ignored.is_dir());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn gc_report_dry_run_reports_progress_without_deleting() {
    let root = std::env::temp_dir().join(format!("buildutil-gcreport-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let orphan = drv("orphan", vec![], "1");
    fake_build(&store, &orphan, "orphan-out");
    let tmp_drv = drv("tmp", vec![], "1");
    let tmp_dir = store.tmp_build_dir(&tmp_drv.store_name());
    std::fs::create_dir_all(&tmp_dir).unwrap();
    std::fs::write(tmp_dir.join("file"), "tmp").unwrap();

    let mut events = Vec::new();
    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy::default(),
                    dry_run: true,
                    prune_roots_older_than_days: None,
                },
                None,
                &mut |ev| events.push(ev),
            )
            .unwrap()
    };
    assert_eq!(report.store_swept.len(), 1);
    assert_eq!(report.store_swept[0].name, orphan.store_name());
    assert!(
        report
            .tmp_swept
            .iter()
            .any(|s| s.name == format!("{}.build", tmp_drv.store_name()))
    );
    assert!(report.bytes_reclaimed > 0);
    assert!(
        store.has_named(&orphan.store_name()),
        "dry-run must not delete store entries"
    );
    assert!(tmp_dir.is_dir(), "dry-run must not delete tmp build dirs");
    assert!(events.contains(&GcProgress::Phase("Sweeping tmp build dirs")));
    assert!(events.contains(&GcProgress::Phase("Marking roots")));
    assert!(events.contains(&GcProgress::Phase("Scanning store entries")));
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, GcProgress::SweepTmp { dry_run: true, .. }))
    );
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, GcProgress::SweepStore { dry_run: true, .. }))
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn temp_roots_keep_unrooted_entries_live_until_dropped() {
    let root = std::env::temp_dir().join(format!("buildutil-temproot-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let orphan = drv("orphan", vec![], "1");
    fake_build(&store, &orphan, "orphan-out");
    let temp_root = store
        .add_temp_roots("hold-orphan", &[orphan.store_name()])
        .unwrap()
        .expect("non-empty temp root");

    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy::default(),
                    dry_run: false,
                    prune_roots_older_than_days: None,
                },
                None,
                &mut |_| {},
            )
            .unwrap()
    };
    assert!(report.store_swept.is_empty());
    assert_eq!(report.roots_scanned, 1);
    assert!(store.has_named(&orphan.store_name()));

    drop(temp_root);
    let swept = store.gc(&GcPolicy::default()).unwrap();
    assert_eq!(swept, vec![orphan.store_name()]);
    assert!(!store.has_named(&orphan.store_name()));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn appending_temp_root_is_visible_to_gc_readers_and_unlinked_on_drop() {
    let root = std::env::temp_dir().join(format!(
        "buildutil-batched-temproot-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let mut temp_root = store.create_temp_root("batched-realize").unwrap();
    let path = temp_root.path().to_path_buf();
    temp_root.append("first-store-name").unwrap();
    temp_root.append("second-store-name").unwrap();

    let reader = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(
        !crate::platform::lock_exclusive(&reader, true).unwrap(),
        "GC's separate reader fd must observe the holder's flock"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "first-store-name\nsecond-store-name\n"
    );
    drop(reader);
    drop(temp_root);
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn gc_keeps_entry_named_by_live_batched_temp_root() {
    let root = std::env::temp_dir().join(format!(
        "buildutil-batched-temproot-gc-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let orphan = drv("batched-orphan", vec![], "1");
    fake_build(&store, &orphan, "orphan-out");
    let mut temp_root = store.create_temp_root("batched-realize").unwrap();
    temp_root.append(&orphan.store_name()).unwrap();

    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy::default(),
                    dry_run: false,
                    prune_roots_older_than_days: None,
                },
                None,
                &mut |_| {},
            )
            .unwrap()
    };
    assert!(report.store_swept.is_empty());
    assert!(store.has_named(&orphan.store_name()));

    drop(temp_root);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn source_gc_retains_locked_plan_and_sweeps_dead_source_cache() {
    let base = std::env::temp_dir().join(format!("buildutil-sourcegc-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let state = base.join("state");
    let store = Store::open(&state).unwrap();
    let (cas, plan) = make_source_plan(&base, "src");
    let live_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_plan(&state, live_hash, &plan);
    let _lock = crate::state::lock_plan(&state, live_hash).unwrap();

    let dead_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let dead_plan = write_plan(&state, dead_hash, &plan);
    std::thread::sleep(std::time::Duration::from_secs(1));
    std::fs::write(crate::state::plan_lock_path(&state, dead_hash), b"stale").unwrap();
    let dead_blob = crate::state::source_cas_dir(&state)
        .join("de")
        .join("deadbeef");
    std::fs::create_dir_all(dead_blob.parent().unwrap()).unwrap();
    std::fs::write(&dead_blob, b"dead").unwrap();
    let dead_tree = crate::state::source_tree_dir(&state).join("dead-tree");
    std::fs::write(&dead_tree, b"dead").unwrap();
    let live_memo = crate::state::source_gittree_dir(&state)
        .join("tree")
        .join("filter");
    std::fs::create_dir_all(live_memo.parent().unwrap()).unwrap();
    std::fs::write(&live_memo, format!("{}\n", plan.nodes[0].srcdirs[0].1)).unwrap();
    let dead_memo = crate::state::source_gittree_dir(&state)
        .join("dead")
        .join("filter");
    std::fs::create_dir_all(dead_memo.parent().unwrap()).unwrap();
    std::fs::write(&dead_memo, "dead-tree\n").unwrap();
    let dead_exec = crate::state::exec_dir(&state).join("dead-exec");
    std::fs::create_dir_all(&dead_exec).unwrap();
    let leased_exec_hash = "cccccccccccccccccccccccccccccccc";
    let leased_exec = crate::state::exec_dir(&state).join(leased_exec_hash);
    std::fs::create_dir_all(&leased_exec).unwrap();
    let executor_lease = crate::state::lock_executor(&state, leased_exec_hash).unwrap();
    let legacy = state.join("sources/worktree");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("old"), b"old").unwrap();

    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy {
                        max_age_days: Some(0),
                        min_free: None,
                    },
                    dry_run: false,
                    prune_roots_older_than_days: None,
                },
                None,
                &mut |_| {},
            )
            .unwrap()
    };

    assert!(report.cas_swept >= 5, "{report:?}");
    assert_eq!(report.plans_swept, 1);
    assert!(
        crate::state::plans_dir(&state)
            .join(format!("{live_hash}.plan"))
            .is_file()
    );
    assert!(!dead_plan.exists());
    assert!(crate::state::plan_lock_path(&state, dead_hash).exists());
    assert!(!dead_blob.exists());
    assert!(!dead_tree.exists());
    assert!(!dead_memo.exists());
    assert!(!dead_exec.exists());
    assert!(leased_exec.exists());
    assert!(!legacy.exists());
    assert!(live_memo.exists());
    assert!(
        crate::state::exec_dir(&state)
            .join(plan.bootstrap_hash())
            .is_dir()
    );
    for entry in &plan.bootstrap {
        assert!(cas.blob_path(&entry.hash, entry.kind).is_file());
    }
    drop(executor_lease);
    {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy {
                        max_age_days: Some(0),
                        min_free: None,
                    },
                    dry_run: false,
                    prune_roots_older_than_days: None,
                },
                None,
                &mut |_| {},
            )
            .unwrap();
    }
    assert!(!leased_exec.exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn source_gc_held_plan_lock_protects_its_complete_closure() {
    let base = std::env::temp_dir().join(format!(
        "buildutil-sourcegc-held-closure-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let state = base.join("state");
    let store = Store::open(&state).unwrap();
    let (cas, plan) = make_source_plan(&base, "src");
    let hash = "dddddddddddddddddddddddddddddddd";
    let plan_path = write_plan(&state, hash, &plan);
    let _plan_lock = crate::state::lock_plan(&state, hash).unwrap();

    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy {
                        max_age_days: Some(0),
                        min_free: None,
                    },
                    dry_run: false,
                    prune_roots_older_than_days: None,
                },
                None,
                &mut |_| {},
            )
            .unwrap()
    };

    assert_eq!(report.plans_swept, 0);
    assert!(plan_path.is_file());
    for entry in &plan.bootstrap {
        assert!(cas.blob_path(&entry.hash, entry.kind).is_file());
    }
    for (kind, _, hash) in &plan.nodes[0].srcs {
        assert!(cas.blob_path(hash, *kind).is_file());
    }
    assert!(
        crate::state::source_tree_dir(&state)
            .join(&plan.nodes[0].srcdirs[0].1)
            .is_file()
    );
    assert!(
        crate::state::exec_dir(&state)
            .join(plan.bootstrap_hash())
            .is_dir()
    );
    drop(_plan_lock);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn source_gc_retains_recent_plan_by_age_policy() {
    let base = std::env::temp_dir().join(format!("buildutil-sourcegc-age-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let state = base.join("state");
    let store = Store::open(&state).unwrap();
    let (_cas, plan) = make_source_plan(&base, "src");
    let hash = "cccccccccccccccccccccccccccccccc";
    let path = write_plan(&state, hash, &plan);

    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy {
                        max_age_days: Some(1),
                        min_free: None,
                    },
                    dry_run: false,
                    prune_roots_older_than_days: None,
                },
                None,
                &mut |_| {},
            )
            .unwrap()
    };

    assert_eq!(report.plans_swept, 0);
    assert!(path.is_file());
    assert!(
        crate::state::exec_dir(&state)
            .join(plan.bootstrap_hash())
            .is_dir()
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn register_read_verify_gc() {
    let root = std::env::temp_dir().join(format!("buildutil-store-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();

    let base = drv("base", vec![], "1");
    fake_build(&store, &base, "base-out");
    let top = drv("top", vec![dep_of(&base)], "1");
    fake_build(&store, &top, "top-out");

    assert!(store.has_named(&base.store_name()) && store.has_named(&top.store_name()));
    let meta = store.read_meta(&top.store_name()).unwrap();
    assert_eq!(meta.refs, vec![base.store_name()]);
    assert_eq!(meta.sandbox, "audit");
    assert!(store.verify().unwrap().is_empty());

    // Root only the top: both stay live through the ref edge.
    store.add_root("latest-top", &top.store_name()).unwrap();
    assert_eq!(
        std::fs::read_link(root.join("roots/latest-top")).unwrap(),
        Path::new("../store").join(top.store_name())
    );
    let orphan = drv("orphan", vec![], "1");
    fake_build(&store, &orphan, "gone");
    let swept = store.gc(&GcPolicy::default()).unwrap();
    assert_eq!(swept, vec![orphan.store_name()]);
    assert!(store.has_named(&base.store_name()) && store.has_named(&top.store_name()));

    // Corruption shows up in verify.
    std::fs::write(store.out_path(&top).join("result"), "tampered").unwrap();
    assert_eq!(
        store.verify().unwrap(),
        vec![format!("{}/result", top.store_name())]
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn warm_store_untar_rechecks_actual_tree_pin() {
    let root =
        std::env::temp_dir().join(format!("buildutil-warm-tree-pin-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let staging = root.join("staging");
    std::fs::create_dir_all(staging.join("tree")).unwrap();
    std::fs::write(staging.join("tree/file"), b"pinned").unwrap();
    let pin = crate::source::filehash::hash_tree_with_dir_modes(&staging).unwrap();
    let d = untar_drv("warm-import", Some(&pin));
    store.write_drv(&d).unwrap();
    store.register(&d, &staging, "audit", &[]).unwrap();
    assert!(store.validate_reuse(&d).unwrap());

    std::fs::write(store.out_path(&d).join("tree/file"), b"tampered").unwrap();
    let err = store.validate_reuse(&d).unwrap_err();
    assert!(err.contains("tree hash mismatch"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn warm_store_untar_without_tree_pin_fails_closed() {
    let root = std::env::temp_dir().join(format!(
        "buildutil-missing-tree-pin-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let d = untar_drv("missing-pin", None);
    let staging = root.join("staging");
    std::fs::create_dir_all(staging.join("tree")).unwrap();
    std::fs::write(staging.join("tree/file"), b"bytes").unwrap();
    store.write_drv(&d).unwrap();
    store.register(&d, &staging, "audit", &[]).unwrap();
    let err = store.validate_reuse(&d).unwrap_err();
    assert!(err.contains("no identity-bearing tree pin"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn gc_keeps_scan_recorded_references_alive() {
    let root = std::env::temp_dir().join(format!("buildutil-refgc-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();

    // `runtime` is NOT a declared dep of `app` — only a scan-recorded
    // runtime reference in app's meta. GC must keep it alive anyway.
    let runtime = drv("runtime", vec![], "1");
    fake_build(&store, &runtime, "runtime-out");
    let app = drv("app", vec![], "1");
    let out = store.tmp_build_dir(&app.store_name()).join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("result"), "app-out").unwrap();
    store.write_drv(&app).unwrap();
    store
        .register(
            &app,
            &out,
            "audit",
            &[format!("reference: {}", runtime.store_name())],
        )
        .unwrap();

    let meta = store.read_meta(&app.store_name()).unwrap();
    assert_eq!(meta.references, vec![runtime.store_name()]);

    store.add_root("latest-app", &app.store_name()).unwrap();
    let swept = store.gc(&GcPolicy::default()).unwrap();
    assert!(swept.is_empty(), "swept: {:?}", swept);
    assert!(store.has_named(&runtime.store_name()) && store.has_named(&app.store_name()));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn realization_digest_is_stable_and_content_addressed() {
    let root = std::env::temp_dir().join(format!("buildutil-digest-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();

    let d = drv("widget", vec![], "1");
    let digest = fake_build(&store, &d, "some-output-bytes");
    // The register-time digest must re-derive byte-for-byte from meta …
    assert_eq!(store.digest_of(&d.store_name()).unwrap(), digest);
    // … and the realization record must carry the same digest.
    assert_eq!(
        store.read_realization_digest(&d.hash()),
        Some(digest.clone())
    );

    // Content-addressed: a different derivation that produces identical
    // output bytes shares the realization digest (the early-cutoff key).
    let d2 = drv("gadget", vec![], "1");
    assert_ne!(d.hash(), d2.hash());
    let digest2 = fake_build(&store, &d2, "some-output-bytes");
    assert_eq!(digest, digest2);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn roots_v2_migrates_absolute_and_prunes_dangling() {
    let root = std::env::temp_dir().join(format!("buildutil-roots-v2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let live = drv("live", vec![], "1");
    fake_build(&store, &live, "live");
    let roots = root.join("roots");
    crate::platform::create_symlink(
        &store.root.join(live.store_name()),
        &roots.join("latest-live-x86_64"),
        crate::platform::SymlinkKind::Directory,
    )
    .unwrap();
    crate::platform::create_symlink(
        &store.root.join("missing-store-entry"),
        &roots.join("latest-dangling-x86_64"),
        crate::platform::SymlinkKind::Directory,
    )
    .unwrap();

    let valid = store.valid_roots_for_gc(false, None).unwrap();
    assert_eq!(valid["latest-live-x86_64"], live.store_name());
    assert_eq!(
        std::fs::read_link(roots.join("latest-live-x86_64")).unwrap(),
        Path::new("..").join("store").join(live.store_name())
    );
    assert!(!roots.join("latest-dangling-x86_64").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn root_expiry_excludes_old_latest_but_not_temproots() {
    let root = std::env::temp_dir().join(format!("buildutil-root-expiry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let expired = drv("expired", vec![], "1");
    fake_build(&store, &expired, "expired");
    let temporary = drv("temporary", vec![], "1");
    fake_build(&store, &temporary, "temporary");
    store
        .add_root("latest-expired-x86_64", &expired.store_name())
        .unwrap();
    set_symlink_mtime_old(&root.join("roots/latest-expired-x86_64"));
    let _temp = store
        .add_temp_roots("expiry", &[temporary.store_name()])
        .unwrap()
        .unwrap();
    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy::default(),
                    dry_run: false,
                    prune_roots_older_than_days: Some(1),
                },
                None,
                &mut |_| {},
            )
            .unwrap()
    };
    assert!(
        report
            .store_swept
            .iter()
            .any(|s| s.name == expired.store_name())
    );
    assert!(store.has_named(&temporary.store_name()));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn world_seed_converges_two_generations_and_preserves_temproot_closure() {
    let root = std::env::temp_dir().join(format!("buildutil-world-two-gen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let old_tc = drv("toolchain", vec![], "old");
    fake_build(&store, &old_tc, "old-tc");
    let old_os = drv("os", vec![dep_of(&old_tc)], "old");
    fake_build(&store, &old_os, "old-os");
    let current_tc = drv("toolchain", vec![], "current");
    fake_build(&store, &current_tc, "current-tc");
    let current_os = drv("os", vec![dep_of(&current_tc)], "current");
    fake_build(&store, &current_os, "current-os");
    let active = drv("active", vec![], "1");
    fake_build(&store, &active, "active");
    let _temp = store
        .add_temp_roots("world", &[active.store_name()])
        .unwrap()
        .unwrap();
    store
        .add_root("latest-os-x86_64", &old_os.store_name())
        .unwrap();
    let desired = BTreeMap::from([("latest-os-x86_64".to_string(), current_os.store_name())]);
    store.sync_latest_roots(&desired).unwrap();
    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_seeded_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy::default(),
                    dry_run: false,
                    prune_roots_older_than_days: None,
                },
                None,
                Some(&desired),
                &mut |_| {},
            )
            .unwrap()
    };
    assert!(
        report
            .store_swept
            .iter()
            .any(|s| s.name == old_os.store_name())
    );
    assert!(
        report
            .store_swept
            .iter()
            .any(|s| s.name == old_tc.store_name())
    );
    assert!(
        store.has_named(&current_os.store_name())
            && store.has_named(&current_tc.store_name())
            && store.has_named(&active.store_name())
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn domain_seed_reclaims_only_replaced_build_generation() {
    let root = std::env::temp_dir().join(format!("buildutil-world-domain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let old_build = drv("buildutil", vec![], "old");
    fake_build(&store, &old_build, "old-build");
    let current_build = drv("buildutil", vec![], "current");
    fake_build(&store, &current_build, "current-build");
    let old_os = drv("os", vec![], "old");
    fake_build(&store, &old_os, "old-os");
    let desired = BTreeMap::from([
        (
            "latest-buildutil-x86_64".to_string(),
            current_build.store_name(),
        ),
        ("latest-os-x86_64".to_string(), old_os.store_name()),
    ]);
    let report = {
        let lease = store.acquire_exclusive_lease().unwrap();
        store
            .gc_report_seeded_with_lease(
                &lease,
                &GcOptions {
                    policy: GcPolicy::default(),
                    dry_run: true,
                    prune_roots_older_than_days: None,
                },
                None,
                Some(&desired),
                &mut |_| {},
            )
            .unwrap()
    };
    assert!(
        report
            .store_swept
            .iter()
            .any(|s| s.name == old_build.store_name())
    );
    assert!(
        !report
            .store_swept
            .iter()
            .any(|s| s.name == old_os.store_name())
    );
    assert!(
        !report
            .store_swept
            .iter()
            .any(|s| s.name == current_build.store_name())
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn required_indirect_roots_hold_an_app_link_until_it_is_removed() {
    let root = std::env::temp_dir().join(format!("buildutil-indirect-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = Store::open(&root).unwrap();
    let kernel = drv("kernel", vec![], "1");
    fake_build(&store, &kernel, "booted");

    // An app keeps a link in its run state and registers it.
    let record = crate::state::run_dir(&root).join("vm").join("7");
    std::fs::create_dir_all(&record).unwrap();
    let link = record.join("kernel");
    crate::platform::create_symlink(
        &store.out_path(&kernel),
        &link,
        crate::platform::SymlinkKind::Directory,
    )
    .unwrap();
    let name = store.add_indirect_root(&link).unwrap();
    assert!(name.starts_with(INDIRECT_ROOT_PREFIX));
    assert_eq!(store.read_root(&name), Some(kernel.store_name()));
    assert!(store.gc(&GcPolicy::default()).unwrap().is_empty());
    assert!(store.has_named(&kernel.store_name()));

    // A link outside the run state is refused.
    assert!(store.add_indirect_root(&root.join("elsewhere")).is_err());

    // Removing the link releases the entry and prunes the root.
    std::fs::remove_file(&link).unwrap();
    assert_eq!(store.read_root(&name), None);
    assert_eq!(
        store.gc(&GcPolicy::default()).unwrap(),
        vec![kernel.store_name()]
    );
    assert!(std::fs::symlink_metadata(root.join("roots").join(&name)).is_err());
    let _ = std::fs::remove_dir_all(&root);
}
