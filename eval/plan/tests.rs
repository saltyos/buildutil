//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — plan wire-format and bootstrap round-trip tests

use super::*;
use crate::spec::{CompileGroup, Step};
use std::fs;
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "buildutil-plan-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn hex(byte: u8) -> String {
    format!("{:02x}", byte).repeat(32)
}

fn sample_plan() -> ExecPlan {
    ExecPlan {
        arch: "x86_64".into(),
        build_host: "x86_64-unknown-linux-gnu".into(),
        filter_hash: hex(1),
        git_rev: "abcdef123456".into(),
        git_dirty: "false".into(),
        targets: vec!["top".into(), "dep".into()],
        bootstrap: vec![
            BootstrapEntry {
                kind: 'f',
                rel: "tools/buildutil/bootstrap.ninja".into(),
                hash: hex(2),
            },
            BootstrapEntry {
                kind: 'x',
                rel: "buildutil".into(),
                hash: hex(3),
            },
        ],
        nodes: vec![
            ExecNode {
                name: "dep".into(),
                arch: "x86_64".into(),
                builder: "clang-obj".into(),
                tools: vec![("cc".into(), "store:host-cc:bin/cc".into())],
                env: vec![("LC_ALL".into(), "C".into())],
                srcs: vec![('f', "src/a.c".into(), hex(4))],
                srcdirs: vec![("include".into(), hex(5))],
                source_roots: vec![("toolchain/llvm-project".into(), hex(6))],
                source_overlays: vec![("{dep:headers}/include".into(), "include".into())],
                deps: vec![],
                config: vec![("OPT".into(), "1".into())],
                module_config: None,
                argv: vec!["cc".into(), "-c".into(), "{srcroot}/src/a.c".into()],
                plan: vec!["identity line with spaces".into()],
                outputs: vec!["a.o".into()],
                exec: ExecMeta {
                    tool: "cc".into(),
                    extra_tools: vec!["sh".into()],
                    env: vec![("EXTRA".into(), "value".into())],
                    srcdirs: vec![("fixed/include".into(), hex(8))],
                    source_roots: vec![("fixed/root".into(), hex(9))],
                    argv: vec!["cc".into(), "-c".into(), "{srcroot}/src/a.c".into()],
                    stage_deps: vec![("{dep:crt}/crt.o".into(), "crt.o".into())],
                    copy: vec![("{out}/a.o".into(), "lib/a.o".into())],
                    host_tool: true,
                    allowed_refs: RefPolicy::Closure,
                    shell: None,
                    mounts: Vec::new(),
                    version_flags: Vec::new(),
                    substituter: None,
                    module_config_text: String::new(),
                },
                active_plan: ActivePlan {
                    compiles: vec![CompileGroup {
                        when: "BUILD_BOOT".into(),
                        kind: "cc".into(),
                        tool: "cc".into(),
                        flags: vec!["-O2".into(), "-DNAME=a b".into()],
                        sources: vec!["src/a.c".into()],
                        scan_dir: "src".into(),
                        scan_ext: ".c".into(),
                        scan_exclude: vec!["skip/*".into()],
                        obj: "{path}.o".into(),
                    }],
                    steps: vec![Step {
                        when: String::new(),
                        tool: "ld.lld".into(),
                        argv: vec!["-o".into(), "{out}/kernel".into(), "{objs}".into()],
                        capture: "link.log".into(),
                        outputs: vec!["{out}/kernel".into()],
                    }],
                },
            },
            ExecNode {
                name: "top".into(),
                arch: "x86_64".into(),
                builder: "script-dag".into(),
                tools: vec![],
                env: vec![],
                srcs: vec![('x', "tools/gen.sh".into(), hex(7))],
                srcdirs: vec![],
                source_roots: vec![],
                source_overlays: vec![],
                deps: vec!["dep".into()],
                config: vec![],
                module_config: None,
                argv: vec![],
                plan: vec![],
                outputs: vec!["out/".into()],
                exec: ExecMeta {
                    tool: "sh".into(),
                    extra_tools: vec![],
                    env: vec![],
                    srcdirs: vec![],
                    source_roots: vec![],
                    argv: vec!["sh".into()],
                    stage_deps: vec![],
                    copy: vec![],
                    host_tool: false,
                    allowed_refs: RefPolicy::List(vec!["dep".into(), "host-cc".into()]),
                    shell: None,
                    mounts: Vec::new(),
                    version_flags: Vec::new(),
                    substituter: None,
                    module_config_text: String::new(),
                },
                active_plan: ActivePlan {
                    compiles: vec![],
                    steps: vec![],
                },
            },
        ],
    }
}

#[test]
fn round_trip_byte_identity_for_multi_node_plan() {
    let plan = sample_plan();
    let text = render(&plan).unwrap();
    let loaded = parse(&text).unwrap();
    assert_eq!(render(&loaded).unwrap(), text);
    assert!(text.contains("xplan-compile\n"));
    assert!(text.contains("exec-srcdir: fixed/include tree:"));
    assert!(text.contains("exec-source-root: fixed/root tree:"));
    assert!(text.contains("exec-stage-dep: {dep:crt}/crt.o=crt.o\n"));
    assert!(text.contains("exec-allowed-refs: closure\n"));
    assert!(text.contains("exec-allowed-ref: dep\n"));
    assert!(text.contains("exec-allowed-ref: host-cc\n"));
    assert!(text.contains("bootstrap: x buildutil sha256:"));
}

#[test]
fn required_realization_targets_are_live_root_keys_in_request_order() {
    let evaluated = Evaluated {
        order: Vec::new(),
        recipes: BTreeMap::new(),
        plans: BTreeMap::new(),
        roots: vec![
            ("native".into(), "native".into()),
            (
                "image-disk-bios-test".into(),
                format!("image-disk-bios@{}", hex(1)[..16].to_string()),
            ),
            ("pe".into(), "pe".into()),
            ("again".into(), "native".into()),
            ("disabled-later".into(), "gone".into()),
        ],
        configured: BTreeMap::new(),
        config_digests: BTreeMap::new(),
        resolved_sources: Default::default(),
        git_state: ("unknown".into(), "false".into()),
    };
    let live = BTreeSet::from([
        "native".to_string(),
        "pe".to_string(),
        format!("image-disk-bios@{}", &hex(1)[..16]),
    ]);
    assert_eq!(
        realization_targets(&evaluated, &live),
        vec![
            "native".to_string(),
            format!("image-disk-bios@{}", &hex(1)[..16]),
            "pe".to_string(),
        ]
    );
}

#[test]
fn required_format_two_carries_node_keys_and_refuses_other_graphs() {
    let key = format!("top@{}", &hex(0xab)[..16]);
    let mut plan = sample_plan();
    plan.nodes[1].name = key.clone();
    plan.targets = vec![key.clone(), "dep".into()];
    let text = render(&plan).unwrap();
    assert!(text.starts_with("buildutil-plan\nformat: 2\n"));
    assert!(text.contains(&format!("target: {key}\n")));
    assert!(text.contains(&format!("drv {key}\n")));
    let loaded = parse(&text).unwrap();
    assert_eq!(render(&loaded).unwrap(), text);
    assert_eq!(loaded.nodes[1].base_name(), "top");
    assert_eq!(loaded.nodes[1].recipe().name, "top");

    // Format 1 plans are not read.
    assert!(parse(&text.replacen("format: 2", "format: 1", 1)).is_err());
    // Two nodes with one key.
    let mut twice = sample_plan();
    twice.nodes[1].name = "dep".into();
    twice.targets = vec!["dep".into()];
    assert!(render(&twice).unwrap_err().contains("two nodes"));
    // A dependency naming no node key.
    let mut dangling = sample_plan();
    dangling.nodes[1].deps = vec![format!("dep@{}", &hex(0xcd)[..16])];
    assert!(render(&dangling).unwrap_err().contains("no node"));
    // A malformed key.
    let mut malformed = sample_plan();
    malformed.nodes[1].name = "top[A=1]".into();
    malformed.targets = vec!["dep".into()];
    assert!(render(&malformed).is_err());
}

#[test]
fn rejects_newlines() {
    let mut plan = sample_plan();
    plan.nodes[0].exec.argv.push("bad\narg".into());
    assert!(render(&plan).unwrap_err().contains("newline"));
}

#[test]
fn rejects_malformed_input() {
    let text = render(&sample_plan()).unwrap();
    assert!(parse(text.replace("end\n", "").as_str()).is_err());
    assert!(parse(&text.replace("exec-tool:", "unknown-key:")).is_err());
    assert!(parse(&text.replace(&hex(4), "abc")).is_err());
    assert!(
        parse(&text.replace(
            "exec-allowed-refs: closure\n",
            "exec-allowed-refs: closure\nexec-allowed-ref: dep\n"
        ))
        .is_err()
    );
}

#[test]
fn rejects_bad_untar_path() {
    assert!(validate_untar_argv("seed", &["untar".into(), "{srcroot}/seed.tar".into()]).is_err());
    assert!(
        validate_untar_argv(
            "seed",
            &["untar".into(), "{srcroot}/.buildutil/seed.tar".into()]
        )
        .is_ok()
    );
    assert!(
        validate_untar_argv(
            "seed",
            &[
                "buildutil".into(),
                "untar".into(),
                "{srcroot}/.buildutil/seed.tar".into(),
                "{out}".into()
            ]
        )
        .is_ok()
    );
    assert!(validate_untar_argv("seed", &["buildutil".into()]).is_err());
}

#[test]
fn plan_hash_names_file() {
    let state = temp_path("hash-name");
    let plans = crate::state::plans_dir(&state);
    fs::create_dir_all(&plans).unwrap();
    let text = render(&sample_plan()).unwrap();
    let hash = crate::crypto::sha256::hash_bytes(text.as_bytes())[..32].to_string();
    let path = plans.join(format!("{hash}.plan"));
    fs::write(&path, text).unwrap();
    assert_eq!(
        path.file_name().unwrap().to_string_lossy(),
        format!("{hash}.plan")
    );
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn materializes_bootstrap_exec_dir() {
    let _cas_guard = crate::source::cas_test_guard();
    let state = temp_path("bootstrap");
    fs::create_dir_all(crate::state::source_tmp_dir(&state)).unwrap();
    crate::source::activate(&state).unwrap();
    let src = state.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("plain"), b"plain").unwrap();
    fs::write(src.join("exec"), b"exec").unwrap();
    crate::platform::set_mode(&src.join("exec"), 0o755).unwrap();
    let (plain_hash, plain_kind) = crate::source::hash_and_ingest_file(&src.join("plain")).unwrap();
    let (exec_hash, exec_kind) = crate::source::hash_and_ingest_file(&src.join("exec")).unwrap();
    let mut plan = sample_plan();
    plan.bootstrap = vec![
        BootstrapEntry {
            kind: exec_kind,
            rel: "bin/buildutil".into(),
            hash: exec_hash,
        },
        BootstrapEntry {
            kind: plain_kind,
            rel: "tools/buildutil/main.rs".into(),
            hash: plain_hash,
        },
    ];
    let out = write_bootstrap_exec_dir(&plan, &state).unwrap();
    assert_eq!(fs::read(out.join("tools/buildutil/main.rs")).unwrap(), b"plain");
    assert_eq!(fs::read(out.join("bin/buildutil")).unwrap(), b"exec");
    assert_eq!(
        crate::platform::file_mode(&fs::metadata(out.join("tools/buildutil/main.rs")).unwrap()) & 0o777,
        0o444
    );
    assert_eq!(
        crate::platform::file_mode(&fs::metadata(out.join("bin/buildutil")).unwrap()) & 0o777,
        0o555
    );
    fs::write(out.join("already-built"), b"cached").unwrap();
    let reused = write_bootstrap_exec_dir(&plan, &state).unwrap();
    assert_eq!(reused, out);
    assert_eq!(fs::read(reused.join("already-built")).unwrap(), b"cached");
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn source_cas_completeness_refuses_missing_blob() {
    let _cas_guard = crate::source::cas_test_guard();
    let state = temp_path("cas-missing");
    fs::create_dir_all(crate::state::source_tmp_dir(&state)).unwrap();
    crate::source::activate(&state).unwrap();
    let mut plan = sample_plan();
    plan.bootstrap.clear();
    plan.nodes[0].srcdirs.clear();
    plan.nodes[0].source_roots.clear();
    let err = verify_source_cas_complete(&plan, &state).unwrap_err();
    assert_eq!(err, "source CAS incomplete — re-run from the host");
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn fixed_output_exec_source_root_round_trips_and_checks_cas() {
    let _cas_guard = crate::source::cas_test_guard();
    let base = temp_path("exec-source-root");
    let state = base.join("state");
    let repo = base.join("repo");
    fs::create_dir_all(repo.join("toolchain/rust/src")).unwrap();
    fs::write(repo.join("toolchain/rust/src/lib.rs"), b"rust").unwrap();
    fs::write(repo.join(".buildutilignore"), "").unwrap();
    crate::source::activate(&state).unwrap();
    let expected = crate::source::hash_and_ingest_dir(&repo.join("toolchain/rust")).unwrap();

    let dspec = DrvSpec {
        repository: None,
        name: "rust-vendor".into(),
        builder: "fetch".into(),
        tool: "curl".into(),
        extra_tools: Vec::new(),
        when: String::new(),
        bootstrap: false,
        native_frontend: false,
        stage: None,
        host_tool: false,
        allowed_refs: RefPolicy::None,
        sources: Vec::new(),
        src_dirs: Vec::new(),
        source_roots: vec!["toolchain/rust".into()],
        source_overlays: vec![("{dep:vendor}/vendor".into(), "toolchain/rust/vendor".into())],
        deps: Vec::new(),
        outputs: vec!["vendor/".into()],
        argv: vec!["https://example.org/vendor.tar".into()],
        env: vec![("BUILDUTIL_FIXED_SHA256".into(), hex(7))],
        copy: Vec::new(),
        stage_deps: Vec::new(),
        groups: Vec::new(),
        compiles: Vec::new(),
        steps: Vec::new(),
        module: String::new(),
        module_role: String::new(),
        config_keys: Vec::new(),
    };
    let recipe = Recipe {
        name: "rust-vendor".into(),
        arch: "x86_64".into(),
        builder: "fetch".into(),
        tools: Vec::new(),
        env: Vec::new(),
        srcs: Vec::new(),
        srcdirs: Vec::new(),
        source_roots: vec![("toolchain/rust".into(), "fixed-output".into())],
        source_overlays: dspec.source_overlays.clone(),
        copy: Vec::new(),
        stage_deps: Vec::new(),
        allowed_refs: RefPolicy::None,
        dep_names: Vec::new(),
        config: Vec::new(),
        module_config: None,
        argv: vec![format!("fixed-output:tree:{}", hex(7))],
        plan: Vec::new(),
        outputs: vec!["vendor/".into()],
    };
    let mut drvs = BTreeMap::new();
    drvs.insert("rust-vendor".into(), dspec);
    let spec = Spec {
        repo_root: repo,
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
    let mut recipes = BTreeMap::new();
    recipes.insert("rust-vendor".into(), recipe);
    let evaluated = Evaluated {
        order: vec!["rust-vendor".into()],
        recipes,
        plans: BTreeMap::new(),
        roots: Vec::new(),
        configured: BTreeMap::new(),
        config_digests: BTreeMap::new(),
        resolved_sources: {
            let mut resolved = crate::eval::graph::ResolvedSources::default();
            resolved
                .trees
                .insert("toolchain/rust".into(), expected.clone());
            resolved
        },
        git_state: ("unknown".into(), "false".into()),
    };

    let node = build_node(
        &spec,
        "rust-vendor",
        evaluated.recipes.get("rust-vendor").unwrap(),
        spec.drvs.get("rust-vendor").unwrap(),
        &evaluated,
        &state,
    )
    .unwrap();
    assert!(node.source_roots.is_empty());
    assert_eq!(node.exec.source_roots.len(), 1);
    assert_eq!(node.exec.source_roots[0].0, "toolchain/rust");
    let plan = ExecPlan {
        arch: spec.arch.clone(),
        build_host: spec.build_host.clone(),
        filter_hash: hex(1),
        git_rev: "unknown".into(),
        git_dirty: "false".into(),
        targets: vec!["rust-vendor".into()],
        bootstrap: Vec::new(),
        nodes: vec![node],
    };
    let text = render(&plan).unwrap();
    assert!(text.contains("exec-source-root: toolchain/rust tree:"));
    let loaded = parse(&text).unwrap();
    verify_source_cas_complete(&loaded, &state).unwrap();

    let tree_hash = &loaded.nodes[0].exec.source_roots[0].1;
    fs::remove_file(crate::state::source_tree_dir(&state).join(tree_hash)).unwrap();
    let err = verify_source_cas_complete(&loaded, &state).unwrap_err();
    assert_eq!(err, "source CAS incomplete — re-run from the host");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn attested_plan_load_rejects_filename_content_mismatch() {
    let plan = sample_plan();
    let text = render(&plan).unwrap();
    let hash = crate::crypto::sha256::hash_bytes(text.as_bytes())[..32].to_string();
    let base = std::env::temp_dir().join(format!("buildutil-plan-attest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let path = base.join(format!("{hash}.plan"));
    fs::write(&path, &text).unwrap();
    assert_eq!(load_attested(&path, &hash).unwrap().arch, plan.arch);
    fs::write(&path, format!("{text}corrupt\n")).unwrap();
    assert!(
        load_attested(&path, &hash)
            .unwrap_err()
            .contains("plan hash mismatch")
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn realize_contract_is_fail_closed_for_host_platform_and_ambient_tools() {
    for (host, platform) in [
        ("x86_64-unknown-linux-gnu", "linux/amd64"),
        ("aarch64-unknown-linux-gnu", "linux/arm64"),
    ] {
        let mut plan = sample_plan();
        plan.build_host = host.to_string();
        verify_realize_contract(&plan, host, platform, host).unwrap();
        assert!(verify_realize_contract(&plan, host, "linux/other", host).is_err());
        assert!(verify_realize_contract(&plan, host, platform, "other-unknown-linux-gnu").is_err());
        assert!(verify_realize_contract(&plan, "wrong-host", platform, host).is_err());

        plan.nodes[0].tools[0].1 = "host-sha256:deadbeef:/usr/bin/cc".into();
        assert!(
            verify_realize_contract(&plan, host, platform, host)
                .unwrap_err()
                .contains("ambient tool")
        );
    }
}

#[test]
fn container_executor_is_a_normal_content_addressed_derivation() {
    let base = container_executor_derivation(
        &"1".repeat(64),
        "aarch64-unknown-linux-gnu",
        "linux/arm64",
        &format!("sha256:{}", "2".repeat(64)),
    );
    assert!(
        base.store_name()
            .ends_with("-buildutil-realize-executor-aarch64-unknown-linux-gnu")
    );
    assert_eq!(base.builder, "container-executor");
    assert_eq!(base.outputs, vec!["buildutil-realize"]);
    let changed_image = container_executor_derivation(
        &"1".repeat(64),
        "aarch64-unknown-linux-gnu",
        "linux/arm64",
        &format!("sha256:{}", "3".repeat(64)),
    );
    let changed_sources = container_executor_derivation(
        &"4".repeat(64),
        "aarch64-unknown-linux-gnu",
        "linux/arm64",
        &format!("sha256:{}", "2".repeat(64)),
    );
    assert_ne!(base.store_name(), changed_image.store_name());
    assert_ne!(base.store_name(), changed_sources.store_name());
}
