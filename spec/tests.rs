//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — spec load tests

use std::path::{Path, PathBuf};

use super::configres::Config;
use super::{RefPolicy, load};
use crate::tools::ToolProvider;

#[test]
fn required_capture_uses_the_output_architecture_projection() {
    let dir = step_repo(
        "required-capture-projection",
        r#"
[derivation.capture]
builder = "script-dag"
tool = "ninja"
outputs = ["capture-{arch}-{build.host.arch}"]
[[derivation.capture.step]]
tool = "sh"
argv = ["-c", "printf checked"]
capture = "{out}/capture-{arch}-{build.host.arch}"
outputs = ["{out}/capture-{arch}-{build.host.arch}"]
"#,
    );
    let root = dir.join("buildutil.toml");
    let text = std::fs::read_to_string(&root).unwrap();
    std::fs::write(&root, format!("{text}\n[arch.aarch64]\n")).unwrap();
    for arch in ["x86_64", "aarch64"] {
        let spec = load(&dir, arch, "aarch64-unknown-linux-gnu").unwrap();
        let step = &spec.drvs["capture"].steps[0];
        assert_eq!(step.capture, format!("{{out}}/capture-{arch}-aarch64"));
        assert_eq!(step.outputs, [step.capture.clone()]);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

fn required_check_repo(tag: &str, rule: &str, check_dep: &str) -> PathBuf {
    let dir = step_repo(
        tag,
        &format!(
            r#"
[derivation.image]
builder = "script-dag"
tool = "ninja"
src-dirs = ["src/kernel"]
outputs = ["image.elf"]
[[derivation.image.step]]
tool = "sh"
argv = ["-c", "printf image > {{out}}/image.elf"]
outputs = ["{{out}}/image.elf"]
[derivation.consumer]
builder = "rustc-crate"
tool = "rustc"
deps = ["image"]
outputs = ["result"]
argv = ["{{dep:image}}/image.elf"]
[derivation.validation]
builder = "script-dag"
tool = "ninja"
deps = [{check_dep}]
sources = ["contract.decl"]
outputs = ["verdict"]
[[derivation.validation.step]]
tool = "sh"
argv = ["-c", "exit 7"]
capture = "{{out}}/verdict"
outputs = ["{{out}}/verdict"]
"#
        ),
    );
    let root = format!(
        r#"
[buildutil]
subsystems = ["sub"]
[arch.x86_64]
[packages]
expose = ["consumer"]
[checks]
expose = ["validation"]
[required-check.test]
derivation = "validation"
{rule}
"#
    );
    write(&dir, "buildutil.toml", &root);
    dir
}

#[test]
fn required_checks_before_are_subject_dependencies_and_after_are_serial_steps() {
    let before = required_check_repo(
        "required-before",
        "phase = \"before\"\nsource-scope = [\"src/kernel\"]",
        "",
    );
    let spec = load(&before, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(spec.drvs["image"].deps, ["validation"]);
    assert!(spec.drvs["validation"].deps.is_empty());
    assert_eq!(spec.drvs["consumer"].deps, ["image"]);
    let after = required_check_repo(
        "required-after",
        "phase = \"after\"\nartifacts = [\"image\"]",
        "\"image\"",
    );
    let spec = load(&after, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    let image = &spec.drvs["image"];
    assert!(
        image.deps.is_empty(),
        "post-validation must not create image/check cycle"
    );
    assert_eq!(image.steps.len(), 2);
    assert_eq!(image.steps[1].argv, ["-c", "exit 7"]);
    assert!(image.sources.contains(&"contract.decl".into()));
    assert!(image.outputs.contains(&"verdict".into()));
    let plan = super::ActivePlan {
        compiles: image.compiles.clone(),
        steps: image.steps.clone(),
    };
    let ninja =
        crate::eval::ninja_emit::emit(&plan, &|value| Ok(value.replace("{out}", "out"))).unwrap();
    assert!(ninja.contains("build out/verdict: s1 | out/image.elf"));
    assert!(ninja.contains("default out/verdict"));
    assert!(
        ninja.contains("> out/verdict"),
        "capture must resolve like argv and outputs"
    );
    std::fs::remove_dir_all(before).unwrap();
    std::fs::remove_dir_all(after).unwrap();
}

#[test]
fn required_checks_reject_cycles_unknown_subjects_and_silent_disabling() {
    for (tag, rule, deps, expected) in [
        (
            "cycle",
            "phase = \"before\"\nartifacts = [\"image\"]",
            "\"consumer\"",
            "dependency cycle",
        ),
        (
            "unknown",
            "phase = \"before\"\nartifacts = [\"ghost\"]",
            "",
            "invalid subject",
        ),
        (
            "scope",
            "phase = \"before\"\nsource-scope = [\"missing\"]",
            "",
            "matches no subjects",
        ),
        (
            "phase",
            "phase = \"optional\"\nartifacts = [\"image\"]",
            "",
            "phase must",
        ),
    ] {
        let dir = required_check_repo(&format!("required-{tag}"), rule, deps);
        assert!(
            load(&dir, "x86_64", "x86_64-unknown-linux-gnu")
                .unwrap_err()
                .contains(expected)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    let dir = required_check_repo(
        "required-disabled",
        "phase = \"before\"\nartifacts = [\"image\"]",
        "",
    );
    let file = dir.join("sub/buildutil.toml");
    let text = std::fs::read_to_string(&file).unwrap().replace(
        "[derivation.validation]",
        "[derivation.validation]\nwhen = \"CHECK_ONLY\"",
    );
    std::fs::write(file, text).unwrap();
    assert!(
        load(&dir, "x86_64", "x86_64-unknown-linux-gnu")
            .unwrap_err()
            .contains("can be enabled")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn required_checks_remap_subject_artifacts_and_bind_check_identity() {
    let dir = required_check_repo(
        "required-remap",
        "phase = \"after\"\nartifacts = [\"image\"]",
        "\"image\"",
    );
    let file = dir.join("sub/buildutil.toml");
    let text = std::fs::read_to_string(&file).unwrap().replace(
        "argv = [\"-c\", \"exit 7\"]",
        "argv = [\"{dep:image}/image.elf\", \"{dep-abs:image}/image.elf\", \"{config.LIMIT}\"]",
    );
    std::fs::write(file, text).unwrap();
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(
        spec.drvs["image"].steps[1].argv,
        ["{out}/image.elf", "{out-abs}/image.elf", "{config.LIMIT}"]
    );
    let config = Config::from_values([("LIMIT".into(), "4096".into())].into_iter().collect());
    let mut view = config.view();
    let plan = spec.eval_plan(&spec.drvs["image"], &mut view).unwrap();
    assert_eq!(plan.steps[1].argv[2], "4096");
    assert!(view.projection().contains(&("LIMIT".into(), "4096".into())));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn required_checks_reject_skipped_verdicts_in_both_phases() {
    for phase in ["before", "after"] {
        let rule = format!("phase = \"{phase}\"\nartifacts = [\"image\"]");
        let deps = if phase == "after" { "\"image\"" } else { "" };
        let dir = required_check_repo(&format!("required-skipped-{phase}"), &rule, deps);
        let file = dir.join("sub/buildutil.toml");
        let text = std::fs::read_to_string(&file).unwrap().replace(
            "[[derivation.validation.step]]",
            "[[derivation.validation.step]]\nwhen = \"CHECK_ONLY\"",
        );
        std::fs::write(file, text).unwrap();
        let error = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(error.contains("cannot be conditionally skipped"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn required_checks_after_reject_lost_execution_contracts_and_output_collisions() {
    for (tag, from, to, diagnostic) in [
        (
            "host-tool",
            "[derivation.validation]",
            "[derivation.validation]\nhost-tool = true",
            "same tool grade",
        ),
        (
            "references",
            "[derivation.validation]",
            "[derivation.validation]\nallowed-references = \"closure\"",
            "same tool grade",
        ),
        (
            "objects",
            "argv = [\"-c\", \"exit 7\"]",
            "argv = [\"{objs}\"]",
            "cannot reference subject compile objects",
        ),
        (
            "step-output",
            "{out}/verdict",
            "{dep:image}/image.elf",
            "step output collides",
        ),
        (
            "tree-output",
            "outputs = [\"verdict\"]",
            "outputs = [\"image.elf/child\"]",
            "collides with subject output",
        ),
    ] {
        let dir = required_check_repo(
            &format!("required-contract-{tag}"),
            "phase = \"after\"\nartifacts = [\"image\"]",
            "\"image\"",
        );
        let file = dir.join("sub/buildutil.toml");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains(from));
        std::fs::write(file, text.replace(from, to)).unwrap();
        let error = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(error.contains(diagnostic), "{tag}: {error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn required_checks_source_scope_uses_path_components_and_original_subject_inputs() {
    let dir = required_check_repo(
        "required-scope-boundary",
        "phase = \"before\"\nsource-scope = [\"src/kernel\"]",
        "",
    );
    let file = dir.join("sub/buildutil.toml");
    let mut text = std::fs::read_to_string(&file).unwrap();
    text.push_str(
        r#"
[derivation.sibling]
builder = "rustc-crate"
tool = "rustc"
src-dirs = ["src/kernel-old"]
outputs = ["sibling"]
[derivation.parent]
builder = "rustc-crate"
tool = "rustc"
source-roots = ["src"]
outputs = ["parent"]
"#,
    );
    std::fs::write(file, text).unwrap();
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(spec.drvs["image"].deps, ["validation"]);
    assert_eq!(spec.drvs["parent"].deps, ["validation"]);
    assert!(spec.drvs["sibling"].deps.is_empty());
    assert!(spec.drvs["validation"].deps.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn required_checks_reject_malformed_policy_instead_of_ignoring_it() {
    for (tag, rule, diagnostic) in [
        (
            "empty",
            "phase = \"before\"",
            "declare artifacts or source-scope",
        ),
        (
            "absolute",
            "phase = \"before\"\nsource-scope = [\"/src\"]",
            "normalized relative path",
        ),
        (
            "parent",
            "phase = \"before\"\nsource-scope = [\"src/../kernel\"]",
            "normalized relative path",
        ),
        (
            "unknown-key",
            "phase = \"before\"\nartifacts = [\"image\"]\noptional = true",
            "unknown key",
        ),
        (
            "nested",
            "phase = \"before\"\nartifacts = [\"image\"]\n[required-check.test.extra]",
            "named policy table",
        ),
    ] {
        let dir = required_check_repo(&format!("required-policy-{tag}"), rule, "");
        let error = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(error.contains(diagnostic), "{tag}: {error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn required_checks_after_preserve_tools_environment_dependencies_and_serial_order() {
    let dir = required_check_repo(
        "required-input-union",
        "phase = \"after\"\nartifacts = [\"image\"]",
        "\"image\", \"support\"",
    );
    let file = dir.join("sub/buildutil.toml");
    let mut text = std::fs::read_to_string(&file).unwrap().replace(
        "[derivation.validation]",
        "[derivation.validation]\nextra-tools = [\"project-check\"]\nsrc-dirs = [\"checks\"]",
    );
    text.push_str(
        r#"
[derivation.validation.env]
SUBJECT = "{dep-abs:image}/image.elf"
[[derivation.validation.step]]
tool = "project-check"
argv = ["{dep:support}/module.bc"]
capture = "{out}/details"
outputs = ["{out}/details"]
[derivation.support]
builder = "rustc-crate"
tool = "rustc"
outputs = ["module.bc"]
[derivation.project-check-tools]
builder = "nasm"
tool = "nasm"
outputs = ["project-check"]
"#,
    );
    std::fs::write(file, text).unwrap();
    let root = dir.join("buildutil.toml");
    let text = std::fs::read_to_string(&root).unwrap();
    std::fs::write(
        root,
        format!(
            "{text}\n[tool-provider.project-check]\nderivation = \"project-check-tools\"\npath = \"project-check\"\n"
        ),
    )
    .unwrap();
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    let subject = &spec.drvs["image"];
    assert_eq!(subject.deps, ["support"]);
    assert!(subject.extra_tools.contains(&"ninja".into()));
    assert!(subject.extra_tools.contains(&"project-check".into()));
    assert!(subject.src_dirs.contains(&"checks".into()));
    assert!(
        subject
            .env
            .contains(&("SUBJECT".into(), "{out-abs}/image.elf".into()))
    );
    assert_eq!(subject.steps.len(), 3);
    assert_eq!(subject.steps[2].argv, ["{dep:support}/module.bc"]);
    let plan = super::ActivePlan {
        compiles: subject.compiles.clone(),
        steps: subject.steps.clone(),
    };
    let ninja = crate::eval::ninja_emit::emit(&plan, &|s| Ok(s.replace("{out}", "out"))).unwrap();
    assert!(ninja.contains("build out/details: s2 | out/verdict"));
    assert!(ninja.contains("default out/details"));
    assert_eq!(
        spec.tool_provider(&spec.drvs["image"], "project-check"),
        Some(ToolProvider::Store {
            drv: "project-check-tools".into(),
            relpath: "project-check".into(),
        }),
        "a required-after tool must retain its declarative provider"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

fn write(dir: &Path, rel: &str, content: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn sample_repo(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("buildutil-spec-test-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write(
        &dir,
        "buildutil.toml",
        r#"
[buildutil]
subsystems = ["sub"]

[packages]
expose = ["gen", "compile"]

[packages.group]
uapi = ["gen", "compile"]

[arch.x86_64]
kernel-target-json = "kernite/x86_64-kernite.json"
userland-target = "x86_64-unknown-saltyos"

[flagset.kernel-support]
flags = ["--edition=2024", "--target={srcroot}/{target.kernel-target-json}"]
tail = ["-Z", "unstable-options"]

[[flagset.kernel-support.flag-group]]
when = "DEBUG_SYMBOLS"
flags = ["-C", "debuginfo=2"]
"#,
    );
    write(
        &dir,
        "sub/buildutil.toml",
        r#"
[derivation.gen]
builder = "bindgen"
tool = "bindgen"
allowed-references = "none"
sources = ["sub/in.h"]
outputs = ["out.rs"]
argv = ["--output", "{out}/out.rs", "{srcroot}/sub/in.h"]
copy = ["{srcroot}/sub/in.h:in.h"]

[derivation.compile]
builder = "rustc-crate"
tool = "rustc"
allowed-references = "closure"
deps = ["gen"]
outputs = ["lib.rmeta"]
argv = ["{flagset:kernel-support}", "{dep:gen}/out.rs"]

[[derivation.compile.flag-group]]
when = "KERNEL_LOG_LEVEL = \"debug\""
flags = ["--cfg", "extra"]
"#,
    );
    dir
}

fn step_repo(tag: &str, subsystem: &str) -> PathBuf {
    let dir = sample_repo(tag);
    write(
        &dir,
        "buildutil.toml",
        r#"
[buildutil]
subsystems = ["sub"]

[arch.x86_64]
kernel-target-json = "kernite/x86_64-kernite.json"
userland-target = "x86_64-unknown-saltyos"
"#,
    );
    write(&dir, "sub/buildutil.toml", subsystem);
    dir
}

#[test]
fn required_declarative_tool_providers_load_from_each_manifest_and_are_grade_neutral() {
    let dir = step_repo(
        "tool-provider-load",
        r#"
[tool-provider.sub-tool]
derivation = "sub-tools"
path = "bin/sub-tool"

[derivation.root-tools]
builder = "nasm"
tool = "nasm"
outputs = ["root-tool"]

[derivation.sub-tools]
builder = "nasm"
tool = "nasm"
outputs = ["sub-tool"]
"#,
    );
    let root = dir.join("buildutil.toml");
    let text = std::fs::read_to_string(&root).unwrap();
    write(
        &dir,
        "buildutil.toml",
        &format!(
            "{text}\n[tool-provider.root-tool]\nderivation = \"root-tools\"\npath = \"root-tool\"\n"
        ),
    );

    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    let mut consumer = spec.drvs["root-tools"].clone();
    for bootstrap in [false, true] {
        consumer.bootstrap = bootstrap;
        assert_eq!(
            spec.tool_provider(&consumer, "root-tool"),
            Some(ToolProvider::Store {
                drv: "root-tools".into(),
                relpath: "root-tool".into(),
            })
        );
        assert_eq!(
            spec.tool_provider(&consumer, "sub-tool"),
            Some(ToolProvider::Store {
                drv: "sub-tools".into(),
                relpath: "bin/sub-tool".into(),
            })
        );
    }
    consumer.native_frontend = true;
    assert_eq!(spec.tool_provider(&consumer, "root-tool"), None);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn required_declarative_tool_providers_reject_missing_unsafe_and_builtin_declarations() {
    for (tag, declaration, expected) in [
        (
            "missing",
            "[tool-provider.project-tool]\nderivation = \"missing\"\npath = \"project-tool\"",
            "missing derivation `missing`",
        ),
        (
            "absolute",
            "[tool-provider.project-tool]\nderivation = \"provider\"\npath = \"/bin/tool\"",
            "normalized relative provider path",
        ),
        (
            "escaping",
            "[tool-provider.project-tool]\nderivation = \"provider\"\npath = \"bin/../tool\"",
            "normalized relative provider path",
        ),
        (
            "malformed",
            "[tool-provider.project-tool]\nderivation = \"provider\"\npath = \"bin//tool\"",
            "normalized relative provider path",
        ),
        (
            "builtin",
            "[tool-provider.buildutil-compose]\nderivation = \"provider\"\npath = \"buildutil-compose\"",
            "reserved by the engine",
        ),
    ] {
        let dir = step_repo(
            &format!("tool-provider-{tag}"),
            &format!(
                "{declaration}\n[derivation.provider]\nbuilder = \"nasm\"\ntool = \"nasm\"\noutputs = [\"tool\"]\n"
            ),
        );
        let error = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(error.contains(expected), "{tag}: {error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn required_declarative_tool_provider_aliases_are_unique_across_loaded_manifests() {
    let dir = step_repo(
        "tool-provider-duplicate",
        r#"
[tool-provider.project-tool]
derivation = "provider"
path = "tool"
[derivation.provider]
builder = "nasm"
tool = "nasm"
outputs = ["tool"]
"#,
    );
    let root = dir.join("buildutil.toml");
    let text = std::fs::read_to_string(&root).unwrap();
    write(
        &dir,
        "buildutil.toml",
        &format!(
            "{text}\n[tool-provider.project-tool]\nderivation = \"provider\"\npath = \"other\"\n"
        ),
    );
    let error = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(error.contains("duplicate tool provider alias `project-tool`"));
    std::fs::remove_dir_all(dir).unwrap();
}

/// A synthetic two-subsystem workspace shaped like the real
/// `host-llvm`/`sysroot-base` → `cross-llvm` relationship: a
/// `script-dag` derivation with a `cmake` step that depends on a
/// derivation in a *different* subsystem via `{dep-abs:*}`, and names
/// `{srcroot-abs}` in the same step. It exercises exactly the contract
/// `toolchain_script_dags_run_inner_ninja` checks — those exec-phase tokens
/// stay literal through `load()`, not resolved at spec-load time — without
/// depending on the real repository's manifest content or subsystem list,
/// which buildutil (a generic build engine) has no business knowing at compile
/// time. Independent of `sample_repo`/`step_repo` because those model a
/// single subsystem with a `deps`-linked pair inside it, not a cross-subsystem
/// dependency edge.
fn cross_subsystem_script_dag_repo(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "buildutil-spec-test-cross-subsystem-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    write(
        &dir,
        "buildutil.toml",
        r#"
[buildutil]
subsystems = ["provider", "consumer"]

[arch.x86_64]
kernel-target-json = "kernite/x86_64-kernite.json"
userland-target = "x86_64-unknown-saltyos"
"#,
    );
    write(
        &dir,
        "provider/buildutil.toml",
        r#"
[derivation.host-llvm]
builder = "x"
tool = "x"
outputs = ["bin/clang"]
argv = ["x"]

[derivation.sysroot-base]
builder = "x"
tool = "x"
outputs = ["sysroot/"]
argv = ["x"]
"#,
    );
    write(
        &dir,
        "consumer/buildutil.toml",
        r#"
[derivation.cross-llvm]
builder = "script-dag"
tool = "ninja"
extra-tools = ["cmake"]
deps = ["host-llvm", "sysroot-base"]
src-dirs = ["tools/cmake"]
outputs = ["bin/", "lib/", "include/", "libexec/", "share/"]

  [[derivation.cross-llvm.step]]
  tool = "cmake"
  argv = [
    "-DCMAKE_C_COMPILER={dep-abs:host-llvm}/bin/clang",
    "-DCMAKE_MODULE_PATH={srcroot-abs}/tools/cmake",
  ]
  outputs = ["build/build.ninja"]

  [[derivation.cross-llvm.step]]
  tool = "ninja"
  argv = ["-C", "build", "install"]
  outputs = ["bin/clang"]
"#,
    );
    dir
}

#[test]
fn loads_and_expands() {
    let dir = sample_repo("load");
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(spec.drvs.len(), 2);
    assert_eq!(
        spec.kinds
            .expand_group(crate::spec::kinds::Kind::Packages, "uapi")
            .unwrap(),
        vec!["gen", "compile"]
    );
    assert_eq!(spec.drvs["gen"].allowed_refs, RefPolicy::None);
    assert_eq!(spec.drvs["compile"].allowed_refs, RefPolicy::Closure);

    let config = Config::from_values(
        [
            ("DEBUG_SYMBOLS".to_string(), "true".to_string()),
            ("KERNEL_LOG_LEVEL".to_string(), "info".to_string()),
        ]
        .into_iter()
        .collect(),
    );
    let mut view = config.view();
    let argv = spec.eval_argv(&spec.drvs["compile"], &mut view).unwrap();
    assert_eq!(
        argv,
        vec![
            "rustc",
            "--color=always",
            "--edition=2024",
            "--target={srcroot}/kernite/x86_64-kernite.json",
            "-C",
            "debuginfo=2",
            "-Z",
            "unstable-options",
            "{dep:gen}/out.rs",
        ]
    );
    // The projection recorded both referenced keys.
    let keys: Vec<String> = view.projection().into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, vec!["DEBUG_SYMBOLS", "KERNEL_LOG_LEVEL"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowed_references_accepts_list_and_rejects_unknown_names() {
    let dir = sample_repo("allowed-refs");
    write(
        &dir,
        "buildutil.toml",
        r#"
[buildutil]
subsystems = ["sub"]

[arch.x86_64]
kernel-target-json = "kernite/x86_64-kernite.json"
userland-target = "x86_64-unknown-saltyos"
"#,
    );
    write(
        &dir,
        "sub/buildutil.toml",
        r#"
[derivation.dep]
builder = "x"
tool = "x"
outputs = ["dep"]
argv = ["x"]

[derivation.mid]
builder = "x"
tool = "x"
deps = ["dep"]
outputs = ["mid"]
argv = ["x"]

[derivation.top]
builder = "x"
tool = "x"
deps = ["mid"]
allowed-references = ["dep"]
outputs = ["top"]
argv = ["x"]
"#,
    );
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(
        spec.drvs["top"].allowed_refs,
        RefPolicy::List(vec!["dep".to_string()])
    );

    write(
        &dir,
        "sub/buildutil.toml",
        r#"
[derivation.top]
builder = "x"
tool = "x"
allowed-references = ["ghost"]
outputs = ["top"]
argv = ["x"]
"#,
    );
    let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(err.contains("allowed-references names unknown `ghost`"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn toolchain_script_dags_run_inner_ninja() {
    let repo = cross_subsystem_script_dag_repo("run-inner-ninja");
    let spec = load(&repo, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    let drv = &spec.drvs["cross-llvm"];

    assert_eq!(drv.builder, "script-dag");
    assert_eq!(drv.tool, "ninja");
    assert!(drv.extra_tools.iter().any(|tool| tool == "cmake"));
    assert_eq!(drv.steps[0].tool, "cmake");
    assert!(drv.src_dirs.iter().any(|path| path == "tools/cmake"));
    assert!(
        drv.steps[0]
            .argv
            .iter()
            .any(|arg| arg == "-DCMAKE_C_COMPILER={dep-abs:host-llvm}/bin/clang")
    );
    assert!(
        drv.steps[0]
            .argv
            .iter()
            .any(|arg| arg == "-DCMAKE_MODULE_PATH={srcroot-abs}/tools/cmake")
    );
    std::fs::remove_dir_all(repo).unwrap();
}

#[test]
fn undeclared_dep_reference_rejected() {
    let dir = sample_repo("baddep");
    write(
        &dir,
        "sub/buildutil.toml",
        "[derivation.bad]\nbuilder = \"x\"\ntool = \"x\"\noutputs = [\"o\"]\nargv = [\"{dep:ghost}/f\"]\n",
    );
    let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(err.contains("without declaring it"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn undeclared_abs_dep_reference_rejected() {
    let dir = sample_repo("baddepabs");
    write(
        &dir,
        "sub/buildutil.toml",
        "[derivation.bad]\nbuilder = \"x\"\ntool = \"x\"\noutputs = [\"o\"]\nargv = [\"{dep-abs:ghost}/f\"]\n",
    );
    let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(err.contains("without declaring it"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn step_each_expands_in_order() {
    let dir = step_repo(
        "step-each-expands",
        r#"
[derivation.pack]
builder = "script-dag"
tool = "ninja"
extra-tools = ["copy"]
outputs = ["bundle"]

[[derivation.pack.step]]
tool = "copy"
each = ["a", "b"]
argv = ["--input", "{item}.in", "--output", "{item}.out"]
capture = "{item}.out"
outputs = ["{item}.out"]
"#,
    );
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    let steps = &spec.drvs["pack"].steps;
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].argv, vec!["--input", "a.in", "--output", "a.out"]);
    assert_eq!(steps[0].outputs, vec!["a.out"]);
    assert_eq!(steps[0].capture, "a.out");
    assert_eq!(steps[1].argv, vec!["--input", "b.in", "--output", "b.out"]);
    assert_eq!(steps[1].outputs, vec!["b.out"]);
    assert_eq!(steps[1].capture, "b.out");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn step_each_dep_references_must_be_declared() {
    let dir = step_repo(
        "step-each-deps",
        r#"
[derivation.a]
builder = "x"
tool = "x"
outputs = ["a"]
argv = ["a"]

[derivation.b]
builder = "x"
tool = "x"
outputs = ["b"]
argv = ["b"]

[derivation.pack]
builder = "script-dag"
tool = "ninja"
extra-tools = ["copy"]
deps = ["a", "b"]
outputs = ["bundle"]

[[derivation.pack.step]]
tool = "copy"
each = ["a", "b"]
argv = ["{dep:{item}}/{item}"]
outputs = ["{item}.out"]
"#,
    );
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(spec.drvs["pack"].steps[1].argv, vec!["{dep:b}/b"]);

    write(
        &dir,
        "sub/buildutil.toml",
        r#"
[derivation.a]
builder = "x"
tool = "x"
outputs = ["a"]
argv = ["a"]

[derivation.b]
builder = "x"
tool = "x"
outputs = ["b"]
argv = ["b"]

[derivation.pack]
builder = "script-dag"
tool = "ninja"
extra-tools = ["copy"]
deps = ["a"]
outputs = ["bundle"]

[[derivation.pack.step]]
tool = "copy"
each = ["a", "b"]
argv = ["{dep:{item}}/{item}"]
outputs = ["{item}.out"]
"#,
    );
    let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(err.contains("without declaring it"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn step_each_requires_item_in_every_output() {
    let dir = step_repo(
        "step-each-output",
        r#"
[derivation.pack]
builder = "script-dag"
tool = "ninja"
outputs = ["bundle"]

[[derivation.pack.step]]
tool = "copy"
each = ["a", "b"]
argv = ["{item}.in"]
outputs = ["same.out"]
"#,
    );
    let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(err.contains("every output must contain {item}"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn step_item_requires_each_in_argv_tool_and_when() {
    let dir = step_repo("step-item-without-each", "");
    for step in [
        r#"
[derivation.pack]
builder = "script-dag"
tool = "ninja"
outputs = ["bundle"]
[[derivation.pack.step]]
tool = "copy"
argv = ["{item}.in"]
outputs = ["out"]
"#,
        r#"
[derivation.pack]
builder = "script-dag"
tool = "ninja"
outputs = ["bundle"]
[[derivation.pack.step]]
tool = "{item}"
outputs = ["out"]
"#,
        r#"
[derivation.pack]
builder = "script-dag"
tool = "ninja"
outputs = ["bundle"]
[[derivation.pack.step]]
when = "{item}"
tool = "copy"
outputs = ["out"]
"#,
    ] {
        write(&dir, "sub/buildutil.toml", step);
        let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(err.contains("{item} requires `each`"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn step_each_rejects_invalid_item_lists() {
    let dir = step_repo("step-each-invalid", "");
    for (each, message) in [
        ("each = []", "must not be empty"),
        ("each = [\"a\", \"a\"]", "duplicate `each` item"),
        ("each = [\"bad{item\"]", "plain literal"),
        (r#"each = ["bad\nitem"]"#, "plain literal"),
    ] {
        let subsystem = format!(
            r#"
[derivation.pack]
builder = "script-dag"
tool = "ninja"
outputs = ["bundle"]

[[derivation.pack.step]]
tool = "copy"
{each}
argv = ["{{item}}.in"]
outputs = ["{{item}}.out"]
"#
        );
        write(&dir, "sub/buildutil.toml", &subsystem);
        let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(err.contains(message), "unexpected error: {err}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn source_overlay_destination_must_be_inside_source_root() {
    let dir = sample_repo("bad-overlay-dest");
    write(
        &dir,
        "sub/buildutil.toml",
        r#"
[derivation.bad]
builder = "x"
tool = "x"
deps = ["vendor"]
source-roots = ["sub/src"]
source-overlays = ["{dep:vendor}/vendor:other/vendor"]
outputs = ["o"]
argv = ["x"]
"#,
    );
    let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(err.contains("must be inside a declared source-root"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn source_overlay_source_must_reference_dep() {
    let dir = sample_repo("bad-overlay-src");
    write(
        &dir,
        "sub/buildutil.toml",
        r#"
[derivation.bad]
builder = "x"
tool = "x"
source-roots = ["sub/src"]
source-overlays = ["sub/vendor:sub/src/vendor"]
outputs = ["o"]
argv = ["x"]
"#,
    );
    let err = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
    assert!(err.contains("must reference a declared {dep:*}"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn kinds_repo(tag: &str, root_extra: &str, sub: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "buildutil-spec-kinds-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    write(
        &dir,
        "buildutil.toml",
        &format!(
            "[buildutil]\nsubsystems = [\"sub\"]\ntarget-system = \"{{arch}}-testos\"\n[arch.x86_64]\n{root_extra}\n"
        ),
    );
    write(&dir, "sub/buildutil.toml", sub);
    dir
}

const KINDS_SUB: &str = r#"
[derivation.image]
builder = "x"
tool = "x"
outputs = ["image"]
argv = ["x"]

[derivation.runner]
builder = "x"
tool = "x"
outputs = ["runner"]
argv = ["x"]

[derivation.validation]
builder = "x"
tool = "x"
outputs = ["stamp"]
argv = ["x"]

[packages]
expose = ["image"]

[checks]
expose = ["validation"]
"#;

#[test]
fn required_kind_tables_merge_from_every_file_and_the_alias_table_is_refused() {
    let dir = kinds_repo(
        "merge",
        "[packages]\nexpose = [\"image-test\"]\n[packages.group]\nimages = [\"image\", \"image-test\"]\n[derivation.image-test]\nvariant-of = \"image\"\nconfig = { TEST_AUTOSHUTDOWN = true }\n",
        KINDS_SUB,
    );
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(spec.target_system, "x86_64-testos");
    assert!(spec.kinds.is_exposed(super::kinds::Kind::Packages, "image"));
    assert!(spec.kinds.is_exposed(super::kinds::Kind::Checks, "validation"));
    assert_eq!(
        spec.kinds
            .expand_group(super::kinds::Kind::Packages, "images")
            .unwrap(),
        ["image", "image-test"]
    );
    let variant = &spec.variants["image-test"];
    assert_eq!(variant.base, "image");
    assert_eq!(variant.overrides["TEST_AUTOSHUTDOWN"], "true");
    assert!(!spec.drvs.contains_key("image-test"));

    let alias = kinds_repo("alias", "[alias]\nall = [\"image\"]\n", KINDS_SUB);
    assert!(
        load(&alias, "x86_64", "x86_64-unknown-linux-gnu")
            .unwrap_err()
            .contains("[alias]")
    );
    // A name exposed by two files.
    let twice = kinds_repo("twice", "[packages]\nexpose = [\"image\"]\n", KINDS_SUB);
    assert!(load(&twice, "x86_64", "x86_64-unknown-linux-gnu").is_err());
    for dir in [dir, alias, twice] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn required_variants_and_their_edges_are_validated_at_load() {
    let refused = |tag: &str, root_extra: &str, sub_extra: &str| {
        let dir = kinds_repo(tag, root_extra, &format!("{KINDS_SUB}\n{sub_extra}"));
        let error = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap_err();
        let _ = std::fs::remove_dir_all(dir);
        error
    };
    // A variant is only a base and its overrides.
    assert!(
        refused(
            "variant-keys",
            "[derivation.v]\nvariant-of = \"image\"\nconfig = { A = \"1\" }\noutputs = [\"x\"]\n",
            ""
        )
        .contains("only")
    );
    // A variant of nothing, a variant without overrides, a looping chain and
    // a chain setting one key twice.
    assert!(refused("variant-unknown", "[derivation.v]\nvariant-of = \"ghost\"\nconfig = { A = \"1\" }\n", "").contains("ghost"));
    assert!(refused("variant-empty", "[derivation.v]\nvariant-of = \"image\"\n", "").contains("override"));
    assert!(refused(
        "variant-loop",
        "[derivation.a]\nvariant-of = \"b\"\nconfig = { A = \"1\" }\n[derivation.b]\nvariant-of = \"a\"\nconfig = { B = \"1\" }\n",
        ""
    )
    .contains("itself"));
    assert!(refused(
        "variant-conflict",
        "[derivation.a]\nvariant-of = \"image\"\nconfig = { A = \"1\" }\n[derivation.b]\nvariant-of = \"a\"\nconfig = { A = \"2\" }\n",
        ""
    )
    .contains("A"));
    // A dependent names a variant's outputs by its base.
    let edge = "[derivation.v]\nvariant-of = \"runner\"\nconfig = { A = \"1\" }\n";
    assert!(refused(
        "variant-token",
        edge,
        "[derivation.user]\nbuilder = \"x\"\ntool = \"x\"\ndeps = [\"v\"]\noutputs = [\"o\"]\nargv = [\"{dep:v}/runner\"]\n"
    )
    .contains("{dep:runner}"));
    // Two configurations of one base in one derivation.
    assert!(refused(
        "variant-two",
        edge,
        "[derivation.user]\nbuilder = \"x\"\ntool = \"x\"\ndeps = [\"v\", \"runner\"]\noutputs = [\"o\"]\nargv = [\"{dep:runner}/runner\"]\n"
    )
    .contains("two configurations"));
    // A required check names a [checks] entry.
    assert!(refused(
        "required-kind",
        "[required-check.gate]\nderivation = \"runner\"\nphase = \"before\"\nartifacts = [\"image\"]\n",
        ""
    )
    .contains("[checks]"));
    let dir = kinds_repo(
        "variant-edge",
        edge,
        &format!(
            "{KINDS_SUB}\n[derivation.user]\nbuilder = \"x\"\ntool = \"x\"\ndeps = [\"v\"]\noutputs = [\"o\"]\nargv = [\"{{dep:runner}}/runner\"]\n"
        ),
    );
    let spec = load(&dir, "x86_64", "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(spec.drvs["user"].deps, ["v"]);
    let _ = std::fs::remove_dir_all(dir);
}
