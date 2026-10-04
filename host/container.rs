//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — host: container image / command / plan / session runner
//!
//! This module is one of two backends an evaluation can be dispatched through
//! (the other being `host::wsl`). Container runs prepare the executor image
//! from its pinned inputs (`host::image`), then run the inner `buildutil`
//! invocation in either a one-shot or daemon-owned resident container,
//! stream its events back, and trap interrupts so the active container is
//! `rm -f`'d on Ctrl-C / SIGTERM. Containers are not privileged: they
//! receive only what the inner namespace sandbox needs. The higher-level
//! entry points (`run_plan_in_container`, `run_dev_build_in_container` and
//! `run_plan_parity_in_container`) are called from the build commands.

use crate::invocation::Io;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::interrupt::{InterruptCleanup, InterruptGuard, container_interrupt_cleanup};

pub(crate) const CONTAINER_STATE_ROOT: &str = "/buildutil-state";
// The input-attestation env-var names live in `source::git` — compiled by both
// the full buildutil and the standalone minibuildutil that consumes the attestation.
// Reference them here rather than keep a second copy that could drift from the
// consumer.
use crate::source::git::{
    CONTAINER_BOOTSTRAP_HASH_ENV, CONTAINER_GIT_IDENTITY_ENV, CONTAINER_INPUT_CONTENT_ENV,
};
const SELFHOST_REPO_ROOT_ENV: &str = "BUILDUTIL_SELFHOST_REPO_ROOT";
const SELFHOST_STATE_ROOT_ENV: &str = "BUILDUTIL_SELFHOST_STATE_ROOT";
pub(crate) const REALIZE_BUILD_HOST_ENV: &str = "BUILDUTIL_REALIZE_BUILD_HOST";
pub(crate) const REALIZE_PLATFORM_ENV: &str = "BUILDUTIL_REALIZE_PLATFORM";
pub(crate) const EXECUTOR_IMAGE_ID_ENV: &str = "BUILDUTIL_EXECUTOR_IMAGE_ID";
pub(crate) const EXECUTOR_DRV_ENV: &str = "BUILDUTIL_EXECUTOR_DRV";
pub(crate) const EXECUTOR_STORE_ENV: &str = "BUILDUTIL_EXECUTOR_STORE";
const RESIDENT_LABEL_PROTOCOL: &str = "io.buildutil.resident-protocol";
const RESIDENT_LABEL_IMAGE_ID: &str = "io.buildutil.executor-image-id";
const RESIDENT_LABEL_EXECUTOR_DRV: &str = "io.buildutil.executor-drv";
const RESIDENT_LABEL_EXECUTOR_STORE: &str = "io.buildutil.executor-store";
const RESIDENT_PROTOCOL: &str = "1";

pub(crate) fn tee_status_script(command: &str, log_path: &str, status_path: &str) -> String {
    let status = super::shell_quote(status_path);
    let log = super::shell_quote(log_path);
    format!(
        "status_file={status}; rm -f \"$status_file\"; \
         ( {command}; code=$?; printf '%s\\n' \"$code\" > \"$status_file\"; exit \"$code\" ) \
         2>&1 | tee -a {log}; \
         code=$(cat \"$status_file\" 2>/dev/null || printf 1); \
         rm -f \"$status_file\"; exit \"$code\""
    )
}

fn container_state_mount_args(state_root: &Path) -> Vec<String> {
    vec![
        "-v".to_string(),
        format!("{}:{}:rw", state_root.display(), CONTAINER_STATE_ROOT),
    ]
}

/// Where a plan-parity run sees the repository: `/parity/<exec hash>`, a
/// `.git`-less view named by the attested bootstrap projection, so the
/// in-container evaluation takes the input content digest and the repository identity
/// from the host's attestation. The executor image carries no git.
fn parity_source_root(exec_hash: &str) -> String {
    format!("/parity/{exec_hash}")
}

/// The repository's top-level entries a plan-parity run binds: every one but
/// `.git`, so the view holds the tree without its git metadata.
fn parity_source_entries(repo_root: &Path) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(repo_root)
        .map_err(|e| format!("cannot read {}: {e}", repo_root.display()))?
    {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", repo_root.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| format!("repository entry {name:?} is not UTF-8"))?;
        if name != ".git" {
            entries.push(name);
        }
    }
    entries.sort();
    Ok(entries)
}

/// Read-only binds of `entries` of the repository under `source_root`.
fn parity_source_mount_args(
    repo_root: &Path,
    entries: &[String],
    source_root: &str,
) -> Vec<String> {
    let mut args = Vec::with_capacity(entries.len() * 2);
    for entry in entries {
        args.push("-v".to_string());
        args.push(format!(
            "{}:{source_root}/{entry}:ro",
            repo_root.join(entry).display()
        ));
    }
    args
}

fn container_exec_workdir(exec_hash: &str) -> String {
    format!("{CONTAINER_STATE_ROOT}/exec/{exec_hash}")
}

/// What every executor container receives in place of `--privileged`: the
/// inner namespace sandbox unshares a user namespace (refused by the
/// runtimes' default seccomp profile), mounts inside it (refused by the
/// default AppArmor profile) and mounts a fresh `/proc` (refused while the
/// runtime masks paths under the container's `/proc`). No capability is
/// added. `/dev/kvm` is passed where this client can open it; the VMs that
/// run containers for macOS and Windows provide none, so guests there use
/// software emulation.
fn sandbox_run_args() -> Vec<String> {
    let mut args = Vec::new();
    for option in [
        "seccomp=unconfined",
        "apparmor=unconfined",
        "systempaths=unconfined",
    ] {
        args.push("--security-opt".to_string());
        args.push(option.to_string());
    }
    if kvm_available() {
        args.push("--device".to_string());
        args.push("/dev/kvm".to_string());
    }
    args
}

#[cfg(target_os = "linux")]
fn kvm_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

#[cfg(not(target_os = "linux"))]
fn kvm_available() -> bool {
    false
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ContainerCommand {
    pub(crate) workdir: String,
    pub(crate) inner_command: String,
    pub(crate) run_args: Vec<String>,
}

/// Host-verified input content bound to the exact bootstrap projection.
/// The projected lock is checked again before compiling the configuration library.
/// Private fields prevent constructing a container command from an unchecked projection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ContainerBootstrap {
    exec_hash: String,
    input_content: String,
    image_id: String,
    executor_drv: String,
    executor_store: String,
}

pub(crate) struct PreparedContainerBootstrap {
    pub(crate) bootstrap: ContainerBootstrap,
    _executor_lock: crate::state::ExecutorLock,
}

impl ContainerBootstrap {
    fn from_verified(
        exec_dir: &Path,
        input_content: String,
        image_id: String,
        build_host: &super::BuildHost,
        bootstrap_digest: &str,
    ) -> Result<Self, String> {
        let exec_hash = exec_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid exec dir {}", exec_dir.display()))?
            .to_string();
        if exec_hash.len() != 32 || !exec_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid bootstrap exec hash `{exec_hash}`"));
        }
        if bootstrap_digest.len() != 64
            || !bootstrap_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!(
                "invalid bootstrap closure digest `{bootstrap_digest}`"
            ));
        }
        if input_content.len() != 64 || !input_content.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!(
                "invalid verified bootstrap input content `{input_content}`"
            ));
        }
        let image_hash = image_id.strip_prefix("sha256:").unwrap_or(&image_id);
        if image_hash.len() != 64 || !image_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "invalid content-addressed container image id `{image_id}`"
            ));
        }
        let drv = crate::eval::plan::container_executor_derivation(
            bootstrap_digest,
            build_host.triple(),
            build_host.container_platform(),
            &image_id,
        );
        Ok(Self {
            exec_hash,
            input_content,
            image_id,
            executor_drv: drv.hash(),
            executor_store: drv.store_name(),
        })
    }

    fn resident_identity(&self) -> ResidentContainerIdentity {
        ResidentContainerIdentity {
            image_id: self.image_id.clone(),
            executor_drv: self.executor_drv.clone(),
            executor_store: self.executor_store.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResidentContainerIdentity {
    image_id: String,
    executor_drv: String,
    executor_store: String,
}

impl ResidentContainerIdentity {
    fn label_values(&self) -> [(&'static str, &str); 4] {
        [
            (RESIDENT_LABEL_PROTOCOL, RESIDENT_PROTOCOL),
            (RESIDENT_LABEL_IMAGE_ID, &self.image_id),
            (RESIDENT_LABEL_EXECUTOR_DRV, &self.executor_drv),
            (RESIDENT_LABEL_EXECUTOR_STORE, &self.executor_store),
        ]
    }

    fn matches_inspection(&self, inspection: &ResidentContainerInspection) -> bool {
        inspection.protocol == RESIDENT_PROTOCOL
            && inspection.image_id == self.image_id
            && inspection.executor_drv == self.executor_drv
            && inspection.executor_store == self.executor_store
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ResidentContainerInspection {
    running: bool,
    protocol: String,
    image_id: String,
    executor_drv: String,
    executor_store: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResidentContainerAction {
    Exec,
    Start,
    Create,
    Recreate,
}

fn resident_container_action(
    inspection: Option<&ResidentContainerInspection>,
    identity: &ResidentContainerIdentity,
) -> ResidentContainerAction {
    match inspection {
        None => ResidentContainerAction::Create,
        Some(inspection) if !identity.matches_inspection(inspection) => {
            ResidentContainerAction::Recreate
        }
        Some(ResidentContainerInspection { running: true, .. }) => ResidentContainerAction::Exec,
        Some(_) => ResidentContainerAction::Start,
    }
}

#[must_use]
struct ContainerLifecycleLease {
    _file: File,
}

fn container_lifecycle_lease_path(state_root: &Path) -> PathBuf {
    state_root.join("locks").join("container.lease")
}

fn acquire_container_lifecycle_lease(state_root: &Path) -> Result<ContainerLifecycleLease, String> {
    let path = container_lifecycle_lease_path(state_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "cannot create container lease directory {}: {e}",
                parent.display()
            )
        })?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)
        .map_err(|e| format!("cannot open container lease {}: {e}", path.display()))?;
    crate::platform::lock_exclusive(&file, false)
        .map_err(|e| format!("cannot lock container lease {}: {e}", path.display()))?;
    Ok(ContainerLifecycleLease { _file: file })
}

fn normalized_state_root(state_root: &Path) -> PathBuf {
    std::fs::canonicalize(state_root).unwrap_or_else(|_| state_root.to_path_buf())
}

pub(crate) fn resident_container_name(state_root: &Path) -> String {
    let state_root = normalized_state_root(state_root);
    let digest = crate::crypto::sha256::hash_bytes(state_root.as_os_str().as_encoded_bytes());
    format!("buildutil-resident-{}", &digest[..16])
}

fn resident_container_label_args(identity: &ResidentContainerIdentity) -> Vec<String> {
    let mut args = Vec::with_capacity(8);
    for (key, value) in identity.label_values() {
        args.push("--label".to_string());
        args.push(format!("{key}={value}"));
    }
    args
}

fn resident_container_create_args(
    state_root: &Path,
    build_host: &super::BuildHost,
    container: &str,
    identity: &ResidentContainerIdentity,
    image_tag: &str,
) -> Vec<String> {
    let mut args = vec![
        "create".to_string(),
        "--init".to_string(),
        "--platform".to_string(),
        build_host.container_platform().to_string(),
        "--name".to_string(),
        container.to_string(),
    ];
    args.extend(sandbox_run_args());
    args.extend(resident_container_label_args(identity));
    args.extend(container_state_mount_args(state_root));
    args.extend([
        image_tag.to_string(),
        "sleep".to_string(),
        "infinity".to_string(),
    ]);
    args
}

#[derive(Debug, PartialEq, Eq)]
struct ResidentContainerCommand {
    inner_command: String,
    exec_args: Vec<String>,
}

fn resident_container_command(
    build_host: &super::BuildHost,
    container: &str,
    bootstrap: &ContainerBootstrap,
    inner_args: &[String],
) -> ResidentContainerCommand {
    let workdir = container_exec_workdir(&bootstrap.exec_hash);
    let inner_command = command_line("./buildutil", inner_args);
    let mut exec_args = vec!["exec".to_string(), "-i".to_string()];
    exec_args.extend(container_bootstrap_env(bootstrap, &workdir, build_host));
    exec_args.extend([
        "-w".to_string(),
        workdir.clone(),
        container.to_string(),
        "sh".to_string(),
        "-lc".to_string(),
        inner_command.clone(),
    ]);
    ResidentContainerCommand {
        inner_command,
        exec_args,
    }
}

fn resident_container_inspect_format() -> String {
    format!(
        "{{{{.State.Running}}}}\n{{{{index .Config.Labels \"{RESIDENT_LABEL_PROTOCOL}\"}}}}\n{{{{index .Config.Labels \"{RESIDENT_LABEL_IMAGE_ID}\"}}}}\n{{{{index .Config.Labels \"{RESIDENT_LABEL_EXECUTOR_DRV}\"}}}}\n{{{{index .Config.Labels \"{RESIDENT_LABEL_EXECUTOR_STORE}\"}}}}"
    )
}

fn inspect_resident_container(
    runtime: &str,
    container: &str,
) -> Result<Option<ResidentContainerInspection>, String> {
    let format = resident_container_inspect_format();
    let output = crate::invocation::command(runtime)
        .args([
            "container",
            "inspect",
            "--format",
            format.as_str(),
            container,
        ])
        .output()
        .map_err(|e| format!("cannot inspect resident container {container}: {e}"))?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if error.contains("no such container") || error.contains("not found") {
            return Ok(None);
        }
        return Err(format!(
            "cannot inspect resident container {container}: {}",
            error.trim()
        ));
    }
    let output = String::from_utf8(output.stdout)
        .map_err(|_| format!("resident container {container} inspection is not UTF-8"))?;
    let mut lines = output.lines();
    let running = match lines.next() {
        Some("true") => true,
        Some("false") => false,
        Some(value) => {
            return Err(format!(
                "resident container {container} returned invalid running state `{value}`"
            ));
        }
        None => {
            return Err(format!(
                "resident container {container} returned no inspection data"
            ));
        }
    };
    let mut next_label = || {
        lines
            .next()
            .map(str::to_string)
            .ok_or_else(|| format!("resident container {container} returned incomplete labels"))
    };
    Ok(Some(ResidentContainerInspection {
        running,
        protocol: next_label()?,
        image_id: next_label()?,
        executor_drv: next_label()?,
        executor_store: next_label()?,
    }))
}

fn run_resident_lifecycle_command(
    runtime: &str,
    args: &[String],
    container: &str,
) -> Result<(), String> {
    let output = crate::invocation::command(runtime)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {runtime} resident-container command: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "resident container {container} command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn ensure_resident_container(
    runtime: &str,
    state_root: &Path,
    build_host: &super::BuildHost,
    bootstrap: &ContainerBootstrap,
    image_tag: &str,
) -> Result<String, String> {
    let container = resident_container_name(state_root);
    let identity = bootstrap.resident_identity();
    if resident_container_action(
        inspect_resident_container(runtime, &container)?.as_ref(),
        &identity,
    ) == ResidentContainerAction::Exec
    {
        return Ok(container);
    }
    let _lease = acquire_container_lifecycle_lease(state_root)?;
    let action = resident_container_action(
        inspect_resident_container(runtime, &container)?.as_ref(),
        &identity,
    );
    match action {
        ResidentContainerAction::Exec => {}
        ResidentContainerAction::Start => {
            run_resident_lifecycle_command(
                runtime,
                &["start".to_string(), container.clone()],
                &container,
            )?;
        }
        ResidentContainerAction::Create | ResidentContainerAction::Recreate => {
            if action == ResidentContainerAction::Recreate {
                run_resident_lifecycle_command(
                    runtime,
                    &["rm".to_string(), "-f".to_string(), container.clone()],
                    &container,
                )?;
            }
            let create = resident_container_create_args(
                state_root, build_host, &container, &identity, image_tag,
            );
            run_resident_lifecycle_command(runtime, &create, &container)?;
            run_resident_lifecycle_command(
                runtime,
                &["start".to_string(), container.clone()],
                &container,
            )?;
        }
    }
    Ok(container)
}

pub(crate) fn teardown_resident_container(runtime: &str, state_root: &Path) -> Result<(), String> {
    let _lease = acquire_container_lifecycle_lease(state_root)?;
    let container = resident_container_name(state_root);
    if inspect_resident_container(runtime, &container)?.is_some() {
        run_resident_lifecycle_command(
            runtime,
            &["rm".to_string(), "-f".to_string(), container.clone()],
            &container,
        )?;
    }
    Ok(())
}

pub(crate) fn reap_orphan_resident_containers(state_root: &Path) {
    for runtime in ["docker", "nerdctl"] {
        let _ = teardown_resident_container(runtime, state_root);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn daemon_owned_container_enabled() -> bool {
    crate::daemon::state::is_active_daemon()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn daemon_owned_container_enabled() -> bool {
    false
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn record_resident_container_runtime(runtime: &str) {
    let _ = crate::daemon::state::with_active_daemon(|state| {
        state.record_resident_container_runtime(runtime)
    });
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn record_resident_container_runtime(_runtime: &str) {}

fn prepare_attested_container_executor(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    image_id: String,
    plan: &crate::eval::plan::ExecPlan,
) -> Result<PreparedContainerBootstrap, String> {
    let input_content = crate::source::git::verified_bootstrap_content(repo_root)?;
    crate::source::activate(state_root)?;
    let exec_hash = plan.bootstrap_hash();
    let executor_lock = crate::state::lock_executor(state_root, &exec_hash)?;
    let root = crate::eval::plan::write_bootstrap_exec_dir(plan, state_root)?;
    let bootstrap = ContainerBootstrap::from_verified(
        &root,
        input_content,
        image_id,
        build_host,
        &plan.bootstrap_digest(),
    )?;
    Ok(PreparedContainerBootstrap {
        bootstrap,
        _executor_lock: executor_lock,
    })
}

fn prepare_attested_current_container_bootstrap(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    image_id: String,
) -> Result<PreparedContainerBootstrap, String> {
    let projection = current_executor_plan(repo_root)?;
    prepare_attested_container_executor(repo_root, state_root, build_host, image_id, &projection)
}

fn current_executor_plan(repo_root: &Path) -> Result<crate::eval::plan::ExecPlan, String> {
    Ok(crate::eval::plan::ExecPlan {
        arch: String::new(),
        build_host: String::new(),
        filter_hash: String::new(),
        git_rev: String::new(),
        git_dirty: String::new(),
        targets: Vec::new(),
        bootstrap: crate::eval::plan::bootstrap::collect_bootstrap(repo_root)?,
        nodes: Vec::new(),
    })
}

fn prepare_plan_container_bootstrap(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    image_id: String,
    plan: &crate::eval::plan::ExecPlan,
) -> Result<PreparedContainerBootstrap, String> {
    let current = crate::eval::plan::bootstrap::collect_bootstrap(repo_root)?;
    let current_hash = crate::eval::plan::ExecPlan {
        arch: String::new(),
        build_host: String::new(),
        filter_hash: String::new(),
        git_rev: String::new(),
        git_dirty: String::new(),
        targets: Vec::new(),
        bootstrap: current,
        nodes: Vec::new(),
    }
    .bootstrap_hash();
    if current_hash != plan.bootstrap_hash() {
        return Err(format!(
            "container bootstrap inputs changed after plan evaluation\n  plan    {}\n  current {current_hash}\nre-evaluate the build before container dispatch",
            plan.bootstrap_hash()
        ));
    }
    prepare_attested_container_executor(repo_root, state_root, build_host, image_id, plan)
}

fn container_bootstrap_env(
    bootstrap: &ContainerBootstrap,
    source_root: &str,
    build_host: &super::BuildHost,
) -> Vec<String> {
    vec![
        "--env".to_string(),
        format!("{CONTAINER_INPUT_CONTENT_ENV}={}", bootstrap.input_content),
        "--env".to_string(),
        format!("{CONTAINER_BOOTSTRAP_HASH_ENV}={}", bootstrap.exec_hash),
        "--env".to_string(),
        format!("{SELFHOST_REPO_ROOT_ENV}={source_root}"),
        "--env".to_string(),
        format!("{SELFHOST_STATE_ROOT_ENV}={CONTAINER_STATE_ROOT}"),
        "--env".to_string(),
        format!("{REALIZE_BUILD_HOST_ENV}={}", build_host.triple()),
        "--env".to_string(),
        format!("{REALIZE_PLATFORM_ENV}={}", build_host.container_platform()),
        "--env".to_string(),
        format!("{EXECUTOR_IMAGE_ID_ENV}={}", bootstrap.image_id),
        "--env".to_string(),
        format!("{EXECUTOR_DRV_ENV}={}", bootstrap.executor_drv),
        "--env".to_string(),
        format!("{EXECUTOR_STORE_ENV}={}", bootstrap.executor_store),
    ]
}

pub(crate) fn container_command(
    _repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    image: &str,
    container: &str,
    bootstrap: &ContainerBootstrap,
    inner_args: &[String],
) -> ContainerCommand {
    let workdir = container_exec_workdir(&bootstrap.exec_hash);
    let inner_command = command_line("./buildutil", inner_args);
    let mut run_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--init".to_string(),
        "--platform".to_string(),
        build_host.container_platform().to_string(),
        "--name".to_string(),
        container.to_string(),
    ];
    run_args.extend(sandbox_run_args());
    run_args.extend(container_state_mount_args(state_root));
    run_args.extend(container_bootstrap_env(bootstrap, &workdir, build_host));
    // The image is named by its tag: a runtime backed by containerd may
    // report another digest than the configuration digest as its id.
    run_args.extend([
        "-w".to_string(),
        workdir.clone(),
        image.to_string(),
        "sh".to_string(),
        "-lc".to_string(),
        inner_command.clone(),
    ]);
    ContainerCommand {
        workdir,
        inner_command,
        run_args,
    }
}

/// The plan-parity run: the executor's `buildutil` evaluates the repository's
/// `entries` at the parity source root, `.git`-less, where git would have
/// read the input content digest, the repository identity and the clean-checkout routes.
/// The pin and the identity (`git_identity`, `<rev> <dirty>` from the host's
/// plan) come from the host's attestation; sources are walked.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_parity_container_command(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    image: &str,
    container: &str,
    bootstrap: &ContainerBootstrap,
    entries: &[String],
    git_identity: &str,
    inner_args: &[String],
) -> ContainerCommand {
    let exec_workdir = container_exec_workdir(&bootstrap.exec_hash);
    let workdir = parity_source_root(&bootstrap.exec_hash);
    let inner_command = command_line(&format!("{exec_workdir}/buildutil"), inner_args);
    let mut run_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--init".to_string(),
        "--platform".to_string(),
        build_host.container_platform().to_string(),
        "--name".to_string(),
        container.to_string(),
    ];
    run_args.extend(sandbox_run_args());
    run_args.extend(container_state_mount_args(state_root));
    run_args.extend(parity_source_mount_args(repo_root, entries, &workdir));
    run_args.extend(container_bootstrap_env(
        bootstrap,
        &exec_workdir,
        build_host,
    ));
    run_args.extend([
        "--env".to_string(),
        format!("{CONTAINER_GIT_IDENTITY_ENV}={git_identity}"),
    ]);
    run_args.extend([
        "-w".to_string(),
        workdir.clone(),
        image.to_string(),
        "sh".to_string(),
        "-lc".to_string(),
        inner_command.clone(),
    ]);
    ContainerCommand {
        workdir,
        inner_command,
        run_args,
    }
}

/// Evaluate `inner_args` (a `buildutil plan` invocation) in the executor over a
/// `.git`-less view of the repository; `git_identity` is the host plan's
/// `<git-rev> <git-dirty>`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_plan_parity_in_container(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    backend: &super::ExecBackend,
    image_spec: Option<&crate::spec::ExecutorImageSpec>,
    git_identity: &str,
    inner_args: &[String],
    output_path: &Path,
) -> Result<i32, String> {
    let state_root = if state_root.is_absolute() {
        state_root.to_path_buf()
    } else {
        repo_root.join(state_root)
    };
    let logs_dir = crate::state::logs_dir(&state_root);
    let tmp_dir = state_root.join("tmp");
    std::fs::create_dir_all(&logs_dir)
        .map_err(|e| format!("cannot create {}: {}", logs_dir.display(), e))?;
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("cannot create {}: {}", tmp_dir.display(), e))?;
    let stamp = super::utc_timestamp();
    let stem = "plan-parity";
    let log_path = logs_dir.join(format!("{stem}-{stamp}.log"));
    let container_log_path = logs_dir.join(format!("{stem}-{stamp}.container.log"));
    let logger = crate::log::Logger::new(std::env::args().any(|a| a == "-v"));
    logger.info(
        "plan-parity",
        &format!("Logging parity command to {}", log_path.display()),
    );

    match backend {
        super::ExecBackend::Docker | super::ExecBackend::Nerdctl => {
            let runtime = backend.as_str();
            let container = "buildutil-plan-parity";
            let image = super::image::prepare_executor_image(
                runtime,
                &state_root,
                build_host,
                image_spec.ok_or("no [executor-image] table declares the executor image")?,
            )?;
            let _ = crate::invocation::command(runtime)
                .args(["rm", "-f", container])
                .stdout(Io::Null)
                .stderr(Io::Null)
                .status();
            let prepared = prepare_attested_current_container_bootstrap(
                repo_root,
                &state_root,
                build_host,
                image.id.clone(),
            )?;
            let bootstrap = &prepared.bootstrap;
            logger.info(
                "plan-parity",
                &format!(
                    "Bootstrap exec dir: {}",
                    crate::state::exec_dir(&state_root)
                        .join(&bootstrap.exec_hash)
                        .display()
                ),
            );

            let entries = parity_source_entries(repo_root)?;
            let command = plan_parity_container_command(
                repo_root,
                &state_root,
                build_host,
                &image.tag,
                container,
                bootstrap,
                &entries,
                git_identity,
                inner_args,
            );
            let inner_command = format!(
                "{} > {}",
                command.inner_command,
                super::shell_quote(&output_path.to_string_lossy())
            );
            let inner = tee_status_script(
                &inner_command,
                &crate::state::logs_dir(Path::new(CONTAINER_STATE_ROOT))
                    .join(format!("{stem}-{stamp}.log"))
                    .to_string_lossy(),
                "/tmp/buildutil-plan-parity.status",
            );
            let mut run_args = command.run_args;
            let shell_arg = run_args
                .last_mut()
                .ok_or("internal error: missing container command")?;
            *shell_arg = inner;
            let code = run_container_command(
                runtime,
                &run_args,
                repo_root,
                Some(&container_log_path),
                container,
                true,
                "plan parity container",
                None,
            )?;
            if code != 0 {
                logger.info(
                    "plan-parity",
                    &format!(
                        "backend log: {}",
                        crate::term::display_path(&container_log_path)
                    ),
                );
            }
            Ok(code)
        }
        super::ExecBackend::Remote => {
            Err("plan-parity: remote backend requires a configured remote builder".to_string())
        }
        super::ExecBackend::LocalLinux => {
            Err("plan-parity: local-linux is not a container backend".to_string())
        }
        super::ExecBackend::Wsl => Err("plan-parity: wsl backend is not supported".to_string()),
    }
}

pub(crate) fn command_line(program: &str, args: &[String]) -> String {
    let mut out = super::shell_quote(program);
    for arg in args {
        out.push(' ');
        out.push_str(&super::shell_quote(arg));
    }
    out
}

/// Remove a one-shot container, whether or not it still exists.
fn remove_container(runtime: &str, container: &str) {
    let _ = crate::invocation::command(runtime)
        .args(["rm", "-f", container])
        .stdout(Io::Null)
        .stderr(Io::Null)
        .status();
}

/// Copy a container runtime's output stream line by line to `show` and,
/// when one is given, append it to the log as the runtime wrote it.
fn copy_runtime_lines(
    stream: impl Read,
    log: Option<&Mutex<File>>,
    show: fn(&str),
) -> Result<(), String> {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("cannot read the container runtime's output: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        if let Some(log) = log {
            log.lock()
                .map_err(|_| "container log lock poisoned".to_string())?
                .write_all(&buf)
                .map_err(|e| format!("cannot write the container log: {e}"))?;
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        show(&String::from_utf8_lossy(&buf));
    }
}

/// Run the container runtime with `args` on this client and wait for it.
/// Its output is shown and, when `log` names a file, appended to it. An
/// interrupt removes a one-shot container while the runtime runs, and tears
/// a resident one (`resident_state_root`) down once the runtime has exited;
/// with `remove_on_failure`, a failed one-shot run removes its container
/// too. The runtime runs directly: no host shell carries it.
#[allow(clippy::too_many_arguments)]
fn run_container_command(
    runtime: &str,
    args: &[String],
    repo_root: &Path,
    log: Option<&Path>,
    container: &str,
    remove_on_failure: bool,
    context: &str,
    resident_state_root: Option<&Path>,
) -> Result<i32, String> {
    let log = match log {
        Some(path) => Some(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("cannot open {}: {e}", path.display()))?,
        )),
        None => None,
    };
    let interrupt_guard = InterruptGuard::install();
    let mut command = crate::invocation::command(runtime);
    command
        .args(args)
        .current_dir(repo_root)
        .stdout(Io::Piped)
        .stderr(Io::Piped)
        .new_process_group();
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run {context}: {e}"))?;
    let _request_group = crate::platform::register_request_process_group(child.id());
    // Resident teardown runs after the runtime exits so it can take the
    // lifecycle lease before removing the container.
    let interrupt_cleanup = InterruptCleanup::start(
        child.id(),
        match resident_state_root {
            Some(_) => Box::new(|| {}),
            None => container_interrupt_cleanup(runtime, container),
        },
    );
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("cannot capture the {context} output"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("cannot capture the {context} output"))?;
    let (status, copied) = std::thread::scope(|scope| {
        let out = scope.spawn(|| copy_runtime_lines(stdout, log.as_ref(), crate::term::result));
        let err = scope.spawn(|| copy_runtime_lines(stderr, log.as_ref(), crate::term::line));
        let status = child.wait();
        (status, [out.join(), err.join()])
    });
    let status = status.map_err(|e| format!("cannot wait for {context}: {e}"))?;
    interrupt_cleanup.finish()?;
    if interrupt_guard.was_interrupted() {
        if let Some(state_root) = resident_state_root {
            teardown_resident_container(runtime, state_root)?;
        }
        return Ok(130);
    }
    let code = status.code().unwrap_or(1);
    if code != 0 && remove_on_failure {
        remove_container(runtime, container);
    }
    for copied in copied {
        copied.map_err(|_| format!("{context} output reader panicked"))??;
    }
    Ok(code)
}

#[allow(clippy::too_many_arguments)]
fn run_streaming_container(
    runtime: &str,
    run_args: &[String],
    repo_root: &Path,
    container_log_path: &Path,
    container: &str,
    require_header: bool,
    remove_container_on_failure: bool,
    resident_state_root: Option<&Path>,
) -> Result<i32, String> {
    let mut stdout_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(container_log_path)
        .map_err(|e| format!("cannot open {}: {}", container_log_path.display(), e))?;
    let interrupt_guard = InterruptGuard::install();
    let mut command = crate::invocation::command(runtime);
    command
        .args(run_args)
        .current_dir(repo_root)
        .stdout(Io::Piped)
        .stderr(Io::Piped)
        .new_process_group();
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run buildutil backend container: {}", e))?;
    let _request_group = crate::platform::register_request_process_group(child.id());
    // Resident teardown runs after the runtime exits so it can take the
    // lifecycle lease before removing the container.
    let interrupt_cleanup = InterruptCleanup::start(
        child.id(),
        match resident_state_root {
            Some(_) => Box::new(|| {}),
            None => container_interrupt_cleanup(runtime, container),
        },
    );
    let stdout = child.stdout.take().ok_or("cannot capture backend stdout")?;
    let stderr = child.stderr.take().ok_or("cannot capture backend stderr")?;
    let mut saw_header = false;
    let stderr_log = container_log_path.to_path_buf();
    let stderr_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stderr_log)
            .map_err(|e| format!("cannot open {}: {}", stderr_log.display(), e))?;
        let mut reader = BufReader::new(stderr);
        let mut buf = [0u8; 8192];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| format!("cannot read backend stderr: {}", e))?;
            if n == 0 {
                break;
            }
            log.write_all(&buf[..n])
                .map_err(|e| format!("cannot write {}: {}", stderr_log.display(), e))?;
        }
        Ok(())
    });
    let mut read_error: Option<String> = None;
    for line in BufReader::new(stdout).lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                read_error = Some(format!("cannot read backend stdout: {}", e));
                break;
            }
        };
        if let Err(e) = writeln!(stdout_log, "{line}") {
            read_error = Some(format!(
                "cannot write {}: {}",
                container_log_path.display(),
                e
            ));
            break;
        }
        let event = crate::events::parse_stream_event(&line);
        if matches!(event, Some(crate::events::StreamEvent::Header(_))) {
            saw_header = true;
        }
        // Events go on to this process's consumer; anything else the
        // backend printed is one of its results and stays on stdout.
        if event.is_some() {
            crate::events::forward_stream_event(&line);
        } else {
            out!("{}", line);
        }
    }
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for buildutil backend container: {}", e))?;
    interrupt_cleanup.finish()?;
    stderr_thread
        .join()
        .map_err(|_| "backend stderr thread panicked".to_string())??;
    if interrupt_guard.was_interrupted() {
        if let Some(state_root) = resident_state_root {
            teardown_resident_container(runtime, state_root)?;
        }
        return Ok(130);
    }
    if !status.success() && remove_container_on_failure {
        remove_container(runtime, container);
    }
    if let Some(error) = read_error {
        return Err(error);
    }
    if require_header && status.success() && !saw_header {
        return Err(format!(
            "backend did not emit a header report; diagnostics saved to {}",
            container_log_path.display()
        ));
    }
    Ok(status.code().unwrap_or(1))
}

fn remap_realize_outputs(
    flags: &[String],
    repo_root: &Path,
    state_root: &Path,
    stem: &str,
    stamp: &str,
) -> Result<(Vec<String>, Vec<(PathBuf, PathBuf)>), String> {
    let mut rewritten = Vec::new();
    let mut copies = Vec::new();
    let mut i = 0;
    while i < flags.len() {
        if flags[i] == "--events" || flags[i] == "--trace" {
            let flag = flags[i].clone();
            let requested = flags
                .get(i + 1)
                .ok_or_else(|| format!("{} needs a value", flags[i]))?;
            let suffix = if flag == "--events" {
                "events.jsonl"
            } else {
                "trace.json"
            };
            let name = format!("{stem}-{stamp}.{suffix}");
            let host_tmp = crate::state::logs_dir(state_root).join(&name);
            let container_tmp = crate::state::logs_dir(Path::new(CONTAINER_STATE_ROOT)).join(&name);
            let destination = if Path::new(requested).is_absolute() {
                PathBuf::from(requested)
            } else {
                repo_root.join(requested)
            };
            rewritten.push(flag);
            rewritten.push(container_tmp.to_string_lossy().into_owned());
            copies.push((host_tmp, destination));
            i += 2;
        } else {
            rewritten.push(flags[i].clone());
            i += 1;
        }
    }
    Ok((rewritten, copies))
}

fn copy_realize_outputs(copies: &[(PathBuf, PathBuf)]) -> Result<(), String> {
    for (source, destination) in copies {
        if !source.is_file() {
            continue;
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        std::fs::copy(source, destination).map_err(|e| {
            format!(
                "cannot copy realize output {} -> {}: {}",
                source.display(),
                destination.display(),
                e
            )
        })?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_dev_build_in_container(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    backend: &super::ExecBackend,
    image_spec: Option<&crate::spec::ExecutorImageSpec>,
    plan_hash: &str,
    target: &str,
    label: &str,
    dev_dir: &Path,
    jobs: usize,
    verbose: bool,
) -> Result<i32, String> {
    let state_root = if state_root.is_absolute() {
        state_root.to_path_buf()
    } else {
        repo_root.join(state_root)
    };
    if plan_hash.len() != 32 || !plan_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid plan hash `{plan_hash}`"));
    }
    let _host_plan_lease = crate::state::lock_plan(&state_root, plan_hash)?;
    let plan_path = crate::state::plans_dir(&state_root).join(format!("{plan_hash}.plan"));
    let exec_plan = crate::eval::plan::load_attested(&plan_path, plan_hash)?;
    crate::eval::plan::verify_realize_contract(
        &exec_plan,
        build_host.triple(),
        build_host.container_platform(),
        build_host.triple(),
    )?;
    crate::eval::plan::verify_source_cas_complete(&exec_plan, &state_root)?;
    if exec_plan.targets.len() != 1 || exec_plan.targets[0].as_str() != target {
        return Err(format!(
            "dev plan target mismatch: expected only `{target}`, got {:?}",
            exec_plan.targets
        ));
    }
    let dev_backend = backend.dev_output_name()?;
    let expected_dev_dir = crate::state::dev_dir(&state_root, dev_backend, &exec_plan.arch, label);
    if dev_dir != expected_dev_dir.as_path() {
        return Err(format!(
            "dev output path mismatch: expected {}, got {}",
            expected_dev_dir.display(),
            dev_dir.display()
        ));
    }

    let logs_dir = crate::state::logs_dir(&state_root);
    let tmp_dir = state_root.join("tmp");
    std::fs::create_dir_all(&logs_dir)
        .map_err(|e| format!("cannot create {}: {}", logs_dir.display(), e))?;
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("cannot create {}: {}", tmp_dir.display(), e))?;
    match backend {
        super::ExecBackend::Docker | super::ExecBackend::Nerdctl => {
            let runtime = backend.as_str();
            let container = format!("buildutil-dev-{}-{}", &plan_hash[..16], std::process::id());
            let image = super::image::prepare_executor_image(
                runtime,
                &state_root,
                build_host,
                image_spec.ok_or("no [executor-image] table declares the executor image")?,
            )?;
            let prepared = prepare_plan_container_bootstrap(
                repo_root,
                &state_root,
                build_host,
                image.id.clone(),
                &exec_plan,
            )?;
            let bootstrap = &prepared.bootstrap;
            let container_plan_path = crate::state::plans_dir(Path::new(CONTAINER_STATE_ROOT))
                .join(format!("{plan_hash}.plan"));
            let container_dev_dir = crate::state::dev_dir(
                Path::new(CONTAINER_STATE_ROOT),
                dev_backend,
                &exec_plan.arch,
                label,
            );
            let mut inner_args = vec![
                "__dev-build".to_string(),
                container_plan_path.to_string_lossy().into_owned(),
                target.to_string(),
                label.to_string(),
                backend.as_str().to_string(),
                container_dev_dir.to_string_lossy().into_owned(),
                "--store".to_string(),
                CONTAINER_STATE_ROOT.to_string(),
                "--jobs".to_string(),
                jobs.to_string(),
            ];
            if verbose {
                inner_args.push("-v".to_string());
            }
            if daemon_owned_container_enabled() {
                record_resident_container_runtime(runtime);
                let resident = ensure_resident_container(
                    runtime,
                    &state_root,
                    build_host,
                    bootstrap,
                    &image.tag,
                )?;
                let command =
                    resident_container_command(build_host, &resident, bootstrap, &inner_args);
                return run_container_command(
                    runtime,
                    &command.exec_args,
                    repo_root,
                    None,
                    &resident,
                    false,
                    "buildutil resident container dev exec",
                    Some(&state_root),
                );
            }

            let _ = crate::invocation::command(runtime)
                .args(["rm", "-f", container.as_str()])
                .stdout(Io::Null)
                .stderr(Io::Null)
                .status();
            let command = container_command(
                repo_root,
                &state_root,
                build_host,
                &image.tag,
                &container,
                bootstrap,
                &inner_args,
            );
            run_container_command(
                runtime,
                &command.run_args,
                repo_root,
                None,
                &container,
                false,
                "buildutil dev container",
                None,
            )
        }
        super::ExecBackend::Remote => {
            Err("remote backend requires a configured remote builder".to_string())
        }
        super::ExecBackend::LocalLinux => Err("local-linux is not a wrapper backend".into()),
        super::ExecBackend::Wsl => Err("wsl backend must run before evaluation".into()),
    }
}

pub(crate) fn run_plan_in_container(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    backend: &super::ExecBackend,
    image_spec: Option<&crate::spec::ExecutorImageSpec>,
    plan_hash: &str,
    header_report: Option<&crate::events::HeaderReport>,
    exec_flags: &[String],
) -> Result<i32, String> {
    let state_root = if state_root.is_absolute() {
        state_root.to_path_buf()
    } else {
        repo_root.join(state_root)
    };
    if plan_hash.len() != 32 || !plan_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid plan hash `{plan_hash}`"));
    }
    // Host and container flocks over the bind mount are separate lock domains.
    // This host lease deliberately covers the complete container run: it blocks
    // host GC from sweeping the plan closure and serializes two host invocations
    // of this plan. Inside the container, only the store-executor worker takes
    // the container-domain lease, which serializes workers and container GC;
    // its bootstrap coordinator takes no lease while spawning that worker. The
    // domains may overlap safely because each excludes GC in the domain where
    // that GC can run, while no parent holds a container lock needed by its child.
    let _host_plan_lease = crate::state::lock_plan(&state_root, plan_hash)?;
    let plan_path = crate::state::plans_dir(&state_root).join(format!("{plan_hash}.plan"));
    let exec_plan = crate::eval::plan::load_attested(&plan_path, plan_hash)?;
    crate::eval::plan::verify_realize_contract(
        &exec_plan,
        build_host.triple(),
        build_host.container_platform(),
        build_host.triple(),
    )?;
    crate::eval::plan::verify_source_cas_complete(&exec_plan, &state_root)?;
    if let Some(report) = header_report {
        let path = crate::state::plans_dir(&state_root).join(format!("{plan_hash}.header.json"));
        std::fs::write(&path, format!("{}\n", crate::events::header_json(report)))
            .map_err(|e| format!("cannot write header report {}: {}", path.display(), e))?;
    }
    let logs_dir = crate::state::logs_dir(&state_root);
    let tmp_dir = state_root.join("tmp");
    std::fs::create_dir_all(&logs_dir)
        .map_err(|e| format!("cannot create {}: {}", logs_dir.display(), e))?;
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("cannot create {}: {}", tmp_dir.display(), e))?;
    let stamp = super::utc_timestamp();
    let stem = "backend-plan";
    let log_path = logs_dir.join(format!("{stem}-{stamp}.log"));
    let container_log_path = logs_dir.join(format!("{stem}-{stamp}.container.log"));
    let logger = crate::log::Logger::new(std::env::args().any(|a| a == "-v"));
    if header_report.is_none() {
        logger.info(
            "backend",
            &format!("Logging backend command to {}", log_path.display()),
        );
    }

    match backend {
        super::ExecBackend::Docker | super::ExecBackend::Nerdctl => {
            let runtime = backend.as_str();
            let container = "buildutil-backend";
            crate::log::announce("backend", &format!("Checking {runtime} backend image"));
            let image = super::image::prepare_executor_image(
                runtime,
                &state_root,
                build_host,
                image_spec.ok_or("no [executor-image] table declares the executor image")?,
            )?;

            let _ = crate::invocation::command(runtime)
                .args(["rm", "-f", container])
                .stdout(Io::Null)
                .stderr(Io::Null)
                .status();
            crate::log::announce("backend", "Preparing the backend executor");
            let prepared = prepare_plan_container_bootstrap(
                repo_root,
                &state_root,
                build_host,
                image.id.clone(),
                &exec_plan,
            )?;
            let bootstrap = &prepared.bootstrap;
            if header_report.is_none() {
                logger.info(
                    "backend",
                    &format!(
                        "Bootstrap exec dir: {}",
                        crate::state::exec_dir(&state_root)
                            .join(&bootstrap.exec_hash)
                            .display()
                    ),
                );
            }
            let container_state_root = Path::new(CONTAINER_STATE_ROOT);
            let container_plan_path =
                crate::state::plans_dir(container_state_root).join(format!("{plan_hash}.plan"));
            let container_log =
                crate::state::logs_dir(container_state_root).join(format!("{stem}-{stamp}.log"));
            let (container_exec_flags, output_copies) =
                remap_realize_outputs(exec_flags, repo_root, &state_root, stem, &stamp)?;
            let mut inner_args = vec![
                "__realize-plan".to_string(),
                container_plan_path.to_string_lossy().into_owned(),
                "--store".to_string(),
                CONTAINER_STATE_ROOT.to_string(),
            ];
            if header_report.is_some() {
                inner_args.push("--stream-events".to_string());
                inner_args.push("--header-report".to_string());
                inner_args.push(
                    crate::state::plans_dir(container_state_root)
                        .join(format!("{plan_hash}.header.json"))
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            inner_args.extend(container_exec_flags);
            crate::log::announce("backend", &format!("Starting the {runtime} backend"));
            if daemon_owned_container_enabled() {
                record_resident_container_runtime(runtime);
                let container = ensure_resident_container(
                    runtime,
                    &state_root,
                    build_host,
                    bootstrap,
                    &image.tag,
                )?;
                let command =
                    resident_container_command(build_host, &container, bootstrap, &inner_args);
                let mut exec_args = command.exec_args;
                let shell_arg = exec_args
                    .last_mut()
                    .ok_or("internal error: missing resident container command")?;
                if header_report.is_none() {
                    let inner = tee_status_script(
                        &command.inner_command,
                        &container_log.to_string_lossy(),
                        "/tmp/buildutil-backend.status",
                    );
                    *shell_arg = inner;
                    let code = run_container_command(
                        runtime,
                        &exec_args,
                        repo_root,
                        Some(&container_log_path),
                        &container,
                        false,
                        "buildutil resident container exec",
                        Some(&state_root),
                    )?;
                    if code != 0 {
                        logger.info(
                            "backend",
                            &format!(
                                "backend log: {}",
                                crate::term::display_path(&container_log_path)
                            ),
                        );
                    }
                    copy_realize_outputs(&output_copies)?;
                    return Ok(code);
                }
                *shell_arg = command.inner_command;
                let code = run_streaming_container(
                    runtime,
                    &exec_args,
                    repo_root,
                    &container_log_path,
                    &container,
                    true,
                    false,
                    Some(&state_root),
                )?;
                if code != 0 {
                    logger.info(
                        "backend",
                        &format!(
                            "backend log: {}",
                            crate::term::display_path(&container_log_path)
                        ),
                    );
                }
                copy_realize_outputs(&output_copies)?;
                return Ok(code);
            }
            let command = container_command(
                repo_root,
                &state_root,
                build_host,
                &image.tag,
                container,
                bootstrap,
                &inner_args,
            );
            let mut run_args = command.run_args;
            let shell_arg = run_args
                .last_mut()
                .ok_or("internal error: missing container command")?;
            if header_report.is_none() {
                let inner = tee_status_script(
                    &command.inner_command,
                    &container_log.to_string_lossy(),
                    "/tmp/buildutil-backend.status",
                );
                *shell_arg = inner;
                let code = run_container_command(
                    runtime,
                    &run_args,
                    repo_root,
                    Some(&container_log_path),
                    container,
                    true,
                    "buildutil backend container",
                    None,
                )?;
                if code != 0 {
                    logger.info(
                        "backend",
                        &format!(
                            "backend log: {}",
                            crate::term::display_path(&container_log_path)
                        ),
                    );
                }
                copy_realize_outputs(&output_copies)?;
                return Ok(code);
            }
            *shell_arg = command.inner_command;
            let code = run_streaming_container(
                runtime,
                &run_args,
                repo_root,
                &container_log_path,
                container,
                true,
                true,
                None,
            )?;
            if code != 0 {
                logger.info(
                    "backend",
                    &format!(
                        "backend log: {}",
                        crate::term::display_path(&container_log_path)
                    ),
                );
            }
            copy_realize_outputs(&output_copies)?;
            Ok(code)
        }
        super::ExecBackend::Remote => {
            Err("remote backend requires a configured remote builder".to_string())
        }
        super::ExecBackend::LocalLinux => Err("local-linux is not a wrapper backend".into()),
        super::ExecBackend::Wsl => Err("wsl backend must run before evaluation".into()),
    }
}

/// Acquire an input archive with the same projected executor and declared state mount.
pub(crate) fn run_input_acquisition(
    repo_root: &Path,
    state_root: &Path,
    build_host: &super::BuildHost,
    backend: &super::ExecBackend,
    image_spec: Option<&crate::spec::ExecutorImageSpec>,
    request_name: &str,
) -> Result<i32, String> {
    crate::inputs::codec::clean_path(request_name)?;
    let state_root = crate::state::absolute_root(repo_root, state_root);
    let runtime = backend.as_str();
    let image = super::image::prepare_executor_image(
        runtime,
        &state_root,
        build_host,
        image_spec.ok_or("no [executor-image] declares the input acquisition executor")?,
    )?;
    let prepared = prepare_attested_current_container_bootstrap(
        repo_root,
        &state_root,
        build_host,
        image.id.clone(),
    )?;
    let container = format!("buildutil-input-fetch-{}", std::process::id());
    let command = container_command(
        repo_root,
        &state_root,
        build_host,
        &image.tag,
        &container,
        &prepared.bootstrap,
        &[
            "__acquire-input".to_string(),
            CONTAINER_STATE_ROOT.to_string(),
            format!("{CONTAINER_STATE_ROOT}/plans/{request_name}"),
        ],
    );
    let cleanup = container_interrupt_cleanup(runtime, &container);
    let guard = InterruptGuard::install();
    let mut child = crate::invocation::command(runtime)
        .args(&command.run_args)
        .spawn()
        .map_err(|e| format!("cannot launch input acquisition executor: {e}"))?;
    let cleanup = InterruptCleanup::start(child.id(), cleanup);
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for input acquisition executor: {e}"))?;
    cleanup.finish()?;
    if guard.was_interrupted() {
        return Err("repository input acquisition interrupted".into());
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    const INPUT_CONTENT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const EXEC_HASH: &str = "abcdef0123456789abcdef0123456789";
    const EXEC_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const IMAGE_ID: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn bootstrap() -> super::ContainerBootstrap {
        let build_host = super::super::BuildHost::parse("x86_64-unknown-linux-musl").unwrap();
        super::ContainerBootstrap::from_verified(
            Path::new("/host/.buildutil/exec/abcdef0123456789abcdef0123456789"),
            INPUT_CONTENT.to_string(),
            IMAGE_ID.to_string(),
            &build_host,
            EXEC_DIGEST,
        )
        .unwrap()
    }

    fn assert_env(args: &[String], value: &str) {
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--env" && pair[1] == value),
            "missing container environment `{value}` in {args:?}"
        );
    }

    fn resident_inspection(
        running: bool,
        identity: &super::ResidentContainerIdentity,
    ) -> super::ResidentContainerInspection {
        super::ResidentContainerInspection {
            running,
            protocol: super::RESIDENT_PROTOCOL.to_string(),
            image_id: identity.image_id.clone(),
            executor_drv: identity.executor_drv.clone(),
            executor_store: identity.executor_store.clone(),
        }
    }

    #[test]
    fn resident_container_name_and_labels_are_state_and_identity_bound() {
        let first = Path::new("/host/.buildutil");
        let second = Path::new("/other/.buildutil");
        assert_eq!(
            super::resident_container_name(first),
            super::resident_container_name(first)
        );
        assert_ne!(
            super::resident_container_name(first),
            super::resident_container_name(second)
        );

        let identity = bootstrap().resident_identity();
        let labels = super::resident_container_label_args(&identity);
        assert!(labels.windows(2).any(|pair| {
            pair[0] == "--label"
                && pair[1] == format!("{}={}", super::RESIDENT_LABEL_IMAGE_ID, IMAGE_ID)
        }));
        assert!(labels.windows(2).any(|pair| {
            pair[0] == "--label"
                && pair[1]
                    == format!(
                        "{}={}",
                        super::RESIDENT_LABEL_EXECUTOR_DRV,
                        identity.executor_drv.as_str()
                    )
        }));
        assert!(labels.windows(2).any(|pair| {
            pair[0] == "--label"
                && pair[1]
                    == format!(
                        "{}={}",
                        super::RESIDENT_LABEL_EXECUTOR_STORE,
                        identity.executor_store.as_str()
                    )
        }));
        assert!(labels.windows(2).any(|pair| {
            pair[0] == "--label"
                && pair[1]
                    == format!(
                        "{}={}",
                        super::RESIDENT_LABEL_PROTOCOL,
                        super::RESIDENT_PROTOCOL
                    )
        }));
    }

    #[test]
    fn resident_container_preflight_selects_the_required_lifecycle_action() {
        let identity = bootstrap().resident_identity();
        assert_eq!(
            super::resident_container_action(
                Some(&resident_inspection(true, &identity)),
                &identity
            ),
            super::ResidentContainerAction::Exec
        );
        assert_eq!(
            super::resident_container_action(
                Some(&resident_inspection(false, &identity)),
                &identity
            ),
            super::ResidentContainerAction::Start
        );
        assert_eq!(
            super::resident_container_action(None, &identity),
            super::ResidentContainerAction::Create
        );
        let mut mismatch = resident_inspection(true, &identity);
        mismatch.executor_store.push_str("-different");
        assert_eq!(
            super::resident_container_action(Some(&mismatch), &identity),
            super::ResidentContainerAction::Recreate
        );
    }

    #[test]
    fn resident_exec_reasserts_the_verified_bootstrap_identity() {
        let build_host = super::super::BuildHost::parse("x86_64-unknown-linux-musl").unwrap();
        let command = super::resident_container_command(
            &build_host,
            "buildutil-resident-test",
            &bootstrap(),
            &[
                "__realize-plan".to_string(),
                "/buildutil-state/plans/a.plan".to_string(),
            ],
        );
        assert_eq!(command.exec_args[0], "exec");
        assert_eq!(command.exec_args[1], "-i");
        assert_env(
            &command.exec_args,
            &format!("BUILDUTIL_CONTAINER_INPUT_CONTENT={INPUT_CONTENT}"),
        );
        assert_env(
            &command.exec_args,
            &format!("BUILDUTIL_CONTAINER_BOOTSTRAP_HASH={EXEC_HASH}"),
        );
        assert_env(
            &command.exec_args,
            &format!("BUILDUTIL_EXECUTOR_IMAGE_ID={IMAGE_ID}"),
        );
        let drv = crate::eval::plan::container_executor_derivation(
            EXEC_DIGEST,
            "x86_64-unknown-linux-musl",
            "linux/amd64",
            IMAGE_ID,
        );
        assert_env(
            &command.exec_args,
            &format!("BUILDUTIL_EXECUTOR_DRV={}", drv.hash()),
        );
        assert_env(
            &command.exec_args,
            &format!("BUILDUTIL_EXECUTOR_STORE={}", drv.store_name()),
        );
    }

    #[test]
    fn realize_container_is_repo_free_and_pins_store_executor() {
        let repo = Path::new("/host/repository");
        let state = Path::new("/host/.buildutil");
        let build_host = super::super::BuildHost::parse("x86_64-unknown-linux-musl").unwrap();
        let inner_args = vec![
            "__realize-plan".to_string(),
            "/buildutil-state/plans/0123456789abcdef0123456789abcdef.plan".to_string(),
            "--store".to_string(),
            "/buildutil-state".to_string(),
            "--jobs".to_string(),
            "2".to_string(),
            "-v".to_string(),
        ];

        let command = super::container_command(
            repo,
            state,
            &build_host,
            "buildutil-executor:0123456789abcdef0123456789abcdef",
            "buildutil-backend",
            &bootstrap(),
            &inner_args,
        );

        assert_eq!(
            command.workdir,
            "/buildutil-state/exec/abcdef0123456789abcdef0123456789"
        );
        assert_eq!(
            command.inner_command,
            "'./buildutil' '__realize-plan' '/buildutil-state/plans/0123456789abcdef0123456789abcdef.plan' '--store' '/buildutil-state' '--jobs' '2' '-v'"
        );
        assert_eq!(
            command
                .run_args
                .iter()
                .filter(|arg| *arg == "/host/.buildutil:/buildutil-state:rw")
                .count(),
            1
        );
        assert!(
            !command
                .run_args
                .iter()
                .any(|arg| arg.contains("/buildutil-src"))
        );
        assert!(
            !command
                .run_args
                .iter()
                .any(|arg| arg.contains("/host/repository"))
        );
        // The image is run by its tag; its content identity rides in the
        // executor environment.
        assert!(
            command
                .run_args
                .iter()
                .any(|arg| arg == "buildutil-executor:0123456789abcdef0123456789abcdef")
        );
        // Unprivileged: only the settings the inner sandbox needs.
        assert!(!command.run_args.iter().any(|arg| arg == "--privileged"));
        assert!(
            !command
                .run_args
                .iter()
                .any(|arg| arg.starts_with("--cap-add"))
        );
        for option in [
            "seccomp=unconfined",
            "apparmor=unconfined",
            "systempaths=unconfined",
        ] {
            assert!(
                command
                    .run_args
                    .windows(2)
                    .any(|pair| pair[0] == "--security-opt" && pair[1] == option),
                "missing {option}"
            );
        }
        assert_eq!(
            command
                .run_args
                .iter()
                .filter(|arg| *arg == "/host/repository:/buildutil-src:ro")
                .count(),
            0
        );
        assert_env(
            &command.run_args,
            &format!("BUILDUTIL_CONTAINER_INPUT_CONTENT={INPUT_CONTENT}"),
        );
        assert_env(
            &command.run_args,
            &format!("BUILDUTIL_CONTAINER_BOOTSTRAP_HASH={EXEC_HASH}"),
        );
        assert_env(
            &command.run_args,
            "BUILDUTIL_SELFHOST_REPO_ROOT=/buildutil-state/exec/abcdef0123456789abcdef0123456789",
        );
        assert_env(
            &command.run_args,
            "BUILDUTIL_SELFHOST_STATE_ROOT=/buildutil-state",
        );
        assert_env(
            &command.run_args,
            "BUILDUTIL_REALIZE_BUILD_HOST=x86_64-unknown-linux-musl",
        );
        assert_env(&command.run_args, "BUILDUTIL_REALIZE_PLATFORM=linux/amd64");
        assert_env(
            &command.run_args,
            &format!("BUILDUTIL_EXECUTOR_IMAGE_ID={IMAGE_ID}"),
        );
        let drv = crate::eval::plan::container_executor_derivation(
            EXEC_DIGEST,
            "x86_64-unknown-linux-musl",
            "linux/amd64",
            IMAGE_ID,
        );
        assert_env(
            &command.run_args,
            &format!("BUILDUTIL_EXECUTOR_DRV={}", drv.hash()),
        );
        assert_env(
            &command.run_args,
            &format!("BUILDUTIL_EXECUTOR_STORE={}", drv.store_name()),
        );
    }

    #[test]
    fn plan_parity_container_evaluates_a_git_less_view_without_git() {
        let repo = Path::new("/host/repository");
        let state = Path::new("/host/.buildutil");
        let build_host = super::super::BuildHost::parse("x86_64-unknown-linux-musl").unwrap();
        let inner_args = vec![
            "plan".to_string(),
            "default".to_string(),
            "--store".to_string(),
            "/buildutil-state".to_string(),
            "--backend".to_string(),
            "local-linux".to_string(),
        ];
        let entries = vec![
            "buildutil".to_string(),
            "buildutil.toml".to_string(),
            "tools".to_string(),
        ];

        let command = super::plan_parity_container_command(
            repo,
            state,
            &build_host,
            "buildutil-executor:0123456789abcdef0123456789abcdef",
            "buildutil-plan-parity",
            &bootstrap(),
            &entries,
            "abcdef123456 false",
            &inner_args,
        );

        // The view is named by the attested projection, so the input content digest and
        // the repository identity come from the attestation.
        assert_eq!(command.workdir, format!("/parity/{EXEC_HASH}"));
        assert_eq!(
            command.inner_command,
            "'/buildutil-state/exec/abcdef0123456789abcdef0123456789/buildutil' 'plan' 'default' '--store' '/buildutil-state' '--backend' 'local-linux'"
        );
        for entry in &entries {
            let bind = format!("/host/repository/{entry}:/parity/{EXEC_HASH}/{entry}:ro");
            assert!(command.run_args.iter().any(|arg| *arg == bind), "{bind}");
        }
        assert!(!command.run_args.iter().any(|arg| arg.contains(".git")));
        assert!(!command.run_args.iter().any(|arg| arg.starts_with("GIT_")));
        assert_env(
            &command.run_args,
            &format!("BUILDUTIL_SELFHOST_REPO_ROOT=/buildutil-state/exec/{EXEC_HASH}"),
        );
        assert_env(
            &command.run_args,
            &format!("BUILDUTIL_CONTAINER_BOOTSTRAP_HASH={EXEC_HASH}"),
        );
        assert_env(
            &command.run_args,
            "BUILDUTIL_CONTAINER_GIT_IDENTITY=abcdef123456 false",
        );
    }

    #[test]
    fn plan_parity_binds_every_repository_entry_but_git() {
        let repo =
            std::env::temp_dir().join(format!("buildutil-parity-entries-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&repo);
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("tools")).unwrap();
        std::fs::write(repo.join(".gitmodules"), b"").unwrap();
        std::fs::write(repo.join("buildutil.toml"), b"").unwrap();
        assert_eq!(
            super::parity_source_entries(&repo).unwrap(),
            [".gitmodules", "buildutil.toml", "tools"]
        );
        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn container_bootstrap_rejects_unbound_content_id_values() {
        let build_host = super::super::BuildHost::parse("x86_64-unknown-linux-musl").unwrap();
        assert!(
            super::ContainerBootstrap::from_verified(
                Path::new("/host/.buildutil/exec/not-a-hash"),
                INPUT_CONTENT.to_string(),
                IMAGE_ID.to_string(),
                &build_host,
                EXEC_DIGEST,
            )
            .is_err()
        );
        assert!(
            super::ContainerBootstrap::from_verified(
                Path::new("/host/.buildutil/exec/abcdef0123456789abcdef0123456789"),
                "not-a-pin".to_string(),
                IMAGE_ID.to_string(),
                &build_host,
                EXEC_DIGEST,
            )
            .is_err()
        );
        assert!(
            super::ContainerBootstrap::from_verified(
                Path::new("/host/.buildutil/exec/abcdef0123456789abcdef0123456789"),
                INPUT_CONTENT.to_string(),
                "mutable-tag".to_string(),
                &build_host,
                EXEC_DIGEST,
            )
            .is_err()
        );
    }

    #[test]
    fn resident_container_is_created_unprivileged_from_the_image_tag() {
        let identity = bootstrap().resident_identity();
        let build_host = super::super::BuildHost::parse("x86_64-unknown-linux-musl").unwrap();
        let args = super::resident_container_create_args(
            Path::new("/host/.buildutil"),
            &build_host,
            "buildutil-resident-test",
            &identity,
            "buildutil-executor:0123456789abcdef0123456789abcdef",
        );
        assert!(!args.iter().any(|arg| arg == "--privileged"));
        let tag = args
            .iter()
            .position(|arg| arg == "buildutil-executor:0123456789abcdef0123456789abcdef")
            .expect("the image tag");
        assert_eq!(&args[tag + 1..], ["sleep", "infinity"]);
    }

    #[test]
    fn realize_outputs_are_remapped_through_shared_state() {
        let flags = vec![
            "--events".to_string(),
            "artifacts/events.jsonl".to_string(),
            "--trace".to_string(),
            "/host/trace.json".to_string(),
            "--jobs".to_string(),
            "4".to_string(),
        ];
        let (rewritten, copies) = super::remap_realize_outputs(
            &flags,
            Path::new("/host/repo"),
            Path::new("/host/state"),
            "backend-plan",
            "stamp",
        )
        .unwrap();
        assert!(
            rewritten.contains(&"/buildutil-state/logs/backend-plan-stamp.events.jsonl".into())
        );
        assert!(rewritten.contains(&"/buildutil-state/logs/backend-plan-stamp.trace.json".into()));
        assert_eq!(copies[0].1, Path::new("/host/repo/artifacts/events.jsonl"));
        assert_eq!(copies[1].1, Path::new("/host/trace.json"));
    }

    #[test]
    fn runtime_output_is_appended_to_the_log_as_written() {
        let dir =
            std::env::temp_dir().join(format!("buildutil-container-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backend.container.log");
        std::fs::write(&path, b"earlier\n").unwrap();
        let log = std::sync::Mutex::new(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap(),
        );
        fn quiet(_: &str) {}
        super::copy_runtime_lines(&b"one\r\ntwo\nthree"[..], Some(&log), quiet).unwrap();
        drop(log);
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier\none\r\ntwo\nthree");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
