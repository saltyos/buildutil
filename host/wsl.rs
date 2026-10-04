//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — host: WSL execution backend
//!
//! The Windows / WSL backend: a host-side `wsl --cd <repo> sh -lc ...`
//! wrapper around the inner buildutil invocation, with interrupt trapping that
//! kills the recorded child PID and SIGINT/SIGTERM/HUP cleanup. On Linux
//! and macOS this is never invoked; the dispatcher in main/cli routes around
//! it with `unreachable!()`.

use std::path::Path;

use super::interrupt::{InterruptCleanup, InterruptGuard};

fn wsl_backend_argv(argv: &[String]) -> Result<Vec<String>, String> {
    let mut requested_build_host = super::DEFAULT_BUILD_HOST.to_string();
    let mut scan = 0;
    while scan < argv.len() {
        if argv[scan] == "--build-host" {
            scan += 1;
            requested_build_host = argv
                .get(scan)
                .ok_or("--build-host needs a value")?
                .to_string();
        }
        scan += 1;
    }
    let build_host = super::BuildHost::resolve(&requested_build_host)?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--backend" | "--build-host" => {
                i += 2;
            }
            _ => {
                out.push(argv[i].clone());
                i += 1;
            }
        }
    }
    out.push("--build-host".to_string());
    out.push(build_host.triple().to_string());
    out.push("--backend".to_string());
    out.push(super::ExecBackend::LocalLinux.as_str().to_string());
    Ok(out)
}

pub(crate) fn run_wsl_script_with_interrupt(
    repo_root: &Path,
    script: String,
    pid_path: String,
    context: &str,
) -> Result<i32, String> {
    let wsl_root = repo_root.to_string_lossy().into_owned();
    let interrupt_script = wsl_interrupt_cleanup_script(&pid_path);
    let cleanup_root = wsl_root.clone();
    let interrupt_guard = InterruptGuard::install();
    let mut command = crate::invocation::command("wsl");
    command.args(["--cd", &wsl_root, "sh", "-lc", &script]);
    command.new_process_group();
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run {context}: {}", e))?;
    let _request_group = crate::platform::register_request_process_group(child.id());
    let interrupt_cleanup = InterruptCleanup::start(
        child.id(),
        Box::new(move || {
            let _ = crate::invocation::command("wsl")
                .args(["--cd", &cleanup_root, "sh", "-lc", &interrupt_script])
                .stdout(crate::invocation::Io::Null)
                .stderr(crate::invocation::Io::Null)
                .status();
        }),
    );
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for {context}: {}", e))?;
    interrupt_cleanup.finish()?;
    if interrupt_guard.was_interrupted() {
        return Ok(130);
    }
    Ok(status.code().unwrap_or(1))
}

pub(crate) fn run_wsl_backend(repo_root: &Path, argv: &[String]) -> Result<i32, String> {
    let inner_argv = wsl_backend_argv(argv)?;
    let cwd = std::env::current_dir()
        .map_err(|e| format!("cannot resolve override checkout directory: {e}"))?;
    let inner_argv = translate_input_paths(&inner_argv, &cwd, |path| {
        let output = crate::invocation::command("wsl")
            .arg("--cd")
            .arg(repo_root)
            .args(["--exec", "wslpath", "-a", "-u", path])
            .output()
            .map_err(|e| format!("cannot translate input checkout to WSL: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "cannot translate input checkout to WSL: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let path = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
        let path = path.trim_end_matches(['\r', '\n']);
        if !path.starts_with('/') {
            return Err("WSL input checkout translation did not return an absolute path".into());
        }
        Ok(path.to_string())
    })?;
    let stamp = super::utc_timestamp();
    let status_path = format!(".buildutil/tmp/wsl-backend-{stamp}.status");
    let pid_path = format!(".buildutil/tmp/wsl-backend-{stamp}.pid");
    let command = super::container::command_line("./buildutil", &inner_argv);
    let script = wsl_status_script(&command, &status_path, &pid_path);
    run_wsl_script_with_interrupt(repo_root, script, pid_path, "buildutil through WSL")
}

fn translate_input_paths(
    argv: &[String],
    cwd: &Path,
    mut translate: impl FnMut(&str) -> Result<String, String>,
) -> Result<Vec<String>, String> {
    let mut out = argv.to_vec();
    let mut i = 0;
    while i < out.len() {
        if out[i] == "--override-input" {
            let value = out
                .get(i + 2)
                .and_then(|value| value.strip_prefix("path:"))
                .ok_or("--override-input needs a name and path:checkout")?;
            if !value.starts_with('/') {
                let absolute = if value.starts_with("\\\\")
                    || (value.as_bytes().get(1) == Some(&b':')
                        && value
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphabetic))
                {
                    std::path::PathBuf::from(value)
                } else {
                    cwd.join(value)
                };
                let path = translate(&absolute.to_string_lossy())?;
                out[i + 2] = format!("path:{path}");
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(out)
}

pub(crate) fn wsl_status_script(command: &str, status_path: &str, pid_path: &str) -> String {
    let status = super::shell_quote(status_path);
    let pid = super::shell_quote(pid_path);
    format!(
        "status_file={status}; pid_file={pid}; \
         status_dir=${{status_file%/*}}; pid_dir=${{pid_file%/*}}; \
         if [ \"$status_dir\" != \"$status_file\" ]; then mkdir -p \"$status_dir\"; fi; \
         if [ \"$pid_dir\" != \"$pid_file\" ]; then mkdir -p \"$pid_dir\"; fi; \
         rm -f \"$status_file\" \"$pid_file\"; \
         cleanup_child() {{ if [ -n \"${{child:-}}\" ]; then kill -TERM \"$child\" >/dev/null 2>&1 || true; wait \"$child\" >/dev/null 2>&1 || true; fi; rm -f \"$pid_file\"; }}; \
         interrupt_child() {{ code=\"$1\"; trap - INT TERM HUP; cleanup_child; \
         printf '%s\\n' \"$code\" > \"$status_file\"; exit \"$code\"; }}; \
         trap 'interrupt_child 130' INT; \
         trap 'interrupt_child 143' TERM HUP; \
         ( {command} ) & child=$!; printf '%s\\n' \"$child\" > \"$pid_file\"; \
         wait \"$child\"; code=$?; \
         printf '%s\\n' \"$code\" > \"$status_file\"; \
         rm -f \"$status_file\" \"$pid_file\"; exit \"$code\""
    )
}

fn wsl_interrupt_cleanup_script(pid_path: &str) -> String {
    let pid = super::shell_quote(pid_path);
    format!(
        "pid_file={pid}; \
         pid=$(cat \"$pid_file\" 2>/dev/null || true); \
         if [ -n \"$pid\" ]; then kill -TERM \"$pid\" >/dev/null 2>&1 || true; fi; \
         rm -f \"$pid_file\""
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn checkout_overrides_are_translated_before_linux_evaluation() {
        let argv = [
            "build",
            "--override-input",
            "compiler",
            "path:C:\\work\\compiler",
            "--override-input",
            "library",
            "path:/work/library",
        ]
        .map(str::to_string);
        let translated =
            super::translate_input_paths(&argv, std::path::Path::new("/repo"), |path| {
                assert_eq!(path, "C:\\work\\compiler");
                Ok("/mnt/c/work/compiler".into())
            })
            .unwrap();
        assert_eq!(translated[3], "path:/mnt/c/work/compiler");
        assert_eq!(translated[6], "path:/work/library");
    }
    #[test]
    fn wsl_backend_argv_selects_local_linux_backend() {
        let argv = vec![
            "build".to_string(),
            "host-llvm".to_string(),
            "--backend".to_string(),
            "docker".to_string(),
            "--build-host".to_string(),
            "x86_64-unknown-linux-musl".to_string(),
            "--store".to_string(),
            ".buildutil".to_string(),
            "-v".to_string(),
        ];

        let rewritten = super::wsl_backend_argv(&argv).unwrap();

        assert_eq!(
            rewritten,
            vec![
                "build",
                "host-llvm",
                "--store",
                ".buildutil",
                "-v",
                "--build-host",
                "x86_64-unknown-linux-musl",
                "--backend",
                "local-linux",
            ]
        );
    }

    #[test]
    fn wsl_status_script_traps_interrupts_and_kills_child() {
        let script = super::wsl_status_script(
            "./buildutil build all --backend local-linux",
            ".buildutil/tmp/wsl-backend.status",
            ".buildutil/tmp/wsl-backend.pid",
        );

        assert!(script.contains("trap 'interrupt_child 130' INT"));
        assert!(script.contains("trap 'interrupt_child 143' TERM HUP"));
        assert!(script.contains("kill -TERM \"$child\""));
        assert!(script.contains("printf '%s\\n' \"$child\" > \"$pid_file\""));
        assert!(script.contains("mkdir -p \"$status_dir\""));
        assert!(script.contains("mkdir -p \"$pid_dir\""));
    }

    #[test]
    fn wsl_interrupt_cleanup_script_kills_recorded_child() {
        let script = super::wsl_interrupt_cleanup_script(".buildutil/tmp/wsl-backend.pid");

        assert!(script.contains("pid=$(cat \"$pid_file\" 2>/dev/null || true)"));
        assert!(script.contains("kill -TERM \"$pid\""));
        assert!(script.contains("rm -f \"$pid_file\""));
    }
}
