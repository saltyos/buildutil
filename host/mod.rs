//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — build-host / execution-backend selection and shared CLI helpers
//!
//! `BuildHost` / `ExecBackend` classify how a derivation runs; the
//! `interrupt` / `container` / `wsl` submodules carry the imperative
//! machinery for those backends. Shared CLI helpers (`shell_quote`,
//! `utc_timestamp` / `civil_from_days`) live here because every backend
//! consumes them.
//!
//! The build hosts are the musl Linux triples: the host chain is clang,
//! musl, libc++, libunwind and compiler-rt, built from the pinned seed.

pub mod container;
pub(crate) mod image;
pub mod interrupt;
pub mod wsl;

use std::fmt;

pub const DEFAULT_BUILD_HOST: &str = "auto";
pub const DEFAULT_BACKEND: &str = "auto";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BuildHost {
    triple: String,
}

impl BuildHost {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "x86_64-unknown-linux-musl" | "aarch64-unknown-linux-musl" => Ok(Self {
                triple: value.to_string(),
            }),
            other => Err(format!(
                "unsupported build host `{}` (supported: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl)",
                other
            )),
        }
    }

    pub fn resolve(value: &str) -> Result<Self, String> {
        if value != DEFAULT_BUILD_HOST {
            return Self::parse(value);
        }
        let arch = std::env::consts::ARCH;
        if arch == "x86_64" {
            Self::parse("x86_64-unknown-linux-musl")
        } else if arch == "aarch64" {
            Self::parse("aarch64-unknown-linux-musl")
        } else {
            Err(format!(
                "cannot infer Linux build host for host architecture `{}`; pass --build-host",
                arch
            ))
        }
    }

    pub fn triple(&self) -> &str {
        &self.triple
    }

    pub fn arch(&self) -> &str {
        self.triple
            .split_once('-')
            .map(|(arch, _)| arch)
            .unwrap_or(&self.triple)
    }

    pub fn container_platform(&self) -> &'static str {
        match self.arch() {
            "x86_64" => "linux/amd64",
            "aarch64" => "linux/arm64",
            _ => "linux/amd64",
        }
    }
}

impl fmt::Display for BuildHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.triple)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecBackend {
    LocalLinux,
    Docker,
    Nerdctl,
    Wsl,
    Remote,
}

impl ExecBackend {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "local-linux" => Ok(Self::LocalLinux),
            "docker" => Ok(Self::Docker),
            "nerdctl" => Ok(Self::Nerdctl),
            "wsl" => Ok(Self::Wsl),
            "remote" => Ok(Self::Remote),
            other => Err(format!(
                "unsupported backend `{}` (supported: auto, local-linux, docker, nerdctl, wsl, remote)",
                other
            )),
        }
    }

    pub fn resolve(value: &str) -> Result<Self, String> {
        if value != DEFAULT_BACKEND {
            return Self::parse(value);
        }
        if cfg!(target_os = "linux") {
            return Ok(Self::LocalLinux);
        }
        if cfg!(target_os = "macos") {
            if crate::invocation::command_exists("docker") {
                return Ok(Self::Docker);
            }
            if crate::invocation::command_exists("nerdctl") {
                return Ok(Self::Nerdctl);
            }
            return Err(
                "macOS needs a Linux container backend for store-native toolchain builds; install Docker/Colima or nerdctl, or pass --backend remote".to_string(),
            );
        }
        if cfg!(target_os = "windows") {
            if crate::invocation::command_exists("wsl") {
                return Ok(Self::Wsl);
            }
            if crate::invocation::command_exists("docker") {
                return Ok(Self::Docker);
            }
            return Err(
                "Windows needs WSL or Docker for store-native Linux toolchain builds; install one or pass --backend remote".to_string(),
            );
        }
        Err("cannot infer execution backend; pass --backend".to_string())
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalLinux => "local-linux",
            Self::Docker => "docker",
            Self::Nerdctl => "nerdctl",
            Self::Wsl => "wsl",
            Self::Remote => "remote",
        }
    }

    pub fn needs_container(&self) -> bool {
        matches!(self, Self::Docker | Self::Nerdctl)
    }

    /// Name of the `state::dev_dir` subtree this backend's dev builds write.
    /// WSL re-runs buildutil inside the distribution with the local-linux
    /// backend, so its dev outputs live under that name.
    pub fn dev_output_name(&self) -> Result<&'static str, String> {
        match self {
            Self::LocalLinux | Self::Wsl => Ok(Self::LocalLinux.as_str()),
            Self::Docker | Self::Nerdctl => Ok(self.as_str()),
            Self::Remote => Err("the remote backend produces no dev outputs".to_string()),
        }
    }
}

pub fn exec_host_triple() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    };
    let os = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        "windows" => "pc-windows-msvc",
        other => other,
    };
    format!("{arch}-{os}")
}

/// The build host this machine realizes store derivations for: the musl
/// triple of its architecture on Linux. A store build uses only the
/// store's toolchain and its own `/lib`, so the C library the running
/// buildutil links does not enter it; off Linux, where store builds are
/// refused, the execution host triple names the mismatch.
pub fn executor_build_host() -> String {
    if cfg!(target_os = "linux") {
        format!("{}-unknown-linux-musl", std::env::consts::ARCH)
    } else {
        exec_host_triple()
    }
}

/// Single-quote a shell argument and escape any embedded single quote.
/// POSIX-safe shell-quoting for embedded shell scripts.
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// UTC `YYYYMMDDTHHMMSSZ` stamp for log file and status file names.
pub(crate) fn utc_timestamp() -> String {
    let (year, month, day, hour, min, sec) = utc_now_fields();
    format!("{year:04}{month:02}{day:02}T{hour:02}{min:02}{sec:02}Z")
}

/// UTC (`YYYY-MM-DD`, `HHMMSSZ`) pair for dated run-log directories and the
/// time-stamped file names inside them.
pub(crate) fn utc_date_and_time() -> (String, String) {
    let (year, month, day, hour, min, sec) = utc_now_fields();
    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!("{hour:02}{min:02}{sec:02}Z"),
    )
}

/// Current UTC time as (year, month, day, hour, minute, second).
fn utc_now_fields() -> (i64, i64, i64, i64, i64, i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = now.div_euclid(86_400);
    let secs = now.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    (year, month, day, secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Convert days-since-Unix-epoch to (year, month, day) using the proleptic
/// Gregorian calendar.
fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}
