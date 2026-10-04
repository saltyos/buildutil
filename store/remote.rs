//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — remote execution
//!
//! Nix-shaped push-build-pull over SSH; no daemon, no service dependency.
//! For a ready derivation assigned to a builder, buildutil pushes the finalized
//! drv text plus any input providers the remote store lacks, the remote
//! realizes under its own enforcing sandbox, and returns a signed
//! realization record + output archive + log. **Trust is the realization
//! signature against the local trusted-key set — never the SSH transport,**
//! so only enforcing-grade builders are eligible.
//!
//! The transport is a trait so the arch-tag scheduler (job caps, timeout,
//! bounded retry, local fallback) is unit-tested with a fake; the SSH impl
//! is the unverified surface (it needs real builders). Scheduler integration
//! into the realize worker pool is the RFC gate deferred to a Linux/SSH CI;
//! this module is the tested, self-contained mechanism the
//! integration will call.

use std::collections::BTreeMap;
use std::time::Duration;

/// A remote builder from `.buildutil/builders`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    pub url: String,
    pub arch: String,
    pub jobs: usize,
    pub grade: String,
}

/// Parse `.buildutil/builders`: one builder per line —
/// `ssh://user@host arch=aarch64 jobs=8 grade=namespace`. Blank lines and
/// `#` comments are skipped. Audit-grade builders are dropped: an
/// audit-sandbox remote cannot produce a substitutable (signable) output.
pub fn parse_builders(text: &str) -> Vec<Builder> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(url) = it.next() else {
            continue;
        };
        let mut b = Builder {
            url: url.to_string(),
            arch: String::new(),
            jobs: 1,
            grade: "namespace".to_string(),
        };
        for kv in it {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "arch" => b.arch = v.to_string(),
                    "jobs" => b.jobs = v.parse().unwrap_or(1),
                    "grade" => b.grade = v.to_string(),
                    _ => {}
                }
            }
        }
        if b.grade == "namespace" || b.grade == "caps" {
            out.push(b);
        }
    }
    out
}

/// A remote realization result: the signed record, the output archive
/// (canonical buildutil-archive), and the streamed build log.
pub struct RemoteResult {
    pub record: String,
    pub archive: Vec<u8>,
    pub log: String,
}

/// The push-build-pull seam. `has` is the content-dedup check against the
/// remote store; `realize` pushes + builds + pulls. A future protocol
/// adapter implements this without touching the scheduler.
pub trait Transport {
    fn has(&self, digest: &str) -> Result<bool, String>;
    fn realize(
        &self,
        drv_text: &str,
        inputs: &[(String, Vec<u8>)],
        timeout: Duration,
    ) -> Result<RemoteResult, String>;
}

/// Pick an eligible builder for `arch` with free job capacity (arch-tag
/// dispatch + per-builder job caps). `in_flight` maps a builder URL to its
/// current job count.
pub fn choose_builder<'a>(
    builders: &'a [Builder],
    arch: &str,
    in_flight: &BTreeMap<String, usize>,
) -> Option<&'a Builder> {
    builders
        .iter()
        .filter(|b| b.arch == arch)
        .find(|b| in_flight.get(&b.url).copied().unwrap_or(0) < b.jobs)
}

/// Dispatch one derivation with bounded retry. Returns the first success;
/// after `retries` retries all fail, returns the last error so the caller
/// can fall back to a local build.
pub fn dispatch_with_retry(
    transport: &dyn Transport,
    drv_text: &str,
    inputs: &[(String, Vec<u8>)],
    timeout: Duration,
    retries: usize,
) -> Result<RemoteResult, String> {
    let mut last = "remote dispatch not attempted".to_string();
    for _ in 0..=retries {
        match transport.realize(drv_text, inputs, timeout) {
            Ok(r) => return Ok(r),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// SSH transport (unverified — needs a real builder). `has`/`realize` shell
/// out to `ssh`/`scp`; the remote runs its own `buildutil` under an enforcing
/// sandbox and hands back the signed record, which the local side verifies
/// against trusted keys before trusting anything.
pub struct SshTransport {
    /// The `user@host` portion of an `ssh://…` URL.
    pub host: String,
}

impl SshTransport {
    pub fn new(url: &str) -> SshTransport {
        SshTransport {
            host: url.trim_start_matches("ssh://").to_string(),
        }
    }
}

impl Transport for SshTransport {
    fn has(&self, digest: &str) -> Result<bool, String> {
        let out = crate::invocation::command("ssh")
            .args([&self.host, "buildutil", "store", "has-digest", digest])
            .output()
            .map_err(|e| format!("ssh {}: {}", self.host, e))?;
        Ok(out.status.success())
    }

    fn realize(
        &self,
        drv_text: &str,
        inputs: &[(String, Vec<u8>)],
        timeout: Duration,
    ) -> Result<RemoteResult, String> {
        // Push the drv text + missing input archives, run remote realize
        // under a timeout, pull the record/archive/log. The remote never
        // trusts us and we never trust it beyond the signed record.
        let _ = (drv_text, inputs, timeout);
        Err(format!(
            "SSH remote realization to {} is unverified on the build host \
             (needs a live builder)",
            self.host
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn parse_keeps_enforcing_drops_audit() {
        let text = "\
# a comment
ssh://ci@fast arch=aarch64 jobs=8 grade=namespace
ssh://ci@slow arch=x86_64 jobs=2 grade=audit

ssh://ci@caps arch=aarch64 grade=caps
";
        let b = parse_builders(text);
        assert_eq!(b.len(), 2); // audit dropped
        assert_eq!(b[0].url, "ssh://ci@fast");
        assert_eq!(b[0].arch, "aarch64");
        assert_eq!(b[0].jobs, 8);
        assert_eq!(b[1].url, "ssh://ci@caps");
        assert_eq!(b[1].jobs, 1); // default
    }

    #[test]
    fn choose_by_arch_and_capacity() {
        let builders = parse_builders(
            "ssh://a arch=aarch64 jobs=1 grade=namespace\n\
             ssh://b arch=aarch64 jobs=2 grade=namespace\n\
             ssh://c arch=x86_64 jobs=4 grade=namespace\n",
        );
        let mut inflight = BTreeMap::new();
        // aarch64 → first eligible is a.
        assert_eq!(
            choose_builder(&builders, "aarch64", &inflight).unwrap().url,
            "ssh://a"
        );
        // a is full → b.
        inflight.insert("ssh://a".to_string(), 1);
        assert_eq!(
            choose_builder(&builders, "aarch64", &inflight).unwrap().url,
            "ssh://b"
        );
        // both full → none for aarch64.
        inflight.insert("ssh://b".to_string(), 2);
        assert!(choose_builder(&builders, "aarch64", &inflight).is_none());
        // x86_64 still available.
        assert_eq!(
            choose_builder(&builders, "x86_64", &inflight).unwrap().url,
            "ssh://c"
        );
    }

    struct FlakyTransport {
        fails_before_success: RefCell<usize>,
    }
    impl Transport for FlakyTransport {
        fn has(&self, _: &str) -> Result<bool, String> {
            Ok(false)
        }
        fn realize(
            &self,
            _: &str,
            _: &[(String, Vec<u8>)],
            _: Duration,
        ) -> Result<RemoteResult, String> {
            let mut n = self.fails_before_success.borrow_mut();
            if *n > 0 {
                *n -= 1;
                Err("transient".to_string())
            } else {
                Ok(RemoteResult {
                    record: "buildutil-realization\ndrv: cafe\n".to_string(),
                    archive: vec![],
                    log: "ok".to_string(),
                })
            }
        }
    }

    #[test]
    fn retry_succeeds_within_budget_and_fails_past_it() {
        let t = FlakyTransport {
            fails_before_success: RefCell::new(2),
        };
        // 2 failures then success: retries=2 (3 attempts) succeeds.
        assert!(dispatch_with_retry(&t, "drv", &[], Duration::from_secs(1), 2).is_ok());

        let t2 = FlakyTransport {
            fails_before_success: RefCell::new(5),
        };
        // retries=1 (2 attempts) < 5 failures → Err (caller falls back local).
        assert!(dispatch_with_retry(&t2, "drv", &[], Duration::from_secs(1), 1).is_err());
    }
}
