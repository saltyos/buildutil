// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — remote build dispatch via SSH push-build-pull.

use std::path::PathBuf;

use super::{Args, flag_value, positional};

pub fn cmd_remote(args: &Args) -> Result<i32, String> {
    let repo_root =
        std::env::current_dir().map_err(|e| format!("cannot determine repo root: {}", e))?;
    let store_root = args
        .store
        .clone()
        .or_else(|| std::env::var_os("BUILDUTIL_STORE").map(PathBuf::from))
        .unwrap_or_else(|| repo_root.join(".buildutil"));
    let st = crate::store::Store::open(&store_root)?;
    let builders_text =
        std::fs::read_to_string(repo_root.join(".buildutil/builders")).unwrap_or_default();
    let builders = crate::store::remote::parse_builders(&builders_text);
    let pos = positional(args);
    match pos.first().copied() {
        Some("ls") | None => {
            if builders.is_empty() {
                crate::log::warn("remote", "no eligible builders in .buildutil/builders");
            }
            for b in &builders {
                out!(
                    "{} arch={} jobs={} grade={}",
                    b.url,
                    b.arch,
                    b.jobs,
                    b.grade
                );
            }
            Ok(0)
        }
        Some("build") => {
            let target = pos.get(1).copied().ok_or("remote build: name a target")?;
            let in_flight = std::collections::BTreeMap::new();
            let builder_url = flag_value(args, "--builder")
                .map(str::to_string)
                .or_else(|| {
                    crate::store::remote::choose_builder(&builders, &args.arch, &in_flight)
                        .map(|b| b.url.clone())
                })
                .ok_or_else(|| format!("no eligible builder for arch `{}`", args.arch))?;
            use crate::store::remote::Transport as _;
            let transport = crate::store::remote::SshTransport::new(&builder_url);
            let keys = crate::store::substitute::load_trusted_keys(&repo_root);
            // Content-dedup: skip the build if the remote store already has it.
            if transport.has(target).unwrap_or(false) {
                crate::log::info(
                    "remote",
                    &format!("Builder {} already has {}", builder_url, target),
                );
                return Ok(0);
            }
            match crate::store::remote::dispatch_with_retry(
                &transport,
                target,
                &[],
                std::time::Duration::from_secs(3600),
                1,
            ) {
                Ok(result) => {
                    if !result.log.is_empty() {
                        crate::term::line(result.log.trim_end());
                    }
                    // Trust is the realization signature, never the SSH hop.
                    let installed = crate::store::substitute::install_verified(
                        &st,
                        "",
                        target,
                        &[],
                        &result.record,
                        &result.archive,
                        &keys,
                    )?;
                    if installed {
                        crate::log::success("remote", &format!("Built and installed {}", target));
                    } else {
                        crate::log::error(
                            "remote",
                            &format!("Built {} but did not install it", target),
                        );
                    }
                    Ok(if installed { 0 } else { 1 })
                }
                Err(e) => {
                    crate::log::error(
                        "remote",
                        &format!(
                            "Remote build of {} on {} failed ({}); a real run falls back to a local build",
                            target, builder_url, e
                        ),
                    );
                    Ok(1)
                }
            }
        }
        _ => Err("remote: expected ls | build <target> [--builder <url>]".to_string()),
    }
}
