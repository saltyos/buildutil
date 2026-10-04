// SPDX-License-Identifier: GPL-2.0-only
//! Persistent host evaluation daemon. This module is Unix-only: native Windows
//! retains the ordinary in-process path without a compatibility shim.

pub mod client;
#[cfg(target_os = "macos")]
mod fsevents;
#[cfg(target_os = "linux")]
mod inotify;
pub mod proto;
pub mod server;
pub mod state;
pub mod watch;

pub fn cmd_daemon(args: &crate::cmd::Args) -> Result<i32, String> {
    match args.targets.first().map(String::as_str).unwrap_or("status") {
        "status" => client::status(args),
        "stop" => client::stop(args),
        "restart" => client::restart(args),
        "verify" => client::verify(args),
        other => Err(format!(
            "daemon: expected status|stop|restart|verify, got `{other}`"
        )),
    }
}
