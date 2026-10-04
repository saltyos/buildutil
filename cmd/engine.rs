//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — running an engine command in a child process
//!
//! Build-engine commands (the ones the daemon serves) never run in the
//! process that owns the terminal. Without a daemon, the client starts its
//! own binary as a child with `--stream-events --no-daemon`: the child's
//! stdout carries build events and any other results, its stderr carries
//! whatever else it writes, and the client draws both through one
//! `term::view::BuildView`. Engine code therefore cannot write past the
//! status row, however it writes.

use crate::cmd::Args;
use crate::invocation::Io;
use crate::term::view::{BuildView, Stream};
use std::io::{BufRead, BufReader, Read};
use std::sync::mpsc;
use std::time::Duration;

/// Requests whose work is evaluation or realization; the same set the
/// daemon accepts. `check` is one when it names declared checks; a built-in
/// check, and a bare `check` with its license check, run in the client
/// like any other engine command they start.
pub fn is_engine_request(argv: &[String]) -> bool {
    match argv.first().map(String::as_str) {
        Some("build" | "dev" | "eval" | "plan" | "lock" | "mkrootfs" | "tc" | "bootstrap") => true,
        Some("check") => crate::cmd::parse_args(argv)
            .and_then(|args| crate::cmd::check_words(&args))
            .is_ok_and(|words| {
                words.checks.first().is_some_and(|word| {
                    !crate::spec::kinds::BUILTIN_CHECKS.contains(&word.as_str())
                })
            }),
        _ => false,
    }
}

/// Run an engine request on behalf of a client command: through the daemon
/// when one serves this state root, else in a child engine. Its events are
/// drawn here like any engine command's.
pub fn request(argv: &[String], args: &Args) -> Result<i32, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(result) = crate::daemon::client::maybe_run(argv, args) {
        return result;
    }
    run(argv, args)
}

enum Msg {
    Line(String),
    Err(Vec<u8>),
    Closed,
}

pub fn run(argv: &[String], args: &Args) -> Result<i32, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot find the buildutil binary for the engine: {}", e))?;
    let mut child_argv = argv.to_vec();
    for flag in ["--stream-events", "--no-daemon"] {
        if !child_argv.iter().any(|a| a == flag) {
            child_argv.push(flag.to_string());
        }
    }
    #[cfg(unix)]
    let interrupt = crate::host::interrupt::InterruptGuard::install();
    let mut child = crate::invocation::isolated(&exe)
        .args(&child_argv)
        .stdin(Io::Null)
        .stdout(Io::Piped)
        .stderr(Io::Piped)
        .spawn()
        .map_err(|e| format!("cannot start the buildutil engine: {}", e))?;
    let out = child.stdout.take().ok_or("cannot capture engine stdout")?;
    let err = child.stderr.take().ok_or("cannot capture engine stderr")?;
    let (tx, rx) = mpsc::channel();
    let tx_err = tx.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(out);
        let mut line = String::new();
        while matches!(reader.read_line(&mut line), Ok(n) if n > 0) {
            let text = line.trim_end_matches(['\n', '\r']).to_string();
            if tx.send(Msg::Line(text)).is_err() {
                return;
            }
            line.clear();
        }
        let _ = tx.send(Msg::Closed);
    });
    std::thread::spawn(move || {
        let mut err = err;
        let mut buf = [0u8; 8192];
        while let Ok(n) = err.read(&mut buf) {
            if n == 0 || tx_err.send(Msg::Err(buf[..n].to_vec())).is_err() {
                break;
            }
        }
        let _ = tx_err.send(Msg::Closed);
    });

    let mut view = BuildView::new(args.view_options());
    let mut open = 2;
    #[cfg(unix)]
    let mut forwarded = false;
    while open > 0 {
        // A terminal Ctrl-C reaches the engine directly; a signal sent to
        // this process alone is passed on so the engine cancels too.
        #[cfg(unix)]
        if !forwarded && interrupt.was_interrupted() {
            crate::host::interrupt::forward_termination(child.id());
            forwarded = true;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Msg::Line(line)) => view.event(&line),
            Ok(Msg::Err(bytes)) => view.raw(Stream::Stderr, &bytes),
            Ok(Msg::Closed) => open -= 1,
            Err(mpsc::RecvTimeoutError::Timeout) => view.tick(),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for the buildutil engine: {}", e))?;
    #[cfg(unix)]
    if interrupt.was_interrupted() {
        view.interrupted();
    }
    view.finish();
    Ok(status.code().unwrap_or(130))
}
