//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — a derivation build engine
//!
//! A pure-functional derivation engine: every artifact is a derivation
//! with an input-addressed SHA-256 identity, realized in a sandboxed
//! private build dir into a persistent content-addressed store. The
//! configuration resolves in process through mica; ninja remains the
//! fine-grained compile executor inside derivations that carry an internal
//! DAG; everything project-specific runs as a module.

// First, so its print macros and their std shadows are in scope everywhere.
#[macro_use]
mod term;

mod cmd;
mod config;
mod crypto;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod daemon;
mod eval;
mod events;
mod exec;
mod glob;
mod host;
mod image;
mod inputs;
mod invocation;
#[path = "../flake-sdk/wire.rs"]
pub mod sdk_wire;
pub(crate) use crypto::sha256 as input_sha256;
pub(crate) use source::filter as input_filter;
pub(crate) use spec::toml as input_toml;
mod license;
mod log;
mod paths;
mod platform;
mod source;
pub mod spec;
mod state;
mod store;
mod toolchain;
pub mod tools;

fn full_builders() -> exec::builder::BuilderRegistry {
    toolchain::builder_registry()
}

use std::process;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    term::install_panic_hook();
    let code = run_argv_in_process(argv, true);
    term::clear_status();
    process::exit(code);
}

/// Execute an argv vector without changing the daemon process's environment or
/// cwd. The daemon calls this with routing disabled after it has installed the
/// request context; ordinary CLI invocations may first use the daemon client.
pub(crate) fn run_argv_in_process(argv: Vec<String>, allow_daemon: bool) -> i32 {
    let realize_only = std::env::args_os().next().is_some_and(|arg0| {
        std::path::Path::new(&arg0)
            .file_name()
            .and_then(|name| name.to_str())
            == Some("buildutil-realize")
    });
    // Realization re-execs the active engine for namespace setup; keep that
    // internal seam available without exposing the normal frontend commands.
    if realize_only
        && argv.first().map(String::as_str) != Some("__realize-plan")
        && !exec::is_internal_command(&argv)
    {
        term::error("buildutil-realize is a realize-only store executor");
        return 2;
    }
    if let Some(result) = exec::dispatch_internal_command(&argv) {
        match result {
            Ok(code) => return code,
            Err(e) => {
                term::error(&e);
                return 1;
            }
        }
    }
    if argv.is_empty() {
        cmd::usage::usage();
        return 1;
    }
    if argv.len() == 1 && cmd::usage::is_help_arg(&argv[0]) {
        cmd::usage::usage();
        return 0;
    }
    if argv[0] == "help" {
        if let Some(command) = argv.get(1) {
            if cmd::usage::command_usage(command) {
                return 0;
            }
        }
        cmd::usage::usage();
        return 0;
    }
    if argv.len() >= 2 && cmd::usage::is_help_arg(&argv[1]) && cmd::usage::command_usage(&argv[0]) {
        return 0;
    }
    let args = match cmd::parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            term::error(&e);
            cmd::usage::usage();
            return 1;
        }
    };
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if args.command == "__daemon" {
        return match daemon::server::run(&args) {
            Ok(code) => code,
            Err(error) => {
                term::error(&error);
                1
            }
        };
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if args.command == "daemon" {
        return match daemon::cmd_daemon(&args) {
            Ok(code) => code,
            Err(error) => {
                term::error(&error);
                1
            }
        };
    }
    // A person is watching this process: engine work runs in a child whose
    // output is drawn here, and in-process events go to a local build view.
    // Internal commands (`__realize-plan`, `__dev-build`) are run only by a
    // parent buildutil over pipes and always stream their events to it.
    let client = allow_daemon && !args.stream_events && !args.command.starts_with("__");
    let view = client.then(|| {
        let view = std::sync::Arc::new(std::sync::Mutex::new(term::view::BuildView::new(
            args.view_options(),
        )));
        let sink = std::sync::Arc::clone(&view);
        events::install_local_sink(Box::new(move |line| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .event(line)
        }));
        view
    });
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if allow_daemon {
        if let Some(result) = daemon::client::maybe_run(&argv, &args) {
            return match result {
                Ok(code) => code,
                Err(error) => {
                    term::error(&format!("daemon request failed: {error}"));
                    1
                }
            };
        }
    }
    if client && cmd::engine::is_engine_request(&argv) {
        return match cmd::engine::run(&argv, &args) {
            Ok(code) => code,
            Err(error) => {
                term::error(&error);
                1
            }
        };
    }
    let run = || match args.command.as_str() {
        "build" => cmd::build::cmd_build(&args),
        "lock" => cmd::inputs::cmd_lock(&args),
        "dev" => cmd::build::cmd_dev(&args),
        "eval" => cmd::build::cmd_eval(&args),
        "plan" => cmd::build::cmd_plan(&args),
        "__realize-plan" => cmd::build::cmd_realize_plan(&args),
        "__dev-build" => cmd::build::cmd_dev_build(&args),
        "why-depends" => cmd::query::cmd_why_depends(&args),
        "graph" => cmd::query::cmd_graph(&args),
        "explain" => cmd::query::cmd_explain(&args),
        "log" => cmd::query::cmd_log(&args),
        "remote" => cmd::remote::cmd_remote(&args),
        "store" => cmd::store::cmd_store(&args),
        "gen" => cmd::r#gen::cmd_gen(&args),
        "cpio" => crate::image::cpio::run(&argv[1..]),
        "untar" => crate::exec::untar::run(&argv[1..]),
        "image" => {
            if args
                .targets
                .first()
                .is_some_and(|verb| verb.starts_with("dump-"))
            {
                crate::image::run(&args.targets)
            } else {
                crate::image::run(&argv[1..])
            }
        }
        "saltyfs" => crate::image::saltyfs::run(&argv[1..]),
        "rootfs" => crate::image::rootfs::run(&argv[1..]),
        "sysroot" => buildutil_compose::sysroot::run(&argv[1..]).map(|_| 0),
        "setup" => cmd::driver::cmd_setup(&argv[1..]),
        "run" => cmd::driver::cmd_run(&args),
        "mkrootfs" => cmd::driver::cmd_mkrootfs(&args),
        "test" => cmd::driver::cmd_test(&args),
        "config" => cmd::driver::cmd_config(&argv[1..]),
        "gdb" => cmd::driver::cmd_gdb(&args),
        "fmt" => cmd::driver::cmd_fmt(&args),
        "check" => cmd::driver::cmd_check(&args, |t| {
            let mut sub = vec!["build".to_string()];
            sub.extend(t.iter().cloned());
            cmd::parse_args(&sub).and_then(|a| cmd::build::cmd_build(&a))
        }),
        "tc" => cmd::driver::cmd_tc(&args),
        "bootstrap" => cmd::driver::cmd_bootstrap(&argv[1..], |t| {
            let mut sub = vec!["build".to_string()];
            sub.extend(t.iter().cloned());
            cmd::parse_args(&sub).and_then(|a| cmd::build::cmd_build(&a))
        }),
        "keygen" => match args.targets.first() {
            Some(out) => crate::store::substitute::cmd_keygen(std::path::Path::new(out)).map(|_| 0),
            None => Err("keygen: name the secret-key output path".to_string()),
        },
        "help" | "--help" | "-h" => {
            cmd::usage::usage();
            Ok(0)
        }
        other => Err(format!("unknown command `{}`", other)),
    };
    let result = run();
    // Persist the source-hash cache before the exit paths below skip
    // destructors (activated in open_context; a no-op otherwise).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let daemon_active = daemon::state::with_active_daemon(|_| ()).is_some();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let daemon_active = false;
    if !daemon_active {
        crate::source::statcache::flush_file_cache();
    }
    if let Some(view) = view {
        view.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .finish();
    }
    match result {
        Ok(code) => code,
        Err(e) => {
            if args.stream_events {
                crate::events::emit_error("buildutil", &e);
            } else {
                term::error(&e);
            }
            1
        }
    }
}
