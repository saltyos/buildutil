//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — logging: messages and job progress as build events
//!
//! `Logger` is the producer-side handle for everything a build reports: log
//! messages, derivation start and finish, and builder output lines. Each call
//! becomes one build event (`events`); how an event is shown is decided by
//! `term::view`, never here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Success,
    Warning,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Success => "success",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
        }
    }
}

/// A message at `level` from code that holds no `Logger`: the same build
/// event a `Logger` emits. `context` names the reporting subsystem for event
/// consumers; the screen shows only the level tag and the message.
pub fn message(level: LogLevel, context: &str, msg: &str) {
    crate::events::emit_log(level.as_str(), context, msg);
}

pub fn info(context: &str, msg: &str) {
    message(LogLevel::Info, context, msg);
}

pub fn success(context: &str, msg: &str) {
    message(LogLevel::Success, context, msg);
}

pub fn warn(context: &str, msg: &str) {
    message(LogLevel::Warning, context, msg);
}

pub fn error(context: &str, msg: &str) {
    message(LogLevel::Error, context, msg);
}

/// A step a person should know happened (starting a backend, a GC phase):
/// one durable `[INFO]` line.
pub fn announce(context: &str, step: &str) {
    info(context, step);
}

pub struct Logger {
    verbose: bool,
}

impl Logger {
    pub fn new(verbose: bool) -> Self {
        Logger { verbose }
    }

    /// Report a message; debug messages only when verbose.
    pub fn log(&self, level: LogLevel, context: &str, message: &str) {
        if level == LogLevel::Debug && !self.verbose {
            return;
        }
        crate::events::emit_log(level.as_str(), context, message);
    }

    pub fn info(&self, ctx: &str, msg: &str) {
        self.log(LogLevel::Info, ctx, msg);
    }

    pub fn success(&self, ctx: &str, msg: &str) {
        self.log(LogLevel::Success, ctx, msg);
    }

    pub fn warn(&self, ctx: &str, msg: &str) {
        self.log(LogLevel::Warning, ctx, msg);
    }

    pub fn error(&self, ctx: &str, msg: &str) {
        self.log(LogLevel::Error, ctx, msg);
    }

    /// A derivation began real work (`action` is the verb shown for it).
    pub fn start_job(&self, name: &str, action: &str, current: usize, total: usize) {
        crate::events::emit_start(name, "", action, current, total);
    }

    /// A running derivation moved to its next step.
    pub fn step(&self, name: &str, action: &str) {
        crate::events::emit_step(name, action);
    }

    /// A derivation reached `outcome` (Realized or Cached), with the
    /// verdict its builder reported when it has one.
    pub fn finish_job(
        &self,
        name: &str,
        outcome: &str,
        current: usize,
        total: usize,
        hash: &str,
        verdict: Option<&str>,
    ) {
        crate::events::emit_finish(name, hash, outcome, current, total, verdict, None);
    }

    /// A derivation failed. `reason` is reported once, with the retained
    /// log given relative to the state root when one was written.
    pub fn fail_job(
        &self,
        name: &str,
        current: usize,
        total: usize,
        hash: &str,
        reason: &str,
        log: Option<&str>,
    ) {
        crate::events::emit_finish(name, hash, "Failed", current, total, Some(reason), log);
    }

    /// One line of builder output from `stream` (`stdout` or `stderr`).
    pub fn output(&self, name: &str, line: &str, stream: &str) {
        crate::events::emit_output(name, line, stream);
    }

    /// A progress item a builder reported through a structured signal.
    pub fn item(&self, name: &str, counter: Option<(usize, usize)>, text: &str) {
        crate::events::emit_item(name, counter, text);
    }
}
