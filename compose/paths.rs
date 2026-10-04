// SPDX-License-Identifier: GPL-2.0-only
//! buildutil-compose — shared path constants.
//!
//! `SETUP_ENV_PATH` is a wire contract with the buildutil engine (which reads
//! the same relative path back out of a composed projection to fold its
//! setup hook into a consuming build's environment) — the value must stay
//! byte-identical to the engine's own copy in `tools/buildutil/paths/mod.rs`.

/// Setup hook carried by projected build inputs.
pub const SETUP_ENV_PATH: &str = "buildutil-support/setup-env";
