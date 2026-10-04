// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — canonical build-tool source locations.
//!
//! Every repo-relative path to a build-tool source (buildutil, mica, compose)
//! that the engine embeds — in the generated `bootstrap.ninja`, in the
//! bootstrap source set — resolves through a const here, so relocating a tool is
//! a one-edit change instead of a hunt across the code.
//!
//! The one path this cannot reach is the repo-root `./buildutil` wrapper, which
//! runs before the engine is compiled; `buildutil gen --selfcheck` greps the
//! wrapper for the expected tokens to keep it honest.

/// The buildutil engine's own source root.
pub const BUILDUTIL: &str = "tools/buildutil";
/// The module wire both buildutil and the module SDK compile.
pub const SDK_WIRE: &str = "tools/buildutil/sdk/wire.rs";
/// The FHS-composition library root the engine links, a standalone store
/// tool outside the engine.
pub const BUILDUTIL_COMPOSE: &str = "tools/buildutil/compose";
/// The configuration library, a submodule of the build tool.
pub const MICA: &str = "tools/buildutil/lib/mica";

/// The generated bootstrap ninja (regenerated from this module by `buildutil gen`).
pub const BOOTSTRAP_NINJA: &str = "tools/buildutil/bootstrap.ninja";
/// Ed25519 substituter trust anchors.
pub const TRUSTED_KEYS: &str = "tools/buildutil/trusted-keys.txt";
/// Setup-hook wire path emitted by compose manifests and consumed by exec.
pub const SETUP_ENV_PATH: &str = "buildutil-support/setup-env";
