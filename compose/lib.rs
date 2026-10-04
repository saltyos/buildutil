// SPDX-License-Identifier: GPL-2.0-only
//! buildutil-compose — FHS composition as a standalone store tool.
//!
//! The compose mechanism operates outside the build engine and
//! reshapes non-engine derivation outputs (port stage trees, the cross
//! sysroot, rootfs staging), so its realization digest must be a declared
//! tool dependency of its consumers rather than living implicitly inside
//! the engine binary.

pub mod glob;
pub mod manifest;
pub mod paths;
pub mod platform;
pub mod projection;
pub mod sysroot;
