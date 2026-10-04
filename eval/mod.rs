// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — evaluation: target resolution, plan serialization, and
//! read-only introspection (`graph`, `plan`, `why-depends`, `explain`).

pub mod cache;
pub mod graph;
pub mod ninja_emit;
pub mod observe;
pub mod plan;
