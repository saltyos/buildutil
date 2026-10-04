//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — peripheral builders the full frontend registers beside the core
//! set: the port builder.
//!
//! Crossing into `host/` is one-way (a toolchain module may call into host
//! for shared helpers; host never depends on toolchain). The bootstrap
//! engine (minibuildutil) registers only the core builders.

mod builders;
pub(super) mod portbuild;

pub(crate) fn builder_registry() -> crate::exec::builder::BuilderRegistry {
    let mut registry = crate::exec::builder::BuilderRegistry::core();
    builders::register(&mut registry);
    registry
}
