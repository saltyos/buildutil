//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — image cluster: disk-image assembly + the format implementations
//! it composes
//!
//! The cluster groups every image-shape concern of the build system into one
//! `tools/buildutil/image/` tree:
//!   * `disk`        — the BIOS / UEFI boot-image assembler (calls fat, gpt,
//!                     bootmanifest, and rootfs).
//!   * `fat`         — FAT16/FAT32 filesystem writer + structure reader.
//!   * `gpt`         — protective MBR + primary/backup GPT header/array
//!                     writer + reader, plus the BIOS rootfs patcher.
//!   * `bootmanifest` — the BRA Boot Manifest writer/reader.
//!   * `cpio`        — newc archive writer + reader (also a permission-load
//!                     helper reused by `saltyfs::build` and `rootfs`).
//!   * `rootfs`      — assembles the rootfs SaltyFS image from manifests and
//!                     port projections.
//!   * `saltyfs`     — the SaltyFS B-tree filesystem cluster (writer / reader
//!                     / CLI / tests).
//!
//! Each sibling is its own module; cross-file access is via `super::`. There
//! are no shared types at this level.

pub mod bootmanifest;
pub mod cpio;
pub mod disk;
pub mod dump;
pub mod fat;
pub mod gpt;
pub mod rootfs;
pub mod saltyfs;

/// Dispatch structure dump verbs or the disk-image assembly arguments.
pub fn run(args: &[String]) -> Result<i32, String> {
    match args.first().map(String::as_str) {
        Some(kind) if kind.starts_with("dump-") => dump::run(kind, &args[1..]),
        _ => disk::run(args),
    }
}
