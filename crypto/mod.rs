// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — cryptographic and content-addressing primitives.
//!
//! Hand-rolled, std-only implementations: the SHA-256 (`sha256`) and SHA-512
//! (`sha512`) hashers, CRC checksums (`crc`), Ed25519 signatures (`ed25519`),
//! and the deterministic-seed derivation (`detseed`) that removes wall-clock
//! nondeterminism from image builders.

pub mod crc;
pub mod detseed;
pub mod ed25519;
#[path = "../lib/crypto/sha256.rs"]
pub mod sha256;
pub mod sha512;
