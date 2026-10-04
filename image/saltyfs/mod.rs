//! SPDX-License-Identifier: GPL-2.0-only
//! flake — SaltyFS format 2 image writer, verifier and parity dumper
//!
//! The format is docs/spec/staging/saltyfs-format.rst. This module is
//! flake's own transcription of it: the provider and the stage3 boot reader
//! transcribe the same document independently and none of the three shares
//! code. Layout identifier 2 is the only layout any of them decodes.
//!
//! Deterministic by construction: filesystem, device and subvolume UUIDs,
//! the volume incarnation, the KDF salt and every object key derive from
//! the content manifest (and, under an encrypted profile, the passphrase or
//! volume key given), every timestamp comes from SOURCE_DATE_EPOCH, and
//! directory inode numbering is (depth, name) order.
//!
//! The cluster is split:
//!   * `mod.rs`        — format constants, keys, pointers, item packers, the
//!                       rows, the superblock, the keyslots, the log record
//!                       codec, the volume keys, xxh3-128, the CLI.
//!   * `build.rs`      — the writer (`build_to_file`, the B-tree builder,
//!                       the three subvolumes and the store).
//!   * `read.rs`       — the reader (`dump_text`, `verify`, `accounting`).
//!   * `read_graph.rs` — structural, ring and allocation authority.
//!   * `primitives.rs` — BLAKE3, the two ciphers, SipHash, Argon2id.
//!   * `codec.rs`      — LZ4, Zstandard, FastCDC.
//!   * `seal.rs`       — seal objects, bodies, store files, the sealer.
//!   * `tests.rs` / `snapshot_tests.rs` — the on-disk conformance tests.

use std::path::{Path, PathBuf};

use super::cpio::{self, Permissions};

pub mod build;
pub(crate) mod casefold;
pub mod codec;
pub mod primitives;
pub mod read;
pub mod seal;
pub mod sha256;

#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;

pub const BLOCK_SIZE: usize = 4096;
pub const MAGIC: &[u8; 8] = b"SALTYFS\0";
pub const LAYOUT: u32 = 2;
pub const NODE_MAGIC: &[u8; 4] = b"SELN";
pub const LOG_MAGIC: &[u8; 4] = b"SLNL";

pub const ROOT_INO: u64 = 1;
pub(crate) const FIRST_INO: u64 = 2;
pub const DEFAULT_SUBVOL: u64 = 1;
pub const KEY_TREE_SUBVOL: u64 = 2;
pub const STORE_SUBVOL: u64 = 3;
pub const FIRST_USER_SUBVOL: u64 = 256;

// Item types of the item tree.
pub const ITEM_INODE: u8 = 0x01;
pub const ITEM_INODE_REF: u8 = 0x02;
pub const ITEM_DIR: u8 = 0x03;
pub const ITEM_SKEY: u8 = 0x04;
pub const ITEM_EXTENT_DATA: u8 = 0x05;
pub const ITEM_SIGNING_SECRET: u8 = 0x06;
pub const ITEM_XATTR: u8 = 0x07;
pub const ITEM_ACCESS_CONTROL: u8 = 0x08;
pub const ITEM_COMMIT_SIGNATURE: u8 = 0x09;
// Data-tag and object-index trees.
pub const ITEM_DATA_TAG: u8 = 0x0A;
pub const ITEM_OBJECT_INDEX: u8 = 0x0B;
pub const ITEM_THAW: u8 = 0x0C;
pub const ITEM_DEVICE: u8 = 0x0D;
pub const ITEM_DIR_MEMBER: u8 = 0x0E;
pub const ITEM_PROJECT: u8 = 0x0F;
pub const ITEM_APPEND_RESULT: u8 = 0x10;
// Subvolume table, deadlogs and the share tree.
pub const ITEM_SUBVOL: u8 = 0x20;
pub const ITEM_SNAP: u8 = 0x21;
pub const ITEM_RETIRE: u8 = 0x22;
pub const ITEM_DEADLOG_ENTRY: u8 = 0x23;
pub const ITEM_SHARE_ENTRY: u8 = 0x24;
// Pin registry.
pub const ITEM_HOLD: u8 = 0x30;
pub const ITEM_GRANT: u8 = 0x31;
pub const ITEM_SOURCE: u8 = 0x32;
pub const ITEM_WATERMARK: u8 = 0x33;
pub const ITEM_KEEP: u8 = 0x34;
pub const ITEM_SHARE: u8 = 0x35;

// Tree kinds carried in every node header.
pub const TREE_ITEM: u32 = 1;
pub const TREE_OBJECT_INDEX: u32 = 2;
pub const TREE_DATA_TAG: u32 = 3;
pub const TREE_SUBVOL_TABLE: u32 = 4;
pub const TREE_PIN_REGISTRY: u32 = 5;
pub const TREE_DEADLOG: u32 = 6;
pub const TREE_SHARE: u32 = 7;

// Extent shapes and encodings.
pub(crate) const EXTENT_INLINE: u8 = 0;
pub(crate) const EXTENT_REGULAR: u8 = 1;
pub(crate) const EXTENT_HOLE: u8 = 2;
pub(crate) const EXTENT_ABSENT: u8 = 3;
pub(crate) const ENCODING_PLAIN: u16 = 0;
pub(crate) const ENCODING_INDIRECT: u16 = 1;
pub(crate) const COMPRESSION_NONE: u8 = 0;
pub(crate) const COMPRESSION_LZ4: u8 = 1;
pub(crate) const COMPRESSION_ZSTD: u8 = 2;
/// A compressed extent covers at most one unit of logical file bytes.
pub(crate) const COMPRESSION_UNIT: usize = 64 * 1024;

/// Longest payload an inline extent carries.
pub(crate) const INLINE_MAX: usize = 208;
/// Longest data-tag run: sixteen 4 KiB units per item.
pub(crate) const DATA_TAG_RUN_MAX: usize = 16;
/// Probes of a byte directory's hash.
pub(crate) const DIR_PROBES: u64 = 16;

// Mode bits.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFBLK: u32 = 0o060000;

// Superblock feature and state words.
pub const INCOMPAT_CASEFOLD: u32 = 1 << 0;
pub(crate) const INCOMPAT_SUPPORTED: u32 = INCOMPAT_CASEFOLD;
pub const CASEFOLD_VERSION_UNICODE_15_1: u32 = 15_001_000;
pub const STATE_CLEAN: u32 = 1;
pub const STATE_DIRTY: u32 = 2;
pub const SUITE_PLAIN: u32 = 0;
pub const SUITE_XCHACHA20_POLY1305: u32 = 1;
pub const SUITE_XAES_256_GCM: u32 = 2;

// Inode flags.
pub(crate) const INODE_CASEFOLD: u32 = 1 << 0;
pub(crate) const INODE_HIDDEN: u32 = 1 << 1;
pub(crate) const INODE_RETAINED: u32 = 1 << 5;
pub(crate) const INODE_CASE_AXIS_SHIFT: u32 = 13;
pub(crate) const INODE_NORM_AXIS_SHIFT: u32 = 15;
/// A symbolic link that names a directory, as a Win32 directory link does;
/// legal on symbolic links only.
pub(crate) const INODE_DIRECTORY_LINK: u32 = 1 << 17;
pub(crate) const INODE_FLAGS_DEFINED: u32 = 0x3_FFFF;
/// The flags a seal tree entry carries: the attribute flags (bits 2-4
/// DOS_HIDDEN, DOS_SYSTEM, DOS_ARCHIVE; bits 6-12 IMMUTABLE, APPEND_ONLY,
/// NOUNLINK, NODUMP, NOATIME, PROJINHERIT, DOS_READONLY), the CASEFOLD
/// projection and DIRECTORY_LINK; never HIDDEN, RETAINED or the axis fields.
pub(crate) const INODE_ENTRY_FLAGS: u32 = 0x1FDC | INODE_CASEFOLD | INODE_DIRECTORY_LINK;
pub(crate) const AXIS_SENSITIVE: u8 = 0;
pub(crate) const AXIS_INSENSITIVE: u8 = 1;
pub(crate) const AXIS_MIXED: u8 = 2;
pub(crate) const PLUGIN_DIR_HASH: usize = 0;
pub(crate) const PLUGIN_COMPRESSION: usize = 2;
pub(crate) const DIR_HASH_FNV1A: u8 = 0;
pub(crate) const DIR_HASH_SIPHASH: u8 = 1;

// Subvolume row words.
pub const SUBVOL_STATE_LIVE: u32 = 1;
pub const SUBVOL_STATE_CLOSING: u32 = 2;
pub const SUBVOL_FLAG_BOOT_DEFAULT: u32 = 1 << 0;
pub const SUBVOL_FLAG_STORE: u32 = 1 << 1;
pub const SUBVOL_FLAG_NOSEAL: u32 = 1 << 2;
pub const SUBVOL_FLAG_MATERIALISING: u32 = 1 << 3;
pub const SUBVOL_FLAG_ATIME: u32 = 1 << 4;
pub const SUBVOL_FLAG_RELATIME: u32 = 1 << 5;
pub const SUBVOL_FLAGS_DEFINED: u32 = 0x3F;
pub const SNAP_STATE_PINNED: u32 = 1;
pub const SNAP_STATE_SEALING: u32 = 2;
pub const SNAP_STATE_SEALED: u32 = 3;
pub const SNAP_FLAG_DELETING: u32 = 1 << 0;
/// The seal time came from a clock the system trusted; legal only once the
/// row is `SEALING` or `SEALED`, and mirrored by the commit's clock byte.
pub const SNAP_FLAG_CLOCK_VALID: u32 = 1 << 1;
pub const SNAP_FLAGS_DEFINED: u32 = SNAP_FLAG_DELETING | SNAP_FLAG_CLOCK_VALID;

// Packed sizes.
pub(crate) const KEY_SIZE: usize = 25;
pub(crate) const POINTER_SIZE: usize = 32;
pub(crate) const NODE_HEADER_SIZE: usize = 64;
pub(crate) const LEAF_ENTRY_SIZE: usize = KEY_SIZE + 8;
pub(crate) const INTERNAL_ENTRY_SIZE: usize = KEY_SIZE + POINTER_SIZE;
pub(crate) const LEAF_ENTRY_MAX: usize = (BLOCK_SIZE - NODE_HEADER_SIZE) / LEAF_ENTRY_SIZE;
pub(crate) const INTERNAL_ENTRY_MAX: usize = (BLOCK_SIZE - NODE_HEADER_SIZE) / INTERNAL_ENTRY_SIZE;
pub(crate) const PAYLOAD_MAX: usize = 320;
pub(crate) const INODE_SIZE: usize = 128;
pub(crate) const EXTENT_HEADER_SIZE: usize = 40;
pub(crate) const DIR_ITEM_HEADER_SIZE: usize = 20;
pub(crate) const DIR_CLASS_BYTES: usize = 16;
pub(crate) const DIR_MEMBER_HEADER_SIZE: usize = 36;
pub(crate) const INODE_REF_HEADER_SIZE: usize = 16;
pub(crate) const XATTR_HEADER_SIZE: usize = 8;
pub(crate) const SUBVOL_ROW_SIZE: usize = 320;
pub(crate) const SNAP_ROW_SIZE: usize = 240;
pub(crate) const DEADLOG_ENTRY_BYTES: usize = 16;
pub(crate) const SHARE_ENTRY_BYTES: usize = 16;
pub(crate) const HOLD_ROW_WORDS: usize = 17;
pub(crate) const KEEP_ROW_WORDS: usize = 8;
pub(crate) const SHARE_ROW_BYTES: usize = POINTER_SIZE + 40;
pub(crate) const WATERMARK_ROW_BYTES: usize = 48;
pub(crate) const RETIRE_ROW_BYTES: usize = POINTER_SIZE + 16;
pub(crate) const MAX_BTREE_DEPTH: usize = 8;
/// Volume-level headroom for one bounded terminal cleanup path.
pub(crate) const CLEANUP_BLOCKS: u64 = MAX_BTREE_DEPTH as u64 + 1;
pub(crate) const NAME_MAX: usize = 255;
pub(crate) const KEY_BYTES: usize = 32;
pub(crate) const NONCE_BYTES: usize = 24;
pub(crate) const TAG_BYTES: usize = 16;
pub(crate) const NAME_BYTES: usize = 32;
pub(crate) const SIGNATURE_BYTES: usize = 64;

// Keyslot area.
pub(crate) const KEYSLOT_COUNT: u64 = 8;
pub(crate) const KEYSLOT_KIND_PASSPHRASE: u32 = 1;
pub(crate) const KEYSLOT_KIND_PLATFORM: u32 = 2;
pub(crate) const KEYSLOT_OFF_NONCE: usize = 0x08;
pub(crate) const KEYSLOT_OFF_SEALED_KEY: usize = 0x20;
pub(crate) const KEYSLOT_OFF_TAG: usize = 0x40;
pub(crate) const KEYSLOT_OFF_PARAMS: usize = 0x50;
pub(crate) const KEYSLOT_OFF_SALT: usize = 0x60;
pub(crate) const KEYSLOT_PARAMS_END: usize = 0x100;
pub(crate) const KEYSLOT_SALT_BYTES: usize = 16;

// Superblock offsets.
pub(crate) const SB_LAYOUT: usize = 0x008;
pub(crate) const SB_INCOMPAT: usize = 0x00C;
pub(crate) const SB_COMPAT_RO: usize = 0x010;
pub(crate) const SB_COMPAT: usize = 0x014;
pub(crate) const SB_FS_UUID: usize = 0x018;
pub(crate) const SB_DEVICE_UUID: usize = 0x028;
pub(crate) const SB_BLOCK_SIZE: usize = 0x038;
pub(crate) const SB_TOTAL_BLOCKS: usize = 0x040;
pub(crate) const SB_BITMAP_START: usize = 0x048;
pub(crate) const SB_BITMAP_BLOCKS: usize = 0x050;
pub(crate) const SB_LOG_START: usize = 0x058;
pub(crate) const SB_LOG_BLOCKS: usize = 0x060;
pub(crate) const SB_TABLE_ROOT: usize = 0x068;
pub(crate) const SB_REGISTRY_ROOT: usize = 0x088;
pub(crate) const SB_CHECKPOINT_SEQ: usize = 0x0A8;
pub(crate) const SB_COMMIT_SEQ: usize = 0x0B0;
pub(crate) const SB_REPLAY_FLOOR: usize = 0x0B8;
pub(crate) const SB_RESERVED_SEQ_HWM: usize = 0x0C0;
pub(crate) const SB_LOG_CYCLE: usize = 0x0C8;
pub(crate) const SB_LOG_HEAD: usize = 0x0D0;
pub(crate) const SB_VOLUME_INCARNATION: usize = 0x0D8;
pub(crate) const SB_SUBVOL_ID_HWM: usize = 0x0E0;
pub(crate) const SB_PROVIDER_GENERATION: usize = 0x0E8;
pub(crate) const SB_LAST_MOUNT_TIME: usize = 0x0F0;
pub(crate) const SB_LAST_WRITE_TIME: usize = 0x0F8;
pub(crate) const SB_LAST_CERTIFICATE: usize = 0x100;
pub(crate) const SB_STATE: usize = 0x110;
pub(crate) const SB_CASEFOLD_VERSION: usize = 0x114;
pub(crate) const SB_LABEL: usize = 0x118;
pub(crate) const SB_SUITE: usize = 0x158;
pub(crate) const SB_KDF_SALT: usize = 0x160;
pub(crate) const SB_KEYSLOT_START: usize = 0x180;
pub(crate) const SB_KEYSLOT_BLOCKS: usize = 0x188;
pub(crate) const SB_STORE_PUBLIC_KEY: usize = 0x190;
pub(crate) const SB_CHUNK_MIN: usize = 0x1B0;
pub(crate) const SB_CHUNK_TARGET: usize = 0x1B4;
pub(crate) const SB_CHUNK_MAX: usize = 0x1B8;
pub(crate) const SB_CHUNK_MASK_S: usize = 0x1C0;
pub(crate) const SB_CHUNK_MASK_L: usize = 0x1C8;
pub(crate) const SB_RESERVED: usize = 0x1D0;
pub(crate) const SB_TAG: usize = 0xFF0;
/// The publisher raises the reservation high-water mark in this window.
pub(crate) const RESERVATION_WINDOW: u64 = 256;

/// The image writer's single publication.
pub(crate) const INITIAL_SEQ: u64 = 1;

/// The key derivation contexts of the volume keys.
const IMAGE_KEY_CONTEXT: &[u8] = b"SaltyFS format 2 image key";
const DIR_MASTER_CONTEXT: &[u8] = b"SaltyFS format 2 directory-hash master";
const NAME_KEY_CONTEXT: &[u8] = b"SaltyFS format 2 name key";
const IMAGE_NONCE_PREFIX: &[u8; 8] = b"SLTYIMG\0";

pub fn fnv1a(name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Padmé's padded length for `length`.
pub const fn padme(length: u64) -> u64 {
    if length < 2 { return length; }
    let e = 63 - length.leading_zeros() as u64;
    let s = (63 - e.leading_zeros() as u64) + 1;
    let m = (1u64 << (e - s)) - 1;
    (length + m) & !m
}

// ---------------------------------------------------------------------------
// Little-endian field access
// ---------------------------------------------------------------------------

pub(crate) fn get16(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }
pub(crate) fn get32(b: &[u8], off: usize) -> u32 { u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) }
pub(crate) fn get64(b: &[u8], off: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(x)
}
pub(crate) fn put16(b: &mut [u8], off: usize, v: u16) { b[off..off + 2].copy_from_slice(&v.to_le_bytes()); }
pub(crate) fn put32(b: &mut [u8], off: usize, v: u32) { b[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
pub(crate) fn put64(b: &mut [u8], off: usize, v: u64) { b[off..off + 8].copy_from_slice(&v.to_le_bytes()); }

// ---------------------------------------------------------------------------
// Keys and pointers
// ---------------------------------------------------------------------------

/// A tree key. The derived order is the numeric field-by-field order the
/// format requires; the little-endian bytes are never compared directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub locality: u64,
    pub objectid: u64,
    pub ty: u8,
    pub offset: u64,
}

impl Key {
    pub const fn new(locality: u64, objectid: u64, ty: u8, offset: u64) -> Self { Self { locality, objectid, ty, offset } }

    pub(crate) fn pack(self) -> [u8; KEY_SIZE] {
        let mut k = [0u8; KEY_SIZE];
        put64(&mut k, 0, self.locality);
        put64(&mut k, 8, self.objectid);
        k[16] = self.ty;
        put64(&mut k, 17, self.offset);
        k
    }

    pub(crate) fn unpack(k: &[u8]) -> Self { Self { locality: get64(k, 0), objectid: get64(k, 8), ty: k[16], offset: get64(k, 17) } }
}

/// A block pointer: an image's address, birth and referencing tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    pub address: u64,
    pub birth: u64,
    pub tag: [u8; 16],
}

impl Pointer {
    pub const NULL: Pointer = Pointer { address: 0, birth: 0, tag: [0; 16] };

    pub fn is_null(&self) -> bool { self.address == 0 }

    pub(crate) fn pack(&self) -> [u8; POINTER_SIZE] {
        let mut p = [0u8; POINTER_SIZE];
        if self.is_null() { return p; }
        put64(&mut p, 0, self.address);
        put64(&mut p, 8, self.birth);
        p[16..32].copy_from_slice(&self.tag);
        p
    }

    /// Decode one pointer: a null pointer is all zero and an address keeps
    /// bits 48–63 clear.
    pub(crate) fn unpack(p: &[u8]) -> Result<Self, String> {
        let address = get64(p, 0);
        if address == 0 {
            if p[..POINTER_SIZE].iter().any(|b| *b != 0) { return Err("null pointer with nonzero bytes".into()); }
            return Ok(Self::NULL);
        }
        if address >> 48 != 0 { return Err(format!("pointer to block {address} names a nonzero vdev")); }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&p[16..32]);
        Ok(Self { address, birth: get64(p, 8), tag })
    }
}

// ---------------------------------------------------------------------------
// Volume keys
// ---------------------------------------------------------------------------

/// What the writer and the verifier hold of a volume's keys: the suite, the
/// directory-hash master, and under an encrypted suite the image and name
/// keys derived from the volume key.
#[derive(Clone, Debug)]
pub struct Keys {
    pub suite: Option<primitives::Suite>,
    pub fs_uuid: [u8; 16],
    pub volume_key: [u8; 32],
    pub image_key: [u8; 32],
    pub name_key: [u8; 32],
    pub dir_master: [u8; 32],
}

impl Keys {
    /// The plain suite: the directory-hash master from the superblock's
    /// KDF salt, no other key.
    pub fn plain(fs_uuid: [u8; 16], kdf_salt: &[u8; 32]) -> Self {
        Self { suite: None, fs_uuid, volume_key: [0; 32], image_key: [0; 32], name_key: [0; 32],
            dir_master: primitives::blake3::derive_key(DIR_MASTER_CONTEXT, kdf_salt) }
    }

    /// An encrypted suite unlocked with `volume_key`.
    pub fn unlocked(suite: primitives::Suite, fs_uuid: [u8; 16], volume_key: [u8; 32]) -> Self {
        Self { suite: Some(suite), fs_uuid, volume_key,
            image_key: primitives::blake3::derive_key(IMAGE_KEY_CONTEXT, &volume_key),
            name_key: primitives::blake3::derive_key(NAME_KEY_CONTEXT, &volume_key),
            dir_master: primitives::blake3::derive_key(DIR_MASTER_CONTEXT, &volume_key) }
    }

    fn image_nonce(address: u64, birth: u64) -> [u8; NONCE_BYTES] {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..8].copy_from_slice(IMAGE_NONCE_PREFIX);
        nonce[8..16].copy_from_slice(&address.to_le_bytes());
        nonce[16..].copy_from_slice(&birth.to_le_bytes());
        nonce
    }

    fn image_ad(&self, address: u64, birth: u64) -> [u8; 32] {
        let mut ad = [0u8; 32];
        ad[..16].copy_from_slice(&self.fs_uuid);
        ad[16..24].copy_from_slice(&address.to_le_bytes());
        ad[24..].copy_from_slice(&birth.to_le_bytes());
        ad
    }

    /// Seal `image` for the device at `(address, birth)`; returns the
    /// referencing tag. A plain volume leaves the image and tags it xxh3.
    pub fn seal_image(&self, image: &mut [u8], address: u64, birth: u64) -> [u8; 16] {
        match self.suite {
            None => xxh3::hash128(image),
            Some(suite) => suite.seal(&self.image_key, &Self::image_nonce(address, birth), &self.image_ad(address, birth), image),
        }
    }

    /// Verify and open `image` read from the device.
    pub fn open_image(&self, image: &mut [u8], address: u64, birth: u64, tag: &[u8; 16]) -> Result<(), String> {
        match self.suite {
            None => if xxh3::hash128(image) == *tag { Ok(()) } else { Err("tag mismatch".into()) },
            Some(suite) => suite.open(&self.image_key, &Self::image_nonce(address, birth), &self.image_ad(address, birth), image, tag)
                .map_err(|_| "tag mismatch".to_string()),
        }
    }

    /// The keyed SipHash key of one directory.
    pub fn dir_key(&self, subvol: u64, objectid: u64) -> [u8; 16] {
        let mut input = [0u8; 16];
        input[..8].copy_from_slice(&subvol.to_le_bytes());
        input[8..].copy_from_slice(&objectid.to_le_bytes());
        let digest = primitives::blake3::keyed_hash(&self.dir_master, &input);
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        key
    }

    /// The directory-hash plugin over `bytes`.
    pub fn dir_hash(&self, plugin: u8, subvol: u64, objectid: u64, bytes: &[u8]) -> u64 {
        match plugin {
            DIR_HASH_SIPHASH => primitives::siphash24(&self.dir_key(subvol, objectid), bytes),
            _ => fnv1a(bytes),
        }
    }
}

/// The keyslot the writer enrolls: a passphrase under Argon2id, or a raw
/// volume key given directly (no slot is then written; the verifier is
/// given the key).
#[derive(Clone, Debug)]
pub enum Unlock {
    Passphrase { passphrase: Vec<u8>, memory_kib: u32, iterations: u32, lanes: u32 },
    VolumeKey([u8; 32]),
}

/// The choices beyond `FsSpec` a build makes.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// `None` is the plain suite.
    pub suite: Option<primitives::Suite>,
    pub unlock: Option<Unlock>,
    /// The compression plugin of every file: `COMPRESSION_*`.
    pub compression: u8,
    /// Seal the default subvolume into the store at build time.
    pub seal: bool,
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

pub enum FileSource {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

impl FileSource {
    pub(crate) fn size(&self) -> Result<u64, String> {
        match self {
            FileSource::Bytes(b) => Ok(b.len() as u64),
            FileSource::Path(p) => std::fs::metadata(p).map(|m| m.len()).map_err(|e| format!("cannot stat {}: {}", p.display(), e)),
        }
    }

    pub(crate) fn sha256(&self) -> Result<String, String> {
        match self {
            FileSource::Bytes(b) => Ok(sha256::hash_bytes(b)),
            FileSource::Path(p) => sha256::hash_file(p),
        }
    }

    /// The whole content.
    pub(crate) fn inline_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            FileSource::Bytes(b) => Ok(b.clone()),
            FileSource::Path(p) => std::fs::read(p).map_err(|e| format!("cannot read {}: {}", p.display(), e)),
        }
    }
}

pub struct FsSpec {
    pub size_bytes: u64,
    pub label: String,
    pub epoch_secs: u64,
    /// `epoch_secs` came from a declared clock (`SOURCE_DATE_EPOCH`) rather
    /// than the fallback; a sealed image records it as a valid seal clock.
    pub clock_valid: bool,
    pub casefold_root: bool,
    /// Extra incompat bits (feature-rejection test images).
    pub extra_incompat: u32,
    pub compat_ro_flags: u32,
    pub casefold_version: u32,
}

pub struct Contents {
    /// (destination path, source) in placement order.
    pub files: Vec<(String, FileSource)>,
    pub empty_dirs: Vec<String>,
    /// (destination path, target bytes).
    pub symlinks: Vec<(String, Vec<u8>)>,
    /// Destination paths among `symlinks` whose target is a directory, as
    /// a Win32 directory link's is; their inodes and seal entries carry the
    /// directory-link flag.
    pub directory_links: Vec<String>,
    pub permissions: Permissions,
}

// ---------------------------------------------------------------------------
// Item packing
// ---------------------------------------------------------------------------

pub(crate) struct InodeFields {
    pub(crate) size: u64,
    pub(crate) blocks: u64,
    pub(crate) nlink: u32,
    pub(crate) owner: u64,
    pub(crate) group: u64,
    pub(crate) mode: u32,
    pub(crate) time_ns: u64,
    pub(crate) incarnation: u64,
    pub(crate) flags: u32,
    pub(crate) hidden_owner: u64,
    pub(crate) plugin: [u8; 4],
    pub(crate) project_id: u32,
}

/// The root's declared case axis and insensitive normalization, inherited by
/// every child directory. Item inodes, seal entries and the commit agree on them.
pub(crate) fn writer_directory_axes(root_case_axis: u8) -> (u8, u8) {
    (root_case_axis, AXIS_INSENSITIVE)
}

/// The axis bits and the `CASEFOLD` projection of a directory.
pub(crate) fn axis_flags(case_axis: u8, norm_axis: u8) -> u32 {
    let mut flags = ((case_axis as u32) << INODE_CASE_AXIS_SHIFT) | ((norm_axis as u32) << INODE_NORM_AXIS_SHIFT);
    if case_axis != AXIS_SENSITIVE { flags |= INODE_CASEFOLD; }
    flags
}

pub(crate) fn pack_inode(f: &InodeFields, birth: u64) -> Vec<u8> {
    let mut out = vec![0u8; INODE_SIZE];
    put64(&mut out, 0x00, birth);
    put64(&mut out, 0x08, f.size);
    put64(&mut out, 0x10, f.blocks);
    put64(&mut out, 0x18, f.owner);
    put64(&mut out, 0x20, f.group);
    for at in [0x28, 0x30, 0x38, 0x40] { put64(&mut out, at, f.time_ns); }
    put64(&mut out, 0x48, f.incarnation);
    put64(&mut out, 0x50, birth);
    put64(&mut out, 0x58, birth);
    put64(&mut out, 0x60, f.hidden_owner);
    put32(&mut out, 0x68, f.mode);
    put32(&mut out, 0x6C, f.nlink);
    put32(&mut out, 0x70, f.flags);
    out[0x74..0x78].copy_from_slice(&f.plugin);
    put32(&mut out, 0x78, f.project_id);
    out
}

pub(crate) fn pack_dir_item(target: (u64, u64), name: &[u8], dir_type: u8) -> Vec<u8> {
    let mut out = vec![0u8; DIR_ITEM_HEADER_SIZE + name.len()];
    put64(&mut out, 0, target.0);
    put64(&mut out, 8, target.1);
    put16(&mut out, 16, name.len() as u16);
    out[18] = dir_type;
    out[DIR_ITEM_HEADER_SIZE..].copy_from_slice(name);
    out
}

pub(crate) fn pack_dir_class(first_member: u64, member_count: u64) -> Vec<u8> {
    let mut out = vec![0u8; DIR_CLASS_BYTES];
    put64(&mut out, 0, first_member);
    put64(&mut out, 8, member_count);
    out
}

pub(crate) fn pack_dir_member(class_offset: u64, next_member: u64, target: (u64, u64), name: &[u8], dir_type: u8) -> Vec<u8> {
    let mut out = vec![0u8; DIR_MEMBER_HEADER_SIZE + name.len()];
    put64(&mut out, 0, class_offset);
    put64(&mut out, 8, next_member);
    put64(&mut out, 16, target.0);
    put64(&mut out, 24, target.1);
    put16(&mut out, 32, name.len() as u16);
    out[34] = dir_type;
    out[DIR_MEMBER_HEADER_SIZE..].copy_from_slice(name);
    out
}

/// A directory's name policy: its two axes and its hash plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) case_axis: u8,
    pub(crate) norm_axis: u8,
    pub(crate) plugin: u8,
}

impl Policy {
    pub(crate) fn of_flags(flags: u32, plugin: u8) -> Self {
        Self { case_axis: ((flags >> INODE_CASE_AXIS_SHIFT) & 3) as u8, norm_axis: ((flags >> INODE_NORM_AXIS_SHIFT) & 3) as u8, plugin }
    }
    pub(crate) fn is_byte(&self) -> bool { self.case_axis == AXIS_SENSITIVE && self.norm_axis == AXIS_SENSITIVE }
    /// The indexed key applies every non-sensitive axis.
    pub(crate) fn indexed_key(&self, name: &[u8]) -> Result<Vec<u8>, String> {
        casefold::key(
            name,
            self.norm_axis != AXIS_SENSITIVE,
            self.case_axis != AXIS_SENSITIVE,
        )
    }

    /// The uniqueness key applies only the insensitive axes.
    pub(crate) fn unique_key(&self, name: &[u8]) -> Result<Vec<u8>, String> {
        casefold::key(
            name,
            self.norm_axis == AXIS_INSENSITIVE,
            self.case_axis == AXIS_INSENSITIVE,
        )
    }
}

/// The `DIR_ITEM` key offset of `name` in a directory: the hash of the
/// stored bytes in a byte directory, of the indexed key otherwise.
pub(crate) fn dir_item_offset(
    keys: &Keys,
    subvol: u64,
    dir: u64,
    policy: Policy,
    name: &[u8],
) -> Result<u64, String> {
    Ok(keys.dir_hash(policy.plugin, subvol, dir, &policy.indexed_key(name)?))
}

/// The `INODE_REF` offset of `name` under `parent`: the hash over the
/// parent, the two policy bytes, the key length, the key, then the name.
pub(crate) fn reference_offset(
    keys: &Keys,
    subvol: u64,
    parent: (u64, u64),
    policy: Policy,
    name: &[u8],
) -> Result<u64, String> {
    let key = policy.indexed_key(name)?;
    let mut input = Vec::with_capacity(20 + key.len() + 2 + name.len());
    input.extend_from_slice(&parent.0.to_le_bytes());
    input.extend_from_slice(&parent.1.to_le_bytes());
    input.push(policy.case_axis);
    input.push(policy.norm_axis);
    input.extend_from_slice(&(key.len() as u16).to_le_bytes());
    input.extend_from_slice(&key);
    input.extend_from_slice(&(name.len() as u16).to_le_bytes());
    input.extend_from_slice(name);
    Ok(keys.dir_hash(policy.plugin, subvol, parent.1, &input))
}

/// An INODE_REF: the parent prefix leading the payload.
pub(crate) fn pack_inode_ref(parent: (u64, u64), name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; INODE_REF_HEADER_SIZE + name.len()];
    put64(&mut out, 0, parent.0);
    put64(&mut out, 8, parent.1);
    out[INODE_REF_HEADER_SIZE..].copy_from_slice(name);
    out
}

pub(crate) fn pack_extent_inline(data: &[u8], birth: u64) -> Vec<u8> {
    let mut out = vec![0u8; EXTENT_HEADER_SIZE + data.len()];
    put64(&mut out, 0x00, birth);
    put64(&mut out, 0x08, data.len() as u64);
    out[0x20] = EXTENT_INLINE;
    out[EXTENT_HEADER_SIZE..].copy_from_slice(data);
    out
}

pub(crate) fn pack_extent_regular(logical: u64, address: u64, stored: u64, birth: u64, compression: u8) -> Vec<u8> {
    let mut out = vec![0u8; EXTENT_HEADER_SIZE];
    put64(&mut out, 0x00, birth);
    put64(&mut out, 0x08, logical);
    put64(&mut out, 0x10, address);
    put64(&mut out, 0x18, stored);
    out[0x20] = EXTENT_REGULAR;
    out[0x21] = compression;
    out
}

pub(crate) fn pack_extent_absent(logical: u64, chunk: &[u8; 32], birth: u64) -> Vec<u8> {
    let mut out = vec![0u8; EXTENT_HEADER_SIZE + 32];
    put64(&mut out, 0x00, birth);
    put64(&mut out, 0x08, logical);
    out[0x20] = EXTENT_ABSENT;
    out[EXTENT_HEADER_SIZE..].copy_from_slice(chunk);
    out
}

pub(crate) fn pack_object_index(locality: u64, incarnation: u64) -> Vec<u8> {
    let mut out = vec![0u8; 16];
    put64(&mut out, 0, locality);
    put64(&mut out, 8, incarnation);
    out
}

pub(crate) fn pack_data_tags(tags: &[[u8; 16]]) -> Vec<u8> { tags.iter().flat_map(|t| t.iter().copied()).collect() }

/// A `PROJECT_ITEM` holding a project's use and no limits.
pub(crate) fn pack_project(blocks_used: u64, objects_used: u64) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    put64(&mut out, 0, blocks_used);
    put64(&mut out, 8, objects_used);
    out
}

/// An `SKEY_ITEM`: the name, its admission epoch and, under an encrypted
/// suite, the object key.
pub(crate) fn pack_skey(name: &[u8; 32], admission_epoch: u64, key: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = name.to_vec();
    out.extend_from_slice(&admission_epoch.to_le_bytes());
    if let Some(key) = key { out.extend_from_slice(key); }
    out
}

/// The key-tree indexing of a seal object's name: three little-endian words
/// of the name select the key.
pub(crate) fn skey_key(name: &[u8; 32]) -> Key {
    Key::new(get64(name, 0), get64(name, 8), ITEM_SKEY, get64(name, 16))
}

pub(crate) fn pack_commit_signature(commit: &[u8; 32], signature: &[u8; 64]) -> Vec<u8> {
    let mut out = commit.to_vec();
    out.extend_from_slice(signature);
    out
}

/// The fields of one subvolume-table row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubvolRow {
    pub(crate) uuid: [u8; 16],
    pub(crate) incarnation: u64,
    pub(crate) item_root: Pointer,
    pub(crate) index_root: Pointer,
    pub(crate) tag_root: Pointer,
    pub(crate) objectid_hwm: u64,
    pub(crate) incarnation_hwm: u64,
    pub(crate) publish_seq: u64,
    pub(crate) origin: (u64, u64),
    pub(crate) owner: (u64, u64),
    pub(crate) limits: [u64; 4],
    pub(crate) referenced: u64,
    pub(crate) owned: u64,
    pub(crate) retained_charge: u64,
    pub(crate) catalog_id_hwm: u64,
    pub(crate) retain_pinned: u32,
    pub(crate) state: u32,
    pub(crate) flags: u32,
    pub(crate) label: [u8; 32],
    pub(crate) sealed_head: [u8; 32],
}

/// Quota, refquota, reservation, refreservation admissibility.
pub(crate) fn valid_limits(l: [u64; 4]) -> bool { l[0] != 0 && l[1] != 0 && l[1] <= l[0] && l[2] <= l[0] && l[3] <= l[1] }

impl SubvolRow {
    pub(crate) fn pack(&self) -> Vec<u8> {
        let mut out = vec![0u8; SUBVOL_ROW_SIZE];
        out[0x000..0x010].copy_from_slice(&self.uuid);
        put64(&mut out, 0x010, self.incarnation);
        out[0x018..0x038].copy_from_slice(&self.item_root.pack());
        out[0x038..0x058].copy_from_slice(&self.index_root.pack());
        out[0x058..0x078].copy_from_slice(&self.tag_root.pack());
        put64(&mut out, 0x078, self.objectid_hwm);
        put64(&mut out, 0x080, self.incarnation_hwm);
        put64(&mut out, 0x088, self.publish_seq);
        put64(&mut out, 0x090, self.origin.0);
        put64(&mut out, 0x098, self.origin.1);
        put64(&mut out, 0x0A0, self.owner.0);
        put64(&mut out, 0x0A8, self.owner.1);
        for (i, limit) in self.limits.iter().enumerate() { put64(&mut out, 0x0B0 + i * 8, *limit); }
        put64(&mut out, 0x0D0, self.referenced);
        put64(&mut out, 0x0D8, self.owned);
        put64(&mut out, 0x0E0, self.retained_charge);
        put64(&mut out, 0x0E8, self.catalog_id_hwm);
        put32(&mut out, 0x0F0, self.retain_pinned);
        put32(&mut out, 0x0F4, self.state);
        put32(&mut out, 0x0F8, self.flags);
        out[0x100..0x120].copy_from_slice(&self.label);
        out[0x120..0x140].copy_from_slice(&self.sealed_head);
        out
    }

    pub(crate) fn unpack(data: &[u8]) -> Result<Self, String> {
        if data.len() != SUBVOL_ROW_SIZE { return Err(format!("subvolume row has {} bytes, expected {}", data.len(), SUBVOL_ROW_SIZE)); }
        if data[0x0FC..0x100].iter().any(|b| *b != 0) { return Err("subvolume row selects an unsupported plugin default".into()); }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&data[..16]);
        let mut label = [0u8; 32];
        label.copy_from_slice(&data[0x100..0x120]);
        let mut sealed_head = [0u8; 32];
        sealed_head.copy_from_slice(&data[0x120..0x140]);
        let row = Self {
            uuid, incarnation: get64(data, 0x010),
            item_root: Pointer::unpack(&data[0x018..0x038])?, index_root: Pointer::unpack(&data[0x038..0x058])?, tag_root: Pointer::unpack(&data[0x058..0x078])?,
            objectid_hwm: get64(data, 0x078), incarnation_hwm: get64(data, 0x080), publish_seq: get64(data, 0x088),
            origin: (get64(data, 0x090), get64(data, 0x098)), owner: (get64(data, 0x0A0), get64(data, 0x0A8)),
            limits: [get64(data, 0x0B0), get64(data, 0x0B8), get64(data, 0x0C0), get64(data, 0x0C8)],
            referenced: get64(data, 0x0D0), owned: get64(data, 0x0D8), retained_charge: get64(data, 0x0E0), catalog_id_hwm: get64(data, 0x0E8),
            retain_pinned: get32(data, 0x0F0), state: get32(data, 0x0F4), flags: get32(data, 0x0F8), label, sealed_head,
        };
        if row.flags & !SUBVOL_FLAGS_DEFINED != 0 { return Err("subvolume row flags".into()); }
        if row.state != SUBVOL_STATE_LIVE && row.state != SUBVOL_STATE_CLOSING { return Err(format!("subvolume row state {}", row.state)); }
        if (row.owner.0 == 0) != (row.owner.1 == 0) { return Err("subvolume row owner and incarnation disagree".into()); }
        if row.limits != [0; 4] && !valid_limits(row.limits) { return Err("subvolume row limits".into()); }
        if row.flags & SUBVOL_FLAG_STORE != 0 && row.flags & SUBVOL_FLAG_NOSEAL == 0 { return Err("store subvolume without NOSEAL".into()); }
        Ok(row)
    }
}

/// One snapshot row of the pin registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SnapRow {
    pub(crate) snapshot_id: u64,
    pub(crate) item_root: Pointer,
    pub(crate) index_root: Pointer,
    pub(crate) tag_root: Pointer,
    pub(crate) objectid_hwm: u64,
    pub(crate) incarnation_hwm: u64,
    pub(crate) creation_time: u64,
    pub(crate) deadlog_root: Pointer,
    pub(crate) deadlog_cursor: u64,
    pub(crate) owner: (u64, u64),
    pub(crate) state: u32,
    pub(crate) holds: u32,
    pub(crate) flags: u32,
    pub(crate) seal_time: u64,
    pub(crate) commit_name: [u8; 32],
}

impl SnapRow {
    pub(crate) fn pack(&self) -> Vec<u8> {
        let mut out = vec![0u8; SNAP_ROW_SIZE];
        put64(&mut out, 0x00, self.snapshot_id);
        out[0x08..0x28].copy_from_slice(&self.item_root.pack());
        out[0x28..0x48].copy_from_slice(&self.index_root.pack());
        out[0x48..0x68].copy_from_slice(&self.tag_root.pack());
        put64(&mut out, 0x68, self.objectid_hwm);
        put64(&mut out, 0x70, self.incarnation_hwm);
        put64(&mut out, 0x78, self.creation_time);
        out[0x80..0xA0].copy_from_slice(&self.deadlog_root.pack());
        put64(&mut out, 0xA0, self.deadlog_cursor);
        put64(&mut out, 0xA8, self.owner.0);
        put64(&mut out, 0xB0, self.owner.1);
        put32(&mut out, 0xB8, self.state);
        put32(&mut out, 0xBC, self.holds);
        put32(&mut out, 0xC0, self.flags);
        put64(&mut out, 0xC8, self.seal_time);
        out[0xD0..0xF0].copy_from_slice(&self.commit_name);
        out
    }

    pub(crate) fn unpack(data: &[u8]) -> Result<Self, String> {
        if data.len() != SNAP_ROW_SIZE { return Err(format!("snapshot row has {} bytes, expected {}", data.len(), SNAP_ROW_SIZE)); }
        if get32(data, 0xC4) != 0 { return Err("snapshot row reserved word is nonzero".into()); }
        let mut commit_name = [0u8; 32];
        commit_name.copy_from_slice(&data[0xD0..0xF0]);
        let row = Self {
            snapshot_id: get64(data, 0x00),
            item_root: Pointer::unpack(&data[0x08..0x28])?, index_root: Pointer::unpack(&data[0x28..0x48])?, tag_root: Pointer::unpack(&data[0x48..0x68])?,
            objectid_hwm: get64(data, 0x68), incarnation_hwm: get64(data, 0x70), creation_time: get64(data, 0x78),
            deadlog_root: Pointer::unpack(&data[0x80..0xA0])?, deadlog_cursor: get64(data, 0xA0), owner: (get64(data, 0xA8), get64(data, 0xB0)),
            state: get32(data, 0xB8), holds: get32(data, 0xBC), flags: get32(data, 0xC0), seal_time: get64(data, 0xC8), commit_name,
        };
        if row.flags & !SNAP_FLAGS_DEFINED != 0 {
            return Err(format!("snapshot row sets undefined flag bits {:#x}", row.flags & !SNAP_FLAGS_DEFINED));
        }
        if row.state == SNAP_STATE_PINNED && row.flags & SNAP_FLAG_CLOCK_VALID != 0 {
            return Err("a pinned snapshot row claims a valid seal clock".into());
        }
        let named = row.commit_name != [0; 32];
        let consistent = match row.state {
            SNAP_STATE_PINNED => row.seal_time == 0 && !named,
            SNAP_STATE_SEALING => row.seal_time != 0 && !named && row.owner.0 != 0,
            SNAP_STATE_SEALED => row.seal_time != 0 && named && row.owner.0 != 0,
            _ => false,
        };
        if !consistent { return Err("snapshot row state, seal time and commit name disagree".into()); }
        Ok(row)
    }
}

/// One keyslot record of an encrypted volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Keyslot {
    pub(crate) kind: u32,
    pub(crate) nonce: [u8; NONCE_BYTES],
    pub(crate) sealed_key: [u8; KEY_BYTES],
    pub(crate) tag: [u8; TAG_BYTES],
    pub(crate) params: [u8; KEYSLOT_PARAMS_END - KEYSLOT_OFF_PARAMS],
}

impl Keyslot {
    pub(crate) fn associated_data(fs_uuid: &[u8; 16], slot: u32) -> [u8; 20] {
        let mut ad = [0u8; 20];
        ad[..16].copy_from_slice(fs_uuid);
        put32(&mut ad, 16, slot);
        ad
    }

    pub(crate) fn passphrase(nonce: [u8; NONCE_BYTES], sealed_key: [u8; KEY_BYTES], tag: [u8; TAG_BYTES], memory_kib: u32, iterations: u32, lanes: u32,
        salt: [u8; KEYSLOT_SALT_BYTES]) -> Self
    {
        let mut params = [0u8; KEYSLOT_PARAMS_END - KEYSLOT_OFF_PARAMS];
        put32(&mut params, 0, memory_kib);
        put32(&mut params, 4, iterations);
        put32(&mut params, 8, lanes);
        params[KEYSLOT_OFF_SALT - KEYSLOT_OFF_PARAMS..KEYSLOT_OFF_SALT - KEYSLOT_OFF_PARAMS + KEYSLOT_SALT_BYTES].copy_from_slice(&salt);
        Self { kind: KEYSLOT_KIND_PASSPHRASE, nonce, sealed_key, tag, params }
    }

    /// `(memory_kib, iterations, lanes, salt)` of a passphrase slot.
    pub(crate) fn passphrase_params(&self) -> Result<(u32, u32, u32, [u8; KEYSLOT_SALT_BYTES]), String> {
        if self.kind != KEYSLOT_KIND_PASSPHRASE || get32(&self.params, 12) != 0 { return Err("not a passphrase slot".into()); }
        let salt_at = KEYSLOT_OFF_SALT - KEYSLOT_OFF_PARAMS;
        if self.params[salt_at + KEYSLOT_SALT_BYTES..].iter().any(|b| *b != 0) { return Err("passphrase slot tail".into()); }
        let mut salt = [0u8; KEYSLOT_SALT_BYTES];
        salt.copy_from_slice(&self.params[salt_at..salt_at + KEYSLOT_SALT_BYTES]);
        let (memory_kib, iterations, lanes) = (get32(&self.params, 0), get32(&self.params, 4), get32(&self.params, 8));
        if memory_kib == 0 || iterations == 0 || lanes == 0 { return Err("passphrase slot parameters are zero".into()); }
        Ok((memory_kib, iterations, lanes, salt))
    }

    pub(crate) fn pack(&self) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE];
        put32(&mut block, 0, self.kind);
        block[KEYSLOT_OFF_NONCE..KEYSLOT_OFF_SEALED_KEY].copy_from_slice(&self.nonce);
        block[KEYSLOT_OFF_SEALED_KEY..KEYSLOT_OFF_TAG].copy_from_slice(&self.sealed_key);
        block[KEYSLOT_OFF_TAG..KEYSLOT_OFF_PARAMS].copy_from_slice(&self.tag);
        block[KEYSLOT_OFF_PARAMS..KEYSLOT_PARAMS_END].copy_from_slice(&self.params);
        block
    }

    /// `Ok(None)` for an unoccupied slot.
    pub(crate) fn unpack(block: &[u8]) -> Result<Option<Self>, String> {
        if block.len() != BLOCK_SIZE { return Err("keyslot block size".into()); }
        let kind = get32(block, 0);
        if kind == 0 {
            if block.iter().any(|b| *b != 0) { return Err("unoccupied keyslot with nonzero bytes".into()); }
            return Ok(None);
        }
        if kind > KEYSLOT_KIND_PLATFORM || get32(block, 4) != 0 || block[KEYSLOT_PARAMS_END..].iter().any(|b| *b != 0) { return Err("keyslot kind or tail".into()); }
        let mut slot = Self { kind, nonce: [0; NONCE_BYTES], sealed_key: [0; KEY_BYTES], tag: [0; TAG_BYTES], params: [0; KEYSLOT_PARAMS_END - KEYSLOT_OFF_PARAMS] };
        slot.nonce.copy_from_slice(&block[KEYSLOT_OFF_NONCE..KEYSLOT_OFF_SEALED_KEY]);
        slot.sealed_key.copy_from_slice(&block[KEYSLOT_OFF_SEALED_KEY..KEYSLOT_OFF_TAG]);
        slot.tag.copy_from_slice(&block[KEYSLOT_OFF_TAG..KEYSLOT_OFF_PARAMS]);
        slot.params.copy_from_slice(&block[KEYSLOT_OFF_PARAMS..KEYSLOT_PARAMS_END]);
        if kind == KEYSLOT_KIND_PASSPHRASE { slot.passphrase_params()?; }
        Ok(Some(slot))
    }
}

// ---------------------------------------------------------------------------
// Superblock
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Superblock {
    pub incompat: u32,
    pub compat_ro: u32,
    pub compat: u32,
    pub fs_uuid: [u8; 16],
    pub device_uuid: [u8; 16],
    pub total_blocks: u64,
    pub bitmap_start: u64,
    pub bitmap_blocks: u64,
    pub log_start: u64,
    pub log_blocks: u64,
    pub table_root: Pointer,
    pub registry_root: Pointer,
    pub checkpoint_seq: u64,
    pub commit_seq: u64,
    pub replay_floor: u64,
    pub reserved_seq_hwm: u64,
    pub log_cycle: u64,
    pub log_head: u64,
    pub volume_incarnation: u64,
    pub subvol_id_hwm: u64,
    pub provider_generation: u64,
    pub last_mount_time: u64,
    pub last_write_time: u64,
    pub last_certificate: [u8; 16],
    pub state: u32,
    pub casefold_version: u32,
    pub label: String,
    pub suite: u32,
    pub kdf_salt: [u8; 32],
    pub keyslot_start: u64,
    pub keyslot_blocks: u64,
    pub store_public_key: [u8; 32],
    pub chunker: codec::fastcdc::Params,
}

/// `(keyslot_start, keyslot_blocks, bitmap_start, bitmap_blocks, log_start, log_blocks)`.
pub type Geometry = (u64, u64, u64, u64, u64, u64);

impl Superblock {
    /// Serialize with the framing tag computed over the preceding bytes.
    pub(crate) fn pack(&self) -> Vec<u8> {
        let mut sb = vec![0u8; BLOCK_SIZE];
        sb[..8].copy_from_slice(MAGIC);
        put32(&mut sb, SB_LAYOUT, LAYOUT);
        put32(&mut sb, SB_INCOMPAT, self.incompat);
        put32(&mut sb, SB_COMPAT_RO, self.compat_ro);
        put32(&mut sb, SB_COMPAT, self.compat);
        sb[SB_FS_UUID..SB_FS_UUID + 16].copy_from_slice(&self.fs_uuid);
        sb[SB_DEVICE_UUID..SB_DEVICE_UUID + 16].copy_from_slice(&self.device_uuid);
        put64(&mut sb, SB_BLOCK_SIZE, BLOCK_SIZE as u64);
        put64(&mut sb, SB_TOTAL_BLOCKS, self.total_blocks);
        put64(&mut sb, SB_BITMAP_START, self.bitmap_start);
        put64(&mut sb, SB_BITMAP_BLOCKS, self.bitmap_blocks);
        put64(&mut sb, SB_LOG_START, self.log_start);
        put64(&mut sb, SB_LOG_BLOCKS, self.log_blocks);
        sb[SB_TABLE_ROOT..SB_TABLE_ROOT + POINTER_SIZE].copy_from_slice(&self.table_root.pack());
        sb[SB_REGISTRY_ROOT..SB_REGISTRY_ROOT + POINTER_SIZE].copy_from_slice(&self.registry_root.pack());
        put64(&mut sb, SB_CHECKPOINT_SEQ, self.checkpoint_seq);
        put64(&mut sb, SB_COMMIT_SEQ, self.commit_seq);
        put64(&mut sb, SB_REPLAY_FLOOR, self.replay_floor);
        put64(&mut sb, SB_RESERVED_SEQ_HWM, self.reserved_seq_hwm);
        put64(&mut sb, SB_LOG_CYCLE, self.log_cycle);
        put64(&mut sb, SB_LOG_HEAD, self.log_head);
        put64(&mut sb, SB_VOLUME_INCARNATION, self.volume_incarnation);
        put64(&mut sb, SB_SUBVOL_ID_HWM, self.subvol_id_hwm);
        put64(&mut sb, SB_PROVIDER_GENERATION, self.provider_generation);
        put64(&mut sb, SB_LAST_MOUNT_TIME, self.last_mount_time);
        put64(&mut sb, SB_LAST_WRITE_TIME, self.last_write_time);
        sb[SB_LAST_CERTIFICATE..SB_LAST_CERTIFICATE + 16].copy_from_slice(&self.last_certificate);
        put32(&mut sb, SB_STATE, self.state);
        put32(&mut sb, SB_CASEFOLD_VERSION, self.casefold_version);
        let label = self.label.as_bytes();
        let n = label.len().min(64);
        sb[SB_LABEL..SB_LABEL + n].copy_from_slice(&label[..n]);
        put32(&mut sb, SB_SUITE, self.suite);
        sb[SB_KDF_SALT..SB_KDF_SALT + 32].copy_from_slice(&self.kdf_salt);
        put64(&mut sb, SB_KEYSLOT_START, self.keyslot_start);
        put64(&mut sb, SB_KEYSLOT_BLOCKS, self.keyslot_blocks);
        sb[SB_STORE_PUBLIC_KEY..SB_STORE_PUBLIC_KEY + 32].copy_from_slice(&self.store_public_key);
        put32(&mut sb, SB_CHUNK_MIN, self.chunker.min);
        put32(&mut sb, SB_CHUNK_TARGET, self.chunker.target);
        put32(&mut sb, SB_CHUNK_MAX, self.chunker.max);
        put64(&mut sb, SB_CHUNK_MASK_S, self.chunker.mask_s);
        put64(&mut sb, SB_CHUNK_MASK_L, self.chunker.mask_l);
        seal_block(&mut sb);
        sb
    }

    /// Decode and validate one copy. Everything a valid copy must satisfy
    /// short of geometry-versus-storage is checked here.
    pub(crate) fn parse(block: &[u8]) -> Result<Self, String> {
        if block.len() != BLOCK_SIZE { return Err("truncated superblock".into()); }
        if &block[..8] != MAGIC { return Err("bad superblock magic".into()); }
        if get32(block, SB_LAYOUT) != LAYOUT { return Err(format!("layout {} is not layout 2", get32(block, SB_LAYOUT))); }
        if !tag_matches(&block[..SB_TAG], &block[SB_TAG..]) { return Err("superblock tag mismatch".into()); }
        if get64(block, SB_BLOCK_SIZE) != BLOCK_SIZE as u64 { return Err("block size is not 4096".into()); }
        if get32(block, SB_SUITE + 4) != 0 || get32(block, SB_CHUNK_MAX + 4) != 0 || block[SB_RESERVED..SB_TAG].iter().any(|b| *b != 0) {
            return Err("superblock reserved bytes are nonzero".into());
        }
        let suite = get32(block, SB_SUITE);
        if suite > SUITE_XAES_256_GCM { return Err(format!("unknown suite {suite}")); }
        let state = get32(block, SB_STATE);
        if state != STATE_CLEAN && state != STATE_DIRTY { return Err(format!("superblock state {state}")); }
        let commit_seq = get64(block, SB_COMMIT_SEQ);
        let replay_floor = get64(block, SB_REPLAY_FLOOR);
        if state == STATE_CLEAN && replay_floor != commit_seq { return Err("CLEAN superblock whose replay floor lags its commit sequence".into()); }
        if replay_floor > commit_seq { return Err("replay floor above commit sequence".into()); }
        if commit_seq == 0 || get64(block, SB_CHECKPOINT_SEQ) == 0 || get64(block, SB_VOLUME_INCARNATION) == 0 || get64(block, SB_LOG_CYCLE) == 0
            || get64(block, SB_PROVIDER_GENERATION) == 0 {
            return Err("superblock sequence, cycle, incarnation or generation is zero".into());
        }
        if get64(block, SB_RESERVED_SEQ_HWM) < commit_seq { return Err("reservation high-water mark below commit sequence".into()); }
        if get64(block, SB_SUBVOL_ID_HWM) < FIRST_USER_SUBVOL { return Err("subvolume id high-water mark below 256".into()); }
        let mut fs_uuid = [0u8; 16];
        fs_uuid.copy_from_slice(&block[SB_FS_UUID..SB_FS_UUID + 16]);
        let mut device_uuid = [0u8; 16];
        device_uuid.copy_from_slice(&block[SB_DEVICE_UUID..SB_DEVICE_UUID + 16]);
        let mut last_certificate = [0u8; 16];
        last_certificate.copy_from_slice(&block[SB_LAST_CERTIFICATE..SB_LAST_CERTIFICATE + 16]);
        let mut kdf_salt = [0u8; 32];
        kdf_salt.copy_from_slice(&block[SB_KDF_SALT..SB_KDF_SALT + 32]);
        let mut store_public_key = [0u8; 32];
        store_public_key.copy_from_slice(&block[SB_STORE_PUBLIC_KEY..SB_STORE_PUBLIC_KEY + 32]);
        let label_raw = &block[SB_LABEL..SB_LABEL + 64];
        let label_end = label_raw.iter().position(|&b| b == 0).unwrap_or(64);
        let table_root = Pointer::unpack(&block[SB_TABLE_ROOT..SB_TABLE_ROOT + POINTER_SIZE])?;
        if table_root.is_null() { return Err("null subvolume table root".into()); }
        let chunker = codec::fastcdc::Params { min: get32(block, SB_CHUNK_MIN), target: get32(block, SB_CHUNK_TARGET), max: get32(block, SB_CHUNK_MAX),
            mask_s: get64(block, SB_CHUNK_MASK_S), mask_l: get64(block, SB_CHUNK_MASK_L) };
        if !chunker.valid() { return Err("superblock chunker parameters".into()); }
        Ok(Superblock {
            incompat: get32(block, SB_INCOMPAT), compat_ro: get32(block, SB_COMPAT_RO), compat: get32(block, SB_COMPAT), fs_uuid, device_uuid,
            total_blocks: get64(block, SB_TOTAL_BLOCKS), bitmap_start: get64(block, SB_BITMAP_START), bitmap_blocks: get64(block, SB_BITMAP_BLOCKS),
            log_start: get64(block, SB_LOG_START), log_blocks: get64(block, SB_LOG_BLOCKS), table_root,
            registry_root: Pointer::unpack(&block[SB_REGISTRY_ROOT..SB_REGISTRY_ROOT + POINTER_SIZE])?,
            checkpoint_seq: get64(block, SB_CHECKPOINT_SEQ), commit_seq, replay_floor, reserved_seq_hwm: get64(block, SB_RESERVED_SEQ_HWM),
            log_cycle: get64(block, SB_LOG_CYCLE), log_head: get64(block, SB_LOG_HEAD), volume_incarnation: get64(block, SB_VOLUME_INCARNATION),
            subvol_id_hwm: get64(block, SB_SUBVOL_ID_HWM), provider_generation: get64(block, SB_PROVIDER_GENERATION),
            last_mount_time: get64(block, SB_LAST_MOUNT_TIME), last_write_time: get64(block, SB_LAST_WRITE_TIME), last_certificate, state,
            casefold_version: get32(block, SB_CASEFOLD_VERSION), label: String::from_utf8_lossy(&label_raw[..label_end]).to_string(),
            suite, kdf_salt, keyslot_start: get64(block, SB_KEYSLOT_START), keyslot_blocks: get64(block, SB_KEYSLOT_BLOCKS), store_public_key, chunker,
        })
    }

    pub fn encrypted(&self) -> bool { self.suite != SUITE_PLAIN }

    /// The geometry the format prescribes for `total_blocks`; the keyslot
    /// area exists under an encrypted suite only.
    pub(crate) fn geometry(total_blocks: u64, encrypted: bool) -> Result<Geometry, String> {
        if total_blocks < 64 { return Err("SaltyFS image too small (needs at least 64 blocks)".to_string()); }
        let keyslot_blocks = if encrypted { KEYSLOT_COUNT } else { 0 };
        let keyslot_start = if encrypted { 2 } else { 0 };
        let bitmap_start = 2 + keyslot_blocks;
        let bitmap_blocks = total_blocks.div_ceil(BLOCK_SIZE as u64 * 8);
        let log_start = bitmap_start + bitmap_blocks;
        let log_blocks = (total_blocks / 8).clamp(8, 16384);
        if log_start + log_blocks + 1 >= total_blocks { return Err("SaltyFS image too small for its log".to_string()); }
        Ok((keyslot_start, keyslot_blocks, bitmap_start, bitmap_blocks, log_start, log_blocks))
    }

    pub(crate) fn first_data_block(&self) -> u64 { self.log_start + self.log_blocks }

    pub(crate) fn is_reserved(&self, block: u64) -> bool {
        block < self.bitmap_start + self.bitmap_blocks || (block >= self.log_start && block < self.log_start + self.log_blocks) || block >= self.total_blocks - 1
    }

    /// The keys a volume's superblock alone yields: the plain suite's, or
    /// `None` for an encrypted volume until it is unlocked.
    pub fn plain_keys(&self) -> Option<Keys> { (!self.encrypted()).then(|| Keys::plain(self.fs_uuid, &self.kdf_salt)) }

    /// Unlock an encrypted volume from the keyslot area with `unlock`.
    pub fn unlock(&self, slots: &[Vec<u8>], unlock: &Unlock) -> Result<Keys, String> {
        let suite = primitives::Suite::from_word(self.suite)?.ok_or("volume is not encrypted")?;
        match unlock {
            Unlock::VolumeKey(key) => Ok(Keys::unlocked(suite, self.fs_uuid, *key)),
            Unlock::Passphrase { passphrase, .. } => {
                for (index, block) in slots.iter().enumerate() {
                    let Some(slot) = Keyslot::unpack(block)? else { continue };
                    if slot.kind != KEYSLOT_KIND_PASSPHRASE { continue; }
                    let (memory_kib, iterations, lanes, salt) = slot.passphrase_params()?;
                    let mut unwrap = [0u8; 32];
                    primitives::argon2::argon2id(passphrase, &salt, iterations, memory_kib, lanes, &mut unwrap)?;
                    let mut key = slot.sealed_key;
                    if suite.open(&unwrap, &slot.nonce, &Keyslot::associated_data(&self.fs_uuid, index as u32), &mut key, &slot.tag).is_ok() {
                        return Ok(Keys::unlocked(suite, self.fs_uuid, key));
                    }
                }
                Err("the passphrase opens no keyslot".into())
            }
        }
    }
}

/// Write a block's framing tag over its first 0xFF0 bytes into its last 16.
pub(crate) fn seal_block(block: &mut [u8]) {
    let tag = xxh3::hash128(&block[..SB_TAG]);
    block[SB_TAG..].copy_from_slice(&tag);
}

pub(crate) fn tag_matches(bytes: &[u8], tag: &[u8]) -> bool { xxh3::hash128(bytes)[..] == tag[..16] }

// ---------------------------------------------------------------------------
// Log record codec
// ---------------------------------------------------------------------------

pub mod log {
    //! Encoders and decoders for the wandering log's record blocks.
    use super::*;

    pub const KIND_ATOM: u32 = 1;
    pub const KIND_CERT: u32 = 2;
    pub const KIND_RESERVE: u32 = 3;
    pub const IMAGE_ENTRY_MAX: usize = 64;
    pub const ALLOC_ENTRY_MAX: usize = 64;
    pub const ROOT_ENTRY_MAX: usize = 8;
    pub const CHARGE_ENTRY_MAX: usize = 8;
    pub const ALLOC_OP_ALLOCATE: u32 = 1;
    pub const ALLOC_OP_FREE: u32 = 2;
    pub const ROOT_KIND_ITEM: u32 = 1;
    pub const ROOT_KIND_INDEX: u32 = 2;
    pub const ROOT_KIND_TAG: u32 = 3;
    pub const ROOT_FLAG_IDENTITY_FOLLOWS: u32 = 1 << 0;
    const OFF_KIND: usize = 0x04;
    const OFF_INCARNATION: usize = 0x08;
    const OFF_CYCLE: usize = 0x10;
    const OFF_LSN: usize = 0x18;
    const OFF_SEQ: usize = 0x20;
    const OFF_FRAGMENT_INDEX: usize = 0x28;
    const OFF_FRAGMENT_COUNT: usize = 0x2C;
    const OFF_PREDECESSOR: usize = 0x30;
    const OFF_IMAGES: usize = 0x050;
    const OFF_ALLOCS: usize = 0x850;
    const OFF_ROOTS: usize = 0xC50;
    const OFF_CHARGES: usize = 0xDD0;
    const OFF_BODY_END: usize = 0xED0;
    const ROOT_ENTRY_SIZE: usize = 48;
    const CHARGE_ENTRY_SIZE: usize = 32;
    const CERT_HWM: usize = 0x40;
    const CERT_FRAGMENTS: usize = 0x48;
    const CERT_IMAGES: usize = 0x4C;
    const CERT_FIRST_LSN: usize = 0x50;
    const CERT_RECORD_BLOCKS: usize = 0x58;
    const CERT_DIGEST: usize = 0x60;
    const CERT_TABLE_ROOT: usize = 0x70;
    const CERT_REGISTRY_ROOT: usize = 0x90;
    const CERT_TIME: usize = 0xB0;
    const CERT_BODY_END: usize = 0xB8;

    /// The fields every record head carries.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Head {
        pub kind: u32,
        pub incarnation: u64,
        pub cycle: u64,
        pub lsn: u64,
        pub seq: u64,
        pub fragment_index: u32,
        pub fragment_count: u32,
        pub predecessor: [u8; 16],
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ImageEntry { pub address: u64, pub birth: u64, pub tag: [u8; 16] }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AllocEntry { pub first: u64, pub count: u32, pub op: u32 }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RootEntry {
        pub subvol: u64,
        pub kind: u32,
        pub pointer: Pointer,
        /// `(objectid_hwm, incarnation_hwm, publish_seq)` when the atom
        /// republishes the subvolume's identity marks.
        pub identity: Option<(u64, u64, u64)>,
    }
    /// The three-part charge of one atom on one subvolume.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ChargeEntry { pub subvol: u64, pub referenced_delta: i64, pub owned_delta: i64, pub retained_delta: i64 }

    #[derive(Clone, Debug, Default)]
    pub struct Fragment {
        pub images: Vec<ImageEntry>,
        pub allocs: Vec<AllocEntry>,
        pub roots: Vec<RootEntry>,
        pub charges: Vec<ChargeEntry>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Certificate {
        pub reserved_seq_hwm: u64,
        pub fragment_count: u32,
        pub image_blocks: u32,
        pub first_lsn: u64,
        pub record_blocks: u64,
        pub digest: [u8; 16],
        pub table_root: Pointer,
        pub registry_root: Pointer,
        pub commit_time: u64,
    }

    fn write_head(block: &mut [u8], head: &Head) {
        block[..4].copy_from_slice(LOG_MAGIC);
        put32(block, OFF_KIND, head.kind);
        put64(block, OFF_INCARNATION, head.incarnation);
        put64(block, OFF_CYCLE, head.cycle);
        put64(block, OFF_LSN, head.lsn);
        put64(block, OFF_SEQ, head.seq);
        put32(block, OFF_FRAGMENT_INDEX, head.fragment_index);
        put32(block, OFF_FRAGMENT_COUNT, head.fragment_count);
        block[OFF_PREDECESSOR..OFF_PREDECESSOR + 16].copy_from_slice(&head.predecessor);
    }

    /// Decode a head; `None` when the block is not a record head of this
    /// volume with a valid tag.
    pub fn parse_head(block: &[u8], incarnation: u64) -> Option<Head> {
        if block.len() != BLOCK_SIZE || &block[..4] != LOG_MAGIC { return None; }
        if get64(block, OFF_INCARNATION) != incarnation { return None; }
        if !tag_matches(&block[..SB_TAG], &block[SB_TAG..]) { return None; }
        let kind = get32(block, OFF_KIND);
        if kind != KIND_ATOM && kind != KIND_CERT && kind != KIND_RESERVE { return None; }
        let mut predecessor = [0u8; 16];
        predecessor.copy_from_slice(&block[OFF_PREDECESSOR..OFF_PREDECESSOR + 16]);
        Some(Head { kind, incarnation, cycle: get64(block, OFF_CYCLE), lsn: get64(block, OFF_LSN), seq: get64(block, OFF_SEQ),
            fragment_index: get32(block, OFF_FRAGMENT_INDEX), fragment_count: get32(block, OFF_FRAGMENT_COUNT), predecessor })
    }

    pub fn record_tag(block: &[u8]) -> [u8; 16] {
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&block[SB_TAG..]);
        tag
    }

    pub fn encode_fragment(head: &Head, fragment: &Fragment) -> Result<Vec<u8>, String> {
        if fragment.images.len() > IMAGE_ENTRY_MAX || fragment.allocs.len() > ALLOC_ENTRY_MAX || fragment.roots.len() > ROOT_ENTRY_MAX
            || fragment.charges.len() > CHARGE_ENTRY_MAX {
            return Err("fragment entry count exceeds the record layout".into());
        }
        let mut block = vec![0u8; BLOCK_SIZE];
        write_head(&mut block, &Head { kind: KIND_ATOM, ..*head });
        put32(&mut block, 0x40, fragment.images.len() as u32);
        put32(&mut block, 0x44, fragment.allocs.len() as u32);
        put32(&mut block, 0x4C, fragment.charges.len() as u32);
        for (i, image) in fragment.images.iter().enumerate() {
            let at = OFF_IMAGES + i * 32;
            put64(&mut block, at, image.address);
            put64(&mut block, at + 8, image.birth);
            block[at + 16..at + 32].copy_from_slice(&image.tag);
        }
        for (i, alloc) in fragment.allocs.iter().enumerate() {
            let at = OFF_ALLOCS + i * 16;
            put64(&mut block, at, alloc.first);
            put32(&mut block, at + 8, alloc.count);
            put32(&mut block, at + 12, alloc.op);
        }
        let mut slot = 0;
        for root in &fragment.roots {
            if slot + root.identity.is_some() as usize >= ROOT_ENTRY_MAX { return Err("root entries with identity marks exceed the record layout".into()); }
            let at = OFF_ROOTS + slot * ROOT_ENTRY_SIZE;
            put64(&mut block, at, root.subvol);
            put32(&mut block, at + 8, root.kind);
            put32(&mut block, at + 12, if root.identity.is_some() { ROOT_FLAG_IDENTITY_FOLLOWS } else { 0 });
            block[at + 16..at + ROOT_ENTRY_SIZE].copy_from_slice(&root.pointer.pack());
            slot += 1;
            if let Some((objectid_hwm, incarnation_hwm, publish_seq)) = root.identity {
                let at = OFF_ROOTS + slot * ROOT_ENTRY_SIZE;
                put64(&mut block, at, objectid_hwm);
                put64(&mut block, at + 8, incarnation_hwm);
                put64(&mut block, at + 16, publish_seq);
                slot += 1;
            }
        }
        put32(&mut block, 0x48, slot as u32);
        for (i, charge) in fragment.charges.iter().enumerate() {
            let at = OFF_CHARGES + i * CHARGE_ENTRY_SIZE;
            put64(&mut block, at, charge.subvol);
            put64(&mut block, at + 8, charge.referenced_delta as u64);
            put64(&mut block, at + 16, charge.owned_delta as u64);
            put64(&mut block, at + 24, charge.retained_delta as u64);
        }
        seal_block(&mut block);
        Ok(block)
    }

    pub fn parse_fragment(block: &[u8]) -> Result<Fragment, String> {
        let images = get32(block, 0x40) as usize;
        let allocs = get32(block, 0x44) as usize;
        let roots = get32(block, 0x48) as usize;
        let charges = get32(block, 0x4C) as usize;
        if images > IMAGE_ENTRY_MAX || allocs > ALLOC_ENTRY_MAX || roots > ROOT_ENTRY_MAX || charges > CHARGE_ENTRY_MAX {
            return Err("fragment entry count exceeds the record layout".into());
        }
        if block[OFF_BODY_END..SB_TAG].iter().any(|b| *b != 0) { return Err("fragment reserved bytes are nonzero".into()); }
        let mut fragment = Fragment::default();
        for i in 0..images {
            let at = OFF_IMAGES + i * 32;
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&block[at + 16..at + 32]);
            fragment.images.push(ImageEntry { address: get64(block, at), birth: get64(block, at + 8), tag });
        }
        for i in 0..allocs {
            let at = OFF_ALLOCS + i * 16;
            let op = get32(block, at + 12);
            if op != ALLOC_OP_ALLOCATE && op != ALLOC_OP_FREE { return Err("allocation entry op".into()); }
            fragment.allocs.push(AllocEntry { first: get64(block, at), count: get32(block, at + 8), op });
        }
        let mut i = 0;
        while i < roots {
            let at = OFF_ROOTS + i * ROOT_ENTRY_SIZE;
            let kind = get32(block, at + 8);
            let flags = get32(block, at + 12);
            if !(1..=3).contains(&kind) || flags & !ROOT_FLAG_IDENTITY_FOLLOWS != 0 { return Err("root entry kind or flags".into()); }
            let pointer = Pointer::unpack(&block[at + 16..at + ROOT_ENTRY_SIZE])?;
            let mut identity = None;
            i += 1;
            if flags & ROOT_FLAG_IDENTITY_FOLLOWS != 0 {
                if i >= roots { return Err("identity marks entry missing".into()); }
                let at = OFF_ROOTS + i * ROOT_ENTRY_SIZE;
                if block[at + 24..at + ROOT_ENTRY_SIZE].iter().any(|b| *b != 0) { return Err("identity marks entry tail".into()); }
                identity = Some((get64(block, at), get64(block, at + 8), get64(block, at + 16)));
                i += 1;
            }
            fragment.roots.push(RootEntry { subvol: get64(block, at), kind, pointer, identity });
        }
        for i in 0..charges {
            let at = OFF_CHARGES + i * CHARGE_ENTRY_SIZE;
            fragment.charges.push(ChargeEntry { subvol: get64(block, at), referenced_delta: get64(block, at + 8) as i64,
                owned_delta: get64(block, at + 16) as i64, retained_delta: get64(block, at + 24) as i64 });
        }
        Ok(fragment)
    }

    pub fn encode_certificate(head: &Head, cert: &Certificate) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE];
        write_head(&mut block, &Head { kind: KIND_CERT, fragment_index: 0, fragment_count: 0, ..*head });
        put64(&mut block, CERT_HWM, cert.reserved_seq_hwm);
        put32(&mut block, CERT_FRAGMENTS, cert.fragment_count);
        put32(&mut block, CERT_IMAGES, cert.image_blocks);
        put64(&mut block, CERT_FIRST_LSN, cert.first_lsn);
        put64(&mut block, CERT_RECORD_BLOCKS, cert.record_blocks);
        block[CERT_DIGEST..CERT_DIGEST + 16].copy_from_slice(&cert.digest);
        block[CERT_TABLE_ROOT..CERT_TABLE_ROOT + POINTER_SIZE].copy_from_slice(&cert.table_root.pack());
        block[CERT_REGISTRY_ROOT..CERT_REGISTRY_ROOT + POINTER_SIZE].copy_from_slice(&cert.registry_root.pack());
        put64(&mut block, CERT_TIME, cert.commit_time);
        seal_block(&mut block);
        block
    }

    pub fn parse_certificate(block: &[u8]) -> Result<Certificate, String> {
        if block[CERT_BODY_END..SB_TAG].iter().any(|b| *b != 0) { return Err("certificate reserved bytes are nonzero".into()); }
        let mut digest = [0u8; 16];
        digest.copy_from_slice(&block[CERT_DIGEST..CERT_DIGEST + 16]);
        let table_root = Pointer::unpack(&block[CERT_TABLE_ROOT..CERT_TABLE_ROOT + POINTER_SIZE])?;
        if table_root.is_null() { return Err("certificate names a null table root".into()); }
        Ok(Certificate { reserved_seq_hwm: get64(block, CERT_HWM), fragment_count: get32(block, CERT_FRAGMENTS), image_blocks: get32(block, CERT_IMAGES),
            first_lsn: get64(block, CERT_FIRST_LSN), record_blocks: get64(block, CERT_RECORD_BLOCKS), digest, table_root,
            registry_root: Pointer::unpack(&block[CERT_REGISTRY_ROOT..CERT_REGISTRY_ROOT + POINTER_SIZE])?, commit_time: get64(block, CERT_TIME) })
    }

    pub fn encode_reserve(head: &Head, new_hwm: u64) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE];
        write_head(&mut block, &Head { kind: KIND_RESERVE, fragment_index: 0, fragment_count: 0, ..*head });
        put64(&mut block, 0x40, new_hwm);
        seal_block(&mut block);
        block
    }

    pub fn parse_reserve(block: &[u8]) -> Result<u64, String> {
        if block[0x48..SB_TAG].iter().any(|b| *b != 0) { return Err("reserve record reserved bytes are nonzero".into()); }
        Ok(get64(block, 0x40))
    }

    /// The certificate's digest: the record tag of every fragment head
    /// followed by the tags of that fragment's images, in ring order.
    pub fn atom_digest(fragments: &[(Vec<u8>, Vec<[u8; 16]>)]) -> [u8; 16] {
        let mut bytes = Vec::new();
        for (head, images) in fragments {
            bytes.extend_from_slice(&record_tag(head));
            for tag in images { bytes.extend_from_slice(tag); }
        }
        xxh3::hash128(&bytes)
    }
}

pub mod xxh3 {
    //! xxh3-128, seed 0, default secret, from the xxHash specification. The
    //! result is returned in canonical form: high 64 bits big-endian, then
    //! low 64 bits big-endian.

    const PRIME32_1: u64 = 0x9E37_79B1;
    const PRIME32_2: u64 = 0x85EB_CA77;
    const PRIME32_3: u64 = 0xC2B2_AE3D;
    const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
    const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
    const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
    const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;
    const PRIME_MX1: u64 = 0x1656_6791_9E37_79F9;
    const PRIME_MX2: u64 = 0x9FB2_1C65_1E98_DF25;

    pub const SECRET: [u8; 192] = [
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad,
        0x1c, 0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3,
        0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc,
        0xff, 0x72, 0x21, 0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6,
        0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65,
        0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19,
        0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8, 0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9,
        0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31,
        0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64, 0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb,
        0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb, 0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0,
        0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16, 0xbe, 0x58, 0x7d,
        0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f,
        0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
    ];

    #[inline]
    fn read64(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes([
            b[at],
            b[at + 1],
            b[at + 2],
            b[at + 3],
            b[at + 4],
            b[at + 5],
            b[at + 6],
            b[at + 7],
        ])
    }

    #[inline]
    fn read32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    #[inline]
    fn mul128(a: u64, b: u64) -> (u64, u64) {
        let p = (a as u128) * (b as u128);
        (p as u64, (p >> 64) as u64)
    }

    #[inline]
    fn mul128_fold64(a: u64, b: u64) -> u64 {
        let (lo, hi) = mul128(a, b);
        lo ^ hi
    }

    #[inline]
    fn avalanche(mut h: u64) -> u64 {
        h ^= h >> 37;
        h = h.wrapping_mul(PRIME_MX1);
        h ^ (h >> 32)
    }

    #[inline]
    fn xxh64_avalanche(mut h: u64) -> u64 {
        h ^= h >> 33;
        h = h.wrapping_mul(PRIME64_2);
        h ^= h >> 29;
        h = h.wrapping_mul(PRIME64_3);
        h ^ (h >> 32)
    }

    #[inline]
    fn mix16(input: &[u8], at: usize, secret: &[u8], sat: usize) -> u64 {
        let lo = read64(input, at);
        let hi = read64(input, at + 8);
        mul128_fold64(lo ^ read64(secret, sat), hi ^ read64(secret, sat + 8))
    }

    #[inline]
    fn mix32(
        acc: (u64, u64),
        input: &[u8],
        a: usize,
        b: usize,
        secret: &[u8],
        sat: usize,
    ) -> (u64, u64) {
        let mut lo = acc.0.wrapping_add(mix16(input, a, secret, sat));
        lo ^= read64(input, b).wrapping_add(read64(input, b + 8));
        let mut hi = acc.1.wrapping_add(mix16(input, b, secret, sat + 16));
        hi ^= read64(input, a).wrapping_add(read64(input, a + 8));
        (lo, hi)
    }

    fn len_0() -> (u64, u64) {
        let s = &SECRET;
        let bitflipl = read64(s, 64) ^ read64(s, 72);
        let bitfliph = read64(s, 80) ^ read64(s, 88);
        (xxh64_avalanche(bitflipl), xxh64_avalanche(bitfliph))
    }

    fn len_1_3(input: &[u8]) -> (u64, u64) {
        let s = &SECRET;
        let len = input.len();
        let c1 = input[0] as u32;
        let c2 = input[len >> 1] as u32;
        let c3 = input[len - 1] as u32;
        let combinedl = (c1 << 16) | (c2 << 24) | c3 | ((len as u32) << 8);
        let combinedh = combinedl.swap_bytes().rotate_left(13);
        let bitflipl = (read32(s, 0) ^ read32(s, 4)) as u64;
        let bitfliph = (read32(s, 8) ^ read32(s, 12)) as u64;
        (
            xxh64_avalanche(combinedl as u64 ^ bitflipl),
            xxh64_avalanche(combinedh as u64 ^ bitfliph),
        )
    }

    fn len_4_8(input: &[u8]) -> (u64, u64) {
        let s = &SECRET;
        let len = input.len();
        let input_lo = read32(input, 0) as u64;
        let input_hi = read32(input, len - 4) as u64;
        let input_64 = input_lo.wrapping_add(input_hi << 32);
        let bitflip = read64(s, 16) ^ read64(s, 24);
        let keyed = input_64 ^ bitflip;
        let (mut lo, mut hi) = mul128(keyed, PRIME64_1.wrapping_add((len as u64) << 2));
        hi = hi.wrapping_add(lo << 1);
        lo ^= hi >> 3;
        lo ^= lo >> 35;
        lo = lo.wrapping_mul(PRIME_MX2);
        lo ^= lo >> 28;
        (lo, avalanche(hi))
    }

    fn len_9_16(input: &[u8]) -> (u64, u64) {
        let s = &SECRET;
        let len = input.len() as u64;
        let bitflipl = read64(s, 32) ^ read64(s, 40);
        let bitfliph = read64(s, 48) ^ read64(s, 56);
        let input_lo = read64(input, 0);
        let mut input_hi = read64(input, input.len() - 8);
        let (mut lo, mut hi) = mul128(input_lo ^ input_hi ^ bitflipl, PRIME64_1);
        lo = lo.wrapping_add((len - 1) << 54);
        input_hi ^= bitfliph;
        hi = hi.wrapping_add(
            input_hi.wrapping_add((input_hi as u32 as u64).wrapping_mul(PRIME32_2 - 1)),
        );
        lo ^= hi.swap_bytes();
        let (mut h_lo, mut h_hi) = mul128(lo, PRIME64_2);
        h_hi = h_hi.wrapping_add(hi.wrapping_mul(PRIME64_2));
        h_lo = avalanche(h_lo);
        h_hi = avalanche(h_hi);
        (h_lo, h_hi)
    }

    fn len_17_128(input: &[u8]) -> (u64, u64) {
        let s = &SECRET;
        let len = input.len();
        let mut acc = ((len as u64).wrapping_mul(PRIME64_1), 0u64);
        if len > 32 {
            if len > 64 {
                if len > 96 {
                    acc = mix32(acc, input, 48, len - 64, s, 96);
                }
                acc = mix32(acc, input, 32, len - 48, s, 64);
            }
            acc = mix32(acc, input, 16, len - 32, s, 32);
        }
        acc = mix32(acc, input, 0, len - 16, s, 0);
        finish_mid(acc, len as u64)
    }

    fn len_129_240(input: &[u8]) -> (u64, u64) {
        let s = &SECRET;
        let len = input.len();
        let mut acc = ((len as u64).wrapping_mul(PRIME64_1), 0u64);
        for i in 0..4 {
            acc = mix32(acc, input, 32 * i, 32 * i + 16, s, 32 * i);
        }
        acc = (avalanche(acc.0), avalanche(acc.1));
        let rounds = len / 32;
        for i in 4..rounds {
            acc = mix32(acc, input, 32 * i, 32 * i + 16, s, 3 + 32 * (i - 4));
        }
        acc = mix32(acc, input, len - 16, len - 32, s, 136 - 17 - 16);
        finish_mid(acc, len as u64)
    }

    fn finish_mid(acc: (u64, u64), len: u64) -> (u64, u64) {
        let lo = acc.0.wrapping_add(acc.1);
        let hi = acc
            .0
            .wrapping_mul(PRIME64_1)
            .wrapping_add(acc.1.wrapping_mul(PRIME64_4))
            .wrapping_add(len.wrapping_mul(PRIME64_2));
        (avalanche(lo), 0u64.wrapping_sub(avalanche(hi)))
    }

    fn accumulate_512(acc: &mut [u64; 8], input: &[u8], at: usize, secret: &[u8], sat: usize) {
        for i in 0..8 {
            let data_val = read64(input, at + 8 * i);
            let data_key = data_val ^ read64(secret, sat + 8 * i);
            acc[i ^ 1] = acc[i ^ 1].wrapping_add(data_val);
            acc[i] = acc[i].wrapping_add((data_key as u32 as u64).wrapping_mul(data_key >> 32));
        }
    }

    fn scramble(acc: &mut [u64; 8], secret: &[u8], sat: usize) {
        for i in 0..8 {
            let key = read64(secret, sat + 8 * i);
            let mut v = acc[i];
            v ^= v >> 47;
            v ^= key;
            v = v.wrapping_mul(PRIME32_1);
            acc[i] = v;
        }
    }

    fn merge_accs(acc: &[u64; 8], secret: &[u8], sat: usize, start: u64) -> u64 {
        let mut result = start;
        for i in 0..4 {
            result = result.wrapping_add(mul128_fold64(
                acc[2 * i] ^ read64(secret, sat + 16 * i),
                acc[2 * i + 1] ^ read64(secret, sat + 16 * i + 8),
            ));
        }
        avalanche(result)
    }

    fn len_long(input: &[u8]) -> (u64, u64) {
        let s = &SECRET;
        let len = input.len();
        let mut acc = [
            PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1,
        ];
        let stripes_per_block = (SECRET.len() - 64) / 8;
        let block_len = 64 * stripes_per_block;
        let blocks = (len - 1) / block_len;
        for n in 0..blocks {
            for stripe in 0..stripes_per_block {
                accumulate_512(&mut acc, input, n * block_len + stripe * 64, s, stripe * 8);
            }
            scramble(&mut acc, s, SECRET.len() - 64);
        }
        let stripes = ((len - 1) - block_len * blocks) / 64;
        for stripe in 0..stripes {
            accumulate_512(
                &mut acc,
                input,
                blocks * block_len + stripe * 64,
                s,
                stripe * 8,
            );
        }
        accumulate_512(&mut acc, input, len - 64, s, SECRET.len() - 64 - 7);
        let lo = merge_accs(&acc, s, 11, (len as u64).wrapping_mul(PRIME64_1));
        let hi = merge_accs(
            &acc,
            s,
            SECRET.len() - 64 - 11,
            !((len as u64).wrapping_mul(PRIME64_2)),
        );
        (lo, hi)
    }

    /// `(low64, high64)` of the xxh3-128 of `input`.
    pub fn hash128_words(input: &[u8]) -> (u64, u64) {
        match input.len() {
            0 => len_0(),
            1..=3 => len_1_3(input),
            4..=8 => len_4_8(input),
            9..=16 => len_9_16(input),
            17..=128 => len_17_128(input),
            129..=240 => len_129_240(input),
            _ => len_long(input),
        }
    }

    /// The canonical 16-byte tag of `input`.
    pub fn hash128(input: &[u8]) -> [u8; 16] {
        let (lo, hi) = hash128_words(input);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&hi.to_be_bytes());
        out[8..].copy_from_slice(&lo.to_be_bytes());
        out
    }
}


// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_uppercase();
    let (num, mul) = match t.chars().last() {
        Some('K') => (&t[..t.len() - 1], 1024u64),
        Some('M') => (&t[..t.len() - 1], 1024 * 1024),
        Some('G') => (&t[..t.len() - 1], 1024 * 1024 * 1024),
        _ => (t.as_str(), 1),
    };
    num.parse::<u64>().map(|n| n * mul).map_err(|_| format!("invalid size `{}`", s))
}

fn parse_hex(s: &str) -> Result<u32, String> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid hex `{}`", s))
    } else {
        t.parse().map_err(|_| format!("invalid number `{}`", s))
    }
}

fn parse_key(s: &str) -> Result<[u8; 32], String> {
    let bytes = primitives::from_hex(s)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| "a volume key is 32 bytes of hex".to_string())?;
    Ok(key)
}

/// The unlock flags shared by `verify`, `dump` and `build`.
fn take_unlock(args: &[String], i: &mut usize, unlock: &mut Option<Unlock>) -> Result<bool, String> {
    let take = |i: &mut usize, what: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i).cloned().ok_or_else(|| format!("{} needs a value", what))
    };
    match args[*i].as_str() {
        "--passphrase" => {
            let passphrase = take(i, "--passphrase")?.into_bytes();
            let (memory_kib, iterations, lanes) = match unlock {
                Some(Unlock::Passphrase { memory_kib, iterations, lanes, .. }) => (*memory_kib, *iterations, *lanes),
                _ => (64 * 1024, 3, 4),
            };
            *unlock = Some(Unlock::Passphrase { passphrase, memory_kib, iterations, lanes });
        }
        "--kdf" => {
            let spec = take(i, "--kdf")?;
            let parts: Vec<&str> = spec.split(',').collect();
            if parts.len() != 3 { return Err("--kdf takes memory-kib,iterations,lanes".into()); }
            let parse = |s: &str| s.trim().parse::<u32>().map_err(|_| format!("invalid --kdf value `{s}`"));
            let (memory_kib, iterations, lanes) = (parse(parts[0])?, parse(parts[1])?, parse(parts[2])?);
            let passphrase = match unlock { Some(Unlock::Passphrase { passphrase, .. }) => passphrase.clone(), _ => Vec::new() };
            *unlock = Some(Unlock::Passphrase { passphrase, memory_kib, iterations, lanes });
        }
        "--volume-key" => *unlock = Some(Unlock::VolumeKey(parse_key(&take(i, "--volume-key")?)?)),
        _ => return Ok(false),
    }
    Ok(true)
}

/// `flake saltyfs` entry point: `build` writes an image, `verify` checks
/// one, `dump` prints its logical contents.
pub fn run(args: &[String]) -> Result<i32, String> {
    match args.first().map(|s| s.as_str()) {
        Some("build") => run_build(&args[1..]),
        Some("verify") | Some("dump") => {
            let dump = args[0] == "dump";
            let path = args.get(1).ok_or("saltyfs verify: needs an image path")?;
            let mut unlock = None;
            let mut i = 2;
            while i < args.len() {
                if !take_unlock(args, &mut i, &mut unlock)? { return Err(format!("saltyfs {}: unknown argument `{}`", args[0], args[i])); }
                i += 1;
            }
            if dump {
                crate::term::result_raw(read::dump_text_with(Path::new(path), unlock.as_ref())?.as_bytes());
                return Ok(0);
            }
            let errors = read::verify_with(Path::new(path), unlock.as_ref())?;
            for e in &errors { crate::log::error("saltyfs", e); }
            if errors.is_empty() {
                crate::log::success("saltyfs", &format!("Verified {}: clean", path));
            } else {
                crate::log::error("saltyfs", &format!("Verification of {} failed ({} problems)", path, errors.len()));
            }
            Ok(if errors.is_empty() { 0 } else { 1 })
        }
        _ => Err("saltyfs: expected `build`, `verify` or `dump`".to_string()),
    }
}

fn run_build(args: &[String]) -> Result<i32, String> {
    let mut output: Option<PathBuf> = None;
    let mut size = 64 * 1024 * 1024u64;
    let mut label = "saltyfs".to_string();
    let mut files: Vec<(String, FileSource)> = Vec::new();
    let mut empty_dirs: Vec<String> = Vec::new();
    let mut symlinks: Vec<(String, Vec<u8>)> = Vec::new();
    let mut directory_links: Vec<String> = Vec::new();
    let mut permissions = Permissions::new();
    let mut casefold_root = false;
    let mut extra_incompat = 0u32;
    let mut compat_ro = 0u32;
    let mut casefold_version = 0u32;
    let mut options = Options::default();

    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize, what: &str| -> Result<String, String> {
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| format!("{} needs a value", what))
        };
        if take_unlock(args, &mut i, &mut options.unlock)? { i += 1; continue; }
        match args[i].as_str() {
            "--output" | "-o" => output = Some(PathBuf::from(take(&mut i, "--output")?)),
            "--size" | "-s" => size = parse_size(&take(&mut i, "--size")?)?,
            "--label" => label = take(&mut i, "--label")?,
            "--add-file" => {
                let name = take(&mut i, "--add-file")?;
                let content = take(&mut i, "--add-file")?;
                files.push((name, FileSource::Bytes(content.into_bytes())));
            }
            "--add-file-from" => {
                let name = take(&mut i, "--add-file-from")?;
                let src = take(&mut i, "--add-file-from")?;
                files.push((name, FileSource::Path(PathBuf::from(src))));
            }
            "--add-dir" => empty_dirs.push(take(&mut i, "--add-dir")?),
            "--add-symlink" => {
                let name = take(&mut i, "--add-symlink")?;
                let target = take(&mut i, "--add-symlink")?;
                symlinks.push((name, target.into_bytes()));
            }
            "--add-directory-symlink" => {
                let name = take(&mut i, "--add-directory-symlink")?;
                let target = take(&mut i, "--add-directory-symlink")?;
                directory_links.push(name.clone());
                symlinks.push((name, target.into_bytes()));
            }
            "--set-permissions" => {
                let p = PathBuf::from(take(&mut i, "--set-permissions")?);
                if p.exists() { permissions = cpio::load_permissions(&p)?; }
            }
            "--casefold-root" => casefold_root = true,
            "--casefold-version" => {
                casefold_version = take(&mut i, "--casefold-version")?.parse().map_err(|_| "--casefold-version needs a number".to_string())?;
            }
            "--fake-incompat" => extra_incompat = parse_hex(&take(&mut i, "--fake-incompat")?)?,
            "--fake-compat-ro" => compat_ro = parse_hex(&take(&mut i, "--fake-compat-ro")?)?,
            "--encrypt" => {
                options.suite = Some(match take(&mut i, "--encrypt")?.as_str() {
                    "xchacha20-poly1305" => primitives::Suite::XChaCha20Poly1305,
                    "xaes-256-gcm" => primitives::Suite::xaes().map_err(|e| format!("--encrypt: {e}"))?,
                    other => return Err(format!("--encrypt: unknown suite `{other}`")),
                });
            }
            "--compress" => {
                options.compression = match take(&mut i, "--compress")?.as_str() {
                    "none" => COMPRESSION_NONE, "lz4" => COMPRESSION_LZ4, "zstd" => COMPRESSION_ZSTD,
                    other => return Err(format!("--compress: unknown codec `{other}`")),
                };
            }
            "--seal" => options.seal = true,
            other => return Err(format!("saltyfs build: unknown argument `{}`", other)),
        }
        i += 1;
    }
    let output = output.ok_or("saltyfs build: --output is required")?;
    if options.suite.is_some() && options.unlock.is_none() { return Err("--encrypt needs --passphrase or --volume-key".into()); }
    let declared_epoch: Option<u64> = crate::invocation::ambient_var("SOURCE_DATE_EPOCH").ok().and_then(|v| v.parse().ok());
    let (epoch_secs, clock_valid) = (declared_epoch.unwrap_or(1), declared_epoch.is_some());
    let stats = build::build_to_file_with(
        &output,
        &FsSpec { size_bytes: size, label, epoch_secs, clock_valid, casefold_root, extra_incompat, compat_ro_flags: compat_ro, casefold_version },
        &Contents { files, empty_dirs, symlinks, directory_links, permissions },
        &options,
    )?;
    crate::log::success(
        "saltyfs",
        &format!("wrote {} ({} blocks, {} used, {} tree blocks, {} files)", output.display(), stats.total_blocks, stats.used_blocks, stats.tree_blocks, stats.files),
    );
    Ok(0)
}
