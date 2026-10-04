//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — deterministic identity seeds for the image writers
//!
//! The retired Python image tools minted random identities (uuid4 GPT
//! GUIDs, wall-clock FAT serials). The buildutil writers derive every identity
//! from content instead: sha256(tag || 0x00 || content-manifest || label),
//! truncated to the identity width, with RFC 4122 version/variant bits
//! patched where a consumer expects a well-formed v4 UUID. Same payload
//! yields the same identity; any payload change yields a new one.

use crate::crypto::sha256::Sha256;

/// Domain tags — one per identity kind, so identical payloads in
/// different roles still get distinct identities.
pub const TAG_GPT_DISK: &str = "GPT-DISK";
pub const TAG_GPT_ESP: &str = "GPT-ESP";
pub const TAG_GPT_ROOTFS: &str = "GPT-ROOTFS";
pub const TAG_FAT_SERIAL: &str = "FAT-SERIAL";
pub const TAG_SALTYFS_FS: &str = "SALTYFS-FS";
pub const TAG_SALTYFS_DEV: &str = "SALTYFS-DEV";

fn digest(tag: &str, content_manifest: &[u8], label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update(&[0]);
    h.update(content_manifest);
    h.update(label.as_bytes());
    h.finalize()
}

/// 16 bytes shaped like a random (version 4) RFC 4122 UUID, in canonical
/// big-endian field order.
pub fn uuid_v4_like(tag: &str, content_manifest: &[u8], label: &str) -> [u8; 16] {
    let d = digest(tag, content_manifest, label);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&d[..16]);
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    uuid
}

/// 32-bit serial (FAT volume id).
pub fn serial32(tag: &str, content_manifest: &[u8], label: &str) -> u32 {
    let d = digest(tag, content_manifest, label);
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_distinct_and_well_formed() {
        let a = uuid_v4_like(TAG_GPT_DISK, b"m", "disk");
        assert_eq!(a, uuid_v4_like(TAG_GPT_DISK, b"m", "disk"));
        assert_ne!(a, uuid_v4_like(TAG_GPT_ESP, b"m", "disk"));
        assert_ne!(a, uuid_v4_like(TAG_GPT_DISK, b"n", "disk"));
        assert_ne!(a, uuid_v4_like(TAG_GPT_DISK, b"m", "esp"));
        assert_eq!(a[6] >> 4, 4);
        assert_eq!(a[8] & 0xC0, 0x80);
        assert_eq!(
            serial32(TAG_FAT_SERIAL, b"m", "esp"),
            serial32(TAG_FAT_SERIAL, b"m", "esp")
        );
    }
}
