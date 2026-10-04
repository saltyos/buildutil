//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — CRC32 (IEEE, zlib-compatible) and CRC64 (boot-manifest variant)
//!
//! CRC32 is the standard reflected IEEE polynomial (0xEDB88320 table form)
//! protecting GPT headers and partition-entry arrays.
//!
//! CRC64 reproduces `manifest_crc64()` from boot/src/common/manifest.h: the
//! LSB-first table algorithm seeded with the non-reflected ECMA-182
//! polynomial 0x42F0E1EBA9EA3693. That combination is NOT the standard
//! reflected CRC-64/XZ, so the table must be generated with exactly this
//! rule; the tests pin spot values against the header's literal table.

const CRC32_POLY: u32 = 0xEDB8_8320;

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &b in data {
        crc = crc32_byte(crc, b);
    }
    crc ^ u32::MAX
}

/// Update an unfinalized IEEE CRC-32 with one byte.
pub(crate) fn crc32_byte(crc: u32, byte: u8) -> u32 {
    CRC32_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8)
}

const CRC64_POLY: u64 = 0x42F0_E1EB_A9EA_3693;

const CRC64_TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u64;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC64_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC64 exactly as the loader computes it over the boot manifest and the
/// boot-state record (boot/src/common/crypto/crc64.c): the ECMA-182
/// polynomial without bit reversal, initial value and final xor all ones.
pub fn crc64_manifest(data: &[u8]) -> u64 {
    let mut crc = u64::MAX;
    for &b in data {
        crc = CRC64_TABLE[((crc ^ b as u64) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ u64::MAX
}

const CRC32C_POLY: u32 = 0x82F6_3B78;

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32C_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC32C (Castagnoli) as used by the SaltyFS on-disk format.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ u32::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_check_values() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn crc32_check_values() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc64_table_matches_manifest_header() {
        // Spot values copied from the crc64_table literal in
        // boot/src/common/manifest.h.
        assert_eq!(CRC64_TABLE[0], 0x0000000000000000);
        assert_eq!(CRC64_TABLE[1], 0x3C3B78E888D80FE1);
        assert_eq!(CRC64_TABLE[2], 0x7876F1D111B01FC2);
        assert_eq!(CRC64_TABLE[3], 0x444D893999681023);
        assert_eq!(CRC64_TABLE[255], 0x1416D7A787B7FAA0);
    }

    #[test]
    fn crc64_check_values() {
        assert_eq!(crc64_manifest(b""), 0);
        assert_eq!(crc64_manifest(b"123456789"), 0xB868_83E6_FA71_0A9F);
    }
}
