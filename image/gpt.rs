//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — GPT / MBR structures for the disk-image writer
//!
//! Writer and reader for the on-disk pieces the UEFI image needs —
//! protective MBR, primary/backup GPT headers (92 bytes, CRC32-protected),
//! the 128x128 partition-entry array — plus the classic-MBR rootfs
//! partition patch used by the BIOS image. GUID identity comes from
//! crate::crypto::detseed; nothing here mints randomness.

use crate::crypto::crc;

pub const SECTOR_SIZE: usize = 512;
pub const GPT_HEADER_LBA: u64 = 1;
pub const GPT_ENTRIES_START_LBA: u64 = 2;
pub const GPT_ENTRIES_COUNT: usize = 128;
pub const GPT_ENTRY_SIZE: usize = 128;
pub const GPT_ENTRIES_SECTORS: u64 = (GPT_ENTRIES_COUNT * GPT_ENTRY_SIZE / SECTOR_SIZE) as u64;
pub const GPT_HEADER_SIZE: usize = 92;

pub const MBR_PART_TYPE_LINUX_FS: u8 = 0x83;

/// RFC 4122 canonical (big-endian) byte order; `to_disk()` produces the
/// GPT mixed-endian layout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Guid(pub [u8; 16]);

/// C12A7328-F81F-11D2-BA4B-00A0C93EC93B
pub const ESP_TYPE_GUID: Guid = Guid([
    0xC1, 0x2A, 0x73, 0x28, 0xF8, 0x1F, 0x11, 0xD2, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
]);

/// 0FC63DAF-8483-4772-8E79-3D69D8477DE4
pub const LINUX_FS_TYPE_GUID: Guid = Guid([
    0x0F, 0xC6, 0x3D, 0xAF, 0x84, 0x83, 0x47, 0x72, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
]);

impl Guid {
    /// GPT stores GUIDs mixed-endian: the first three fields little-endian,
    /// the last two big-endian.
    pub fn to_disk(self) -> [u8; 16] {
        let b = self.0;
        [
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15],
        ]
    }

    pub fn from_disk(d: &[u8]) -> Guid {
        Guid([
            d[3], d[2], d[1], d[0], d[5], d[4], d[7], d[6], d[8], d[9], d[10], d[11], d[12], d[13],
            d[14], d[15],
        ])
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

fn get32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn get64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Protective MBR: one 0xEE partition from LBA 1 covering the disk.
pub fn protective_mbr(total_sectors: u64) -> [u8; SECTOR_SIZE] {
    let mut mbr = [0u8; SECTOR_SIZE];
    let e = &mut mbr[0x1BE..0x1CE];
    e[2] = 0x02; // CHS start: sector 1
    e[4] = 0xEE; // GPT protective
    e[5] = 0xFF;
    e[6] = 0xFF;
    e[7] = 0xFF; // CHS end: maxed for large disks
    e[8..12].copy_from_slice(&1u32.to_le_bytes());
    let size = u32::try_from(total_sectors.saturating_sub(1)).unwrap_or(u32::MAX);
    e[12..16].copy_from_slice(&size.to_le_bytes());
    mbr[0x1FE] = 0x55;
    mbr[0x1FF] = 0xAA;
    mbr
}

/// Patch the single authoritative rootfs partition into a bootable MBR.
/// Clears the whole partition table first — BIOS boot is driven by the
/// Boot Manifest, not a partition scan — then writes entry 0 as type 0x83
/// in LBA mode.
pub fn patch_mbr_linux_partition(
    mbr: &[u8],
    start_lba: u64,
    sectors: u64,
) -> Result<[u8; SECTOR_SIZE], String> {
    if mbr.len() != SECTOR_SIZE {
        return Err(format!(
            "MBR must be exactly {} bytes, got {}",
            SECTOR_SIZE,
            mbr.len()
        ));
    }
    if mbr[0x1FE] != 0x55 || mbr[0x1FF] != 0xAA {
        return Err("MBR signature missing (0x55AA)".to_string());
    }
    if start_lba == 0 || sectors == 0 {
        return Err(format!(
            "invalid MBR partition: start={} sectors={}",
            start_lba, sectors
        ));
    }
    if start_lba > u32::MAX as u64 || sectors > u32::MAX as u64 {
        return Err(format!(
            "MBR partition exceeds 32-bit LBA limits: start={} sectors={}",
            start_lba, sectors
        ));
    }
    let mut out = [0u8; SECTOR_SIZE];
    out.copy_from_slice(mbr);
    out[0x1BE..0x1FE].fill(0);
    let e = &mut out[0x1BE..0x1CE];
    e[1] = 0xFF;
    e[2] = 0xFF;
    e[3] = 0xFF; // CHS unused, maxed for LBA mode
    e[4] = MBR_PART_TYPE_LINUX_FS;
    e[5] = 0xFF;
    e[6] = 0xFF;
    e[7] = 0xFF;
    e[8..12].copy_from_slice(&(start_lba as u32).to_le_bytes());
    e[12..16].copy_from_slice(&(sectors as u32).to_le_bytes());
    Ok(out)
}

pub struct Partition {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub name: String,
}

/// Serialize the full 128-entry partition array (unused slots zeroed).
pub fn entries_block(parts: &[Partition]) -> Result<Vec<u8>, String> {
    if parts.len() > GPT_ENTRIES_COUNT {
        return Err(format!("too many GPT partitions: {}", parts.len()));
    }
    let mut block = vec![0u8; GPT_ENTRIES_COUNT * GPT_ENTRY_SIZE];
    for (i, p) in parts.iter().enumerate() {
        let e = &mut block[i * GPT_ENTRY_SIZE..(i + 1) * GPT_ENTRY_SIZE];
        e[0..16].copy_from_slice(&p.type_guid.to_disk());
        e[16..32].copy_from_slice(&p.unique_guid.to_disk());
        e[32..40].copy_from_slice(&p.first_lba.to_le_bytes());
        e[40..48].copy_from_slice(&p.last_lba.to_le_bytes());
        // attributes (48..56) zero
        let mut off = 56;
        for unit in p.name.encode_utf16().take(36) {
            e[off..off + 2].copy_from_slice(&unit.to_le_bytes());
            off += 2;
        }
    }
    Ok(block)
}

/// One GPT header sector. `backup` selects the mirrored placement fields;
/// the header CRC32 is computed with its own field zeroed.
pub fn header(
    disk_guid: Guid,
    total_sectors: u64,
    entries_crc32: u32,
    backup: bool,
) -> [u8; SECTOR_SIZE] {
    let mut h = [0u8; SECTOR_SIZE];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    h[12..16].copy_from_slice(&(GPT_HEADER_SIZE as u32).to_le_bytes());
    let (my_lba, alternate_lba, entries_start) = if backup {
        (
            total_sectors - 1,
            GPT_HEADER_LBA,
            total_sectors - GPT_ENTRIES_SECTORS - 1,
        )
    } else {
        (GPT_HEADER_LBA, total_sectors - 1, GPT_ENTRIES_START_LBA)
    };
    let first_usable = GPT_ENTRIES_START_LBA + GPT_ENTRIES_SECTORS;
    let last_usable = total_sectors - GPT_ENTRIES_SECTORS - 2;
    h[24..32].copy_from_slice(&my_lba.to_le_bytes());
    h[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    h[40..48].copy_from_slice(&first_usable.to_le_bytes());
    h[48..56].copy_from_slice(&last_usable.to_le_bytes());
    h[56..72].copy_from_slice(&disk_guid.to_disk());
    h[72..80].copy_from_slice(&entries_start.to_le_bytes());
    h[80..84].copy_from_slice(&(GPT_ENTRIES_COUNT as u32).to_le_bytes());
    h[84..88].copy_from_slice(&(GPT_ENTRY_SIZE as u32).to_le_bytes());
    h[88..92].copy_from_slice(&entries_crc32.to_le_bytes());
    let crc = crc::crc32(&h[..GPT_HEADER_SIZE]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    h
}

pub struct ParsedHeader {
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    pub disk_guid: Guid,
    pub entries_start: u64,
    pub entries_count: u32,
    pub entry_size: u32,
    pub entries_crc: u32,
    pub header_crc_ok: bool,
}

/// Decode one GPT header sector (used by the parity dumper).
pub fn parse_header(sector: &[u8]) -> Result<ParsedHeader, String> {
    if sector.len() < GPT_HEADER_SIZE {
        return Err("GPT header: sector too short".to_string());
    }
    if &sector[0..8] != b"EFI PART" {
        return Err("GPT header: bad signature".to_string());
    }
    let header_size = get32(sector, 12) as usize;
    if header_size < GPT_HEADER_SIZE || header_size > sector.len() {
        return Err(format!(
            "GPT header: implausible header_size {}",
            header_size
        ));
    }
    let stored_crc = get32(sector, 16);
    let mut copy = sector[..header_size].to_vec();
    copy[16..20].fill(0);
    let header_crc_ok = crc::crc32(&copy) == stored_crc;
    Ok(ParsedHeader {
        my_lba: get64(sector, 24),
        alternate_lba: get64(sector, 32),
        first_usable: get64(sector, 40),
        last_usable: get64(sector, 48),
        disk_guid: Guid::from_disk(&sector[56..72]),
        entries_start: get64(sector, 72),
        entries_count: get32(sector, 80),
        entry_size: get32(sector, 84),
        entries_crc: get32(sector, 88),
        header_crc_ok,
    })
}

pub struct ParsedPartition {
    pub index: usize,
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

/// Decode the partition array, skipping all-zero (unused) slots.
pub fn parse_entries(
    block: &[u8],
    count: u32,
    entry_size: u32,
) -> Result<Vec<ParsedPartition>, String> {
    let entry_size = entry_size as usize;
    let count = count as usize;
    if entry_size < GPT_ENTRY_SIZE {
        return Err(format!(
            "GPT entries: implausible entry size {}",
            entry_size
        ));
    }
    if block.len() < count * entry_size {
        return Err("GPT entries: block shorter than count * entry_size".to_string());
    }
    let mut parts = Vec::new();
    for i in 0..count {
        let e = &block[i * entry_size..(i + 1) * entry_size];
        let type_guid = Guid::from_disk(&e[0..16]);
        if type_guid.is_zero() {
            continue;
        }
        let mut name = String::new();
        let mut units = Vec::new();
        let mut off = 56;
        while off + 2 <= GPT_ENTRY_SIZE {
            let unit = u16::from_le_bytes([e[off], e[off + 1]]);
            if unit == 0 {
                break;
            }
            units.push(unit);
            off += 2;
        }
        name.extend(char::decode_utf16(units).map(|c| c.unwrap_or('\u{FFFD}')));
        parts.push(ParsedPartition {
            index: i,
            type_guid,
            unique_guid: Guid::from_disk(&e[16..32]),
            first_lba: get64(e, 32),
            last_lba: get64(e, 40),
            attributes: get64(e, 48),
            name,
        });
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_disk_roundtrip_and_display() {
        assert_eq!(
            ESP_TYPE_GUID.to_string(),
            "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
        );
        let disk = ESP_TYPE_GUID.to_disk();
        // First three fields byte-swapped on disk.
        assert_eq!(&disk[..4], &[0x28, 0x73, 0x2A, 0xC1]);
        assert_eq!(Guid::from_disk(&disk), ESP_TYPE_GUID);
    }

    #[test]
    fn protective_mbr_layout() {
        let mbr = protective_mbr(131072);
        assert_eq!(mbr[0x1BE + 4], 0xEE);
        assert_eq!(&mbr[0x1BE + 8..0x1BE + 12], &1u32.to_le_bytes());
        assert_eq!(&mbr[0x1BE + 12..0x1BE + 16], &131071u32.to_le_bytes());
        assert_eq!((mbr[0x1FE], mbr[0x1FF]), (0x55, 0xAA));
    }

    #[test]
    fn header_crc_and_placement() {
        let disk_guid = Guid([7u8; 16]);
        let entries = entries_block(&[Partition {
            type_guid: ESP_TYPE_GUID,
            unique_guid: Guid([9u8; 16]),
            first_lba: 2048,
            last_lba: 67583,
            name: "EFI System Partition".to_string(),
        }])
        .unwrap();
        let entries_crc = crc::crc32(&entries);
        let total = 262144u64;

        let primary = parse_header(&header(disk_guid, total, entries_crc, false)).unwrap();
        assert!(primary.header_crc_ok);
        assert_eq!(primary.my_lba, 1);
        assert_eq!(primary.alternate_lba, total - 1);
        assert_eq!(primary.first_usable, 34);
        assert_eq!(primary.last_usable, total - 34);
        assert_eq!(primary.entries_start, 2);

        let backup = parse_header(&header(disk_guid, total, entries_crc, true)).unwrap();
        assert!(backup.header_crc_ok);
        assert_eq!(backup.my_lba, total - 1);
        assert_eq!(backup.alternate_lba, 1);
        assert_eq!(backup.entries_start, total - 33);

        let parts =
            parse_entries(&entries, GPT_ENTRIES_COUNT as u32, GPT_ENTRY_SIZE as u32).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].type_guid, ESP_TYPE_GUID);
        assert_eq!(parts[0].first_lba, 2048);
        assert_eq!(parts[0].name, "EFI System Partition");
    }

    #[test]
    fn mbr_partition_patch() {
        let mut base = [0u8; SECTOR_SIZE];
        base[0x1FE] = 0x55;
        base[0x1FF] = 0xAA;
        // Pre-existing garbage entry that the patch must clear.
        base[0x1BE + 16 + 4] = 0x0C;
        let patched = patch_mbr_linux_partition(&base, 4096, 8192).unwrap();
        assert_eq!(patched[0x1BE + 4], MBR_PART_TYPE_LINUX_FS);
        assert_eq!(&patched[0x1BE + 8..0x1BE + 12], &4096u32.to_le_bytes());
        assert_eq!(&patched[0x1BE + 12..0x1BE + 16], &8192u32.to_le_bytes());
        assert_eq!(patched[0x1BE + 16 + 4], 0);
        assert!(patch_mbr_linux_partition(&[0u8; SECTOR_SIZE], 1, 1).is_err());
    }
}
