//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — boot manifest writer and reader, version 2 of the boot handoff
//! family
//!
//! The manifest describes the images a disk carries as named, digested raw
//! block extents in the Boot Reserved Area, so the BIOS loader needs no
//! filesystem to find them. The loader's transcription of the format in
//! boot/src/common/bootproto.h is the layout authority; this module mirrors
//! it field for field. The writer emits an unsigned manifest; a signing
//! tool embeds the keyring and the Ed25519 signature, and the disk writer
//! accepts the signed manifest only when its entry table is the one it
//! laid out.

use crate::crypto::crc;

/// The family prefix: magic "SLTM" (first character in the lowest byte),
/// version, architecture, total size and flags.
pub const MAGIC: u32 = 0x4D54_4C53;
pub const VERSION: u16 = 2;
pub const ARCH_X86_64: u16 = 1;
pub const ARCH_AARCH64: u16 = 2;

pub const HEADER_SIZE: usize = 136;
pub const ENTRY_SIZE: usize = 224;
pub const MAX_EXTENTS: usize = 8;
pub const NAME_BYTES: usize = 32;
pub const MAX_ENTRIES: usize = 64;
pub const MAX_BYTES: usize = 32768;

pub const ENTRY_KERNEL: u16 = 1;
pub const ENTRY_INITRD: u16 = 2;
pub const ENTRY_MODULE: u16 = 3;
pub const ENTRY_CONFIG: u16 = 4;

pub const HASH_SHA256: u8 = 1;
pub const SIGNATURE_NONE: u8 = 0;
pub const SIGNATURE_ED25519: u8 = 1;

// Header field offsets.
const OFF_TOTAL_SIZE: usize = 8;
const OFF_HEADER_SIZE: usize = 16;
const OFF_ENTRY_COUNT: usize = 18;
const OFF_TABLE: usize = 20;
const OFF_KEYRING: usize = 24;
const OFF_KEYRING_SIZE: usize = 28;
const OFF_SIGNING_KEY: usize = 32;
const OFF_GENERATION: usize = 36;
const OFF_SIG_ALG: usize = 40;
const OFF_CRC: usize = 112;

// Boot Reserved Area layout, in 512-byte sectors.
pub const SECTOR_SIZE: u64 = 512;
pub const BRA_START_LBA: u64 = 2048;
pub const MANIFEST_LBA: u64 = BRA_START_LBA;
pub const MANIFEST_SECTORS: u64 = 64;
pub const STAGE2_LBA: u64 = MANIFEST_LBA + MANIFEST_SECTORS;
pub const STAGE2_SECTORS: u64 = 128;
pub const STAGE3_LBA: u64 = STAGE2_LBA + STAGE2_SECTORS;
pub const STAGE3_SECTORS: u64 = 512;
/// Two 4 KiB boot-state slots the loader writes; the image leaves them zero.
pub const STATE_LBA: u64 = STAGE3_LBA + STAGE3_SECTORS;
pub const STATE_SECTORS: u64 = 16;
pub const PAYLOAD_LBA: u64 = STATE_LBA + STATE_SECTORS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extent {
    pub lba: u64,
    pub sectors: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub entry_type: u16,
    pub id: u32,
    /// At most 31 bytes; stored NUL-terminated.
    pub name: String,
    pub size_bytes: u64,
    pub load_align: u64,
    pub digest: [u8; 32],
    pub extents: Vec<Extent>,
}

pub struct Parsed {
    pub version: u16,
    pub arch: u16,
    pub total_size: u32,
    pub header_size: u16,
    pub entry_table_offset: u32,
    pub keyring_size: u32,
    pub signing_key_id: u32,
    pub security_generation: u32,
    pub signature_algorithm: u8,
    pub crc_ok: bool,
    pub entries: Vec<Entry>,
}

fn put16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn get32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn get64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// The SHA-256 digest an entry records for its image bytes.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = crate::crypto::sha256::Sha256::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// The CRC64 of a whole manifest, its own field zeroed.
fn manifest_crc(bytes: &[u8]) -> u64 {
    let mut copy = bytes.to_vec();
    copy[OFF_CRC..OFF_CRC + 8].fill(0);
    crc::crc64_manifest(&copy)
}

/// Serialize an unsigned manifest: header and entry table, no keyring, a
/// zero signature, and the CRC64 over the whole with its field zeroed. The
/// entries are all disk entries, with extents, or all network entries,
/// without.
pub fn build(arch: u16, entries: &[Entry]) -> Result<Vec<u8>, String> {
    if entries.len() > MAX_ENTRIES {
        return Err(format!(
            "boot manifest: {} entries exceed the {MAX_ENTRIES} the format holds",
            entries.len()
        ));
    }
    // A disk entry names its extents; a network entry names none, the
    // loader fetching `prefix/name` instead.
    let network = entries.iter().all(|e| e.extents.is_empty());
    for e in entries {
        if (!network && e.extents.is_empty()) || e.extents.len() > MAX_EXTENTS {
            return Err(format!(
                "boot manifest: entry `{}` has {} extents (a disk entry has 1..={MAX_EXTENTS}, a network entry none)",
                e.name,
                e.extents.len()
            ));
        }
        if e.name.is_empty() || e.name.len() >= NAME_BYTES || e.name.contains('\0') {
            return Err(format!(
                "boot manifest: entry name `{}` must be 1..{} bytes without NUL",
                e.name,
                NAME_BYTES - 1
            ));
        }
        if !matches!(
            e.entry_type,
            ENTRY_KERNEL | ENTRY_INITRD | ENTRY_MODULE | ENTRY_CONFIG
        ) {
            return Err(format!(
                "boot manifest: entry `{}` has unknown type {}",
                e.name, e.entry_type
            ));
        }
    }
    let total = HEADER_SIZE + entries.len() * ENTRY_SIZE;
    if total > MAX_BYTES {
        return Err(format!("boot manifest: {total} bytes exceed {MAX_BYTES}"));
    }
    let mut out = vec![0u8; total];
    put32(&mut out, 0, MAGIC);
    put16(&mut out, 4, VERSION);
    put16(&mut out, 6, arch);
    put32(&mut out, OFF_TOTAL_SIZE, total as u32);
    // Prefix flags (offset 12) stay zero.
    put16(&mut out, OFF_HEADER_SIZE, HEADER_SIZE as u16);
    put16(&mut out, OFF_ENTRY_COUNT, entries.len() as u16);
    put32(&mut out, OFF_TABLE, HEADER_SIZE as u32);
    // Keyring offset and size, signing key, generation and the signature
    // stay zero until signing. The build identity after the CRC stays zero,
    // which names none.
    out[OFF_SIG_ALG] = SIGNATURE_NONE;
    for (i, e) in entries.iter().enumerate() {
        let base = HEADER_SIZE + i * ENTRY_SIZE;
        put16(&mut out, base, e.entry_type);
        // Entry flags (base + 2) stay zero.
        put32(&mut out, base + 4, e.id);
        out[base + 8..base + 8 + e.name.len()].copy_from_slice(e.name.as_bytes());
        put64(&mut out, base + 40, e.size_bytes);
        put64(&mut out, base + 48, e.load_align);
        out[base + 56] = HASH_SHA256;
        put32(&mut out, base + 60, e.extents.len() as u32);
        out[base + 64..base + 96].copy_from_slice(&e.digest);
        for (j, x) in e.extents.iter().enumerate() {
            let xoff = base + 96 + j * 16;
            put64(&mut out, xoff, x.lba);
            put32(&mut out, xoff + 8, x.sectors);
        }
    }
    let crc = manifest_crc(&out);
    put64(&mut out, OFF_CRC, crc);
    Ok(out)
}

/// Decode a manifest and check its CRC64.
pub fn parse(data: &[u8]) -> Result<Parsed, String> {
    if data.len() < HEADER_SIZE {
        return Err("boot manifest: buffer shorter than the header".to_string());
    }
    if get32(data, 0) != MAGIC {
        return Err("boot manifest: bad magic".to_string());
    }
    let version = get16(data, 4);
    if version != VERSION {
        return Err(format!("boot manifest: version {version} is not {VERSION}"));
    }
    let arch = get16(data, 6);
    let total_size = get32(data, OFF_TOTAL_SIZE);
    let total = total_size as usize;
    if total < HEADER_SIZE || total > data.len() || total > MAX_BYTES {
        return Err(format!(
            "boot manifest: total_size {total} outside the buffer ({} bytes)",
            data.len()
        ));
    }
    let header_size = get16(data, OFF_HEADER_SIZE);
    let entry_count = get16(data, OFF_ENTRY_COUNT) as usize;
    let entry_table_offset = get32(data, OFF_TABLE);
    let table = entry_table_offset as usize;
    if (header_size as usize) < HEADER_SIZE
        || table < HEADER_SIZE
        || table % 8 != 0
        || entry_count > MAX_ENTRIES
        || table + entry_count * ENTRY_SIZE > total
    {
        return Err("boot manifest: entry table out of bounds".to_string());
    }
    let keyring_offset = get32(data, OFF_KEYRING) as usize;
    let keyring_size = get32(data, OFF_KEYRING_SIZE);
    if keyring_offset != 0
        && (keyring_offset < table + entry_count * ENTRY_SIZE
            || keyring_offset + keyring_size as usize > total)
    {
        return Err("boot manifest: keyring out of bounds".to_string());
    }
    let crc_ok = manifest_crc(&data[..total]) == get64(data, OFF_CRC);
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let base = table + i * ENTRY_SIZE;
        let extent_count = get32(data, base + 60) as usize;
        if extent_count > MAX_EXTENTS {
            return Err(format!("boot manifest: entry {i} has {extent_count} extents"));
        }
        let name_bytes = &data[base + 8..base + 8 + NAME_BYTES];
        let name_len = name_bytes
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| format!("boot manifest: entry {i} name is not NUL-terminated"))?;
        let name = String::from_utf8(name_bytes[..name_len].to_vec())
            .map_err(|_| format!("boot manifest: entry {i} name is not UTF-8"))?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[base + 64..base + 96]);
        let mut extents = Vec::with_capacity(extent_count);
        for j in 0..extent_count {
            let xoff = base + 96 + j * 16;
            extents.push(Extent {
                lba: get64(data, xoff),
                sectors: get32(data, xoff + 8),
            });
        }
        entries.push(Entry {
            entry_type: get16(data, base),
            id: get32(data, base + 4),
            name,
            size_bytes: get64(data, base + 40),
            load_align: get64(data, base + 48),
            digest,
            extents,
        });
    }
    Ok(Parsed {
        version,
        arch,
        total_size,
        header_size,
        entry_table_offset,
        keyring_size,
        signing_key_id: get32(data, OFF_SIGNING_KEY),
        security_generation: get32(data, OFF_GENERATION),
        signature_algorithm: data[OFF_SIG_ALG],
        crc_ok,
        entries,
    })
}

/// Accept `signed`, a manifest a signing tool produced from `unsigned`,
/// only when it carries the same prefix fields, header and entry table,
/// an Ed25519 signature algorithm and a valid CRC64. The signature itself
/// is the loader's to verify against its embedded root.
pub fn check_signed(unsigned: &[u8], signed: &[u8]) -> Result<(), String> {
    let parsed = parse(signed)?;
    if !parsed.crc_ok {
        return Err("signed boot manifest: CRC64 mismatch".to_string());
    }
    if parsed.signature_algorithm != SIGNATURE_ED25519 || parsed.keyring_size == 0 {
        return Err("signed boot manifest: no Ed25519 signature and keyring".to_string());
    }
    let table_end = get32(unsigned, OFF_TABLE) as usize
        + get16(unsigned, OFF_ENTRY_COUNT) as usize * ENTRY_SIZE;
    // Magic, version and architecture; then header size through the table
    // offset; then the whole entry table.
    let same = signed.len() >= table_end
        && unsigned[0..8] == signed[0..8]
        && unsigned[OFF_HEADER_SIZE..OFF_KEYRING] == signed[OFF_HEADER_SIZE..OFF_KEYRING]
        && unsigned[HEADER_SIZE..table_end] == signed[HEADER_SIZE..table_end];
    if !same {
        return Err(
            "signed boot manifest describes other images than this disk lays out".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(entry_type: u16, id: u32, name: &str, lba: u64, sectors: u32) -> Entry {
        Entry {
            entry_type,
            id,
            name: name.to_string(),
            size_bytes: sectors as u64 * 512,
            load_align: 4096,
            digest: digest(name.as_bytes()),
            extents: vec![Extent { lba, sectors }],
        }
    }

    #[test]
    fn required_version_two_layout_round_trips() {
        let entries = vec![
            entry(ENTRY_KERNEL, 1, "kernel", PAYLOAD_LBA, 8),
            entry(ENTRY_INITRD, 2, "initrd", PAYLOAD_LBA + 8, 4),
        ];
        let manifest = build(ARCH_X86_64, &entries).unwrap();
        assert_eq!(manifest.len(), HEADER_SIZE + 2 * ENTRY_SIZE);
        assert_eq!(&manifest[0..4], b"SLTM");
        let parsed = parse(&manifest).unwrap();
        assert!(parsed.crc_ok);
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.header_size as usize, HEADER_SIZE);
        assert_eq!(parsed.signature_algorithm, SIGNATURE_NONE);
        assert_eq!(parsed.entries, entries);
        assert_eq!(build(ARCH_X86_64, &entries).unwrap(), manifest);
        let mut corrupt = manifest.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        assert!(!parse(&corrupt).unwrap().crc_ok);
    }

    #[test]
    fn required_signed_manifest_must_describe_the_laid_out_images() {
        let entries = vec![entry(ENTRY_KERNEL, 1, "kernel", PAYLOAD_LBA, 8)];
        let unsigned = build(ARCH_X86_64, &entries).unwrap();
        // What the signing tool writes: keyring after the table, key id,
        // generation, algorithm, signature, then the CRC64.
        let table_end = unsigned.len();
        let ring_off = (table_end + 7) & !7;
        let ring = vec![0xAB; 16 + 40 + 64];
        let mut signed = vec![0u8; ring_off + ring.len()];
        signed[..table_end].copy_from_slice(&unsigned);
        signed[ring_off..].copy_from_slice(&ring);
        let total = signed.len() as u32;
        put32(&mut signed, OFF_TOTAL_SIZE, total);
        put32(&mut signed, OFF_KEYRING, ring_off as u32);
        put32(&mut signed, OFF_KEYRING_SIZE, ring.len() as u32);
        put32(&mut signed, OFF_SIGNING_KEY, 1);
        put32(&mut signed, OFF_GENERATION, 7);
        signed[OFF_SIG_ALG] = SIGNATURE_ED25519;
        signed[48..112].fill(0x5A);
        let crc = manifest_crc(&signed);
        put64(&mut signed, OFF_CRC, crc);
        check_signed(&unsigned, &signed).unwrap();

        let other = build(ARCH_X86_64, &[entry(ENTRY_KERNEL, 1, "kernel", PAYLOAD_LBA, 9)]).unwrap();
        assert!(check_signed(&other, &signed).is_err());
        assert!(check_signed(&unsigned, &unsigned).is_err(), "an unsigned manifest is refused");
    }

    #[test]
    fn required_network_manifests_carry_entries_without_extents() {
        let mut kernel = entry(ENTRY_KERNEL, 1, "kernite.elf", 0, 0);
        kernel.extents.clear();
        let mut root = entry(ENTRY_MODULE, 2, "rootfs.img", 0, 0);
        root.extents.clear();
        let manifest = build(ARCH_AARCH64, &[kernel.clone(), root]).unwrap();
        let parsed = parse(&manifest).unwrap();
        assert!(parsed.crc_ok);
        assert_eq!(parsed.arch, ARCH_AARCH64);
        assert!(parsed.entries.iter().all(|e| e.extents.is_empty()));
        // Disk and network entries do not mix.
        let disk = entry(ENTRY_INITRD, 3, "initrd", PAYLOAD_LBA, 1);
        assert!(build(ARCH_X86_64, &[kernel, disk]).is_err());
    }

    #[test]
    fn required_names_and_counts_are_bounded() {
        assert!(build(ARCH_X86_64, &[entry(ENTRY_KERNEL, 1, &"k".repeat(32), PAYLOAD_LBA, 1)]).is_err());
        assert!(build(ARCH_X86_64, &[entry(9, 1, "x", PAYLOAD_LBA, 1)]).is_err());
        let many: Vec<Entry> = (0..65)
            .map(|i| entry(ENTRY_MODULE, i, "m", PAYLOAD_LBA, 1))
            .collect();
        assert!(build(ARCH_X86_64, &many).is_err());
    }
}
