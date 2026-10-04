// SPDX-License-Identifier: GPL-2.0-only
//! buildutil — canonical logical-structure image dumpers
//!
//! Incidental GUIDs, serials, timestamps, padding and physical placement are
//! excluded; checksums are verified and reported as ok/BAD.

use std::path::Path;
use crate::crypto::crc;
use crate::image::bootmanifest;
use crate::image::cpio;
use crate::image::fat;
use crate::image::gpt;

fn ok(b: bool) -> &'static str {
    if b { "ok" } else { "BAD" }
}

fn chain(contiguous: bool) -> &'static str {
    if contiguous {
        "contiguous"
    } else {
        "fragmented"
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))
}

/// Dump the selected image's logical structure without loading a build specification.
pub fn run(kind: &str, args: &[String]) -> Result<i32, String> {
    let Some(path) = args.first() else {
        return Err(format!("image {}: needs a file argument", kind));
    };
    let path = Path::new(path);
    let text = match kind {
        "dump-cpio" => {
            // The alignment the archive was written with, declared the
            // same way, is asserted on every entry it selects.
            let rest = &args[1..];
            let mut align = cpio::Align::default();
            let mut i = 0;
            while i < rest.len() {
                if !align.take(rest, &mut i)? {
                    return Err(format!("image dump-cpio: unknown argument `{}`", rest[i]));
                }
                i += 1;
            }
            align.validate().map_err(|e| format!("image dump-cpio: {e}"))?;
            dump_cpio(path, &align)?
        }
        "dump-gpt" => dump_gpt(path)?,
        "dump-bios" => dump_bios(path)?,
        "dump-fat" => dump_fat(path)?,
        "dump-saltyfs" => crate::image::saltyfs::read::dump_text(path)?,
        other => return Err(format!("unknown dumper `{}`", other)),
    };
    crate::term::result_raw(text.as_bytes());
    Ok(0)
}

fn dump_cpio(path: &Path, align: &cpio::Align) -> Result<String, String> {
    let archive = read(path)?;
    let entries = cpio::parse(&archive)?;
    // `.pad/` alignment filler is incidental layout, not content — skipped,
    // while the declared alignment it exists to satisfy is asserted on every
    // entry the declaration selects.
    let kept: Vec<&cpio::ParsedEntry> = entries
        .iter()
        .filter(|e| !e.name.starts_with(".pad/"))
        .collect();
    let mut out = format!("cpio newc entries={}\n", kept.len());
    for e in kept {
        out.push_str(&format!(
            "entry {} mode={:o} uid={} gid={} size={} sha256={}",
            e.name, e.mode, e.uid, e.gid, e.size, e.sha256
        ));
        let data = &archive[e.data_offset..e.data_offset + e.size as usize];
        if align.selects(&e.name, data) {
            if e.data_offset % align.bytes == 0 {
                out.push_str(&format!(" align={}", align.bytes));
            } else {
                out.push_str(" align=VIOLATION");
            }
        }
        out.push('\n');
    }
    Ok(out)
}

fn dump_gpt(path: &Path) -> Result<String, String> {
    let img = read(path)?;
    if img.len() < 34 * 512 {
        return Err("image too small to carry a GPT".to_string());
    }
    let total_sectors = img.len() as u64 / 512;
    let mut out = format!("gpt total-sectors={}\n", total_sectors);

    let e = &img[0x1BE..0x1CE];
    out.push_str(&format!(
        "pmbr type={:02X} start={} size={}\n",
        e[4],
        u32::from_le_bytes(e[8..12].try_into().unwrap()),
        u32::from_le_bytes(e[12..16].try_into().unwrap())
    ));

    let primary = gpt::parse_header(&img[512..1024])?;
    let eoff = primary.entries_start as usize * 512;
    let elen = (primary.entries_count * primary.entry_size) as usize;
    if eoff + elen > img.len() {
        return Err("GPT entry array lies beyond the image".to_string());
    }
    let entries = &img[eoff..eoff + elen];
    out.push_str(&format!(
        "primary crc={} entries-crc={} placement={} first-usable={} last-usable={} entries-at={}\n",
        ok(primary.header_crc_ok),
        ok(crc::crc32(entries) == primary.entries_crc),
        ok(primary.my_lba == 1 && primary.alternate_lba == total_sectors - 1),
        primary.first_usable,
        primary.last_usable,
        primary.entries_start
    ));

    let boff = ((total_sectors - 1) * 512) as usize;
    let backup = gpt::parse_header(&img[boff..boff + 512])?;
    let beoff = backup.entries_start as usize * 512;
    if beoff + elen > img.len() {
        return Err("backup GPT entry array lies beyond the image".to_string());
    }
    out.push_str(&format!(
        "backup crc={} placement={} guid-match={} entries-at={} mirror={}\n",
        ok(backup.header_crc_ok),
        ok(backup.my_lba == total_sectors - 1 && backup.alternate_lba == 1),
        ok(backup.disk_guid == primary.disk_guid),
        backup.entries_start,
        ok(&img[beoff..beoff + elen] == entries)
    ));

    let mut unique_guids = Vec::new();
    for p in gpt::parse_entries(entries, primary.entries_count, primary.entry_size)? {
        unique_guids.push(p.unique_guid);
        out.push_str(&format!(
            "part idx={} type={} name={} first={} last={} attrs={}\n",
            p.index, p.type_guid, p.name, p.first_lba, p.last_lba, p.attributes
        ));
        // Opaque payload partitions get a raw region hash; the ESP is
        // structured and compared via dump-fat instead.
        if p.type_guid != gpt::ESP_TYPE_GUID {
            let off = p.first_lba as usize * 512;
            let end = (p.last_lba + 1) as usize * 512;
            if end > img.len() {
                return Err(format!("partition {} lies beyond the image", p.index));
            }
            out.push_str(&format!(
                "region part{} sha256={}\n",
                p.index,
                crate::crypto::sha256::hash_bytes(&img[off..end])
            ));
        }
    }
    // Unique GUID values are writer identity and excluded from the dump,
    // but they must exist and not collide.
    let mut guid_text: Vec<String> = unique_guids.iter().map(|g| g.to_string()).collect();
    let count = guid_text.len();
    guid_text.sort();
    guid_text.dedup();
    let nonzero = guid_text
        .iter()
        .all(|g| g != "00000000-0000-0000-0000-000000000000");
    out.push_str(&format!(
        "unique-guids={}\n",
        ok(guid_text.len() == count && nonzero)
    ));
    Ok(out)
}

fn dump_bios(path: &Path) -> Result<String, String> {
    let img = read(path)?;
    let manifest_end = ((bootmanifest::MANIFEST_LBA + bootmanifest::MANIFEST_SECTORS)
        * bootmanifest::SECTOR_SIZE) as usize;
    if img.len() < manifest_end {
        return Err("image too small to carry the Boot Reserved Area".to_string());
    }
    if img[0x1FE] != 0x55 || img[0x1FF] != 0xAA {
        return Err("MBR signature missing".to_string());
    }
    let mut out = String::from("bios-image\n");
    for idx in 0..4 {
        let e = &img[0x1BE + idx * 16..0x1BE + (idx + 1) * 16];
        if e[4] == 0 {
            continue;
        }
        out.push_str(&format!(
            "mbr-part idx={} type={:02X} start={} size={}\n",
            idx,
            e[4],
            u32::from_le_bytes(e[8..12].try_into().unwrap()),
            u32::from_le_bytes(e[12..16].try_into().unwrap())
        ));
    }

    let moff = (bootmanifest::MANIFEST_LBA * bootmanifest::SECTOR_SIZE) as usize;
    let m = bootmanifest::parse(&img[moff..manifest_end])?;
    out.push_str(&format!(
        "manifest version={} arch={} header-size={} table={} size={} keyring={} key-id={} generation={} signature={} checksum={} entries={}\n",
        m.version,
        m.arch,
        m.header_size,
        m.entry_table_offset,
        m.total_size,
        m.keyring_size,
        m.signing_key_id,
        m.security_generation,
        m.signature_algorithm,
        if m.crc_ok { "ok" } else { "BAD" },
        m.entries.len()
    ));
    for e in &m.entries {
        let extents: Vec<String> = e
            .extents
            .iter()
            .map(|x| format!("({},{})", x.lba, x.sectors))
            .collect();
        out.push_str(&format!(
            "manifest-entry type={} id={} name={} size={} align={} digest={} extents={}\n",
            e.entry_type,
            e.id,
            e.name,
            e.size_bytes,
            e.load_align,
            e.digest.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            extents.join(",")
        ));
        let mut data = Vec::new();
        for x in &e.extents {
            let off = (x.lba * 512) as usize;
            let end = off + x.sectors as usize * 512;
            if end > img.len() {
                return Err(format!(
                    "manifest extent {:?} lies beyond the image",
                    extents
                ));
            }
            data.extend_from_slice(&img[off..end]);
        }
        data.truncate(e.size_bytes as usize);
        out.push_str(&format!(
            "region entry-type-{} sha256={}\n",
            e.entry_type,
            crate::crypto::sha256::hash_bytes(&data)
        ));
    }

    // stage2 and stage3 are not manifest-described; they live in their
    // fixed BRA slots.
    for (label, lba, count) in [
        ("stage2", bootmanifest::STAGE2_LBA, bootmanifest::STAGE2_SECTORS),
        ("stage3", bootmanifest::STAGE3_LBA, bootmanifest::STAGE3_SECTORS),
    ] {
        let off = (lba * 512) as usize;
        let len = (count * 512) as usize;
        if off + len > img.len() {
            return Err(format!("image too small to carry the {label} slot"));
        }
        out.push_str(&format!(
            "region {label}-slot sha256={}\n",
            crate::crypto::sha256::hash_bytes(&img[off..off + len])
        ));
    }

    let e = &img[0x1BE..0x1CE];
    if e[4] == 0x83 {
        let start = u32::from_le_bytes(e[8..12].try_into().unwrap()) as usize * 512;
        let len = u32::from_le_bytes(e[12..16].try_into().unwrap()) as usize * 512;
        if start + len > img.len() {
            return Err("rootfs partition lies beyond the image".to_string());
        }
        out.push_str(&format!(
            "region rootfs sha256={}\n",
            crate::crypto::sha256::hash_bytes(&img[start..start + len])
        ));
    }
    Ok(out)
}

fn dump_fat(path: &Path) -> Result<String, String> {
    let img = read(path)?;
    // A GPT disk carries the ESP as a partition; a raw image is the
    // filesystem itself.
    let fs_owned;
    let fs: &[u8] = if img.len() > 1024 && &img[512..520] == b"EFI PART" {
        let hdr = gpt::parse_header(&img[512..1024])?;
        let eoff = hdr.entries_start as usize * 512;
        let elen = (hdr.entries_count * hdr.entry_size) as usize;
        if eoff + elen > img.len() {
            return Err("GPT entry array lies beyond the image".to_string());
        }
        let parts = gpt::parse_entries(&img[eoff..eoff + elen], hdr.entries_count, hdr.entry_size)?;
        let esp = parts
            .iter()
            .find(|p| p.type_guid == gpt::ESP_TYPE_GUID)
            .ok_or("no EFI System Partition in the GPT")?;
        let off = esp.first_lba as usize * 512;
        let end = (esp.last_lba + 1) as usize * 512;
        if end > img.len() {
            return Err("ESP lies beyond the image".to_string());
        }
        fs_owned = img[off..end].to_vec();
        &fs_owned
    } else {
        &img
    };
    let d = fat::dump(fs)?;
    let mut out = format!(
        "fat type={} bps={} label={}\n",
        d.fat_type,
        d.bytes_per_sector,
        d.label.as_deref().unwrap_or("-")
    );
    for f in &d.files {
        if f.is_dir {
            out.push_str(&format!("dir {} chain={}\n", f.path, chain(f.contiguous)));
        } else {
            out.push_str(&format!(
                "file {} size={} sha256={} attr={:02X} chain={}\n",
                f.path,
                f.size,
                f.sha256,
                f.attr,
                chain(f.contiguous)
            ));
        }
    }
    Ok(out)
}
