//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — bootable disk image assembler (BIOS + UEFI)
//!
//! BIOS images carry the Boot Reserved Area — the boot manifest, stage2,
//! stage3, the two boot-state slots and the named payloads the manifest
//! describes — plus an optional rootfs partition patched into the MBR. UEFI images carry a
//! GPT with a FAT ESP (built in-process by crate::fat) and the optional
//! rootfs partition. Every identity (GUIDs, FAT serial) derives from the
//! payload contents via crate::crypto::detseed, and timestamps come from
//! SOURCE_DATE_EPOCH — same inputs, same image bytes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::bootmanifest;
use super::fat;
use super::gpt;
use crate::crypto::detseed;
use crate::source;

const SECTOR_SIZE: u64 = 512;
/// 1 MiB alignment for partition starts.
const PART_ALIGN_SECTORS: u64 = 2048;

// UEFI layout.
const ESP_START_LBA: u64 = 2048;
// A data alignment the FAT builder gives a file holds on the disk only if
// the ESP itself starts on the largest one it accepts.
const _: () = assert!((ESP_START_LBA * SECTOR_SIZE) % fat::MAX_ALIGN_BYTES == 0);
/// Smallest ESP the image carries. The partition is sized from its contents
/// (crate::fat::required_bytes) and never below this floor, the value
/// systemd-repart applies to an ESP on 512-byte sectors; at this size the
/// filesystem is FAT32.
const ESP_MIN_BYTES: u64 = 100 * 1024 * 1024;

fn sectors(bytes: u64) -> u64 {
    bytes.div_ceil(SECTOR_SIZE)
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))
}

fn epoch_from_env() -> u64 {
    crate::invocation::ambient_var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}

struct Out {
    file: File,
    path: PathBuf,
}

impl Out {
    fn create(path: &Path, total_sectors: u64) -> Result<Out, String> {
        let file =
            File::create(path).map_err(|e| format!("cannot create {}: {}", path.display(), e))?;
        file.set_len(total_sectors * SECTOR_SIZE)
            .map_err(|e| format!("cannot size {}: {}", path.display(), e))?;
        Ok(Out {
            file,
            path: path.to_path_buf(),
        })
    }

    fn write_at(&mut self, lba: u64, data: &[u8]) -> Result<(), String> {
        self.file
            .seek(SeekFrom::Start(lba * SECTOR_SIZE))
            .and_then(|_| self.file.write_all(data))
            .map_err(|e| format!("cannot write {}: {}", self.path.display(), e))
    }

    /// Stream a file into the image at `lba` (large rootfs payloads).
    fn copy_file_at(&mut self, lba: u64, src: &Path) -> Result<u64, String> {
        let mut f = File::open(src).map_err(|e| format!("cannot read {}: {}", src.display(), e))?;
        self.file
            .seek(SeekFrom::Start(lba * SECTOR_SIZE))
            .map_err(|e| format!("cannot seek {}: {}", self.path.display(), e))?;
        let mut buf = vec![0u8; 1024 * 1024];
        let mut copied = 0u64;
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| format!("read {}: {}", src.display(), e))?;
            if n == 0 {
                break;
            }
            self.file
                .write_all(&buf[..n])
                .map_err(|e| format!("write {}: {}", self.path.display(), e))?;
            copied += n as u64;
        }
        Ok(copied)
    }

    fn finish(mut self) -> Result<(), String> {
        self.file
            .flush()
            .map_err(|e| format!("cannot flush {}: {}", self.path.display(), e))
    }
}

// ---------------------------------------------------------------------------
// BIOS image
// ---------------------------------------------------------------------------

/// A named payload the manifest describes.
pub struct Payload {
    pub entry_type: u16,
    pub name: String,
    pub path: PathBuf,
    pub load_align: u64,
}

pub struct BiosInputs {
    pub mbr: PathBuf,
    pub stage2: PathBuf,
    pub stage3: PathBuf,
    /// Kernel, initrd, configuration and module payloads, in manifest order.
    pub payloads: Vec<Payload>,
    pub rootfs: Option<PathBuf>,
    /// A signed manifest to place instead of the unsigned one; it must
    /// describe exactly the payloads laid out here.
    pub signed_manifest: Option<PathBuf>,
}

/// The payloads' manifest entries at their extents from the payload LBA,
/// and the first free LBA after them.
fn lay_out(payloads: &[(&Payload, Vec<u8>)]) -> Result<(Vec<bootmanifest::Entry>, u64), String> {
    let mut entries = Vec::new();
    let mut lba = bootmanifest::PAYLOAD_LBA;
    for (id, (payload, bytes)) in payloads.iter().enumerate() {
        let count = sectors(bytes.len() as u64);
        let count32 = u32::try_from(count)
            .map_err(|_| format!("payload `{}` is too large for one extent", payload.name))?;
        entries.push(bootmanifest::Entry {
            entry_type: payload.entry_type,
            id: id as u32 + 1,
            name: payload.name.clone(),
            size_bytes: bytes.len() as u64,
            load_align: payload.load_align,
            digest: bootmanifest::digest(bytes),
            extents: vec![bootmanifest::Extent {
                lba,
                sectors: count32,
            }],
        });
        lba += count;
    }
    Ok((entries, lba))
}

fn read_payloads(inputs: &BiosInputs) -> Result<Vec<(&Payload, Vec<u8>)>, String> {
    if !inputs
        .payloads
        .iter()
        .any(|p| p.entry_type == bootmanifest::ENTRY_KERNEL)
    {
        return Err("image: a BIOS image needs a --kernel payload".to_string());
    }
    inputs
        .payloads
        .iter()
        .map(|payload| Ok((payload, read_input(&payload.path)?)))
        .collect()
}

/// The unsigned manifest a BIOS image with `inputs` carries, for a signing
/// tool to sign.
pub fn bios_manifest(inputs: &BiosInputs) -> Result<Vec<u8>, String> {
    let payloads = read_payloads(inputs)?;
    let (entries, _) = lay_out(&payloads)?;
    bootmanifest::build(bootmanifest::ARCH_X86_64, &entries)
}

pub fn build_bios(output: &Path, inputs: &BiosInputs, size_mb: u64) -> Result<(), String> {
    let mbr = read_input(&inputs.mbr)?;
    if mbr.len() as u64 != SECTOR_SIZE {
        return Err(format!(
            "MBR must be exactly {} bytes, got {}",
            SECTOR_SIZE,
            mbr.len()
        ));
    }
    let stage2 = read_input(&inputs.stage2)?;
    if sectors(stage2.len() as u64) > bootmanifest::STAGE2_SECTORS {
        return Err(format!(
            "stage2 ({} bytes) exceeds its {}-sector slot",
            stage2.len(),
            bootmanifest::STAGE2_SECTORS
        ));
    }
    let stage3 = read_input(&inputs.stage3)?;
    if sectors(stage3.len() as u64) > bootmanifest::STAGE3_SECTORS {
        return Err(format!(
            "stage3 ({} bytes) exceeds its {}-sector slot",
            stage3.len(),
            bootmanifest::STAGE3_SECTORS
        ));
    }
    let payloads = read_payloads(inputs)?;
    let (entries, last_used) = lay_out(&payloads)?;
    let unsigned = bootmanifest::build(bootmanifest::ARCH_X86_64, &entries)?;
    let manifest = match &inputs.signed_manifest {
        Some(path) => {
            let signed = read_input(path)?;
            bootmanifest::check_signed(&unsigned, &signed)?;
            signed
        }
        None => unsigned,
    };
    if sectors(manifest.len() as u64) > bootmanifest::MANIFEST_SECTORS {
        return Err(format!(
            "boot manifest ({} bytes) exceeds its slot",
            manifest.len()
        ));
    }

    let mut mbr = mbr;
    let mut rootfs_start = 0u64;
    let mut required = last_used;
    if let Some(rootfs) = &inputs.rootfs {
        let rootfs_len = std::fs::metadata(rootfs)
            .map_err(|e| format!("cannot stat {}: {}", rootfs.display(), e))?
            .len();
        let rootfs_sectors = sectors(rootfs_len);
        rootfs_start = align_up(last_used, PART_ALIGN_SECTORS);
        required = rootfs_start + rootfs_sectors;
        mbr = gpt::patch_mbr_linux_partition(&mbr, rootfs_start, rootfs_sectors)?.to_vec();
    }

    let requested = size_mb * 1024 * 1024 / SECTOR_SIZE;
    let total_sectors = if required > requested {
        align_up(required, PART_ALIGN_SECTORS)
    } else {
        requested
    };

    // The boot-state slots are left zero: the loader writes them.
    let mut out = Out::create(output, total_sectors)?;
    out.write_at(0, &mbr)?;
    out.write_at(bootmanifest::MANIFEST_LBA, &manifest)?;
    out.write_at(bootmanifest::STAGE2_LBA, &stage2)?;
    out.write_at(bootmanifest::STAGE3_LBA, &stage3)?;
    for (entry, (_, bytes)) in entries.iter().zip(payloads.iter()) {
        out.write_at(entry.extents[0].lba, bytes)?;
    }
    if let Some(rootfs) = &inputs.rootfs {
        out.copy_file_at(rootfs_start, rootfs)?;
    }
    out.finish()
}

// ---------------------------------------------------------------------------
// UEFI image
// ---------------------------------------------------------------------------

pub struct UefiInputs {
    /// (ESP path, source file) in declaration order; the order fixes the
    /// directory layout and the content manifest the identifiers derive
    /// from.
    pub esp: Vec<(String, PathBuf)>,
    /// (ESP path, bytes): the disk alignment an ESP file's data needs, for
    /// a file a reader rewrites in place block by block.
    pub esp_align: Vec<(String, u64)>,
    /// The boot sector's OEM name.
    pub oem: [u8; 8],
    pub rootfs: Option<PathBuf>,
    /// GPT partition name of the rootfs partition.
    pub rootfs_label: String,
}

pub fn build_uefi(
    output: &Path,
    inputs: &UefiInputs,
    size_mb: u64,
    epoch_secs: u64,
) -> Result<(), String> {
    // ESP file tree, as the image declaration lays it out.
    if inputs.esp.is_empty() {
        return Err("image: a UEFI image needs at least one --esp file".to_string());
    }
    let mut esp_files: Vec<(String, Vec<u8>)> = Vec::with_capacity(inputs.esp.len());
    for (dest, src) in &inputs.esp {
        if esp_files.iter().any(|(existing, _)| existing.eq_ignore_ascii_case(dest)) {
            return Err(format!("image: ESP path `{dest}` is given twice"));
        }
        esp_files.push((dest.clone(), read_input(src)?));
    }

    // Content manifest: the identity preimage for every GUID and serial.
    let mut content = String::new();
    for (name, data) in &esp_files {
        content.push_str(&format!(
            "esp/{} {}\n",
            name,
            crate::crypto::sha256::hash_bytes(data)
        ));
    }
    // The alignment moves the ESP layout, so it is part of the identity.
    for (name, bytes) in &inputs.esp_align {
        content.push_str(&format!("esp-align/{} {}\n", name, bytes));
    }
    if let Some(rootfs) = &inputs.rootfs {
        content.push_str(&format!(
            "rootfs {}\n",
            source::filehash::hash_file(rootfs)?
        ));
    }
    let content = content.as_bytes();

    let esp_bytes = fat::required_bytes(
        &esp_files,
        &inputs.esp_align,
        ESP_MIN_BYTES,
        PART_ALIGN_SECTORS * SECTOR_SIZE,
    )?;
    let esp_size_sectors = esp_bytes / SECTOR_SIZE;
    let esp_end_lba = ESP_START_LBA + esp_size_sectors - 1;
    let mut rootfs_start = 0u64;
    let mut rootfs_sectors = 0u64;
    let mut min_sectors = esp_end_lba + gpt::GPT_ENTRIES_SECTORS + 2;
    if let Some(rootfs) = &inputs.rootfs {
        let rootfs_len = std::fs::metadata(rootfs)
            .map_err(|e| format!("cannot stat {}: {}", rootfs.display(), e))?
            .len();
        rootfs_sectors = sectors(rootfs_len);
        rootfs_start = align_up(esp_end_lba + 1, PART_ALIGN_SECTORS);
        min_sectors = min_sectors.max(rootfs_start + rootfs_sectors + gpt::GPT_ENTRIES_SECTORS + 1);
    }
    let requested = size_mb * 1024 * 1024 / SECTOR_SIZE;
    let total_sectors = requested.max(min_sectors);

    // Partitions + GPT structures.
    let disk_guid = gpt::Guid(detseed::uuid_v4_like(
        detseed::TAG_GPT_DISK,
        content,
        "disk",
    ));
    let esp_guid = gpt::Guid(detseed::uuid_v4_like(detseed::TAG_GPT_ESP, content, "esp"));
    let mut partitions = vec![gpt::Partition {
        type_guid: gpt::ESP_TYPE_GUID,
        unique_guid: esp_guid,
        first_lba: ESP_START_LBA,
        last_lba: esp_end_lba,
        name: "EFI System Partition".to_string(),
    }];
    if inputs.rootfs.is_some() {
        partitions.push(gpt::Partition {
            type_guid: gpt::LINUX_FS_TYPE_GUID,
            unique_guid: gpt::Guid(detseed::uuid_v4_like(
                detseed::TAG_GPT_ROOTFS,
                content,
                "rootfs",
            )),
            first_lba: rootfs_start,
            last_lba: rootfs_start + rootfs_sectors - 1,
            name: inputs.rootfs_label.clone(),
        });
    }
    let entries = gpt::entries_block(&partitions)?;
    let entries_crc = crate::crypto::crc::crc32(&entries);

    // ESP filesystem.
    let esp = fat::build(
        &fat::Params {
            total_bytes: esp_bytes,
            volume_label: "ESP".to_string(),
            serial: detseed::serial32(detseed::TAG_FAT_SERIAL, content, "esp"),
            epoch_secs,
            oem: inputs.oem,
        },
        &esp_files,
        &inputs.esp_align,
    )?;

    let backup_entries_lba = total_sectors - gpt::GPT_ENTRIES_SECTORS - 1;
    let backup_header_lba = total_sectors - 1;

    let mut out = Out::create(output, total_sectors)?;
    out.write_at(0, &gpt::protective_mbr(total_sectors))?;
    out.write_at(
        gpt::GPT_HEADER_LBA,
        &gpt::header(disk_guid, total_sectors, entries_crc, false),
    )?;
    out.write_at(gpt::GPT_ENTRIES_START_LBA, &entries)?;
    out.write_at(backup_entries_lba, &entries)?;
    out.write_at(
        backup_header_lba,
        &gpt::header(disk_guid, total_sectors, entries_crc, true),
    )?;
    out.write_at(ESP_START_LBA, &esp)?;
    if let Some(rootfs) = &inputs.rootfs {
        out.copy_file_at(rootfs_start, rootfs)?;
    }
    out.finish()
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// `buildutil image` entry point. A BIOS image takes its boot chain by role
/// (`--mbr`, `--stage2`, `--stage3`), which the Boot Reserved Area places at
/// fixed LBAs, and its named payloads (`--kernel`, `--initrd`, `--config`,
/// `--module`, each `<name>=<file>`), which the manifest describes;
/// `--write-manifest <file>` writes only that manifest, unsigned, and
/// `--signed-manifest <file>` places its signed form. `--network-manifest
/// <file>` with `--arch` and the payloads writes a network source's
/// unsigned manifest, whose entries have no extents. A UEFI image
/// (`--uefi`) takes its ESP as `--esp <path>=<file>` in layout order,
/// `--esp-align <path>=<bytes>` for an ESP file whose data must start on a
/// disk boundary of that many bytes, the FAT OEM name (`--fat-oem`) and the
/// rootfs partition name (`--rootfs-label`) from its declaration.
pub fn run(args: &[String]) -> Result<i32, String> {
    let mut uefi = false;
    let mut arch = "x86_64".to_string();
    let mut output: Option<PathBuf> = None;
    let mut size_mb: Option<u64> = None;
    let mut esp: Vec<(String, PathBuf)> = Vec::new();
    let mut esp_align: Vec<(String, u64)> = Vec::new();
    let mut oem: Option<String> = None;
    let mut rootfs_label: Option<String> = None;
    let mut paths: std::collections::BTreeMap<&'static str, PathBuf> =
        std::collections::BTreeMap::new();
    let mut payloads: Vec<Payload> = Vec::new();
    let mut signed_manifest: Option<PathBuf> = None;
    let mut write_manifest: Option<PathBuf> = None;
    let mut network_manifest: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize, what: &str| -> Result<PathBuf, String> {
            *i += 1;
            args.get(*i)
                .map(PathBuf::from)
                .ok_or_else(|| format!("{} needs a path", what))
        };
        let take_str = |i: &mut usize, what: &str| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", what))
        };
        match args[i].as_str() {
            "--uefi" => uefi = true,
            "--arch" => arch = take_str(&mut i, "--arch")?,
            "--size-mb" => {
                size_mb = Some(
                    take_str(&mut i, "--size-mb")?
                        .parse()
                        .map_err(|_| "--size-mb needs a number".to_string())?,
                );
            }
            "--output" | "-o" => output = Some(take(&mut i, "--output")?),
            "--esp" => {
                let entry = take_str(&mut i, "--esp")?;
                let (dest, src) = entry
                    .split_once('=')
                    .ok_or_else(|| format!("--esp `{entry}` is not <path>=<file>"))?;
                let dest = dest.trim_start_matches('/');
                if dest.is_empty()
                    || dest
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                {
                    return Err(format!("--esp path `{dest}` is not a clean ESP path"));
                }
                esp.push((dest.to_string(), PathBuf::from(src)));
            }
            "--esp-align" => {
                let entry = take_str(&mut i, "--esp-align")?;
                let (dest, bytes) = entry
                    .split_once('=')
                    .ok_or_else(|| format!("--esp-align `{entry}` is not <path>=<bytes>"))?;
                let bytes: u64 = bytes
                    .parse()
                    .map_err(|_| format!("--esp-align `{entry}`: `{bytes}` is not a byte count"))?;
                esp_align.push((dest.trim_start_matches('/').to_string(), bytes));
            }
            "--fat-oem" => oem = Some(take_str(&mut i, "--fat-oem")?),
            "--rootfs-label" => rootfs_label = Some(take_str(&mut i, "--rootfs-label")?),
            "--mbr" => {
                paths.insert("mbr", take(&mut i, "--mbr")?);
            }
            "--stage2" => {
                paths.insert("stage2", take(&mut i, "--stage2")?);
            }
            "--stage3" => {
                paths.insert("stage3", take(&mut i, "--stage3")?);
            }
            flag @ ("--kernel" | "--initrd" | "--config" | "--module") => {
                let entry = take_str(&mut i, flag)?;
                let (name, path) = entry
                    .split_once('=')
                    .ok_or_else(|| format!("{flag} `{entry}` is not <name>=<file>"))?;
                let (entry_type, load_align) = match flag {
                    "--kernel" => (bootmanifest::ENTRY_KERNEL, 2 * 1024 * 1024),
                    "--initrd" => (bootmanifest::ENTRY_INITRD, 4096),
                    "--config" => (bootmanifest::ENTRY_CONFIG, 4096),
                    _ => (bootmanifest::ENTRY_MODULE, 4096),
                };
                payloads.push(Payload {
                    entry_type,
                    name: name.to_string(),
                    path: PathBuf::from(path),
                    load_align,
                });
            }
            "--signed-manifest" => signed_manifest = Some(take(&mut i, "--signed-manifest")?),
            "--write-manifest" => write_manifest = Some(take(&mut i, "--write-manifest")?),
            "--network-manifest" => {
                network_manifest = Some(take(&mut i, "--network-manifest")?);
            }
            "--rootfs" => {
                paths.insert("rootfs", take(&mut i, "--rootfs")?);
            }
            other => return Err(format!("image: unknown argument `{}`", other)),
        }
        i += 1;
    }
    let need = |key: &str| -> Result<PathBuf, String> {
        paths
            .get(key)
            .cloned()
            .ok_or_else(|| format!("image: --{} is required", key))
    };
    if let Some(path) = network_manifest {
        // A network source's unsigned manifest: every payload an entry
        // the loader fetches by name, with no extents.
        if uefi || !paths.is_empty() || !esp.is_empty() || !esp_align.is_empty() || output.is_some() {
            return Err(
                "image: --network-manifest takes only --arch and the named payloads".to_string(),
            );
        }
        let arch_code = match arch.as_str() {
            "x86_64" => bootmanifest::ARCH_X86_64,
            "aarch64" => bootmanifest::ARCH_AARCH64,
            other => return Err(format!("image: unknown architecture `{other}`")),
        };
        let mut entries = Vec::new();
        for (id, payload) in payloads.iter().enumerate() {
            let bytes = read_input(&payload.path)?;
            entries.push(bootmanifest::Entry {
                entry_type: payload.entry_type,
                id: id as u32 + 1,
                name: payload.name.clone(),
                size_bytes: bytes.len() as u64,
                load_align: payload.load_align,
                digest: bootmanifest::digest(&bytes),
                extents: Vec::new(),
            });
        }
        let manifest = bootmanifest::build(arch_code, &entries)?;
        std::fs::write(&path, manifest)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        crate::log::success("image", &format!("wrote {}", path.display()));
        return Ok(0);
    }
    if uefi {
        let output = output.ok_or("image: --output is required")?;
        let bios_only = ["mbr", "stage2", "stage3"]
            .iter()
            .any(|role| paths.contains_key(role))
            || !payloads.is_empty()
            || signed_manifest.is_some()
            || write_manifest.is_some();
        if bios_only {
            return Err(
                "image: a UEFI image places its boot files through --esp <path>=<file>; the boot chain, payload and manifest flags are BIOS-only"
                    .to_string(),
            );
        }
        let rootfs = paths.get("rootfs").cloned();
        let rootfs_label = match (&rootfs, rootfs_label) {
            (Some(_), Some(label)) if !label.is_empty() => label,
            (Some(_), _) => return Err("image: --rootfs needs --rootfs-label".to_string()),
            (None, _) => String::new(),
        };
        build_uefi(
            &output,
            &UefiInputs {
                esp,
                esp_align,
                oem: fat::oem_name(oem.as_deref().ok_or("image: --fat-oem is required")?)?,
                rootfs,
                rootfs_label,
            },
            size_mb.unwrap_or(64),
            epoch_from_env(),
        )?;
        crate::log::success("image", &format!("wrote {}", output.display()));
        Ok(0)
    } else {
        if arch != "x86_64" {
            return Err("image: BIOS images are x86_64-only".to_string());
        }
        if !esp.is_empty() || !esp_align.is_empty() || oem.is_some() || rootfs_label.is_some() {
            return Err(
                "image: --esp, --esp-align, --fat-oem and --rootfs-label belong to --uefi"
                    .to_string(),
            );
        }
        let inputs = BiosInputs {
            mbr: need("mbr")?,
            stage2: need("stage2")?,
            stage3: need("stage3")?,
            payloads,
            rootfs: paths.get("rootfs").cloned(),
            signed_manifest,
        };
        if let Some(path) = write_manifest {
            // Only the manifest, for a signing tool; no image is written.
            let manifest = bios_manifest(&inputs)?;
            std::fs::write(&path, manifest)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            crate::log::success("image", &format!("wrote {}", path.display()));
            return Ok(0);
        }
        let output = output.ok_or("image: --output is required")?;
        build_bios(&output, &inputs, size_mb.unwrap_or(16))?;
        crate::log::success("image", &format!("wrote {}", output.display()));
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("buildutil-image-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn required_bios_image_layout_follows_the_version_two_manifest() {
        let dir = tmpdir("bios");
        let mut mbr = vec![0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let payload = |entry_type, name: &str, file: &str, data: &[u8], align| Payload {
            entry_type,
            name: name.to_string(),
            path: write(&dir, file, data),
            load_align: align,
        };
        let inputs = BiosInputs {
            mbr: write(&dir, "mbr.bin", &mbr),
            stage2: write(&dir, "stage2.bin", &[2u8; 700]),
            stage3: write(&dir, "stage3.bin", &[3u8; 1500]),
            payloads: vec![
                payload(
                    bootmanifest::ENTRY_KERNEL,
                    "kernel",
                    "kernel.elf",
                    &[0x7F, b'E', b'L', b'F', 9, 9],
                    2 * 1024 * 1024,
                ),
                payload(bootmanifest::ENTRY_INITRD, "initrd", "initrd.cpio", &[5u8; 600], 4096),
            ],
            rootfs: Some(write(&dir, "rootfs.img", &[6u8; 4096])),
            signed_manifest: None,
        };
        let out = dir.join("bios.img");
        build_bios(&out, &inputs, 4).unwrap();
        let img = std::fs::read(&out).unwrap();
        assert_eq!(img.len() % (PART_ALIGN_SECTORS as usize * 512), 0);

        let moff = (bootmanifest::MANIFEST_LBA * SECTOR_SIZE) as usize;
        let parsed = bootmanifest::parse(&img[moff..moff + 32 * 1024]).unwrap();
        assert!(parsed.crc_ok);
        assert_eq!(parsed.arch, bootmanifest::ARCH_X86_64);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "kernel");
        assert_eq!(parsed.entries[0].extents[0].lba, bootmanifest::PAYLOAD_LBA);
        assert_eq!(
            parsed.entries[0].digest,
            bootmanifest::digest(&[0x7F, b'E', b'L', b'F', 9, 9])
        );
        // Initrd directly after the 1-sector kernel.
        assert_eq!(parsed.entries[1].extents[0].lba, bootmanifest::PAYLOAD_LBA + 1);
        // The boot-state slots stay zero.
        let state = (bootmanifest::STATE_LBA * SECTOR_SIZE) as usize;
        let state_end = state + (bootmanifest::STATE_SECTORS * SECTOR_SIZE) as usize;
        assert!(img[state..state_end].iter().all(|&b| b == 0));

        let s2 = (bootmanifest::STAGE2_LBA * SECTOR_SIZE) as usize;
        assert_eq!(&img[s2..s2 + 4], &[2u8; 4]);
        let k = (bootmanifest::PAYLOAD_LBA * SECTOR_SIZE) as usize;
        assert_eq!(&img[k..k + 4], b"\x7fELF");

        let rootfs_start = u32::from_le_bytes(img[0x1BE + 8..0x1BE + 12].try_into().unwrap());
        assert_eq!(rootfs_start as u64 % PART_ALIGN_SECTORS, 0);
        let r = rootfs_start as usize * 512;
        assert_eq!(&img[r..r + 4], &[6u8; 4]);

        // The standalone manifest is the one the image carries.
        let manifest = bios_manifest(&inputs).unwrap();
        assert_eq!(&img[moff..moff + manifest.len()], manifest.as_slice());
        // An unsigned manifest offered as the signed one is refused.
        let unsigned = write(&dir, "unsigned.bin", &manifest);
        let signed_inputs = BiosInputs {
            signed_manifest: Some(unsigned),
            ..inputs
        };
        assert!(build_bios(&dir.join("refused.img"), &signed_inputs, 4).is_err());

        let out2 = dir.join("bios-2.img");
        let inputs = BiosInputs {
            signed_manifest: None,
            ..signed_inputs
        };
        build_bios(&out2, &inputs, 4).unwrap();
        assert_eq!(img, std::fs::read(&out2).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uefi_image_layout() {
        let dir = tmpdir("uefi");
        let inputs = UefiInputs {
            esp: vec![
                (
                    "EFI/BOOT/BOOTX64.EFI".to_string(),
                    write(&dir, "BOOTX64.EFI", &[0x4D, 0x5A, 1]),
                ),
                (
                    "EFI/TESTOS/stage2.efi".to_string(),
                    write(&dir, "stage2.efi", &[0x4D, 0x5A, 2]),
                ),
                (
                    "EFI/TESTOS/stage3.bin".to_string(),
                    write(&dir, "stage3_uefi.bin", &[3u8; 900]),
                ),
                (
                    "EFI/TESTOS/kernel.elf".to_string(),
                    write(&dir, "kernel.elf", &[0x7F, b'E', b'L', b'F']),
                ),
                (
                    "EFI/TESTOS/initrd.img".to_string(),
                    write(&dir, "initrd.cpio", &[5u8; 600]),
                ),
                (
                    "EFI/TESTOS/boot.state".to_string(),
                    write(&dir, "boot.state", &[0u8; 8192]),
                ),
            ],
            esp_align: vec![("EFI/TESTOS/boot.state".to_string(), 4096)],
            oem: fat::oem_name("TESTOS").unwrap(),
            rootfs: None,
            rootfs_label: String::new(),
        };
        let out = dir.join("uefi.img");
        build_uefi(&out, &inputs, 64, 1).unwrap();
        let img = std::fs::read(&out).unwrap();
        let total_sectors = img.len() as u64 / SECTOR_SIZE;

        // Protective MBR + valid primary and backup GPT headers.
        assert_eq!(img[0x1BE + 4], 0xEE);
        let primary = gpt::parse_header(&img[512..1024]).unwrap();
        assert!(primary.header_crc_ok);
        assert_eq!(primary.alternate_lba, total_sectors - 1);
        let boff = ((total_sectors - 1) * SECTOR_SIZE) as usize;
        let backup = gpt::parse_header(&img[boff..boff + 512]).unwrap();
        assert!(backup.header_crc_ok);
        assert_eq!(backup.disk_guid, primary.disk_guid);

        // Partition array names the ESP; entry CRC matches both headers.
        let eoff = (gpt::GPT_ENTRIES_START_LBA * SECTOR_SIZE) as usize;
        let entries = &img[eoff..eoff + 128 * 128];
        assert_eq!(crate::crypto::crc::crc32(entries), primary.entries_crc);
        let parts = gpt::parse_entries(entries, 128, 128).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].type_guid, gpt::ESP_TYPE_GUID);
        assert_eq!(parts[0].first_lba, ESP_START_LBA);
        // Small contents: the ESP sits at its floor, which is FAT32 territory.
        let esp_sectors = parts[0].last_lba - parts[0].first_lba + 1;
        assert_eq!(esp_sectors * SECTOR_SIZE, ESP_MIN_BYTES);
        assert_eq!(esp_sectors % PART_ALIGN_SECTORS, 0);

        // The ESP decodes and holds the boot files.
        let esp_off = (ESP_START_LBA * SECTOR_SIZE) as usize;
        let esp_len = (esp_sectors * SECTOR_SIZE) as usize;
        let d = fat::dump(&img[esp_off..esp_off + esp_len]).unwrap();
        assert_eq!(d.fat_type, "FAT32");
        let paths: Vec<&str> = d.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"/EFI/BOOT/BOOTX64.EFI"));
        assert!(paths.contains(&"/EFI/TESTOS/INITRD.IMG"));
        assert_eq!(&img[esp_off + 3..esp_off + 11], b"TESTOS  ");
        // The aligned file's data lies on a 4 KiB boundary of the disk, in
        // one run.
        let state = d.files.iter().find(|f| f.path == "/EFI/TESTOS/BOOT.STATE").unwrap();
        assert!(state.contiguous);
        assert_eq!((esp_off as u64 + state.data_offset) % 4096, 0);

        // Deterministic.
        let out2 = dir.join("uefi-2.img");
        build_uefi(&out2, &inputs, 64, 1).unwrap();
        assert_eq!(img, std::fs::read(&out2).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
