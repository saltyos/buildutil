//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil — FAT16/FAT32 filesystem builder and structure reader
//!
//! Replaces mkfs.vfat/mmd/mcopy on the ESP path. Deterministic by
//! construction: geometry is chosen from the FAT specification (no
//! mkfs.vfat mimicry), clusters are allocated sequentially in tree order,
//! timestamps come from SOURCE_DATE_EPOCH (clamped to the DOS 1980 floor),
//! and the volume serial is supplied by the caller (crate::crypto::detseed).
//! Names that are not plain uppercase 8.3 get VFAT long-name entries
//! preserving the original spelling — the FAT namespace is case-insensitive
//! for every consumer we have (UEFI firmware), and the parity dumper folds
//! case accordingly. A file may request an alignment for its data: the
//! geometry puts the data region on the largest requested boundary and the
//! file's run starts on its own, so a reader that writes the file in place
//! addresses whole aligned blocks.

pub const SECTOR_SIZE: usize = 512;

/// The largest data alignment a file may request. The disk writer starts
/// the filesystem on a boundary of this size, so an offset aligned inside
/// the filesystem is equally aligned on the disk.
pub const MAX_ALIGN_BYTES: u64 = 1 << 20;
const DIR_ENTRY_SIZE: usize = 32;

const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = 0x0F;

/// DOS timestamp floor: 1980-01-01T00:00:00Z.
const DOS_EPOCH_FLOOR: u64 = 315_532_800;

pub struct Params {
    /// Filesystem size; must be a multiple of the sector size.
    pub total_bytes: u64,
    /// Volume label (up to 11 bytes, stored uppercase, space-padded).
    pub volume_label: String,
    /// Volume serial number (content-derived via crate::crypto::detseed).
    pub serial: u32,
    /// Timestamp for every entry, seconds since the Unix epoch.
    pub epoch_secs: u64,
    /// The boot sector's OEM name: printable ASCII, space-padded to 8
    /// bytes (see `oem_name`).
    pub oem: [u8; 8],
}

/// Validate and pad an OEM name for `Params::oem`.
pub fn oem_name(text: &str) -> Result<[u8; 8], String> {
    if text.is_empty() || text.len() > 8 || !text.bytes().all(|b| (0x20..0x7F).contains(&b)) {
        return Err(format!(
            "FAT OEM name `{text}` must be 1 to 8 printable ASCII characters"
        ));
    }
    let mut oem = [b' '; 8];
    oem[..text.len()].copy_from_slice(text.as_bytes());
    Ok(oem)
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

struct Layout {
    fat32: bool,
    sectors_per_cluster: usize,
    reserved_sectors: usize,
    fat_sectors: usize,
    root_entries: usize, // FAT16 only
    total_sectors: u64,
    cluster_count: usize,
    data_start_sector: usize,
}

impl Layout {
    fn cluster_bytes(&self) -> usize {
        self.sectors_per_cluster * SECTOR_SIZE
    }

    fn root_dir_sectors(&self) -> usize {
        self.root_entries * DIR_ENTRY_SIZE / SECTOR_SIZE
    }

    fn cluster_offset(&self, cluster: usize) -> usize {
        (self.data_start_sector + (cluster - 2) * self.sectors_per_cluster) * SECTOR_SIZE
    }
}

/// Pick geometry from the FAT specification: FAT16 below 64 MiB, FAT32 at
/// or above; the smallest power-of-two cluster size whose cluster count
/// lands in the type's valid range. The FAT size is the standard
/// conservative over-estimate (a slightly oversized FAT is legal). The data
/// region starts on a multiple of `data_align_sectors`, a power of two: the
/// reserved region absorbs the padding, since the BPB allows any nonzero
/// reserved count.
fn plan_geometry(total_bytes: u64, data_align_sectors: usize) -> Result<Layout, String> {
    if total_bytes % SECTOR_SIZE as u64 != 0 {
        return Err(format!("FAT size {} is not sector-aligned", total_bytes));
    }
    let total_sectors = total_bytes / SECTOR_SIZE as u64;
    let fat32 = total_bytes >= 64 * 1024 * 1024;
    let (base_reserved, root_entries, entry_bytes) = if fat32 {
        (32usize, 0usize, 4u64)
    } else {
        (1usize, 512usize, 2u64)
    };
    let root_dir_sectors = root_entries * DIR_ENTRY_SIZE / SECTOR_SIZE;

    for shift in 0..8 {
        let spc = 1usize << shift; // 1..=128 sectors per cluster
        let fat_sectors = (total_sectors / spc as u64 + 2)
            .saturating_mul(entry_bytes)
            .div_ceil(SECTOR_SIZE as u64) as usize;
        let unaligned = base_reserved + 2 * fat_sectors + root_dir_sectors;
        let reserved_sectors =
            base_reserved + (data_align_sectors - unaligned % data_align_sectors) % data_align_sectors;
        let overhead = reserved_sectors as u64 + root_dir_sectors as u64 + 2 * fat_sectors as u64;
        if overhead >= total_sectors {
            continue;
        }
        let cluster_count = ((total_sectors - overhead) / spc as u64) as usize;
        let fits = if fat32 {
            (65525..=0x0FFF_FFF4).contains(&cluster_count)
        } else {
            (4085..=65524).contains(&cluster_count)
        };
        if fits {
            return Ok(Layout {
                fat32,
                sectors_per_cluster: spc,
                reserved_sectors,
                fat_sectors,
                root_entries,
                total_sectors,
                cluster_count,
                data_start_sector: reserved_sectors + 2 * fat_sectors + root_dir_sectors,
            });
        }
    }
    Err(format!(
        "no valid FAT{} geometry for {} bytes",
        if fat32 { 32 } else { 16 },
        total_bytes
    ))
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Unix seconds -> (DOS date, DOS time), clamped to the 1980 floor.
fn dos_datetime(epoch_secs: u64) -> (u16, u16) {
    let secs = epoch_secs.max(DOS_EPOCH_FLOOR);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm), UTC.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    let date = (((year - 1980) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let time = ((h as u16) << 11) | ((mi as u16) << 5) | (s as u16 / 2);
    (date, time)
}

// ---------------------------------------------------------------------------
// Name handling
// ---------------------------------------------------------------------------

fn valid_short_char(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || b"$%'-_@~`!(){}^#&".contains(&c)
}

/// Derive the 11-byte short name; returns (short, needs_lfn).
fn short_name(original: &str, used: &mut Vec<[u8; 11]>) -> Result<([u8; 11], bool), String> {
    if original.is_empty() || original == "." || original == ".." {
        return Err(format!("invalid FAT name `{}`", original));
    }
    let (base_src, ext_src) = match original.rfind('.') {
        Some(i) if i > 0 => (&original[..i], &original[i + 1..]),
        _ => (original, ""),
    };
    let sanitize = |src: &str, max: usize| -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut lossy = false;
        for &b in src.as_bytes() {
            if out.len() == max {
                lossy = true;
                break;
            }
            let up = b.to_ascii_uppercase();
            if valid_short_char(up) {
                if up != b {
                    lossy = true;
                }
                out.push(up);
            } else {
                lossy = true;
                out.push(b'_');
            }
        }
        (out, lossy)
    };
    let (base, base_lossy) = sanitize(base_src, 8);
    let (ext, ext_lossy) = sanitize(ext_src, 3);
    if base.is_empty() {
        return Err(format!("FAT name `{}` has an empty basis", original));
    }
    let mut needs_lfn = base_lossy || ext_lossy || original.contains(' ');

    let render = |base: &[u8], ext: &[u8]| -> [u8; 11] {
        let mut s = [b' '; 11];
        s[..base.len()].copy_from_slice(base);
        s[8..8 + ext.len()].copy_from_slice(ext);
        s
    };
    let mut short = render(&base, &ext);
    if used.contains(&short) {
        needs_lfn = true;
        let mut resolved = false;
        'outer: for n in 1..1_000_000u32 {
            let tail = format!("~{}", n);
            let keep = 8usize.saturating_sub(tail.len()).min(base.len());
            let mut candidate = Vec::from(&base[..keep]);
            candidate.extend_from_slice(tail.as_bytes());
            short = render(&candidate, &ext);
            if !used.contains(&short) {
                resolved = true;
                break 'outer;
            }
        }
        if !resolved {
            return Err(format!(
                "cannot derive a unique short name for `{}`",
                original
            ));
        }
    }
    used.push(short);
    Ok((short, needs_lfn))
}

fn lfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in short.iter() {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
    }
    sum
}

/// Number of directory slots (long-name entries + the short entry).
fn entry_slots(name: &str, short_used: &mut Vec<[u8; 11]>) -> Result<usize, String> {
    let (_, needs_lfn) = short_name(name, short_used)?;
    if needs_lfn {
        let units = name.encode_utf16().count();
        Ok(1 + units.div_ceil(13))
    } else {
        Ok(1)
    }
}

/// Serialize the long-name entries (reverse order) plus the short entry.
#[allow(clippy::too_many_arguments)]
fn write_entry(
    out: &mut Vec<u8>,
    name: &str,
    short: [u8; 11],
    needs_lfn: bool,
    attr: u8,
    first_cluster: u32,
    size: u32,
    date: u16,
    time: u16,
) {
    if needs_lfn {
        let units: Vec<u16> = name.encode_utf16().collect();
        let count = units.len().div_ceil(13);
        let checksum = lfn_checksum(&short);
        for seq in (1..=count).rev() {
            let mut e = [0u8; DIR_ENTRY_SIZE];
            e[0] = seq as u8 | if seq == count { 0x40 } else { 0 };
            e[11] = ATTR_LONG_NAME;
            e[13] = checksum;
            let chunk_base = (seq - 1) * 13;
            let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            for (k, &off) in offsets.iter().enumerate() {
                let idx = chunk_base + k;
                let unit: u16 = match idx.cmp(&units.len()) {
                    std::cmp::Ordering::Less => units[idx],
                    std::cmp::Ordering::Equal => 0x0000,
                    std::cmp::Ordering::Greater => 0xFFFF,
                };
                e[off..off + 2].copy_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&e);
        }
    }
    let mut e = [0u8; DIR_ENTRY_SIZE];
    e[..11].copy_from_slice(&short);
    e[11] = attr;
    e[14..16].copy_from_slice(&time.to_le_bytes());
    e[16..18].copy_from_slice(&date.to_le_bytes());
    e[18..20].copy_from_slice(&date.to_le_bytes());
    e[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
    e[22..24].copy_from_slice(&time.to_le_bytes());
    e[24..26].copy_from_slice(&date.to_le_bytes());
    e[26..28].copy_from_slice(&((first_cluster & 0xFFFF) as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&e);
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

enum Node {
    Dir { name: String, children: Vec<Node> },
    /// `align_sectors` is 1 unless the file requested a data alignment.
    File { name: String, data: Vec<u8>, align_sectors: usize },
}

/// The sectors of a requested data alignment, `bytes`: a power of two from
/// one sector to `MAX_ALIGN_BYTES`.
fn alignment_sectors(path: &str, bytes: u64) -> Result<usize, String> {
    if !bytes.is_power_of_two() || bytes < SECTOR_SIZE as u64 || bytes > MAX_ALIGN_BYTES {
        return Err(format!(
            "FAT alignment {bytes} for `{path}` is not a power of two from {SECTOR_SIZE} to {MAX_ALIGN_BYTES} bytes"
        ));
    }
    Ok((bytes / SECTOR_SIZE as u64) as usize)
}

/// The data region's alignment: the largest one any file requests, in
/// sectors (1 without requests). Every request is validated here.
fn data_alignment(aligned: &[(String, u64)]) -> Result<usize, String> {
    let mut largest = 1;
    for (path, bytes) in aligned {
        largest = largest.max(alignment_sectors(path, *bytes)?);
    }
    Ok(largest)
}

fn node_name(n: &Node) -> &str {
    match n {
        Node::Dir { name, .. } => name,
        Node::File { name, .. } => name,
    }
}

/// Build the tree from slash-separated paths; intermediate directories are
/// created in first-mention order. `aligned` names files, by the same path
/// spelling up to case, and the data alignment each requests.
fn build_tree(files: &[(String, Vec<u8>)], aligned: &[(String, u64)]) -> Result<Vec<Node>, String> {
    for (index, (path, _)) in aligned.iter().enumerate() {
        if !files.iter().any(|(file, _)| file.eq_ignore_ascii_case(path)) {
            return Err(format!("FAT alignment names `{path}`, which is not a file of the image"));
        }
        if aligned[..index].iter().any(|(other, _)| other.eq_ignore_ascii_case(path)) {
            return Err(format!("FAT alignment for `{path}` is given twice"));
        }
    }
    let mut root: Vec<Node> = Vec::new();
    for (path, data) in files {
        let align_sectors = match aligned.iter().find(|(p, _)| p.eq_ignore_ascii_case(path)) {
            Some((p, bytes)) => alignment_sectors(p, *bytes)?,
            None => 1,
        };
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err(format!("empty FAT path `{}`", path));
        }
        let mut cur = &mut root;
        for part in &parts[..parts.len() - 1] {
            if cur
                .iter()
                .any(|n| matches!(n, Node::File { name, .. } if name == part))
            {
                return Err(format!(
                    "`{}`: `{}` is both a file and a directory",
                    path, part
                ));
            }
            let pos = cur
                .iter()
                .position(|n| matches!(n, Node::Dir { name, .. } if name == part));
            let idx = match pos {
                Some(i) => i,
                None => {
                    cur.push(Node::Dir {
                        name: part.to_string(),
                        children: Vec::new(),
                    });
                    cur.len() - 1
                }
            };
            cur = match &mut cur[idx] {
                Node::Dir { children, .. } => children,
                Node::File { .. } => unreachable!(),
            };
        }
        let leaf = parts[parts.len() - 1];
        if cur.iter().any(|n| node_name(n) == leaf) {
            return Err(format!("duplicate FAT path `{}`", path));
        }
        cur.push(Node::File {
            name: leaf.to_string(),
            data: data.clone(),
            align_sectors,
        });
    }
    Ok(root)
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

struct Alloc {
    /// The cluster after the last run handed out.
    next_free: usize,
    /// Clusters in runs; clusters skipped to align a run stay free.
    used: usize,
    /// (first_cluster, cluster_run_length) per node id; 0 length = no chain.
    chains: Vec<(usize, usize)>,
}

impl Alloc {
    /// A run of `clusters` whose distance from cluster 2 is a multiple of
    /// `step` clusters. Cluster 2 starts the data region, which the geometry
    /// aligned, so such a run starts on the requested boundary.
    fn take(&mut self, clusters: usize, step: usize, limit: usize) -> Result<usize, String> {
        if clusters == 0 {
            self.chains.push((0, 0));
            return Ok(0);
        }
        let first = 2 + (self.next_free - 2).div_ceil(step) * step;
        if first + clusters - 1 > limit {
            return Err("FAT filesystem too small for its contents".to_string());
        }
        self.next_free = first + clusters;
        self.used += clusters;
        self.chains.push((first, clusters));
        Ok(first)
    }
}

/// Slot demand of one directory level (validates names once, up front).
fn dir_slots(children: &[Node]) -> Result<usize, String> {
    let mut used = Vec::new();
    let mut slots = 0;
    for c in children {
        slots += entry_slots(node_name(c), &mut used)?;
    }
    Ok(slots)
}

struct Planned {
    first_cluster: usize,
    clusters: usize,
}

/// Pass 1 of a build: every cluster chain of the tree, allocated depth-first
/// in tree order so each chain is a contiguous ascending run and the layout
/// is deterministic. Fails when the geometry cannot hold the tree.
struct Plan {
    alloc: Alloc,
    planned: Vec<Planned>,
    root_first_cluster: usize,
}

fn plan_allocation(layout: &Layout, tree: &[Node]) -> Result<Plan, String> {
    let cluster_bytes = layout.cluster_bytes();
    fn plan(
        nodes: &[Node],
        alloc: &mut Alloc,
        layout: &Layout,
        cluster_bytes: usize,
        out: &mut Vec<Planned>,
    ) -> Result<(), String> {
        for n in nodes {
            match n {
                Node::Dir { children, .. } => {
                    let slots = 2 + dir_slots(children)?;
                    let clusters = (slots * DIR_ENTRY_SIZE).div_ceil(cluster_bytes).max(1);
                    let first = alloc.take(clusters, 1, layout.cluster_count + 1)?;
                    out.push(Planned {
                        first_cluster: first,
                        clusters,
                    });
                    plan(children, alloc, layout, cluster_bytes, out)?;
                }
                Node::File {
                    data, align_sectors, ..
                } => {
                    let clusters = data.len().div_ceil(cluster_bytes);
                    // Both are powers of two; a cluster at least as large as
                    // the alignment starts on it wherever it lies.
                    let step = (*align_sectors / layout.sectors_per_cluster).max(1);
                    let first = alloc.take(clusters, step, layout.cluster_count + 1)?;
                    out.push(Planned {
                        first_cluster: first,
                        clusters,
                    });
                }
            }
        }
        Ok(())
    }

    let mut alloc = Alloc {
        next_free: 2,
        used: 0,
        chains: Vec::new(),
    };
    let mut planned: Vec<Planned> = Vec::new();
    // FAT32: the root directory itself is a cluster chain and must be
    // allocated first so it lands on cluster 2 (the BPB root_cluster).
    let root_first_cluster = if layout.fat32 {
        let slots = 1 + dir_slots(tree)?; // + volume label
        let clusters = (slots * DIR_ENTRY_SIZE).div_ceil(cluster_bytes).max(1);
        alloc.take(clusters, 1, layout.cluster_count + 1)?;
        planned.push(Planned {
            first_cluster: 2,
            clusters,
        });
        2usize
    } else {
        let slots = 1 + dir_slots(tree)?;
        if slots > layout.root_entries {
            return Err(format!(
                "FAT16 root directory overflow: {} slots > {}",
                slots, layout.root_entries
            ));
        }
        0
    };
    plan(tree, &mut alloc, layout, cluster_bytes, &mut planned)?;
    Ok(Plan {
        alloc,
        planned,
        root_first_cluster,
    })
}

/// The smallest filesystem size, a multiple of `step_bytes` and at least
/// `floor_bytes`, whose geometry holds `files` with the `aligned` requests —
/// the same allocation the build performs, so a size this function returns
/// never fails to build. The search starts at the larger of the floor and
/// the raw payload and grows by `step_bytes`; a step is never smaller than
/// one sector.
pub fn required_bytes(
    files: &[(String, Vec<u8>)],
    aligned: &[(String, u64)],
    floor_bytes: u64,
    step_bytes: u64,
) -> Result<u64, String> {
    let step = step_bytes.max(SECTOR_SIZE as u64);
    let tree = build_tree(files, aligned)?;
    let data_align = data_alignment(aligned)?;
    let payload: u64 = files.iter().map(|(_, data)| data.len() as u64).sum();
    // FAT tables, directories, cluster rounding and alignment padding never
    // need more than the payload again, the padding bound, plus one step at
    // the sizes this builder produces, so the search is bounded without a
    // second estimate.
    let padding: u64 = aligned.iter().map(|(_, bytes)| *bytes).sum();
    let ceiling = payload
        .saturating_mul(2)
        .saturating_add(padding.saturating_mul(2))
        .saturating_add(floor_bytes)
        .saturating_add(step);
    let mut candidate = floor_bytes.max(payload).div_ceil(step) * step;
    while candidate <= ceiling {
        if let Ok(layout) = plan_geometry(candidate, data_align) {
            if plan_allocation(&layout, &tree).is_ok() {
                return Ok(candidate);
            }
        }
        candidate += step;
    }
    Err(format!(
        "no FAT size up to {} bytes holds {} payload bytes",
        ceiling, payload
    ))
}

/// Build the filesystem image. `files` are `(slash/separated/path, data)`
/// in the order they should appear on disk; `aligned` are `(path, bytes)`
/// data alignments some of them request (see `MAX_ALIGN_BYTES`).
pub fn build(
    params: &Params,
    files: &[(String, Vec<u8>)],
    aligned: &[(String, u64)],
) -> Result<Vec<u8>, String> {
    let layout = plan_geometry(params.total_bytes, data_alignment(aligned)?)?;
    let tree = build_tree(files, aligned)?;
    let (date, time) = dos_datetime(params.epoch_secs);
    let cluster_bytes = layout.cluster_bytes();

    let Plan {
        alloc,
        planned,
        root_first_cluster,
    } = plan_allocation(&layout, &tree)?;
    let clusters_used = alloc.used;

    let mut image = vec![0u8; (layout.total_sectors as usize) * SECTOR_SIZE];

    // Boot sector.
    {
        let label11 = {
            let mut l = [b' '; 11];
            for (i, &b) in params.volume_label.as_bytes().iter().take(11).enumerate() {
                l[i] = b.to_ascii_uppercase();
            }
            l
        };
        let bs = &mut image[..SECTOR_SIZE];
        bs[0] = 0xEB;
        bs[1] = if layout.fat32 { 0x58 } else { 0x3C };
        bs[2] = 0x90;
        bs[3..11].copy_from_slice(&params.oem);
        bs[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        bs[13] = layout.sectors_per_cluster as u8;
        bs[14..16].copy_from_slice(&(layout.reserved_sectors as u16).to_le_bytes());
        bs[16] = 2; // number of FATs
        bs[17..19].copy_from_slice(&(layout.root_entries as u16).to_le_bytes());
        if layout.total_sectors < 65_536 && !layout.fat32 {
            bs[19..21].copy_from_slice(&(layout.total_sectors as u16).to_le_bytes());
        }
        bs[21] = 0xF8; // media: fixed disk
        if !layout.fat32 {
            bs[22..24].copy_from_slice(&(layout.fat_sectors as u16).to_le_bytes());
        }
        bs[24..26].copy_from_slice(&63u16.to_le_bytes()); // sectors/track
        bs[26..28].copy_from_slice(&255u16.to_le_bytes()); // heads
        // hidden sectors (28..32) zero
        if layout.total_sectors >= 65_536 || layout.fat32 {
            bs[32..36].copy_from_slice(&(layout.total_sectors as u32).to_le_bytes());
        }
        if layout.fat32 {
            bs[36..40].copy_from_slice(&(layout.fat_sectors as u32).to_le_bytes());
            // ext_flags (40..42) zero: FAT mirroring enabled
            // fs_version (42..44) zero
            bs[44..48].copy_from_slice(&(root_first_cluster as u32).to_le_bytes());
            bs[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
            bs[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector
            bs[64] = 0x80; // drive number
            bs[66] = 0x29; // extended boot signature
            bs[67..71].copy_from_slice(&params.serial.to_le_bytes());
            bs[71..82].copy_from_slice(&label11);
            bs[82..90].copy_from_slice(b"FAT32   ");
        } else {
            bs[36] = 0x80; // drive number
            bs[38] = 0x29; // extended boot signature
            bs[39..43].copy_from_slice(&params.serial.to_le_bytes());
            bs[43..54].copy_from_slice(&label11);
            bs[54..62].copy_from_slice(b"FAT16   ");
        }
        bs[510] = 0x55;
        bs[511] = 0xAA;
    }

    // FSInfo + backup boot region (FAT32).
    if layout.fat32 {
        let free = (layout.cluster_count - clusters_used) as u32;
        let next_free = (alloc.next_free as u32).min(layout.cluster_count as u32 + 1);
        {
            let fsinfo = &mut image[SECTOR_SIZE..2 * SECTOR_SIZE];
            fsinfo[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
            fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
            fsinfo[488..492].copy_from_slice(&free.to_le_bytes());
            fsinfo[492..496].copy_from_slice(&next_free.to_le_bytes());
            fsinfo[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
        }
        let (head, tail) = image.split_at_mut(6 * SECTOR_SIZE);
        tail[..SECTOR_SIZE].copy_from_slice(&head[..SECTOR_SIZE]);
        tail[SECTOR_SIZE..2 * SECTOR_SIZE].copy_from_slice(&head[SECTOR_SIZE..2 * SECTOR_SIZE]);
    }

    // FAT tables.
    {
        let mut fat = vec![0u8; layout.fat_sectors * SECTOR_SIZE];
        let mut set = |cluster: usize, value: u32| {
            if layout.fat32 {
                let off = cluster * 4;
                fat[off..off + 4].copy_from_slice(&(value & 0x0FFF_FFFF).to_le_bytes());
            } else {
                let off = cluster * 2;
                fat[off..off + 2].copy_from_slice(&(value as u16).to_le_bytes());
            }
        };
        if layout.fat32 {
            set(0, 0x0FFF_FFF8);
            set(1, 0x0FFF_FFFF);
        } else {
            set(0, 0xFFF8);
            set(1, 0xFFFF);
        }
        let eoc: u32 = if layout.fat32 { 0x0FFF_FFFF } else { 0xFFFF };
        for &(first, len) in &alloc.chains {
            for k in 0..len {
                let c = first + k;
                set(c, if k + 1 == len { eoc } else { (c + 1) as u32 });
            }
        }
        let fat_off = layout.reserved_sectors * SECTOR_SIZE;
        let fat_len = layout.fat_sectors * SECTOR_SIZE;
        image[fat_off..fat_off + fat_len].copy_from_slice(&fat);
        image[fat_off + fat_len..fat_off + 2 * fat_len].copy_from_slice(&fat);
    }

    // Pass 2: serialize directories and file data. Chain assignment order
    // is identical to pass 1, so we re-walk with an index cursor.
    struct Cursor<'a> {
        planned: &'a [Planned],
        idx: usize,
    }
    fn emit(
        nodes: &[Node],
        cur: &mut Cursor,
        layout: &Layout,
        image: &mut [u8],
        parent_cluster: usize,
        entries_out: &mut Vec<u8>,
        date: u16,
        time: u16,
    ) -> Result<(), String> {
        let cluster_bytes = layout.cluster_bytes();
        let mut used = Vec::new();
        for n in nodes {
            let p = &cur.planned[cur.idx];
            cur.idx += 1;
            let (short, needs_lfn) = short_name(node_name(n), &mut used)?;
            match n {
                Node::Dir { name, children } => {
                    let my_cluster = p.first_cluster;
                    write_entry(
                        entries_out,
                        name,
                        short,
                        needs_lfn,
                        ATTR_DIRECTORY,
                        my_cluster as u32,
                        0,
                        date,
                        time,
                    );
                    let mut sub = Vec::new();
                    // "." and ".." carry no long names.
                    let mut dot = [b' '; 11];
                    dot[0] = b'.';
                    write_entry(
                        &mut sub,
                        ".",
                        dot,
                        false,
                        ATTR_DIRECTORY,
                        my_cluster as u32,
                        0,
                        date,
                        time,
                    );
                    let mut dotdot = [b' '; 11];
                    dotdot[0] = b'.';
                    dotdot[1] = b'.';
                    // A ".." pointing at the root uses cluster 0 even on FAT32.
                    let parent_ref = if parent_cluster == 2 || parent_cluster == 0 {
                        0
                    } else {
                        parent_cluster
                    };
                    write_entry(
                        &mut sub,
                        "..",
                        dotdot,
                        false,
                        ATTR_DIRECTORY,
                        parent_ref as u32,
                        0,
                        date,
                        time,
                    );
                    emit(
                        children, cur, layout, image, my_cluster, &mut sub, date, time,
                    )?;
                    if sub.len() > p.clusters * cluster_bytes {
                        return Err(format!("directory `{}` overflows its clusters", name));
                    }
                    let off = layout.cluster_offset(p.first_cluster);
                    image[off..off + sub.len()].copy_from_slice(&sub);
                }
                Node::File { name, data, .. } => {
                    write_entry(
                        entries_out,
                        name,
                        short,
                        needs_lfn,
                        ATTR_ARCHIVE,
                        p.first_cluster as u32,
                        data.len() as u32,
                        date,
                        time,
                    );
                    if !data.is_empty() {
                        let off = layout.cluster_offset(p.first_cluster);
                        image[off..off + data.len()].copy_from_slice(data);
                    }
                }
            }
        }
        Ok(())
    }

    let mut root_entries_bytes = Vec::new();
    {
        // Volume label leads the root directory.
        let mut label11 = [b' '; 11];
        for (i, &b) in params.volume_label.as_bytes().iter().take(11).enumerate() {
            label11[i] = b.to_ascii_uppercase();
        }
        let mut e = [0u8; DIR_ENTRY_SIZE];
        e[..11].copy_from_slice(&label11);
        e[11] = ATTR_VOLUME_ID;
        e[14..16].copy_from_slice(&time.to_le_bytes());
        e[16..18].copy_from_slice(&date.to_le_bytes());
        e[18..20].copy_from_slice(&date.to_le_bytes());
        e[22..24].copy_from_slice(&time.to_le_bytes());
        e[24..26].copy_from_slice(&date.to_le_bytes());
        root_entries_bytes.extend_from_slice(&e);
    }
    let mut cursor = Cursor {
        planned: &planned,
        idx: if layout.fat32 { 1 } else { 0 },
    };
    emit(
        &tree,
        &mut cursor,
        &layout,
        &mut image,
        root_first_cluster,
        &mut root_entries_bytes,
        date,
        time,
    )?;

    if layout.fat32 {
        let cap = planned[0].clusters * cluster_bytes;
        if root_entries_bytes.len() > cap {
            return Err("FAT32 root directory overflows its clusters".to_string());
        }
        let off = layout.cluster_offset(2);
        image[off..off + root_entries_bytes.len()].copy_from_slice(&root_entries_bytes);
    } else {
        let root_off = (layout.reserved_sectors + 2 * layout.fat_sectors) * SECTOR_SIZE;
        let cap = layout.root_dir_sectors() * SECTOR_SIZE;
        if root_entries_bytes.len() > cap {
            return Err("FAT16 root directory overflow".to_string());
        }
        image[root_off..root_off + root_entries_bytes.len()].copy_from_slice(&root_entries_bytes);
    }

    Ok(image)
}

// ---------------------------------------------------------------------------
// Reader / dumper (parity)
// ---------------------------------------------------------------------------

pub struct DumpFile {
    pub path: String,
    pub is_dir: bool,
    pub attr: u8,
    pub size: u32,
    pub sha256: String,
    pub contiguous: bool,
    /// Byte offset of the first data cluster inside the filesystem; 0 for
    /// an entry with no cluster chain.
    pub data_offset: u64,
}

struct Reader<'a> {
    image: &'a [u8],
    fat32: bool,
    fat_off: usize,
    sectors_per_cluster: usize,
    data_start_sector: usize,
    cluster_count: usize,
}

impl<'a> Reader<'a> {
    fn fat_entry(&self, cluster: usize) -> u32 {
        if self.fat32 {
            let off = self.fat_off + cluster * 4;
            u32::from_le_bytes([
                self.image[off],
                self.image[off + 1],
                self.image[off + 2],
                self.image[off + 3],
            ]) & 0x0FFF_FFFF
        } else {
            let off = self.fat_off + cluster * 2;
            u16::from_le_bytes([self.image[off], self.image[off + 1]]) as u32
        }
    }

    fn is_eoc(&self, v: u32) -> bool {
        if self.fat32 {
            v >= 0x0FFF_FFF8
        } else {
            v >= 0xFFF8
        }
    }

    fn cluster_bytes(&self) -> usize {
        self.sectors_per_cluster * SECTOR_SIZE
    }

    fn cluster_offset(&self, cluster: usize) -> usize {
        (self.data_start_sector + (cluster - 2) * self.sectors_per_cluster) * SECTOR_SIZE
    }

    /// Follow a chain; returns (bytes, contiguous).
    fn read_chain(&self, first: usize, limit: Option<usize>) -> Result<(Vec<u8>, bool), String> {
        let mut out = Vec::new();
        let mut contiguous = true;
        let mut cluster = first;
        let mut hops = 0usize;
        if first == 0 {
            return Ok((out, true));
        }
        loop {
            if cluster < 2 || cluster >= self.cluster_count + 2 {
                return Err(format!("FAT chain references invalid cluster {}", cluster));
            }
            hops += 1;
            if hops > self.cluster_count {
                return Err("FAT chain loop detected".to_string());
            }
            let off = self.cluster_offset(cluster);
            if off + self.cluster_bytes() > self.image.len() {
                return Err(format!("cluster {} lies beyond the image", cluster));
            }
            out.extend_from_slice(&self.image[off..off + self.cluster_bytes()]);
            let next = self.fat_entry(cluster);
            if self.is_eoc(next) {
                break;
            }
            if next as usize != cluster + 1 {
                contiguous = false;
            }
            cluster = next as usize;
        }
        if let Some(l) = limit {
            if l > out.len() {
                return Err(format!("file size {} exceeds chain bytes {}", l, out.len()));
            }
            out.truncate(l);
        }
        Ok((out, contiguous))
    }

    fn walk_dir(
        &self,
        entries: &[u8],
        prefix: &str,
        out: &mut Vec<DumpFile>,
        label: &mut Option<String>,
    ) -> Result<(), String> {
        let mut i = 0;
        let mut pending_lfn: Vec<(u8, Vec<u16>)> = Vec::new();
        while i + DIR_ENTRY_SIZE <= entries.len() {
            let e = &entries[i..i + DIR_ENTRY_SIZE];
            i += DIR_ENTRY_SIZE;
            if e[0] == 0 {
                break; // end of directory
            }
            if e[0] == 0xE5 {
                pending_lfn.clear();
                continue; // deleted
            }
            let attr = e[11];
            if attr == ATTR_LONG_NAME {
                let mut units = Vec::new();
                for &off in &[1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
                    units.push(u16::from_le_bytes([e[off], e[off + 1]]));
                }
                pending_lfn.push((e[0], units));
                continue;
            }
            if attr & ATTR_VOLUME_ID != 0 {
                let l = String::from_utf8_lossy(&e[..11]).trim_end().to_string();
                *label = Some(l);
                pending_lfn.clear();
                continue;
            }
            // Reconstruct the name: prefer the accumulated long name.
            let name = if !pending_lfn.is_empty() {
                pending_lfn.sort_by_key(|(seq, _)| seq & 0x3F);
                let mut units: Vec<u16> = Vec::new();
                for (_, u) in &pending_lfn {
                    units.extend_from_slice(u);
                }
                while matches!(units.last(), Some(&0x0000) | Some(&0xFFFF)) {
                    units.pop();
                }
                char::decode_utf16(units.iter().copied())
                    .map(|c| c.unwrap_or('\u{FFFD}'))
                    .collect::<String>()
            } else {
                let base = String::from_utf8_lossy(&e[..8]).trim_end().to_string();
                let ext = String::from_utf8_lossy(&e[8..11]).trim_end().to_string();
                if ext.is_empty() {
                    base
                } else {
                    format!("{}.{}", base, ext)
                }
            };
            pending_lfn.clear();
            if name == "." || name == ".." {
                continue;
            }
            let first_cluster = ((u16::from_le_bytes([e[20], e[21]]) as u32) << 16)
                | u16::from_le_bytes([e[26], e[27]]) as u32;
            let size = u32::from_le_bytes([e[28], e[29], e[30], e[31]]);
            // The FAT namespace is case-insensitive for every consumer we
            // have; fold to uppercase so short-name and long-name spellings
            // of the same file dump identically.
            let path = format!("{}/{}", prefix, name.to_uppercase());
            let data_offset = if first_cluster >= 2 && (first_cluster as usize) < self.cluster_count + 2 {
                self.cluster_offset(first_cluster as usize) as u64
            } else {
                0
            };
            if attr & ATTR_DIRECTORY != 0 {
                let (sub, contiguous) = self.read_chain(first_cluster as usize, None)?;
                out.push(DumpFile {
                    path: path.clone(),
                    is_dir: true,
                    attr,
                    size: 0,
                    sha256: String::new(),
                    contiguous,
                    data_offset,
                });
                self.walk_dir(&sub, &path, out, label)?;
            } else {
                let (data, contiguous) =
                    self.read_chain(first_cluster as usize, Some(size as usize))?;
                out.push(DumpFile {
                    path,
                    is_dir: false,
                    attr,
                    size,
                    sha256: crate::crypto::sha256::hash_bytes(&data),
                    contiguous,
                    data_offset,
                });
            }
        }
        Ok(())
    }
}

pub struct Dump {
    pub fat_type: &'static str,
    pub bytes_per_sector: u16,
    pub label: Option<String>,
    pub files: Vec<DumpFile>,
}

/// Decode a FAT16/FAT32 filesystem into its comparable logical structure.
/// Incidental identity (OEM name, serial, geometry, timestamps, cluster
/// numbers) is deliberately not part of the dump.
pub fn dump(image: &[u8]) -> Result<Dump, String> {
    if image.len() < 3 * SECTOR_SIZE {
        return Err("FAT image too small".to_string());
    }
    let bs = &image[..SECTOR_SIZE];
    if bs[510] != 0x55 || bs[511] != 0xAA {
        return Err("FAT boot sector signature missing".to_string());
    }
    let bytes_per_sector = u16::from_le_bytes([bs[11], bs[12]]);
    if bytes_per_sector as usize != SECTOR_SIZE {
        return Err(format!("unsupported FAT sector size {}", bytes_per_sector));
    }
    let sectors_per_cluster = bs[13] as usize;
    let reserved = u16::from_le_bytes([bs[14], bs[15]]) as usize;
    let num_fats = bs[16] as usize;
    let root_entries = u16::from_le_bytes([bs[17], bs[18]]) as usize;
    let total16 = u16::from_le_bytes([bs[19], bs[20]]) as u64;
    let fat_size_16 = u16::from_le_bytes([bs[22], bs[23]]) as usize;
    let total32 = u32::from_le_bytes([bs[32], bs[33], bs[34], bs[35]]) as u64;
    let fat_size_32 = u32::from_le_bytes([bs[36], bs[37], bs[38], bs[39]]) as usize;
    let total_sectors = if total16 != 0 { total16 } else { total32 };
    let fat_sectors = if fat_size_16 != 0 {
        fat_size_16
    } else {
        fat_size_32
    };
    if sectors_per_cluster == 0 || num_fats == 0 || fat_sectors == 0 || total_sectors == 0 {
        return Err("implausible FAT BPB".to_string());
    }
    let root_dir_sectors = (root_entries * DIR_ENTRY_SIZE).div_ceil(SECTOR_SIZE);
    let data_start = reserved + num_fats * fat_sectors + root_dir_sectors;
    if data_start >= total_sectors as usize || total_sectors as usize * SECTOR_SIZE > image.len() {
        return Err("FAT BPB describes more sectors than the image holds".to_string());
    }
    let cluster_count = (total_sectors as usize - data_start) / sectors_per_cluster;
    let fat32 = if cluster_count < 4085 {
        return Err("FAT12 volumes are not supported".to_string());
    } else {
        cluster_count >= 65525
    };
    let reader = Reader {
        image,
        fat32,
        fat_off: reserved * SECTOR_SIZE,
        sectors_per_cluster,
        data_start_sector: data_start,
        cluster_count,
    };
    let mut label = None;
    let mut files = Vec::new();
    if fat32 {
        let root_cluster = u32::from_le_bytes([bs[44], bs[45], bs[46], bs[47]]) as usize;
        let (root, _) = reader.read_chain(root_cluster, None)?;
        reader.walk_dir(&root, "", &mut files, &mut label)?;
    } else {
        let root_off = (reserved + num_fats * fat_sectors) * SECTOR_SIZE;
        let root = &image[root_off..root_off + root_entries * DIR_ENTRY_SIZE];
        reader.walk_dir(root, "", &mut files, &mut label)?;
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Dump {
        fat_type: if fat32 { "FAT32" } else { "FAT16" },
        bytes_per_sector,
        label,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_oem_name_is_an_argument() {
        assert_eq!(&oem_name("MYOS").unwrap(), b"MYOS    ");
        assert!(oem_name("").is_err());
        assert!(oem_name("NINECHARS").is_err());
        assert!(oem_name("BAD\u{7f}").is_err());
        let image = build(&params(32 * 1024 * 1024), &[], &[]).unwrap();
        assert_eq!(&image[3..11], b"TESTOEM ");
    }

    fn params(bytes: u64) -> Params {
        Params {
            total_bytes: bytes,
            volume_label: "ESP".to_string(),
            serial: 0x1234_5678,
            epoch_secs: 1,
            oem: *b"TESTOEM ",
        }
    }

    fn esp_tree() -> Vec<(String, Vec<u8>)> {
        vec![
            (
                "EFI/BOOT/BOOTX64.EFI".to_string(),
                vec![0x4D, 0x5A, 1, 2, 3],
            ),
            ("EFI/SALTYOS/stage2.efi".to_string(), vec![7u8; 5000]),
            ("EFI/SALTYOS/stage3.bin".to_string(), vec![9u8; 100]),
            (
                "EFI/SALTYOS/kernite.elf".to_string(),
                vec![0x7F, b'E', b'L', b'F'],
            ),
        ]
    }

    #[test]
    fn fat16_build_and_dump() {
        let img = build(&params(32 * 1024 * 1024), &esp_tree(), &[]).unwrap();
        assert_eq!(img.len(), 32 * 1024 * 1024);
        let d = dump(&img).unwrap();
        assert_eq!(d.fat_type, "FAT16");
        assert_eq!(d.label.as_deref(), Some("ESP"));
        let paths: Vec<&str> = d.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/EFI",
                "/EFI/BOOT",
                "/EFI/BOOT/BOOTX64.EFI",
                "/EFI/SALTYOS",
                "/EFI/SALTYOS/KERNITE.ELF",
                "/EFI/SALTYOS/STAGE2.EFI",
                "/EFI/SALTYOS/STAGE3.BIN",
            ]
        );
        for f in &d.files {
            assert!(f.contiguous, "{} not contiguous", f.path);
        }
        let s2 = d
            .files
            .iter()
            .find(|f| f.path.ends_with("STAGE2.EFI"))
            .unwrap();
        assert_eq!(s2.size, 5000);
        assert_eq!(
            s2.sha256,
            crate::crypto::sha256::hash_bytes(&vec![7u8; 5000])
        );
        assert_eq!(s2.attr & ATTR_ARCHIVE, ATTR_ARCHIVE);

        // Deterministic: same inputs, same bytes.
        assert_eq!(img, build(&params(32 * 1024 * 1024), &esp_tree(), &[]).unwrap());
    }

    #[test]
    fn fat32_build_and_dump() {
        let img = build(&params(64 * 1024 * 1024), &esp_tree(), &[]).unwrap();
        let d = dump(&img).unwrap();
        assert_eq!(d.fat_type, "FAT32");
        assert_eq!(d.files.len(), 7);
        assert!(d.files.iter().all(|f| f.contiguous));
        // Backup boot sector in place.
        assert_eq!(&img[..SECTOR_SIZE], &img[6 * SECTOR_SIZE..7 * SECTOR_SIZE]);
    }

    #[test]
    fn required_bytes_is_the_smallest_size_that_builds() {
        const MIB: u64 = 1024 * 1024;
        // Small tree: the floor wins.
        assert_eq!(required_bytes(&esp_tree(), &[], 8 * MIB, MIB).unwrap(), 8 * MIB);
        // A payload above the floor grows the size, and the answer is exact:
        // it builds, and one step less does not.
        let mut big = esp_tree();
        big.push((
            "EFI/SALTYOS/initrd.img".to_string(),
            vec![0xA5u8; 20 * MIB as usize],
        ));
        let need = required_bytes(&big, &[], 8 * MIB, MIB).unwrap();
        assert!(need > 20 * MIB && need % MIB == 0, "{need}");
        assert!(build(&params(need), &big, &[]).is_ok());
        assert!(build(&params(need - MIB), &big, &[]).is_err());
        // Deterministic.
        assert_eq!(need, required_bytes(&big, &[], 8 * MIB, MIB).unwrap());
    }

    /// A file with a requested alignment starts on it and stays one run,
    /// on FAT16 and FAT32, after files of sizes that leave the allocator
    /// off the boundary; the skipped clusters count as free.
    #[test]
    fn aligned_file_starts_on_its_boundary() {
        const MIB: u64 = 1024 * 1024;
        let mut tree = esp_tree();
        tree.push(("EFI/SALTYOS/odd.bin".to_string(), vec![1u8; 1537]));
        tree.push(("EFI/SALTYOS/boot.state".to_string(), vec![0u8; 8192]));
        let aligned = [("EFI/SALTYOS/boot.state".to_string(), 4096u64)];
        for bytes in [32 * MIB, 100 * MIB] {
            let img = build(&params(bytes), &tree, &aligned).unwrap();
            let d = dump(&img).unwrap();
            let state = d
                .files
                .iter()
                .find(|f| f.path == "/EFI/SALTYOS/BOOT.STATE")
                .unwrap();
            assert!(state.contiguous);
            assert_eq!(state.size, 8192);
            assert_eq!(state.data_offset % 4096, 0, "{bytes}: {}", state.data_offset);
            // Unaligned files keep the sequential placement.
            assert!(d.files.iter().all(|f| f.contiguous));
            if bytes >= 64 * MIB {
                // FSInfo's free count matches the FAT's zero entries.
                let reserved = u16::from_le_bytes([img[14], img[15]]) as usize;
                let fat_sectors = u32::from_le_bytes([img[36], img[37], img[38], img[39]]) as usize;
                let total = u32::from_le_bytes([img[32], img[33], img[34], img[35]]) as usize;
                let spc = img[13] as usize;
                let clusters = (total - reserved - 2 * fat_sectors) / spc;
                let fat = &img[reserved * SECTOR_SIZE..];
                let zero = (2..clusters + 2)
                    .filter(|c| fat[c * 4..c * 4 + 4] == [0, 0, 0, 0])
                    .count();
                let free = u32::from_le_bytes([
                    img[SECTOR_SIZE + 488],
                    img[SECTOR_SIZE + 489],
                    img[SECTOR_SIZE + 490],
                    img[SECTOR_SIZE + 491],
                ]) as usize;
                assert_eq!(free, zero);
            }
            // Deterministic.
            assert_eq!(img, build(&params(bytes), &tree, &aligned).unwrap());
        }
        // The size search accounts for the alignment.
        let need = required_bytes(&tree, &aligned, 8 * MIB, MIB).unwrap();
        assert!(build(&params(need), &tree, &aligned).is_ok());
        // Requests are validated.
        let unknown = [("EFI/SALTYOS/absent".to_string(), 4096u64)];
        assert!(build(&params(32 * MIB), &tree, &unknown).is_err());
        let odd = [("EFI/SALTYOS/boot.state".to_string(), 3000u64)];
        assert!(build(&params(32 * MIB), &tree, &odd).is_err());
        let huge = [("EFI/SALTYOS/boot.state".to_string(), 2 * MIB)];
        assert!(build(&params(32 * MIB), &tree, &huge).is_err());
        let twice = [
            ("EFI/SALTYOS/boot.state".to_string(), 4096u64),
            ("efi/saltyos/BOOT.STATE".to_string(), 4096u64),
        ];
        assert!(build(&params(32 * MIB), &tree, &twice).is_err());
    }

    #[test]
    fn dos_datetime_clamps_to_1980() {
        let (date, time) = dos_datetime(1);
        assert_eq!(date, (0 << 9) | (1 << 5) | 1); // 1980-01-01
        assert_eq!(time, 0);
        let (date2, _) = dos_datetime(DOS_EPOCH_FLOOR + 86_400);
        assert_eq!(date2, (0 << 9) | (1 << 5) | 2); // 1980-01-02
    }

    #[test]
    fn short_name_rules() {
        let mut used = Vec::new();
        let (s, lfn) = short_name("BOOTX64.EFI", &mut used).unwrap();
        assert_eq!(&s, b"BOOTX64 EFI");
        assert!(!lfn);
        let (s2, lfn2) = short_name("stage2.efi", &mut used).unwrap();
        assert_eq!(&s2, b"STAGE2  EFI");
        assert!(lfn2);
        // Collision forces a ~N tail.
        let (_s3, _) = short_name("Stage2.EFI", &mut used).unwrap();
        assert!(used.last().unwrap().starts_with(b"STAGE2~1"));
    }
}
