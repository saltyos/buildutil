//! SPDX-License-Identifier: GPL-2.0-only
//! flake — SaltyFS format 2 image reader, verifier and parity dumper
//!
//! Reads the format definitions of mod.rs, reports every tag, structure,
//! log, seal or allocation violation (`verify`) and emits a canonical
//! logical dump for parity comparison (`dump_text`). A dirty log is
//! replayed into a memory overlay before verification so the checked state
//! is the certified state; the dirtiness itself is reported. An encrypted
//! volume is unlocked from its keyslot area with the passphrase or volume
//! key the caller supplies; sealed images are opened under the image key,
//! and compressed or absent extents are decoded or fetched from the store
//! when a file's content is read.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

use super::{
    AXIS_MIXED, AXIS_SENSITIVE, BLOCK_SIZE, COMPRESSION_LZ4, COMPRESSION_NONE, COMPRESSION_UNIT, COMPRESSION_ZSTD, DATA_TAG_RUN_MAX, ENCODING_INDIRECT, ENCODING_PLAIN, EXTENT_ABSENT,
    EXTENT_HEADER_SIZE, EXTENT_HOLE, EXTENT_INLINE, EXTENT_REGULAR, INODE_CASEFOLD, INODE_CASE_AXIS_SHIFT, INODE_DIRECTORY_LINK, INODE_FLAGS_DEFINED, INODE_HIDDEN,
    INODE_NORM_AXIS_SHIFT, INODE_RETAINED, INODE_SIZE, ITEM_DATA_TAG, ITEM_DEVICE, ITEM_EXTENT_DATA, ITEM_INODE,
    Key, Keys, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFSOCK, STATE_DIRTY, SUITE_PLAIN, SUITE_XAES_256_GCM, SUITE_XCHACHA20_POLY1305, Superblock,
    Unlock, codec, get16, get32, get64, seal,
};

#[path = "read_graph.rs"]
mod graph;
pub use graph::Accounting;

pub(super) struct ImageReader {
    file: File,
    pub(super) len: u64,
    /// Replayed home copies: the certified bytes of an address the log has
    /// not yet copied home.
    pub(super) overlay: BTreeMap<u64, Vec<u8>>,
    /// The volume's keys once the superblock is read and, under an
    /// encrypted suite, a keyslot is opened.
    keys: Option<Keys>,
}

impl ImageReader {
    fn open(path: &Path) -> Result<ImageReader, String> {
        let file = File::open(path).map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
        let len = file.metadata().map_err(|e| format!("cannot stat {}: {}", path.display(), e))?.len();
        Ok(ImageReader { file, len, overlay: BTreeMap::new(), keys: None })
    }

    fn keys(&self) -> Result<&Keys, String> { self.keys.as_ref().ok_or_else(|| "volume keys are not available".to_string()) }

    /// The device bytes of one block, ignoring the replay overlay.
    pub(super) fn raw_block(&self, block_nr: u64) -> Result<Vec<u8>, String> {
        let off = block_nr.checked_mul(BLOCK_SIZE as u64).ok_or_else(|| format!("block {} offset overflows", block_nr))?;
        let end = off.checked_add(BLOCK_SIZE as u64).ok_or_else(|| format!("block {} end offset overflows", block_nr))?;
        if end > self.len { return Err(format!("block {} lies beyond the image", block_nr)); }
        let mut buf = vec![0u8; BLOCK_SIZE];
        crate::platform::read_exact_at(&self.file, &mut buf, off).map_err(|e| format!("cannot read block {}: {}", block_nr, e))?;
        Ok(buf)
    }

    /// The certified bytes of one block: the overlay's copy when the log
    /// holds a newer image, the device's otherwise. Bitmap pages and log
    /// records are read this way; they are never sealed.
    pub(super) fn read_block(&self, block_nr: u64) -> Result<Vec<u8>, String> {
        if let Some(image) = self.overlay.get(&block_nr) { return Ok(image.clone()); }
        self.raw_block(block_nr)
    }

    /// A tree node or data block opened under the volume's keys: the tag
    /// is verified (and the image decrypted) for `(address, birth)`.
    pub(super) fn read_image(&self, address: u64, birth: u64, tag: &[u8; 16]) -> Result<Vec<u8>, String> {
        let mut image = self.read_block(address)?;
        self.keys()?.open_image(&mut image, address, birth, tag)?;
        Ok(image)
    }
}

/// The fresh-image writer has no transaction or hold protocol for replacing
/// a volume that carries pins or a dirty log; an invalid copy never hides a
/// valid one that does.
pub(super) fn refuse_overwrite(file: &File) -> Result<(), String> {
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    let mut candidates = vec![0u64, 1];
    let read = |base: u64| -> Result<Option<Superblock>, String> {
        let start = base * BLOCK_SIZE as u64;
        if start + BLOCK_SIZE as u64 > len { return Ok(None); }
        let mut bytes = vec![0; BLOCK_SIZE];
        crate::platform::read_exact_at(file, &mut bytes, start).map_err(|e| e.to_string())?;
        if &bytes[..8] != super::MAGIC { return Ok(None); }
        Ok(Superblock::parse(&bytes).ok())
    };
    let mut seen = Vec::new();
    for base in candidates.clone() {
        if let Some(sb) = read(base)? {
            if sb.total_blocks >= 2 && !candidates.contains(&(sb.total_blocks - 1)) { candidates.push(sb.total_blocks - 1); }
            seen.push(sb);
        }
    }
    if let Some(last) = candidates.get(2).copied() {
        if let Some(sb) = read(last)? { seen.push(sb); }
    }
    for sb in seen {
        if !sb.registry_root.is_null() || sb.state == STATE_DIRTY {
            return Err("fresh-image writer refuses to overwrite a SaltyFS volume with pins or a dirty log".into());
        }
    }
    Ok(())
}

fn select_superblock(reader: &ImageReader) -> Result<(Superblock, bool, Vec<String>), String> {
    let mut errors = Vec::new();
    let mut valid: Vec<(&str, Superblock, Vec<u8>)> = Vec::new();
    let mut raw_copies = Vec::new();
    for (name, block_nr) in [("A", 0u64), ("B", 1u64)] {
        match reader.raw_block(block_nr).and_then(|raw| Superblock::parse(&raw).map(|sb| (sb, raw))) {
            Ok((sb, raw)) => { raw_copies.push(raw.clone()); valid.push((name, sb, raw)); }
            Err(error) => errors.push(format!("superblock {name}: {error}")),
        }
    }
    // Copy C sits at the last block; without a valid A or B the image
    // length names it.
    let total = valid.first().map_or(reader.len / BLOCK_SIZE as u64, |(_, sb, _)| sb.total_blocks);
    if total >= 2 {
        match reader.raw_block(total - 1).and_then(|raw| Superblock::parse(&raw).map(|sb| (sb, raw))) {
            Ok((sb, raw)) => { raw_copies.push(raw.clone()); valid.push(("C", sb, raw)); }
            Err(error) => errors.push(format!("superblock C: {error}")),
        }
    }
    if valid.is_empty() { return Err(format!("no valid superblock: {}", errors.join("; "))); }
    let mut selected = 0;
    for index in 1..valid.len() {
        if valid[index].1.checkpoint_seq > valid[selected].1.checkpoint_seq { selected = index; }
    }
    let identical = errors.is_empty() && valid.len() == 3 && raw_copies.windows(2).all(|pair| pair[0] == pair[1]);
    let (_, sb, _) = valid.swap_remove(selected);
    Ok((sb, identical, errors))
}

/// The keys of the selected superblock: the plain suite's from the KDF
/// salt, an encrypted suite's from the keyslot the caller's unlock opens.
fn unlock_keys(reader: &ImageReader, sb: &Superblock, unlock: Option<&Unlock>) -> Result<Keys, String> {
    if !sb.encrypted() {
        if unlock.is_some() { return Err("the volume is not encrypted; no passphrase or volume key applies".into()); }
        return sb.plain_keys().ok_or_else(|| "plain volume without keys".to_string());
    }
    let slots = graph::keyslot_area(reader, sb)?;
    let unlock = unlock.ok_or("the volume is encrypted; pass --passphrase or --volume-key")?;
    sb.unlock(&slots, unlock)
}

pub(super) type ItemMap = BTreeMap<Key, Vec<u8>>;

#[derive(Debug)]
pub(super) struct Inode {
    pub(super) size: u64,
    pub(super) blocks: u64,
    pub(super) nlink: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
    pub(super) incarnation: u64,
    pub(super) flags: u32,
    pub(super) birth: u64,
    pub(super) content_revision: u64,
    pub(super) namespace_revision: u64,
    pub(super) hidden_owner: u64,
    pub(super) plugin: [u8; 4],
    pub(super) project_id: u32,
}

fn posix_alias(id: u64, namespace: u8) -> u32 {
    if (id >> 56) as u8 == namespace && id & 0x00ff_ffff_0000_0000 == 0 { id as u32 } else { u32::MAX }
}

pub(super) fn parse_inode(data: &[u8]) -> Result<Inode, String> {
    if data.len() != INODE_SIZE { return Err(format!("inode item has invalid size ({} bytes, expected {})", data.len(), INODE_SIZE)); }
    if data[0x7C..0x80].iter().any(|b| *b != 0) { return Err("inode has nonzero reserved bytes".into()); }
    let flags = get32(data, 0x70);
    if flags & !INODE_FLAGS_DEFINED != 0 { return Err(format!("inode sets undefined flag bits {:#x}", flags & !INODE_FLAGS_DEFINED)); }
    let kind = get32(data, 0x68) & S_IFMT;
    if flags & INODE_DIRECTORY_LINK != 0 && kind != S_IFLNK {
        return Err("a directory-link flag on an inode that is not a symbolic link".into());
    }
    // Each axis is 0 sensitive, 1 insensitive or 2 mixed, and CASEFOLD is
    // the projection of a case axis that is not sensitive.
    let case_axis = ((flags >> INODE_CASE_AXIS_SHIFT) & 3) as u8;
    let norm_axis = ((flags >> INODE_NORM_AXIS_SHIFT) & 3) as u8;
    if case_axis > AXIS_MIXED || norm_axis > AXIS_MIXED {
        return Err("inode encodes an undefined case or normalization axis".into());
    }
    if (flags & INODE_CASEFOLD != 0) != (case_axis != AXIS_SENSITIVE) {
        return Err("inode CASEFOLD flag disagrees with its case axis".into());
    }
    // Only a directory indexes names; every other inode is sensitive on
    // both axes.
    if kind != S_IFDIR && (case_axis != AXIS_SENSITIVE || norm_axis != AXIS_SENSITIVE) {
        return Err("a case or normalization axis on an inode that is not a directory".into());
    }
    // A hidden inode is storage an owner reaches; a retained inode is a
    // narrowed copy that drops HIDDEN. No inode is both.
    if flags & INODE_HIDDEN != 0 && flags & INODE_RETAINED != 0 {
        return Err("inode is both hidden and retained".into());
    }
    // A project id is below the reserved sentinel; hidden storage belongs to
    // project zero, its owner's project carrying its use.
    let project_id = get32(data, 0x78);
    if project_id == u32::MAX { return Err("inode carries the reserved project id".into()); }
    if flags & INODE_HIDDEN != 0 && project_id != 0 { return Err("hidden inode with a nonzero project id".into()); }
    let mut plugin = [0u8; 4];
    plugin.copy_from_slice(&data[0x74..0x78]);
    if plugin[super::PLUGIN_DIR_HASH] > super::DIR_HASH_SIPHASH || plugin[1] != 0 || plugin[super::PLUGIN_COMPRESSION] > COMPRESSION_ZSTD || plugin[3] != 0 {
        return Err("inode selects an unsupported plugin".into());
    }
    Ok(Inode {
        birth: get64(data, 0x00),
        size: get64(data, 0x08),
        blocks: get64(data, 0x10),
        uid: posix_alias(get64(data, 0x18), 0x01),
        gid: posix_alias(get64(data, 0x20), 0x02),
        incarnation: get64(data, 0x48),
        content_revision: get64(data, 0x50),
        namespace_revision: get64(data, 0x58),
        hidden_owner: get64(data, 0x60),
        mode: get32(data, 0x68),
        nlink: get32(data, 0x6C),
        flags,
        plugin,
        project_id,
    })
}

pub(super) fn item_of(items: &ItemMap, key: Key) -> Option<&Vec<u8>> { items.get(&key) }

/// One subvolume version as file content is read from it: its item tree,
/// its data-tag tree, and the store that holds any absent extent.
#[derive(Clone, Copy)]
pub(super) struct View<'a> {
    pub(super) items: &'a ItemMap,
    pub(super) tags: &'a ItemMap,
    pub(super) store: Option<&'a graph::Store>,
}

/// The tag of data block `address` born at `birth`, from the tag run that
/// covers it.
fn data_tag(tags: &ItemMap, address: u64, birth: u64) -> Result<[u8; 16], String> {
    let from = Key::new(0, address.saturating_sub(DATA_TAG_RUN_MAX as u64 - 1), ITEM_DATA_TAG, 0);
    let to = Key::new(0, address, ITEM_DATA_TAG, u64::MAX);
    for (key, run) in tags.range(from..=to) {
        if key.offset != birth { continue; }
        let index = (address - key.objectid) as usize;
        if index * 16 + 16 <= run.len() {
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&run[index * 16..index * 16 + 16]);
            return Ok(tag);
        }
    }
    Err(format!("data block {address} born at {birth} has no tag"))
}

/// The logical bytes of one regular extent: its blocks opened under the
/// keys and, for a compressed extent, its frame decoded.
fn regular_extent_content(reader: &ImageReader, view: View<'_>, extent: &[u8], logical: u64) -> Result<Vec<u8>, String> {
    let birth = get64(extent, 0);
    let address = get64(extent, 0x10);
    let stored = get64(extent, 0x18) as usize;
    let compression = extent[0x21];
    let mut bytes = Vec::with_capacity(stored);
    for i in 0..(stored / BLOCK_SIZE) as u64 {
        let tag = data_tag(view.tags, address + i, birth)?;
        bytes.extend_from_slice(&reader.read_image(address + i, birth, &tag)?);
    }
    let logical = logical as usize;
    match compression {
        COMPRESSION_NONE => { bytes.truncate(logical); Ok(bytes) }
        COMPRESSION_LZ4 => {
            let mut out = vec![0u8; logical];
            codec::lz4::decompress_padded(&bytes, &mut out)?;
            Ok(out)
        }
        COMPRESSION_ZSTD => {
            let header = codec::zstd::frame_header(&bytes)?;
            if header.window_size > COMPRESSION_UNIT as u64 && !header.single_segment { return Err("compressed extent window exceeds the unit".into()); }
            if header.content_size.is_some_and(|size| size != logical as u64) { return Err("compressed extent content size disagrees with its length".into()); }
            let out = codec::zstd::decompress(&bytes)?;
            if out.len() != logical { return Err("compressed extent decodes to the wrong length".into()); }
            Ok(out)
        }
        _ => Err("unsupported compression".into()),
    }
}

/// Feed a file's logical content to `sink` in order: extents decoded,
/// holes and gaps as zeros, absent chunks fetched from the store, indirect
/// inline data read from its hidden inode.
#[allow(clippy::too_many_arguments)]
fn for_each_file_range(reader: &ImageReader, view: View<'_>, locality: u64, objectid: u64, size: u64, depth: usize, sink: &mut dyn FnMut(&[u8])) -> Result<(), String> {
    if depth >= super::MAX_BTREE_DEPTH { return Err("indirect file-content cycle".into()); }
    let mut zeros = |sink: &mut dyn FnMut(&[u8]), mut count: u64| {
        let block = [0u8; BLOCK_SIZE];
        while count > 0 { let n = count.min(BLOCK_SIZE as u64) as usize; sink(&block[..n]); count -= n as u64; }
    };
    let mut cursor = 0u64;
    let from = Key::new(locality, objectid, ITEM_EXTENT_DATA, 0);
    let to = Key::new(locality, objectid, ITEM_EXTENT_DATA, u64::MAX);
    for (&key, extent) in view.items.range(from..=to) {
        let shape = graph::extent_shape(key, extent)?;
        if shape.start >= size { break; }
        if shape.start < cursor { return Err("overlapping extents".into()); }
        zeros(sink, shape.start - cursor);
        let take = shape.len.min(size - shape.start);
        match (extent[0x20], get16(extent, 0x22)) {
            (EXTENT_INLINE, ENCODING_INDIRECT) => {
                let hidden = (get64(extent, EXTENT_HEADER_SIZE), get64(extent, EXTENT_HEADER_SIZE + 8));
                let mut inner = Vec::new();
                for_each_file_range(reader, view, hidden.0, hidden.1, take, depth + 1, &mut |bytes| inner.extend_from_slice(bytes))?;
                sink(&inner);
            }
            (EXTENT_INLINE, ENCODING_PLAIN) => sink(&extent[EXTENT_HEADER_SIZE..EXTENT_HEADER_SIZE + take as usize]),
            (EXTENT_REGULAR, _) => {
                let bytes = regular_extent_content(reader, view, extent, shape.len)?;
                sink(&bytes[..take as usize]);
            }
            (EXTENT_HOLE, _) => zeros(sink, take),
            (EXTENT_ABSENT, _) => {
                let store = view.store.ok_or("absent extent without a store to fetch from")?;
                let mut chunk = [0u8; 32];
                chunk.copy_from_slice(&extent[EXTENT_HEADER_SIZE..EXTENT_HEADER_SIZE + 32]);
                let encoding = store.object(&chunk, seal::KIND_CHUNK)?;
                if encoding.len() as u64 != 1 + shape.len { return Err("absent extent length disagrees with its chunk".into()); }
                sink(&encoding[1..1 + take as usize]);
            }
            _ => return Err("unsupported extent shape".into()),
        }
        cursor = shape.start + take;
    }
    zeros(sink, size.saturating_sub(cursor));
    Ok(())
}

/// The whole logical content of one file.
pub(super) fn file_content(reader: &ImageReader, view: View<'_>, locality: u64, objectid: u64, size: u64) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(size).map_err(|_| "file size exceeds host address space")?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| "cannot allocate file-content output")?;
    for_each_file_range(reader, view, locality, objectid, size, 0, &mut |chunk| bytes.extend_from_slice(chunk))?;
    Ok(bytes)
}

fn file_hash(reader: &ImageReader, view: View<'_>, locality: u64, objectid: u64, size: u64) -> Result<String, String> {
    let mut hash = super::sha256::Sha256::new();
    for_each_file_range(reader, view, locality, objectid, size, 0, &mut |chunk| hash.update(chunk))?;
    Ok(super::primitives::hex(&hash.finalize()))
}

struct DumpNode {
    path: String,
    kind: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    sha256: String,
    target: String,
}

#[allow(clippy::too_many_arguments)]
fn walk_logical(reader: &ImageReader, view: View<'_>, dir: (u64, u64), path: &str, depth: usize, hash_contents: bool, out: &mut Vec<DumpNode>, errors: &mut Vec<String>)
    -> Result<(), String>
{
    if depth > 64 { return Err("directory tree deeper than 64 levels (loop?)".to_string()); }
    for (_, child, dir_type, name_bytes) in graph::dir_entries(view.items, dir.0, dir.1)? {
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        let child_path = format!("{}/{}", path.trim_end_matches('/'), name);
        let Some(inode_raw) = item_of(view.items, Key::new(child.0, child.1, ITEM_INODE, 0)) else {
            errors.push(format!("`{}`: dir item references missing inode", child_path));
            continue;
        };
        let inode = parse_inode(inode_raw)?;
        let expected_type = match inode.mode & S_IFMT {
            S_IFDIR => 4, S_IFLNK => 7, super::S_IFREG => 1, S_IFIFO => 5, S_IFCHR => 2, S_IFBLK => 6, S_IFSOCK => 12,
            _ => { errors.push(format!("`{}`: unknown inode type", child_path)); 0 }
        };
        if dir_type != expected_type { errors.push(format!("`{}`: dir_type {} disagrees with mode {:o}", child_path, dir_type, inode.mode)); }
        if child.0 != dir.1 && inode.mode & S_IFMT == S_IFDIR { errors.push(format!("`{}`: locality {} is not its parent {}", child_path, child.0, dir.1)); }
        let node = |kind: &'static str, size: u64, sha256: String, target: String| DumpNode {
            path: child_path.clone(), kind, mode: inode.mode, uid: inode.uid, gid: inode.gid, nlink: inode.nlink, size, sha256, target,
        };
        match inode.mode & S_IFMT {
            S_IFDIR => {
                out.push(node("dir", 0, String::new(), String::new()));
                walk_logical(reader, view, child, &child_path, depth + 1, hash_contents, out, errors)?;
            }
            S_IFLNK => {
                let target = if hash_contents { file_content(reader, view, child.0, child.1, inode.size)? } else { Vec::new() };
                out.push(node("symlink", inode.size, String::new(), String::from_utf8_lossy(&target).to_string()));
            }
            S_IFCHR | S_IFBLK => {
                let device = item_of(view.items, Key::new(child.0, child.1, ITEM_DEVICE, 0)).map_or(0, |d| get64(d, 0));
                out.push(node("device", 0, String::new(), format!("{}:{}", device >> 32, device & 0xFFFF_FFFF)));
            }
            S_IFIFO => out.push(node("fifo", 0, String::new(), String::new())),
            S_IFSOCK => out.push(node("socket", 0, String::new(), String::new())),
            _ => {
                let sha256 = if hash_contents { file_hash(reader, view, child.0, child.1, inode.size)? } else { String::new() };
                out.push(node("file", inode.size, sha256, String::new()));
            }
        }
    }
    Ok(())
}

struct Analysis {
    sb: Superblock,
    copies_identical: bool,
    nodes: Vec<DumpNode>,
    retained: Vec<(graph::SnapshotSummary, Vec<DumpNode>)>,
    errors: Vec<String>,
    accounting: Accounting,
    catalog_rows: Vec<String>,
    log: graph::LogSummary,
}

fn logical_nodes(reader: &ImageReader, view: View<'_>, hash_contents: bool, errors: &mut Vec<String>) -> Result<Vec<DumpNode>, String> {
    let root = parse_inode(item_of(view.items, Key::new(super::ROOT_INO, super::ROOT_INO, ITEM_INODE, 0)).ok_or("root inode item missing")?)?;
    let mut nodes = vec![DumpNode {
        path: "/".into(), kind: "dir", mode: root.mode, uid: root.uid, gid: root.gid, nlink: root.nlink, size: 0, sha256: String::new(), target: String::new(),
    }];
    walk_logical(reader, view, (super::ROOT_INO, super::ROOT_INO), "", 0, hash_contents, &mut nodes, errors)?;
    nodes.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(nodes)
}

fn analyze(path: &Path, hash_contents: bool, unlock: Option<&Unlock>) -> Result<Analysis, String> {
    let mut reader = ImageReader::open(path)?;
    let (mut sb, copies_identical, mut errors) = select_superblock(&reader)?;
    graph::validate_geometry(&reader, &sb)?;
    let keys = unlock_keys(&reader, &sb, unlock)?;
    reader.keys = Some(keys.clone());
    let log = graph::replay(&mut reader, &mut sb)?;
    let volume = graph::inspect(&reader, &sb, &keys)?;
    errors.extend(graph::bitmap_errors(&reader, &sb, &volume)?);
    errors.extend(volume.findings.iter().cloned());
    let empty = ItemMap::new();
    let tree_items = |root: super::Pointer| -> &ItemMap { volume.trees.get(&root.address).map_or(&empty, |t| &t.items) };
    let live = volume.subvolumes.get(&super::DEFAULT_SUBVOL).ok_or("subvolume 1 missing")?;
    let view = View { items: tree_items(live.row.item_root), tags: tree_items(live.row.tag_root), store: volume.store.as_ref() };
    let nodes = logical_nodes(&reader, view, hash_contents, &mut errors)?;
    let mut retained = Vec::new();
    for snapshot in &volume.snapshots {
        let view = View { items: tree_items(snapshot.row.item_root), tags: tree_items(snapshot.row.tag_root), store: volume.store.as_ref() };
        let nodes = logical_nodes(&reader, view, hash_contents, &mut errors)?;
        retained.push((snapshot.summary(), nodes));
    }
    Ok(Analysis { sb, copies_identical, nodes, retained, errors, accounting: volume.accounting, catalog_rows: volume.catalog_rows, log })
}

/// Counts derive from the validated union of live, retained and registry
/// roots after replay. The image tests are its only consumer.
#[cfg(test)]
pub fn accounting(path: &Path, unlock: Option<&Unlock>) -> Result<Accounting, String> {
    let result = analyze(path, false, unlock)?;
    if !result.errors.is_empty() { return Err(result.errors.join("; ")); }
    Ok(result.accounting)
}

/// The number of certified atoms the log holds above the checkpoint.
#[cfg(test)]
pub fn uncheckpointed_atoms(path: &Path) -> Result<usize, String> { Ok(analyze(path, false, None)?.log.applied) }

fn suite_name(suite: u32) -> &'static str {
    match suite { SUITE_PLAIN => "plain", SUITE_XCHACHA20_POLY1305 => "xchacha20-poly1305", SUITE_XAES_256_GCM => "xaes-256-gcm", _ => "unknown" }
}

/// Canonical logical-structure dump of a plain volume.
pub fn dump_text(path: &Path) -> Result<String, String> { dump_text_with(path, None) }

/// Canonical logical-structure dump. Physical identity (inode numbers,
/// UUIDs, timestamps, block placement, keys) is excluded so that images
/// from different writers dump identically. Snapshot identities remain
/// visible because changing them changes retention authority.
pub fn dump_text_with(path: &Path, unlock: Option<&Unlock>) -> Result<String, String> {
    let Analysis { sb, copies_identical, nodes, retained, errors, catalog_rows, log, .. } = analyze(path, true, unlock)?;
    let mut out = format!(
        "saltyfs layout=2 label={} block-size=4096 incompat={:#x} compat-ro={:#x} casefold-version={} suite={} state={} copies={} replayed={}\n",
        sb.label, sb.incompat, sb.compat_ro, sb.casefold_version, suite_name(sb.suite),
        if sb.state == STATE_DIRTY { "dirty" } else { "clean" }, if copies_identical { "identical" } else { "DIVERGED" }, log.applied,
    );
    for n in &nodes {
        match n.kind {
            "dir" => out.push_str(&format!("dir {} mode={:o} uid={} gid={} nlink={}\n", n.path, n.mode, n.uid, n.gid, n.nlink)),
            "symlink" => out.push_str(&format!("symlink {} -> {} mode={:o} uid={} gid={}\n", n.path, n.target, n.mode, n.uid, n.gid)),
            "device" => out.push_str(&format!("device {} {} mode={:o} uid={} gid={}\n", n.path, n.target, n.mode, n.uid, n.gid)),
            "fifo" | "socket" => out.push_str(&format!("{} {} mode={:o} uid={} gid={}\n", n.kind, n.path, n.mode, n.uid, n.gid)),
            _ => out.push_str(&format!("file {} mode={:o} uid={} gid={} nlink={} size={} sha256={}\n", n.path, n.mode, n.uid, n.gid, n.nlink, n.size, n.sha256)),
        }
    }
    for e in &errors { out.push_str(&format!("ERROR {}\n", e)); }
    for row in catalog_rows { out.push_str(&row); out.push('\n'); }
    for (snapshot, nodes) in retained {
        out.push_str(&format!("snapshot subvol={} epoch={} id={} owner={}:{} deleting={} sealed={}\n",
            snapshot.subvol, snapshot.epoch, snapshot.id, snapshot.owner.0, snapshot.owner.1, snapshot.deleting, snapshot.sealed));
        for node in nodes {
            out.push_str(&format!("  {} {} mode={:o} size={} sha256={} target={}\n", node.kind, node.path, node.mode, node.size, node.sha256, node.target));
        }
    }
    Ok(out)
}

/// Walk a plain volume with the format definitions; report every violation.
pub fn verify(path: &Path) -> Result<Vec<String>, String> { verify_with(path, None) }

/// Walk the image with the format definitions, unlocking an encrypted
/// volume with `unlock`; report every violation.
pub fn verify_with(path: &Path, unlock: Option<&Unlock>) -> Result<Vec<String>, String> {
    let Analysis { sb, copies_identical, mut errors, accounting, log, .. } = analyze(path, false, unlock)?;
    if !copies_identical { errors.push("superblock copies diverge".to_string()); }
    if sb.state == STATE_DIRTY { errors.push(format!("log dirty: {} certified atoms above the checkpoint", log.applied)); }
    errors.extend(log.findings);
    if accounting.combined > accounting.capacity {
        errors.push(format!("retained allocation graph ({} blocks) exceeds capacity ({} blocks)", accounting.combined, accounting.capacity));
    }
    Ok(errors)
}
