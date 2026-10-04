//! SPDX-License-Identifier: GPL-2.0-only
//! flake — SaltyFS format 2 image writer
//!
//! Assembles the three subvolumes of a fresh volume (the default, the key
//! tree and the store), the subvolume table, the pin registry when the
//! default subvolume is sealed at build time, the keyslot area of an
//! encrypted volume, the bitmap and the three superblock copies of a clean
//! checkpoint; places regular files on data extents, compressed per unit
//! when a plugin is chosen, and writes the image. Reached by the writer CLI
//! (`flake saltyfs build`) and by `rootfs::build` for the system rootfs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use super::codec::{fastcdc, lz4, zstd};
use super::cpio::Permissions;
use super::primitives::{self, blake3};
use super::seal;
use super::*;

// ---------------------------------------------------------------------------
// B-tree builder
// ---------------------------------------------------------------------------

/// The header fields every node of one tree shares.
#[derive(Clone, Copy)]
pub(super) struct NodeMeta {
    pub(super) owner: u64,
    pub(super) birth: u64,
    pub(super) tree: u32,
    pub(super) incarnation: u64,
}

fn node_header(block: &mut [u8], meta: NodeMeta, address: u64, level: u16, count: usize) {
    block[0..4].copy_from_slice(NODE_MAGIC);
    put32(block, 0x04, count as u32);
    put64(block, 0x08, meta.owner);
    put64(block, 0x10, meta.birth);
    put64(block, 0x18, address);
    put16(block, 0x20, level);
    put32(block, 0x24, meta.tree);
    put64(block, 0x28, meta.incarnation);
}

pub(super) fn build_leaf(meta: NodeMeta, address: u64, items: &[(Key, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let data_start = NODE_HEADER_SIZE + items.len() * LEAF_ENTRY_SIZE;
    let data_len: usize = items.iter().map(|(_, d)| d.len()).sum();
    if items.len() > LEAF_ENTRY_MAX || data_start + data_len > BLOCK_SIZE {
        return Err(format!("leaf overflow: {} items need {} bytes", items.len(), data_start + data_len));
    }
    let mut block = vec![0u8; BLOCK_SIZE];
    node_header(&mut block, meta, address, 0, items.len());
    let mut entry_off = NODE_HEADER_SIZE;
    let mut data_off = data_start;
    for (key, data) in items {
        if data.len() > PAYLOAD_MAX { return Err(format!("item payload of {} bytes exceeds the format maximum", data.len())); }
        block[entry_off..entry_off + KEY_SIZE].copy_from_slice(&key.pack());
        put32(&mut block, entry_off + KEY_SIZE, data_off as u32);
        put32(&mut block, entry_off + KEY_SIZE + 4, data.len() as u32);
        block[data_off..data_off + data.len()].copy_from_slice(data);
        entry_off += LEAF_ENTRY_SIZE;
        data_off += data.len();
    }
    Ok(block)
}

pub(super) fn build_internal(meta: NodeMeta, address: u64, level: u16, entries: &[(Key, Pointer)]) -> Result<Vec<u8>, String> {
    if entries.is_empty() || entries.len() > INTERNAL_ENTRY_MAX { return Err(format!("internal node overflow: {} pointers", entries.len())); }
    let mut block = vec![0u8; BLOCK_SIZE];
    node_header(&mut block, meta, address, level, entries.len());
    let mut off = NODE_HEADER_SIZE;
    for (key, child) in entries {
        block[off..off + KEY_SIZE].copy_from_slice(&key.pack());
        block[off + KEY_SIZE..off + INTERNAL_ENTRY_SIZE].copy_from_slice(&child.pack());
        off += INTERNAL_ENTRY_SIZE;
    }
    Ok(block)
}

pub(super) fn split_leaves(items: &[(Key, Vec<u8>)]) -> Result<Vec<Vec<(Key, Vec<u8>)>>, String> {
    let mut leaves: Vec<Vec<(Key, Vec<u8>)>> = Vec::new();
    let mut cur: Vec<(Key, Vec<u8>)> = Vec::new();
    let mut cur_data = 0usize;
    for (key, data) in items {
        let mut need = NODE_HEADER_SIZE + (cur.len() + 1) * LEAF_ENTRY_SIZE + cur_data + data.len();
        if (need > BLOCK_SIZE || cur.len() == LEAF_ENTRY_MAX) && !cur.is_empty() {
            leaves.push(std::mem::take(&mut cur));
            cur_data = 0;
            need = NODE_HEADER_SIZE + LEAF_ENTRY_SIZE + data.len();
        }
        if need > BLOCK_SIZE { return Err(format!("single item exceeds block size: {} bytes", data.len())); }
        cur_data += data.len();
        cur.push((*key, data.clone()));
    }
    if !cur.is_empty() { leaves.push(cur); }
    Ok(leaves)
}

/// The referencing tag of a plaintext image as it will lie on the device.
pub(super) fn tag_of(keys: &Keys, block: &[u8], address: u64, birth: u64) -> [u8; 16] {
    let mut copy = block.to_vec();
    keys.seal_image(&mut copy, address, birth)
}

/// Build one tree from `items` starting at `start`; returns the root
/// pointer (with its tag) and the plaintext blocks ordered by block number.
pub(super) fn build_tree(mut items: Vec<(Key, Vec<u8>)>, meta: NodeMeta, start: u64, keys: &Keys) -> Result<(Pointer, Vec<(u64, Vec<u8>)>), String> {
    if items.is_empty() { return Ok((Pointer::NULL, Vec::new())); }
    items.sort_by_key(|(k, _)| *k);
    if items.windows(2).any(|pair| pair[0].0 == pair[1].0) { return Err("duplicate key in tree input".to_string()); }
    let leaf_chunks = split_leaves(&items)?;
    let mut blocks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut next_block = start;
    let mut level: Vec<(Key, Pointer)> = Vec::new();
    for chunk in &leaf_chunks {
        let address = next_block;
        next_block += 1;
        let block = build_leaf(meta, address, chunk)?;
        level.push((chunk[0].0, Pointer { address, birth: meta.birth, tag: tag_of(keys, &block, address, meta.birth) }));
        blocks.push((address, block));
    }
    let mut height = 1u16;
    while level.len() > 1 {
        let mut next: Vec<(Key, Pointer)> = Vec::new();
        for group in level.chunks(INTERNAL_ENTRY_MAX) {
            let address = next_block;
            next_block += 1;
            let block = build_internal(meta, address, height, group)?;
            next.push((group[0].0, Pointer { address, birth: meta.birth, tag: tag_of(keys, &block, address, meta.birth) }));
            blocks.push((address, block));
        }
        level = next;
        height += 1;
    }
    Ok((level[0].1, blocks))
}

// ---------------------------------------------------------------------------
// Metadata assembly
// ---------------------------------------------------------------------------

fn split_parent(path: &str) -> (String, String) {
    let stripped = path.trim_matches('/');
    match stripped.rfind('/') {
        Some(i) => (stripped[..i].to_string(), stripped[i + 1..].to_string()),
        None => (String::new(), stripped.to_string()),
    }
}

/// Namespace prefixes of a `PrincipalId`, whose high byte selects the id
/// space: `0x01` is a POSIX user and `0x02` a POSIX group.
const PRINCIPAL_POSIX_USER: u64 = 0x0100_0000_0000_0000;
const PRINCIPAL_POSIX_GROUP: u64 = 0x0200_0000_0000_0000;

pub(super) fn lookup_perm(perms: &Permissions, path: &str, default_mode: u32) -> (u32, u32, u32) {
    let stripped = path.trim_matches('/');
    let slash = format!("/{}", stripped);
    perms.get(&slash).or_else(|| perms.get(stripped)).copied().unwrap_or((default_mode, 0, 0))
}

fn allocate_node_identity(next_objectid: &mut u64, next_incarnation: &mut u64) -> Result<(u64, u64), String> {
    let objectid = *next_objectid;
    let incarnation = *next_incarnation;
    if objectid == 0 || incarnation == 0 { return Err("SaltyFS node identity allocator reached zero".to_string()); }
    *next_objectid = objectid.checked_add(1).ok_or_else(|| "SaltyFS objectid space exhausted".to_string())?;
    *next_incarnation = incarnation.checked_add(1).ok_or_else(|| "SaltyFS incarnation space exhausted".to_string())?;
    Ok((objectid, incarnation))
}

/// One data run to write: `blocks` stored blocks at `start` holding
/// `bytes` (compressed or plain) of file `file`, unit `unit`.
#[derive(Clone, Debug)]
pub(super) struct Placement {
    pub(super) start: u64,
    pub(super) file: usize,
    /// The unit of the file (`COMPRESSION_UNIT` bytes each), or `None` for
    /// a whole uncompressed file.
    pub(super) unit: Option<usize>,
    pub(super) compression: u8,
    pub(super) blocks: u64,
}

pub(super) struct Metadata {
    pub(super) items: Vec<(Key, Vec<u8>)>,
    pub(super) index_items: Vec<(Key, Vec<u8>)>,
    pub(super) tag_items: Vec<(Key, Vec<u8>)>,
    pub(super) placements: Vec<Placement>,
    pub(super) next_free_block: u64,
    pub(super) next_objectid: u64,
    pub(super) next_incarnation: u64,
    /// Blocks the data extents occupy.
    pub(super) data_blocks: u64,
}

/// An object's key prefix: the directory it was created in, then itself.
#[derive(Clone, Copy, Debug)]
pub(super) struct Object {
    pub(super) locality: u64,
    pub(super) objectid: u64,
}

/// A directory being assembled: its items are keyed under its policy.
struct DirState {
    object: Object,
    policy: Policy,
    /// Byte directory: the offsets taken so a collision probes forward.
    taken: BTreeSet<u64>,
    /// Indexed directory: `class offset -> (member ids in order)`.
    classes: BTreeMap<u64, Vec<u64>>,
    /// Names already admitted under the directory's insensitive axes.
    names: BTreeSet<Vec<u8>>,
    next_member: u64,
}

/// The stored form of one compression unit.
pub(super) fn encode_unit(compression: u8, unit: &[u8]) -> (u8, Vec<u8>) {
    let candidate = match compression {
        COMPRESSION_LZ4 => Some(lz4::compress(unit)),
        COMPRESSION_ZSTD => Some(zstd::compress(unit, false)),
        _ => None,
    };
    match candidate {
        Some(c) if c.len().div_ceil(BLOCK_SIZE) < unit.len().div_ceil(BLOCK_SIZE) => (compression, c),
        _ => (COMPRESSION_NONE, unit.to_vec()),
    }
}

/// Visit the file in compression units; the last unit is short.
pub(super) fn for_each_unit(source: &FileSource, mut visit: impl FnMut(usize, &[u8]) -> Result<(), String>) -> Result<(), String> {
    use std::io::Read;
    match source {
        FileSource::Bytes(b) => {
            if b.is_empty() { return Ok(()); }
            for (i, chunk) in b.chunks(COMPRESSION_UNIT).enumerate() { visit(i, chunk)?; }
            Ok(())
        }
        FileSource::Path(p) => {
            let mut file = File::open(p).map_err(|e| format!("cannot read {}: {}", p.display(), e))?;
            let mut unit = vec![0u8; COMPRESSION_UNIT];
            let mut index = 0usize;
            loop {
                let mut filled = 0;
                while filled < COMPRESSION_UNIT {
                    let n = file.read(&mut unit[filled..]).map_err(|e| format!("read {}: {}", p.display(), e))?;
                    if n == 0 { break; }
                    filled += n;
                }
                if filled == 0 { break; }
                visit(index, &unit[..filled])?;
                index += 1;
                if filled < COMPRESSION_UNIT { break; }
            }
            Ok(())
        }
    }
}

/// The tags of a stored run: each block image as it will lie on the device.
fn run_tags(keys: &Keys, start: u64, bytes: &[u8], blocks: u64, birth: u64) -> Vec<[u8; 16]> {
    let mut tags = Vec::with_capacity(blocks as usize);
    for i in 0..blocks as usize {
        let mut image = vec![0u8; BLOCK_SIZE];
        let from = i * BLOCK_SIZE;
        if from < bytes.len() { let to = (from + BLOCK_SIZE).min(bytes.len()); image[..to - from].copy_from_slice(&bytes[from..to]); }
        tags.push(keys.seal_image(&mut image, start + i as u64, birth));
    }
    tags
}

pub(super) struct SubvolInputs<'a> {
    pub(super) subvol: u64,
    pub(super) contents: &'a Contents,
    pub(super) root_case_axis: u8,
    pub(super) compression: u8,
    pub(super) time_ns: u64,
    pub(super) keys: &'a Keys,
    pub(super) first_data_block: u64,
    pub(super) birth: u64,
}

impl DirState {
    fn new(object: Object, policy: Policy) -> Self {
        Self {
            object,
            policy,
            taken: BTreeSet::new(),
            classes: BTreeMap::new(),
            names: BTreeSet::new(),
            next_member: 1,
        }
    }
}

/// Assemble the items of one subvolume from `contents`.
pub(super) fn build_metadata(inputs: &SubvolInputs<'_>) -> Result<Metadata, String> {
    let contents = inputs.contents;
    let keys = inputs.keys;
    let birth = inputs.birth;
    let time_ns = inputs.time_ns;
    let subvol = inputs.subvol;
    let mut items: Vec<(Key, Vec<u8>)> = Vec::new();
    let mut index_items: Vec<(Key, Vec<u8>)> = Vec::new();
    let mut tag_items: Vec<(Key, Vec<u8>)> = Vec::new();
    let mut placements: Vec<Placement> = Vec::new();

    let mut dir_paths: BTreeSet<String> = BTreeSet::new();
    let add_parents = |path: &str, include_self: bool, set: &mut BTreeSet<String>| {
        let stripped = path.trim_matches('/');
        if stripped.is_empty() { return; }
        let parts: Vec<&str> = stripped.split('/').collect();
        let upto = if include_self { parts.len() } else { parts.len() - 1 };
        for i in 1..=upto { set.insert(parts[..i].join("/")); }
    };
    for (path, _) in &contents.files { add_parents(path, false, &mut dir_paths); }
    for (path, _) in &contents.symlinks { add_parents(path, false, &mut dir_paths); }
    for path in &contents.empty_dirs { add_parents(path, true, &mut dir_paths); }
    let mut sorted_dirs: Vec<String> = dir_paths.into_iter().collect();
    sorted_dirs.sort_by_key(|d| (d.matches('/').count(), d.clone()));

    let plugin = [DIR_HASH_SIPHASH, 0, inputs.compression, 0];
    let (root_case, root_norm) = writer_directory_axes(inputs.root_case_axis);
    let (sub_case, sub_norm) = writer_directory_axes(inputs.root_case_axis);
    let root_policy = Policy { case_axis: root_case, norm_axis: root_norm, plugin: DIR_HASH_SIPHASH };
    let sub_policy = Policy { case_axis: sub_case, norm_axis: sub_norm, plugin: DIR_HASH_SIPHASH };
    // The root directory is its own locality.
    let root = Object { locality: ROOT_INO, objectid: ROOT_INO };
    let root_child_dirs = sorted_dirs.iter().filter(|d| !d.contains('/')).count() as u32;
    let (root_mode, root_uid, root_gid) = lookup_perm(&contents.permissions, "/", S_IFDIR | 0o755);
    items.push((Key::new(root.locality, root.objectid, ITEM_INODE, 0), pack_inode(&InodeFields {
        size: 0, blocks: 0, nlink: 2 + root_child_dirs, owner: PRINCIPAL_POSIX_USER | root_uid as u64, group: PRINCIPAL_POSIX_GROUP | root_gid as u64,
        mode: root_mode, time_ns, incarnation: ROOT_INO, flags: axis_flags(root_policy.case_axis, root_policy.norm_axis), hidden_owner: 0, plugin, project_id: 0,
    }, birth)));
    index_items.push((Key::new(0, ROOT_INO, ITEM_OBJECT_INDEX, 0), pack_object_index(root.locality, ROOT_INO)));

    let mut next_objectid = FIRST_INO;
    let mut next_incarnation = FIRST_INO;
    let mut dirs: BTreeMap<String, DirState> = BTreeMap::new();
    dirs.insert(String::new(), DirState::new(root, root_policy));

    // Insert one entry under `parent`: the directory item under the parent's
    // policy and the child's reference.
    let mut entry = |items: &mut Vec<(Key, Vec<u8>)>, parent: &mut DirState, child: Object, name: &[u8], dir_type: u8| -> Result<(), String> {
        let dir = parent.object;
        if name.is_empty() || name.len() > NAME_MAX || name.contains(&0) || name.contains(&b'/') {
            return Err("invalid directory name".into());
        }
        if !parent.names.insert(parent.policy.unique_key(name)?) {
            return Err(format!("equivalent directory name `{}`", String::from_utf8_lossy(name)));
        }
        let offset = dir_item_offset(keys, subvol, dir.objectid, parent.policy, name)?;
        if parent.policy.is_byte() {
            let mut chosen = None;
            for probe in 0..DIR_PROBES {
                let candidate = offset.wrapping_add(probe);
                if !parent.taken.contains(&candidate) { chosen = Some(candidate); break; }
            }
            let key_offset = chosen.ok_or_else(|| format!("directory hash probes exhausted for `{}`", String::from_utf8_lossy(name)))?;
            parent.taken.insert(key_offset);
            items.push((Key::new(dir.locality, dir.objectid, ITEM_DIR, key_offset), pack_dir_item((child.locality, child.objectid), name, dir_type)));
        } else {
            // The class header sits at the indexed key's hash (probing as a
            // byte directory does); members chain in id order.
            let key = parent.policy.indexed_key(name)?;
            let mut chosen = None;
            for probe in 0..DIR_PROBES {
                let candidate = offset.wrapping_add(probe);
                match parent.classes.get(&candidate) {
                    None => { chosen = Some(candidate); break; }
                    Some(members) => {
                        // Same class when the first member's key is ours.
                        let first = members[0];
                        let first_key = items.iter().find(|(k, _)| k.locality == dir.locality && k.objectid == dir.objectid && k.ty == ITEM_DIR_MEMBER && k.offset == first)
                            .map(|(_, payload)| {
                                parent.policy.indexed_key(&payload[DIR_MEMBER_HEADER_SIZE..])
                            })
                            .transpose()?;
                        if first_key.as_deref() == Some(key.as_slice()) {
                            chosen = Some(candidate);
                            break;
                        }
                    }
                }
            }
            let class_offset = chosen.ok_or("directory class hash probes exhausted")?;
            let member_id = parent.next_member;
            parent.next_member = member_id.checked_add(1).ok_or("directory member ids exhausted")?;
            let members = parent.classes.entry(class_offset).or_default();
            if let Some(&last) = members.last() {
                // The previous last member now points at the new one.
                if let Some((_, payload)) = items.iter_mut().find(|(k, _)| k.locality == dir.locality && k.objectid == dir.objectid && k.ty == ITEM_DIR_MEMBER && k.offset == last) {
                    put64(payload, 8, member_id);
                }
            }
            members.push(member_id);
            items.push((Key::new(dir.locality, dir.objectid, ITEM_DIR_MEMBER, member_id), pack_dir_member(class_offset, 0, (child.locality, child.objectid), name, dir_type)));
            let class = pack_dir_class(members[0], members.len() as u64);
            match items.iter_mut().find(|(k, _)| k.locality == dir.locality && k.objectid == dir.objectid && k.ty == ITEM_DIR && k.offset == class_offset) {
                Some((_, payload)) => *payload = class,
                None => items.push((Key::new(dir.locality, dir.objectid, ITEM_DIR, class_offset), class)),
            }
        }
        let reference = reference_offset(
            keys, subvol, (dir.locality, dir.objectid), parent.policy, name,
        )?;
        items.push((Key::new(child.locality, child.objectid, ITEM_INODE_REF, reference), pack_inode_ref((dir.locality, dir.objectid), name)));
        Ok(())
    };

    for dir in &sorted_dirs {
        let (objectid, incarnation) = allocate_node_identity(&mut next_objectid, &mut next_incarnation)?;
        let (parent_path, name) = split_parent(dir);
        let parent_object = dirs.get(&parent_path).map(|d| d.object).unwrap_or(root);
        let object = Object { locality: parent_object.objectid, objectid };
        let name = name.as_bytes();
        let (dir_mode, dir_uid, dir_gid) = lookup_perm(&contents.permissions, dir, S_IFDIR | 0o755);
        items.push((Key::new(object.locality, object.objectid, ITEM_INODE, 0), pack_inode(&InodeFields {
            size: 0, blocks: 0, nlink: 2, owner: PRINCIPAL_POSIX_USER | dir_uid as u64, group: PRINCIPAL_POSIX_GROUP | dir_gid as u64, mode: dir_mode, time_ns,
            incarnation, flags: axis_flags(sub_policy.case_axis, sub_policy.norm_axis), hidden_owner: 0, plugin, project_id: 0,
        }, birth)));
        index_items.push((Key::new(0, objectid, ITEM_OBJECT_INDEX, 0), pack_object_index(object.locality, incarnation)));
        let parent = dirs.get_mut(&parent_path).ok_or("parent directory missing")?;
        entry(&mut items, parent, object, name, 4)?;
        dirs.insert(dir.clone(), DirState::new(object, sub_policy));
    }
    // Subdirectory counts: every directory's nlink is two plus its children.
    for dir in &sorted_dirs {
        let (parent_path, _) = split_parent(dir);
        if parent_path.is_empty() { continue; }
        let parent = dirs.get(&parent_path).ok_or("parent directory missing")?.object;
        if let Some((_, inode)) = items.iter_mut().find(|(k, _)| k.locality == parent.locality && k.objectid == parent.objectid && k.ty == ITEM_INODE) {
            let nlink = get32(inode, 0x6C) + 1;
            put32(inode, 0x6C, nlink);
        }
    }

    let mut next_data_block = inputs.first_data_block;
    let mut data_blocks = 0u64;
    for (idx, (path, source)) in contents.files.iter().enumerate() {
        let (objectid, incarnation) = allocate_node_identity(&mut next_objectid, &mut next_incarnation)?;
        let (parent_path, name) = split_parent(path);
        let parent_object = dirs.get(&parent_path).map(|d| d.object).unwrap_or(root);
        let object = Object { locality: parent_object.objectid, objectid };
        let name = name.as_bytes();
        let size = source.size()?;
        let (mode, uid, gid) = lookup_perm(&contents.permissions, path, S_IFREG | 0o644);
        let inline = size as usize <= INLINE_MAX;
        let mut blocks = 0u64;
        if inline {
            let data = source.inline_bytes()?;
            items.push((Key::new(object.locality, object.objectid, ITEM_EXTENT_DATA, 0), pack_extent_inline(&data, birth)));
        } else if inputs.compression == COMPRESSION_NONE {
            blocks = size.div_ceil(BLOCK_SIZE as u64);
            let start = next_data_block;
            next_data_block += blocks;
            items.push((Key::new(object.locality, object.objectid, ITEM_EXTENT_DATA, 0),
                pack_extent_regular(size, start, blocks * BLOCK_SIZE as u64, birth, COMPRESSION_NONE)));
            let mut tags: Vec<[u8; 16]> = Vec::with_capacity(blocks as usize);
            let mut at = start;
            for_each_unit(source, |_, unit| {
                let unit_blocks = (unit.len() as u64).div_ceil(BLOCK_SIZE as u64);
                tags.extend(run_tags(keys, at, unit, unit_blocks, birth));
                at += unit_blocks;
                Ok(())
            })?;
            if tags.len() as u64 != blocks { return Err(format!("`{}` changed size while being read", path)); }
            for (run, chunk) in tags.chunks(DATA_TAG_RUN_MAX).enumerate() {
                let address = start + (run * DATA_TAG_RUN_MAX) as u64;
                tag_items.push((Key::new(0, address, ITEM_DATA_TAG, birth), pack_data_tags(chunk)));
            }
            placements.push(Placement { start, file: idx, unit: None, compression: COMPRESSION_NONE, blocks });
        } else {
            // One extent per compression unit: compressed when that is
            // smaller in blocks, plain otherwise.
            let mut offset = 0u64;
            let mut file_index = idx;
            for_each_unit(source, |unit_index, unit| {
                let (compression, stored) = encode_unit(inputs.compression, unit);
                let unit_blocks = (stored.len() as u64).div_ceil(BLOCK_SIZE as u64).max(1);
                let start = next_data_block;
                next_data_block += unit_blocks;
                blocks += unit_blocks;
                items.push((Key::new(object.locality, object.objectid, ITEM_EXTENT_DATA, offset),
                    pack_extent_regular(unit.len() as u64, start, unit_blocks * BLOCK_SIZE as u64, birth, compression)));
                let tags = run_tags(keys, start, &stored, unit_blocks, birth);
                for (run, chunk) in tags.chunks(DATA_TAG_RUN_MAX).enumerate() {
                    let address = start + (run * DATA_TAG_RUN_MAX) as u64;
                    tag_items.push((Key::new(0, address, ITEM_DATA_TAG, birth), pack_data_tags(chunk)));
                }
                placements.push(Placement { start, file: file_index, unit: Some(unit_index), compression, blocks: unit_blocks });
                offset += unit.len() as u64;
                file_index = idx;
                Ok(())
            })?;
            if offset != size { return Err(format!("`{}` changed size while being read", path)); }
        }
        data_blocks += blocks;
        items.push((Key::new(object.locality, object.objectid, ITEM_INODE, 0), pack_inode(&InodeFields {
            size, blocks, nlink: 1, owner: PRINCIPAL_POSIX_USER | uid as u64, group: PRINCIPAL_POSIX_GROUP | gid as u64, mode, time_ns, incarnation, flags: 0,
            hidden_owner: 0, plugin, project_id: 0,
        }, birth)));
        index_items.push((Key::new(0, objectid, ITEM_OBJECT_INDEX, 0), pack_object_index(object.locality, incarnation)));
        let parent = dirs.get_mut(&parent_path).ok_or("parent directory missing")?;
        entry(&mut items, parent, object, name, 1)?;
    }

    if let Some(stray) = contents.directory_links.iter().find(|link| !contents.symlinks.iter().any(|(path, _)| path == *link)) {
        return Err(format!("`{}` is marked a directory link but is not a symbolic link", stray));
    }
    for (path, target) in &contents.symlinks {
        let (objectid, incarnation) = allocate_node_identity(&mut next_objectid, &mut next_incarnation)?;
        let (parent_path, name) = split_parent(path);
        let parent_object = dirs.get(&parent_path).map(|d| d.object).unwrap_or(root);
        let object = Object { locality: parent_object.objectid, objectid };
        let name = name.as_bytes();
        if target.len() > INLINE_MAX { return Err(format!("symlink target too long for `{}`", path)); }
        let (link_mode, link_uid, link_gid) = lookup_perm(&contents.permissions, path, S_IFLNK | 0o777);
        items.push((Key::new(object.locality, object.objectid, ITEM_INODE, 0), pack_inode(&InodeFields {
            size: target.len() as u64, blocks: 0, nlink: 1, owner: PRINCIPAL_POSIX_USER | link_uid as u64, group: PRINCIPAL_POSIX_GROUP | link_gid as u64,
            mode: link_mode, time_ns, incarnation,
            flags: if contents.directory_links.contains(path) { INODE_DIRECTORY_LINK } else { 0 },
            hidden_owner: 0, plugin, project_id: 0,
        }, birth)));
        index_items.push((Key::new(0, objectid, ITEM_OBJECT_INDEX, 0), pack_object_index(object.locality, incarnation)));
        let parent = dirs.get_mut(&parent_path).ok_or("parent directory missing")?;
        entry(&mut items, parent, object, name, 7)?;
        items.push((Key::new(object.locality, object.objectid, ITEM_EXTENT_DATA, 0), pack_extent_inline(target, birth)));
    }

    // Every inode this writer makes is in project zero and none is hidden:
    // the project's use is every inode once, with the stored regular blocks.
    let objects = items.iter().filter(|(key, _)| key.ty == ITEM_INODE).count() as u64;
    items.push((Key::new(0, 0, ITEM_PROJECT, 0), pack_project(data_blocks, objects)));

    Ok(Metadata { items, index_items, tag_items, placements, next_free_block: next_data_block, next_objectid, next_incarnation, data_blocks })
}

// ---------------------------------------------------------------------------
// Image writer
// ---------------------------------------------------------------------------

pub(crate) struct BuildStats {
    pub total_blocks: u64,
    pub used_blocks: u64,
    pub tree_blocks: usize,
    pub files: usize,
}

struct Trees {
    item: (Pointer, Vec<(u64, Vec<u8>)>),
    index: (Pointer, Vec<(u64, Vec<u8>)>),
    tag: (Pointer, Vec<(u64, Vec<u8>)>),
    next_block: u64,
}

impl Trees {
    fn blocks(&self) -> usize { self.item.1.len() + self.index.1.len() + self.tag.1.len() }
    fn all(&self) -> impl Iterator<Item = &(u64, Vec<u8>)> { self.item.1.iter().chain(self.index.1.iter()).chain(self.tag.1.iter()) }
}

fn build_subvolume_trees(meta: &Metadata, owner: u64, start: u64, incarnation: u64, keys: &Keys) -> Result<Trees, String> {
    let node = |tree| NodeMeta { owner, birth: INITIAL_SEQ, tree, incarnation };
    let item = build_tree(meta.items.clone(), node(TREE_ITEM), start, keys)?;
    let after_item = start + item.1.len() as u64;
    let index = build_tree(meta.index_items.clone(), node(TREE_OBJECT_INDEX), after_item, keys)?;
    let after_index = after_item + index.1.len() as u64;
    let tag = build_tree(meta.tag_items.clone(), node(TREE_DATA_TAG), after_index, keys)?;
    let next_block = after_index + tag.1.len() as u64;
    Ok(Trees { item, index, tag, next_block })
}

fn sha256_bytes(tag: &str, manifest: &[u8], label: &str) -> [u8; 32] {
    let mut h = sha256::Sha256::new();
    h.update(tag.as_bytes());
    h.update(&[0]);
    h.update(manifest);
    h.update(label.as_bytes());
    h.finalize()
}

fn nonzero_word(bytes: &[u8]) -> u64 { let word = get64(bytes, 0); if word == 0 { 1 } else { word } }

fn identity_uuid(tag: &str, manifest: &[u8], label: &str) -> [u8; 16] {
    let digest = sha256_bytes(tag, manifest, label);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = uuid[6] & 0x0F | 0x40;
    uuid[8] = uuid[8] & 0x3F | 0x80;
    uuid
}

/// The volume keys of a build: the plain suite's from the KDF salt, an
/// encrypted suite's from the passphrase or key given, derived with the
/// manifest so equal inputs give equal images.
fn build_keys(options: &Options, fs_uuid: [u8; 16], kdf_salt: &[u8; 32], manifest: &[u8]) -> Result<Keys, String> {
    let Some(suite) = options.suite else { return Ok(Keys::plain(fs_uuid, kdf_salt)) };
    let volume_key = match options.unlock.as_ref().ok_or("an encrypted image needs a passphrase or a volume key")? {
        Unlock::VolumeKey(key) => *key,
        Unlock::Passphrase { passphrase, .. } => blake3::derive_key(b"SaltyFS image writer volume key", &[passphrase.as_slice(), &sha256_bytes("SALTYFS-VOLUME-KEY", manifest, "")].concat()),
    };
    Ok(Keys::unlocked(suite, fs_uuid, volume_key))
}

/// The keyslot area: slot 0 enrolls the passphrase, the others are empty.
fn keyslot_area(options: &Options, keys: &Keys, kdf_salt: &[u8; 32]) -> Result<Vec<Vec<u8>>, String> {
    let mut slots = vec![vec![0u8; BLOCK_SIZE]; KEYSLOT_COUNT as usize];
    let (Some(suite), Some(Unlock::Passphrase { passphrase, memory_kib, iterations, lanes })) = (keys.suite, options.unlock.as_ref()) else { return Ok(slots) };
    let mut salt = [0u8; KEYSLOT_SALT_BYTES];
    salt.copy_from_slice(&kdf_salt[..KEYSLOT_SALT_BYTES]);
    let mut unwrap = [0u8; 32];
    primitives::argon2::argon2id(passphrase, &salt, *iterations, *memory_kib, *lanes, &mut unwrap)?;
    let nonce_source = blake3::derive_key(b"SaltyFS image writer keyslot nonce", &[keys.fs_uuid.as_slice(), &keys.volume_key].concat());
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&nonce_source[..NONCE_BYTES]);
    let mut sealed = keys.volume_key;
    let tag = suite.seal(&unwrap, &nonce, &Keyslot::associated_data(&keys.fs_uuid, 0), &mut sealed);
    slots[0] = Keyslot::passphrase(nonce, sealed, tag, *memory_kib, *iterations, *lanes, salt).pack();
    Ok(slots)
}

pub(crate) fn build_to_file(output: &Path, spec: &FsSpec, contents: &Contents) -> Result<BuildStats, String> {
    build_to_file_with(output, spec, contents, &Options::default())
}

pub(crate) fn build_to_file_with(output: &Path, spec: &FsSpec, contents: &Contents, options: &Options) -> Result<BuildStats, String> {
    if spec.size_bytes % BLOCK_SIZE as u64 != 0 { return Err(format!("SaltyFS size {} is not block-aligned", spec.size_bytes)); }
    let total_blocks = spec.size_bytes / BLOCK_SIZE as u64;
    let encrypted = options.suite.is_some();
    let (keyslot_start, keyslot_blocks, bitmap_start, bitmap_blocks, log_start, log_blocks) = Superblock::geometry(total_blocks, encrypted)?;
    let tree_start = log_start + log_blocks;
    let time_ns = spec.epoch_secs.saturating_mul(1_000_000_000);

    // Identity derives from the full logical content and the profile.
    let mut manifest = String::new();
    manifest.push_str(&format!("label {}\n", spec.label));
    manifest.push_str(&format!("suite {} compression {} seal {}\n", options.suite.map_or(0, |s| s.word()), options.compression, options.seal));
    for (path, source) in &contents.files { manifest.push_str(&format!("file {} {}\n", path, source.sha256()?)); }
    for dir in &contents.empty_dirs { manifest.push_str(&format!("dir {}\n", dir)); }
    for (path, target) in &contents.symlinks {
        let kind = if contents.directory_links.contains(path) { "directory-symlink" } else { "symlink" };
        manifest.push_str(&format!("{} {} {}\n", kind, path, String::from_utf8_lossy(target)));
    }
    let manifest = manifest.as_bytes();
    let fs_uuid = identity_uuid("SALTYFS-FS", manifest, &spec.label);
    let dev_uuid = identity_uuid("SALTYFS-DEV", manifest, &spec.label);
    let subvol_uuid = |id: u64| {
        identity_uuid(&format!("SALTYFS-SUBVOL-{id}"), manifest, &spec.label)
    };
    let volume_incarnation =
        nonzero_word(&identity_uuid("SALTYFS-INCARNATION", manifest, &spec.label));
    let kdf_salt = sha256_bytes("SALTYFS-KDF-SALT", manifest, &spec.label);
    let keys = build_keys(options, fs_uuid, &kdf_salt, manifest)?;
    let store_identity = subvol_uuid(STORE_SUBVOL);

    // The default subvolume: pass 1 sizes its trees with a provisional
    // first data block; pass 2 uses the real one. Data-tag keys change
    // with placement but their count and size do not.
    let root_case_axis = if spec.casefold_root { AXIS_INSENSITIVE } else { AXIS_SENSITIVE };
    let inputs = |first_data_block: u64| SubvolInputs { subvol: DEFAULT_SUBVOL, contents, root_case_axis, compression: options.compression, time_ns, keys: &keys,
        first_data_block, birth: INITIAL_SEQ };
    let probe = build_metadata(&inputs(tree_start + 1))?;
    let probe_trees = build_subvolume_trees(&probe, DEFAULT_SUBVOL, tree_start, volume_incarnation, &keys)?;

    // The store: sealed objects as files of subvolume 3, when asked.
    let empty_permissions = Permissions::new();
    let perm = |path: &str, default_mode: u32| lookup_perm(&contents.permissions, path, default_mode);
    let sealed = if options.seal {
        let inputs = seal::SealInputs { suite: keys.suite, name_key: keys.name_key, key_material: keys.volume_key, store_identity, subvol_uuid: subvol_uuid(DEFAULT_SUBVOL),
            seal_time: time_ns.max(1), clock_valid: spec.clock_valid, chunker: fastcdc::Params::DEFAULT, casefold_root: spec.casefold_root, time_ns, contents, pack_identity: (FIRST_INO, FIRST_INO), perm: &perm };
        Some(seal::seal(&inputs)?)
    } else { None };
    let store_contents = Contents {
        files: sealed.as_ref().map_or(Vec::new(), |s| vec![
            (seal::pack_file_name(FIRST_INO, false), FileSource::Bytes(s.pack.clone())),
            (seal::pack_file_name(FIRST_INO, true), FileSource::Bytes(s.index.clone())),
            (String::from_utf8_lossy(seal::SUPER_INDEX_NAME).to_string(), FileSource::Bytes(s.super_index.clone())),
        ]),
        empty_dirs: Vec::new(), symlinks: Vec::new(), directory_links: Vec::new(), permissions: empty_permissions,
    };
    let store_inputs = |first_data_block: u64| SubvolInputs { subvol: STORE_SUBVOL, contents: &store_contents, root_case_axis: AXIS_SENSITIVE, compression: COMPRESSION_NONE,
        time_ns, keys: &keys, first_data_block, birth: INITIAL_SEQ };
    let store_probe = build_metadata(&store_inputs(tree_start + 1))?;
    let store_probe_trees = build_subvolume_trees(&store_probe, STORE_SUBVOL, probe_trees.next_block, volume_incarnation, &keys)?;

    // The key tree: the objects' keys, the signing secret and the commit's
    // signature, when sealed; empty otherwise.
    let signing_seed = blake3::derive_key(b"SaltyFS image writer signing seed", &[keys.volume_key.as_slice(), &kdf_salt].concat());
    let store_public_key = if sealed.is_some() { crate::crypto::ed25519::public_key(&signing_seed) } else { [0u8; 32] };
    let mut key_items: Vec<(Key, Vec<u8>)> = Vec::new();
    if let Some(s) = &sealed {
        for object in &s.objects {
            key_items.push((skey_key(&object.name), pack_skey(&object.name, INITIAL_SEQ, keys.suite.map(|_| &object.key))));
        }
        key_items.push((Key::new(0, 0, ITEM_SIGNING_SECRET, 0), signing_seed.to_vec()));
        let signature = crate::crypto::ed25519::sign(&signing_seed, &s.commit_encoding);
        key_items.push((Key::new(DEFAULT_SUBVOL, INITIAL_SEQ, ITEM_COMMIT_SIGNATURE, 0), pack_commit_signature(&s.commit_name, &signature)));
    }
    let key_meta = NodeMeta { owner: KEY_TREE_SUBVOL, birth: INITIAL_SEQ, tree: TREE_ITEM, incarnation: volume_incarnation };
    let key_probe = build_tree(key_items.clone(), key_meta, store_probe_trees.next_block, &keys)?;
    // Table leaf, registry leaf (when sealed), then data.
    let table_block = store_probe_trees.next_block + key_probe.1.len() as u64;
    let registry_block = if sealed.is_some() { Some(table_block + 1) } else { None };
    let data_start_block = table_block + 1 + registry_block.is_some() as u64;

    let meta = build_metadata(&inputs(data_start_block))?;
    let trees = build_subvolume_trees(&meta, DEFAULT_SUBVOL, tree_start, volume_incarnation, &keys)?;
    if trees.next_block != probe_trees.next_block { return Err("B-tree block count changed between sizing passes".to_string()); }
    let store_meta = build_metadata(&store_inputs(meta.next_free_block))?;
    let store_trees = build_subvolume_trees(&store_meta, STORE_SUBVOL, trees.next_block, volume_incarnation, &keys)?;
    if store_trees.next_block != store_probe_trees.next_block { return Err("store B-tree block count changed between sizing passes".to_string()); }
    let key_tree = build_tree(key_items, key_meta, store_trees.next_block, &keys)?;
    if store_trees.next_block + key_tree.1.len() as u64 != table_block { return Err("key tree block count changed between sizing passes".to_string()); }
    if let Some(s) = &sealed {
        // The pack file's identity is the one the index names.
        let pack_ino = store_meta.items.iter().filter(|(k, _)| k.ty == ITEM_INODE && k.objectid != ROOT_INO).map(|(k, _)| k.objectid).min().unwrap_or(0);
        if pack_ino != FIRST_INO || store_meta.next_objectid != FIRST_INO + 3 { return Err("store file identities are not the ones the index names".into()); }
        let _ = s;
    }
    let tree_blocks = trees.blocks() + store_trees.blocks() + key_tree.1.len() + 1 + registry_block.is_some() as usize;

    let used_blocks = store_meta.next_free_block;
    if used_blocks + CLEANUP_BLOCKS > total_blocks - 1 { return Err(format!("SaltyFS image too small: {} blocks used, {} available", used_blocks, total_blocks - 1)); }

    let mut label = [0u8; 32];
    let label_bytes = spec.label.as_bytes();
    let n = label_bytes.len().min(32);
    label[..n].copy_from_slice(&label_bytes[..n]);
    let default_charge = trees.blocks() as u64 + meta.data_blocks;
    let store_charge = store_trees.blocks() as u64 + store_meta.data_blocks;
    let owner = if sealed.is_some() { (1, 1) } else { (0, 0) };
    let mut default_row = SubvolRow {
        uuid: subvol_uuid(DEFAULT_SUBVOL), incarnation: nonzero_word(&subvol_uuid(DEFAULT_SUBVOL)[8..]), item_root: trees.item.0, index_root: trees.index.0,
        tag_root: trees.tag.0, objectid_hwm: meta.next_objectid, incarnation_hwm: meta.next_incarnation, publish_seq: INITIAL_SEQ, origin: (0, 0), owner, limits: [0; 4],
        referenced: default_charge, owned: default_charge, retained_charge: 0, catalog_id_hwm: if sealed.is_some() { 2 } else { 1 }, retain_pinned: 0,
        state: SUBVOL_STATE_LIVE, flags: SUBVOL_FLAG_BOOT_DEFAULT | SUBVOL_FLAG_ATIME | SUBVOL_FLAG_RELATIME, label, sealed_head: [0; 32],
    };
    if let Some(s) = &sealed { default_row.sealed_head = s.commit_name; }
    let key_row = SubvolRow {
        uuid: subvol_uuid(KEY_TREE_SUBVOL), incarnation: nonzero_word(&subvol_uuid(KEY_TREE_SUBVOL)[8..]), item_root: key_tree.0, index_root: Pointer::NULL, tag_root: Pointer::NULL,
        objectid_hwm: 1, incarnation_hwm: 1, publish_seq: INITIAL_SEQ, origin: (0, 0), owner: (0, 0), limits: [0; 4], referenced: key_tree.1.len() as u64,
        owned: key_tree.1.len() as u64, retained_charge: 0, catalog_id_hwm: 1, retain_pinned: 0, state: SUBVOL_STATE_LIVE, flags: SUBVOL_FLAG_NOSEAL, label: *b"key-tree\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        sealed_head: [0; 32],
    };
    let store_row = SubvolRow {
        uuid: store_identity, incarnation: nonzero_word(&store_identity[8..]), item_root: store_trees.item.0, index_root: store_trees.index.0, tag_root: store_trees.tag.0,
        objectid_hwm: store_meta.next_objectid, incarnation_hwm: store_meta.next_incarnation, publish_seq: INITIAL_SEQ, origin: (0, 0), owner: (0, 0), limits: [0; 4],
        referenced: store_charge, owned: store_charge, retained_charge: 0, catalog_id_hwm: 1, retain_pinned: 0, state: SUBVOL_STATE_LIVE,
        flags: SUBVOL_FLAG_STORE | SUBVOL_FLAG_NOSEAL, label: *b"store\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sealed_head: [0; 32],
    };
    let volume_meta = |tree| NodeMeta { owner: 0, birth: INITIAL_SEQ, tree, incarnation: volume_incarnation };
    let table_leaf = build_leaf(volume_meta(TREE_SUBVOL_TABLE), table_block, &[
        (Key::new(0, DEFAULT_SUBVOL, ITEM_SUBVOL, 0), default_row.pack()),
        (Key::new(0, KEY_TREE_SUBVOL, ITEM_SUBVOL, 0), key_row.pack()),
        (Key::new(0, STORE_SUBVOL, ITEM_SUBVOL, 0), store_row.pack()),
    ])?;
    let table_root = Pointer { address: table_block, birth: INITIAL_SEQ, tag: tag_of(&keys, &table_leaf, table_block, INITIAL_SEQ) };
    let registry = match (&sealed, registry_block) {
        (Some(s), Some(block)) => {
            let snap = SnapRow { snapshot_id: 1, item_root: trees.item.0, index_root: trees.index.0, tag_root: trees.tag.0, objectid_hwm: meta.next_objectid,
                incarnation_hwm: meta.next_incarnation, creation_time: time_ns.max(1), deadlog_root: Pointer::NULL, deadlog_cursor: 0, owner, state: SNAP_STATE_SEALED,
                // The row and the commit it names agree on the seal clock.
                holds: 0, flags: if spec.clock_valid { SNAP_FLAG_CLOCK_VALID } else { 0 }, seal_time: time_ns.max(1), commit_name: s.commit_name };
            let leaf = build_leaf(volume_meta(TREE_PIN_REGISTRY), block, &[(Key::new(DEFAULT_SUBVOL, INITIAL_SEQ, ITEM_SNAP, 0), snap.pack())])?;
            Some((block, Pointer { address: block, birth: INITIAL_SEQ, tag: tag_of(&keys, &leaf, block, INITIAL_SEQ) }, leaf))
        }
        _ => None,
    };

    let incompat = spec.extra_incompat | if spec.casefold_root { INCOMPAT_CASEFOLD } else { 0 };
    let casefold_version = if spec.casefold_version == 0 { CASEFOLD_VERSION_UNICODE_15_1 } else { spec.casefold_version };
    let sb = Superblock {
        incompat, compat_ro: spec.compat_ro_flags, compat: 0, fs_uuid, device_uuid: dev_uuid, total_blocks, bitmap_start, bitmap_blocks, log_start, log_blocks, table_root,
        registry_root: registry.as_ref().map_or(Pointer::NULL, |r| r.1), checkpoint_seq: 1, commit_seq: INITIAL_SEQ, replay_floor: INITIAL_SEQ,
        reserved_seq_hwm: INITIAL_SEQ + RESERVATION_WINDOW, log_cycle: 1, log_head: 0, volume_incarnation, subvol_id_hwm: FIRST_USER_SUBVOL, provider_generation: 1,
        last_mount_time: spec.epoch_secs, last_write_time: spec.epoch_secs, last_certificate: [0; 16], state: STATE_CLEAN, casefold_version, label: spec.label.clone(),
        suite: options.suite.map_or(SUITE_PLAIN, |s| s.word()), kdf_salt, keyslot_start, keyslot_blocks, store_public_key, chunker: fastcdc::Params::DEFAULT,
    };
    let sb_bytes = sb.pack();
    let keyslots = keyslot_area(options, &keys, &kdf_salt)?;

    let mut bitmap = vec![0u8; (bitmap_blocks as usize) * BLOCK_SIZE];
    let mut mark = |block: u64| bitmap[(block / 8) as usize] |= 1 << (block % 8);
    for block in 0..used_blocks { mark(block); }
    mark(total_blocks - 1);

    // Inspect the exact file before truncating it: the fresh-image writer
    // has no protocol for replacing a volume that carries pins or a dirty log.
    let mut file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(output)
        .map_err(|e| format!("cannot open {}: {}", output.display(), e))?;
    super::read::refuse_overwrite(&file)?;
    file.set_len(0).map_err(|e| format!("cannot truncate {}: {}", output.display(), e))?;
    file.set_len(spec.size_bytes).map_err(|e| format!("cannot size {}: {}", output.display(), e))?;
    let write_block = |file: &mut File, block_nr: u64, data: &[u8]| -> Result<(), String> {
        file.seek(SeekFrom::Start(block_nr * BLOCK_SIZE as u64)).and_then(|_| file.write_all(data)).map_err(|e| format!("cannot write {}: {}", output.display(), e))
    };
    let write_sealed = |file: &mut File, block_nr: u64, plain: &[u8], birth: u64| -> Result<(), String> {
        let mut image = plain.to_vec();
        keys.seal_image(&mut image, block_nr, birth);
        write_block(file, block_nr, &image)
    };
    write_block(&mut file, 0, &sb_bytes)?;
    write_block(&mut file, 1, &sb_bytes)?;
    write_block(&mut file, total_blocks - 1, &sb_bytes)?;
    for (i, slot) in keyslots.iter().enumerate().take(keyslot_blocks as usize) { write_block(&mut file, keyslot_start + i as u64, slot)?; }
    write_block(&mut file, bitmap_start, &bitmap)?;
    // The log ring stays zero (sparse): a clean checkpoint with an empty log.
    for (nr, block) in trees.all().chain(store_trees.all()).chain(key_tree.1.iter()) { write_sealed(&mut file, *nr, block, INITIAL_SEQ)?; }
    write_sealed(&mut file, table_block, &table_leaf, INITIAL_SEQ)?;
    if let Some((block, _, leaf)) = &registry { write_sealed(&mut file, *block, leaf, INITIAL_SEQ)?; }
    write_placements(&mut file, &keys, &meta.placements, &contents.files, output)?;
    write_placements(&mut file, &keys, &store_meta.placements, &store_contents.files, output)?;
    file.flush().map_err(|e| format!("cannot flush {}: {}", output.display(), e))?;

    Ok(BuildStats { total_blocks, used_blocks, tree_blocks, files: contents.files.len() })
}

/// Write every data run: the file's units re-read, re-encoded and sealed
/// exactly as their tags were computed.
fn write_placements(file: &mut File, keys: &Keys, placements: &[Placement], files: &[(String, FileSource)], output: &Path) -> Result<(), String> {
    let write_block = |file: &mut File, block_nr: u64, data: &[u8]| -> Result<(), String> {
        file.seek(SeekFrom::Start(block_nr * BLOCK_SIZE as u64)).and_then(|_| file.write_all(data)).map_err(|e| format!("cannot write {}: {}", output.display(), e))
    };
    let write_run = |file: &mut File, start: u64, bytes: &[u8], blocks: u64| -> Result<(), String> {
        for i in 0..blocks as usize {
            let mut image = vec![0u8; BLOCK_SIZE];
            let from = i * BLOCK_SIZE;
            if from < bytes.len() { let to = (from + BLOCK_SIZE).min(bytes.len()); image[..to - from].copy_from_slice(&bytes[from..to]); }
            keys.seal_image(&mut image, start + i as u64, INITIAL_SEQ);
            write_block(file, start + i as u64, &image)?;
        }
        Ok(())
    };
    // Group placements by file so each file is read once.
    let mut by_file: BTreeMap<usize, Vec<&Placement>> = BTreeMap::new();
    for p in placements { by_file.entry(p.file).or_default().push(p); }
    for (file_index, runs) in by_file {
        let (_, source) = &files[file_index];
        if runs.len() == 1 && runs[0].unit.is_none() {
            let run = runs[0];
            let mut at = run.start;
            for_each_unit(source, |_, unit| {
                let unit_blocks = (unit.len() as u64).div_ceil(BLOCK_SIZE as u64);
                write_run(file, at, unit, unit_blocks)?;
                at += unit_blocks;
                Ok(())
            })?;
            continue;
        }
        let by_unit: BTreeMap<usize, &Placement> = runs.iter().filter_map(|p| p.unit.map(|u| (u, *p))).collect();
        for_each_unit(source, |unit_index, unit| {
            let Some(run) = by_unit.get(&unit_index) else { return Err("unit without a placement".into()) };
            let (compression, stored) = encode_unit(run.compression, unit);
            if compression != run.compression && run.compression != COMPRESSION_NONE { return Err("unit compression changed between passes".into()); }
            let bytes = if run.compression == COMPRESSION_NONE { unit } else { &stored };
            write_run(file, run.start, bytes, run.blocks)
        })?;
    }
    Ok(())
}
