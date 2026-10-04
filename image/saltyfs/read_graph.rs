//! SPDX-License-Identifier: GPL-2.0-only
//! Structural, ring, allocation and store authority for the format 2
//! reader. Every root is verified pointer by pointer (tag, birth, level,
//! owner, tree kind, key order); the wandering log is scanned whole and its
//! certified atoms replayed into the reader's overlay; allocation is
//! reconstructed from roots, registry, deadlogs, share trees and retirement
//! logs and compared with the bitmap; a sealed snapshot's commit is located
//! in the store, its signature checked and its closure walked.

use std::collections::{BTreeMap, BTreeSet};

use super::super::*;
use super::{ImageReader, ItemMap, View, item_of, parse_inode};

/// Longest xattr item stored inline: header, name and value together.
const XATTR_INLINE_MAX: usize = 200;
/// The access-control item's fixed words: owner, group, header, eight ACEs.
const ACL_MAX_ACES: u64 = 8;
const ACCESS_CONTROL_FIXED_BYTES: usize = (3 + 2 * ACL_MAX_ACES as usize) * 8;
const ACCESS_CONTROL_VERSION: u64 = 2;
const ACCESS_CONTROL_INDIRECT: u64 = 1 << 48;
const ACCESS_CONTROL_RESERVED: u64 = 0xFFFE_0000_0000_0000;
const CHUNK_ABSOLUTE_MAX: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accounting {
    /// Blocks reachable from every subvolume's live roots.
    pub live: u64,
    /// Blocks reachable from snapshot roots, deadlogs and retirement logs.
    pub snapshots: u64,
    /// Table, registry, deadlog and share-tree nodes.
    pub registry: u64,
    pub combined: u64,
    pub reserved: u64,
    pub capacity: u64,
    /// Reachable metadata, data, registry and retained blocks plus the
    /// reserved regions: the bitmap's population.
    pub expected_used: u64,
    /// Blocks of the store subvolume's files.
    pub store_data: u64,
}

#[derive(Default)]
pub(super) struct Tree {
    pub items: ItemMap,
    pub nodes: BTreeSet<u64>,
    pub data: BTreeSet<u64>,
    /// The newest birth under the root; a second root sharing this tree
    /// must publish at or above it.
    pub newest_birth: u64,
}

pub(super) struct SubvolInfo { pub row: SubvolRow }

pub(super) struct SnapInfo { pub subvol: u64, pub epoch: u64, pub row: SnapRow }

#[derive(Clone, Debug)]
pub(super) struct SnapshotSummary { pub subvol: u64, pub epoch: u64, pub id: u64, pub owner: (u64, u64), pub deleting: bool, pub sealed: bool }

impl SnapInfo {
    pub(super) fn summary(&self) -> SnapshotSummary {
        SnapshotSummary { subvol: self.subvol, epoch: self.epoch, id: self.row.snapshot_id, owner: self.row.owner,
            deleting: self.row.flags & SNAP_FLAG_DELETING != 0, sealed: self.row.state == SNAP_STATE_SEALED }
    }
}

pub(super) struct Volume {
    pub trees: BTreeMap<u64, Tree>,
    pub subvolumes: BTreeMap<u64, SubvolInfo>,
    pub snapshots: Vec<SnapInfo>,
    pub accounting: Accounting,
    pub catalog_rows: Vec<String>,
    pub findings: Vec<String>,
    /// The store subvolume's objects, loaded when the volume holds sealed
    /// snapshots or key-tree items.
    pub store: Option<Store>,
    pub(super) allocated: BTreeSet<u64>,
}

pub(super) fn validate_geometry(reader: &ImageReader, sb: &Superblock) -> Result<(), String> {
    let (keyslot_start, keyslot_blocks, bitmap_start, bitmap_blocks, log_start, log_blocks) = Superblock::geometry(sb.total_blocks, sb.encrypted())?;
    if sb.total_blocks.checked_mul(BLOCK_SIZE as u64) != Some(reader.len) { return Err("superblock total_blocks disagrees with the image size".into()); }
    if (sb.keyslot_start, sb.keyslot_blocks, sb.bitmap_start, sb.bitmap_blocks, sb.log_start, sb.log_blocks)
        != (keyslot_start, keyslot_blocks, bitmap_start, bitmap_blocks, log_start, log_blocks) {
        return Err("superblock regions disagree with the prescribed geometry".into());
    }
    if sb.incompat & !INCOMPAT_SUPPORTED != 0 { return Err(format!("unknown incompat flags {:#x}", sb.incompat)); }
    if sb.casefold_version != CASEFOLD_VERSION_UNICODE_15_1 { return Err("unsupported casefold version".into()); }
    if sb.log_head >= sb.log_blocks { return Err("log head outside the ring".into()); }
    Ok(())
}

/// Every keyslot block parses; returns the raw slots for unlocking.
pub(super) fn keyslot_area(reader: &ImageReader, sb: &Superblock) -> Result<Vec<Vec<u8>>, String> {
    let mut slots = Vec::new();
    for index in 0..sb.keyslot_blocks {
        let block = reader.raw_block(sb.keyslot_start + index)?;
        Keyslot::unpack(&block).map_err(|e| format!("keyslot {index}: {e}"))?;
        slots.push(block);
    }
    Ok(slots)
}

// ---------------------------------------------------------------------------
// Tree collection
// ---------------------------------------------------------------------------

struct Expect { level: Option<u16>, parent_birth: u64, tree: u32, owner: u64 }

/// Journaled overwrite images land on bitmap pages or in tree/data space,
/// never on a superblock, in the keyslot area or inside the ring.
fn overwrite_target(sb: &Superblock, block: u64) -> bool {
    block >= sb.bitmap_start && block < sb.total_blocks - 1 && !(block >= sb.log_start && block < sb.log_start + sb.log_blocks)
}

fn check_pointer_target(sb: &Superblock, block: u64, where_: &str) -> Result<(), String> {
    if block >= sb.total_blocks || sb.is_reserved(block) || block < sb.first_data_block() { return Err(format!("{where_}: block {block} lies outside tree/data space")); }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect(reader: &ImageReader, sb: &Superblock, ptr: Pointer, depth: usize, expect: Expect, lower: Option<Key>, upper: Option<Key>, tree: &mut Tree) -> Result<(), String> {
    if depth >= MAX_BTREE_DEPTH { return Err(format!("tree block {}: depth exceeds {}", ptr.address, MAX_BTREE_DEPTH)); }
    check_pointer_target(sb, ptr.address, "tree pointer")?;
    if !tree.nodes.insert(ptr.address) { return Err(format!("tree block {}: cycle or shared child within one root", ptr.address)); }
    let block = reader.read_image(ptr.address, ptr.birth, &ptr.tag).map_err(|e| format!("tree block {}: {e}", ptr.address))?;
    if &block[..4] != NODE_MAGIC { return Err(format!("tree block {}: bad node magic", ptr.address)); }
    let count = get32(&block, 0x04) as usize;
    let owner = get64(&block, 0x08);
    let birth = get64(&block, 0x10);
    let address = get64(&block, 0x18);
    let level = get16(&block, 0x20);
    let flags = get16(&block, 0x22);
    let kind = get32(&block, 0x24);
    let incarnation = get64(&block, 0x28);
    if address != ptr.address || birth != ptr.birth { return Err(format!("tree block {}: header address/birth disagree with its pointer", ptr.address)); }
    if birth > expect.parent_birth { return Err(format!("tree block {}: birth {} above its parent's {}", ptr.address, birth, expect.parent_birth)); }
    if expect.level.is_some_and(|l| l != level) || level as usize >= MAX_BTREE_DEPTH { return Err(format!("tree block {}: level {}", ptr.address, level)); }
    if flags != 0 || kind != expect.tree || owner != expect.owner || incarnation != sb.volume_incarnation || block[0x30..0x40].iter().any(|b| *b != 0) {
        return Err(format!("tree block {}: header flags, tree, owner or incarnation", ptr.address));
    }
    tree.newest_birth = tree.newest_birth.max(birth);
    let width = if level == 0 { LEAF_ENTRY_SIZE } else { INTERNAL_ENTRY_SIZE };
    let max = if level == 0 { LEAF_ENTRY_MAX } else { INTERNAL_ENTRY_MAX };
    if count > max || (level != 0 && count == 0) { return Err(format!("tree block {}: invalid entry count", ptr.address)); }
    let floor = NODE_HEADER_SIZE + count * width;
    let mut previous: Option<Key> = None;
    let mut payloads: Vec<(usize, usize)> = Vec::new();
    for index in 0..count {
        let at = NODE_HEADER_SIZE + index * width;
        let key = Key::unpack(&block[at..at + KEY_SIZE]);
        if previous.is_some_and(|p| key <= p) || lower.is_some_and(|b| key < b) || upper.is_some_and(|b| key >= b) {
            return Err(format!("tree block {}: invalid key order or parent range", ptr.address));
        }
        previous = Some(key);
        if level == 0 {
            let start = get32(&block, at + KEY_SIZE) as usize;
            let size = get32(&block, at + KEY_SIZE + 4) as usize;
            let end = start.checked_add(size).ok_or("leaf payload overflow")?;
            if start < floor || end > BLOCK_SIZE || size > PAYLOAD_MAX || payloads.iter().any(|&(a, b)| start < b && a < end) {
                return Err(format!("tree block {}: invalid or overlapping leaf payload", ptr.address));
            }
            payloads.push((start, end));
            if tree.items.insert(key, block[start..end].to_vec()).is_some() { return Err(format!("tree block {}: duplicate key {:?}", ptr.address, key)); }
        } else {
            let child = Pointer::unpack(&block[at + KEY_SIZE..at + width])?;
            if child.is_null() { return Err(format!("tree block {}: null child pointer", ptr.address)); }
            let child_upper = if index + 1 < count { let next = at + width; Some(Key::unpack(&block[next..next + KEY_SIZE])) } else { upper };
            collect(reader, sb, child, depth + 1, Expect { level: Some(level - 1), parent_birth: birth, tree: expect.tree, owner: expect.owner }, Some(key), child_upper, tree)?;
        }
    }
    Ok(())
}

fn cache_tree(reader: &ImageReader, sb: &Superblock, root: Pointer, tree_kind: u32, owner: u64, publish: u64, trees: &mut BTreeMap<u64, Tree>) -> Result<(), String> {
    if root.is_null() { return Ok(()); }
    if let Some(cached) = trees.get(&root.address) {
        if cached.newest_birth > publish { return Err(format!("tree block {}: birth {} above its parent's {}", root.address, cached.newest_birth, publish)); }
        return Ok(());
    }
    let mut tree = Tree::default();
    collect(reader, sb, root, 0, Expect { level: None, parent_birth: publish, tree: tree_kind, owner }, None, None, &mut tree)?;
    trees.insert(root.address, tree);
    Ok(())
}

// ---------------------------------------------------------------------------
// Content validation
// ---------------------------------------------------------------------------

pub(super) struct Shape { pub start: u64, pub len: u64 }

/// Decode one extent's logical range; physical allocation is accounted
/// separately.
pub(super) fn extent_shape(key: Key, data: &[u8]) -> Result<Shape, String> {
    if data.len() < EXTENT_HEADER_SIZE || get32(data, 0x24) != 0 { return Err(format!("inode {}:{}: short extent", key.locality, key.objectid)); }
    let len = get64(data, 0x08);
    let address = get64(data, 0x10);
    let stored = get64(data, 0x18);
    let compression = data[0x21];
    let encoding = get16(data, 0x22);
    if compression > COMPRESSION_ZSTD || (data[0x20] != EXTENT_REGULAR && compression != COMPRESSION_NONE) {
        return Err(format!("inode {}:{}: compression byte", key.locality, key.objectid));
    }
    match data[0x20] {
        EXTENT_INLINE => {
            if address != 0 || stored != 0 { return Err("inline extent with a physical address".into()); }
            match encoding {
                ENCODING_PLAIN if len as usize + EXTENT_HEADER_SIZE == data.len() && len as usize <= INLINE_MAX => {}
                ENCODING_INDIRECT if data.len() == EXTENT_HEADER_SIZE + 16 => {}
                _ => return Err(format!("inode {}:{}: invalid inline/indirect extent", key.locality, key.objectid)),
            }
        }
        EXTENT_REGULAR => {
            if encoding != ENCODING_PLAIN || data.len() != EXTENT_HEADER_SIZE || address == 0 || stored % BLOCK_SIZE as u64 != 0 || stored == 0 || len == 0
                || (compression == COMPRESSION_NONE && len > stored) || (compression != COMPRESSION_NONE && (len as usize > COMPRESSION_UNIT || stored as usize > COMPRESSION_UNIT)) {
                return Err(format!("inode {}:{}: invalid regular extent geometry", key.locality, key.objectid));
            }
        }
        EXTENT_HOLE => {
            if encoding != ENCODING_PLAIN || data.len() != EXTENT_HEADER_SIZE || address != 0 || stored != 0 || len == 0 {
                return Err(format!("inode {}:{}: invalid hole", key.locality, key.objectid));
            }
        }
        EXTENT_ABSENT => {
            if encoding != ENCODING_PLAIN || data.len() != EXTENT_HEADER_SIZE + 32 || address != 0 || stored != 0 || len == 0 || len > CHUNK_ABSOLUTE_MAX {
                return Err(format!("inode {}:{}: invalid absent extent", key.locality, key.objectid));
            }
        }
        _ => return Err(format!("inode {}:{}: unknown extent shape", key.locality, key.objectid)),
    }
    key.offset.checked_add(len).ok_or("extent logical range overflow")?;
    Ok(Shape { start: key.offset, len })
}

fn hidden_inode(items: &ItemMap, hidden: (u64, u64), owner: u64, size: u64) -> Result<(), String> {
    let inode = parse_inode(item_of(items, Key::new(hidden.0, hidden.1, ITEM_INODE, 0)).ok_or("indirect data has no hidden inode in its root")?)?;
    if inode.flags != INODE_HIDDEN || inode.size != size || inode.hidden_owner != owner || inode.mode != 0o100600 || inode.nlink != 1 || inode.uid != 0 || inode.gid != 0 {
        return Err("invalid indirect-data inode".into());
    }
    let mut covered = 0;
    let mut stored_blocks = 0;
    let from = Key::new(hidden.0, hidden.1, ITEM_EXTENT_DATA, 0);
    let to = Key::new(hidden.0, hidden.1, ITEM_EXTENT_DATA, u64::MAX);
    for (&key, extent) in items.range(from..=to) {
        let shape = extent_shape(key, extent)?;
        if extent[0x20] != EXTENT_REGULAR || shape.start != covered { return Err("invalid indirect-data extent chain".into()); }
        covered = shape.start.checked_add(shape.len).ok_or("hidden inode range overflow")?;
        stored_blocks += get64(extent, 0x18) / BLOCK_SIZE as u64;
    }
    if covered != size || inode.blocks != stored_blocks { return Err("hidden inode extents disagree with value size or block count".into()); }
    Ok(())
}

/// The directory a `DIR` or `DIR_MEMBER` item belongs to: its policy.
fn dir_policy(items: &ItemMap, dir: u64) -> Result<Policy, String> {
    let inode = parse_inode(items.iter().find(|(k, _)| k.ty == ITEM_INODE && k.objectid == dir).map(|(_, v)| v).ok_or("directory item without its inode")?)?;
    if inode.mode & S_IFMT != S_IFDIR { return Err(format!("entry item under non-directory {dir}")); }
    Ok(Policy::of_flags(inode.flags, inode.plugin[PLUGIN_DIR_HASH]))
}

/// The entries of one directory as `(key, target, dir_type, name)`, from
/// its `DIR` items (byte directory) or `DIR_MEMBER` items (indexed).
pub(super) fn dir_entries(items: &ItemMap, locality: u64, dir: u64) -> Result<Vec<(Key, (u64, u64), u8, Vec<u8>)>, String> {
    let policy = dir_policy(items, dir)?;
    let mut out = Vec::new();
    if policy.is_byte() {
        for (key, data) in items.range(Key::new(locality, dir, ITEM_DIR, 0)..=Key::new(locality, dir, ITEM_DIR, u64::MAX)) {
            if data.len() <= DIR_ITEM_HEADER_SIZE || data.len() > DIR_ITEM_HEADER_SIZE + NAME_MAX || get16(data, 16) as usize != data.len() - DIR_ITEM_HEADER_SIZE || data[19] != 0 {
                return Err(format!("dir item under inode {dir}: payload"));
            }
            out.push((*key, (get64(data, 0), get64(data, 8)), data[18], data[DIR_ITEM_HEADER_SIZE..].to_vec()));
        }
    } else {
        for (key, data) in items.range(Key::new(locality, dir, ITEM_DIR_MEMBER, 0)..=Key::new(locality, dir, ITEM_DIR_MEMBER, u64::MAX)) {
            if data.len() <= DIR_MEMBER_HEADER_SIZE || data.len() > DIR_MEMBER_HEADER_SIZE + NAME_MAX || get16(data, 32) as usize != data.len() - DIR_MEMBER_HEADER_SIZE || data[35] != 0 {
                return Err(format!("dir member under inode {dir}: payload"));
            }
            out.push((*key, (get64(data, 16), get64(data, 24)), data[34], data[DIR_MEMBER_HEADER_SIZE..].to_vec()));
        }
    }
    Ok(out)
}

/// The directory items of `dir` agree with their keys under the keys and
/// the directory's policy; indexed classes chain every member once.
fn validate_directory(keys: &Keys, subvol: u64, items: &ItemMap, dir: u64, locality: u64, context: &str) -> Result<(), String> {
    let policy = dir_policy(items, dir)?;
    let entries = dir_entries(items, locality, dir)?;
    let mut unique_names = BTreeSet::new();
    for (_, _, _, name) in &entries {
        if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
            return Err(format!("{context}: invalid directory name"));
        }
        policy.indexed_key(name)?;
        if !unique_names.insert(policy.unique_key(name)?) {
            return Err(format!("{context}: equivalent directory names"));
        }
    }
    if policy.is_byte() {
        for (key, target, _, name) in &entries {
            let base = dir_item_offset(keys, subvol, dir, policy, name)?;
            if key.offset.wrapping_sub(base) >= DIR_PROBES { return Err(format!("{context}: dir item `{}`: key hash disagrees with name", String::from_utf8_lossy(name))); }
            let reference = reference_offset(keys, subvol, (locality, dir), policy, name)?;
            let refer = items.get(&Key::new(target.0, target.1, ITEM_INODE_REF, reference)).ok_or_else(|| format!("{context}: `{}` has no inode reference", String::from_utf8_lossy(name)))?;
            if refer.len() != INODE_REF_HEADER_SIZE + name.len() || get64(refer, 0) != locality || get64(refer, 8) != dir || &refer[INODE_REF_HEADER_SIZE..] != name.as_slice() {
                return Err(format!("{context}: inode reference of `{}` disagrees", String::from_utf8_lossy(name)));
            }
        }
        if items.range(Key::new(locality, dir, ITEM_DIR_MEMBER, 0)..=Key::new(locality, dir, ITEM_DIR_MEMBER, u64::MAX)).next().is_some() {
            return Err(format!("{context}: byte directory {dir} holds member items"));
        }
        return Ok(());
    }
    // Indexed: every class header names a chain of members whose keys hash
    // to the header's offset; every member belongs to exactly one class.
    let mut chained: BTreeSet<u64> = BTreeSet::new();
    for (key, data) in items.range(Key::new(locality, dir, ITEM_DIR, 0)..=Key::new(locality, dir, ITEM_DIR, u64::MAX)) {
        if data.len() != DIR_CLASS_BYTES { return Err(format!("{context}: class header payload")); }
        let (first, count) = (get64(data, 0), get64(data, 8));
        if first == 0 || count == 0 { return Err(format!("{context}: empty class")); }
        let mut next = first;
        let mut seen = 0u64;
        let mut class_key: Option<Vec<u8>> = None;
        while next != 0 {
            let member = items.get(&Key::new(locality, dir, ITEM_DIR_MEMBER, next)).ok_or_else(|| format!("{context}: class names a missing member {next}"))?;
            if get64(member, 0) != key.offset { return Err(format!("{context}: member {next} names another class")); }
            if !chained.insert(next) { return Err(format!("{context}: member {next} chained twice")); }
            let name = &member[DIR_MEMBER_HEADER_SIZE..];
            let indexed = policy.indexed_key(name)?;
            match &class_key { None => class_key = Some(indexed), Some(k) if *k == indexed => {}, _ => return Err(format!("{context}: class mixes keys")) }
            seen += 1;
            next = get64(member, 8);
            if seen > count { return Err(format!("{context}: class chain longer than its count")); }
        }
        if seen != count { return Err(format!("{context}: class count disagrees with its chain")); }
        let indexed = class_key.as_deref().ok_or("empty directory class")?;
        let base = keys.dir_hash(policy.plugin, subvol, dir, indexed);
        if key.offset.wrapping_sub(base) >= DIR_PROBES { return Err(format!("{context}: class header offset disagrees with its key")); }
    }
    for (key, target, _, name) in &entries {
        if !chained.contains(&key.offset) { return Err(format!("{context}: member {} in no class", key.offset)); }
        let reference = reference_offset(keys, subvol, (locality, dir), policy, name)?;
        let refer = items.get(&Key::new(target.0, target.1, ITEM_INODE_REF, reference)).ok_or_else(|| format!("{context}: `{}` has no inode reference", String::from_utf8_lossy(name)))?;
        if get64(refer, 0) != locality || get64(refer, 8) != dir || &refer[INODE_REF_HEADER_SIZE..] != name.as_slice() {
            return Err(format!("{context}: inode reference of `{}` disagrees", String::from_utf8_lossy(name)));
        }
    }
    Ok(())
}

/// Validate one subvolume version's three trees against each other and the
/// data they name, and collect its data blocks.
#[allow(clippy::too_many_arguments)]
fn validate_version(reader: &ImageReader, sb: &Superblock, keys: &Keys, subvol: u64, trees: &mut BTreeMap<u64, Tree>, roots: (Pointer, Pointer, Pointer), publish: u64,
    objectid_hwm: u64, incarnation_hwm: u64, findings: &mut Vec<String>, tag_context: &str) -> Result<(), String>
{
    let (item_root, index_root, tag_root) = roots;
    if item_root.is_null() && index_root.is_null() && tag_root.is_null() {
        // The key tree before its first item: an empty subvolume.
        if subvol != KEY_TREE_SUBVOL { return Err(format!("{tag_context}: null roots")); }
        return Ok(());
    }
    if item_root.is_null() { return Err(format!("{tag_context}: null item root")); }
    let tag_items: ItemMap = if tag_root.is_null() { ItemMap::new() } else { trees[&tag_root.address].items.clone() };
    let index_items: ItemMap = if index_root.is_null() { ItemMap::new() } else { trees[&index_root.address].items.clone() };
    let tree = trees.get_mut(&item_root.address).ok_or("missing item tree")?;
    for (&key, values) in &tag_items {
        if key.ty != ITEM_DATA_TAG || key.locality != 0 || values.is_empty() || values.len() % 16 != 0 || values.len() / 16 > DATA_TAG_RUN_MAX {
            return Err(format!("{tag_context}: malformed data-tag item"));
        }
        if key.offset > publish { return Err(format!("{tag_context}: data tag birth above publish sequence")); }
    }
    let mut max_objectid = 0;
    let mut max_incarnation = 0;
    let mut inode_count = 0u64;
    let mut ends = BTreeMap::<(u64, u64), u64>::new();
    let mut data_owned: Vec<(u64, u64, u64)> = Vec::new();
    let mut directories: Vec<(u64, u64)> = Vec::new();
    // Project use as the live inodes give it: `(locality, objectid,
    // project, flags, hidden owner)` of each inode, and the stored regular
    // blocks of each.
    let mut inodes: Vec<(u64, u64, u32, u32, u64)> = Vec::new();
    let mut regular_blocks = BTreeMap::<(u64, u64), u64>::new();
    for (&key, data) in &tree.items {
        match key.ty {
            ITEM_INODE => {
                if key.offset != 0 || key.objectid == 0 { return Err(format!("{tag_context}: inode key")); }
                let inode = parse_inode(data)?;
                if inode.incarnation == 0 || inode.content_revision == 0 || inode.namespace_revision == 0 {
                    return Err(format!("{tag_context}: inode {} with zero incarnation or revision", key.objectid));
                }
                if inode.birth > publish || inode.content_revision > publish || inode.namespace_revision > publish {
                    return Err(format!("{tag_context}: inode {} birth or revision above publish sequence", key.objectid));
                }
                let index = index_items.get(&Key::new(0, key.objectid, ITEM_OBJECT_INDEX, 0))
                    .ok_or_else(|| format!("{tag_context}: inode {} has no object index entry", key.objectid))?;
                if index.len() != 16 || get64(index, 0) != key.locality || get64(index, 8) != inode.incarnation {
                    return Err(format!("{tag_context}: object index disagrees with inode {}", key.objectid));
                }
                max_objectid = max_objectid.max(key.objectid);
                max_incarnation = max_incarnation.max(inode.incarnation);
                inode_count += 1;
                if key.objectid == ROOT_INO && key.locality != ROOT_INO { return Err(format!("{tag_context}: root inode locality")); }
                if inode.mode & S_IFMT == S_IFDIR { directories.push((key.locality, key.objectid)); }
                inodes.push((key.locality, key.objectid, inode.project_id, inode.flags, inode.hidden_owner));
            }
            ITEM_INODE_REF => {
                if data.len() <= INODE_REF_HEADER_SIZE || data.len() > INODE_REF_HEADER_SIZE + NAME_MAX { return Err(format!("{tag_context}: inode ref payload")); }
            }
            ITEM_DIR | ITEM_DIR_MEMBER => {
                // Keyed by its directory's own inode key, (dir_locality, dir_objectid).
                let owner = tree.items.get(&Key::new(key.locality, key.objectid, ITEM_INODE, 0))
                    .ok_or_else(|| format!("{tag_context}: dir item key names no inode"))?;
                if parse_inode(owner)?.mode & S_IFMT != S_IFDIR { return Err(format!("{tag_context}: dir item key names a non-directory")); }
            }
            ITEM_XATTR => {
                if data.len() < XATTR_HEADER_SIZE { return Err(format!("{tag_context}: short xattr header")); }
                let name_len = get16(data, 0) as usize;
                let value_len = get32(data, 4) as u64;
                if name_len == 0 || name_len > 255 || data[2] > 1 || data[3] != 0 || XATTR_HEADER_SIZE + name_len > data.len() {
                    return Err(format!("{tag_context}: invalid xattr header/name"));
                }
                let inline_size = XATTR_HEADER_SIZE + name_len + value_len as usize;
                if data[2] == 1 {
                    if data.len() != XATTR_HEADER_SIZE + name_len + 16 || inline_size <= XATTR_INLINE_MAX { return Err(format!("{tag_context}: invalid indirect xattr payload")); }
                    hidden_inode(&tree.items, (get64(data, XATTR_HEADER_SIZE + name_len), get64(data, XATTR_HEADER_SIZE + name_len + 8)), key.objectid, value_len)?;
                } else if value_len != (data.len() - XATTR_HEADER_SIZE - name_len) as u64 || inline_size > XATTR_INLINE_MAX {
                    return Err(format!("{tag_context}: invalid inline xattr size"));
                }
            }
            ITEM_ACCESS_CONTROL => {
                if data.len() < ACCESS_CONTROL_FIXED_BYTES || key.offset != 0 { return Err(format!("{tag_context}: short access-control item")); }
                let header = get64(data, 16);
                let acl_len = (header >> 8) & 0xFF;
                let label_len = ((header >> 32) & 0xFFFF) as usize;
                let indirect = header & ACCESS_CONTROL_INDIRECT != 0;
                if header & 0xFF != ACCESS_CONTROL_VERSION || acl_len > ACL_MAX_ACES || header & ACCESS_CONTROL_RESERVED != 0 {
                    return Err(format!("{tag_context}: access-control header"));
                }
                let owner = item_of(&tree.items, Key::new(key.locality, key.objectid, ITEM_INODE, 0)).ok_or_else(|| format!("{tag_context}: access-control item without its inode"))?;
                if get64(owner, 0x18) != get64(data, 0) || get64(owner, 0x20) != get64(data, 8) {
                    return Err(format!("{tag_context}: access-control owner or group disagrees with inode {}", key.objectid));
                }
                if indirect {
                    if data.len() != ACCESS_CONTROL_FIXED_BYTES + 16 || label_len == 0 { return Err(format!("{tag_context}: indirect access-control payload")); }
                    hidden_inode(&tree.items, (get64(data, ACCESS_CONTROL_FIXED_BYTES), get64(data, ACCESS_CONTROL_FIXED_BYTES + 8)), key.objectid, label_len as u64)?;
                } else if data.len() != ACCESS_CONTROL_FIXED_BYTES + label_len {
                    return Err(format!("{tag_context}: inline access-control label length"));
                }
            }
            ITEM_EXTENT_DATA => {
                let shape = extent_shape(key, data)?;
                if get64(data, 0) > publish { return Err(format!("{tag_context}: extent birth above publish sequence")); }
                if ends.get(&(key.locality, key.objectid)).is_some_and(|end| shape.start < *end) { return Err(format!("{tag_context}: inode {}: overlapping extents", key.objectid)); }
                ends.insert((key.locality, key.objectid), shape.start + shape.len);
                if item_of(&tree.items, Key::new(key.locality, key.objectid, ITEM_INODE, 0)).is_none() { return Err(format!("{tag_context}: extent has no inode in its own root")); }
                if data[0x20] == EXTENT_INLINE && get16(data, 0x22) == ENCODING_INDIRECT {
                    let hidden = (get64(data, EXTENT_HEADER_SIZE), get64(data, EXTENT_HEADER_SIZE + 8));
                    if hidden == (key.locality, key.objectid) { return Err("self-referencing indirect extent".into()); }
                    hidden_inode(&tree.items, hidden, key.objectid, shape.len)?;
                }
                if data[0x20] == EXTENT_REGULAR {
                    let first = get64(data, 0x10);
                    let blocks = get64(data, 0x18) / BLOCK_SIZE as u64;
                    let end = first.checked_add(blocks).ok_or("physical extent overflow")?;
                    if end > sb.total_blocks { return Err("extent exceeds filesystem geometry".into()); }
                    data_owned.push((first, blocks, get64(data, 0)));
                    *regular_blocks.entry((key.locality, key.objectid)).or_insert(0) += blocks;
                }
                if data[0x20] == EXTENT_ABSENT && (subvol == KEY_TREE_SUBVOL || subvol == STORE_SUBVOL) { return Err(format!("{tag_context}: absent extent in an internal subvolume")); }
            }
            ITEM_DEVICE => {
                if data.len() != 8 || key.offset != 0 { return Err(format!("{tag_context}: device item")); }
                let inode = parse_inode(item_of(&tree.items, Key::new(key.locality, key.objectid, ITEM_INODE, 0)).ok_or("device item without its inode")?)?;
                if inode.mode & S_IFMT != S_IFCHR && inode.mode & S_IFMT != S_IFBLK { return Err(format!("{tag_context}: device item on a non-device")); }
            }
            ITEM_PROJECT => {
                // One item iff a word is nonzero, under a valid project id.
                if data.len() != 32 || key.locality != 0 || key.offset != 0 || key.objectid >= u32::MAX as u64 || data.iter().all(|b| *b == 0) {
                    return Err(format!("{tag_context}: project item"));
                }
            }
            ITEM_APPEND_RESULT => {
                if data.len() != 40 || key.locality != 0 || get32(data, 36) != 0 { return Err(format!("{tag_context}: append result item")); }
            }
            ITEM_THAW => {
                if data.len() != 32 || key != Key::new(0, 0, ITEM_THAW, 0) || subvol == KEY_TREE_SUBVOL || subvol == STORE_SUBVOL { return Err(format!("{tag_context}: thaw item")); }
            }
            ITEM_SKEY => {
                if subvol != KEY_TREE_SUBVOL { return Err(format!("{tag_context}: key-tree item outside the key tree")); }
                let expected = if keys.suite.is_some() { NAME_BYTES + 8 + KEY_BYTES } else { NAME_BYTES + 8 };
                if data.len() != expected { return Err(format!("{tag_context}: skey item length")); }
                let mut name = [0u8; 32];
                name.copy_from_slice(&data[..32]);
                if skey_key(&name) != key { return Err(format!("{tag_context}: skey key disagrees with its name")); }
                if get64(data, 32) == 0 || get64(data, 32) > publish { return Err(format!("{tag_context}: skey admission epoch")); }
            }
            ITEM_SIGNING_SECRET => {
                if subvol != KEY_TREE_SUBVOL || data.len() != 32 || key != Key::new(0, 0, ITEM_SIGNING_SECRET, 0) { return Err(format!("{tag_context}: signing secret item")); }
            }
            ITEM_COMMIT_SIGNATURE => {
                if subvol != KEY_TREE_SUBVOL || data.len() != NAME_BYTES + SIGNATURE_BYTES || key.offset != 0 { return Err(format!("{tag_context}: commit signature item")); }
            }
            other => return Err(format!("{tag_context}: unsupported item type {:#x}", other)),
        }
    }
    if subvol != KEY_TREE_SUBVOL && inode_count == 0 { return Err(format!("{tag_context}: no inode")); }
    if objectid_hwm <= max_objectid || incarnation_hwm <= max_incarnation { return Err(format!("{tag_context}: inode identity high-water violation")); }
    for (&key, _) in &index_items {
        if key.ty != ITEM_OBJECT_INDEX || key.locality != 0 || key.offset != 0 || !tree.items.iter().any(|(k, _)| k.ty == ITEM_INODE && k.objectid == key.objectid) {
            return Err(format!("{tag_context}: object index names an absent inode {}", key.objectid));
        }
    }
    for (locality, dir) in directories { validate_directory(keys, subvol, &tree.items, dir, locality, tag_context)?; }
    // Stored project use equals the use the live inodes give: each live,
    // non-hidden, non-retained inode counts once in its project's objects
    // with its stored regular blocks, and a hidden inode's blocks count in
    // the project of the inode that owns it, unless that owner is retained.
    let project_of: BTreeMap<u64, Option<u32>> = inodes.iter()
        .map(|&(_, objectid, project, flags, _)| (objectid, (flags & (INODE_HIDDEN | INODE_RETAINED) == 0).then_some(project)))
        .collect();
    let mut derived = BTreeMap::<u32, (u64, u64)>::new();
    for &(locality, objectid, project, flags, owner) in &inodes {
        let blocks = regular_blocks.get(&(locality, objectid)).copied().unwrap_or(0);
        if flags & INODE_HIDDEN != 0 {
            if let Some(Some(owner_project)) = project_of.get(&owner) { derived.entry(*owner_project).or_default().0 += blocks; }
        } else if flags & INODE_RETAINED == 0 {
            let used = derived.entry(project).or_default();
            used.0 += blocks;
            used.1 += 1;
        }
    }
    let stored: BTreeMap<u32, (u64, u64)> = tree.items.iter().filter(|(key, _)| key.ty == ITEM_PROJECT)
        .map(|(key, data)| (key.objectid as u32, (get64(data, 0), get64(data, 8)))).collect();
    for project in derived.keys().chain(stored.keys()) {
        let (found, expected) = (stored.get(project).copied().unwrap_or((0, 0)), derived.get(project).copied().unwrap_or((0, 0)));
        if found != expected {
            return Err(format!("{tag_context}: project {project} stores use {found:?} (blocks, objects) but its inodes use {expected:?}"));
        }
    }
    for (first, blocks, birth) in data_owned {
        for block in first..first + blocks {
            check_pointer_target(sb, block, tag_context)?;
            tree.data.insert(block);
        }
        // Every unit of the run carries a tag at its birth.
        let mut unit = 0;
        while unit < blocks {
            let run_start = first + unit;
            let Some(tags) = tag_items.get(&Key::new(0, run_start, ITEM_DATA_TAG, birth)) else {
                return Err(format!("{tag_context}: data at block {run_start} birth {birth} has no tag run"));
            };
            let run = (tags.len() / 16) as u64;
            if run > blocks - unit { return Err(format!("{tag_context}: data-tag run past its extent")); }
            for i in 0..run {
                let mut tag = [0u8; 16];
                tag.copy_from_slice(&tags[(i as usize) * 16..(i as usize + 1) * 16]);
                if reader.read_image(run_start + i, birth, &tag).is_err() { findings.push(format!("{tag_context}: data block {} tag mismatch", run_start + i)); }
            }
            unit += run;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deadlogs and share trees
// ---------------------------------------------------------------------------

struct Deadlog {
    blocks: Vec<u64>,
    /// `(sequence, address, length, birth)` entries above the cursor.
    entries: Vec<(u64, u64, u64, u64)>,
}

/// Walk a deadlog tree: a tree of kind `TREE_DEADLOG` owned by the
/// subvolume, keyed `(subvol, sequence, DEADLOG_ENTRY, address)`, whose
/// entries at or below the row's cursor have settled and must be absent.
fn walk_deadlog(reader: &ImageReader, sb: &Superblock, root: Pointer, owner: u64, cursor: u64, where_: &str, trees: &mut BTreeMap<u64, Tree>) -> Result<Deadlog, String> {
    let mut log = Deadlog { blocks: Vec::new(), entries: Vec::new() };
    if root.is_null() { return Ok(log); }
    cache_tree(reader, sb, root, TREE_DEADLOG, owner, sb.commit_seq, trees)?;
    let tree = &trees[&root.address];
    log.blocks.extend(&tree.nodes);
    for (key, data) in &tree.items {
        if key.locality != owner || key.ty != ITEM_DEADLOG_ENTRY || data.len() != DEADLOG_ENTRY_BYTES { return Err(format!("{where_}: deadlog entry key or payload")); }
        let length = get32(data, 0) as u64;
        if get32(data, 4) != 0 || length == 0 { return Err(format!("{where_}: deadlog entry")); }
        let birth = get64(data, 8);
        if key.objectid <= cursor { return Err(format!("{where_}: deadlog entry at or below the cursor")); }
        let address = key.offset;
        for b in address..address.checked_add(length).ok_or("deadlog range overflow")? { check_pointer_target(sb, b, where_)?; }
        log.entries.push((key.objectid, address, length, birth));
    }
    Ok(log)
}

/// Walk a share tree: `(0, address, SHARE_ENTRY, birth)` rows counting the
/// live and retained references of one run; returns its nodes and the
/// shared blocks it names.
fn walk_share(reader: &ImageReader, sb: &Superblock, root: Pointer, owner: u64, entry_count: u64, shared_blocks: u64, where_: &str, trees: &mut BTreeMap<u64, Tree>)
    -> Result<(Vec<u64>, BTreeSet<u64>), String>
{
    if root.is_null() {
        if entry_count != 0 || shared_blocks != 0 { return Err(format!("{where_}: share row without a tree counts entries")); }
        return Ok((Vec::new(), BTreeSet::new()));
    }
    cache_tree(reader, sb, root, TREE_SHARE, owner, sb.commit_seq, trees)?;
    let tree = &trees[&root.address];
    let mut blocks = BTreeSet::new();
    let mut entries = 0u64;
    for (key, data) in &tree.items {
        if key.locality != 0 || key.ty != ITEM_SHARE_ENTRY || data.len() != SHARE_ENTRY_BYTES || get32(data, 12) != 0 { return Err(format!("{where_}: share entry")); }
        let length = get32(data, 0) as u64;
        let references = get32(data, 4) as u64 + get32(data, 8) as u64;
        if length == 0 || references < 2 { return Err(format!("{where_}: share entry length or references")); }
        for b in key.objectid..key.objectid.checked_add(length).ok_or("share range overflow")? { check_pointer_target(sb, b, where_)?; blocks.insert(b); }
        entries += 1;
    }
    if entries != entry_count || blocks.len() as u64 != shared_blocks { return Err(format!("{where_}: share row counts disagree with the tree")); }
    Ok((tree.nodes.iter().copied().collect(), blocks))
}

// ---------------------------------------------------------------------------
// Log replay
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct LogSummary {
    /// Certified atoms above the checkpoint that the chain reached.
    pub applied: usize,
    pub findings: Vec<String>,
    pub reserved_hwm: u64,
}

struct ScannedFragment { head: log::Head, fragment: log::Fragment, images: Vec<Vec<u8>>, head_block: Vec<u8>, complete: bool }
struct ScannedCert { head: log::Head, cert: log::Certificate, tag: [u8; 16] }
struct CertifiedAtom { seq: u64, fragments: Vec<ScannedFragment>, cert: ScannedCert }

/// Scan the whole ring, assemble complete record sets, follow the chain from
/// the checkpoint and apply each certified atom to the overlay and the
/// effective superblock. Journaled images are framed by xxh3 whatever the
/// suite: a home copy is a copy of bytes.
pub(super) fn replay(reader: &mut ImageReader, sb: &mut Superblock) -> Result<LogSummary, String> {
    let mut summary = LogSummary { reserved_hwm: sb.reserved_seq_hwm, ..Default::default() };
    let mut fragments: Vec<ScannedFragment> = Vec::new();
    let mut certs: Vec<ScannedCert> = Vec::new();
    let mut lsn = 0u64;
    while lsn < sb.log_blocks {
        let block = reader.raw_block(sb.log_start + lsn)?;
        let Some(head) = log::parse_head(&block, sb.volume_incarnation) else { lsn += 1; continue };
        if head.lsn != lsn { summary.findings.push(format!("log record at {lsn} claims offset {}", head.lsn)); lsn += 1; continue; }
        match head.kind {
            log::KIND_ATOM => {
                let fragment = match log::parse_fragment(&block) {
                    Ok(f) => f,
                    Err(error) => { summary.findings.push(format!("log record at {lsn}: {error}")); lsn += 1; continue; }
                };
                let count = fragment.images.len() as u64;
                if lsn + 1 + count > sb.log_blocks { summary.findings.push(format!("log record at {lsn} straddles the ring end")); lsn += 1; continue; }
                let mut images = Vec::new();
                let mut complete = true;
                for (i, entry) in fragment.images.iter().enumerate() {
                    let image = reader.raw_block(sb.log_start + lsn + 1 + i as u64)?;
                    if xxh3::hash128(&image) != entry.tag || !overwrite_target(sb, entry.address) || entry.birth != head.seq { complete = false; }
                    images.push(image);
                }
                for root in &fragment.roots {
                    if root.pointer.birth > head.seq || (!root.pointer.is_null() && check_pointer_target(sb, root.pointer.address, "root entry").is_err()) { complete = false; }
                }
                for alloc in &fragment.allocs {
                    let end = alloc.first.checked_add(alloc.count as u64);
                    if alloc.count == 0 || end.is_none_or(|end| end > sb.total_blocks) || sb.is_reserved(alloc.first) { complete = false; }
                }
                fragments.push(ScannedFragment { head, fragment, images, head_block: block, complete });
                lsn += 1 + count;
            }
            log::KIND_CERT => {
                match log::parse_certificate(&block) {
                    Ok(cert) => certs.push(ScannedCert { head, cert, tag: log::record_tag(&block) }),
                    Err(error) => summary.findings.push(format!("log record at {lsn}: {error}")),
                }
                lsn += 1;
            }
            _ => {
                match log::parse_reserve(&block) {
                    Ok(hwm) => summary.reserved_hwm = summary.reserved_hwm.max(hwm),
                    Err(error) => summary.findings.push(format!("log record at {lsn}: {error}")),
                }
                lsn += 1;
            }
        }
    }
    for cert in &certs { summary.reserved_hwm = summary.reserved_hwm.max(cert.cert.reserved_seq_hwm); }

    let mut atoms: Vec<CertifiedAtom> = Vec::new();
    for cert in certs {
        let mut set: Vec<usize> = fragments.iter().enumerate().filter(|(_, f)| f.head.seq == cert.head.seq && f.head.cycle == cert.head.cycle).map(|(i, _)| i).collect();
        set.sort_by_key(|&i| fragments[i].head.fragment_index);
        let count = cert.cert.fragment_count as usize;
        let mut ok = set.len() == count && count > 0;
        let mut expected_lsn = cert.cert.first_lsn;
        let mut image_blocks = 0u32;
        for (position, &i) in set.iter().enumerate() {
            let f = &fragments[i];
            if f.head.fragment_index as usize != position || f.head.fragment_count as usize != count || f.head.lsn != expected_lsn || !f.complete
                || f.head.predecessor != cert.head.predecessor { ok = false; break; }
            expected_lsn += 1 + f.fragment.images.len() as u64;
            image_blocks += f.fragment.images.len() as u32;
        }
        if ok && (expected_lsn != cert.head.lsn || cert.cert.record_blocks != expected_lsn - cert.cert.first_lsn + 1 || cert.cert.image_blocks != image_blocks) { ok = false; }
        if ok {
            let digest_input: Vec<(Vec<u8>, Vec<[u8; 16]>)> = set.iter().map(|&i| { let f = &fragments[i]; (f.head_block.clone(), f.fragment.images.iter().map(|e| e.tag).collect()) }).collect();
            if log::atom_digest(&digest_input) != cert.cert.digest { ok = false; }
        }
        if !ok { continue; }
        let mut taken = Vec::new();
        for &i in set.iter().rev() { taken.push(fragments.remove(i)); }
        taken.reverse();
        atoms.push(CertifiedAtom { seq: cert.head.seq, fragments: taken, cert });
    }

    let mut current = sb.last_certificate;
    loop {
        let candidates: Vec<usize> = atoms.iter().enumerate().filter(|(_, a)| a.cert.head.predecessor == current).map(|(i, _)| i).collect();
        if candidates.is_empty() { break; }
        if candidates.len() > 1 { summary.findings.push("two certificates name one predecessor; writable mount refused".into()); break; }
        let atom = atoms.remove(candidates[0]);
        if atom.seq <= sb.commit_seq { summary.findings.push(format!("certified atom {} on the chain is not above the checkpoint", atom.seq)); break; }
        for fragment in &atom.fragments {
            for (entry, image) in fragment.fragment.images.iter().zip(&fragment.images) { reader.overlay.insert(entry.address, image.clone()); }
        }
        sb.table_root = atom.cert.cert.table_root;
        sb.registry_root = atom.cert.cert.registry_root;
        sb.commit_seq = atom.seq;
        sb.last_certificate = atom.cert.tag;
        sb.reserved_seq_hwm = sb.reserved_seq_hwm.max(atom.cert.cert.reserved_seq_hwm);
        current = atom.cert.tag;
        summary.applied += 1;
    }
    for atom in atoms {
        if atom.seq > sb.commit_seq { summary.findings.push(format!("certified atom {} is not reachable from the checkpoint chain", atom.seq)); }
    }
    if summary.reserved_hwm < sb.commit_seq { summary.findings.push("reservation high-water mark below the certified sequence".into()); }
    Ok(summary)
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// The store subvolume as the verifier reads it: its files by name.
pub(super) struct Store {
    files: BTreeMap<Vec<u8>, (u64, u64, Vec<u8>)>,
    keys: BTreeMap<[u8; 32], [u8; 32]>,
    suite: Option<primitives::Suite>,
    name_key: [u8; 32],
    /// The store subvolume's UUID, which every pack header names.
    identity: [u8; 16],
}

impl Store {
    /// Read every store file and every key-tree key; `identity` is the store
    /// subvolume row's UUID.
    pub(super) fn load(reader: &ImageReader, keys: &Keys, store: View<'_>, key_items: &ItemMap, identity: [u8; 16]) -> Result<Self, String> {
        let mut files = BTreeMap::new();
        for (_, target, dir_type, name) in dir_entries(store.items, ROOT_INO, ROOT_INO)? {
            if dir_type != 1 { return Err("store root holds a non-file".into()); }
            let inode = parse_inode(item_of(store.items, Key::new(target.0, target.1, ITEM_INODE, 0)).ok_or("store entry without its inode")?)?;
            let content = super::file_content(reader, store, target.0, target.1, inode.size)?;
            files.insert(name, (target.1, inode.incarnation, content));
        }
        let mut object_keys = BTreeMap::new();
        for (key, data) in key_items {
            if key.ty != ITEM_SKEY { continue; }
            let mut name = [0u8; 32];
            name.copy_from_slice(&data[..32]);
            let mut object_key = [0u8; 32];
            if keys.suite.is_some() { object_key.copy_from_slice(&data[40..72]); }
            object_keys.insert(name, object_key);
        }
        Ok(Self { files, keys: object_keys, suite: keys.suite, name_key: keys.name_key, identity })
    }

    /// A pack's header: the magic, a zero word and the identity of the store
    /// it belongs to, as the provider checks before it reads a pack.
    fn check_pack_header(&self, pack: &[u8]) -> Result<(), String> {
        if pack.len() < seal::PACK_HEADER_SIZE || &pack[..4] != seal::PACK_MAGIC || pack[4..8] != [0; 4] {
            return Err("pack header".into());
        }
        if pack[8..seal::PACK_HEADER_SIZE] != self.identity {
            return Err("pack header names another store".into());
        }
        Ok(())
    }

    /// The canonical encoding of the object `name`, located through the
    /// super-index and opened under its key.
    pub(super) fn object(&self, name: &[u8; 32], kind: u8) -> Result<Vec<u8>, String> {
        let (_, _, index) = self.files.get(seal::SUPER_INDEX_NAME).ok_or("store has no super-index")?;
        let (packs, rows) = seal::read_super_index(index)?;
        let row = rows.iter().find(|r| r.name == *name).ok_or_else(|| format!("object {} is not in the super-index", primitives::hex(name)))?;
        let (pack_id, pack_incarnation) = packs[row.pack as usize];
        let (ino, incarnation, pack) = self.files.get(seal::pack_file_name(pack_id, false).as_bytes()).ok_or("super-index names a missing pack")?;
        if *ino != pack_id || *incarnation != pack_incarnation { return Err("pack file identity disagrees with the super-index".into()); }
        self.check_pack_header(pack)?;
        let at = row.offset as usize;
        let header = pack.get(at..at + seal::PACK_ENTRY_HEADER_SIZE).ok_or("pack entry outside the pack")?;
        if header[..32] != name[..] || get64(header, 32) != row.stored_length { return Err("pack entry header disagrees with the index".into()); }
        let body = pack.get(at + seal::PACK_ENTRY_HEADER_SIZE..at + seal::PACK_ENTRY_HEADER_SIZE + row.stored_length as usize).ok_or("pack body outside the pack")?;
        let key = self.keys.get(name).ok_or_else(|| format!("object {} has no key-tree item", primitives::hex(name)))?;
        let encoding = seal::open_body(body, kind, self.suite, key, name)?;
        if seal::name_of(&self.name_key, &encoding) != *name { return Err("object name disagrees with its encoding".into()); }
        Ok(encoding)
    }

    /// Every pack index agrees with its pack and the super-index covers
    /// every entry.
    pub(super) fn check_indexes(&self) -> Result<(), String> {
        let (_, _, index) = self.files.get(seal::SUPER_INDEX_NAME).ok_or("store has no super-index")?;
        let (packs, rows) = seal::read_super_index(index)?;
        let mut covered: BTreeSet<[u8; 32]> = rows.iter().map(|r| r.name).collect();
        for (name, (_, _, content)) in &self.files {
            if name.ends_with(b".pack") { self.check_pack_header(content)?; }
        }
        for (name, (ino, incarnation, content)) in &self.files {
            if !name.ends_with(b".idx") { continue; }
            let (pack, index_rows) = seal::read_pack_index(content)?;
            let (pack_ino, pack_incarnation, pack_bytes) = self.files.get(seal::pack_file_name(pack.0, false).as_bytes()).ok_or("index names a missing pack")?;
            if pack != (*pack_ino, *pack_incarnation) { return Err("pack index names another pack".into()); }
            let _ = (ino, incarnation);
            for row in &index_rows {
                let at = row.offset as usize;
                let header = pack_bytes.get(at..at + seal::PACK_ENTRY_HEADER_SIZE).ok_or("index row outside the pack")?;
                if header[..32] != row.name[..] || get64(header, 32) != row.stored_length { return Err("index row disagrees with the pack entry".into()); }
                if !covered.remove(&row.name) && !packs.contains(&pack) { return Err("index row not in the super-index".into()); }
            }
        }
        Ok(())
    }
}

/// Walk a commit's closure: every tree, manifest and chunk present and
/// named by its encoding; returns the entries of every tree keyed by the
/// tree's name.
pub(super) fn walk_commit(store: &Store, commit_name: &[u8; 32], public_key: &[u8; 32], signature: &[u8; 64], findings: &mut Vec<String>)
    -> Result<(seal::Commit, BTreeMap<[u8; 32], Vec<seal::Entry>>), String>
{
    let encoding = store.object(commit_name, seal::KIND_COMMIT)?;
    if !crate::crypto::ed25519::verify(public_key, &encoding, signature) { findings.push(format!("commit {}: signature does not verify", primitives::hex(commit_name))); }
    let commit = seal::decode_commit(&encoding)?;
    if !commit.chunker.valid() || commit.casefold_version != CASEFOLD_VERSION_UNICODE_15_1 || commit.key_algorithm != seal::KEY_ALGORITHM_SIPHASH {
        return Err("commit parameters".into());
    }
    let mut trees = BTreeMap::new();
    // Each tree with the axes of the directory its entries land in.
    let mut pending = vec![(commit.root, (commit.root_case_axis, commit.root_norm_axis))];
    while let Some((tree_name, container)) = pending.pop() {
        if trees.contains_key(&tree_name) { continue; }
        let entries = decode_tree(&store.object(&tree_name, seal::KIND_TREE)?, container)?;
        for entry in &entries {
            match &entry.target {
                seal::Target::Name(name) if entry.header.kind == seal::ENTRY_DIRECTORY => {
                    pending.push((*name, (entry.header.case_axis, entry.header.norm_axis)));
                }
                seal::Target::Name(name) => check_manifest(store, name, entry.header.size)?,
                _ => {}
            }
            for (_, value) in &entry.xattrs { if let seal::Value::Manifest(name) = value { check_manifest(store, name, 0)?; } }
        }
        trees.insert(tree_name, entries);
    }
    Ok((commit, trees))
}

fn check_manifest(store: &Store, name: &[u8; 32], size: u64) -> Result<(), String> {
    let encoding = store.object(name, seal::KIND_MANIFEST)?;
    let (total, chunks) = decode_manifest(&encoding)?;
    if size != 0 && total != size { return Err("manifest total disagrees with the entry size".into()); }
    for (chunk, len) in chunks {
        let encoding = store.object(&chunk, seal::KIND_CHUNK)?;
        if encoding.len() != 1 + len as usize { return Err("chunk length disagrees with the manifest".into()); }
    }
    Ok(())
}

/// The manifest's content: every chunk in order.
pub(super) fn manifest_content(store: &Store, name: &[u8; 32]) -> Result<Vec<u8>, String> {
    let (total, chunks) = decode_manifest(&store.object(name, seal::KIND_MANIFEST)?)?;
    let mut out = Vec::with_capacity(total as usize);
    for (chunk, _) in chunks { out.extend_from_slice(&store.object(&chunk, seal::KIND_CHUNK)?[1..]); }
    if out.len() as u64 != total { return Err("manifest chunks do not sum to its total".into()); }
    Ok(out)
}

pub(super) fn decode_manifest(data: &[u8]) -> Result<(u64, Vec<([u8; 32], u32)>), String> {
    if data.len() < 13 || data[0] != seal::KIND_MANIFEST { return Err("manifest header".into()); }
    let total = get64(data, 1);
    let count = get32(data, 9) as usize;
    if data.len() != 13 + count * 36 { return Err("manifest length".into()); }
    let mut chunks = Vec::with_capacity(count);
    let mut sum = 0u64;
    for i in 0..count {
        let at = 13 + i * 36;
        let mut name = [0u8; 32];
        name.copy_from_slice(&data[at..at + 32]);
        let len = get32(data, at + 32);
        if len == 0 || len as u64 > CHUNK_ABSOLUTE_MAX { return Err("manifest chunk length".into()); }
        sum += len as u64;
        chunks.push((name, len));
    }
    if sum != total || total <= 4096 { return Err("manifest total".into()); }
    Ok((total, chunks))
}

/// Decode a tree encoding into its entries; a non-canonical encoding is
/// refused by re-encoding.
/// Decode a tree whose entries land in a directory of the `(case,
/// normalization)` axes `container`: a name there is valid UTF-8 when
/// either axis is not sensitive.
pub(super) fn decode_tree(data: &[u8], container: (u8, u8)) -> Result<Vec<seal::Entry>, String> {
    if container.0 > AXIS_MIXED || container.1 > AXIS_MIXED {
        return Err("directory axes".into());
    }
    let policy = Policy {
        case_axis: container.0, norm_axis: container.1, plugin: DIR_HASH_SIPHASH,
    };
    let mut unique_names = BTreeSet::new();
    let mut at = 0usize;
    let take = |at: &mut usize, n: usize| -> Result<&[u8], String> { let s = data.get(*at..*at + n).ok_or("tree truncated")?; *at += n; Ok(s) };
    if take(&mut at, 1)?[0] != seal::KIND_TREE { return Err("not a tree".into()); }
    let count = get32(take(&mut at, 4)?, 0) as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = get16(take(&mut at, 2)?, 0) as usize;
        let name = take(&mut at, name_len)?.to_vec();
        if name.is_empty() || name.len() > NAME_MAX || name.contains(&b'/') || name.contains(&0) {
            return Err("entry name".into());
        }
        if (container.0 != AXIS_SENSITIVE || container.1 != AXIS_SENSITIVE) && std::str::from_utf8(&name).is_err() {
            return Err("an invalid UTF-8 name in a directory with a non-sensitive axis".into());
        }
        if !unique_names.insert(policy.unique_key(&name)?) {
            return Err("equivalent seal tree names".into());
        }
        let header = seal::EntryHeader {
            kind: take(&mut at, 1)?[0], mode: get32(take(&mut at, 4)?, 0), owner: get64(take(&mut at, 8)?, 0), group: get64(take(&mut at, 8)?, 0),
            atime: get64(take(&mut at, 8)?, 0), mtime: get64(take(&mut at, 8)?, 0), ctime: get64(take(&mut at, 8)?, 0), crtime: get64(take(&mut at, 8)?, 0),
            flags: get32(take(&mut at, 4)?, 0), case_axis: take(&mut at, 1)?[0], norm_axis: take(&mut at, 1)?[0], project_id: get32(take(&mut at, 4)?, 0),
            size: get64(take(&mut at, 8)?, 0), device: get64(take(&mut at, 8)?, 0), link_group: get64(take(&mut at, 8)?, 0),
        };
        // An entry carries the inode's attribute flags, the CASEFOLD
        // projection of its case axis and a symbolic link's DIRECTORY_LINK;
        // the provider refuses anything else.
        if header.flags & !INODE_ENTRY_FLAGS != 0 {
            return Err(format!("entry flags {:#x}", header.flags));
        }
        if header.flags & INODE_DIRECTORY_LINK != 0 && header.kind != seal::ENTRY_SYMLINK {
            return Err("a directory-link flag on an entry that is not a symbolic link".into());
        }
        if header.case_axis > AXIS_MIXED || header.norm_axis > AXIS_MIXED
            || (header.flags & INODE_CASEFOLD != 0) != (header.case_axis != AXIS_SENSITIVE)
            || header.project_id == u32::MAX {
            return Err("entry axes, casefold projection or project id".into());
        }
        // Only a directory indexes names, so every other entry is
        // sensitive on both axes, as its inode is.
        if header.kind != seal::ENTRY_DIRECTORY && (header.case_axis != AXIS_SENSITIVE || header.norm_axis != AXIS_SENSITIVE) {
            return Err("a case or normalization axis on an entry that is not a directory".into());
        }
        let target = match take(&mut at, 1)?[0] {
            seal::TARGET_NONE => seal::Target::None,
            seal::TARGET_NAME => { let mut n = [0u8; 32]; n.copy_from_slice(take(&mut at, 32)?); seal::Target::Name(n) }
            seal::TARGET_INLINE => { let len = get32(take(&mut at, 4)?, 0) as usize; seal::Target::Inline(take(&mut at, len)?.to_vec()) }
            _ => return Err("entry target form".into()),
        };
        let value = |at: &mut usize| -> Result<seal::Value, String> {
            match take(at, 1)?[0] {
                seal::VALUE_INLINE => { let len = get32(take(at, 4)?, 0) as usize; Ok(seal::Value::Inline(take(at, len)?.to_vec())) }
                seal::VALUE_NAME => { let mut n = [0u8; 32]; n.copy_from_slice(take(at, 32)?); Ok(seal::Value::Manifest(n)) }
                _ => Err("value form".into()),
            }
        };
        let xattr_count = get32(take(&mut at, 4)?, 0) as usize;
        let mut xattrs = Vec::with_capacity(xattr_count);
        for _ in 0..xattr_count {
            let len = get16(take(&mut at, 2)?, 0) as usize;
            let xname = take(&mut at, len)?.to_vec();
            xattrs.push((xname, value(&mut at)?));
        }
        let access_control = match take(&mut at, 1)?[0] {
            0 => None,
            1 => {
                let mut words = [0u64; seal::ACCESS_CONTROL_WORDS];
                for w in words.iter_mut() { *w = get64(take(&mut at, 8)?, 0); }
                Some((words, value(&mut at)?))
            }
            _ => return Err("access-control form".into()),
        };
        entries.push(seal::Entry { name, header, target, xattrs, access_control });
    }
    if at != data.len() { return Err("tree trailer".into()); }
    if seal::encode_tree(&entries)? != data { return Err("tree encoding is not canonical".into()); }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Volume inspection
// ---------------------------------------------------------------------------

pub(super) fn inspect(reader: &ImageReader, sb: &Superblock, keys: &Keys) -> Result<Volume, String> {
    let mut trees = BTreeMap::new();
    let mut findings = Vec::new();
    let mut catalog_rows = Vec::new();
    cache_tree(reader, sb, sb.table_root, TREE_SUBVOL_TABLE, 0, sb.commit_seq, &mut trees)?;
    cache_tree(reader, sb, sb.registry_root, TREE_PIN_REGISTRY, 0, sb.commit_seq, &mut trees)?;

    let mut subvolumes: BTreeMap<u64, SubvolInfo> = BTreeMap::new();
    let table_items = trees[&sb.table_root.address].items.clone();
    for (&key, data) in &table_items {
        if key.ty != ITEM_SUBVOL || key.locality != 0 || key.offset != 0 { return Err("subvolume table holds a foreign item".into()); }
        let id = key.objectid;
        let row = SubvolRow::unpack(data)?;
        if id == 0 || (id > STORE_SUBVOL && id < FIRST_USER_SUBVOL) || (id >= sb.subvol_id_hwm && id > STORE_SUBVOL) { return Err(format!("subvolume id {id} is not allocatable")); }
        if row.incarnation == 0 || row.publish_seq == 0 || row.publish_seq > sb.commit_seq || row.catalog_id_hwm == 0 || row.objectid_hwm == 0 || row.incarnation_hwm == 0
            || (row.state != SUBVOL_STATE_LIVE && row.state != SUBVOL_STATE_CLOSING) {
            return Err(format!("subvolume {id}: incarnation, publish sequence, catalog mark or state"));
        }
        if row.flags & !SUBVOL_FLAGS_DEFINED != 0 { return Err(format!("subvolume {id}: undefined flag bits {:#x}", row.flags & !SUBVOL_FLAGS_DEFINED)); }
        if id == DEFAULT_SUBVOL && row.flags & SUBVOL_FLAG_BOOT_DEFAULT == 0 { return Err("subvolume 1 is not the boot default".into()); }
        if (id == KEY_TREE_SUBVOL || id == STORE_SUBVOL) && row.flags & SUBVOL_FLAG_NOSEAL == 0 { return Err(format!("subvolume {id}: internal subvolume is not marked no-seal")); }
        if (id == STORE_SUBVOL) != (row.flags & SUBVOL_FLAG_STORE != 0) { return Err(format!("subvolume {id}: store flag")); }
        if row.limits != [0; 4] && !valid_limits(row.limits) { return Err(format!("subvolume {id}: limits")); }
        cache_tree(reader, sb, row.item_root, TREE_ITEM, id, row.publish_seq, &mut trees)?;
        cache_tree(reader, sb, row.index_root, TREE_OBJECT_INDEX, id, row.publish_seq, &mut trees)?;
        cache_tree(reader, sb, row.tag_root, TREE_DATA_TAG, id, row.publish_seq, &mut trees)?;
        validate_version(reader, sb, keys, id, &mut trees, (row.item_root, row.index_root, row.tag_root), row.publish_seq, row.objectid_hwm, row.incarnation_hwm,
            &mut findings, &format!("subvolume {id}"))?;
        let label_end = row.label.iter().position(|&b| b == 0).unwrap_or(32);
        catalog_rows.push(format!("subvolume {} incarnation={} publish-seq={} origin={}:{} owner={}:{} limits={:?} referenced={} owned={} retained={} retain-pinned={} state={} flags={:#x} sealed-head={} label={}",
            id, row.incarnation, row.publish_seq, row.origin.0, row.origin.1, row.owner.0, row.owner.1, row.limits, row.referenced, row.owned, row.retained_charge,
            row.retain_pinned, row.state, row.flags, primitives::hex(&row.sealed_head), String::from_utf8_lossy(&row.label[..label_end])));
        subvolumes.insert(id, SubvolInfo { row });
    }
    for required in [DEFAULT_SUBVOL, KEY_TREE_SUBVOL, STORE_SUBVOL] {
        if !subvolumes.contains_key(&required) { return Err(format!("subvolume {required} missing")); }
    }

    let mut snapshots: Vec<SnapInfo> = Vec::new();
    let mut deadlogs: Vec<(u64, Deadlog)> = Vec::new();
    let mut holds: Vec<(Key, Vec<u64>)> = Vec::new();
    let mut registry_blocks: BTreeSet<u64> = BTreeSet::new();
    let mut shared_blocks: BTreeSet<u64> = BTreeSet::new();
    let mut keep_rows: Vec<(u64, u64, u64)> = Vec::new();
    if !sb.registry_root.is_null() {
        let registry_items = trees[&sb.registry_root.address].items.clone();
        registry_blocks.extend(&trees[&sb.registry_root.address].nodes);
        for (&key, data) in &registry_items {
            let subvol = key.locality;
            let row_owner = subvolumes.get(&subvol).ok_or_else(|| format!("registry row for absent subvolume {subvol}"))?;
            match key.ty {
                ITEM_SNAP => {
                    if key.offset != 0 { return Err("snapshot key offset".into()); }
                    let row = SnapRow::unpack(data)?;
                    let epoch = key.objectid;
                    if epoch == 0 || epoch > row_owner.row.publish_seq || row.snapshot_id == 0 || row.snapshot_id >= row_owner.row.catalog_id_hwm
                        || (row.owner.0 == 0) != (row.owner.1 == 0) {
                        return Err(format!("subvolume {subvol}: invalid snapshot record at epoch {epoch}"));
                    }
                    cache_tree(reader, sb, row.item_root, TREE_ITEM, subvol, epoch, &mut trees)?;
                    cache_tree(reader, sb, row.index_root, TREE_OBJECT_INDEX, subvol, epoch, &mut trees)?;
                    cache_tree(reader, sb, row.tag_root, TREE_DATA_TAG, subvol, epoch, &mut trees)?;
                    validate_version(reader, sb, keys, subvol, &mut trees, (row.item_root, row.index_root, row.tag_root), epoch, row.objectid_hwm, row.incarnation_hwm,
                        &mut findings, &format!("snapshot {subvol}@{epoch}"))?;
                    let deadlog = walk_deadlog(reader, sb, row.deadlog_root, subvol, row.deadlog_cursor, &format!("snapshot {subvol}@{epoch}"), &mut trees)?;
                    deadlogs.push((subvol, deadlog));
                    catalog_rows.push(format!("snapshot subvol={} epoch={} id={} owner={}:{} holds={} state={} deleting={} seal-time={} commit={}",
                        subvol, epoch, row.snapshot_id, row.owner.0, row.owner.1, row.holds, row.state, row.flags & SNAP_FLAG_DELETING != 0, row.seal_time,
                        primitives::hex(&row.commit_name)));
                    snapshots.push(SnapInfo { subvol, epoch, row });
                }
                ITEM_RETIRE => {
                    if key.objectid != 0 || key.offset != 0 || data.len() != RETIRE_ROW_BYTES { return Err("retirement row".into()); }
                    let root = Pointer::unpack(&data[..POINTER_SIZE])?;
                    let cursor = get64(data, POINTER_SIZE);
                    let pending = get64(data, POINTER_SIZE + 8);
                    let deadlog = walk_deadlog(reader, sb, root, subvol, cursor, &format!("retirement {subvol}"), &mut trees)?;
                    let listed: u64 = deadlog.entries.iter().map(|e| e.2).sum();
                    if listed != pending { return Err(format!("retirement {subvol}: pending count disagrees with the tree")); }
                    for entry in &deadlog.entries { if entry.0 == 0 || entry.0 > sb.commit_seq { return Err(format!("retirement {subvol}: entry sequence")); } }
                    catalog_rows.push(format!("retirement subvol={} pending={}", subvol, pending));
                    deadlogs.push((subvol, deadlog));
                }
                ITEM_HOLD => {
                    if data.len() != HOLD_ROW_WORDS * 8 { return Err("hold row".into()); }
                    let w: Vec<u64> = (0..HOLD_ROW_WORDS).map(|i| get64(data, i * 8)).collect();
                    if key.objectid == 0 || key.offset != w[2] || !(1..=4).contains(&w[0]) || w[2] == 0 || w[3] == 0 || w[4] == 0 || w[8] == 0 || w[13] == 0
                        || !(1..=3).contains(&w[16]) || w[9].checked_add(w[10]).is_none() {
                        return Err(format!("subvolume {subvol}: invalid hold row"));
                    }
                    catalog_rows.push(format!("hold subvol={} owner={}:{} view={} state={} retained={} attempt={} badge={} provider-generation={} session={} session-generation={} inode={} incarnation={} start={} length={} size={} revision={} carrier={}",
                        subvol, key.objectid, w[13], w[2], w[0], w[1], w[8], w[14], w[3], w[4], w[5], w[6], w[7], w[9], w[10], w[11], w[12], w[16]));
                    holds.push((key, w));
                }
                ITEM_GRANT => {
                    if data.len() != 8 || key.objectid == 0 || key.offset == 0 || get64(data, 0) > 1 { return Err("grant row".into()); }
                    catalog_rows.push(format!("grant subvol={} owner={}:{} capture={}", subvol, key.objectid, key.offset, get64(data, 0)));
                }
                ITEM_SOURCE => {
                    if data.len() != 8 || key.objectid == 0 || key.offset == 0 || get64(data, 0) == 0 { return Err("source row".into()); }
                }
                ITEM_WATERMARK => {
                    if data.len() != WATERMARK_ROW_BYTES || key.objectid == 0 || get64(data, 0) == 0 || get64(data, 16) == 0 || get64(data, 24) == 0 || get64(data, 40) == 0 {
                        return Err("watermark row".into());
                    }
                }
                ITEM_KEEP => {
                    if data.len() != KEEP_ROW_WORDS * 8 || key.objectid == 0 || key.offset == 0 || get64(data, 56) != 0 { return Err("keep row".into()); }
                    keep_rows.push((subvol, key.objectid, key.offset));
                    catalog_rows.push(format!("keep subvol={} source={} retained={} holds={} revision={}", subvol, key.objectid, key.offset, get64(data, 32), get64(data, 16)));
                }
                ITEM_SHARE => {
                    if data.len() != SHARE_ROW_BYTES || key.objectid != 0 || key.offset != 0 { return Err("share row".into()); }
                    let root = Pointer::unpack(&data[..POINTER_SIZE])?;
                    let (nodes, blocks) = walk_share(reader, sb, root, subvol, get64(data, 32), get64(data, 40), &format!("share {subvol}"), &mut trees)?;
                    registry_blocks.extend(nodes);
                    shared_blocks.extend(blocks);
                    catalog_rows.push(format!("share subvol={} entries={} shared={}", subvol, get64(data, 32), get64(data, 40)));
                }
                other => return Err(format!("unknown pin registry item {:#x}", other)),
            }
        }
        for (key, w) in &holds {
            if w[0] == 1 || w[0] == 4 {
                let items = &trees[&subvolumes[&key.locality].row.item_root.address].items;
                let retained = items.iter().find(|(k, _)| k.ty == ITEM_INODE && k.objectid == w[1]).map(|(k, _)| *k).ok_or("held inode missing from the live root")?;
                let inode = parse_inode(&items[&retained])?;
                if inode.flags & INODE_RETAINED == 0 && inode.nlink == 0 { return Err("hold names an inode that is neither retained nor named".into()); }
            }
        }
        for source in registry_items.keys().filter(|k| k.ty == ITEM_SOURCE) {
            if !holds.iter().any(|(k, _)| k.locality == source.locality && k.objectid == source.objectid && k.offset == source.offset) {
                return Err("source row without its hold".into());
            }
        }
        for (subvol, _, retained) in &keep_rows {
            let items = &trees[&subvolumes[subvol].row.item_root.address].items;
            if !items.iter().any(|(k, _)| k.ty == ITEM_INODE && k.objectid == *retained) { return Err("keep row names a missing inode".into()); }
        }
    }

    // Sealed snapshots: the key tree signs a commit the store holds whose
    // closure is complete and whose contents are the snapshot's.
    let key_items = subvolumes[&KEY_TREE_SUBVOL].row.item_root;
    let key_items: ItemMap = if key_items.is_null() { ItemMap::new() } else { trees[&key_items.address].items.clone() };
    let empty = ItemMap::new();
    let items_of = |root: Pointer| -> &ItemMap { trees.get(&root.address).map_or(&empty, |t| &t.items) };
    let store_row = &subvolumes[&STORE_SUBVOL].row;
    let store = if snapshots.iter().any(|s| s.row.state == SNAP_STATE_SEALED) || !key_items.is_empty() {
        let store = Store::load(reader, keys, View { items: items_of(store_row.item_root), tags: items_of(store_row.tag_root), store: None }, &key_items, store_row.uuid)?;
        store.check_indexes()?;
        Some(store)
    } else { None };
    for snapshot in &snapshots {
        if snapshot.row.state != SNAP_STATE_SEALED { continue; }
        let store = store.as_ref().ok_or("sealed snapshot without a store")?;
        let signature = key_items.get(&Key::new(snapshot.subvol, snapshot.epoch, ITEM_COMMIT_SIGNATURE, 0)).ok_or("sealed snapshot without its signature item")?;
        if signature[..32] != snapshot.row.commit_name { return Err("signature item names another commit".into()); }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&signature[32..]);
        let (commit, commit_trees) = walk_commit(store, &snapshot.row.commit_name, &sb.store_public_key, &sig, &mut findings)?;
        if commit.subvol_uuid != subvolumes[&snapshot.subvol].row.uuid || commit.epoch != snapshot.epoch || commit.seal_time != snapshot.row.seal_time {
            return Err("commit does not describe its snapshot".into());
        }
        if commit.clock_valid != u8::from(snapshot.row.flags & SNAP_FLAG_CLOCK_VALID != 0) {
            return Err("commit's clock byte disagrees with its snapshot row".into());
        }
        let view = View { items: items_of(snapshot.row.item_root), tags: items_of(snapshot.row.tag_root), store: Some(store) };
        compare_tree(reader, &commit_trees, &commit.root, view, (ROOT_INO, ROOT_INO), 0, &mut findings)?;
        if subvolumes[&snapshot.subvol].row.sealed_head != snapshot.row.commit_name
            && !snapshots.iter().any(|s| s.subvol == snapshot.subvol && s.epoch > snapshot.epoch && s.row.state == SNAP_STATE_SEALED) {
            findings.push(format!("subvolume {}: sealed head is not the newest sealed commit", snapshot.subvol));
        }
    }

    // Allocation model and accounting.
    let mut live_blocks: BTreeSet<u64> = BTreeSet::new();
    let mut snapshot_blocks: BTreeSet<u64> = BTreeSet::new();
    let table_tree = &trees[&sb.table_root.address];
    registry_blocks.extend(&table_tree.nodes);
    let blocks_of = |trees: &BTreeMap<u64, Tree>, root: Pointer| -> BTreeSet<u64> {
        let mut set = BTreeSet::new();
        if let Some(tree) = trees.get(&root.address) { set.extend(&tree.nodes); set.extend(&tree.data); }
        set
    };
    let mut per_subvol_live: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (&id, info) in &subvolumes {
        let mut set = BTreeSet::new();
        for root in [info.row.item_root, info.row.index_root, info.row.tag_root] { set.extend(blocks_of(&trees, root)); }
        live_blocks.extend(&set);
        per_subvol_live.insert(id, set);
    }
    let mut per_subvol_retained: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for snapshot in &snapshots {
        let mut set = BTreeSet::new();
        for root in [snapshot.row.item_root, snapshot.row.index_root, snapshot.row.tag_root] { set.extend(blocks_of(&trees, root)); }
        snapshot_blocks.extend(&set);
        per_subvol_retained.entry(snapshot.subvol).or_default().extend(set.difference(&per_subvol_live[&snapshot.subvol]));
    }
    for (subvol, deadlog) in &deadlogs {
        registry_blocks.extend(&deadlog.blocks);
        for &(_, address, length, _) in &deadlog.entries {
            for block in address..address + length {
                snapshot_blocks.insert(block);
                per_subvol_retained.entry(*subvol).or_default().insert(block);
            }
        }
    }
    let mut metadata = BTreeSet::<u64>::new();
    let mut data = BTreeSet::<u64>::new();
    for tree in trees.values() { metadata.extend(&tree.nodes); data.extend(&tree.data); }
    if metadata.iter().any(|block| data.contains(block)) { return Err("data extent aliases reachable tree metadata".into()); }
    if registry_blocks.iter().any(|block| data.contains(block)) { return Err("registry, deadlog or share block aliases data".into()); }
    if shared_blocks.iter().any(|block| !data.contains(block)) { return Err("share tree names a block no extent holds".into()); }
    let mut allocated = live_blocks.clone();
    allocated.extend(&snapshot_blocks);
    allocated.extend(&registry_blocks);
    let combined = allocated.len() as u64;
    let mut reserved = 0u64;
    for block in 0..sb.total_blocks {
        if sb.is_reserved(block) { allocated.insert(block); reserved += 1; }
    }
    let capacity = sb.total_blocks.checked_sub(reserved).and_then(|c| c.checked_sub(CLEANUP_BLOCKS)).ok_or("no cleanup headroom")?;
    for (&id, info) in &subvolumes {
        let live = per_subvol_live[&id].len() as u64;
        let retained = per_subvol_retained.get(&id).map_or(0, |set| set.len() as u64);
        if info.row.referenced != live { findings.push(format!("subvolume {id}: referenced {} disagrees with reachable {}", info.row.referenced, live)); }
        if info.row.owned > info.row.referenced { findings.push(format!("subvolume {id}: owned {} above referenced {}", info.row.owned, info.row.referenced)); }
        if shared_blocks.is_empty() && info.row.owned != live { findings.push(format!("subvolume {id}: owned {} disagrees with reachable {} with nothing shared", info.row.owned, live)); }
        if info.row.retained_charge != retained { findings.push(format!("subvolume {id}: retained charge {} disagrees with retained {}", info.row.retained_charge, retained)); }
        if info.row.limits != [0; 4] {
            let [quota, refquota, reservation, refreservation] = info.row.limits;
            if live > refquota || live + retained > quota || reservation.max(refreservation) > capacity {
                findings.push(format!("subvolume {id}: quota, refquota, reservation or refreservation violated"));
            }
        }
    }
    let store_data = trees.get(&subvolumes[&STORE_SUBVOL].row.item_root.address).map_or(0, |t| t.data.len() as u64);
    let accounting = Accounting {
        live: live_blocks.len() as u64, snapshots: snapshot_blocks.len() as u64, registry: registry_blocks.len() as u64, combined, reserved, capacity,
        expected_used: allocated.len() as u64, store_data,
    };
    Ok(Volume { trees, subvolumes, snapshots, accounting, catalog_rows, findings, store, allocated })
}

/// Compare a commit's tree with the snapshot's directory: the same names,
/// kinds, sizes and contents.
#[allow(clippy::too_many_arguments)]
fn compare_tree(reader: &ImageReader, trees: &BTreeMap<[u8; 32], Vec<seal::Entry>>, tree: &[u8; 32], view: View<'_>, dir: (u64, u64), depth: usize, findings: &mut Vec<String>)
    -> Result<(), String>
{
    if depth > 64 { return Err("commit tree deeper than 64 levels".into()); }
    let store = view.store.ok_or("sealed snapshot compared without a store")?;
    let items = view.items;
    let entries = trees.get(tree).ok_or("commit names a tree its closure lacks")?;
    let actual = dir_entries(items, dir.0, dir.1)?;
    if actual.len() != entries.len() { findings.push(format!("sealed directory {}: {} entries in the commit, {} in the snapshot", dir.1, entries.len(), actual.len())); }
    for entry in entries {
        let Some((_, target, dir_type, _)) = actual.iter().find(|(_, _, _, name)| *name == entry.name) else {
            findings.push(format!("sealed directory {}: `{}` is not in the snapshot", dir.1, String::from_utf8_lossy(&entry.name)));
            continue;
        };
        if *dir_type != entry.header.kind { findings.push(format!("`{}`: kind differs", String::from_utf8_lossy(&entry.name))); }
        let inode = parse_inode(item_of(items, Key::new(target.0, target.1, ITEM_INODE, 0)).ok_or("sealed entry without its inode")?)?;
        if inode.mode & 0o7777 != entry.header.mode || inode.size != entry.header.size {
            findings.push(format!("`{}`: mode or size differs from the commit", String::from_utf8_lossy(&entry.name)));
        }
        // An entry carries the inode's attribute flags, the CASEFOLD
        // projection and DIRECTORY_LINK, and both of its axes.
        if inode.flags & INODE_ENTRY_FLAGS != entry.header.flags {
            findings.push(format!("`{}`: flags differ from the commit", String::from_utf8_lossy(&entry.name)));
        }
        let case_axis = ((inode.flags >> INODE_CASE_AXIS_SHIFT) & 3) as u8;
        let norm_axis = ((inode.flags >> INODE_NORM_AXIS_SHIFT) & 3) as u8;
        if (case_axis, norm_axis) != (entry.header.case_axis, entry.header.norm_axis) {
            findings.push(format!("`{}`: case or normalization axis differs from the commit", String::from_utf8_lossy(&entry.name)));
        }
        match &entry.target {
            seal::Target::Name(name) if entry.header.kind == seal::ENTRY_DIRECTORY => compare_tree(reader, trees, name, view, *target, depth + 1, findings)?,
            seal::Target::Name(name) => {
                let content = manifest_content(store, name)?;
                let actual = super::file_content(reader, view, target.0, target.1, inode.size)?;
                if content != actual { findings.push(format!("`{}`: sealed content differs", String::from_utf8_lossy(&entry.name))); }
            }
            seal::Target::Inline(bytes) => {
                let actual = super::file_content(reader, view, target.0, target.1, inode.size)?;
                if *bytes != actual { findings.push(format!("`{}`: sealed inline content differs", String::from_utf8_lossy(&entry.name))); }
            }
            seal::Target::None => {}
        }
    }
    Ok(())
}

pub(super) fn bitmap_errors(reader: &ImageReader, sb: &Superblock, volume: &Volume) -> Result<Vec<String>, String> {
    let mut missing = 0u64;
    let mut extra = 0u64;
    let mut trailing = false;
    for index in 0..sb.bitmap_blocks {
        let bits = reader.read_block(sb.bitmap_start + index)?;
        let first = index * BLOCK_SIZE as u64 * 8;
        for bit in 0..BLOCK_SIZE as u64 * 8 {
            let block = first + bit;
            let present = bits[(bit / 8) as usize] & (1 << (bit % 8)) != 0;
            if block >= sb.total_blocks { trailing |= present; continue; }
            let reachable = volume.allocated.contains(&block);
            missing += (reachable && !present) as u64;
            extra += (present && !reachable) as u64;
        }
    }
    let mut errors = Vec::new();
    if missing != 0 { errors.push(format!("allocation bitmap misses {missing} reachable, retained or reserved blocks")); }
    if extra != 0 { errors.push(format!("allocation bitmap has {extra} blocks no root, pin or retirement names")); }
    if trailing { errors.push("allocation bitmap sets bits past total_blocks".into()); }
    Ok(errors)
}

#[cfg(test)]
mod store_tests {
    use super::*;

    fn store(identity: [u8; 16]) -> Store {
        Store { files: BTreeMap::new(), keys: BTreeMap::new(), suite: None, name_key: [0; 32], identity }
    }

    /// A pack belongs to the store whose UUID its header names, after the
    /// magic and a zero word.
    #[test]
    fn pack_headers_name_their_store() {
        let own = store([7; 16]);
        assert!(own.check_pack_header(&seal::pack_header(&[7; 16])).is_ok());
        assert!(own.check_pack_header(&seal::pack_header(&[8; 16])).is_err());
        let mut nonzero = seal::pack_header(&[7; 16]);
        nonzero[5] = 1;
        assert!(own.check_pack_header(&nonzero).is_err());
        assert!(own.check_pack_header(&seal::pack_header(&[7; 16])[..seal::PACK_HEADER_SIZE - 1]).is_err());
    }

    /// Only a directory entry may carry a case or normalization axis.
    #[test]
    fn tree_entries_carry_axes_only_on_directories() {
        let entry = |kind: u8, case_axis: u8, norm_axis: u8| seal::Entry {
            name: b"n".to_vec(),
            header: seal::EntryHeader {
                kind,
                flags: if case_axis != AXIS_SENSITIVE { INODE_CASEFOLD } else { 0 },
                case_axis,
                norm_axis,
                ..seal::EntryHeader::default()
            },
            target: if kind == seal::ENTRY_DIRECTORY { seal::Target::Name([9; 32]) } else { seal::Target::Inline(Vec::new()) },
            xattrs: Vec::new(),
            access_control: None,
        };
        let decode = |e: seal::Entry| decode_tree(&seal::encode_tree(&[e]).unwrap(), (AXIS_SENSITIVE, AXIS_SENSITIVE));
        assert!(decode(entry(seal::ENTRY_DIRECTORY, AXIS_INSENSITIVE, AXIS_MIXED)).is_ok());
        assert!(decode(entry(seal::ENTRY_REGULAR, AXIS_SENSITIVE, AXIS_SENSITIVE)).is_ok());
        let refused = decode(entry(seal::ENTRY_REGULAR, AXIS_INSENSITIVE, AXIS_SENSITIVE)).unwrap_err();
        assert!(refused.contains("not a directory"), "{refused}");
        assert!(decode(entry(seal::ENTRY_SYMLINK, AXIS_SENSITIVE, AXIS_INSENSITIVE)).is_err());
    }
}
