// SPDX-License-Identifier: GPL-2.0-only
//! flake — SaltyFS seal objects, transcribed for the image writer: the
//! canonical encodings of chunk, manifest, tree and commit, their keyed
//! names, the compressed, padded and sealed body form, the pack, pack-index
//! and super-index files of the store, and the sealer that turns the
//! writer's logical contents into one commit with its store files and key
//! tree items. Shares no code with the provider or the loader.

use std::collections::{BTreeMap, BTreeSet};

use super::codec::{fastcdc, zstd};
use super::primitives::{Suite, blake3};
use super::{
    AXIS_INSENSITIVE, AXIS_SENSITIVE, Contents, FileSource, INODE_CASEFOLD, INODE_DIRECTORY_LINK, axis_flags, padme, writer_directory_axes,
};

pub type Name = [u8; 32];

pub const KIND_COMMIT: u8 = 1;
pub const KIND_TREE: u8 = 2;
pub const KIND_MANIFEST: u8 = 3;
pub const KIND_CHUNK: u8 = 4;
/// Tree entry kinds, the directory entry `dir_type` values.
pub const ENTRY_REGULAR: u8 = 1;
pub const ENTRY_DIRECTORY: u8 = 4;
pub const ENTRY_SYMLINK: u8 = 7;
pub const TARGET_NONE: u8 = 0;
pub const TARGET_NAME: u8 = 1;
pub const TARGET_INLINE: u8 = 2;
pub const VALUE_NAME: u8 = 1;
pub const VALUE_INLINE: u8 = 2;
pub const VALUE_INLINE_LIMIT: usize = 200;
pub const CHUNK_ABSOLUTE_MAX: u64 = 16 * 1024 * 1024;
pub const BODY_WINDOW_MAX: u64 = 1024 * 1024;
pub const KEY_ALGORITHM_SIPHASH: u8 = 1;
pub const ACCESS_CONTROL_WORDS: usize = 19;

pub const PACK_MAGIC: &[u8; 4] = b"SLNP";
pub const PACK_INDEX_MAGIC: &[u8; 4] = b"SLNI";
pub const SUPER_INDEX_MAGIC: &[u8; 4] = b"SLNS";
pub const PACK_HEADER_SIZE: usize = 0x18;
pub const PACK_ENTRY_HEADER_SIZE: usize = 40;
pub const PACK_INDEX_ROWS_OFFSET: usize = 0x830;
pub const PACK_INDEX_ROW_SIZE: usize = 48;
pub const SUPER_INDEX_PACKS_OFFSET: usize = 0x828;
pub const SUPER_INDEX_ROW_SIZE: usize = 56;
pub const SUPER_INDEX_NAME: &[u8] = b"super-index";

// ---------------------------------------------------------------------------
// Canonical encodings
// ---------------------------------------------------------------------------

fn put_name(out: &mut Vec<u8>, n: &[u8]) { out.extend_from_slice(&(n.len() as u16).to_le_bytes()); out.extend_from_slice(n); }

/// A value: inline bytes or a manifest name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value { Inline(Vec<u8>), Manifest(Name) }

fn put_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Inline(bytes) => { out.push(VALUE_INLINE); out.extend_from_slice(&(bytes.len() as u32).to_le_bytes()); out.extend_from_slice(bytes); }
        Value::Manifest(name) => { out.push(VALUE_NAME); out.extend_from_slice(name); }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target { None, Name(Name), Inline(Vec<u8>) }

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EntryHeader {
    pub kind: u8,
    pub mode: u32,
    pub owner: u64,
    pub group: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub crtime: u64,
    pub flags: u32,
    pub case_axis: u8,
    pub norm_axis: u8,
    pub project_id: u32,
    pub size: u64,
    pub device: u64,
    pub link_group: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub header: EntryHeader,
    pub target: Target,
    pub xattrs: Vec<(Vec<u8>, Value)>,
    pub access_control: Option<([u64; ACCESS_CONTROL_WORDS], Value)>,
}

pub fn encode_entry(out: &mut Vec<u8>, e: &Entry) -> Result<(), String> {
    if e.name.is_empty() || e.name.len() > 255 || e.name.contains(&b'/') || e.name.contains(&0) { return Err("entry name".into()); }
    put_name(out, &e.name);
    let h = &e.header;
    out.push(h.kind);
    out.extend_from_slice(&h.mode.to_le_bytes());
    for v in [h.owner, h.group, h.atime, h.mtime, h.ctime, h.crtime] { out.extend_from_slice(&v.to_le_bytes()); }
    out.extend_from_slice(&h.flags.to_le_bytes());
    out.push(h.case_axis);
    out.push(h.norm_axis);
    out.extend_from_slice(&h.project_id.to_le_bytes());
    for v in [h.size, h.device, h.link_group] { out.extend_from_slice(&v.to_le_bytes()); }
    match &e.target {
        Target::None => out.push(TARGET_NONE),
        Target::Name(n) => { out.push(TARGET_NAME); out.extend_from_slice(n); }
        Target::Inline(bytes) => {
            if bytes.len() as u64 != h.size { return Err("inline target length disagrees with size".into()); }
            out.push(TARGET_INLINE);
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
    }
    if e.xattrs.windows(2).any(|w| w[0].0 >= w[1].0) { return Err("xattrs are not sorted".into()); }
    out.extend_from_slice(&(e.xattrs.len() as u32).to_le_bytes());
    for (name, value) in &e.xattrs { put_name(out, name); put_value(out, value); }
    match &e.access_control {
        None => out.push(0),
        Some((words, label)) => {
            out.push(1);
            let mut words = *words;
            words[2] &= !(1u64 << 48);
            for w in words { out.extend_from_slice(&w.to_le_bytes()); }
            put_value(out, label);
        }
    }
    Ok(())
}

/// A tree: the kind, the entry count, then the entries sorted by name.
pub fn encode_tree(entries: &[Entry]) -> Result<Vec<u8>, String> {
    if entries.windows(2).any(|w| w[0].name >= w[1].name) { return Err("tree entries are not sorted".into()); }
    let mut out = vec![KIND_TREE];
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries { encode_entry(&mut out, e)?; }
    Ok(out)
}

pub fn encode_manifest(total: u64, chunks: &[(Name, u32)]) -> Result<Vec<u8>, String> {
    if total as usize <= 4096 { return Err("a manifest names more than the inline bound".into()); }
    if chunks.iter().any(|(_, len)| *len == 0 || *len as u64 > CHUNK_ABSOLUTE_MAX) {
        return Err("manifest chunk length".into());
    }
    if chunks.iter().map(|(_, l)| *l as u64).sum::<u64>() != total { return Err("manifest lengths".into()); }
    let mut out = vec![KIND_MANIFEST];
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for (name, len) in chunks { out.extend_from_slice(name); out.extend_from_slice(&len.to_le_bytes()); }
    Ok(out)
}

pub fn encode_chunk(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 1);
    out.push(KIND_CHUNK);
    out.extend_from_slice(content);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub chunker: fastcdc::Params,
    pub subvol_uuid: [u8; 16],
    pub epoch: u64,
    pub seal_time: u64,
    pub clock_valid: u8,
    pub parents: Vec<Name>,
    pub root: Name,
    pub casefold_version: u32,
    pub key_algorithm: u8,
    pub root_case_axis: u8,
    pub root_norm_axis: u8,
}

pub fn encode_commit(c: &Commit) -> Result<Vec<u8>, String> {
    if c.parents.windows(2).any(|w| w[0] >= w[1]) { return Err("commit parents are not sorted".into()); }
    let mut out = vec![KIND_COMMIT];
    out.extend_from_slice(&c.chunker.min.to_le_bytes());
    out.extend_from_slice(&c.chunker.target.to_le_bytes());
    out.extend_from_slice(&c.chunker.max.to_le_bytes());
    out.extend_from_slice(&c.chunker.mask_s.to_le_bytes());
    out.extend_from_slice(&c.chunker.mask_l.to_le_bytes());
    out.extend_from_slice(&c.subvol_uuid);
    out.extend_from_slice(&c.epoch.to_le_bytes());
    out.extend_from_slice(&c.seal_time.to_le_bytes());
    out.push(c.clock_valid);
    out.extend_from_slice(&(c.parents.len() as u32).to_le_bytes());
    for p in &c.parents { out.extend_from_slice(p); }
    out.extend_from_slice(&c.root);
    out.extend_from_slice(&c.casefold_version.to_le_bytes());
    out.push(c.key_algorithm);
    out.push(c.root_case_axis);
    out.push(c.root_norm_axis);
    out.push(0);
    Ok(out)
}

/// Decode a commit encoding.
pub fn decode_commit(data: &[u8]) -> Result<Commit, String> {
    let mut at = 0usize;
    let take = |at: &mut usize, n: usize| -> Result<&[u8], String> { let s = data.get(*at..*at + n).ok_or("commit truncated")?; *at += n; Ok(s) };
    let u32_at = |s: &[u8]| u32::from_le_bytes(s.try_into().unwrap_or([0; 4]));
    let u64_at = |s: &[u8]| u64::from_le_bytes(s.try_into().unwrap_or([0; 8]));
    if take(&mut at, 1)?[0] != KIND_COMMIT { return Err("not a commit".into()); }
    let chunker = fastcdc::Params { min: u32_at(take(&mut at, 4)?), target: u32_at(take(&mut at, 4)?), max: u32_at(take(&mut at, 4)?),
        mask_s: u64_at(take(&mut at, 8)?), mask_l: u64_at(take(&mut at, 8)?) };
    let mut subvol_uuid = [0u8; 16];
    subvol_uuid.copy_from_slice(take(&mut at, 16)?);
    let epoch = u64_at(take(&mut at, 8)?);
    let seal_time = u64_at(take(&mut at, 8)?);
    let clock_valid = take(&mut at, 1)?[0];
    if clock_valid > 1 { return Err("commit clock byte is neither 0 nor 1".into()); }
    let count = u32_at(take(&mut at, 4)?) as usize;
    let mut parents = Vec::new();
    for _ in 0..count { let mut n = [0u8; 32]; n.copy_from_slice(take(&mut at, 32)?); parents.push(n); }
    let mut root = [0u8; 32];
    root.copy_from_slice(take(&mut at, 32)?);
    let casefold_version = u32_at(take(&mut at, 4)?);
    let key_algorithm = take(&mut at, 1)?[0];
    let root_case_axis = take(&mut at, 1)?[0];
    let root_norm_axis = take(&mut at, 1)?[0];
    if take(&mut at, 1)?[0] != 0 || at != data.len() { return Err("commit trailer".into()); }
    let commit = Commit { chunker, subvol_uuid, epoch, seal_time, clock_valid, parents, root, casefold_version, key_algorithm, root_case_axis, root_norm_axis };
    if encode_commit(&commit)? != data { return Err("commit encoding is not canonical".into()); }
    Ok(commit)
}

/// The name of an encoding under the volume's name key.
pub fn name_of(name_key: &[u8; 32], encoding: &[u8]) -> Name { blake3::keyed_hash(name_key, encoding) }

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// The stored body of an encoding: `u64 c || zstd frame || zero padding`
/// to Padmé's length, sealed under `key` when the suite encrypts (the
/// twenty-four zero nonce, associated data the name and the stored length).
pub fn build_body(encoding: &[u8], kind: u8, suite: Option<Suite>, key: &[u8; 32], name: &Name) -> Vec<u8> {
    let frame = zstd::compress(encoding, kind == KIND_CHUNK);
    let c = frame.len() as u64;
    let padded = padme(8 + c) as usize;
    let mut body = vec![0u8; padded];
    body[..8].copy_from_slice(&c.to_le_bytes());
    body[8..8 + frame.len()].copy_from_slice(&frame);
    if let Some(suite) = suite {
        let stored = padded as u64 + 16;
        let tag = suite.seal(key, &[0; 24], &body_ad(name, stored), &mut body);
        body.extend_from_slice(&tag);
    }
    body
}

fn body_ad(name: &Name, stored_length: u64) -> [u8; 40] {
    let mut ad = [0u8; 40];
    ad[..32].copy_from_slice(name);
    ad[32..].copy_from_slice(&stored_length.to_le_bytes());
    ad
}

/// Open a stored body and decode its frame; the window rule follows the
/// kind. The result is the canonical encoding.
pub fn open_body(body: &[u8], kind: u8, suite: Option<Suite>, key: &[u8; 32], name: &Name) -> Result<Vec<u8>, String> {
    let mut body = body.to_vec();
    let stored = body.len() as u64;
    let padded = match suite {
        None => body.len(),
        Some(suite) => {
            if body.len() < 16 { return Err("body shorter than a tag".into()); }
            let padded = body.len() - 16;
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&body[padded..]);
            suite.open(key, &[0; 24], &body_ad(name, stored), &mut body[..padded], &tag).map_err(|_| "body tag failed".to_string())?;
            padded
        }
    };
    if padded < 8 { return Err("body shorter than its length word".into()); }
    let c = u64::from_le_bytes(body[..8].try_into().unwrap_or([0; 8])) as usize;
    if c > padded - 8 || padme(8 + c as u64) as usize != padded || body[8 + c..padded].iter().any(|b| *b != 0) { return Err("body padding".into()); }
    let frame = &body[8..8 + c];
    let header = zstd::frame_header(frame)?;
    if kind == KIND_CHUNK {
        if !header.single_segment || header.content_size.is_none_or(|s| s > CHUNK_ABSOLUTE_MAX + 1) { return Err("chunk frame".into()); }
    } else if header.window_size > BODY_WINDOW_MAX { return Err("body window".into()); }
    let encoding = zstd::decompress(frame)?;
    if encoding.first() != Some(&kind) { return Err("body kind".into()); }
    Ok(encoding)
}

// ---------------------------------------------------------------------------
// Store files
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexRow { pub name: Name, pub offset: u64, pub stored_length: u64 }

fn fanout(rows: impl Iterator<Item = u8>) -> Vec<u8> {
    let mut counts = [0u64; 256];
    for b in rows { counts[b as usize] += 1; }
    let mut out = Vec::with_capacity(2048);
    let mut running = 0u64;
    for c in counts { running += c; out.extend_from_slice(&running.to_le_bytes()); }
    out
}

pub fn pack_header(store_identity: &[u8; 16]) -> Vec<u8> {
    let mut out = PACK_MAGIC.to_vec();
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(store_identity);
    out
}

pub fn pack_entry_header(name: &Name, stored_length: u64) -> Vec<u8> {
    let mut out = name.to_vec();
    out.extend_from_slice(&stored_length.to_le_bytes());
    out
}

pub fn pack_index(store_identity: &[u8; 16], pack: (u64, u64), rows: &[IndexRow]) -> Result<Vec<u8>, String> {
    if rows.windows(2).any(|w| w[0].name >= w[1].name) { return Err("index rows are not sorted".into()); }
    let mut out = PACK_INDEX_MAGIC.to_vec();
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(store_identity);
    out.extend_from_slice(&pack.0.to_le_bytes());
    out.extend_from_slice(&pack.1.to_le_bytes());
    out.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    out.extend_from_slice(&fanout(rows.iter().map(|r| r.name[0])));
    debug_assert_eq!(out.len(), PACK_INDEX_ROWS_OFFSET);
    for row in rows { out.extend_from_slice(&row.name); out.extend_from_slice(&row.offset.to_le_bytes()); out.extend_from_slice(&row.stored_length.to_le_bytes()); }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuperRow { pub name: Name, pub pack: u64, pub offset: u64, pub stored_length: u64 }

pub fn super_index(store_identity: &[u8; 16], packs: &[(u64, u64)], rows: &[SuperRow]) -> Result<Vec<u8>, String> {
    if rows.windows(2).any(|w| w[0].name >= w[1].name) || rows.iter().any(|r| r.pack as usize >= packs.len()) { return Err("super-index rows".into()); }
    let mut out = SUPER_INDEX_MAGIC.to_vec();
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(store_identity);
    out.extend_from_slice(&(packs.len() as u64).to_le_bytes());
    out.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    out.extend_from_slice(&fanout(rows.iter().map(|r| r.name[0])));
    debug_assert_eq!(out.len(), SUPER_INDEX_PACKS_OFFSET);
    for p in packs { out.extend_from_slice(&p.0.to_le_bytes()); out.extend_from_slice(&p.1.to_le_bytes()); }
    for r in rows {
        out.extend_from_slice(&r.name);
        out.extend_from_slice(&r.pack.to_le_bytes());
        out.extend_from_slice(&r.offset.to_le_bytes());
        out.extend_from_slice(&r.stored_length.to_le_bytes());
    }
    Ok(out)
}

/// The rows of a pack index, for the verifier.
pub fn read_pack_index(data: &[u8]) -> Result<((u64, u64), Vec<IndexRow>), String> {
    if data.len() < PACK_INDEX_ROWS_OFFSET || &data[..4] != PACK_INDEX_MAGIC { return Err("pack index header".into()); }
    let u64_at = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or([0; 8]));
    let pack = (u64_at(0x18), u64_at(0x20));
    let count = u64_at(0x28) as usize;
    if data.len() != PACK_INDEX_ROWS_OFFSET + count * PACK_INDEX_ROW_SIZE { return Err("pack index length".into()); }
    let mut rows = Vec::with_capacity(count);
    for i in 0..count {
        let at = PACK_INDEX_ROWS_OFFSET + i * PACK_INDEX_ROW_SIZE;
        let mut name = [0u8; 32];
        name.copy_from_slice(&data[at..at + 32]);
        rows.push(IndexRow { name, offset: u64_at(at + 32), stored_length: u64_at(at + 40) });
    }
    if rows.windows(2).any(|w| w[0].name >= w[1].name) { return Err("pack index order".into()); }
    if fanout(rows.iter().map(|r| r.name[0])) != data[0x30..PACK_INDEX_ROWS_OFFSET] { return Err("pack index fanout".into()); }
    Ok((pack, rows))
}

/// The packs and rows of a super-index, for the verifier.
pub fn read_super_index(data: &[u8]) -> Result<(Vec<(u64, u64)>, Vec<SuperRow>), String> {
    if data.len() < SUPER_INDEX_PACKS_OFFSET || &data[..4] != SUPER_INDEX_MAGIC { return Err("super-index header".into()); }
    let u64_at = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or([0; 8]));
    let packs = u64_at(0x18) as usize;
    let count = u64_at(0x20) as usize;
    let rows_at = SUPER_INDEX_PACKS_OFFSET + packs * 16;
    if data.len() != rows_at + count * SUPER_INDEX_ROW_SIZE { return Err("super-index length".into()); }
    let pack_ids: Vec<(u64, u64)> = (0..packs).map(|i| (u64_at(SUPER_INDEX_PACKS_OFFSET + i * 16), u64_at(SUPER_INDEX_PACKS_OFFSET + i * 16 + 8))).collect();
    let mut rows = Vec::with_capacity(count);
    for i in 0..count {
        let at = rows_at + i * SUPER_INDEX_ROW_SIZE;
        let mut name = [0u8; 32];
        name.copy_from_slice(&data[at..at + 32]);
        let row = SuperRow { name, pack: u64_at(at + 32), offset: u64_at(at + 40), stored_length: u64_at(at + 48) };
        if row.pack as usize >= packs { return Err("super-index pack index".into()); }
        rows.push(row);
    }
    if rows.windows(2).any(|w| w[0].name >= w[1].name) { return Err("super-index order".into()); }
    if fanout(rows.iter().map(|r| r.name[0])) != data[0x28..SUPER_INDEX_PACKS_OFFSET] { return Err("super-index fanout".into()); }
    Ok((pack_ids, rows))
}

pub fn pack_file_name(objectid: u64, index: bool) -> String { format!("pack-{objectid:016x}.{}", if index { "idx" } else { "pack" }) }

// ---------------------------------------------------------------------------
// The sealer over the writer's contents
// ---------------------------------------------------------------------------

/// One sealed object as the store holds it.
pub struct Object { pub name: Name, pub key: [u8; 32], pub body: Vec<u8> }

/// The seal of one image: its commit, the objects in store order, and the
/// files the store subvolume carries.
pub struct Sealed {
    pub commit: Commit,
    pub commit_name: Name,
    pub commit_encoding: Vec<u8>,
    /// Every object by name: `(name, key, stored length)`, in pack order.
    pub objects: Vec<Object>,
    pub pack: Vec<u8>,
    pub index: Vec<u8>,
    pub super_index: Vec<u8>,
}

/// What the sealer knows about the volume.
pub struct SealInputs<'a> {
    pub suite: Option<Suite>,
    pub name_key: [u8; 32],
    /// Object keys are derived per object from this material; zero under the
    /// plain suite.
    pub key_material: [u8; 32],
    pub store_identity: [u8; 16],
    pub subvol_uuid: [u8; 16],
    pub seal_time: u64,
    /// `seal_time` came from a declared clock.
    pub clock_valid: bool,
    pub chunker: fastcdc::Params,
    pub casefold_root: bool,
    pub time_ns: u64,
    pub contents: &'a Contents,
    pub pack_identity: (u64, u64),
    /// `(mode, uid, gid)` of a path, the writer's permission lookup.
    pub perm: &'a dyn Fn(&str, u32) -> (u32, u32, u32),
}

const POSIX_USER: u64 = 0x0100_0000_0000_0000;
const POSIX_GROUP: u64 = 0x0200_0000_0000_0000;

struct Sealer<'a> {
    inputs: &'a SealInputs<'a>,
    objects: Vec<Object>,
    seen: BTreeMap<Name, ()>,
}

impl Sealer<'_> {
    fn object_key(&self, name: &Name) -> [u8; 32] {
        if self.inputs.suite.is_none() { return [0; 32]; }
        blake3::derive_key(b"SaltyFS image writer object key", &[self.inputs.key_material.as_slice(), name].concat())
    }

    fn put(&mut self, kind: u8, encoding: &[u8]) -> Name {
        let name = name_of(&self.inputs.name_key, encoding);
        if self.seen.insert(name, ()).is_none() {
            let key = self.object_key(&name);
            let body = build_body(encoding, kind, self.inputs.suite, &key, &name);
            self.objects.push(Object { name, key, body });
        }
        name
    }

    fn seal_bytes(&mut self, data: &[u8]) -> Result<Target, String> {
        if data.len() <= 4096 { return Ok(Target::Inline(data.to_vec())); }
        let mut chunks = Vec::new();
        let mut at = 0usize;
        for len in fastcdc::chunks(data, &self.inputs.chunker) {
            let name = self.put(KIND_CHUNK, &encode_chunk(&data[at..at + len]));
            chunks.push((name, len as u32));
            at += len;
        }
        let manifest = encode_manifest(data.len() as u64, &chunks)?;
        Ok(Target::Name(self.put(KIND_MANIFEST, &manifest)))
    }

    /// The root's declared case axis, as the item tree's writer reads it.
    fn root_case_axis(&self) -> u8 {
        if self.inputs.casefold_root { AXIS_INSENSITIVE } else { AXIS_SENSITIVE }
    }

    fn seal_dir(&mut self, tree: &DirTree<'_>, path: &str) -> Result<Name, String> {
        let mut entries: Vec<Entry> = Vec::new();
        let (case_axis, norm_axis) = writer_directory_axes(self.root_case_axis());
        let policy = super::Policy { case_axis, norm_axis, plugin: super::DIR_HASH_SIPHASH };
        let mut unique_names = BTreeSet::new();
        for (name, node) in &tree.children {
            if !unique_names.insert(policy.unique_key(name.as_bytes())?) {
                return Err(format!("equivalent seal tree name `{name}`"));
            }
            let child_path = if path.is_empty() { name.clone() } else { format!("{path}/{name}") };
            let t = self.inputs.time_ns;
            let mut header = EntryHeader { atime: t, mtime: t, ctime: t, crtime: t, ..EntryHeader::default() };
            let target = match node {
                Node::Dir(sub) => {
                    let (mode, uid, gid) = (self.inputs.perm)(&child_path, 0o040755);
                    header.kind = ENTRY_DIRECTORY;
                    // The entry carries the directory inode's axes and their
                    // CASEFOLD projection, as the item tree gives them.
                    let (case_axis, norm_axis) = writer_directory_axes(self.root_case_axis());
                    header.case_axis = case_axis;
                    header.norm_axis = norm_axis;
                    header.flags = axis_flags(case_axis, norm_axis) & INODE_CASEFOLD;
                    header.mode = mode & 0o7777;
                    header.owner = POSIX_USER | uid as u64;
                    header.group = POSIX_GROUP | gid as u64;
                    Target::Name(self.seal_dir(sub, &child_path)?)
                }
                Node::File(source) => {
                    let (mode, uid, gid) = (self.inputs.perm)(&child_path, 0o100644);
                    let data = source.inline_bytes()?;
                    header.kind = ENTRY_REGULAR;
                    header.mode = mode & 0o7777;
                    header.owner = POSIX_USER | uid as u64;
                    header.group = POSIX_GROUP | gid as u64;
                    header.size = data.len() as u64;
                    self.seal_bytes(&data)?
                }
                Node::Symlink(target, directory_link) => {
                    let (mode, uid, gid) = (self.inputs.perm)(&child_path, 0o120777);
                    header.kind = ENTRY_SYMLINK;
                    if *directory_link { header.flags = INODE_DIRECTORY_LINK; }
                    header.mode = mode & 0o7777;
                    header.owner = POSIX_USER | uid as u64;
                    header.group = POSIX_GROUP | gid as u64;
                    header.size = target.len() as u64;
                    Target::Inline(target.clone())
                }
            };
            entries.push(Entry { name: name.as_bytes().to_vec(), header, target, xattrs: Vec::new(), access_control: None });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let encoding = encode_tree(&entries)?;
        Ok(self.put(KIND_TREE, &encoding))
    }
}

/// A symbolic link carries whether its target is a directory.
enum Node<'a> { Dir(DirTree<'a>), File(&'a FileSource), Symlink(Vec<u8>, bool) }
#[derive(Default)]
struct DirTree<'a> { children: BTreeMap<String, Node<'a>> }

fn insert<'a>(tree: &mut DirTree<'a>, path: &str, node: Node<'a>) -> Result<(), String> {
    let parts: Vec<&str> = path.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() { return Err("empty seal path".into()); }
    let mut cursor = tree;
    for part in &parts[..parts.len() - 1] {
        let entry = cursor.children.entry(part.to_string()).or_insert_with(|| Node::Dir(DirTree::default()));
        match entry {
            Node::Dir(d) => cursor = d,
            _ => return Err(format!("seal parent `{part}` is not a directory")),
        }
    }
    let last = parts[parts.len() - 1];
    match cursor.children.entry(last.to_string()) {
        std::collections::btree_map::Entry::Vacant(entry) => { entry.insert(node); }
        std::collections::btree_map::Entry::Occupied(entry) => {
            if !matches!((entry.get(), &node), (Node::Dir(_), Node::Dir(_))) {
                return Err(format!("duplicate seal path `{path}`"));
            }
        }
    }
    Ok(())
}

/// Seal the writer's contents: the commit and the store files.
pub fn seal(inputs: &SealInputs<'_>) -> Result<Sealed, String> {
    let mut root = DirTree::default();
    for dir in &inputs.contents.empty_dirs {
        insert(&mut root, dir, Node::Dir(DirTree::default()))?;
    }
    for (path, source) in &inputs.contents.files { insert(&mut root, path, Node::File(source))?; }
    for (path, target) in &inputs.contents.symlinks {
        insert(&mut root, path, Node::Symlink(
            target.clone(), inputs.contents.directory_links.contains(path),
        ))?;
    }
    let mut sealer = Sealer { inputs, objects: Vec::new(), seen: BTreeMap::new() };
    let root_name = sealer.seal_dir(&root, "")?;
    let (root_case_axis, root_norm_axis) = writer_directory_axes(sealer.root_case_axis());
    let commit = Commit { chunker: inputs.chunker, subvol_uuid: inputs.subvol_uuid, epoch: super::INITIAL_SEQ, seal_time: inputs.seal_time, clock_valid: u8::from(inputs.clock_valid),
        parents: Vec::new(), root: root_name, casefold_version: super::CASEFOLD_VERSION_UNICODE_15_1, key_algorithm: KEY_ALGORITHM_SIPHASH,
        root_case_axis, root_norm_axis };
    let commit_encoding = encode_commit(&commit)?;
    let commit_name = sealer.put(KIND_COMMIT, &commit_encoding);
    // The pack, its index and the super-index.
    let mut pack = pack_header(&inputs.store_identity);
    let mut rows = Vec::new();
    for object in &sealer.objects {
        rows.push(IndexRow { name: object.name, offset: pack.len() as u64, stored_length: object.body.len() as u64 });
        pack.extend_from_slice(&pack_entry_header(&object.name, object.body.len() as u64));
        pack.extend_from_slice(&object.body);
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let index = pack_index(&inputs.store_identity, inputs.pack_identity, &rows)?;
    let super_rows: Vec<SuperRow> = rows.iter().map(|r| SuperRow { name: r.name, pack: 0, offset: r.offset, stored_length: r.stored_length }).collect();
    let super_index = super_index(&inputs.store_identity, &[inputs.pack_identity], &super_rows)?;
    Ok(Sealed { commit, commit_name, commit_encoding, objects: sealer.objects, pack, index, super_index })
}
